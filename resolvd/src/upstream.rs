//! Sockets to upstream servers, one per transaction.
//!
//! A fresh UDP socket per query is how source-port randomisation happens:
//! the kernel picks an ephemeral port each time, and a forger has to guess
//! it along with the id and the 0x20 pattern. TCP is for truncated answers
//! only, nonblocking end to end so a server that accepts and then sits
//! there costs a poll slot, not the loop.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use resolvd::engine::Txid;

pub const DNS_PORT: u16 = 53;

enum TcpState {
    Connecting,
    Sending { frame: Vec<u8>, sent: usize },
    Receiving { buf: Vec<u8> },
}

struct Tcp {
    stream: TcpStream,
    state: TcpState,
}

pub enum Event {
    Received(Vec<u8>),
    Failed,
}

#[derive(Default)]
pub struct Upstream {
    udp: HashMap<Txid, UdpSocket>,
    tcp: HashMap<Txid, Tcp>,
}

impl Upstream {
    pub fn new() -> Upstream {
        Upstream::default()
    }

    /// Open a socket and send. A failure here is reported as `Failed`
    /// synchronously — a route to nowhere is known at `connect`.
    pub fn send(
        &mut self,
        tx: Txid,
        server: IpAddr,
        tcp: bool,
        payload: Vec<u8>,
    ) -> Result<(), io::Error> {
        let addr = SocketAddr::new(server, DNS_PORT);
        if tcp {
            let stream = connect_nonblocking(addr)?;
            let mut frame = Vec::with_capacity(2 + payload.len());
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            frame.extend_from_slice(&payload);
            self.tcp.insert(
                tx,
                Tcp {
                    stream,
                    state: TcpState::Connecting,
                },
            );
            if let Some(t) = self.tcp.get_mut(&tx) {
                t.state = TcpState::Sending { frame, sent: 0 };
            }
            return Ok(());
        }
        let bind: SocketAddr = match server {
            IpAddr::V4(_) => "0.0.0.0:0".parse().expect("literal"),
            IpAddr::V6(_) => "[::]:0".parse().expect("literal"),
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(addr)?;
        socket.set_nonblocking(true)?;
        socket.send(&payload)?;
        self.udp.insert(tx, socket);
        Ok(())
    }

    pub fn cancel(&mut self, tx: Txid) {
        self.udp.remove(&tx);
        self.tcp.remove(&tx);
    }

    /// Descriptors to poll, with the events each wants.
    pub fn fds(&self) -> Vec<(Txid, RawFd, i16)> {
        let mut out: Vec<(Txid, RawFd, i16)> = self
            .udp
            .iter()
            .map(|(tx, s)| (*tx, s.as_raw_fd(), libc::POLLIN))
            .collect();
        for (tx, t) in &self.tcp {
            let events = match t.state {
                TcpState::Connecting | TcpState::Sending { .. } => libc::POLLOUT,
                TcpState::Receiving { .. } => libc::POLLIN,
            };
            out.push((*tx, t.stream.as_raw_fd(), events));
        }
        out
    }

    /// The descriptor for `tx` is ready. Returns what happened, if the
    /// transaction is over; the socket is closed on any outcome.
    pub fn service(&mut self, tx: Txid, revents: i16) -> Option<Event> {
        if let Some(socket) = self.udp.get(&tx) {
            let mut buf = vec![0u8; 4096];
            let result = socket.recv(&mut buf);
            return match result {
                Ok(n) => {
                    buf.truncate(n);
                    self.udp.remove(&tx);
                    Some(Event::Received(buf))
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
                Err(_) => {
                    // ECONNREFUSED from an ICMP port-unreachable, most likely.
                    self.udp.remove(&tx);
                    Some(Event::Failed)
                }
            };
        }
        let t = self.tcp.get_mut(&tx)?;
        if revents & (libc::POLLERR | libc::POLLHUP) != 0
            && !matches!(t.state, TcpState::Receiving { .. })
        {
            self.tcp.remove(&tx);
            return Some(Event::Failed);
        }
        match &mut t.state {
            TcpState::Connecting => None,
            TcpState::Sending { frame, sent } => {
                // The first POLLOUT is connect completing; SO_ERROR says how.
                if *sent == 0
                    && let Ok(Some(_)) | Err(_) = t.stream.take_error()
                {
                    self.tcp.remove(&tx);
                    return Some(Event::Failed);
                }
                match t.stream.write(&frame[*sent..]) {
                    Ok(n) => {
                        *sent += n;
                        if *sent == frame.len() {
                            t.state = TcpState::Receiving {
                                buf: Vec::with_capacity(512),
                            };
                        }
                        None
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
                    Err(_) => {
                        self.tcp.remove(&tx);
                        Some(Event::Failed)
                    }
                }
            }
            TcpState::Receiving { buf } => {
                let mut chunk = [0u8; 4096];
                loop {
                    match t.stream.read(&mut chunk) {
                        Ok(0) => {
                            self.tcp.remove(&tx);
                            return Some(Event::Failed);
                        }
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            self.tcp.remove(&tx);
                            return Some(Event::Failed);
                        }
                    }
                }
                if buf.len() >= 2 {
                    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if buf.len() >= 2 + len {
                        let message = buf[2..2 + len].to_vec();
                        self.tcp.remove(&tx);
                        return Some(Event::Received(message));
                    }
                }
                None
            }
        }
    }
}

/// `connect(2)` on a nonblocking socket: returns once EINPROGRESS is in
/// hand; completion is a POLLOUT.
fn connect_nonblocking(addr: SocketAddr) -> io::Result<TcpStream> {
    let family = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: plain socket creation; the descriptor is owned immediately.
    let fd = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor we own.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let (ptr, len): (*const libc::sockaddr, libc::socklen_t) = match addr {
        SocketAddr::V4(a) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            let boxed = Box::new(sa);
            (
                Box::leak(boxed) as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(a) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: a.scope_id(),
            };
            let boxed = Box::new(sa);
            (
                Box::leak(boxed) as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };
    // SAFETY: `ptr` points at a live, correctly sized sockaddr for the call.
    let rc = unsafe { libc::connect(owned.as_raw_fd(), ptr, len) };
    // SAFETY: reclaim the leaked sockaddr now the call is over.
    unsafe {
        match addr {
            SocketAddr::V4(_) => drop(Box::from_raw(ptr as *mut libc::sockaddr_in)),
            SocketAddr::V6(_) => drop(Box::from_raw(ptr as *mut libc::sockaddr_in6)),
        }
    }
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(e);
        }
    }
    Ok(TcpStream::from(owned))
}
