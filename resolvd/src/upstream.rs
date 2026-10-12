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

/// These failures describe this process or host, not the upstream server.
/// A different configured address may still work; none should be demoted
/// on the strength of these errors.
pub fn is_local_failure(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::EMFILE
                | libc::ENFILE
                | libc::ENOMEM
                | libc::ENOBUFS
                | libc::EADDRNOTAVAIL
                | libc::EADDRINUSE
                | libc::EACCES
                | libc::EPERM
        )
    )
}

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
    /// transaction is over. Unmatched replies are discarded without closing
    /// the socket or changing the engine's deadline.
    pub fn service(
        &mut self,
        tx: Txid,
        revents: i16,
        accepts: impl Fn(&[u8]) -> bool,
    ) -> Option<Event> {
        if let Some(socket) = self.udp.get(&tx) {
            let mut buf = vec![0u8; 4096];
            let result = socket.recv(&mut buf);
            return match result {
                Ok(n) => {
                    buf.truncate(n);
                    if !accepts(&buf) {
                        return None;
                    }
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
                let mut read = false;
                loop {
                    // Consume complete frames before reading again, including
                    // before EOF. A valid frame may follow an unmatched one in
                    // this same buffer, with no further readiness notification.
                    if buf.len() >= 2 {
                        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        if buf.len() >= 2 + len {
                            let message = buf[2..2 + len].to_vec();
                            buf.drain(..2 + len);
                            if accepts(&message) {
                                self.tcp.remove(&tx);
                                return Some(Event::Received(message));
                            }
                            continue;
                        }
                    }
                    // Bound work per ready event even if a peer continuously
                    // sends unmatched frames. An incomplete frame stays here.
                    if read {
                        return None;
                    }
                    read = true;
                    match t.stream.read(&mut chunk) {
                        Ok(0) => {
                            self.tcp.remove(&tx);
                            return Some(Event::Failed);
                        }
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) =>
                        {
                            return None;
                        }
                        Err(_) => {
                            self.tcp.remove(&tx);
                            return Some(Event::Failed);
                        }
                    }
                }
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

#[cfg(test)]
mod pre_query_reset_tests {
    use super::*;
    use std::net::TcpListener;

    // TRM engine-servers.tcp-error-before-query-sent-fails-attempt. Hold
    // service() until the peer resets, without using a blocked reply write.
    #[test]
    fn a_reset_after_handshake_before_query_write_fails_immediately() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = connect_nonblocking(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: live peer socket and initialized linger option.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    peer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&linger as *const libc::linger).cast(),
                    std::mem::size_of_val(&linger) as libc::socklen_t,
                )
            },
            0
        );
        drop(peer);
        let mut pfd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live poll record.
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 1000) }, 1);
        let mut upstream = Upstream::new();
        upstream.tcp.insert(
            1,
            Tcp {
                stream,
                state: TcpState::Sending {
                    frame: vec![0, 1, 42],
                    sent: 0,
                },
            },
        );
        assert!(matches!(
            upstream.service(1, pfd.revents, |_| false),
            Some(Event::Failed)
        ));
        assert!(upstream.fds().is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, TcpListener};

    fn ready(upstream: &Upstream) -> i16 {
        let (_, fd, events) = upstream.fds()[0];
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: pollfd is one live descriptor record.
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 1000) }, 1);
        pollfd.revents
    }

    fn tcp_receiver() -> (Upstream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let mut upstream = Upstream::new();
        upstream.tcp.insert(
            1,
            Tcp {
                stream,
                state: TcpState::Receiving { buf: Vec::new() },
            },
        );
        (upstream, peer)
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = (payload.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn unmatched_udp_keeps_the_socket_for_the_matching_reply() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.connect(socket.local_addr().unwrap()).unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut upstream = Upstream::new();
        upstream.udp.insert(1, socket);
        peer.send(b"unmatched").unwrap();
        peer.send(b"matching").unwrap();
        let revents = ready(&upstream);
        assert!(upstream.service(1, revents, |p| p == b"matching").is_none());
        assert_eq!(upstream.fds().len(), 1);
        let revents = ready(&upstream);
        match upstream.service(1, revents, |p| p == b"matching") {
            Some(Event::Received(bytes)) => assert_eq!(bytes, b"matching"),
            _ => panic!("matching datagram was lost"),
        }
        assert!(upstream.fds().is_empty());
    }

    #[test]
    fn tcp_uses_a_matching_frame_after_unmatched_frames_and_before_eof() {
        let (mut upstream, mut peer) = tcp_receiver();
        let mut bytes = frame(b"unmatched");
        bytes.extend(frame(b""));
        bytes.extend(frame(b"matching"));
        peer.write_all(&bytes).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let revents = ready(&upstream);
        match upstream.service(1, revents, |p| p == b"matching") {
            Some(Event::Received(bytes)) => assert_eq!(bytes, b"matching"),
            _ => panic!("matching TCP frame was lost"),
        }
        assert!(upstream.fds().is_empty());
    }

    #[test]
    fn tcp_retains_a_partial_matching_frame_and_bounds_each_read() {
        let (mut upstream, mut peer) = tcp_receiver();
        let matching = vec![42; 8192];
        let mut bytes = frame(b"unmatched");
        bytes.extend(frame(&matching));
        peer.write_all(&bytes).unwrap();
        let revents = ready(&upstream);
        assert!(upstream.service(1, revents, |p| p == matching).is_none());
        assert_eq!(upstream.fds().len(), 1);
        loop {
            let revents = ready(&upstream);
            if let Some(event) = upstream.service(1, revents, |p| p == matching) {
                match event {
                    Event::Received(bytes) => assert_eq!(bytes, matching),
                    Event::Failed => panic!("partial TCP frame was lost"),
                }
                break;
            }
        }
        assert!(upstream.fds().is_empty());
    }

    #[test]
    fn unmatched_tcp_can_still_fail_on_eof_or_be_cancelled() {
        let (mut upstream, mut peer) = tcp_receiver();
        peer.write_all(&frame(b"unmatched")).unwrap();
        let revents = ready(&upstream);
        assert!(upstream.service(1, revents, |_| false).is_none());
        assert_eq!(upstream.fds().len(), 1);
        peer.shutdown(Shutdown::Write).unwrap();
        let revents = ready(&upstream);
        assert!(matches!(
            upstream.service(1, revents, |_| false),
            Some(Event::Failed)
        ));
        assert!(upstream.fds().is_empty());
        let (mut upstream, _peer) = tcp_receiver();
        upstream.cancel(1);
        assert!(upstream.fds().is_empty());
    }
}

#[cfg(test)]
mod local_failure_tests {
    use super::*;

    #[test]
    fn resource_and_permission_errors_do_not_describe_server_health() {
        for errno in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOMEM,
            libc::ENOBUFS,
            libc::EADDRNOTAVAIL,
            libc::EADDRINUSE,
            libc::EACCES,
            libc::EPERM,
        ] {
            assert!(is_local_failure(&io::Error::from_raw_os_error(errno)));
        }
        for errno in [
            libc::ECONNREFUSED,
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::ETIMEDOUT,
        ] {
            assert!(!is_local_failure(&io::Error::from_raw_os_error(errno)));
        }
    }
}
