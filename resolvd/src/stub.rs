//! The stub door: DNS itself on `127.0.0.53:53`, UDP and TCP.
//!
//! For everything that speaks DNS directly — Go's netgo, musl, hickory —
//! and for the constant `/etc/resolv.conf` to point at. Every query here
//! runs the same engine as the native door, single-label expansion
//! included; the door is different, the answer is not.
//!
//! Loopback only: `127.0.0.53`, never `::1` (which a local DNS server may
//! legitimately want) and never a routable address.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use dns::{Message, RData, Record, rcode};
use libresolv::{Outcome, STUB_ADDRESS, STUB_PORT};

use crate::engine::Answer;
use crate::log;

/// A TCP client has this long to send a query and read its answer.
pub const TCP_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Stub {
    pub udp: UdpSocket,
    pub tcp: TcpListener,
    /// TCP connections still reading a query.
    clients: HashMap<u64, TcpClient>,
    next_client: u64,
}

pub struct TcpClient {
    pub stream: TcpStream,
    buf: Vec<u8>,
    pub since: Instant,
}

/// Where a stub query came from, so its answer can go back.
pub enum Origin {
    Udp { peer: SocketAddr, query: Message },
    Tcp { stream: TcpStream, query: Message },
}

pub enum Incoming {
    /// A well-formed query to resolve.
    Query { origin: Origin },
    /// Nothing to do (a reply was sent, or the packet was not a query).
    Nothing,
}

impl Stub {
    pub fn open() -> io::Result<Stub> {
        let addr: SocketAddr = format!("{STUB_ADDRESS}:{STUB_PORT}").parse().expect("literal");
        let udp = UdpSocket::bind(addr)?;
        udp.set_nonblocking(true)?;
        let tcp = TcpListener::bind(addr)?;
        tcp.set_nonblocking(true)?;
        Ok(Stub { udp, tcp, clients: HashMap::new(), next_client: 1 })
    }

    /// Read every datagram waiting.
    pub fn receive_udp(&mut self) -> Vec<Incoming> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match self.udp.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    // Only loopback may ask. The bind address enforces the
                    // destination; this enforces the source.
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    match parse_query(&buf[..n]) {
                        Ok(query) => out.push(Incoming::Query { origin: Origin::Udp { peer, query } }),
                        Err(Some(reply)) => {
                            let _ = self.udp.send_to(&reply, peer);
                        }
                        Err(None) => {}
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::warn(format_args!("stub udp: {e}"));
                    break;
                }
            }
        }
        out
    }

    pub fn accept(&mut self, now: Instant) {
        loop {
            match self.tcp.accept() {
                Ok((stream, peer)) => {
                    if !peer.ip().is_loopback() || stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    let id = self.next_client;
                    self.next_client += 1;
                    self.clients.insert(id, TcpClient { stream, buf: Vec::with_capacity(512), since: now });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::warn(format_args!("stub tcp accept: {e}"));
                    break;
                }
            }
        }
    }

    pub fn client_fds(&self) -> Vec<(u64, RawFd)> {
        self.clients.iter().map(|(id, c)| (*id, c.stream.as_raw_fd())).collect()
    }

    /// Progress a TCP client. `Some` means it produced a query (or is
    /// gone); the connection leaves the table either way.
    pub fn service_client(&mut self, id: u64) -> Option<Incoming> {
        let c = self.clients.get_mut(&id)?;
        let mut chunk = [0u8; 4096];
        loop {
            match c.stream.read(&mut chunk) {
                Ok(0) => {
                    self.clients.remove(&id);
                    return Some(Incoming::Nothing);
                }
                Ok(n) => {
                    c.buf.extend_from_slice(&chunk[..n]);
                    if c.buf.len() > 2 + dns::MAX_MESSAGE_SIZE {
                        self.clients.remove(&id);
                        return Some(Incoming::Nothing);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.clients.remove(&id);
                    return Some(Incoming::Nothing);
                }
            }
        }
        if c.buf.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([c.buf[0], c.buf[1]]) as usize;
        if c.buf.len() < 2 + len {
            return None;
        }
        let mut client = self.clients.remove(&id)?;
        match parse_query(&client.buf[2..2 + len]) {
            Ok(query) => Some(Incoming::Query { origin: Origin::Tcp { stream: client.stream, query } }),
            Err(Some(reply)) => {
                send_tcp(&mut client.stream, &reply);
                Some(Incoming::Nothing)
            }
            Err(None) => Some(Incoming::Nothing),
        }
    }

    /// Drop TCP clients that have sat too long.
    pub fn expire(&mut self, now: Instant) {
        self.clients.retain(|_, c| now.duration_since(c.since) < TCP_TIMEOUT);
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.clients.values().map(|c| c.since + TCP_TIMEOUT).min()
    }

    /// Answer a query at its origin.
    pub fn answer(&mut self, origin: Origin, answer: &Answer) {
        match origin {
            Origin::Udp { peer, query } => {
                let reply = build_reply(&query, answer);
                if let Ok(bytes) = reply.encode_udp(query.udp_size()) {
                    let _ = self.udp.send_to(&bytes, peer);
                }
            }
            Origin::Tcp { mut stream, query } => {
                let reply = build_reply(&query, answer);
                if let Ok(bytes) = reply.encode() {
                    send_tcp(&mut stream, &bytes);
                }
            }
        }
    }
}

fn send_tcp(stream: &mut TcpStream, message: &[u8]) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let mut frame = Vec::with_capacity(2 + message.len());
    frame.extend_from_slice(&(message.len() as u16).to_be_bytes());
    frame.extend_from_slice(message);
    let _ = stream.write_all(&frame);
}

/// Decode a query, or produce the error reply it deserves. `Err(None)` is
/// "not even answerable" — not a query, or undecodable.
fn parse_query(bytes: &[u8]) -> Result<Message, Option<Vec<u8>>> {
    let message = Message::decode(bytes).map_err(|_| {
        // Enough of a header to echo the id back with FORMERR.
        if bytes.len() >= 12 {
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            let mut m = Message::default();
            m.header.id = id;
            m.header.response = true;
            m.header.rcode = rcode::FORMERR;
            m.encode().ok()
        } else {
            None
        }
    })?;
    if message.header.response {
        return Err(None);
    }
    let error = |code: u8| {
        let mut r = Message::reply_to(&message);
        r.header.rcode = code;
        if let Some(opt) = message.opt() {
            r.additional.push(Record::opt(dns::EDNS_UDP_SIZE, false).with_class(opt.class));
        }
        Err(r.encode().ok())
    };
    if message.header.opcode != 0 {
        return error(rcode::NOTIMP);
    }
    if message.question().is_none() {
        return error(rcode::FORMERR);
    }
    Ok(message)
}

/// The DNS rendering of an engine answer.
pub fn build_reply(query: &Message, answer: &Answer) -> Message {
    let mut reply = Message::reply_to(query);
    let question = query.question().cloned();
    match answer.outcome {
        Outcome::Found => {
            reply.header.rcode = rcode::NOERROR;
            // The answer may be at an expanded name; say so with a CNAME so
            // a client that checks names sees a well-formed chain.
            if let (Some(q), Some(resolved)) = (&question, &answer.resolved_name) {
                if &q.name != resolved && !answer.records.is_empty() {
                    let ttl = answer.records.iter().map(|r| r.ttl).min().unwrap_or(0);
                    reply.answers.push(Record::new(q.name.clone(), ttl, RData::Cname(resolved.clone())));
                }
            }
            reply.answers.extend(answer.records.iter().cloned());
        }
        Outcome::NotFound => reply.header.rcode = rcode::NXDOMAIN,
        Outcome::Unavailable => reply.header.rcode = rcode::SERVFAIL,
    }
    if query.opt().is_some() {
        reply.additional.push(Record::opt(dns::EDNS_UDP_SIZE, false));
    }
    reply
}

trait WithClass {
    fn with_class(self, class: u16) -> Self;
}

impl WithClass for Record {
    fn with_class(mut self, class: u16) -> Self {
        self.class = class;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{Name, Question, rtype};
    use std::net::Ipv4Addr;

    #[test]
    fn a_found_answer_becomes_noerror_with_records_and_a_cname_when_expanded() {
        let q = Message::query(9, Question::new(Name::parse("printer").unwrap(), rtype::A));
        let answer = Answer {
            outcome: Outcome::Found,
            records: vec![Record::new(Name::parse("printer.lan").unwrap(), 30, RData::A(Ipv4Addr::new(10, 0, 2, 9)))],
            resolved_name: Some(Name::parse("printer.lan").unwrap()),
            ..Default::default()
        };
        let r = build_reply(&q, &answer);
        assert_eq!(r.header.id, 9);
        assert!(r.header.response && r.header.recursion_available);
        assert_eq!(r.answers.len(), 2);
        assert_eq!(r.answers[0].rdata, RData::Cname(Name::parse("printer.lan").unwrap()));
        assert!(r.opt().is_some());
        let bytes = r.encode().unwrap();
        Message::decode(&bytes).unwrap();
    }

    #[test]
    fn outcomes_map_to_rcodes() {
        let q = Message::query(1, Question::new(Name::parse("x.example").unwrap(), rtype::A));
        let nf = build_reply(&q, &Answer { outcome: Outcome::NotFound, ..Default::default() });
        assert_eq!(nf.header.rcode, rcode::NXDOMAIN);
        let un = build_reply(&q, &Answer { outcome: Outcome::Unavailable, ..Default::default() });
        assert_eq!(un.header.rcode, rcode::SERVFAIL);
    }

    #[test]
    fn bad_queries_get_error_replies() {
        let mut m = Message::query(5, Question::new(Name::parse("x").unwrap(), rtype::A));
        m.header.opcode = 2;
        let bytes = m.encode().unwrap();
        let reply = parse_query(&bytes).err().flatten().unwrap();
        assert_eq!(Message::decode(&reply).unwrap().header.rcode, rcode::NOTIMP);
        assert!(parse_query(&[0u8; 12]).is_err());
        let mut r = Message::query(5, Question::new(Name::parse("x").unwrap(), rtype::A));
        r.header.response = true;
        assert!(matches!(parse_query(&r.encode().unwrap()), Err(None)));
        let mut bad = bytes.clone();
        bad.truncate(20);
        let reply = parse_query(&bad).err().flatten().unwrap();
        assert_eq!(Message::decode(&reply).unwrap().header.rcode, rcode::FORMERR);
    }
}
