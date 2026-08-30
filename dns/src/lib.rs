//! The DNS wire format (RFC 1035, with EDNS0 from RFC 6891).
//!
//! This is the code on a Peios machine that reads bytes a stranger on the
//! network chose, which shapes everything about it:
//!
//! - **Pure.** No sockets, no clocks, no allocation the input does not bound.
//!   A message decodes into owned records; nothing borrows the wire.
//! - **Total.** Every input either decodes or returns [`Error`]; nothing
//!   panics, and every loop is bounded by the input length (compression
//!   pointers may only go backwards, so a chain terminates).
//! - **Small.** Only what a stub resolver needs: names, the header, questions,
//!   records with typed data for the handful of types callers act on, and raw
//!   bytes for the rest. An authoritative server's needs are not here.
//!
//! Names are kept as they arrived — case preserved — and compared
//! case-insensitively, which is what RFC 4343 requires and what 0x20
//! randomisation (RFC draft-vixie-dnsext-dns0x20) relies on.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The ceiling on a UDP payload without EDNS. Every server must accept this.
pub const CLASSIC_UDP_SIZE: u16 = 512;
/// The EDNS buffer size we advertise: what survives on the public internet
/// without fragmentation (DNS flag day 2020).
pub const EDNS_UDP_SIZE: u16 = 1232;
/// The largest DNS message; the TCP length prefix is 16 bits.
pub const MAX_MESSAGE_SIZE: usize = 65_535;
/// RFC 1035 §2.3.4.
pub const MAX_NAME_LEN: usize = 255;
pub const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The message ended before the field did.
    Truncated,
    /// A label longer than 63 octets, or a name longer than 255.
    NameTooLong,
    /// A label with the reserved 0x40/0x80 prefixes.
    BadLabel,
    /// A compression pointer forwards or to itself.
    BadPointer,
    /// A record's data length disagrees with its type's fixed size.
    BadRData,
    /// Bytes after the last section.
    TrailingBytes,
    /// A name that cannot be encoded (empty label, too long).
    BadName,
    /// The message would exceed 65535 bytes.
    TooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::Truncated => "truncated message",
            Error::NameTooLong => "name or label too long",
            Error::BadLabel => "reserved label type",
            Error::BadPointer => "bad compression pointer",
            Error::BadRData => "malformed record data",
            Error::TrailingBytes => "trailing bytes after the last section",
            Error::BadName => "name cannot be encoded",
            Error::TooLarge => "message too large",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------- names ---

/// A domain name: a sequence of labels, without the trailing root label.
///
/// Stored in presentation-free form — the labels themselves, as bytes — so
/// a label containing a dot or a NUL is representable and compared correctly.
#[derive(Clone, PartialOrd, Ord, Default)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    pub fn root() -> Name {
        Name { labels: Vec::new() }
    }

    /// Parse presentation form: `www.example.com` or `www.example.com.`.
    /// Escapes are not supported (nothing on this machine produces them).
    pub fn parse(s: &str) -> Result<Name, Error> {
        let s = s.strip_suffix('.').unwrap_or(s);
        if s.is_empty() {
            return Ok(Name::root());
        }
        let mut labels = Vec::new();
        for label in s.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(Error::BadName);
            }
            labels.push(label.as_bytes().to_vec());
        }
        let name = Name { labels };
        if name.wire_len() > MAX_NAME_LEN {
            return Err(Error::NameTooLong);
        }
        Ok(name)
    }

    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Name, Error> {
        for l in &labels {
            if l.is_empty() || l.len() > MAX_LABEL_LEN {
                return Err(Error::BadName);
            }
        }
        let name = Name { labels };
        if name.wire_len() > MAX_NAME_LEN {
            return Err(Error::NameTooLong);
        }
        Ok(name)
    }

    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Bytes on the wire, uncompressed, including the root label.
    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1
    }

    /// `self` is `suffix` or ends with it (case-insensitively).
    pub fn ends_with(&self, suffix: &Name) -> bool {
        if suffix.labels.len() > self.labels.len() {
            return false;
        }
        let skip = self.labels.len() - suffix.labels.len();
        self.labels[skip..].iter().zip(&suffix.labels).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// `self` with `suffix` appended: `host` + `example.com` → `host.example.com`.
    pub fn join(&self, suffix: &Name) -> Result<Name, Error> {
        let mut labels = self.labels.clone();
        labels.extend(suffix.labels.iter().cloned());
        Name::from_labels(labels)
    }

    /// The name with every label lowercased — a cache key.
    pub fn to_lowercase(&self) -> Name {
        Name { labels: self.labels.iter().map(|l| l.to_ascii_lowercase()).collect() }
    }

    /// The reverse-mapping name for an address: `4.3.2.1.in-addr.arpa`.
    pub fn reverse_v4(addr: Ipv4Addr) -> Name {
        let o = addr.octets();
        Name::parse(&format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])).expect("fits")
    }

    /// `...ip6.arpa` for an IPv6 address.
    pub fn reverse_v6(addr: Ipv6Addr) -> Name {
        let mut s = String::with_capacity(72);
        for b in addr.octets().iter().rev() {
            s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
        }
        s.push_str("ip6.arpa");
        Name::parse(&s).expect("fits")
    }

    /// The address a reverse-mapping name denotes, if it is one.
    pub fn reverse_address(&self) -> Option<std::net::IpAddr> {
        let in_addr = Name::parse("in-addr.arpa").expect("fits");
        let ip6 = Name::parse("ip6.arpa").expect("fits");
        if self.ends_with(&in_addr) && self.labels.len() == 6 {
            let mut o = [0u8; 4];
            for (i, l) in self.labels[..4].iter().enumerate() {
                let s = std::str::from_utf8(l).ok()?;
                o[3 - i] = s.parse().ok()?;
            }
            return Some(Ipv4Addr::from(o).into());
        }
        if self.ends_with(&ip6) && self.labels.len() == 34 {
            let mut o = [0u8; 16];
            for (i, l) in self.labels[..32].iter().enumerate() {
                if l.len() != 1 {
                    return None;
                }
                let nibble = (l[0] as char).to_digit(16)? as u8;
                let byte = 15 - i / 2;
                if i % 2 == 0 {
                    o[byte] |= nibble;
                } else {
                    o[byte] |= nibble << 4;
                }
            }
            return Some(Ipv6Addr::from(o).into());
        }
        None
    }

    /// Apply 0x20 case randomisation from a bit source (RFC draft-vixie).
    pub fn randomise_case(&self, mut bits: impl FnMut() -> bool) -> Name {
        Name {
            labels: self
                .labels
                .iter()
                .map(|l| {
                    l.iter()
                        .map(|&b| if b.is_ascii_alphabetic() && bits() { b ^ 0x20 } else { b })
                        .collect()
                })
                .collect(),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        for l in &self.labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l);
        }
        out.push(0);
    }

    /// Read a possibly-compressed name at `pos` in `msg`. Returns the name and
    /// the position after it in the *uncompressed* stream (i.e. after the
    /// first pointer, if any).
    fn read(msg: &[u8], pos: usize) -> Result<(Name, usize), Error> {
        let mut labels = Vec::new();
        let mut total = 0usize;
        let mut p = pos;
        let mut end: Option<usize> = None;
        // A pointer must point strictly backwards, so each hop strictly
        // decreases `p` and the loop terminates; `hops` is belt and braces.
        let mut hops = 0;
        loop {
            let len = *msg.get(p).ok_or(Error::Truncated)? as usize;
            match len & 0xC0 {
                0x00 => {
                    p += 1;
                    if len == 0 {
                        break;
                    }
                    let label = msg.get(p..p + len).ok_or(Error::Truncated)?;
                    total += len + 1;
                    if total + 1 > MAX_NAME_LEN {
                        return Err(Error::NameTooLong);
                    }
                    labels.push(label.to_vec());
                    p += len;
                }
                0xC0 => {
                    let lo = *msg.get(p + 1).ok_or(Error::Truncated)? as usize;
                    let target = ((len & 0x3F) << 8) | lo;
                    if end.is_none() {
                        end = Some(p + 2);
                    }
                    if target >= p {
                        return Err(Error::BadPointer);
                    }
                    hops += 1;
                    if hops > 64 {
                        return Err(Error::BadPointer);
                    }
                    p = target;
                }
                _ => return Err(Error::BadLabel),
            }
        }
        Ok((Name { labels }, end.unwrap_or(p)))
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Name) -> bool {
        self.labels.len() == other.labels.len()
            && self.labels.iter().zip(&other.labels).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl Eq for Name {}

impl std::hash::Hash for Name {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.labels.len().hash(state);
        for l in &self.labels {
            for b in l {
                b.to_ascii_lowercase().hash(state);
            }
            0xffu8.hash(state);
        }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_str(".");
        }
        for (i, l) in self.labels.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            for &b in l {
                match b {
                    b'.' | b'\\' => write!(f, "\\{}", b as char)?,
                    0x21..=0x7e => write!(f, "{}", b as char)?,
                    _ => write!(f, "\\{:03}", b)?,
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

// ------------------------------------------------------------- constants ---

/// Record types, as u16 so unknown ones pass through untouched.
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const OPT: u16 = 41;
    pub const ANY: u16 = 255;

    pub fn name(t: u16) -> String {
        match t {
            A => "A".into(),
            NS => "NS".into(),
            CNAME => "CNAME".into(),
            SOA => "SOA".into(),
            PTR => "PTR".into(),
            MX => "MX".into(),
            TXT => "TXT".into(),
            AAAA => "AAAA".into(),
            SRV => "SRV".into(),
            OPT => "OPT".into(),
            ANY => "ANY".into(),
            other => format!("TYPE{other}"),
        }
    }

    pub fn parse(s: &str) -> Option<u16> {
        Some(match s.to_ascii_uppercase().as_str() {
            "A" => A,
            "NS" => NS,
            "CNAME" => CNAME,
            "SOA" => SOA,
            "PTR" => PTR,
            "MX" => MX,
            "TXT" => TXT,
            "AAAA" => AAAA,
            "SRV" => SRV,
            "ANY" => ANY,
            other => other.strip_prefix("TYPE")?.parse().ok()?,
        })
    }
}

pub mod class {
    pub const IN: u16 = 1;
}

/// Response codes.
pub mod rcode {
    pub const NOERROR: u8 = 0;
    pub const FORMERR: u8 = 1;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const NOTIMP: u8 = 4;
    pub const REFUSED: u8 = 5;

    pub fn name(r: u8) -> String {
        match r {
            NOERROR => "NOERROR".into(),
            FORMERR => "FORMERR".into(),
            SERVFAIL => "SERVFAIL".into(),
            NXDOMAIN => "NXDOMAIN".into(),
            NOTIMP => "NOTIMP".into(),
            REFUSED => "REFUSED".into(),
            other => format!("RCODE{other}"),
        }
    }
}

// ---------------------------------------------------------------- header ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    pub id: u16,
    pub response: bool,
    /// Opcode, 4 bits. 0 is QUERY; everything else is refused by a stub.
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    /// AD: the answer was DNSSEC-validated by the responder. We never trust
    /// it from a plaintext upstream, but we carry it.
    pub authentic_data: bool,
    pub checking_disabled: bool,
    /// The low 4 bits; EDNS extends it (see [`Message::rcode`]).
    pub rcode: u8,
}

impl Header {
    fn flags(&self) -> u16 {
        (u16::from(self.response) << 15)
            | ((u16::from(self.opcode) & 0xF) << 11)
            | (u16::from(self.authoritative) << 10)
            | (u16::from(self.truncated) << 9)
            | (u16::from(self.recursion_desired) << 8)
            | (u16::from(self.recursion_available) << 7)
            | (u16::from(self.authentic_data) << 5)
            | (u16::from(self.checking_disabled) << 4)
            | (u16::from(self.rcode) & 0xF)
    }

    fn from_flags(id: u16, flags: u16) -> Header {
        Header {
            id,
            response: flags & 0x8000 != 0,
            opcode: ((flags >> 11) & 0xF) as u8,
            authoritative: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursion_desired: flags & 0x0100 != 0,
            recursion_available: flags & 0x0080 != 0,
            authentic_data: flags & 0x0020 != 0,
            checking_disabled: flags & 0x0010 != 0,
            rcode: (flags & 0xF) as u8,
        }
    }
}

// ------------------------------------------------------------- questions ---

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    pub name: Name,
    pub rtype: u16,
    pub class: u16,
}

impl Question {
    pub fn new(name: Name, rtype: u16) -> Question {
        Question { name, rtype, class: class::IN }
    }
}

// --------------------------------------------------------------- records ---

/// Typed record data for the types a stub acts on; raw bytes for the rest.
///
/// Types whose data contains names (CNAME, PTR, NS, SOA, MX, SRV) are decoded
/// so compression pointers are resolved — a raw copy of compressed rdata
/// would be meaningless outside the message it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Name),
    Ptr(Name),
    Ns(Name),
    Soa { mname: Name, rname: Name, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    Mx { preference: u16, exchange: Name },
    Srv { priority: u16, weight: u16, port: u16, target: Name },
    Txt(Vec<Vec<u8>>),
    /// An EDNS pseudo-record: the class and TTL fields carry its meaning, and
    /// the data is options we neither send nor read.
    Opt(Vec<u8>),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: RData,
}

impl Record {
    pub fn new(name: Name, ttl: u32, rdata: RData) -> Record {
        let rtype = match &rdata {
            RData::A(_) => rtype::A,
            RData::Aaaa(_) => rtype::AAAA,
            RData::Cname(_) => rtype::CNAME,
            RData::Ptr(_) => rtype::PTR,
            RData::Ns(_) => rtype::NS,
            RData::Soa { .. } => rtype::SOA,
            RData::Mx { .. } => rtype::MX,
            RData::Srv { .. } => rtype::SRV,
            RData::Txt(_) => rtype::TXT,
            RData::Opt(_) => rtype::OPT,
            RData::Unknown(_) => 0,
        };
        Record { name, rtype, class: class::IN, ttl, rdata }
    }

    /// The EDNS OPT pseudo-record advertising `udp_size`.
    pub fn opt(udp_size: u16, do_bit: bool) -> Record {
        Record {
            name: Name::root(),
            rtype: rtype::OPT,
            class: udp_size,
            ttl: if do_bit { 0x8000 } else { 0 },
            rdata: RData::Opt(Vec::new()),
        }
    }

    /// The data in presentation form.
    pub fn rdata_text(&self) -> String {
        match &self.rdata {
            RData::A(a) => a.to_string(),
            RData::Aaaa(a) => a.to_string(),
            RData::Cname(n) | RData::Ptr(n) | RData::Ns(n) => n.to_string(),
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}")
            }
            RData::Mx { preference, exchange } => format!("{preference} {exchange}"),
            RData::Srv { priority, weight, port, target } => format!("{priority} {weight} {port} {target}"),
            RData::Txt(strings) => strings
                .iter()
                .map(|s| format!("\"{}\"", String::from_utf8_lossy(s).replace('"', "\\\"")))
                .collect::<Vec<_>>()
                .join(" "),
            RData::Opt(b) | RData::Unknown(b) => {
                let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
                format!("\\# {} {hex}", b.len())
            }
        }
    }

    /// The data as it would appear on the wire, uncompressed.
    pub fn rdata_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_rdata(&mut out, &self.rdata);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.name.write(out);
        out.extend_from_slice(&self.rtype.to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let at = out.len();
        out.extend_from_slice(&[0, 0]);
        write_rdata(out, &self.rdata);
        let len = (out.len() - at - 2) as u16;
        out[at..at + 2].copy_from_slice(&len.to_be_bytes());
    }
}

fn write_rdata(out: &mut Vec<u8>, rdata: &RData) {
    match rdata {
        RData::A(a) => out.extend_from_slice(&a.octets()),
        RData::Aaaa(a) => out.extend_from_slice(&a.octets()),
        RData::Cname(n) | RData::Ptr(n) | RData::Ns(n) => n.write(out),
        RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
            mname.write(out);
            rname.write(out);
            for v in [serial, refresh, retry, expire, minimum] {
                out.extend_from_slice(&v.to_be_bytes());
            }
        }
        RData::Mx { preference, exchange } => {
            out.extend_from_slice(&preference.to_be_bytes());
            exchange.write(out);
        }
        RData::Srv { priority, weight, port, target } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            target.write(out);
        }
        RData::Txt(strings) => {
            for s in strings {
                let n = s.len().min(255);
                out.push(n as u8);
                out.extend_from_slice(&s[..n]);
            }
        }
        RData::Opt(b) | RData::Unknown(b) => out.extend_from_slice(b),
    }
}

fn read_rdata(msg: &[u8], rtype: u16, start: usize, len: usize) -> Result<RData, Error> {
    let data = msg.get(start..start + len).ok_or(Error::Truncated)?;
    let end = start + len;
    // A name inside rdata may point anywhere earlier in the message, so it is
    // read against the whole message; but it must not run past the rdata.
    let name_at = |pos: usize| -> Result<(Name, usize), Error> {
        let (n, next) = Name::read(msg, pos)?;
        if next > end {
            return Err(Error::BadRData);
        }
        Ok((n, next))
    };
    let u32_at = |pos: usize| -> Result<u32, Error> {
        let b = msg.get(pos..pos + 4).ok_or(Error::BadRData)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    let u16_at = |pos: usize| -> Result<u16, Error> {
        let b = msg.get(pos..pos + 2).ok_or(Error::BadRData)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    };
    Ok(match rtype {
        rtype::A => {
            if len != 4 {
                return Err(Error::BadRData);
            }
            RData::A(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
        }
        rtype::AAAA => {
            if len != 16 {
                return Err(Error::BadRData);
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(data);
            RData::Aaaa(Ipv6Addr::from(o))
        }
        rtype::CNAME | rtype::PTR | rtype::NS => {
            let (n, next) = name_at(start)?;
            if next != end {
                return Err(Error::BadRData);
            }
            match rtype {
                rtype::CNAME => RData::Cname(n),
                rtype::PTR => RData::Ptr(n),
                _ => RData::Ns(n),
            }
        }
        rtype::SOA => {
            let (mname, p) = name_at(start)?;
            let (rname, p) = name_at(p)?;
            if p + 20 != end {
                return Err(Error::BadRData);
            }
            RData::Soa {
                mname,
                rname,
                serial: u32_at(p)?,
                refresh: u32_at(p + 4)?,
                retry: u32_at(p + 8)?,
                expire: u32_at(p + 12)?,
                minimum: u32_at(p + 16)?,
            }
        }
        rtype::MX => {
            if len < 3 {
                return Err(Error::BadRData);
            }
            let (exchange, next) = name_at(start + 2)?;
            if next != end {
                return Err(Error::BadRData);
            }
            RData::Mx { preference: u16_at(start)?, exchange }
        }
        rtype::SRV => {
            if len < 7 {
                return Err(Error::BadRData);
            }
            let (target, next) = name_at(start + 6)?;
            if next != end {
                return Err(Error::BadRData);
            }
            RData::Srv { priority: u16_at(start)?, weight: u16_at(start + 2)?, port: u16_at(start + 4)?, target }
        }
        rtype::TXT => {
            let mut strings = Vec::new();
            let mut p = 0;
            while p < data.len() {
                let n = data[p] as usize;
                let s = data.get(p + 1..p + 1 + n).ok_or(Error::BadRData)?;
                strings.push(s.to_vec());
                p += 1 + n;
            }
            RData::Txt(strings)
        }
        rtype::OPT => RData::Opt(data.to_vec()),
        _ => RData::Unknown(data.to_vec()),
    })
}

// --------------------------------------------------------------- message ---

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Message {
    /// A recursion-desired query for one question, with EDNS advertising
    /// [`EDNS_UDP_SIZE`].
    pub fn query(id: u16, question: Question) -> Message {
        Message {
            header: Header { id, recursion_desired: true, ..Default::default() },
            questions: vec![question],
            additional: vec![Record::opt(EDNS_UDP_SIZE, false)],
            ..Default::default()
        }
    }

    /// The reply skeleton for `query`: same id, same question, RA set.
    pub fn reply_to(query: &Message) -> Message {
        Message {
            header: Header {
                id: query.header.id,
                response: true,
                opcode: query.header.opcode,
                recursion_desired: query.header.recursion_desired,
                recursion_available: true,
                checking_disabled: query.header.checking_disabled,
                ..Default::default()
            },
            questions: query.questions.clone(),
            ..Default::default()
        }
    }

    pub fn opt(&self) -> Option<&Record> {
        self.additional.iter().find(|r| r.rtype == rtype::OPT)
    }

    /// The peer's advertised UDP payload size, or the classic 512.
    pub fn udp_size(&self) -> u16 {
        self.opt().map(|o| o.class.max(CLASSIC_UDP_SIZE)).unwrap_or(CLASSIC_UDP_SIZE)
    }

    /// The full response code, with the EDNS extended bits.
    pub fn rcode(&self) -> u16 {
        let ext = self.opt().map(|o| ((o.ttl >> 24) & 0xFF) as u16).unwrap_or(0);
        (ext << 4) | u16::from(self.header.rcode)
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&self.header.id.to_be_bytes());
        out.extend_from_slice(&self.header.flags().to_be_bytes());
        for n in [self.questions.len(), self.answers.len(), self.authority.len(), self.additional.len()] {
            if n > u16::MAX as usize {
                return Err(Error::TooLarge);
            }
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        for q in &self.questions {
            q.name.write(&mut out);
            out.extend_from_slice(&q.rtype.to_be_bytes());
            out.extend_from_slice(&q.class.to_be_bytes());
        }
        for r in self.answers.iter().chain(&self.authority).chain(&self.additional) {
            r.write(&mut out);
        }
        if out.len() > MAX_MESSAGE_SIZE {
            return Err(Error::TooLarge);
        }
        Ok(out)
    }

    /// Encode for UDP: if the message exceeds `limit`, drop the answer
    /// sections and set TC so the client retries over TCP.
    pub fn encode_udp(&self, limit: u16) -> Result<Vec<u8>, Error> {
        let full = self.encode()?;
        if full.len() <= limit as usize {
            return Ok(full);
        }
        let mut truncated = Message {
            header: Header { truncated: true, ..self.header },
            questions: self.questions.clone(),
            ..Default::default()
        };
        if let Some(opt) = self.opt() {
            truncated.additional.push(opt.clone());
        }
        truncated.encode()
    }

    pub fn decode(msg: &[u8]) -> Result<Message, Error> {
        if msg.len() < 12 {
            return Err(Error::Truncated);
        }
        let u16_at = |pos: usize| u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let header = Header::from_flags(u16_at(0), u16_at(2));
        let counts = [u16_at(4), u16_at(6), u16_at(8), u16_at(10)];
        let mut p = 12;
        let mut questions = Vec::new();
        for _ in 0..counts[0] {
            let (name, next) = Name::read(msg, p)?;
            let b = msg.get(next..next + 4).ok_or(Error::Truncated)?;
            questions.push(Question {
                name,
                rtype: u16::from_be_bytes([b[0], b[1]]),
                class: u16::from_be_bytes([b[2], b[3]]),
            });
            p = next + 4;
        }
        let mut sections: [Vec<Record>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for (i, section) in sections.iter_mut().enumerate() {
            for _ in 0..counts[i + 1] {
                let (name, next) = Name::read(msg, p)?;
                let b = msg.get(next..next + 10).ok_or(Error::Truncated)?;
                let rtype = u16::from_be_bytes([b[0], b[1]]);
                let class = u16::from_be_bytes([b[2], b[3]]);
                let ttl = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                let len = u16::from_be_bytes([b[8], b[9]]) as usize;
                let start = next + 10;
                let rdata = read_rdata(msg, rtype, start, len)?;
                section.push(Record { name, rtype, class, ttl, rdata });
                p = start + len;
            }
        }
        // Trailing bytes are tolerated: some middleboxes pad, and RFC 1035
        // does not forbid it. Being strict would refuse real answers.
        let [answers, authority, additional] = sections;
        Ok(Message { header, questions, answers, authority, additional })
    }

    /// The single question, when there is exactly one.
    pub fn question(&self) -> Option<&Question> {
        match self.questions.as_slice() {
            [q] => Some(q),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    #[test]
    fn names_parse_display_and_compare_case_insensitively() {
        assert_eq!(n("www.Example.COM").to_string(), "www.Example.COM");
        assert_eq!(n("www.example.com"), n("WWW.EXAMPLE.COM"));
        assert_eq!(n("."), Name::root());
        assert_eq!(n("example.com.").label_count(), 2);
        assert!(Name::parse("a..b").is_err());
        assert!(Name::parse(&"a".repeat(64)).is_err());
        assert!(n("host.example.com").ends_with(&n("EXAMPLE.com")));
        assert!(!n("example.com").ends_with(&n("host.example.com")));
        assert_eq!(n("host").join(&n("example.com")).unwrap(), n("host.example.com"));
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        n("A.b").hash(&mut h1);
        n("a.B").hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn reverse_names_round_trip() {
        let v4 = Name::reverse_v4(Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(v4.to_string(), "15.2.0.10.in-addr.arpa");
        assert_eq!(v4.reverse_address(), Some(Ipv4Addr::new(10, 0, 2, 15).into()));
        let a6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let v6 = Name::reverse_v6(a6);
        assert!(v6.to_string().starts_with("1.0.0.0.0.0.0.0."));
        assert_eq!(v6.reverse_address(), Some(a6.into()));
        assert_eq!(n("example.com").reverse_address(), None);
        assert_eq!(n("x.2.0.10.in-addr.arpa").reverse_address(), None);
    }

    #[test]
    fn a_query_round_trips() {
        let q = Message::query(0x1234, Question::new(n("example.com"), rtype::A));
        let bytes = q.encode().unwrap();
        assert_eq!(&bytes[..2], &[0x12, 0x34]);
        assert_eq!(bytes[2] & 0x01, 0x01); // RD
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back, q);
        assert_eq!(back.udp_size(), EDNS_UDP_SIZE);
    }

    #[test]
    fn a_response_with_every_typed_record_round_trips() {
        let mut m = Message::reply_to(&Message::query(7, Question::new(n("example.com"), rtype::ANY)));
        let recs = vec![
            Record::new(n("example.com"), 300, RData::A(Ipv4Addr::new(93, 184, 216, 34))),
            Record::new(n("example.com"), 300, RData::Aaaa("2606:2800::1".parse().unwrap())),
            Record::new(n("www.example.com"), 60, RData::Cname(n("example.com"))),
            Record::new(n("34.216.184.93.in-addr.arpa"), 60, RData::Ptr(n("example.com"))),
            Record::new(n("example.com"), 60, RData::Ns(n("a.iana-servers.net"))),
            Record::new(
                n("example.com"),
                60,
                RData::Soa {
                    mname: n("ns.icann.org"),
                    rname: n("noc.dns.icann.org"),
                    serial: 2024,
                    refresh: 7200,
                    retry: 3600,
                    expire: 1209600,
                    minimum: 3600,
                },
            ),
            Record::new(n("example.com"), 60, RData::Mx { preference: 10, exchange: n("mail.example.com") }),
            Record::new(
                n("_sip._tcp.example.com"),
                60,
                RData::Srv { priority: 1, weight: 2, port: 5060, target: n("sip.example.com") },
            ),
            Record::new(n("example.com"), 60, RData::Txt(vec![b"v=spf1 -all".to_vec(), b"x".to_vec()])),
            Record { name: n("example.com"), rtype: 99, class: 1, ttl: 1, rdata: RData::Unknown(vec![1, 2, 3]) },
        ];
        m.answers = recs.clone();
        m.additional.push(Record::opt(4096, true));
        let bytes = m.encode().unwrap();
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back.answers, recs);
        assert!(back.header.response && back.header.recursion_available);
        assert_eq!(back.udp_size(), 4096);
        assert_eq!(back.rcode(), 0);
        assert_eq!(back.answers[8].rdata_text(), "\"v=spf1 -all\" \"x\"");
        assert_eq!(back.answers[5].rdata_text(), "ns.icann.org noc.dns.icann.org 2024 7200 3600 1209600 3600");
    }

    #[test]
    fn compression_pointers_are_followed_and_loops_refused() {
        // Header + question "a.b" + answer with name pointer to offset 12.
        let mut bytes = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        bytes.extend_from_slice(&[1, b'a', 1, b'b', 0, 0, 1, 0, 1]);
        bytes.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 1, 2, 3, 4]);
        let m = Message::decode(&bytes).unwrap();
        assert_eq!(m.answers[0].name, n("a.b"));
        assert_eq!(m.answers[0].rdata, RData::A(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(m.answers[0].ttl, 5);

        // A pointer to itself.
        let mut bad = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        bad.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert_eq!(Message::decode(&bad), Err(Error::BadPointer));
        // A forward pointer.
        let mut fwd = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        fwd.extend_from_slice(&[0xC0, 20, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Message::decode(&fwd), Err(Error::BadPointer));
    }

    #[test]
    fn malformed_input_never_panics() {
        let q = Message::query(1, Question::new(n("example.com"), rtype::A));
        let good = q.encode().unwrap();
        for cut in 0..good.len() {
            let _ = Message::decode(&good[..cut]);
        }
        // Every single-byte mutation.
        for i in 0..good.len() {
            for v in [0u8, 0x3f, 0x40, 0x80, 0xc0, 0xff] {
                let mut m = good.clone();
                m[i] = v;
                let _ = Message::decode(&m);
            }
        }
        // A record whose rdlength runs past the end.
        let mut bytes = vec![0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        bytes.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(Message::decode(&bytes), Err(Error::Truncated));
        // A count claiming records that are not there.
        let bytes = vec![0, 1, 0x81, 0x80, 0xff, 0xff, 0, 0, 0, 0, 0, 0];
        assert_eq!(Message::decode(&bytes), Err(Error::Truncated));
    }

    #[test]
    fn udp_encoding_truncates_over_the_limit() {
        let mut m = Message::reply_to(&Message::query(1, Question::new(n("big.example"), rtype::A)));
        for i in 0..100u8 {
            m.answers.push(Record::new(n("big.example"), 1, RData::A(Ipv4Addr::new(10, 0, 0, i))));
        }
        let bytes = m.encode_udp(512).unwrap();
        assert!(bytes.len() <= 512);
        let back = Message::decode(&bytes).unwrap();
        assert!(back.header.truncated);
        assert!(back.answers.is_empty());
        assert_eq!(back.questions, m.questions);
    }

    #[test]
    fn case_randomisation_keeps_equality() {
        let mut i = 0;
        let r = n("www.example.com").randomise_case(|| {
            i += 1;
            i % 2 == 0
        });
        assert_eq!(r, n("www.example.com"));
        assert_ne!(r.to_string(), "www.example.com");
    }

    #[test]
    fn extended_rcode_is_read_from_opt() {
        let mut m = Message::reply_to(&Message::query(1, Question::new(n("x"), rtype::A)));
        m.header.rcode = 0;
        let mut opt = Record::opt(1232, false);
        opt.ttl = 1 << 24; // BADVERS
        m.additional.push(opt);
        assert_eq!(m.rcode(), 16);
        assert_eq!(rtype::parse("aaaa"), Some(rtype::AAAA));
        assert_eq!(rtype::parse("TYPE65"), Some(65));
        assert_eq!(rtype::name(65), "TYPE65");
    }
}

#[cfg(test)]
mod fuzz_tests;
