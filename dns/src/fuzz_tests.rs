//! Structure-aware random testing on the stable toolchain.
//!
//! The cargo-fuzz targets in `fuzz/` are the real campaign; these run the
//! same invariants under `cargo test` with a deterministic generator, so a
//! regression is caught without nightly. `DNS_FUZZ_ITERS` raises the count
//! (`DNS_FUZZ_ITERS=2000000 cargo test --release fuzz_ -- --nocapture`).

use super::*;

pub(crate) struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    pub fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    pub fn chance(&mut self, one_in: u64) -> bool {
        self.next() % one_in == 0
    }
}

fn iters() -> usize {
    std::env::var("DNS_FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(20_000)
}

fn random_name(rng: &mut Rng) -> Name {
    let n = rng.below(6);
    let mut labels = Vec::new();
    for _ in 0..n {
        let long = rng.chance(20);
        let len = 1 + rng.below(if long { 63 } else { 8 });
        labels.push((0..len).map(|_| rng.byte()).collect());
    }
    Name::from_labels(labels).unwrap_or_else(|_| Name::root())
}

fn random_record(rng: &mut Rng) -> Record {
    let name = random_name(rng);
    let ttl = rng.next() as u32;
    let rdata = match rng.below(11) {
        0 => RData::A(Ipv4Addr::from(rng.next() as u32)),
        1 => RData::Aaaa(Ipv6Addr::from(rng.next() as u128 | ((rng.next() as u128) << 64))),
        2 => RData::Cname(random_name(rng)),
        3 => RData::Ptr(random_name(rng)),
        4 => RData::Ns(random_name(rng)),
        5 => RData::Soa {
            mname: random_name(rng),
            rname: random_name(rng),
            serial: rng.next() as u32,
            refresh: rng.next() as u32,
            retry: rng.next() as u32,
            expire: rng.next() as u32,
            minimum: rng.next() as u32,
        },
        6 => RData::Mx { preference: rng.next() as u16, exchange: random_name(rng) },
        7 => RData::Srv { priority: rng.next() as u16, weight: rng.next() as u16, port: rng.next() as u16, target: random_name(rng) },
        8 => RData::Txt((0..rng.below(4)).map(|_| (0..rng.below(300)).map(|_| rng.byte()).collect()).collect()),
        9 => RData::Opt((0..rng.below(20)).map(|_| rng.byte()).collect()),
        _ => RData::Unknown((0..rng.below(40)).map(|_| rng.byte()).collect()),
    };
    let mut r = Record::new(name, ttl, rdata);
    if let RData::Unknown(_) = r.rdata {
        r.rtype = 200 + rng.below(50) as u16;
    }
    r
}

fn random_message(rng: &mut Rng) -> Message {
    let mut m = Message::default();
    m.header.id = rng.next() as u16;
    m.header.response = rng.chance(2);
    m.header.opcode = rng.below(16) as u8;
    m.header.rcode = rng.below(16) as u8;
    m.header.truncated = rng.chance(4);
    m.header.recursion_desired = rng.chance(2);
    for _ in 0..rng.below(3) {
        m.questions.push(Question { name: random_name(rng), rtype: rng.next() as u16, class: rng.next() as u16 });
    }
    for section in [&mut m.answers, &mut m.authority, &mut m.additional] {
        for _ in 0..rng.below(4) {
            section.push(random_record(rng));
        }
    }
    m
}

/// Whatever we encode, we decode to the same thing.
#[test]
fn fuzz_encode_decode_round_trip() {
    let mut rng = Rng::new(0x5eed);
    for i in 0..iters() {
        let m = random_message(&mut rng);
        let bytes = match m.encode() {
            Ok(b) => b,
            Err(Error::TooLarge) => continue,
            Err(e) => panic!("iteration {i}: encode failed: {e}"),
        };
        let back = Message::decode(&bytes).unwrap_or_else(|e| panic!("iteration {i}: decode of our own encoding failed: {e}\n{m:?}"));
        // TXT strings longer than 255 are truncated on encode; compare
        // everything else exactly.
        let normalise = |m: &Message| {
            let mut m = m.clone();
            for r in m.answers.iter_mut().chain(&mut m.authority).chain(&mut m.additional) {
                if let RData::Txt(s) = &mut r.rdata {
                    for x in s.iter_mut() {
                        x.truncate(255);
                    }
                }
            }
            m
        };
        assert_eq!(normalise(&back), normalise(&m), "iteration {i}");
        // Re-encoding the decoded form is byte-identical.
        assert_eq!(back.encode().unwrap(), bytes, "iteration {i}: not canonical");
    }
}

/// Mutations of valid messages, and pure noise, never panic — and whatever
/// decodes re-encodes and decodes again to the same value.
#[test]
fn fuzz_mutations_never_panic() {
    let mut rng = Rng::new(0xfeed);
    for i in 0..iters() {
        let mut bytes = if rng.chance(4) {
            (0..rng.below(300)).map(|_| rng.byte()).collect::<Vec<u8>>()
        } else {
            match random_message(&mut rng).encode() {
                Ok(b) => b,
                Err(_) => continue,
            }
        };
        for _ in 0..1 + rng.below(6) {
            if bytes.is_empty() {
                break;
            }
            match rng.below(5) {
                0 => {
                    let at = rng.below(bytes.len());
                    bytes[at] = rng.byte();
                }
                1 => {
                    let at = rng.below(bytes.len());
                    bytes[at] |= 0xC0; // manufacture a pointer
                }
                2 => {
                    let at = rng.below(bytes.len());
                    bytes.truncate(at);
                }
                3 => {
                    let at = rng.below(bytes.len());
                    bytes.insert(at, rng.byte());
                }
                _ => {
                    let at = rng.below(bytes.len());
                    let n = rng.below(4).min(bytes.len() - at);
                    bytes.drain(at..at + n);
                }
            }
        }
        if let Ok(m) = Message::decode(&bytes) {
            if let Ok(again) = m.encode() {
                let m2 = Message::decode(&again).unwrap_or_else(|e| panic!("iteration {i}: re-decode failed: {e}"));
                assert_eq!(m2, m, "iteration {i}: not idempotent");
            }
        }
    }
}

/// Names: parse/display round trip and the reverse-name inverse.
#[test]
fn fuzz_names() {
    let mut rng = Rng::new(0xabcd);
    for i in 0..iters() {
        let n = random_name(&mut rng);
        let text = n.to_string();
        if n.labels().iter().all(|l| l.iter().all(|b| b.is_ascii_graphic() && *b != b'.' && *b != b'\\')) {
            assert_eq!(Name::parse(&text).unwrap(), n, "iteration {i}: {text}");
        }
        let _ = n.reverse_address();
        let _ = n.to_lowercase();
        let v4 = Ipv4Addr::from(rng.next() as u32);
        assert_eq!(Name::reverse_v4(v4).reverse_address(), Some(v4.into()));
        let v6 = Ipv6Addr::from(rng.next() as u128 ^ ((rng.next() as u128) << 64));
        assert_eq!(Name::reverse_v6(v6).reverse_address(), Some(v6.into()));
        let s: String = (0..rng.below(300)).map(|_| if rng.chance(5) { '.' } else { (b'a' + rng.below(26) as u8) as char }).collect();
        let _ = Name::parse(&s);
    }
}
