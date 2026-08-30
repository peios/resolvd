//! The resolver engine as a whole system under a hostile, arbitrary world.
//!
//! The input is a script: questions, scope changes, replies (well-formed,
//! mutated, or noise) to whichever transactions are open, transport
//! failures, and time. Invariants:
//!
//! - nothing panics;
//! - the engine never has more upstream transactions open than its ceiling;
//! - every question asked is answered exactly once — after the script, time
//!   is run forward until every transaction has timed out, and by then each
//!   qid must have completed;
//! - every answer's records are class IN and its outcome is consistent with
//!   its records (NotFound/Unavailable carry none).
#![no_main]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use dns::{Message, Name, RData, Record, rcode, rtype};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use libnetd::Level;
use libresolv::Outcome;
use resolvd::engine::{Action, Completion, Engine, Family, MAX_IN_FLIGHT, SERVER_TIMEOUT, Scope};

#[derive(Arbitrary, Debug)]
enum Op {
    Resolve { name: u8, rtype: u8, no_cache: bool },
    Lookup { name: u8, family: u8 },
    Reverse { addr: u32 },
    /// Reply to the n-th open transaction with a plausible answer.
    Answer { which: u8, code: u8, records: u8, truncated: bool, soa: bool, ttl: u32 },
    /// Reply with the bytes as they are.
    Raw { which: u8, bytes: Vec<u8> },
    /// Reply with the right id but the wrong question.
    Wrong { which: u8 },
    Fail { which: u8 },
    Tick { ms: u16 },
    Scopes { variant: u8 },
    Fallback { on: bool },
    Hosts { on: bool },
    Flush,
}

#[derive(Arbitrary, Debug)]
struct Script {
    seed: u64,
    ops: Vec<Op>,
}

const NAMES: &[&str] = &[
    "example.com",
    "www.example.com",
    "printer",
    "localhost",
    "box",
    "git.corp.example",
    "thing.local",
    "1.2.0.10.in-addr.arpa",
    "a.b.c.d.e.f.g.h.example",
    "x",
    "",
    "..",
    "EXAMPLE.COM.",
    "loop.example.com",
];

const TYPES: &[u16] = &[rtype::A, rtype::AAAA, rtype::PTR, rtype::CNAME, rtype::TXT, rtype::ANY, 65, rtype::SOA];

fn name(i: u8) -> &'static str {
    NAMES[i as usize % NAMES.len()]
}

fn scope(id: &str, servers: &[&str], domains: &[&str], default_route: bool, exclusive: bool, metric: u32) -> Scope {
    Scope {
        id: id.into(),
        interface: id.into(),
        servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
        domains: domains.iter().map(|d| Name::parse(d).unwrap()).collect(),
        addresses: vec![("10.0.2.15".parse().unwrap(), 24)],
        default_route,
        exclusive,
        metric,
        level: Level::Routed,
    }
}

fn scopes(variant: u8) -> Vec<Scope> {
    match variant % 5 {
        0 => vec![],
        1 => vec![scope("lan", &["10.0.2.3"], &["lan"], true, false, 100)],
        2 => vec![scope("lan", &["10.0.2.3", "10.0.2.4"], &["lan"], true, false, 100), scope("vpn", &["10.8.0.1"], &["corp.example"], false, false, 50)],
        3 => vec![scope("lan", &["10.0.2.3"], &["lan"], true, false, 100), scope("vpn", &["10.8.0.1"], &["corp.example"], false, true, 50)],
        _ => vec![scope("lan", &["10.0.2.9"], &["a.example", "b.example", "c.example"], false, false, 100)],
    }
}

/// A message that matches the transaction: decode what was sent and reply
/// to it, so id and case pattern are right.
fn answer_for(sent: &[u8], code: u8, records: u8, truncated: bool, soa: bool, ttl: u32) -> Vec<u8> {
    let Ok(q) = Message::decode(sent) else { return Vec::new() };
    let mut m = Message::reply_to(&q);
    m.header.rcode = code % 6;
    m.header.truncated = truncated;
    let qn = q.questions[0].name.clone();
    for i in 0..records % 4 {
        let rec = match i % 3 {
            0 => Record::new(qn.clone(), ttl, RData::A(Ipv4Addr::new(10, 0, 0, i))),
            1 => Record::new(qn.clone(), ttl, RData::Cname(Name::parse("loop.example.com").unwrap())),
            _ => Record::new(Name::parse("loop.example.com").unwrap(), ttl, RData::Cname(qn.clone())),
        };
        m.answers.push(rec);
    }
    if soa {
        m.authority.push(Record::new(
            Name::parse("example.com").unwrap(),
            ttl,
            RData::Soa { mname: Name::parse("a").unwrap(), rname: Name::parse("b").unwrap(), serial: 1, refresh: 1, retry: 1, expire: 1, minimum: ttl },
        ));
    }
    m.encode().unwrap_or_default()
}

fuzz_target!(|script: Script| {
    let mut e = Engine::new(script.seed);
    e.set_scopes(scopes(1));
    e.set_hostname(Some("box"));
    let start = Instant::now();
    let mut now = start;
    let mut open: HashMap<u64, Vec<u8>> = HashMap::new(); // tx -> bytes sent
    let mut asked: HashSet<u64> = HashSet::new();
    let mut answered: HashMap<u64, u32> = HashMap::new();
    let mut qid = 0u64;

    let mut apply = |actions: Vec<Action>, open: &mut HashMap<u64, Vec<u8>>, answered: &mut HashMap<u64, u32>| {
        for a in actions {
            match a {
                Action::Send { tx, payload, .. } => {
                    assert!(open.insert(tx, payload).is_none(), "tx reused");
                }
                Action::Cancel { tx } => {
                    open.remove(&tx);
                }
                Action::Done { qid, completion } => {
                    *answered.entry(qid).or_default() += 1;
                    match completion {
                        Completion::Answer(a) => {
                            if a.outcome != Outcome::Found {
                                assert!(a.records.is_empty());
                            }
                            for r in &a.records {
                                assert_eq!(r.class, dns::class::IN);
                            }
                        }
                        Completion::Addresses(a) => {
                            if a.outcome != Outcome::Found {
                                assert!(a.addresses.is_empty());
                            }
                        }
                    }
                }
            }
        }
    };

    let pick = |which: u8, open: &HashMap<u64, Vec<u8>>| -> Option<u64> {
        if open.is_empty() {
            return None;
        }
        let mut keys: Vec<u64> = open.keys().copied().collect();
        keys.sort_unstable();
        Some(keys[which as usize % keys.len()])
    };

    for op in script.ops.into_iter().take(400) {
        let actions = match op {
            Op::Resolve { name: n, rtype, no_cache } => {
                qid += 1;
                asked.insert(qid);
                e.resolve(qid, name(n), TYPES[rtype as usize % TYPES.len()], no_cache, now)
            }
            Op::Lookup { name: n, family } => {
                qid += 1;
                asked.insert(qid);
                let f = match family % 3 {
                    0 => Family::Any,
                    1 => Family::V4,
                    _ => Family::V6,
                };
                e.lookup(qid, name(n), f, now)
            }
            Op::Reverse { addr } => {
                qid += 1;
                asked.insert(qid);
                e.reverse(qid, IpAddr::V4(Ipv4Addr::from(addr)), now)
            }
            Op::Answer { which, code, records, truncated, soa, ttl } => match pick(which, &open) {
                Some(tx) => {
                    let bytes = answer_for(&open[&tx], code, records, truncated, soa, ttl);
                    let acts = e.received(tx, &bytes, now);
                    if !acts.is_empty() {
                        open.remove(&tx);
                    }
                    acts
                }
                None => Vec::new(),
            },
            Op::Raw { which, bytes } => match pick(which, &open) {
                Some(tx) => {
                    let acts = e.received(tx, &bytes, now);
                    if !acts.is_empty() {
                        open.remove(&tx);
                    }
                    acts
                }
                None => Vec::new(),
            },
            Op::Wrong { which } => match pick(which, &open) {
                Some(tx) => {
                    let Ok(mut q) = Message::decode(&open[&tx]) else { continue };
                    q.questions[0].rtype ^= 1;
                    let m = Message::reply_to(&q).encode().unwrap();
                    let acts = e.received(tx, &m, now);
                    assert!(acts.is_empty(), "a reply to the wrong question was accepted");
                    acts
                }
                None => Vec::new(),
            },
            Op::Fail { which } => match pick(which, &open) {
                Some(tx) => {
                    open.remove(&tx);
                    e.failed(tx, now)
                }
                None => Vec::new(),
            },
            Op::Tick { ms } => {
                now += Duration::from_millis(u64::from(ms));
                e.tick(now)
            }
            Op::Scopes { variant } => {
                e.set_scopes(scopes(variant));
                Vec::new()
            }
            Op::Fallback { on } => {
                if on {
                    e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![Name::parse("fb.example").unwrap()]);
                } else {
                    e.set_fallback(vec![], vec![]);
                }
                Vec::new()
            }
            Op::Hosts { on } => {
                let mut h = HashMap::new();
                if on {
                    h.insert(Name::parse("printer").unwrap(), vec!["10.0.2.9".parse().unwrap()]);
                }
                e.set_hosts(h);
                Vec::new()
            }
            Op::Flush => {
                e.flush();
                Vec::new()
            }
        };
        apply(actions, &mut open, &mut answered);
        assert!(e.in_flight() <= MAX_IN_FLIGHT);
        assert!(open.len() <= MAX_IN_FLIGHT + 1);
    }

    // Drain: time alone must complete everything.
    for _ in 0..(3 * 4 + 2) {
        now += SERVER_TIMEOUT;
        let acts = e.tick(now);
        apply(acts, &mut open, &mut answered);
    }
    assert_eq!(e.in_flight(), 0, "transactions left after draining");
    for q in &asked {
        assert_eq!(answered.get(q).copied().unwrap_or(0), 1, "qid {q} answered {:?} times", answered.get(q));
    }
    assert_eq!(rcode::NOERROR, 0);
});
