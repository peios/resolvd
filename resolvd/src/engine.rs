//! The resolution engine: every door runs this and nothing else.
//!
//! A pure state machine, like `dhcp4::Client`. It owns the scopes, the
//! cache, the synthetic names and the in-flight table; it takes questions,
//! replies and ticks, and returns [`Action`]s — bytes to send to a server,
//! transactions to abandon, questions answered. It never touches a socket
//! or a clock, so it is tested without a network and could be run several
//! to a process if a single loop ever proved CPU-bound.
//!
//! # Routing
//!
//! Every interface contributes a *scope*: servers, search domains, its
//! addresses, whether it claims unmatched names, whether it is exclusive.
//! A name goes to exactly one scope — never "everyone" (the classic VPN
//! leak):
//!
//! 1. an exclusive scope, if any is up: it takes everything;
//! 2. the scope with the longest search domain the name ends with;
//! 3. a reverse name, to the scope whose subnet holds the address;
//! 4. the default-route claimant with the lowest metric;
//! 5. the fallback servers from the registry, only when no interface
//!    supplies any.
//!
//! A single-label name is expanded with the applicable search domains and
//! never sent bare; with no domain to apply it is `NotFound` without a
//! query. A multi-label name is never expanded.
//!
//! # What the outcomes mean
//!
//! `Found` is an answer, including "the name exists but has no records of
//! that type". `NotFound` is authoritative absence and is cached briefly.
//! `Unavailable` is "nothing that could answer did" — never cached, and
//! never rendered as absence by any door.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use dns::{Message, Name, Question, RData, Record, rcode, rtype};
use libnetd::Level;
use libresolv::Outcome;

use crate::cache::{Cache, CacheKey, Entry};

pub type Qid = u64;
pub type Txid = u64;
type TaskId = u64;

/// Per-server timeout, then the next server. ~2s: long enough for a
/// recursive resolver's own recursion, short enough that a dead first
/// server costs a few seconds rather than a minute.
pub const SERVER_TIMEOUT: Duration = Duration::from_secs(2);
/// Attempts per question across the scope's servers.
pub const MAX_ATTEMPTS: u32 = 3;
/// How long a failing server is tried last.
pub const DEMOTION: Duration = Duration::from_secs(30);
/// Positive answers live at most this long, whatever the TTL says.
pub const MAX_POSITIVE_TTL: u32 = 86_400;
/// Negative answers (RFC 2308) at most this long.
pub const MAX_NEGATIVE_TTL: u32 = 300;
/// A ceiling on outstanding upstream transactions (each is a socket);
/// beyond it a question that needs the network is refused rather than
/// queued without bound. Synthetic and cached answers are never refused.
pub const MAX_IN_FLIGHT: usize = 4096;

/// What an interface contributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub id: String,
    pub interface: String,
    pub servers: Vec<IpAddr>,
    pub domains: Vec<Name>,
    pub addresses: Vec<(IpAddr, u8)>,
    pub default_route: bool,
    pub exclusive: bool,
    pub metric: u32,
    pub level: Level,
}

impl Scope {
    fn contains(&self, addr: IpAddr) -> bool {
        self.addresses.iter().any(|(a, prefix)| same_subnet(*a, *prefix, addr))
    }
}

fn same_subnet(a: IpAddr, prefix: u8, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32)) };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix.min(128)) };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

pub const FALLBACK_SCOPE: &str = "fallback";

/// An answer, in the engine's terms.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Answer {
    pub outcome: Outcome,
    pub records: Vec<Record>,
    pub source: Source,
    pub server: Option<IpAddr>,
    pub interface: Option<String>,
    pub rcode: u16,
    /// The name the records are at, after search expansion.
    pub resolved_name: Option<Name>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Source {
    #[default]
    Local,
    Synthetic,
    Hosts,
    Cache,
    Dns,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Local => "local",
            Source::Synthetic => "synthetic",
            Source::Hosts => "hosts",
            Source::Cache => "cache",
            Source::Dns => "dns",
        }
    }
}

/// The addresses of a name: what `lookup` returns.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Addresses {
    pub outcome: Outcome,
    pub canonical: Name,
    pub addresses: Vec<(IpAddr, u32)>,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    Answer(Answer),
    Addresses(Addresses),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send { tx: Txid, server: IpAddr, tcp: bool, payload: Vec<u8> },
    Cancel { tx: Txid },
    Done { qid: Qid, completion: Completion },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Any,
    V4,
    V6,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counters {
    pub queries: u64,
    pub synthetic: u64,
    pub cache_hits: u64,
    pub upstream_sent: u64,
    pub upstream_answered: u64,
    pub upstream_failed: u64,
    pub refused: u64,
}

#[derive(Debug)]
enum Owner {
    Resolve(Qid),
    Lookup(Qid),
}

#[derive(Debug)]
struct Task {
    owner: Owner,
    original: Name,
    rtype: u16,
    no_cache: bool,
    candidates: VecDeque<Name>,
    /// The candidate in flight.
    current: Option<Name>,
    scope: Option<String>,
    attempt: u32,
    /// Servers already asked for this candidate, so a retry goes elsewhere.
    tried: Vec<IpAddr>,
    tx: Option<Txid>,
}

#[derive(Debug)]
struct Tx {
    task: TaskId,
    dns_id: u16,
    /// The question exactly as sent (0x20-randomised), for matching.
    question: Question,
    server: IpAddr,
    tcp: bool,
    deadline: Instant,
}

#[derive(Debug)]
struct Lookup {
    name: Name,
    pending: Vec<TaskId>,
    results: Vec<(u16, Answer)>,
}

pub struct Engine {
    scopes: Vec<Scope>,
    fallback_servers: Vec<IpAddr>,
    fallback_domains: Vec<Name>,
    hostname: Option<Name>,
    hosts: HashMap<Name, Vec<IpAddr>>,
    cache: Cache,
    demoted: HashMap<IpAddr, Instant>,
    tasks: HashMap<TaskId, Task>,
    txs: HashMap<Txid, Tx>,
    lookups: HashMap<Qid, Lookup>,
    next_id: u64,
    rng: u64,
    pub counters: Counters,
}

impl Engine {
    pub fn new(seed: u64) -> Engine {
        Engine {
            scopes: Vec::new(),
            fallback_servers: Vec::new(),
            fallback_domains: Vec::new(),
            hostname: None,
            hosts: HashMap::new(),
            cache: Cache::new(),
            demoted: HashMap::new(),
            tasks: HashMap::new(),
            txs: HashMap::new(),
            lookups: HashMap::new(),
            next_id: 1,
            rng: seed | 1,
            counters: Counters::default(),
        }
    }

    // ------------------------------------------------------- configuration

    /// Replace the scopes. A scope whose servers changed loses its cache:
    /// a VPN's answers die with the VPN.
    pub fn set_scopes(&mut self, scopes: Vec<Scope>) {
        for new in &scopes {
            let old = self.scopes.iter().find(|s| s.id == new.id);
            if old.is_none_or(|o| o.servers != new.servers) {
                self.cache.flush_scope(&new.id);
            }
        }
        for old in &self.scopes {
            if !scopes.iter().any(|s| s.id == old.id) {
                self.cache.flush_scope(&old.id);
            }
        }
        self.scopes = scopes;
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    pub fn set_fallback(&mut self, servers: Vec<IpAddr>, domains: Vec<Name>) {
        if servers != self.fallback_servers {
            self.cache.flush_scope(FALLBACK_SCOPE);
        }
        self.fallback_servers = servers;
        self.fallback_domains = domains;
    }

    pub fn fallback_servers(&self) -> &[IpAddr] {
        &self.fallback_servers
    }

    pub fn set_hostname(&mut self, hostname: Option<&str>) {
        self.hostname = hostname.and_then(|h| Name::parse(h).ok()).filter(|n| !n.is_root());
    }

    pub fn hostname(&self) -> Option<&Name> {
        self.hostname.as_ref()
    }

    pub fn set_hosts(&mut self, hosts: HashMap<Name, Vec<IpAddr>>) {
        self.hosts = hosts;
    }

    pub fn flush(&mut self) {
        self.cache.clear();
    }

    pub fn cache_entries(&self) -> usize {
        self.cache.len()
    }

    pub fn demoted(&self, now: Instant) -> Vec<IpAddr> {
        self.demoted.iter().filter(|(_, until)| **until > now).map(|(s, _)| *s).collect()
    }

    /// The next moment `tick` has something to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.txs.values().map(|t| t.deadline).min()
    }

    #[cfg(test)]
    pub fn in_flight(&self) -> usize {
        self.txs.len()
    }

    // ------------------------------------------------------------ questions

    pub fn resolve(&mut self, qid: Qid, name: &str, rtype: u16, no_cache: bool, now: Instant) -> Vec<Action> {
        self.counters.queries += 1;
        let Some(name) = Name::parse(name).ok() else {
            return vec![Action::Done { qid, completion: Completion::Answer(Answer { outcome: Outcome::NotFound, ..Default::default() }) }];
        };
        let id = self.start_task(Owner::Resolve(qid), name, rtype, no_cache);
        self.advance(id, now)
    }

    pub fn resolve_question(&mut self, qid: Qid, question: &Question, now: Instant) -> Vec<Action> {
        self.resolve(qid, &question.name.to_string(), question.rtype, false, now)
    }

    pub fn lookup(&mut self, qid: Qid, name: &str, family: Family, now: Instant) -> Vec<Action> {
        self.counters.queries += 1;
        let Some(name) = Name::parse(name).ok() else {
            return vec![Action::Done { qid, completion: Completion::Addresses(Addresses { outcome: Outcome::NotFound, ..Default::default() }) }];
        };
        let types: &[u16] = match family {
            Family::Any => &[rtype::A, rtype::AAAA],
            Family::V4 => &[rtype::A],
            Family::V6 => &[rtype::AAAA],
        };
        let mut pending = Vec::new();
        for &t in types {
            pending.push(self.start_task(Owner::Lookup(qid), name.clone(), t, false));
        }
        self.lookups.insert(qid, Lookup { name, pending: pending.clone(), results: Vec::new() });
        let mut actions = Vec::new();
        for id in pending {
            actions.extend(self.advance(id, now));
        }
        actions
    }

    pub fn reverse(&mut self, qid: Qid, address: IpAddr, now: Instant) -> Vec<Action> {
        let name = match address {
            IpAddr::V4(a) => Name::reverse_v4(a),
            IpAddr::V6(a) => Name::reverse_v6(a),
        };
        self.resolve(qid, &name.to_string(), rtype::PTR, false, now)
    }

    /// Forget a question whose asker went away.
    #[cfg(test)]
    pub fn abandon(&mut self, qid: Qid) -> Vec<Action> {
        let mut actions = Vec::new();
        let ids: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|(_, t)| matches!(t.owner, Owner::Resolve(q) | Owner::Lookup(q) if q == qid))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some(task) = self.tasks.remove(&id) {
                if let Some(tx) = task.tx {
                    self.txs.remove(&tx);
                    actions.push(Action::Cancel { tx });
                }
            }
        }
        self.lookups.remove(&qid);
        actions
    }

    // --------------------------------------------------------------- inputs

    /// A datagram or TCP message arrived for `tx`.
    pub fn received(&mut self, tx: Txid, bytes: &[u8], now: Instant) -> Vec<Action> {
        let Some(t) = self.txs.get(&tx) else { return Vec::new() };
        let message = match Message::decode(bytes) {
            Ok(m) => m,
            Err(_) => return Vec::new(), // not ours, or garbage; the timer handles it
        };
        // Everything must match: id, the question as sent (0x20-exact), and
        // it must be a response. A forged reply has to guess the port, the
        // id and the case pattern.
        if message.header.id != t.dns_id || !message.header.response {
            return Vec::new();
        }
        let Some(q) = message.question() else { return Vec::new() };
        if q.rtype != t.question.rtype || q.class != t.question.class || !same_case(&q.name, &t.question.name) {
            return Vec::new();
        }
        let task_id = t.task;
        let server = t.server;
        let tcp = t.tcp;
        self.txs.remove(&tx);
        let Some(task) = self.tasks.get_mut(&task_id) else { return Vec::new() };
        task.tx = None;
        self.counters.upstream_answered += 1;

        if message.header.truncated && !tcp {
            // Ask again over TCP, same server, not counted as an attempt.
            return self.send(task_id, server, true, now);
        }
        let code = message.rcode();
        match code as u8 {
            rcode::NOERROR | rcode::NXDOMAIN if code < 16 => {
                self.demoted.remove(&server);
                let candidate = task.current.clone().unwrap_or_else(|| task.original.clone());
                let scope = task.scope.clone().unwrap_or_default();
                let outcome = if code as u8 == rcode::NXDOMAIN { Outcome::NotFound } else { Outcome::Found };
                // Records come back in the case we sent (0x20); give them
                // the case the caller used.
                let records: Vec<Record> = message
                    .answers
                    .into_iter()
                    .filter(|r| r.class == dns::class::IN)
                    .map(|mut r| {
                        if r.name == candidate {
                            r.name = candidate.clone();
                        }
                        r
                    })
                    .collect();
                let ttl = if outcome == Outcome::Found && !records.is_empty() {
                    records.iter().map(|r| r.ttl).min().unwrap_or(0).min(MAX_POSITIVE_TTL)
                } else {
                    negative_ttl(&message.authority)
                };
                let entry = Entry { outcome, records: records.clone(), rcode: code, server, expires: now + Duration::from_secs(u64::from(ttl)) };
                let rtype = task.rtype;
                let more = !task.candidates.is_empty();
                if ttl > 0 {
                    self.cache.insert(CacheKey::new(&candidate, rtype, &scope), entry);
                }
                if outcome == Outcome::NotFound && more {
                    return self.next_candidate(task_id, now);
                }
                let answer = Answer {
                    outcome,
                    records,
                    source: Source::Dns,
                    server: Some(server),
                    interface: self.interface_of(&scope),
                    rcode: code,
                    resolved_name: Some(candidate),
                };
                self.settle(task_id, answer, now)
            }
            _ => {
                // SERVFAIL, REFUSED, FORMERR, an extended code: this server
                // cannot answer this; try the next.
                self.counters.upstream_failed += 1;
                self.demote(server, now);
                self.next_attempt(task_id, now)
            }
        }
    }

    /// The transport failed for `tx` (ICMP unreachable, connection refused).
    pub fn failed(&mut self, tx: Txid, now: Instant) -> Vec<Action> {
        let Some(t) = self.txs.remove(&tx) else { return Vec::new() };
        self.counters.upstream_failed += 1;
        self.demote(t.server, now);
        if let Some(task) = self.tasks.get_mut(&t.task) {
            task.tx = None;
        }
        self.next_attempt(t.task, now)
    }

    /// Time passed. Expired transactions move to the next attempt.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let expired: Vec<Txid> = self.txs.iter().filter(|(_, t)| t.deadline <= now).map(|(id, _)| *id).collect();
        let mut actions = Vec::new();
        for tx in expired {
            actions.push(Action::Cancel { tx });
            actions.extend(self.failed(tx, now));
        }
        actions
    }

    // ---------------------------------------------------------- internals

    fn fresh_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn random(&mut self) -> u64 {
        // xorshift64*: not cryptographic, but the id and case pattern are
        // one of three things a forger must guess (the port is the third).
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn interface_of(&self, scope: &str) -> Option<String> {
        self.scopes.iter().find(|s| s.id == scope).map(|s| s.interface.clone())
    }

    fn demote(&mut self, server: IpAddr, now: Instant) {
        self.demoted.insert(server, now + DEMOTION);
    }

    fn is_demoted(&self, server: IpAddr, now: Instant) -> bool {
        self.demoted.get(&server).is_some_and(|until| *until > now)
    }

    fn start_task(&mut self, owner: Owner, name: Name, rtype: u16, no_cache: bool) -> TaskId {
        let id = self.fresh_id();
        self.tasks.insert(
            id,
            Task { owner, original: name, rtype, no_cache, candidates: VecDeque::new(), current: None, scope: None, attempt: 0, tried: Vec::new(), tx: None },
        );
        id
    }

    /// Decide what a fresh task does: answer locally, or build its
    /// candidate list.
    fn advance(&mut self, id: TaskId, now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.get(&id) else { return Vec::new() };
        let name = task.original.clone();
        let rtype = task.rtype;
        if task.current.is_none() && task.candidates.is_empty() && task.attempt == 0 {
            // First visit: synthetic answers come before any network.
            if let Some(answer) = self.synthetic(&name, rtype) {
                self.counters.synthetic += 1;
                return self.settle(id, answer, now);
            }
            let candidates = self.candidates(&name);
            if candidates.is_empty() {
                // A single label with no domain to apply: nothing to ask.
                return self.settle(id, Answer { outcome: Outcome::NotFound, ..Default::default() }, now);
            }
            if let Some(task) = self.tasks.get_mut(&id) {
                task.candidates = candidates;
            }
        }
        self.next_candidate(id, now)
    }

    fn next_candidate(&mut self, id: TaskId, now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.get_mut(&id) else { return Vec::new() };
        let Some(candidate) = task.candidates.pop_front() else {
            // Every candidate was NotFound.
            return self.settle(id, Answer { outcome: Outcome::NotFound, ..Default::default() }, now);
        };
        task.current = Some(candidate.clone());
        task.attempt = 0;
        task.tried.clear();
        let rtype = task.rtype;
        let no_cache = task.no_cache;
        let more = !task.candidates.is_empty();
        let Some(scope) = self.route(&candidate, now) else {
            return self.settle(id, Answer { outcome: Outcome::Unavailable, ..Default::default() }, now);
        };
        if let Some(task) = self.tasks.get_mut(&id) {
            task.scope = Some(scope.clone());
        }
        if !no_cache {
            if let Some(entry) = self.cache.get(&CacheKey::new(&candidate, rtype, &scope), now) {
                self.counters.cache_hits += 1;
                if entry.outcome == Outcome::NotFound && more {
                    return self.next_candidate(id, now);
                }
                let answer = Answer {
                    outcome: entry.outcome,
                    records: entry.records,
                    source: Source::Cache,
                    server: Some(entry.server),
                    interface: self.interface_of(&scope),
                    rcode: entry.rcode,
                    resolved_name: Some(candidate),
                };
                return self.settle(id, answer, now);
            }
        }
        self.next_attempt(id, now)
    }

    /// Send the current candidate to the next server, or give up.
    fn next_attempt(&mut self, id: TaskId, now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.get(&id) else { return Vec::new() };
        let attempt = task.attempt;
        let scope_id = task.scope.clone().unwrap_or_default();
        if attempt >= MAX_ATTEMPTS {
            return self.settle(id, Answer { outcome: Outcome::Unavailable, interface: self.interface_of(&scope_id), ..Default::default() }, now);
        }
        let servers = self.servers_of(&scope_id, now);
        if servers.is_empty() {
            return self.settle(id, Answer { outcome: Outcome::Unavailable, ..Default::default() }, now);
        }
        if attempt == 0 && self.txs.len() >= MAX_IN_FLIGHT {
            self.counters.refused += 1;
            return self.settle(id, Answer { outcome: Outcome::Unavailable, ..Default::default() }, now);
        }
        // A server not yet asked, healthiest first; else round-robin.
        let server = servers
            .iter()
            .copied()
            .find(|s| !task.tried.contains(s))
            .unwrap_or(servers[attempt as usize % servers.len()]);
        if let Some(task) = self.tasks.get_mut(&id) {
            task.attempt += 1;
            task.tried.push(server);
        }
        self.send(id, server, false, now)
    }

    fn send(&mut self, id: TaskId, server: IpAddr, tcp: bool, now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.get(&id) else { return Vec::new() };
        let candidate = task.current.clone().unwrap_or_else(|| task.original.clone());
        let rtype = task.rtype;
        let dns_id = self.random() as u16;
        let mut bits = self.random();
        let mut n = 0;
        let name = candidate.randomise_case(|| {
            if n == 64 {
                bits = self.random();
                n = 0;
            }
            let b = bits & 1 == 1;
            bits >>= 1;
            n += 1;
            b
        });
        let question = Question::new(name, rtype);
        let message = Message::query(dns_id, question.clone());
        let payload = message.encode().expect("a query encodes");
        let tx = self.fresh_id();
        self.txs.insert(tx, Tx { task: id, dns_id, question, server, tcp, deadline: now + SERVER_TIMEOUT });
        if let Some(task) = self.tasks.get_mut(&id) {
            task.tx = Some(tx);
        }
        self.counters.upstream_sent += 1;
        vec![Action::Send { tx, server, tcp, payload }]
    }

    /// The task is over: hand the answer to its owner.
    fn settle(&mut self, id: TaskId, answer: Answer, _now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.remove(&id) else { return Vec::new() };
        if let Some(tx) = task.tx {
            self.txs.remove(&tx);
        }
        match task.owner {
            Owner::Resolve(qid) => vec![Action::Done { qid, completion: Completion::Answer(answer) }],
            Owner::Lookup(qid) => {
                let Some(lookup) = self.lookups.get_mut(&qid) else { return Vec::new() };
                lookup.pending.retain(|t| *t != id);
                lookup.results.push((task.rtype, answer));
                if !lookup.pending.is_empty() {
                    return Vec::new();
                }
                let lookup = self.lookups.remove(&qid).expect("present");
                vec![Action::Done { qid, completion: Completion::Addresses(combine(lookup)) }]
            }
        }
    }

    // ----------------------------------------------------------- routing

    fn up_scopes(&self) -> impl Iterator<Item = &Scope> {
        self.scopes.iter().filter(|s| s.level >= Level::Link && !s.servers.is_empty())
    }

    fn exclusive(&self) -> Option<&Scope> {
        self.up_scopes().filter(|s| s.exclusive && s.level >= Level::Addressed).min_by_key(|s| s.metric)
    }

    /// The scope a name goes to, or `None` when nothing could answer.
    fn route(&self, name: &Name, _now: Instant) -> Option<String> {
        if let Some(x) = self.exclusive() {
            return Some(x.id.clone());
        }
        // Longest matching search domain wins; ties by metric.
        let mut best: Option<(usize, u32, &Scope)> = None;
        for s in self.up_scopes() {
            for d in &s.domains {
                if name.ends_with(d) {
                    let key = (d.label_count(), s.metric);
                    if best.is_none_or(|(l, m, _)| key.0 > l || (key.0 == l && key.1 < m)) {
                        best = Some((key.0, key.1, s));
                    }
                }
            }
        }
        if let Some((_, _, s)) = best {
            return Some(s.id.clone());
        }
        if let Some(addr) = name.reverse_address() {
            if let Some(s) = self.up_scopes().filter(|s| s.contains(addr)).min_by_key(|s| s.metric) {
                return Some(s.id.clone());
            }
        }
        if let Some(s) = self.up_scopes().filter(|s| s.default_route).min_by_key(|s| s.metric) {
            return Some(s.id.clone());
        }
        if let Some(s) = self.up_scopes().min_by_key(|s| s.metric) {
            return Some(s.id.clone());
        }
        if !self.fallback_servers.is_empty() {
            return Some(FALLBACK_SCOPE.to_owned());
        }
        None
    }

    /// The servers to try, healthy ones first.
    fn servers_of(&self, scope: &str, now: Instant) -> Vec<IpAddr> {
        let servers: Vec<IpAddr> = if scope == FALLBACK_SCOPE {
            self.fallback_servers.clone()
        } else {
            self.scopes.iter().find(|s| s.id == scope).map(|s| s.servers.clone()).unwrap_or_default()
        };
        let (healthy, demoted): (Vec<IpAddr>, Vec<IpAddr>) = servers.into_iter().partition(|s| !self.is_demoted(*s, now));
        healthy.into_iter().chain(demoted).collect()
    }

    /// The names to try, in order.
    fn candidates(&self, name: &Name) -> VecDeque<Name> {
        if name.label_count() != 1 {
            return VecDeque::from([name.clone()]);
        }
        let mut out = VecDeque::new();
        let domains: Vec<&Name> = match self.exclusive() {
            Some(x) => x.domains.iter().collect(),
            None => {
                let mut scopes: Vec<&Scope> = self.up_scopes().collect();
                scopes.sort_by_key(|s| s.metric);
                scopes.iter().flat_map(|s| s.domains.iter()).chain(self.fallback_domains.iter()).collect()
            }
        };
        for d in domains {
            if let Ok(full) = name.join(d) {
                if !out.contains(&full) {
                    out.push_back(full);
                }
            }
        }
        out
    }

    // --------------------------------------------------------- synthetic

    fn own_addresses(&self) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self
            .scopes
            .iter()
            .filter(|s| s.level >= Level::Addressed)
            .flat_map(|s| s.addresses.iter().map(|(a, _)| *a))
            .filter(|a| !a.is_loopback())
            .collect();
        out.dedup();
        out
    }

    /// Answered before any network: loopback, our own name, static hosts,
    /// reverse of both, and `.local` (never forwarded).
    fn synthetic(&self, name: &Name, rtype: u16) -> Option<Answer> {
        let localhost = Name::parse("localhost").expect("fits");
        let local = Name::parse("local").expect("fits");
        let found = |records: Vec<Record>, source: Source| {
            Some(Answer { outcome: Outcome::Found, records, source, resolved_name: Some(name.clone()), ..Default::default() })
        };
        let addresses = |addrs: &[IpAddr], source: Source| {
            let records = addrs
                .iter()
                .filter_map(|a| match (a, rtype) {
                    (IpAddr::V4(v4), rtype::A | rtype::ANY) => Some(Record::new(name.clone(), 0, RData::A(*v4))),
                    (IpAddr::V6(v6), rtype::AAAA | rtype::ANY) => Some(Record::new(name.clone(), 0, RData::Aaaa(*v6))),
                    _ => None,
                })
                .collect();
            found(records, source)
        };
        if name == &localhost || name.ends_with(&localhost) {
            return addresses(&[Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()], Source::Synthetic);
        }
        if let Some(hosts) = self.hosts.get(name) {
            return addresses(hosts, Source::Hosts);
        }
        if self.hostname.as_ref() == Some(name) {
            let mut own = self.own_addresses();
            if own.is_empty() {
                own = vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
            }
            return addresses(&own, Source::Synthetic);
        }
        if name.ends_with(&local) {
            return Some(Answer { outcome: Outcome::NotFound, source: Source::Synthetic, ..Default::default() });
        }
        if let Some(addr) = name.reverse_address() {
            if rtype != rtype::PTR && rtype != rtype::ANY {
                return None;
            }
            let ptr = |target: Name, source: Source| found(vec![Record::new(name.clone(), 0, RData::Ptr(target))], source);
            if addr.is_loopback() {
                return ptr(localhost, Source::Synthetic);
            }
            if let Some((host, _)) = self.hosts.iter().find(|(_, a)| a.contains(&addr)) {
                return ptr(host.clone(), Source::Hosts);
            }
            if let Some(h) = &self.hostname {
                if self.own_addresses().contains(&addr) {
                    return ptr(h.clone(), Source::Synthetic);
                }
            }
        }
        None
    }
}

/// Byte-exact name equality: the reply must echo our case pattern.
fn same_case(a: &Name, b: &Name) -> bool {
    a.labels() == b.labels()
}

/// RFC 2308: the negative TTL is the SOA's minimum field, bounded by its own
/// TTL and our cap.
fn negative_ttl(authority: &[Record]) -> u32 {
    authority
        .iter()
        .find_map(|r| match &r.rdata {
            RData::Soa { minimum, .. } => Some((*minimum).min(r.ttl)),
            _ => None,
        })
        .unwrap_or(0)
        .min(MAX_NEGATIVE_TTL)
}

/// Fold a lookup's per-type answers into addresses plus a canonical name.
fn combine(lookup: Lookup) -> Addresses {
    let mut out = Addresses { canonical: lookup.name.clone(), ..Default::default() };
    let mut any_found = false;
    let mut any_unavailable = false;
    let mut source = Source::Local;
    for (rtype, answer) in &lookup.results {
        match answer.outcome {
            Outcome::Found => {
                any_found = true;
                source = answer.source;
                let start = answer.resolved_name.clone().unwrap_or_else(|| lookup.name.clone());
                let (canonical, addrs) = chase(&answer.records, &start, *rtype);
                if !addrs.is_empty() {
                    out.canonical = canonical;
                }
                out.addresses.extend(addrs);
            }
            Outcome::Unavailable => any_unavailable = true,
            Outcome::NotFound => {}
        }
    }
    out.outcome = if any_found {
        Outcome::Found
    } else if any_unavailable {
        Outcome::Unavailable
    } else {
        Outcome::NotFound
    };
    out.source = source;
    out
}

/// Follow CNAMEs from `start` and collect the addresses at the end.
fn chase(records: &[Record], start: &Name, rtype: u16) -> (Name, Vec<(IpAddr, u32)>) {
    let mut name = start.clone();
    for _ in 0..16 {
        let next = records.iter().find(|r| &r.name == &name).and_then(|r| match &r.rdata {
            RData::Cname(t) => Some(t.clone()),
            _ => None,
        });
        match next {
            Some(t) if !records.iter().any(|r| &r.name == &name && r.rtype == rtype) => name = t,
            _ => break,
        }
    }
    let addrs = records
        .iter()
        .filter(|r| &r.name == &name)
        .filter_map(|r| match &r.rdata {
            RData::A(a) if rtype == rtype::A => Some((IpAddr::V4(*a), r.ttl)),
            RData::Aaaa(a) if rtype == rtype::AAAA => Some((IpAddr::V6(*a), r.ttl)),
            _ => None,
        })
        .collect();
    (name, addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    fn scope(id: &str, servers: &[&str], domains: &[&str], default_route: bool) -> Scope {
        Scope {
            id: id.into(),
            interface: id.into(),
            servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
            domains: domains.iter().map(|d| n(d)).collect(),
            addresses: vec![("10.0.2.15".parse().unwrap(), 24)],
            default_route,
            exclusive: false,
            metric: 100,
            level: Level::Routed,
        }
    }

    fn engine() -> Engine {
        let mut e = Engine::new(42);
        e.set_scopes(vec![scope("lan", &["10.0.2.3"], &["lan"], true)]);
        e.set_hostname(Some("box"));
        e
    }

    fn sent(actions: &[Action]) -> (Txid, IpAddr, Message) {
        for a in actions {
            if let Action::Send { tx, server, payload, .. } = a {
                return (*tx, *server, Message::decode(payload).unwrap());
            }
        }
        panic!("nothing sent: {actions:?}");
    }

    fn done(actions: &[Action]) -> Answer {
        for a in actions {
            if let Action::Done { completion: Completion::Answer(ans), .. } = a {
                return ans.clone();
            }
        }
        panic!("not done: {actions:?}");
    }

    fn reply(query: &Message, records: Vec<Record>, code: u8) -> Vec<u8> {
        let mut m = Message::reply_to(query);
        m.header.rcode = code;
        m.answers = records;
        m.encode().unwrap()
    }

    #[test]
    fn localhost_hostname_and_hosts_are_synthetic() {
        let mut e = engine();
        let now = Instant::now();
        let a = done(&e.resolve(1, "localhost", rtype::A, false, now));
        assert_eq!(a.source, Source::Synthetic);
        assert_eq!(a.records[0].rdata, RData::A(Ipv4Addr::LOCALHOST));
        let a = done(&e.resolve(2, "foo.localhost", rtype::AAAA, false, now));
        assert_eq!(a.records[0].rdata, RData::Aaaa(Ipv6Addr::LOCALHOST));
        let a = done(&e.resolve(3, "BOX", rtype::A, false, now));
        assert_eq!(a.records[0].rdata, RData::A("10.0.2.15".parse().unwrap()));
        e.set_hosts(HashMap::from([(n("printer"), vec!["10.0.2.9".parse().unwrap()])]));
        let a = done(&e.resolve(4, "printer", rtype::A, false, now));
        assert_eq!(a.source, Source::Hosts);
        let a = done(&e.resolve(5, "9.2.0.10.in-addr.arpa", rtype::PTR, false, now));
        assert_eq!(a.records[0].rdata, RData::Ptr(n("printer")));
        let a = done(&e.resolve(6, "1.0.0.127.in-addr.arpa", rtype::PTR, false, now));
        assert_eq!(a.records[0].rdata, RData::Ptr(n("localhost")));
        let a = done(&e.resolve(7, "thing.local", rtype::A, false, now));
        assert_eq!(a.outcome, Outcome::NotFound);
        assert_eq!(e.counters.upstream_sent, 0);
    }

    #[test]
    fn an_upstream_answer_is_returned_and_cached_per_scope() {
        let mut e = engine();
        let now = Instant::now();
        let actions = e.resolve(1, "www.example.com", rtype::A, false, now);
        let (tx, server, q) = sent(&actions);
        assert_eq!(server, "10.0.2.3".parse::<IpAddr>().unwrap());
        assert_eq!(q.questions[0].name, n("www.example.com"));
        assert!(q.header.recursion_desired);
        let rec = Record::new(n("www.example.com"), 60, RData::A("1.2.3.4".parse().unwrap()));
        let a = done(&e.received(tx, &reply(&q, vec![rec.clone()], rcode::NOERROR), now));
        assert_eq!(a.outcome, Outcome::Found);
        assert_eq!(a.source, Source::Dns);
        assert_eq!(a.records, vec![rec]);
        assert_eq!(a.interface.as_deref(), Some("lan"));
        // Second time: cache, no send.
        let actions = e.resolve(2, "WWW.EXAMPLE.COM", rtype::A, false, now + Duration::from_secs(10));
        let a = done(&actions);
        assert_eq!(a.source, Source::Cache);
        assert_eq!(e.counters.cache_hits, 1);
        // Servers change: the scope's cache dies.
        e.set_scopes(vec![scope("lan", &["10.0.2.4"], &["lan"], true)]);
        let actions = e.resolve(3, "www.example.com", rtype::A, false, now);
        sent(&actions);
    }

    #[test]
    fn a_forged_reply_is_ignored() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "www.example.com", rtype::A, false, now));
        let mut wrong_id = q.clone();
        wrong_id.header.id ^= 1;
        assert!(e.received(tx, &reply(&wrong_id, vec![], 0), now).is_empty());
        let mut wrong_case = q.clone();
        wrong_case.questions[0].name = n("www.example.com");
        if same_case(&wrong_case.questions[0].name, &q.questions[0].name) {
            wrong_case.questions[0].name = n("WWW.EXAMPLE.COM");
        }
        assert!(e.received(tx, &reply(&wrong_case, vec![], 0), now).is_empty());
        assert!(e.received(tx, b"garbage", now).is_empty());
        assert_eq!(e.in_flight(), 1);
    }

    #[test]
    fn timeouts_walk_servers_then_give_up_unavailable() {
        let mut e = Engine::new(1);
        e.set_scopes(vec![scope("lan", &["10.0.2.3", "10.0.2.4"], &[], true)]);
        let mut now = Instant::now();
        let (tx1, s1, _) = sent(&e.resolve(1, "example.com", rtype::A, false, now));
        assert_eq!(e.next_deadline(), Some(now + SERVER_TIMEOUT));
        now += SERVER_TIMEOUT;
        let actions = e.tick(now);
        assert!(actions.contains(&Action::Cancel { tx: tx1 }));
        let (_, s2, _) = sent(&actions);
        assert_ne!(s1, s2);
        now += SERVER_TIMEOUT;
        let actions = e.tick(now);
        let (_, s3, _) = sent(&actions);
        // Third attempt: both demoted, order preserved.
        assert_eq!(s3, s1);
        now += SERVER_TIMEOUT;
        let a = done(&e.tick(now));
        assert_eq!(a.outcome, Outcome::Unavailable);
        assert_eq!(e.in_flight(), 0);
        assert_eq!(e.demoted(now).len(), 2);
        // An Unavailable is never cached.
        sent(&e.resolve(2, "example.com", rtype::A, false, now));
    }

    #[test]
    fn nxdomain_is_negative_cached_and_servfail_moves_on() {
        let mut e = Engine::new(1);
        e.set_scopes(vec![scope("lan", &["10.0.2.3", "10.0.2.4"], &[], true)]);
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "nope.example.com", rtype::A, false, now));
        let mut m = Message::reply_to(&q);
        m.header.rcode = rcode::NXDOMAIN;
        m.authority.push(Record::new(
            n("example.com"),
            3600,
            RData::Soa { mname: n("ns"), rname: n("h"), serial: 1, refresh: 1, retry: 1, expire: 1, minimum: 60 },
        ));
        let a = done(&e.received(tx, &m.encode().unwrap(), now));
        assert_eq!(a.outcome, Outcome::NotFound);
        let a = done(&e.resolve(2, "nope.example.com", rtype::A, false, now + Duration::from_secs(30)));
        assert_eq!(a.source, Source::Cache);
        assert_eq!(a.outcome, Outcome::NotFound);
        sent(&e.resolve(3, "nope.example.com", rtype::A, false, now + Duration::from_secs(61)));

        let (tx, s1, q) = sent(&e.resolve(4, "x.example.com", rtype::A, false, now));
        let actions = e.received(tx, &reply(&q, vec![], rcode::SERVFAIL), now);
        let (_, s2, _) = sent(&actions);
        assert_ne!(s1, s2);
        assert!(e.demoted(now).contains(&s1));
    }

    #[test]
    fn truncation_retries_over_tcp() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "big.example.com", rtype::TXT, false, now));
        let mut m = Message::reply_to(&q);
        m.header.truncated = true;
        let actions = e.received(tx, &m.encode().unwrap(), now);
        match &actions[0] {
            Action::Send { tcp, .. } => assert!(tcp),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn single_labels_are_expanded_and_never_sent_bare() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "printer", rtype::A, false, now));
        assert_eq!(q.questions[0].name, n("printer.lan"));
        let rec = Record::new(n("printer.lan"), 60, RData::A("10.0.2.9".parse().unwrap()));
        let a = done(&e.received(tx, &reply(&q, vec![rec], 0), now));
        assert_eq!(a.resolved_name, Some(n("printer.lan")));
        // With no domains at all, a single label is NotFound locally.
        let mut e2 = Engine::new(1);
        e2.set_scopes(vec![scope("lan", &["10.0.2.3"], &[], true)]);
        let a = done(&e2.resolve(1, "printer", rtype::A, false, now));
        assert_eq!(a.outcome, Outcome::NotFound);
        assert_eq!(e2.counters.upstream_sent, 0);
        // Two domains: the second is tried after NXDOMAIN on the first.
        let mut e3 = Engine::new(1);
        e3.set_scopes(vec![scope("lan", &["10.0.2.3"], &["a.example", "b.example"], true)]);
        let (tx, _, q) = sent(&e3.resolve(1, "printer", rtype::A, false, now));
        assert_eq!(q.questions[0].name, n("printer.a.example"));
        let actions = e3.received(tx, &reply(&q, vec![], rcode::NXDOMAIN), now);
        let (_, _, q2) = sent(&actions);
        assert_eq!(q2.questions[0].name, n("printer.b.example"));
    }

    #[test]
    fn routing_prefers_domain_match_then_default_route_then_exclusive_takes_all() {
        let mut e = Engine::new(1);
        let mut vpn = scope("vpn", &["10.8.0.1"], &["corp.example"], false);
        vpn.metric = 50;
        let lan = scope("lan", &["10.0.2.3"], &["lan"], true);
        e.set_scopes(vec![lan.clone(), vpn.clone()]);
        let now = Instant::now();
        let (_, s, _) = sent(&e.resolve(1, "git.corp.example", rtype::A, false, now));
        assert_eq!(s, "10.8.0.1".parse::<IpAddr>().unwrap());
        let (_, s, _) = sent(&e.resolve(2, "www.example.com", rtype::A, false, now));
        assert_eq!(s, "10.0.2.3".parse::<IpAddr>().unwrap());
        // A reverse name routes by subnet.
        let mut vpn2 = vpn.clone();
        vpn2.addresses = vec![("10.8.0.2".parse().unwrap(), 24)];
        e.set_scopes(vec![lan.clone(), vpn2.clone()]);
        let (_, s, _) = sent(&e.resolve(3, "7.0.8.10.in-addr.arpa", rtype::PTR, false, now));
        assert_eq!(s, "10.8.0.1".parse::<IpAddr>().unwrap());
        // Exclusive: everything, even the LAN's own domain, goes to the VPN.
        let mut excl = vpn2.clone();
        excl.exclusive = true;
        e.set_scopes(vec![lan, excl]);
        let (_, s, _) = sent(&e.resolve(4, "printer.lan", rtype::A, false, now));
        assert_eq!(s, "10.8.0.1".parse::<IpAddr>().unwrap());
        let (_, _, q) = sent(&e.resolve(5, "printer", rtype::A, false, now));
        assert_eq!(q.questions[0].name, n("printer.corp.example"));
    }

    #[test]
    fn fallback_servers_only_when_no_interface_supplies_any() {
        let mut e = Engine::new(1);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![n("fb.example")]);
        let now = Instant::now();
        let (_, s, _) = sent(&e.resolve(1, "example.com", rtype::A, false, now));
        assert_eq!(s, "9.9.9.9".parse::<IpAddr>().unwrap());
        e.set_scopes(vec![scope("lan", &["10.0.2.3"], &[], true)]);
        let (_, s, _) = sent(&e.resolve(2, "example.com", rtype::A, false, now));
        assert_eq!(s, "10.0.2.3".parse::<IpAddr>().unwrap());
        // No servers anywhere: Unavailable, not NotFound.
        let mut e2 = Engine::new(1);
        let a = done(&e2.resolve(1, "example.com", rtype::A, false, now));
        assert_eq!(a.outcome, Outcome::Unavailable);
    }

    #[test]
    fn lookup_combines_both_families_and_chases_cnames() {
        let mut e = engine();
        let now = Instant::now();
        let actions = e.lookup(1, "www.example.com", Family::Any, now);
        let sends: Vec<(Txid, Message)> = actions
            .iter()
            .filter_map(|a| match a {
                Action::Send { tx, payload, .. } => Some((*tx, Message::decode(payload).unwrap())),
                _ => None,
            })
            .collect();
        assert_eq!(sends.len(), 2);
        let mut result = None;
        for (tx, q) in sends {
            let records = match q.questions[0].rtype {
                rtype::A => vec![
                    Record::new(n("www.example.com"), 60, RData::Cname(n("example.com"))),
                    Record::new(n("example.com"), 30, RData::A("1.2.3.4".parse().unwrap())),
                ],
                _ => vec![Record::new(n("www.example.com"), 60, RData::Cname(n("example.com")))],
            };
            for a in e.received(tx, &reply(&q, records, 0), now) {
                if let Action::Done { completion: Completion::Addresses(x), .. } = a {
                    result = Some(x);
                }
            }
        }
        let r = result.expect("completed");
        assert_eq!(r.outcome, Outcome::Found);
        assert_eq!(r.canonical, n("example.com"));
        assert_eq!(r.addresses, vec![("1.2.3.4".parse::<IpAddr>().unwrap(), 30)]);
    }

    #[test]
    fn abandon_cancels_the_transaction() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, _) = sent(&e.resolve(1, "example.com", rtype::A, false, now));
        let actions = e.abandon(1);
        assert_eq!(actions, vec![Action::Cancel { tx }]);
        assert_eq!(e.in_flight(), 0);
        assert!(e.received(tx, b"", now).is_empty());
    }

    #[test]
    fn a_reply_with_the_wrong_question_or_a_dead_transaction_is_ignored() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "www.example.com", rtype::A, false, now));
        let mut wrong_type = q.clone();
        wrong_type.questions[0].rtype = rtype::AAAA;
        assert!(e.received(tx, &reply(&wrong_type, vec![], 0), now).is_empty());
        let mut two_questions = q.clone();
        two_questions.questions.push(q.questions[0].clone());
        assert!(e.received(tx, &reply(&two_questions, vec![], 0), now).is_empty());
        let mut not_a_response = q.clone();
        not_a_response.header.response = false;
        assert!(e.received(tx, &not_a_response.encode().unwrap(), now).is_empty());
        // Answered once; the same bytes again hit a dead transaction.
        let ok = reply(&q, vec![Record::new(n("www.example.com"), 5, RData::A("1.2.3.4".parse().unwrap()))], 0);
        assert!(!e.received(tx, &ok, now).is_empty());
        assert!(e.received(tx, &ok, now).is_empty());
        assert!(e.received(tx + 1000, &ok, now).is_empty());
    }

    #[test]
    fn in_flight_is_bounded_and_refused_beyond_it() {
        let mut e = engine();
        let now = Instant::now();
        for i in 0..MAX_IN_FLIGHT as u64 {
            let actions = e.resolve(i, &format!("h{i}.example.com"), rtype::A, false, now);
            assert!(matches!(actions[0], Action::Send { .. }));
        }
        let a = done(&e.resolve(u64::MAX, "one-more.example.com", rtype::A, false, now));
        assert_eq!(a.outcome, Outcome::Unavailable);
        assert_eq!(e.counters.refused, 1);
        // Synthetic names still answer under load.
        let a = done(&e.resolve(u64::MAX - 1, "localhost", rtype::A, false, now));
        assert_eq!(a.outcome, Outcome::Found);
        // Timeouts drain it.
        let actions = e.tick(now + SERVER_TIMEOUT * 4);
        assert!(actions.len() >= MAX_IN_FLIGHT);
    }

    #[test]
    fn hostile_ttls_and_missing_soa_are_bounded() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "long.example.com", rtype::A, false, now));
        let rec = Record::new(n("long.example.com"), u32::MAX, RData::A("1.2.3.4".parse().unwrap()));
        done(&e.received(tx, &reply(&q, vec![rec], 0), now));
        // Cached, but not forever.
        let a = done(&e.resolve(2, "long.example.com", rtype::A, false, now + Duration::from_secs(u64::from(MAX_POSITIVE_TTL) - 1)));
        assert_eq!(a.source, Source::Cache);
        sent(&e.resolve(3, "long.example.com", rtype::A, false, now + Duration::from_secs(u64::from(MAX_POSITIVE_TTL) + 1)));
        // NXDOMAIN with no SOA: not cached at all.
        let (tx, _, q) = sent(&e.resolve(4, "gone.example.com", rtype::A, false, now));
        done(&e.received(tx, &reply(&q, vec![], rcode::NXDOMAIN), now));
        sent(&e.resolve(5, "gone.example.com", rtype::A, false, now + Duration::from_secs(1)));
        // An NXDOMAIN whose SOA claims a week: capped to minutes.
        let (tx, _, q) = sent(&e.resolve(6, "neg.example.com", rtype::A, false, now));
        let mut m = Message::reply_to(&q);
        m.header.rcode = rcode::NXDOMAIN;
        m.authority.push(Record::new(n("example.com"), 604800, RData::Soa { mname: n("a"), rname: n("b"), serial: 1, refresh: 1, retry: 1, expire: 1, minimum: 604800 }));
        done(&e.received(tx, &m.encode().unwrap(), now));
        sent(&e.resolve(7, "neg.example.com", rtype::A, false, now + Duration::from_secs(u64::from(MAX_NEGATIVE_TTL) + 1)));
    }

    #[test]
    fn a_cname_loop_in_a_lookup_terminates() {
        let mut e = engine();
        let now = Instant::now();
        let actions = e.lookup(1, "loop.example.com", Family::V4, now);
        let (tx, _, q) = sent(&actions);
        let records = vec![
            Record::new(n("loop.example.com"), 60, RData::Cname(n("a.example.com"))),
            Record::new(n("a.example.com"), 60, RData::Cname(n("b.example.com"))),
            Record::new(n("b.example.com"), 60, RData::Cname(n("a.example.com"))),
        ];
        let actions = e.received(tx, &reply(&q, records, 0), now);
        match &actions[0] {
            Action::Done { completion: Completion::Addresses(a), .. } => {
                assert_eq!(a.outcome, Outcome::Found);
                assert!(a.addresses.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_hostname_with_no_addresses_is_loopback() {
        let mut e = Engine::new(1);
        e.set_hostname(Some("lonely"));
        let a = done(&e.resolve(1, "lonely", rtype::A, false, Instant::now()));
        assert_eq!(a.records[0].rdata, RData::A(Ipv4Addr::LOCALHOST));
        let a = done(&e.resolve(2, "lonely", rtype::AAAA, false, Instant::now()));
        assert_eq!(a.records[0].rdata, RData::Aaaa(Ipv6Addr::LOCALHOST));
    }
}
