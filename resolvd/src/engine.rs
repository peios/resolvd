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
//! 5. the lowest-metric up scope with servers when none claims the default;
//! 6. the fallback servers from the registry, only when no up interface
//!    supplies any.
//!
//! Up means link or better, regardless of servers. An exclusive scope must
//! also be addressed or better. If an earlier step chooses a scope without
//! servers, an upstream attempt finishes Unavailable rather than querying
//! another scope. Synthetic answers and the chosen scope's cache still apply.
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
        self.addresses
            .iter()
            .any(|(a, prefix)| same_subnet(*a, *prefix, addr))
    }
}

fn same_subnet(a: IpAddr, prefix: u8, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix.min(32))
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix.min(128))
            };
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
    /// Remaining cache lifetime of an empty answer, for the stub's expansion CNAME.
    pub negative_ttl: u32,
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
    Send {
        tx: Txid,
        server: IpAddr,
        tcp: bool,
        payload: Vec<u8>,
    },
    Cancel {
        tx: Txid,
    },
    Done {
        qid: Qid,
        completion: Completion,
    },
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
    /// Once invalidated, this task cannot populate the cache, including on
    /// retries or later search candidates. Its requester still completes.
    cache_invalidated: bool,
    candidates: VecDeque<Name>,
    /// The candidate in flight.
    current: Option<Name>,
    scope: Option<String>,
    /// Upstream transactions charged to the whole question, across names and
    /// transports. A transaction answered NXDOMAIN that moves the question to
    /// its next candidate is refunded; failures and TCP retries are not.
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

type Entropy = dyn FnMut(&mut [u8]) -> std::io::Result<()> + Send;

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
    entropy: Box<Entropy>,
    pub counters: Counters,
}

impl Engine {
    /// The caller supplies fresh cryptographic bytes for each upstream send.
    /// Tests and fuzzers can inject a deterministic source without doing I/O.
    pub fn with_entropy(
        entropy: impl FnMut(&mut [u8]) -> std::io::Result<()> + Send + 'static,
    ) -> Engine {
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
            entropy: Box::new(entropy),
            counters: Counters::default(),
        }
    }

    #[cfg(test)]
    fn new(mut seed: u64) -> Engine {
        Self::with_entropy(move |out| {
            for byte in out {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (seed >> 32) as u8;
            }
            Ok(())
        })
    }

    // ------------------------------------------------------- configuration

    /// Replace the scopes. A scope whose servers changed loses its cache:
    /// a VPN's answers die with the VPN.
    pub fn set_scopes(&mut self, scopes: Vec<Scope>) {
        let mut invalidated = Vec::new();
        for new in &scopes {
            let old = self.scopes.iter().find(|s| s.id == new.id);
            if old.is_none_or(|o| o.servers != new.servers) {
                invalidated.push(new.id.clone());
            }
        }
        for old in &self.scopes {
            if !scopes.iter().any(|s| s.id == old.id) {
                invalidated.push(old.id.clone());
            }
        }
        for id in invalidated {
            self.invalidate_scope_cache(&id);
        }
        self.scopes = scopes;
    }

    fn invalidate_scope_cache(&mut self, scope: &str) {
        self.cache.flush_scope(scope);
        for task in self.tasks.values_mut() {
            if task.scope.as_deref() == Some(scope) {
                task.cache_invalidated = true;
            }
        }
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    pub fn set_fallback(&mut self, servers: Vec<IpAddr>, domains: Vec<Name>) {
        if servers != self.fallback_servers {
            self.invalidate_scope_cache(FALLBACK_SCOPE);
        }
        self.fallback_servers = servers;
        self.fallback_domains = domains;
    }

    pub fn fallback_servers(&self) -> &[IpAddr] {
        &self.fallback_servers
    }

    pub fn set_hostname(&mut self, hostname: Option<&str>) {
        self.hostname = hostname
            .and_then(|h| Name::parse(h).ok())
            .filter(|n| !n.is_root());
    }

    pub fn hostname(&self) -> Option<&Name> {
        self.hostname.as_ref()
    }

    pub fn set_hosts(&mut self, hosts: HashMap<Name, Vec<IpAddr>>) {
        self.hosts = hosts;
    }

    pub fn flush(&mut self) {
        self.cache.clear();
        for task in self.tasks.values_mut() {
            task.cache_invalidated = true;
        }
    }

    pub fn cache_entries(&self) -> usize {
        self.cache.len()
    }

    pub fn demoted(&self, now: Instant) -> Vec<IpAddr> {
        self.demoted
            .iter()
            .filter(|(_, until)| **until > now)
            .map(|(s, _)| *s)
            .collect()
    }

    /// The next moment `tick` has something to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.txs.values().map(|t| t.deadline).min()
    }

    pub fn in_flight(&self) -> usize {
        self.txs.len()
    }

    // ------------------------------------------------------------ questions

    pub fn resolve(
        &mut self,
        qid: Qid,
        name: &str,
        rtype: u16,
        no_cache: bool,
        now: Instant,
    ) -> Vec<Action> {
        self.counters.queries += 1;
        let Some(name) = Name::parse(name).ok() else {
            return vec![Action::Done {
                qid,
                completion: Completion::Answer(Answer {
                    outcome: Outcome::NotFound,
                    ..Default::default()
                }),
            }];
        };
        self.resolve_name(qid, name, rtype, no_cache, now)
    }

    /// Resolve the already-decoded IN-class name without presentation parsing.
    pub fn resolve_question(&mut self, qid: Qid, question: &Question, now: Instant) -> Vec<Action> {
        self.counters.queries += 1;
        self.resolve_name(qid, question.name.clone(), question.rtype, false, now)
    }

    fn resolve_name(
        &mut self,
        qid: Qid,
        name: Name,
        rtype: u16,
        no_cache: bool,
        now: Instant,
    ) -> Vec<Action> {
        let id = self.start_task(Owner::Resolve(qid), name, rtype, no_cache);
        self.advance(id, now)
    }

    pub fn lookup(&mut self, qid: Qid, name: &str, family: Family, now: Instant) -> Vec<Action> {
        self.counters.queries += 1;
        let Some(name) = Name::parse(name).ok() else {
            return vec![Action::Done {
                qid,
                completion: Completion::Addresses(Addresses {
                    outcome: Outcome::NotFound,
                    ..Default::default()
                }),
            }];
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
        self.lookups.insert(
            qid,
            Lookup {
                name,
                pending: pending.clone(),
                results: Vec::new(),
            },
        );
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
            if let Some(task) = self.tasks.remove(&id)
                && let Some(tx) = task.tx
            {
                self.txs.remove(&tx);
                actions.push(Action::Cancel { tx });
            }
        }
        self.lookups.remove(&qid);
        actions
    }

    // --------------------------------------------------------------- inputs

    /// Whether a wire reply belongs to a live transaction. Transports use
    /// this before closing its socket; ignoring a reply must leave the real
    /// answer able to arrive on that same socket.
    pub fn response_matches(&self, tx: Txid, bytes: &[u8]) -> bool {
        self.matching_response(tx, bytes).is_some()
    }

    fn matching_response(&self, tx: Txid, bytes: &[u8]) -> Option<Message> {
        let t = self.txs.get(&tx)?;
        let message = Message::decode(bytes).ok()?;
        // Match the ID, response bit, and exactly one 0x20-exact question.
        if message.header.id != t.dns_id || !message.header.response {
            return None;
        }
        let q = message.question()?;
        if q.rtype != t.question.rtype
            || q.class != t.question.class
            || !same_case(&q.name, &t.question.name)
        {
            return None;
        }
        Some(message)
    }

    /// A datagram or TCP message arrived for `tx`.
    pub fn received(&mut self, tx: Txid, bytes: &[u8], now: Instant) -> Vec<Action> {
        let Some(t) = self.txs.get(&tx) else {
            return Vec::new();
        };
        let Some(message) = self.matching_response(tx, bytes) else {
            return Vec::new();
        };
        let task_id = t.task;
        let server = t.server;
        let tcp = t.tcp;
        self.txs.remove(&tx);
        let Some(task) = self.tasks.get_mut(&task_id) else {
            return Vec::new();
        };
        task.tx = None;
        self.counters.upstream_answered += 1;

        if message.header.truncated && !tcp {
            // Ask again over TCP on the same server, spending another attempt.
            return self.send(task_id, server, true, now);
        }
        let code = message.rcode();
        match code as u8 {
            rcode::NOERROR | rcode::NXDOMAIN if code < 16 => {
                self.demoted.remove(&server);
                let candidate = task
                    .current
                    .clone()
                    .unwrap_or_else(|| task.original.clone());
                let scope = task.scope.clone().unwrap_or_default();
                let outcome = if code as u8 == rcode::NXDOMAIN {
                    Outcome::NotFound
                } else {
                    Outcome::Found
                };
                let (relevant, effective_name) =
                    relevant_records(message.answers, &candidate, task.rtype);
                let alias_ttl = relevant
                    .iter()
                    .filter(|r| r.rtype == rtype::CNAME)
                    .map(|r| r.ttl)
                    .min()
                    .unwrap_or(u32::MAX);
                // Records come back in the case we sent (0x20); give them
                // the case the caller used. A negative answer carries none:
                // records riding on an NXDOMAIN are a server's mistake or a
                // forger's payload, and neither is an answer.
                let records: Vec<Record> = relevant
                    .into_iter()
                    .filter(|_| outcome == Outcome::Found)
                    .map(|mut r| {
                        if r.name == candidate {
                            r.name = candidate.clone();
                        }
                        r
                    })
                    .collect();
                let ttl = if outcome == Outcome::Found && !records.is_empty() {
                    records
                        .iter()
                        .map(|r| r.ttl)
                        .min()
                        .unwrap_or(0)
                        .min(MAX_POSITIVE_TTL)
                } else {
                    negative_ttl(&message.authority, &effective_name).min(alias_ttl)
                };
                let entry = Entry {
                    outcome,
                    records: records.clone(),
                    rcode: code,
                    server,
                    expires: now + Duration::from_secs(u64::from(ttl)),
                };
                let rtype = task.rtype;
                let more = !task.candidates.is_empty();
                if ttl > 0 && !task.cache_invalidated {
                    self.cache
                        .insert(CacheKey::new(&candidate, rtype, &scope), entry, now);
                }
                if outcome == Outcome::NotFound && more {
                    // A valid NXDOMAIN is an answer, not a failure: the
                    // transaction that carried it is not charged to the
                    // question's budget, so every candidate can be asked.
                    if let Some(task) = self.tasks.get_mut(&task_id) {
                        task.attempt = task.attempt.saturating_sub(1);
                    }
                    return self.next_candidate(task_id, now);
                }
                let answer = Answer {
                    outcome,
                    negative_ttl: if records.is_empty() { ttl } else { 0 },
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
        let Some(t) = self.txs.remove(&tx) else {
            return Vec::new();
        };
        self.counters.upstream_failed += 1;
        self.demote(t.server, now);
        if let Some(task) = self.tasks.get_mut(&t.task) {
            task.tx = None;
        }
        self.next_attempt(t.task, now)
    }

    /// A local resource or permission error prevented sending. Preserve
    /// the bounded retry sequence without attributing the failure to the
    /// server: a different address or family may still be usable.
    pub fn local_failed(&mut self, tx: Txid, now: Instant) -> Vec<Action> {
        let Some(t) = self.txs.remove(&tx) else {
            return Vec::new();
        };
        self.counters.upstream_failed += 1;
        if let Some(task) = self.tasks.get_mut(&t.task) {
            task.tx = None;
        }
        self.next_attempt(t.task, now)
    }

    /// Time passed. Expired transactions move to the next attempt.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let expired: Vec<Txid> = self
            .txs
            .iter()
            .filter(|(_, t)| t.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
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

    fn interface_of(&self, scope: &str) -> Option<String> {
        self.scopes
            .iter()
            .find(|s| s.id == scope)
            .map(|s| s.interface.clone())
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
            Task {
                owner,
                original: name,
                rtype,
                no_cache,
                cache_invalidated: false,
                candidates: VecDeque::new(),
                current: None,
                scope: None,
                attempt: 0,
                tried: Vec::new(),
                tx: None,
            },
        );
        id
    }

    /// Decide what a fresh task does: answer locally, or build its
    /// candidate list.
    fn advance(&mut self, id: TaskId, now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.get(&id) else {
            return Vec::new();
        };
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
                return self.settle(
                    id,
                    Answer {
                        outcome: Outcome::NotFound,
                        ..Default::default()
                    },
                    now,
                );
            }
            if let Some(task) = self.tasks.get_mut(&id) {
                task.candidates = candidates;
            }
        }
        self.next_candidate(id, now)
    }

    fn next_candidate(&mut self, id: TaskId, now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.get_mut(&id) else {
            return Vec::new();
        };
        let Some(candidate) = task.candidates.pop_front() else {
            // Every candidate was NotFound.
            return self.settle(
                id,
                Answer {
                    outcome: Outcome::NotFound,
                    ..Default::default()
                },
                now,
            );
        };
        task.current = Some(candidate.clone());
        task.tried.clear();
        let rtype = task.rtype;
        let no_cache = task.no_cache;
        let more = !task.candidates.is_empty();
        let Some(scope) = self.route(&candidate, now) else {
            return self.settle(
                id,
                Answer {
                    outcome: Outcome::Unavailable,
                    ..Default::default()
                },
                now,
            );
        };
        if let Some(task) = self.tasks.get_mut(&id) {
            task.scope = Some(scope.clone());
        }
        if !no_cache
            && let Some(entry) = self
                .cache
                .get(&CacheKey::new(&candidate, rtype, &scope), now)
        {
            self.counters.cache_hits += 1;
            if entry.outcome == Outcome::NotFound && more {
                return self.next_candidate(id, now);
            }
            let answer = Answer {
                outcome: entry.outcome,
                negative_ttl: if entry.records.is_empty() {
                    entry.expires.saturating_duration_since(now).as_secs() as u32
                } else {
                    0
                },
                records: entry.records,
                source: Source::Cache,
                server: Some(entry.server),
                interface: self.interface_of(&scope),
                rcode: entry.rcode,
                resolved_name: Some(candidate),
            };
            return self.settle(id, answer, now);
        }
        self.next_attempt(id, now)
    }

    /// Send the current candidate to the next server, or give up.
    fn next_attempt(&mut self, id: TaskId, now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.get(&id) else {
            return Vec::new();
        };
        let attempt = task.attempt;
        let scope_id = task.scope.clone().unwrap_or_default();
        if attempt >= MAX_ATTEMPTS {
            return self.settle(
                id,
                Answer {
                    outcome: Outcome::Unavailable,
                    interface: self.interface_of(&scope_id),
                    ..Default::default()
                },
                now,
            );
        }
        let servers = self.servers_of(&scope_id, now);
        if servers.is_empty() {
            return self.settle(
                id,
                Answer {
                    outcome: Outcome::Unavailable,
                    ..Default::default()
                },
                now,
            );
        }
        if attempt == 0 && self.txs.len() >= MAX_IN_FLIGHT {
            self.counters.refused += 1;
            return self.settle(
                id,
                Answer {
                    outcome: Outcome::Unavailable,
                    ..Default::default()
                },
                now,
            );
        }
        // A server not yet asked, healthiest first; else round-robin.
        let server = servers
            .iter()
            .copied()
            .find(|s| !task.tried.contains(s))
            .unwrap_or(servers[task.tried.len() % servers.len()]);
        if let Some(task) = self.tasks.get_mut(&id) {
            task.tried.push(server);
        }
        self.send(id, server, false, now)
    }

    fn send(&mut self, id: TaskId, server: IpAddr, tcp: bool, now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.get(&id) else {
            return Vec::new();
        };
        // TCP truncation retries arrive here directly. All transports spend
        // the same question budget, even after moving to a search candidate.
        if task.attempt >= MAX_ATTEMPTS {
            let scope = task.scope.clone().unwrap_or_default();
            return self.settle(
                id,
                Answer {
                    outcome: Outcome::Unavailable,
                    interface: self.interface_of(&scope),
                    ..Default::default()
                },
                now,
            );
        }
        let candidate = task
            .current
            .clone()
            .unwrap_or_else(|| task.original.clone());
        let rtype = task.rtype;
        // Two ID bytes and 256 independent case bits cover every letter in
        // a DNS name (whose complete wire form is at most 255 bytes).
        let mut random = [0u8; 34];
        if (self.entropy)(&mut random).is_err() {
            self.counters.refused += 1;
            return self.settle(
                id,
                Answer {
                    outcome: Outcome::Unavailable,
                    ..Default::default()
                },
                now,
            );
        }
        let dns_id = u16::from_le_bytes([random[0], random[1]]);
        let mut n = 0;
        let name = candidate.randomise_case(|| {
            let flip = random[2 + n / 8] & (1 << (n % 8)) != 0;
            n += 1;
            flip
        });
        let question = Question::new(name, rtype);
        let message = Message::query(dns_id, question.clone());
        let payload = message.encode().expect("a query encodes");
        let tx = self.fresh_id();
        self.txs.insert(
            tx,
            Tx {
                task: id,
                dns_id,
                question,
                server,
                tcp,
                deadline: now + SERVER_TIMEOUT,
            },
        );
        if let Some(task) = self.tasks.get_mut(&id) {
            task.attempt += 1;
            task.tx = Some(tx);
        }
        self.counters.upstream_sent += 1;
        vec![Action::Send {
            tx,
            server,
            tcp,
            payload,
        }]
    }

    /// The task is over: hand the answer to its owner.
    fn settle(&mut self, id: TaskId, answer: Answer, _now: Instant) -> Vec<Action> {
        let Some(task) = self.tasks.remove(&id) else {
            return Vec::new();
        };
        if let Some(tx) = task.tx {
            self.txs.remove(&tx);
        }
        match task.owner {
            Owner::Resolve(qid) => vec![Action::Done {
                qid,
                completion: Completion::Answer(answer),
            }],
            Owner::Lookup(qid) => {
                let Some(lookup) = self.lookups.get_mut(&qid) else {
                    return Vec::new();
                };
                lookup.pending.retain(|t| *t != id);
                lookup.results.push((task.rtype, answer));
                if !lookup.pending.is_empty() {
                    return Vec::new();
                }
                let lookup = self.lookups.remove(&qid).expect("present");
                vec![Action::Done {
                    qid,
                    completion: Completion::Addresses(combine(lookup)),
                }]
            }
        }
    }

    // ----------------------------------------------------------- routing

    /// Link availability is independent of whether DNS servers have arrived.
    fn up_scopes(&self) -> impl Iterator<Item = &Scope> {
        self.scopes.iter().filter(|s| s.level >= Level::Link)
    }

    fn exclusive(&self) -> Option<&Scope> {
        self.up_scopes()
            .filter(|s| s.exclusive && s.level >= Level::Addressed)
            .min_by_key(|s| s.metric)
    }

    /// The scope a name goes to, even if it has no servers, or `None` if none qualifies.
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
        if let Some(addr) = name.reverse_address()
            && let Some(s) = self
                .up_scopes()
                .filter(|s| s.contains(addr))
                .min_by_key(|s| s.metric)
        {
            return Some(s.id.clone());
        }
        if let Some(s) = self
            .up_scopes()
            .filter(|s| s.default_route)
            .min_by_key(|s| s.metric)
        {
            return Some(s.id.clone());
        }
        // Only this last-resort interface step requires servers. An earlier
        // winner without servers stays selected; if an upstream attempt is
        // needed, it finishes Unavailable instead of using another scope.
        if let Some(s) = self
            .up_scopes()
            .filter(|s| !s.servers.is_empty())
            .min_by_key(|s| s.metric)
        {
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
            self.scopes
                .iter()
                .find(|s| s.id == scope)
                .map(|s| s.servers.clone())
                .unwrap_or_default()
        };
        let (healthy, demoted): (Vec<IpAddr>, Vec<IpAddr>) =
            servers.into_iter().partition(|s| !self.is_demoted(*s, now));
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
                scopes
                    .iter()
                    .flat_map(|s| s.domains.iter())
                    .chain(self.fallback_domains.iter())
                    .collect()
            }
        };
        for d in domains {
            if let Ok(full) = name.join(d)
                && !out.contains(&full)
            {
                out.push_back(full);
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
            Some(Answer {
                outcome: Outcome::Found,
                records,
                source,
                resolved_name: Some(name.clone()),
                ..Default::default()
            })
        };
        let addresses = |addrs: &[IpAddr], source: Source| {
            let records = addrs
                .iter()
                .filter_map(|a| match (a, rtype) {
                    (IpAddr::V4(v4), rtype::A | rtype::ANY) => {
                        Some(Record::new(name.clone(), 0, RData::A(*v4)))
                    }
                    (IpAddr::V6(v6), rtype::AAAA | rtype::ANY) => {
                        Some(Record::new(name.clone(), 0, RData::Aaaa(*v6)))
                    }
                    _ => None,
                })
                .collect();
            found(records, source)
        };
        if name == &localhost || name.ends_with(&localhost) {
            return addresses(
                &[Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()],
                Source::Synthetic,
            );
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
            return Some(Answer {
                outcome: Outcome::NotFound,
                source: Source::Synthetic,
                ..Default::default()
            });
        }
        if let Some(addr) = name.reverse_address() {
            if rtype != rtype::PTR && rtype != rtype::ANY {
                return None;
            }
            let ptr = |target: Name, source: Source| {
                found(
                    vec![Record::new(name.clone(), 0, RData::Ptr(target))],
                    source,
                )
            };
            if addr.is_loopback() {
                return ptr(localhost, Source::Synthetic);
            }
            // A rebuilt HashMap has a new iteration order. Choose by the
            // canonical presentation name so reloads cannot change a shared
            // address's reverse answer merely by changing the hash seed.
            if let Some((host, _)) = self
                .hosts
                .iter()
                .filter(|(_, a)| a.contains(&addr))
                .min_by_key(|(host, _)| host.to_lowercase().to_string())
            {
                return ptr(host.clone(), Source::Hosts);
            }
            if let Some(h) = &self.hostname
                && self.own_addresses().contains(&addr)
            {
                return ptr(h.clone(), Source::Synthetic);
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
fn negative_ttl(authority: &[Record], name: &Name) -> u32 {
    authority
        .iter()
        .filter(|r| r.class == dns::class::IN && name.ends_with(&r.name))
        .find_map(|r| match &r.rdata {
            RData::Soa { minimum, .. } => Some((*minimum).min(r.ttl)),
            _ => None,
        })
        .unwrap_or(0)
        .min(MAX_NEGATIVE_TTL)
}

/// Keep the requested RRset and its CNAME path, in the server's record order.
/// ANY and explicit CNAME questions stop at the queried owner. Other types
/// follow at most the same sixteen aliases as lookup's address chase.
fn relevant_records(records: Vec<Record>, candidate: &Name, qtype: u16) -> (Vec<Record>, Name) {
    let mut keep = vec![false; records.len()];
    let mut name = candidate.clone();
    let mut seen = Vec::new();
    for depth in 0..=16 {
        let mut terminal = false;
        for (index, record) in records.iter().enumerate() {
            if record.class == dns::class::IN
                && record.name == name
                && (record.rtype == qtype || qtype == rtype::ANY)
            {
                keep[index] = true;
                terminal = true;
            }
        }
        if terminal || depth == 16 || seen.contains(&name) {
            break;
        }
        seen.push(name.clone());
        let next = records.iter().enumerate().find_map(|(index, record)| {
            if record.class == dns::class::IN && record.name == name {
                if let RData::Cname(target) = &record.rdata {
                    return Some((index, target.clone()));
                }
            }
            None
        });
        let Some((index, target)) = next else { break };
        keep[index] = true;
        name = target;
    }
    let records = records
        .into_iter()
        .zip(keep)
        .filter_map(|(record, keep)| keep.then_some(record))
        .collect();
    (records, name)
}

/// Fold a lookup's per-type answers into addresses plus a canonical name.
fn combine(lookup: Lookup) -> Addresses {
    let mut out = Addresses {
        canonical: lookup.name.clone(),
        ..Default::default()
    };
    let mut any_found = false;
    let mut any_unavailable = false;
    let mut metadata_rank = None;
    for (rtype, answer) in &lookup.results {
        match answer.outcome {
            Outcome::Found => {
                any_found = true;
                let start = answer
                    .resolved_name
                    .clone()
                    .unwrap_or_else(|| lookup.name.clone());
                let (canonical, addrs) = chase(&answer.records, &start, *rtype);
                // Prefer an address-producing family, then A over AAAA, for
                // both metadata fields. Arrival order still orders addresses.
                let rank = (addrs.is_empty(), *rtype);
                if metadata_rank.is_none_or(|best| rank < best) {
                    out.canonical = canonical;
                    out.source = answer.source;
                    metadata_rank = Some(rank);
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
    out
}

/// Follow CNAMEs from `start` and collect the addresses at the end.
fn chase(records: &[Record], start: &Name, rtype: u16) -> (Name, Vec<(IpAddr, u32)>) {
    let mut name = start.clone();
    for _ in 0..16 {
        let next = records
            .iter()
            .find(|r| r.name == name)
            .and_then(|r| match &r.rdata {
                RData::Cname(t) => Some(t.clone()),
                _ => None,
            });
        match next {
            Some(t) if !records.iter().any(|r| r.name == name && r.rtype == rtype) => name = t,
            _ => break,
        }
    }
    let addrs = records
        .iter()
        .filter(|r| r.name == name)
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
            if let Action::Send {
                tx,
                server,
                payload,
                ..
            } = a
            {
                return (*tx, *server, Message::decode(payload).unwrap());
            }
        }
        panic!("nothing sent: {actions:?}");
    }

    fn done(actions: &[Action]) -> Answer {
        for a in actions {
            if let Action::Done {
                completion: Completion::Answer(ans),
                ..
            } = a
            {
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
    fn stub_names_preserve_wire_labels_and_count_once() {
        let cases = [
            vec![b"dot.label".to_vec(), b"example".to_vec()],
            vec![b"back\\slash\0\x01\xff".to_vec(), b"example".to_vec()],
            vec![vec![0xc3; 63], b"example".to_vec()],
            vec![vec![1; 15]; 5],
        ];
        for labels in cases {
            let mut e = engine();
            let name = Name::from_labels(labels.clone()).unwrap();
            let actions = e.resolve_question(1, &Question::new(name, rtype::A), Instant::now());
            let (_, _, query) = sent(&actions);
            let actual: Vec<_> = query
                .question()
                .unwrap()
                .name
                .labels()
                .iter()
                .map(|label| label.to_ascii_lowercase())
                .collect();
            assert_eq!(actual, labels);
            assert_eq!(e.counters.queries, 1);
        }
    }

    #[test]
    fn empty_lookup_keeps_expansion_and_cname_target() {
        for records in [
            vec![],
            vec![Record::new(
                n("printer.lan"),
                30,
                RData::Cname(n("target.lan")),
            )],
        ] {
            let expected = if records.is_empty() {
                n("printer.lan")
            } else {
                n("target.lan")
            };
            let out = combine(Lookup {
                name: n("printer"),
                pending: vec![],
                results: vec![(
                    rtype::AAAA,
                    Answer {
                        outcome: Outcome::Found,
                        records,
                        source: Source::Dns,
                        resolved_name: Some(n("printer.lan")),
                        ..Default::default()
                    },
                )],
            });
            assert_eq!(out.canonical, expected);
            assert_eq!(out.source, Source::Dns);
            assert_eq!(out.outcome, Outcome::Found);
            assert!(out.addresses.is_empty());
        }
    }

    #[test]
    fn stub_single_label_with_embedded_dot_uses_search_domain() {
        let mut e = engine();
        let name = Name::from_labels(vec![b"dot.label".to_vec()]).unwrap();
        let actions = e.resolve_question(1, &Question::new(name, rtype::A), Instant::now());
        let (_, _, query) = sent(&actions);
        let labels: Vec<_> = query
            .question()
            .unwrap()
            .name
            .labels()
            .iter()
            .map(|label| label.to_ascii_lowercase())
            .collect();
        assert_eq!(labels, vec![b"dot.label".to_vec(), b"lan".to_vec()]);
    }

    #[test]
    fn lookup_metadata_prefers_addresses_then_a_in_either_completion_order() {
        for a_has_addresses in [false, true] {
            for aaaa_has_addresses in [false, true] {
                for reverse in [false, true] {
                    let mut results = vec![
                        (
                            rtype::A,
                            Answer {
                                outcome: Outcome::Found,
                                source: Source::Cache,
                                resolved_name: Some(n("a.lan")),
                                records: if a_has_addresses {
                                    vec![Record::new(
                                        n("a.lan"),
                                        11,
                                        RData::A("10.0.2.9".parse().unwrap()),
                                    )]
                                } else {
                                    vec![]
                                },
                                ..Default::default()
                            },
                        ),
                        (
                            rtype::AAAA,
                            Answer {
                                outcome: Outcome::Found,
                                source: Source::Dns,
                                resolved_name: Some(n("aaaa.lan")),
                                records: if aaaa_has_addresses {
                                    vec![Record::new(
                                        n("aaaa.lan"),
                                        22,
                                        RData::Aaaa("fd00::9".parse().unwrap()),
                                    )]
                                } else {
                                    vec![]
                                },
                                ..Default::default()
                            },
                        ),
                    ];
                    if reverse {
                        results.reverse();
                    }
                    let out = combine(Lookup {
                        name: n("printer"),
                        pending: vec![],
                        results,
                    });
                    let prefer_a = a_has_addresses || !aaaa_has_addresses;
                    assert_eq!(
                        out.canonical,
                        n(if prefer_a { "a.lan" } else { "aaaa.lan" })
                    );
                    assert_eq!(
                        out.source,
                        if prefer_a { Source::Cache } else { Source::Dns }
                    );
                    assert_eq!(
                        out.addresses.len(),
                        usize::from(a_has_addresses) + usize::from(aaaa_has_addresses)
                    );
                    if a_has_addresses && aaaa_has_addresses {
                        assert_eq!(out.addresses[0].1, if reverse { 22 } else { 11 });
                    }
                }
            }
        }
    }

    #[test]
    fn unrelated_zero_ttl_records_do_not_escape_or_prevent_caching() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "wanted.example", rtype::A, false, now));
        let good = Record::new(
            n("wanted.example"),
            60,
            RData::A("10.0.2.9".parse().unwrap()),
        );
        let bytes = reply(
            &q,
            vec![
                Record::new(
                    n("elsewhere.example"),
                    0,
                    RData::A("10.0.2.99".parse().unwrap()),
                ),
                good.clone(),
                Record::new(
                    n("wanted.example"),
                    0,
                    RData::Aaaa("fd00::99".parse().unwrap()),
                ),
            ],
            rcode::NOERROR,
        );
        let answer = done(&e.received(tx, &bytes, now));
        assert_eq!(answer.records, vec![good]);
        let cached = done(&e.resolve(
            2,
            "wanted.example",
            rtype::A,
            false,
            now + Duration::from_secs(1),
        ));
        assert_eq!(cached.source, Source::Cache);
        assert_eq!(cached.records.len(), 1);
        assert_eq!(cached.records[0].ttl, 59);
    }

    #[test]
    fn relevant_chain_preserves_server_order_and_stops_explicit_cname_and_any() {
        let alias = Record::new(n("alias.example"), 30, RData::Cname(n("target.example")));
        let target = Record::new(
            n("target.example"),
            60,
            RData::A("10.0.2.9".parse().unwrap()),
        );
        let other = Record::new(
            n("elsewhere.example"),
            0,
            RData::A("10.0.2.99".parse().unwrap()),
        );
        let mut wrong_class = alias.clone();
        wrong_class.class = 3;
        let records = vec![target.clone(), other, wrong_class, alias.clone()];
        let (kept, end) = relevant_records(records.clone(), &n("alias.example"), rtype::A);
        assert_eq!(kept, vec![target, alias.clone()]);
        assert_eq!(end, n("target.example"));
        for qtype in [rtype::CNAME, rtype::ANY] {
            let (kept, end) = relevant_records(records.clone(), &n("alias.example"), qtype);
            assert_eq!(kept, vec![alias.clone()]);
            assert_eq!(end, n("alias.example"));
        }
    }

    #[test]
    fn relevant_chain_is_bounded_and_does_not_revisit_aliases() {
        let records: Vec<_> = (0..20)
            .map(|i| {
                Record::new(
                    n(&format!("n{i}.example")),
                    60,
                    RData::Cname(n(&format!("n{}.example", i + 1))),
                )
            })
            .collect();
        let (kept, end) = relevant_records(records, &n("n0.example"), rtype::A);
        assert_eq!(kept.len(), 16);
        assert_eq!(end, n("n16.example"));
        let records = vec![
            Record::new(n("a.example"), 60, RData::Cname(n("b.example"))),
            Record::new(n("b.example"), 60, RData::Cname(n("a.example"))),
        ];
        let (kept, end) = relevant_records(records.clone(), &n("a.example"), rtype::A);
        assert_eq!(kept, records);
        assert_eq!(end, n("a.example"));
    }

    #[test]
    fn negative_soa_must_have_the_right_class_and_enclose_the_effective_name() {
        let soa = |owner: &str, ttl| {
            Record::new(
                n(owner),
                ttl,
                RData::Soa {
                    mname: n("ns.example"),
                    rname: n("hostmaster.example"),
                    serial: 1,
                    refresh: 1,
                    retry: 1,
                    expire: 1,
                    minimum: 60,
                },
            )
        };
        let mut wrong_class = soa("example", 0);
        wrong_class.class = 3;
        let records = vec![soa("other.example", 0), wrong_class, soa("example", 30)];
        assert_eq!(negative_ttl(&records, &n("host.example")), 30);
        assert_eq!(negative_ttl(&records, &n("host.notexample")), 0);
        assert_eq!(negative_ttl(&[soa(".", 30)], &n("anywhere")), 30);

        let mut e = engine();
        let now = Instant::now();
        let (tx, _, query) = sent(&e.resolve(1, "alias.example", rtype::A, false, now));
        let mut response = Message::reply_to(&query);
        response.header.rcode = rcode::NXDOMAIN;
        response.answers.push(Record::new(
            n("alias.example"),
            10,
            RData::Cname(n("missing.other")),
        ));
        response.authority.push(soa("other", 30));
        let answer = done(&e.received(tx, &response.encode().unwrap(), now));
        assert_eq!(answer.outcome, Outcome::NotFound);
        assert!(answer.records.is_empty());
        assert_eq!(
            done(&e.resolve(
                2,
                "alias.example",
                rtype::A,
                false,
                now + Duration::from_secs(9)
            ))
            .source,
            Source::Cache
        );
        sent(&e.resolve(
            3,
            "alias.example",
            rtype::A,
            false,
            now + Duration::from_secs(10),
        ));
    }

    #[test]
    fn entropy_failure_sends_nothing_and_releases_the_lookup() {
        let mut e = engine();
        let mut calls = 0;
        e.entropy = Box::new(move |out| {
            calls += 1;
            if calls == 1 {
                // Even a partially filled buffer must never reach the wire.
                out[..2].fill(0x55);
                Err(std::io::ErrorKind::PermissionDenied.into())
            } else {
                out.fill(0xAA);
                Ok(())
            }
        });
        let now = Instant::now();
        let actions = e.resolve(1, "entropy.example.", rtype::A, false, now);
        assert_eq!(done(&actions).outcome, Outcome::Unavailable);
        assert!(!actions.iter().any(|a| matches!(a, Action::Send { .. })));
        assert!(e.tasks.is_empty() && e.txs.is_empty() && e.lookups.is_empty());
        assert_eq!(e.counters.upstream_sent, 0);
        assert_eq!(e.counters.refused, 1);
        let (_, _, query) = sent(&e.resolve(2, "entropy.example.", rtype::A, false, now));
        assert_eq!(query.header.id, 0xAAAA);
        assert_eq!(e.counters.upstream_sent, 1);
    }

    #[test]
    fn each_attempt_draws_fresh_id_and_case_bytes_including_long_names() {
        let mut e = engine();
        let mut calls = 0u8;
        e.entropy = Box::new(move |out| {
            calls += 1;
            assert_eq!(out.len(), 34);
            out.fill(if calls == 1 { 0 } else { 0xFF });
            out[..2].copy_from_slice(&(calls as u16).to_le_bytes());
            Ok(())
        });
        // Maximum wire length: four labels plus the final root octet.
        let name = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let now = Instant::now();
        let (_, _, first) = sent(&e.resolve(1, &name, rtype::A, false, now));
        assert_eq!(first.header.id, 1);
        assert_eq!(first.questions[0].name, n(&name));
        let (_, _, second) = sent(&e.tick(now + SERVER_TIMEOUT));
        assert_eq!(second.header.id, 2);
        assert_eq!(
            second.questions[0].name.labels(),
            n(&name.to_ascii_uppercase()).labels()
        );
        assert_eq!(first.questions[0].name.labels(), n(&name).labels());
    }

    #[test]
    fn case_entropy_consumes_low_bits_only_for_ascii_letters() {
        let mut e = engine();
        e.entropy = Box::new(|out| {
            out.fill(0);
            out[..2].copy_from_slice(&0x1234u16.to_le_bytes());
            out[2] = 0b1000_0101;
            out[3] = 0b0000_0010;
            Ok(())
        });
        let (_, _, query) = sent(&e.resolve(
            1, "a1b-c.d2ef3gh-i4jk.", rtype::A, false, Instant::now(),
        ));
        assert_eq!(query.header.id, 0x1234);
        // Bits 0, 2, 7 and 9 uppercase a, c, h and j. Digits, hyphens,
        // label lengths and separators consume no bits, including at the
        // byte boundary between h and i.
        assert_eq!(query.questions[0].name.labels(), n("A1b-C.d2ef3gH-i4Jk.").labels());
    }

    #[test]
    fn local_answers_do_not_need_upstream_entropy() {
        let mut e = engine();
        e.entropy = Box::new(|_| panic!("local answers must not request entropy"));
        assert_eq!(
            done(&e.resolve(1, "localhost", rtype::A, false, Instant::now())).outcome,
            Outcome::Found
        );
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
        e.set_hosts(HashMap::from([(
            n("printer"),
            vec!["10.0.2.9".parse().unwrap()],
        )]));
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
    fn shared_static_reverse_is_stable_across_host_table_rebuilds() {
        let now = Instant::now();
        let addresses: Vec<IpAddr> = vec!["10.0.2.9".parse().unwrap(), "fd99::9".parse().unwrap()];
        // New HashMaps exercise independent hash seeds as well as both insertion orders.
        for rebuild in 0..32 {
            let mut e = engine();
            for names in [
                ["Zulu.home", "alpha.home", "ALPHA-1.home"],
                ["ALPHA-1.home", "alpha.home", "Zulu.home"],
            ] {
                e.set_hosts(
                    names
                        .into_iter()
                        .map(|name| (n(name), addresses.clone()))
                        .collect(),
                );
                for address in &addresses {
                    let answer = done(&e.reverse(1, *address, now));
                    assert_eq!(answer.source, Source::Hosts);
                    assert_eq!(answer.records.len(), 1);
                    assert_eq!(
                        answer.records[0].rdata,
                        RData::Ptr(n("ALPHA-1.home")),
                        "rebuild {rebuild}"
                    );
                    let reverse = match address {
                        IpAddr::V4(a) => Name::reverse_v4(*a),
                        IpAddr::V6(a) => Name::reverse_v6(*a),
                    };
                    let any = done(&e.resolve(2, &reverse.to_string(), rtype::ANY, false, now));
                    assert_eq!(any.records, answer.records);
                }
                assert_eq!(e.counters.upstream_sent, 0);
            }
        }
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
        let rec = Record::new(
            n("www.example.com"),
            60,
            RData::A("1.2.3.4".parse().unwrap()),
        );
        let a = done(&e.received(tx, &reply(&q, vec![rec.clone()], rcode::NOERROR), now));
        assert_eq!(a.outcome, Outcome::Found);
        assert_eq!(a.source, Source::Dns);
        assert_eq!(a.records, vec![rec]);
        assert_eq!(a.interface.as_deref(), Some("lan"));
        // Second time: cache, no send.
        let actions = e.resolve(
            2,
            "WWW.EXAMPLE.COM",
            rtype::A,
            false,
            now + Duration::from_secs(10),
        );
        let a = done(&actions);
        assert_eq!(a.source, Source::Cache);
        assert_eq!(e.counters.cache_hits, 1);
        // Servers change: the scope's cache dies.
        e.set_scopes(vec![scope("lan", &["10.0.2.4"], &["lan"], true)]);
        let actions = e.resolve(3, "www.example.com", rtype::A, false, now);
        sent(&actions);
    }

    #[test]
    fn a_long_lived_answer_at_capacity_preserves_other_live_answers() {
        let mut e = engine();
        let now = Instant::now() + Duration::from_secs(3_600);
        for i in 0..crate::cache::MAX_ENTRIES {
            let name = format!("n{i}.example.com");
            let (tx, _, q) = sent(&e.resolve(i as u64, &name, rtype::A, false, now));
            let ttl = if i == 0 { 60 } else { 300 };
            let record = Record::new(n(&name), ttl, RData::A("1.2.3.4".parse().unwrap()));
            done(&e.received(tx, &reply(&q, vec![record], rcode::NOERROR), now));
        }
        assert_eq!(e.cache_entries(), crate::cache::MAX_ENTRIES);
        let (tx, _, q) = sent(&e.resolve(u64::MAX, "long.example.com", rtype::A, false, now));
        let record = Record::new(
            n("long.example.com"),
            86_400,
            RData::A("1.2.3.5".parse().unwrap()),
        );
        done(&e.received(tx, &reply(&q, vec![record], rcode::NOERROR), now));

        assert_eq!(e.cache_entries(), crate::cache::MAX_ENTRIES);
        let sent_before = e.counters.upstream_sent;
        for name in ["n1.example.com", "long.example.com"] {
            let answer = done(&e.resolve(u64::MAX, name, rtype::A, false, now));
            assert_eq!(answer.source, Source::Cache);
        }
        assert_eq!(e.counters.upstream_sent, sent_before);
        sent(&e.resolve(u64::MAX, "n0.example.com", rtype::A, false, now));
        assert_eq!(e.counters.upstream_sent, sent_before + 1);
    }

    #[test]
    fn an_expired_answer_is_removed_from_the_cache_count_on_lookup() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "expire.example.com", rtype::A, false, now));
        let record = Record::new(
            n("expire.example.com"),
            10,
            RData::A("1.2.3.4".parse().unwrap()),
        );
        done(&e.received(tx, &reply(&q, vec![record], rcode::NOERROR), now));
        assert_eq!(e.cache_entries(), 1);

        sent(&e.resolve(
            2,
            "expire.example.com",
            rtype::A,
            false,
            now + Duration::from_secs(10),
        ));
        assert_eq!(e.cache_entries(), 0);
        assert_eq!(e.counters.cache_hits, 0);
        assert_eq!(e.counters.upstream_sent, 2);
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
        assert!(
            e.received(tx, &reply(&wrong_case, vec![], 0), now)
                .is_empty()
        );
        assert!(e.received(tx, b"garbage", now).is_empty());
        assert_eq!(e.in_flight(), 1);
    }

    #[test]
    fn local_send_failures_preserve_bounded_retries_without_server_demotion() {
        let mut e = engine();
        e.set_scopes(vec![scope("lan", &["10.0.2.3", "10.0.2.4"], &[], true)]);
        let now = Instant::now();
        let mut actions = e.resolve(1, "example.com", rtype::A, false, now);
        let (_, first, _) = sent(&actions);
        for attempt in 0..MAX_ATTEMPTS {
            let (tx, server, _) = sent(&actions);
            if attempt == 1 {
                assert_ne!(server, first);
            }
            actions = e.local_failed(tx, now);
            assert!(e.demoted(now).is_empty());
            assert!(e.local_failed(tx, now).is_empty());
        }
        assert_eq!(done(&actions).outcome, Outcome::Unavailable);
        assert_eq!(e.in_flight(), 0);
        assert_eq!(e.counters.upstream_sent, MAX_ATTEMPTS as u64);
        assert_eq!(e.counters.upstream_failed, MAX_ATTEMPTS as u64);
        // Not cached: a later question can use the same healthy server.
        let (_, retried_server, _) = sent(&e.resolve(2, "example.com", rtype::A, false, now));
        assert_eq!(retried_server, first);
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
    fn expanded_nodata_cname_uses_the_negative_lifetime_and_ages_with_the_cache() {
        let now = Instant::now();
        // SOA minimum, SOA TTL, resolver cap, and no cacheable SOA.
        for (soa, expected) in [
            (Some((80, 30)), 30),
            (Some((20, 90)), 20),
            (Some((86_400, 86_400)), MAX_NEGATIVE_TTL),
            (None, 0),
        ] {
            let mut e = engine();
            let (tx, _, q) = sent(&e.resolve(1, "PrInTeR", rtype::AAAA, false, now));
            let mut m = Message::reply_to(&q);
            if let Some((ttl, minimum)) = soa {
                m.authority.push(Record::new(
                    n("lan"),
                    ttl,
                    RData::Soa {
                        mname: n("ns.lan"),
                        rname: n("hostmaster.lan"),
                        serial: 1,
                        refresh: 1,
                        retry: 1,
                        expire: 1,
                        minimum,
                    },
                ));
            }
            let answer = done(&e.received(tx, &m.encode().unwrap(), now));
            assert_eq!(answer.outcome, Outcome::Found);
            assert!(answer.records.is_empty());
            assert_eq!(answer.negative_ttl, expected);
            let query = Message::query(9, Question::new(n("PrInTeR"), rtype::AAAA));
            let rendered = crate::stub::build_reply(&query, &answer);
            assert_eq!(rendered.answers.len(), 1);
            assert_eq!(rendered.answers[0].name.labels(), n("PrInTeR").labels());
            assert_eq!(rendered.answers[0].rdata, RData::Cname(n("printer.lan")));
            assert_eq!(rendered.answers[0].ttl, expected);
            if expected > 0 {
                for elapsed in [
                    Duration::from_millis(2_500),
                    Duration::from_secs(u64::from(expected)) - Duration::from_millis(1),
                ] {
                    let cached = done(&e.resolve(2, "PrInTeR", rtype::AAAA, false, now + elapsed));
                    assert_eq!(cached.source, Source::Cache);
                    let remaining =
                        (Duration::from_secs(u64::from(expected)) - elapsed).as_secs() as u32;
                    assert_eq!(cached.negative_ttl, remaining);
                    assert_eq!(
                        crate::stub::build_reply(&query, &cached).answers[0].ttl,
                        remaining
                    );
                }
            }
            // No SOA means no cache admission; otherwise expiry is exact.
            sent(&e.resolve(
                3,
                "PrInTeR",
                rtype::AAAA,
                false,
                now + Duration::from_secs(u64::from(expected)),
            ));
        }
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
            RData::Soa {
                mname: n("ns"),
                rname: n("h"),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 60,
            },
        ));
        let a = done(&e.received(tx, &m.encode().unwrap(), now));
        assert_eq!(a.outcome, Outcome::NotFound);
        let a = done(&e.resolve(
            2,
            "nope.example.com",
            rtype::A,
            false,
            now + Duration::from_secs(30),
        ));
        assert_eq!(a.source, Source::Cache);
        assert_eq!(a.outcome, Outcome::NotFound);
        sent(&e.resolve(
            3,
            "nope.example.com",
            rtype::A,
            false,
            now + Duration::from_secs(61),
        ));

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
    fn nxdomain_moves_to_the_next_candidate_without_spending_the_budget() {
        let mut e = Engine::new(1);
        e.set_scopes(vec![scope(
            "lan",
            &["10.0.2.3"],
            &["one.test", "two.test"],
            true,
        )]);
        let mut now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "printer", rtype::A, false, now));
        assert_eq!(q.questions[0].name, n("printer.one.test"));
        let actions = e.received(tx, &reply(&q, vec![], rcode::NXDOMAIN), now);
        let (_, _, q) = sent(&actions);
        assert_eq!(q.questions[0].name, n("printer.two.test"));
        // The second candidate still has the whole budget for failures.
        now += SERVER_TIMEOUT;
        sent(&e.tick(now));
        now += SERVER_TIMEOUT;
        sent(&e.tick(now));
        now += SERVER_TIMEOUT;
        assert_eq!(done(&e.tick(now)).outcome, Outcome::Unavailable);
        assert_eq!(e.counters.upstream_sent, 4);
        assert_eq!(e.in_flight(), 0);
    }

    #[test]
    fn more_search_candidates_than_attempts_are_all_asked() {
        let mut e = Engine::new(1);
        let domains = ["a.test", "b.test", "c.test", "d.test", "e.test"];
        e.set_scopes(vec![scope("lan", &["10.0.2.3"], &domains, true)]);
        let now = Instant::now();
        let mut actions = e.resolve(1, "printer", rtype::A, false, now);
        for domain in &domains[..4] {
            let (tx, _, q) = sent(&actions);
            assert_eq!(q.questions[0].name, n(&format!("printer.{domain}")));
            actions = e.received(tx, &reply(&q, vec![], rcode::NXDOMAIN), now);
        }
        let (tx, _, q) = sent(&actions);
        assert_eq!(q.questions[0].name, n("printer.e.test"));
        let found = Record::new(
            n("printer.e.test"),
            60,
            RData::A("10.0.2.50".parse().unwrap()),
        );
        let answer = done(&e.received(tx, &reply(&q, vec![found], rcode::NOERROR), now));
        assert_eq!(answer.outcome, Outcome::Found);
        assert_eq!(e.counters.upstream_sent, 5);
    }

    #[test]
    fn truncation_retry_consumes_the_question_budget() {
        let mut e = engine();
        let mut now = Instant::now();
        let (tx, server, q) = sent(&e.resolve(1, "large.example", rtype::TXT, false, now));
        let mut truncated = Message::reply_to(&q);
        truncated.header.truncated = true;
        let actions = e.received(tx, &truncated.encode().unwrap(), now);
        let (_, tcp_server, _) = sent(&actions);
        assert_eq!(server, tcp_server);
        assert!(matches!(actions[0], Action::Send { tcp: true, .. }));
        now += SERVER_TIMEOUT;
        let (tx, _, q) = sent(&e.tick(now));
        let mut truncated = Message::reply_to(&q);
        truncated.header.truncated = true;
        assert_eq!(
            done(&e.received(tx, &truncated.encode().unwrap(), now)).outcome,
            Outcome::Unavailable
        );
        assert_eq!(e.counters.upstream_sent, 3);
        assert_eq!(e.in_flight(), 0);
    }

    #[test]
    fn final_budgeted_attempt_can_still_complete_successfully() {
        for code in [rcode::NOERROR, rcode::NXDOMAIN] {
            let mut e = engine();
            let mut now = Instant::now();
            sent(&e.resolve(1, "last.example", rtype::A, false, now));
            now += SERVER_TIMEOUT;
            sent(&e.tick(now));
            now += SERVER_TIMEOUT;
            let (tx, _, q) = sent(&e.tick(now));
            let answer = done(&e.received(tx, &reply(&q, vec![], code), now));
            assert_eq!(
                answer.outcome,
                if code == rcode::NXDOMAIN {
                    Outcome::NotFound
                } else {
                    Outcome::Found
                }
            );
            assert_eq!(e.counters.upstream_sent, 3);
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
        e3.set_scopes(vec![scope(
            "lan",
            &["10.0.2.3"],
            &["a.example", "b.example"],
            true,
        )]);
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

    // Exercise public engine actions, including the absence of a delayed send.
    fn assert_local_resolution(
        e: &mut Engine,
        name: &str,
        rtype: u16,
        outcome: Outcome,
        now: Instant,
    ) {
        let actions = e.resolve(1, name, rtype, false, now);
        assert_eq!(
            actions,
            vec![Action::Done {
                qid: 1,
                completion: Completion::Answer(Answer {
                    outcome,
                    ..Default::default()
                }),
            }],
            "{name} must finish locally without any Send action"
        );
        assert_eq!(e.counters.upstream_sent, 0);
        assert_eq!(e.next_deadline(), None);
        assert!(e.tick(now + SERVER_TIMEOUT * 4).is_empty());
        assert_eq!(e.counters.upstream_sent, 0);
    }

    #[test]
    fn serverless_exclusive_scope_blocks_other_scopes_and_fallback() {
        let mut vpn = scope("vpn", &[], &["corp.example"], false);
        vpn.exclusive = true;
        vpn.level = Level::Addressed;
        vpn.metric = 50;
        let mut other = scope("other", &["10.9.0.1"], &["eng.corp.example"], true);
        other.exclusive = true;
        other.metric = 200;
        let now = Instant::now();
        for (name, rtype) in [
            ("www.example.com", rtype::A),
            ("git.eng.corp.example", rtype::AAAA),
            ("printer.lan", rtype::A),
            ("7.2.0.10.in-addr.arpa", rtype::PTR),
        ] {
            let mut e = engine();
            e.set_scopes(vec![e.scopes()[0].clone(), other.clone(), vpn.clone()]);
            e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![n("extra.example")]);
            assert_local_resolution(&mut e, name, rtype, Outcome::Unavailable, now);
        }
    }

    #[test]
    fn serverless_link_scope_wins_longest_matching_domain() {
        let mut e = engine();
        let mut shorter = scope("shorter", &["10.9.0.1"], &["example"], false);
        shorter.metric = 1;
        let mut vpn = scope("vpn", &[], &["corp.example"], false);
        vpn.level = Level::Link;
        vpn.metric = 200;
        e.set_scopes(vec![e.scopes()[0].clone(), shorter, vpn]);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![]);
        assert_local_resolution(
            &mut e,
            "git.corp.example",
            rtype::A,
            Outcome::Unavailable,
            Instant::now(),
        );
    }

    #[test]
    fn serverless_subnet_winner_does_not_use_another_scope() {
        let mut e = engine();
        let mut vpn = scope("vpn", &[], &[], false);
        vpn.addresses = vec![("10.8.0.2".parse().unwrap(), 24)];
        vpn.metric = 50;
        let mut other = scope("other", &["10.9.0.1"], &[], false);
        other.addresses = vpn.addresses.clone();
        other.metric = 200;
        e.set_scopes(vec![e.scopes()[0].clone(), other, vpn]);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![]);
        assert_local_resolution(
            &mut e,
            "7.0.8.10.in-addr.arpa",
            rtype::PTR,
            Outcome::Unavailable,
            Instant::now(),
        );
    }

    #[test]
    fn serverless_default_claimant_blocks_lower_metric_nonclaimant() {
        let mut e = Engine::new(1);
        let claimant = scope("lan", &[], &[], true);
        let mut other = scope("vpn", &["10.8.0.1"], &[], false);
        other.metric = 50;
        e.set_scopes(vec![other, claimant]);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![]);
        assert_local_resolution(
            &mut e,
            "www.example.com",
            rtype::A,
            Outcome::Unavailable,
            Instant::now(),
        );
    }

    #[test]
    fn serverless_lower_metric_default_claimant_still_wins() {
        let mut e = Engine::new(1);
        let claimant = scope("lan", &[], &[], true);
        let mut other = scope("vpn", &["10.8.0.1"], &[], true);
        other.metric = 200;
        e.set_scopes(vec![other, claimant]);
        assert_local_resolution(
            &mut e,
            "www.example.com",
            rtype::A,
            Outcome::Unavailable,
            Instant::now(),
        );
    }

    #[test]
    fn serverless_earlier_winner_blocks_fallback_even_without_other_interfaces() {
        let now = Instant::now();
        for (domains, default_route, exclusive, name, rtype) in [
            (vec![], false, true, "www.example.com", rtype::A),
            (
                vec!["corp.example"],
                false,
                false,
                "git.corp.example",
                rtype::A,
            ),
            (vec![], false, false, "7.2.0.10.in-addr.arpa", rtype::PTR),
            (vec![], true, false, "www.example.com", rtype::A),
        ] {
            let mut e = Engine::new(1);
            let mut s = scope("serverless", &[], &domains, default_route);
            s.exclusive = exclusive;
            e.set_scopes(vec![s]);
            e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![]);
            assert_local_resolution(&mut e, name, rtype, Outcome::Unavailable, now);
        }
    }

    #[test]
    fn serverless_search_domain_ends_expansion_without_trying_later_domains() {
        let mut e = engine();
        let mut vpn = scope("vpn", &[], &["corp.example"], false);
        vpn.level = Level::Link;
        vpn.metric = 50;
        e.set_scopes(vec![e.scopes()[0].clone(), vpn]);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![n("extra.example")]);
        assert_local_resolution(
            &mut e,
            "printer",
            rtype::A,
            Outcome::Unavailable,
            Instant::now(),
        );
    }

    #[test]
    fn serverless_exclusive_search_ignores_other_and_extra_domains() {
        let mut e = engine();
        let mut vpn = scope("vpn", &[], &["corp.example"], false);
        vpn.exclusive = true;
        vpn.level = Level::Addressed;
        vpn.metric = 200;
        e.set_scopes(vec![e.scopes()[0].clone(), vpn]);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![n("extra.example")]);
        assert_local_resolution(
            &mut e,
            "printer",
            rtype::A,
            Outcome::Unavailable,
            Instant::now(),
        );
    }

    #[test]
    fn serverless_exclusive_without_domains_keeps_single_label_notfound() {
        let mut e = engine();
        let mut vpn = scope("vpn", &[], &[], false);
        vpn.exclusive = true;
        vpn.level = Level::Addressed;
        e.set_scopes(vec![e.scopes()[0].clone(), vpn]);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![n("extra.example")]);
        assert_local_resolution(
            &mut e,
            "printer",
            rtype::A,
            Outcome::NotFound,
            Instant::now(),
        );
    }

    #[test]
    fn serverless_routing_ties_keep_snapshot_order() {
        let now = Instant::now();
        // Equal metrics for the exclusive, domain, subnet and default steps.
        for (domains, default_route, exclusive, name, rtype) in [
            (vec![], false, true, "www.example.com", rtype::A),
            (
                vec!["corp.example"],
                false,
                false,
                "git.corp.example",
                rtype::A,
            ),
            (vec![], false, false, "7.2.0.10.in-addr.arpa", rtype::PTR),
            (vec![], true, false, "www.example.com", rtype::A),
        ] {
            let mut first = scope("first", &[], &domains, default_route);
            first.exclusive = exclusive;
            let mut second = scope("second", &["10.9.0.1"], &domains, default_route);
            second.exclusive = exclusive;
            let mut e = Engine::new(1);
            e.set_scopes(vec![first.clone(), second.clone()]);
            assert_local_resolution(&mut e, name, rtype, Outcome::Unavailable, now);
            // Reversing only snapshot order gives the serverful peer the question.
            let mut e = Engine::new(1);
            e.set_scopes(vec![second, first]);
            let actions = e.resolve(1, name, rtype, false, now);
            assert_eq!(actions.len(), 1);
            let (_, server, _) = sent(&actions);
            assert_eq!(server, "10.9.0.1".parse::<IpAddr>().unwrap());
        }
    }

    #[test]
    fn serverless_nonclaimant_is_skipped_at_lowest_metric_step() {
        let mut e = Engine::new(1);
        let mut serverless = scope("serverless", &[], &[], false);
        serverless.metric = 1;
        let mut usable = scope("usable", &["10.8.0.1"], &[], false);
        usable.metric = 200;
        e.set_scopes(vec![serverless, usable]);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![]);
        let actions = e.resolve(1, "www.example.com", rtype::A, false, Instant::now());
        assert_eq!(actions.len(), 1);
        let (_, server, _) = sent(&actions);
        assert_eq!(server, "10.8.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn serverless_nonclaimant_allows_fallback_when_no_earlier_step_matches() {
        let mut e = Engine::new(1);
        e.set_scopes(vec![scope("serverless", &[], &["corp.example"], false)]);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![n("extra.example")]);
        let actions = e.resolve(1, "www.example.com", rtype::A, false, Instant::now());
        assert_eq!(actions.len(), 1);
        let (_, server, _) = sent(&actions);
        assert_eq!(server, "9.9.9.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn below_link_scopes_do_not_route_or_expand_names() {
        let now = Instant::now();
        for servers in [vec![], vec!["10.8.0.1"]] {
            let mut ignored = scope("ignored", &servers, &["corp.example"], true);
            ignored.level = Level::Absent;
            ignored.metric = 1;
            ignored.exclusive = true;
            for (name, rtype, expected) in [
                ("www.example.com", rtype::A, "www.example.com"),
                ("git.corp.example", rtype::A, "git.corp.example"),
                ("7.2.0.10.in-addr.arpa", rtype::PTR, "7.2.0.10.in-addr.arpa"),
                ("printer", rtype::A, "printer.lan"),
            ] {
                let mut e = engine();
                e.set_scopes(vec![ignored.clone(), e.scopes()[0].clone()]);
                let actions = e.resolve(1, name, rtype, false, now);
                assert_eq!(actions.len(), 1);
                let (_, server, q) = sent(&actions);
                assert_eq!(server, "10.0.2.3".parse::<IpAddr>().unwrap());
                assert_eq!(q.questions[0].name, n(expected));
            }
        }
    }

    #[test]
    fn serverless_exclusive_at_link_is_only_an_ordinary_scope() {
        let now = Instant::now();
        let mut vpn = scope("vpn", &[], &["corp.example"], false);
        vpn.level = Level::Link;
        vpn.exclusive = true;
        let mut e = engine();
        e.set_scopes(vec![e.scopes()[0].clone(), vpn.clone()]);
        let actions = e.resolve(1, "www.example.com", rtype::A, false, now);
        assert_eq!(actions.len(), 1);
        let (_, server, _) = sent(&actions);
        assert_eq!(server, "10.0.2.3".parse::<IpAddr>().unwrap());
        let mut e = engine();
        e.set_scopes(vec![e.scopes()[0].clone(), vpn]);
        assert_local_resolution(
            &mut e,
            "git.corp.example",
            rtype::A,
            Outcome::Unavailable,
            now,
        );
    }

    #[test]
    fn synthetic_answers_still_precede_a_serverless_exclusive_scope() {
        let now = Instant::now();
        let mut e = engine();
        let mut vpn = scope("vpn", &[], &["corp.example"], false);
        vpn.exclusive = true;
        e.set_scopes(vec![vpn]);
        let actions = e.resolve(1, "localhost", rtype::A, false, now);
        assert_eq!(actions.len(), 1);
        let answer = done(&actions);
        assert_eq!(answer.outcome, Outcome::Found);
        assert_eq!(answer.source, Source::Synthetic);
        assert_eq!(answer.records[0].rdata, RData::A(Ipv4Addr::LOCALHOST));
        assert_eq!(e.counters.upstream_sent, 0);
        assert_eq!(e.next_deadline(), None);
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
                _ => vec![Record::new(
                    n("www.example.com"),
                    60,
                    RData::Cname(n("example.com")),
                )],
            };
            for a in e.received(tx, &reply(&q, records, 0), now) {
                if let Action::Done {
                    completion: Completion::Addresses(x),
                    ..
                } = a
                {
                    result = Some(x);
                }
            }
        }
        let r = result.expect("completed");
        assert_eq!(r.outcome, Outcome::Found);
        assert_eq!(r.canonical, n("example.com"));
        assert_eq!(
            r.addresses,
            vec![("1.2.3.4".parse::<IpAddr>().unwrap(), 30)]
        );
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
        assert!(
            e.received(tx, &reply(&wrong_type, vec![], 0), now)
                .is_empty()
        );
        let mut two_questions = q.clone();
        two_questions.questions.push(q.questions[0].clone());
        assert!(
            e.received(tx, &reply(&two_questions, vec![], 0), now)
                .is_empty()
        );
        let mut not_a_response = q.clone();
        not_a_response.header.response = false;
        assert!(
            e.received(tx, &not_a_response.encode().unwrap(), now)
                .is_empty()
        );
        // Answered once; the same bytes again hit a dead transaction.
        let ok = reply(
            &q,
            vec![Record::new(
                n("www.example.com"),
                5,
                RData::A("1.2.3.4".parse().unwrap()),
            )],
            0,
        );
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
        let rec = Record::new(
            n("long.example.com"),
            u32::MAX,
            RData::A("1.2.3.4".parse().unwrap()),
        );
        done(&e.received(tx, &reply(&q, vec![rec], 0), now));
        // Cached, but not forever.
        let a = done(&e.resolve(
            2,
            "long.example.com",
            rtype::A,
            false,
            now + Duration::from_secs(u64::from(MAX_POSITIVE_TTL) - 1),
        ));
        assert_eq!(a.source, Source::Cache);
        sent(&e.resolve(
            3,
            "long.example.com",
            rtype::A,
            false,
            now + Duration::from_secs(u64::from(MAX_POSITIVE_TTL) + 1),
        ));
        // NXDOMAIN with no SOA: not cached at all.
        let (tx, _, q) = sent(&e.resolve(4, "gone.example.com", rtype::A, false, now));
        done(&e.received(tx, &reply(&q, vec![], rcode::NXDOMAIN), now));
        sent(&e.resolve(
            5,
            "gone.example.com",
            rtype::A,
            false,
            now + Duration::from_secs(1),
        ));
        // An NXDOMAIN whose SOA claims a week: capped to minutes.
        let (tx, _, q) = sent(&e.resolve(6, "neg.example.com", rtype::A, false, now));
        let mut m = Message::reply_to(&q);
        m.header.rcode = rcode::NXDOMAIN;
        m.authority.push(Record::new(
            n("example.com"),
            604800,
            RData::Soa {
                mname: n("a"),
                rname: n("b"),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 604800,
            },
        ));
        done(&e.received(tx, &m.encode().unwrap(), now));
        sent(&e.resolve(
            7,
            "neg.example.com",
            rtype::A,
            false,
            now + Duration::from_secs(u64::from(MAX_NEGATIVE_TTL) + 1),
        ));
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
            Action::Done {
                completion: Completion::Addresses(a),
                ..
            } => {
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
    // PEI-1339: all replies below are encoded in memory; Send is inspected,
    // never dispatched. Advance injected time instead of sleeping.
    fn admission_reply(q: &Message, negative: bool) -> Vec<u8> {
        let mut m = Message::reply_to(q);
        if negative {
            m.header.rcode = rcode::NXDOMAIN;
            m.authority.push(Record::new(
                n("example.com"),
                60,
                RData::Soa {
                    mname: n("ns.example.com"),
                    rname: n("hostmaster.example.com"),
                    serial: 1,
                    refresh: 1,
                    retry: 1,
                    expire: 1,
                    minimum: 60,
                },
            ));
        } else {
            m.answers.push(Record::new(
                q.questions[0].name.clone(),
                60,
                RData::A("1.2.3.4".parse().unwrap()),
            ));
        }
        m.encode().unwrap()
    }

    fn late_admission_after_invalidation(kind: u8, negative: bool) {
        let mut e = engine();
        if kind == 2 {
            e.set_scopes(vec![]);
            e.set_fallback(vec!["10.0.2.3".parse().unwrap()], vec![]);
        }
        let now = Instant::now();
        let (tx, old_server, q) = sent(&e.resolve(1, "late.example.com", rtype::A, false, now));
        match kind {
            0 => e.flush(),
            1 => e.set_scopes(vec![scope("lan", &["10.0.2.4"], &["lan"], true)]),
            2 => e.set_fallback(vec!["10.0.2.4".parse().unwrap()], vec![]),
            3 => {
                e.set_scopes(vec![]);
                e.set_scopes(vec![scope("lan", &["10.0.2.3"], &["lan"], true)]);
            }
            _ => unreachable!(),
        }
        assert_eq!(e.in_flight(), 1, "invalidation does not cancel the asker");
        let at = now + Duration::from_millis(100);
        let a = done(&e.received(tx, &admission_reply(&q, negative), at));
        assert_eq!(a.source, Source::Dns);
        assert_eq!(a.server, Some(old_server));
        assert_eq!(
            a.outcome,
            if negative {
                Outcome::NotFound
            } else {
                Outcome::Found
            }
        );
        assert_eq!(e.in_flight(), 0);
        assert_eq!(
            e.cache_entries(),
            0,
            "late reply must not restore flushed state"
        );
        let at = now + Duration::from_millis(200);
        let (fresh, server, q) = sent(&e.resolve(2, "late.example.com", rtype::A, false, at));
        let expected = if kind == 1 || kind == 2 {
            "10.0.2.4"
        } else {
            "10.0.2.3"
        };
        assert_eq!(server, expected.parse::<IpAddr>().unwrap());
        done(&e.received(fresh, &admission_reply(&q, negative), at));
        assert_eq!(e.cache_entries(), 1, "a new request can cache normally");
        let a = done(&e.resolve(3, "late.example.com", rtype::A, false, at));
        assert_eq!(a.source, Source::Cache);
        assert_eq!(a.server, Some(server));
        assert_eq!(
            a.outcome,
            if negative {
                Outcome::NotFound
            } else {
                Outcome::Found
            }
        );
    }

    #[test]
    fn flush_prevents_late_positive_admission() {
        late_admission_after_invalidation(0, false);
    }
    #[test]
    fn flush_prevents_late_negative_admission() {
        late_admission_after_invalidation(0, true);
    }
    #[test]
    fn changed_scope_prevents_late_positive_admission() {
        late_admission_after_invalidation(1, false);
    }
    #[test]
    fn changed_scope_prevents_late_negative_admission() {
        late_admission_after_invalidation(1, true);
    }
    #[test]
    fn changed_fallback_prevents_late_positive_admission() {
        late_admission_after_invalidation(2, false);
    }
    #[test]
    fn changed_fallback_prevents_late_negative_admission() {
        late_admission_after_invalidation(2, true);
    }
    #[test]
    fn removed_and_readded_scope_does_not_restore_late_admission() {
        late_admission_after_invalidation(3, false);
    }

    #[test]
    fn unchanged_scope_configuration_preserves_pending_admission() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "same.example.com", rtype::A, false, now));
        let mut s = e.scopes()[0].clone();
        s.metric += 1;
        s.domains = vec![n("other.example")];
        e.set_scopes(vec![s]);
        done(&e.received(tx, &admission_reply(&q, false), now));
        assert_eq!(
            done(&e.resolve(2, "same.example.com", rtype::A, false, now)).source,
            Source::Cache
        );
    }

    #[test]
    fn unchanged_fallback_servers_preserve_pending_admission() {
        let mut e = Engine::new(42);
        let now = Instant::now();
        e.set_fallback(vec!["10.0.2.3".parse().unwrap()], vec![]);
        let (tx, _, q) = sent(&e.resolve(1, "same.example.com", rtype::A, false, now));
        e.set_fallback(vec!["10.0.2.3".parse().unwrap()], vec![n("new.example")]);
        done(&e.received(tx, &admission_reply(&q, false), now));
        assert_eq!(
            done(&e.resolve(2, "same.example.com", rtype::A, false, now)).source,
            Source::Cache
        );
    }

    #[test]
    fn changing_one_scope_preserves_other_pending_admission() {
        let mut e = engine();
        let now = Instant::now();
        let lan = e.scopes()[0].clone();
        e.set_scopes(vec![
            lan.clone(),
            scope("vpn", &["10.8.0.1"], &["corp.example"], false),
        ]);
        let (tx, _, q) = sent(&e.resolve(1, "same.example.com", rtype::A, false, now));
        e.set_scopes(vec![
            lan,
            scope("vpn", &["10.9.0.1"], &["corp.example"], false),
        ]);
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![]);
        done(&e.received(tx, &admission_reply(&q, false), now));
        assert_eq!(
            done(&e.resolve(2, "same.example.com", rtype::A, false, now)).source,
            Source::Cache
        );
    }

    #[test]
    fn late_invalidated_reply_does_not_overwrite_new_request_answer() {
        let mut e = engine();
        let now = Instant::now();
        let (old_tx, _, old_q) = sent(&e.resolve(1, "race.example.com", rtype::A, false, now));
        e.flush();
        let at = now + Duration::from_millis(100);
        let (new_tx, _, new_q) = sent(&e.resolve(2, "race.example.com", rtype::A, false, at));
        let newer = vec![Record::new(
            n("race.example.com"),
            60,
            RData::A("5.6.7.8".parse().unwrap()),
        )];
        done(&e.received(new_tx, &reply(&new_q, newer.clone(), 0), at));
        done(&e.received(old_tx, &admission_reply(&old_q, false), at));
        let a = done(&e.resolve(3, "race.example.com", rtype::A, false, at));
        assert_eq!(a.source, Source::Cache);
        assert_eq!(
            a.records, newer,
            "the old task must not overwrite the fresh cache entry"
        );
    }

    #[test]
    fn invalidated_udp_task_stays_uncacheable_through_tcp_retry() {
        let mut e = engine();
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "tcp.example.com", rtype::A, false, now));
        e.flush();
        let mut m = Message::reply_to(&q);
        m.header.truncated = true;
        let at = now + Duration::from_millis(100);
        let actions = e.received(tx, &m.encode().unwrap(), at);
        assert!(matches!(
            actions.as_slice(),
            [Action::Send { tcp: true, .. }]
        ));
        let (tx, _, q) = sent(&actions);
        assert_eq!(
            done(&e.received(tx, &admission_reply(&q, false), at)).source,
            Source::Dns
        );
        assert_eq!(e.cache_entries(), 0);
        sent(&e.resolve(2, "tcp.example.com", rtype::A, false, at));
    }

    #[test]
    fn invalidated_task_stays_uncacheable_through_timeout_retry() {
        let mut e = engine();
        let now = Instant::now();
        let (old_tx, _, _) = sent(&e.resolve(1, "retry.example.com", rtype::A, false, now));
        e.set_scopes(vec![scope("lan", &["10.0.2.4"], &["lan"], true)]);
        let at = now + SERVER_TIMEOUT;
        let actions = e.tick(at);
        assert!(actions.contains(&Action::Cancel { tx: old_tx }));
        let (tx, server, q) = sent(&actions);
        assert_eq!(server, "10.0.2.4".parse::<IpAddr>().unwrap());
        assert_eq!(
            done(&e.received(tx, &admission_reply(&q, false), at)).source,
            Source::Dns
        );
        assert_eq!(
            e.cache_entries(),
            0,
            "even a new attempt retains old task invalidation"
        );
    }

    #[test]
    fn invalidated_task_stays_uncacheable_through_search_candidates() {
        let mut e = engine();
        e.set_scopes(vec![scope(
            "lan",
            &["10.0.2.3"],
            &["a.example", "b.example"],
            true,
        )]);
        let now = Instant::now();
        let (tx, _, q) = sent(&e.resolve(1, "printer", rtype::A, false, now));
        e.flush();
        let at = now + Duration::from_millis(100);
        let (tx2, _, q2) = sent(&e.received(tx, &reply(&q, vec![], rcode::NXDOMAIN), at));
        assert_eq!(q2.questions[0].name, n("printer.b.example"));
        assert_eq!(
            e.cache_entries(),
            0,
            "the first negative candidate has zero TTL"
        );
        assert_eq!(
            done(&e.received(tx2, &admission_reply(&q2, false), at)).source,
            Source::Dns
        );
        assert_eq!(
            e.cache_entries(),
            0,
            "the next candidate must not reset admission"
        );
        sent(&e.resolve(2, "printer.b.example", rtype::A, false, at));
    }

    #[test]
    fn flush_keeps_lookup_completion_and_cname_chasing_without_cache_admission() {
        let mut e = engine();
        let now = Instant::now();
        let actions = e.lookup(1, "alias.example.com", Family::Any, now);
        assert_eq!(actions.len(), 2);
        e.flush();
        let mut result = None;
        for action in actions {
            let (tx, _, q) = sent(&[action]);
            let records = if q.questions[0].rtype == rtype::A {
                vec![
                    Record::new(
                        n("alias.example.com"),
                        60,
                        RData::Cname(n("target.example.com")),
                    ),
                    Record::new(
                        n("target.example.com"),
                        60,
                        RData::A("1.2.3.4".parse().unwrap()),
                    ),
                ]
            } else {
                vec![]
            };
            for action in e.received(tx, &reply(&q, records, 0), now + Duration::from_millis(100)) {
                if let Action::Done {
                    completion: Completion::Addresses(a),
                    ..
                } = action
                {
                    result = Some(a);
                }
            }
        }
        let a = result.expect("both families complete the existing lookup");
        assert_eq!(a.outcome, Outcome::Found);
        assert_eq!(a.canonical, n("target.example.com"));
        assert_eq!(
            a.addresses,
            vec![("1.2.3.4".parse::<IpAddr>().unwrap(), 60)]
        );
        assert_eq!(e.cache_entries(), 0);
        assert_eq!(e.in_flight(), 0);
        assert!(e.tick(now + SERVER_TIMEOUT * 2).is_empty());
    }
    #[test]
    fn global_flush_invalidates_all_pending_scopes_including_fallback() {
        let mut e = Engine::new(42);
        let now = Instant::now();
        e.set_fallback(vec!["9.9.9.9".parse().unwrap()], vec![]);
        let fallback = sent(&e.resolve(1, "fallback.example.com", rtype::A, false, now));
        e.set_scopes(vec![
            scope("lan", &["10.0.2.3"], &["lan"], true),
            scope("vpn", &["10.8.0.1"], &["corp.example"], false),
        ]);
        let lan = sent(&e.resolve(2, "lan.example.com", rtype::A, false, now));
        let vpn = sent(&e.resolve(3, "secret.corp.example", rtype::A, false, now));
        assert_eq!(e.in_flight(), 3);
        e.flush();
        for (tx, server, q) in [fallback, lan, vpn] {
            let a = done(&e.received(
                tx,
                &admission_reply(&q, false),
                now + Duration::from_millis(100),
            ));
            assert_eq!(a.source, Source::Dns);
            assert_eq!(a.server, Some(server));
        }
        assert_eq!(e.in_flight(), 0);
        assert_eq!(e.cache_entries(), 0);
    }
}
