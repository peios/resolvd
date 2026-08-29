//! resolvd — the Peios stub resolver.
//!
//! One thread, one `poll`. Inputs: the native socket, the stub listener
//! (UDP and TCP), sockets to upstream servers, the netd channel, the
//! registry watch, and time. Every door hands its question to the one
//! [`engine::Engine`] and sends back whatever it says; nothing here decides
//! an answer.

mod cache;
mod config;
mod control;
mod engine;
mod log;
mod netd_link;
mod stub;
mod upstream;

use std::collections::HashMap;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::process::ExitCode;
use std::time::Instant;

use dns::{Name, Record};
use libnetd::{DnsScope, Snapshot};
use libresolv::{Addresses, Answer, AddressOut, Counters, Family, RecordOut, Reply, Request, ScopeStatus, StatusReport, Validation};
use peios::registry::Key;

use engine::{Action, Completion, Engine, Qid, Scope};
use stub::{Incoming, Origin};

/// Who is waiting for `qid`.
enum Waiter {
    Native(UnixStream),
    Stub(Origin),
}

struct Resolvd {
    engine: Engine,
    config: config::Config,
    control: control::ControlObject,
    upstream: upstream::Upstream,
    stub: stub::Stub,
    netd: netd_link::NetdLink,
    clients: HashMap<u64, control::Client>,
    waiters: HashMap<Qid, Waiter>,
    next_id: u64,
}

impl Resolvd {
    fn fresh_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn apply_config(&mut self, fresh: config::Config) {
        if fresh == self.config {
            return;
        }
        self.control = control::ControlObject::new(fresh.control_security.as_deref());
        self.engine.set_fallback(fresh.servers.clone(), fresh.search.clone());
        self.engine.set_hosts(fresh.hosts.clone());
        self.config = fresh;
        log::info(format_args!("configuration changed"));
    }

    fn apply_snapshot(&mut self, snapshot: Snapshot) {
        // netd's name when it set one; else whatever the kernel has.
        let hostname = if snapshot.hostname.is_empty() { kernel_hostname() } else { Some(snapshot.hostname.clone()) };
        self.engine.set_hostname(hostname.as_deref());
        let scopes: Vec<Scope> = snapshot.scopes.iter().map(to_scope).collect();
        let summary: Vec<String> = scopes
            .iter()
            .map(|s| format!("{}: {} server(s), {} domain(s){}", s.interface, s.servers.len(), s.domains.len(), if s.default_route { ", default" } else { "" }))
            .collect();
        log::info(format_args!("netd: {}", if summary.is_empty() { "no scopes".to_owned() } else { summary.join("; ") }));
        self.engine.set_scopes(scopes);
    }

    /// Carry out what the engine asked for.
    fn perform(&mut self, actions: Vec<Action>, now: Instant) {
        let mut follow_ups = Vec::new();
        for action in actions {
            match action {
                Action::Send { tx, server, tcp, payload } => {
                    if let Err(e) = self.upstream.send(tx, server, tcp, payload) {
                        log::warn(format_args!("upstream {server}: {e}"));
                        follow_ups.extend(self.engine.failed(tx, now));
                    }
                }
                Action::Cancel { tx } => self.upstream.cancel(tx),
                Action::Done { qid, completion } => self.deliver(qid, completion),
            }
        }
        if !follow_ups.is_empty() {
            self.perform(follow_ups, now);
        }
    }

    fn deliver(&mut self, qid: Qid, completion: Completion) {
        let Some(waiter) = self.waiters.remove(&qid) else { return };
        match (waiter, completion) {
            (Waiter::Native(mut stream), Completion::Answer(a)) => control::respond(&mut stream, &Reply::Answer(to_answer(&a))),
            (Waiter::Native(mut stream), Completion::Addresses(a)) => control::respond(&mut stream, &Reply::Addresses(to_addresses(&a))),
            (Waiter::Stub(origin), Completion::Answer(a)) => self.stub.answer(origin, &a),
            (Waiter::Stub(_), Completion::Addresses(_)) => {}
        }
    }

    fn handle_request(&mut self, mut stream: UnixStream, request: Request, now: Instant) {
        if !self.control.permits(&stream, request.required_right()) {
            control::respond(&mut stream, &Reply::Error("access denied".into()));
            return;
        }
        let qid = self.fresh_id();
        let actions = match request {
            Request::Status => {
                control::respond(&mut stream, &Reply::Status(self.status(now)));
                return;
            }
            Request::Flush => {
                self.engine.flush();
                log::info(format_args!("cache flushed"));
                control::respond(&mut stream, &Reply::Ok);
                return;
            }
            Request::Resolve { name, rtype, no_cache } => self.engine.resolve(qid, &name, rtype, no_cache, now),
            Request::Lookup { name, family } => {
                let family = match family {
                    Family::Any => engine::Family::Any,
                    Family::V4 => engine::Family::V4,
                    Family::V6 => engine::Family::V6,
                };
                self.engine.lookup(qid, &name, family, now)
            }
            Request::Reverse { address } => self.engine.reverse(qid, address, now),
        };
        self.waiters.insert(qid, Waiter::Native(stream));
        self.perform(actions, now);
    }

    fn handle_stub(&mut self, incoming: Vec<Incoming>, now: Instant) {
        for i in incoming {
            let Incoming::Query { origin } = i else { continue };
            let question = match &origin {
                Origin::Udp { query, .. } | Origin::Tcp { query, .. } => query.question().cloned(),
            };
            let Some(question) = question else { continue };
            let qid = self.fresh_id();
            self.waiters.insert(qid, Waiter::Stub(origin));
            let actions = self.engine.resolve_question(qid, &question, now);
            self.perform(actions, now);
        }
    }

    fn status(&self, now: Instant) -> StatusReport {
        let demoted = self.engine.demoted(now);
        let c = &self.engine.counters;
        StatusReport {
            hostname: self.engine.hostname().map(|n| n.to_string()).unwrap_or_default(),
            netd: self.netd.connected(),
            scopes: self
                .engine
                .scopes()
                .iter()
                .map(|s| ScopeStatus {
                    interface: s.interface.clone(),
                    servers: s.servers.iter().map(|a| a.to_string()).collect(),
                    domains: s.domains.iter().map(|d| d.to_string()).collect(),
                    default_route: s.default_route,
                    exclusive: s.exclusive,
                    metric: s.metric,
                    subnets: s.addresses.iter().map(|(a, p)| format!("{a}/{p}")).collect(),
                    demoted: s.servers.iter().filter(|a| demoted.contains(a)).map(|a| a.to_string()).collect(),
                })
                .collect(),
            fallback_servers: self.engine.fallback_servers().iter().map(|a| a.to_string()).collect(),
            cache_entries: self.engine.cache_entries() as u64,
            counters: Counters {
                queries: c.queries,
                synthetic: c.synthetic,
                cache_hits: c.cache_hits,
                upstream_sent: c.upstream_sent,
                upstream_answered: c.upstream_answered,
                upstream_failed: c.upstream_failed,
                refused: c.refused,
            },
        }
    }
}

fn to_scope(s: &DnsScope) -> Scope {
    Scope {
        id: s.ifid.clone(),
        interface: s.name.clone(),
        servers: s.servers.iter().filter_map(|a| a.parse().ok()).collect(),
        domains: s.domains.iter().filter_map(|d| Name::parse(d).ok()).filter(|n| !n.is_root()).collect(),
        addresses: s
            .addresses
            .iter()
            .filter_map(|c| {
                let (a, p) = c.split_once('/')?;
                Some((a.parse::<IpAddr>().ok()?, p.parse().ok()?))
            })
            .collect(),
        default_route: s.default_route,
        exclusive: s.exclusive,
        metric: s.metric,
        level: s.level,
    }
}

fn to_record(r: &Record) -> RecordOut {
    RecordOut { name: r.name.to_string(), rtype: r.rtype, ttl: r.ttl, data: r.rdata_bytes(), text: r.rdata_text() }
}

fn to_answer(a: &engine::Answer) -> Answer {
    Answer {
        outcome: a.outcome,
        records: a.records.iter().map(to_record).collect(),
        source: a.source.as_str().to_owned(),
        server: a.server.map(|s| s.to_string()),
        interface: a.interface.clone(),
        validation: Validation::Unvalidated,
        rcode: a.rcode,
    }
}

fn to_addresses(a: &engine::Addresses) -> Addresses {
    Addresses {
        outcome: a.outcome,
        canonical: a.canonical.to_string(),
        addresses: a.addresses.iter().map(|(address, ttl)| AddressOut { address: *address, ttl: *ttl }).collect(),
        source: a.source.as_str().to_owned(),
        validation: Validation::Unvalidated,
    }
}

fn kernel_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is live and its length is its own.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[..end]).into_owned();
    if s.is_empty() || s == "(none)" { None } else { Some(s) }
}

fn notify_ready() {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else { return };
    match UnixDatagram::unbound() {
        Ok(s) => {
            if let Err(e) = s.send_to(b"READY=1", &path) {
                log::warn(format_args!("readiness notify: {e}"));
            }
        }
        Err(e) => log::warn(format_args!("readiness notify: {e}")),
    }
}

fn seed() -> u64 {
    let mut b = [0u8; 8];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b)).is_ok() {
        return u64::from_le_bytes(b);
    }
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1)
}

fn main() -> ExitCode {
    let listener = match control::listen() {
        Ok(l) => l,
        Err(e) => {
            log::error(format_args!("native socket: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let stub = match stub::Stub::open() {
        Ok(s) => s,
        Err(e) => {
            log::error(format_args!("stub listener on {}:{}: {e}", libresolv::STUB_ADDRESS, libresolv::STUB_PORT));
            return ExitCode::FAILURE;
        }
    };
    let now = Instant::now();
    let config = config::load();
    let mut watch: Option<Key> = match config::watch() {
        Ok(k) => Some(k),
        Err(e) => {
            log::warn(format_args!("registry watch unavailable ({e}); configuration is read once"));
            None
        }
    };
    let mut engine = Engine::new(seed());
    engine.set_hostname(kernel_hostname().as_deref());
    engine.set_fallback(config.servers.clone(), config.search.clone());
    engine.set_hosts(config.hosts.clone());
    let control = control::ControlObject::new(config.control_security.as_deref());
    let mut r = Resolvd {
        engine,
        config,
        control,
        upstream: upstream::Upstream::new(),
        stub,
        netd: netd_link::NetdLink::new(now),
        clients: HashMap::new(),
        waiters: HashMap::new(),
        next_id: 1,
    };
    r.netd.maintain(now);
    log::info(format_args!("listening on {} and {}:{}", libresolv::SOCKET_PATH, libresolv::STUB_ADDRESS, libresolv::STUB_PORT));
    notify_ready();

    let mut watch_buffer = vec![0u8; 16384];
    loop {
        let now = Instant::now();
        let mut deadline: Option<Instant> = None;
        let mut consider = |t: Option<Instant>| {
            if let Some(t) = t {
                deadline = Some(deadline.map_or(t, |d: Instant| d.min(t)));
            }
        };
        consider(r.engine.next_deadline());
        consider(r.netd.next_deadline());
        consider(r.stub.next_deadline());
        consider(r.clients.values().map(|c| c.since + control::CLIENT_TIMEOUT).min());
        let timeout_ms: i32 = match deadline {
            Some(t) => t.saturating_duration_since(now).as_millis().min(i32::MAX as u128) as i32,
            None => -1,
        };

        // Poll set: [listener, stub udp, stub tcp, netd?, watch?, clients..., stub clients..., upstream...]
        let mut fds: Vec<libc::pollfd> = Vec::new();
        fn push(fds: &mut Vec<libc::pollfd>, fd: i32, events: i16) -> usize {
            fds.push(libc::pollfd { fd, events, revents: 0 });
            fds.len() - 1
        }
        push(&mut fds, listener.as_raw_fd(), libc::POLLIN);
        push(&mut fds, r.stub.udp.as_raw_fd(), libc::POLLIN);
        push(&mut fds, r.stub.tcp.as_raw_fd(), libc::POLLIN);
        let netd_slot = r.netd.fd().map(|fd| push(&mut fds, fd, libc::POLLIN));
        let watch_slot = watch.as_ref().map(|w| push(&mut fds, w.as_raw_fd(), libc::POLLIN));
        let client_slots: Vec<(u64, usize)> = r.clients.iter().map(|(id, c)| (*id, push(&mut fds, c.stream.as_raw_fd(), libc::POLLIN))).collect();
        let stub_slots: Vec<(u64, usize)> = r.stub.client_fds().into_iter().map(|(id, fd)| (id, push(&mut fds, fd, libc::POLLIN))).collect();
        let upstream_slots: Vec<(u64, usize)> = r.upstream.fds().into_iter().map(|(tx, fd, ev)| (tx, push(&mut fds, fd, ev))).collect();

        // SAFETY: `fds` is a live, exclusively borrowed array for the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::error(format_args!("poll: {e}"));
            return ExitCode::FAILURE;
        }
        let now = Instant::now();

        // Upstream first: answers waiting are answers owed.
        for (tx, slot) in &upstream_slots {
            if fds[*slot].revents == 0 {
                continue;
            }
            match r.upstream.service(*tx, fds[*slot].revents) {
                Some(upstream::Event::Received(bytes)) => {
                    let actions = r.engine.received(*tx, &bytes, now);
                    r.perform(actions, now);
                }
                Some(upstream::Event::Failed) => {
                    let actions = r.engine.failed(*tx, now);
                    r.perform(actions, now);
                }
                None => {}
            }
        }
        if fds[1].revents != 0 {
            let incoming = r.stub.receive_udp();
            r.handle_stub(incoming, now);
        }
        if fds[2].revents != 0 {
            r.stub.accept(now);
        }
        for (id, slot) in &stub_slots {
            if fds[*slot].revents != 0 {
                if let Some(incoming) = r.stub.service_client(*id) {
                    r.handle_stub(vec![incoming], now);
                }
            }
        }
        if fds[0].revents != 0 {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Some(client) = control::Client::new(stream, now) {
                            let id = r.fresh_id();
                            r.clients.insert(id, client);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::warn(format_args!("native accept: {e}"));
                        break;
                    }
                }
            }
        }
        for (id, slot) in &client_slots {
            if fds[*slot].revents == 0 {
                continue;
            }
            let Some(client) = r.clients.get_mut(id) else { continue };
            match client.read() {
                control::Progress::Incomplete => {}
                control::Progress::Closed => {
                    r.clients.remove(id);
                }
                control::Progress::Request(request) => {
                    let client = r.clients.remove(id).expect("present");
                    r.handle_request(client.stream, request, now);
                }
            }
        }
        if let Some(slot) = netd_slot {
            if fds[slot].revents != 0 {
                for snapshot in r.netd.service(now) {
                    r.apply_snapshot(snapshot);
                }
            }
        }
        if let Some(slot) = watch_slot {
            if fds[slot].revents != 0 {
                if let Some(w) = &watch {
                    match w.read_watch_events(&mut watch_buffer) {
                        Ok(events) if !events.is_empty() => r.apply_config(config::load()),
                        Ok(_) => {}
                        Err(e) => {
                            log::warn(format_args!("registry watch: {e}; re-arming"));
                            watch = config::watch().ok();
                        }
                    }
                }
            }
        }

        // Timers.
        let actions = r.engine.tick(now);
        r.perform(actions, now);
        r.netd.maintain(now);
        r.stub.expire(now);
        r.clients.retain(|_, c| now.duration_since(c.since) < control::CLIENT_TIMEOUT);
    }
}
