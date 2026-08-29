//! resolv — the resolvd operator command.
//!
//! ```text
//! resolv status                 scopes, servers, cache, counters
//! resolv query <name> [type]    one question, with where the answer came from
//! resolv lookup <name>          the addresses of a name, as getaddrinfo sees them
//! resolv reverse <address>      the names of an address
//! resolv flush                  drop the cache (RESOLVER_CONTROL)
//! ```
//!
//! Owns nothing: every verb is one request on the native socket.

use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use libresolv::{Family, Outcome, Reply, Request, SOCKET_PATH};

fn call(request: &Request) -> Result<Reply, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH).map_err(|e| format!("resolvd is not reachable at {SOCKET_PATH}: {e}"))?;
    libresolv::call(&mut stream, request).map_err(|e| e.to_string())
}

fn outcome_code(o: Outcome) -> ExitCode {
    match o {
        Outcome::Found => ExitCode::SUCCESS,
        Outcome::NotFound => ExitCode::from(2),
        Outcome::Unavailable => ExitCode::from(3),
    }
}

fn status() -> ExitCode {
    let s = match call(&Request::Status) {
        Ok(Reply::Status(s)) => s,
        Ok(Reply::Error(e)) | Err(e) => {
            eprintln!("resolv: {e}");
            return ExitCode::FAILURE;
        }
        Ok(_) => return ExitCode::FAILURE,
    };
    println!("hostname   {}", if s.hostname.is_empty() { "(unset)" } else { &s.hostname });
    println!("netd       {}", if s.netd { "connected" } else { "not connected" });
    println!("cache      {} entries", s.cache_entries);
    if s.scopes.is_empty() {
        println!("scopes     (none)");
    }
    for sc in &s.scopes {
        println!();
        let mut flags = Vec::new();
        if sc.default_route {
            flags.push("default-route");
        }
        if sc.exclusive {
            flags.push("exclusive");
        }
        println!("{}  metric {}{}", sc.interface, sc.metric, if flags.is_empty() { String::new() } else { format!("  [{}]", flags.join(", ")) });
        for server in &sc.servers {
            let demoted = if sc.demoted.contains(server) { "  (demoted)" } else { "" };
            println!("  server   {server}{demoted}");
        }
        for d in &sc.domains {
            println!("  domain   {d}");
        }
        for n in &sc.subnets {
            println!("  subnet   {n}");
        }
    }
    if !s.fallback_servers.is_empty() {
        println!();
        println!("fallback   {}", s.fallback_servers.join(" "));
    }
    let c = &s.counters;
    println!();
    println!(
        "queries {}  synthetic {}  cache-hits {}  upstream sent {} answered {} failed {}  refused {}",
        c.queries, c.synthetic, c.cache_hits, c.upstream_sent, c.upstream_answered, c.upstream_failed, c.refused
    );
    ExitCode::SUCCESS
}

fn query(name: &str, rtype: &str, no_cache: bool) -> ExitCode {
    let Some(rtype) = dns::rtype::parse(rtype) else {
        eprintln!("resolv: unknown record type {rtype:?}");
        return ExitCode::FAILURE;
    };
    match call(&Request::Resolve { name: name.to_owned(), rtype, no_cache }) {
        Ok(Reply::Answer(a)) => {
            println!(
                "{}  {}{}{}  validation {}",
                a.outcome.as_str(),
                a.source,
                a.server.as_ref().map(|s| format!(" via {s}")).unwrap_or_default(),
                a.interface.as_ref().map(|i| format!(" on {i}")).unwrap_or_default(),
                a.validation.as_str()
            );
            if a.outcome == Outcome::Found && a.rcode != 0 {
                println!("rcode {}", dns::rcode::name(a.rcode as u8));
            }
            for r in &a.records {
                println!("{}\t{}\t{}\t{}", r.name, r.ttl, dns::rtype::name(r.rtype), r.text);
            }
            outcome_code(a.outcome)
        }
        Ok(Reply::Error(e)) | Err(e) => {
            eprintln!("resolv: {e}");
            ExitCode::FAILURE
        }
        Ok(_) => ExitCode::FAILURE,
    }
}

fn lookup(name: &str) -> ExitCode {
    match call(&Request::Lookup { name: name.to_owned(), family: Family::Any }) {
        Ok(Reply::Addresses(a)) => {
            println!("{}  {}  canonical {}", a.outcome.as_str(), a.source, a.canonical);
            for x in &a.addresses {
                println!("{}\t{}", x.address, x.ttl);
            }
            outcome_code(a.outcome)
        }
        Ok(Reply::Error(e)) | Err(e) => {
            eprintln!("resolv: {e}");
            ExitCode::FAILURE
        }
        Ok(_) => ExitCode::FAILURE,
    }
}

fn reverse(address: &str) -> ExitCode {
    let Ok(address) = address.parse() else {
        eprintln!("resolv: {address:?} is not an address");
        return ExitCode::FAILURE;
    };
    match call(&Request::Reverse { address }) {
        Ok(Reply::Answer(a)) => {
            println!("{}  {}", a.outcome.as_str(), a.source);
            for r in &a.records {
                println!("{}", r.text);
            }
            outcome_code(a.outcome)
        }
        Ok(Reply::Error(e)) | Err(e) => {
            eprintln!("resolv: {e}");
            ExitCode::FAILURE
        }
        Ok(_) => ExitCode::FAILURE,
    }
}

fn flush() -> ExitCode {
    match call(&Request::Flush) {
        Ok(Reply::Ok) => ExitCode::SUCCESS,
        Ok(Reply::Error(e)) | Err(e) => {
            eprintln!("resolv: {e}");
            ExitCode::FAILURE
        }
        Ok(_) => ExitCode::FAILURE,
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: resolv status | query <name> [type] [--no-cache] | lookup <name> | reverse <address> | flush");
    ExitCode::from(64)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let no_cache = args.iter().any(|a| a == "--no-cache");
    let args: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != "--no-cache").collect();
    match args.as_slice() {
        ["status"] => status(),
        ["query", name] => query(name, "A", no_cache),
        ["query", name, rtype] => query(name, rtype, no_cache),
        ["lookup", name] => lookup(name),
        ["reverse", address] => reverse(address),
        ["flush"] => flush(),
        _ => usage(),
    }
}
