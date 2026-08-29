//! The answer cache, keyed by the scope that answered.
//!
//! `(name, type, scope)` rather than `(name, type)`: the same name may
//! legitimately have different answers on the VPN and on the LAN (split
//! horizon), and when an interface goes away or its servers change its
//! answers go with it — nothing learned through a VPN is served after the
//! VPN is down.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use dns::{Name, Record};
use libresolv::Outcome;

/// Entries beyond this evict the soonest-to-expire. Sized for a busy
/// workstation; a resolver with a hundred thousand hot names is not a stub.
pub const MAX_ENTRIES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    name: Name,
    rtype: u16,
    scope: String,
}

impl CacheKey {
    pub fn new(name: &Name, rtype: u16, scope: &str) -> CacheKey {
        CacheKey { name: name.to_lowercase(), rtype, scope: scope.to_owned() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub outcome: Outcome,
    pub records: Vec<Record>,
    pub rcode: u16,
    pub server: IpAddr,
    pub expires: Instant,
}

#[derive(Default)]
pub struct Cache {
    entries: HashMap<CacheKey, Entry>,
}

impl Cache {
    pub fn new() -> Cache {
        Cache::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// A live entry, with its records' TTLs reduced by the time in cache.
    pub fn get(&self, key: &CacheKey, now: Instant) -> Option<Entry> {
        let e = self.entries.get(key)?;
        if e.expires <= now {
            return None;
        }
        let remaining = e.expires.saturating_duration_since(now).as_secs() as u32;
        let mut out = e.clone();
        for r in &mut out.records {
            r.ttl = r.ttl.min(remaining);
        }
        Some(out)
    }

    pub fn insert(&mut self, key: CacheKey, entry: Entry) {
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&key) {
            let now = entry.expires; // any instant works for a sweep
            self.entries.retain(|_, e| e.expires > now.checked_sub(std::time::Duration::from_secs(1)).unwrap_or(now));
            if self.entries.len() >= MAX_ENTRIES {
                if let Some(victim) = self.entries.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| k.clone()) {
                    self.entries.remove(&victim);
                }
            }
        }
        self.entries.insert(key, entry);
    }

    pub fn flush_scope(&mut self, scope: &str) {
        self.entries.retain(|k, _| k.scope != scope);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn entry(expires: Instant) -> Entry {
        Entry { outcome: Outcome::Found, records: vec![], rcode: 0, server: "10.0.0.1".parse().unwrap(), expires }
    }

    #[test]
    fn entries_expire_and_scopes_flush() {
        let mut c = Cache::new();
        let now = Instant::now();
        let k = CacheKey::new(&Name::parse("A.example").unwrap(), 1, "lan");
        c.insert(k.clone(), entry(now + Duration::from_secs(10)));
        assert!(c.get(&CacheKey::new(&Name::parse("a.EXAMPLE").unwrap(), 1, "lan"), now).is_some());
        assert!(c.get(&k, now + Duration::from_secs(10)).is_none());
        assert!(c.get(&CacheKey::new(&Name::parse("a.example").unwrap(), 1, "vpn"), now).is_none());
        c.flush_scope("lan");
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn the_cache_is_bounded() {
        let mut c = Cache::new();
        let now = Instant::now();
        for i in 0..MAX_ENTRIES + 10 {
            let k = CacheKey::new(&Name::parse(&format!("n{i}.example")).unwrap(), 1, "lan");
            c.insert(k, entry(now + Duration::from_secs(100 + i as u64)));
        }
        assert!(c.len() <= MAX_ENTRIES);
    }
}
