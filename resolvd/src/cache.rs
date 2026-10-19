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
use resolvd_core::Outcome;

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
        CacheKey {
            name: name.to_lowercase(),
            rtype,
            scope: scope.to_owned(),
        }
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

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// A live entry, with its records' TTLs reduced by the time in cache.
    /// Remove the requested entry if it has expired.
    pub fn get(&mut self, key: &CacheKey, now: Instant) -> Option<Entry> {
        let e = self.entries.get(key)?;
        if e.expires <= now {
            self.entries.remove(key);
            return None;
        }
        let remaining = e.expires.saturating_duration_since(now).as_secs() as u32;
        let mut out = e.clone();
        for r in &mut out.records {
            r.ttl = r.ttl.min(remaining);
        }
        Some(out)
    }

    pub fn insert(&mut self, key: CacheKey, entry: Entry, now: Instant) {
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&key) {
            self.entries.retain(|_, e| e.expires > now);
            if self.entries.len() >= MAX_ENTRIES
                && let Some(victim) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, e)| e.expires)
                    .map(|(k, _)| k.clone())
            {
                self.entries.remove(&victim);
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
        Entry {
            outcome: Outcome::Found,
            records: vec![],
            rcode: 0,
            server: "10.0.0.1".parse().unwrap(),
            expires,
        }
    }

    #[test]
    fn entries_expire_and_scopes_flush() {
        let mut c = Cache::new();
        let now = Instant::now();
        let k = CacheKey::new(&Name::parse("A.example").unwrap(), 1, "lan");
        c.insert(k.clone(), entry(now + Duration::from_secs(10)), now);
        assert!(
            c.get(
                &CacheKey::new(&Name::parse("a.EXAMPLE").unwrap(), 1, "lan"),
                now
            )
            .is_some()
        );
        assert!(c.get(&k, now + Duration::from_secs(10)).is_none());
        assert!(
            c.get(
                &CacheKey::new(&Name::parse("a.example").unwrap(), 1, "vpn"),
                now
            )
            .is_none()
        );
        c.flush_scope("lan");
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn the_cache_is_bounded() {
        let mut c = Cache::new();
        let now = Instant::now();
        for i in 0..MAX_ENTRIES + 10 {
            let k = CacheKey::new(&Name::parse(&format!("n{i}.example")).unwrap(), 1, "lan");
            c.insert(k, entry(now + Duration::from_secs(100 + i as u64)), now);
        }
        assert!(c.len() <= MAX_ENTRIES);
    }

    fn key(i: usize) -> CacheKey {
        CacheKey::new(&Name::parse(&format!("n{i}.example")).unwrap(), 1, "lan")
    }

    #[test]
    fn a_long_lived_insert_evicts_only_the_soonest_live_entry() {
        let mut c = Cache::new();
        let now = Instant::now();
        for i in 0..MAX_ENTRIES {
            let ttl = if i == 0 { 60 } else { 300 };
            c.insert(key(i), entry(now + Duration::from_secs(ttl)), now);
        }
        assert_eq!(c.len(), MAX_ENTRIES);

        c.insert(
            key(MAX_ENTRIES),
            entry(now + Duration::from_secs(86_400)),
            now,
        );

        assert_eq!(c.len(), MAX_ENTRIES);
        assert!(c.get(&key(0), now).is_none());
        for i in 1..=MAX_ENTRIES {
            assert!(c.get(&key(i), now).is_some(), "lost live entry {i}");
        }
    }

    #[test]
    fn a_full_cache_sweeps_expired_entries_before_evicting_live_ones() {
        let mut c = Cache::new();
        let start = Instant::now();
        let now = start + Duration::from_secs(2);
        for i in 0..MAX_ENTRIES {
            let expires = match i {
                0 | 1 => start + Duration::from_secs(1),
                2 => now,
                3 => now + Duration::from_nanos(1),
                _ => now + Duration::from_secs(300),
            };
            c.insert(key(i), entry(expires), start);
        }
        assert_eq!(c.len(), MAX_ENTRIES);

        c.insert(
            key(MAX_ENTRIES),
            entry(now + Duration::from_secs(86_400)),
            now,
        );

        assert_eq!(c.len(), MAX_ENTRIES - 2);
        for i in 0..3 {
            assert!(c.get(&key(i), now).is_none());
        }
        for i in 3..=MAX_ENTRIES {
            assert!(c.get(&key(i), now).is_some(), "lost live entry {i}");
        }
    }

    #[test]
    fn an_expired_lookup_removes_only_the_requested_entry() {
        let mut c = Cache::new();
        let now = Instant::now();
        let expires = now + Duration::from_secs(10);
        c.insert(key(0), entry(expires), now);
        c.insert(key(1), entry(expires), now);
        c.insert(key(2), entry(expires + Duration::from_secs(10)), now);

        assert!(c.get(&key(0), expires).is_none());
        assert_eq!(c.len(), 2);
        assert!(c.get(&key(0), expires).is_none());
        assert_eq!(c.len(), 2);
        assert!(c.get(&key(2), expires).is_some());
        // An unrelated expired entry still occupies a slot until touched
        // or swept under capacity pressure: this is not background pruning.
        assert!(c.get(&key(1), expires).is_none());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn an_overwrite_at_capacity_preserves_every_other_entry() {
        let mut c = Cache::new();
        let now = Instant::now();
        let original = entry(now + Duration::from_secs(60));
        for i in 0..MAX_ENTRIES {
            c.insert(key(i), original.clone(), now);
        }
        let replacement = entry(now + Duration::from_secs(86_400));
        c.insert(key(0), replacement.clone(), now);

        assert_eq!(c.len(), MAX_ENTRIES);
        assert_eq!(c.get(&key(0), now), Some(replacement));
        for i in 1..MAX_ENTRIES {
            assert_eq!(c.get(&key(i), now), Some(original.clone()));
        }
    }

    #[test]
    fn record_ttls_age_without_expiring_a_live_subsecond_entry() {
        let mut c = Cache::new();
        let now = Instant::now();
        let mut answer = entry(now + Duration::from_secs(10));
        answer.records = vec![
            Record::new(
                Name::parse("n0.example").unwrap(),
                30,
                dns::RData::A("1.2.3.4".parse().unwrap()),
            ),
            Record::new(
                Name::parse("n0.example").unwrap(),
                3,
                dns::RData::A("1.2.3.5".parse().unwrap()),
            ),
        ];
        c.insert(key(0), answer, now);

        let hit = c.get(&key(0), now + Duration::from_millis(2_500)).unwrap();
        assert_eq!(
            hit.records.iter().map(|r| r.ttl).collect::<Vec<_>>(),
            vec![7, 3]
        );
        let hit = c.get(&key(0), now + Duration::from_millis(9_500)).unwrap();
        assert_eq!(
            hit.records.iter().map(|r| r.ttl).collect::<Vec<_>>(),
            vec![0, 0]
        );
        assert_eq!(c.len(), 1);
        assert!(c.get(&key(0), now + Duration::from_secs(10)).is_none());
        assert!(c.is_empty());
    }

    #[test]
    fn negative_answers_keep_their_outcome_until_exact_expiry() {
        let mut c = Cache::new();
        let now = Instant::now();
        let mut answer = entry(now + Duration::from_secs(10));
        answer.outcome = Outcome::NotFound;
        answer.rcode = u16::from(dns::rcode::NXDOMAIN);
        c.insert(key(0), answer.clone(), now);

        assert_eq!(
            c.get(&key(0), now + Duration::from_millis(9_999)),
            Some(answer)
        );
        assert!(c.get(&key(0), now + Duration::from_secs(10)).is_none());
        assert!(c.is_empty());
    }

    #[test]
    fn keys_fold_case_but_separate_types_and_scopes_and_flush_selectively() {
        let mut c = Cache::new();
        let now = Instant::now();
        let name = Name::parse("A.example").unwrap();
        let a_lan = CacheKey::new(&name, dns::rtype::A, "lan");
        let a_vpn = CacheKey::new(&name, dns::rtype::A, "vpn");
        let aaaa_lan = CacheKey::new(&name, dns::rtype::AAAA, "lan");
        c.insert(a_lan.clone(), entry(now + Duration::from_secs(10)), now);
        c.insert(a_vpn.clone(), entry(now + Duration::from_secs(20)), now);
        c.insert(aaaa_lan.clone(), entry(now + Duration::from_secs(30)), now);

        let lower = CacheKey::new(&Name::parse("a.EXAMPLE").unwrap(), dns::rtype::A, "lan");
        assert_eq!(c.get(&lower, now), c.get(&a_lan, now));
        assert_ne!(c.get(&a_lan, now), c.get(&a_vpn, now));
        assert_ne!(c.get(&a_lan, now), c.get(&aaaa_lan, now));
        assert_eq!(c.len(), 3);
        c.flush_scope("lan");
        assert!(c.get(&a_lan, now).is_none());
        assert!(c.get(&aaaa_lan, now).is_none());
        assert!(c.get(&a_vpn, now).is_some());
        assert_eq!(c.len(), 1);
        c.clear();
        assert!(c.is_empty());
        assert!(c.get(&a_vpn, now).is_none());
    }
}
