//! `Machine\System\Network\Dns`: what the registry tells resolvd.
//!
//! Read whole on start and on every watch event. Everything here is a
//! fallback or an override; the live facts — which interface has which
//! servers — come from netd over its control socket and are never in the
//! registry.

use std::collections::HashMap;
use std::net::IpAddr;

use dns::Name;
use libresolv::RESOLVER_KEY;
use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};

use resolvd::log;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// `FallbackServers`: used only when no interface supplies any.
    pub servers: Vec<IpAddr>,
    /// `ExtraSearchDomains`: applied to single labels after every
    /// interface's own.
    pub search: Vec<Name>,
    /// `Hosts\`: value name = hostname, data = address(es). Exact match,
    /// wins over DNS; answered at every door.
    pub hosts: HashMap<Name, Vec<IpAddr>>,
    /// `ControlSecurity`: the control object's descriptor.
    pub control_security: Option<Vec<u8>>,
}

fn sz(v: &RegValue) -> Option<String> {
    if v.ty != ValueType::SZ && v.ty != ValueType::EXPAND_SZ {
        return None;
    }
    let end = v.data.iter().position(|&b| b == 0).unwrap_or(v.data.len());
    String::from_utf8(v.data[..end].to_vec()).ok()
}

fn multi(v: &RegValue) -> Option<Vec<String>> {
    match v.ty {
        ValueType::MULTI_SZ => Some(
            v.data
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| String::from_utf8(s.to_vec()).ok())
                .collect(),
        ),
        ValueType::SZ | ValueType::EXPAND_SZ => sz(v).map(|s| vec![s]),
        _ => None,
    }
}

fn read(key: &Key, name: &str) -> Option<RegValue> {
    key.query_value(name.as_bytes(), None).ok()
}

fn read_multi(key: &Key, name: &str) -> Vec<String> {
    read(key, name).and_then(|v| multi(&v)).unwrap_or_default()
}

fn open(parent: Option<&Key>, path: &str) -> Option<Key> {
    Key::open(
        parent,
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    )
    .ok()
}

fn addresses(strings: &[String], what: &str) -> Vec<IpAddr> {
    strings
        .iter()
        .filter_map(|s| {
            let r = s.trim().parse().ok();
            if r.is_none() {
                log::warn(format_args!("{what}: ignoring malformed address {s:?}"));
            }
            r
        })
        .collect()
}

pub fn load() -> Config {
    let mut config = Config::default();
    let Some(root) = open(None, RESOLVER_KEY) else {
        return config;
    };
    config.servers = addresses(&read_multi(&root, "FallbackServers"), "Dns FallbackServers");
    config.search = read_multi(&root, "ExtraSearchDomains")
        .iter()
        .filter_map(|d| {
            let r = Name::parse(d).ok().filter(|n| !n.is_root());
            if r.is_none() {
                log::warn(format_args!(
                    "Dns ExtraSearchDomains: ignoring malformed domain {d:?}"
                ));
            }
            r
        })
        .collect();
    config.control_security = read(&root, "ControlSecurity")
        .filter(|v| v.ty == ValueType::BINARY && !v.data.is_empty())
        .map(|v| v.data);
    if let Some(hosts) = open(Some(&root), "Hosts") {
        for v in hosts.values(None) {
            let Ok(v) = v else { continue };
            let Ok(name) = String::from_utf8(v.name.clone()) else {
                continue;
            };
            let Ok(name) = Name::parse(&name) else {
                log::warn(format_args!("Dns Hosts: ignoring malformed name {name:?}"));
                continue;
            };
            if name.is_root() {
                continue;
            }
            let value = RegValue {
                sequence: 0,
                ty: v.ty,
                data: v.data.clone(),
                layer: Vec::new(),
            };
            let addrs = addresses(&multi(&value).unwrap_or_default(), "Dns Hosts");
            if !addrs.is_empty() {
                config.hosts.insert(name, addrs);
            }
        }
    }
    config
}

/// Arm a subtree watch. On `Machine\System\Network`, not `Dns`
/// itself: the latter need not exist at boot (the first `reg new` creates
/// it), and a watch on a key that is not there cannot see it appear.
pub fn watch() -> peios::Result<Key> {
    use peios::registry::NotifyFilter;
    let key = Key::open(
        None,
        libnetd::NETWORK_KEY,
        KeyAccess::NOTIFY,
        OpenFlags::empty(),
    )?;
    key.notify(NotifyFilter::ALL, true)?;
    key.set_nonblocking(true)?;
    Ok(key)
}
