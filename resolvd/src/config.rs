//! `Machine\System\Network\Dns`: what the registry tells resolvd.
//!
//! Read whole on start and on every watch event. Everything here is a
//! fallback or an override; the live facts — which interface has which
//! servers — come from netd over its control socket and are never in the
//! registry.

use std::collections::HashMap;
use std::net::IpAddr;

use dns::Name;
use std::io;
use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};
#[path = "registry_reader.rs"]
mod reader;
use reader::{Reader, open, multi, strings};
use resolvd_core::RESOLVER_KEY;

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

pub fn load() -> io::Result<Config> {
    let root = open(None, RESOLVER_KEY)?;
    load_from(root.as_ref())
}

fn load_from(root: Option<&impl Reader>) -> io::Result<Config> {
    let mut config = Config::default();
    let Some(root) = root else {
        return Ok(config);
    };
    config.servers = addresses(
        &strings(root, "FallbackServers")?.unwrap_or_default(),
        "Dns FallbackServers",
    );
    config.search = strings(root, "ExtraSearchDomains")?
        .unwrap_or_default()
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
    config.control_security = root
        .value("ControlSecurity")?
        .filter(|v| v.ty == ValueType::BINARY && !v.data.is_empty())
        .map(|v| v.data);
    if let Some(hosts) = root.child("Hosts")? {
        for v in hosts.values()? {
            let name = reader::text(&v.name)?;
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
            let addrs = addresses(&multi(&value)?.unwrap_or_default(), "Dns Hosts");
            if !addrs.is_empty() {
                config.hosts.insert(name, addrs);
            }
        }
    }
    Ok(config)
}

/// Arm a subtree watch. On `Machine\System\Network`, not `Dns`
/// itself: the latter need not exist at boot (the first `reg new` creates
/// it), and a watch on a key that is not there cannot see it appear.
pub fn watch() -> peios::Result<Key> {
    use peios::registry::NotifyFilter;
    let key = Key::open(
        None,
        netd_core::NETWORK_KEY,
        KeyAccess::NOTIFY,
        OpenFlags::empty(),
    )?;
    key.notify(NotifyFilter::ALL, true)?;
    key.set_nonblocking(true)?;
    Ok(key)
}

#[cfg(test)]
mod read_tests {
    use super::*;
    struct Fixture {
        fault: &'static str,
    }
    impl Reader for Fixture {
        fn value(&self, name: &str) -> io::Result<Option<peios::registry::RegValue>> {
            if self.fault == "value" && name == "ControlSecurity" {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(None)
        }

        fn values(&self) -> io::Result<Vec<peios::registry::ValueRecord>> {
            if self.fault == "values" {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(vec![])
        }
        fn child(&self, name: &str) -> io::Result<Option<Self>> {
            if self.fault == "child" {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            if self.fault == "disappeared" && name == "entry" {
                return Ok(None);
            }
            Ok(Some(Self { fault: self.fault }))
        }
    }

    #[test]
    fn missing_configuration_keeps_documented_defaults() {
        assert_eq!(load_from(None::<&Fixture>).unwrap(), Config::default());
        assert_eq!(
            load_from(Some(&Fixture { fault: "" })).unwrap(),
            Config::default()
        );
    }
    #[test]
    fn failed_value_reads_do_not_produce_a_partial_configuration() {
        let error = load_from(Some(&Fixture { fault: "value" })).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }
    #[test]
    fn malformed_text_cannot_silently_remove_one_list_entry() {
        let value = peios::registry::RegValue {
            sequence: 0,
            ty: ValueType::MULTI_SZ,
            data: b"valid\0\xff\0\0".to_vec(),
            layer: vec![],
        };
        assert_eq!(
            reader::multi(&value).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn unreadable_subtrees_and_enumeration_failures_reject_the_read() {
        for fault in ["child", "values"] {
            assert!(load_from(Some(&Fixture { fault })).is_err(), "{fault}");
        }
    }
}
