//! **libnss_peios_net.so.2** — how a POSIX program resolves a host.
//!
//! `getaddrinfo` and `gethostbyname` end here. This object forwards the
//! question to resolvd over `/run/resolvd/resolv.sock` and renders the
//! answer as a `struct hostent` or a `gaih_addrtuple` list. It is a shim in
//! exactly the sense `libnss_peios.so.2` is: the protocol is in resolvd's
//! terms — records, TTLs, outcomes, a validation state — and this flattens
//! it into what the libc interface can carry.
//!
//! # What it does not do
//!
//! It does not read `/etc/hosts` (there is none; static names live in the
//! registry and resolvd answers them at every door), it does not speak DNS
//! itself (a second policy path), and it does not cache (that is resolvd's,
//! shared by every process and flushable when the network changes). Before
//! resolvd is running it answers `localhost` on its own — the one name a
//! machine can never be without — and `UNAVAIL` for everything else.
//!
//! # A connection per call
//!
//! As in the identity shim: a shared object cannot see its process fork,
//! and a connection inherited across one is how a resolver hands back
//! someone else's answer.
//!
//! # Failing the right way
//!
//! `NotFound` is `NSS_STATUS_NOTFOUND` with `HOST_NOT_FOUND`. `Unavailable`
//! — resolvd exists but nothing could answer — is `NSS_STATUS_TRYAGAIN`
//! with `TRY_AGAIN`, never an absence. resolvd itself absent is
//! `NSS_STATUS_UNAVAIL`.

#![deny(unsafe_op_in_unsafe_fn)]

mod buffer;

use core::ffi::{c_char, c_int};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use libresolv::{Addresses, Answer, Family, Outcome, Reply, Request, SOCKET_PATH};

use crate::buffer::Packer;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssStatus {
    TryAgain = -2,
    Unavail = -1,
    NotFound = 0,
    Success = 1,
}

// <netdb.h>
const HOST_NOT_FOUND: c_int = 1;
const TRY_AGAIN: c_int = 2;
const NO_RECOVERY: c_int = 3;
const NO_DATA: c_int = 4;

/// How long resolvd has to answer. Longer than resolvd's own worst case
/// (three attempts at two seconds) so a slow upstream is reported as
/// `Unavailable` by resolvd rather than as a timeout here.
const TIMEOUT: Duration = Duration::from_secs(10);

/// glibc's `struct gaih_addrtuple` (resolv/resolv_context.h / nss.h).
#[repr(C)]
pub struct GaihAddrtuple {
    next: *mut GaihAddrtuple,
    name: *mut c_char,
    family: c_int,
    addr: [u32; 4],
    scopeid: u32,
}

enum Got<T> {
    Value(T),
    NotFound,
    TryAgain,
    Unavailable,
}

fn connect() -> Option<UnixStream> {
    let stream = UnixStream::connect(SOCKET_PATH).ok()?;
    stream.set_read_timeout(Some(TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(TIMEOUT)).ok()?;
    Some(stream)
}

fn lookup(name: &str, family: Family) -> Got<Addresses> {
    let Some(mut stream) = connect() else { return Got::Unavailable };
    match libresolv::call(&mut stream, &Request::Lookup { name: name.to_owned(), family }) {
        Ok(Reply::Addresses(a)) => match a.outcome {
            Outcome::Found => Got::Value(a),
            Outcome::NotFound => Got::NotFound,
            Outcome::Unavailable => Got::TryAgain,
        },
        Ok(_) => Got::Unavailable,
        // A timeout lands here: resolvd exists and did not answer in time.
        Err(libresolv::WireError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => Got::TryAgain,
        Err(_) => Got::Unavailable,
    }
}

fn reverse(address: IpAddr) -> Got<Answer> {
    let Some(mut stream) = connect() else { return Got::Unavailable };
    match libresolv::call(&mut stream, &Request::Reverse { address }) {
        Ok(Reply::Answer(a)) => match a.outcome {
            Outcome::Found if a.records.is_empty() => Got::NotFound,
            Outcome::Found => Got::Value(a),
            Outcome::NotFound => Got::NotFound,
            Outcome::Unavailable => Got::TryAgain,
        },
        Ok(_) => Got::Unavailable,
        Err(libresolv::WireError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => Got::TryAgain,
        Err(_) => Got::Unavailable,
    }
}

/// `localhost` without a daemon: the one answer the shim gives itself.
fn is_localhost(name: &str) -> bool {
    let n = name.trim_end_matches('.');
    n.eq_ignore_ascii_case("localhost") || n.to_ascii_lowercase().ends_with(".localhost")
}

fn local_addresses(family: Family) -> Addresses {
    let mut addresses = Vec::new();
    if family != Family::V6 {
        addresses.push(libresolv::AddressOut { address: Ipv4Addr::LOCALHOST.into(), ttl: 0 });
    }
    if family != Family::V4 {
        addresses.push(libresolv::AddressOut { address: Ipv6Addr::LOCALHOST.into(), ttl: 0 });
    }
    Addresses { outcome: Outcome::Found, canonical: "localhost".into(), addresses, source: "local".into(), validation: Default::default() }
}

unsafe fn borrow<'a>(pointer: *const c_char) -> Option<&'a str> {
    if pointer.is_null() {
        return None;
    }
    unsafe { core::ffi::CStr::from_ptr(pointer) }.to_str().ok()
}

unsafe fn fail(status: NssStatus, errnop: *mut c_int, h_errnop: *mut c_int, errno: c_int, h_errno: c_int) -> NssStatus {
    unsafe {
        if !errnop.is_null() {
            errnop.write(errno);
        }
        if !h_errnop.is_null() {
            h_errnop.write(h_errno);
        }
    }
    status
}

unsafe fn status_of<T>(got: &Got<T>, errnop: *mut c_int, h_errnop: *mut c_int) -> Option<NssStatus> {
    Some(match got {
        Got::Value(_) => return None,
        Got::NotFound => unsafe { fail(NssStatus::NotFound, errnop, h_errnop, libc::ENOENT, HOST_NOT_FOUND) },
        Got::TryAgain => unsafe { fail(NssStatus::TryAgain, errnop, h_errnop, libc::EAGAIN, TRY_AGAIN) },
        Got::Unavailable => unsafe { fail(NssStatus::Unavail, errnop, h_errnop, libc::ENOENT, NO_RECOVERY) },
    })
}

unsafe fn out_of_room(errnop: *mut c_int, h_errnop: *mut c_int) -> NssStatus {
    unsafe { fail(NssStatus::TryAgain, errnop, h_errnop, libc::ERANGE, 0) }
}

fn family_of(af: c_int) -> Option<Family> {
    match af {
        libc::AF_INET => Some(Family::V4),
        libc::AF_INET6 => Some(Family::V6),
        libc::AF_UNSPEC => Some(Family::Any),
        _ => None,
    }
}

fn resolve_addresses(name: &str, family: Family) -> Got<Addresses> {
    if is_localhost(name) {
        return Got::Value(local_addresses(family));
    }
    match lookup(name, family) {
        Got::Value(mut a) => {
            a.addresses.retain(|x| match family {
                Family::Any => true,
                Family::V4 => x.address.is_ipv4(),
                Family::V6 => x.address.is_ipv6(),
            });
            if a.addresses.is_empty() {
                // The name exists with no address of this family: NO_DATA,
                // which is NotFound with a different h_errno.
                return Got::NotFound;
            }
            Got::Value(a)
        }
        other => other,
    }
}

/// Fill a `hostent` from addresses of one family.
///
/// # Safety
///
/// `result` and the buffer must be valid as glibc guarantees for an NSS call.
unsafe fn render_hostent(
    a: &Addresses,
    af: c_int,
    result: *mut libc::hostent,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    ttlp: *mut i32,
    canonp: *mut *mut c_char,
) -> NssStatus {
    let mut packer = unsafe { Packer::new(buffer, buflen) };
    let Some(name) = packer.str(&a.canonical) else { return unsafe { out_of_room(errnop, h_errnop) } };
    let addr_len = if af == libc::AF_INET6 { 16 } else { 4 };
    let Some(aliases) = packer.pointers(1) else { return unsafe { out_of_room(errnop, h_errnop) } };
    let Some(addr_list) = packer.pointers(a.addresses.len() + 1) else { return unsafe { out_of_room(errnop, h_errnop) } };
    for (i, x) in a.addresses.iter().enumerate() {
        let bytes: Vec<u8> = match x.address {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        let Some(slot) = packer.bytes(&bytes, 4) else { return unsafe { out_of_room(errnop, h_errnop) } };
        // SAFETY: `pointers` reserved `len + 1` slots.
        unsafe { addr_list.add(i).write(slot) };
    }
    // SAFETY: the arrays are NUL-terminated by the packer and `result` is
    // the caller's to fill.
    unsafe {
        (*result).h_name = name;
        (*result).h_aliases = aliases;
        (*result).h_addrtype = af;
        (*result).h_length = addr_len;
        (*result).h_addr_list = addr_list;
        if !ttlp.is_null() {
            ttlp.write(a.addresses.iter().map(|x| x.ttl).min().unwrap_or(0) as i32);
        }
        if !canonp.is_null() {
            canonp.write(name);
        }
    }
    NssStatus::Success
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_net_gethostbyname4_r(
    name: *const c_char,
    pat: *mut *mut GaihAddrtuple,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    ttlp: *mut i32,
) -> NssStatus {
    let Some(name) = (unsafe { borrow(name) }) else {
        return unsafe { fail(NssStatus::NotFound, errnop, h_errnop, libc::ENOENT, HOST_NOT_FOUND) };
    };
    let got = resolve_addresses(name, Family::Any);
    if let Some(status) = unsafe { status_of(&got, errnop, h_errnop) } {
        return status;
    }
    let Got::Value(a) = got else { unreachable!() };
    let mut packer = unsafe { Packer::new(buffer, buflen) };
    let Some(canonical) = packer.str(&a.canonical) else { return unsafe { out_of_room(errnop, h_errnop) } };
    let mut previous: *mut GaihAddrtuple = core::ptr::null_mut();
    let mut first: *mut GaihAddrtuple = core::ptr::null_mut();
    for x in &a.addresses {
        let Some(slot) = packer.reserve(core::mem::size_of::<GaihAddrtuple>(), core::mem::align_of::<GaihAddrtuple>()) else {
            return unsafe { out_of_room(errnop, h_errnop) };
        };
        let tuple = slot as *mut GaihAddrtuple;
        let (family, addr) = match x.address {
            IpAddr::V4(v) => (libc::AF_INET, [u32::from_ne_bytes(v.octets()), 0, 0, 0]),
            IpAddr::V6(v) => {
                let o = v.octets();
                let w = |i: usize| u32::from_ne_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]]);
                (libc::AF_INET6, [w(0), w(4), w(8), w(12)])
            }
        };
        // SAFETY: `slot` is aligned, sized and owned by the caller's buffer.
        unsafe {
            tuple.write(GaihAddrtuple { next: core::ptr::null_mut(), name: canonical, family, addr, scopeid: 0 });
            if previous.is_null() {
                first = tuple;
            } else {
                (*previous).next = tuple;
            }
        }
        previous = tuple;
    }
    // SAFETY: `pat` is the caller's out-parameter.
    unsafe {
        if !pat.is_null() {
            // glibc may hand in a preallocated first tuple; the convention
            // is to overwrite the pointer with our list.
            pat.write(first);
        }
        if !ttlp.is_null() {
            ttlp.write(a.addresses.iter().map(|x| x.ttl).min().unwrap_or(0) as i32);
        }
    }
    NssStatus::Success
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_net_gethostbyname3_r(
    name: *const c_char,
    af: c_int,
    result: *mut libc::hostent,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    ttlp: *mut i32,
    canonp: *mut *mut c_char,
) -> NssStatus {
    let Some(name) = (unsafe { borrow(name) }) else {
        return unsafe { fail(NssStatus::NotFound, errnop, h_errnop, libc::ENOENT, HOST_NOT_FOUND) };
    };
    let Some(family) = family_of(af).filter(|f| *f != Family::Any) else {
        return unsafe { fail(NssStatus::Unavail, errnop, h_errnop, libc::EAFNOSUPPORT, NO_DATA) };
    };
    let got = resolve_addresses(name, family);
    if let Some(status) = unsafe { status_of(&got, errnop, h_errnop) } {
        return status;
    }
    let Got::Value(a) = got else { unreachable!() };
    unsafe { render_hostent(&a, af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_net_gethostbyname2_r(
    name: *const c_char,
    af: c_int,
    result: *mut libc::hostent,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> NssStatus {
    unsafe { _nss_peios_net_gethostbyname3_r(name, af, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut(), core::ptr::null_mut()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_net_gethostbyname_r(
    name: *const c_char,
    result: *mut libc::hostent,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> NssStatus {
    unsafe { _nss_peios_net_gethostbyname3_r(name, libc::AF_INET, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut(), core::ptr::null_mut()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_net_gethostbyaddr2_r(
    addr: *const core::ffi::c_void,
    len: libc::socklen_t,
    af: c_int,
    result: *mut libc::hostent,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    ttlp: *mut i32,
) -> NssStatus {
    if addr.is_null() {
        return unsafe { fail(NssStatus::NotFound, errnop, h_errnop, libc::ENOENT, HOST_NOT_FOUND) };
    }
    let address: IpAddr = match (af, len) {
        (libc::AF_INET, 4) => {
            let mut o = [0u8; 4];
            // SAFETY: the caller promises `len` bytes at `addr`.
            unsafe { core::ptr::copy_nonoverlapping(addr as *const u8, o.as_mut_ptr(), 4) };
            Ipv4Addr::from(o).into()
        }
        (libc::AF_INET6, 16) => {
            let mut o = [0u8; 16];
            // SAFETY: as above.
            unsafe { core::ptr::copy_nonoverlapping(addr as *const u8, o.as_mut_ptr(), 16) };
            Ipv6Addr::from(o).into()
        }
        _ => return unsafe { fail(NssStatus::Unavail, errnop, h_errnop, libc::EAFNOSUPPORT, NO_RECOVERY) },
    };
    let got = if address.is_loopback() {
        Got::Value(Answer {
            outcome: Outcome::Found,
            records: vec![libresolv::RecordOut { name: String::new(), rtype: 12, ttl: 0, data: vec![], text: "localhost".into() }],
            ..Default::default()
        })
    } else {
        reverse(address)
    };
    if let Some(status) = unsafe { status_of(&got, errnop, h_errnop) } {
        return status;
    }
    let Got::Value(a) = got else { unreachable!() };
    let names: Vec<&str> = a.records.iter().filter(|r| r.rtype == 12).map(|r| r.text.trim_end_matches('.')).collect();
    let Some(first) = names.first() else {
        return unsafe { fail(NssStatus::NotFound, errnop, h_errnop, libc::ENOENT, HOST_NOT_FOUND) };
    };
    let mut packer = unsafe { Packer::new(buffer, buflen) };
    let Some(name) = packer.str(first) else { return unsafe { out_of_room(errnop, h_errnop) } };
    let Some(aliases) = packer.pointers(names.len()) else { return unsafe { out_of_room(errnop, h_errnop) } };
    for (i, alias) in names.iter().skip(1).enumerate() {
        let Some(p) = packer.str(alias) else { return unsafe { out_of_room(errnop, h_errnop) } };
        // SAFETY: `pointers` reserved `names.len()` slots; skip(1) uses one fewer.
        unsafe { aliases.add(i).write(p) };
    }
    let bytes: Vec<u8> = match address {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    };
    let Some(addr_list) = packer.pointers(2) else { return unsafe { out_of_room(errnop, h_errnop) } };
    let Some(slot) = packer.bytes(&bytes, 4) else { return unsafe { out_of_room(errnop, h_errnop) } };
    // SAFETY: as in render_hostent.
    unsafe {
        addr_list.write(slot);
        (*result).h_name = name;
        (*result).h_aliases = aliases;
        (*result).h_addrtype = af;
        (*result).h_length = len as c_int;
        (*result).h_addr_list = addr_list;
        if !ttlp.is_null() {
            ttlp.write(a.records.iter().map(|r| r.ttl).min().unwrap_or(0) as i32);
        }
    }
    NssStatus::Success
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_net_gethostbyaddr_r(
    addr: *const core::ffi::c_void,
    len: libc::socklen_t,
    af: c_int,
    result: *mut libc::hostent,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> NssStatus {
    unsafe { _nss_peios_net_gethostbyaddr2_r(addr, len, af, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_is_answered_without_a_daemon() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("LOCALHOST."));
        assert!(is_localhost("foo.localhost"));
        assert!(!is_localhost("localhost.example"));
        let a = local_addresses(Family::V4);
        assert_eq!(a.addresses.len(), 1);
        assert!(a.addresses[0].address.is_ipv4());
    }
}
