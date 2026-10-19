use super::*;
use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::ptr;

// usize storage gives the packer the alignment required by glibc's ABI.
const BUFFER_WORDS: usize = 1024;

#[derive(Clone, Copy, Debug)]
enum HostentLookup {
    Name,
    Name2,
    Name3,
    Address,
    Address2,
}

#[test]
fn hostent_entrypoints_request_a_larger_buffer() {
    for entry in [
        HostentLookup::Name,
        HostentLookup::Name2,
        HostentLookup::Name3,
        HostentLookup::Address,
        HostentLookup::Address2,
    ] {
        for af in [libc::AF_INET, libc::AF_INET6] {
            if matches!(entry, HostentLookup::Name) && af == libc::AF_INET6 {
                continue; // gethostbyname_r is IPv4-only.
            }
            let address = if af == libc::AF_INET {
                Ipv4Addr::LOCALHOST.octets().to_vec()
            } else {
                Ipv6Addr::LOCALHOST.octets().to_vec()
            };
            let mut storage = [0usize; BUFFER_WORDS];
            let capacity = size_of_val(&storage);
            let mut succeeded = false;
            // Visit every undersized length, including failures after the
            // canonical name, pointer arrays and address have been packed.
            for len in 0..=capacity {
                let mut result = MaybeUninit::<libc::hostent>::uninit();
                let mut errno = 123;
                let mut h_errno = 456;
                let mut ttl = -1;
                let mut canonical = ptr::null_mut();
                let buffer = storage.as_mut_ptr().cast();
                // SAFETY: all pointers address appropriately aligned live
                // storage. Localhost/loopback never needs a running daemon.
                let status = unsafe {
                    match entry {
                        HostentLookup::Name => _nss_peios_net_gethostbyname_r(
                            c"localhost".as_ptr(),
                            result.as_mut_ptr(),
                            buffer,
                            len,
                            &mut errno,
                            &mut h_errno,
                        ),
                        HostentLookup::Name2 => _nss_peios_net_gethostbyname2_r(
                            c"localhost".as_ptr(),
                            af,
                            result.as_mut_ptr(),
                            buffer,
                            len,
                            &mut errno,
                            &mut h_errno,
                        ),
                        HostentLookup::Name3 => _nss_peios_net_gethostbyname3_r(
                            c"localhost".as_ptr(),
                            af,
                            result.as_mut_ptr(),
                            buffer,
                            len,
                            &mut errno,
                            &mut h_errno,
                            &mut ttl,
                            &mut canonical,
                        ),
                        HostentLookup::Address => _nss_peios_net_gethostbyaddr_r(
                            address.as_ptr().cast(),
                            address.len() as libc::socklen_t,
                            af,
                            result.as_mut_ptr(),
                            buffer,
                            len,
                            &mut errno,
                            &mut h_errno,
                        ),
                        HostentLookup::Address2 => _nss_peios_net_gethostbyaddr2_r(
                            address.as_ptr().cast(),
                            address.len() as libc::socklen_t,
                            af,
                            result.as_mut_ptr(),
                            buffer,
                            len,
                            &mut errno,
                            &mut h_errno,
                            &mut ttl,
                        ),
                    }
                };
                if status == NssStatus::Success {
                    // SAFETY: a successful call initialized result and its
                    // NUL-terminated arrays inside the still-live buffer.
                    let result = unsafe { result.assume_init() };
                    assert_eq!(unsafe { CStr::from_ptr(result.h_name) }, c"localhost");
                    assert_eq!(result.h_addrtype, af);
                    assert_eq!(result.h_length as usize, address.len());
                    assert!(unsafe { *result.h_aliases }.is_null());
                    assert_eq!(
                        unsafe {
                            std::slice::from_raw_parts(
                                (*result.h_addr_list).cast::<u8>(),
                                address.len(),
                            )
                        },
                        address
                    );
                    assert!(unsafe { *result.h_addr_list.add(1) }.is_null());
                    if matches!(entry, HostentLookup::Name3) {
                        assert_eq!(canonical, result.h_name);
                    }
                    if matches!(entry, HostentLookup::Name3 | HostentLookup::Address2) {
                        assert_eq!(ttl, 0);
                    }
                    succeeded = true;
                    break;
                }
                assert_eq!(
                    (status, errno, h_errno),
                    (NssStatus::TryAgain, libc::ERANGE, -1),
                    "{entry:?}, af={af}, buflen={len}: glibc requires NETDB_INTERNAL (-1)"
                );
                assert_eq!(ttl, -1);
                assert!(canonical.is_null());
            }
            assert!(succeeded, "{entry:?}, af={af} never fit");
        }
    }
}

#[test]
fn address_tuple_entrypoint_requests_a_larger_buffer() {
    let mut storage = [0usize; BUFFER_WORDS];
    let mut succeeded = false;
    for len in 0..=size_of_val(&storage) {
        let mut tuple = ptr::null_mut();
        let mut errno = 123;
        let mut h_errno = 456;
        let mut ttl = -1;
        // SAFETY: live, aligned storage and valid output pointers.
        let status = unsafe {
            _nss_peios_net_gethostbyname4_r(
                c"localhost".as_ptr(),
                &mut tuple,
                storage.as_mut_ptr().cast(),
                len,
                &mut errno,
                &mut h_errno,
                &mut ttl,
            )
        };
        if status == NssStatus::Success {
            // SAFETY: the complete list is initialized on success and points
            // into storage, which remains live throughout these assertions.
            unsafe {
                assert!(!tuple.is_null());
                assert_eq!(CStr::from_ptr((*tuple).name), c"localhost");
                assert_eq!((*tuple).family, libc::AF_INET);
                assert_eq!((*tuple).addr[0].to_ne_bytes(), Ipv4Addr::LOCALHOST.octets());
                tuple = (*tuple).next;
                assert!(!tuple.is_null());
                assert_eq!((*tuple).family, libc::AF_INET6);
                let expected: [u8; 16] = Ipv6Addr::LOCALHOST.octets();
                let actual: Vec<u8> = (*tuple).addr.iter().flat_map(|x| x.to_ne_bytes()).collect();
                assert_eq!(actual, expected);
                assert!((*tuple).next.is_null());
            }
            assert_eq!(ttl, 0);
            succeeded = true;
            break;
        }
        assert_eq!(
            (status, errno, h_errno),
            (NssStatus::TryAgain, libc::ERANGE, -1),
            "buflen={len}: glibc requires NETDB_INTERNAL (-1)"
        );
        assert!(tuple.is_null());
        assert_eq!(ttl, -1);
    }
    assert!(succeeded, "localhost tuples never fit");
}

#[test]
fn many_addresses_can_be_retried_with_a_larger_buffer() {
    for af in [libc::AF_INET, libc::AF_INET6] {
        let mut answer = local_addresses(if af == libc::AF_INET {
            Family::V4
        } else {
            Family::V6
        });
        // 128 addresses exceed 1024 bytes even with 32-bit pointers.
        answer.addresses = (1..=128)
            .map(|i| resolvd_core::AddressOut {
                address: if af == libc::AF_INET {
                    Ipv4Addr::new(192, 0, 2, i).into()
                } else {
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(i)).into()
                },
                ttl: 60,
            })
            .collect();
        let mut storage = [0usize; BUFFER_WORDS];
        let mut result = MaybeUninit::<libc::hostent>::uninit();
        let mut errno = 0;
        let mut h_errno = 0;
        for len in [1024, size_of_val(&storage)] {
            // SAFETY: valid aligned storage; result is only read on success.
            let status = unsafe {
                render_hostent(
                    &answer,
                    af,
                    result.as_mut_ptr(),
                    storage.as_mut_ptr().cast(),
                    len,
                    &mut errno,
                    &mut h_errno,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if len == 1024 {
                assert_eq!(
                    (status, errno, h_errno),
                    (NssStatus::TryAgain, libc::ERANGE, -1)
                );
                continue;
            }
            assert_eq!(status, NssStatus::Success);
            // SAFETY: the successful call initialized all 128 addresses and
            // their terminating pointer in the still-live storage.
            let result = unsafe { result.assume_init() };
            for (i, expected) in answer.addresses.iter().enumerate() {
                let bytes = match expected.address {
                    IpAddr::V4(v) => v.octets().to_vec(),
                    IpAddr::V6(v) => v.octets().to_vec(),
                };
                assert_eq!(
                    unsafe {
                        std::slice::from_raw_parts(
                            (*result.h_addr_list.add(i)).cast::<u8>(),
                            bytes.len(),
                        )
                    },
                    bytes
                );
            }
            assert!(unsafe { *result.h_addr_list.add(128) }.is_null());
        }
    }
}
