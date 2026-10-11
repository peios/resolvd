//! Exercise the production reply classifiers without a daemon or sockets.
use super::*;

fn status<T>(got: &Got<T>) -> (Option<NssStatus>, c_int, c_int) {
    let mut errno = -77;
    let mut h_errno = -77;
    // SAFETY: both output pointers refer to live, writable integers.
    let result = unsafe { status_of(got, &mut errno, &mut h_errno) };
    (result, errno, h_errno)
}

fn no_data<T>(got: &Got<T>) {
    assert_eq!(
        status(got),
        (Some(NssStatus::NotFound), libc::ENOENT, NO_DATA)
    );
}

#[test]
fn found_without_the_requested_family_is_no_data() {
    for family in [Family::V4, Family::V6, Family::Any] {
        let mut empty = local_addresses(Family::Any);
        empty.addresses.clear();
        no_data(&classify_addresses(empty, family));
    }
    no_data(&classify_addresses(local_addresses(Family::V4), Family::V6));
    no_data(&classify_addresses(local_addresses(Family::V6), Family::V4));
}

#[test]
fn found_addresses_keep_only_the_requested_family_in_reply_order() {
    for family in [Family::V4, Family::V6, Family::Any] {
        let mut input = local_addresses(Family::Any);
        input.addresses[0].ttl = 7;
        input.addresses[1].ttl = 11;
        // Repeated records make accidental sorting/deduplication observable.
        input.addresses.push(input.addresses[0].clone());
        let expected: Vec<_> = input
            .addresses
            .iter()
            .filter(|x| match family {
                Family::Any => true,
                Family::V4 => x.address.is_ipv4(),
                Family::V6 => x.address.is_ipv6(),
            })
            .map(|x| (x.address, x.ttl))
            .collect();
        let got = classify_addresses(input, family);
        assert_eq!(status(&got), (None, -77, -77));
        let Got::Value(a) = got else {
            panic!("expected addresses")
        };
        assert_eq!(a.canonical, "localhost");
        assert_eq!(
            a.addresses
                .iter()
                .map(|x| (x.address, x.ttl))
                .collect::<Vec<_>>(),
            expected
        );
    }
}

fn answer(outcome: Outcome, rtypes: &[u16]) -> Answer {
    Answer {
        outcome,
        records: rtypes
            .iter()
            .map(|&rtype| libresolv::RecordOut {
                name: "owner.test".into(),
                rtype,
                ttl: 13,
                data: vec![],
                text: "target.test.".into(),
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn found_reverse_without_ptr_is_no_data() {
    no_data(&classify_reverse(answer(Outcome::Found, &[])));
    no_data(&classify_reverse(answer(Outcome::Found, &[5, 1, 28])));
    let got = classify_reverse(answer(Outcome::Found, &[5, 12, 12]));
    assert_eq!(status(&got), (None, -77, -77));
    let Got::Value(a) = got else {
        panic!("expected PTR answer")
    };
    assert_eq!(
        a.records.iter().map(|r| r.rtype).collect::<Vec<_>>(),
        [5, 12, 12]
    );
    assert_eq!(a.records[1].text, "target.test.");
    assert_eq!(a.records[1].ttl, 13);
}

#[test]
fn negative_and_unavailable_outcomes_do_not_become_no_data() {
    for (outcome, expected) in [
        (
            Outcome::NotFound,
            (Some(NssStatus::NotFound), libc::ENOENT, HOST_NOT_FOUND),
        ),
        (
            Outcome::Unavailable,
            (Some(NssStatus::TryAgain), libc::EAGAIN, TRY_AGAIN),
        ),
    ] {
        for populated in [false, true] {
            let mut a = local_addresses(Family::Any);
            a.outcome = outcome;
            if !populated {
                a.addresses.clear();
            }
            assert_eq!(status(&classify_addresses(a, Family::V4)), expected);
            assert_eq!(
                status(&classify_reverse(answer(
                    outcome,
                    if populated { &[12] } else { &[] }
                ))),
                expected
            );
        }
    }
    assert_eq!(
        status(&Got::<()>::Unavailable),
        (Some(NssStatus::Unavail), libc::ENOENT, NO_RECOVERY)
    );
}

#[test]
fn no_data_accepts_null_error_outputs() {
    // SAFETY: status_of explicitly allows absent output pointers.
    assert_eq!(
        unsafe {
            status_of(
                &Got::<()>::NoData,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        },
        Some(NssStatus::NotFound)
    );
}
