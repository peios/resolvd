//! Arbitrary bytes as native-channel requests and replies, and as raw
//! MessagePack; nothing may panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use resolvd_core::msgpack::Reader;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = resolvd_core::Request::decode(data) {
        let again = r.encode();
        assert_eq!(resolvd_core::Request::decode(&again).unwrap(), r);
    }
    if let Ok(r) = resolvd_core::Reply::decode(data) {
        let again = r.encode();
        let _ = resolvd_core::Reply::decode(&again).unwrap();
    }
    let mut r = Reader::new(data);
    let _ = r.skip();
    let _ = resolvd_core::recv(&mut &data[..]);
});
