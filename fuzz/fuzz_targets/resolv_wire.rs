//! Arbitrary bytes as native-channel requests and replies, and as raw
//! MessagePack; nothing may panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use libresolv::msgpack::Reader;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = libresolv::Request::decode(data) {
        let again = r.encode();
        assert_eq!(libresolv::Request::decode(&again).unwrap(), r);
    }
    if let Ok(r) = libresolv::Reply::decode(data) {
        let again = r.encode();
        let _ = libresolv::Reply::decode(&again).unwrap();
    }
    let mut r = Reader::new(data);
    let _ = r.skip();
    let _ = libresolv::recv(&mut &data[..]);
});
