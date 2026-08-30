//! Decode arbitrary bytes as a DNS message; whatever decodes must re-encode
//! and decode again to the same value, and never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = dns::Message::decode(data) {
        let _ = m.udp_size();
        let _ = m.rcode();
        for r in m.answers.iter().chain(&m.authority).chain(&m.additional) {
            let _ = r.rdata_text();
            let _ = r.rdata_bytes();
            let _ = r.name.to_string();
            let _ = r.name.reverse_address();
        }
        if let Ok(again) = m.encode() {
            let m2 = dns::Message::decode(&again).expect("our own encoding decodes");
            assert_eq!(m2, m);
            let _ = m.encode_udp(512);
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(n) = dns::Name::parse(s) {
            let _ = n.to_string();
            let _ = n.to_lowercase();
        }
    }
});
