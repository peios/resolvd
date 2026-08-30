//! The stub door's codec: arbitrary bytes as a client query, then the DNS
//! rendering of an arbitrary engine answer to it. Nothing may panic and the
//! rendered reply must decode.
#![no_main]

use dns::{Message, Name, RData, Record};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use libresolv::Outcome;
use resolvd::engine::{Answer, Source};
use resolvd::stub::{build_reply, parse_query};

#[derive(Arbitrary, Debug)]
struct Input {
    query: Vec<u8>,
    outcome: u8,
    resolved: Option<Vec<u8>>,
    records: u8,
    ttl: u32,
    limit: u16,
}

fuzz_target!(|input: Input| {
    let query = match parse_query(&input.query) {
        Ok(q) => q,
        Err(Some(reply)) => {
            Message::decode(&reply).expect("an error reply decodes");
            return;
        }
        Err(None) => return,
    };
    let resolved = input.resolved.and_then(|b| std::str::from_utf8(&b).ok().and_then(|s| Name::parse(s).ok()));
    let qname = query.question().map(|q| q.name.clone()).unwrap_or_default();
    let at = resolved.clone().unwrap_or(qname);
    let mut records = Vec::new();
    for i in 0..input.records % 50 {
        records.push(Record::new(at.clone(), input.ttl, RData::A(std::net::Ipv4Addr::new(10, 0, 0, i))));
    }
    let outcome = match input.outcome % 3 {
        0 => Outcome::Found,
        1 => Outcome::NotFound,
        _ => Outcome::Unavailable,
    };
    let answer = Answer { outcome, records, source: Source::Dns, server: None, interface: None, rcode: 0, resolved_name: resolved };
    let reply = build_reply(&query, &answer);
    let bytes = reply.encode().expect("a reply encodes");
    Message::decode(&bytes).expect("our reply decodes");
    let udp = reply.encode_udp(input.limit.max(12)).expect("udp encodes");
    assert!(udp.len() <= usize::from(input.limit.max(12)) || udp.len() <= bytes.len());
    Message::decode(&udp).expect("our udp reply decodes");
});
