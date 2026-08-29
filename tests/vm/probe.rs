//! Guest-side probe for the doors that `resolv` does not exercise.
//!
//!   probe gai <name>            getaddrinfo(3) — glibc + libnss_peios_net (static-glibc build),
//!                               or musl's own resolver via /etc/resolv.conf (musl build)
//!   probe dns <server> <name>   a raw A query over UDP, then over TCP
//!
//! Build (host glibc must equal the image's):
//!   rustc -O -C target-feature=+crt-static probe.rs -o probe-glibc
//!   rustc -O --target x86_64-unknown-linux-musl probe.rs -o probe-musl

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

fn query(name: &str) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m
}

fn describe(reply: &[u8]) -> String {
    if reply.len() < 12 {
        return format!("short reply ({} bytes)", reply.len());
    }
    let rcode = reply[3] & 0xF;
    let ancount = u16::from_be_bytes([reply[6], reply[7]]);
    // Find A records: scan for 4-byte rdata following type 1 class 1.
    let mut addrs = Vec::new();
    let mut i = 12;
    while i + 10 <= reply.len() {
        if reply[i] == 0 && reply[i + 1] == 1 && reply[i + 2] == 0 && reply[i + 3] == 1 && i + 10 <= reply.len() {
            let rdlen = u16::from_be_bytes([reply[i + 8], reply[i + 9]]) as usize;
            if rdlen == 4 && i + 14 <= reply.len() && i > 12 + 4 {
                addrs.push(format!("{}.{}.{}.{}", reply[i + 10], reply[i + 11], reply[i + 12], reply[i + 13]));
            }
        }
        i += 1;
    }
    format!("rcode={rcode} ancount={ancount} A={addrs:?} ({} bytes)", reply.len())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [_, "gai", name] => match (name.as_ref() as &str, 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let list: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                println!("gai {name}: ok {list:?}");
            }
            Err(e) => println!("gai {name}: error {e} (os {:?})", e.raw_os_error()),
        },
        [_, "dns", server, name] => {
            let q = query(name);
            let udp = UdpSocket::bind("0.0.0.0:0").expect("bind");
            udp.set_read_timeout(Some(Duration::from_secs(8))).ok();
            udp.connect(format!("{server}:53")).expect("connect");
            udp.send(&q).expect("send");
            let mut buf = [0u8; 4096];
            match udp.recv(&mut buf) {
                Ok(n) => println!("udp {name}: {}", describe(&buf[..n])),
                Err(e) => println!("udp {name}: error {e}"),
            }
            match TcpStream::connect_timeout(&format!("{server}:53").parse().unwrap(), Duration::from_secs(3)) {
                Ok(mut s) => {
                    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
                    let mut frame = (q.len() as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&q);
                    s.write_all(&frame).expect("write");
                    let mut len = [0u8; 2];
                    match s.read_exact(&mut len) {
                        Ok(()) => {
                            let n = u16::from_be_bytes(len) as usize;
                            let mut reply = vec![0u8; n];
                            match s.read_exact(&mut reply) {
                                Ok(()) => println!("tcp {name}: {}", describe(&reply)),
                                Err(e) => println!("tcp {name}: error {e}"),
                            }
                        }
                        Err(e) => println!("tcp {name}: error {e}"),
                    }
                }
                Err(e) => println!("tcp {name}: connect error {e}"),
            }
        }
        _ => eprintln!("usage: probe gai <name> | probe dns <server> <name>"),
    }
}
