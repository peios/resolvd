//! The native door: `/run/resolvd/resolv.sock`, one request per connection,
//! authorised against the resolvd control object.
//!
//! The object is `Machine\System\Network\Dns ControlSecurity` when set,
//! else a compiled default — Everyone may query, SYSTEM and Administrators
//! may control. The check is a KACS access check against the peer's token,
//! never `SO_PEERCRED`. The peer's SID is also what identity-aware policy
//! (PEI-502) will key on; it is available here and nowhere else.
//!
//! Connections are nonblocking end to end: a client that sends half a
//! request and stops holds a few bytes of buffer, not the loop.

use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use peios::access::AccessCheck;
use peios::security::{
    AccessMask, AceFlags, AclBuilder, GenericMapping, SdBuilder, SecurityDescriptor, Sid, WellKnown,
};
use peios::token::Token;
use resolvd_core::{
    MAX_MESSAGE_BYTES, RESOLVD_RUN_DIR, RESOLVER_ALL_ACCESS, RESOLVER_CONTROL, RESOLVER_QUERY,
    Reply, Request, SOCKET_PATH,
};

use resolvd::log;

const DIRECTORY_MODE: u32 = 0o755;
const SOCKET_MODE: u32 = 0o666;
/// A client has this long to send its whole request.
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn listen() -> io::Result<UnixListener> {
    let directory = Path::new(RESOLVD_RUN_DIR);
    std::fs::create_dir_all(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(DIRECTORY_MODE))?;
    protect(directory);
    let path = Path::new(SOCKET_PATH);
    match std::fs::remove_file(path) {
        Ok(()) => log::warn(format_args!("removed a stale {SOCKET_PATH}")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    protect(path);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Let everyone reach the socket; the object check decides what they may do.
///
/// **The DACL only.** This used to set the owner to SYSTEM as well, and
/// that is the one thing a LocalService process cannot do: making somebody
/// else the owner of an object needs a privilege resolvd does not have and
/// should not have. `set_sd` is all-or-nothing, so asking for the owner
/// failed the whole call with `EPERM` and the DACL was never written
/// either — leaving `resolv.sock` at `O:LSG:LS` with no DACL component at
/// all, and `/run/resolvd` carrying only peinit's descriptor, which admits
/// SYSTEM, Administrators and this service and nobody else.
///
/// That mattered here more than anywhere: this is the socket every program
/// on the machine uses to resolve a name, and an ordinary client could not
/// traverse the directory to reach it. Resolution kept working through the
/// other two doors — `127.0.0.53` and the NSS shim — which is why nothing
/// obviously broke and the defect sat here since resolvd shipped.
///
/// It failed silently because the error only went to the log, and a
/// LocalService daemon's lines do not reach the console (PEI-581);
/// `evctl 'LOGS FROM resolvd'` had them all along. PEI-329 recorded the
/// symptom — a NULL DACL on the socket — and guessed it was benign.
///
/// The owner is left as whoever created the object, which is resolvd: the
/// correct answer, and what it already was.
///
/// **resolvd keeps full access for itself.** peinit leaves `/run/resolvd`
/// in place across a restart, and the stale socket a previous run left
/// behind has to be deleted before the new one can bind. Everyone's read,
/// write and execute include neither DELETE nor deleting a child, so a
/// descriptor of SYSTEM and Everyone alone gave a resolvd that started once
/// and could never start again: every restart, including the ones
/// `RestartPolicy` makes after a crash, failed with EACCES and the machine
/// lost name resolution until a reboot (PEI-1373). timed had the same
/// defect (PEI-1229).
fn protect(path: &Path) {
    use peios::file::SecInfo;
    use peios::token::TokenAccess;
    let system = Sid::well_known(WellKnown::System);
    let everyone = Sid::well_known(WellKnown::Everyone);
    let me = Token::open_self(true, TokenAccess::QUERY).and_then(|t| t.user());
    let mut acl = AclBuilder::new();
    acl.allow(
        system.as_ref(),
        AccessMask::GENERIC_ALL.bits(),
        AceFlags::empty(),
    );
    match &me {
        Ok(me) => {
            acl.allow(
                me.as_ref(),
                AccessMask::GENERIC_ALL.bits(),
                AceFlags::empty(),
            );
        }
        Err(e) => log::warn(format_args!(
            "could not read resolvd's own identity ({e}); a restart may not be able to \
             replace {}",
            path.display()
        )),
    }
    acl.allow(
        everyone.as_ref(),
        AccessMask::GENERIC_READ.bits()
            | AccessMask::GENERIC_WRITE.bits()
            | AccessMask::GENERIC_EXECUTE.bits(),
        AceFlags::empty(),
    );
    let descriptor = acl
        .build()
        .and_then(|dacl| SdBuilder::new().dacl(&dacl).build());
    match descriptor {
        Ok(sd) => {
            if let Err(e) = peios::file::set_sd(None, path, SecInfo::DACL, &sd, 0) {
                log::error(format_args!(
                    "could not set a descriptor on {} ({e}); programs other than SYSTEM and \
                     administrators will not be able to reach the socket",
                    path.display()
                ));
            }
        }
        Err(e) => log::warn(format_args!("could not build a descriptor: {e}")),
    }
}

pub struct ControlObject {
    sd: SecurityDescriptor,
}

impl ControlObject {
    pub fn new(configured: Option<&[u8]>) -> ControlObject {
        if let Some(bytes) = configured {
            match SecurityDescriptor::from_validated_bytes(bytes.to_vec()) {
                Ok(sd) => return ControlObject { sd },
                Err(e) => log::warn(format_args!(
                    "ControlSecurity is not a valid descriptor ({e}); using the default"
                )),
            }
        }
        ControlObject {
            sd: Self::default_sd(),
        }
    }

    fn default_sd() -> SecurityDescriptor {
        let system = Sid::well_known(WellKnown::System);
        let administrators = Sid::well_known(WellKnown::Administrators);
        let everyone = Sid::well_known(WellKnown::Everyone);
        AclBuilder::new()
            .allow(system.as_ref(), RESOLVER_ALL_ACCESS, AceFlags::empty())
            .allow(
                administrators.as_ref(),
                RESOLVER_ALL_ACCESS,
                AceFlags::empty(),
            )
            .allow(
                everyone.as_ref(),
                RESOLVER_QUERY | AccessMask::READ_CONTROL.bits(),
                AceFlags::empty(),
            )
            .build()
            .and_then(|dacl| {
                SdBuilder::new()
                    .owner(system.as_ref())
                    .group(system.as_ref())
                    .dacl(&dacl)
                    .build()
            })
            .expect("the compiled default descriptor builds")
    }

    fn mapping() -> GenericMapping {
        let rc = AccessMask::READ_CONTROL.bits();
        GenericMapping::new(
            RESOLVER_QUERY | rc,
            RESOLVER_CONTROL | rc,
            RESOLVER_QUERY,
            RESOLVER_ALL_ACCESS,
        )
    }

    pub fn permits(&self, stream: &UnixStream, right: u32) -> bool {
        let token = match Token::open_peer(stream.as_fd()) {
            Ok(t) => t,
            Err(e) => {
                log::warn(format_args!("control: no peer token: {e}"));
                return false;
            }
        };
        AccessCheck::new(
            &self.sd,
            AccessMask::from_bits_retain(right),
            Self::mapping(),
        )
        .token(token.as_fd())
        .check()
        .map(|d| d.allowed)
        .unwrap_or(false)
    }
}

/// A connection that has not yet sent a whole request.
pub struct Client {
    pub stream: UnixStream,
    buf: Vec<u8>,
    pub since: Instant,
}

pub enum Progress {
    /// Still reading.
    Incomplete,
    /// A whole request arrived.
    Request(Request),
    /// A malformed request should receive this error through the reply queue.
    Reply(Reply),
    /// The connection is over.
    Closed,
}

impl Client {
    pub fn new(stream: UnixStream, now: Instant) -> Option<Client> {
        stream.set_nonblocking(true).ok()?;
        Some(Client {
            stream,
            buf: Vec::with_capacity(256),
            since: now,
        })
    }

    /// Read the header first, then only the declared payload of one request.
    pub fn read(&mut self) -> Progress {
        let mut chunk = [0u8; 4096];
        loop {
            let target = if self.buf.len() < 4 {
                4
            } else {
                let len = u32::from_le_bytes(self.buf[..4].try_into().expect("header")) as usize;
                if len > MAX_MESSAGE_BYTES {
                    return Progress::Reply(Reply::Error("request too large".into()));
                }
                if self.buf.len() == 4 + len {
                    return match Request::decode(&self.buf[4..]) {
                        Ok(r) => Progress::Request(r),
                        Err(e) => Progress::Reply(Reply::Error(e.to_string())),
                    };
                }
                4 + len
            };
            let take = chunk.len().min(target - self.buf.len());
            match self.stream.read(&mut chunk[..take]) {
                Ok(0) => return Progress::Closed,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Progress::Incomplete,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Progress::Closed,
            }
        }
    }
}

/// Frame one bounded reply, replacing oversized payloads with a protocol error.
pub fn response_frame(reply: &Reply) -> Vec<u8> {
    let mut bytes = reply.encode();
    if bytes.len() > MAX_MESSAGE_BYTES {
        bytes = Reply::Error("reply too large".into()).encode();
    }
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&bytes);
    frame
}

#[cfg(test)]
mod reply_size_tests {
    use super::*;

    #[test]
    fn native_reply_ceiling_is_inclusive_and_oversize_gets_an_error() {
        // The error shape gives an exact controllable encoded payload length;
        // every reply goes through the same responder regardless of its kind.
        let overhead = Reply::Error("x".repeat(32768)).encode().len() - 32768;
        for size in [
            MAX_MESSAGE_BYTES - 1,
            MAX_MESSAGE_BYTES,
            MAX_MESSAGE_BYTES + 1,
        ] {
            let reply = Reply::Error("x".repeat(size - overhead));
            assert_eq!(reply.encode().len(), size);
            let frame = response_frame(&reply);
            let len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
            assert_eq!(len, frame.len() - 4);
            assert!(len <= MAX_MESSAGE_BYTES, "wrote {len} payload bytes");
            let expected = if size > MAX_MESSAGE_BYTES {
                Reply::Error("reply too large".into()).encode()
            } else {
                reply.encode()
            };
            assert_eq!(&frame[4..], &expected);
        }
    }
}

#[cfg(test)]
mod request_frame_tests {
    use super::*;
    use std::io::Write;
    use std::net::Shutdown;

    fn pair() -> (Client, UnixStream) {
        let (server, peer) = UnixStream::pair().unwrap();
        (Client::new(server, Instant::now()).unwrap(), peer)
    }

    fn frame() -> Vec<u8> {
        let payload = Request::Status.encode();
        let mut out = (payload.len() as u32).to_le_bytes().to_vec();
        out.extend(payload);
        out
    }

    #[test]
    fn fragmented_header_and_payload_resume_until_complete() {
        let (mut client, mut peer) = pair();
        let bytes = frame();
        for (i, byte) in bytes.iter().enumerate() {
            peer.write_all(&[*byte]).unwrap();
            let progress = client.read();
            if i + 1 == bytes.len() {
                assert!(matches!(progress, Progress::Request(Request::Status)));
            } else {
                assert!(matches!(progress, Progress::Incomplete));
            }
        }
        assert_eq!(client.buf, bytes);
    }

    #[test]
    fn an_oversized_header_leaves_every_payload_byte_unread() {
        for length in [MAX_MESSAGE_BYTES as u32 + 1, u32::MAX] {
            let (mut client, mut peer) = pair();
            let payload = vec![42; 80_000];
            peer.write_all(&length.to_le_bytes()).unwrap();
            peer.write_all(&payload).unwrap();
            peer.shutdown(Shutdown::Write).unwrap();
            assert!(
                matches!(client.read(), Progress::Reply(Reply::Error(e)) if e == "request too large")
            );
            assert_eq!(client.buf.len(), 4);
            let mut unread = Vec::new();
            client.stream.read_to_end(&mut unread).unwrap();
            assert_eq!(unread, payload);
        }
    }

    #[test]
    fn a_complete_request_is_decoded_before_trailing_bytes_or_eof() {
        for trailing in [vec![], vec![42; 80_000], frame()] {
            let (mut client, mut peer) = pair();
            let bytes = frame();
            peer.write_all(&bytes).unwrap();
            peer.write_all(&trailing).unwrap();
            peer.shutdown(Shutdown::Write).unwrap();
            assert!(matches!(client.read(), Progress::Request(Request::Status)));
            assert_eq!(client.buf, bytes);
            let mut unread = Vec::new();
            client.stream.read_to_end(&mut unread).unwrap();
            assert_eq!(unread, trailing);
        }
    }

    #[test]
    fn eof_before_a_complete_frame_is_dropped_and_empty_payload_is_decoded() {
        let bytes = frame();
        for prefix in 0..bytes.len() {
            let (mut client, mut peer) = pair();
            peer.write_all(&bytes[..prefix]).unwrap();
            peer.shutdown(Shutdown::Write).unwrap();
            assert!(matches!(client.read(), Progress::Closed));
        }
        let (mut client, mut peer) = pair();
        peer.write_all(&0u32.to_le_bytes()).unwrap();
        assert!(matches!(client.read(), Progress::Reply(Reply::Error(_))));
    }
}
