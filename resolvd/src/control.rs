//! The native door: `/run/resolvd/resolv.sock`, one request per connection,
//! authorised against the resolvd control object.
//!
//! The object is `Machine\System\Network\Resolver ControlSecurity` when set,
//! else a compiled default — Everyone may query, SYSTEM and Administrators
//! may control. The check is a KACS access check against the peer's token,
//! never `SO_PEERCRED`. The peer's SID is also what identity-aware policy
//! (PEI-502) will key on; it is available here and nowhere else.
//!
//! Connections are nonblocking end to end: a client that sends half a
//! request and stops holds a few bytes of buffer, not the loop.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use libresolv::{MAX_MESSAGE_BYTES, RESOLVD_RUN_DIR, RESOLVER_ALL_ACCESS, RESOLVER_CONTROL, RESOLVER_QUERY, Reply, Request, SOCKET_PATH};
use peios::access::AccessCheck;
use peios::security::{AccessMask, AceFlags, AclBuilder, GenericMapping, SdBuilder, SecurityDescriptor, Sid, WellKnown};
use peios::token::Token;

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

/// Everyone may connect; the object check decides what they may do.
fn protect(path: &Path) {
    use peios::file::SecInfo;
    let system = Sid::well_known(WellKnown::System);
    let everyone = Sid::well_known(WellKnown::Everyone);
    let descriptor = AclBuilder::new()
        .allow(system.as_ref(), AccessMask::GENERIC_ALL.bits(), AceFlags::empty())
        .allow(
            everyone.as_ref(),
            AccessMask::GENERIC_READ.bits() | AccessMask::GENERIC_WRITE.bits() | AccessMask::GENERIC_EXECUTE.bits(),
            AceFlags::empty(),
        )
        .build()
        .and_then(|dacl| SdBuilder::new().owner(system.as_ref()).group(system.as_ref()).dacl(&dacl).build());
    match descriptor {
        Ok(sd) => {
            if let Err(e) = peios::file::set_sd(None, path, SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL, &sd, 0) {
                log::error(format_args!("could not set a descriptor on {}: {e}", path.display()));
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
                Err(e) => log::warn(format_args!("ControlSecurity is not a valid descriptor ({e}); using the default")),
            }
        }
        ControlObject { sd: Self::default_sd() }
    }

    fn default_sd() -> SecurityDescriptor {
        let system = Sid::well_known(WellKnown::System);
        let administrators = Sid::well_known(WellKnown::Administrators);
        let everyone = Sid::well_known(WellKnown::Everyone);
        AclBuilder::new()
            .allow(system.as_ref(), RESOLVER_ALL_ACCESS, AceFlags::empty())
            .allow(administrators.as_ref(), RESOLVER_ALL_ACCESS, AceFlags::empty())
            .allow(everyone.as_ref(), RESOLVER_QUERY | AccessMask::READ_CONTROL.bits(), AceFlags::empty())
            .build()
            .and_then(|dacl| SdBuilder::new().owner(system.as_ref()).group(system.as_ref()).dacl(&dacl).build())
            .expect("the compiled default descriptor builds")
    }

    fn mapping() -> GenericMapping {
        let rc = AccessMask::READ_CONTROL.bits();
        GenericMapping::new(RESOLVER_QUERY | rc, RESOLVER_CONTROL | rc, RESOLVER_QUERY, RESOLVER_ALL_ACCESS)
    }

    pub fn permits(&self, stream: &UnixStream, right: u32) -> bool {
        let token = match Token::open_peer(stream.as_fd()) {
            Ok(t) => t,
            Err(e) => {
                log::warn(format_args!("control: no peer token: {e}"));
                return false;
            }
        };
        AccessCheck::new(&self.sd, AccessMask::from_bits_retain(right), Self::mapping())
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
    /// The connection is over, or the bytes were not a request (a reply
    /// has been sent where one was possible).
    Closed,
}

impl Client {
    pub fn new(stream: UnixStream, now: Instant) -> Option<Client> {
        stream.set_nonblocking(true).ok()?;
        Some(Client { stream, buf: Vec::with_capacity(256), since: now })
    }

    /// Read what is available and see whether a request is complete.
    pub fn read(&mut self) -> Progress {
        let mut chunk = [0u8; 4096];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => return Progress::Closed,
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    if self.buf.len() > 4 + MAX_MESSAGE_BYTES {
                        respond(&mut self.stream, &Reply::Error("request too large".into()));
                        return Progress::Closed;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Progress::Closed,
            }
        }
        if self.buf.len() < 4 {
            return Progress::Incomplete;
        }
        let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_MESSAGE_BYTES {
            respond(&mut self.stream, &Reply::Error("request too large".into()));
            return Progress::Closed;
        }
        if self.buf.len() < 4 + len {
            return Progress::Incomplete;
        }
        match Request::decode(&self.buf[4..4 + len]) {
            Ok(r) => Progress::Request(r),
            Err(e) => {
                respond(&mut self.stream, &Reply::Error(e.to_string()));
                Progress::Closed
            }
        }
    }
}

/// Send a reply. Blocking with a short timeout: a reply is at most a few
/// KB and a peer that will not drain that is not one worth waiting on.
pub fn respond(stream: &mut UnixStream, reply: &Reply) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let bytes = reply.encode();
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&bytes);
    if let Err(e) = stream.write_all(&frame) {
        log::warn(format_args!("control: reply failed: {e}"));
    }
}
