//! Connect without waiting indefinitely for space in the local listener queue.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

pub(super) fn connect_socket(path: &Path) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is plain C storage; all fields are initialized below.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid resolver socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    // SAFETY: constants request a new nonblocking, close-on-exec Unix stream.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is newly allocated and uniquely owned here.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    // SAFETY: the initialized address covers length bytes and socket remains owned.
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            length as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let stream = UnixStream::from(socket);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_full_listener_queue_returns_without_blocking() {
        let directory =
            std::env::temp_dir().join(format!("nss-resolver-queue-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("socket");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // SAFETY: the live listener is a stream socket; backlog zero keeps this test small.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let first = connect_socket(&path).unwrap();
        let (done, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            done.send(connect_socket(&path)).unwrap();
        });
        let error = wait
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        worker.join().unwrap();
        drop((first, listener));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
