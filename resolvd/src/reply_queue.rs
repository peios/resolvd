//! Bounded nonblocking writes for replies whose peer is not draining them.

use std::collections::HashMap;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

pub const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
pub const MAX_PENDING_REPLIES: usize = 256;

pub struct Replies<S> {
    pending: HashMap<u64, Pending<S>>,
    next_id: u64,
}

struct Pending<S> {
    stream: S,
    frame: Vec<u8>,
    sent: usize,
    deadline: Instant,
}

impl<S> Default for Replies<S> {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            next_id: 0,
        }
    }
}

impl<S: Write + AsRawFd> Replies<S> {
    /// The caller supplies an already-nonblocking stream and a bounded frame.
    /// Try once even when full, so stalled peers cannot exclude ready readers.
    pub fn enqueue(&mut self, mut stream: S, frame: Vec<u8>, now: Instant) -> io::Result<()> {
        let sent = write_once(&mut stream, &frame)?;
        if sent == frame.len() {
            return Ok(());
        }
        if self.pending.len() >= MAX_PENDING_REPLIES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many pending replies",
            ));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.pending.insert(
            id,
            Pending {
                stream,
                frame,
                sent,
                deadline: now + WRITE_TIMEOUT,
            },
        );
        Ok(())
    }

    pub fn fds(&self) -> Vec<(u64, RawFd)> {
        self.pending
            .iter()
            .map(|(&id, p)| (id, p.stream.as_raw_fd()))
            .collect()
    }

    pub fn service(&mut self, id: u64, now: Instant) -> io::Result<()> {
        let Some(mut pending) = self.pending.remove(&id) else {
            return Ok(());
        };
        if pending.deadline <= now {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "reply write deadline expired",
            ));
        }
        pending.sent += write_once(&mut pending.stream, &pending.frame[pending.sent..])?;
        if pending.sent < pending.frame.len() {
            self.pending.insert(id, pending);
        }
        Ok(())
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.values().map(|p| p.deadline).min()
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.pending.len();
        self.pending.retain(|_, p| p.deadline > now);
        before - self.pending.len()
    }
}

fn write_once(stream: &mut impl Write, bytes: &[u8]) -> io::Result<usize> {
    match stream.write(bytes) {
        Ok(0) => Err(io::ErrorKind::WriteZero.into()),
        Ok(n) => Ok(n),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(0)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    fn slow_pair() -> (UnixStream, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let size: libc::c_int = 1024;
        // SAFETY: live descriptor and initialized integer option value.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        (stream, peer)
    }

    #[test]
    fn partial_reply_resumes_without_loss_and_does_not_block_another_peer() {
        let now = Instant::now();
        let mut replies = Replies::default();
        let (stream, mut peer) = slow_pair();
        let frame: Vec<u8> = (0..60_000).map(|i| (i % 251) as u8).collect();
        replies.enqueue(stream, frame.clone(), now).unwrap();
        let id = replies.fds()[0].0;
        for _ in 0..4 {
            replies.service(id, now).unwrap();
        }
        let (other, mut other_peer) = slow_pair();
        replies
            .enqueue(other, b"another reply".to_vec(), now)
            .unwrap();
        let mut small = Vec::new();
        other_peer.read_to_end(&mut small).unwrap();
        assert_eq!(small, b"another reply");
        assert_eq!(replies.next_deadline(), Some(now + WRITE_TIMEOUT));
        let mut received = Vec::new();
        let mut closed = false;
        for _ in 0..100 {
            replies.service(id, now).unwrap();
            let mut chunk = [0; 4096];
            match peer.read(&mut chunk) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("read: {e}"),
            }
        }
        assert!(closed);
        assert_eq!(received, frame);
        assert!(replies.fds().is_empty());
    }

    #[test]
    fn progress_does_not_extend_the_write_deadline() {
        let now = Instant::now();
        let mut replies = Replies::default();
        let (stream, mut peer) = slow_pair();
        replies.enqueue(stream, vec![42; 60_000], now).unwrap();
        let id = replies.fds()[0].0;
        let mut chunk = [0; 4096];
        assert!(peer.read(&mut chunk).unwrap() > 0);
        replies
            .service(id, now + Duration::from_millis(500))
            .unwrap();
        assert_eq!(replies.next_deadline(), Some(now + WRITE_TIMEOUT));
        assert_eq!(replies.expire(now + WRITE_TIMEOUT), 1);
        assert!(replies.fds().is_empty());
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).unwrap();
        assert!(rest.len() < 60_000);
    }

    #[test]
    fn a_failed_write_removes_its_pending_reply() {
        let now = Instant::now();
        let mut replies = Replies::default();
        let (stream, peer) = slow_pair();
        replies.enqueue(stream, vec![42; 60_000], now).unwrap();
        let id = replies.fds()[0].0;
        drop(peer);
        assert!(replies.service(id, now).is_err());
        assert!(replies.fds().is_empty());
    }

    struct Writer {
        blocked: bool,
        written: Rc<RefCell<Vec<u8>>>,
    }
    impl AsRawFd for Writer {
        fn as_raw_fd(&self) -> RawFd {
            -1
        }
    }
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.written.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_full_queue_rejects_only_another_stalled_reply_and_recovers_on_expiry() {
        let now = Instant::now();
        let mut replies = Replies::default();
        let written = Rc::new(RefCell::new(Vec::new()));
        let writer = |blocked| Writer {
            blocked,
            written: written.clone(),
        };
        for _ in 0..MAX_PENDING_REPLIES {
            replies.enqueue(writer(true), vec![1], now).unwrap();
        }
        assert!(replies.enqueue(writer(true), vec![2], now).is_err());
        replies.enqueue(writer(false), vec![3], now).unwrap();
        assert_eq!(&*written.borrow(), &[3]);
        assert_eq!(replies.expire(now + WRITE_TIMEOUT), MAX_PENDING_REPLIES);
        replies
            .enqueue(writer(true), vec![4], now + WRITE_TIMEOUT)
            .unwrap();
        assert_eq!(replies.fds().len(), 1);
    }
}
