//! Keep an accept error from turning a readable listener into a busy loop.

use std::os::fd::RawFd;
use std::time::{Duration, Instant};

const RETRY_DELAY: Duration = Duration::from_millis(250);

#[derive(Default)]
pub struct AcceptBackoff {
    until: Option<Instant>,
}

impl AcceptBackoff {
    pub fn failed(&mut self, now: Instant) {
        self.until = Some(now + RETRY_DELAY);
    }

    pub fn deadline(&self, now: Instant) -> Option<Instant> {
        self.until.filter(|t| *t > now)
    }

    pub fn poll_fd(&self, fd: RawFd, now: Instant) -> RawFd {
        if self.deadline(now).is_some() { -1 } else { fd }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_pauses_only_until_the_retry_deadline() {
        let now = Instant::now();
        let mut backoff = AcceptBackoff::default();
        assert_eq!(backoff.poll_fd(7, now), 7);
        backoff.failed(now);
        assert_eq!(backoff.poll_fd(7, now), -1);
        assert_eq!(backoff.deadline(now), Some(now + RETRY_DELAY));
        // Expiry must remove the deadline even if nobody is waiting to
        // connect: a stale past deadline would itself cause a busy loop.
        assert_eq!(backoff.poll_fd(7, now + RETRY_DELAY), 7);
        assert_eq!(backoff.deadline(now + RETRY_DELAY), None);
    }
}
