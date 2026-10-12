//! Kernel CSPRNG input for upstream queries; never fall back to a clock or PRNG.

use std::io;

pub fn fill(out: &mut [u8]) -> io::Result<()> {
    let result = fill_with(out, |remaining| {
        // SAFETY: the kernel writes at most the length of this live mutable slice.
        let n = unsafe {
            libc::getrandom(
                remaining.as_mut_ptr().cast(),
                remaining.len(),
                libc::GRND_NONBLOCK,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    });
    if let Err(err) = &result {
        resolvd::log::error(format_args!("query entropy unavailable: {err}"));
    }
    result
}

fn fill_with(
    mut out: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> io::Result<()> {
    while !out.is_empty() {
        match read(out) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => out = &mut out[n..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_and_short_reads_fill_the_entire_request() {
        let mut calls = 0;
        let mut out = [0; 5];
        fill_with(&mut out, |remaining| {
            calls += 1;
            if calls == 1 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = remaining.len().min(2);
            remaining[..n].fill(calls);
            Ok(n)
        })
        .unwrap();
        assert_eq!(out, [2, 2, 3, 3, 4]);
    }

    #[test]
    fn failures_and_zero_reads_are_not_replaced_with_other_entropy() {
        let mut out = [0; 34];
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Unsupported,
            io::ErrorKind::WouldBlock,
        ] {
            assert_eq!(
                fill_with(&mut out, |_| Err(kind.into()))
                    .unwrap_err()
                    .kind(),
                kind
            );
        }
        assert_eq!(
            fill_with(&mut out, |_| Ok(0)).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn kernel_fills_query_entropy() {
        fill(&mut [0; 34]).unwrap();
    }
}
