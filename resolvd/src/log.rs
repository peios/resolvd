//! Lines on stderr, mirrored to the kernel log.
//!
//! peinit captures stderr and forwards it to eventd, which is where these
//! lines actually end up and how to read them:
//!
//! ```sh
//! evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 40'
//! ```
//!
//! Every line is *also* written to `/dev/kmsg`, so that on an image with no
//! collector it still reaches `dmesg` and the serial console. That mirror
//! is best-effort and, for resolvd, always fails: `/dev/kmsg` is writable by
//! SYSTEM and resolvd is LocalService (PEI-581). The failure is reported
//! once on stderr, so do not go looking for these on the console — ask
//! eventd.

use std::fmt::Arguments;
use std::io::Write;
use std::sync::OnceLock;

/// The one line written to stderr when the kmsg mirror cannot be opened.
///
/// Written directly rather than through [`emit`]: `emit` calls [`kmsg`], and
/// re-entering a `OnceLock` while it is initialising deadlocks.
fn mirror_unavailable(err: &std::io::Error) -> String {
    format!("resolvd: warn: /dev/kmsg mirror unavailable ({err}): log lines go to stderr only\n")
}

fn kmsg() -> Option<&'static std::fs::File> {
    static KMSG: OnceLock<Option<std::fs::File>> = OnceLock::new();
    KMSG.get_or_init(
        || match std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            Ok(file) => Some(file),
            Err(err) => {
                // Say so once, on stderr, where peinit's forwarder picks it
                // up. Discarding this is how PEI-581 went unnoticed through
                // three daemons: a mirror that opens nothing looks identical
                // to a mirror nobody is reading.
                let _ = std::io::stderr().write_all(mirror_unavailable(&err).as_bytes());
                None
            }
        },
    )
    .as_ref()
}

fn emit(level: &str, args: Arguments<'_>) {
    let line = format!("resolvd: {level}: {args}\n");
    let _ = std::io::stderr().write_all(line.as_bytes());
    if let Some(mut k) = kmsg() {
        // One write per record: kmsg turns every write(2) into a line, so the
        // text is assembled first rather than streamed piecewise.
        // <6> is KERN_INFO; warnings and errors use <4> and <3>.
        let priority = match level {
            "error" => 3,
            "warn" => 4,
            _ => 6,
        };
        let _ = k.write_all(format!("<{priority}>{line}").as_bytes());
    }
}

pub fn info(args: Arguments<'_>) {
    emit("info", args);
}

pub fn warn(args: Arguments<'_>) {
    emit("warn", args);
}

pub fn error(args: Arguments<'_>) {
    emit("error", args);
}

#[cfg(test)]
mod tests {
    use super::mirror_unavailable;

    #[test]
    fn mirror_unavailable_names_the_daemon_the_path_and_the_cause() {
        let line = mirror_unavailable(&std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(line.starts_with("resolvd: warn: "), "{line}");
        assert!(line.contains("/dev/kmsg"), "{line}");
        assert!(line.to_lowercase().contains("permission denied"), "{line}");
        assert_eq!(line.matches('\n').count(), 1, "one line per record: {line}");
        assert!(line.ends_with('\n'), "{line}");
    }
}
