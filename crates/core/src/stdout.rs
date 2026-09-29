//! The one place stdout is written (cadence-hooks#980).
//!
//! `println!` panics on any write error. On Unix the binary restores the
//! default `SIGPIPE` disposition (`src/sigpipe.rs`), so a closed pipe kills the
//! process quietly before the write returns. Windows has no `SIGPIPE`: the
//! write fails with `ErrorKind::BrokenPipe` and `println!` would turn an
//! ordinary `cadence-hooks doctor | head -1` into a panic and a false
//! `"reason":"panic"` failopen row. [`out!`] / [`outln!`] own that decision:
//! a `BrokenPipe` means the reader is gone, which is not a defect, so it is
//! dropped and the caller carries on (exit codes and ledgers are unaffected).
//! Any other error — a full disk, a closed file — stays loud and panics with
//! `println!`'s own message, so real failures still reach the panic hook.
//!
//! `tests/no_bare_println.rs` fails when a bare `println!`/`print!` appears in
//! shipped source, keeping every writer on this path.

use std::fmt;
use std::io::{self, ErrorKind, Write};

/// Write `args` (plus a newline when `newline`) to `w`, treating a
/// `BrokenPipe` as success. Any other error is returned.
pub fn write_ignoring_broken_pipe<W: Write>(
    w: &mut W,
    args: fmt::Arguments<'_>,
    newline: bool,
) -> io::Result<()> {
    let result = if newline {
        w.write_fmt(format_args!("{args}\n"))
    } else {
        w.write_fmt(args)
    };
    match result {
        Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// Backend of [`out!`] / [`outln!`]: locked stdout, `BrokenPipe` swallowed,
/// any other failure a panic (as `println!` would).
#[doc(hidden)]
pub fn write_stdout(args: fmt::Arguments<'_>, newline: bool) {
    let mut out = io::stdout().lock();
    if let Err(e) = write_ignoring_broken_pipe(&mut out, args, newline) {
        panic!("failed printing to stdout: {e}");
    }
}

/// `print!` that ignores a closed stdout pipe.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::stdout::write_stdout(format_args!($($arg)*), false)
    };
}

/// `println!` that ignores a closed stdout pipe.
#[macro_export]
macro_rules! outln {
    () => {
        $crate::stdout::write_stdout(format_args!(""), true)
    };
    ($($arg:tt)*) => {
        $crate::stdout::write_stdout(format_args!($($arg)*), true)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailWith(ErrorKind);
    impl Write for FailWith {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn broken_pipe_is_swallowed_and_other_errors_surface() {
        for (kind, newline, swallowed) in [
            (ErrorKind::BrokenPipe, true, true),
            (ErrorKind::BrokenPipe, false, true),
            (ErrorKind::StorageFull, true, false),
            (ErrorKind::PermissionDenied, false, false),
            (ErrorKind::Other, true, false),
        ] {
            let r = write_ignoring_broken_pipe(&mut FailWith(kind), format_args!("x"), newline);
            assert_eq!(r.is_ok(), swallowed, "{kind:?} newline={newline}");
        }
    }

    #[test]
    fn writes_the_text_with_and_without_newline() {
        let mut buf = Vec::new();
        write_ignoring_broken_pipe(&mut buf, format_args!("a{}", 1), true).unwrap();
        write_ignoring_broken_pipe(&mut buf, format_args!("b"), false).unwrap();
        assert_eq!(buf, b"a1\nb");
    }
}
