// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Local file timestamps: the `-R, --remote-time` writer and the
//! `-z, --time-cond` reader.
//!
//! This module supersedes one C translation unit, `src/tool_filetime.c`
//! (152 lines), which provides `-R` timestamp preservation. It carries both
//! of that file's functions:
//!
//! | Item | C origin | Purpose |
//! |---|---|---|
//! | [`getfiletime`] | `src/tool_filetime.c:35-83` | read a local file's modification time, so `-z <file>` can compare against it |
//! | [`setfiletime`] | `src/tool_filetime.c:86-150` | stamp the saved file with the server's `Last-Modified`, which is what `-R` does |
//!
//! # It needs neither `unsafe` nor a dependency
//!
//! `std::fs::FileTimes`, `FileTimes::set_accessed`, `FileTimes::set_modified`
//! and `std::fs::File::set_times` were all stabilised in Rust 1.75.0 -- the
//! exact MSRV this workspace declares (`Cargo.toml`'s
//! `[workspace.package] rust-version = "1.75"`, echoed by `clippy.toml`'s
//! `msrv = "1.75"`). Measured, not assumed: every API this module uses --
//! those four plus `OsStr::as_encoded_bytes`, `i64::unsigned_abs` and
//! `MetadataExt::mtime`/`mtime_nsec` -- compiles under
//! `rustup run 1.75.0 rustc --edition 2021`. There is therefore no gap to
//! bridge here, and consequently no `filetime`, `chrono`, `nix` or `libc`
//! dependency and no hand-written `utimes`/`utimensat`/`futimens` call.
//! Nothing here asks for an `unsafe` exemption, and nothing in this crate can
//! grant one: `curl-rs` has no `mod ffi`, which is why the literal
//! `#![forbid(unsafe_code)]` applies to both of its roots -- `src/main.rs` and
//! `src/bin/curlinfo.rs` -- unlike `curl-rs-lib`, whose FFI island needs an
//! inner `#[allow(unsafe_code)]` that `forbid` rejects as `error[E0453]`, so
//! its root carries `#![deny(unsafe_code)]` with exactly one exemption
//! instead.
//!
//! # The two frozen texts
//!
//! The observable bytes are frozen, so both warnings are
//! reproduced exactly, including the detail that they are *not* symmetrical:
//!
//! | Frozen text | C origin |
//! |---|---|
//! | `Failed to get filetime: %s` -- **no filename**, only the errno string | `src/tool_filetime.c:78-79` |
//! | `Failed to set filetime %<off_t> on '%s': %s` -- value, filename in **single quotes**, errno string | `src/tool_filetime.c:134-136`, repeated verbatim at `:145-147` |
//!
//! Both route through [`crate::output::msgs`], which owns the `Warning: `
//! prefix (`src/tool_msgs.c:30`) and the `!silent` gate
//! (`src/tool_msgs.c:95`). The format strings stay here, at their call sites,
//! exactly as each `warnf(...)` in C holds its own literal; hoisting them into
//! the channel would create a second source of truth.
//!
//! A failure of either function is a *warning*, never an error. C returns
//! `void` from `setfiletime` and the transfer still succeeds, so nothing here
//! escalates.
//!
//! # What is deliberately absent
//!
//! The Windows arms -- `src/tool_filetime.c:42-69` (`curlx_CreateFile` plus
//! `GetFileTime`) and `:91-126` (`SetFileTime`, the `910670515199` and
//! `-6857222400` clamps, and the two `Capping set filetime ...` warnings) --
//! are out of scope, because the four mandated targets are
//! `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
//! `x86_64-apple-darwin` and `aarch64-apple-darwin`. No `#[cfg(windows)]` arm
//! is added.
//!
//! One consequence is easy to miss and is load-bearing: **the clamps live only
//! in the Windows arm**, so the live Unix path must not reject an out-of-range
//! value, it must carry it arithmetically. That is why [`setfiletime`] accepts
//! a negative `filetime` -- a pre-1970 `Last-Modified` -- instead of treating
//! it as an error. Confirmed against a C oracle built from `:128-137`: real
//! `utimes` accepts `-1`, `-6857222400`, `i64::MIN` and `i64::MAX` alike and
//! lets the kernel clamp, and so does this module.
//!
//! # Three documented translation differences
//!
//! None changes the emitted bytes at curl's own call sites, and none required
//! `unsafe`, a new dependency, or dropping a behaviour. They are recorded so a
//! later reader does not mistake any of them for an oversight.
//!
//! ## 1. `utimes` takes a path; `File::set_times` needs an open handle
//!
//! `src/tool_filetime.c:132` calls `utimes(filename, times)` on a *path*.
//! Rust's safe equivalent is a method on an open [`std::fs::File`], which
//! lowers to `futimens` on both mandated operating systems -- the same
//! effective operation on the same inode -- but it has to open the file first,
//! and the open can fail where `utimes` would have succeeded.
//!
//! Two manifestations, both measured against a C oracle built from the live
//! `utimes` arm of `src/tool_filetime.c:128-137`:
//!
//! * a *directory* -- `utimes()` succeeds, whereas
//!   `OpenOptions::new().write(true).open(<directory>)` fails with
//!   `Is a directory (os error 21)`;
//! * a *read-only regular file owned by the caller*, observed as a non-root
//!   user -- `utimes()` succeeds, because it requires ownership rather than
//!   write permission, whereas the open fails with
//!   `Permission denied (os error 13)`.
//!
//! Why this is unreachable at curl's only call site: `setfiletime` is invoked
//! from exactly one place, `src/tool_operate.c:696-701`, and the guard there
//! is `if(!result && config->remote_time && outs->regular_file &&
//! outs->filename)`. Both conjuncts matter, and between them they exclude both
//! manifestations: `outs->regular_file` rules out the directory case, and
//! `!result` means the transfer succeeded, which means curl had already
//! created, written and closed this same file, so it was writable by the
//! process moments earlier and the read-only case cannot arise either. For the
//! residual cases -- reachable only if another process changes the mode or
//! replaces the path between the close and this call -- the
//! observable behaviour is still matched rather than lost: an open failure
//! emits the same frozen `Failed to set filetime ...` warning, with the same
//! errno text, that a `utimes` failure would have emitted. The common failure
//! is byte-identical -- measured, both `utimes()` and this module report
//! `No such file or directory` for a path that does not exist.
//!
//! Closing the gap completely would need a safe path-based timestamp setter,
//! which `std` does not offer. The only faithful alternative would be a
//! `utimensat` wrapper added to `curl-rs-lib/src/ffi/sys.rs` -- the one
//! sanctioned `unsafe` island in the engine --
//! exposed through a safe `pub` function. That is an engine change, outside
//! this file's scope, and it is not required by any behaviour reachable from
//! curl's command line; it is named here so the option is on record rather
//! than rediscovered.
//!
//! ## 2. `std` has no `strerror`, so the ` (os error N)` suffix is stripped
//!
//! `src/tool_filetime.c:79` and `:136` render the errno with
//! `curlx_strerror(errno, errbuf, sizeof(errbuf))`, which yields the bare
//! system text. Rust's `std::io::Error` `Display` appends the numeric code:
//! measured, `No such file or directory (os error 2)` against C's
//! `No such file or directory`. `std` exposes no `strerror`, and re-creating
//! `curlx_strerror` is ruled out -- this migration retires the duplicate
//! compilation of `../lib/curlx/*.c` into the tool that
//! `src/Makefile.inc:33-51`
//! arranges ("we reuse the code here to avoid duplication"), stating that it
//! "disappears entirely; the CLI depends on the library crate instead".
//!
//! The suffix is therefore removed by `curl_rs_lib::os_error_message`, the
//! engine's single renderer, and **not** by anything in this file. That is the
//! same conclusion AAP section 0.4.2 reaches for `curlx`: the CLI depends on
//! the library crate. It also fixes a real divergence rather than merely
//! tidying one up -- this file once carried its own fixed-point stripper while
//! `output/formparse.rs` carried a single-pass one, so the same kind of error
//! produced different frozen bytes in different diagnostics of the same tool.
//!
//! ## 3. `int rc = 1` becomes the value of the failing branch
//!
//! `src/tool_filetime.c:37` initialises `rc` to failure and overwrites it only
//! on success. [`getfiletime`] returns [`FILETIME_FAILURE`] from its error arm
//! instead, which preserves both halves of the contract at `:34` -- "Returns 0
//! on success, non-zero on file problems" -- and the property its caller
//! depends on: `src/tool_getparam.c:1635-1637` declares `curl_off_t value;`
//! *uninitialised* and reads it only `if(!rc)`, so `stamp` must be left
//! untouched on failure. Here it is assigned in the success arm alone, which
//! makes that guarantee structural rather than incidental.

use std::fs::{self, FileTimes, OpenOptions};
use std::io::{self};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::output::msgs::{warnf, warnf_bytes, DiagnosticSink, MsgConfig};

/// The `int` [`getfiletime`] returns when the timestamp was read.
///
/// `src/tool_filetime.c:74` reaches this by assigning `rc = 0`, and the
/// contract at `:34` is "Returns 0 on success, non-zero on file problems".
#[allow(dead_code)]
pub(crate) const FILETIME_SUCCESS: i32 = 0;

/// The `int` [`getfiletime`] returns when the file could not be inspected.
///
/// `src/tool_filetime.c:37` -- `int rc = 1;`. The caller at
/// `src/tool_getparam.c:1637` only tests it for truth (`if(!rc)`), so the
/// exact magnitude is not observable, but 1 is the value C yields and there is
/// no reason to pick another.
#[allow(dead_code)]
pub(crate) const FILETIME_FAILURE: i32 = 1;

/// `EINVAL`, reported when the requested instant cannot be represented.
///
/// 22 on every one of the four mandated targets: Linux and Darwin agree on
/// this part of the errno range, so no platform selection is needed and no
/// `libc` dependency is introduced to look it up.
///
/// This is the errno POSIX specifies for a `utimes` whose `times` argument
/// cannot be used, so reporting it keeps the frozen warning's `%s` faithful
/// rather than inventing a message C could never print.
///
/// The arm is defensive rather than reachable: `SystemTime::UNIX_EPOCH` sits at
/// `tv_sec == 0`, so offsetting it by `i64::unsigned_abs` can never overflow
/// the `i64` seconds field, and both `i64::MIN` and `i64::MAX` were measured to
/// yield `Some`. It exists so that [`filetime_to_times`] has no panicking path,
/// as AAP section 0.7 requires of this crate.
#[allow(dead_code)]
const EINVAL: i32 = 22;

// `strerror` rendering: not implemented here.
//
// `src/tool_filetime.c:79` and `:136` render the errno with
// `curlx_strerror(errno, errbuf, sizeof(errbuf))`, and both frozen texts take
// their `%s` from `curl_rs_lib::os_error_message`, the workspace's single
// renderer. See translation difference 2 in the module documentation for why
// `std` needs a renderer at all, and `curl-rs-lib`'s own documentation for the
// measured reason the annotation is stripped to a fixed point rather than once.
//
// A second, independent fixed-point implementation used to live here. It agreed
// with the engine's by coincidence rather than by construction, and it did not
// agree with `output/formparse.rs`'s single-pass one, so the same kind of error
// rendered different bytes in different diagnostics of the same tool. Nothing
// is defined in this section on purpose: a private copy here would restore that
// drift.

/// Reads a local file's modification time.
///
/// `src/tool_filetime.c:35-83`, live Unix arm `:70-81`. Returns
/// [`FILETIME_SUCCESS`] when `stamp` has been written and
/// [`FILETIME_FAILURE`] otherwise -- the contract stated at `:34`, "Returns 0
/// on success, non-zero on file problems".
///
/// `stamp` is written **only** on success, because
/// `src/tool_getparam.c:1635-1637` passes an uninitialised `curl_off_t value;`
/// and reads it only `if(!rc)`.
///
/// The time comes from [`MetadataExt::mtime`], which is `st_mtime` -- exactly
/// the field `:73` casts to `curl_off_t` -- as whole signed seconds, so a
/// pre-1970 file yields a negative stamp here just as it does in C.
/// [`fs::metadata`] follows symbolic links, matching C's `curlx_stat`, which is
/// `stat()` rather than `lstat()`.
///
/// A failure emits the frozen `Failed to get filetime: %s` of `:78-79`. That
/// text carries **no filename**; only the errno string follows. Its sibling
/// [`setfiletime`] does include one, and the asymmetry is deliberate on C's
/// part, so it is preserved.
///
/// The Windows arm at `:42-69` is out of scope; see the
/// module documentation.
#[allow(dead_code)]
pub(crate) fn getfiletime(
    sink: &mut dyn DiagnosticSink,
    config: &MsgConfig,
    filename: &Path,
    stamp: &mut i64,
) -> i32 {
    match fs::metadata(filename) {
        Ok(metadata) => {
            // `:73-74`
            *stamp = metadata.mtime();
            FILETIME_SUCCESS
        }
        Err(error) => {
            // `:77-79`. The literal is the frozen text; it must not gain the
            // filename that `setfiletime`'s message carries.
            let reason = curl_rs_lib::os_error_message(&error);
            warnf(
                sink,
                config,
                format_args!("Failed to get filetime: {reason}"),
            );
            // `:37` -- the value `rc` was initialised to.
            FILETIME_FAILURE
        }
    }
}

/// Stamps a local file with a remote modification time: `-R, --remote-time`.
///
/// `src/tool_filetime.c:86-150`, live `HAVE_UTIMES` arm `:128-137`. Both the
/// access time and the modification time are set, to the **same whole second**,
/// with a **zero sub-second component** -- `:130-131` assign
/// `times[0].tv_sec = times[1].tv_sec = (time_t)filetime` and
/// `times[0].tv_usec = times[1].tv_usec = 0`. The `HAVE_UTIME` fallback at
/// `:139-148` does the same through `times.actime` and `times.modtime` and
/// carries a byte-identical warning at `:145-147`, so one implementation
/// satisfies both.
///
/// A negative `filetime` -- a pre-1970 `Last-Modified` -- is applied, not
/// rejected: the clamps of the Windows arm at `:96-105` have no counterpart on
/// this path, and a C oracle built from `:128-137` was measured accepting
/// `-1`, `-6857222400`, `i64::MIN` and `i64::MAX`.
///
/// Any failure emits the frozen `Failed to set filetime %<off_t> on '%s': %s`
/// of `:134-136` -- the value, then the filename in single quotes, then the
/// errno text -- and returns normally. C's return type is `void` and its only
/// caller ignores the outcome, so a failure here must never become an error
/// for the transfer.
///
/// The filename reaches the message as raw operating-system bytes, matching
/// C's `%s` over a `char *`; see [`set_failure_message`].
///
/// The Windows arm at `:91-126` is out of scope, as is its
/// pair of `Capping set filetime ...` warnings. See translation difference 1 in
/// the module documentation for the path-versus-handle consequence of using
/// `std`.
#[allow(dead_code)]
pub(crate) fn setfiletime(
    sink: &mut dyn DiagnosticSink,
    config: &MsgConfig,
    filetime: i64,
    filename: &Path,
) {
    // `:132` -- C tests `utimes`' non-zero return; the failing branch below is
    // that `if` body, and the success branch is C's fall-through.
    if let Err(error) = apply_filetime(filetime, filename) {
        // `:133-136`
        let message = set_failure_message(filetime, filename, &error);
        warnf_bytes(sink, config, &message);
    }
}

/// The `utimes` call of `src/tool_filetime.c:132`, expressed safely.
///
/// Separated from [`setfiletime`] so that the operation and its diagnostic are
/// independently testable, and so that the three ways it can fail -- an
/// unrepresentable instant, a failed open, and a failed `set_times` -- all
/// converge on the single frozen warning, exactly as C's one `if` does.
#[allow(dead_code)]
fn apply_filetime(filetime: i64, filename: &Path) -> io::Result<()> {
    let times = filetime_to_times(filetime)?;

    // Translation difference 1: `utimes` takes a path, `File::set_times` needs
    // an open handle. `write(true)` matches the intent of a timestamp change
    // and, at curl's only call site (`src/tool_operate.c:696`, guarded by
    // `outs->regular_file`), the target is a regular file curl has just
    // written, so the open cannot fail for want of permission. `create` is
    // deliberately absent: `utimes` never creates, and neither may this.
    let file = OpenOptions::new().write(true).open(filename)?;

    file.set_times(times)
}

/// Builds the `struct timeval times[2]` of `src/tool_filetime.c:129-131`.
///
/// One instant, used for both the access time and the modification time, with
/// no sub-second component -- [`Duration::from_secs`] contributes exactly zero
/// nanoseconds, which is what `tv_usec = 0` means.
///
/// `unsigned_abs` is used on both branches rather than an `as` cast, so no
/// value is ever silently truncated or reinterpreted: it yields the magnitude
/// as `u64`, and the sign selects the direction from the epoch. This is what
/// makes a pre-1970 timestamp work.
#[allow(dead_code)]
fn filetime_to_times(filetime: i64) -> io::Result<FileTimes> {
    let magnitude = Duration::from_secs(filetime.unsigned_abs());

    let instant = if filetime < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(magnitude)
    } else {
        SystemTime::UNIX_EPOCH.checked_add(magnitude)
    };

    // Unreachable for any `i64` -- see [`EINVAL`] -- but handled rather than
    // unwrapped, so this function has no panicking path.
    let Some(instant) = instant else {
        return Err(io::Error::from_raw_os_error(EINVAL));
    };

    // `:130-131` -- the same instant for both, sub-second component zero.
    Ok(FileTimes::new().set_accessed(instant).set_modified(instant))
}

/// Renders the frozen warning of `src/tool_filetime.c:134-136`.
///
/// ```text
/// Failed to set filetime %" CURL_FORMAT_CURL_OFF_T " on '%s': %s
/// ```
///
/// Built as bytes rather than as a `String` because the middle `%s` is a
/// filename. `include/curl/system.h:53`, `:86` and `:106` make `curl_off_t` a
/// 64-bit signed type on all four mandated targets, and
/// `CURL_FORMAT_CURL_OFF_T` is `"lld"` or `"ld"` -- plain signed decimal,
/// including the leading `-`, which is exactly what `{}` produces for an
/// `i64`.
///
/// The filename is appended with `OsStr::as_encoded_bytes`, which on the four
/// mandated targets is the raw byte sequence the operating system gave us and
/// therefore what C's `%s` would print. Going through `Path::display` or
/// `to_string_lossy` instead would substitute U+FFFD for any non-UTF-8 byte and
/// change the emitted bytes, which the frozen-output rule does not permit. This
/// is why the message is handed to
/// [`warnf_bytes`](crate::output::msgs::warnf_bytes) rather than to
/// [`warnf`](crate::output::msgs::warnf).
///
/// The single quotes around the filename are part of the frozen text. So is
/// the absence of a filename from [`getfiletime`]'s message.
#[allow(dead_code)]
fn set_failure_message(
    filetime: i64,
    filename: &Path,
    error: &io::Error,
) -> Vec<u8> {
    let mut message = Vec::new();

    // `:134` -- "Failed to set filetime %" CURL_FORMAT_CURL_OFF_T
    message.extend_from_slice(
        format!("Failed to set filetime {filetime}").as_bytes(),
    );

    // `:135` -- " on '%s'", the filename as raw operating-system bytes.
    message.extend_from_slice(b" on '");
    message.extend_from_slice(filename.as_os_str().as_encoded_bytes());

    // `:135-136` -- "': %s", closing quote then the errno text.
    message.extend_from_slice(b"': ");
    message.extend_from_slice(curl_rs_lib::os_error_message(error).as_bytes());

    message
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    use crate::output::msgs::WARN_PREFIX;

    /// A timestamp comfortably inside every filesystem's range, chosen so that
    /// a wrong sign or a truncated cast would be obvious in a failure message.
    const SAMPLE_STAMP: i64 = 1_234_567_890;

    /// A pre-1970 timestamp: the case the Windows-only clamps at
    /// `src/tool_filetime.c:100-105` would have rejected and this path must
    /// not.
    const PRE_EPOCH_STAMP: i64 = -1_234_567_890;

    /// Binds a scratch directory, failing the test loudly if the environment
    /// cannot provide one.
    ///
    /// A macro rather than a function because the failure arm has to leave the
    /// *test*, and because `unwrap`, `expect`, `panic!` and `unreachable!` are
    /// avoided throughout this file. The `let ... else` arm is unreachable --
    /// the assertion above it has already failed the test -- but it keeps the
    /// binding free of any panicking construct.
    macro_rules! scratch {
        ($name:ident) => {
            let $name = tempfile::tempdir();
            assert!(
                $name.is_ok(),
                "this test needs a scratch directory: {:?}",
                $name.as_ref().err()
            );
            let Ok($name) = $name else { return };
        };
    }

    /// Creates a one-byte regular file, asserting that it worked.
    fn touch(path: &Path) {
        let written = fs::write(path, b"x");
        assert!(written.is_ok(), "could not create {path:?}: {written:?}");
    }

    /// Runs [`getfiletime`] against a capturing sink with default gates.
    ///
    /// [`MsgConfig::default`] is all-false, which is the state of C's
    /// zero-initialised `global` before any option is parsed, so warnings are
    /// emitted.
    fn emit_get(filename: &Path, stamp: &mut i64) -> (i32, Vec<u8>) {
        let mut sink: Vec<u8> = Vec::new();
        let rc = getfiletime(&mut sink, &MsgConfig::default(), filename, stamp);
        (rc, sink)
    }

    /// Runs [`setfiletime`] against a capturing sink with default gates.
    fn emit_set(filetime: i64, filename: &Path) -> Vec<u8> {
        let mut sink: Vec<u8> = Vec::new();
        setfiletime(&mut sink, &MsgConfig::default(), filetime, filename);
        sink
    }

    /// Recovers the single message from however many lines `voutf` wrapped it
    /// into.
    ///
    /// `crate::output::msgs` wraps at the terminal width and repeats the
    /// prefix on every line (`src/tool_msgs.c:49`), keeping the blank it broke
    /// on at the end of the preceding line, so concatenating the bodies
    /// reproduces the original exactly. Doing this rather than assuming one
    /// line is what makes these assertions independent of the ambient
    /// `COLUMNS`.
    fn message_of(output: &[u8]) -> Vec<u8> {
        let mut joined = Vec::new();
        for line in output.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let body =
                line.strip_prefix(WARN_PREFIX.as_bytes()).unwrap_or(line);
            joined.extend_from_slice(body);
        }
        joined
    }

    /// Reads back the four timestamp components `set_times` should have
    /// written: seconds and nanoseconds for both the modification and the
    /// access time.
    fn times_of(path: &Path) -> (i64, i64, i64, i64) {
        let metadata = fs::metadata(path);
        assert!(metadata.is_ok(), "could not stat {path:?}: {metadata:?}");
        let Ok(metadata) = metadata else {
            return (0, 0, 0, 0);
        };
        (
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.atime(),
            metadata.atime_nsec(),
        )
    }

    // -- The `strerror` replacement -----------------------------------------

    /// The annotation that `curl_rs_lib::os_error_message` removes and
    /// `curlx_strerror` never produces.
    ///
    /// Kept only so the two assertions below can scan emitted diagnostics for
    /// it. It is deliberately NOT used to render anything: the stripping policy
    /// and its unit tests belong to `curl-rs-lib`, and a second copy of either
    /// is what made the three implementations drift.
    const OS_ERROR_INFIX: &str = " (os error ";

    /// Both frozen texts take their `%s` from the shared renderer.
    ///
    /// The expected values are obtained from that renderer rather than written
    /// out, because the message is the platform's and differs between Linux and
    /// Darwin. What is asserted is the property the centralization exists for:
    /// this file's bytes are the same bytes any other consumer would emit for
    /// the same error. The stripping algorithm itself -- the fixed point, the
    /// Miri double annotation, the near misses and the degenerate inputs -- is
    /// unit-tested where it lives, in `curl-rs-lib`'s `util` module.
    #[test]
    fn the_frozen_texts_use_the_shared_renderer() {
        // `:79` -- `Failed to get filetime: %s`. The error is not synthesised
        // from an errno: the same call is made a second time so the expected
        // text comes from the error the platform actually produced.
        let missing = Path::new("/nonexistent-dir-for-filetime/absent");
        let Err(same_error) = fs::metadata(missing) else {
            panic!("{missing:?} must not exist");
        };
        let expected = curl_rs_lib::os_error_message(&same_error);

        let mut stamp = 0_i64;
        let (rc, sink) = emit_get(missing, &mut stamp);
        assert_eq!(rc, FILETIME_FAILURE);
        let emitted = String::from_utf8_lossy(&sink).into_owned();
        assert!(emitted.contains("Failed to get filetime: "), "{emitted}");
        assert!(
            emitted.contains(expected.as_str()),
            "expected {expected:?} verbatim in {emitted:?}"
        );
        assert!(!emitted.contains(OS_ERROR_INFIX), "{emitted}");

        // `:136` -- the `setfiletime` message ends with the same rendering.
        let invalid = io::Error::from_raw_os_error(EINVAL);
        let invalid_text = curl_rs_lib::os_error_message(&invalid);
        let message = set_failure_message(42, Path::new("/tmp/nope"), &invalid);
        assert!(
            message.ends_with(invalid_text.as_bytes()),
            "{:?}",
            String::from_utf8_lossy(&message)
        );
        assert!(!invalid_text.contains(OS_ERROR_INFIX));
    }

    // -- `setfiletime`: the timestamps actually written --------------------

    /// `src/tool_filetime.c:130-131` sets **both** times to the **same whole
    /// second** with a **zero** sub-second component. All four components are
    /// checked, because a partial implementation that set only `mtime`, or that
    /// left `atime` at "now", would satisfy a weaker assertion.
    #[test]
    fn set_applies_both_times_to_the_same_whole_second() {
        scratch!(dir);
        let path = dir.path().join("stamped");
        touch(&path);

        let output = emit_set(SAMPLE_STAMP, &path);
        assert!(output.is_empty(), "a success must emit nothing: {output:?}");

        let (mtime, mtime_nsec, atime, atime_nsec) = times_of(&path);
        assert_eq!(mtime, SAMPLE_STAMP, "modification time");
        assert_eq!(atime, SAMPLE_STAMP, "access time -- `:130` sets both");
        assert_eq!(mtime_nsec, 0, "`:131` sets tv_usec to 0");
        assert_eq!(atime_nsec, 0, "`:131` sets tv_usec to 0");
    }

    /// A pre-1970 `Last-Modified` must be applied, not rejected: the clamps
    /// live only in the Windows arm (`:96-105`), and the C oracle was measured
    /// accepting negative values.
    ///
    /// Skipped under Miri only, and for a measured reason rather than a
    /// convenient one: Miri's emulated `futimens` rejects a negative `tv_sec`
    /// with `EINVAL`, whereas every real kernel accepts it. That was confirmed
    /// three independent ways -- on `x86_64-unknown-linux-gnu`, on
    /// `aarch64-unknown-linux-gnu` running the cross-built test binary under
    /// `qemu-aarch64`, and against a C oracle calling real `utimes` -- all of
    /// which store `-1234567890` and read it back unchanged. The negative
    /// *arithmetic* stays covered under Miri by
    /// [`filetime_to_times_is_total_over_curl_off_t`], which touches no
    /// filesystem; only the negative *syscall* is skipped.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri's emulated futimens rejects a negative tv_sec; real \
                  kernels and C's utimes accept it"
    )]
    fn set_accepts_a_negative_filetime() {
        scratch!(dir);
        let path = dir.path().join("pre-epoch");
        touch(&path);

        let output = emit_set(PRE_EPOCH_STAMP, &path);
        assert!(output.is_empty(), "a success must emit nothing: {output:?}");

        let (mtime, mtime_nsec, atime, atime_nsec) = times_of(&path);
        assert_eq!(mtime, PRE_EPOCH_STAMP, "the `checked_sub` path");
        assert_eq!(atime, PRE_EPOCH_STAMP, "the `checked_sub` path");
        assert_eq!(mtime_nsec, 0);
        assert_eq!(atime_nsec, 0);
    }

    /// The epoch itself and the second after it: the `filetime < 0` branch
    /// boundary from its non-negative side, which `checked_add` serves.
    #[test]
    fn set_handles_the_epoch_and_the_second_after_it() {
        assert_epoch_offsets_are_applied(&[0, 1]);
    }

    /// The second *before* the epoch: the same boundary from its negative side,
    /// which `checked_sub` serves.
    ///
    /// Split from its non-negative sibling, and skipped under Miri, for the
    /// reason recorded on [`set_accepts_a_negative_filetime`]. Splitting rather
    /// than skipping the whole boundary keeps `0` and `1` covered under Miri.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri's emulated futimens rejects a negative tv_sec; real \
                  kernels and C's utimes accept it"
    )]
    fn set_handles_the_second_before_the_epoch() {
        assert_epoch_offsets_are_applied(&[-1]);
    }

    /// Applies each stamp to a fresh file and checks it round-trips exactly.
    fn assert_epoch_offsets_are_applied(stamps: &[i64]) {
        scratch!(dir);
        for stamp in stamps {
            let path = dir.path().join(format!("boundary{stamp}"));
            touch(&path);
            let output = emit_set(*stamp, &path);
            assert!(output.is_empty(), "{stamp} should succeed: {output:?}");
            let (mtime, _, atime, _) = times_of(&path);
            assert_eq!(mtime, *stamp);
            assert_eq!(atime, *stamp);
        }
    }

    /// No value of `curl_off_t` may be rejected by our own arithmetic: the
    /// Windows clamps are out of scope, so the conversion must be total.
    ///
    /// `SystemTime::UNIX_EPOCH` sits at `tv_sec == 0`, so offsetting it by
    /// `i64::unsigned_abs` cannot overflow the `i64` seconds field. This is
    /// what makes [`EINVAL`] defensive rather than reachable.
    #[test]
    fn filetime_to_times_is_total_over_curl_off_t() {
        for stamp in [
            i64::MIN,
            i64::MIN + 1,
            -6_857_222_400,
            -1,
            0,
            1,
            910_670_515_199,
            i64::MAX,
        ] {
            assert!(
                filetime_to_times(stamp).is_ok(),
                "{stamp} must not be rejected"
            );
        }
    }

    // -- `getfiletime`: reading a timestamp back ---------------------------

    #[test]
    fn get_round_trips_what_set_wrote() {
        scratch!(dir);
        let path = dir.path().join("round-trip");
        touch(&path);
        let _ = emit_set(SAMPLE_STAMP, &path);

        let mut stamp = 0_i64;
        let (rc, output) = emit_get(&path, &mut stamp);
        assert_eq!(rc, FILETIME_SUCCESS, "`:74` -- rc = 0");
        assert!(output.is_empty(), "a success must emit nothing: {output:?}");
        assert_eq!(stamp, SAMPLE_STAMP);
    }

    /// `:73` reads `st_mtime`, which is signed, so a pre-1970 file reads back
    /// negative rather than as a huge positive value.
    ///
    /// Skipped under Miri only, for the reason recorded on
    /// [`set_accepts_a_negative_filetime`]: the negative stamp this reads back
    /// cannot be written there in the first place.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri's emulated futimens rejects a negative tv_sec; real \
                  kernels and C's utimes accept it"
    )]
    fn get_round_trips_a_negative_stamp() {
        scratch!(dir);
        let path = dir.path().join("negative-round-trip");
        touch(&path);
        let _ = emit_set(PRE_EPOCH_STAMP, &path);

        let mut stamp = 0_i64;
        let (rc, _) = emit_get(&path, &mut stamp);
        assert_eq!(rc, FILETIME_SUCCESS);
        assert_eq!(stamp, PRE_EPOCH_STAMP);
    }

    /// C's `curlx_stat` is `stat()`, not `lstat()`, so a symbolic link reports
    /// its target's time.
    #[test]
    fn get_follows_symbolic_links_as_stat_does() {
        scratch!(dir);
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        touch(&target);
        let _ = emit_set(SAMPLE_STAMP, &target);
        let linked = std::os::unix::fs::symlink(&target, &link);
        assert!(linked.is_ok(), "could not create a symlink: {linked:?}");

        let mut stamp = 0_i64;
        let (rc, _) = emit_get(&link, &mut stamp);
        assert_eq!(rc, FILETIME_SUCCESS);
        assert_eq!(stamp, SAMPLE_STAMP, "stat() resolves the link");
    }

    // -- The two frozen warnings -------------------------------------------

    /// `:78-79`. The text carries **no filename**, and the caller contract from
    /// `src/tool_getparam.c:1635-1637` requires `stamp` to be left untouched.
    #[test]
    fn get_on_a_missing_file_fails_and_omits_the_filename() {
        scratch!(dir);
        let path = dir.path().join("absent");

        let sentinel = 0x5AFE_5AFE_i64;
        let mut stamp = sentinel;
        let (rc, output) = emit_get(&path, &mut stamp);

        assert_ne!(rc, FILETIME_SUCCESS, "`:34` -- non-zero on file problems");
        assert_eq!(rc, FILETIME_FAILURE, "`:37` -- rc was initialised to 1");
        assert_eq!(stamp, sentinel, "stamp must be untouched on failure");

        let message = message_of(&output);
        assert_eq!(
            message,
            b"Failed to get filetime: No such file or directory".to_vec(),
            "frozen text of `:78-79`"
        );

        // The filename must not have leaked into this message.
        let name = dir.path().as_os_str().as_encoded_bytes();
        assert!(
            !message.windows(name.len()).any(|window| window == name),
            "`:78-79` has no %s for the filename"
        );
    }

    /// `:134-136`: the value, then the filename in **single quotes**, then the
    /// errno text. A path that does not exist is the case where C and this
    /// module agree byte for byte -- measured, real `utimes` also reports
    /// `No such file or directory`.
    #[test]
    fn set_on_a_missing_file_warns_with_the_frozen_layout() {
        scratch!(dir);
        let path = dir.path().join("absent");

        let output = emit_set(SAMPLE_STAMP, &path);
        assert!(!output.is_empty(), "a failure must warn");
        assert!(
            output.starts_with(WARN_PREFIX.as_bytes()),
            "`src/tool_msgs.c:30` supplies the prefix"
        );

        let mut expected = Vec::new();
        expected.extend_from_slice(b"Failed to set filetime 1234567890 on '");
        expected.extend_from_slice(path.as_os_str().as_encoded_bytes());
        expected.extend_from_slice(b"': No such file or directory");
        assert_eq!(message_of(&output), expected);
    }

    /// The negative rendering of `CURL_FORMAT_CURL_OFF_T`: a plain signed
    /// decimal, leading `-` included.
    #[test]
    fn set_failure_message_renders_a_negative_value_as_decimal() {
        let message = set_failure_message(
            PRE_EPOCH_STAMP,
            Path::new("/tmp/x"),
            &io::Error::from_raw_os_error(2),
        );
        assert_eq!(
            message,
            b"Failed to set filetime -1234567890 on '/tmp/x': \
              No such file or directory"
                .to_vec()
        );
    }

    /// Neither frozen text may carry Rust's ` (os error N)` tail, because
    /// `curlx_strerror` does not produce one.
    #[test]
    fn neither_message_carries_the_os_error_suffix() {
        scratch!(dir);
        let path = dir.path().join("absent");

        let mut stamp = 0_i64;
        let (_, get_output) = emit_get(&path, &mut stamp);
        let set_output = emit_set(SAMPLE_STAMP, &path);

        for (label, output) in
            [("getfiletime", get_output), ("setfiletime", set_output)]
        {
            let message = message_of(&output);
            assert!(!message.is_empty(), "{label} must have warned");
            assert!(
                !message
                    .windows(OS_ERROR_INFIX.len())
                    .any(|window| window == OS_ERROR_INFIX.as_bytes()),
                "{label} leaked the Rust-only suffix: {:?}",
                String::from_utf8_lossy(&message)
            );
        }
    }

    /// A failure is a warning, never an error: C returns `void` and the
    /// transfer continues. The proof is that the next call still works.
    #[test]
    fn a_failure_does_not_escalate_or_poison_later_calls() {
        scratch!(dir);
        let missing = dir.path().join("absent");
        let present = dir.path().join("present");
        touch(&present);

        let failed = emit_set(SAMPLE_STAMP, &missing);
        assert!(!failed.is_empty(), "the failure must warn");

        let succeeded = emit_set(SAMPLE_STAMP, &present);
        assert!(succeeded.is_empty(), "the next call must be unaffected");
        let (mtime, _, atime, _) = times_of(&present);
        assert_eq!(mtime, SAMPLE_STAMP);
        assert_eq!(atime, SAMPLE_STAMP);
    }

    /// Translation difference 1, asserted rather than merely described: an
    /// unopenable target warns through the frozen text instead of panicking.
    ///
    /// A directory is used because it fails the open regardless of privilege,
    /// which a permission bit does not when the tests run as root. Real
    /// `utimes` succeeds here -- that is precisely the measured divergence --
    /// and it is unreachable from curl's command line because
    /// `src/tool_operate.c:696` guards the only call site with
    /// `outs->regular_file`.
    #[test]
    fn set_on_an_unopenable_target_warns_rather_than_panicking() {
        scratch!(dir);
        let path = dir.path().to_path_buf();

        let output = emit_set(SAMPLE_STAMP, &path);
        assert!(!output.is_empty(), "the open failure must warn");

        let message = message_of(&output);
        let mut lead = Vec::new();
        lead.extend_from_slice(b"Failed to set filetime 1234567890 on '");
        lead.extend_from_slice(path.as_os_str().as_encoded_bytes());
        lead.extend_from_slice(b"': ");
        assert!(
            message.starts_with(&lead),
            "frozen layout: {:?}",
            String::from_utf8_lossy(&message)
        );
        assert!(
            !message
                .windows(OS_ERROR_INFIX.len())
                .any(|window| window == OS_ERROR_INFIX.as_bytes()),
            "the errno text must still be bare"
        );
    }

    // -- Paths that are not UTF-8 ------------------------------------------

    /// curl accepts any byte sequence the operating system accepts, so the
    /// filename never passes through `String` or `to_string_lossy`.
    #[test]
    fn a_non_utf8_path_is_stamped_and_reported_verbatim() {
        scratch!(dir);
        let raw: &[u8] = b"na\xffme";
        // 0xFF cannot occur in any position of a valid UTF-8 sequence, so this
        // fixture is genuinely unrepresentable as a `str`. Asserting the byte
        // rather than calling `str::from_utf8` keeps the check free of the
        // `invalid_from_utf8` lint, which fires on a literal it can evaluate at
        // compile time and would breach the zero-warning gate.
        assert!(
            raw.contains(&0xff),
            "the fixture must contain a non-UTF-8 byte"
        );
        let present = dir.path().join(OsStr::from_bytes(raw));
        touch(&present);

        // The success path.
        let output = emit_set(SAMPLE_STAMP, &present);
        assert!(output.is_empty(), "a success must emit nothing: {output:?}");
        let (mtime, _, atime, _) = times_of(&present);
        assert_eq!(mtime, SAMPLE_STAMP);
        assert_eq!(atime, SAMPLE_STAMP);

        let mut stamp = 0_i64;
        let (rc, _) = emit_get(&present, &mut stamp);
        assert_eq!(rc, FILETIME_SUCCESS);
        assert_eq!(stamp, SAMPLE_STAMP);

        // The failure path: the raw bytes must survive into the message, with
        // no U+FFFD replacement anywhere.
        let missing = dir.path().join(OsStr::from_bytes(b"go\xfene"));
        let message = message_of(&emit_set(SAMPLE_STAMP, &missing));
        let name = missing.as_os_str().as_encoded_bytes();
        assert!(
            message.windows(name.len()).any(|window| window == name),
            "the raw path bytes must appear verbatim"
        );
        assert!(
            !message
                .windows(3)
                .any(|window| window == "\u{fffd}".as_bytes()),
            "no lossy replacement character may appear"
        );
    }

    // -- The channel's gate ------------------------------------------------

    /// `src/tool_msgs.c:95` -- `--silent` suppresses a warning. Both of this
    /// module's warnings go through `warnf`, so both are gated.
    #[test]
    fn silent_suppresses_both_warnings() {
        scratch!(dir);
        let path = dir.path().join("absent");
        let silent = MsgConfig::new(true, false, false);

        let mut sink: Vec<u8> = Vec::new();
        let mut stamp = 0_i64;
        let rc = getfiletime(&mut sink, &silent, &path, &mut stamp);
        assert_eq!(rc, FILETIME_FAILURE, "the return value is not gated");
        assert!(sink.is_empty(), "`--silent` suppresses the warning");

        let mut sink: Vec<u8> = Vec::new();
        setfiletime(&mut sink, &silent, SAMPLE_STAMP, &path);
        assert!(sink.is_empty(), "`--silent` suppresses the warning");
    }
}
