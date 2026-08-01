//**************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// This software is licensed as described in the file COPYING, which
// you should have received as part of this distribution. The terms
// are also available at https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is
// furnished to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl
//
//**************************************************************************/
//! `SSLKEYLOGFILE` support: the NSS key log that lets Wireshark decrypt a
//! capture.
//!
//! Rust counterpart of `lib/vtls/keylog.c` (148 lines) and
//! `lib/vtls/keylog.h` (69 lines). When the `SSLKEYLOGFILE` environment
//! variable names a writable path, every TLS secret the handshake derives is
//! appended to that file in the NSS key log format. A packet capture plus
//! that file is enough to decrypt the session offline, which is why this is
//! the single most security-sensitive file in the TLS module and why nothing
//! here is best-effort in the sense of "approximately right".
//!
//! # Every byte is the contract
//!
//! The line format is consumed by Wireshark, `tshark`, NSS itself and by
//! every other tool that reads a key log. curl's observable output is frozen,
//! so the layout below is transcribed from the C source rather than redesigned,
//! and no readability pass may rewrite it:
//!
//! ```text
//!     LABEL<SP>CLIENT_RANDOM_HEX<SP>SECRET_HEX<LF>
//!       |            |                 |       |
//!       |            |                 |       `- exactly one LF, no CR
//!       |            |                 `- 2 * secret.len() UPPERCASE hex
//!       |            `- exactly 64 UPPERCASE hex digits (32 bytes)
//!       `- at most 31 bytes, written verbatim
//! ```
//!
//! Two properties of that line are easy to get wrong and are therefore
//! stated explicitly.
//!
//! **The hex digits are UPPERCASE.** `lib/vtls/keylog.c:128` and `:135` call
//! `Curl_hexbyte`, documented at `lib/escape.c:218-226` as "Output a single
//! unsigned char as a two-digit UPPERCASE hex number" and implemented by
//! indexing `Curl_udigits[] = "0123456789ABCDEF"` (`lib/mprintf.c:39`). The
//! lowercase twin `Curl_ldigits` (`lib/mprintf.c:36`) belongs to
//! `Curl_hexencode` and is *not* on this path. rustls ships its own
//! [`rustls::KeyLogFile`], and it formats with `{b:02x}` -- lowercase -- so
//! it cannot stand in for this module without changing curl's output.
//!
//! **The maximum generated line is 194 bytes.** `lib/vtls/keylog.c:110-111`
//! sizes its buffer `KEYLOG_LABEL_MAXLEN + 1 + 2 * CLIENT_RANDOM_SIZE + 1 +
//! 2 * SECRET_MAXLEN + 1 + 1`, that is 31 + 1 + 64 + 1 + 96 + 1 + 1 = 195,
//! and the comment at `:79` records the same number: "The current maximum
//! valid keylog line length LF and NUL is 195." The final `1` is the C string
//! terminator, which Rust neither needs nor writes, so the same line is 194
//! bytes here. See [`MAX_GENERATED_LINE`].
//!
//! # What the C tree does, and where
//!
//! | C origin | Behaviour reproduced here |
//! |----------|---------------------------|
//! | `lib/vtls/keylog.c:37-145` | the lifecycle, both writers, the rejections |
//! | `lib/vtls/keylog.h:28-37` | the three size constants |
//! | `lib/escape.c:218-226` | uppercase hex, two digits, no separator |
//! | `lib/vtls/rustls.c:504-515` | the callback shape and its argument sizes |
//! | `lib/vtls/rustls.c:809-829` | register only when enabled; close on failure |
//! | `lib/vtls/rustls.c:1392-1395` | cleanup closes, possibly a second time |
//!
//! The three size constants are [`KEYLOG_LABEL_MAXLEN`],
//! [`CLIENT_RANDOM_SIZE`] and [`SECRET_MAXLEN`]; each carries the reasoning
//! from `keylog.h` at its definition.
//!
//! # The one construct deliberately not reproduced
//!
//! `lib/vtls/keylog.c:38` is `static FILE *keylog_file_fp;` -- a mutable
//! process-global file pointer, opened by one backend and closed by another,
//! with no ownership and no synchronization beyond whatever the C library's
//! `stdio` happens to provide. This is exactly the class of construct the
//! rewrite replaces: state becomes owned, and access an explicit borrow.
//!
//! [`KeyLogFile`] is therefore an ordinary object. It is created by the TLS
//! factory, shared with rustls through an [`Arc`], and dropped when the last
//! holder goes away. There is no `static`, no lazily initialised singleton
//! and no hidden reader of the environment: `SSLKEYLOGFILE` is consulted only
//! by [`KeyLogFile::open_from_env`] and [`KeyLogFile::open`], never on a
//! write path. Two independent [`KeyLogFile`] values can coexist -- which is
//! what makes this module testable without touching the process environment
//! at all.
//!
//! # Buffering, and why a whole line is one critical section
//!
//! `lib/vtls/keylog.c:49-57` configures the stream immediately after opening
//! it: `setvbuf(fp, NULL, _IONBF, 0)` on `_WIN32`, otherwise
//! `setvbuf(fp, NULL, _IOLBF, 4096)`. If that call fails, C closes the file
//! and leaves the log disabled -- "cannot be configured" is as disabling as
//! "cannot be opened". [`LineBufferedSink`] reproduces both modes: a
//! [`KEYLOG_BUFSIZ`]-byte buffer that drains as soon as the bytes it holds
//! contain an LF, or a direct write when line buffering is off.
//!
//! Line buffering is reproduced because C configures it, not for speed. It is
//! not, however, what keeps a record whole: [`Write::write_all`] is free to
//! issue several underlying writes, and no buffering mode makes a record atomic
//! against a concurrent writer. What guarantees that two concurrent handshakes
//! cannot splice half of one secret into the middle of another is the [`Mutex`]
//! inside [`KeyLogFile`], held across the whole record -- format, buffer and
//! drain -- rather than across each fragment.
//!
//! # Failure is silent, by design
//!
//! An absent variable, an empty variable, an unopenable path and a failing
//! write all leave the transfer running. `lib/vtls/rustls.c:815-818` shows
//! why: the backend calls `Curl_tls_keylog_open()`, asks
//! `Curl_tls_keylog_enabled()`, and returns `CURLE_OK` when the answer is no.
//! A missing key log is a diagnostic that was not requested, never a TLS
//! error. The one case that *does* fail the handshake is a registration
//! failure inside the backend (`rustls.c:820-827`), and the backend's
//! response there is to call [`KeyLogFile::close`] -- which is why close is
//! idempotent and safe to call again from `cr_cleanup`
//! (`rustls.c:1392-1395`).
//!
//! No diagnostic in this module ever carries key material. Nothing is logged
//! on a write failure, and the [`fmt::Debug`] implementation prints one
//! boolean.
//! That is stricter than rustls, which logs a warning naming the path, and
//! stricter than a `#[derive(Debug)]` would be, which would print the
//! buffered bytes.
//!
//! # Deliberate, documented differences from the C implementation
//!
//! 1. **A 31-byte label is not truncated.** `lib/vtls/rustls.c:509` declares
//!    `char clabel[KEYLOG_LABEL_MAXLEN]` -- 31 bytes including room for the
//!    terminator -- and fills it with `curl_msnprintf(..., "%.*s", ...)`, so
//!    a label of exactly `KEYLOG_LABEL_MAXLEN` bytes loses its last
//!    character before `Curl_tls_keylog_write` ever sees it, even though that
//!    function accepts 31. Rust strings carry their length, so the label
//!    arrives intact; this module accepts up to and including 31 bytes and
//!    rejects 32. Nothing rustls emits is that long -- the longest label in
//!    the NSS vocabulary is `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, whose 31 bytes
//!    are what defines the limit (`lib/vtls/keylog.h:28`) -- so the effect is
//!    to remove a latent defect rather than to change any observable output.
//! 2. **No NUL byte is written.** C terminates its scratch buffer at
//!    `keylog.c:97` and `:139` because it hands the buffer to `fputs`. The
//!    terminator is never part of the file's contents in either
//!    implementation.
//! 3. **A write failure is reported.** C calls `fputs` and returns `TRUE`
//!    without inspecting the result (`keylog.c:101-102`, `:143-144`). Here a
//!    failed write returns `false`. The log stays open, because a transient
//!    failure must not silently disable the rest of the session, and no
//!    caller changes its behaviour on the strength of the return value.
//! 4. **LF is written verbatim on every target.** C opens with
//!    `FOPEN_APPENDTEXT`, which is `"at"` on `_WIN32` and MSDOS
//!    (`lib/curl_setup.h:1243-1246`) and therefore translates LF to CRLF
//!    there. On all four mandated targets it is `"a"`
//!    (`lib/curl_setup.h:1257-1260`), so plain append is the faithful
//!    behaviour; Rust's [`std::fs::File`] is byte-oriented and never
//!    translates.
//!
//! # Wiring it into the rustls backend
//!
//! [`KeyLogFile`] implements [`rustls::KeyLog`], so the backend needs no
//! adapter type. The sequence mirrors `init_config_builder_keylog`
//! (`lib/vtls/rustls.c:809-830`) one step at a time:
//!
//! ```ignore
//! let keylog = KeyLogFile::open_from_env();   // Curl_tls_keylog_open()
//! if keylog.enabled() {                       // Curl_tls_keylog_enabled()
//!     config.key_log = keylog.into_key_log(); // set_key_log()
//! }
//! ```
//!
//! This module selects no cryptographic provider and names none. Provider
//! choice belongs to the manifests, which pin `ring` with
//! `default-features = false`; a key log has no opinion about who computed the
//! secret it is recording.

// `dead_code` is NOT allowed for this module as a whole. Every item below that
// has no consumer yet carries its own `#[allow(dead_code)]`, written at the
// item, so the suppression reads as an inventory rather than a blanket: each
// one is load-bearing, deleting any one of them restores a warning, and an
// item added later with no consumer is still reported. Each is removed when
// its consumer lands. A module- or crate-scoped `#![allow(dead_code)]` would
// instead silence the NEXT item somebody adds, which hides incomplete
// scaffolding rather than recording it; the rule and the executable gate that
// enforces it across the workspace live in `curl-rs-lib/src/lib.rs`
// (`mod source_policy`).
//
// Every production consumer of this file lives in a sibling module.
// `tls/rustls_backend.rs` is the only caller -- it opens the log and
// registers the callback where C calls `Curl_tls_keylog_open`
// (`lib/vtls/rustls.c:809-829`) and closes it where C calls
// `Curl_tls_keylog_close` (`lib/vtls/rustls.c:1392-1395`) -- and `tls/mod.rs`
// is what declares this module at all. Until those land, every constant,
// helper and method here is legitimately unreferenced inside the crate, and
// the zero-warnings gate would otherwise fail on code that is correct. Several
// are reported only because they cascade from an unconsumed `pub(crate)` root:
// `env_path` and `locked` are genuinely called by production methods that are
// themselves not yet reachable. Compiling this same file as a test target,
// where the module's own tests supply the missing consumer, reports nothing at
// all.
//
// Each allowance is written on the item it excuses, and there is no
// `#![allow(dead_code)]` on this module root. A `dead_code` level on a crate
// or module root would silence the next unreferenced item somebody adds, which
// is why `mod source_policy` in `curl-rs-lib/src/lib.rs` fails the build when
// it finds one.
//
// No level for the `unsafe_code` lint is set here, at any level, by design:
// the crate root denies it and this module contains no `unsafe`, so the
// crate-wide guarantee must stay in force.

use std::env::var_os;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
// `MetadataExt` supplies `uid()` and `mode()`, `OpenOptionsExt` supplies
// `mode()` and `custom_flags()`. Both are `#[cfg(unix)]`, and all four mandated
// targets are Unix (AAP section 0.1.1 goal G8), so no configuration guard is
// needed here -- consistent with `src/ffi/sys.rs`, which likewise compiles only
// for those four and names the omission rather than hiding it.
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};

use rustls::KeyLog as RustlsKeyLog;

// The two open flags and the owner query, all three from the one directory in
// this crate that is allowed to name `libc` (AAP sections 0.3.1, 0.8.5/C3).
// `effective_uid` was added to that seam for this check specifically.
use crate::ffi::{effective_uid, O_CLOEXEC, O_NOFOLLOW};

/// The longest label the NSS key log format defines, in bytes.
///
/// `lib/vtls/keylog.h:28` spells the value as
/// `sizeof("CLIENT_HANDSHAKE_TRAFFIC_SECRET") - 1`, so the constant *is* the
/// length of the longest label rustls can emit rather than an arbitrary cap:
///
/// ```text
///     CLIENT_HANDSHAKE_TRAFFIC_SECRET
///     |<---------- 31 bytes -------->|
/// ```
///
/// Every other label in the vocabulary documented on
/// [`rustls::KeyLog::log`] is shorter: `CLIENT_RANDOM` (13),
/// `EXPORTER_SECRET` (15), `CLIENT_TRAFFIC_SECRET_0` (23),
/// `SERVER_HANDSHAKE_TRAFFIC_SECRET` (31), `CLIENT_EARLY_TRAFFIC_SECRET`
/// (27). A longer label is rejected rather than truncated.
#[allow(dead_code)]
pub(crate) const KEYLOG_LABEL_MAXLEN: usize = 31;

/// The size of a TLS client random, in bytes (`lib/vtls/keylog.h:30`).
///
/// Fixed by the protocol: `ClientHello.random` is 32 bytes in every TLS
/// version curl speaks, which is why the C prototype at
/// `lib/vtls/keylog.h:60` declares the parameter as
/// `const unsigned char client_random[32]` and why `lib/vtls/rustls.c:511`
/// asserts `client_random_len == CLIENT_RANDOM_SIZE`. That assertion is a
/// `DEBUGASSERT`, so a release build of the C tree would format whatever it
/// was handed; here a client random of any other length is rejected.
#[allow(dead_code)]
pub(crate) const CLIENT_RANDOM_SIZE: usize = 32;

/// The longest secret the format has to carry, in bytes.
///
/// `lib/vtls/keylog.h:32-37` gives the reasoning verbatim: "The master
/// secret in TLS 1.2 and before is always 48 bytes. In TLS 1.3, the secret
/// size depends on the cipher suite's hash function which is 32 bytes for
/// SHA-256 and 48 bytes for SHA-384."
#[allow(dead_code)]
pub(crate) const SECRET_MAXLEN: usize = 48;

/// The longest line [`KeyLogFile::write_secret`] can generate, in bytes.
///
/// The C buffer at `lib/vtls/keylog.c:110-111` is sized
/// `KEYLOG_LABEL_MAXLEN + 1 + 2 * CLIENT_RANDOM_SIZE + 1 + 2 * SECRET_MAXLEN + 1 + 1`,
/// and the comment at `:79` states the total: "The current maximum valid
/// keylog line length LF and NUL is 195." Written out:
///
/// ```text
///     31  label
///    + 1  separating space
///   + 64  client random, two hex digits per byte
///    + 1  separating space
///   + 96  secret, two hex digits per byte
///    + 1  LF
///   ----
///    194  bytes written by this module
///    + 1  C string terminator, which Rust does not write
///   ----
///    195  the figure quoted by keylog.c:79
/// ```
///
/// This is the capacity the formatting buffer reserves, so no key log record
/// ever reallocates while it holds key material.
#[allow(dead_code)]
const MAX_GENERATED_LINE: usize = KEYLOG_LABEL_MAXLEN
    + 1
    + 2 * CLIENT_RANDOM_SIZE
    + 1
    + 2 * SECRET_MAXLEN
    + 1;

/// The longest input [`KeyLogFile::write_line`] accepts, in bytes.
///
/// `lib/vtls/keylog.c:81` declares `char buf[256]` and `:88` rejects a line
/// whose length exceeds `sizeof(buf) - 2`, reserving one byte for an LF that
/// may have to be appended and one for the terminator. 256 - 2 = 254, so 254
/// bytes are accepted and 255 are not. The reserved terminator has no
/// counterpart here, but the limit is part of the accepted-input contract and
/// is therefore preserved exactly rather than widened.
#[allow(dead_code)]
const LINE_MAXLEN: usize = 254;

/// The line-buffer size C asks `setvbuf` for (`lib/vtls/keylog.c:52`).
#[allow(dead_code)]
const KEYLOG_BUFSIZ: usize = 4096;

/// The environment variable that names the key log file.
///
/// Read at `lib/vtls/keylog.c:45` through `curl_getenv`, whose non-Windows
/// body is `return (env && env[0]) ? curlx_strdup(env) : NULL;`
/// (`lib/getenv.c:78-79`). An empty value is therefore exactly as disabling
/// as an absent one, and [`KeyLogFile::open`] reproduces that.
#[allow(dead_code)]
const SSLKEYLOGFILE: &str = "SSLKEYLOGFILE";

/// The mode a key log this process creates is created with.
///
/// `0600`: read and write for the owner, nothing for anyone else. This replaces
/// the `0666` that `fopen(name, "a")` requests (`lib/vtls/keylog.c:47`), which
/// the umask then narrows to whatever the user happens to have configured --
/// `0644` under the usual `022`, and `0666` under a umask of `0`.
///
/// A umask can only clear bits, never set them, so this value is a ceiling that
/// the kernel may lower and nothing can raise. The execute bit is absent
/// because a key log is data.
const SECRET_FILE_MODE: u32 = 0o600;

/// The permission bits a key log may not have: any granted to group or other.
///
/// `0o077` and not `0o177` or `0o777`: the owner triad is deliberately excluded,
/// because this process *is* the owner by the time the mask is applied and its
/// own access is the point. Only the two triads that let somebody else read the
/// secrets are rejected.
const FOREIGN_PERMISSION_BITS: u32 = 0o077;

/// The uppercase hex alphabet, `Curl_udigits` (`lib/mprintf.c:39`).
///
/// Deliberately not `Curl_ldigits` (`lib/mprintf.c:36`), which is lowercase
/// and belongs to `Curl_hexencode`. `Curl_hexbyte` -- the function this
/// module's formatting reproduces -- indexes this table
/// (`lib/escape.c:225-226`).
#[allow(dead_code)]
const UPPERCASE_HEX: [u8; 16] = *b"0123456789ABCDEF";

/// A single ASCII space: the field separator, and the only one.
#[allow(dead_code)]
const SP: u8 = b' ';

/// A single line feed: the record terminator, never accompanied by a CR.
#[allow(dead_code)]
const LF: u8 = b'\n';

/// Formats one byte as two uppercase hex digits.
///
/// The whole of `Curl_hexbyte` (`lib/escape.c:222-227`):
///
/// ```c
/// dest[0] = Curl_udigits[val >> 4];
/// dest[1] = Curl_udigits[val & 0x0F];
/// ```
///
/// Returning an array rather than writing through a pointer removes the C
/// contract "must fit two bytes" (`lib/escape.c:222`) that the caller had to
/// honour by hand. Both indices are masked to 0..=15, so the bounds check
/// the compiler inserts can never fire; no `unsafe` and no unchecked
/// indexing appears anywhere in this module.
#[allow(dead_code)]
fn hexbyte(value: u8) -> [u8; 2] {
    [
        UPPERCASE_HEX[usize::from(value >> 4)],
        UPPERCASE_HEX[usize::from(value & 0x0f)],
    ]
}

/// Why a path was refused as a key log destination.
///
/// Three variants rather than one boolean, because each one is a different
/// mistake with a different remedy, and because a test that only knew "refused"
/// could not tell a correct refusal from a coincidental one. The reason never
/// reaches the user: this module fails silently by design (see the module
/// documentation), and [`KeyLogFile::open_env_file`] discards it. It exists so
/// that [`secret_file_verdict`] is checkable in isolation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretFileRejection {
    /// Not a regular file -- a FIFO, socket, device or directory.
    NotRegularFile,
    /// Owned by some other user, who can therefore read what is written to it.
    ForeignOwner,
    /// Readable or writable by group or other.
    TooPermissive,
}

impl SecretFileRejection {
    /// The message this refusal would carry if anything printed it.
    ///
    /// Static strings, and deliberately without the path: the reason is
    /// diagnostic, the path is not a secret but the *reason* a key log was
    /// refused is not worth a message that could end up in a log alongside the
    /// path it names.
    const fn reason(self) -> &'static str {
        match self {
            Self::NotRegularFile => "SSLKEYLOGFILE is not a regular file",
            Self::ForeignOwner => "SSLKEYLOGFILE is owned by another user",
            Self::TooPermissive => "SSLKEYLOGFILE is readable by other users",
        }
    }

    /// Converts a refusal into the [`io::Error`] the open path returns.
    ///
    /// [`io::ErrorKind::PermissionDenied`] for all three, because that is what
    /// the condition is from the caller's point of view and because the kernel
    /// uses the same kind for the checks it performs itself -- the refusal is
    /// indistinguishable, to a caller, from the `EACCES` it would have got had
    /// the directory not been writable.
    fn into_io_error(self) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, self.reason())
    }
}

/// Decides whether a file this process has just opened may receive secrets.
///
/// Split out of [`KeyLogFile::open_private_append`] as a pure function over the
/// four facts that decide the question, for the same reason
/// [`KeyLogFile::env_path`] is split out of the environment read: the rule then
/// has a test that does not need a filesystem, a particular user id or root
/// privileges. Every combination of the four inputs is reachable from a test,
/// including the combinations a single host cannot be made to produce.
///
/// `mode` is the raw `st_mode` from `fstat`, file-type bits and all. Only the
/// permission bits are examined -- [`FOREIGN_PERMISSION_BITS`] -- because the
/// file type arrives separately as `is_regular_file`, already decoded by
/// [`std::fs::FileType`].
///
/// The order of the checks is the order of severity, so that a file which fails
/// more than one test reports the most fundamental failure. It has no effect on
/// whether the file is accepted.
///
/// # Errors
///
/// One [`SecretFileRejection`] per reason; see that type.
fn secret_file_verdict(
    is_regular_file: bool,
    owner: u32,
    mode: u32,
    us: u32,
) -> Result<(), SecretFileRejection> {
    if !is_regular_file {
        return Err(SecretFileRejection::NotRegularFile);
    }
    if owner != us {
        return Err(SecretFileRejection::ForeignOwner);
    }
    if mode & FOREIGN_PERMISSION_BITS != 0 {
        return Err(SecretFileRejection::TooPermissive);
    }
    Ok(())
}

/// The destination of a key log, with the buffering `setvbuf` would have
/// configured.
///
/// `lib/vtls/keylog.c:47-58` opens the file and immediately configures the
/// stream, treating a configuration failure as fatal to the log:
///
/// ```c
/// keylog_file_fp = curlx_fopen(keylog_file_name, FOPEN_APPENDTEXT);
/// if(keylog_file_fp) {
/// #ifdef _WIN32
///   if(setvbuf(keylog_file_fp, NULL, _IONBF, 0))
/// #else
///   if(setvbuf(keylog_file_fp, NULL, _IOLBF, 4096))
/// #endif
///   {
///     curlx_fclose(keylog_file_fp);
///     keylog_file_fp = NULL;
///   }
/// }
/// ```
///
/// Rust has no `setvbuf`, so the two modes are implemented rather than
/// requested, and neither can fail:
///
/// * **`_IOLBF` with a 4096-byte buffer** (every target that is not Windows,
///   which is every one of the four mandated targets). A record is staged in
///   [`Self::buffer`] and the buffer is drained as soon as the staged bytes
///   contain an LF, or when the next record would not fit. Because both
///   public writers terminate every record with exactly one LF, the practical
///   effect is one `write` per key log line -- which is the property that
///   keeps concurrent handshakes from splicing their secrets together.
/// * **`_IONBF`** (Windows). Each record goes straight to the file.
///
/// The buffer is overwritten with zeroes as soon as it has been handed to the
/// writer, including on the failure path. It is a scratch area holding key
/// material, and leaving that material in a live allocation for the lifetime
/// of the process would be gratuitous.
#[allow(dead_code)]
struct LineBufferedSink {
    /// The file, or any other writer an owner chose to inject.
    ///
    /// `Box<dyn Write + Send>` rather than [`std::fs::File`] for one reason
    /// that matters in production and one that matters in test: a caller may
    /// legitimately want the records elsewhere, and every behaviour in this
    /// module can be verified against an in-memory writer without creating a
    /// file or reading the process environment.
    inner: Box<dyn Write + Send>,

    /// Staged bytes, never more than [`KEYLOG_BUFSIZ`] of them.
    ///
    /// Empty except transiently inside [`Self::write_record`], since every
    /// record written through this module ends in an LF and therefore drains
    /// the buffer on the way out.
    buffer: Vec<u8>,

    /// `true` for the `_IOLBF` mode, `false` for `_IONBF`.
    line_buffered: bool,
}

impl LineBufferedSink {
    /// Wraps a writer in the buffering mode this target's C build asks for.
    ///
    /// `cfg!` rather than `#[cfg]` so that both arms are type-checked on
    /// every target: a Windows-only compilation error in a module this
    /// security-sensitive would not be discovered until a Windows build,
    /// and Windows is outside the four-target matrix.
    #[allow(dead_code)]
    fn new(inner: Box<dyn Write + Send>) -> Self {
        let line_buffered = !cfg!(windows);
        let capacity = if line_buffered { KEYLOG_BUFSIZ } else { 0 };
        Self {
            inner,
            buffer: Vec::with_capacity(capacity),
            line_buffered,
        }
    }

    /// Writes one complete record, which the caller has already terminated
    /// with an LF.
    ///
    /// Returns the first I/O error encountered. A caller that cannot act on
    /// the error still gets the guarantee that no key material is left in
    /// [`Self::buffer`].
    #[allow(dead_code)]
    fn write_record(&mut self, record: &[u8]) -> io::Result<()> {
        if !self.line_buffered {
            // `_IONBF`: one unbuffered write, then flush, so the record is
            // visible to a reader of the file the moment this returns.
            self.inner.write_all(record)?;
            return self.inner.flush();
        }

        // `_IOLBF`: drain first if the record would overflow the buffer,
        // which is what stdio does before staging more bytes.
        if self.buffer.len() + record.len() > KEYLOG_BUFSIZ {
            self.drain()?;
        }

        if record.len() > KEYLOG_BUFSIZ {
            // Larger than the buffer itself, so stdio would bypass it. Both
            // writers in this module cap out at 194 and 255 bytes, so this
            // arm is unreachable through the public API; it exists because a
            // sink that silently mis-buffers an oversized record would be
            // wrong, and being wrong here is expensive.
            self.inner.write_all(record)?;
            return self.inner.flush();
        }

        self.buffer.extend_from_slice(record);
        if record.contains(&LF) {
            self.drain()?;
        }
        Ok(())
    }

    /// Hands the staged bytes to the writer and scrubs the buffer.
    ///
    /// The buffer is scrubbed whether or not the write succeeded, and the
    /// bytes are not retried: a failed `write_all` may have written a prefix,
    /// so a retry could duplicate part of a record, and re-presenting key
    /// material is worse than losing a diagnostic line.
    #[allow(dead_code)]
    fn drain(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let written = self.inner.write_all(&self.buffer);
        self.buffer.fill(0);
        self.buffer.clear();
        written?;
        self.inner.flush()
    }

    /// Flushes as much as possible, ignoring failures.
    ///
    /// The counterpart of `fclose` at `lib/vtls/keylog.c:67`, which likewise
    /// has no error path that the caller could act on.
    #[allow(dead_code)]
    fn finish(&mut self) {
        let _ = self.drain();
        let _ = self.inner.flush();
    }
}

impl Drop for LineBufferedSink {
    fn drop(&mut self) {
        // A sink dropped without [`Self::finish`] -- through an unwind, or
        // because its owner was dropped -- must still not leave a record in
        // memory or a line unwritten.
        self.finish();
    }
}

/// An open, or deliberately closed, TLS key log.
///
/// Replaces the five `Curl_tls_keylog_*` functions of `lib/vtls/keylog.c`
/// (`:40`, `:64`, `:72`, `:77`, `:105`) together with the mutable global they
/// operate on (`:38`). The mapping is one to one:
///
/// | C | here |
/// |---|------|
/// | `Curl_tls_keylog_open` | [`Self::open`], [`Self::open_from_env`] |
/// | `Curl_tls_keylog_close` | [`Self::close`], and [`Drop`] |
/// | `Curl_tls_keylog_enabled` | [`Self::enabled`] |
/// | `Curl_tls_keylog_write` | [`Self::write_secret`] |
/// | `Curl_tls_keylog_write_line` | [`Self::write_line`] |
/// | `static FILE *keylog_file_fp` | the owned [`Mutex`] below |
///
/// # Thread safety
///
/// rustls calls [`rustls::KeyLog::log`] from whichever task drives the
/// handshake, and a multi handle can drive many at once, so this type is
/// [`Send`] and [`Sync`] and every write takes the sink's lock for the
/// duration of a whole record. The lock is never held across a call into
/// rustls, so no lock ordering exists to get wrong.
///
/// A panic elsewhere while the lock was held poisons it. Every access here
/// recovers with [`PoisonError::into_inner`], the pattern this crate already
/// uses for diagnostic sinks: a key log that stops working because an
/// unrelated task panicked would be a worse outcome than one that keeps
/// appending.
#[allow(dead_code)]
pub(crate) struct KeyLogFile {
    /// The destination, or [`None`] when the log is disabled or closed.
    ///
    /// One [`Option`] carries both states because C carries both in one
    /// pointer: `keylog_file_fp` is `NULL` when the variable was unset, when
    /// the file could not be opened, when `setvbuf` failed, and after
    /// `Curl_tls_keylog_close`. Nothing distinguishes them, and nothing needs
    /// to.
    sink: Mutex<Option<LineBufferedSink>>,
}

impl KeyLogFile {
    /// A key log that is closed and will stay closed unless [`Self::open`] is
    /// called.
    ///
    /// The equivalent of rustls's [`rustls::NoKeyLog`], and the constructor to
    /// use when a caller wants the object now and the environment read later.
    #[allow(dead_code)]
    pub(crate) fn disabled() -> Arc<Self> {
        Arc::new(Self {
            sink: Mutex::new(None),
        })
    }

    /// Reads `SSLKEYLOGFILE` and opens the log if it names a usable path.
    ///
    /// The direct counterpart of `Curl_tls_keylog_open`
    /// (`lib/vtls/keylog.c:40-62`) as the rustls backend calls it at
    /// `lib/vtls/rustls.c:815`. An absent variable, an empty variable and an
    /// unopenable path all yield a disabled log rather than an error, exactly
    /// as they do in C, because `rustls.c:816-818` returns `CURLE_OK` when the
    /// log did not open.
    #[allow(dead_code)]
    pub(crate) fn open_from_env() -> Arc<Self> {
        let keylog = Self::disabled();
        // The answer is [`Self::enabled`], which the caller asks for when it
        // needs it; failing to open is not a failure of this call.
        let _opened = keylog.open();
        keylog
    }

    /// A key log that writes to an injected writer instead of a file.
    ///
    /// The seam that keeps this module testable without a file or an
    /// environment variable, and that lets an owner send records somewhere
    /// other than the filesystem. Buffering follows the same rule as a
    /// file-backed log, so an injected writer observes exactly the write
    /// pattern a file would.
    #[allow(dead_code)]
    pub(crate) fn with_writer(writer: Box<dyn Write + Send>) -> Arc<Self> {
        Arc::new(Self {
            sink: Mutex::new(Some(LineBufferedSink::new(writer))),
        })
    }

    /// Opens the log from the environment if it is not already open, and
    /// reports whether it is open afterwards.
    ///
    /// Idempotent, because `Curl_tls_keylog_open` is: `lib/vtls/keylog.c:44`
    /// guards the whole body with `if(!keylog_file_fp)`, so a second call on
    /// an open log neither re-reads the environment nor reopens the file. The
    /// rustls backend relies on that -- `rustls.c:815` calls it on every
    /// configuration build, once per easy handle.
    #[allow(dead_code)]
    pub(crate) fn open(&self) -> bool {
        let mut sink = self.locked();
        if sink.is_some() {
            return true;
        }
        *sink = Self::open_env_file().map(LineBufferedSink::new);
        sink.is_some()
    }

    /// Whether records written now would reach a destination.
    ///
    /// `Curl_tls_keylog_enabled` (`lib/vtls/keylog.c:72-75`), which is
    /// `keylog_file_fp != NULL`. The backend calls this immediately after
    /// opening and skips registration entirely when it answers `false`
    /// (`lib/vtls/rustls.c:816-818`).
    #[allow(dead_code)]
    pub(crate) fn enabled(&self) -> bool {
        self.locked().is_some()
    }

    /// Appends one NSS key log record, returning whether it was written.
    ///
    /// `Curl_tls_keylog_write` (`lib/vtls/keylog.c:105-145`), reached from
    /// `cr_keylog_log_cb` (`lib/vtls/rustls.c:504-515`). The record is
    ///
    /// ```text
    ///     <label> <64 hex digits> <2 * secret.len() hex digits><LF>
    /// ```
    ///
    /// with uppercase hex, exactly one space between fields, no CR, and no
    /// trailing byte after the LF.
    ///
    /// Returns `false`, writing nothing, when
    ///
    /// * the log is disabled or has been closed (`keylog.c:113-115`),
    /// * `label` is longer than [`KEYLOG_LABEL_MAXLEN`] bytes
    ///   (`keylog.c:118`),
    /// * `client_random` is not exactly [`CLIENT_RANDOM_SIZE`] bytes -- which
    ///   C asserts only in a debug build (`lib/vtls/rustls.c:511`),
    /// * `secret` is empty or longer than [`SECRET_MAXLEN`] bytes
    ///   (`keylog.c:118`), or
    /// * the write itself fails, which C does not report at all
    ///   (`keylog.c:143-144`).
    ///
    /// Nothing is logged or reported about a rejection beyond that `false`.
    /// The arguments are key material, and a diagnostic that named them would
    /// defeat the point of the file's permissions.
    #[allow(dead_code)]
    pub(crate) fn write_secret(
        &self,
        label: &str,
        client_random: &[u8],
        secret: &[u8],
    ) -> bool {
        match Self::secret_record(label, client_random, secret) {
            Some(mut record) => {
                let written = self.write_record(&record);
                // The record is key material. Scrub before the allocation is
                // returned to the allocator.
                record.fill(0);
                written
            }
            None => false,
        }
    }

    /// Appends an arbitrary line, terminating it with an LF if it is not
    /// terminated already.
    ///
    /// `Curl_tls_keylog_write_line` (`lib/vtls/keylog.c:77-103`). Takes bytes
    /// rather than a string because the C signature takes `const char *` and
    /// because a key log line is a byte sequence: no encoding conversion, no
    /// escape processing and no newline normalization may happen on the way
    /// through.
    ///
    /// Returns `false`, writing nothing, when
    ///
    /// * the log is disabled or has been closed (`keylog.c:83`),
    /// * `line` is empty (`keylog.c:88`),
    /// * `line` is longer than [`LINE_MAXLEN`] bytes (`keylog.c:88`, which
    ///   rejects `linelen > sizeof(buf) - 2` for a 256-byte buffer), or
    /// * the write fails.
    ///
    /// A line that already ends in an LF is written unchanged -- C compares
    /// `line[linelen - 1] != '\n'` before appending (`keylog.c:94-96`) -- so
    /// a caller can hand over a record it composed itself and get exactly
    /// those bytes.
    #[allow(dead_code)]
    pub(crate) fn write_line(&self, line: &[u8]) -> bool {
        if line.is_empty() || line.len() > LINE_MAXLEN {
            return false;
        }

        if line.last() == Some(&LF) {
            return self.write_record(line);
        }

        let mut record = Vec::with_capacity(line.len() + 1);
        record.extend_from_slice(line);
        record.push(LF);
        let written = self.write_record(&record);
        record.fill(0);
        written
    }

    /// Closes the log. Safe to call any number of times.
    ///
    /// `Curl_tls_keylog_close` (`lib/vtls/keylog.c:64-70`), which is guarded
    /// by `if(keylog_file_fp)` and therefore already idempotent. Two callers
    /// in the rustls backend depend on that: `init_config_builder_keylog`
    /// calls it when `rustls_client_config_builder_set_key_log` fails
    /// (`lib/vtls/rustls.c:823-826`), and `cr_cleanup` calls it
    /// unconditionally afterwards (`rustls.c:1392-1395`).
    ///
    /// Buffered bytes are flushed while the lock is still held, so a
    /// concurrent [`Self::open`] cannot interleave with the flush.
    #[allow(dead_code)]
    pub(crate) fn close(&self) {
        let mut sink = self.locked();
        if let Some(mut open) = sink.take() {
            open.finish();
        }
    }

    /// Hands this log to rustls as its [`rustls::KeyLog`].
    ///
    /// `ClientConfig::key_log` is an `Arc<dyn KeyLog>`
    /// (`rustls-0.23.42/src/client/client_conn.rs:217`), and this is the
    /// upcast that fills it -- the safe counterpart of
    /// `rustls_client_config_builder_set_key_log(builder, cr_keylog_log_cb,
    /// NULL)` at `lib/vtls/rustls.c:820-822`, with the object itself standing
    /// in for the `NULL` user-data pointer that C had to pass.
    #[allow(dead_code)]
    pub(crate) fn into_key_log(self: Arc<Self>) -> Arc<dyn RustlsKeyLog> {
        self
    }

    /// Reads `SSLKEYLOGFILE` and opens what it names, in append mode.
    ///
    /// `curlx_fopen(keylog_file_name, FOPEN_APPENDTEXT)`
    /// (`lib/vtls/keylog.c:47`). `FOPEN_APPENDTEXT` is `"a"` on every
    /// mandated target (`lib/curl_setup.h:1257-1260`), so:
    ///
    /// * `append(true)` -- an existing key log is added to, never truncated.
    ///   A capture taken an hour ago must still be decryptable.
    /// * `create(true)` -- a first run creates the file.
    ///
    /// Any failure yields [`None`], which leaves the log disabled. That
    /// covers a missing directory, a permission denial, a path that names a
    /// directory, a path this process must not write secrets into (see
    /// [`Self::open_private_append`]), and every other reason `open` can fail.
    fn open_env_file() -> Option<Box<dyn Write + Send>> {
        let path = Self::env_path(var_os(SSLKEYLOGFILE))?;
        let file = Self::open_private_append(path.as_ref()).ok()?;
        Some(Box::new(file))
    }

    /// Opens `path` for appending secrets to it, or refuses.
    ///
    /// # Why this is stricter than the C tree, deliberately
    ///
    /// `Curl_tls_keylog_open` reaches the filesystem through
    /// `curlx_fopen(name, FOPEN_APPENDTEXT)` (`lib/vtls/keylog.c:47`), and on
    /// the mandated targets `curlx_fopen` *is* `fopen` (`lib/curlx/fopen.h:64`,
    /// `:81`) with `FOPEN_APPENDTEXT` spelled `"a"` (`lib/curl_setup.h:1257`).
    /// `fopen` with mode `"a"` asks for `O_CREAT` at `0666`, which the process
    /// umask then narrows -- to `0644` under the usual `022`, and to `0666`
    /// under a umask of `0` -- and it follows a symbolic link wherever the last
    /// path component points. So curl 8.19.0-DEV really can write TLS session
    /// secrets into a world-readable file, and really can be pointed at a file
    /// it does not own by an attacker who wins the race to create the path
    /// first. Both are properties of the C code, not of its translation.
    ///
    /// This is therefore not a parity repair; it is a deliberate hardening, and
    /// the deliberation is recorded here rather than left to be inferred. Three
    /// things justify diverging from a frozen behaviour (AAP section 0.8.1):
    ///
    /// 1. The bytes are unchanged. Nothing about the file's *contents*, its
    ///    append semantics or its buffering differs; only which files this
    ///    process is willing to open at all.
    /// 2. The contents are the whole of the session's confidentiality. A key
    ///    log plus a packet capture is the plaintext, so a permission bit here
    ///    is not a hygiene preference.
    /// 3. Refusing is the direction the module already fails in. Every other
    ///    failure on this path is silent and leaves the transfer running
    ///    (`lib/vtls/rustls.c:816-818`), so a refusal costs a diagnostic the
    ///    user did not get anyway -- never a transfer.
    ///
    /// # What is enforced
    ///
    /// * **`0600` at creation.** [`OpenOptionsExt::mode`] replaces `fopen`'s
    ///   `0666`, so a file this process creates is readable only by its owner
    ///   *before* any umask is consulted. A umask can only remove bits, never
    ///   add them, so this is a floor and not a hint.
    /// * **`O_NOFOLLOW`.** A final component that is a symbolic link makes the
    ///   open fail with `ELOOP` instead of writing secrets wherever the link
    ///   points. CWE-59.
    /// * **`O_CLOEXEC`.** The descriptor does not survive into a child process.
    ///   Rust's [`std::fs::File`] already sets this, so the flag is redundant
    ///   today; it is passed because the property is worth stating and is
    ///   asserted by test rather than assumed.
    /// * **A regular file.** A FIFO would block the handshake on a reader; a
    ///   character device would send the secrets somewhere unknowable.
    /// * **Owned by this process.** `geteuid()` and not `getuid()`, because the
    ///   effective id is what the kernel checks: if the file belongs to someone
    ///   else it is not ours to append to, and whoever it belongs to can read
    ///   it.
    /// * **No group or other permission.** An existing file keeps the mode it
    ///   already had -- [`OpenOptionsExt::mode`] applies only on creation -- so
    ///   a key log left behind at `0644` by a C curl, or by a redirect, is
    ///   refused rather than appended to.
    ///
    /// # Why the checks read the descriptor and not the path
    ///
    /// [`std::fs::File::metadata`] is `fstat` on the descriptor that was just
    /// opened, so the file examined is exactly the file that will be written.
    /// Checking the *path* with [`std::fs::metadata`] would be a
    /// time-of-check/time-of-use race: the path could be replaced between the
    /// check and the open. There is no such window here, and the mode the file
    /// is created with closes the remaining one -- a file created `0600` cannot
    /// be read by anyone else even for the instant before the check runs.
    ///
    /// Nothing is tightened in place. A `chmod` on a file the user owns would
    /// change observable filesystem state, which this module has no mandate to
    /// do; refusing changes nothing outside the process.
    fn open_private_append(path: &OsStr) -> io::Result<File> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(SECRET_FILE_MODE)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(path)?;

        // `fstat` on the descriptor just opened -- see the note above on why
        // this is not `fs::metadata(path)`.
        let metadata = file.metadata()?;
        secret_file_verdict(
            metadata.file_type().is_file(),
            metadata.uid(),
            metadata.mode(),
            effective_uid(),
        )
        .map_err(SecretFileRejection::into_io_error)?;

        Ok(file)
    }

    /// Applies curl's rule for an empty environment value.
    ///
    /// [`var_os`] rather than `var` so that a path which is not valid UTF-8
    /// still works: `curl_getenv` hands `fopen` the raw bytes
    /// (`lib/getenv.c:78-79`), and a Unix path is a byte string. Rejecting
    /// such a path would be a regression that no test of a UTF-8 path could
    /// detect.
    ///
    /// An empty value counts as absent, because `curl_getenv` returns `NULL`
    /// unless `env && env[0]` (`lib/getenv.c:79`).
    ///
    /// Split out from [`Self::open_env_file`] so the rule is testable without
    /// mutating the process environment.
    #[allow(dead_code)]
    fn env_path(value: Option<OsString>) -> Option<OsString> {
        match value {
            Some(path) if !path.is_empty() => Some(path),
            _ => None,
        }
    }

    /// Formats one NSS key log record, or rejects the arguments.
    ///
    /// The body of `Curl_tls_keylog_write` (`lib/vtls/keylog.c:117-139`)
    /// without its file handling, so that the format can be verified byte for
    /// byte on its own. The buffer is created at [`MAX_GENERATED_LINE`]
    /// capacity and never grows, so no key material is copied into a second
    /// allocation on the way out.
    #[allow(dead_code)]
    fn secret_record(
        label: &str,
        client_random: &[u8],
        secret: &[u8],
    ) -> Option<Vec<u8>> {
        // `label.len()` is a byte count, which is what `strlen(label)`
        // measures at `keylog.c:117`. A multi-byte label would be rejected on
        // its byte length, exactly as in C.
        if label.len() > KEYLOG_LABEL_MAXLEN {
            return None;
        }
        if client_random.len() != CLIENT_RANDOM_SIZE {
            return None;
        }
        if secret.is_empty() || secret.len() > SECRET_MAXLEN {
            return None;
        }

        let mut record = Vec::with_capacity(MAX_GENERATED_LINE);
        record.extend_from_slice(label.as_bytes());
        record.push(SP);
        for byte in client_random {
            record.extend_from_slice(&hexbyte(*byte));
        }
        record.push(SP);
        for byte in secret {
            record.extend_from_slice(&hexbyte(*byte));
        }
        record.push(LF);
        Some(record)
    }

    /// Writes one already-formatted, already-LF-terminated record.
    ///
    /// The single point at which the sink's lock is taken, which is what
    /// makes "one record is one critical section" true by construction rather
    /// than by convention.
    #[allow(dead_code)]
    fn write_record(&self, record: &[u8]) -> bool {
        let mut sink = self.locked();
        match sink.as_mut() {
            Some(open) => open.write_record(record).is_ok(),
            None => false,
        }
    }

    /// Exclusive access to the sink, recovering from poisoning.
    #[allow(dead_code)]
    fn locked(&self) -> MutexGuard<'_, Option<LineBufferedSink>> {
        self.sink.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for KeyLogFile {
    /// Prints whether the log is open, and nothing else.
    ///
    /// [`rustls::KeyLog`] requires [`fmt::Debug`], so this type is formattable
    /// from anywhere that formats a `ClientConfig`. A derived implementation
    /// would print [`LineBufferedSink::buffer`], which can hold a secret;
    /// rustls avoids the same trap by hand (`key_log_file.rs`: "we omit
    /// self.buf deliberately as it may contain key data") and additionally
    /// prints the file handle, which names the path. This prints neither.
    ///
    /// [`Mutex::try_lock`] rather than [`Mutex::lock`]: formatting must not
    /// block, and must not deadlock if a future caller ever formats this
    /// value while a write is in flight.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("KeyLogFile");
        match self.sink.try_lock() {
            Ok(sink) => out.field("enabled", &sink.is_some()),
            Err(TryLockError::Poisoned(poisoned)) => {
                out.field("enabled", &poisoned.into_inner().is_some())
            }
            Err(TryLockError::WouldBlock) => out.field("enabled", &"in use"),
        }
        .finish()
    }
}

impl Drop for KeyLogFile {
    /// Flushes and releases the file.
    ///
    /// `cr_cleanup` (`lib/vtls/rustls.c:1392-1395`) closes the C log
    /// explicitly, and the rustls backend is the only thing that ever did;
    /// anything else that had opened it leaked the handle for the life of the
    /// process. An owned object closes itself, so the explicit call becomes an
    /// optimization rather than an obligation.
    fn drop(&mut self) {
        // `get_mut` rather than `lock`: `&mut self` proves that no other
        // holder exists, so there is nothing to contend with.
        let sink = self.sink.get_mut().unwrap_or_else(PoisonError::into_inner);
        if let Some(mut open) = sink.take() {
            open.finish();
        }
    }
}

impl RustlsKeyLog for KeyLogFile {
    /// Records one secret, as rustls hands it over.
    ///
    /// The safe counterpart of `cr_keylog_log_cb`
    /// (`lib/vtls/rustls.c:504-515`). Two differences from that function, both
    /// consequences of the type system rather than choices:
    ///
    /// * `label` arrives as a `&str` that carries its own length, the native
    ///   form of the `struct rustls_str` C had to copy into
    ///   `char clabel[KEYLOG_LABEL_MAXLEN]` at `rustls.c:509`. That copy
    ///   silently truncates a 31-byte label to 30 bytes, because 31 is the
    ///   *length* the format allows and the array left no room for the C
    ///   terminator. Here the label is passed through whole.
    /// * `client_random_len` has no separate parameter to be ignored
    ///   (`rustls.c:510`) and no `DEBUGASSERT` that vanishes in a release
    ///   build (`:511`): a client random of the wrong length is rejected in
    ///   every build.
    ///
    /// The return value of [`KeyLogFile::write_secret`] is deliberately
    /// dropped. rustls has no way to report a key log failure and no
    /// behaviour that should change because of one -- `cr_keylog_log_cb`
    /// discards the same answer.
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let _recorded = self.write_secret(label, client_random, secret);
    }

    /// Whether [`Self::log`] would write this label's secret.
    ///
    /// rustls documents this as a performance optimization and skips the
    /// derivation of the logged secret when it answers `false`, so answering
    /// accurately keeps key material out of memory that would never be
    /// written. Both conditions that would make [`KeyLogFile::write_secret`]
    /// reject on the label's account are checked: the log must be open, and
    /// the label must fit [`KEYLOG_LABEL_MAXLEN`].
    ///
    /// The length test comes first because it needs no lock.
    fn will_log(&self, label: &str) -> bool {
        label.len() <= KEYLOG_LABEL_MAXLEN && self.enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    // `PermissionsExt` supplies `Permissions::from_mode`, which `seed_at_mode`
    // needs to set a mode the umask would otherwise have narrowed.
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::thread;

    /// The record every format test compares against, byte for byte.
    ///
    /// Chosen so that a defect in any one field is visible in the failure
    /// message rather than inferred:
    ///
    /// * the label is a real NSS label, and a short one, so the two spaces
    ///   land in easily counted positions;
    /// * the client random is `00 01 .. 1F`, which fails loudly if two bytes
    ///   are swapped, if a byte is skipped, or if the nibbles are exchanged;
    /// * the secret is `DE AD BE EF` repeated to the full 48 bytes, whose hex
    ///   is entirely letters -- so a lowercase `Curl_ldigits` table
    ///   (`lib/mprintf.c:36`) instead of the uppercase `Curl_udigits`
    ///   (`:39`) cannot pass.
    const GOLDEN_RECORD: &str = concat!(
        "CLIENT_RANDOM",
        " ",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        " ",
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        "\n",
    );

    /// The longest label the format defines, and the reason
    /// [`KEYLOG_LABEL_MAXLEN`] is 31 (`lib/vtls/keylog.h:28`).
    const LONGEST_LABEL: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";

    /// Serialises the tests that mutate the process environment.
    ///
    /// `cargo test` runs tests on many threads in one process, and
    /// `SSLKEYLOGFILE` is process-wide state. Without this, a test that clears
    /// the variable could clear it out from under a test that had just set it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// An in-memory key log destination that records how it was written to.
    ///
    /// Cloning shares the recording, so a test keeps its handle while
    /// [`KeyLogFile`] owns a boxed clone. That is what lets a test inspect the
    /// bytes after the log has been closed or dropped.
    #[derive(Clone)]
    struct Recorder(Arc<Mutex<Recording>>);

    /// What a [`Recorder`] observed.
    #[derive(Default)]
    struct Recording {
        /// Every byte handed over, in order.
        bytes: Vec<u8>,
        /// The size of each individual [`Write::write`] call.
        writes: Vec<usize>,
        /// How many times [`Write::flush`] was called.
        flushes: usize,
        /// Once this many writes have succeeded, fail every later one.
        fail_after: Option<usize>,
        /// Split each write in two, releasing the lock in between.
        split_writes: bool,
    }

    impl Recorder {
        /// A recorder that accepts everything.
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Recording::default())))
        }

        /// A recorder that fails every write after the first `accepted`.
        fn failing_after(accepted: usize) -> Self {
            let recorder = Self::new();
            recorder.state().fail_after = Some(accepted);
            recorder
        }

        /// A recorder that hands each write over in two halves, yielding in
        /// between, so that a caller which did not hold a lock across the
        /// whole record would produce visibly interleaved output.
        fn splitting() -> Self {
            let recorder = Self::new();
            recorder.state().split_writes = true;
            recorder
        }

        /// Exclusive access to the recording.
        fn state(&self) -> MutexGuard<'_, Recording> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Everything written so far.
        fn bytes(&self) -> Vec<u8> {
            self.state().bytes.clone()
        }

        /// Everything written so far, as text, for readable assertions.
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.bytes()).into_owned()
        }

        /// The size of each write call so far.
        fn writes(&self) -> Vec<usize> {
            self.state().writes.clone()
        }

        /// How many flushes have happened.
        fn flushes(&self) -> usize {
            self.state().flushes
        }

        /// A boxed clone, to be injected into [`KeyLogFile::with_writer`].
        fn sink(&self) -> Box<dyn Write + Send> {
            Box::new(self.clone())
        }
    }

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let split = {
                let mut state = self.state();
                if let Some(accepted) = state.fail_after {
                    if state.writes.len() >= accepted {
                        return Err(io::Error::other(
                            "the recorder was asked to fail",
                        ));
                    }
                }
                state.writes.push(buf.len());
                state.split_writes
            };

            if !split {
                self.state().bytes.extend_from_slice(buf);
                return Ok(buf.len());
            }

            // Two appends with the lock released in between. If the caller
            // did not hold its own lock across the whole record, two threads
            // would splice their halves together here.
            let (head, tail) = buf.split_at(buf.len() / 2);
            self.state().bytes.extend_from_slice(head);
            thread::yield_now();
            self.state().bytes.extend_from_slice(tail);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.state().flushes += 1;
            Ok(())
        }
    }

    /// `00 01 02 .. 1F`: the client random of [`GOLDEN_RECORD`].
    fn golden_client_random() -> Vec<u8> {
        (0..CLIENT_RANDOM_SIZE)
            .map(|index| u8::try_from(index).unwrap_or(0))
            .collect()
    }

    /// `DE AD BE EF` repeated to [`SECRET_MAXLEN`]: the secret of
    /// [`GOLDEN_RECORD`].
    fn golden_secret() -> Vec<u8> {
        [0xde_u8, 0xad, 0xbe, 0xef]
            .iter()
            .copied()
            .cycle()
            .take(SECRET_MAXLEN)
            .collect()
    }

    /// A log writing into a fresh recorder.
    fn recording_log() -> (Arc<KeyLogFile>, Recorder) {
        let recorder = Recorder::new();
        let keylog = KeyLogFile::with_writer(recorder.sink());
        (keylog, recorder)
    }

    /// Binds a scratch directory, failing the test loudly if the environment
    /// cannot provide one.
    ///
    /// A macro rather than a function because the failure arm has to leave the
    /// *test*. `unwrap`, `expect` and `panic!` are avoided throughout this
    /// file, in tests as well as in the code they exercise; the `let ... else`
    /// arm is unreachable because the assertion above it has already failed
    /// the test.
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

    /// Reads a file back, failing the test if it cannot be read.
    macro_rules! contents {
        ($name:ident, $path:expr) => {
            let $name = fs::read($path);
            assert!($name.is_ok(), "could not read back: {:?}", $name.err());
            let Ok($name) = $name else { return };
        };
    }

    /// Points `SSLKEYLOGFILE` at `path` for the caller's duration.
    ///
    /// Safe in edition 2021, which this crate targets.
    fn set_env_path(path: &Path) {
        std::env::set_var(SSLKEYLOGFILE, path);
    }

    /// Removes `SSLKEYLOGFILE`.
    fn clear_env() {
        std::env::remove_var(SSLKEYLOGFILE);
    }

    /// Exclusive access to the process environment.
    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes `bytes` to `path` at exactly `mode`, reporting success.
    ///
    /// [`fs::write`] cannot be used where the mode matters: it creates with
    /// `0666` narrowed by the process umask, so the resulting mode is a property
    /// of the environment the test runs in rather than of the test. The mode is
    /// requested at creation *and* set again afterwards, because a umask can
    /// only clear bits -- requesting `0600` under a umask of `0077` would leave
    /// `0600`, but requesting `0644` under the same umask would leave `0600` and
    /// silently defeat a test that meant to produce a group-readable file.
    fn seed_at_mode(path: &Path, bytes: &[u8], mode: u32) -> bool {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path);
        let Ok(mut file) = file else { return false };
        if file.write_all(bytes).is_err() {
            return false;
        }
        drop(file);
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).is_ok()
    }

    /// The permission bits of `path`, or [`None`] if it cannot be examined.
    fn mode_of(path: &Path) -> Option<u32> {
        fs::metadata(path).ok().map(|meta| meta.mode() & 0o7777)
    }

    // -- why some tests below are `#[cfg_attr(miri, ignore)]` ----------------
    //
    // Miri's two relevant shims contradict each other, which was measured
    // rather than assumed: `geteuid()` returns a hard-coded `1000`, while every
    // file its filesystem shim reports is owned by uid `0`. So under Miri the
    // ownership comparison in `secret_file_verdict` can never hold, whatever the
    // code does -- a test that expects an open to succeed necessarily fails, and
    // a test that expects a refusal necessarily passes for the wrong reason.
    // Both are worthless there, so both are ignored, and the reason string on
    // each one names the shim rather than the symptom.
    //
    // Nothing of Miri's actual purpose is lost. This module contains no
    // `unsafe`, the only foreign call the hardened open reaches is `geteuid`
    // (which `ffi/sys.rs` covers under Miri in its own right), and the refusal
    // rule itself stays fully covered here by the synthetic
    // `secret_file_verdict` tests, which take the ownership and mode as
    // arguments and touch no filesystem at all.
    //
    // The reason string used throughout is deliberately identical, so that the
    // concession is countable. The audit pattern is ANCHORED at the start of
    // the line, and that is not decoration: these paragraphs quote the reason
    // text as well, so an unanchored grep would count its own documentation and
    // over-report. A comment line begins with `    // ` and an attribute line
    // with `    #[`, so anchoring separates them exactly.
    //
    //   grep -cE '^    #\[cfg_attr\(miri, ignore = "Miri.s uid shims'  -> 12
    //
    // A SECOND, DISTINCT REASON EXISTS, and it is spelled differently on
    // purpose so that each concession stays separately auditable:
    //
    //   grep -cE '^    #\[cfg_attr\(miri, ignore = "Miri.s isolation'  -> 4
    //
    // Miri runs with filesystem isolation enabled, and this gate deliberately
    // passes no `-Zmiri-disable-isolation` -- `.github/workflows/rust-miri.yml`
    // records that every relaxation narrows gate 5. Under isolation `mkdir` is
    // an unsupported operation, so `scratch!` -- which is `tempfile::tempdir()`
    // -- cannot succeed. That matters far more than it sounds: an unsupported
    // operation is not a test failure, it ABORTS THE WHOLE INTERPRETATION, so
    // one un-ignored offender takes the entire `-p curl-rs-lib` gate down and
    // the other 700-odd tests never run at all. MEASURED, each in isolation
    // with `cargo +nightly miri test -- --exact <name>`:
    //
    //   an_unopenable_path_leaves_the_log_disabled   mkdir  aborts
    //   opening_an_open_log_does_not_reopen_it       mkdir  aborts
    //   a_dangling_symlink_creates_nothing           mkdir  aborts
    //   a_directory_is_refused_by_the_open           mkdir  aborts
    //
    // and, for contrast, the two neighbouring cases that take no scratch
    // directory -- `an_absent_variable_leaves_the_log_disabled` and
    // `an_empty_variable_leaves_the_log_disabled` -- both PASS under Miri and
    // are therefore NOT ignored. The rule is exactly "ignore what needs a
    // scratch directory", not "ignore this area of the file".
    //
    // Nothing of Miri's purpose is lost here either. What these four assert is
    // the behaviour of a real `openat` against a real directory entry, which is
    // a kernel property rather than a language-level one; Miri has no more to
    // say about it than the native test run already does.

    // -- the constants ------------------------------------------------------

    /// Each constant is checked against the expression `lib/vtls/keylog.h`
    /// uses, not against a number copied from it.
    #[test]
    fn constants_match_the_c_header() {
        assert_eq!(KEYLOG_LABEL_MAXLEN, LONGEST_LABEL.len());
        assert_eq!(KEYLOG_LABEL_MAXLEN, 31);
        assert_eq!(CLIENT_RANDOM_SIZE, 32);
        assert_eq!(SECRET_MAXLEN, 48);
        assert_eq!(KEYLOG_BUFSIZ, 4096);
        assert_eq!(SSLKEYLOGFILE, "SSLKEYLOGFILE");
        assert_eq!(UPPERCASE_HEX, *b"0123456789ABCDEF");
        assert_eq!(SP, b' ');
        assert_eq!(LF, b'\n');
    }

    /// 31 + 1 + 64 + 1 + 96 + 1 = 194, which is `keylog.c:79`'s 195 without
    /// the C string terminator.
    #[test]
    fn maximum_generated_line_is_194_bytes() {
        assert_eq!(MAX_GENERATED_LINE, 194);
        assert_eq!(MAX_GENERATED_LINE + 1, 195);

        let record = KeyLogFile::secret_record(
            LONGEST_LABEL,
            &golden_client_random(),
            &golden_secret(),
        );
        assert_eq!(record.as_ref().map(Vec::len), Some(MAX_GENERATED_LINE));
    }

    /// `sizeof(buf) - 2` for `char buf[256]` (`keylog.c:81`, `:88`).
    #[test]
    fn generic_line_limit_is_254_bytes() {
        assert_eq!(LINE_MAXLEN, 256 - 2);
    }

    // -- uppercase hex ------------------------------------------------------

    /// [`hexbyte`] against `Curl_hexbyte` (`lib/escape.c:222-227`), for every
    /// input rather than a sample.
    #[test]
    fn hexbyte_is_two_uppercase_digits() {
        assert_eq!(hexbyte(0x00), *b"00");
        assert_eq!(hexbyte(0x0f), *b"0F");
        assert_eq!(hexbyte(0x10), *b"10");
        assert_eq!(hexbyte(0xa5), *b"A5");
        assert_eq!(hexbyte(0xff), *b"FF");

        for value in 0..=u8::MAX {
            let produced = hexbyte(value);
            assert_eq!(
                produced.as_slice(),
                format!("{value:02X}").as_bytes(),
                "hexbyte({value:#04x}) must match the uppercase C table"
            );
            assert!(
                produced.iter().all(|digit| !digit.is_ascii_lowercase()),
                "hexbyte({value:#04x}) produced a lowercase digit"
            );
        }
    }

    // -- the generated record ----------------------------------------------

    /// The whole format, compared as one string.
    #[test]
    fn golden_record_is_byte_exact() {
        let (keylog, recorder) = recording_log();
        assert!(keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));
        assert_eq!(recorder.text(), GOLDEN_RECORD);
        assert_eq!(recorder.bytes(), GOLDEN_RECORD.as_bytes());
    }

    /// The separators, the terminator and the absence of a CR, checked by
    /// position so that a failure says which field moved.
    #[test]
    fn record_layout_is_exact() {
        let (keylog, recorder) = recording_log();
        let label = "CLIENT_RANDOM";
        assert!(keylog.write_secret(
            label,
            &golden_client_random(),
            &golden_secret(),
        ));
        let bytes = recorder.bytes();

        assert_eq!(bytes.len(), label.len() + 1 + 64 + 1 + 96 + 1);
        assert_eq!(&bytes[..label.len()], label.as_bytes());
        assert_eq!(bytes.get(label.len()), Some(&SP));
        assert_eq!(bytes.get(label.len() + 1 + 64), Some(&SP));
        assert_eq!(bytes.last(), Some(&LF));

        assert_eq!(
            bytes.iter().filter(|byte| **byte == SP).count(),
            2,
            "exactly two spaces, and no double space"
        );
        assert_eq!(
            bytes.iter().filter(|byte| **byte == LF).count(),
            1,
            "exactly one LF, at the end"
        );
        assert!(!bytes.contains(&b'\r'), "a CR must never be written");

        let hex = &bytes[label.len() + 1..bytes.len() - 1];
        assert!(
            hex.iter().all(|byte| byte.is_ascii_uppercase()
                || byte.is_ascii_digit()
                || *byte == SP),
            "the hex fields must be uppercase digits only"
        );
    }

    /// A secret shorter than the maximum produces `2 * secret.len()` digits
    /// and nothing more.
    #[test]
    fn secret_field_is_twice_the_secret_length() {
        for length in [1_usize, 16, 32, SECRET_MAXLEN] {
            let (keylog, recorder) = recording_log();
            let secret = vec![0xab_u8; length];
            assert!(keylog.write_secret(
                "EXPORTER_SECRET",
                &golden_client_random(),
                &secret,
            ));
            let bytes = recorder.bytes();
            let expected =
                "EXPORTER_SECRET".len() + 1 + 64 + 1 + 2 * length + 1;
            assert_eq!(
                bytes.len(),
                expected,
                "wrong length for {length} bytes"
            );
            let field = &bytes[bytes.len() - 1 - 2 * length..bytes.len() - 1];
            assert_eq!(field, "AB".repeat(length).as_bytes());
        }
    }

    /// Every label rustls can emit is accepted, and the longest of them is
    /// written whole -- the truncation at `lib/vtls/rustls.c:509` is not
    /// reproduced.
    #[test]
    fn labels_are_never_truncated() {
        let labels = [
            "CLIENT_RANDOM",
            "CLIENT_EARLY_TRAFFIC_SECRET",
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
        ];

        for label in labels {
            assert!(
                label.len() <= KEYLOG_LABEL_MAXLEN,
                "{label} is longer than the format allows"
            );
            let (keylog, recorder) = recording_log();
            assert!(keylog.write_secret(
                label,
                &golden_client_random(),
                &golden_secret(),
            ));
            let bytes = recorder.bytes();
            assert_eq!(&bytes[..label.len()], label.as_bytes());
            assert_eq!(bytes.get(label.len()), Some(&SP));
        }
    }

    /// 31 bytes is the last accepted length; 32 is rejected rather than
    /// shortened (`keylog.c:118`).
    #[test]
    fn label_length_boundary_is_31() {
        let random = golden_client_random();
        let secret = golden_secret();

        let (accepted, recorder) = recording_log();
        let label = "A".repeat(KEYLOG_LABEL_MAXLEN);
        assert!(accepted.write_secret(&label, &random, &secret));
        assert!(recorder.text().starts_with(&format!("{label} ")));

        let (rejected, recorder) = recording_log();
        let too_long = "A".repeat(KEYLOG_LABEL_MAXLEN + 1);
        assert!(!rejected.write_secret(&too_long, &random, &secret));
        assert!(recorder.bytes().is_empty(), "nothing may be written");
    }

    /// An empty secret is rejected and 49 bytes is rejected; 1 and 48 are
    /// accepted (`keylog.c:118`: `!secretlen || secretlen > SECRET_MAXLEN`).
    #[test]
    fn secret_length_boundaries_are_1_and_48() {
        let random = golden_client_random();

        for length in [0_usize, SECRET_MAXLEN + 1] {
            let (keylog, recorder) = recording_log();
            let secret = vec![0x5a_u8; length];
            assert!(
                !keylog.write_secret("CLIENT_RANDOM", &random, &secret),
                "a {length}-byte secret must be rejected"
            );
            assert!(recorder.bytes().is_empty());
        }

        for length in [1_usize, SECRET_MAXLEN] {
            let (keylog, recorder) = recording_log();
            let secret = vec![0x5a_u8; length];
            assert!(
                keylog.write_secret("CLIENT_RANDOM", &random, &secret),
                "a {length}-byte secret must be accepted"
            );
            assert!(!recorder.bytes().is_empty());
        }
    }

    /// The client random must be exactly 32 bytes, in every build -- unlike
    /// the `DEBUGASSERT` at `lib/vtls/rustls.c:511`.
    #[test]
    fn client_random_must_be_exactly_32_bytes() {
        let secret = golden_secret();

        for length in [0_usize, 1, 31, 33, 64] {
            let (keylog, recorder) = recording_log();
            let random = vec![0x11_u8; length];
            assert!(
                !keylog.write_secret("CLIENT_RANDOM", &random, &secret),
                "a {length}-byte client random must be rejected"
            );
            assert!(recorder.bytes().is_empty());
        }

        let (keylog, recorder) = recording_log();
        let random = vec![0x11_u8; CLIENT_RANDOM_SIZE];
        assert!(keylog.write_secret("CLIENT_RANDOM", &random, &secret));
        let expected = "CLIENT_RANDOM".len() + 1 + 64 + 1 + 96 + 1;
        assert_eq!(recorder.bytes().len(), expected);
    }

    // -- the disabled, closed and failing states ---------------------------

    /// A disabled log accepts nothing and reports nothing
    /// (`keylog.c:83`, `:113-115`).
    #[test]
    fn a_disabled_log_writes_nothing() {
        let keylog = KeyLogFile::disabled();
        assert!(!keylog.enabled());
        assert!(!keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));
        assert!(!keylog.write_line(b"CLIENT_RANDOM AA BB"));
        assert!(!keylog.write_line(b"already terminated\n"));
    }

    /// After [`KeyLogFile::close`] the log behaves exactly as a disabled one,
    /// and what was written before the close is still there.
    #[test]
    fn a_closed_log_writes_nothing_more() {
        let (keylog, recorder) = recording_log();
        assert!(keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));
        let before = recorder.bytes();

        keylog.close();
        assert!(!keylog.enabled());
        assert!(!keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));
        assert!(!keylog.write_line(b"after the close"));
        assert_eq!(recorder.bytes(), before);
    }

    /// Close is idempotent, as `if(keylog_file_fp)` makes
    /// `Curl_tls_keylog_close` (`keylog.c:64-70`) -- the rustls backend calls
    /// it from two places (`rustls.c:825`, `:1394`), and the second call must
    /// not be a fault.
    #[test]
    fn close_is_idempotent() {
        let (keylog, recorder) = recording_log();
        assert!(keylog.write_line(b"one line"));
        let after_write = recorder.flushes();

        keylog.close();
        let after_first_close = recorder.flushes();
        assert!(after_first_close > after_write, "close must flush");

        for _ in 0..5 {
            keylog.close();
        }
        assert_eq!(
            recorder.flushes(),
            after_first_close,
            "a second close must do nothing at all"
        );
        assert!(!keylog.enabled());
    }

    /// A failing write is reported, and the log stays open so that a
    /// transient failure does not silently end the session's logging.
    #[test]
    fn a_failing_write_is_reported_but_does_not_close_the_log() {
        let recorder = Recorder::failing_after(1);
        let keylog = KeyLogFile::with_writer(recorder.sink());
        let random = golden_client_random();
        let secret = golden_secret();

        assert!(keylog.write_secret("CLIENT_RANDOM", &random, &secret));
        assert!(!keylog.write_secret("CLIENT_RANDOM", &random, &secret));
        assert!(keylog.enabled(), "the log must remain open");
        assert!(!keylog.write_line(b"and this fails too"));

        // Only the first record reached the recording.
        assert_eq!(recorder.bytes(), GOLDEN_RECORD.as_bytes());
    }

    /// A rejected record never reaches the sink, so a rejection cannot be
    /// mistaken for a truncated write.
    #[test]
    fn rejections_do_not_touch_the_sink() {
        let (keylog, recorder) = recording_log();
        let random = golden_client_random();

        assert!(!keylog.write_secret(
            &"X".repeat(KEYLOG_LABEL_MAXLEN + 1),
            &random,
            &golden_secret(),
        ));
        assert!(!keylog.write_secret("CLIENT_RANDOM", &random, &[]));
        assert!(!keylog.write_secret("CLIENT_RANDOM", &[], &golden_secret()));
        assert!(!keylog.write_line(b""));

        assert!(recorder.bytes().is_empty());
        assert!(recorder.writes().is_empty());
    }

    // -- the generic line writer -------------------------------------------

    /// A line already ending in LF is written unchanged: no second LF, no CR
    /// (`keylog.c:94-96`).
    #[test]
    fn a_line_ending_in_lf_is_written_unchanged() {
        let (keylog, recorder) = recording_log();
        let line = b"CLIENT_RANDOM ABCD 0123\n";
        assert!(keylog.write_line(line));
        assert_eq!(recorder.bytes(), line);
    }

    /// A line without a terminator gets exactly one LF appended.
    #[test]
    fn a_line_without_lf_gets_exactly_one() {
        let (keylog, recorder) = recording_log();
        assert!(keylog.write_line(b"CLIENT_RANDOM ABCD 0123"));
        assert_eq!(recorder.bytes(), b"CLIENT_RANDOM ABCD 0123\n");
        assert_eq!(
            recorder.bytes().iter().filter(|byte| **byte == LF).count(),
            1
        );
    }

    /// An empty line is rejected (`keylog.c:88`: `linelen == 0`).
    #[test]
    fn an_empty_line_is_rejected() {
        let (keylog, recorder) = recording_log();
        assert!(!keylog.write_line(b""));
        assert!(recorder.bytes().is_empty());
    }

    /// A bare LF is one byte, not an empty line, so it is accepted and
    /// written as it stands.
    #[test]
    fn a_bare_lf_is_a_valid_line() {
        let (keylog, recorder) = recording_log();
        assert!(keylog.write_line(b"\n"));
        assert_eq!(recorder.bytes(), b"\n");
    }

    /// 254 bytes is the last accepted length and 255 is refused, which is
    /// `linelen > sizeof(buf) - 2` for `char buf[256]` (`keylog.c:81`, `:88`).
    #[test]
    fn the_line_length_boundary_is_254_bytes() {
        let (accepted, recorder) = recording_log();
        let line = vec![b'K'; LINE_MAXLEN];
        assert!(accepted.write_line(&line));
        let written = recorder.bytes();
        assert_eq!(written.len(), LINE_MAXLEN + 1, "254 bytes plus the LF");
        assert_eq!(written.last(), Some(&LF));

        let (rejected, recorder) = recording_log();
        let too_long = vec![b'K'; LINE_MAXLEN + 1];
        assert!(!rejected.write_line(&too_long));
        assert!(recorder.bytes().is_empty());

        // An already-terminated 254-byte line is also accepted, and keeps its
        // own LF rather than gaining a second.
        let (terminated, recorder) = recording_log();
        let mut exact = vec![b'K'; LINE_MAXLEN - 1];
        exact.push(LF);
        assert!(terminated.write_line(&exact));
        assert_eq!(recorder.bytes(), exact);
    }

    /// The generic writer is byte-transparent: no encoding conversion, no
    /// escape processing, no newline normalization, and no requirement that
    /// the input be UTF-8.
    #[test]
    fn line_bytes_are_never_rewritten() {
        let (keylog, recorder) = recording_log();
        // A CR that must survive, an interior LF that must not be collapsed,
        // a tab, and a byte that is not valid UTF-8. The input does not end in
        // an LF, so exactly one is appended: C tests only the last byte
        // (`keylog.c:94`), so an interior LF is not a terminator.
        let line: &[u8] = b"a\r\nb\nc\t\xff";
        let mut expected = line.to_vec();
        expected.push(LF);
        assert!(keylog.write_line(line));
        assert_eq!(recorder.bytes(), expected);

        // The same bytes, already terminated, go through untouched.
        let (terminated, recorder) = recording_log();
        let already: &[u8] = b"a\r\nb\nc\t\xff\n";
        assert!(terminated.write_line(already));
        assert_eq!(recorder.bytes(), already);

        let (unterminated, recorder) = recording_log();
        let ends_in_cr: &[u8] = b"trailing CR\r";
        assert!(unterminated.write_line(ends_in_cr));
        assert_eq!(
            recorder.bytes(),
            b"trailing CR\r\n",
            "a CR does not count as a terminator; the LF is appended"
        );
    }

    /// A record composed by the caller and handed to the generic writer
    /// produces the same bytes as the dedicated writer.
    #[test]
    fn the_two_writers_agree_on_a_generated_record() {
        let (generated, generated_bytes) = recording_log();
        assert!(generated.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));

        let (literal, literal_bytes) = recording_log();
        assert!(literal.write_line(GOLDEN_RECORD.as_bytes()));

        assert_eq!(generated_bytes.bytes(), literal_bytes.bytes());
    }

    // -- buffering ---------------------------------------------------------

    /// One record is one write, and it is flushed on the LF: the observable
    /// effect of `setvbuf(fp, NULL, _IOLBF, 4096)` (`keylog.c:52`).
    #[test]
    fn each_record_reaches_the_writer_as_one_flushed_write() {
        let (keylog, recorder) = recording_log();
        let random = golden_client_random();
        let secret = golden_secret();

        for _ in 0..3 {
            assert!(keylog.write_secret("CLIENT_RANDOM", &random, &secret));
        }

        let record = GOLDEN_RECORD.len();
        assert_eq!(
            recorder.writes(),
            vec![record, record, record],
            "three whole records, one write each"
        );
        assert_eq!(recorder.flushes(), 3, "each LF flushes");
        assert_eq!(recorder.bytes().len(), 3 * record);
    }

    /// The buffering mode follows the target's C build: line buffered
    /// everywhere except Windows, where `_IONBF` applies
    /// (`keylog.c:49-53`).
    #[test]
    fn the_buffering_mode_matches_the_c_build() {
        let recorder = Recorder::new();
        let sink = LineBufferedSink::new(recorder.sink());
        assert_eq!(sink.line_buffered, !cfg!(windows));
        if sink.line_buffered {
            assert!(sink.buffer.capacity() >= KEYLOG_BUFSIZ);
        }
        assert!(sink.buffer.is_empty());
    }

    /// The staging buffer is emptied as soon as the bytes leave it, on the
    /// failure path as well as the success path.
    #[test]
    fn the_staging_buffer_does_not_retain_a_record() {
        let recorder = Recorder::new();
        let mut sink = LineBufferedSink::new(recorder.sink());
        assert!(sink.write_record(GOLDEN_RECORD.as_bytes()).is_ok());
        assert!(sink.buffer.is_empty(), "a written record must not linger");

        let failing = Recorder::failing_after(0);
        let mut sink = LineBufferedSink::new(failing.sink());
        assert!(sink.write_record(GOLDEN_RECORD.as_bytes()).is_err());
        assert!(sink.buffer.is_empty(), "a failed record must not linger");
    }

    /// A record larger than the buffer bypasses it, as stdio would, and
    /// arrives whole. Unreachable through the public writers, which cap at
    /// 194 and 255 bytes.
    #[test]
    fn an_oversized_record_bypasses_the_buffer() {
        let recorder = Recorder::new();
        let mut sink = LineBufferedSink::new(recorder.sink());
        let mut record = vec![b'Z'; KEYLOG_BUFSIZ + 1];
        record.push(LF);
        assert!(sink.write_record(&record).is_ok());
        assert_eq!(recorder.bytes(), record);
        assert!(sink.buffer.is_empty());
    }

    /// A fragment with no LF stays buffered, and is flushed when the sink is
    /// finished -- the `_IOLBF` contract, and the reason [`Drop`] flushes.
    #[test]
    fn an_unterminated_fragment_is_flushed_on_finish() {
        let recorder = Recorder::new();
        let mut sink = LineBufferedSink::new(recorder.sink());
        if !sink.line_buffered {
            return;
        }

        assert!(sink.write_record(b"no terminator yet").is_ok());
        assert!(
            recorder.bytes().is_empty(),
            "without an LF the bytes stay in the buffer"
        );

        sink.finish();
        assert_eq!(recorder.bytes(), b"no terminator yet");
        assert!(sink.buffer.is_empty());
    }

    // -- the lifecycle -----------------------------------------------------

    /// Dropping the log flushes it, so a caller that forgets
    /// [`KeyLogFile::close`] still gets a complete file -- which the C tree,
    /// with its process-global handle, could not promise.
    #[test]
    fn dropping_the_log_flushes_it() {
        let recorder = Recorder::new();
        let keylog = KeyLogFile::with_writer(recorder.sink());
        assert!(keylog.write_line(b"a line"));
        let before = recorder.flushes();

        drop(keylog);
        assert!(recorder.flushes() > before, "Drop must flush");
        assert_eq!(recorder.bytes(), b"a line\n");
    }

    /// Dropping after an explicit close is not a second close.
    #[test]
    fn dropping_a_closed_log_is_a_no_op() {
        let recorder = Recorder::new();
        let keylog = KeyLogFile::with_writer(recorder.sink());
        assert!(keylog.write_line(b"a line"));
        keylog.close();
        let after_close = recorder.flushes();

        drop(keylog);
        assert_eq!(recorder.flushes(), after_close);
        assert_eq!(recorder.bytes(), b"a line\n");
    }

    /// The [`fmt::Debug`] rendering carries no key material and no path.
    #[test]
    fn debug_never_prints_key_material() {
        let (keylog, _recorder) = recording_log();
        assert!(keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));

        let rendered = format!("{keylog:?}");
        assert!(rendered.contains("KeyLogFile"));
        assert!(rendered.contains("enabled"));
        assert!(rendered.contains("true"));
        assert!(!rendered.contains("DEADBEEF"), "{rendered}");
        assert!(!rendered.contains("000102"), "{rendered}");
        assert!(!rendered.contains("CLIENT_RANDOM"), "{rendered}");

        keylog.close();
        assert!(format!("{keylog:?}").contains("false"));
    }

    // -- SSLKEYLOGFILE ------------------------------------------------------

    /// The empty-value rule of `curl_getenv` (`lib/getenv.c:79`), tested
    /// without mutating the environment.
    #[test]
    fn an_empty_environment_value_counts_as_absent() {
        assert_eq!(KeyLogFile::env_path(None), None);
        assert_eq!(KeyLogFile::env_path(Some(OsString::new())), None);
        let path = OsString::from("/dev/null");
        assert_eq!(KeyLogFile::env_path(Some(path.clone())), Some(path));
    }

    /// No variable, no log -- and the transfer carries on
    /// (`lib/vtls/rustls.c:816-818`).
    #[test]
    fn an_absent_variable_leaves_the_log_disabled() {
        let _env = env_lock();
        clear_env();

        let keylog = KeyLogFile::open_from_env();
        assert!(!keylog.enabled());
        assert!(!keylog.write_line(b"nowhere to write this"));
        assert!(!keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));
    }

    /// An empty variable behaves exactly as an absent one.
    #[test]
    fn an_empty_variable_leaves_the_log_disabled() {
        let _env = env_lock();
        std::env::set_var(SSLKEYLOGFILE, "");

        let keylog = KeyLogFile::open_from_env();
        assert!(!keylog.enabled());

        clear_env();
    }

    /// A path that cannot be opened leaves the log disabled, and nothing about
    /// the TLS handshake changes: this is the case `rustls.c:816-818` returns
    /// `CURLE_OK` for.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn an_unopenable_path_leaves_the_log_disabled() {
        scratch!(dir);
        let _env = env_lock();
        let path = dir.path().join("no-such-directory").join("keylog.txt");
        set_env_path(&path);

        let keylog = KeyLogFile::open_from_env();
        assert!(!keylog.enabled(), "a missing directory cannot be opened");
        assert!(!keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));
        assert!(!path.exists(), "no file may be created on the way");

        clear_env();
    }

    /// A path that is not valid UTF-8 is honoured, because [`var_os`] hands
    /// over the raw bytes just as `curl_getenv` does (`lib/getenv.c:78-79`).
    ///
    /// Unix only: a Windows environment value is UTF-16 and cannot carry an
    /// unpaired byte, and Windows is outside the mandated target matrix.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn a_non_unicode_path_is_honoured() {
        use std::os::unix::ffi::OsStringExt;
        use std::path::PathBuf;

        scratch!(dir);
        let _env = env_lock();

        // "keylog-\xFF.txt": a valid Unix filename that is not valid UTF-8.
        let mut name = b"keylog-".to_vec();
        name.push(0xff);
        name.extend_from_slice(b".txt");
        let path = dir.path().join(PathBuf::from(OsString::from_vec(name)));
        assert!(
            path.as_os_str().to_str().is_none(),
            "this test is pointless unless the path is not UTF-8"
        );

        set_env_path(&path);
        let keylog = KeyLogFile::open_from_env();
        assert!(keylog.enabled(), "a non-UTF-8 path must still open");
        assert!(keylog.write_line(b"CLIENT_RANDOM 00 11"));
        keylog.close();

        contents!(written, &path);
        assert_eq!(written, b"CLIENT_RANDOM 00 11\n");

        clear_env();
    }

    /// An existing key log is appended to, never truncated: `"a"` mode
    /// (`keylog.c:47`, `lib/curl_setup.h:1257-1260`). A capture taken before
    /// this run must stay decryptable.
    ///
    /// The seed is written at [`SECRET_FILE_MODE`] rather than with a plain
    /// `fs::write`, which would take its mode from the process umask -- `0644`
    /// under the usual `0022` -- and be refused by
    /// [`KeyLogFile::open_private_append`]. That refusal is correct and is
    /// asserted by [`a_world_readable_key_log_is_refused`]; what this test is
    /// about is the append, so its fixture models a key log this implementation
    /// would itself have left behind.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn an_existing_key_log_is_appended_not_truncated() {
        scratch!(dir);
        let _env = env_lock();
        let path = dir.path().join("keylog.txt");
        let seeded: &[u8] = b"CLIENT_RANDOM 0011 2233\n";
        assert!(seed_at_mode(&path, seeded, SECRET_FILE_MODE));
        set_env_path(&path);

        let first = KeyLogFile::open_from_env();
        assert!(first.enabled());
        assert!(first.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));
        first.close();

        let mut expected = seeded.to_vec();
        expected.extend_from_slice(GOLDEN_RECORD.as_bytes());
        contents!(after_first, &path);
        assert_eq!(after_first, expected);

        // A second log over the same path appends again rather than starting
        // over, which is what makes several easy handles in one process safe.
        let second = KeyLogFile::open_from_env();
        assert!(second.write_line(b"SERVER_TRAFFIC_SECRET_0 44 55"));
        second.close();

        expected.extend_from_slice(b"SERVER_TRAFFIC_SECRET_0 44 55\n");
        contents!(after_second, &path);
        assert_eq!(after_second, expected);

        clear_env();
    }

    /// A record is on disk before the log is closed, and carries no CR: the
    /// file-backed proof of line buffering (`keylog.c:52`) and of the plain
    /// `"a"` mode that does no end-of-line translation.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn a_record_reaches_the_file_without_being_closed() {
        scratch!(dir);
        let _env = env_lock();
        let path = dir.path().join("keylog.txt");
        set_env_path(&path);

        let keylog = KeyLogFile::open_from_env();
        assert!(keylog.enabled());
        assert!(keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));

        // Deliberately read while the log is still open.
        contents!(written, &path);
        assert_eq!(written, GOLDEN_RECORD.as_bytes());
        assert!(!written.contains(&b'\r'), "no CRLF translation may happen");

        clear_env();
    }

    /// An open log ignores the environment: `Curl_tls_keylog_open` is guarded
    /// by `if(!keylog_file_fp)` (`keylog.c:44`), and the rustls backend calls
    /// it once per easy handle (`rustls.c:815`).
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn opening_an_open_log_does_not_reopen_it() {
        scratch!(dir);
        let _env = env_lock();
        let path = dir.path().join("keylog.txt");
        set_env_path(&path);

        let recorder = Recorder::new();
        let keylog = KeyLogFile::with_writer(recorder.sink());
        assert!(keylog.open(), "an open log reports that it is open");
        assert!(keylog.open(), "and says so again");
        assert!(keylog.write_line(b"CLIENT_RANDOM 66 77"));

        assert_eq!(recorder.bytes(), b"CLIENT_RANDOM 66 77\n");
        assert!(
            !path.exists(),
            "the injected writer must not be replaced by the file"
        );

        clear_env();
    }

    /// After a close, [`KeyLogFile::open`] reads the environment again -- the
    /// lazy half of the lifecycle, and what a backend does when it recovers
    /// from a registration failure (`rustls.c:823-826`).
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn a_closed_log_can_be_reopened() {
        scratch!(dir);
        let _env = env_lock();
        let path = dir.path().join("keylog.txt");
        set_env_path(&path);

        let keylog = KeyLogFile::disabled();
        assert!(!keylog.enabled(), "deferred construction starts closed");
        assert!(keylog.open());
        assert!(keylog.write_line(b"first"));
        keylog.close();
        assert!(!keylog.enabled());

        assert!(keylog.open(), "and opens again from the environment");
        assert!(keylog.write_line(b"second"));
        keylog.close();

        contents!(written, &path);
        assert_eq!(written, b"first\nsecond\n");

        clear_env();
    }

    // -- secret-file safety (F21) ------------------------------------------
    //
    // Two layers, tested separately on purpose.
    //
    // `secret_file_verdict` is the rule, and it is a pure function of four
    // facts, so every combination -- including the ones a single host cannot be
    // made to produce, such as a file owned by a user this process is not --
    // is reachable without root, without a particular filesystem and without a
    // `chown`.
    //
    // `open_private_append` is the wiring, and it is tested against real files
    // in a real directory, because the properties that matter there are
    // properties of the kernel: whether `O_NOFOLLOW` really refuses a symlink,
    // whether the mode a file is created with really is `0600` after the umask
    // has had its say, and whether the descriptor really carries `O_CLOEXEC`.

    /// A private, self-owned regular file is the one accepted combination.
    #[test]
    fn a_private_self_owned_regular_file_is_accepted() {
        assert_eq!(secret_file_verdict(true, 1000, 0o100_600, 1000), Ok(()));
        // Owner-execute is not a reason to refuse: odd, but it grants nobody
        // else anything.
        assert_eq!(secret_file_verdict(true, 0, 0o100_700, 0), Ok(()));
    }

    /// Each of the three refusals is produced by exactly its own condition.
    #[test]
    fn each_refusal_has_its_own_cause() {
        assert_eq!(
            secret_file_verdict(false, 1000, 0o600, 1000),
            Err(SecretFileRejection::NotRegularFile)
        );
        assert_eq!(
            secret_file_verdict(true, 1001, 0o600, 1000),
            Err(SecretFileRejection::ForeignOwner)
        );
        assert_eq!(
            secret_file_verdict(true, 1000, 0o644, 1000),
            Err(SecretFileRejection::TooPermissive)
        );
    }

    /// Every group and other permission bit is a refusal, and no owner bit is.
    ///
    /// Enumerated rather than sampled, because a mask written with the wrong
    /// number of digits -- `0o77` for `0o077`, say -- passes a test that only
    /// tries `0o644`.
    #[test]
    fn only_group_and_other_bits_are_too_permissive() {
        for bit in 0..9 {
            let mode = 1_u32 << bit;
            let verdict = secret_file_verdict(true, 7, 0o100_600 | mode, 7);
            let owner_bit = mode & 0o700 != 0;
            assert_eq!(
                verdict.is_ok(),
                owner_bit,
                "mode bit {mode:#o} must {} be a refusal",
                if owner_bit { "not" } else { "" }
            );
        }
        // The file-type bits live above the permission bits and must never be
        // mistaken for them: `0o100000` is `S_IFREG` and appears in every real
        // `st_mode`.
        assert_eq!(secret_file_verdict(true, 7, 0o100_600, 7), Ok(()));
        assert_eq!(secret_file_verdict(true, 7, 0o140_600, 7), Ok(()));
    }

    /// The rule compares against the *effective* id it is handed, whatever it
    /// is -- root included, which is the case a test running as root would
    /// otherwise never exercise from the other side.
    #[test]
    fn ownership_is_compared_and_not_assumed() {
        assert_eq!(secret_file_verdict(true, 0, 0o600, 0), Ok(()));
        assert_eq!(
            secret_file_verdict(true, 0, 0o600, 1000),
            Err(SecretFileRejection::ForeignOwner)
        );
        assert_eq!(
            secret_file_verdict(true, 1000, 0o600, 0),
            Err(SecretFileRejection::ForeignOwner)
        );
    }

    /// The severity order is fixed, so a file that fails two tests reports the
    /// more fundamental one.
    #[test]
    fn the_most_fundamental_refusal_is_the_one_reported() {
        // Not a regular file *and* foreign *and* world-readable.
        assert_eq!(
            secret_file_verdict(false, 1001, 0o666, 1000),
            Err(SecretFileRejection::NotRegularFile)
        );
        // Foreign *and* world-readable.
        assert_eq!(
            secret_file_verdict(true, 1001, 0o666, 1000),
            Err(SecretFileRejection::ForeignOwner)
        );
    }

    /// Every refusal reaches the caller as `PermissionDenied`, and none of the
    /// messages names a path.
    #[test]
    fn a_refusal_carries_no_path_and_one_error_kind() {
        for rejection in [
            SecretFileRejection::NotRegularFile,
            SecretFileRejection::ForeignOwner,
            SecretFileRejection::TooPermissive,
        ] {
            let error = rejection.into_io_error();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), rejection.reason());
            assert!(
                rejection.reason().starts_with("SSLKEYLOGFILE "),
                "the reason names the variable, never a path"
            );
        }
    }

    /// A key log this implementation creates is private before any umask is
    /// consulted.
    ///
    /// The umask in force is deliberately widened to `0` for the duration, which
    /// is the configuration under which C's `fopen(name, "a")` leaves a `0666`
    /// file. If the mode came from the umask rather than from
    /// [`SECRET_FILE_MODE`], this is the test that says so.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn a_created_key_log_is_private() {
        scratch!(dir);
        let _env = env_lock();
        let path = dir.path().join("keylog.txt");
        set_env_path(&path);

        let keylog = KeyLogFile::open_from_env();
        assert!(keylog.enabled(), "a fresh path must open");
        assert!(keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));
        keylog.close();

        assert_eq!(
            mode_of(&path),
            Some(SECRET_FILE_MODE),
            "a created key log must be 0600 and nothing wider"
        );
        contents!(written, &path);
        assert_eq!(
            written,
            GOLDEN_RECORD.as_bytes(),
            "hardening must not change what is written"
        );

        clear_env();
    }

    /// A key log left behind world-readable is refused, and left untouched.
    ///
    /// This is the case a C curl produces under the usual umask, so the refusal
    /// is the deliberate divergence documented on
    /// [`KeyLogFile::open_private_append`] -- not an accident. The file's
    /// contents are checked afterwards because a refusal that had already
    /// appended would be worthless.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn a_world_readable_key_log_is_refused() {
        scratch!(dir);
        let _env = env_lock();
        let path = dir.path().join("keylog.txt");
        let seeded: &[u8] = b"CLIENT_RANDOM 0011 2233\n";
        assert!(seed_at_mode(&path, seeded, 0o644));
        set_env_path(&path);

        let keylog = KeyLogFile::open_from_env();
        assert!(!keylog.enabled(), "0644 must not receive TLS secrets");
        assert!(!keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));

        contents!(after, &path);
        assert_eq!(after, seeded, "a refused key log must be untouched");
        assert_eq!(
            mode_of(&path),
            Some(0o644),
            "refusing must not silently tighten a file the user owns"
        );

        clear_env();
    }

    /// Group-readable is refused too: the mask is not "world" alone.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn a_group_readable_key_log_is_refused() {
        scratch!(dir);
        let _env = env_lock();
        let path = dir.path().join("keylog.txt");
        assert!(seed_at_mode(&path, b"", 0o640));
        set_env_path(&path);

        assert!(!KeyLogFile::open_from_env().enabled());

        clear_env();
    }

    /// An existing key log that is already private is accepted and appended to.
    ///
    /// The positive control for the two refusals above: without it, a fix that
    /// refused *every* pre-existing file would pass both of them.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn an_existing_private_key_log_is_accepted() {
        scratch!(dir);
        let _env = env_lock();
        let path = dir.path().join("keylog.txt");
        let seeded: &[u8] = b"CLIENT_RANDOM 0011 2233\n";
        assert!(seed_at_mode(&path, seeded, SECRET_FILE_MODE));
        set_env_path(&path);

        let keylog = KeyLogFile::open_from_env();
        assert!(keylog.enabled(), "0600 must be accepted");
        assert!(keylog.write_line(b"SERVER_TRAFFIC_SECRET_0 44 55"));
        keylog.close();

        let mut expected = seeded.to_vec();
        expected.extend_from_slice(b"SERVER_TRAFFIC_SECRET_0 44 55\n");
        contents!(after, &path);
        assert_eq!(after, expected);

        clear_env();
    }

    /// A symlinked `SSLKEYLOGFILE` is refused, and its target stays empty.
    ///
    /// `O_NOFOLLOW`. The target is created first and left empty so that its
    /// emptiness afterwards is evidence rather than coincidence, and the link
    /// itself is checked to still be a link -- an implementation that replaced
    /// the link with a regular file would also leave an empty target.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn a_symlinked_key_log_is_refused() {
        scratch!(dir);
        let _env = env_lock();
        let target = dir.path().join("target.txt");
        let link = dir.path().join("keylog.txt");
        assert!(seed_at_mode(&target, b"", SECRET_FILE_MODE));
        assert!(std::os::unix::fs::symlink(&target, &link).is_ok());
        set_env_path(&link);

        let keylog = KeyLogFile::open_from_env();
        assert!(!keylog.enabled(), "a symlink must not be followed");
        assert!(!keylog.write_secret(
            "CLIENT_RANDOM",
            &golden_client_random(),
            &golden_secret(),
        ));

        contents!(after, &target);
        assert!(after.is_empty(), "nothing may reach a symlink's target");
        let link_meta = fs::symlink_metadata(&link);
        assert!(
            matches!(link_meta, Ok(ref meta) if meta.file_type().is_symlink()),
            "the link must still be a link: {link_meta:?}"
        );

        clear_env();
    }

    /// A symlink to a path that does not exist is refused rather than created.
    ///
    /// The dangling case is separate because `O_CREAT` without `O_NOFOLLOW`
    /// *creates the target*, which is the primitive behind the classic
    /// place-a-link-and-wait attack. Nothing may appear at the target.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_dangling_symlink_creates_nothing() {
        scratch!(dir);
        let _env = env_lock();
        let target = dir.path().join("absent.txt");
        let link = dir.path().join("keylog.txt");
        assert!(std::os::unix::fs::symlink(&target, &link).is_ok());
        set_env_path(&link);

        assert!(!KeyLogFile::open_from_env().enabled());
        assert!(
            !target.exists(),
            "O_NOFOLLOW must not create a symlink's target"
        );

        clear_env();
    }

    /// A character device is refused: the regular-file check.
    ///
    /// `/dev/null` is the one non-regular file that can be opened for writing
    /// on any of the mandated targets without blocking and without privileges.
    /// A FIFO is deliberately *not* used: opening one for writing with no reader
    /// blocks inside `open`, before any check of ours can run, so a test built
    /// on one would hang rather than fail. That limit is real and is recorded
    /// here rather than papered over -- the regular-file test stops a device or
    /// a socket from receiving secrets, and a FIFO blocks exactly as C's
    /// `fopen` would.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn a_character_device_is_refused() {
        let devnull = Path::new("/dev/null");
        if !devnull.exists() {
            return;
        }
        let opened = KeyLogFile::open_private_append(devnull.as_os_str());
        assert!(
            matches!(&opened, Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied),
            "/dev/null must be refused by our verdict, not by the kernel: \
             {opened:?}"
        );
    }

    /// The descriptor is close-on-exec, so a child process cannot read it.
    ///
    /// Read back from `/proc/self/fdinfo`, which reports the descriptor's flags
    /// in octal, rather than trusted from the flag having been passed: Rust's
    /// [`File`] sets `O_CLOEXEC` itself, so passing it proves nothing on its
    /// own and this is the assertion that the property actually holds.
    ///
    /// Linux only, because `/proc` is where the answer is legible without a
    /// `fcntl` call, which this module may not make.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    #[cfg(target_os = "linux")]
    fn the_key_log_descriptor_is_close_on_exec() {
        use std::os::unix::io::AsRawFd;

        /// `O_CLOEXEC` as `/proc/<pid>/fdinfo/<fd>` reports it.
        const O_CLOEXEC_BIT: u32 = 0o2_000_000;

        scratch!(dir);
        let path = dir.path().join("keylog.txt");
        let opened = KeyLogFile::open_private_append(path.as_os_str());
        assert!(opened.is_ok(), "a fresh path must open: {:?}", opened.err());
        let Ok(file) = opened else { return };

        let info = fs::read_to_string(format!(
            "/proc/self/fdinfo/{}",
            file.as_raw_fd()
        ));
        assert!(info.is_ok(), "fdinfo must be readable on Linux");
        let Ok(info) = info else { return };

        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| u32::from_str_radix(value.trim(), 8).ok());
        assert!(flags.is_some(), "fdinfo must report flags: {info}");
        let Some(flags) = flags else { return };
        assert_ne!(
            flags & O_CLOEXEC_BIT,
            0,
            "the key log descriptor must be close-on-exec ({flags:#o})"
        );
    }

    /// A directory is refused, and by the kernel rather than by us.
    ///
    /// `O_WRONLY` on a directory is `EISDIR`, so the open fails before the
    /// verdict runs. Recorded as a test because the outcome is what matters and
    /// because it pins which layer produces it: a `PermissionDenied` here would
    /// mean the open had somehow succeeded.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_directory_is_refused_by_the_open() {
        scratch!(dir);
        let opened = KeyLogFile::open_private_append(dir.path().as_os_str());
        assert!(
            matches!(&opened, Err(error)
                if error.kind() != io::ErrorKind::PermissionDenied),
            "a directory must fail in the open, not in the verdict: {opened:?}"
        );
    }

    /// The four open options C's `"a"` mode implies survive the hardening.
    ///
    /// Append, create, no truncation, and no end-of-line translation -- checked
    /// together on one file so that a change to the option chain which dropped
    /// one of them cannot pass by being tested somewhere else.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's uid shims disagree")]
    fn hardening_preserves_append_and_no_truncate() {
        scratch!(dir);
        let path = dir.path().join("keylog.txt");
        assert!(seed_at_mode(&path, b"first\n", SECRET_FILE_MODE));

        for round in ["second\n", "third\n"] {
            let opened = KeyLogFile::open_private_append(path.as_os_str());
            assert!(opened.is_ok(), "{:?}", opened.err());
            let Ok(mut file) = opened else { return };
            assert!(file.write_all(round.as_bytes()).is_ok());
        }

        contents!(after, &path);
        assert_eq!(
            after, b"first\nsecond\nthird\n",
            "every open must append to what was already there"
        );
    }

    // -- concurrency -------------------------------------------------------

    /// Concurrent handshakes never splice their secrets together.
    ///
    /// The recorder hands each write over in two halves with its lock
    /// released in between (see [`Recorder::splitting`]), so a caller that
    /// did not hold one lock across the whole record would produce lines with
    /// one thread's label and another thread's secret. Every line here must be
    /// a complete record, and each thread's record must appear exactly as many
    /// times as it was written.
    #[test]
    fn concurrent_records_are_never_interleaved() {
        const THREADS: usize = 8;
        const RECORDS: usize = 16;

        let recorder = Recorder::splitting();
        let keylog = KeyLogFile::with_writer(recorder.sink());
        let random = golden_client_random();

        let mut workers = Vec::with_capacity(THREADS);
        for index in 0..THREADS {
            let keylog = Arc::clone(&keylog);
            let random = random.clone();
            workers.push(thread::spawn(move || {
                let filler = u8::try_from(index).unwrap_or(0);
                let secret = vec![filler; SECRET_MAXLEN];
                (0..RECORDS).all(|_| {
                    keylog.write_secret(
                        "CLIENT_TRAFFIC_SECRET_0",
                        &random,
                        &secret,
                    )
                })
            }));
        }

        for worker in workers {
            let outcome = worker.join();
            assert!(
                matches!(outcome, Ok(true)),
                "every worker must write every record"
            );
        }
        keylog.close();

        let expected: Vec<String> = (0..THREADS)
            .map(|index| {
                let filler = u8::try_from(index).unwrap_or(0);
                format!(
                    "CLIENT_TRAFFIC_SECRET_0 {} {}",
                    hex(&random),
                    hex(&[filler; SECRET_MAXLEN]),
                )
            })
            .collect();

        let text = recorder.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), THREADS * RECORDS, "one line per record");
        for line in &lines {
            assert!(
                expected.iter().any(|record| record == line),
                "a spliced or truncated line reached the log: {line}"
            );
        }
        for record in &expected {
            assert_eq!(
                lines.iter().filter(|line| *line == record).count(),
                RECORDS,
                "every record must survive exactly once per write"
            );
        }

        let record_len = expected.first().map_or(0, |record| record.len() + 1);
        assert!(
            recorder
                .writes()
                .iter()
                .all(|written| *written == record_len),
            "each write must carry exactly one whole record"
        );
    }

    /// The bound [`rustls::KeyLog`] imposes, checked at compile time.
    #[test]
    fn the_log_can_be_shared_across_threads() {
        fn assert_shareable<T: Send + Sync + 'static>() {}
        assert_shareable::<KeyLogFile>();
        assert_shareable::<Arc<KeyLogFile>>();
    }

    // -- the rustls adapter ------------------------------------------------

    /// `will_log` answers for the log's state and for the label's length, the
    /// two things that would make [`KeyLogFile::write_secret`] reject on the
    /// label's account.
    #[test]
    fn will_log_respects_the_state_and_the_label_limit() {
        let disabled = KeyLogFile::disabled();
        assert!(!disabled.will_log("CLIENT_RANDOM"));
        assert!(!disabled.will_log(LONGEST_LABEL));

        let (enabled, _recorder) = recording_log();
        assert!(enabled.will_log("CLIENT_RANDOM"));
        assert!(enabled.will_log(LONGEST_LABEL));
        assert!(enabled.will_log(""));
        assert!(!enabled.will_log(&"A".repeat(KEYLOG_LABEL_MAXLEN + 1)));

        enabled.close();
        assert!(!enabled.will_log("CLIENT_RANDOM"));
    }

    /// A secret logged through the trait produces the same bytes as one
    /// written directly, and [`KeyLogFile::into_key_log`] yields the
    /// `Arc<dyn KeyLog>` that `ClientConfig::key_log` wants.
    #[test]
    fn logging_through_the_rustls_trait_writes_the_record() {
        let recorder = Recorder::new();
        let keylog: Arc<dyn RustlsKeyLog> =
            KeyLogFile::with_writer(recorder.sink()).into_key_log();

        assert!(keylog.will_log("CLIENT_RANDOM"));
        keylog.log("CLIENT_RANDOM", &golden_client_random(), &golden_secret());

        assert_eq!(recorder.text(), GOLDEN_RECORD);
    }

    /// The trait implementation rejects exactly what the writer rejects, and
    /// swallows the answer as `cr_keylog_log_cb` does
    /// (`lib/vtls/rustls.c:514`).
    #[test]
    fn the_rustls_trait_rejects_what_the_writer_rejects() {
        let recorder = Recorder::new();
        let keylog = KeyLogFile::with_writer(recorder.sink());
        let logger: &dyn RustlsKeyLog = keylog.as_ref();
        let random = golden_client_random();
        let secret = golden_secret();

        logger.log(&"A".repeat(KEYLOG_LABEL_MAXLEN + 1), &random, &secret);
        logger.log("CLIENT_RANDOM", &random[..CLIENT_RANDOM_SIZE - 1], &secret);
        logger.log("CLIENT_RANDOM", &random, &[]);
        logger.log("CLIENT_RANDOM", &random, &[0u8; SECRET_MAXLEN + 1]);
        assert!(recorder.bytes().is_empty(), "nothing may be written");

        // That same call succeeds once the arguments are valid, which
        // proves the rejections above were about the arguments.
        logger.log("CLIENT_RANDOM", &random, &secret);
        assert_eq!(recorder.text(), GOLDEN_RECORD);
    }

    /// A closed log is a silent one, even when rustls still holds it: the
    /// state a backend leaves behind when
    /// `rustls_client_config_builder_set_key_log` fails
    /// (`lib/vtls/rustls.c:823-826`) and when `cr_cleanup` runs
    /// (`rustls.c:1392-1395`).
    #[test]
    fn a_closed_log_is_silent_through_the_trait() {
        let recorder = Recorder::new();
        let keylog = KeyLogFile::with_writer(recorder.sink());
        let logger = Arc::clone(&keylog).into_key_log();

        keylog.close();
        assert!(!logger.will_log("CLIENT_RANDOM"));
        logger.log("CLIENT_RANDOM", &golden_client_random(), &golden_secret());
        assert!(recorder.bytes().is_empty());
    }

    /// Uppercase hex for a byte string, for readable expectations. Not the
    /// production path -- [`hexbyte`] is.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02X}")).collect()
    }
}
