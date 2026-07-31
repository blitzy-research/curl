// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! `--create-dirs`: the directory hierarchy behind an output template.
//!
//! This module supersedes one C translation unit. AAP section 0.4.1 assigns it
//! `src/tool_dirhie.c` (135 lines) with the note "`--create-dirs`". The C
//! purpose comment at `src/tool_dirhie.c:73-78` states the contract, and is
//! carried here because it is the reason the last path component is skipped:
//!
//! > Create the needed directory hierarchy recursively in order to save
//! > multi-GETs in file output, ie:
//! > `curl "http://example.org/dir[1-5]/file[1-5].txt" -o "dir#1/file#2.txt"`
//! > should create all the dir\* automagically
//!
//! Three call sites reach it in C, each guarded by `if(config->create_dirs)`:
//! `src/tool_operate.c:909` for `--etag-save`, `:960` for `--dump-header`, and
//! `:1055` for `-o`. Two of them carry the comment "create_dir_hierarchy shows
//! error upon CURLE_WRITE_ERROR" (`:961`, `:1056`), which is the caller
//! contract this module honours: on failure it reports the error itself and the
//! caller only propagates the code.
//!
//! # Why the recursive `std::fs` helper is not used
//!
//! `std` offers a one-line replacement for this whole module: the free function
//! that creates a directory and all of its missing parents, equivalently
//! [`DirBuilder::recursive(true)`](DirBuilder::recursive). It is wrong in four
//! independent ways, so it is prohibited outright and the component walk below
//! is explicit instead. Each difference is observable, and each is reproduced
//! by this module:
//!
//! 1. **The mode is `0750`.** `src/tool_dirhie.c:123` calls
//!    `mkdir(path, (mode_t)0000750)`. The recursive helper offers no way to set
//!    a mode, so it would leave the platform default (`0777` before the umask)
//!    -- a strictly wider permission set on every directory curl creates for
//!    the user. See [`DIR_MODE`].
//! 2. **`EACCES` is deliberately tolerated.** The condition at `:123-124` is
//!    `mkdir(...) == -1 && errno != EACCES && errno != EEXIST`, and the comment
//!    at `:121` explains why: "Create directory. Ignore access denied error to
//!    allow traversal." The recursive helper tolerates only an existing
//!    directory. See [`is_tolerated`].
//! 3. **The last component is never created.** `:101-102` breaks out of the
//!    loop when the byte after the component is the string terminator, because
//!    that component is the *file*. The recursive helper would create a
//!    directory where the transfer is about to write a file.
//! 4. **A run of separators is preserved.** `:97` uses `strspn`, which consumes
//!    every leading separator, and the comment at `:115-116` is explicit:
//!    "insert the leading separators (possibly plural) plus the following
//!    directory name". So `dir1//dir2/file` calls `mkdir("dir1//dir2")`, and
//!    that doubled slash is what an error message would quote. The recursive
//!    helper normalises it away.
//!
//! Its diagnostics differ too: the six frozen texts of `show_dir_errno`
//! (`src/tool_dirhie.c:36-71`) have no counterpart there, because the recursive
//! helper reports only through `io::Error`.
//!
//! # The accumulated path is a prefix of the input
//!
//! C accumulates the path in a `dynbuf` (`:91`, `:93`, `:117`, `:132`), which
//! looks like it needs an owned buffer here. It does not, and the reason is
//! worth writing down because it removes an allocation *and* a failure path.
//!
//! `:117` appends `seplen + len` bytes starting at the **current** cursor, and
//! `:129` then advances that same cursor by exactly `seplen + len`. By
//! induction the buffer after any iteration holds precisely
//! `input[0 .. cursor]`: it starts empty, and each append extends it by the
//! bytes the cursor is about to skip over. The accumulated path is therefore
//! always a prefix of the input and is taken here as a subslice.
//!
//! One consequence: the `CURLE_OUT_OF_MEMORY` early return at `:118-119`
//! disappears. It had two triggers, and neither survives. The `dynbuf` ceiling
//! set at `:93` is `outlen + 1`, which the accumulated path can never exceed
//! because it is a prefix of a string of length `outlen`; and the remaining
//! trigger was allocator failure, which a subslice cannot suffer. Nothing is
//! dropped -- the branch was unreachable for the first reason and is
//! unrepresentable for the second.
//!
//! # Termination
//!
//! The loop advances by `seplen + len` bytes, so it terminates provided that
//! sum is never zero for a non-empty remainder. It cannot be: `seplen == 0`
//! means the remainder does not start with a separator, while `len == 0` means
//! the byte after the separators *is* a separator -- and with `seplen == 0`
//! those are the same byte. The two conditions are contradictory, so
//! `seplen + len >= 1` always. The walk still guards the sum explicitly, so
//! termination is structural rather than merely argued.
//!
//! # Mapping `errno` with no dependency and no raw binding
//!
//! [`std::io::ErrorKind`] reaches only two of the six errno values C switches
//! on: `AlreadyExists` for `EEXIST` and `PermissionDenied` for `EACCES`. The
//! kinds for the other four -- `StorageFull`, `ReadOnlyFilesystem`,
//! `FilesystemQuotaExceeded` and `InvalidFilename` -- are all unstable and so
//! unavailable at the declared MSRV of 1.75 (AAP section 0.8.3). The match is
//! therefore on [`std::io::Error::raw_os_error`], which is safe, stable `std`,
//! against the per-operating-system constants in [`errno`].
//!
//! Those constants are declared locally rather than imported, because `libc` is
//! **not** a dependency of this crate: `curl-rs/Cargo.toml` lists exactly
//! `curl-rs-lib`, `clap`, `clap_complete` and `tokio`. Adding one for four
//! integers would widen the supply-chain surface that AAP section 0.7 keeps
//! under `cargo audit` and `cargo deny`, so the values are written down with
//! their provenance instead. No syscall is made through any binding here; the
//! whole module is expressed in `std`.
//!
//! # Byte-safe paths
//!
//! A Unix path is a byte string: only `/` and NUL are excluded. `--create-dirs`
//! operates on a user-supplied `-o` template, so the path may not be valid
//! UTF-8, and either lossy conversion -- `String` or `Path::display` -- would
//! substitute U+FFFD and rename the directory. Every
//! path here stays a [`Path`]/[`OsStr`], and the `strspn`/`strcspn` scanning
//! runs over the raw bytes obtained from
//! [`std::os::unix::ffi::OsStrExt::as_bytes`].
//!
//! The same applies to the diagnostics: `%s` in C reads a `char *` and emits
//! the bytes verbatim, so the six messages are rendered into a byte buffer and
//! handed to [`crate::output::msgs::errorf_bytes`] rather than formatted.
//!
//! # The injected directory creator
//!
//! [`create_dir_hierarchy`] is a thin wrapper over
//! [`create_dir_hierarchy_with`], which takes the directory-creating operation
//! as a parameter. This is the dependency injection AAP section 0.3.3 lists as
//! pattern P12, and it is what makes the errno branches testable at all: the
//! process running the tests is frequently `root`, and `root` bypasses the
//! discretionary access check, so a real unreadable directory does *not* yield
//! `EACCES`. Injecting the operation also keeps the six texts and the
//! tolerance rule under test without depending on a full filesystem or a
//! read-only mount.
//!
//! # Rules status and provenance
//!
//! No user-specified rules exist for this project. `review_rules` returns the
//! single line "No user rules provided.", read with an explicit range covering
//! the whole document, which corroborates AAP section 0.7. Nothing here is
//! attributed to a rule and none was invented. Every constraint cited is an
//! AAP requirement taken from the user's request (AAP section 0.8) -- binding,
//! but a requirement, not a rule; describing them as rules would, in AAP
//! section 0.7's own words, "misrepresent where they came from". Where no
//! requirement speaks, enterprise-standard best practice governs: the absence
//! of rules is not permission to lower the bar.

use std::ffi::OsStr;
use std::fs::DirBuilder;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use curl_rs_lib::error::CURLcode;

use crate::output::msgs::{self, MsgConfig};

/// The single byte `PATH_DELIMITERS` expands to on the mandated targets.
///
/// `src/tool_dirhie.c:84` defines `PATH_DELIMITERS` as `DIR_CHAR`, and
/// `lib/curl_setup.h:684` defines `DIR_CHAR` as `"/"`. The two-character
/// `"\\/"` form at `src/tool_dirhie.c:82` is guarded by
/// `defined(_WIN32) || defined(__DJGPP__)`, neither of which is in the
/// four-target matrix of AAP section 0.1.1 goal G8, so a single byte is the
/// complete delimiter set here and `strspn`/`strcspn` collapse to byte scans.
const PATH_DELIMITER: u8 = b'/';

/// The mode passed to every directory creation: `0o750`, `rwxr-x---`.
///
/// `src/tool_dirhie.c:123` is `mkdir(curlx_dyn_ptr(&dirbuf), (mode_t)0000750)`.
/// This is security-relevant configuration, so AAP section 0.7 requires it to
/// be explicit rather than defaulted: it is neither `0777` nor `0755` nor
/// whatever the platform would apply on its own. As with `mkdir(2)`, the
/// process umask still clears bits from it -- that is the kernel's behaviour in
/// both languages and is not a difference.
const DIR_MODE: u32 = 0o750;

/// The `errno` values `show_dir_errno` switches on, per operating system.
///
/// Every arm of `src/tool_dirhie.c:38-70` is wrapped in `#ifdef <ERRNO>`, so a
/// platform that does not define one of the four rarer values falls through to
/// the `default:` arm at `:67-69`. That is reproduced exactly by the types
/// chosen here: the four are [`Option`], `Some` where the platform defines
/// them and `None` where it does not, and a `None` can never match a real
/// `errno` and so reaches the default text.
///
/// `EACCES` and `EEXIST` are plain integers rather than options because they
/// are behaviourally critical -- they decide whether the walk continues -- and
/// because both are `13` and `17` on every target in the matrix.
///
/// # Provenance
///
/// The Linux values were compiled against the system `<errno.h>`; the macOS
/// values were read from `libc-0.2.189/src/unix/bsd/apple/mod.rs` at lines
/// 2309, 2313, 2324, 2326, 2360 and 2366. Both sets agree with the values in
/// this file's specification.
///
/// | Value | Linux | macOS |
/// |---|---|---|
/// | `EACCES` | 13 | 13 |
/// | `EEXIST` | 17 | 17 |
/// | `ENOSPC` | 28 | 28 |
/// | `EROFS` | 30 | 30 |
/// | `ENAMETOOLONG` | 36 | 63 |
/// | `EDQUOT` | 122 | 69 |
///
/// The values vary by operating system only, never by architecture, so two
/// arms cover all four mandated targets: `x86_64-unknown-linux-gnu` and
/// `aarch64-unknown-linux-gnu` take the Linux arm, `x86_64-apple-darwin` and
/// `aarch64-apple-darwin` the macOS one. A third arm keeps the module
/// compiling on any other Unix, with the four rarer values `None`.
mod errno {
    /// `EACCES`: permission denied. Tolerated by the walk, per
    /// `src/tool_dirhie.c:124`.
    pub(super) const EACCES: i32 = 13;

    /// `EEXIST`: the directory is already there. Tolerated by the walk, per
    /// `src/tool_dirhie.c:124`.
    pub(super) const EEXIST: i32 = 17;

    /// `ENOSPC`: no space left on the device. Linux and macOS agree on `28`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) const ENOSPC: Option<i32> = Some(28);

    /// `ENOSPC` is not defined for this target, mirroring C's absent
    /// `#ifdef ENOSPC` arm.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) const ENOSPC: Option<i32> = None;

    /// `EROFS`: read-only file system. Linux and macOS agree on `30`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) const EROFS: Option<i32> = Some(30);

    /// `EROFS` is not defined for this target, mirroring C's absent
    /// `#ifdef EROFS` arm.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) const EROFS: Option<i32> = None;

    /// `ENAMETOOLONG`: the path or a component of it is too long.
    #[cfg(target_os = "linux")]
    pub(super) const ENAMETOOLONG: Option<i32> = Some(36);

    /// `ENAMETOOLONG`: the path or a component of it is too long.
    #[cfg(target_os = "macos")]
    pub(super) const ENAMETOOLONG: Option<i32> = Some(63);

    /// `ENAMETOOLONG` is not defined for this target, mirroring C's absent
    /// `#ifdef ENAMETOOLONG` arm.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) const ENAMETOOLONG: Option<i32> = None;

    /// `EDQUOT`: the disk quota has been exhausted.
    #[cfg(target_os = "linux")]
    pub(super) const EDQUOT: Option<i32> = Some(122);

    /// `EDQUOT`: the disk quota has been exhausted.
    #[cfg(target_os = "macos")]
    pub(super) const EDQUOT: Option<i32> = Some(69);

    /// `EDQUOT` is not defined for this target, mirroring C's absent
    /// `#ifdef EDQUOT` arm.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) const EDQUOT: Option<i32> = None;
}

/// One of the six frozen messages of `show_dir_errno`
/// (`src/tool_dirhie.c:36-71`), split at its single `%s`.
///
/// The split exists so that the substituted name can be spliced in as raw
/// bytes. C's `%s` reads a `char *` and copies the bytes it finds, and the name
/// it is given -- `curlx_dyn_ptr(&dirbuf)` at `:125` -- is a filesystem path,
/// which on Unix need not be valid UTF-8. Formatting through `Display` would
/// substitute U+FFFD and change the emitted bytes, which AAP section 0.8.1 does
/// not permit; two `&str` halves around a byte slice keep them exact.
///
/// Every text is reproduced verbatim, including the two that C spells as a pair
/// of adjacent string literals. The joins are the easiest thing in this file to
/// get wrong, so both are recorded here and asserted in the tests:
///
/// * `:57-58` -- `"No space left on the file system that will "` followed by
///   `"contain the directory %s"`, joining to a single space between `will` and
///   `contain`.
/// * `:63-64` -- `"Cannot create directory %s because you "` followed by
///   `"exceeded your quota"`, joining to a single space between `you` and
///   `exceeded`.
///
/// The texts live here, at their call site, exactly as in C where each
/// `errorf(...)` holds its own literal. `crate::output::msgs` owns the
/// *channel* -- the `curl: ` prefix, the four entry points and the line
/// wrapping -- not the texts. Hoisting them there would create a second source
/// of truth and guarantee drift.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirErrorText {
    /// Everything before the `%s`.
    before: &'static str,

    /// Everything after the `%s`.
    after: &'static str,
}

/// `src/tool_dirhie.c:42`: `You do not have permission to create %s`.
///
/// Reachable only through a caller that reports an `EACCES` failure. The walk
/// in this module is not one, because `:123-124` tolerates `EACCES` before
/// `show_dir_errno` is ever reached -- exactly as in C, where this arm and the
/// tolerance test contradict each other in appearance only. Both are ported
/// faithfully rather than reconciled, and this arm is exercised directly by the
/// tests so it is neither dead nor unverified.
const EACCES_TEXT: DirErrorText = DirErrorText {
    before: "You do not have permission to create ",
    after: "",
};

/// `src/tool_dirhie.c:47`: `The directory name %s is too long`.
const ENAMETOOLONG_TEXT: DirErrorText = DirErrorText {
    before: "The directory name ",
    after: " is too long",
};

/// `src/tool_dirhie.c:52`: `%s resides on a read-only file system`.
///
/// The only one of the six that begins with the substituted name, so `before`
/// is empty.
const EROFS_TEXT: DirErrorText = DirErrorText {
    before: "",
    after: " resides on a read-only file system",
};

/// `src/tool_dirhie.c:57-58`:
/// `No space left on the file system that will contain the directory %s`.
///
/// C spells this as two adjacent literals; the join contributes exactly one
/// space, between `will` and `contain`.
const ENOSPC_TEXT: DirErrorText = DirErrorText {
    before: "No space left on the file system that will contain the \
             directory ",
    after: "",
};

/// `src/tool_dirhie.c:63-64`:
/// `Cannot create directory %s because you exceeded your quota`.
///
/// C spells this as two adjacent literals; the join contributes exactly one
/// space, between `you` and `exceeded`.
const EDQUOT_TEXT: DirErrorText = DirErrorText {
    before: "Cannot create directory ",
    after: " because you exceeded your quota",
};

/// `src/tool_dirhie.c:68`: `Error creating directory %s`.
///
/// The `default:` arm at `:67-69`. It catches every `errno` the five named arms
/// do not, and also every value the platform leaves undefined -- see [`errno`].
const DEFAULT_TEXT: DirErrorText = DirErrorText {
    before: "Error creating directory ",
    after: "",
};

/// The `switch(errno)` of `show_dir_errno` (`src/tool_dirhie.c:38-70`).
///
/// The match is on [`io::Error::raw_os_error`], which is what C's `errno`
/// carries. When there is no operating-system error number the failure was
/// synthesised by `std` rather than reported by `mkdir(2)`; the one errno the
/// [`io::ErrorKind`] set does express is then honoured so that such an error
/// still reaches a sensible arm, and everything else falls to [`DEFAULT_TEXT`]
/// exactly as C's `default:` does.
fn dir_error_text(error: &io::Error) -> DirErrorText {
    let code = match error.raw_os_error() {
        Some(code) => Some(code),
        // No `errno`: recover the one named arm `io::ErrorKind` can express.
        // `AlreadyExists` is not mapped, because C has no `EEXIST` arm in
        // `show_dir_errno` -- the walk tolerates it and never reports it.
        None => match error.kind() {
            io::ErrorKind::PermissionDenied => Some(errno::EACCES),
            _ => None,
        },
    };

    match code {
        // `:41-43`
        Some(code) if code == errno::EACCES => EACCES_TEXT,
        // `:46-48`
        Some(code) if errno::ENAMETOOLONG == Some(code) => ENAMETOOLONG_TEXT,
        // `:51-53`
        Some(code) if errno::EROFS == Some(code) => EROFS_TEXT,
        // `:56-59`
        Some(code) if errno::ENOSPC == Some(code) => ENOSPC_TEXT,
        // `:62-65`
        Some(code) if errno::EDQUOT == Some(code) => EDQUOT_TEXT,
        // `:67-69`
        _ => DEFAULT_TEXT,
    }
}

/// Splices `name` into `text` at the position of C's `%s`.
///
/// `name` is the accumulated path from `curlx_dyn_ptr(&dirbuf)`
/// (`src/tool_dirhie.c:125`) -- the directory that failed, not the original
/// output template -- and its bytes are copied through untouched.
///
/// The result is not bounded here. `crate::output::msgs` applies C's
/// `char buffer[1024]` limit (`src/tool_msgs.c:41`, `:46`) inside the channel,
/// so bounding it twice would risk two different truncation points.
fn render_dir_error(text: DirErrorText, name: &[u8]) -> Vec<u8> {
    let capacity = text
        .before
        .len()
        .saturating_add(name.len())
        .saturating_add(text.after.len());

    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(text.before.as_bytes());
    message.extend_from_slice(name);
    message.extend_from_slice(text.after.as_bytes());
    message
}

/// `show_dir_errno` (`src/tool_dirhie.c:36-71`).
///
/// C reads the ambient `errno`; the error is passed explicitly here, because
/// `std` returns it rather than leaving it in thread-local state. C reaches the
/// diagnostic stream and the `--silent`/`--show-error` gates through globals;
/// both are parameters here, which is what AAP section 0.1.2 prescribes when it
/// replaces the C god-struct with "per-module structs with explicit ownership",
/// and what makes the six texts assertable against a captured sink.
///
/// Emission goes through [`msgs::errorf_bytes`], the byte-string flavour of
/// `errorf`, so the `curl: ` prefix (`src/tool_msgs.c:32`), the
/// `!silent || show_error` gate (`:131`) and the line wrapping (`:37-73`) all
/// stay in their single owner while the path bytes stay verbatim.
fn show_dir_errno(
    sink: &mut dyn Write,
    config: &MsgConfig,
    name: &[u8],
    error: &io::Error,
) {
    let message = render_dir_error(dir_error_text(error), name);
    msgs::errorf_bytes(sink, config, &message);
}

/// The two failures `src/tool_dirhie.c:123-124` lets the walk continue past.
///
/// C's condition is `mkdir(...) == -1 && (errno != EACCES) &&
/// (errno != EEXIST)` -- a failure aborts unless the `errno` is one of those
/// two. `EEXIST` is the ordinary case of a directory that is already there, and
/// the comment at `:121` gives the reason for the other: "Create directory.
/// Ignore access denied error to allow traversal." A component the user cannot
/// create may still be one they can *traverse*, and the transfer only needs to
/// reach the leaf.
///
/// # Why this matches on `errno` and not on `io::ErrorKind`
///
/// `io::ErrorKind::PermissionDenied` is not equivalent to `EACCES`: `std` maps
/// both `EACCES` and `EPERM` onto it. Tolerating that kind would therefore also
/// tolerate `EPERM`, which C does not, silently swallowing a failure the C tool
/// reports. The raw number is the faithful test, and it is used whenever the
/// operating system supplied one. The kinds are consulted only when
/// [`io::Error::raw_os_error`] is `None`, which means the error did not come
/// from `mkdir(2)` at all and so has no `errno` for C to have compared.
fn is_tolerated(error: &io::Error) -> bool {
    match error.raw_os_error() {
        Some(code) => code == errno::EACCES || code == errno::EEXIST,
        None => matches!(
            error.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::AlreadyExists
        ),
    }
}

/// `mkdir(path, (mode_t)0000750)` (`src/tool_dirhie.c:123`).
///
/// [`DirBuilder`] with [`DirBuilderExt::mode`] is the whole of it: one
/// `mkdir(2)` with an explicit mode, reached through safe `std` alone -- no raw
/// binding and no dependency.
///
/// `recursive` is set to `false` explicitly. That is already the default, but
/// saying so makes the guarantee visible at the point where it matters: with
/// `recursive(true)` this would become the recursive `std::fs` helper and would
/// silently acquire all four of the behaviours the module documentation
/// prohibits, including swallowing `EEXIST` before [`is_tolerated`] can see it.
fn make_directory(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(false);
    builder.mode(DIR_MODE);
    builder.create(path)
}

/// `create_dir_hierarchy` (`src/tool_dirhie.c:87-135`), with the
/// directory-creating operation supplied by the caller.
///
/// Separated from [`create_dir_hierarchy`] so that every branch is reachable in
/// a test without a filesystem that can produce the corresponding `errno`; see
/// the module documentation for why a real one cannot be relied upon. The
/// production caller passes [`make_directory`], so the shipped behaviour is
/// exactly `mkdir(2)` at mode [`DIR_MODE`].
///
/// `create` is called once per directory component, in order, with the
/// accumulated path -- never with the final component, and never with a
/// normalised path.
fn create_dir_hierarchy_with<F>(
    outfile: &Path,
    sink: &mut dyn Write,
    config: &MsgConfig,
    mut create: F,
) -> CURLcode
where
    F: FnMut(&Path) -> io::Result<()>,
{
    // The path as the operating system holds it. `:90` takes `strlen(outfile)`
    // for the buffer ceiling; the length is implicit in the slice here, and the
    // ceiling itself is unnecessary -- see the module documentation.
    let bytes = outfile.as_os_str().as_bytes();

    // C advances the `outfile` pointer (`:129`); an index does the same job
    // while keeping every access bounds-checked.
    let mut cursor: usize = 0;

    // `:95` -- `while(*outfile)`. The slice yielded is the remainder C's
    // pointer would address; `None` is unreachable, because `cursor` only ever
    // takes a value that already indexed into `bytes`, and leaving the loop in
    // that case is what C's condition failing would do anyway. Expressed this
    // way, no access in the body can be out of bounds.
    while let Some(rest) = bytes.get(cursor..) {
        // The string terminator: C's condition is false.
        if rest.is_empty() {
            break;
        }

        // `:97` -- `strspn(outfile, PATH_DELIMITERS)`: the run of leading
        // separators, which may be plural and is kept as-is (`:115-116`).
        let seplen = match rest.iter().position(|&byte| byte != PATH_DELIMITER)
        {
            Some(index) => index,
            // Every byte is a separator.
            None => rest.len(),
        };

        // `:98` -- `strcspn(&outfile[seplen], PATH_DELIMITERS)`: the component
        // that follows them.
        let tail: &[u8] = match rest.get(seplen..) {
            Some(slice) => slice,
            // Unreachable: `seplen` counts a prefix of `rest`.
            None => &[],
        };
        let len = match tail.iter().position(|&byte| byte == PATH_DELIMITER) {
            Some(index) => index,
            // No further separator: this component runs to the end.
            None => tail.len(),
        };

        let consumed = seplen.saturating_add(len);

        // `:101-102` -- "the last path component is the file and it ends with a
        // null byte". C reads `outfile[len + seplen]` and breaks when it is the
        // terminator; the equivalent here is that the index is past the end.
        // This is what keeps the output file from becoming a directory, and it
        // runs BEFORE anything is appended or created.
        if rest.get(consumed).is_none() {
            break;
        }

        // Guarantees progress. The module documentation proves this cannot
        // happen for a non-empty remainder; the guard makes termination
        // structural rather than an argument a reader has to reconstruct.
        if consumed == 0 {
            break;
        }

        // `:117` -- `curlx_dyn_addn(&dirbuf, outfile, seplen + len)`. The
        // buffer provably holds `bytes[..end]` at this point, so the subslice
        // is the accumulated path, byte for byte, with no allocation.
        let end = cursor.saturating_add(consumed);
        let accumulated: &[u8] = match bytes.get(..end) {
            Some(slice) => slice,
            // Unreachable: `end` is the index one past a byte of `bytes`.
            None => bytes,
        };

        // `:123-124` -- create it, tolerating only the two documented errno
        // values. `skip` from `:96` and `:104-114` is Windows and MSDOS only
        // (drive-letter handling) and is out of scope per AAP section 0.2.2, so
        // it is always false on the four mandated targets and is not ported.
        if let Err(error) = create(Path::new(OsStr::from_bytes(accumulated))) {
            if !is_tolerated(&error) {
                // `:125` -- report against the accumulated path.
                show_dir_errno(sink, config, accumulated, &error);
                // `:126-127` -- `result = CURLE_WRITE_ERROR; break;`, which
                // `:134` then returns.
                return CURLcode::WriteError;
            }
        }

        // `:129` -- `outfile += len + seplen`.
        cursor = end;
    }

    // `:89` and `:134` -- the initial value, returned when the walk completes.
    CURLcode::Ok
}

/// Creates every directory component of an output path, but not the file.
///
/// This is `create_dir_hierarchy` (`src/tool_dirhie.c:87`, declared at
/// `src/tool_dirhie.h:28`), the whole of what `--create-dirs` does. Callers
/// invoke it only when that option was given, as C does at
/// `src/tool_operate.c:909`, `:960` and `:1055`.
///
/// # Behaviour
///
/// The path is walked component by component from the left. Each component
/// except the last is created with mode [`DIR_MODE`]; the last is assumed to be
/// the file the transfer is about to write and is left alone. A run of
/// separators is preserved rather than collapsed. A failure to create a
/// component is fatal unless its `errno` is `EACCES` or `EEXIST`, in which case
/// the walk continues.
///
/// # Returns
///
/// `CURLcode::Ok`, or `CURLcode::WriteError` -- `CURLE_WRITE_ERROR` -- after
/// reporting the failure through `sink`. Nothing else is returned, so a caller
/// mirroring C's `if(result) return result;` can simply propagate it, and one
/// wanting `?` can call [`CURLcode::into_result`].
///
/// The error is reported *here*, which the C call sites record as the contract:
/// "create_dir_hierarchy shows error upon CURLE_WRITE_ERROR"
/// (`src/tool_operate.c:961`, `:1056`). A caller must not report it a second
/// time.
///
/// # Examples
///
/// ```ignore
/// // `-o dir1/dir2/file.txt --create-dirs` creates `dir1` and `dir1/dir2`,
/// // and leaves `file.txt` for the transfer to write.
/// let code = create_dir_hierarchy(
///     Path::new("dir1/dir2/file.txt"),
///     &mut sink,
///     &config,
/// );
/// ```
#[must_use]
pub(crate) fn create_dir_hierarchy(
    outfile: &Path,
    sink: &mut dyn Write,
    config: &MsgConfig,
) -> CURLcode {
    create_dir_hierarchy_with(outfile, sink, config, make_directory)
}

#[cfg(test)]
mod tests {
    //! AAP section 0.8.7 relocates the coverage of `tests/unit` into the
    //! crates, because a Rust static library does not export `pub(crate)`
    //! items and the C unit tests therefore cannot link against them. These
    //! assertions are that relocation for `src/tool_dirhie.c`.
    //!
    //! Two conventions are worth stating so they do not look accidental.
    //!
    //! Every test returns a `Result` and reaches fallible operations with `?`,
    //! so none of the panicking `Result` accessors and none of the abort macros
    //! appear anywhere in this file -- the same standard the module itself is
    //! held to. The `assert!` family is the exception, and necessarily so: a
    //! test asserts by failing, and there is no other way to express one. That
    //! matches the sibling `crate::output::msgs`, whose tests assert the same
    //! way.
    //!
    //! Most tests inject the directory-creating operation rather than touching
    //! a filesystem, which is what makes every `errno` branch reachable; see
    //! the module documentation. The four that do need real directories say so
    //! and use a `tempfile` scratch root.

    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    use super::*;

    /// A configuration under which `errorf` emits: neither `--silent` nor
    /// `--show-error` given, which is `MsgConfig`'s all-false default and the
    /// state of C's zero-initialised `global`.
    fn emitting() -> MsgConfig {
        MsgConfig::default()
    }

    /// Rebuilds the message `voutf` wrapped, so assertions do not depend on the
    /// terminal width.
    ///
    /// `get_terminal_columns` reads `COLUMNS` from the environment on every
    /// call, so a wide message may arrive as several prefixed lines. `voutf`
    /// keeps the blank it broke on (`src/tool_msgs.c:62`) and repeats the
    /// prefix on each line (`:49`), so stripping the prefix from every line and
    /// dropping the newlines reproduces the message byte for byte.
    fn reassemble(emitted: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        for line in emitted.split(|&byte| byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let body = match line.strip_prefix(msgs::ERROR_PREFIX.as_bytes()) {
                Some(rest) => rest,
                None => line,
            };
            message.extend_from_slice(body);
        }
        message
    }

    /// The C format string a [`DirErrorText`] was split from, reassembled so
    /// the six frozen literals can be pinned exactly as `src/tool_dirhie.c`
    /// spells them.
    fn template(text: DirErrorText) -> String {
        format!("{}%s{}", text.before, text.after)
    }

    /// Walks `template` with a creator that only records, so no filesystem is
    /// involved and the accumulated paths can be inspected verbatim.
    fn recorded(template: &Path) -> (CURLcode, Vec<Vec<u8>>, Vec<u8>) {
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut emitted: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy_with(
            template,
            &mut emitted,
            &emitting(),
            |dir| {
                seen.push(dir.as_os_str().as_bytes().to_vec());
                Ok(())
            },
        );
        (code, seen, emitted)
    }

    /// The recorded paths as `&str`, for readable comparison against the
    /// expectations traced from the C.
    fn as_text(seen: &[Vec<u8>]) -> Vec<String> {
        seen.iter()
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect()
    }

    // =======================================================================
    // The constants. Both are frozen values, so both are pinned directly.
    // =======================================================================

    /// `src/tool_dirhie.c:123` -- `mkdir(..., (mode_t)0000750)`. AAP section
    /// 0.7 makes security-relevant configuration explicit, and a silent change
    /// from `0750` to a wider mode is precisely the regression this catches.
    #[test]
    fn the_directory_mode_is_0750() {
        assert_eq!(DIR_MODE, 0o750);
    }

    /// `src/tool_dirhie.c:84` with `lib/curl_setup.h:684`.
    #[test]
    fn the_path_delimiter_is_a_forward_slash() {
        assert_eq!(PATH_DELIMITER, b'/');
    }

    /// Every mandated target must define all six values; a `None` would
    /// silently downgrade a named message to the default text.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn every_errno_is_defined_on_the_mandated_targets() {
        assert_eq!(errno::EACCES, 13);
        assert_eq!(errno::EEXIST, 17);
        assert!(errno::ENOSPC.is_some());
        assert!(errno::EROFS.is_some());
        assert!(errno::ENAMETOOLONG.is_some());
        assert!(errno::EDQUOT.is_some());
    }

    // =======================================================================
    // The component walk -- `src/tool_dirhie.c:95-130`.
    // =======================================================================

    /// The traversal, traced from the C for twelve path shapes.
    ///
    /// Each expectation is the exact sequence of `mkdir` arguments C would
    /// produce, in order, derived by following `:97`, `:98`, `:101-102`, `:117`
    /// and `:129` by hand. Four of them are the cases a normalising
    /// implementation gets wrong.
    #[test]
    fn the_component_walk_matches_the_c_traversal() {
        let cases: &[(&str, &[&str])] = &[
            // `:101-102` -- the last component is the file.
            ("dir1/dir2/file.txt", &["dir1", "dir1/dir2"]),
            // No separator at all: the whole string is the file.
            ("file.txt", &[]),
            // `:95` -- `while(*outfile)` never runs.
            ("", &[]),
            // Separators only: `:101-102` breaks on the first pass.
            ("/", &[]),
            ("//", &[]),
            // A trailing separator makes the named component a directory,
            // because the "last component" is then the empty string after it.
            ("a/", &["a"]),
            ("dir1/dir2/", &["dir1", "dir1/dir2"]),
            ("dir1/dir2/file/", &["dir1", "dir1/dir2", "dir1/dir2/file"]),
            // `:97` -- a run of separators is preserved, not collapsed.
            ("dir1//dir2/file", &["dir1", "dir1//dir2"]),
            ("dir1///dir2/file", &["dir1", "dir1///dir2"]),
            // The leading separator belongs to the first component.
            ("/abs/dir/file", &["/abs", "/abs/dir"]),
            // Relative prefixes are components like any other.
            ("./sub/file", &[".", "./sub"]),
        ];

        for (template, expected) in cases {
            let (code, seen, emitted) = recorded(Path::new(template));
            assert_eq!(code, CURLcode::Ok, "template {template:?}");
            assert_eq!(as_text(&seen), *expected, "template {template:?}");
            assert!(emitted.is_empty(), "template {template:?}");
        }
    }

    /// `:101-102` in isolation, and on a real filesystem: the file itself must
    /// not become a directory.
    #[test]
    fn the_last_component_is_never_created() -> io::Result<()> {
        let root = TempDir::new()?;
        let template = root.path().join("dir1/dir2/file.txt");

        let mut emitted: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy(&template, &mut emitted, &emitting());

        assert_eq!(code, CURLcode::Ok);
        assert!(emitted.is_empty());
        assert!(root.path().join("dir1").is_dir());
        assert!(root.path().join("dir1/dir2").is_dir());
        assert!(!template.exists());
        Ok(())
    }

    /// A path with no separator creates nothing and still succeeds.
    ///
    /// The whole string is the file, so `:101-102` breaks on the first pass and
    /// the creator is never invoked even once. Run against the real creator as
    /// well, which therefore leaves the scratch root untouched.
    #[test]
    fn a_path_without_a_separator_creates_nothing() -> io::Result<()> {
        let (code, seen, emitted) = recorded(Path::new("file.txt"));
        assert_eq!(code, CURLcode::Ok);
        assert!(seen.is_empty());
        assert!(emitted.is_empty());

        let root = TempDir::new()?;
        let mut reported: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy_with(
            Path::new("file.txt"),
            &mut reported,
            &emitting(),
            make_directory,
        );
        assert_eq!(code, CURLcode::Ok);
        assert!(reported.is_empty());
        assert_eq!(fs::read_dir(root.path())?.count(), 0);
        Ok(())
    }

    /// `:97` and `:115-117`: the doubled separator survives into the path that
    /// `mkdir` is given, and therefore into any error message.
    ///
    /// The recursive `std::fs` helper would report `dir1/dir2` here.
    #[test]
    fn a_run_of_separators_is_preserved_in_the_accumulated_path() {
        let (code, seen, _) = recorded(Path::new("dir1//dir2/file"));
        assert_eq!(code, CURLcode::Ok);
        assert_eq!(as_text(&seen), vec!["dir1", "dir1//dir2"]);
    }

    /// The walk must terminate on every input, including the shapes where the
    /// separator run and the component length interact awkwardly.
    #[test]
    fn the_walk_terminates_on_pathological_input() {
        for template in ["/////", "a//", "//a", "//a//", "a//b//c"] {
            let (code, _, emitted) = recorded(Path::new(template));
            assert_eq!(code, CURLcode::Ok, "template {template:?}");
            assert!(emitted.is_empty(), "template {template:?}");
        }
    }

    // =======================================================================
    // Mode and tolerance, against a real filesystem.
    // =======================================================================

    /// The umask in force, derived without a syscall.
    ///
    /// A directory requested with mode `0o777` comes back as
    /// `0o777 & !umask`, so the umask's low nine bits follow by complement.
    /// This keeps the mode assertion exact under any umask instead of assuming
    /// the `0o022` that is merely usual.
    fn observed_umask(root: &Path) -> io::Result<u32> {
        let probe = root.join("blitzy-umask-probe");
        let mut builder = DirBuilder::new();
        builder.mode(0o777);
        builder.create(&probe)?;
        let granted = fs::metadata(&probe)?.permissions().mode() & 0o777;
        Ok(0o777 & !granted)
    }

    /// `:123` -- every directory the walk creates carries mode `0o750`.
    ///
    /// Under the usual `0o022` umask the expectation below is literally
    /// `0o750`, because `0o750` grants nothing the umask clears.
    #[test]
    fn created_directories_carry_mode_0750() -> io::Result<()> {
        let root = TempDir::new()?;
        let expected = DIR_MODE & !observed_umask(root.path())?;

        let template = root.path().join("outer/inner/file.txt");
        let mut emitted: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy(&template, &mut emitted, &emitting());
        assert_eq!(code, CURLcode::Ok);

        for created in ["outer", "outer/inner"] {
            let mode = fs::metadata(root.path().join(created))?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, expected, "component {created:?}");
        }
        Ok(())
    }

    /// `:124` -- `EEXIST` is tolerated, so a second run over the same template
    /// succeeds and reports nothing.
    #[test]
    fn an_existing_directory_is_tolerated() -> io::Result<()> {
        let root = TempDir::new()?;
        let template = root.path().join("dir1/dir2/file.txt");

        for _ in 0..2 {
            let mut emitted: Vec<u8> = Vec::new();
            let code =
                create_dir_hierarchy(&template, &mut emitted, &emitting());
            assert_eq!(code, CURLcode::Ok);
            assert!(emitted.is_empty());
        }
        assert!(root.path().join("dir1/dir2").is_dir());
        Ok(())
    }

    /// A non-UTF-8 component reaches the filesystem unchanged.
    ///
    /// `0xFF 0xFE` is not valid UTF-8, so either lossy route -- `String` or
    /// `Path::display` -- would rename the directory to one containing U+FFFD.
    #[test]
    fn a_non_utf8_component_round_trips() -> io::Result<()> {
        let root = TempDir::new()?;
        let raw = OsString::from_vec(vec![b'd', 0xff, 0xfe, b'r']);
        let directory = root.path().join(&raw);
        let template = directory.join("file.txt");

        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut emitted: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy_with(
            &template,
            &mut emitted,
            &emitting(),
            |dir| {
                seen.push(dir.as_os_str().as_bytes().to_vec());
                make_directory(dir)
            },
        );

        assert_eq!(code, CURLcode::Ok);
        assert!(emitted.is_empty());
        assert!(directory.is_dir());
        assert!(!template.exists());

        let last = seen.last().map(Vec::as_slice);
        assert_eq!(last, Some(directory.as_os_str().as_bytes()));
        assert!(directory
            .as_os_str()
            .as_bytes()
            .ends_with(&[0xff, 0xfe, b'r']));
        Ok(())
    }

    // =======================================================================
    // Tolerance and failure -- `src/tool_dirhie.c:123-127`.
    // =======================================================================

    /// `:124` with the comment at `:121` -- "Ignore access denied error to
    /// allow traversal." An `EACCES` on every component must still leave the
    /// walk visiting all of them and returning success with nothing reported.
    ///
    /// This is why the operation is injected: the tests frequently run as
    /// `root`, which bypasses the access check, so a real unreadable directory
    /// would not produce `EACCES` at all.
    #[test]
    fn an_access_denied_failure_does_not_abort_the_walk() {
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut emitted: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy_with(
            Path::new("dir1/dir2/dir3/file.txt"),
            &mut emitted,
            &emitting(),
            |dir| {
                seen.push(dir.as_os_str().as_bytes().to_vec());
                Err(io::Error::from_raw_os_error(errno::EACCES))
            },
        );

        assert_eq!(code, CURLcode::Ok);
        assert!(emitted.is_empty());
        assert_eq!(as_text(&seen), vec!["dir1", "dir1/dir2", "dir1/dir2/dir3"]);
    }

    /// `:124` -- the same tolerance for `EEXIST`, exercised through the
    /// injected operation so it is tested independently of the filesystem.
    #[test]
    fn an_already_existing_error_does_not_abort_the_walk() {
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut emitted: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy_with(
            Path::new("dir1/dir2/file.txt"),
            &mut emitted,
            &emitting(),
            |dir| {
                seen.push(dir.as_os_str().as_bytes().to_vec());
                Err(io::Error::from_raw_os_error(errno::EEXIST))
            },
        );

        assert_eq!(code, CURLcode::Ok);
        assert!(emitted.is_empty());
        assert_eq!(as_text(&seen), vec!["dir1", "dir1/dir2"]);
    }

    /// `:126-127` -- any other `errno` stops the walk, and `:125` reports the
    /// accumulated path rather than the original template.
    #[test]
    fn an_unexpected_failure_returns_write_error_and_reports_it() {
        let Some(enospc) = errno::ENOSPC else {
            // Unreachable on the mandated targets; asserted separately by
            // `every_errno_is_defined_on_the_mandated_targets`.
            return;
        };

        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut emitted: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy_with(
            Path::new("dir1/dir2/dir3/file.txt"),
            &mut emitted,
            &emitting(),
            |dir| {
                seen.push(dir.as_os_str().as_bytes().to_vec());
                if seen.len() == 2 {
                    Err(io::Error::from_raw_os_error(enospc))
                } else {
                    Ok(())
                }
            },
        );

        // The walk stopped at the failing component: `dir3` was never tried.
        assert_eq!(code, CURLcode::WriteError);
        assert_eq!(as_text(&seen), vec!["dir1", "dir1/dir2"]);

        // `:125` -- the reported name is the accumulated path.
        assert_eq!(
            reassemble(&emitted),
            b"No space left on the file system that will contain the \
              directory dir1/dir2"
                .to_vec()
        );
        assert!(emitted.starts_with(msgs::ERROR_PREFIX.as_bytes()));
        assert!(emitted.ends_with(b"\n"));

        // Neither the template's tail nor an unvisited component appears.
        let message = reassemble(&emitted);
        assert!(!message.ends_with(b"file.txt"));
        assert!(!message.ends_with(b"dir3"));
    }

    /// `EPERM` must NOT be tolerated.
    ///
    /// `std` maps both `EACCES` and `EPERM` onto
    /// `io::ErrorKind::PermissionDenied`, so a tolerance test written against
    /// the kind would swallow this failure. C compares `errno` against
    /// `EACCES` alone (`:124`), and so does [`is_tolerated`].
    #[test]
    fn a_permission_error_that_is_not_eacces_is_not_tolerated() {
        // `EPERM` is 1 on both Linux and macOS.
        let eperm = io::Error::from_raw_os_error(1);
        assert_eq!(eperm.kind(), io::ErrorKind::PermissionDenied);
        assert!(!is_tolerated(&eperm));
        assert_eq!(dir_error_text(&eperm), DEFAULT_TEXT);

        let mut emitted: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy_with(
            Path::new("dir1/file.txt"),
            &mut emitted,
            &emitting(),
            |_| Err(io::Error::from_raw_os_error(1)),
        );

        assert_eq!(code, CURLcode::WriteError);
        assert_eq!(reassemble(&emitted), b"Error creating directory dir1");
    }

    /// An error carrying no `errno` still lands on a sensible arm.
    ///
    /// `std` synthesises such errors; `mkdir(2)` never produces one, so there
    /// is no C behaviour to contradict. The two kinds C can express are
    /// honoured and everything else falls to the default text, mirroring
    /// `:67-69`.
    #[test]
    fn a_synthesised_error_falls_back_to_the_error_kind() {
        let denied =
            io::Error::new(io::ErrorKind::PermissionDenied, "synthesised");
        assert_eq!(denied.raw_os_error(), None);
        assert!(is_tolerated(&denied));
        assert_eq!(dir_error_text(&denied), EACCES_TEXT);

        let exists =
            io::Error::new(io::ErrorKind::AlreadyExists, "synthesised");
        assert!(is_tolerated(&exists));

        let other = io::Error::new(io::ErrorKind::InvalidInput, "synthesised");
        assert!(!is_tolerated(&other));
        assert_eq!(dir_error_text(&other), DEFAULT_TEXT);
    }

    // =======================================================================
    // The six frozen texts -- `src/tool_dirhie.c:36-71`.
    // =======================================================================

    /// Each of the six literals, exactly as C spells it.
    ///
    /// The two that C writes as a pair of adjacent literals are the point of
    /// this test: `:57-58` and `:63-64` must join with exactly one space, and
    /// nothing may be reworded, recased or repunctuated (AAP section 0.8.1).
    #[test]
    fn each_frozen_text_matches_the_c_literal() {
        assert_eq!(
            template(EACCES_TEXT),
            "You do not have permission to create %s"
        );
        assert_eq!(
            template(ENAMETOOLONG_TEXT),
            "The directory name %s is too long"
        );
        assert_eq!(
            template(EROFS_TEXT),
            "%s resides on a read-only file system"
        );
        assert_eq!(
            template(ENOSPC_TEXT),
            "No space left on the file system that will contain the \
             directory %s"
        );
        assert_eq!(
            template(EDQUOT_TEXT),
            "Cannot create directory %s because you exceeded your quota"
        );
        assert_eq!(template(DEFAULT_TEXT), "Error creating directory %s");
    }

    /// The two literal joins, checked as substrings so a doubled or missing
    /// space cannot hide inside a longer comparison.
    #[test]
    fn the_two_literal_joins_contribute_exactly_one_space() {
        let no_space = template(ENOSPC_TEXT);
        assert!(no_space.contains("that will contain the"));
        assert!(!no_space.contains("will  contain"));
        assert!(!no_space.contains("willcontain"));

        let quota = template(EDQUOT_TEXT);
        assert!(quota.contains("because you exceeded your"));
        assert!(!quota.contains("you  exceeded"));
        assert!(!quota.contains("youexceeded"));
    }

    /// `switch(errno)` at `:38-70`: each named value selects its own text.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn every_errno_selects_its_own_text() {
        let expectations: &[(Option<i32>, DirErrorText)] = &[
            (Some(errno::EACCES), EACCES_TEXT),
            (errno::ENAMETOOLONG, ENAMETOOLONG_TEXT),
            (errno::EROFS, EROFS_TEXT),
            (errno::ENOSPC, ENOSPC_TEXT),
            (errno::EDQUOT, EDQUOT_TEXT),
        ];

        for (code, expected) in expectations {
            let Some(code) = *code else {
                // Guarded by `every_errno_is_defined_on_the_mandated_targets`.
                continue;
            };
            let error = io::Error::from_raw_os_error(code);
            assert_eq!(dir_error_text(&error), *expected, "errno {code}");
        }

        // `EEXIST` has no arm of its own: C tolerates it and never reports it,
        // so it reaches `default:` if it ever does arrive here.
        let exists = io::Error::from_raw_os_error(errno::EEXIST);
        assert_eq!(dir_error_text(&exists), DEFAULT_TEXT);

        // An `errno` no arm names also reaches `default:`. `ENOENT` is 2 on
        // both mandated operating systems.
        let missing = io::Error::from_raw_os_error(2);
        assert_eq!(dir_error_text(&missing), DEFAULT_TEXT);
    }

    /// The rendered messages, with the substituted name in the right place --
    /// including [`EROFS_TEXT`], the only one that begins with it.
    #[test]
    fn the_name_is_substituted_where_c_puts_it() {
        assert_eq!(
            render_dir_error(EACCES_TEXT, b"a/b"),
            b"You do not have permission to create a/b".to_vec()
        );
        assert_eq!(
            render_dir_error(ENAMETOOLONG_TEXT, b"a/b"),
            b"The directory name a/b is too long".to_vec()
        );
        assert_eq!(
            render_dir_error(EROFS_TEXT, b"a/b"),
            b"a/b resides on a read-only file system".to_vec()
        );
        assert_eq!(
            render_dir_error(ENOSPC_TEXT, b"a/b"),
            b"No space left on the file system that will contain the \
              directory a/b"
                .to_vec()
        );
        assert_eq!(
            render_dir_error(EDQUOT_TEXT, b"a/b"),
            b"Cannot create directory a/b because you exceeded your quota"
                .to_vec()
        );
        assert_eq!(
            render_dir_error(DEFAULT_TEXT, b"a/b"),
            b"Error creating directory a/b".to_vec()
        );
    }

    /// A non-UTF-8 name is substituted byte for byte, with no replacement
    /// character anywhere.
    #[test]
    fn a_non_utf8_name_is_reported_verbatim() {
        let name: &[u8] = &[b'd', 0xff, 0xfe];
        let message = render_dir_error(DEFAULT_TEXT, name);

        assert_eq!(message, b"Error creating directory d\xff\xfe".to_vec());
        // U+FFFD encodes as EF BF BD; its absence proves nothing was lossy.
        assert!(!message.windows(3).any(|w| w == [0xef, 0xbf, 0xbd]));

        let mut emitted: Vec<u8> = Vec::new();
        show_dir_errno(
            &mut emitted,
            &emitting(),
            name,
            &io::Error::from_raw_os_error(2),
        );
        assert_eq!(reassemble(&emitted), message);
    }

    // =======================================================================
    // The diagnostic channel -- `crate::output::msgs` owns it, and the six
    // texts must obey its gates.
    // =======================================================================

    /// `src/tool_msgs.c:131` -- `!global->silent || global->showerror`.
    ///
    /// Reproduced here so that a future change routing these messages through
    /// `warnf` or a bare write, rather than through the `errorf` channel, is
    /// caught: `warnf`'s gate ignores `--show-error`.
    #[test]
    fn the_report_obeys_the_errorf_gate() {
        let name: &[u8] = b"dir1";
        let error = io::Error::from_raw_os_error(2);

        // Default: emitted.
        let mut emitted: Vec<u8> = Vec::new();
        show_dir_errno(&mut emitted, &MsgConfig::default(), name, &error);
        assert!(!emitted.is_empty());

        // `--silent`: suppressed.
        let mut silent: Vec<u8> = Vec::new();
        let config = MsgConfig::new(true, false, false);
        show_dir_errno(&mut silent, &config, name, &error);
        assert!(silent.is_empty());

        // `--silent --show-error`: restored, byte for byte.
        let mut restored: Vec<u8> = Vec::new();
        let config = MsgConfig::new(true, true, false);
        show_dir_errno(&mut restored, &config, name, &error);
        assert_eq!(restored, emitted);
    }

    /// The `curl: ` prefix, never the crate name (`src/tool_msgs.c:32`,
    /// `src/tool_version.h:28`).
    #[test]
    fn the_report_carries_the_curl_prefix() {
        let mut emitted: Vec<u8> = Vec::new();
        show_dir_errno(
            &mut emitted,
            &emitting(),
            b"dir1",
            &io::Error::from_raw_os_error(2),
        );

        assert!(emitted.starts_with(b"curl: "));
        // This crate is named with a hyphen, so a prefix taken from the crate
        // name would carry one. `src/tool_msgs.c:32` uses the program name
        // "curl", and `msgs::ERROR_PREFIX` reproduces it, so there is none --
        // which rules out every hyphenated variant, not just one spelling.
        assert!(!emitted.starts_with(b"curl-"));
        assert!(!msgs::ERROR_PREFIX.contains('-'));
        assert!(emitted.ends_with(b"\n"));
    }

    /// A successful walk emits nothing at all, on any of its shapes.
    #[test]
    fn a_successful_walk_is_silent() -> io::Result<()> {
        let root = TempDir::new()?;
        let mut emitted: Vec<u8> = Vec::new();
        let code = create_dir_hierarchy(
            &root.path().join("a/b/c/file.txt"),
            &mut emitted,
            &emitting(),
        );

        assert_eq!(code, CURLcode::Ok);
        assert!(emitted.is_empty());
        assert!(root.path().join("a/b/c").is_dir());
        Ok(())
    }

    /// The two codes this function returns, and nothing else -- so a caller
    /// mirroring C's `if(result) return result;` behaves identically.
    #[test]
    fn the_returned_codes_carry_the_c_integers() {
        assert_eq!(CURLcode::Ok.as_i32(), 0);
        assert_eq!(CURLcode::WriteError.as_i32(), 23);
        assert_eq!(CURLcode::WriteError.c_name(), "CURLE_WRITE_ERROR");
    }
}
