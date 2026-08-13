//***************************************************************************
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
//***************************************************************************

//! Atomic-replace file creation for curl's persisted state files, and the one
//! cross-platform seek helper.
//!
//! # `Curl_fopen`, in the C's own words
//!
//! Reproduced verbatim from `lib/curl_fopen.c:78-84`:
//!
//! ```text
//! /*
//!  * Curl_fopen() opens a file for writing with a temp name, to be renamed
//!  * to the final name when completed. If there is an existing file using
//!  * this name at the time of the open, this function will clone the mode
//!  * from that file. if 'tempname' is non-NULL, it needs a rename after the
//!  * file is written.
//!  */
//! ```
//!
//! # NOTE: step one no longer truncates the target, and that is deliberate
//!
//! `lib/curl_fopen.c:99` opens the *target* with `FOPEN_WRITETEXT`, which is
//! `"w"` on all four mandated targets (`lib/curl_setup.h:1259`; the `"wt"`
//! spelling at `:1245` is the DOS branch). `"w"` is
//! `O_WRONLY | O_CREAT | O_TRUNC`, so in the C **the existing file is emptied
//! before its mode is stat'd** -- and it is emptied on the temporary-file path
//! too, where it then sits as a zero-length placeholder until the caller's
//! rename replaces it. If the save fails after that point, the previous
//! contents are already gone.
//!
//! Measured, not inferred: a C probe that wrote `old contents` to a target
//! with mode `0600`, called `fopen(path, "w")` and then `fstat`ed the
//! descriptor reported `st_size == 0` and `st_mode == 0100600`.
//!
//! The whole family is recorded here so the mode string cannot be mistaken
//! for something with content on these targets. `lib/curl_setup.h:1258-1260`
//! defines `FOPEN_READTEXT` as `"r"`, `FOPEN_WRITETEXT` as `"w"` and
//! `FOPEN_APPENDTEXT` as `"a"`; the `"rt"` / `"wt"` / `"at"` spellings at
//! `:1244-1246` are the DOS and Windows branch, and `:1254-1256` is a third
//! branch that keeps `"rt"` while dropping the other two. **Text mode is a
//! no-op on Unix**, so all three carry no bits beyond the access mode -- which
//! is why this module opens files with
//! [`OpenOptions`](std::fs::OpenOptions) flags alone and needs no
//! mode-string equivalent anywhere. Only `FOPEN_WRITETEXT` is actually
//! reached by the code superseded here; the other two are named for
//! completeness, because a reader checking the header will find all three
//! together.
//!
//! **`O_TRUNC` is not reproduced here.** It was, and the deviation is recorded
//! rather than quietly taken -- see [the hardening section](#the-hardening-of-step-one)
//! immediately below for why, and for the two other things step one now does
//! that the C does not.
//!
//! # The hardening of step one
//!
//! Three changes to step one, all of them within the C's *contract* -- which
//! file is opened and what the caller may then do with it -- and none of them
//! touching a byte that reaches a socket, a flag the user types, or an
//! exported signature. AAP 0.8.1 freezes protocol wire behaviour, CLI flag
//! semantics, libcurl API signatures, test definitions and default option
//! values; a permission bit on a state file and whether a symbolic link is
//! followed are none of those five. The precedent is
//! [`crate::tls::keylog`], which hardens its own open with the same reasoning
//! recorded in the same way.
//!
//! ## 1. No `O_TRUNC`
//!
//! Opening the *final target* with `O_CREAT | O_TRUNC` before the protected
//! temporary file exists is a destructive primitive that a caller cannot opt
//! out of: any process that can create a name in the output directory can
//! aim it at a file it could not otherwise write, and a more privileged curl
//! empties that file on its behalf. CWE-22, and CWE-367 for the window
//! between the open and the rename.
//!
//! Removing it costs nothing observable on the success path. The temporary
//! file is renamed *over* the target, so the target's previous contents are
//! replaced wholesale either way -- truncating first only decides whether the
//! file is briefly empty in between. On the *failure* path the previous
//! contents now survive, which is the behaviour a reader of
//! [`OpenedFile::discard`] would expect and the opposite of the wart the C
//! documents.
//!
//! ## 2. `O_NOFOLLOW`, injected
//!
//! A final path component that is a symbolic link now makes the open fail
//! rather than resolve. CWE-59.
//!
//! The flag's *value* is injected as [`NoFollow`] rather than named here, and
//! that is the layering rule of [`crate::util`] rather than a stylistic
//! choice: `O_NOFOLLOW` is a `libc` integer whose value differs between Linux
//! and macOS, `crate::ffi` is the only directory in this crate permitted to
//! name `libc`, and `util` may not import `crate::ffi`. The module
//! documentation for `crate::util` gives the remedy for exactly this shape of
//! problem -- "take the value as a parameter instead" -- and this module
//! already applies it once, to the random suffix.
//!
//! What this does *not* refuse is a target that is not a regular file. A
//! character device, a FIFO and a directory all still reach the early-success
//! path below, because `--cookie-jar /dev/null` is a documented idiom and
//! discarding cookies is a legitimate thing to ask for. `O_NOFOLLOW` and the
//! `S_ISREG` test answer different questions: the first is about a name an
//! attacker planted, the second about a file the user chose.
//!
//! One undocumented spelling is lost and is named here rather than left to be
//! discovered: `--cookie-jar /dev/stdout` no longer works on Linux, because
//! `/dev/stdout` is itself a symbolic link to `/proc/self/fd/1`. The
//! documented route to standard output is the literal `-`
//! (`docs/cmdline-opts/cookie-jar.md:27`), which `lib/cookie.c:1477-1481`
//! intercepts before this module is reached, and no fixture in
//! `tests/data/test*` names `/dev/stdout`.
//!
//! ## 3. A private mode for the credential store
//!
//! [`StoreClass`] splits the three consumers in two. The Alt-Svc and HSTS
//! caches are [`StoreClass::Public`] and keep the C's mode handling exactly:
//! the temporary file is created at `S_IRUSR | S_IWUSR | sb.st_mode`, so an
//! existing file's mode is cloned. The cookie jar is
//! [`StoreClass::Credential`] and is created at `0600` regardless -- it holds
//! session credentials, and `0666 & ~umask` is normally `0644`, which makes a
//! first-ever jar readable by every local user.
//!
//! Forcing the mode rather than refusing an already-permissive jar is
//! deliberate. Refusing would fail a command the user typed, which *is* CLI
//! behaviour; forcing repairs a `0644` jar left behind by a C curl on the next
//! save and never fails. It also removes the need to compare the target's
//! owner against this process's effective user id, which would have broken
//! `sudo curl -c ~/.cookies` -- where the file legitimately belongs to
//! somebody other than the caller -- and which would have required a second
//! injected value for no gain.
//!
//! # NOTE: the early-success path is the entire reason step one exists
//!
//! If `fstat` fails **or** the target is not a regular file, `:102-104`
//! returns `CURLE_OK` immediately, with the plain handle still open and
//! `*tempname` still `NULL`:
//!
//! ```text
//! if(curlx_fstat(fileno(*fh), &sb) == -1 || !S_ISREG(sb.st_mode)) {
//!   return CURLE_OK;
//! }
//! ```
//!
//! That is what makes `--cookie-jar /dev/null`, a FIFO, a character device
//! and `/dev/stdout` work: the caller writes straight through and performs no
//! rename. Measured: `/dev/null` reports `st_mode == 020666` with
//! `S_ISREG == 0`.
//!
//! A `(File, Option<PathBuf>)` return would reproduce it, and would let a
//! caller reach for the rename anyway. [`OpenedFile`] is a two-variant
//! enumeration instead, so the "no rename" case cannot be forgotten: it has
//! no path to rename from.
//!
//! # What the caller still owns
//!
//! The rename is **not** this module's step, and neither is the cleanup. All
//! three consumers spell it identically; `lib/hsts.c:361-368` is the
//! canonical form:
//!
//! ```text
//! curlx_fclose(out);
//! if(!result && tempstore && curlx_rename(tempstore, file))
//!   result = CURLE_WRITE_ERROR;
//! if(result && tempstore)
//!   unlink(tempstore);
//! curlx_free(tempstore);
//! ```
//!
//! Close first, then rename, mapping a rename failure to
//! `CURLcode::WriteError`, and unlink the temporary file on any error.
//! [`OpenedFile::commit`] and [`OpenedFile::discard`] are that sequence
//! written once, so the three consumers cannot each get it subtly wrong.
//! `curlx_rename` is plain `rename(2)` on the mandated targets
//! (`lib/curlx/fopen.h:70`), which is [`std::fs::rename`].
//!
//! The primitives stay available beside the helpers, because
//! `lib/cookie.c:1477-1481` has a path that bypasses this module altogether:
//!
//! ```text
//! if(!strcmp("-", filename)) {
//!   out = stdout;
//!   use_stdout = TRUE;
//! }
//! ```
//!
//! and `:1530-1537` then skips both the close and the rename for it.
//!
//! # A measured correction to `dirslash`
//!
//! One documented expectation for this module was wrong, and it is corrected
//! here with the evidence rather than quietly implemented the other way.
//! `dirslash("/c")` was said to produce `"/"`. **It produces `""`.**
//!
//! The reason is in the second backward scan. For `"/c"` the first loop stops
//! at `n == 1`, because `path[0]` *is* a separator; the second loop then
//! consumes that separator and drives `n` to `0`; and the trailing separator
//! is appended only `if(n)`. So nothing is appended at all.
//!
//! This was settled by compiling a literal transliteration of
//! `lib/curl_fopen.c:55-76` with a plain buffer standing in for the dynbuf and
//! running it, in preference to re-reading the source a third time. Sixteen
//! inputs, and every one of them is asserted by `mod tests` below:
//!
//! | input | output | |
//! |---|---|---|
//! | `/a/b/c` | `/a/b/` | the ordinary case |
//! | `/a//b//c` | `/a//b/` | the run *before the filename* collapses to one |
//! | `a/b` | `a/` | relative, one component |
//! | `./x` | `./` | the dot is not special |
//! | `../x` | `../` | nor is the double dot |
//! | `/a/b/` | `/a/b/` | an empty filename part |
//! | `a/` | `a/` | likewise, relative |
//! | `dir/` | `dir/` | likewise |
//! | `c` | `""` | no directory at all |
//! | `x.txt` | `""` | likewise |
//! | `""` | `""` | the `if(n)` guard is skipped entirely |
//! | `/c` | `""` | **the correction** -- root is NOT preserved |
//! | `//c` | `""` | and neither is a doubled root |
//! | `/` | `""` | no filename part, nothing survives |
//! | `//` | `""` | likewise |
//! | `a\b` | `""` | a backslash is not a separator here |
//!
//! The consequence of the corrected row is worth stating plainly, because it
//! is a real defect rather than a curiosity: a state file at the filesystem
//! **root** -- `--cookie-jar /cookies.txt` -- has its temporary file created
//! in the process's *current working directory*, and the caller's rename then
//! has to cross whatever mount boundary lies between them. Reproduced
//! anyway, for the reason given for the truncation above.
//!
//! # `dirslash`, in the C's own words
//!
//! Reproduced verbatim from `lib/curl_fopen.c:33-42`:
//!
//! ```text
//! /*
//!   The dirslash() function breaks a null-terminated pathname string into
//!   directory and filename components then returns the directory component
//!   up to, *AND INCLUDING*, a final '/'. If there is no directory in the
//!   path, this instead returns a "" string.
//!
//!   This function returns a pointer to malloc'ed memory.
//!
//!   The input path to this function is expected to have a filename part.
//! */
//! ```
//!
//! ## Why the scan is written over bytes and not over [`std::path::Path`]
//!
//! [`Path::parent`](std::path::Path::parent) is **not** this function, and
//! substituting it would change behaviour on almost every row of the table
//! above. It is documented in terms of *components*, so it drops the trailing
//! separator this function is defined to include, it collapses repeated
//! separators the C leaves alone, it yields `None` where the C yields `""`,
//! and for `"/c"` it yields `Some("/")` -- which is precisely the value the
//! corrected row says the C does *not* produce.
//! [`Path::file_name`](std::path::Path::file_name) and
//! [`Path::join`](std::path::Path::join) normalise for the same reasons.
//!
//! So [`dirslash`] takes a `&[u8]` and walks it index by index, and
//! [`open_for_write`] reaches the bytes of its `&Path` through
//! [`std::os::unix::ffi::OsStrExt`], which is a lossless view and not a
//! conversion. A path that is not UTF-8 survives unchanged, exactly as the
//! C's `const char *` does.
//!
//! ## The length ceiling
//!
//! `lib/curl_fopen.c:60` initialises its dynbuf with `CURL_MAX_INPUT_LENGTH`,
//! which is `8000000` at `lib/urldata.h:131`, and `dirslash` returns `NULL`
//! on any dynbuf failure. Its caller does not inspect the reason -- `:113-124`
//! only tests `if(dir)` and then `if(!tempstore)` -- so **every** name
//! composition failure becomes `CURLE_OUT_OF_MEMORY`, including one that the
//! dynbuf reported as `CURLE_TOO_LARGE`.
//!
//! Both halves are reproduced. [`dirslash`] surfaces the dynbuf's own code,
//! so the ceiling is observable and testable; [`open_for_write`] collapses it,
//! so a consumer sees the code the C gives it. The second ceiling is real
//! too: `curl_maprintf` composes the name through
//! `curlx_dyn_init(info.b, DYN_APRINTF)` (`lib/mprintf.c:1144`), also
//! `8000000`, so an over-long composition returns `NULL` and lands on the
//! same `CURLE_OUT_OF_MEMORY`.
//!
//! # The error ladder, measured exactly
//!
//! `result` is initialised to `CURLE_WRITE_ERROR` at `:88` and reset to it at
//! `:126`, which is what makes the table below as flat as it is:
//!
//! | Failure | Code |
//! |---|---|
//! | step 1, opening the target | `CURLcode::WriteError` |
//! | step 2, the randomness provider | whatever the provider returned |
//! | step 3, composing the name | `CURLcode::OutOfMemory` |
//! | step 4, creating the temporary file | `CURLcode::WriteError` |
//! | step 5, `fdopen` | eliminated -- see below |
//!
//! No [`std::io::ErrorKind`] is inspected anywhere in this module, and that is
//! a decision rather than an omission: the C collapses every `errno` to
//! `CURLE_WRITE_ERROR`, so a finer-grained mapping would hand consumers a
//! code curl 8.19.0-DEV never returns. Every code is named through
//! [`crate::error::CURLcode`]; no integer is written.
//!
//! # What `lib/curlx/fopen.h` expands to here, and what is excluded
//!
//! The non-Windows branch at `lib/curlx/fopen.h:61-71` is a set of aliases for
//! the plain POSIX calls, and reading it is the shortest route to knowing what
//! this module has to do:
//!
//! | C alias | Expands to | Here |
//! |---|---|---|
//! | `curlx_fopen` | `fopen` | [`std::fs::OpenOptions`] |
//! | `curlx_fdopen` | `fdopen` | eliminated -- the `File` *is* the handle |
//! | `curlx_fclose` | `fclose` | dropping the [`File`] |
//! | `curlx_fstat` | `fstat` | [`File::metadata`] |
//! | `curlx_struct_stat` | `struct stat` | [`std::fs::Metadata`] |
//! | `curlx_open` | `open` | [`std::fs::OpenOptions`] |
//! | `curlx_close` | `close` | dropping the [`File`] |
//! | `curlx_rename` | `rename` | [`std::fs::rename`] |
//! | `curlx_stat` | `stat` | unused by this module |
//!
//! `fdopen` deserves the emphasis it gets in that table: it is one of the C's
//! five failure modes, and it does not exist here. `OpenOptions::open`
//! returns the handle directly, so there is no second step to fail and no
//! descriptor left dangling if it does. The C's `fail:` label unlinks the
//! temporary file only `if(fd != -1)`, and the *only* way to arrive there with
//! a live descriptor is a failed `fdopen` -- so that unlink has no reachable
//! counterpart in this module either. It is not lost: the same unlink is what
//! every consumer performs on its own errors, and it is written once as
//! [`OpenedFile::discard`].
//!
//! ## The excluded Windows surface, named so the exclusion is visible
//!
//! Two further C branches are excluded by the same boundary and are recorded
//! because they are the *only* places the C's own logic differs by platform:
//! the `MSDOS`/`OS2` separator branch at `lib/curl_fopen.c:47-49`, where
//! `PATHSEP` is a backslash, and the 32-bit-Android `mode_t` cast at
//! `:130-133`. Neither applies to Linux or macOS on x86_64 or aarch64.
//!
//! ## The `CURL_MEMDEBUG` aliases are somebody else's job
//!
//! `lib/curlx/fopen.h:73-85` swaps `curlx_fopen`, `curlx_freopen`,
//! `curlx_fdopen` and `curlx_fclose` for `curl_dbg_fopen`,
//! `curl_dbg_freopen`, `curl_dbg_fdopen` and `curl_dbg_fclose` when the
//! allocation tracker is compiled in. Those belong to the counting
//! `GlobalAlloc` that AAP 0.6.6 puts behind the default-off `memdebug`
//! feature, whose home is `crate::ffi::sys`, and **none of them is
//! implemented here.** This module opens files through the standard library
//! and has no allocation log to write to.
//!
//! # Conventions this file holds itself to
//!
//! No `unsafe` and no `libc`. The two extension traits this module needs --
//! [`std::os::unix::fs::OpenOptionsExt`] for the cloned mode, the private mode
//! and the injected open flag, and [`std::os::unix::ffi::OsStrExt`] for the
//! byte view of a path -- are ordinary safe traits, so the crate root's
//! `#![deny(unsafe_code)]` needs no exemption here and none is taken. Both are
//! `#[cfg(unix)]`, and all four mandated targets are Unix, so no configuration
//! guard is written -- consistent with `crate::tls::keylog`, which names the
//! same omission.
//!
//! `O_NOFOLLOW` is the one platform constant this module needs and cannot
//! name, which is why it arrives as [`NoFollow`]; see
//! [the hardening section](#the-hardening-of-step-one). Nothing else about the
//! import list changes: no `libc`, and no `crate::ffi`.
//!
//! Blocking I/O, with no `async` and no `tokio::fs`. Saving a state file is
//! synchronous in curl and stays synchronous here; the asynchrony in this
//! crate belongs to the transfer path, and putting an `.await` on a cookie-jar
//! write would change when it happens relative to teardown.
//!
//! Imports are `std`, [`crate::error`] and [`crate::util::dynbuf`], and
//! nothing else -- in particular not `crate::crypto` and not `crate::ffi`, for
//! the reasons given above. Every item is `pub(crate)`: nothing here backs an
//! exported symbol,
//! `grep -i fopen lib/libcurl.def` finds nothing, and per AAP 0.8.7 no
//! internal is widened to make `tests/unit` or `tests/libtest` link. The C
//! stems are kept so that a grep against `lib/curl_fopen.c` still lands.
//!
//! Edition 2021 and a minimum supported Rust version of 1.75. The newest
//! thing used is
//! [`OpenOptions::create_new`](std::fs::OpenOptions::create_new), stable
//! since 1.0; `OpenOptionsExt::mode` and `MetadataExt::mode` have both been
//! stable since 1.1. Performance is an explicit non-goal, so nothing here is
//! restructured on speed grounds.

// The seek surface below is the residue of `lib/curlx/fopen.c`, which carries
// NO feature guard, so neither does this import. See the module documentation.
use std::io::{self, Seek, SeekFrom};

// Everything from here down came from `lib/curl_fopen.c`, which IS guarded, so
// every one of these imports repeats that guard. Writing the condition on each
// line rather than once as an inner attribute is what keeps the seek surface
// above reachable at `--no-default-features`.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
use std::ffi::OsString;
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
use std::fs::{self, File, OpenOptions};
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
use std::path::{Path, PathBuf};

#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
use crate::error::{CURLcode, CodeResult};
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
use crate::util::dynbuf::{DynBuf, DYN_APRINTF};

/// The path separator this module appends, as bytes.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
const PATHSEP: &[u8] = b"/";

/// The suffix every temporary name ends in.
///
/// From the format string at `lib/curl_fopen.c:117`,
/// `curl_maprintf("%s%s.tmp", dir, randbuf)`. Preserved exactly: a consumer
/// or a system administrator sweeping for abandoned temporary files greps for
/// this.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
const TEMP_SUFFIX: &[u8] = b".tmp";

/// `CURL_MAX_INPUT_LENGTH`, the ceiling `dirslash` gives its dynbuf.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
const MAX_INPUT_LENGTH: usize = 8_000_000;

/// The length, in characters, of the random component of a temporary name.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
pub(crate) const RAND_SUFFIX_LEN: usize = 40;

/// The alphabet the random component is drawn from.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
pub(crate) const RAND_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// True when `byte` is a path separator on the four mandated targets.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
const fn is_sep(byte: u8) -> bool {
    byte == b'/'
}

/// Returns the directory component of `path`, up to *and including* one final
/// separator, or an empty vector when `path` has no directory component.
///
/// The C is four lines of index arithmetic and this is a line-for-line
/// reading of it:
///
/// ```text
/// n = strlen(path);
/// if(n) {
///   while(n && !IS_SEP(path[n - 1]))   /* past the filename */
///     --n;
///   while(n && IS_SEP(path[n - 1]))    /* past the whole separator run */
///     --n;
/// }
/// if(curlx_dyn_addn(&out, path, n))
///   return NULL;
/// if(n && curlx_dyn_addn(&out, PATHSEP, 1))
///   return NULL;
/// ```
///
/// Three details in that are easy to lose in translation, so each is called
/// out where it happens below:
///
/// 1. **Two scans, in this order.** The first walks back over the filename to
///    the rightmost separator; the second walks back over the *entire* run of
///    separators that precedes it. A single scan would give `"/a//b//"` for
///    `"/a//b//c"` instead of the measured `"/a//b/"`.
/// 2. **Exactly one separator is appended, and only `if(n)`.** That `if` is
///    the whole of the corrected `"/c"` row: when the second scan reaches the
///    start of the string there is no directory left to terminate.
/// 3. **The empty result is a value, not a failure.** `dyn_addn(&out, path, 0)`
///    succeeds, and the C then returns a pointer to an empty string. The C
///    returns `NULL` only when the dynbuf itself fails, which is why the
///    signature below is a `CodeResult<Vec<u8>>` and not an `Option`.
///
/// # Errors
///
/// The ceiling is [`MAX_INPUT_LENGTH`], so a `path` longer than eight million
/// bytes yields `CURLcode::TooLarge` from the buffer -- the C's `NULL`, with
/// its reason preserved. [`open_for_write`] deliberately discards that reason;
/// see the module documentation.
///
/// # Panics
///
/// Never. The two loops are guarded on `n != 0` before every index, so
/// `path[n - 1]` cannot underflow, and `path[..n]` cannot exceed the slice
/// because `n` only ever decreases from `path.len()`.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
#[allow(dead_code)]
pub(crate) fn dirslash(path: &[u8]) -> CodeResult<Vec<u8>> {
    let mut out = DynBuf::new(MAX_INPUT_LENGTH);

    // `n = strlen(path)`. A slice carries its own length, so there is no scan
    // and no way to be handed a string that is not terminated.
    let mut n = path.len();

    // `if(n)`. Skipped for an empty path, which is why `""` falls through to
    // the zero-length append below and comes back as `""` rather than as an
    // error.
    if n != 0 {
        // Scan one: `while(n && !IS_SEP(path[n - 1])) --n;`
        while n != 0 && !is_sep(path[n - 1]) {
            n -= 1;
        }

        // Scan two: `while(n && IS_SEP(path[n - 1])) --n;` -- the whole run,
        // not just one.
        while n != 0 && is_sep(path[n - 1]) {
            n -= 1;
        }
    }

    // `curlx_dyn_addn(&out, path, n)`. Appending nothing is not special-cased
    // here for the same reason the C does not special-case it: a zero-length
    // append is how the empty result comes into existence.
    out.addn(&path[..n])?;

    // `if(n && curlx_dyn_addn(&out, PATHSEP, 1))`. One separator, and only
    // when something was appended before it.
    if n != 0 {
        out.addn(PATHSEP)?;
    }

    Ok(out.take())
}

/// The temporary name for `filename`, composed exactly as the C composes it.
///
/// Supersedes `lib/curl_fopen.c:113-119`:
///
/// ```text
/// dir = dirslash(filename);
/// if(dir) {
///   /* The temp filename should not end up too long for the target file
///      system */
///   tempstore = curl_maprintf("%s%s.tmp", dir, randbuf);
///   curlx_free(dir);
/// }
/// ```
///
/// # Errors
///
/// Either ceiling, surfaced as the buffer's own code. [`open_for_write`]
/// collapses both to `CURLcode::OutOfMemory`, which is what the C's
/// `if(!tempstore)` test does.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
fn temp_name(filename: &Path, rand_suffix: &str) -> CodeResult<PathBuf> {
    // `OsStrExt::as_bytes` is a lossless view of the platform string, not a
    // conversion, so a path that is not valid UTF-8 reaches `dirslash`
    // unchanged -- exactly as the C's `const char *` does.
    let dir = dirslash(filename.as_os_str().as_bytes())?;

    let mut out = DynBuf::new(DYN_APRINTF);
    out.addn(&dir)?;
    out.addn(rand_suffix.as_bytes())?;
    out.addn(TEMP_SUFFIX)?;

    // Back to a path through the same lossless view, in the other direction.
    Ok(PathBuf::from(OsString::from_vec(out.take())))
}

/// A state file opened for writing, and whether it still needs a rename.
///
/// # No `Drop`, deliberately
///
/// A `Drop` implementation that removed an uncommitted temporary file would be
/// an improvement, and it is not made, because observable behaviour is frozen:
/// `Curl_fopen` does not unlink on the way out, and all three consumers unlink
/// for themselves. [`Self::discard`] is that unlink, written once.
/// `#[must_use]` on [`open_for_write`] is the Rust-shaped nudge that costs no
/// behaviour.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum OpenedFile {
    /// The target is not a regular file, so write to it directly and do **not**
    /// rename.
    ///
    /// The C's early success at `lib/curl_fopen.c:102-104`: `fstat` failed, or
    /// `S_ISREG` was false. `*fh` is the open target and `*tempname` is
    /// `NULL`. `/dev/null`, a FIFO and a character device all arrive here --
    /// measured: `/dev/null` reports `st_mode == 020666` with `S_ISREG == 0`.
    ///
    /// `/dev/stdout` no longer arrives here on Linux, because it is a symbolic
    /// link and step one now passes `O_NOFOLLOW`; see the module
    /// documentation, which names that consequence and the documented `-`
    /// spelling that replaces it.
    Direct {
        /// The target itself, open for writing.
        ///
        /// **Not** truncated: step one no longer passes `O_TRUNC`. For the
        /// character devices and FIFOs that reach this variant the flag never
        /// meant anything anyway, and the module documentation records why it
        /// is gone for the regular-file path too.
        file: File,
    },

    /// The target is a regular file, so write here and then rename over it.
    ///
    /// The C's ordinary path: `*fh` is a fresh descriptor on `tempstore` and
    /// `*tempname` is that name. The target still holds its previous contents
    /// -- step one no longer truncates it -- until the rename replaces it
    /// wholesale, so a save that fails leaves the old state file intact.
    Temp {
        /// The temporary file, created with `O_EXCL` and the cloned mode.
        file: File,

        /// The temporary file's path, which the caller renames or removes.
        ///
        /// `<directory including its separator><40 random characters>.tmp`,
        /// and relative when the directory component is empty.
        temp_path: PathBuf,
    },
}

#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
#[allow(dead_code)]
impl OpenedFile {
    /// The handle to write the state file's contents to.
    ///
    /// Both variants have one, which is the point: `lib/hsts.c:350-359` and
    /// `lib/altsvc.c:372-382` write through `out` without ever asking which
    /// kind of file it is.
    pub(crate) fn file_mut(&mut self) -> &mut File {
        match self {
            Self::Direct { file } | Self::Temp { file, .. } => file,
        }
    }

    /// The temporary path, or `None` when there is nothing to rename.
    pub(crate) fn temp_path(&self) -> Option<&Path> {
        match self {
            Self::Direct { .. } => None,
            Self::Temp { temp_path, .. } => Some(temp_path),
        }
    }

    /// True when this file still needs a rename to become the target.
    ///
    /// `*tempname != NULL`, phrased as the question the consumers actually
    /// ask.
    pub(crate) fn needs_rename(&self) -> bool {
        matches!(self, Self::Temp { .. })
    }

    /// Closes the file and, if it was a temporary, renames it over `target`.
    ///
    /// This is `lib/hsts.c:361-367` written once so that the three consumers
    /// share one implementation rather than three transcriptions:
    ///
    /// ```text
    /// curlx_fclose(out);
    /// if(!result && tempstore && curlx_rename(tempstore, file))
    ///   result = CURLE_WRITE_ERROR;
    /// if(result && tempstore)
    ///   unlink(tempstore);
    /// ```
    ///
    /// Three properties of that sequence are reproduced exactly:
    ///
    /// * **The close comes first.** Renaming a file that is still open works
    ///   on Unix, but the C closes first and the buffered contents have to
    ///   reach the filesystem before the name changes. Dropping the [`File`]
    ///   is that close.
    /// * **A failed rename leaves nothing behind.** The C's `if(result &&
    ///   tempstore) unlink(tempstore)` fires because `result` has just been
    ///   set, so the temporary file is removed on the way out.
    /// * **The unlink's own failure is ignored.** The C does not test
    ///   `unlink`'s return value, so neither does this.
    ///
    /// # Errors
    ///
    /// `CURLcode::WriteError` if the rename fails, matching the C's single
    /// mapping. No [`std::io::ErrorKind`] is inspected.
    pub(crate) fn commit(self, target: &Path) -> CodeResult<()> {
        match self {
            // `if(!use_stdout)` in `lib/cookie.c`, and the untaken branch of
            // `if(... tempstore ...)` in the other two: close, and stop.
            Self::Direct { file } => {
                drop(file);
                Ok(())
            }

            Self::Temp { file, temp_path } => {
                // `curlx_fclose(out)`.
                drop(file);

                // `curlx_rename(tempstore, file)`.
                if fs::rename(&temp_path, target).is_err() {
                    // `result = CURLE_WRITE_ERROR;` then `unlink(tempstore)`.
                    // The C ignores the unlink's result and so does this.
                    let _ = fs::remove_file(&temp_path);
                    return Err(CURLcode::WriteError);
                }

                Ok(())
            }
        }
    }

    /// Closes the file and removes the temporary, abandoning the save.
    ///
    /// The other arm of the consumers' cleanup: `if(result && tempstore)
    /// unlink(tempstore);` at `lib/hsts.c:365-366`, `lib/altsvc.c:389-390` and
    /// -- with the close folded in -- `lib/cookie.c:1549-1554`.
    ///
    /// Returns nothing, because the C ignores `unlink`'s return value.
    pub(crate) fn discard(self) {
        if let Self::Temp { file, temp_path } = self {
            drop(file);
            let _ = fs::remove_file(&temp_path);
        }
    }
}

/// Which of the three state files is being written, and therefore how private
/// its mode must be.
///
/// The C makes no such distinction: `Curl_fopen` clones the target's mode for
/// all three consumers, so a cookie jar that did not previously exist is
/// created at `0666 & ~umask` -- normally `0644`, readable by every local user
/// -- and keeps that mode for the rest of its life. The Alt-Svc and HSTS
/// caches are public knowledge and that is fine for them; a jar of session
/// cookies is a credential store and it is not.
///
/// Splitting the two is what lets the mode policy differ without the caller
/// having to know a mode number. See
/// [the hardening section](index.html#the-hardening-of-step-one) of the module
/// documentation for why this is a permitted deviation from AAP 0.8.1 and why
/// the jar's mode is *forced* rather than an existing permissive jar refused.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum StoreClass {
    /// The Alt-Svc cache (`lib/altsvc.c:371`) and the HSTS cache
    /// (`lib/hsts.c:349`).
    ///
    /// Mode handling is the C's, unchanged: created at `fopen`'s `0666` when
    /// absent, and the temporary file is created at
    /// `S_IRUSR | S_IWUSR | sb.st_mode`, cloning whatever the target already
    /// had. Neither file holds a secret -- an Alt-Svc entry is a hostname the
    /// server advertised in the clear, and an HSTS entry is a hostname that
    /// asked for HTTPS -- so there is nothing here to protect from a local
    /// reader and no reason to diverge.
    Public,

    /// The Netscape cookie jar (`lib/cookie.c:1483`).
    ///
    /// Created at `0600` and written through a temporary file created at
    /// `0600`, so neither the placeholder nor the finished jar is ever
    /// readable by another local user, and a `0644` jar inherited from a C
    /// curl is repaired by the next save rather than cloned forward.
    Credential,
}

#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
impl StoreClass {
    /// The mode step one asks for when the target does not yet exist.
    ///
    /// `0o666` for [`Self::Public`] is `fopen`'s own default and therefore the
    /// C's behaviour exactly; `OpenOptions` would have used it anyway, and it
    /// is written out so that the two classes read as one decision rather than
    /// as one decision and one omission.
    ///
    /// The kernel masks either value with the umask, so both are ceilings.
    const fn creation_mode(self) -> u32 {
        match self {
            Self::Public => 0o666,
            Self::Credential => PRIVATE_FILE_MODE,
        }
    }

    /// The mode step four asks for when creating the temporary file.
    ///
    /// `target_mode` is the full `st_mode` word from `fstat`, file-type bits
    /// included. `open(2)` ignores every bit outside the permission set, so
    /// passing it through unmasked is safe and is what the C does -- see step
    /// four.
    ///
    /// [`Self::Credential`] ignores `target_mode` entirely. That is the whole
    /// point: cloning it is how a `0644` jar stays `0644` forever.
    const fn temp_mode(self, target_mode: u32) -> u32 {
        match self {
            Self::Public => PRIVATE_FILE_MODE | target_mode,
            Self::Credential => PRIVATE_FILE_MODE,
        }
    }

    /// Whether an extra hard link to the target is grounds for refusing.
    ///
    /// Only for [`Self::Credential`]. A cookie jar with two names is not a
    /// thing a user creates; it is what an attacker with write access to the
    /// output directory leaves behind so that a copy of the jar survives under
    /// a name they control. A legitimate jar has `st_nlink == 1`.
    ///
    /// The Alt-Svc and HSTS caches are exempt because there is nothing in them
    /// worth linking to, and refusing would turn a harmless oddity into a
    /// failed command.
    const fn rejects_extra_links(self) -> bool {
        matches!(self, Self::Credential)
    }
}

/// `S_IRUSR | S_IWUSR` -- readable and writable by the owner alone.
///
/// Spelled once, as the octal the C's two macros expand to. It appears in
/// three places: the mode step four unions into a public store's cloned mode
/// (`lib/curl_fopen.c:135-136`), and the mode a credential store is created
/// and written at.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// The `O_NOFOLLOW` bit, injected because this module may not name `libc`.
///
/// `crate::util`'s layering rule forbids every file in this directory from
/// importing `crate::ffi`, which is the only directory in this crate permitted
/// to name `libc`, and the rule's own remedy is to take the value as a
/// parameter. [`crate::tls::keylog`] imports the constant directly because
/// `tls` is not bound by that rule; this module cannot, and hard-coding the
/// number is worse than either -- it is `0o400000` on Linux/x86-64 and
/// `0x0100` on macOS, so a literal would be silently wrong on one of the four
/// mandated targets.
///
/// A newtype rather than a bare `i32` parameter, because a bare integer
/// invites a caller to pass `0` and disable the guard without anything saying
/// so -- the same shape of defect as a warning function called with literals.
/// [`Self::new`] is the only way to build one, it refuses zero in a debug
/// build, and [`Self::DISABLED`] exists so that a test which wants the
/// unhardened behaviour has to say the word.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) struct NoFollow(i32);

#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
impl NoFollow {
    /// No guard at all, for the tests that exercise what the C does.
    ///
    /// Named rather than spelled `NoFollow::new(0)` so that
    /// [`Self::new`]'s debug assertion can stay unconditional and so that
    /// `grep DISABLED` finds every place the guard is deliberately absent.
    ///
    /// `#[allow(dead_code)]` and **not** `#[cfg(test)]`: no production caller
    /// should ever want this, which is the point, but hiding it behind the test
    /// gate would break the reference to it in this type's own documentation.
    /// Its only use is [`the_guard_is_what_refuses_a_symlink`], which needs the
    /// unguarded open in order to prove that the guarded one refuses for the
    /// reason claimed.
    ///
    /// [`the_guard_is_what_refuses_a_symlink`]: index.html#the-hardening-of-step-one
    #[allow(dead_code)]
    pub(crate) const DISABLED: Self = Self(0);

    /// Wraps the platform's `O_NOFOLLOW`, and anything else the caller wants
    /// in the same flag word.
    ///
    /// `O_CLOEXEC` may be included and is harmless: [`std::fs::File`] already
    /// sets it on every descriptor it opens, so passing it changes nothing and
    /// documents the intent. `O_TRUNC` must **not** be included -- see the
    /// module documentation -- and neither must `O_CREAT` or an access mode,
    /// which [`OpenOptions`] owns.
    ///
    /// # Panics
    ///
    /// In a debug build only, if `flags` is zero, which would silently disable
    /// the symlink guard. Use [`Self::DISABLED`] to mean that on purpose. A
    /// release build proceeds, for the same reason the suffix contract below
    /// is only debug-asserted: this is a wiring mistake, not a runtime
    /// condition, and refusing to save a state file over it would be worse
    /// than saving one unhardened.
    pub(crate) fn new(flags: i32) -> Self {
        debug_assert!(
            flags != 0,
            "NoFollow::new(0) disables the symlink guard; say NoFollow::DISABLED"
        );
        Self(flags)
    }

    /// The flag word, for [`OpenOptionsExt::custom_flags`].
    const fn bits(self) -> i32 {
        self.0
    }
}

/// Opens `filename` for writing, through a temporary file when it is safe to.
///
/// Supersedes `Curl_fopen` (`lib/curl_fopen.c:85-156`). The C's own summary,
/// the truncation note, the early-success note, the error ladder and the
/// injected-randomness rationale are all in the module documentation; this
/// comment walks the five steps.
///
/// `class` selects the mode policy: see [`StoreClass`]. `no_follow` carries the
/// platform's `O_NOFOLLOW`, which this module may not name for itself: see
/// [`NoFollow`].
///
/// `rand_suffix` is the injected randomness. It must return
/// [`RAND_SUFFIX_LEN`] characters drawn from [`RAND_ALPHABET`], and it is
/// called **at most once** -- never on the not-a-regular-file path, because
/// the C returns at `:103` before reaching `:109`.
///
/// # Steps
///
/// 1. Open the target for writing, creating it if absent, with `no_follow` and
///    **without** `O_TRUNC` -- see
///    [the hardening section](index.html#the-hardening-of-step-one). Stat the
///    descriptor. If the stat fails or the target is not a regular file,
///    return [`OpenedFile::Direct`] with that handle -- the C's early
///    `CURLE_OK`. If it is a regular file with an extra hard link and `class`
///    refuses those, fail.
/// 2. Close the target and ask `rand_suffix` for the random component.
/// 3. Compose `<dirslash(filename)><suffix>.tmp`.
/// 4. Create that name with `O_WRONLY | O_CREAT | O_EXCL` and the mode
///    `class` chooses -- `0o600 | <the target's own mode>` for a public store,
///    a flat `0o600` for the credential store.
/// 5. `fdopen` -- eliminated. The [`File`] from step 4 *is* the handle.
///
/// # Errors
///
/// * `CURLcode::WriteError` if the target cannot be opened -- which now
///   includes the case where its final component is a symbolic link, because
///   that is what `no_follow` is for -- if a credential store's target has more
///   than one hard link, or if the temporary file cannot be created, which
///   includes the case where the name already exists, because `O_EXCL` is the
///   point of step 4.
/// * Whatever `rand_suffix` returned, unchanged.
/// * `CURLcode::OutOfMemory` if the name cannot be composed.
///
/// # Panics
///
/// In a debug build only, if `rand_suffix` breaks its contract. That mirrors
/// the severity of `DEBUGASSERT(num > 1)` at `lib/rand.c:267`, which is the
/// C's only check on the same thing; a release build, like the C, proceeds.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
#[allow(dead_code)]
#[must_use = "an OpenedFile::Temp that is neither committed nor discarded \
              leaves the temporary file behind"]
pub(crate) fn open_for_write<F>(
    filename: &Path,
    class: StoreClass,
    no_follow: NoFollow,
    rand_suffix: F,
) -> CodeResult<OpenedFile>
where
    F: FnOnce() -> CodeResult<String>,
{
    // ---- STEP 1 -------------------------------------------------------------
    //
    // `*fh = curlx_fopen(filename, FOPEN_WRITETEXT);` at `:99`.
    //
    // NOTE: `FOPEN_WRITETEXT` is `"w"` on the mandated targets
    // (`lib/curl_setup.h:1259`), which is `O_WRONLY | O_CREAT | O_TRUNC`.
    //
    // THREE DELIBERATE DIVERGENCES, all justified in the module
    // documentation's hardening section, which is the single place they are
    // argued rather than four places they are half-argued:
    //
    //   * NO `.truncate(true)`. `O_TRUNC` on the *final target*, before the
    //     protected temporary file exists, is a destructive primitive aimed by
    //     whoever can create a name in this directory. Removing it is
    //     invisible on the success path -- the rename replaces the contents
    //     wholesale either way -- and on the failure path the old state file
    //     now survives.
    //   * `custom_flags(no_follow)` carries `O_NOFOLLOW`, so a symlinked final
    //     component fails here instead of resolving. The value is injected
    //     because this module may not name `libc`; see `NoFollow`.
    //   * `.mode(class.creation_mode())` is `0o666` for a public store, which
    //     is `fopen`'s own default and therefore no change at all, and `0o600`
    //     for the credential store so that a jar which did not previously
    //     exist is never created world-readable.
    //
    // A read-only `fs::metadata(filename)` would avoid the truncation too, and
    // is still not used: it would stat the *path* rather than a descriptor,
    // reintroducing the time-of-check/time-of-use gap that reading `fstat` off
    // this handle closes.
    let target = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(class.creation_mode())
        .custom_flags(no_follow.bits())
        .open(filename)
        // `if(!*fh) goto fail;` with `result` still holding its initial value
        // from `:88`. `ELOOP` from `O_NOFOLLOW` arrives here, and collapses to
        // the same code as every other reason the target would not open --
        // which is what the C would report had the open failed for any reason,
        // so no caller learns a distinction it did not previously have.
        .map_err(|_| CURLcode::WriteError)?;

    // `curlx_fstat(fileno(*fh), &sb)` at `:102`. `File::metadata` is `fstat`
    // on this descriptor, not `stat` on the path, which matters: the two can
    // disagree if the path is replaced between the open and the query.
    let metadata = match target.metadata() {
        Ok(metadata) => metadata,

        // The `== -1` half of `:102`. EARLY SUCCESS: the handle stays open and
        // there is no temporary file and no rename.
        Err(_) => return Ok(OpenedFile::Direct { file: target }),
    };

    // The `!S_ISREG(sb.st_mode)` half of `:102`. `FileType::is_file` is that
    // macro: it tests `S_IFREG` and nothing else, so a FIFO, a socket, a
    // device node and a directory all take this branch.
    if !metadata.is_file() {
        return Ok(OpenedFile::Direct { file: target });
    }

    // ADDED, not the C's: an extra hard link to a credential store is refused.
    //
    // `st_nlink` is read from the same `fstat` as the mode, so this costs no
    // second syscall and no second race. A legitimate cookie jar has exactly
    // one name; a second link is how a writer of this directory keeps a copy
    // of the jar under a name the rename will not disturb. `StoreClass`
    // decides, because the Alt-Svc and HSTS caches hold nothing worth copying
    // and refusing would only turn an oddity into a failed command.
    //
    // The refusal happens before the temporary file is created, so nothing has
    // been written and there is nothing to unlink -- the same shape as the C's
    // `goto fail` before `fd` is valid.
    if class.rejects_extra_links() && metadata.nlink() > 1 {
        return Err(CURLcode::WriteError);
    }

    // `sb.st_mode`, read BEFORE the close because the descriptor is about to
    // go away. This is the full mode word, file-type bits included -- see
    // step 4, where that is deliberate rather than sloppy.
    let target_mode = metadata.mode();

    // `curlx_fclose(*fh);` at `:105` and `*fh = NULL;` at `:107`. The C closes
    // the target before generating the name, and the order is preserved: the
    // provider below is called with no descriptor held.
    drop(target);

    // ---- STEP 2 -------------------------------------------------------------
    //
    // `result = Curl_rand_alnum(data, randbuf, sizeof(randbuf));` at `:109`,
    // and `if(result) goto fail;` at `:110-111` -- the provider's code is
    // propagated unchanged, not remapped.
    let suffix = rand_suffix()?;

    // The C's `DEBUGASSERT(num > 1)` is the only check it makes on this, and
    // it is debug-only. These two are the same severity, and they exist
    // because the provider lives in a sibling directory: a drift in either the
    // length or the alphabet would otherwise show up only as a temporary file
    // with an unexpected name.
    debug_assert!(
        suffix.len() == RAND_SUFFIX_LEN,
        "the injected provider must return exactly {RAND_SUFFIX_LEN} \
         characters, as Curl_rand_alnum does; got {}",
        suffix.len()
    );
    debug_assert!(
        suffix.bytes().all(|byte| RAND_ALPHABET.contains(&byte)),
        "the injected provider must draw from RAND_ALPHABET"
    );

    // ---- STEP 3 -------------------------------------------------------------
    let temp_path =
        temp_name(filename, &suffix).map_err(|_| CURLcode::OutOfMemory)?;

    // ---- STEP 4 -------------------------------------------------------------
    //
    // `result = CURLE_WRITE_ERROR;` at `:126`, then
    // `fd = curlx_open(tempstore, O_WRONLY | O_CREAT | O_EXCL,
    //                  S_IRUSR | S_IWUSR | sb.st_mode);` at `:135-136`.
    //
    // `create_new(true)` is `O_CREAT | O_EXCL` exactly. It is the atomicity
    // and anti-symlink guarantee of the whole function: creation fails if the
    // name exists, so a collision and a planted symlink both become errors
    // instead of a silent write to somebody else's file.
    // `.create(true).truncate(true)` is `O_CREAT | O_TRUNC` and would lose
    // that, which is why it appears in step 1 and must never appear here.
    //
    // The mode is `StoreClass`'s decision, and the two arms differ:
    //
    //   * `StoreClass::Public` is `S_IRUSR | S_IWUSR | sb.st_mode` -- the C's
    //     expression, unchanged, so an Alt-Svc or HSTS cache keeps cloning
    //     whatever mode its target already had.
    //   * `StoreClass::Credential` is a flat `0o600`, ignoring `target_mode`.
    //     Cloning is precisely how a `0644` jar stays `0644` for ever: because
    //     step 1 CREATES a target that did not exist, `target_mode` on a
    //     first-ever save is whatever the creation mode produced, and under the
    //     C's `0o666` that is `0o666 & ~umask`, normally 0o644. Forcing the
    //     mode here also repairs a jar inherited from a C curl on its next
    //     save, which refusing to write it would not.
    //
    // Two properties hold for both arms:
    //
    //   * `target_mode` still carries `S_IFREG` (0o100000). `open(2)` ignores
    //     every bit outside the permission set, so a request of 0o100600 is
    //     effectively 0o600 -- measured, and the reason the word is passed
    //     through unmasked rather than anded with 0o777.
    //   * `open(2)` masks the request with the umask, and so does
    //     `OpenOptionsExt::mode`, because it is the same syscall with the same
    //     argument. Both arms are therefore ceilings; a umask can only remove
    //     bits, so `0o600` cannot become more permissive than it says.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(class.temp_mode(target_mode))
        .open(&temp_path)
        // `if(fd == -1) goto fail;`. `fd` is still -1 at that point, so the C
        // does NOT unlink -- and nothing was created, so there is nothing to
        // unlink.
        .map_err(|_| CURLcode::WriteError)?;

    // ---- STEP 5 -------------------------------------------------------------
    Ok(OpenedFile::Temp { file, temp_path })
}

/// Where a seek measures its offset from.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum Whence {
    /// `SEEK_SET`: from the start of the stream. A negative offset is invalid.
    Set = 0,

    /// `SEEK_CUR`: from the current position, in either direction.
    Cur = 1,

    /// `SEEK_END`: from the end of the stream, in either direction.
    End = 2,
}

#[allow(dead_code)]
impl Whence {
    /// Reads the `origin` integer a C caller supplies, or `None` if it names
    /// nothing.
    pub(crate) fn from_origin(origin: i32) -> Option<Self> {
        match origin {
            0 => Some(Self::Set),
            1 => Some(Self::Cur),
            2 => Some(Self::End),
            _ => None,
        }
    }

    /// The standard library's spelling of this origin, applied to `offset`.
    ///
    /// # Errors
    ///
    /// [`std::io::ErrorKind::InvalidInput`] for a negative offset from the
    /// start, which is what `fseeko(stream, -1, SEEK_SET)` reports as
    /// `EINVAL`. [`SeekFrom::Start`] takes a `u64` and so cannot express it,
    /// and casting would turn `-1` into an offset of sixteen exabytes -- a
    /// silent behaviour change of exactly the kind this port exists to avoid.
    fn seek_from(self, offset: i64) -> io::Result<SeekFrom> {
        match self {
            Self::Set => match u64::try_from(offset) {
                Ok(start) => Ok(SeekFrom::Start(start)),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a negative offset from the start of a stream",
                )),
            },
            Self::Cur => Ok(SeekFrom::Current(offset)),
            Self::End => Ok(SeekFrom::End(offset)),
        }
    }
}

/// Seeks `stream` to `offset`, measured from `whence`.
///
/// Supersedes `curlx_fseek` (`lib/curlx/fopen.c:28-39`), the only
/// cross-platform function in that file. The C is a three-branch preprocessor
/// ladder over a portability problem that does not exist in Rust:
///
/// ```text
/// #ifdef _WIN32
///   return _fseeki64(stream, (__int64)offset, whence);
/// #elif defined(HAVE_FSEEKO) && defined(HAVE_DECL_FSEEKO)
///   return fseeko(stream, (off_t)offset, whence);
/// #else
///   if(offset > LONG_MAX)
///     return -1;
///   return fseek(stream, (long)offset, whence);
/// #endif
/// ```
///
/// # Errors
///
/// Whatever [`Seek::seek`] reports, plus
/// [`std::io::ErrorKind::InvalidInput`] for a negative offset from the start.
/// An [`std::io::Result`] rather than a `CURLcode`, because the C returns a
/// bare 0 or -1 and leaves the interpretation to its callers:
/// `lib/mime.c:641-642` turns a non-zero return into
/// `CURL_SEEKFUNC_CANTSEEK`, which is a value from the public ABI and not a
/// `CURLcode` at all. Choosing a `CURLcode` here would put a code in the
/// caller's hands that the C never produced.
#[allow(dead_code)]
pub(crate) fn fseek<S: Seek>(
    stream: &mut S,
    offset: i64,
    whence: Whence,
) -> io::Result<u64> {
    stream.seek(whence.seek_from(offset)?)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{fseek, Whence};

    // -- the seek surface ---------------------------------------------------
    //
    // These need no filesystem at all: `io::Cursor` implements `Seek`, so the
    // whole of `curlx_fseek`'s behaviour is exercisable in memory and stays
    // visible under Miri. That is not a happy accident -- it is the reason a
    // generic over `Seek` was chosen instead of a function taking a `File`.

    /// The three integers are ABI-visible, so they are asserted, not assumed.
    ///
    /// `SEEK_SET`, `SEEK_CUR` and `SEEK_END` are 0, 1 and 2 on every platform
    /// curl builds for, and `curl_seek_callback` hands them to user code as an
    /// `int origin`. A reordering of this enumeration would compile silently
    /// and break every seek callback ever written against curl.
    #[test]
    fn whence_discriminants_are_the_c_seek_constants() {
        assert_eq!(Whence::Set as i32, 0, "SEEK_SET");
        assert_eq!(Whence::Cur as i32, 1, "SEEK_CUR");
        assert_eq!(Whence::End as i32, 2, "SEEK_END");
    }

    #[test]
    fn from_origin_accepts_exactly_the_three_c_constants() {
        assert_eq!(Whence::from_origin(0), Some(Whence::Set));
        assert_eq!(Whence::from_origin(1), Some(Whence::Cur));
        assert_eq!(Whence::from_origin(2), Some(Whence::End));
    }

    #[test]
    fn from_origin_rejects_everything_else() {
        for origin in [-1, 3, 4, 100, i32::MAX, i32::MIN] {
            assert_eq!(
                Whence::from_origin(origin),
                None,
                "{origin} names no SEEK_* constant"
            );
        }
    }

    #[test]
    fn seeking_from_the_start_positions_absolutely() {
        let mut stream = Cursor::new(vec![0_u8; 16]);
        assert_eq!(fseek(&mut stream, 5, Whence::Set).ok(), Some(5));
        assert_eq!(stream.position(), 5);
    }

    #[test]
    fn seeking_from_the_current_position_moves_in_both_directions() {
        let mut stream = Cursor::new(vec![0_u8; 16]);
        assert_eq!(fseek(&mut stream, 8, Whence::Set).ok(), Some(8));
        assert_eq!(fseek(&mut stream, 3, Whence::Cur).ok(), Some(11));
        assert_eq!(fseek(&mut stream, -6, Whence::Cur).ok(), Some(5));
    }

    #[test]
    fn seeking_from_the_end_accepts_a_negative_offset() {
        let mut stream = Cursor::new(vec![0_u8; 16]);
        assert_eq!(fseek(&mut stream, 0, Whence::End).ok(), Some(16));
        assert_eq!(fseek(&mut stream, -4, Whence::End).ok(), Some(12));
    }

    /// `fseeko(stream, -1, SEEK_SET)` reports `EINVAL`, and so does this.
    ///
    /// The alternative -- casting `-1` to a `u64` -- would seek to sixteen
    /// exabytes and report success, which is the class of silent behaviour
    /// change this port exists to avoid.
    #[test]
    fn seeking_to_a_negative_absolute_position_is_rejected() {
        let mut stream = Cursor::new(vec![0_u8; 16]);
        let outcome = fseek(&mut stream, -1, Whence::Set);

        assert!(outcome.is_err(), "a negative absolute position is invalid");
        assert_eq!(
            outcome.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::InvalidInput)
        );
        assert_eq!(stream.position(), 0, "a rejected seek moves nothing");
    }

    /// Seeking past the end is legal, exactly as it is for `fseeko`.
    #[test]
    fn seeking_past_the_end_is_permitted() {
        let mut stream = Cursor::new(vec![0_u8; 4]);
        assert_eq!(fseek(&mut stream, 4096, Whence::Set).ok(), Some(4096));
    }

    /// The whole point of the `#ifdef` ladder this replaced.
    ///
    /// `_fseeki64` existed because Windows' `fseek` took a 32-bit offset, and
    /// the third branch guarded on `LONG_MAX` for the same reason. `Seek` is
    /// 64-bit everywhere, so an offset of 2^40 -- far past any 32-bit `long`
    /// -- round-trips with no special case.
    #[test]
    fn seeking_spans_the_full_sixty_four_bit_range() {
        let mut stream = Cursor::new(Vec::new());
        let far = 1_i64 << 40;

        assert_eq!(fseek(&mut stream, far, Whence::Set).ok(), Some(1 << 40));
        assert!(
            far > i64::from(i32::MAX),
            "the probe offset must exceed a 32-bit long to prove anything"
        );
    }

    // -- the atomic-replace surface -----------------------------------------
    //
    // Behind the same gate its items carry, for the same reason: these tests
    // name `open_for_write` and `dirslash`, which do not exist when all three
    // state-file features are off.
    #[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
    mod state_files {
        use std::cell::Cell;
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::path::{Path, PathBuf};

        use super::super::{
            dirslash, open_for_write, temp_name, NoFollow, OpenedFile,
            StoreClass, RAND_ALPHABET, RAND_SUFFIX_LEN,
        };
        use crate::error::{CURLcode, CodeResult};

        /// Binds a scratch directory, failing the test loudly if the
        /// environment cannot provide one.
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

        /// `O_NOFOLLOW | O_CLOEXEC`, spelled here because the tests cannot
        /// import them either.
        ///
        /// The production callers take these from `crate::ffi`, which is the
        /// one directory allowed to name `libc`. This module may not, and
        /// neither may its test module, so the two numbers are written out --
        /// and they are the *only* hard-coded platform constants in this file.
        ///
        /// A wrong value here would be caught rather than tolerated:
        /// [`a_symlinked_target_is_refused`] passes only if the flag really is
        /// `O_NOFOLLOW` on the host, and
        /// [`the_guard_is_what_refuses_a_symlink`] pins the converse by
        /// repeating the same open with [`NoFollow::DISABLED`] and observing
        /// that it succeeds. So the constants are validated by behaviour rather
        /// than trusted.
        #[cfg(target_os = "linux")]
        const GUARD_FLAGS: i32 = 0o400_000 | 0o2_000_000;
        /// The macOS spellings of the same two flags.
        #[cfg(target_os = "macos")]
        const GUARD_FLAGS: i32 = 0x0100 | 0x0100_0000;

        /// The guard every test passes unless it is specifically testing its
        /// absence.
        fn guard() -> NoFollow {
            NoFollow::new(GUARD_FLAGS)
        }

        /// A deterministic stand-in for `Curl_rand_alnum`.
        fn fixed_suffix(seed: usize) -> String {
            RAND_ALPHABET
                .iter()
                .cycle()
                .skip(seed % RAND_ALPHABET.len())
                .take(RAND_SUFFIX_LEN)
                .map(|byte| char::from(*byte))
                .collect()
        }

        /// The permission bits of `path`, or `None` if it cannot be stat'ed.
        fn mode_of(path: &Path) -> Option<u32> {
            fs::metadata(path).ok().map(|meta| meta.mode() & 0o7777)
        }

        /// The size of `path`, or `None` if it cannot be stat'ed.
        ///
        /// Not named `size_of`: `core::mem::size_of` reached the standard
        /// prelude in Rust 1.80, and a local function of that name would
        /// shadow it silently for every later reader of this module.
        fn len_of(path: &Path) -> Option<u64> {
            fs::metadata(path).ok().map(|meta| meta.len())
        }

        /// Unwraps an [`open_for_write`] result, reporting the code.
        ///
        /// A function rather than a `let ... else`, because the scrutinee of a
        /// `let ... else` is moved into the pattern and so cannot be named in
        /// the diverging arm -- which is exactly where the code is wanted.
        fn opened(outcome: CodeResult<OpenedFile>) -> OpenedFile {
            match outcome {
                Ok(file) => file,
                Err(code) => panic!("the open should have succeeded: {code:?}"),
            }
        }

        /// The same, additionally insisting on the temporary-file variant.
        fn temp_parts(outcome: CodeResult<OpenedFile>) -> (fs::File, PathBuf) {
            match opened(outcome) {
                OpenedFile::Temp { file, temp_path } => (file, temp_path),
                OpenedFile::Direct { .. } => {
                    panic!("a regular file takes the temporary path")
                }
            }
        }

        /// The mode a freshly created file gets in `dir`: `0o666 & ~umask`.
        fn default_creation_mode(dir: &Path) -> Option<u32> {
            let probe = dir.join("umask-probe");
            drop(fs::File::create(&probe).ok()?);
            let mode = mode_of(&probe);
            let _ = fs::remove_file(&probe);
            mode
        }

        /// Writes `contents` to `path`, failing the test if it cannot.
        fn seed_file(path: &Path, contents: &[u8]) {
            let written = fs::write(path, contents);
            assert!(
                written.is_ok(),
                "the test could not seed {}: {:?}",
                path.display(),
                written.err()
            );
        }

        // -- dirslash, the sixteen measured rows ----------------------------

        /// Every row of the table in the module documentation, asserted.
        #[test]
        fn dirslash_reproduces_every_measured_row() {
            let rows: &[(&[u8], &[u8])] = &[
                // The ordinary cases.
                (b"/a/b/c", b"/a/b/"),
                (b"a/b", b"a/"),
                (b"./x", b"./"),
                (b"../x", b"../"),
                // A run of separators before the filename collapses to one,
                // and an interior run is left alone.
                (b"/a//b//c", b"/a//b/"),
                // An empty filename part: the first scan does not move.
                (b"/a/b/", b"/a/b/"),
                (b"a/", b"a/"),
                (b"dir/", b"dir/"),
                // No directory component at all.
                (b"c", b""),
                (b"x.txt", b""),
                (b"", b""),
                // THE CORRECTION. The second scan consumes the leading
                // separator and drives the index to zero, so the trailing
                // separator is never appended and the root is NOT preserved.
                (b"/c", b""),
                (b"//c", b""),
                (b"/", b""),
                (b"//", b""),
                // A backslash is an ordinary filename byte on the four
                // mandated targets: the `_WIN32` branch of `IS_SEP` is out of
                // scope.
                (b"a\\b", b""),
            ];

            assert_eq!(rows.len(), 16, "all sixteen measured inputs");

            for (input, expected) in rows {
                assert_eq!(
                    dirslash(input).as_deref(),
                    Ok(*expected),
                    "dirslash({:?})",
                    String::from_utf8_lossy(input)
                );
            }
        }

        /// The empty result is a value, not a failure.
        #[test]
        fn dirslash_returns_an_empty_value_rather_than_an_error() {
            let outcome = dirslash(b"jar.txt");

            assert!(outcome.is_ok(), "no directory component is not an error");
            assert_eq!(outcome.as_deref(), Ok(&b""[..]));
        }

        /// A path that is not UTF-8 survives byte for byte.
        ///
        /// The C takes a `const char *` and never inspects encoding. A
        /// conversion through `str` would refuse this input or replace bytes
        /// in it; the byte view does neither.
        #[test]
        fn dirslash_is_indifferent_to_encoding() {
            let input: &[u8] = &[0x2F, 0xFF, 0xFE, 0x2F, 0x80];
            assert_eq!(
                dirslash(input).as_deref(),
                Ok(&[0x2F, 0xFF, 0xFE, 0x2F][..]),
                "invalid UTF-8 passes through unchanged"
            );
        }

        // -- the CURL_MAX_INPUT_LENGTH ceiling ------------------------------

        /// A directory component past the ceiling is the C's `NULL`.
        #[test]
        #[cfg_attr(miri, ignore = "an eight-megabyte path is far too slow")]
        fn dirslash_rejects_a_directory_component_past_the_ceiling() {
            // The run of eight million and one bytes becomes the directory
            // component once the separator and the filename are stripped, so
            // the very first append crosses the ceiling.
            let mut path = vec![b'x'; 8_000_001];
            path.push(b'/');
            path.push(b'f');

            assert_eq!(
                dirslash(&path),
                Err(CURLcode::TooLarge),
                "the ceiling is CURL_MAX_INPUT_LENGTH, lib/urldata.h:131"
            );
        }

        /// The largest directory component that does fit, to the byte.
        #[test]
        #[cfg_attr(miri, ignore = "an eight-megabyte path is far too slow")]
        fn dirslash_accepts_a_directory_component_at_the_ceiling() {
            // 7,999,998 bytes plus the one separator this function appends is
            // 7,999,999, which is the most the buffer admits.
            let mut path = vec![b'x'; 7_999_998];
            path.push(b'/');
            path.push(b'f');

            let outcome = dirslash(&path);
            assert!(outcome.is_ok(), "7,999,999 bytes must fit");
            assert_eq!(outcome.map(|dir| dir.len()), Ok(7_999_999));
        }

        // -- temp_name ------------------------------------------------------

        /// The name is `<directory><forty characters>.tmp`, in that order.
        #[test]
        fn the_temporary_name_is_composed_in_the_c_order() {
            let suffix = fixed_suffix(0);
            let composed = temp_name(Path::new("/var/tmp/jar.txt"), &suffix);

            assert_eq!(
                composed,
                Ok(PathBuf::from(format!("/var/tmp/{suffix}.tmp"))),
                "dirslash output, then the suffix, then .tmp"
            );
        }

        /// An empty directory component leaves the name relative.
        #[test]
        fn an_empty_directory_component_yields_a_relative_name() {
            let suffix = fixed_suffix(1);

            for target in ["jar.txt", "/jar.txt", "//jar.txt"] {
                let composed = temp_name(Path::new(target), &suffix);

                assert_eq!(
                    composed,
                    Ok(PathBuf::from(format!("{suffix}.tmp"))),
                    "{target} has no directory component"
                );
                assert!(
                    composed.as_ref().is_ok_and(|path| path.is_relative()),
                    "{target} yields a name relative to the working directory"
                );
            }
        }

        /// The suffix is forty characters, so the name is forty-four.
        ///
        /// The corrected count. `unsigned char randbuf[41]` is a buffer of 41
        /// bytes holding a string of 40 characters and a terminator.
        #[test]
        fn the_random_component_is_forty_characters() {
            let suffix = fixed_suffix(0);

            assert_eq!(RAND_SUFFIX_LEN, 40, "not 41 -- lib/rand.c:269");
            assert_eq!(suffix.len(), 40, "the test provider honours it");

            let composed = temp_name(Path::new("/d/jar"), &suffix);
            let name = composed
                .as_ref()
                .ok()
                .and_then(|path| path.file_name())
                .map(|name| name.to_string_lossy().into_owned());

            assert_eq!(name.as_deref().map(str::len), Some(44), "40 + .tmp");
            assert_eq!(name.as_deref(), Some(format!("{suffix}.tmp").as_str()));
        }

        /// The alphabet is the 62 characters of `alnum[]`, in the C's order.
        #[test]
        fn the_alphabet_matches_lib_rand_c() {
            assert_eq!(RAND_ALPHABET.len(), 62, "alnumspace at lib/rand.c:265");

            // The alphabet is pure ASCII, so comparing it as text is exact,
            // and a line-continued literal -- which drops the newline and
            // the following indentation -- keeps the expectation inside the
            // workspace's 80-column budget. A single 62-byte byte-string
            // token cannot be wrapped by `rustfmt` and would overrun it.
            assert_eq!(
                core::str::from_utf8(RAND_ALPHABET).ok(),
                Some(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                     abcdefghijklmnopqrstuvwxyz\
                     0123456789"
                )
            );

            let uppers =
                RAND_ALPHABET.iter().filter(|b| b.is_ascii_uppercase());
            let lowers =
                RAND_ALPHABET.iter().filter(|b| b.is_ascii_lowercase());
            let digits = RAND_ALPHABET.iter().filter(|b| b.is_ascii_digit());
            assert_eq!(uppers.count(), 26);
            assert_eq!(lowers.count(), 26);
            assert_eq!(digits.count(), 10);
        }

        /// The rejection threshold the provider has to use, arithmetic and all.
        ///
        /// `while(r >= (UINT_MAX - UINT_MAX % alnumspace))` at
        /// `lib/rand.c:277`. Recorded as an assertion rather than as prose
        /// because the number is what makes the draw unbiased, and the
        /// provider lives in another directory.
        #[test]
        fn the_rejection_threshold_is_four_billion_two_hundred_ninety_four() {
            let space = u32::try_from(RAND_ALPHABET.len());
            assert_eq!(space, Ok(62));

            let threshold = u32::MAX - u32::MAX % 62;
            assert_eq!(u32::MAX % 62, 3, "4294967295 mod 62");
            assert_eq!(threshold, 4_294_967_292);
            assert_eq!(
                u32::MAX - threshold + 1,
                4,
                "exactly four values are discarded"
            );
        }

        // -- open_for_write, the ordinary path ------------------------------

        /// A target that does not exist yields a temporary, and a placeholder.
        ///
        /// Three things at once, because they are one behaviour: step one
        /// CREATES the missing target, so afterwards the target exists and is
        /// empty, and the temporary file exists beside it under the injected
        /// name.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn a_missing_target_gains_a_placeholder_and_a_temporary() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");
            let suffix = fixed_suffix(0);
            let expected = dir.path().join(format!("{suffix}.tmp"));

            let (file, temp_path) = temp_parts(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(suffix.clone()),
            ));
            drop(file);

            assert_eq!(temp_path, expected, "the name lands beside the target");
            assert_eq!(len_of(&temp_path), Some(0), "nothing written yet");
            assert_eq!(
                len_of(&target),
                Some(0),
                "step one created the target as an empty placeholder"
            );
        }

        /// The temporary file is created in the TARGET's directory.
        ///
        /// Not in the working directory, and not in a system temporary
        /// directory: the rename that follows has to be on the same filesystem
        /// as the target, which is the whole reason `dirslash` exists.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn the_temporary_file_sits_next_to_the_target() {
            scratch!(dir);
            let nested = dir.path().join("state");
            assert!(fs::create_dir(&nested).is_ok(), "the test needs a subdir");
            let target = nested.join("hsts.txt");

            let file = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(2)),
            ));

            let parent = file.temp_path().and_then(Path::parent);
            assert_eq!(parent, Some(nested.as_path()));
            file.discard();
        }

        // -- the truncation the C performs and this module does not ---------

        /// The target keeps its contents until the rename replaces them.
        ///
        /// A DELIBERATE DIVERGENCE from `lib/curl_fopen.c:99`, which opens the
        /// target with `FOPEN_WRITETEXT` -- `"w"`, and therefore `O_TRUNC` --
        /// and so destroys the previous contents before the mode is even read.
        /// The module documentation's hardening section argues it; this test is
        /// what holds it.
        ///
        /// Two properties, and the second is the one that matters:
        ///
        /// 1. The target still holds its old bytes while the temporary file is
        ///    open, so a save that fails leaves the previous state file intact
        ///    rather than empty.
        /// 2. Nothing was written *through* the target handle. That is the whole
        ///    of CWE-22 here: `O_TRUNC` on a name somebody else chose is a
        ///    destructive primitive they aim, and a curl running with more
        ///    privilege than they have empties the file on their behalf.
        ///
        /// The inverse of this test used to exist and asserted `Some(0)`. It was
        /// not wrong about the C; it pinned a defect. It is replaced rather than
        /// deleted, and this paragraph is the record of that.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn the_target_is_not_truncated_before_anything_is_written() {
            scratch!(dir);
            let target = dir.path().join("altsvc.txt");
            seed_file(&target, b"old contents");
            assert_eq!(len_of(&target), Some(12), "the seed is in place");

            let file = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(3)),
            ));

            assert!(file.needs_rename(), "a regular file takes the temp path");
            assert_eq!(
                len_of(&target),
                Some(12),
                "the previous contents survive until the rename -- no O_TRUNC"
            );
            assert_eq!(
                file.temp_path().and_then(len_of),
                Some(0),
                "and the temporary file is empty, not a copy"
            );

            // The failure path is why this matters: discarding leaves the old
            // state file exactly as it was.
            file.discard();
            assert_eq!(
                len_of(&target),
                Some(12),
                "a failed save no longer destroys the previous state file"
            );
        }

        // -- the cloned mode, for a PUBLIC store ---------------------------

        /// A public store's temporary file is `0o600` unioned with the target's.
        ///
        /// The C's expression, `S_IRUSR | S_IWUSR | sb.st_mode`, reproduced
        /// exactly -- and it is [`StoreClass::Public`] that keeps it. Two
        /// pre-existing modes, because one would not distinguish "cloned" from
        /// "always 0o600". `0o640` is the interesting one: the group-read bit is
        /// PRESERVED here, which is correct for an Alt-Svc or HSTS cache and is
        /// exactly what [`a_credential_store_never_clones_a_permissive_mode`]
        /// asserts does *not* happen to a cookie jar.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn the_temporary_file_clones_the_targets_mode() {
            for (seeded, expected) in [(0o600_u32, 0o600_u32), (0o640, 0o640)] {
                scratch!(dir);
                let target = dir.path().join("jar.txt");
                seed_file(&target, b"x");
                let set = fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(seeded),
                );
                assert!(set.is_ok(), "the test needs to set mode {seeded:o}");
                assert_eq!(mode_of(&target), Some(seeded), "seeded mode");

                let file = opened(open_for_write(
                    &target,
                    StoreClass::Public,
                    guard(),
                    || Ok(fixed_suffix(4)),
                ));

                assert_eq!(
                    file.temp_path().and_then(mode_of),
                    Some(expected),
                    "S_IRUSR | S_IWUSR | sb.st_mode, with S_IFREG ignored"
                );
                file.discard();
            }
        }

        /// A first-ever PUBLIC save ends up at the umask-derived mode.
        ///
        /// Because step one CREATES a target that did not exist, `sb.st_mode`
        /// is whatever the creation mode produced -- for
        /// [`StoreClass::Public`] that is the C's `0o666 & ~umask`, typically
        /// `0o644` -- and the union with `0o600` changes nothing. So an Alt-Svc
        /// or HSTS cache is group- and world-readable, which is upstream
        /// behaviour and is deliberately kept: neither file holds a secret.
        ///
        /// The credential store is the one that had to change, and
        /// [`a_first_ever_credential_store_is_private`] is its counterpart.
        ///
        /// The expectation is measured from the process's actual umask rather
        /// than written as `0o644`, so the test says something true on a
        /// machine configured differently.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn a_first_ever_save_takes_the_umask_derived_mode() {
            scratch!(dir);
            let Some(fresh) = default_creation_mode(dir.path()) else {
                panic!("the test needs to measure the umask");
            };
            let target = dir.path().join("cookies.txt");

            let file = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(5)),
            ));

            assert_eq!(
                file.temp_path().and_then(mode_of),
                Some(0o600 | fresh),
                "0o600 unioned with what a plain create just produced"
            );
            assert_eq!(
                mode_of(&target),
                Some(fresh),
                "and the placeholder itself is plain fopen's mode"
            );
            file.discard();
        }

        // -- the credential store's private mode (M-16) --------------------

        /// A cookie jar that did not previously exist is created `0600`.
        ///
        /// The counterpart of
        /// [`a_first_ever_save_takes_the_umask_derived_mode`], and the reason
        /// [`StoreClass`] exists. Both the temporary file the jar is written
        /// into and the placeholder step one creates are private, so at no
        /// point between the open and the rename is there a readable file at
        /// either name.
        ///
        /// The assertion is a literal `0o600` rather than a umask-derived
        /// value, and that is the point: `OpenOptionsExt::mode` is a ceiling
        /// that the umask can only narrow, so `0o600` is what a jar gets on any
        /// machine. A umask of `0o077` would still produce `0o600`; a umask of
        /// `0o777` would produce `0o000`, which is unreadable rather than
        /// over-shared, so the direction of any surprise is safe.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn a_first_ever_credential_store_is_private() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");

            let file = opened(open_for_write(
                &target,
                StoreClass::Credential,
                guard(),
                || Ok(fixed_suffix(19)),
            ));

            assert_eq!(
                file.temp_path().and_then(mode_of),
                Some(0o600),
                "the jar is written into a file no other local user can read"
            );
            assert_eq!(
                mode_of(&target),
                Some(0o600),
                "and the placeholder step one created is private too"
            );

            // And the mode survives the rename, which is what the user ends up
            // with. `commit` consumes the handle, so this is the last step.
            let committed = file.commit(&target);
            assert!(committed.is_ok(), "the rename must succeed");
            assert_eq!(
                mode_of(&target),
                Some(0o600),
                "the finished jar is 0600 -- the whole point of the class"
            );
        }

        /// A jar inherited at `0644` is repaired, not cloned forward.
        ///
        /// This is the case the C cannot escape: it clones `sb.st_mode`, so a
        /// jar created world-readable once stays world-readable for every
        /// subsequent save. `StoreClass::Credential` ignores the target's mode
        /// entirely, so the next save fixes it.
        ///
        /// Repairing rather than refusing is deliberate. Refusing to write a
        /// jar the user asked for would fail their command, which is CLI
        /// behaviour that AAP 0.8.1 freezes; forcing the mode costs them
        /// nothing and closes the exposure. `0o640` is included because a
        /// group-readable jar is the case a `umask 027` machine produces, and
        /// it is exactly the mode
        /// [`the_temporary_file_clones_the_targets_mode`] proves a *public*
        /// store still preserves.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn a_credential_store_never_clones_a_permissive_mode() {
            for inherited in [0o644_u32, 0o640, 0o666, 0o604] {
                scratch!(dir);
                let target = dir.path().join("cookies.txt");
                seed_file(&target, b"# Netscape HTTP Cookie File\n");
                let set = fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(inherited),
                );
                assert!(set.is_ok(), "the test needs mode {inherited:o}");
                assert_eq!(mode_of(&target), Some(inherited), "seeded");

                let file = opened(open_for_write(
                    &target,
                    StoreClass::Credential,
                    guard(),
                    || Ok(fixed_suffix(20)),
                ));

                assert_eq!(
                    file.temp_path().and_then(mode_of),
                    Some(0o600),
                    "a jar inherited at {inherited:o} is rewritten at 0600"
                );
                file.discard();
            }
        }

        // -- the symlink guard (M-15) --------------------------------------

        /// A symlinked final component is refused outright.
        ///
        /// CWE-59. `O_NOFOLLOW` arrives as [`NoFollow`] because this module may
        /// not name `libc`; this test is also what validates that the injected
        /// number really is `O_NOFOLLOW` on the host, since a wrong value would
        /// let the open succeed and fail this assertion.
        ///
        /// The refusal is `CURLcode::WriteError`, which is what the C reports
        /// for every other reason the target will not open, so no caller learns
        /// a distinction it did not previously have.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses symlink")]
        fn a_symlinked_target_is_refused() {
            for class in [StoreClass::Public, StoreClass::Credential] {
                scratch!(dir);
                let victim = dir.path().join("victim.txt");
                seed_file(&victim, b"data an attacker cannot write");
                let link = dir.path().join("cookies.txt");
                let made = std::os::unix::fs::symlink(&victim, &link).is_ok();
                assert!(made, "the test needs to plant a symlink");

                let outcome = open_for_write(&link, class, guard(), || {
                    panic!("the provider must not be reached")
                });

                assert_eq!(
                    outcome.err(),
                    Some(CURLcode::WriteError),
                    "{class:?}: a symlinked target must not be opened"
                );
                assert_eq!(
                    len_of(&victim),
                    Some(29),
                    "{class:?}: and the link's target is untouched"
                );
            }
        }

        /// The guard is what refuses it -- the converse, so the test is not
        /// passing for an unrelated reason.
        ///
        /// With [`NoFollow::DISABLED`] the very same open succeeds, which
        /// proves the refusal above comes from the flag rather than from the
        /// scratch directory, the class or the provider. It also documents
        /// precisely what the C does here, since the C passes no such flag.
        ///
        /// Even unguarded, the victim is **not truncated**: that is the
        /// `O_TRUNC` removal doing its own half of the work, and it is why the
        /// two mitigations are independent rather than redundant.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses symlink")]
        fn the_guard_is_what_refuses_a_symlink() {
            scratch!(dir);
            let victim = dir.path().join("victim.txt");
            seed_file(&victim, b"data an attacker cannot write");
            let link = dir.path().join("cookies.txt");
            assert!(
                std::os::unix::fs::symlink(&victim, &link).is_ok(),
                "the test needs to plant a symlink"
            );

            let file = opened(open_for_write(
                &link,
                StoreClass::Public,
                NoFollow::DISABLED,
                || Ok(fixed_suffix(21)),
            ));

            assert!(
                file.needs_rename(),
                "unguarded, the link resolves to a regular file"
            );
            assert_eq!(
                len_of(&victim),
                Some(29),
                "and even then O_TRUNC's removal keeps the victim intact"
            );
            file.discard();
        }

        /// An extra hard link to a credential store is refused; a public store
        /// tolerates one.
        ///
        /// A second name for a cookie jar is not something a user creates. It
        /// is what a writer of the output directory leaves behind so that a
        /// copy of the jar survives under a name the rename will not disturb --
        /// the rename replaces one link, and the other keeps whatever the file
        /// held.
        ///
        /// The Alt-Svc and HSTS caches are exempt because there is nothing in
        /// them worth copying, and refusing would turn an oddity into a failed
        /// command. Both halves are asserted, because a check that fired for
        /// every class would be a behaviour change nobody asked for.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn an_extra_hard_link_is_refused_only_for_a_credential_store() {
            for (class, tolerated) in
                [(StoreClass::Public, true), (StoreClass::Credential, false)]
            {
                scratch!(dir);
                let target = dir.path().join("store.txt");
                seed_file(&target, b"x");
                let second = dir.path().join("attacker-holds-this");
                assert!(
                    fs::hard_link(&target, &second).is_ok(),
                    "the test needs a second link"
                );

                let outcome = open_for_write(&target, class, guard(), || {
                    Ok(fixed_suffix(22))
                });

                if tolerated {
                    let file = opened(outcome);
                    assert!(
                        file.needs_rename(),
                        "{class:?}: an extra link is not this class's concern"
                    );
                    file.discard();
                } else {
                    assert_eq!(
                        outcome.err(),
                        Some(CURLcode::WriteError),
                        "{class:?}: an extra link must refuse the save"
                    );
                }
            }
        }

        /// `--cookie-jar /dev/null` still works, class notwithstanding.
        ///
        /// The one behaviour the hardening most plausibly threatened, asserted
        /// for the credential class specifically. `/dev/null` is a character
        /// device and **not** a symbolic link -- measured, `crw-rw-rw-` -- so
        /// `O_NOFOLLOW` lets it through, and the `S_ISREG` test then routes it
        /// to the early-success path exactly as `lib/curl_fopen.c:102-104`
        /// does. Discarding cookies is a legitimate request and it still
        /// succeeds.
        #[test]
        #[cfg_attr(miri, ignore = "Miri does not model /dev/null")]
        fn a_credential_store_at_dev_null_still_writes_directly() {
            let called = Cell::new(false);

            let file = opened(open_for_write(
                Path::new("/dev/null"),
                StoreClass::Credential,
                guard(),
                || {
                    called.set(true);
                    Ok(fixed_suffix(23))
                },
            ));

            assert!(!file.needs_rename(), "a device takes the direct path");
            assert!(!called.get(), "and no temporary name was ever generated");
            file.discard();
        }

        // -- the early-success path ----------------------------------------

        /// A target that is not a regular file is written directly.
        #[test]
        #[cfg_attr(miri, ignore = "Miri does not model /dev/null")]
        fn a_character_device_is_written_directly() {
            let called = Cell::new(false);

            let file = opened(open_for_write(
                Path::new("/dev/null"),
                StoreClass::Public,
                guard(),
                || {
                    called.set(true);
                    Ok(fixed_suffix(6))
                },
            ));

            assert!(!file.needs_rename(), "no rename for a device node");
            assert_eq!(file.temp_path(), None, "*tempname stays NULL");
            assert!(
                !called.get(),
                "the C returns at :103, before Curl_rand_alnum at :109"
            );
            assert!(matches!(file, OpenedFile::Direct { .. }));
        }

        /// The direct handle is genuinely writable, not merely returned.
        #[test]
        #[cfg_attr(miri, ignore = "Miri does not model /dev/null")]
        fn the_direct_handle_accepts_writes() {
            let mut file = opened(open_for_write(
                Path::new("/dev/null"),
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(7)),
            ));

            assert!(
                file.file_mut().write_all(b"# Your HSTS cache.\n").is_ok(),
                "the caller writes straight through"
            );
            assert!(
                file.commit(Path::new("/dev/null")).is_ok(),
                "committing a Direct file closes it and renames nothing"
            );
        }

        /// A FIFO takes the same path, which is the case a device cannot prove.
        ///
        /// Two environmental dependencies, both handled by reporting a gap
        /// rather than by failing, because the property under test belongs to
        /// this module and not to the environment:
        ///
        /// * `mkfifo(1)`, because creating a FIFO otherwise would need `libc`,
        ///   which this module does not import.
        /// * Opening the read end with `O_RDWR`, which never blocks on Linux
        ///   (`fifo(7)` says so explicitly) and does not block on the BSD-
        ///   derived Apple targets either. The plain read-only open the
        ///   intuition reaches for would deadlock against the write-only open
        ///   under test, since each waits for the other.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn a_fifo_is_written_directly_too() {
            scratch!(dir);
            let fifo = dir.path().join("jar.fifo");

            match std::process::Command::new("mkfifo").arg(&fifo).status() {
                Ok(status) if status.success() => {}
                _ => {
                    eprintln!("gap: mkfifo(1) unusable, FIFO case unproven");
                    return;
                }
            }

            let holder =
                fs::OpenOptions::new().read(true).write(true).open(&fifo);
            let Ok(holder) = holder else {
                eprintln!("gap: the FIFO refused O_RDWR, case unproven");
                return;
            };

            let called = Cell::new(false);
            let file = opened(open_for_write(
                &fifo,
                StoreClass::Public,
                guard(),
                || {
                    called.set(true);
                    Ok(fixed_suffix(8))
                },
            ));

            assert!(!file.needs_rename(), "S_ISREG is false for a FIFO");
            assert_eq!(file.temp_path(), None, "*tempname stays NULL");
            assert!(!called.get(), "and the provider is never reached");
            drop(holder);
        }

        // -- O_EXCL, the atomicity guarantee --------------------------------

        /// A name that already exists is refused, and left untouched.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn an_existing_temporary_name_is_refused_and_not_overwritten() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");
            seed_file(&target, b"jar");
            let suffix = fixed_suffix(9);

            // The name step four is about to try, computed the same way.
            let Ok(collision) = temp_name(&target, &suffix) else {
                panic!("the test needs to predict the temporary name");
            };
            seed_file(&collision, b"someone else was here first");

            let outcome =
                open_for_write(&target, StoreClass::Public, guard(), || {
                    Ok(suffix.clone())
                });

            assert_eq!(
                outcome.err(),
                Some(CURLcode::WriteError),
                "O_EXCL turns the collision into CURLE_WRITE_ERROR"
            );
            assert_eq!(
                fs::read(&collision).ok().as_deref(),
                Some(&b"someone else was here first"[..]),
                "and the existing file is untouched"
            );
        }

        // -- commit and discard --------------------------------------------

        /// The whole save, end to end: write, commit, read back.
        ///
        /// This is `lib/hsts.c:349-368` in miniature, and it is the assertion
        /// that the two halves of this module actually compose.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn committing_renames_the_temporary_over_the_target() {
            scratch!(dir);
            let target = dir.path().join("hsts.txt");
            seed_file(&target, b"stale");

            let mut file = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(10)),
            ));
            let Some(temp_path) = file.temp_path().map(Path::to_path_buf)
            else {
                panic!("a regular file takes the temporary path");
            };
            assert!(file.file_mut().write_all(b"# Your HSTS cache.\n").is_ok());

            assert_eq!(file.commit(&target), Ok(()), "the rename succeeds");

            assert_eq!(
                fs::read(&target).ok().as_deref(),
                Some(&b"# Your HSTS cache.\n"[..]),
                "the target now holds what was written to the temporary"
            );
            assert!(!temp_path.exists(), "and the temporary name is gone");
        }

        /// A failed rename reports `CURLE_WRITE_ERROR` and cleans up.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn a_failed_commit_reports_a_write_error_and_removes_the_temporary() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");

            let file = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(11)),
            ));
            let Some(temp_path) = file.temp_path().map(Path::to_path_buf)
            else {
                panic!("a regular file takes the temporary path");
            };
            let unreachable =
                dir.path().join("no-such-dir").join("cookies.txt");

            assert_eq!(
                file.commit(&unreachable),
                Err(CURLcode::WriteError),
                "every rename failure is CURLE_WRITE_ERROR, with no finer kind"
            );
            assert!(
                !temp_path.exists(),
                "the temporary file is removed on the way out"
            );
        }

        /// `discard` is the consumers' `unlink(tempstore)`, written once.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn discarding_removes_the_temporary_and_leaves_the_target() {
            scratch!(dir);
            let target = dir.path().join("altsvc.txt");

            let file = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(12)),
            ));
            let Some(temp_path) = file.temp_path().map(Path::to_path_buf)
            else {
                panic!("a regular file takes the temporary path");
            };
            assert!(temp_path.exists(), "the temporary file exists first");

            file.discard();

            assert!(!temp_path.exists(), "and is gone afterwards");
            assert_eq!(
                len_of(&target),
                Some(0),
                "the placeholder step one created is NOT removed -- the C's \
                 unlink names only tempstore"
            );
        }

        /// Discarding a `Direct` file must not remove the target.
        ///
        /// The target on that path is the device node or FIFO the user named,
        /// and removing it would be a great deal worse than an abandoned
        /// temporary file.
        #[test]
        #[cfg_attr(miri, ignore = "Miri does not model /dev/null")]
        fn discarding_a_direct_file_removes_nothing() {
            let file = opened(open_for_write(
                Path::new("/dev/null"),
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(13)),
            ));

            file.discard();

            assert!(
                Path::new("/dev/null").exists(),
                "the device node survives being discarded"
            );
        }

        // -- the error ladder ----------------------------------------------

        /// Step one failing is `CURLE_WRITE_ERROR`, the initialised default.
        ///
        /// Provoked with a parent directory that does not exist, which is
        /// `ENOENT` for every process regardless of privilege -- unlike a mode
        /// change, which a container's root user simply ignores.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn an_unopenable_target_is_a_write_error() {
            scratch!(dir);
            let target = dir.path().join("no-such-dir").join("cookies.txt");
            let called = Cell::new(false);

            let outcome =
                open_for_write(&target, StoreClass::Public, guard(), || {
                    called.set(true);
                    Ok(fixed_suffix(14))
                });

            assert_eq!(outcome.err(), Some(CURLcode::WriteError));
            assert!(!called.get(), "the C never reaches :109 from here");
        }

        /// A directory as the target fails at step one, for the same code.
        ///
        /// `fopen(dir, "w")` is `EISDIR`. Worth its own assertion because a
        /// directory *does* stat successfully, so an implementation that had
        /// reordered the open and the stat would take the early-success path
        /// here and hand the caller a handle it cannot write to.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn a_directory_as_the_target_is_a_write_error() {
            scratch!(dir);

            let outcome =
                open_for_write(dir.path(), StoreClass::Public, guard(), || {
                    Ok(fixed_suffix(15))
                });

            assert_eq!(outcome.err(), Some(CURLcode::WriteError));
        }

        /// A directory with no write permission is a `CURLE_WRITE_ERROR`.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn an_unwritable_directory_is_a_write_error() {
            scratch!(dir);
            let locked = dir.path().join("locked");
            assert!(fs::create_dir(&locked).is_ok(), "the test needs a subdir");
            let set =
                fs::set_permissions(&locked, fs::Permissions::from_mode(0o500));
            assert!(set.is_ok(), "the test needs to drop the write bit");

            let bypassed = fs::File::create(locked.join("dac-probe")).is_ok();
            let outcome = open_for_write(
                &locked.join("cookies.txt"),
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(16)),
            );

            let restored =
                fs::set_permissions(&locked, fs::Permissions::from_mode(0o700));
            assert!(
                restored.is_ok(),
                "the scratch directory must be removable"
            );

            if bypassed {
                eprintln!("gap: this process ignores directory modes");
                return;
            }
            assert_eq!(outcome.err(), Some(CURLcode::WriteError));
        }

        /// The provider's own code is propagated unchanged, not remapped.
        ///
        /// `result = Curl_rand_alnum(...); if(result) goto fail;` at
        /// `lib/curl_fopen.c:109-111`. Asserted with a code that this module
        /// never produces itself, so that a remapping could not pass by
        /// coincidence.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn a_failing_provider_has_its_code_propagated() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");

            let outcome =
                open_for_write(&target, StoreClass::Public, guard(), || {
                    Err(CURLcode::FailedInit)
                });

            assert_eq!(
                outcome.err(),
                Some(CURLcode::FailedInit),
                "not remapped to WriteError, and not to OutOfMemory"
            );
            assert_eq!(
                len_of(&target),
                Some(0),
                "step one created the placeholder, so it exists and is empty \
                 -- empty because it is NEW, not because it was truncated; \
                 the_target_is_not_truncated_before_anything_is_written covers \
                 the case where the target already had contents"
            );
        }

        /// The provider is called exactly once on the regular-file path.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn the_provider_is_called_exactly_once() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");
            let calls = Cell::new(0_u32);

            let file = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || {
                    calls.set(calls.get() + 1);
                    Ok(fixed_suffix(17))
                },
            ));

            assert_eq!(calls.get(), 1, "once, as the C calls it once");
            file.discard();
        }

        /// The temporary name is the provider's suffix, not something derived.
        ///
        /// Two saves of the same target with different suffixes must produce
        /// different names, which is what stops two concurrent saves from
        /// colliding -- and it is the reason the C reaches for randomness at
        /// all.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn distinct_suffixes_yield_distinct_temporary_names() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");

            let first = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(0)),
            ));
            let first_path = first.temp_path().map(Path::to_path_buf);
            let second = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(1)),
            ));
            let second_path = second.temp_path().map(Path::to_path_buf);

            assert!(first_path.is_some() && second_path.is_some());
            assert_ne!(first_path, second_path, "the suffix reaches the name");

            first.discard();
            second.discard();
        }

        /// The `Direct` variant reports no temporary path, and `Temp` does.
        ///
        /// The accessor pair is what a consumer branches on in place of the C's
        /// `if(tempstore)`, so both answers are asserted rather than assumed.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn the_accessors_agree_with_the_variant() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");

            let file = opened(open_for_write(
                &target,
                StoreClass::Public,
                guard(),
                || Ok(fixed_suffix(18)),
            ));

            assert!(file.needs_rename());
            assert!(file.temp_path().is_some());
            assert!(
                file.temp_path().is_some_and(|path| {
                    path.extension().is_some_and(|ext| ext == "tmp")
                }),
                "the .tmp suffix is preserved"
            );
            file.discard();
        }
    }
}
