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
//! Supersedes `lib/curl_fopen.c` (159 lines) with `lib/curl_fopen.h` (32),
//! which AAP 0.4.1 maps onto this file, together with the cross-platform
//! residue of `lib/curlx/fopen.c` -- `curlx_fseek` at `:28-39` -- and the
//! non-Windows half of `lib/curlx/fopen.h` (88 lines).
//!
//! # The three consumers, all of them "save a state file safely"
//!
//! Measured by reading every call site rather than by inference:
//!
//! | Call site | What it saves |
//! |---|---|
//! | `lib/cookie.c:1483` | the Netscape cookie jar |
//! | `lib/altsvc.c:371` | the Alt-Svc cache |
//! | `lib/hsts.c:349` | the HSTS cache |
//!
//! There is no fourth. That is why the C wraps the whole translation unit in
//!
//! ```text
//! #if !defined(CURL_DISABLE_COOKIES) || !defined(CURL_DISABLE_ALTSVC) || \
//!   !defined(CURL_DISABLE_HSTS)
//! ```
//!
//! at `lib/curl_fopen.c:26-27`, and all three of those knobs map onto real
//! names in this workspace's fifteen-name feature vocabulary. The
//! atomic-replace surface below is therefore gated on
//! `any(feature = "cookies", feature = "altsvc", feature = "hsts")`.
//!
//! # Two guards, not one -- and why there is no inner `#![cfg]`
//!
//! The obvious way to express that gate is an inner attribute on the whole
//! file, which is the form `crate::util::fnmatch` uses for its `ftp` gate.
//! It is **rejected here**, and the reason is a measurement rather than a
//! preference: the two C translation units this file supersedes carry
//! **different** guards.
//!
//! * `lib/curl_fopen.c` is guarded by the three-knob `#if` quoted above.
//! * `lib/curlx/fopen.c` is guarded by **nothing at all**. `curlx_fseek` is
//!   compiled unconditionally, and its consumers are `lib/mime.c:641`,
//!   `lib/formdata.c:796`, `src/tool_formparse.c:244`,
//!   `src/tool_operate.c:568` and `src/tool_paramhlp.c:131` -- none of which
//!   is a cookie, an Alt-Svc or an HSTS consumer.
//!
//! An inner `#![cfg]` would delete [`fseek`] along with everything else at
//! `--no-default-features`, hiding it from `crate::mime`, which is
//! unconditional. So the gate is written per item: it appears on exactly the
//! items that came from `lib/curl_fopen.c`, and the seek surface below it
//! carries none. The repetition is the price of reproducing the C's guard
//! placement rather than approximating it, and it is greppable:
//! `grep -c 'feature = "cookies"'` counts the guarded surface.
//!
//! # The injected randomness, and why the layering forced it
//!
//! The C composes its temporary name from 40 random alphanumeric characters
//! obtained with `Curl_rand_alnum(data, randbuf, sizeof(randbuf))`
//! (`lib/curl_fopen.c:109`). `Curl_rand_alnum` lives in `lib/rand.c`, which
//! AAP 0.4.1 maps onto `crate::crypto::rand` -- a **sibling** of this
//! directory, not a descendant.
//!
//! `crate::util` depends on nothing inside this crate except
//! [`crate::error`], and every other module here depends on `util`. A `use
//! crate::crypto::rand` on this line would invert the crate's dependency
//! graph, so the randomness is **injected**: [`open_for_write`] takes a
//! provider and calls it. `crate::util`'s own module documentation records
//! this file as one of the two places where that rule is satisfied by
//! parameterization rather than by luck.
//!
//! The provider is an `FnOnce() -> CodeResult<String>`, and both halves of
//! that choice are deliberate:
//!
//! * **`FnOnce`, not `FnMut`.** The C reaches `Curl_rand_alnum` at most once
//!   per call, and *not at all* on the not-a-regular-file path, because
//!   `:103` returns before `:109` is reached. Taking the provider by value
//!   and simply not calling it reproduces that exactly.
//! * **Returning `CodeResult`, not `String`.** `Curl_rand_alnum` returns a
//!   `CURLcode`, and `:110-111` propagates it unchanged. A provider that
//!   could not fail would silently delete a failure mode the C has.
//!
//! The C's `struct Curl_easy *data` parameter existed **only** to reach that
//! one call, so it is dropped entirely: nothing in this module sees a handle.
//!
//! ## The provider's contract, pinned here so the two cannot drift
//!
//! Reproducing the alphabet and the length is the provider's job, but the
//! contract belongs beside the consumer that depends on it. Measured from
//! `lib/rand.c:258-283`:
//!
//! ```text
//! static const char alnum[] =
//!   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
//!
//! CURLcode Curl_rand_alnum(struct Curl_easy *data, unsigned char *rnd,
//!                          size_t num)
//! {
//!   const unsigned int alnumspace = sizeof(alnum) - 1;
//!   DEBUGASSERT(num > 1);
//!   num--; /* save one for null-termination */
//!   while(num) {
//!     do {
//!       result = randit(data, &r, TRUE);
//!       if(result) return result;
//!     } while(r >= (UINT_MAX - UINT_MAX % alnumspace));
//!     *rnd++ = (unsigned char)alnum[r % alnumspace];
//!     num--;
//!   }
//!   *rnd = 0;
//! }
//! ```
//!
//! Four facts follow, and the third is the one that is easy to get wrong:
//!
//! 1. The alphabet is [`RAND_ALPHABET`]: 26 upper, 26 lower, 10 digits,
//!    **62** characters, so `alnumspace` is 62.
//! 2. Values are drawn with **rejection sampling** to avoid modulo bias:
//!    `r >= UINT_MAX - UINT_MAX % 62` is redrawn. With `UINT_MAX` at
//!    4294967295 and `4294967295 % 62 == 3`, the threshold is **4294967292**,
//!    so exactly the four values `4294967292..=4294967295` are discarded.
//! 3. The caller declares `unsigned char randbuf[41]` and passes
//!    `sizeof(randbuf)`, and `Curl_rand_alnum` spends one of those bytes on
//!    the terminator. **The string is 40 characters long, not 41** --
//!    [`RAND_SUFFIX_LEN`]. A reading of "41 characters" is wrong and would
//!    lengthen every temporary name by one.
//! 4. `DEBUGASSERT(num > 1)` is the C's only check on the length, and it is
//!    debug-only. [`open_for_write`] mirrors that severity: it
//!    `debug_assert!`s the returned suffix against both constants and does
//!    not re-check in a release build.
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
//! # NOTE: step one TRUNCATES the target before it reads the mode
//!
//! `lib/curl_fopen.c:99` opens the *target* with `FOPEN_WRITETEXT`, which is
//! `"w"` on all four mandated targets (`lib/curl_setup.h:1259`; the `"wt"`
//! spelling at `:1245` is the DOS branch). `"w"` is
//! `O_WRONLY | O_CREAT | O_TRUNC`, so **the existing file is emptied before
//! its mode is stat'd** -- and it is emptied on the temporary-file path too,
//! where it then sits as a zero-length placeholder until the caller's rename
//! replaces it. If the save fails after that point, the previous contents are
//! already gone.
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
//! This is an upstream wart. It is reproduced rather than repaired, because
//! AAP 0.8.1 freezes observable behaviour and AAP 0.1.1 settles the tie in
//! favour of faithfulness. The note is prominent because the natural Rust
//! expression -- a read-only `fs::metadata(path)` call -- would quietly
//! change it, and nothing in the test corpus would say so.
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
//! `lib/curlx/fopen.c` is 508 lines and its `#ifdef _WIN32` opens at `:41` and
//! runs to the end of the file, so roughly 467 lines are excluded by the
//! four-target boundary of AAP 0.2.2 rather than migrated. Named in full:
//! `curlx_CreateFile`, `curlx_win32_fopen`, `curlx_win32_freopen`,
//! `curlx_win32_stat`, `curlx_win32_open`, `curlx_win32_rename`, the
//! `_fstati64` and `struct _stati64` aliases, `_close`, `_fdopen`,
//! `_O_WRONLY | _O_CREAT | _O_EXCL` with `_S_IREAD | _S_IWRITE`, and the
//! `_SH_DENYNO` share mode from `<share.h>`. `_fseeki64` goes with them; see
//! [`fseek`].
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
//! [`std::os::unix::fs::OpenOptionsExt`] for the cloned mode and
//! [`std::os::unix::ffi::OsStrExt`] for the byte view of a path -- are
//! ordinary safe traits, so the crate root's `#![deny(unsafe_code)]` needs no
//! exemption here and none is taken. Both are `#[cfg(unix)]`, and all four
//! mandated targets are Unix, so no configuration guard is written --
//! consistent with `crate::tls::keylog`, which names the same omission.
//!
//! Blocking I/O, with no `async` and no `tokio::fs`. Saving a state file is
//! synchronous in curl and stays synchronous here; the asynchrony in this
//! crate belongs to the transfer path, and putting an `.await` on a cookie-jar
//! write would change when it happens relative to teardown.
//!
//! Imports are `std`, [`crate::error`] and [`crate::util::dynbuf`], and
//! nothing else -- in particular not `crate::crypto`, for the reason given
//! above. Every item is `pub(crate)`: nothing here backs an exported symbol,
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
///
/// `PATHSEP` at `lib/curl_fopen.c:51`, the `#else` branch of the three-way
/// split at `:44-53`. The other two branches -- `_WIN32` at `:45` and
/// `MSDOS`/`OS2` at `:48` -- both spell it as a backslash and both are outside
/// the four-target boundary, so this is the only value that can arise.
///
/// A byte slice rather than a `char`, because the whole of `dirslash` works in
/// bytes and the C appends it with `curlx_dyn_addn(&out, PATHSEP, 1)`.
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
///
/// `8000000` at `lib/urldata.h:131`, passed at `lib/curl_fopen.c:60`. Eight
/// million exactly, not eight mebibytes -- the C literal is decimal.
///
/// Held as a file-local constant rather than imported, matching
/// `crate::util::bufref`, which transcribes the same value for the same
/// reason: it belongs to `lib/urldata.h`, which has no single Rust successor,
/// so each consumer of it carries its own transcription with its own citation.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
const MAX_INPUT_LENGTH: usize = 8_000_000;

/// The length, in characters, of the random component of a temporary name.
///
/// **Forty, not forty-one.** The caller declares `unsigned char randbuf[41]`
/// and passes `sizeof(randbuf)` (`lib/curl_fopen.c:89`, `:109`), and
/// `Curl_rand_alnum` opens with `num--; /* save one for null-termination */`
/// (`lib/rand.c:269`), so one of the 41 bytes is the terminator that a Rust
/// `String` does not have.
///
/// Published because the provider passed to [`open_for_write`] has to satisfy
/// it and lives in a different directory; keeping the number here is what
/// stops the two from drifting apart silently.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
pub(crate) const RAND_SUFFIX_LEN: usize = 40;

/// The alphabet the random component is drawn from.
///
/// Transcribed character for character from `alnum[]` at `lib/rand.c:258-259`.
/// Sixty-two characters: 26 upper case, then 26 lower case, then 10 digits,
/// in that order. The count is what `lib/rand.c:265` calls `alnumspace`, and
/// it is what sets the rejection threshold recorded in the module
/// documentation, so the length of this array is load-bearing rather than
/// incidental.
///
/// Typed as a fixed-size array so that the 62 is checked by the compiler
/// rather than by a comment.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
pub(crate) const RAND_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// True when `byte` is a path separator on the four mandated targets.
///
/// `IS_SEP` at `lib/curl_fopen.c:52`, which on the `#else` branch tests
/// against `'/'` and nothing else. The `_WIN32` branch at `:46` accepts a
/// backslash as well; that branch is out of scope, so a backslash here is an
/// ordinary filename character -- which is why `dirslash(b"a\\b")` is `""` and
/// not `"a\\"`.
///
/// A `const fn` so that it reads as the macro it replaces.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
const fn is_sep(byte: u8) -> bool {
    byte == b'/'
}

/// Returns the directory component of `path`, up to *and including* one final
/// separator, or an empty vector when `path` has no directory component.
///
/// Supersedes `dirslash` (`lib/curl_fopen.c:55-76`). The C's own description
/// of it, and the sixteen-row table of measured outputs including the one
/// corrected row, are in the module documentation above; this comment covers
/// the mechanism.
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
/// The composition order is part of the behaviour and is preserved literally:
/// the directory component *including* its trailing separator, then the
/// forty random characters, then `.tmp`. When the directory component is empty
/// -- a bare filename, or the corrected root case -- the name is relative and
/// the file lands in the process's current working directory.
///
/// The buffer is given [`DYN_APRINTF`] rather than [`MAX_INPUT_LENGTH`],
/// because that is the ceiling `curl_maprintf` actually imposes:
/// `curl_mvaprintf` initialises its own dynbuf with it at
/// `lib/mprintf.c:1144`. The two happen to be the same number, and they are
/// still kept distinct, because they are different constants that could be
/// changed independently upstream.
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
/// Supersedes the pair of out-parameters `FILE **fh` and `char **tempname`
/// that `Curl_fopen` writes through (`lib/curl_fopen.c:85-86`). The C's
/// contract is carried entirely by whether `*tempname` came back `NULL`, and
/// its own summary comment says so: *"if 'tempname' is non-NULL, it needs a
/// rename after the file is written."*
///
/// An `(File, Option<PathBuf>)` tuple would reproduce that literally. This is
/// an enumeration instead, for one reason: a tuple lets a caller ignore the
/// `None` and reach for a rename anyway, whereas [`Self::Direct`] has no path
/// to rename *from*. The distinction is not cosmetic -- it is what keeps
/// `--cookie-jar /dev/null` working.
///
/// # No `Drop`, deliberately
///
/// A `Drop` implementation that removed an uncommitted temporary file would be
/// an improvement, and it is not made, because AAP 0.8.1 freezes observable
/// behaviour: `Curl_fopen` does not unlink on the way out, and all three
/// consumers unlink for themselves. [`Self::discard`] is that unlink, written
/// once. `#[must_use]` on [`open_for_write`] is the Rust-shaped nudge that
/// costs no behaviour.
#[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum OpenedFile {
    /// The target is not a regular file, so write to it directly and do **not**
    /// rename.
    ///
    /// The C's early success at `lib/curl_fopen.c:102-104`: `fstat` failed, or
    /// `S_ISREG` was false. `*fh` is the open target and `*tempname` is
    /// `NULL`. `/dev/null`, `/dev/stdout`, a FIFO and a character device all
    /// arrive here -- measured: `/dev/null` reports `st_mode == 020666` with
    /// `S_ISREG == 0`.
    Direct {
        /// The target itself, open for writing and already truncated.
        file: File,
    },

    /// The target is a regular file, so write here and then rename over it.
    ///
    /// The C's ordinary path: `*fh` is a fresh descriptor on `tempstore` and
    /// `*tempname` is that name. The target has *already* been truncated to
    /// zero length by step one and sits there as a placeholder until the
    /// rename replaces it.
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
    ///
    /// The direct reading of the C's `*tempname`, for a caller that needs the
    /// primitive rather than [`Self::commit`] -- `lib/cookie.c` is one, because
    /// its `stdout` path at `:1477-1481` bypasses this module entirely and it
    /// then tests `if(!use_stdout)` and `if(tempstore)` separately at
    /// `:1530-1537`.
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
    /// `target` is taken as an argument rather than stored, because that is
    /// the C's shape -- `curlx_rename(tempstore, file)` names the destination
    /// at the call site -- and all three consumers pass back the same path
    /// they passed to `Curl_fopen`.
    ///
    /// [`Self::Direct`] closes and returns success, performing no rename. That
    /// is not a special case bolted on: it is the whole reason the two
    /// variants are distinguished.
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
    /// A caller reaches here when the *contents* failed to serialise, which is
    /// the only way the C's consumers get a non-zero `result` after
    /// `Curl_fopen` has already succeeded. It is also the home of the one
    /// cleanup the C performs inside `Curl_fopen` itself, at `:149-152`,
    /// which has no reachable counterpart in this module: the C arrives there
    /// only from a failed `fdopen`, and `fdopen` does not exist here.
    ///
    /// [`Self::Direct`] closes and does nothing else -- there is no temporary
    /// file to remove, and removing the *target* would destroy a device node.
    ///
    /// Returns nothing, because the C ignores `unlink`'s return value.
    pub(crate) fn discard(self) {
        if let Self::Temp { file, temp_path } = self {
            drop(file);
            let _ = fs::remove_file(&temp_path);
        }
    }
}

/// Opens `filename` for writing, through a temporary file when it is safe to.
///
/// Supersedes `Curl_fopen` (`lib/curl_fopen.c:85-156`). The C's own summary,
/// the truncation note, the early-success note, the error ladder and the
/// injected-randomness rationale are all in the module documentation; this
/// comment walks the five steps.
///
/// `rand_suffix` is the injected randomness. It must return
/// [`RAND_SUFFIX_LEN`] characters drawn from [`RAND_ALPHABET`], and it is
/// called **at most once** -- never on the not-a-regular-file path, because
/// the C returns at `:103` before reaching `:109`.
///
/// # Steps
///
/// 1. Open the target with `"w"`. **This truncates it.** Stat the descriptor.
///    If the stat fails or the target is not a regular file, return
///    [`OpenedFile::Direct`] with that handle -- the C's early `CURLE_OK`.
/// 2. Close the target and ask `rand_suffix` for the random component.
/// 3. Compose `<dirslash(filename)><suffix>.tmp`.
/// 4. Create that name with `O_WRONLY | O_CREAT | O_EXCL` and mode
///    `0o600 | <the target's own mode>`.
/// 5. `fdopen` -- eliminated. The [`File`] from step 4 *is* the handle.
///
/// # Errors
///
/// * `CURLcode::WriteError` if the target cannot be opened, or if the
///   temporary file cannot be created -- which includes the case where the
///   name already exists, because `O_EXCL` is the point of step 4.
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
    // (`lib/curl_setup.h:1259`), which is `O_WRONLY | O_CREAT | O_TRUNC`. THE
    // TARGET IS TRUNCATED HERE, before its mode is read and before anything
    // has been written. A read-only `fs::metadata(filename)` would look like
    // the same thing and would not truncate, which is exactly why this is
    // written out rather than tidied. See the module documentation.
    //
    // The mode is left at `OpenOptions`' default of 0o666, which is `fopen`'s
    // own, so a target that does not exist is created with the same
    // umask-derived permissions the C gives it.
    let target = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(filename)
        // `if(!*fh) goto fail;` with `result` still holding its initial value
        // from `:88`.
        .map_err(|_| CURLcode::WriteError)?;

    // `curlx_fstat(fileno(*fh), &sb)` at `:102`. `File::metadata` is `fstat`
    // on this descriptor, not `stat` on the path, which matters: the two can
    // disagree if the path is replaced between the open and the query.
    let metadata = match target.metadata() {
        Ok(metadata) => metadata,

        // The `== -1` half of `:102`. EARLY SUCCESS: the handle stays open and
        // there is no temporary file and no rename.
        //
        // This arm is reproduced but is not reachable from a test, and so is
        // the one line of this function that coverage reports as unvisited:
        // `fstat` on a descriptor that has just been opened successfully does
        // not fail, and safe Rust offers no way to make it. It is kept because
        // the C keeps it, and because `EOVERFLOW` on a pathological filesystem
        // is the one real way to arrive here -- in which case writing the
        // target directly is exactly the right thing to do. The `!is_file()`
        // arm immediately below reaches the same variant and IS covered, by
        // the `/dev/null` and FIFO tests.
        Err(_) => return Ok(OpenedFile::Direct { file: target }),
    };

    // The `!S_ISREG(sb.st_mode)` half of `:102`. `FileType::is_file` is that
    // macro: it tests `S_IFREG` and nothing else, so a FIFO, a socket, a
    // device node and a directory all take this branch.
    if !metadata.is_file() {
        return Ok(OpenedFile::Direct { file: target });
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
    //
    // `dir = dirslash(filename);` and the `curl_maprintf` at `:113-119`, then
    // `if(!tempstore) { result = CURLE_OUT_OF_MEMORY; goto fail; }` at
    // `:121-124`. The C cannot tell a `dirslash` failure from a `maprintf`
    // failure -- both arrive as a null pointer -- so both collapse to the one
    // code here, discarding the buffer's more specific `CURLcode::TooLarge`.
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
    // The mode clones the target's, unioned with `S_IRUSR | S_IWUSR`:
    //
    //   * `0o600` is `S_IRUSR | S_IWUSR`, spelled as the octal the C's macros
    //     expand to.
    //   * `target_mode` still carries `S_IFREG` (0o100000). `open(2)` ignores
    //     every bit outside the permission set, so the effective request is
    //     `0o600 | <permission bits>` -- measured: a request of 0o100600
    //     produced a file at 0o600.
    //   * Because step 1 CREATES a target that did not exist, `target_mode` on
    //     a first-ever save is `0o666 & ~umask`, typically 0o644. So a brand
    //     new cookie jar ends up 0o644 and NOT 0o600. That is upstream
    //     behaviour and it is not "hardened" here -- measured, and asserted by
    //     test against the process's actual umask rather than against a
    //     guessed 0o644.
    //   * `open(2)` masks this request with the umask, and so does
    //     `OpenOptionsExt::mode`, because it is the same syscall with the same
    //     argument. Nothing extra is needed to reproduce it.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600 | target_mode)
        .open(&temp_path)
        // `if(fd == -1) goto fail;`. `fd` is still -1 at that point, so the C
        // does NOT unlink -- and nothing was created, so there is nothing to
        // unlink.
        .map_err(|_| CURLcode::WriteError)?;

    // ---- STEP 5 -------------------------------------------------------------
    //
    // `*fh = curlx_fdopen(fd, FOPEN_WRITETEXT); if(!*fh) goto fail;` at
    // `:141-143`, and `*tempname = tempstore;` at `:145`.
    //
    // ELIMINATED. `fdopen` wraps a descriptor in a `FILE *` and can fail;
    // `OpenOptions::open` already returned the handle, so there is no second
    // step, no second failure mode, and no window in which a live descriptor
    // has to be closed and its file unlinked. That is the C's `:149-152`
    // cleanup gone, and it is the reason `discard` documents where it went.
    //
    // Text mode is a no-op on Unix, so nothing is lost by there being no mode
    // string here: `FOPEN_WRITETEXT` is plain `"w"`, not `"wt"`, on all four
    // mandated targets.
    Ok(OpenedFile::Temp { file, temp_path })
}

/// Where a seek measures its offset from.
///
/// Supersedes the `int whence` parameter of `curlx_fseek`
/// (`lib/curlx/fopen.c:28`), which is one of C's `SEEK_SET`, `SEEK_CUR` or
/// `SEEK_END`.
///
/// The three discriminants are written out and `#[repr(i32)]` is not
/// decorative, for the reason AAP 0.6.1 gives for `CURLcode`: these integers
/// are **ABI-visible**. `curl_seek_callback` hands a user-supplied function an
/// `int origin` holding exactly these values, so a program compiled against
/// curl 8.19.0-DEV holds the numbers rather than the names, and 0, 1 and 2 are
/// what it will compare against. A [`SeekFrom`] alone cannot carry them --
/// it is a Rust enumeration with no stable representation -- which is why this
/// type exists rather than the helper below simply taking a `SeekFrom`.
///
/// The translation *at* the ABI boundary belongs to `curl-rs-ffi`; this is the
/// engine-internal counterpart, so that a module needing to seek does not have
/// to reach across the boundary for a constant.
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
    ///
    /// `Option` rather than a `CURLcode`, because the C never converts this
    /// value: `curlx_fseek` passes it straight to `fseeko`, which reports
    /// `EINVAL` for anything else. Inventing a curl code here would be a
    /// finer-grained answer than curl gives.
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
/// cross-platform function in that 508-line file. The C is a three-branch
/// preprocessor ladder over a portability problem that does not exist in Rust:
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
/// All three branches collapse. [`Seek::seek`] takes an `i64` offset and
/// returns a `u64` position on every platform, so `_fseeki64` is unnecessary,
/// `fseeko` is what remains on the mandated targets anyway -- both
/// `configure.ac` and `CMakeLists.txt` detect it on Linux and macOS -- and the
/// `LONG_MAX` guard of the last branch is guarding against a 32-bit `long`
/// that none of the four mandated targets has. The one thing the ladder did
/// carry forward is the `whence` integer, which is why [`Whence`] exists.
///
/// This function is deliberately **outside** the feature gate that covers the
/// rest of this module: `lib/curlx/fopen.c` has no `#if` around it, and its
/// consumers -- `lib/mime.c:641`, `lib/formdata.c:796` and three call sites
/// under `src/` -- have nothing to do with cookies, Alt-Svc or HSTS.
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
            dirslash, open_for_write, temp_name, OpenedFile, RAND_ALPHABET,
            RAND_SUFFIX_LEN,
        };
        use crate::error::{CURLcode, CodeResult};

        /// Binds a scratch directory, failing the test loudly if the
        /// environment cannot provide one.
        ///
        /// A macro rather than a function because the failure arm has to leave
        /// the *test*; the `let ... else` arm is unreachable because the
        /// assertion above it has already failed. Modelled on the same helper
        /// in `crate::tls::keylog`, so that a reader who knows one knows both.
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

        /// A deterministic stand-in for `Curl_rand_alnum`.
        ///
        /// Satisfies the injected provider's contract exactly -- exactly
        /// [`RAND_SUFFIX_LEN`] characters, every one of them from
        /// [`RAND_ALPHABET`] -- while being reproducible, so a test can compute
        /// the temporary path in advance and assert on it. `seed` merely
        /// rotates the alphabet, which is enough to make two calls in one test
        /// produce different names.
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
        ///
        /// Measured rather than assumed. The umask is a property of the
        /// process, it is not readable through any safe standard-library call,
        /// and hard-coding the usual `0o644` would make the mode-cloning tests
        /// fail on a machine configured differently -- for a reason that has
        /// nothing to do with this module. Creating a probe with
        /// `File::create`, whose mode is `OpenOptions`' default of `0o666`,
        /// measures it directly.
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
        ///
        /// The expectations are not derived from reading the C a second time:
        /// they were produced by compiling a literal transliteration of
        /// `lib/curl_fopen.c:55-76` and running it, which is how the `"/c"`
        /// row came to be corrected from `"/"` to `""`.
        ///
        /// Pure bytes, no filesystem, so this stays visible under Miri -- and
        /// it is the assertion that matters most, because a `Path`-based
        /// rewrite would change several of these rows at once.
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
        ///
        /// The C returns a pointer to an allocated empty string, never `NULL`,
        /// for a path with no directory component -- `dyn_addn(&out, path, 0)`
        /// succeeds. Distinguishing the two matters: the caller turns `NULL`
        /// into `CURLE_OUT_OF_MEMORY`, so getting this wrong would turn every
        /// bare filename into an allocation failure.
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
        //
        // The buffer's contract is `content + 1 > ceiling` fails -- the `+ 1`
        // is the C's terminator, and it is part of the ceiling contract -- so
        // the largest directory component that fits is 7,999,999 bytes. Both
        // sides of that line are asserted, because a ceiling only tested from
        // one side is a ceiling that could be off by one.

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
        ///
        /// This is the observable half of the corrected `"/c"` row and of the
        /// bare-filename row: with nothing before the suffix, the temporary
        /// file is created in the process's current working directory. Asserted
        /// on the composed name rather than by creating the file, so the test
        /// stays hermetic -- changing the working directory would race every
        /// other test in this binary.
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

            let (file, temp_path) =
                temp_parts(open_for_write(&target, || Ok(suffix.clone())));
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

            let file = opened(open_for_write(&target, || Ok(fixed_suffix(2))));

            let parent = file.temp_path().and_then(Path::parent);
            assert_eq!(parent, Some(nested.as_path()));
            file.discard();
        }

        // -- the truncation wart -------------------------------------------

        /// NOTE: reproduced C behaviour. The target is emptied immediately.
        ///
        /// `lib/curl_fopen.c:99` opens the target with `FOPEN_WRITETEXT`, which
        /// is `"w"` on the mandated targets (`lib/curl_setup.h:1259`), so the
        /// previous contents are destroyed before the mode is even read -- and
        /// destroyed on the temporary-file path too, where the target then sits
        /// empty until the caller's rename. If the save fails after this point
        /// the old contents are already gone.
        ///
        /// This test exists to make that a deliberate, asserted property. A
        /// future change to a read-only `fs::metadata` call would look
        /// harmless, would be an improvement on its own terms, and would break
        /// exactly this assertion -- which is the point.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn the_target_is_truncated_before_anything_is_written() {
            scratch!(dir);
            let target = dir.path().join("altsvc.txt");
            seed_file(&target, b"old contents");
            assert_eq!(len_of(&target), Some(12), "the seed is in place");

            let file = opened(open_for_write(&target, || Ok(fixed_suffix(3))));

            assert!(file.needs_rename(), "a regular file takes the temp path");
            assert_eq!(
                len_of(&target),
                Some(0),
                "the previous contents are already gone -- upstream behaviour"
            );
            assert_eq!(
                file.temp_path().and_then(len_of),
                Some(0),
                "and the temporary file is empty, not a copy"
            );
            file.discard();
        }

        // -- the cloned mode -----------------------------------------------

        /// The temporary file's mode is `0o600` unioned with the target's.
        ///
        /// Two pre-existing modes, because one would not distinguish "cloned"
        /// from "always 0o600". `0o640` is the interesting one: the group-read
        /// bit is preserved, which a hardened implementation would drop.
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

                let file =
                    opened(open_for_write(&target, || Ok(fixed_suffix(4))));

                assert_eq!(
                    file.temp_path().and_then(mode_of),
                    Some(expected),
                    "S_IRUSR | S_IWUSR | sb.st_mode, with S_IFREG ignored"
                );
                file.discard();
            }
        }

        /// A first-ever save ends up at the umask-derived mode, NOT `0o600`.
        ///
        /// Because step one CREATES a target that did not exist, `sb.st_mode`
        /// is whatever `fopen` just produced -- `0o666 & ~umask`, typically
        /// `0o644` -- and the union with `0o600` changes nothing. So a brand
        /// new cookie jar is group- and world-readable. That is upstream
        /// behaviour and it is not hardened here.
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

            let file = opened(open_for_write(&target, || Ok(fixed_suffix(5))));

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

        // -- the early-success path ----------------------------------------

        /// A target that is not a regular file is written directly.
        ///
        /// `/dev/null` reports `st_mode == 020666` with `S_ISREG == 0`, so
        /// `lib/curl_fopen.c:102-104` returns `CURLE_OK` with the plain handle
        /// open and `*tempname` still `NULL`. That is what makes
        /// `--cookie-jar /dev/null` work.
        ///
        /// The strongest available evidence that no temporary file was created
        /// anywhere is that the provider was never asked for a name, so there
        /// was never a name to create one under. That is asserted directly.
        #[test]
        #[cfg_attr(miri, ignore = "Miri does not model /dev/null")]
        fn a_character_device_is_written_directly() {
            let called = Cell::new(false);

            let file = opened(open_for_write(Path::new("/dev/null"), || {
                called.set(true);
                Ok(fixed_suffix(6))
            }));

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
            let mut file =
                opened(open_for_write(Path::new("/dev/null"), || {
                    Ok(fixed_suffix(7))
                }));

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
        /// `/dev/null` is a character device; a FIFO is a different `S_IFMT`
        /// value reaching the same branch, and it is the one a user is most
        /// likely to point `--cookie-jar` at deliberately.
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
            let file = opened(open_for_write(&fifo, || {
                called.set(true);
                Ok(fixed_suffix(8))
            }));

            assert!(!file.needs_rename(), "S_ISREG is false for a FIFO");
            assert_eq!(file.temp_path(), None, "*tempname stays NULL");
            assert!(!called.get(), "and the provider is never reached");
            drop(holder);
        }

        // -- O_EXCL, the atomicity guarantee --------------------------------

        /// A name that already exists is refused, and left untouched.
        ///
        /// `O_EXCL` is why step four uses `create_new(true)` and not
        /// `create(true).truncate(true)`. It is what turns a name collision --
        /// and a symlink planted at the predicted name -- into an error rather
        /// than a write into somebody else's file. The pre-existing file's
        /// contents are asserted afterwards, because a lost `O_EXCL` would show
        /// up as a truncation rather than as a failure.
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

            let outcome = open_for_write(&target, || Ok(suffix.clone()));

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

            let mut file =
                opened(open_for_write(&target, || Ok(fixed_suffix(10))));
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
        ///
        /// The C's `if(!result && tempstore && curlx_rename(...)) result =
        /// CURLE_WRITE_ERROR;` followed by `if(result && tempstore)
        /// unlink(tempstore);`. The rename is made to fail by naming a
        /// destination inside a directory that does not exist, which is
        /// `ENOENT` and does not depend on the process's privileges.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn a_failed_commit_reports_a_write_error_and_removes_the_temporary() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");

            let file = opened(open_for_write(&target, || Ok(fixed_suffix(11))));
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

            let file = opened(open_for_write(&target, || Ok(fixed_suffix(12))));
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
            let file = opened(open_for_write(Path::new("/dev/null"), || {
                Ok(fixed_suffix(13))
            }));

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

            let outcome = open_for_write(&target, || {
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

            let outcome = open_for_write(dir.path(), || Ok(fixed_suffix(15)));

            assert_eq!(outcome.err(), Some(CURLcode::WriteError));
        }

        /// A directory with no write permission is a `CURLE_WRITE_ERROR`.
        ///
        /// The mode is restored before the assertions so that the scratch
        /// directory can be cleaned up whatever the outcome.
        ///
        /// A process that bypasses the directory's mode -- root in a
        /// container, which is how this suite is often run -- cannot observe
        /// the property at all, so it is detected by probing and reported as a
        /// gap. Probing rather than asking for the effective user identity,
        /// which would need `libc` and does not belong in this module.
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
            let outcome = open_for_write(&locked.join("cookies.txt"), || {
                Ok(fixed_suffix(16))
            });

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

            let outcome = open_for_write(&target, || Err(CURLcode::FailedInit));

            assert_eq!(
                outcome.err(),
                Some(CURLcode::FailedInit),
                "not remapped to WriteError, and not to OutOfMemory"
            );
            assert_eq!(
                len_of(&target),
                Some(0),
                "and the target has already been truncated by step one"
            );
        }

        /// The provider is called exactly once on the regular-file path.
        #[test]
        #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
        fn the_provider_is_called_exactly_once() {
            scratch!(dir);
            let target = dir.path().join("cookies.txt");
            let calls = Cell::new(0_u32);

            let file = opened(open_for_write(&target, || {
                calls.set(calls.get() + 1);
                Ok(fixed_suffix(17))
            }));

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

            let first = opened(open_for_write(&target, || Ok(fixed_suffix(0))));
            let first_path = first.temp_path().map(Path::to_path_buf);
            let second =
                opened(open_for_write(&target, || Ok(fixed_suffix(1))));
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

            let file = opened(open_for_write(&target, || Ok(fixed_suffix(18))));

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
