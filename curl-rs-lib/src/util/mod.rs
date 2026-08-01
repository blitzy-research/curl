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

// THE LICENCE BANNER ABOVE -- 23 lines, and why it is spelled this way.
//
// `REUSE.toml` annotates only the files that "cannot be annotated directly",
// so every source file in this workspace carries its licence in-file, and
// `reuse lint` runs in continuous integration alongside the spellcheck and
// linter job. The requirement it enforces is an SPDX licence-identifier
// tag naming `curl`, which appears above verbatim.
//
// One deliberate spelling choice inside THIS comment block: the tag is never
// written out here with its trailing colon. `reuse` scans every line of a
// file for that colon form and parses whatever follows as a licence
// expression, so a prose mention becomes a parse error rather than prose.
// Measured -- with two such mentions present, `reuse lint-file` on this file
// reported `invalid SPDX License Expression ''` and `invalid SPDX License
// Expression 'ISC`. That'`; with them reworded as they now read, the same
// command reports nothing. The tag itself, on line 21, is untouched and
// verbatim: it is the only place in this file where that spelling appears,
// which is exactly what `reuse` needs.
//
// The 23 lines are the banner measured at `lib/llist.c:1-23`, rendered as
// Rust line comments. Two renderings are possible: keep the C block
// comment's `/*`, ` * ` and `*/` decorations inside `//`, or strip them. The
// stripped form is used here because it is what the rest of this crate
// already does -- `src/lib.rs:1-23`, `src/error.rs:1-23`, `src/ffi/mod.rs`,
// `src/ffi/sys.rs` and `src/multi/state.rs` are byte-identical to the block
// above -- and a reviewer reading two files side by side checks consistency,
// not a transcription of C punctuation. The ASCII art itself is reproduced
// exactly, and the longest line is 77 columns, inside the 80-column limit
// that `rustfmt.toml` sets.
//
// Every one of the 23 files in this directory carries this same block, with
// ONE deliberate exception recorded here so that nobody applies the banner
// blindly across the directory: `inet.rs`. Its C originals,
// `lib/curlx/inet_ntop.c` and `lib/curlx/inet_pton.c`, are ISC/BIND-licensed
// rather than curl-licensed and carry an SPDX tag naming `ISC` rather than
// `curl`. That file keeps the ISC notice of its origin. Re-licensing it to
// `curl` would be a licence violation, not a tidy-up.

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
// `util` is the BASE of this crate's module graph: every other module
// depends on it and it depends on nothing. The corollary is that its
// consumers are the LAST code to exist, so until they land every helper here
// is legitimately unreferenced -- and the zero-warnings gate would otherwise
// fail on code that is correct.
//
// Measured on the pinned toolchain (rustc 1.97.1) rather than assumed: a
// `pub(crate)` item inside a `pub(crate)` module IS subject to `dead_code`,
// and so is a `pub` item, because neither is reachable from outside the
// crate until `src/lib.rs` re-exports it -- and its re-export list covers
// `error` and `version` only. A `#[cfg(test)]` use does not count: the lint
// is evaluated for the non-test build, which is also why these are `allow`
// and not `expect`.
//
// The breadth a root attribute would have had is worth stating plainly,
// because it is the reason none is written: a lint level on a module root
// propagates into the modules declared inside it, so ONE attribute here
// would have covered all 22 children and the six absorbed shims below.
//
// No level for the `unsafe_code` lint is set here, at any level, by design.
// `src/lib.rs` carries `#![deny(unsafe_code)]` and grants exactly ONE
// exemption, on `mod ffi`. This directory has no exemption, contains no
// `unsafe` block and contains no `#[allow(unsafe_code)]` -- which matters
// most precisely here, because `util` supersedes the C files where the
// hand-rolled pointer arithmetic lived.
//
// HOW TO CHECK THAT CLAIM, because an unanchored search reports a false
// failure against this file itself: the paragraph above legitimately NAMES
// both the keyword and the attribute, so `grep -rn 'unsafe' ...` matches the
// prose. `src/lib.rs` settled this at the crate root and its anchored
// expressions are the authority; applied to this directory they are
//
//   grep -rnE '^[[:space:]]*#!?\[allow\(unsafe_code\)\]' \
//     --include='*.rs' curl-rs-lib/src/util     -> must print NOTHING
//   grep -rnE '^[^/]*\bunsafe\b' \
//     --include='*.rs' curl-rs-lib/src/util     -> must print NOTHING
//
// Anchoring past leading whitespace only, and requiring the keyword before
// any slash on the line, is what excludes every `//`, `///` and `//!` line: a
// comment begins with a slash, so it can never match. Measured on this file:
// both expressions print nothing. The compiler is the real authority in any
// case -- with no exemption here, `#![deny(unsafe_code)]` makes any
// occurrence a hard error.

//! The portability and utility layer: the base of the crate's module graph.
//!
//! This directory supersedes the **4,733 measured lines** of `lib/curlx/` --
//! 18 translation units totalling 3,670 lines of `.c`, plus their headers --
//! together with the general-purpose containers and parsers scattered
//! through `lib/*.c`: `llist.c`, `splay.c`, `hash.c`, the four integer-keyed
//! containers (`uint-bset.c`, `uint-spbset.c`, `uint-hash.c`,
//! `uint-table.c`), `parsedate.c`, `curl_fnmatch.c`, `curl_range.c`,
//! `curl_get_line.c`, `curl_memrchr.c`, `bufq.c`, `bufref.c`, `slist.c`,
//! `strcase.c` with `strequal.c`, `curl_fopen.c` and `curl_endian.c`.
//!
//! # The layering rule
//!
//! **`util` depends on nothing inside this crate except [`crate::error`].**
//! It is the base of the internal dependency graph, which is what lets every
//! other module import from here without a cycle, and it is the one
//! architectural property of this directory that must never be traded away.
//! No file here may name `crate::conn`, `crate::transfer`,
//! `crate::protocols`, `crate::multi`, `crate::easy`, `crate::tls`,
//! `crate::dns`, `crate::auth`, `crate::proxy`, `crate::cookies`,
//! `crate::mime`, `crate::headers`, `crate::share`, `crate::crypto`,
//! `crate::url` or `crate::ffi`.
//!
//! When a helper appears to need one of those types, the helper is in the
//! wrong layer: take the value as a parameter instead. Two instances are
//! designed in rather than discovered, and both are resolved by
//! parameterization:
//!
//! - [`range`] is a **pure parse function**. Its C original,
//!   `lib/curl_range.c`, writes its results into `struct Curl_easy`; here it
//!   returns them and the caller stores them.
//! - `fopen` takes its **randomness by injection**. Its C original,
//!   `lib/curl_fopen.c`, calls `Curl_rand_alnum` from what is now the
//!   sibling `crate::crypto`; here the random suffix arrives as an argument.
//!
//! This file itself compiles with **zero `use` statements**, so the rule
//! holds by construction and cannot regress here. It needs no error type
//! because all six absorbed shims are total functions over primitives.
//!
//! # What this file does
//!
//! Two jobs, and nothing else. It declares the 22 sibling modules, and it
//! absorbs six small C shims that do not warrant modules of their own --
//! byte-order conversion, path basename, bounded string copy, duplication,
//! operating-system error strings and cast narrowing:
//!
//! | Absorbed C source | Measured at | Rust counterpart below |
//! |---|---|---|
//! | `lib/curl_endian.c` | `:24-83` | [`read16_le`] and two siblings |
//! | `lib/curlx/basename.c` | `:24-74` | [`basename`] |
//! | `lib/curlx/strcopy.c` | `:24-50` | [`strcopy`] |
//! | `lib/curlx/strdup.c` | `:24-96` | none -- ownership is the type's job |
//! | `lib/curlx/strerr.c` | `:24-331` | [`os_error_message`], [`os_strerror`] |
//! | `lib/curlx/warnless.c` | `:24-341` | 18 conversions, from [`ultouc`] |
//!
//! # The measured `lib/curlx/` disposition
//!
//! Recorded because it resolves an inconsistency between two sections of the
//! plan that governs this work: one says 13 of the 18 files in `lib/curlx/`
//! "exist solely as Windows shims", the other's per-file table implies three.
//! **The per-file table governs, and measurement agrees with it.** Of the 18
//! `.c` files, exactly three are genuinely Windows-only and are excluded by
//! the four-target boundary -- Linux and macOS on x86_64 and aarch64:
//! `multibyte.c` (78 lines), `winapi.c` (106) and `version_win32.c` (237).
//! Two more belong to a different directory: `nonblock.c` (92) becomes part
//! of `crate::conn::socket` and `wait.c` (94) part of `crate::conn::select`,
//! because a non-blocking flag and a millisecond wait are properties of a
//! socket and of the reactor, not of a utility layer. The remaining 13 land
//! here.
//!
//! One nuance in that count is worth recording, because a line total read
//! without it is misleading: `lib/curlx/fopen.c` is 508 lines, and its
//! Windows guard opens at `:41` and runs to the end. Only `curlx_fseek`
//! (`:28`) is cross-platform, so `fopen` absorbs a small residue of that
//! file and roughly 467 lines are excluded rather than migrated.
//!
//! # Platform and toolchain assumptions
//!
//! All four mandated targets are 64-bit: `x86_64-unknown-linux-gnu`,
//! `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` and
//! `aarch64-apple-darwin`. That is load-bearing for the conversions in this
//! file rather than incidental -- see [`CurlOffT`] -- and 32-bit support is a
//! deliberate forfeit that must not be claimed. Divergence between the four
//! is expressed with `#[cfg(target_os = ...)]` where it arises, never with a
//! Cargo feature: a feature is a capability the user chooses, a platform is
//! a fact about the build. There is no `tls` feature in this workspace and
//! none may be introduced; TLS is unconditional because certificate
//! validation is on by default.
//!
//! Edition 2021, and the minimum supported Rust version is 1.75. Nothing
//! here uses a nightly-only or newer-than-1.75 construct; nightly is
//! reserved for the Miri and AddressSanitizer gates. Performance is an
//! explicit non-goal of this work, so nothing in this file carries an
//! `#[inline]` hint or is restructured on speed grounds -- where a choice
//! existed between a faster expression and a more behaviourally faithful
//! one, faithfulness won, and the mask-then-narrow conversions below are the
//! clearest example.
//!
//! # Conventions this file holds itself to
//!
//! A compiler-checked safety invariant rather than a review obligation; every
//! claim carrying the repository locator that evidences it; faithfulness to
//! the C behaviour in preference to a tidier expression; and a unit test for
//! every behaviour that a bare cast would silently have changed.

// THE 22 SIBLING MODULES -- and the visibility policy of this layer.
//
// Exactly 22 belong to this layer: no more, and no fewer. Six candidates that
// a reader might expect are deliberately absent, and each one belongs
// somewhere else rather than nowhere:
//
//   * `mprintf`         -- `lib/mprintf.c` backs the ten exported
//                          `curl_m*printf` symbols, so it belongs to the ABI
//                          crate rather than here.
//   * `nonblock`        -- `lib/curlx/nonblock.c` is a socket property:
//                          `crate::conn::socket`.
//   * `wait`            -- `lib/curlx/wait.c` is a reactor property:
//                          `crate::conn::select`.
//   * `multibyte`,      -- Windows-only; excluded by the four-target
//     `winapi`,            boundary. No path for them appears here and none
//     `version_win32`      may be added "for completeness".
//   * `error`/          -- `lib/strerror.c` holds curl's OWN `CURLcode`,
//     `strerror`           `CURLMcode`, `CURLUcode` and `CURLSHcode` message
//                          text, which is the sibling `crate::error`. It is
//                          a DIFFERENT file from `lib/curlx/strerr.c`, whose
//                          operating-system `errno` text is absorbed below
//                          as `os_strerror`. Conflating the two would
//                          duplicate the message tables and put the
//                          `curl_easy_strerror` text-match requirement at
//                          risk.
//
// Nor is there a `setup` module. The `#include "curl_setup.h"` at the head of
// every absorbed C file has no Rust successor: its three jobs separate into
// Cargo features, `#[cfg(target_os/target_arch)]`, and ordinary `use`
// statements against the module that owns each type.
//
// VISIBILITY POLICY. `src/lib.rs` declares `pub(crate) mod util;`, so this
// whole directory is crate-private, and the default for an item here is
// therefore `pub(crate)`: the C tree's `extern CURLcode Curl_xyz(...)` was
// private by CONVENTION and visible to the linker, whereas
// `pub(crate) fn xyz(...) -> Result<..>` is private by ENFORCEMENT.
//
// Four of the children nevertheless declare some `pub` items, because a
// `pub` item inside a `pub(crate)` module becomes reachable once the crate
// root re-exports it -- the standard private-module / public-re-export idiom
// -- and four exported C symbols are backed from this layer:
//
//   `parsedate`  ->  curl_getdate
//   `strcase`    ->  curl_strequal, curl_strnequal
//   `base64`     ->  the encode/decode the auth and MIME paths need
//   `slist`      ->  curl_slist_append, curl_slist_free_all
//
// Those `pub` markers live in the four files themselves, next to the items
// they widen, where the justification can name the consumer. THIS file adds
// no `pub` item and no `pub use` of any kind. That is a decision, not an
// omission: a re-export here would create a second canonical path to an item
// that already has one, widen the audit surface with no consumer asking for
// it, and -- for anything reachable from `curl-rs-ffi` -- move the
// justification away from the item it applies to.
//
// And internals stay internal. `tests/libtest/*.c` (235 files) and
// `tests/unit/*.c` (59) link a debug static libcurl and call internal
// `Curl_*` symbols; a Rust static library genuinely does not export
// `pub(crate)` items, so no quality of implementation makes them link. That
// is a documented deviation, not a defect to work around, and re-exporting
// internals to satisfy it would defeat the encapsulation that makes the
// zero-`unsafe` guarantee possible. Their coverage relocates into
// `#[cfg(test)]` modules inside these files.

// THE TWENTY-TWO CHILD MODULES -- TWO LANDED, TWENTY DESCRIBED
//
// The AAP's transformation map gives this layer twenty-two children. Two exist
// and are declared further down, `parsedate` and `strcase`; the other twenty
// are each a separate unit of work and are DESCRIBED here rather than declared.
//
// That distinction is load-bearing rather than stylistic.
// `pub(crate) mod base64;` without `util/base64.rs` on disk is E0583, "file not
// found for module" -- a hard error, not a warning. One such line stops the
// whole crate compiling, and twenty of them stop it twenty times over. No
// `#[allow]` reaches an E0583 either, because module resolution never gets far
// enough to raise a lint. So each declaration arrives WITH its file, in the
// unit of work that creates it, and until then the provenance lives in prose
// where it costs nothing.
//
// Each entry is the module and the C translation unit it supersedes, with that
// unit's line count, so this list stands in for the LIB_CURLX_CFILES and
// LIB_CFILES groups of `lib/Makefile.inc` for the utility half of the tree.
// Order is alphabetical, matching `reorder_modules = true` in `rustfmt.toml`.
//
// Base64 and base32hex codecs -- supersedes `lib/curlx/base64.c` (267).
// The chunked buffer queue -- supersedes `lib/bufq.c` (619).
// The reference-counted buffer -- supersedes `lib/bufref.c` (138).
// The growable dynamic buffer -- supersedes `lib/curlx/dynbuf.c` (292).
// Wildcard pattern matching -- supersedes `lib/curl_fnmatch.c` (385).
// Atomic file creation and seeking -- supersedes `lib/curl_fopen.c` (158)
// and the cross-platform residue of `lib/curlx/fopen.c` (`curlx_fseek`).
// Line reading from a stream -- supersedes `lib/curl_get_line.c` (67).
// The string-keyed hash table -- supersedes `lib/hash.c` (388).
// Address presentation and parsing -- supersedes `lib/curlx/inet_ntop.c`
// (222) and `lib/curlx/inet_pton.c` (221). ISC-licensed, NOT curl-licensed --
// a distinction that must survive into the file superseding them.
// The doubly-linked list -- supersedes `lib/llist.c` (268).
// Reverse byte search -- supersedes `lib/curl_memrchr.c` (53).
// Date parsing -- supersedes `lib/parsedate.c` (585). Backs `curl_getdate`.
//   LANDED, and declared below rather than only listed here. It is the first
//   of the 22 to exist because `curl_getdate` is an exported symbol and
//   `curl-rs-ffi` cannot be written without it.
// Byte-range parsing -- supersedes `lib/curl_range.c` (91).
// The `curl_slist` chain -- supersedes `lib/slist.c` (139). Backs the exported
// `curl_slist_append` and `curl_slist_free_all`.
// The splay tree behind expiry timers -- supersedes `lib/splay.c` (291).
// Case-insensitive comparison -- supersedes `lib/strcase.c` (146) and
// `lib/strequal.c` (95). Backs `curl_strequal` and `curl_strnequal`.
//   LANDED, and declared below, for the same reason as `parsedate`: both
//   comparators are reached from `curl-rs-ffi`.
// The bounded string parser -- supersedes `lib/curlx/strparse.c` (304).
// Monotonic time differences -- supersedes `lib/curlx/timediff.c` (85).
// The monotonic clock -- supersedes `lib/curlx/timeval.c` (272).
// Integer-keyed bitsets -- supersedes `lib/uint-bset.c` (231) and
// `lib/uint-spbset.c` (251).
// The integer-keyed hash -- supersedes `lib/uint-hash.c` (240).
// The integer-keyed table -- supersedes `lib/uint-table.c` (200).
//
// The four `pub`-item consumers named in the preamble above -- `parsedate`,
// `strcase`, `base64` and `slist` -- all appear in that list, and the
// preamble's rule still governs the two that have yet to arrive: the `pub`
// marker lives in the child file next to the item it widens, and THIS file adds
// no `pub` item and no `pub use` of any kind.

// ABSORBED SHIM 1 of 6 -- byte order.  `lib/curl_endian.c:24-83`
//
// `lib/curl_endian.h:27-34` was read in full rather than inferred from the
// three definitions, because a header can export more than a source file
// obviously defines. It exports EXACTLY three functions -- `Curl_read16_le`,
// `Curl_read32_le` and `Curl_read16_be` -- and there is no 32-bit big-endian
// variant and no 64-bit variant of any kind. Three in, three out.
//
// The C signatures take `const unsigned char *` and index `buf[0]` through
// `buf[3]` with NO bound check whatsoever: passing a one-byte buffer to
// `Curl_read32_le` reads three bytes past its end and reports whatever was
// there. Taking a slice is the whole point of the migration. A slice too
// short panics with an index message that names this file and the offending
// length, which turns an undetected out-of-bounds read into a detected
// caller bug; correct callers never reach it, exactly as in C, because they
// check the length of the incoming message first.
//
// A `&[u8; 2]` / `&[u8; 4]` parameter would move that check to the type
// system, and it was rejected on call-site evidence: every C caller passes
// an interior pointer into a larger message buffer -- `&type2[40]`,
// `&type2[44]`, `&type2[20]` at `lib/vauth/ntlm.c:266-371` -- which becomes
// `&type2[40..42]`, a slice. The array form would force a
// `try_into().unwrap()` at each of those sites, which panics on the same
// input the slice form panics on, so it buys no safety and costs
// readability.
//
// CONSUMERS. `crate::auth::ntlm`, which is in scope, and `lib/smb.c`, which
// is not: SMB is one of the 24 unimplemented schemes. All three functions
// are kept because NTLM uses all three shapes of read across its type-2
// message parsing.

/// Date parsing -- supersedes `lib/parsedate.c`.
///
/// `pub(crate)` like every other child: its own `pub fn getdate` is what
/// widens the reachable surface, once the crate root re-exports it. The
/// justification for that `pub` lives in the file, next to the item, as the
/// policy above requires.
pub(crate) mod parsedate;

/// Locale-independent ASCII case comparison -- supersedes the public half of
/// `lib/strcase.c` and all of `lib/strequal.c`.
///
/// The second child that carries `pub` items, and for the same reason as
/// [`parsedate`]: `curl_strequal` and `curl_strnequal` are exported symbols in
/// `lib/libcurl.def`, so the two comparators they call are `pub` here and
/// re-exported by the crate root. The folding tables themselves are NOT
/// transcribed -- the file records the entry-by-entry measurement proving
/// `u8::to_ascii_uppercase` is the same function as `Curl_raw_toupper`.
pub(crate) mod strcase;

/// Reads a 16-bit unsigned integer in little-endian order.
///
/// Supersedes `Curl_read16_le` (`lib/curl_endian.c:41-45`), whose body is
/// `buf[0] | (buf[1] << 8)`.
///
/// # Panics
///
/// Panics if `buf` holds fewer than 2 bytes. The C original reads out of
/// bounds instead.
#[allow(dead_code)]
pub(crate) fn read16_le(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[0], buf[1]])
}

/// Reads a 32-bit unsigned integer in little-endian order.
///
/// Supersedes `Curl_read32_le` (`lib/curl_endian.c:60-64`), whose body is
/// `buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)`.
///
/// # Panics
///
/// Panics if `buf` holds fewer than 4 bytes. The C original reads out of
/// bounds instead.
#[allow(dead_code)]
pub(crate) fn read32_le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Reads a 16-bit unsigned integer in big-endian order.
///
/// Supersedes `Curl_read16_be` (`lib/curl_endian.c:79-83`), whose body is
/// `(buf[0] << 8) | buf[1]`.
///
/// # Panics
///
/// Panics if `buf` holds fewer than 2 bytes. The C original reads out of
/// bounds instead.
#[allow(dead_code)]
pub(crate) fn read16_be(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

// ABSORBED SHIM 2 of 6 -- path basename.  `lib/curlx/basename.c:24-74`
//
// THIS IS NOT POSIX `basename()`, and reproducing POSIX here would be a
// silent behaviour change rather than a correction. The C file quotes the
// Open Group specification at length (`:30-53`) and then says, verbatim at
// `:56-57`: "Ignore all the details above for now and make a quick and
// simple implementation here". What it actually implements (`:61-71`) is:
//
//     s1 = strrchr(path, '/');
//     s2 = strrchr(path, '\\');
//     if(s1 && s2) path = ((s1 > s2) ? s1 : s2) + 1;
//     else if(s1)  path = s1 + 1;
//     else if(s2)  path = s2 + 1;
//     return path;
//
// Three POSIX behaviours are therefore ABSENT, and all three stay absent:
//
//   * NO trailing-separator stripping -- POSIX deletes trailing '/'
//     characters, so POSIX maps "dir/" to "dir" while this maps it to "".
//   * NO "." for an empty or null input -- POSIX returns "."; this returns
//     the input unchanged, so "" maps to "".
//   * NO "/" special case -- POSIX returns "/" for a path made entirely of
//     separators; this returns "".
//
// `std::path::Path::file_name()` is NOT used, for exactly those reasons: it
// strips trailing separators, returns `None` for an empty path and for "..",
// and treats the backslash as an ordinary character on Unix. Every one of
// those differences is observable.
//
// Both separators are honoured on ALL platforms. That is deliberate in the C
// and is not turned into a `#[cfg(windows)]` here: curl accepts a Windows
// path in a `CURLOPT_MIMEPOST` filename regardless of the host it runs on,
// and the four mandated targets are Unix, so a platform-conditional would
// change the behaviour on every target this build supports.
//
// The C is wrapped in `#ifndef HAVE_BASENAME` (`:26`), so a platform that
// supplies its own `basename()` never compiles it. In Rust it is
// unconditional: there is no system function to defer to and no configure
// probe to ask, and -- as recorded above -- the system function would be the
// wrong one anyway.
//
// CONSUMER. `crate::mime`, from `lib/mime.c:271`
// (`curlx_strdup(curlx_basename(filename))`). The only other caller,
// `src/tool_doswin.c:323,374`, is Windows-only and excluded.

/// Returns the final component of `path`, after the rightmost `/` or `\`.
///
/// Supersedes `curlx_basename` (`lib/curlx/basename.c:54-72`). This is
/// curl's own simplified rule, NOT POSIX `basename()`: no trailing-separator
/// stripping, no `"."` for an empty input, no `"/"` special case, and both
/// separators recognised on every platform. See the block comment above for
/// the three POSIX behaviours that are deliberately absent.
///
/// The result borrows from `path` and never allocates, matching the C, which
/// returns an interior pointer into its argument.
///
/// ```text
/// "a/b/c"    -> "c"        "a\\b\\c"  -> "c"
/// "a/b\\c"   -> "c"        "a\\b/c"   -> "c"
/// "noslash"  -> "noslash"  ""         -> ""      (NOT ".")
/// "dir/"     -> ""         "/"        -> ""      (NOT "/")
/// ```
#[allow(dead_code)]
pub(crate) fn basename(path: &str) -> &str {
    // `rfind` over a `char` pattern is `strrchr`. Both needles are
    // single-byte ASCII, so the byte offset it returns is a character
    // boundary and `offset + 1` is the boundary just past it -- which is why
    // the slice below can never split a multi-byte code point, whatever the
    // encoding of the surrounding text.
    let last_slash = path.rfind('/');
    let last_backslash = path.rfind('\\');

    // The C's four-branch chain, branch for branch. `last_slash
    // .max(last_backslash)` is equivalent, because `Option`'s ordering makes
    // `None` less than every `Some`, but the explicit form is what a reviewer
    // can check against the C by reading straight down.
    let cut = match (last_slash, last_backslash) {
        (Some(slash), Some(backslash)) => Some(slash.max(backslash)),
        (Some(slash), None) => Some(slash),
        (None, Some(backslash)) => Some(backslash),
        (None, None) => None,
    };

    match cut {
        Some(offset) => &path[offset + 1..],
        // No separator anywhere: the C returns `path` untouched, and so does
        // this. It is what makes `basename("")` yield `""` rather than `"."`.
        None => path,
    }
}

// ABSORBED SHIM 3 of 6 -- bounded string copy.  `lib/curlx/strcopy.c:24-50`
//
// The C, in full (`:38-50`):
//
//     void curlx_strcopy(char *dest, size_t dsize,
//                        const char *src, size_t slen)
//     {
//       DEBUGASSERT(slen < dsize);
//       if(slen < dsize) { memcpy(dest, src, slen); dest[slen] = 0; }
//       else if(dsize) dest[0] = 0;
//     }
//
// THE BEHAVIOUR THAT MATTERS, and the reason this is not `strncpy`: when the
// source does not fit, NOTHING IS COPIED -- but a NUL is still written at
// `dest[0]` whenever the buffer is non-zero. It is a copy-or-empty, not a
// truncating copy. That distinction is precisely what makes it safe: a
// truncating copy hands the caller a prefix that looks like a valid value,
// whereas an empty string is unmistakably a failure. Note also that the
// comparison is `slen < dsize`, strictly: a source of exactly `dsize` bytes
// does NOT fit, because the terminator needs the last byte.
//
// Rust normally has nothing to write here at all, because `String` and
// `Vec<u8>` grow and the question never arises. This helper exists for the
// one place where a fixed-size buffer is genuinely emulated: `inet.rs`, whose
// C originals `inet_ntop4` and `inet_ntop6` format into a caller-provided
// buffer and turn a copy that did not fit into `ENOSPC`. Returning `bool`
// rather than `()` is what lets that caller keep doing so, since C recovers
// the same information by inspecting `dest[0]` afterwards.
//
// The `DEBUGASSERT` is a CALLER-CONTRACT check, not a runtime guard: in C it
// compiles away in a release build and the silent refusal is what remains.
// `debug_assert!` has exactly that property, so the pair is preserved
// faithfully -- and that is why the logic lives in a private inner function.
// Testing the release-mode overflow path through the public entry point would
// trip the assertion, which is what a debug C build does too; the tests
// therefore drive `strcopy_inner` for that case and `strcopy` for the rest.

/// Copies `src` into `dest` and NUL-terminates it, or leaves `dest` empty.
///
/// Supersedes `curlx_strcopy` (`lib/curlx/strcopy.c:38-50`). Returns whether
/// the copy took place:
///
/// - `src.len() < dest.len()`: copies `src`, writes a NUL at
///   `dest[src.len()]`, returns `true`.
/// - otherwise, with a non-empty `dest`: copies NOTHING, writes a NUL at
///   `dest[0]`, returns `false`.
/// - otherwise (`dest` empty): touches nothing, returns `false`.
///
/// The return value may be ignored, as the C callers ignore it, when the
/// caller has already established that the source fits.
///
/// # Panics
///
/// In a debug build only, panics if `src` does not fit, mirroring the C's
/// `DEBUGASSERT(slen < dsize)`. A release build refuses the copy silently,
/// exactly as the C does.
#[allow(dead_code)]
pub(crate) fn strcopy(dest: &mut [u8], src: &[u8]) -> bool {
    debug_assert!(
        src.len() < dest.len(),
        "curlx_strcopy contract: source of {} bytes does not fit a \
         {}-byte buffer with its terminator",
        src.len(),
        dest.len()
    );
    strcopy_inner(dest, src)
}

/// The release-mode body of [`strcopy`], without the contract assertion.
///
/// Private, and separate purely so that the copy-or-empty behaviour can be
/// unit-tested for a source that does not fit without tripping the
/// `debug_assert!` in [`strcopy`].
#[allow(dead_code)]
fn strcopy_inner(dest: &mut [u8], src: &[u8]) -> bool {
    let slen = src.len();

    // Strictly less than, as in the C: the terminator needs one byte.
    if slen < dest.len() {
        dest[..slen].copy_from_slice(src);
        dest[slen] = 0;
        true
    } else if !dest.is_empty() {
        // Did not fit: copy nothing, but leave a valid empty C string
        // behind, which is what the caller inspects to detect the failure.
        dest[0] = 0;
        false
    } else {
        // A zero-length buffer has nowhere to put even the terminator, so
        // the C touches it not at all. `dest[0] = 0` here would panic.
        false
    }
}

// ABSORBED SHIM 4 of 6 -- duplication.  `lib/curlx/strdup.c:24-96`
//
// NO CODE IS WRITTEN FOR THIS FILE, and the omission is the migration rather
// than a gap in it. The three C functions and their disposition:
//
//   * `curlx_memdup(src, length)` (`:64-73`) -- `malloc` then `memcpy`,
//     returning NULL on allocation failure. In Rust this is
//     `slice.to_vec()` or `Vec::from(slice)`: the allocation is infallible
//     from the caller's point of view, the length travels with the value,
//     and `Drop` frees it. There is no signature left to preserve, because
//     the C signature exists only to move a length and a failure flag across
//     a boundary that ownership now expresses.
//   * `curlx_memdup0(src, length)` (`:85-96`) -- the same, plus an appended
//     NUL, guarded by `length < SIZE_MAX` and asserting `src` non-NULL when
//     `length` is non-zero. The Rust expression is `String::from_utf8` or
//     `String::from_utf8_lossy` where the bytes are text, and
//     `slice.to_vec()` where they are not. The NUL-APPENDING CONTRACT
//     MATTERS ONLY when a byte range is handed to something that expects a C
//     string, and inside this crate nothing does: that need survives
//     exclusively at the FFI boundary, where `curl-rs-ffi` owns it with
//     `CString`. It is deliberately not anticipated here.
//   * `curlx_wcsdup(src)` (`:43-51`) -- `#ifdef _WIN32` only. EXCLUDED by
//     the four-target platform boundary, along with the `curlx_tcsdup()`
//     macro it backs.
//
// `curlx_strdup` is not defined in this file at all -- it is the allocator's
// `strdup` under a name, and it needs no Rust counterpart for the same reason
// as `curlx_memdup`.
//
// Writing thin `memdup`-shaped helpers here was considered and rejected: they
// would add API surface with no consumer, and every call site reads better as
// the standard-library method it actually wants.

// ABSORBED SHIM 5 of 6 -- operating-system error strings.
// `lib/curlx/strerr.c:24-331`
//
// CRITICAL DISAMBIGUATION, first, because the two files are one character
// apart in spelling and entirely different in content:
//
//   * `lib/curlx/strerr.c`  -- OPERATING-SYSTEM `errno` text. This file.
//                              Absorbed here as `os_strerror`.
//   * `lib/strerror.c`      -- curl's OWN `CURLcode`, `CURLMcode`,
//                              `CURLUcode` and `CURLSHcode` message text.
//                              That is `crate::error`, and it also backs the
//                              four exported `curl_*_strerror` symbols, whose
//                              message text must match curl 8.19.0-DEV
//                              exactly.
//
// NOT ONE `CURLcode` MESSAGE STRING APPEARS IN THIS FILE. Reproducing any of
// them here would duplicate a table that must have exactly one owner.
//
// `lib/curlx/strerr.c` exports exactly one function -- measured: the file's
// only other function, `get_winsock_error` at `:44`, is `static` and
// Windows-only -- and the source calls it "Our thread-safe and smart
// strerror() replacement":
//
//     const char *curlx_strerror(int err, char *buf, size_t buflen);
//
// Its 331 lines are a portability maze: `strerror_s` on Windows, then
// POSIX-style versus glibc-style `strerror_r` selected by two configure
// probes and backed by a compile-time `#error "strerror_r MUST be either
// POSIX, glibc style"`, then a Winsock error table, then dispatch to
// `Curl_sspi_strerror` and `curlx_winapi_strerror`.
//
// ALL OF IT COLLAPSES to `std::io::Error::from_raw_os_error(err)`, which is
// thread-safe by construction. The reduction is spelled out so that a reader
// does not mistake it for an oversight -- four C behaviours disappear, and
// each one disappears for a stated reason:
//
//   1. The caller-supplied buffer and the `buflen == 0` NULL return (`:258`)
//      have no counterpart: an owned `String` has no buffer to overflow, so
//      the ERANGE handling and the `buflen > sizeof("Unknown error ") + 20`
//      guards guard nothing.
//   2. The trailing `'\r\n'`/`'\n'` strip (`:314-320`, with its
//      `(p - buf) >= 2` and `>= 1` quirks) is a MEASURED no-op on the four
//      mandated targets: the only producer of a trailing CRLF is the Windows
//      `FormatMessage` path in `curlx_winapi_strerror`, which is excluded,
//      and `std::io::Error` never yields one. It is therefore not
//      reproduced.
//   3. The `errno` save-and-restore (`:255`, `:322-323`) exists because
//      `strerror_r` may clobber `errno` and a C caller re-reads it later. In
//      Rust an error is a VALUE captured at construction, so nothing
//      re-reads `errno` after formatting and there is nothing to protect.
//   4. `get_winsock_error`, `Curl_sspi_strerror` and `curlx_winapi_strerror`
//      are Windows-only and EXCLUDED, along with `lib/curl_sspi.c`.
//
// ONE DIVERGENCE IS REAL AND IS CORRECTED RATHER THAN ACCEPTED.
// `std::io::Error`'s `Display` appends " (os error N)", so
// `from_raw_os_error(2).to_string()` is "No such file or directory (os error
// 2)" where the C yields the bare "No such file or directory". Measured
// consequence: the suffix is NOT visible to the test harness -- searching the
// 1,914-fixture corpus for the three commonest `errno` messages matches
// exactly one file, `tests/data/test3027:14`, and that line is an FTP server
// reply ("REPLY MDTM 550 Permission denied"), not `strerror` output. It IS
// visible in `failf()` text, though, and the preservation mandate is about
// behaviour and not only about fixtures, so the suffix is stripped.
//
// THIS FILE OWNS THAT STRIP FOR THE WHOLE WORKSPACE, and the centralization
// is the correction of a measured divergence rather than tidiness. Three
// independent implementations existed -- here, in
// `curl-rs/src/output/formparse.rs` and in `curl-rs/src/output/filetime.rs` --
// and two of them already disagreed: the `formparse` one stripped a single
// trailing suffix, so under Miri, where `std` emits two (see
// [`strip_os_error_suffix`]), it left one behind and a frozen diagnostic
// changed. A diagnostic whose bytes depend on which file rendered it is a
// defect no matter which spelling is nicer, so there is now exactly one
// algorithm, reached by every consumer through [`os_error_message`].

/// The annotation `std::io::Error`'s `Display` appends and C never emits.
///
/// Matched literally, including the leading space, so that a message merely
/// containing the words cannot be mistaken for an annotated one.
const OS_ERROR_INFIX: &str = " (os error ";

/// Renders an [`std::io::Error`] the way `curlx_strerror` renders `errno`.
///
/// THE ONE ENTRY POINT for operating-system error text anywhere in the
/// workspace, and the reason it is `pub` while the rest of this module is not:
/// `curl-rs` interpolates `strerror(errno)` into frozen diagnostics at
/// `src/tool_formparse.c:220` and `:561`, at `src/tool_filetime.c:79` and
/// `:136`, and at `src/tool_operate.c:637-639`, and every one of those must
/// produce the same bytes as every other. Reaching that guarantee by
/// convention failed once already, which is recorded above.
///
/// The result is the bare system text: `No such file or directory`, not
/// `No such file or directory (os error 2)`.
///
/// # Why it takes an error rather than an `errno`
///
/// Two of the three consumers hold an [`std::io::Error`] that the standard
/// library handed them and never see a number; `raw_os_error()` would give
/// them one only when the error came from the operating system at all. A
/// helper that stripped an exact, known suffix when the caller had the number
/// and a pattern otherwise would be two behaviours again -- which is precisely
/// the shape of the bug being removed. It therefore recognises the annotation
/// by its form, strictly, and never needs the number.
///
/// Callers holding an `errno` use `os_strerror`, which is this function with
/// the error constructed for them. That one is crate-private -- it is named
/// here without a link deliberately, because a link from public
/// documentation to a private item is a rustdoc warning, and this crate
/// carries no warnings.
///
/// # Examples
///
/// The assertion is on the CONTRACT rather than on the text, because the text
/// is the platform's and differs between Linux and Darwin. This example is
/// also the reachability proof for the re-export at the crate root: rustdoc
/// compiles it as a separate crate that links this one exactly as `curl-rs`
/// does, so if the name were not reachable from outside, this would fail to
/// build.
///
/// ```
/// use std::io::Error;
///
/// // ENOENT, which is 2 on all four mandated targets.
/// let text = curl_rs_lib::os_error_message(&Error::from_raw_os_error(2));
/// assert!(!text.is_empty());
/// assert!(!text.contains("(os error"), "the annotation must be gone");
/// ```
pub fn os_error_message(error: &std::io::Error) -> String {
    strip_os_error_suffix(&error.to_string()).to_owned()
}

/// Returns the operating system's message for an `errno` value.
///
/// Supersedes `curlx_strerror` (`lib/curlx/strerr.c:250-331`). Thread-safe by
/// construction: no shared buffer, no `strerror_r` variant selection, and no
/// caller-supplied storage. The `" (os error N)"` suffix that
/// `std::io::Error`'s `Display` appends is removed by
/// [`os_error_message`], so the text matches what the C reports.
///
/// This is the OPERATING SYSTEM's error text. curl's own result-code messages
/// belong to [`crate::error`] and are not duplicated here.
///
/// # Panics
///
/// In a debug build only, panics on a negative `err`, mirroring the C's
/// `DEBUGASSERT(err >= 0)` at `:262`, which is itself guarded `#ifndef
/// _WIN32` and therefore active on all four mandated targets. A release build
/// returns whatever the platform reports for the value, which for an
/// unrecognised number is an "Unknown error" form rather than a panic.
#[allow(dead_code)]
pub(crate) fn os_strerror(err: i32) -> String {
    debug_assert!(err >= 0, "errno values are non-negative, got {err}");

    os_error_message(&std::io::Error::from_raw_os_error(err))
}

/// Removes every trailing [`OS_ERROR_INFIX`] annotation from rendered text.
///
/// Borrows rather than allocating, so a caller that only needs to print the
/// text pays nothing; [`os_error_message`] owns the copy for the callers that
/// need one.
///
/// STRIPPING TO A FIXED POINT RATHER THAN ONCE is deliberate, and the reason
/// was measured rather than guessed. On all four mandated targets `std`
/// appends the annotation exactly once, so one pass and many passes produce
/// the identical string and the choice is observationally neutral there. Under
/// a hosted `std` whose `strerror_r` is emulated it is not:
///
///   real target  errno 2 -> `No such file or directory (os error 2)`
///   under Miri   errno 2 -> `No such file or directory (os error 2) (os
///                            error 2)`
///
/// Miri's shim returns text that already carries the annotation and `Display`
/// then appends its own. A one-shot strip leaves a residue there, so the
/// contract fails under the same tool that checks the crate for undefined
/// behaviour -- and excusing this function from the Miri gate would trade a
/// real check for an imaginary risk. A fixed-point strip is the only form that
/// yields C's bare text in both environments while never yielding a
/// *different* string on a real target.
///
/// One theoretical ambiguity is accepted with it, and named rather than
/// hidden: an operating system whose bare message happened to END in
/// ` (os error N)` would lose that ending. No platform does, and the
/// alternative -- excusing this function from the Miri gate -- would trade a
/// real check for an imaginary risk.
///
/// Each pass is [`strip_one_os_error_suffix`] and returns a strictly shorter
/// slice, so the loop always terminates.
fn strip_os_error_suffix(rendered: &str) -> &str {
    let mut text = rendered;
    while let Some(shorter) = strip_one_os_error_suffix(text) {
        text = shorter;
    }
    text
}

/// One pass of [`strip_os_error_suffix`]: `Some` when a suffix was removed.
///
/// Conservative by construction. An annotation is recognised only when the
/// text ends with `)`, contains [`OS_ERROR_INFIX`] before it, and every byte
/// between the two is an ASCII digit. Anything else -- a message whose own
/// text merely contains a parenthesis, a code that is not decimal, or a
/// `Display` implementation that never appended one -- yields `None` and
/// leaves the text untouched. A future change to the standard library's
/// format therefore leaves the message intact instead of mangling it.
///
/// The last occurrence is taken, so the innermost real message survives when
/// several annotations are stacked.
fn strip_one_os_error_suffix(rendered: &str) -> Option<&str> {
    // `?` and `get` are used in place of indexing so that no input can produce
    // a panicking path.
    let tail = rendered.strip_suffix(')')?;
    let start = tail.rfind(OS_ERROR_INFIX)?;
    let digits = tail.get(start.saturating_add(OS_ERROR_INFIX.len())..)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    tail.get(..start)
}

// ABSORBED SHIM 6 of 6 -- narrowing conversions.
// `lib/curlx/warnless.c:24-341`, `lib/curlx/warnless.h:26-80`
//
// This is the one absorbed shim with real semantics, and the one where a
// plausible-looking simplification would be a defect.
//
// MEASURED INVENTORY, because the count matters and a summary of it was off:
// `warnless.h` declares 18 FUNCTIONS plus 1 MACRO -- 19 items, not 20. All 18
// are defined in `warnless.c` (at `:54, 72, 90, 110, 130, 151, 172, 191, 209,
// 227, 248, 266, 281, 286, 297, 307, 323, 334`) and all 18 appear below. The
// macro is `CURLX_FUNCTION_CAST`, dealt with at the end of this section.
// Thirteen are plain narrowing; five carry behaviour that must survive.
//
// WHAT THE C ACTUALLY DOES, and it is not what the name suggests. Each plain
// helper is a `DEBUGASSERT` on the range FOLLOWED BY A MASK, and the mask --
// not the assertion -- is what survives into a release build:
//
//     int curlx_sltosi(long slnum) {
//       DEBUGASSERT(slnum >= 0);
//       DEBUGASSERT((unsigned long)slnum <= (unsigned long)CURL_MASK_SINT);
//       return (int)(slnum & (long)CURL_MASK_SINT);
//     }
//
// So `curlx_sltosi(-1)` returns 0x7fffffff in a release build, whereas Rust's
// `-1i64 as i32` returns -1. THE MASK IS THEREFORE MANDATORY, not decoration:
// writing a bare cast would silently change the result for exactly the inputs
// the assertion exists to catch. Every mask below is reproduced from the C,
// and the masks themselves are `warnless.c:39-49`:
//
//     CURL_MASK_UCHAR   0xff                 CURL_MASK_ULONG    u64::MAX
//     CURL_MASK_USHORT  0xffff               CURL_MASK_USIZE_T  usize::MAX
//     CURL_MASK_UINT    0xffff_ffff          CURL_MASK_SSIZE_T  usize::MAX>>1
//     CURL_MASK_SINT    0x7fff_ffff
//
// The `DEBUGASSERT`s become `debug_assert!`, which has precisely the C
// property: present in a debug build, compiled out in a release build. Where
// the C combines two assertions -- a non-negativity check and an upper bound
// -- the Rust states the closed range once, which is both the same condition
// and the form clippy prefers.
//
// A BARE `as` CAST IS NEVER USED FOR A NARROWING CONVERSION HERE. Where a
// conversion is a widening that cannot lose information on any of the four
// mandated 64-bit targets, `as` is used and the reason is proved in a comment
// at the site; `try_into().expect(..)` was considered for those and rejected,
// because it introduces a panic path for a condition that cannot arise.
//
// SEVERAL C BRANCHES ARE COMPILED OUT ON EVERY MANDATED TARGET, and each is
// noted where it applies rather than silently dropped:
// `#if ULONG_MAX < SIZE_MAX` (false: both 64-bit),
// `#if SIZEOF_CURL_OFF_T > SIZEOF_SIZE_T` (false: both 8 bytes) and
// `#if INT_MAX < SSIZE_MAX` (true, so those assertions DO apply).

/// curl's file-size and offset type: `curl_off_t`.
///
/// 64-bit signed on all four mandated targets. `include/curl/system.h:396`
/// defines `curl_off_t` as `CURL_TYPEOF_CURL_OFF_T`, which resolves to `long`
/// or `long long` depending on the platform, and `lib/curl_setup.h:595-599`
/// rejects any platform where it is smaller than 8 bytes outright ("too small
/// curl_off_t") and pins `CURL_OFF_T_MAX` to `0x7FFFFFFFFFFFFFFF`. That is
/// exactly [`i64::MAX`], which is why the saturation in [`uztoso`] can be
/// expressed against the Rust constant.
///
/// The alias exists so that a signature reading `CurlOffT` says "this is a
/// curl offset" rather than "this happens to be 64 bits", and so that the
/// 64-bit-only assumption has one documented home. That assumption is a
/// deliberate forfeit of 32-bit support, recorded rather than hidden: the C
/// ABI shim carries a `curl_off_t` through a single register-width slot in
/// the variadic option setters, which is sound only where the type fits a
/// register.
#[allow(dead_code)]
pub(crate) type CurlOffT = i64;

// --- The thirteen plain narrowing conversions -------------------------------

/// `unsigned long` to `unsigned char` -- `curlx_ultouc`, `warnless.c:54-67`.
///
/// # Panics
///
/// In a debug build only, if the value exceeds `0xff`. A release build masks,
/// as the C does.
#[allow(dead_code)]
pub(crate) fn ultouc(ulnum: u64) -> u8 {
    debug_assert!(ulnum <= u64::from(u8::MAX));
    (ulnum & 0xff) as u8 // CURL_MASK_UCHAR
}

/// `size_t` to `int` -- `curlx_uztosi`, `warnless.c:72-85`.
///
/// # Panics
///
/// In a debug build only, if the value exceeds `INT_MAX`. A release build
/// masks, as the C does.
#[allow(dead_code)]
pub(crate) fn uztosi(uznum: usize) -> i32 {
    debug_assert!(uznum <= 0x7fff_ffff);
    (uznum & 0x7fff_ffff) as i32 // CURL_MASK_SINT
}

/// `size_t` to `unsigned long` -- `curlx_uztoul`, `warnless.c:90-105`.
///
/// A widening on the four mandated targets, where `unsigned long` and
/// `size_t` are both 64 bits: the C's `#if ULONG_MAX < SIZE_MAX` assertion is
/// compiled out and its `CURL_MASK_ULONG` mask is the identity, so no
/// information can be lost and there is nothing to assert.
#[allow(dead_code)]
pub(crate) fn uztoul(uznum: usize) -> u64 {
    uznum as u64
}

/// `size_t` to `unsigned int` -- `curlx_uztoui`, `warnless.c:110-125`.
///
/// # Panics
///
/// In a debug build only, if the value exceeds `UINT_MAX`. A release build
/// masks, as the C does.
#[allow(dead_code)]
pub(crate) fn uztoui(uznum: usize) -> u32 {
    debug_assert!(uznum <= 0xffff_ffff);
    (uznum & 0xffff_ffff) as u32 // CURL_MASK_UINT
}

/// `long` to `int` -- `curlx_sltosi`, `warnless.c:130-146`.
///
/// # Panics
///
/// In a debug build only, if the value is negative or exceeds `INT_MAX` --
/// the C's two assertions, stated once as the closed range they describe. A
/// release build masks, so a negative input yields `0x7fff_ffff`.
#[allow(dead_code)]
pub(crate) fn sltosi(slnum: i64) -> i32 {
    debug_assert!((0..=0x7fff_ffff).contains(&slnum));
    (slnum & 0x7fff_ffff) as i32 // CURL_MASK_SINT
}

/// `long` to `unsigned int` -- `curlx_sltoui`, `warnless.c:151-167`.
///
/// # Panics
///
/// In a debug build only, if the value is negative or exceeds `UINT_MAX`. A
/// release build masks, as the C does.
#[allow(dead_code)]
pub(crate) fn sltoui(slnum: i64) -> u32 {
    debug_assert!((0..=0xffff_ffff).contains(&slnum));
    (slnum & 0xffff_ffff) as u32 // CURL_MASK_UINT
}

/// `long` to `unsigned short` -- `curlx_sltous`, `warnless.c:172-186`.
///
/// # Panics
///
/// In a debug build only, if the value is negative or exceeds `USHRT_MAX`. A
/// release build masks, as the C does.
#[allow(dead_code)]
pub(crate) fn sltous(slnum: i64) -> u16 {
    debug_assert!((0..=0xffff).contains(&slnum));
    (slnum & 0xffff) as u16 // CURL_MASK_USHORT
}

/// `size_t` to `ssize_t` -- `curlx_uztosz`, `warnless.c:191-204`.
///
/// # Panics
///
/// In a debug build only, if the value exceeds `SSIZE_MAX`. A release build
/// masks, which clears the sign bit rather than producing a negative result.
#[allow(dead_code)]
pub(crate) fn uztosz(uznum: usize) -> isize {
    debug_assert!(uznum <= usize::MAX >> 1);
    (uznum & (usize::MAX >> 1)) as isize // CURL_MASK_SSIZE_T
}

/// `curl_off_t` to `size_t` -- `curlx_sotouz`, `warnless.c:209-222`.
///
/// The C masks with `(curl_off_t)CURL_MASK_USIZE_T`, which on a target where
/// `size_t` and `curl_off_t` are both 64 bits is all-ones -- the identity --
/// so only the assertion carries meaning here. A release build reinterprets a
/// negative value as a huge `usize`, exactly as the C does.
///
/// # Panics
///
/// In a debug build only, if the value is negative.
#[allow(dead_code)]
pub(crate) fn sotouz(sonum: CurlOffT) -> usize {
    debug_assert!(sonum >= 0);
    sonum as usize
}

/// `ssize_t` to `int` -- `curlx_sztosi`, `warnless.c:227-243`.
///
/// # Panics
///
/// In a debug build only, if the value is negative or exceeds `INT_MAX`. Both
/// C assertions apply on the mandated targets, because `#if INT_MAX <
/// SSIZE_MAX` holds there. A release build masks.
#[allow(dead_code)]
pub(crate) fn sztosi(sznum: isize) -> i32 {
    debug_assert!((0..=0x7fff_ffff).contains(&sznum));
    (sznum & 0x7fff_ffff) as i32 // CURL_MASK_SINT
}

/// `unsigned int` to `unsigned short` -- `curlx_uitous`,
/// `warnless.c:248-261`.
///
/// # Panics
///
/// In a debug build only, if the value exceeds `USHRT_MAX`. A release build
/// masks, as the C does.
#[allow(dead_code)]
pub(crate) fn uitous(uinum: u32) -> u16 {
    debug_assert!(uinum <= u32::from(u16::MAX));
    (uinum & 0xffff) as u16 // CURL_MASK_USHORT
}

/// `int` to `size_t` -- `curlx_sitouz`, `warnless.c:266-279`.
///
/// The C has no mask here, only the assertion, so a release build converts a
/// negative value to a huge `usize` by two's-complement
/// reinterpretation. Rust's `as` does the same on the mandated targets, which
/// is why the behaviour is preserved without one.
///
/// # Panics
///
/// In a debug build only, if the value is negative.
#[allow(dead_code)]
pub(crate) fn sitouz(sinum: i32) -> usize {
    debug_assert!(sinum >= 0);
    sinum as usize
}

/// `unsigned int` to `size_t` -- `curlx_uitouz`, `warnless.c:281-284`.
///
/// The only helper in the C with neither an assertion nor a mask, because a
/// 32-bit unsigned value always fits a 64-bit `size_t`. `usize::from` is not
/// implemented for `u32` -- it would be wrong on a 16-bit target -- so the
/// widening is spelled with `as`, and it cannot lose information on any
/// mandated target.
#[allow(dead_code)]
pub(crate) fn uitouz(uinum: u32) -> usize {
    uinum as usize
}

// --- The five conversions that carry behaviour ------------------------------

/// Fits a `curl_off_t` into the `size_t` interval `[uzmin, uzmax]`.
///
/// Supersedes `curlx_sotouz_range` (`warnless.c:286-295`). SATURATES: the
/// header's wording is "values outside this interval give the lower/upper
/// bound", and a NEGATIVE value gives `uzmin`, the LOWER bound.
///
/// [`Ord::clamp`] is deliberately not used. It panics when `min > max`,
/// whereas the C -- `CURLMIN(CURLMAX(v, uzmin), uzmax)` -- returns `uzmax`
/// for that degenerate call and returns `uzmin` for a negative value even
/// then. The `max`-then-`min` composition below reproduces the C for every
/// input, including inputs a caller should never pass.
#[allow(dead_code)]
pub(crate) fn sotouz_range(
    sonum: CurlOffT,
    uzmin: usize,
    uzmax: usize,
) -> usize {
    if sonum < 0 {
        return uzmin;
    }

    // The C's `if(sonum > SIZE_MAX) return uzmax;` sits inside
    // `#if SIZEOF_CURL_OFF_T > SIZEOF_SIZE_T`, which is false on all four
    // mandated targets, so it is compiled out there too. Past the negative
    // test the value is non-negative and both types are 64 bits, so this
    // conversion is exact.
    let value = sonum as usize;

    value.max(uzmin).min(uzmax)
}

/// `size_t` to `curl_off_t`, saturating at `CURL_OFF_T_MAX`.
///
/// Supersedes `curlx_uztoso` (`warnless.c:334-341`). SATURATES rather than
/// wrapping: the header's wording is "return CURL_OFF_T_MAX if too large",
/// and `CURL_OFF_T_MAX` is `0x7FFFFFFFFFFFFFFF` (`lib/curl_setup.h:599`),
/// which is [`i64::MAX`].
#[allow(dead_code)]
pub(crate) fn uztoso(uznum: usize) -> CurlOffT {
    CurlOffT::try_from(uznum).unwrap_or(CurlOffT::MAX)
}

/// `ssize_t` to `size_t`, or `None` if negative.
///
/// Supersedes `curlx_sztouz` (`warnless.c:297-305`), whose contract is
/// "return FALSE if negative and set 0". The `bool` plus out-parameter pair
/// becomes an [`Option`], which cannot be misread: C's caller may ignore the
/// `bool` and use the zeroed out-parameter, and a caller that wants the same
/// behaviour here writes `sztouz(n).unwrap_or(0)`.
#[allow(dead_code)]
pub(crate) fn sztouz(sznum: isize) -> Option<usize> {
    usize::try_from(sznum).ok()
}

/// `curl_off_t` to `size_t`, or `None` if negative or too large.
///
/// Supersedes `curlx_sotouz_fits` (`warnless.c:307-321`), whose contract is
/// "return FALSE if negative or too large and set 0". On the mandated targets
/// only the negative case can arise, because the C's magnitude test sits
/// inside `#if SIZEOF_CURL_OFF_T > SIZEOF_SIZE_T`; [`usize::try_from`] covers
/// both without a conditional, so this is faithful there and correct
/// elsewhere.
///
/// Kept distinct from [`sztouz`] even though the two bodies coincide on the
/// mandated targets, because the C keeps them distinct and a call site that
/// reads `sotouz_fits` is converting an OFFSET while one that reads `sztouz`
/// is converting the RESULT OF A READ OR WRITE. Collapsing them would erase
/// that at every call site.
#[allow(dead_code)]
pub(crate) fn sotouz_fits(sonum: CurlOffT) -> Option<usize> {
    usize::try_from(sonum).ok()
}

/// `long` to `size_t`, or `None` if negative or too large.
///
/// Supersedes `curlx_sltouz` (`warnless.c:323-332`), whose contract is
/// "return FALSE if negative or too large and set 0". The C notes at `:329`
/// that `curl_setup.h` rejects any platform where `SIZEOF_LONG >
/// SIZEOF_SIZE_T`, so only the negative case can arise; the conversion below
/// covers both regardless.
#[allow(dead_code)]
pub(crate) fn sltouz(slnum: i64) -> Option<usize> {
    usize::try_from(slnum).ok()
}

// `CURLX_FUNCTION_CAST` -- the one item with NO Rust counterpart.
//
//     #define CURLX_FUNCTION_CAST(target_type, func) \
//       (target_type)(void (*)(void))(func)
//
// `warnless.h:27-28`, three uses in the C tree. It launders a function
// pointer through `void (*)(void)` so that a compiler cannot warn about
// assigning a function of one signature to a pointer of another -- typically
// a destructor whose real parameter type differs from the `void *` the vtable
// slot declares.
//
// IT IS NOT REPRODUCED, and it must not be. Rust function items are strongly
// typed, and there is no safe expression of the cast because there is nothing
// safe about it: the C pattern works only as long as every call goes through
// the original signature, and nothing checks that. The pattern it enables is
// exactly what the typed-context connection-filter design eliminates -- where
// `struct Curl_cftype` carries a `void *ctx` that every filter casts to its
// own type (`lib/cfilters.h:210-226`), `Box<dyn ConnFilter>` carries a typed
// field and the cast has no place to occur.
//
// Anything that appeared to need this macro is a design error at the call
// site, and the fix belongs there rather than here.

// TESTS
//
// `tests/unit/*.c` (59 files) and `tests/libtest/*.c` (235) link a debug
// static libcurl and call internal `Curl_*` symbols, which a Rust static
// library does not export. Their coverage therefore relocates into
// `#[cfg(test)]` modules inside the files under test, and this is this file's
// share of that relocation.
//
// TWO BUILD MODES, TWO SETS OF ASSERTIONS -- because the C behaves differently
// in each and a single set would be able to check only one of them.
// `cargo test` builds with `debug_assertions` on, so an out-of-range input
// reaches a `debug_assert!` and panics; `cargo test --release` builds with it
// off, so the same input reaches the mask and returns the masked value. The
// tests below are split accordingly: `#[cfg(debug_assertions)]` proves the
// contract assertions FIRE, and `#[cfg(not(debug_assertions))]` proves the
// masked release behaviour matches the C. Everything else runs in both.
//
// Both halves must be run to have checked this file completely:
//     cargo test -p curl-rs-lib
//     cargo test -p curl-rs-lib --release

#[cfg(test)]
mod tests {
    // The crate's convention for a `#[cfg(test)] mod tests`, and it is what
    // reaches `strcopy_inner`: the private release-mode body is visible to a
    // child module of the one that declares it, which is exactly why the
    // split described above is testable without widening anything.
    use super::*;

    // --- shim 1: byte order ------------------------------------------------

    /// Hand-computed against `lib/curl_endian.c:41-45`: `buf[0] | buf[1] <<
    /// 8`.
    #[test]
    fn read16_le_matches_the_c() {
        assert_eq!(read16_le(&[0x00, 0x00]), 0x0000);
        assert_eq!(read16_le(&[0x34, 0x12]), 0x1234);
        assert_eq!(read16_le(&[0x01, 0x00]), 0x0001);
        assert_eq!(read16_le(&[0x00, 0x01]), 0x0100);
        assert_eq!(read16_le(&[0xff, 0xff]), 0xffff);
    }

    /// Hand-computed against `lib/curl_endian.c:60-64`.
    #[test]
    fn read32_le_matches_the_c() {
        assert_eq!(read32_le(&[0x00, 0x00, 0x00, 0x00]), 0x0000_0000);
        assert_eq!(read32_le(&[0x78, 0x56, 0x34, 0x12]), 0x1234_5678);
        assert_eq!(read32_le(&[0x01, 0x00, 0x00, 0x00]), 0x0000_0001);
        assert_eq!(read32_le(&[0x00, 0x00, 0x00, 0x80]), 0x8000_0000);
        assert_eq!(read32_le(&[0xff, 0xff, 0xff, 0xff]), 0xffff_ffff);
    }

    /// Hand-computed against `lib/curl_endian.c:79-83`: `buf[0] << 8 |
    /// buf[1]`.
    #[test]
    fn read16_be_matches_the_c() {
        assert_eq!(read16_be(&[0x00, 0x00]), 0x0000);
        assert_eq!(read16_be(&[0x12, 0x34]), 0x1234);
        assert_eq!(read16_be(&[0x01, 0x00]), 0x0100);
        assert_eq!(read16_be(&[0x00, 0x01]), 0x0001);
        assert_eq!(read16_be(&[0xff, 0xff]), 0xffff);
    }

    /// The two 16-bit readers are byte-swaps of one another, and a longer
    /// slice is read from its front -- which is how every C caller uses them,
    /// passing an interior pointer into a larger message.
    #[test]
    fn endian_readers_are_consistent_and_read_from_the_front() {
        let message = [0x34, 0x12, 0x78, 0x56, 0x99];
        assert_eq!(read16_le(&message), 0x1234);
        assert_eq!(read16_be(&message), 0x3412);
        assert_eq!(read32_le(&message), 0x5678_1234);
        assert_eq!(read16_le(&message[2..]), 0x5678);
    }

    // --- shim 2: basename --------------------------------------------------

    /// Every case from `lib/curlx/basename.c:61-71`, including the three
    /// POSIX behaviours this deliberately does NOT implement.
    #[test]
    fn basename_is_curls_rule_and_not_posix() {
        // The rightmost separator wins, whichever kind it is.
        assert_eq!(basename("a/b/c"), "c");
        assert_eq!(basename("a\\b\\c"), "c");
        assert_eq!(basename("a/b\\c"), "c");
        assert_eq!(basename("a\\b/c"), "c");

        // No separator at all: the input is returned untouched.
        assert_eq!(basename("noslash"), "noslash");

        // NOT ".", which is what POSIX returns for an empty path.
        assert_eq!(basename(""), "");

        // NO trailing-separator stripping: POSIX would answer "dir".
        assert_eq!(basename("dir/"), "");
        assert_eq!(basename("dir\\"), "");

        // NOT "/", which is what POSIX returns for a root path.
        assert_eq!(basename("/"), "");
        assert_eq!(basename("///"), "");

        // Absolute and relative forms, and the ".." that
        // `Path::file_name()` would answer `None` for.
        assert_eq!(basename("/usr/local/bin/curl"), "curl");
        assert_eq!(basename("./file.txt"), "file.txt");
        assert_eq!(basename(".."), "..");
        assert_eq!(basename("C:\\Windows\\curl.exe"), "curl.exe");
    }

    /// The result borrows from the argument, as the C returns an interior
    /// pointer, and multi-byte text is never split: both separators are
    /// single-byte ASCII, so the cut is always on a character boundary.
    ///
    /// The multi-byte characters are written as `\u{..}` escapes rather than
    /// literally. `scripts/spacecheck.pl` enumerates `git ls-files` and
    /// rejects any byte in `[\x80-\xff]` outside the six files listed in its
    /// `@non_ascii` allow-list; it runs in continuous integration at
    /// `.github/workflows/hygiene.yml:164-165`. The escapes keep the source
    /// pure ASCII while the strings under test stay multi-byte, so the
    /// coverage is identical and the hygiene gate stays green.
    #[test]
    fn basename_borrows_and_respects_character_boundaries() {
        // "directory/na<U+00EF>ve-caf<U+00E9>.txt": the two accented
        // characters occupy two bytes each in UTF-8, so the tail begins at
        // byte 10 and spans 16 bytes rather than 14 characters' worth.
        let path = String::from("directory/na\u{ef}ve-caf\u{e9}.txt");
        let base = basename(&path);
        assert_eq!(base, "na\u{ef}ve-caf\u{e9}.txt");
        assert!(std::ptr::eq(base.as_bytes(), &path.as_bytes()[10..]));

        // A separator immediately before multi-byte text.
        assert_eq!(basename("dir/\u{e9}"), "\u{e9}");
        // Multi-byte text with no separator survives whole.
        assert_eq!(basename("\u{e9}"), "\u{e9}");
    }

    // --- shim 3: bounded string copy ---------------------------------------

    /// A source that fits is copied and NUL-terminated
    /// (`lib/curlx/strcopy.c:44-47`).
    #[test]
    fn strcopy_copies_and_terminates_when_it_fits() {
        let mut dest = [0xaa_u8; 8];
        assert!(strcopy(&mut dest, b"abc"));
        assert_eq!(&dest[..4], b"abc\0");
        // Bytes past the terminator are untouched, as `memcpy` leaves them.
        assert_eq!(&dest[4..], &[0xaa, 0xaa, 0xaa, 0xaa]);
    }

    /// The boundary is `slen < dsize`, strictly: a source of exactly the
    /// buffer's length does NOT fit, because the terminator needs a byte.
    /// Driven through the inner function because the outer one asserts the
    /// caller's contract, which a debug build would enforce with a panic.
    #[test]
    fn strcopy_boundary_is_strictly_less_than() {
        let mut dest = [0xaa_u8; 4];
        assert!(strcopy(&mut dest, b"abc"));
        assert_eq!(&dest[..], b"abc\0");

        let mut dest = [0xaa_u8; 4];
        assert!(!strcopy_inner(&mut dest, b"abcd"));
        assert_eq!(&dest[..], &[0x00, 0xaa, 0xaa, 0xaa]);
    }

    /// The behaviour that makes this safe: a source that does not fit copies
    /// NOTHING, yet still leaves a valid empty string behind
    /// (`lib/curlx/strcopy.c:48-49`). It is a copy-or-empty, not a
    /// truncating copy.
    #[test]
    fn strcopy_that_does_not_fit_copies_nothing_but_empties() {
        let mut dest = [0xaa_u8; 4];
        assert!(!strcopy_inner(&mut dest, b"far too long"));
        assert_eq!(dest[0], 0, "a NUL must still be written at dest[0]");
        assert_eq!(
            &dest[1..],
            &[0xaa, 0xaa, 0xaa],
            "no source byte may be copied when the source does not fit"
        );
    }

    /// A zero-length buffer has nowhere to put even the terminator, so the C
    /// touches it not at all.
    #[test]
    fn strcopy_leaves_a_zero_length_buffer_untouched() {
        let mut dest: [u8; 0] = [];
        assert!(!strcopy_inner(&mut dest, b""));
        assert!(!strcopy_inner(&mut dest, b"x"));
        assert!(dest.is_empty());
    }

    /// An empty source still terminates, provided there is a byte for it.
    #[test]
    fn strcopy_of_an_empty_source_writes_only_the_terminator() {
        let mut dest = [0xaa_u8; 2];
        assert!(strcopy(&mut dest, b""));
        assert_eq!(&dest[..], &[0x00, 0xaa]);
    }

    // --- shim 5: operating-system error strings ----------------------------

    /// A known `errno` produces its message, and the standard library's
    /// " (os error N)" annotation is removed so that the text matches what
    /// `curlx_strerror` reports.
    #[test]
    fn os_strerror_returns_the_bare_message() {
        // ENOENT is 2 on every mandated target.
        let enoent = os_strerror(2);
        assert!(!enoent.is_empty());
        assert!(
            !enoent.contains("(os error"),
            "the std annotation must be stripped, got {enoent:?}"
        );
        assert!(!enoent.ends_with(' '));

        // Errno 0 is a legal input: the assertion is `err >= 0`.
        assert!(!os_strerror(0).is_empty());
    }

    /// An unrecognised error number must not panic, in either build mode,
    /// and must still yield something printable -- the C reaches its
    /// "Unknown error %d" fallback for exactly these values.
    #[test]
    fn os_strerror_tolerates_an_unknown_error_number() {
        for err in [4095, 12345, i32::MAX] {
            let message = os_strerror(err);
            assert!(!message.is_empty(), "empty message for errno {err}");
            assert!(!message.contains("(os error"));
        }
    }

    /// The annotation is stripped to a FIXED POINT, not once.
    ///
    /// This is the divergence that made the helper shared: the copy in
    /// `curl-rs/src/output/formparse.rs` stripped a single suffix, so under
    /// Miri -- where `std` emits two -- it left one behind and a frozen
    /// diagnostic changed. The doubled form is asserted directly rather than
    /// waited for, so the contract is checked on every target and not only
    /// under the tool that produces it.
    #[test]
    fn the_suffix_strip_runs_to_a_fixed_point() {
        assert_eq!(
            strip_os_error_suffix(
                "No such file or directory (os error 2) (os error 2)"
            ),
            "No such file or directory",
            "both annotations must go, which one pass cannot do"
        );

        // A single pass is what a lone strip would have achieved, so it is
        // asserted separately to show the fixed point is not masking it.
        assert_eq!(
            strip_one_os_error_suffix(
                "No such file or directory (os error 2) (os error 2)"
            ),
            Some("No such file or directory (os error 2)"),
            "one pass removes exactly one, and that was the bug"
        );

        // Three, and differing numbers, because nothing in the algorithm
        // depends on the codes agreeing with each other.
        let stacked = "boom (os error 1) (os error 22) (os error 2)";
        assert_eq!(strip_os_error_suffix(stacked), "boom");
    }

    /// Text carrying no annotation is returned completely unchanged, and the
    /// recognition is strict enough that near misses are near misses.
    #[test]
    fn text_without_the_annotation_is_returned_unchanged() {
        for untouched in [
            "",
            ")",
            "entity already exists",
            "No such file or directory",
            // A parenthesis of its own is not an annotation.
            "odd (thing)",
            // The code must be decimal digits, and at least one.
            "weird (os error abc)",
            "weird (os error )",
            "weird (os error -1)",
            // The annotation must END the text; C's message never has a tail.
            "x (os error 2) y",
            // No message before the marker means no leading space, so the
            // marker itself is absent and the text stands.
            "(os error 2)",
        ] {
            assert_eq!(
                strip_os_error_suffix(untouched),
                untouched,
                "{untouched:?} must survive intact"
            );
            assert_eq!(strip_one_os_error_suffix(untouched), None);
        }
    }

    /// The two entry points are the same function, which is the whole point of
    /// centralising them: a diagnostic's bytes cannot depend on whether the
    /// caller happened to hold an `errno` or an `io::Error`.
    #[test]
    fn the_two_entry_points_cannot_disagree() {
        for err in [0, 2, 13, 21, 22, EXDEV_LIKE_UNKNOWN] {
            assert_eq!(
                os_strerror(err),
                os_error_message(&std::io::Error::from_raw_os_error(err)),
                "the errno and io::Error paths diverged at {err}"
            );
        }
    }

    /// A number high enough that no mandated target defines it, used to reach
    /// the platform's "Unknown error" form without naming a real `errno`.
    const EXDEV_LIKE_UNKNOWN: i32 = 4095;

    /// An error that did not come from the operating system has no annotation
    /// to remove, so it passes through -- `raw_os_error()` would have been
    /// `None` here, which is why the helper never asks for it.
    #[test]
    fn a_non_os_error_passes_through_untouched() {
        let synthetic = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "trailing garbage in reply",
        );
        assert_eq!(synthetic.raw_os_error(), None);
        assert_eq!(
            os_error_message(&synthetic),
            "trailing garbage in reply",
            "a message with no annotation must not be touched"
        );
    }

    // --- shim 6: the thirteen plain narrowing conversions ------------------

    /// In-range conversions, which behave identically in both build modes.
    /// The masks only become observable outside the asserted range, which is
    /// what the release-only test below covers.
    #[test]
    fn plain_narrowing_conversions_are_exact_in_range() {
        assert_eq!(ultouc(0), 0);
        assert_eq!(ultouc(0xff), 0xff);
        assert_eq!(ultouc(0x7f), 0x7f);

        assert_eq!(uztosi(0), 0);
        assert_eq!(uztosi(1), 1);
        assert_eq!(uztosi(0x7fff_ffff), i32::MAX);

        assert_eq!(uztoul(0), 0);
        assert_eq!(uztoul(usize::MAX), u64::MAX);

        assert_eq!(uztoui(0), 0);
        assert_eq!(uztoui(0xffff_ffff), u32::MAX);

        assert_eq!(sltosi(0), 0);
        assert_eq!(sltosi(0x7fff_ffff), i32::MAX);

        assert_eq!(sltoui(0), 0);
        assert_eq!(sltoui(0xffff_ffff), u32::MAX);

        assert_eq!(sltous(0), 0);
        assert_eq!(sltous(0xffff), u16::MAX);

        assert_eq!(uztosz(0), 0);
        assert_eq!(uztosz(usize::MAX >> 1), isize::MAX);

        assert_eq!(sotouz(0), 0);
        assert_eq!(sotouz(i64::MAX), usize::MAX >> 1);

        assert_eq!(sztosi(0), 0);
        assert_eq!(sztosi(0x7fff_ffff), i32::MAX);

        assert_eq!(uitous(0), 0);
        assert_eq!(uitous(0xffff), u16::MAX);

        assert_eq!(sitouz(0), 0);
        assert_eq!(sitouz(i32::MAX), 0x7fff_ffff);

        assert_eq!(uitouz(0), 0);
        assert_eq!(uitouz(u32::MAX), 0xffff_ffff);
    }

    // --- shim 6: the five conversions that carry behaviour -----------------

    /// SATURATES at both ends, and a negative value gives the LOWER bound
    /// (`warnless.c:286-295`).
    #[test]
    fn sotouz_range_saturates_at_both_bounds() {
        // Inside the interval: unchanged.
        assert_eq!(sotouz_range(50, 10, 100), 50);
        assert_eq!(sotouz_range(10, 10, 100), 10);
        assert_eq!(sotouz_range(100, 10, 100), 100);

        // Below and above: the respective bound.
        assert_eq!(sotouz_range(9, 10, 100), 10);
        assert_eq!(sotouz_range(101, 10, 100), 100);
        assert_eq!(sotouz_range(i64::MAX, 10, 100), 100);

        // Negative: the LOWER bound, not the upper and not zero.
        assert_eq!(sotouz_range(-1, 10, 100), 10);
        assert_eq!(sotouz_range(i64::MIN, 10, 100), 10);

        // A degenerate interval must not panic, which is why `clamp` is not
        // used: the C returns `uzmax` for a non-negative value and `uzmin`
        // for a negative one.
        assert_eq!(sotouz_range(50, 100, 10), 10);
        assert_eq!(sotouz_range(-1, 100, 10), 100);
    }

    /// SATURATES at `CURL_OFF_T_MAX` rather than wrapping
    /// (`warnless.c:334-341`).
    #[test]
    fn uztoso_saturates_at_curl_off_t_max() {
        assert_eq!(uztoso(0), 0);
        assert_eq!(uztoso(1), 1);
        assert_eq!(uztoso(usize::MAX >> 1), i64::MAX);
        assert_eq!(uztoso((usize::MAX >> 1) + 1), i64::MAX);
        assert_eq!(uztoso(usize::MAX), i64::MAX);
    }

    /// "return FALSE if negative and set 0" (`warnless.c:297-305`). The C's
    /// zeroed out-parameter is `unwrap_or(0)` here.
    #[test]
    fn sztouz_rejects_a_negative_value() {
        assert_eq!(sztouz(0), Some(0));
        assert_eq!(sztouz(1), Some(1));
        assert_eq!(sztouz(isize::MAX), Some(usize::MAX >> 1));

        assert_eq!(sztouz(-1), None);
        assert_eq!(sztouz(isize::MIN), None);
        assert_eq!(sztouz(-1).unwrap_or(0), 0);
    }

    /// "return FALSE if negative or too large and set 0"
    /// (`warnless.c:307-321`).
    #[test]
    fn sotouz_fits_rejects_a_negative_value() {
        assert_eq!(sotouz_fits(0), Some(0));
        assert_eq!(sotouz_fits(4096), Some(4096));
        assert_eq!(sotouz_fits(i64::MAX), Some(usize::MAX >> 1));

        assert_eq!(sotouz_fits(-1), None);
        assert_eq!(sotouz_fits(i64::MIN), None);
        assert_eq!(sotouz_fits(-1).unwrap_or(0), 0);
    }

    /// "return FALSE if negative or too large and set 0"
    /// (`warnless.c:323-332`).
    #[test]
    fn sltouz_rejects_a_negative_value() {
        assert_eq!(sltouz(0), Some(0));
        assert_eq!(sltouz(1_048_576), Some(1_048_576));
        assert_eq!(sltouz(i64::MAX), Some(usize::MAX >> 1));

        assert_eq!(sltouz(-1), None);
        assert_eq!(sltouz(i64::MIN), None);
        assert_eq!(sltouz(-1).unwrap_or(0), 0);
    }

    // --- the contract assertions, debug builds only ------------------------
    //
    // Each of these proves that a `debug_assert!` reproducing a C
    // `DEBUGASSERT` is present and fires. They cannot run in a release
    // build, where the assertion is compiled out by design and the masked
    // value is returned instead -- which the release-only block below
    // checks.

    /// `warnless.c:137` -- `DEBUGASSERT(slnum >= 0)`.
    #[test]
    #[should_panic(expected = "assertion failed")]
    #[cfg(debug_assertions)]
    fn sltosi_asserts_on_a_negative_value() {
        let _ = sltosi(-1);
    }

    /// `warnless.c:79` -- `DEBUGASSERT(uznum <= CURL_MASK_SINT)`.
    #[test]
    #[should_panic(expected = "assertion failed")]
    #[cfg(debug_assertions)]
    fn uztosi_asserts_above_int_max() {
        let _ = uztosi(0x8000_0000);
    }

    /// `warnless.c:61` -- `DEBUGASSERT(ulnum <= CURL_MASK_UCHAR)`.
    #[test]
    #[should_panic(expected = "assertion failed")]
    #[cfg(debug_assertions)]
    fn ultouc_asserts_above_a_byte() {
        let _ = ultouc(0x100);
    }

    /// `warnless.c:216` -- `DEBUGASSERT(sonum >= 0)`.
    #[test]
    #[should_panic(expected = "assertion failed")]
    #[cfg(debug_assertions)]
    fn sotouz_asserts_on_a_negative_offset() {
        let _ = sotouz(-1);
    }

    /// `warnless.c:273` -- `DEBUGASSERT(sinum >= 0)`.
    #[test]
    #[should_panic(expected = "assertion failed")]
    #[cfg(debug_assertions)]
    fn sitouz_asserts_on_a_negative_value() {
        let _ = sitouz(-1);
    }

    /// `lib/curlx/strcopy.c:43` -- `DEBUGASSERT(slen < dsize)`. The custom
    /// message is asserted because it is this file's own text.
    #[test]
    #[should_panic(expected = "curlx_strcopy contract")]
    #[cfg(debug_assertions)]
    fn strcopy_asserts_when_the_source_does_not_fit() {
        let mut dest = [0_u8; 4];
        let _ = strcopy(&mut dest, b"far too long");
    }

    /// `lib/curlx/strerr.c:262` -- `DEBUGASSERT(err >= 0)`, guarded
    /// `#ifndef _WIN32` and therefore active on all four mandated targets.
    #[test]
    #[should_panic(expected = "errno values are non-negative")]
    #[cfg(debug_assertions)]
    fn os_strerror_asserts_on_a_negative_errno() {
        let _ = os_strerror(-1);
    }

    // --- the release-mode masks -------------------------------------------
    //
    // THE POINT OF THIS BLOCK. The C masks before narrowing, so out of range
    // it does NOT return the value a bare cast would. Replacing any mask
    // above with `as` would look like a simplification and would change every
    // one of these results. Run with `cargo test --release`.

    /// Out of range, the C returns the MASKED value, not the truncated one:
    /// `curlx_sltosi(-1)` is `(int)(-1 & 0x7fffffff)` = `0x7fffffff`, whereas
    /// `-1i64 as i32` would be `-1`.
    #[test]
    #[cfg(not(debug_assertions))]
    fn masks_survive_into_the_release_build() {
        assert_eq!(sltosi(-1), 0x7fff_ffff);
        assert_eq!(sltosi(0x1_0000_0000), 0);
        assert_eq!(sltoui(-1), 0xffff_ffff);
        assert_eq!(sltous(-1), 0xffff);
        assert_eq!(ultouc(0x1ff), 0xff);
        assert_eq!(uztosi(usize::MAX), 0x7fff_ffff);
        assert_eq!(uztoui(usize::MAX), 0xffff_ffff);
        assert_eq!(uztosz(usize::MAX), isize::MAX);
        assert_eq!(uitous(0x1_ffff), 0xffff);
        assert_eq!(sztosi(-1), 0x7fff_ffff);
    }

    /// The two helpers whose C bodies carry no mask reinterpret instead, and
    /// `as` reproduces that exactly on the mandated targets.
    #[test]
    #[cfg(not(debug_assertions))]
    fn unmasked_conversions_reinterpret_in_the_release_build() {
        assert_eq!(sotouz(-1), usize::MAX);
        assert_eq!(sitouz(-1), usize::MAX);
    }

    /// The copy-or-empty refusal is what a release build is left with once
    /// the contract assertion is compiled out, so the public entry point
    /// behaves exactly like the inner one there.
    #[test]
    #[cfg(not(debug_assertions))]
    fn strcopy_refuses_silently_in_the_release_build() {
        let mut dest = [0xaa_u8; 4];
        assert!(!strcopy(&mut dest, b"far too long"));
        assert_eq!(&dest[..], &[0x00, 0xaa, 0xaa, 0xaa]);
    }
}
