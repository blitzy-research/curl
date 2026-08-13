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

// THE LICENCE BANNER ABOVE, and why it is spelled this way.
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

// `util` is the BASE of this crate's module graph: every other module
// depends on it and it depends on nothing. The corollary is that its
// consumers are the LAST code to exist, so until they land every helper here
// is legitimately unreferenced -- and the zero-warnings gate would otherwise
// fail on code that is correct.
//
// HOW TO CHECK THAT CLAIM, because an unanchored search reports a false
// failure against this file itself: the paragraph above legitimately NAMES
// both the keyword and the attribute, so `grep -rn 'unsafe' ...` matches the
// prose. `src/lib.rs` settled this at the crate root and its anchored
// expressions are the authority; applied to this directory they are
//
// Anchoring past leading whitespace only, and requiring the keyword before
// any slash on the line, is what excludes every `//`, `///` and `//!` line: a
// comment begins with a slash, so it can never match. Measured on this file:
// both expressions print nothing. The compiler is the real authority in any
// case -- with no exemption here, `#![deny(unsafe_code)]` makes any
// occurrence a hard error.

//! The portability and utility layer: the base of the crate's module graph.
//!
//! This directory supersedes `lib/curlx/` -- its translation units and their
//! headers --
//! together with the general-purpose containers and parsers scattered
//! through `lib/*.c`: `llist.c`, `splay.c`, `hash.c`, the four integer-keyed
//! containers (`uint-bset.c`, `uint-spbset.c`, `uint-hash.c`,
//! `uint-table.c`), `parsedate.c`, `curl_fnmatch.c`, `curl_range.c`,
//! `curl_get_line.c`, `curl_memrchr.c`, `bufq.c`, `bufref.c`, `slist.c`,
//! `strcase.c` with `strequal.c`, `curl_fopen.c` and `curl_endian.c`.
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
//! One nuance is worth recording: `lib/curlx/fopen.c`'s Windows guard opens at
//! `:41` and runs to the end of the file. Only `curlx_fseek` (`:28`) is
//! cross-platform, so `fopen` absorbs a small residue of that file and the
//! remainder is excluded rather than migrated.
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
// Three of the children nevertheless declare some `pub` items, because a
// `pub` item inside a `pub(crate)` module becomes reachable once the crate
// root re-exports it -- the standard private-module / public-re-export idiom
// -- and the exported C symbols behind them are backed from this layer:
//
//   `parsedate`  ->  curl_getdate
//   `strcase`    ->  curl_strequal, curl_strnequal
//   `slist`      ->  curl_slist_append, curl_slist_free_all
//
// And internals stay internal. `tests/libtest/*.c` (235 files) and
// `tests/unit/*.c` link a debug static libcurl and call internal `Curl_*`
// symbols; a Rust static library genuinely does not export `pub(crate)` items,
// so no quality of implementation makes them link. That is a documented
// deviation, not a defect to work around, and re-exporting internals to
// satisfy it would defeat the encapsulation that makes the zero-`unsafe`
// guarantee possible. Their coverage relocates into `#[cfg(test)]` modules
// inside these files.

// THE CHILD MODULES -- THOSE DECLARED, AND THOSE DESCRIBED
//
// A described module is one this root names without declaring, and the
// distinction is load-bearing rather than stylistic.
// `pub(crate) mod base64;` without `util/base64.rs` on disk is E0583, "file not
// found for module" -- a hard error, not a warning. One such line stops the
// whole crate compiling, and one for every child still absent stops it that
// many times over. No `#[allow]` reaches an E0583 either, because module
// resolution never gets far enough to raise a lint. So each declaration
// arrives WITH its file, in the unit of work that creates it, and until then
// the provenance lives in prose where it costs nothing.
//
// The base64 and base64url codecs -- supersedes `lib/curlx/base64.c`. LANDED,
// and declared below. The file carries base64 and base64url and nothing else.
// The chunked buffer queue -- supersedes `lib/bufq.c`. LANDED, and declared
// below. It is the largest single module in this directory and the substrate
// the whole connection-filter chain buffers on, so the layers that consume it
// cannot be written against a placeholder. The borrowed-or-owned buffer
// reference -- supersedes `lib/bufref.c`. LANDED, and declared below. Named
// "reference-counted" in an earlier reading of this list, which the
// measurement corrects: `struct bufref` holds no count. Its `dtor` field is a
// single owned-versus-borrowed discriminator, which is `std::borrow::Cow<'_,
// [u8]>`. The growable dynamic buffer -- supersedes `lib/curlx/dynbuf.c`.
// LANDED, and declared below. It is the third of the 22 to exist because its
// nineteen size limits gate `CURLE_TOO_LARGE` across the DoH, HTTP, chunked,
// FTP, IMAP, MQTT, RTSP, HAProxy, proxy-CONNECT, paused-writer, `aprintf` and
// TLS file-loading paths, so the modules that supersede any of those cannot be
// written without it. Wildcard pattern matching -- supersedes
// `lib/curl_fnmatch.c`. LANDED, and declared below rather than only listed
// here. Its contents are gated on the `ftp` feature, because the whole of the
// C sits inside `#ifndef CURL_DISABLE_FTP`; the declaration is unconditional
// and the gate lives in the file. Atomic file creation and seeking --
// supersedes `lib/curl_fopen.c` and the cross-platform residue of
// `lib/curlx/fopen.c` (`curlx_fseek`). LANDED, and declared below rather than
// only listed here. The second child whose contents are conditional, and the
// first whose gate is written PER ITEM rather than as an inner attribute: the
// two C files it supersedes carry different guards, and an inner `#![cfg]`
// would hide the seek helper from `crate::mime`. It is also the second place
// the layering rule above is honoured by parameterization -- the random
// component of the temporary name is injected, because `Curl_rand_alnum` is
// now in `crate::crypto`. Line reading from a stream -- supersedes
// `lib/curl_get_line.c`. LANDED, and declared below rather than only listed
// here. It carries no `pub` item: nothing in it is reachable from
// `curl-rs-ffi`, and its four consumers -- the cookie jar, the Alt-Svc cache,
// `.netrc` and the HSTS cache -- are all inside this crate. Declared
// unconditionally even though the C guards the whole file on four
// `CURL_DISABLE_*` names, because one of the four has no feature counterpart
// and the disjunction is therefore always true. The string-keyed hash table --
// supersedes `lib/hash.c`. LANDED, and declared below. It differs from the
// other two that have arrived in carrying no `pub` item at all: `lib/hash.h`
// is an internal header, and the two helpers it does export, `Curl_hash_str`
// and `curlx_str_key_compare`, are `Curl_`- and `curlx_`-prefixed rather than
// members of the 100-symbol export set, so nothing there is reachable from
// `curl-rs-ffi` and nothing there needs widening. Address presentation and
// parsing -- supersedes `lib/curlx/inet_ntop.c` and `lib/curlx/inet_pton.c`.
// ISC-licensed, NOT curl-licensed -- a distinction that must survive into the
// file superseding them. LANDED, and declared below. It is the ONE file in
// this directory whose licence banner differs from every other, and the
// exception recorded at the head of this file is the reason: the banner it
// carries is the ISC notice of its two C originals, and `reuse lint-file` on
// it is silent. Both formatters are infallible where the C can fail twice,
// because the family collapses into the type system and the caller's buffer
// becomes an owned `String`; both parsers return `Option`, so the C's promise
// to leave `dst` untouched on failure becomes structural. The general-purpose
// ordered collection -- supersedes `lib/llist.c`. LANDED, and declared below.
// It is the first of the 22 with no `pub` item, because no exported C symbol
// is backed from it. Reverse byte search -- supersedes `lib/curl_memrchr.c`.
// LANDED, and declared below. The only one of the three that backs no exported
// symbol: it is declared because the transformation map names it, and it
// carries no `pub` item at all. Date parsing -- supersedes `lib/parsedate.c`.
// Backs `curl_getdate`. LANDED, and declared below rather than only listed
// here. It is the first of the 22 to exist because `curl_getdate` is an
// exported symbol and `curl-rs-ffi` cannot be written without it. Byte-range
// parsing -- supersedes `lib/curl_range.c`. LANDED, and declared below rather
// than only listed here. It backs no exported symbol, and it exists at this
// point because it is the first of the two children the layering rule above
// bites on: its C original writes into `struct Curl_easy`, so it becomes a
// pure parse function whose answer the caller stores. Its two consumers are
// `crate::protocols::file` and `crate::protocols::ftp`, and HTTP is
// deliberately not among them -- that path forwards the range string in a
// `Range:` header instead. The `curl_slist` chain -- supersedes `lib/slist.c`.
// Backs the exported `curl_slist_append` and `curl_slist_free_all`. LANDED,
// and declared below rather than only listed here, for the same reason as
// `parsedate` and `strcase`: both of the symbols it backs are exported, so
// `curl-rs-ffi` reaches it. The chain itself does not come with it -- the
// C-shaped struct stays at the ABI boundary and this module holds an owned,
// ordered sequence instead. The splay tree behind expiry timers -- supersedes
// `lib/splay.c`. LANDED, and declared below. It backs no exported symbol, so
// it carries no `pub` item, and it is the second child in this directory whose
// NAME no longer describes its contents: like `llist`, it holds an owned
// collection rather than the pointer structure it supersedes. The path is the
// one the transformation map gives it, and the type inside says what it is.
// Case-insensitive comparison -- supersedes `lib/strcase.c` and
// `lib/strequal.c`. Backs `curl_strequal` and `curl_strnequal`. LANDED, and
// declared below, for the same reason as `parsedate`: both comparators are
// reached from `curl-rs-ffi`. The bounded string parser -- supersedes
// `lib/curlx/strparse.c`. Time differences and the millisecond conversions --
// supersedes `lib/curlx/timediff.c`. LANDED, and declared below. Third of the
// 22 to exist, and for a different reason from the first two: it backs no
// exported symbol, but `timeval` and `splay` cannot be written before the type
// every timeout is carried in. The monotonic clock -- supersedes
// `lib/curlx/timeval.c`. LANDED, and declared below. It backs no exported
// symbol, so it carries no `pub` item, and it arrives directly after
// `timediff` because it is written in terms of the type that file defines. It
// is also the one child with an architectural obligation of its own: it owns
// the crate's CLOCK SEAM, so no other module -- here or anywhere in
// `curl-rs-lib` -- may read a monotonic or a wall clock directly.
// Integer-keyed bitsets -- supersedes `lib/uint-bset.c` and
// `lib/uint-spbset.c`. LANDED, and declared below. The third to exist, and the
// first that backs no exported symbol: it is here because `struct Curl_multi`
// holds four of the dense sets beside its transfer table, so the multi handle
// cannot be written until they do. Two types in the one file, because the AAP
// maps both C translation units onto it. The integer-keyed hash -- supersedes
// `lib/uint-hash.c`. LANDED, and declared below. It is the transfer-identifier
// to per-stream-state map for the multiplexed protocols: all three C call
// sites construct it with 63 slots and key it on `data->mid`. The
// integer-keyed table -- supersedes `lib/uint-table.c`.

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

/// The base64 codec -- supersedes `lib/curlx/base64.c`.
pub(crate) mod base64;

/// The chunked byte queue -- supersedes `lib/bufq.c` and `lib/bufq.h`.
///
/// `pub(crate)` with no `pub` item at all, and unlike [`parsedate`] and
/// [`strcase`] there is no reason for one: no `curl_bufq_*` name appears among
/// the 100 exported symbols of `lib/libcurl.def`, so nothing in
/// `curl-rs-ffi` reaches it. It is the buffering substrate the
/// connection-filter chain sits on, and `CURLE_AGAIN` out of it is how "would
/// block" travels up that chain.
pub(crate) mod bufq;

/// The generic buffer reference -- supersedes `lib/bufref.c` and
/// `lib/bufref.h`.
///
/// `pub(crate)` throughout, and unlike [`parsedate`] and [`strcase`] it
/// carries no `pub` item at all: `lib/libcurl.def` exports no
/// `curl_bufref_*` symbol, so nothing here is reachable from `curl-rs-ffi`
/// and nothing needs to be. Its whole content is a `Cow<'_, [u8]>` alias and
/// five constructors, because the C struct's `dtor` function pointer, its
/// `0x5c48e9b2` signature and its `ptr || !len` invariant all vanish into the
/// standard library rather than being reproduced.
pub(crate) mod bufref;

/// The growable, size-capped byte buffer -- supersedes
/// `lib/curlx/dynbuf.c` and `lib/curlx/dynbuf.h`.
///
/// `pub(crate)` with no `pub` item at all, unlike the two children below it:
/// nothing in `curl-rs-ffi` reaches this type. Its nineteen size limits are
/// nevertheless behaviour rather than tuning -- crossing one produces
/// `CURLE_TOO_LARGE`, a code a caller observes -- which is why they are
/// transcribed there verbatim from the C header and asserted by test.
pub(crate) mod dynbuf;

/// Wildcard pattern matching -- supersedes `lib/curl_fnmatch.c`.
///
/// `pub(crate)` and nothing wider: no exported symbol is backed from here.
/// `Curl_fnmatch` is internal, and the ABI surface it is reachable from is
/// `CURLOPT_FNMATCH_FUNCTION`, which takes a comparator from the user rather
/// than handing curl's own out.
///
/// Declared unconditionally even though its contents are gated. The whole of
/// the C is inside `#ifndef CURL_DISABLE_FTP`, so the file carries an inner
/// `#![cfg(feature = "ftp")]` -- the form `crate::ffi::gss` already uses --
/// which keeps the gate beside the code it governs and leaves this line free
/// of a condition that would have to be repeated at every future FTP child.
pub(crate) mod fnmatch;

/// Atomic-replace file creation and stream seeking -- supersedes
/// `lib/curl_fopen.c` with `lib/curl_fopen.h`, and the cross-platform residue
/// of `lib/curlx/fopen.c` (`curlx_fseek`, `:28-39`) with the non-Windows half
/// of `lib/curlx/fopen.h`.
///
/// The one thing a reader of THIS file should carry away is the layering
/// consequence recorded in the preamble: the C reaches `Curl_rand_alnum` in
/// what is now the sibling `crate::crypto`, so the random component of the
/// temporary name is INJECTED as a provider argument and the C's
/// `struct Curl_easy *data` parameter -- which existed only for that one call
/// -- is dropped entirely. The child also records a measured correction to
/// `dirslash`: for a path at the filesystem root the directory component
/// comes back EMPTY, not `"/"`, so the temporary file lands in the current
/// working directory.
pub(crate) mod fopen;

/// Whole-line reading from a stream -- supersedes `lib/curl_get_line.c` and
/// `lib/curl_get_line.h`.
///
/// The one thing a reader of THIS file should carry away: **every successful
/// return ends in a newline, and at end of input the function synthesises a
/// line consisting solely of one.** `lib/hsts.c:517-520` documents its
/// reliance on that, so it is a contract rather than an artefact, and the
/// child records the two further places where the C's behaviour is surprising
/// -- a chunk truncated at an embedded zero byte, and a carriage return that
/// is never stripped.
pub(crate) mod get_line;

/// The string-keyed hash table -- supersedes `lib/hash.c` and `lib/hash.h`.
pub(crate) mod hash;

/// Address presentation and parsing -- supersedes `lib/curlx/inet_ntop.c`
/// and `lib/curlx/inet_pton.c`.
///
/// **The one child of this directory that is not curl-licensed.** Both C
/// originals are Internet Software Consortium code from BIND and declare an
/// SPDX licence identifier naming `ISC`; the file carries that notice, both
/// of the two copyright lines, and the BIND 4.9.4 provenance note. The
/// exception is recorded at the head of this file for exactly this reason,
/// and applying the neighbours' banner to it would be a licence violation.
///
/// `pub(crate)` with no `pub` item: neither `curlx_inet_ntop` nor
/// `curlx_inet_pton` appears in `lib/libcurl.def`, so nothing in
/// `curl-rs-ffi` reaches it and the crate root adds no re-export.
pub(crate) mod inet;

/// The general-purpose ordered collection -- supersedes `lib/llist.c`.
///
/// This module declares no list type. `std::collections::VecDeque<T>` is what
/// replaced `Curl_llist`, and the module holds the three helpers that
/// container genuinely lacks plus the documentation recording the substitution
/// -- including the one divergence, that `Curl_llist_destroy` disposes of
/// elements tail-first where dropping a `VecDeque` disposes of them front to
/// back.
pub(crate) mod llist;

/// Reverse byte search -- supersedes `lib/curl_memrchr.c`.
///
/// `pub(crate)` with no `pub` item at all, unlike the two children below.
/// Neither `memrchr` nor `Curl_memrchr` appears in `lib/libcurl.def`, so no
/// exported symbol is backed from there and nothing in `curl-rs-ffi` reaches
/// it. Its single function delegates to the `memchr` crate, which the crate
/// manifest already declares for exactly that purpose.
pub(crate) mod memrchr;

/// Date parsing -- supersedes `lib/parsedate.c`.
///
/// `pub(crate)` like every other child: its own `pub fn getdate` is what
/// widens the reachable surface, once the crate root re-exports it. The
/// justification for that `pub` lives in the file, next to the item, as the
/// policy above requires.
pub(crate) mod parsedate;

/// Byte-range parsing -- supersedes `lib/curl_range.c` and
/// `lib/curl_range.h`.
///
/// Range parsing is the FIRST of the two places the layering rule at the head of this
/// file is honoured by parameterization, and the more consequential of them:
/// the C's `Curl_range(struct Curl_easy *data)` writes its two results into
/// the handle, and `lib/curl_range.h` includes `urldata.h` to make that
/// signature expressible. Here it is a pure parse function returning a
/// `RangeSpec`, because reproducing the C's shape would place `crate::easy`
/// and `crate::transfer` below the base of the module graph.
pub(crate) mod range;

/// Redaction adaptors for [`fmt::Debug`](core::fmt::Debug), so that a
/// diagnostic cannot become a credential disclosure.
///
/// The one child of this module with **no C counterpart at all**, and the
/// reason is recorded here rather than only in the file: C has no derived
/// formatter, so every diagnostic in `lib/` names the field it prints and no
/// `struct` can leak a secret merely by existing. `#[derive(Debug)]` renders
/// every field, which makes it easy to attach a formatter to a secret-bearing
/// type without noticing -- and once attached, any `{:?}` anywhere writes the
/// secret out. This child restores that property explicitly, and its scope is
/// strictly the *formatting* of a value: nothing in it changes a byte that
/// reaches the wire, a file or a callback.
///
/// `pub(crate)` with no `pub` item: `grep -i redact lib/libcurl.def` finds
/// nothing, so no exported symbol is backed from here.
pub(crate) mod redact;

/// The `curl_slist` string list -- supersedes `lib/slist.c` and
/// `lib/slist.h`.
///
/// The third child that carries `pub` items, and for the same reason as
/// [`parsedate`] and [`strcase`]: `curl_slist_append` and
/// `curl_slist_free_all` are exported symbols, at `lib/libcurl.def:85-86`, so
/// the items backing them are `pub` there. The intrusive chain does NOT come
/// with them -- the `#[repr(C)]` `struct curl_slist` lives only in
/// `curl-rs-ffi/src/ffi/slist.rs`, and this child exposes an owned, ordered
/// sequence with no node type and no successor pointer.
pub(crate) mod slist;

/// The expiry timer tree -- supersedes `lib/splay.c` and `lib/splay.h`.
pub(crate) mod splay;

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

/// The bounded cursor parser -- supersedes `lib/curlx/strparse.c` and
/// `lib/curlx/strparse.h`, and additionally owns `lib/curl_ctype.h`.
///
/// `pub(crate)` with no `pub` item inside it, unlike [`parsedate`] and
/// [`strcase`]: `grep curlx_str lib/libcurl.def` finds nothing, so no
/// exported symbol is backed from here and nothing in `curl-rs-ffi` reaches
/// it. The `tests/unit` coverage that would have called these functions
/// through a debug static library relocates into the file's own
/// `#[cfg(test)]` module, per the policy at the head of this file.
pub(crate) mod strparse;

/// Time differences and the millisecond conversions -- supersedes
/// `lib/curlx/timediff.c` and `lib/curlx/timediff.h`.
pub(crate) mod timediff;

/// The monotonic clock, the instant type and the UTC calendar conversion --
/// supersedes `lib/curlx/timeval.c` and `lib/curlx/timeval.h`.
///
/// It is the one child of this directory with an obligation beyond its own
/// correctness: **it owns the clock seam.** No other module in this crate may
/// call a monotonic or a wall-clock primitive; each one receives a `Clock` and
/// asks it. The `TestClock` it exports is deliberately NOT `#[cfg(test)]`, so
/// that those modules' own tests can inject it.
pub(crate) mod timeval;

/// Integer-keyed bitsets -- supersedes `lib/uint-bset.c` and
/// `lib/uint-spbset.c`, the pair the inventory above lists together.
pub(crate) mod uint_bset;

/// The integer-keyed hash -- supersedes `lib/uint-hash.c` and
/// `lib/uint-hash.h`.
pub(crate) mod uint_hash;

/// The integer-keyed table that assigns `mid` -- supersedes
/// `lib/uint-table.c` and `lib/uint-table.h`.
///
/// Carries no `#[allow(dead_code)]` on this declaration by design: an
/// attribute on a `mod` covers the module's whole contents, which
/// `mod source_policy`'s
/// `no_lint_level_for_dead_code_is_set_on_a_crate_or_module_root` rejects for
/// the reason given at the head of this file. The allowances are written at
/// the items instead.
pub(crate) mod uint_table;

/// Allocation that reports failure instead of aborting the process.
///
/// # Why this module exists
///
/// C's allocation wrappers return null and every caller has a code for it:
/// `CURLE_OUT_OF_MEMORY`, `CURLSHE_NOMEM`, `CURLUE_OUT_OF_MEMORY`,
/// `CURLHE_OUT_OF_MEMORY`. Rust's infallible allocation calls
/// `alloc::alloc::handle_alloc_error` instead, which **aborts the process**.
/// For a library reached through a C ABI that is a strictly worse contract than
/// the one it replaces: an embedding application that is prepared to handle
/// `CURLE_OUT_OF_MEMORY` is killed instead of being told, and the panic
/// boundary in `curl-rs-ffi` cannot help, because an allocator abort is not an
/// unwind and `catch_unwind` never sees it.
///
/// The exposure that matters is **externally sized** allocation: a capacity
/// derived from a length the caller chose. `curl_easy_escape` with a 700 MB
/// string, a `CURLOPT_POSTFIELDSIZE` the application picked, a header a server
/// sent -- each is a number this library did not choose, and multiplying it by
/// three for percent-encoding is how a large-but-legal input becomes a failed
/// allocation. Those are the sites routed through this module.
///
/// # What is deliberately NOT routed through it
///
/// A fixed-size allocation -- `Box::new` of a handle, a `Vec` of a compile-time
/// count -- has no stable fallible spelling at the declared minimum Rust
/// version: `Box::try_new` is unstable. Those sites keep their acknowledgement
/// comment, narrowed to say that the size is fixed, so a reader can tell the
/// two cases apart. A fixed-size allocation failing means the process could not
/// obtain a few dozen bytes, which is a different situation from a caller
/// asking for a gigabyte.
///
/// # The two failure routes, and why both are tested
///
/// [`TryReserveError`] carries either `CapacityOverflow` -- the requested
/// capacity cannot be expressed as a [`std::alloc::Layout`] at all -- or
/// `AllocError`, the allocator declining. Both arrive here as the same
/// `Err`, and both must map to the same curl code, which is why the tests
/// exercise each route rather than assuming the variants are interchangeable.
///
/// [`TryReserveError`]: std::collections::TryReserveError
pub(crate) mod fallible {
    use std::collections::TryReserveError;

    use crate::error::CURLcode;

    /// `CURLE_OUT_OF_MEMORY`, for `.map_err(oom)`.
    ///
    /// A function rather than a closure at every site so that the mapping is
    /// stated once and a site cannot quietly choose a different code.
    pub(crate) fn oom(_: TryReserveError) -> CURLcode {
        CURLcode::OutOfMemory
    }

    /// `Vec::with_capacity`, reporting failure.
    ///
    /// Written as `Vec::new` plus `try_reserve_exact` because that is the only
    /// stable spelling: `Vec::with_capacity` itself has no fallible form. The
    /// `exact` variant is used because the caller has already computed the
    /// figure it wants -- `try_reserve` may round up, which turns a request the
    /// allocator would have served into one it declines.
    pub(crate) fn vec_with_capacity<T>(
        capacity: usize,
    ) -> Result<Vec<T>, TryReserveError> {
        let mut vec = Vec::new();
        vec.try_reserve_exact(capacity)?;
        Ok(vec)
    }

    /// `String::with_capacity`, reporting failure.
    pub(crate) fn string_with_capacity(
        capacity: usize,
    ) -> Result<String, TryReserveError> {
        let mut string = String::new();
        string.try_reserve_exact(capacity)?;
        Ok(string)
    }

    /// `Vec::push`, reporting failure.
    ///
    /// The reservation is the growth-doubling `try_reserve`, not the exact
    /// form: a push in a loop that reserved exactly one byte at a time would
    /// reallocate on every iteration.
    pub(crate) fn push<T>(
        vec: &mut Vec<T>,
        value: T,
    ) -> Result<(), TryReserveError> {
        vec.try_reserve(1)?;
        vec.push(value);
        Ok(())
    }

    /// `Vec::reserve`, reporting failure.
    #[allow(dead_code)] // used by some growth sites and not others
    pub(crate) fn reserve<T>(
        vec: &mut Vec<T>,
        additional: usize,
    ) -> Result<(), TryReserveError> {
        vec.try_reserve(additional)
    }

    #[cfg(test)]
    mod tests {
        use super::{oom, push, string_with_capacity, vec_with_capacity};
        use crate::error::CURLcode;

        /// One past the largest expressible allocation, for `u8`.
        ///
        /// `std::alloc::Layout` refuses a size above `isize::MAX`, so a request
        /// of `isize::MAX + 1` bytes fails **inside `Layout::array`** and the
        /// allocator is never called. That distinction is the whole point of
        /// this constant, and it is not a stylistic preference:
        ///
        /// * Asking for exactly `isize::MAX` is a LEGAL layout, so the request
        ///   reaches the allocator. Natively glibc declines and the `Err` looks
        ///   the same, but under Miri the interpreter answers
        ///   `error: resource exhaustion: tried to allocate more memory than
        ///   available to compiler` -- a hard interpreter error that no
        ///   `Result` can carry and that fails the Miri gate outright.
        /// * It also made the assertion depend on the host allocator declining
        ///   rather than on anything in this crate, which is not a property
        ///   worth testing.
        ///
        /// The wrong first attempt is recorded here rather than silently
        /// replaced, because the failure mode is invisible until the Miri leg
        /// runs.
        const PAST_LAYOUT_LIMIT: usize = (isize::MAX as usize) + 1;

        #[test]
        fn a_capacity_past_the_layout_limit_is_reported_not_fatal() {
            let refused = vec_with_capacity::<u8>(PAST_LAYOUT_LIMIT);
            assert!(
                refused.is_err(),
                "isize::MAX + 1 bytes cannot be a Layout"
            );
            assert_eq!(refused.map_err(oom), Err(CURLcode::OutOfMemory));

            let refused = string_with_capacity(PAST_LAYOUT_LIMIT);
            assert!(refused.is_err());
            assert_eq!(refused.map_err(oom), Err(CURLcode::OutOfMemory));
        }

        /// The other `TryReserveError` route: the element size multiplies out.
        ///
        /// `usize::MAX / 4` `u64`s is eight times that many bytes, so the
        /// failure comes from the multiplication in `Layout::array` rather than
        /// from the count itself. Both routes must map to the same code, which
        /// is why they are asserted separately instead of being assumed
        /// interchangeable.
        #[test]
        fn an_element_size_that_overflows_the_layout_is_reported_too() {
            let refused = vec_with_capacity::<u64>(usize::MAX / 4);
            assert!(refused.is_err());
            assert_eq!(refused.map_err(oom), Err(CURLcode::OutOfMemory));
        }

        /// A refused reservation leaves the container exactly as it was.
        #[test]
        fn a_refused_reservation_changes_nothing() {
            let mut vec: Vec<u8> = Vec::new();
            assert!(super::reserve(&mut vec, PAST_LAYOUT_LIMIT).is_err());
            assert_eq!(vec.capacity(), 0, "no capacity was taken");
            assert!(vec.is_empty(), "and no element appeared");

            let mut text = String::from("kept");
            assert!(text.try_reserve(PAST_LAYOUT_LIMIT).is_err());
            assert_eq!(text, "kept", "the contents survive a refusal");
        }

        /// The served path is ordinary: these wrappers are not a slow lane.
        #[test]
        fn a_servable_request_behaves_as_the_infallible_form_does() {
            let mut vec: Vec<u8> =
                vec_with_capacity(8).expect("eight bytes are servable");
            assert!(vec.capacity() >= 8);
            for byte in b"abcdefgh" {
                push(&mut vec, *byte).expect("within the reservation");
            }
            assert_eq!(vec, b"abcdefgh");

            let mut text =
                string_with_capacity(4).expect("four bytes are servable");
            text.push_str("ok");
            assert_eq!(text, "ok", "within the reservation, so no growth");
        }
    }
}

/// A `RefCell`-shaped cell that is `Sync`, for test doubles behind an [`Arc`].
///
/// [`Arc`]: std::sync::Arc
///
/// # Why this exists
///
/// The connection layer's injected seams are shared, not owned: a test
/// installs one double and then inspects what it recorded, so the double is
/// held twice. `std::rc::Rc<std::cell::RefCell<T>>` is the single-threaded
/// spelling of that, and it is what these tests used before the connection
/// pool had to become [`Send`] -- `crate::share::Share` holds a
/// `Mutex<Option<ConnectionPool>>`, and `Mutex<T>: Send + Sync` requires
/// `T: Send`, which requires every injected seam behind the pool to be
/// `Send + Sync`. `Arc<T>: Send` requires `T: Send + Sync`, and `RefCell` is
/// not `Sync`, so the cell itself had to change with the pointer.
///
/// # Why it is `RwLock` and not `Mutex`
///
/// [`RefCell`] permits any number of simultaneous shared borrows and exactly
/// one exclusive borrow. [`std::sync::RwLock`] has the same rule, so a test
/// that holds two `borrow()`s at once keeps working; a [`std::sync::Mutex`]
/// would deadlock where the original merely worked. The method names are
/// [`RefCell`]'s so that converting a double is a change of type name and
/// nothing else.
///
/// [`RefCell`]: std::cell::RefCell
///
/// # Poisoning
///
/// A panic while a guard is held poisons the lock. `crate::share` explains at
/// length why poisoning must never convert a transient fault into a permanent
/// one, and the same reasoning applies here for a different reason: a test
/// that panics inside a guard should report *its own* assertion failure, not a
/// second panic from the recovery path. Both accessors therefore recover with
/// `unwrap_or_else(PoisonError::into_inner)`.
///
/// This is `#[cfg(test)]` because it has no production caller: production code
/// that needs shared mutable state names its lock directly, and a shim that
/// hid the choice there would be the wrong trade.
#[cfg(test)]
pub(crate) mod sync_cell {
    use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

    /// Interior mutability with `RefCell`'s API and `RwLock`'s bounds.
    #[derive(Debug, Default)]
    pub(crate) struct SyncCell<T>(RwLock<T>);

    impl<T> SyncCell<T> {
        /// `RefCell::new`.
        pub(crate) fn new(value: T) -> Self {
            Self(RwLock::new(value))
        }

        /// `RefCell::borrow`, as a read guard.
        pub(crate) fn borrow(&self) -> RwLockReadGuard<'_, T> {
            self.0.read().unwrap_or_else(PoisonError::into_inner)
        }

        /// `RefCell::borrow_mut`, as a write guard.
        ///
        /// `&self` rather than `&mut self`, exactly as [`RefCell`]'s is: the
        /// whole point of the type is exclusive access through a shared
        /// reference.
        ///
        /// [`RefCell`]: std::cell::RefCell
        pub(crate) fn borrow_mut(&self) -> RwLockWriteGuard<'_, T> {
            self.0.write().unwrap_or_else(PoisonError::into_inner)
        }

        /// `RefCell::into_inner`.
        #[allow(dead_code)] // used by some doubles and not others
        pub(crate) fn into_inner(self) -> T {
            self.0.into_inner().unwrap_or_else(PoisonError::into_inner)
        }

        /// `RefCell::replace` / `Cell::replace`.
        #[allow(dead_code)] // used by some doubles and not others
        pub(crate) fn replace(&self, value: T) -> T {
            std::mem::replace(&mut self.borrow_mut(), value)
        }
    }

    impl<T: Copy> SyncCell<T> {
        /// `Cell::get`.
        ///
        /// The guard is released before the value leaves the call, which is
        /// why the `self.counter.set(self.counter.get() + 1)` idiom the
        /// doubles use does not deadlock: the argument is evaluated, and its
        /// read guard dropped, before `set` asks for the write guard.
        #[allow(dead_code)] // used by some doubles and not others
        pub(crate) fn get(&self) -> T {
            *self.borrow()
        }

        /// `Cell::set`.
        #[allow(dead_code)] // used by some doubles and not others
        pub(crate) fn set(&self, value: T) {
            *self.borrow_mut() = value;
        }
    }

    impl<T: Default> SyncCell<T> {
        /// `RefCell::take` / `Cell::take`.
        #[allow(dead_code)] // used by some doubles and not others
        pub(crate) fn take(&self) -> T {
            std::mem::take(&mut self.borrow_mut())
        }
    }
}

/// Reads a 16-bit unsigned integer in little-endian order.
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
// Both `/` and `\` are honoured on ALL platforms. That is deliberate in the C
// and is not turned into a `#[cfg(windows)]` here: curl accepts a Windows
// path in a `CURLOPT_MIMEPOST` filename regardless of the host it runs on,
// and the four mandated targets are Unix, so a platform-conditional would
// change the behaviour on every target this build supports.

/// Returns the final component of `path`, after the rightmost `/` or `\`.
///
/// Supersedes `curlx_basename` (`lib/curlx/basename.c:54-72`). This is
/// curl's own simplified rule, NOT POSIX `basename()`: no trailing-separator
/// stripping, no `"."` for an empty input, no `"/"` special case, and both
/// separators recognised on every platform. See the block comment above for
/// the three POSIX behaviours that are deliberately absent.
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

    // The C's four-branch chain, branch for branch.
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
// Rust normally has nothing to write here at all, because `String` and
// `Vec<u8>` grow and the question never arises. This helper exists for the
// one place where a fixed-size buffer is genuinely emulated: `inet.rs`, whose
// C originals `inet_ntop4` and `inet_ntop6` format into a caller-provided
// buffer and turn a copy that did not fit into `ENOSPC`. Returning `bool`
// rather than `()` is what lets that caller keep doing so, since C recovers
// the same information by inspecting `dest[0]` afterwards.

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
// `lib/curlx/strerr.c` exports exactly one function -- measured: the file's
// only other function, `get_winsock_error` at `:44`, is `static` and
// Windows-only -- and the source calls it "Our thread-safe and smart
// strerror() replacement":
//
//     const char *curlx_strerror(int err, char *buf, size_t buflen);
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

/// The annotation `std::io::Error`'s `Display` appends and C never emits.
///
/// Matched literally, including the leading space, so that a message merely
/// containing the words cannot be mistaken for an annotated one.
const OS_ERROR_INFIX: &str = " (os error ";

/// Renders an [`std::io::Error`] the way `curlx_strerror` renders `errno`.
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

/// curl's file-size and offset type: `curl_off_t`.
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
/// # Panics
///
/// In a debug build only, if the value is negative.
#[allow(dead_code)]
pub(crate) fn sitouz(sinum: i32) -> usize {
    debug_assert!(sinum >= 0);
    sinum as usize
}

/// `unsigned int` to `size_t` -- `curlx_uitouz`, `warnless.c:281-284`.
#[allow(dead_code)]
pub(crate) fn uitouz(uinum: u32) -> usize {
    uinum as usize
}

// --- The five conversions that carry behaviour ------------------------------

/// Fits a `curl_off_t` into the `size_t` interval `[uzmin, uzmax]`.
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
// The macro is NOT REPRODUCED, and it must not be. Rust function items are strongly
// typed, and there is no safe expression of the cast because there is nothing
// safe about it: the C pattern works only as long as every call goes through
// the original signature, and nothing checks that. The pattern it enables is
// exactly what the typed-context connection-filter design eliminates -- where
// `struct Curl_cftype` carries a `void *ctx` that every filter casts to its
// own type (`lib/cfilters.h:210-226`), `Box<dyn ConnFilter>` carries a typed
// field and the cast has no place to occur.

// TESTS
//
// `tests/unit/*.c` (59 files) and `tests/libtest/*.c` link a debug static
// libcurl and call internal `Curl_*` symbols, which a Rust static library does
// not export. Their coverage therefore relocates into `#[cfg(test)]` modules
// inside the files under test, and this is this file's share of that
// relocation.
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
    #[test]
    fn basename_borrows_and_respects_character_boundaries() {
        // "directory/na<U+00EF>ve-caf<U+00E9>.txt": spellchecker:disable-line
        // the two accented characters occupy two bytes each in UTF-8, so the
        // tail begins at byte 10 and spans 16 bytes rather than 14
        // characters' worth.
        let name = "na\u{ef}ve-caf\u{e9}.txt"; // spellchecker:disable-line
        let path = String::from("directory/") + name;
        let base = basename(&path);
        assert_eq!(base, name);
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
