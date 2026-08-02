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

// THREE CONVENTIONS OF THIS DIRECTORY, APPLIED HERE, AND ONE DEPARTURE.
//
// 1. The 23-line banner above is the one measured at `lib/llist.c:1-23`,
//    rendered as Rust line comments with the C block-comment decorations
//    stripped. It is byte-identical to `super`'s and to every other child of
//    this directory except `inet.rs`, whose C originals carry a different
//    licence. The licence-identifier line is line 21 and is verbatim; it is
//    the only place in this file where that spelling appears, which is what
//    `reuse lint` needs.
//
// 2. `dead_code` allowances are written at the ITEM, never on the module
//    declaration and never at a file root. The gate that enforces it lives in
//    `curl-rs-lib/src/lib.rs` (`mod source_policy`), and the reason is in
//    `super`: an attribute on a module root would silence the NEXT item
//    somebody adds. Every item in this file carries its own allowance today
//    because this module has no consumer yet -- the parsers that sit on top of
//    it (header, cookie, alt-svc, HSTS, netrc, the URL API, the FTP list
//    parser, `parsedate`, `range` and `inet`) are later code. Each allowance
//    is removed when its consumer lands, and until then it reads as an
//    inventory rather than as a blanket.
//
// 3. No level for the `unsafe_code` lint is set here, at any level. The crate
//    root carries `#![deny(unsafe_code)]` and grants exactly one exemption,
//    on `mod ffi`; this file is not it, contains no exemption, and contains
//    nothing the compiler would need one for. That matters more here than in
//    most of this directory, because the C original is a pointer-walking
//    parser: `curlx_str_until` advances a `const char *` and dereferences it
//    on every iteration with no bound but a terminator it trusts the caller
//    to have placed. Slice indexing with an explicit length replaces it.
//
// THE DEPARTURE, recorded rather than left silent. The specification for this
// file proposes `#[inline]` on the byte predicates below. None carries it.
// `super` states the convention -- performance is an explicit non-goal of
// this work, so nothing in this layer carries a performance hint or is
// restructured on speed grounds -- and the whole of `curl-rs-lib` holds to
// it: the one hint in the crate is an `#[inline(never)]` in `strcase.rs`
// placed for a semantic reason rather than a speed one. A hint that changed
// no observable behaviour would still make this file the odd one out, and
// `const fn` already gives call sites everything the hint was meant to buy.

//! The cursor-based bounded parser -- supersedes `lib/curlx/strparse.c`
//! (304 lines) and `lib/curlx/strparse.h` (113), and additionally owns the
//! ASCII-only byte classification of `lib/curl_ctype.h` (52).
//!
//! Three C translation units rather than the usual one, and the third is the
//! reason to read this paragraph. `lib/curl_ctype.h` has no row of its own in
//! the transformation map, yet it is a hard dependency of this module and of
//! four later ones -- `parsedate`, `fnmatch`, `range` and `base64` all
//! classify bytes, and every one of them classifies them curl's way rather
//! than the C library's. Owning the predicates here, once, prevents five
//! divergent re-derivations of a set that is observable in wire output.
//!
//! # Why faithfulness is the whole job
//!
//! This is one of the most widely consumed modules in the crate. Header
//! parsing, cookie parsing, alt-svc, HSTS, `.netrc`, the URL API, the FTP
//! list parser, `parsedate`, `range` and `inet` all sit on top of it, and a
//! behavioural deviation here does not stay here: it propagates into the
//! bytes on the wire, which the fixture corpus compares byte for byte across
//! 1,476 of its 1,914 cases. Where a tidier expression and a more faithful
//! one conflict in this file, the faithful one wins, and the places that
//! happens are each marked at the item.
//!
//! Four of those places are worth naming up front, because each is a
//! plausible "improvement" that would change output:
//!
//! * [`str_until`]'s `max` is an INCLUSIVE cap and its test runs AFTER the
//!   increment, so a span of exactly `max` bytes succeeds.
//! * [`str_quotedword`] does NOT unescape. It returns the raw bytes between
//!   the quotes with every backslash still in place.
//! * [`HEXASCIITABLE`]'s first entry is 16 rather than 0, and
//!   [`hexval`] masks it back down. Transcribing it as 0 makes the byte `0`
//!   stop being a digit.
//! * `str_num_base`, the private core of the number parsers, has TWO overflow
//!   algorithms, chosen by `max < base`, and they disagree at the boundaries.
//!   Both ship.
//!
//! # The C surface, function by function
//!
//! Every one of the 20 entry points that `lib/curlx/strparse.h` declares is
//! accounted for. Four are subsumed rather than reproduced, and the reason is
//! given beside each.
//!
//! | C entry point | Measured at | Rust counterpart |
//! |---|---|---|
//! | `curlx_str_init` | `strparse.c:26-30` | subsumed: an empty span is `&[]` |
//! | `curlx_str_assign` | `:32-36` | subsumed: assignment is a binding |
//! | `curlx_str` | `strparse.h:48` | subsumed: the span itself |
//! | `curlx_strlen` | `strparse.h:49` | subsumed: `span.len()` |
//! | `curlx_str_until` | `:40-60` | [`str_until`] |
//! | `curlx_str_word` | `:64-67` | [`str_word`] |
//! | `curlx_str_untilnl` | `:71-90` | [`str_untilnl`] |
//! | `curlx_str_quotedword` | `:94-121` | [`str_quotedword`] |
//! | `curlx_str_single` | `:125-132` | [`str_single`] |
//! | `curlx_str_singlespace` | `:136-139` | [`str_singlespace`] |
//! | `curlx_str_number` | `:195-198` | [`str_number`] |
//! | `curlx_str_hex` | `:202-205` | [`str_hex`] |
//! | `curlx_str_octal` | `:209-212` | [`str_octal`] |
//! | `curlx_str_numblanks` | `:218-222` | [`str_numblanks`] |
//! | `curlx_str_newline` | `:226-234` | [`str_newline`] |
//! | `curlx_str_casecompare` | `:239-243` | [`str_casecompare`] |
//! | `curlx_str_cmp` | `:247-254` | [`str_cmp`] |
//! | `curlx_str_nudge` | `:258-266` | [`str_nudge`] |
//! | `curlx_str_cspn` | `:270-286` | [`str_cspn`] |
//! | `curlx_str_trimblanks` | `:289-297` | [`str_trimblanks`] |
//! | `curlx_str_passblanks` | `:300-304` | [`str_passblanks`] |
//! | `curlx_hexasciitable` | `:148-154` | [`HEXASCIITABLE`] |
//! | `curlx_hexval` | `strparse.h:111` | [`hexval`] |
//!
//! # The byte classification, macro by macro
//!
//! All 20 macros of `lib/curl_ctype.h:27-50`, so that the correspondence can
//! be audited without reading the bodies:
//!
//! | C macro | Measured at | Rust counterpart |
//! |---|---|---|
//! | `ISLOWHEXALHA` | `:27` | [`is_lowhexalpha`] |
//! | `ISUPHEXALHA` | `:28` | [`is_uphexalpha`] |
//! | `ISLOWCNTRL` | `:30` | [`is_lowcntrl`] |
//! | `IS7F` | `:31` | [`is_7f`] |
//! | `ISLOWPRINT` | `:33` | [`is_lowprint`] |
//! | `ISPRINT` | `:35` | [`is_print`] |
//! | `ISGRAPH` | `:36` | [`is_graph`] |
//! | `ISCNTRL` | `:37` | [`is_cntrl`] |
//! | `ISALPHA` | `:38` | [`is_alpha`] |
//! | `ISXDIGIT` | `:39` | [`is_xdigit`] |
//! | `ISODIGIT` | `:40` | [`is_odigit`] |
//! | `ISALNUM` | `:41` | [`is_alnum`] |
//! | `ISUPPER` | `:42` | [`is_upper`] |
//! | `ISLOWER` | `:43` | [`is_lower`] |
//! | `ISDIGIT` | `:44` | [`is_digit`] |
//! | `ISBLANK` | `:45` | [`is_blank`] |
//! | `ISSPACE` | `:46` | [`is_space`] |
//! | `ISURLPUNTCS` | `:47-48` | [`is_urlpunct`] |
//! | `ISUNRESERVED` | `:49` | [`is_unreserved`] |
//! | `ISNEWLINE` | `:50` | [`is_newline`] |
//!
//! The upstream name of the eighteenth is spelled `ISURLPUNTCS`, with the
//! `C` and the `T` transposed. The Rust name fixes the spelling and this note
//! records the original so that a reader can still grep the C tree for it.
//!
//! # The cursor and the span
//!
//! The C API is a pointer-to-pointer cursor plus an out-parameter span:
//!
//! ```c
//! struct Curl_str { const char *str; size_t len; };
//! int curlx_str_until(const char **linep, struct Curl_str *out,
//!                     const size_t max, char delim);
//! ```
//!
//! Here the cursor is `&mut &[u8]` -- a mutable reference to a shrinking
//! slice. Reading advances the slice by reassigning it to its own tail, and
//! the extracted span is returned rather than written through a pointer, so
//! it borrows from the same buffer and cannot outlive it:
//!
//! ```ignore
//! let mut cursor: &[u8] = b"gzip, deflate";
//! let first = str_until(&mut cursor, 32, b',')?;   // b"gzip"
//! str_single(&mut cursor, b',')?;                  // consume the comma
//! ```
//!
//! Two consequences of that shape are improvements rather than translations,
//! and both are stated because they are the point of the migration. The C
//! header says of its span type, "public struct, but all accesses should be
//! done using the provided functions" -- a convention. A caller here receives
//! a `&[u8]` and has no invariant to break, so the convention becomes a
//! property. The second is that the C's `(pointer, length)` pair, which can
//! disagree, becomes one slice that cannot.
//!
//! # Bytes, not text
//!
//! Every signature takes and returns `u8` and `&[u8]`. The C walks
//! `const char *` and validates nothing, so a header value holding arbitrary
//! high bytes parses in C and must parse here; a `&str` boundary would reject
//! it, and a `char` boundary would silently re-interpret one byte as a
//! multi-byte scalar. [`as_str`] exists for the rare call site that genuinely
//! wants text, and it is fallible precisely so that the failure surfaces at
//! the caller rather than inside the parse.
//!
//! One decision follows from working in slices where the C worked in
//! terminated strings, and it is deliberate: **the byte `0x00` terminates a
//! span exactly as a delimiter does.** The C stops on it because it is
//! scanning a C string, and a caller that hands this module a buffer with an
//! embedded zero must see the same stopping behaviour or the parse diverges
//! from curl 8.19.0-DEV. That is faithfulness winning over elegance, and it
//! is asserted by test for each extractor rather than left as a claim.
//!
//! # Error vocabulary and what it is not
//!
//! [`StrError`] carries the eight failure codes of
//! `lib/curlx/strparse.h:29-36`. They are INTERNAL parse outcomes and have no
//! place in the C ABI, so they carry no pinned discriminants -- see the type's
//! own documentation for why conflating them with [`crate::error::CURLcode`]
//! would be a defect.
//!
//! # Visibility and layering
//!
//! `pub(crate)` throughout, with no `pub` item. No `curlx_str_*` name appears
//! among the 100 exported symbols of `lib/libcurl.def`, so nothing in
//! `curl-rs-ffi` reaches this module and the crate root adds no re-export for
//! it. The internal functions are internal by enforcement here where they
//! were internal by naming convention in C, and the coverage that
//! `tests/unit` obtained by linking a debug static library is relocated into
//! the test module at the foot of this file instead of being bought back with
//! a wider surface.
//!
//! This module names exactly one sibling, [`crate::util::strcase`], and needs
//! nothing else: `util` is the base of the crate's module graph and depends on
//! nothing above it.
//!
//! # Why every link target below is spelled absolutely
//!
//! `util/mod.rs` documents this module with an outer doc comment on its `mod`
//! declaration, and rustdoc concatenates that with the inner doc comment
//! above. The measured consequence is that intra-doc links in the merged text
//! resolve in `util`'s scope rather than this module's, so a target written as
//! a bare item name is reported unresolved. Each reference definition below
//! therefore carries a full path, which resolves under either scope and leaves
//! the tables above at their readable short spellings. The order is the order
//! of the file: the parser surface, then the error type and the text helper,
//! then the byte classification.
//!
//! One target is deliberately absent. `str_num_base` is private, and a link
//! from a module's own documentation to a private item does not resolve either,
//! so the prose above names it in plain code spelling instead.
//!
//! [`str_until`]: crate::util::strparse::str_until
//! [`str_word`]: crate::util::strparse::str_word
//! [`str_untilnl`]: crate::util::strparse::str_untilnl
//! [`str_quotedword`]: crate::util::strparse::str_quotedword
//! [`str_cspn`]: crate::util::strparse::str_cspn
//! [`str_single`]: crate::util::strparse::str_single
//! [`str_singlespace`]: crate::util::strparse::str_singlespace
//! [`str_newline`]: crate::util::strparse::str_newline
//! [`str_passblanks`]: crate::util::strparse::str_passblanks
//! [`str_trimblanks`]: crate::util::strparse::str_trimblanks
//! [`str_nudge`]: crate::util::strparse::str_nudge
//! [`HEXASCIITABLE`]: crate::util::strparse::HEXASCIITABLE
//! [`hexval`]: crate::util::strparse::hexval
//! [`str_number`]: crate::util::strparse::str_number
//! [`str_hex`]: crate::util::strparse::str_hex
//! [`str_octal`]: crate::util::strparse::str_octal
//! [`str_numblanks`]: crate::util::strparse::str_numblanks
//! [`str_casecompare`]: crate::util::strparse::str_casecompare
//! [`str_cmp`]: crate::util::strparse::str_cmp
//! [`StrError`]: crate::util::strparse::StrError
//! [`as_str`]: crate::util::strparse::as_str
//! [`is_lowhexalpha`]: crate::util::strparse::is_lowhexalpha
//! [`is_uphexalpha`]: crate::util::strparse::is_uphexalpha
//! [`is_lowcntrl`]: crate::util::strparse::is_lowcntrl
//! [`is_7f`]: crate::util::strparse::is_7f
//! [`is_lowprint`]: crate::util::strparse::is_lowprint
//! [`is_print`]: crate::util::strparse::is_print
//! [`is_graph`]: crate::util::strparse::is_graph
//! [`is_cntrl`]: crate::util::strparse::is_cntrl
//! [`is_alpha`]: crate::util::strparse::is_alpha
//! [`is_xdigit`]: crate::util::strparse::is_xdigit
//! [`is_odigit`]: crate::util::strparse::is_odigit
//! [`is_alnum`]: crate::util::strparse::is_alnum
//! [`is_upper`]: crate::util::strparse::is_upper
//! [`is_lower`]: crate::util::strparse::is_lower
//! [`is_digit`]: crate::util::strparse::is_digit
//! [`is_blank`]: crate::util::strparse::is_blank
//! [`is_space`]: crate::util::strparse::is_space
//! [`is_urlpunct`]: crate::util::strparse::is_urlpunct
//! [`is_unreserved`]: crate::util::strparse::is_unreserved
//! [`is_newline`]: crate::util::strparse::is_newline

use crate::util::strcase;

// ---------------------------------------------------------------------------
// The error vocabulary. `lib/curlx/strparse.h:28-36`.
// ---------------------------------------------------------------------------

/// Why a parse failed.
///
/// The eight non-success codes of `lib/curlx/strparse.h:29-36`, one variant
/// each. `STRE_OK` (`:28`) is deliberately absent: success is `Ok`, and a
/// success variant inside the error type would let a caller write a match arm
/// that cannot be reached.
///
/// | C code | Value | Variant |
/// |---|---|---|
/// | `STRE_BIG` | 1 | [`StrError::Big`] |
/// | `STRE_SHORT` | 2 | [`StrError::Short`] |
/// | `STRE_BEGQUOTE` | 3 | [`StrError::BegQuote`] |
/// | `STRE_ENDQUOTE` | 4 | [`StrError::EndQuote`] |
/// | `STRE_BYTE` | 5 | [`StrError::Byte`] |
/// | `STRE_NEWLINE` | 6 | [`StrError::Newline`] |
/// | `STRE_OVERFLOW` | 7 | [`StrError::Overflow`] |
/// | `STRE_NO_NUM` | 8 | [`StrError::NoNum`] |
///
/// # These are not `CURLcode`, and the difference matters
///
/// The values in that table are shown for provenance only. Nothing depends on
/// them, no discriminant is pinned, and no `#[repr(...)]` appears on this
/// type, because these codes never crossed the C ABI: they are defined in an
/// internal header, no public header mentions them, and no exported symbol
/// returns one. A caller that needs a `CURLcode` maps the variant at its own
/// layer, which is also where the mapping belongs -- the same
/// [`StrError::Overflow`] becomes `CURLE_BAD_FUNCTION_ARGUMENT` from one call
/// site and a silently-clamped value at another.
///
/// [`crate::error::CURLcode`] is the opposite case in every respect: its 103
/// discriminants are written out explicitly because a C program compiled
/// against curl 8.19.0-DEV holds their numeric values in its instruction
/// stream. Merging the two enumerations to save a type would attach that
/// obligation to codes that do not carry it, and would put a pinned public
/// enumeration one careless reordering away from breaking every consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrError {
    /// `STRE_BIG` -- the span reached `max + 1` bytes.
    Big,
    /// `STRE_SHORT` -- the span would have been empty, and every extractor
    /// requires at least one byte.
    Short,
    /// `STRE_BEGQUOTE` -- [`str_quotedword`] found no opening quote.
    BegQuote,
    /// `STRE_ENDQUOTE` -- [`str_quotedword`] found no closing quote.
    EndQuote,
    /// `STRE_BYTE` -- [`str_single`] found some other byte, or nothing.
    Byte,
    /// `STRE_NEWLINE` -- [`str_newline`] found a byte that is neither
    /// carriage return nor line feed.
    Newline,
    /// `STRE_OVERFLOW` -- a number exceeded its `max`, or [`str_nudge`] was
    /// asked to drop more bytes than the span holds.
    Overflow,
    /// `STRE_NO_NUM` -- the cursor was not looking at a digit of the
    /// requested base. Distinct from [`StrError::Overflow`] because callers
    /// discriminate: "not a number here" is a parse decision, "too large" is
    /// a rejection.
    NoNum,
}

// ---------------------------------------------------------------------------
// Reading past the end. The one rule the whole file rests on.
// ---------------------------------------------------------------------------

/// The byte at `index`, or the terminator the C would have read there.
///
/// Every loop in `lib/curlx/strparse.c` is written against a terminated
/// string and reads the terminator itself: `:48` tests `*s` as its loop
/// condition, `:106` reads `s[1]` one byte ahead of the cursor, and `:169`
/// dereferences `*p` before any bound is known. A slice has no terminator, so
/// every such read goes through this helper and index `len()` yields the zero
/// the C would have found.
///
/// That is what makes the zero byte an implicit terminator throughout this
/// module, and the choice is deliberate rather than incidental: a caller whose
/// buffer holds an embedded zero must get the same span curl gives it. The
/// sibling `strcase.rs:207-216` resolves the same problem the same way for the
/// same reason, and the two helpers are independent because neither module may
/// widen its surface for the other.
///
/// `slice::get` is not a `const fn` under this crate's minimum supported Rust
/// version, so the bound is tested directly. Both arms are total: the index
/// is only reached when it is known to be inside the slice.
#[must_use]
const fn byte_at(bytes: &[u8], index: usize) -> u8 {
    if index < bytes.len() {
        bytes[index]
    } else {
        0
    }
}

/// An extracted span as text, when it happens to be valid text.
///
/// There is no C counterpart, because the C has nothing to convert: its spans
/// are already `const char *` and it never checks them. This exists so that
/// the handful of call sites that genuinely want text -- a scheme name to
/// place in a message, a token to log -- can ask for it explicitly and handle
/// the refusal, instead of the parser imposing a text requirement on every
/// caller. Returning [`None`] rather than replacing malformed sequences is
/// what keeps that decision at the call site.
#[allow(dead_code)] // No consumer yet; trace and message output will call it.
#[must_use]
pub(crate) fn as_str(span: &[u8]) -> Option<&str> {
    core::str::from_utf8(span).ok()
}

// ---------------------------------------------------------------------------
// The byte classification -- `lib/curl_ctype.h:27-50`, range by range.
//
// Every predicate is a `const fn` taking a `u8`, and the shape of each body is
// the C macro's own: two comparisons joined by `&&`, or a disjunction of
// predicates already defined. Three notes on that choice, because each rules
// out an alternative that looks better in isolation.
//
// FIRST, why not the standard library. `u8::is_ascii_hexdigit`,
// `is_ascii_alphanumeric` and their siblings agree with several of these
// macros and disagree with others, and the disagreements are silent.
// `u8::is_ascii_whitespace` admits form feed, which `ISBLANK` refuses and
// `ISSPACE` reaches by a different route; `char::is_alphanumeric` and
// `char::is_whitespace` are Unicode-aware, so they answer a different question
// entirely. The classification decides which byte ends a header value, and
// that decision is visible in the request bytes the fixture corpus compares,
// so it is transcribed rather than delegated.
//
// SECOND, why not `(LO..=HI).contains(&b)`. `RangeInclusive::contains` is not
// a `const fn`, so it would cost the `const` qualifier that lets these appear
// in a constant initialiser. The direct comparison is also the literal
// transcription: `ISDIGIT(x)` is `((x) >= '0') && ((x) <= '9')`, character for
// character. Measured on the pinned toolchain: `clippy::manual_range_contains`
// does not fire inside a `const fn`, precisely because the replacement it
// would suggest is not available there, so the faithful form is also the
// lint-clean one and no allowance is needed.
//
// THIRD, why `u8` is equivalent to the C's `char`. The C macros are handed a
// plain `char`, which is signed on every platform in the four-target matrix,
// so a byte of 0x80 or above arrives as a negative value and fails the lower
// bound of every range. A `u8` of 0x80 passes the lower bound instead and
// fails the upper one. The answer is the same either way, for all 256 values,
// because every macro bounds its range on both sides -- and the one macro
// whose lower bound is open, `ISLOWCNTRL`, casts to `unsigned char` first
// (`:30`). The equivalence is asserted for all 256 bytes by
// `tests::the_predicates_agree_with_curl_ctype_h_for_every_byte`.
// ---------------------------------------------------------------------------

/// `ISLOWHEXALHA` -- `lib/curl_ctype.h:27`. The lower-case hexadecimal
/// letters, `a` through `f`.
#[allow(dead_code)] // No consumer yet; `is_xdigit` covers the joint case.
#[must_use]
pub(crate) const fn is_lowhexalpha(byte: u8) -> bool {
    byte >= b'a' && byte <= b'f'
}

/// `ISUPHEXALHA` -- `lib/curl_ctype.h:28`. The upper-case hexadecimal
/// letters, `A` through `F`.
#[allow(dead_code)] // No consumer yet; `is_xdigit` covers the joint case.
#[must_use]
pub(crate) const fn is_uphexalpha(byte: u8) -> bool {
    byte >= b'A' && byte <= b'F'
}

/// `ISLOWCNTRL` -- `lib/curl_ctype.h:30`. Everything up to and including
/// 0x1f.
///
/// The only macro in the header whose C form casts to `unsigned char` before
/// comparing, which it must: with a signed `char` the test would otherwise
/// admit every byte from 0x80 upward. Taking a `u8` makes the cast
/// unnecessary rather than merely correct.
#[allow(dead_code)] // No consumer yet; `is_cntrl` composes it.
#[must_use]
pub(crate) const fn is_lowcntrl(byte: u8) -> bool {
    byte <= 0x1f
}

/// `IS7F` -- `lib/curl_ctype.h:31`. The delete byte, and nothing else.
#[allow(dead_code)] // No consumer yet; `is_cntrl` composes it.
#[must_use]
pub(crate) const fn is_7f(byte: u8) -> bool {
    byte == 0x7f
}

/// `ISLOWPRINT` -- `lib/curl_ctype.h:33`. The five control bytes 9 through
/// 0x0d: tab, line feed, vertical tab, form feed and carriage return.
///
/// Named for the role it plays rather than for what it contains: both
/// [`is_print`] and [`is_graph`] admit this range, which is why neither of
/// them is the `isprint(3)` of the C library.
#[allow(dead_code)] // No consumer yet; `is_print` and `is_graph` compose it.
#[must_use]
pub(crate) const fn is_lowprint(byte: u8) -> bool {
    byte >= 9 && byte <= 0x0d
}

/// `ISPRINT` -- `lib/curl_ctype.h:35`, defined as
/// `ISLOWPRINT || (>= ' ' && <= 0x7e)`.
///
/// 0x7e is `~`, the last graphic byte of ASCII; the C spells it in hex and
/// this follows, so the two read alike.
#[allow(dead_code)] // No consumer yet; trace formatting will call it.
#[must_use]
pub(crate) const fn is_print(byte: u8) -> bool {
    is_lowprint(byte) || (byte >= b' ' && byte <= 0x7e)
}

/// `ISGRAPH` -- `lib/curl_ctype.h:36`, defined as
/// `ISLOWPRINT || (> ' ' && <= 0x7e)`.
///
/// Differs from [`is_print`] by the space alone. The C bound is strictly
/// greater than a space, which is transcribed as written rather than turned
/// into `>= 0x21` so that the two files diff line for line.
#[allow(dead_code)] // No consumer yet; trace formatting will call it.
#[must_use]
pub(crate) const fn is_graph(byte: u8) -> bool {
    is_lowprint(byte) || (byte > b' ' && byte <= 0x7e)
}

/// `ISCNTRL` -- `lib/curl_ctype.h:37`, defined as `ISLOWCNTRL || IS7F`.
///
/// Note the overlap with [`is_lowprint`]: tab, line feed, vertical tab, form
/// feed and carriage return satisfy both this and [`is_print`]. That is
/// curl's definition rather than an oversight, and it is why header parsing
/// cannot use this predicate alone to decide what to reject.
#[allow(dead_code)] // No consumer yet; header value validation will call it.
#[must_use]
pub(crate) const fn is_cntrl(byte: u8) -> bool {
    is_lowcntrl(byte) || is_7f(byte)
}

/// `ISALPHA` -- `lib/curl_ctype.h:38`, defined as `ISLOWER || ISUPPER`.
#[allow(dead_code)] // No consumer yet; scheme parsing will call it.
#[must_use]
pub(crate) const fn is_alpha(byte: u8) -> bool {
    is_lower(byte) || is_upper(byte)
}

/// `ISXDIGIT` -- `lib/curl_ctype.h:39`, defined as
/// `ISDIGIT || ISLOWHEXALHA || ISUPHEXALHA`.
///
/// The validator the C header demands before [`hexval`] may be used, and the
/// two agree exactly: `hexval` returns a value for precisely the bytes this
/// admits, which
/// `tests::hexval_answers_for_exactly_the_bytes_is_xdigit_admits` proves for
/// all 256 values rather than asserting.
#[allow(dead_code)] // No consumer yet; `inet` and chunk parsing will call it.
#[must_use]
pub(crate) const fn is_xdigit(byte: u8) -> bool {
    is_digit(byte) || is_lowhexalpha(byte) || is_uphexalpha(byte)
}

/// `ISODIGIT` -- `lib/curl_ctype.h:40`. The octal digits, `0` through `7`.
#[allow(dead_code)] // No consumer yet; file mode parsing will call it.
#[must_use]
pub(crate) const fn is_odigit(byte: u8) -> bool {
    byte >= b'0' && byte <= b'7'
}

/// `ISALNUM` -- `lib/curl_ctype.h:41`, defined as
/// `ISDIGIT || ISLOWER || ISUPPER`.
///
/// Spelled as three predicates rather than as [`is_digit`] with
/// [`is_alpha`], because that is how the C spells it. The two are the same
/// set.
#[allow(dead_code)] // No consumer yet; `is_unreserved` composes it.
#[must_use]
pub(crate) const fn is_alnum(byte: u8) -> bool {
    is_digit(byte) || is_lower(byte) || is_upper(byte)
}

/// `ISUPPER` -- `lib/curl_ctype.h:42`. `A` through `Z`.
#[allow(dead_code)] // No consumer yet; several composites use it.
#[must_use]
pub(crate) const fn is_upper(byte: u8) -> bool {
    byte >= b'A' && byte <= b'Z'
}

/// `ISLOWER` -- `lib/curl_ctype.h:43`. `a` through `z`.
#[allow(dead_code)] // No consumer yet; several composites use it.
#[must_use]
pub(crate) const fn is_lower(byte: u8) -> bool {
    byte >= b'a' && byte <= b'z'
}

/// `ISDIGIT` -- `lib/curl_ctype.h:44`. `0` through `9`.
#[allow(dead_code)] // No consumer yet; date and range parsing will call it.
#[must_use]
pub(crate) const fn is_digit(byte: u8) -> bool {
    byte >= b'0' && byte <= b'9'
}

/// `ISBLANK` -- `lib/curl_ctype.h:45`. Space and tab, and nothing else.
///
/// The set that [`str_passblanks`] skips and [`str_trimblanks`] removes.
/// Carriage return, line feed, vertical tab and form feed are NOT blanks
/// here, which is what keeps a line-oriented parser from stepping over the
/// end of its own line.
#[must_use]
pub(crate) const fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// `ISSPACE` -- `lib/curl_ctype.h:46`, defined as
/// `ISBLANK || (>= 0xa && <= 0x0d)`.
///
/// The second range is worth spelling out because it is easy to assume it
/// holds only the two line endings: it runs from line feed to carriage
/// return inclusive, so vertical tab (0x0b) and form feed (0x0c) are BOTH
/// members. Only the space of 0x20 and the tab of 0x09 come from the first
/// half.
#[allow(dead_code)] // No consumer yet; header folding will call it.
#[must_use]
pub(crate) const fn is_space(byte: u8) -> bool {
    is_blank(byte) || (byte >= 0x0a && byte <= 0x0d)
}

/// The four unreserved punctuation bytes of a URL: `-`, `.`, `_` and `~`.
///
/// Supersedes `ISURLPUNTCS` (`lib/curl_ctype.h:47-48`). The upstream name
/// transposes the `C` and the `T` of "punctuation"; the spelling is corrected
/// here and the original recorded so the C tree remains greppable.
#[allow(dead_code)] // No consumer yet; `is_unreserved` composes it.
#[must_use]
pub(crate) const fn is_urlpunct(byte: u8) -> bool {
    byte == b'-' || byte == b'.' || byte == b'_' || byte == b'~'
}

/// `ISUNRESERVED` -- `lib/curl_ctype.h:49`, defined as
/// `ISALNUM || ISURLPUNTCS`. The bytes a URL may carry unescaped.
#[allow(dead_code)] // No consumer yet; the URL API will call it.
#[must_use]
pub(crate) const fn is_unreserved(byte: u8) -> bool {
    is_alnum(byte) || is_urlpunct(byte)
}

/// `ISNEWLINE` -- `lib/curl_ctype.h:50`. Line feed or carriage return.
///
/// The stop condition of [`str_untilnl`] and the accept condition of
/// [`str_newline`]. It admits either byte on its own, so a two-byte line
/// ending is two members rather than one token, which is why
/// [`str_newline`] consumes only one byte per call.
#[must_use]
pub(crate) const fn is_newline(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r'
}

// ---------------------------------------------------------------------------
// The span extractors -- `lib/curlx/strparse.c:39-135` and `:268-286`.
//
// All five share one contract, stated once here so that each item can record
// only what is peculiar to it:
//
//   * On success the extracted span is returned and the cursor is advanced to
//     the first byte the span did not take. The delimiter itself is NOT
//     consumed -- `str_single` exists for that -- and the one exception,
//     `str_quotedword`, says so at the item.
//   * On failure the cursor is left exactly where it was, so a caller can
//     retry a different parse from the same position. Several callers depend
//     on it; the C obtains the same property by never writing back to
//     `*linep` before its last statement.
//   * An empty result is an error, `StrError::Short`, never an empty span.
//     The C header states the requirement as "At least one byte long".
//   * A zero byte terminates the span exactly as the delimiter does. See
//     `byte_at` above for why, and note that this makes the extractors total:
//     no input can make one of them read out of bounds or fail to terminate.
// ---------------------------------------------------------------------------

/// Takes the bytes up to the first `delim`, the first zero, or the end.
///
/// Supersedes `curlx_str_until` (`lib/curlx/strparse.c:40-60`), the primitive
/// every other extractor is built from:
///
/// ```c
/// curlx_str_init(out);
/// while(*s && (*s != delim)) {
///   s++;
///   if(++len > max)
///     return STRE_BIG;
/// }
/// if(!len)
///   return STRE_SHORT;
/// out->str = *linep;
/// out->len = len;
/// *linep = s;              /* point to the first byte after the word */
/// ```
///
/// # `max` is inclusive, and the test is post-increment
///
/// The single most off-by-one-sensitive line in this file. `++len > max`
/// increments first and compares afterwards, so a span of exactly `max` bytes
/// passes and one of `max + 1` bytes yields [`StrError::Big`]. Writing the
/// test before the increment would silently truncate every value that happens
/// to be exactly at the limit, and a truncated header value is a wire
/// difference rather than a local one.
///
/// # The delimiter is left in place
///
/// On success the cursor points AT the delimiter, not past it. That split is
/// load-bearing rather than incidental: it is what lets a caller distinguish
/// "the span ended because the delimiter arrived" from "the span ended because
/// the input did", by asking [`str_single`] for the delimiter and reading its
/// answer. `curl-rs-lib/src/trace.rs` parses a comma-separated configuration
/// exactly that way, calling this with a `max` of 32 and a delimiter of `,`.
///
/// # Errors
///
/// [`StrError::Big`] when more than `max` bytes precede the delimiter, and
/// [`StrError::Short`] when the delimiter is the first byte, the cursor is
/// empty, or the first byte is zero.
///
/// # Panics
///
/// Never. The two `debug_assert!` calls reproduce the C's
/// `DEBUGASSERT(linep && *linep && out && max && delim)` (`:45`), whose
/// surviving halves are that `max` is non-zero and the delimiter is not the
/// terminator; the two pointer clauses have no Rust counterpart because a
/// reference cannot be null. Both are caller contract violations rather than
/// input errors, which is why they are debug assertions here as they are
/// there, and neither can be reached from untrusted bytes.
#[allow(dead_code)] // No consumer yet; trace and header parsing will call it.
pub(crate) fn str_until<'a>(
    cursor: &mut &'a [u8],
    max: usize,
    delim: u8,
) -> Result<&'a [u8], StrError> {
    debug_assert!(max > 0, "the C asserts a non-zero max");
    debug_assert!(delim != 0, "the C asserts a non-terminator delimiter");

    let input = *cursor;
    let mut len = 0usize;

    // `while(*s && (*s != delim)) { s++; if(++len > max) return STRE_BIG; }`
    for &byte in input {
        if byte == 0 || byte == delim {
            break;
        }
        len += 1;
        if len > max {
            return Err(StrError::Big);
        }
    }

    // `if(!len) return STRE_SHORT;`
    if len == 0 {
        return Err(StrError::Short);
    }

    // `out->str = *linep; out->len = len; *linep = s;`
    //
    // `len` counted iterations of a walk over `input`, so `len <=
    // input.len()` holds by construction and the split is in range for every
    // possible input.
    let (span, rest) = input.split_at(len);
    *cursor = rest;
    Ok(span)
}

/// Takes the bytes up to the first space, the first zero, or the end.
///
/// Supersedes `curlx_str_word` (`lib/curlx/strparse.c:64-67`), whose body is
/// one line: `return curlx_str_until(linep, out, max, ' ')`. Reproduced as a
/// delegation rather than a copy, so that the boundary rules of
/// [`str_until`] cannot drift apart from this one.
///
/// A space and nothing else. A tab does not end a word here, which follows
/// from the C passing a single character rather than a predicate, and matters
/// because several header grammars separate on space alone.
///
/// # Errors
///
/// As [`str_until`], with a delimiter of `b' '`.
#[allow(dead_code)] // No consumer yet; netrc and FTP parsing will call it.
pub(crate) fn str_word<'a>(
    cursor: &mut &'a [u8],
    max: usize,
) -> Result<&'a [u8], StrError> {
    str_until(cursor, max, b' ')
}

/// Takes the bytes up to the first line ending, the first zero, or the end.
///
/// Supersedes `curlx_str_untilnl` (`lib/curlx/strparse.c:71-90`). Identical
/// to [`str_until`] in every respect except the stop condition, which is
/// [`is_newline`] rather than one byte -- so BOTH a carriage return and a
/// line feed end the span, and the cursor is left on whichever arrived
/// first.
///
/// The C is a separate function rather than a call into `curlx_str_until`
/// with a delimiter, because a predicate cannot be passed where a `char` is
/// expected; the duplication in the C is a consequence of that, not a
/// behavioural difference. The two bodies are otherwise line for line the
/// same, including the post-increment bound test.
///
/// Note that the C's assertion at `:76` drops the delimiter clause the
/// `curlx_str_until` assertion carries, exactly because there is no
/// delimiter to check.
///
/// # Errors
///
/// [`StrError::Big`] when more than `max` bytes precede the line ending, and
/// [`StrError::Short`] when the first byte is already a line ending, a zero,
/// or absent.
#[allow(dead_code)] // No consumer yet; netrc and cookie reading will call it.
pub(crate) fn str_untilnl<'a>(
    cursor: &mut &'a [u8],
    max: usize,
) -> Result<&'a [u8], StrError> {
    debug_assert!(max > 0, "the C asserts a non-zero max");

    let input = *cursor;
    let mut len = 0usize;

    // `while(*s && !ISNEWLINE(*s)) { s++; if(++len > max) return STRE_BIG; }`
    for &byte in input {
        if byte == 0 || is_newline(byte) {
            break;
        }
        len += 1;
        if len > max {
            return Err(StrError::Big);
        }
    }

    if len == 0 {
        return Err(StrError::Short);
    }

    let (span, rest) = input.split_at(len);
    *cursor = rest;
    Ok(span)
}

/// Takes a quoted word, returning the RAW bytes between the quotes.
///
/// Supersedes `curlx_str_quotedword` (`lib/curlx/strparse.c:94-121`):
///
/// ```c
/// if(*s != '\"')
///   return STRE_BEGQUOTE;
/// s++;
/// while(*s && (*s != '\"')) {
///   if(*s == '\\' && s[1]) {
///     s++;
///     if(++len > max)
///       return STRE_BIG;
///   }
///   s++;
///   if(++len > max)
///     return STRE_BIG;
/// }
/// if(*s != '\"')
///   return STRE_ENDQUOTE;
/// out->str = (*linep) + 1;
/// out->len = len;
/// *linep = s + 1;
/// ```
///
/// # It does NOT unescape, and that is the point
///
/// The returned span is the bytes between the quotes exactly as they appear
/// in the input, with every backslash still present. `"a\"b"` yields the four
/// bytes `a\"b`, not the three bytes `a"b`. The C does no unescaping and
/// neither does this, because unescaping is the caller's decision and
/// different callers make it differently -- a cookie attribute and an
/// alt-svc parameter do not agree on what an escape means.
///
/// This is the single most likely place in the module to "improve" curl's
/// behaviour by accident, and the improvement would be a defect: a caller
/// handed pre-unescaped bytes re-emits different bytes than curl
/// 8.19.0-DEV, which the fixture corpus compares literally.
///
/// # What an escape costs
///
/// A backslash followed by any non-terminator byte consumes TWO bytes and
/// counts TWO toward `max`, so `max` bounds the raw length rather than the
/// unescaped length. One consequence deserves a test of its own and has one:
/// a lone backslash immediately before the closing quote swallows that quote
/// as its escape partner, so `"a\"` is not terminated at all and yields
/// [`StrError::EndQuote`].
///
/// # The cursor lands past the closing quote
///
/// The one extractor that consumes its terminator. `*linep = s + 1` steps
/// over the quote because a quote, unlike a delimiter, cannot begin the next
/// token and is of no use to the caller.
///
/// # Errors
///
/// [`StrError::BegQuote`] when the first byte is not a quote,
/// [`StrError::EndQuote`] when the input ends or a zero arrives before the
/// closing quote, and [`StrError::Big`] when the raw length exceeds `max`.
///
/// Note that an empty pair of quotes is NOT an error: `""` yields an empty
/// span, because the C tests `len` only through the `max` bound and has no
/// `STRE_SHORT` path here. That asymmetry with every other extractor is the
/// C's, and it is preserved.
///
/// # Panics
///
/// Never. `debug_assert!(max > 0)` reproduces the C's `DEBUGASSERT` at `:99`
/// and states a caller contract, not an input condition.
#[allow(dead_code)] // No consumer yet; cookie and alt-svc parsing will call it.
pub(crate) fn str_quotedword<'a>(
    cursor: &mut &'a [u8],
    max: usize,
) -> Result<&'a [u8], StrError> {
    debug_assert!(max > 0, "the C asserts a non-zero max");

    let input = *cursor;

    // `if(*s != '\"') return STRE_BEGQUOTE;` -- and `s++`, which is why the
    // walk below starts at index 1.
    if byte_at(input, 0) != b'"' {
        return Err(StrError::BegQuote);
    }

    // `index` is the C's `s`, as an offset. `len` is the C's `len`: the count
    // of raw bytes taken since the opening quote. The two stay in step --
    // every iteration adds the same amount to both -- so `len == index - 1`
    // throughout, which is what makes the span below exactly `len` bytes long.
    let mut index = 1usize;
    let mut len = 0usize;

    // `while(*s && (*s != '\"')) { ... }`
    loop {
        let byte = byte_at(input, index);
        if byte == 0 || byte == b'"' {
            break;
        }

        // `if(*s == '\\' && s[1]) { s++; if(++len > max) return STRE_BIG; }`
        //
        // The look-ahead is the C's `s[1]`, which reads one byte past the
        // cursor and relies on the terminator being there. `byte_at` supplies
        // the same zero at the end of the slice, so a trailing backslash is
        // not treated as an escape -- and a backslash before the closing
        // quote IS, because a quote is not a terminator.
        if byte == b'\\' && byte_at(input, index + 1) != 0 {
            index += 1;
            len += 1;
            if len > max {
                return Err(StrError::Big);
            }
        }

        // `s++; if(++len > max) return STRE_BIG;`
        index += 1;
        len += 1;
        if len > max {
            return Err(StrError::Big);
        }
    }

    // `if(*s != '\"') return STRE_ENDQUOTE;` -- reached when the loop stopped
    // on a zero or ran out of input rather than on the closing quote.
    if byte_at(input, index) != b'"' {
        return Err(StrError::EndQuote);
    }

    // `out->str = (*linep) + 1; out->len = len; *linep = s + 1;`
    //
    // Both slicings are in range for every input: the test above proves
    // `byte_at(input, index)` read a real byte, so `index < input.len()`, and
    // `index >= 1` because the walk started there.
    let span = &input[1..index];
    *cursor = &input[index + 1..];
    Ok(span)
}

/// Takes the longest prefix containing no byte of `reject`.
///
/// Supersedes `curlx_str_cspn` (`lib/curlx/strparse.c:270-286`), whose body
/// delegates to `strcspn(s, reject)` and then splits on whether the answer
/// was zero. The name is the C library function's: "complement span".
///
/// Two differences from every other extractor, both the C's:
///
/// * There is no `max`. The span is bounded only by the input, and no bound
///   parameter is added here -- adding one would be a new refusal that curl
///   does not make.
/// * A zero-length answer resets the span to empty AND returns
///   [`StrError::Short`], so the C's caller sees a cleared out-parameter
///   rather than a stale one. Returning `Err` gives the caller nothing to
///   read, which is the same guarantee reached more directly.
///
/// `reject` is a byte set rather than a string. A zero inside it can never
/// match, because a zero in the input stops the scan first -- the same
/// reason `strcspn` cannot be handed a set containing its own terminator.
///
/// # Errors
///
/// [`StrError::Short`] when the first byte is rejected, is zero, or is
/// absent.
#[allow(dead_code)] // No consumer yet; URL and cookie parsing will call it.
pub(crate) fn str_cspn<'a>(
    cursor: &mut &'a [u8],
    reject: &[u8],
) -> Result<&'a [u8], StrError> {
    let input = *cursor;
    let mut len = 0usize;

    // `len = strcspn(s, reject);`
    for &byte in input {
        if byte == 0 || reject.contains(&byte) {
            break;
        }
        len += 1;
    }

    // `if(len) { ...take it... } curlx_str_init(out); return STRE_SHORT;`
    if len == 0 {
        return Err(StrError::Short);
    }

    let (span, rest) = input.split_at(len);
    *cursor = rest;
    Ok(span)
}

// ---------------------------------------------------------------------------
// Single bytes, blanks, and span adjustment -- `lib/curlx/strparse.c:123-139`,
// `:224-234` and `:255-304`.
// ---------------------------------------------------------------------------

/// Consumes exactly `byte`, or fails without moving.
///
/// Supersedes `curlx_str_single` (`lib/curlx/strparse.c:125-132`):
///
/// ```c
/// if(**linep != byte)
///   return STRE_BYTE;
/// (*linep)++;                 /* move over it */
/// ```
///
/// The counterpart to [`str_until`] leaving its delimiter in place: a caller
/// takes a token, then steps over the separator with this and learns from the
/// answer whether the separator was really there.
///
/// # An empty cursor is a refusal, not a panic
///
/// The C dereferences `**linep` with no bound at all, relying on a terminator
/// being present, so at the end of a string it compares against zero. Here the
/// cursor may simply be empty, and the comparison is written as
/// `first() != Some(&byte)` so that the absent byte matches nothing.
///
/// That leaves one input on which this deliberately differs from a literal
/// reading of the C, and it is recorded rather than glossed: asking for the
/// zero byte at the end of a C string makes the C advance its pointer PAST the
/// terminator, after which every later read is out of bounds. No call site in
/// the C tree does that -- every caller passes a printable separator -- and
/// returning [`StrError::Byte`] is the only total answer available, so that is
/// what happens here.
///
/// # Errors
///
/// [`StrError::Byte`] when the next byte is something else or there is no next
/// byte. The cursor is untouched in both cases.
#[allow(dead_code)] // No consumer yet; every list parser will call it.
pub(crate) fn str_single(cursor: &mut &[u8], byte: u8) -> Result<(), StrError> {
    let input = *cursor;

    // `if(**linep != byte) return STRE_BYTE;`
    if input.first() != Some(&byte) {
        return Err(StrError::Byte);
    }

    // `(*linep)++;` -- in range because the comparison above proves the slice
    // holds at least one byte.
    *cursor = &input[1..];
    Ok(())
}

/// Consumes exactly one space, or fails without moving.
///
/// Supersedes `curlx_str_singlespace` (`lib/curlx/strparse.c:136-139`), whose
/// body is `return curlx_str_single(linep, ' ')`. A delegation here too, for
/// the same reason as [`str_word`]: one definition of the behaviour.
///
/// One space, not any run of whitespace and not a tab. [`str_passblanks`] is
/// the function for a run.
///
/// # Errors
///
/// As [`str_single`] with a byte of `b' '`.
#[allow(dead_code)] // No consumer yet; header and FTP replies will call it.
pub(crate) fn str_singlespace(cursor: &mut &[u8]) -> Result<(), StrError> {
    str_single(cursor, b' ')
}

/// Consumes one line-ending byte, or fails without moving.
///
/// Supersedes `curlx_str_newline` (`lib/curlx/strparse.c:226-234`):
///
/// ```c
/// if(ISNEWLINE(**linep)) {
///   (*linep)++;
///   return STRE_OK;           /* yessir */
/// }
/// return STRE_NEWLINE;
/// ```
///
/// **One byte per call.** Either a carriage return or a line feed is accepted,
/// and exactly one is consumed, so a two-byte line ending takes two calls. The
/// C is written that way on purpose: it lets one parser accept both endings
/// without deciding which it is looking at, and a caller that requires the
/// pair asks twice.
///
/// # Errors
///
/// [`StrError::Newline`] when the next byte is neither ending, or when the
/// cursor is empty. The cursor is untouched in both cases -- an empty cursor
/// reads as the zero `byte_at` supplies, which [`is_newline`] refuses.
#[allow(dead_code)] // No consumer yet; netrc and cookie reading will call it.
pub(crate) fn str_newline(cursor: &mut &[u8]) -> Result<(), StrError> {
    let input = *cursor;

    // `if(ISNEWLINE(**linep))`
    if !is_newline(byte_at(input, 0)) {
        return Err(StrError::Newline);
    }

    // In range because `is_newline` cannot admit the zero that `byte_at`
    // returns past the end, so the slice holds at least one byte.
    *cursor = &input[1..];
    Ok(())
}

/// Advances over every leading blank.
///
/// Supersedes `curlx_str_passblanks` (`lib/curlx/strparse.c:300-304`), whose
/// body is `while(ISBLANK(**linep)) (*linep)++;`.
///
/// Blank means space or tab and nothing else ([`is_blank`]), so a line ending
/// stops the walk. That is what keeps a line-oriented parser inside its own
/// line, and it is the reason this is not spelled with [`is_space`].
///
/// Returns nothing and cannot fail: skipping no blanks at all is a valid
/// outcome, which is also why the C returns `void`. A zero byte is not blank,
/// so the walk stops there exactly as the C's does at its terminator.
#[allow(dead_code)] // No consumer yet; header and cookie parsing will call it.
pub(crate) fn str_passblanks(cursor: &mut &[u8]) {
    let input = *cursor;
    let mut skip = 0usize;

    for &byte in input {
        if !is_blank(byte) {
            break;
        }
        skip += 1;
    }

    // `skip` counted iterations of a walk over `input`, so it cannot exceed
    // the length.
    *cursor = &input[skip..];
}

/// Removes blanks from both ends of an already-extracted span.
///
/// Supersedes `curlx_str_trimblanks` (`lib/curlx/strparse.c:289-297`):
///
/// ```c
/// while(out->len && ISBLANK(*out->str))
///   curlx_str_nudge(out, 1);
/// /* trim trailing spaces and tabs */
/// while(out->len && ISBLANK(out->str[out->len - 1]))
///   out->len--;
/// ```
///
/// Space and tab only, at both ends, and every other byte left alone --
/// including a carriage return or line feed, which a general-purpose trim
/// would remove and which curl's header handling relies on still being there.
///
/// # A pure function where the C mutates
///
/// The C rewrites the span in place, once from the left through
/// `curlx_str_nudge` and once from the right by shortening the length. This
/// returns the trimmed sub-slice instead, which composes to the same thing at
/// a call site that wants the mutation -- `span = str_trimblanks(span);` --
/// while also being usable where the input must not change. Offering both
/// shapes would be surface with no second caller.
#[allow(dead_code)] // No consumer yet; header value handling will call it.
#[must_use]
pub(crate) fn str_trimblanks(span: &[u8]) -> &[u8] {
    // `while(out->len && ISBLANK(*out->str)) curlx_str_nudge(out, 1);`
    let mut start = 0usize;
    while start < span.len() && is_blank(span[start]) {
        start += 1;
    }

    // `while(out->len && ISBLANK(out->str[out->len - 1])) out->len--;`
    //
    // The lower bound is `start` rather than 0, which is what the C's `len`
    // reaching zero expresses: once the left walk has consumed everything,
    // there is nothing for the right walk to look at.
    let mut end = span.len();
    while end > start && is_blank(span[end - 1]) {
        end -= 1;
    }

    &span[start..end]
}

/// Drops `num` leading bytes from a span.
///
/// Supersedes `curlx_str_nudge` (`lib/curlx/strparse.c:258-266`):
///
/// ```c
/// if(num <= str->len) {
///   str->str += num;
///   str->len -= num;
///   return STRE_OK;
/// }
/// return STRE_OVERFLOW;
/// ```
///
/// `num == span.len()` is legal and yields an empty span; only `num` strictly
/// greater than the length is an error. `slice::get` over a range expresses
/// exactly that boundary -- it answers `Some` for `num <= len` and `None`
/// above it -- so the condition is the standard library's rather than
/// re-derived here, and there is no arithmetic that could underflow.
///
/// # Errors
///
/// [`StrError::Overflow`] when `num` exceeds the length of `span`.
#[allow(dead_code)] // No consumer yet; alt-svc and HSTS parsing will call it.
pub(crate) fn str_nudge(span: &[u8], num: usize) -> Result<&[u8], StrError> {
    span.get(num..).ok_or(StrError::Overflow)
}

// ---------------------------------------------------------------------------
// The hexadecimal table and the number parsers --
// `lib/curlx/strparse.c:137-222` and `lib/curlx/strparse.h:106-111`. The most
// detail-sensitive part of the file, and the part where a transcription slip
// is silent.
// ---------------------------------------------------------------------------

/// The digit value of every byte from `0` through `f`, indexed by
/// `byte - b'0'`.
///
/// Transcribed from `curlx_hexasciitable` (`lib/curlx/strparse.c:148-154`).
/// **Exactly 55 entries**, covering 0x30 (`0`) through 0x66 (`f`) with no gap:
/// ten digits, seven non-digits, six upper-case hexadecimal letters,
/// twenty-six non-digits, six lower-case hexadecimal letters. The count is
/// asserted by `tests::the_table_holds_exactly_the_fifty_five_c_entries`, so a
/// dropped or doubled entry fails the test run rather than shifting every
/// later index by one.
///
/// # The first entry is 16, not 0
///
/// The one detail that makes this table unlike every other digit lookup, and
/// the C explains it at `:145-147`: *"We use 16 for the zero index (and the
/// necessary bitwise AND in the loop) to be able to have a non-zero value
/// there to make valid_digit() able to use the info."*
///
/// The table therefore does double duty. A non-zero entry means "this byte is
/// a digit", which is how the digit test is written without a second range
/// check, and the sentinel is masked back down to its real value of zero on
/// the way out. Transcribing the entry as 0 would compile, pass a casual read,
/// and make the byte `0` stop being a digit -- so `007` would fail to parse
/// and `0` would parse as nothing at all.
///
/// The mask is applied by [`hexval`] and by nothing else, which is why no
/// caller ever sees the 16.
///
/// # Why the rows are grouped as they are
///
/// `#[rustfmt::skip]` is not cosmetic here. This table decides which bytes are
/// accepted as digits, and that decision reaches the wire, so the
/// transcription has to stay reviewable against the C side by side. One
/// presentational change is made and is confined to presentation: the C writes
/// its twenty-six-entry row on a single line that would exceed this crate's
/// 80-column limit at Rust indentation, so it appears below as two rows of
/// thirteen. The values, their order and their count are untouched, and the
/// test named above rebuilds the whole table from the C's five original rows
/// to prove the split changed nothing.
#[allow(dead_code)] // No consumer yet; `inet` will pre-validate against it.
#[rustfmt::skip]
pub(crate) const HEXASCIITABLE: [u8; 55] = [
    // 0x30 ..= 0x39 -- '0' through '9'. The leading 16 is the sentinel.
    16, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    // 0x3a ..= 0x40 -- ':' ';' '<' '=' '>' '?' '@'
    0, 0, 0, 0, 0, 0, 0,
    // 0x41 ..= 0x46 -- 'A' through 'F'
    10, 11, 12, 13, 14, 15,
    // 0x47 ..= 0x53 -- 'G' through 'S'
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0x54 ..= 0x60 -- 'T' through '`'
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0x61 ..= 0x66 -- 'a' through 'f'
    10, 11, 12, 13, 14, 15,
];

/// The raw table entry for `byte`, or 0 when the byte is outside the table.
///
/// The C indexes `curlx_hexasciitable[(x) - '0']` with no bound check of any
/// kind, which is safe there only because both of its callers -- the digit test
/// at `:142-143` and `curlx_hexval` at `strparse.h:111` -- are guarded by a
/// range test the caller is trusted to have made. The header says so in
/// capitals: *"THIS ONLY WORKS ON VALID HEXADECIMAL LETTER INPUT. Verify
/// before calling this!"*
///
/// This helper makes the guard unnecessary instead of merely documented. A
/// byte below `0` fails the subtraction and a byte above `f` falls off the end
/// of the table, and both answer 0 -- which is already the table's own value
/// for "not a digit", so the total function agrees with the partial one
/// wherever the partial one was defined.
///
/// The widening to an index goes through `usize::from` rather than a cast. The
/// two cannot differ for a `u8` on any target, but the conversion that cannot
/// lose information is the one written, because a cast is how the narrowing
/// defects this migration exists to remove are spelled.
#[must_use]
fn hexasciitable_entry(byte: u8) -> u8 {
    byte.checked_sub(b'0')
        .and_then(|index| HEXASCIITABLE.get(usize::from(index)))
        .copied()
        .unwrap_or(0)
}

/// The value of a hexadecimal digit, or [`None`] when `byte` is not one.
///
/// Supersedes `curlx_hexval` (`lib/curlx/strparse.h:111`), which is
/// `(unsigned char)(curlx_hexasciitable[(x) - '0'] & 0x0f)` -- the table
/// lookup and the mask that removes the sentinel described on
/// [`HEXASCIITABLE`].
///
/// # Fallible where the C is not, deliberately
///
/// The C macro is a partial function with its precondition stated in a comment
/// and enforced nowhere, and its two failure modes are both silent: a byte
/// below `0` indexes before the table, and a byte above `f` indexes past it.
/// Returning [`Option`] moves the precondition into the type, so a caller
/// cannot forget it, and no accessor that panics or answers wrongly is offered
/// alongside -- an "unchecked" twin would reintroduce exactly the hazard this
/// removes.
///
/// Nothing is lost for callers that do validate. `hexval` answers `Some` for
/// precisely the bytes [`is_xdigit`] admits, so a caller that pre-validates
/// the way the C requires can rely on the answer being present, and
/// [`HEXASCIITABLE`] is reachable for a caller that wants the table itself.
/// `curl-rs-lib/src/dns` consumes this pair when parsing a literal IPv6
/// address, which is the shape `lib/curlx/inet_pton.c` uses.
///
/// `hexval(b'0')` is `Some(0)`, which is the mask doing its work: the raw
/// entry there is 16.
#[allow(dead_code)] // No consumer yet; `inet` and chunk parsing will call it.
#[must_use]
pub(crate) fn hexval(byte: u8) -> Option<u8> {
    let entry = hexasciitable_entry(byte);
    if entry == 0 {
        // Not a digit: either outside the table, or one of the thirty-three
        // in-table bytes that are not hexadecimal.
        None
    } else {
        // `& 0x0f` -- the mask that turns the sentinel back into zero.
        Some(entry & 0x0f)
    }
}

/// The value of `byte` as a digit in a base whose largest digit is `largest`.
///
/// Fuses the C's two steps into one lookup. `valid_digit(x, m)`
/// (`lib/curlx/strparse.c:142-143`) is
///
/// ```c
/// (((x) >= '0') && ((x) <= (m)) && curlx_hexasciitable[(x) - '0'])
/// ```
///
/// and every place it succeeds is immediately followed by `curlx_hexval(*p++)`
/// reading the same table entry again. Asking once returns both answers, and
/// the fusion is what removes an otherwise-unreachable branch: written as two
/// calls, the value lookup would need a "cannot happen" arm for the case the
/// test has already excluded, and a branch no input can reach is a branch no
/// test can cover.
///
/// The three clauses survive intact. The lower bound and the table truth are
/// both inside [`hexval`], which answers [`None`] for a byte below `0` and for
/// any in-table byte whose entry is zero; the upper bound is the one
/// comparison written here. `largest` is `9` for base ten, `f` for base
/// sixteen and `7` for base eight, which is what makes base eight refuse `8`
/// and `9`, and what makes bases eight and ten refuse `A` through `F` -- the
/// letters are above `9` in ASCII, so the bound alone rejects them.
#[must_use]
fn digit_value(byte: u8, largest: u8) -> Option<i64> {
    // `((x) <= (m))`
    if byte > largest {
        return None;
    }

    // `((x) >= '0') && curlx_hexasciitable[(x) - '0']`, then the value.
    hexval(byte).map(i64::from)
}

/// Parses an unsigned number in base 8, 10 or 16, bounded by `max`.
///
/// Supersedes `str_num_base` (`lib/curlx/strparse.c:157-191`), which is
/// `static` in the C and private here for the same reason: the three public
/// entry points ([`str_number`], [`str_hex`], [`str_octal`]) are the surface,
/// and the base belongs to them rather than to their callers.
///
/// # What it does not accept
///
/// The C states the restrictions in two comments, at `:156` and `:193-194`:
/// *"no support for 0x prefix nor leading spaces"* and *"with no leading space
/// or minus"*. So:
///
/// * No `0x` prefix. `0x10` parses as the single digit `0` and leaves the
///   cursor on the `x`, which is a successful parse of zero rather than an
///   error, and callers rely on being able to look at what follows.
/// * No leading `0` octal prefix. The base is chosen by the entry point, never
///   sniffed from the input.
/// * No leading blanks. [`str_numblanks`] is the entry point that skips them.
/// * No sign. `-1` yields [`StrError::NoNum`], because `-` is not a digit.
/// * Leading zeroes ARE accepted: `007` is 7.
///
/// # Two overflow algorithms, and why both must ship
///
/// The C selects between them on `max < base`:
///
/// ```c
/// if(max < base) {   /* special-case low max scenario because check needs
///                       to be different */
///   do {
///     int n = curlx_hexval(*p++);
///     num = num * base + n;
///     if(num > max)
///       return STRE_OVERFLOW;
///   } while(valid_digit(*p, m));
/// }
/// else {
///   do {
///     int n = curlx_hexval(*p++);
///     if(num > ((max - n) / base))
///       return STRE_OVERFLOW;
///     num = num * base + n;
///   } while(valid_digit(*p, m));
/// }
/// ```
///
/// The low-`max` arm multiplies and then tests the product; the general arm
/// tests before multiplying, because the product it is guarding against is the
/// one that would not fit. They are not interchangeable at the boundaries --
/// the pre-test divides by `base`, and with `max` below `base` that division
/// floors to zero, so the general arm would reject every digit from 1 upward
/// including ones that fit. Both arms are reproduced, and both are covered by
/// their own test.
///
/// # Neither arm can overflow an `i64`
///
/// Rust arithmetic is checked in debug builds and wraps in release, so "the C
/// would have had undefined behaviour" is not an available answer. Neither arm
/// reaches either outcome:
///
/// * Low-`max` arm: the branch condition is `max < base` and `base` is at most
///   16, so `max` is at most 15. Every iteration ends by proving `num <= max`,
///   and the first starts from zero, so the multiplication is at most
///   `15 * 16 + 15`, which is 255.
/// * General arm: the pre-test proves `num <= (max - digit) / base` with every
///   term non-negative, and integer division floors, so `num * base <= max -
///   digit` and the sum is at most `max`. `max - digit` cannot underflow
///   either, because this arm runs only when `max >= base > digit`.
///
/// A negative `max` reaches the low-`max` arm and fails the first digit with
/// [`StrError::Overflow`], which is what the C does too. The
/// `debug_assert!(max >= 0)` reproduces the C's assertion at `:166` and its
/// comment, *"mostly to catch SIZE_MAX, which is too large"*: the value is a
/// caller mistake rather than bad input, and the release behaviour is a clean
/// refusal either way.
///
/// # On failure the cursor does not move, and no value is produced
///
/// The C writes `*nump = 0` before it looks at anything (`:167`) and assigns
/// `*linep = p` only on the last line, so a failed parse leaves the caller's
/// cursor untouched and its number at zero. Here the cursor is written once at
/// the end, giving the same guarantee, and `Result` gives a stronger version of
/// the second: there is no value to read at all. A caller that wants the C's
/// zero writes `unwrap_or(0)` and says so.
///
/// # Errors
///
/// [`StrError::NoNum`] when the first byte is not a digit of this base, and
/// [`StrError::Overflow`] when the accumulated value would exceed `max`.
fn str_num_base(
    cursor: &mut &[u8],
    max: i64,
    base: i64,
) -> Result<i64, StrError> {
    debug_assert!(
        base == 8 || base == 10 || base == 16,
        "the C asserts base 8, 10 or 16"
    );
    debug_assert!(max >= 0, "the C asserts a non-negative max");

    // `int m = (base == 10) ? '9' : (base == 16) ? 'f' : '7';` -- the largest
    // digit this base admits.
    let largest: u8 = match base {
        10 => b'9',
        16 => b'f',
        _ => b'7',
    };

    let input = *cursor;
    let mut index = 0usize;
    let mut num: i64 = 0;

    // `if(!valid_digit(*p, m)) return STRE_NO_NUM;`
    //
    // `byte_at` supplies the zero the C reads from its terminator, so an empty
    // cursor and a cursor at an embedded zero both land here.
    let mut digit = match digit_value(byte_at(input, index), largest) {
        Some(value) => value,
        None => return Err(StrError::NoNum),
    };

    if max < base {
        // The C's low-`max` arm: multiply, then test the product.
        loop {
            index += 1;
            num = num * base + digit;
            if num > max {
                return Err(StrError::Overflow);
            }
            // `while(valid_digit(*p, m));`
            match digit_value(byte_at(input, index), largest) {
                Some(next) => digit = next,
                None => break,
            }
        }
    } else {
        // The C's general arm: test before multiplying.
        loop {
            index += 1;
            if num > (max - digit) / base {
                return Err(StrError::Overflow);
            }
            num = num * base + digit;
            // `while(valid_digit(*p, m));`
            match digit_value(byte_at(input, index), largest) {
                Some(next) => digit = next,
                None => break,
            }
        }
    }

    // `*nump = num; *linep = p;`
    //
    // `index` counted digits accepted from `input`, so it cannot exceed the
    // length: `digit_value` refuses the zero that `byte_at` returns past the
    // end, which stops the loop before the index can run past it.
    *cursor = &input[index..];
    Ok(num)
}

/// Parses an unsigned decimal number bounded by `max`.
///
/// Supersedes `curlx_str_number` (`lib/curlx/strparse.c:195-198`), whose body
/// is `str_num_base(linep, nump, max, 10)`. The C's comment states the
/// contract: *"Get an unsigned decimal number with no leading space or minus.
/// Leading zeroes are accepted."*
///
/// # Errors
///
/// As [`str_num_base`] in base ten.
#[allow(dead_code)] // No consumer yet; nearly every later parser will call it.
pub(crate) fn str_number(
    cursor: &mut &[u8],
    max: i64,
) -> Result<i64, StrError> {
    str_num_base(cursor, max, 10)
}

/// Parses an unsigned hexadecimal number bounded by `max`.
///
/// Supersedes `curlx_str_hex` (`lib/curlx/strparse.c:202-205`), whose body is
/// `str_num_base(linep, nump, max, 16)`. The C's comment is explicit that
/// there is *"no `0x` support"*, and both letter cases are accepted because
/// [`HEXASCIITABLE`] carries both.
///
/// # Errors
///
/// As [`str_num_base`] in base sixteen.
#[allow(dead_code)] // No consumer yet; chunked framing will call it.
pub(crate) fn str_hex(cursor: &mut &[u8], max: i64) -> Result<i64, StrError> {
    str_num_base(cursor, max, 16)
}

/// Parses an unsigned octal number bounded by `max`.
///
/// Supersedes `curlx_str_octal` (`lib/curlx/strparse.c:209-212`), whose body
/// is `str_num_base(linep, nump, max, 8)`. No leading `0` is required and none
/// is consumed as a prefix, and the digits stop at `7`: an `8` or a `9` is not
/// a digit of this base, so it ends the number, or yields
/// [`StrError::NoNum`] when it is the first byte.
///
/// # Errors
///
/// As [`str_num_base`] in base eight.
#[allow(dead_code)] // No consumer yet; file mode parsing will call it.
pub(crate) fn str_octal(cursor: &mut &[u8], max: i64) -> Result<i64, StrError> {
    str_num_base(cursor, max, 8)
}

/// Skips leading blanks, then parses an unbounded unsigned decimal number.
///
/// Supersedes `curlx_str_numblanks` (`lib/curlx/strparse.c:218-222`), whose
/// two-line body is `curlx_str_passblanks(str)` followed by
/// `curlx_str_number(str, num, CURL_OFF_T_MAX)`. The C's comment describes it
/// as parsing *"a positive number up to 63-bit number written in ASCII. Skip
/// leading blanks. No support for prefixes."*
///
/// The bound is [`i64::MAX`], which is `CURL_OFF_T_MAX` on every target in the
/// four-target matrix: `lib/curl_setup.h:599` defines it as
/// `0x7FFFFFFFFFFFFFFF`, and all four targets are 64-bit. That equivalence is
/// asserted rather than assumed, by
/// `tests::the_unbounded_maximum_is_curl_off_t_max`.
///
/// # The blanks are consumed even when the number fails
///
/// Worth stating because it is the one place in this module where a failure
/// leaves the cursor moved. `str_passblanks` runs first and unconditionally,
/// so `"   x"` advances past three spaces and then reports
/// [`StrError::NoNum`] from the `x`. The C behaves identically, for the same
/// structural reason, and a caller that needs to retry from the original
/// position keeps its own copy of the cursor.
///
/// # Errors
///
/// As [`str_number`]. Overflow is possible despite the bound being the
/// largest representable value: a long enough run of digits exceeds it.
#[allow(dead_code)] // No consumer yet; header and reply parsing will call it.
pub(crate) fn str_numblanks(cursor: &mut &[u8]) -> Result<i64, StrError> {
    str_passblanks(cursor);
    str_number(cursor, i64::MAX)
}

// ---------------------------------------------------------------------------
// The comparators -- `lib/curlx/strparse.c:236-254`.
//
// READ THIS BEFORE DIFFING EITHER FUNCTION AGAINST THE C. These two invert the
// return convention of every other function in the C file. Everything else
// there returns non-zero for an ERROR; these two return non-zero for a MATCH.
// Their own comments say so -- "Returns non-zero on match" at `:238` and
// `:246` -- and reading them with the other convention in mind inverts the
// meaning of every call site.
//
// Returning `bool` here removes the ambiguity rather than translating it: there
// is no "zero" to interpret, and a caller writing `if str_cmp(span, b"gzip")`
// gets the reading the name suggests. Nothing in this module returns `bool` for
// a failure, so the two conventions cannot be confused once they are types.
// ---------------------------------------------------------------------------

/// True when `span` equals `check`, ignoring ASCII letter case.
///
/// Supersedes `curlx_str_casecompare` (`lib/curlx/strparse.c:239-243`):
///
/// ```c
/// size_t clen = check ? strlen(check) : 0;
/// return ((str->len == clen) && curl_strnequal(str->str, check, clen));
/// ```
///
/// The composition is preserved exactly: a length test, then a folded
/// comparison of that many bytes. `curl_strnequal` is the exported name of the
/// comparator in [`crate::util::strcase`], and routing through it is what keeps
/// ONE definition of curl's folding in the crate. Reaching instead for
/// `eq_ignore_ascii_case` would be a second definition that happens to agree
/// today, on a fold that is visible through the exported `curl_strequal` and
/// `curl_strnequal` and therefore not this module's to choose.
///
/// The fold is ASCII-only and locale-independent, which is the whole reason
/// curl carries its own: only the twenty-six letter pairs fold, so the two
/// bytes 0xc3 0xa9 do NOT compare equal to 0xc3 0x89 however a locale might
/// feel about it. That is asserted by test rather than left as a claim.
///
/// # The C's conditional compilation has no successor
///
/// The C wraps this function in `#ifndef WITHOUT_LIBCURL` (`:236` and `:244`)
/// because it calls an exported libcurl symbol, and the utility layer is also
/// built into standalone tools that do not link the library. Here the fold and
/// the parser are modules of one crate, so there is nothing to exclude and the
/// function is unconditional. No Cargo feature gates it, and none should be
/// added: the guard answered a question about linkage, not about capability.
///
/// # The C's null comparand
///
/// `check` is a `&[u8]` and cannot be null, so the C's `check ? ... : 0` has no
/// second arm to reproduce. For THIS function the two coincide anyway: a null
/// comparand gives the C a length of zero and a zero-length comparison, which
/// succeeds exactly when the span is empty -- and `str_casecompare(span, &[])`
/// is true exactly when `span` is empty. [`str_cmp`] is where the two paths
/// genuinely differ, and it says so.
#[allow(dead_code)] // No consumer yet; header and scheme matching will call it.
#[must_use]
pub(crate) fn str_casecompare(span: &[u8], check: &[u8]) -> bool {
    // `(str->len == clen) && curl_strnequal(str->str, check, clen)`.
    span.len() == check.len() && strcase::ncasecompare(span, check, check.len())
}

/// True when `span` equals `check` byte for byte.
///
/// Supersedes `curlx_str_cmp` (`lib/curlx/strparse.c:247-254`):
///
/// ```c
/// if(check) {
///   size_t clen = strlen(check);
///   return ((str->len == clen) && !strncmp(str->str, check, clen));
/// }
/// return !!(str->len);
/// ```
///
/// Case-sensitive, unlike [`str_casecompare`]. The first arm is a length test
/// followed by a byte comparison of that length, which is exactly what slice
/// equality is, so the whole arm is one operator here.
///
/// # The null arm, recorded because it does not translate
///
/// The second arm is measured, not a typo: with a null comparand the C returns
/// `!!(str->len)`, so a null "matches" every NON-EMPTY span and fails on an
/// empty one. Read as a comparison that is backwards; read as a test the
/// call site can make, it is "did the parse produce anything".
///
/// A `&[u8]` cannot be null, so that arm is unreachable here, and passing an
/// empty slice does NOT reach it -- `str_cmp(span, &[])` is true when `span` is
/// empty, which is the opposite answer. The observation is recorded rather than
/// dropped so that a caller porting C code which relied on the null arm writes
/// `!span.is_empty()` at the call site, where the inverted meaning is local and
/// visible, instead of expecting it from this function.
#[allow(dead_code)] // No consumer yet; token and header matching will call it.
#[must_use]
pub(crate) fn str_cmp(span: &[u8], check: &[u8]) -> bool {
    // `(str->len == clen) && !strncmp(str->str, check, clen)`.
    span == check
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A quote, spelled as a constant so that test inputs can be written as
    /// byte arrays.
    ///
    /// The inputs for [`str_quotedword`] are the one place in this module where
    /// a byte-string literal needs three levels of escaping to say what it
    /// means, and a reviewer checking the raw span against the C should not
    /// have to unpick `b"\"a\\\"b\""` first. Arrays of named bytes say the same
    /// thing and cannot be misread.
    const QUOTE: u8 = b'"';

    /// A backslash, for the same reason as [`QUOTE`].
    const BACKSLASH: u8 = b'\\';

    // -----------------------------------------------------------------------
    // The byte classification. `lib/curl_ctype.h:27-50`.
    // -----------------------------------------------------------------------

    /// A second, independent transcription of `lib/curl_ctype.h`, used as the
    /// oracle for the predicates above.
    ///
    /// Written with explicit comparisons rather than by delegating to
    /// `u8::is_ascii_*`, because an oracle that called the standard library
    /// would be testing whether the standard library agrees with itself. It has
    /// to be a reading of the header, so it is one, macro by macro and in the
    /// header's own order.
    ///
    /// The single allowance below is what that costs: the comparisons are the
    /// point, so the lint that would replace them with a range method is
    /// silenced here and nowhere else.
    #[allow(clippy::manual_range_contains)]
    fn c_macro(name: &str, x: u8) -> bool {
        match name {
            // ISLOWHEXALHA(x) -- :27
            "ISLOWHEXALHA" => x >= b'a' && x <= b'f',
            // ISUPHEXALHA(x) -- :28
            "ISUPHEXALHA" => x >= b'A' && x <= b'F',
            // ISLOWCNTRL(x) -- :30, with the C's unsigned-char cast
            "ISLOWCNTRL" => x <= 0x1f,
            // IS7F(x) -- :31
            "IS7F" => x == 0x7f,
            // ISLOWPRINT(x) -- :33
            "ISLOWPRINT" => x >= 9 && x <= 0x0d,
            // ISPRINT(x) -- :35
            "ISPRINT" => c_macro("ISLOWPRINT", x) || (x >= b' ' && x <= 0x7e),
            // ISGRAPH(x) -- :36
            "ISGRAPH" => c_macro("ISLOWPRINT", x) || (x > b' ' && x <= 0x7e),
            // ISCNTRL(x) -- :37
            "ISCNTRL" => c_macro("ISLOWCNTRL", x) || c_macro("IS7F", x),
            // ISALPHA(x) -- :38
            "ISALPHA" => c_macro("ISLOWER", x) || c_macro("ISUPPER", x),
            // ISXDIGIT(x) -- :39
            "ISXDIGIT" => {
                c_macro("ISDIGIT", x)
                    || c_macro("ISLOWHEXALHA", x)
                    || c_macro("ISUPHEXALHA", x)
            }
            // ISODIGIT(x) -- :40
            "ISODIGIT" => x >= b'0' && x <= b'7',
            // ISALNUM(x) -- :41
            "ISALNUM" => {
                c_macro("ISDIGIT", x)
                    || c_macro("ISLOWER", x)
                    || c_macro("ISUPPER", x)
            }
            // ISUPPER(x) -- :42
            "ISUPPER" => x >= b'A' && x <= b'Z',
            // ISLOWER(x) -- :43
            "ISLOWER" => x >= b'a' && x <= b'z',
            // ISDIGIT(x) -- :44
            "ISDIGIT" => x >= b'0' && x <= b'9',
            // ISBLANK(x) -- :45
            "ISBLANK" => x == b' ' || x == b'\t',
            // ISSPACE(x) -- :46
            "ISSPACE" => c_macro("ISBLANK", x) || (x >= 0x0a && x <= 0x0d),
            // ISURLPUNTCS(x) -- :47-48
            "ISURLPUNTCS" => x == b'-' || x == b'.' || x == b'_' || x == b'~',
            // ISUNRESERVED(x) -- :49
            "ISUNRESERVED" => {
                c_macro("ISALNUM", x) || c_macro("ISURLPUNTCS", x)
            }
            // ISNEWLINE(x) -- :50
            "ISNEWLINE" => x == b'\n' || x == b'\r',
            other => unreachable!("no such macro in curl_ctype.h: {other}"),
        }
    }

    /// Every predicate against the oracle, for all 256 byte values.
    ///
    /// Exhaustive rather than sampled, which is affordable at this size and is
    /// the only way to prove the two claims that matter: that the twenty
    /// predicates are the twenty macros, and that taking a `u8` where the C
    /// takes a signed `char` changes no answer anywhere -- including across the
    /// 0x80 boundary, where a sign-extended comparison and an unsigned one
    /// reach the same verdict by opposite routes.
    #[test]
    fn the_predicates_agree_with_curl_ctype_h_for_every_byte() {
        for value in 0..=u8::MAX {
            assert_eq!(
                is_lowhexalpha(value),
                c_macro("ISLOWHEXALHA", value),
                "ISLOWHEXALHA at {value:#04x}"
            );
            assert_eq!(
                is_uphexalpha(value),
                c_macro("ISUPHEXALHA", value),
                "ISUPHEXALHA at {value:#04x}"
            );
            assert_eq!(
                is_lowcntrl(value),
                c_macro("ISLOWCNTRL", value),
                "ISLOWCNTRL at {value:#04x}"
            );
            assert_eq!(is_7f(value), c_macro("IS7F", value), "IS7F");
            assert_eq!(
                is_lowprint(value),
                c_macro("ISLOWPRINT", value),
                "ISLOWPRINT at {value:#04x}"
            );
            assert_eq!(
                is_print(value),
                c_macro("ISPRINT", value),
                "ISPRINT at {value:#04x}"
            );
            assert_eq!(
                is_graph(value),
                c_macro("ISGRAPH", value),
                "ISGRAPH at {value:#04x}"
            );
            assert_eq!(
                is_cntrl(value),
                c_macro("ISCNTRL", value),
                "ISCNTRL at {value:#04x}"
            );
            assert_eq!(
                is_alpha(value),
                c_macro("ISALPHA", value),
                "ISALPHA at {value:#04x}"
            );
            assert_eq!(
                is_xdigit(value),
                c_macro("ISXDIGIT", value),
                "ISXDIGIT at {value:#04x}"
            );
            assert_eq!(
                is_odigit(value),
                c_macro("ISODIGIT", value),
                "ISODIGIT at {value:#04x}"
            );
            assert_eq!(
                is_alnum(value),
                c_macro("ISALNUM", value),
                "ISALNUM at {value:#04x}"
            );
            assert_eq!(
                is_upper(value),
                c_macro("ISUPPER", value),
                "ISUPPER at {value:#04x}"
            );
            assert_eq!(
                is_lower(value),
                c_macro("ISLOWER", value),
                "ISLOWER at {value:#04x}"
            );
            assert_eq!(
                is_digit(value),
                c_macro("ISDIGIT", value),
                "ISDIGIT at {value:#04x}"
            );
            assert_eq!(
                is_blank(value),
                c_macro("ISBLANK", value),
                "ISBLANK at {value:#04x}"
            );
            assert_eq!(
                is_space(value),
                c_macro("ISSPACE", value),
                "ISSPACE at {value:#04x}"
            );
            assert_eq!(
                is_urlpunct(value),
                c_macro("ISURLPUNTCS", value),
                "ISURLPUNTCS at {value:#04x}"
            );
            assert_eq!(
                is_unreserved(value),
                c_macro("ISUNRESERVED", value),
                "ISUNRESERVED at {value:#04x}"
            );
            assert_eq!(
                is_newline(value),
                c_macro("ISNEWLINE", value),
                "ISNEWLINE at {value:#04x}"
            );
        }
    }

    /// Blank is space and tab, and the four bytes a general-purpose trim would
    /// also take are refused.
    ///
    /// Named individually rather than left to the exhaustive test above,
    /// because these four are the ones a reader is most likely to assume are
    /// members: line feed, vertical tab, form feed and carriage return. Their
    /// exclusion is what keeps [`str_passblanks`] and [`str_trimblanks`] inside
    /// a single line.
    #[test]
    fn blank_is_space_and_tab_and_refuses_the_four_other_whitespace_bytes() {
        assert!(is_blank(b' '));
        assert!(is_blank(b'\t'));

        assert!(!is_blank(b'\n'), "line feed is not blank");
        assert!(!is_blank(0x0b), "vertical tab is not blank");
        assert!(!is_blank(0x0c), "form feed is not blank");
        assert!(!is_blank(b'\r'), "carriage return is not blank");
    }

    /// `ISSPACE` reaches 0x0a through 0x0d, so vertical tab and form feed are
    /// members even though they are not blanks.
    ///
    /// The measured set rather than the assumed one. It would be natural to
    /// read the second half of the macro as "the two line endings", and it is
    /// an inclusive range over four bytes.
    #[test]
    fn space_covers_the_whole_range_from_line_feed_to_carriage_return() {
        assert!(is_space(b' '));
        assert!(is_space(b'\t'));

        assert!(is_space(0x0a), "line feed");
        assert!(is_space(0x0b), "vertical tab IS a space");
        assert!(is_space(0x0c), "form feed IS a space");
        assert!(is_space(0x0d), "carriage return");

        // The bytes either side of that range are not: 0x08 is backspace and
        // 0x0e is shift-out, and neither macro admits them.
        assert!(!is_space(0x08), "backspace is not a space");
        assert!(!is_space(0x0e), "shift-out is not a space");
    }

    /// No byte at or above 0x80 is alphanumeric.
    ///
    /// The property that a Unicode-aware classifier would break: every one of
    /// the 128 high bytes is refused, so a header value carrying arbitrary
    /// bytes is classified the same way curl classifies it.
    #[test]
    fn no_high_byte_is_alphanumeric() {
        for value in 0x80..=u8::MAX {
            assert!(!is_alnum(value), "{value:#04x} must not be alphanumeric");
            assert!(!is_alpha(value), "{value:#04x} must not be alphabetic");
            assert!(!is_digit(value), "{value:#04x} must not be a digit");
            assert!(!is_xdigit(value), "{value:#04x} must not be hexadecimal");
            assert!(!is_print(value), "{value:#04x} must not be printable");
            assert!(!is_space(value), "{value:#04x} must not be a space");
        }
    }

    // -----------------------------------------------------------------------
    // The hexadecimal table. `lib/curlx/strparse.c:148-154`.
    // -----------------------------------------------------------------------

    /// The table, rebuilt from the C's five original rows and compared.
    ///
    /// This is the test the two-row split of the twenty-six zeroes exists to be
    /// checked by. The rows below are the C's, in the C's grouping and with the
    /// C's counts, concatenated in order; if the table above lost, gained or
    /// reordered an entry -- or if the split changed anything -- the vectors
    /// differ here.
    ///
    /// Three further properties are asserted because each is a distinct way for
    /// a transcription to go wrong: the total length is 55, the first entry is
    /// the sentinel 16 rather than 0, and the last index maps to `f`.
    #[test]
    fn the_table_holds_exactly_the_fifty_five_c_entries() {
        // `lib/curlx/strparse.c:149-153`, row for row.
        let digits: [u8; 10] = [16, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let after_digits: [u8; 7] = [0; 7];
        let upper: [u8; 6] = [10, 11, 12, 13, 14, 15];
        let after_upper: [u8; 26] = [0; 26];
        let lower: [u8; 6] = [10, 11, 12, 13, 14, 15];

        let mut rebuilt: Vec<u8> = Vec::new();
        rebuilt.extend_from_slice(&digits);
        rebuilt.extend_from_slice(&after_digits);
        rebuilt.extend_from_slice(&upper);
        rebuilt.extend_from_slice(&after_upper);
        rebuilt.extend_from_slice(&lower);

        assert_eq!(rebuilt.len(), 55, "the C rows total 55 entries");
        assert_eq!(
            HEXASCIITABLE.len(),
            55,
            "the table must hold exactly 55 entries"
        );
        assert_eq!(
            rebuilt.as_slice(),
            HEXASCIITABLE.as_slice(),
            "the table diverges from the C rows"
        );

        // The sentinel, and the mask that hides it.
        assert_eq!(HEXASCIITABLE[0], 16, "index 0 holds the sentinel");
        assert_eq!(hexval(b'0'), Some(0), "the sentinel is masked to zero");

        // The last index is `f`, which is what makes `byte - b'0'` a total
        // index over the whole hexadecimal alphabet and no further.
        assert_eq!(usize::from(b'f' - b'0'), HEXASCIITABLE.len() - 1);
    }

    /// Every one of the 22 hexadecimal digits, and a sample of the refusals.
    #[test]
    fn hexval_answers_for_every_hexadecimal_digit() {
        let cases: [(u8, u8); 22] = [
            (b'0', 0),
            (b'1', 1),
            (b'2', 2),
            (b'3', 3),
            (b'4', 4),
            (b'5', 5),
            (b'6', 6),
            (b'7', 7),
            (b'8', 8),
            (b'9', 9),
            (b'A', 10),
            (b'B', 11),
            (b'C', 12),
            (b'D', 13),
            (b'E', 14),
            (b'F', 15),
            (b'a', 10),
            (b'b', 11),
            (b'c', 12),
            (b'd', 13),
            (b'e', 14),
            (b'f', 15),
        ];

        for (byte, value) in cases {
            assert_eq!(hexval(byte), Some(value), "hexval({byte:#04x})");
        }

        // The four boundary refusals, one on each side of a valid run, plus a
        // letter past `f` and a high byte. `/` and `:` bracket the digits,
        // `@` and `G` bracket the upper-case letters.
        for byte in [b'/', b':', b'@', b'G', b'g', b'~', 0x80, 0xff] {
            assert_eq!(hexval(byte), None, "hexval({byte:#04x}) must refuse");
        }
    }

    /// [`hexval`] and [`is_xdigit`] describe the same set of bytes.
    ///
    /// The property that lets a caller pre-validate the way the C header
    /// demands and then rely on the value being present. Proven over all 256
    /// bytes rather than at the boundaries, because the table's thirty-three
    /// interior zeroes are exactly where an off-by-one transcription would
    /// hide.
    #[test]
    fn hexval_answers_for_exactly_the_bytes_is_xdigit_admits() {
        for value in 0..=u8::MAX {
            assert_eq!(
                hexval(value).is_some(),
                is_xdigit(value),
                "disagreement at {value:#04x}"
            );
        }
    }

    /// The raw entry helper is total, and answers zero outside the table.
    ///
    /// Covers the two reads the C makes out of bounds: below the table, where
    /// the C would index negatively, and above it, where the C would read past
    /// the end. Both answer zero, which is already the table's own value for
    /// "not a digit", so the total function agrees with the C wherever the C
    /// was defined at all.
    #[test]
    fn the_raw_table_lookup_is_total_in_both_directions() {
        // Below `0`: the C computes a negative index here.
        assert_eq!(hexasciitable_entry(0), 0);
        assert_eq!(hexasciitable_entry(b'/'), 0);

        // Above `f`: the C reads past the end of a 55-entry array here.
        assert_eq!(hexasciitable_entry(b'g'), 0);
        assert_eq!(hexasciitable_entry(0xff), 0);

        // Inside, the entry is the C's, sentinel included.
        assert_eq!(hexasciitable_entry(b'0'), 16);
        assert_eq!(hexasciitable_entry(b'9'), 9);
        assert_eq!(hexasciitable_entry(b'A'), 10);
        assert_eq!(hexasciitable_entry(b'f'), 15);
        assert_eq!(hexasciitable_entry(b':'), 0);
    }

    // -----------------------------------------------------------------------
    // `str_until`. `lib/curlx/strparse.c:40-60`.
    // -----------------------------------------------------------------------

    /// A span of exactly `max` bytes succeeds and one of `max + 1` does not.
    ///
    /// The post-increment boundary, asserted from both sides. A single test
    /// covers both because the pair is the property: an implementation that
    /// tested before incrementing would fail the first assertion, and one that
    /// tested two bytes late would fail the second.
    #[test]
    fn until_accepts_exactly_max_bytes_and_refuses_one_more() {
        let mut cursor: &[u8] = b"abcd,rest";
        assert_eq!(str_until(&mut cursor, 4, b','), Ok(&b"abcd"[..]));
        assert_eq!(cursor, b",rest");

        let mut cursor: &[u8] = b"abcde,rest";
        assert_eq!(str_until(&mut cursor, 4, b','), Err(StrError::Big));
        assert_eq!(cursor, b"abcde,rest", "a refusal must not move the cursor");
    }

    /// A delimiter in the first position is [`StrError::Short`], not an empty
    /// span.
    #[test]
    fn until_refuses_an_empty_span() {
        let mut cursor: &[u8] = b",rest";
        assert_eq!(str_until(&mut cursor, 32, b','), Err(StrError::Short));
        assert_eq!(cursor, b",rest");

        let mut cursor: &[u8] = b"";
        assert_eq!(str_until(&mut cursor, 32, b','), Err(StrError::Short));
        assert!(cursor.is_empty());
    }

    /// With no delimiter anywhere, the span is the whole remainder and the
    /// cursor ends empty.
    #[test]
    fn until_takes_the_whole_remainder_when_the_delimiter_is_absent() {
        let mut cursor: &[u8] = b"no delimiter here";
        assert_eq!(
            str_until(&mut cursor, 64, b','),
            Ok(&b"no delimiter here"[..])
        );
        assert!(cursor.is_empty());
    }

    /// The cursor is left ON the delimiter, which the caller then consumes.
    ///
    /// The split that `curl-rs-lib/src/trace.rs` depends on: it walks a
    /// comma-separated configuration by alternating [`str_until`] and
    /// [`str_single`], and a delimiter consumed by the first would leave the
    /// second with nothing to report.
    #[test]
    fn until_leaves_the_delimiter_for_the_caller() {
        let mut cursor: &[u8] = b"gzip, deflate";

        let first = str_until(&mut cursor, 32, b',');
        assert_eq!(first, Ok(&b"gzip"[..]));
        assert_eq!(cursor.first(), Some(&b','), "the comma is still there");

        assert_eq!(str_single(&mut cursor, b','), Ok(()));
        assert_eq!(cursor, b" deflate");
    }

    /// A zero byte ends the span exactly as the delimiter does.
    ///
    /// The decision recorded at `byte_at`: the C stops on its terminator, so a
    /// buffer carrying an embedded zero must produce the same span here. The
    /// cursor is left ON the zero, because it was not consumed.
    #[test]
    fn until_treats_an_embedded_zero_as_a_terminator() {
        let input: [u8; 8] = [b'a', b'b', 0, b'c', b'd', b',', b'e', b'f'];
        let mut cursor: &[u8] = &input;

        assert_eq!(str_until(&mut cursor, 32, b','), Ok(&b"ab"[..]));
        assert_eq!(cursor.first(), Some(&0), "the cursor stops on the zero");
    }

    /// A leading zero byte is a short span, not an empty success.
    #[test]
    fn until_refuses_a_leading_zero_byte() {
        let input: [u8; 3] = [0, b'a', b','];
        let mut cursor: &[u8] = &input;
        assert_eq!(str_until(&mut cursor, 32, b','), Err(StrError::Short));
        assert_eq!(cursor, &input[..]);
    }

    // -----------------------------------------------------------------------
    // `str_word` and `str_untilnl`. `:64-67` and `:71-90`.
    // -----------------------------------------------------------------------

    /// A word ends at a space and NOT at a tab.
    ///
    /// The C passes a single character rather than a predicate, so the tab is
    /// an ordinary byte here. Asserting the negative is the point: a
    /// "whitespace" reading of the delimiter would split this input in two.
    #[test]
    fn word_stops_at_a_space_but_not_at_a_tab() {
        let mut cursor: &[u8] = b"first second";
        assert_eq!(str_word(&mut cursor, 32), Ok(&b"first"[..]));
        assert_eq!(cursor, b" second");

        // The tab is written as an escape, never as a literal tab byte: the
        // repository's whitespace gate rejects a tab anywhere in a source file.
        let mut cursor: &[u8] = b"first\tnext!";
        assert_eq!(str_word(&mut cursor, 32), Ok(&b"first\tnext!"[..]));
        assert!(cursor.is_empty(), "the tab did not end the word");
    }

    /// A line ends at either a line feed or a carriage return.
    #[test]
    fn untilnl_stops_at_both_line_endings() {
        let mut cursor: &[u8] = b"line\nnext";
        assert_eq!(str_untilnl(&mut cursor, 32), Ok(&b"line"[..]));
        assert_eq!(cursor, b"\nnext");

        let mut cursor: &[u8] = b"line\r\nnext";
        assert_eq!(str_untilnl(&mut cursor, 32), Ok(&b"line"[..]));
        assert_eq!(cursor, b"\r\nnext");
    }

    /// The bound and the empty case behave as [`str_until`]'s do.
    #[test]
    fn untilnl_keeps_the_same_bound_and_empty_rules() {
        let mut cursor: &[u8] = b"abcde\n";
        assert_eq!(str_untilnl(&mut cursor, 5), Ok(&b"abcde"[..]));
        assert_eq!(cursor, b"\n");

        let mut cursor: &[u8] = b"abcdef\n";
        assert_eq!(str_untilnl(&mut cursor, 5), Err(StrError::Big));
        assert_eq!(cursor, b"abcdef\n");

        let mut cursor: &[u8] = b"\nrest";
        assert_eq!(str_untilnl(&mut cursor, 5), Err(StrError::Short));
        assert_eq!(cursor, b"\nrest");
    }

    // -----------------------------------------------------------------------
    // `str_quotedword`. `:94-121`.
    // -----------------------------------------------------------------------

    /// A missing opening quote is [`StrError::BegQuote`].
    #[test]
    fn quotedword_requires_an_opening_quote() {
        let mut cursor: &[u8] = b"abc";
        assert_eq!(str_quotedword(&mut cursor, 32), Err(StrError::BegQuote));
        assert_eq!(cursor, b"abc");

        let mut cursor: &[u8] = b"";
        assert_eq!(str_quotedword(&mut cursor, 32), Err(StrError::BegQuote));
    }

    /// A missing closing quote is [`StrError::EndQuote`].
    #[test]
    fn quotedword_requires_a_closing_quote() {
        let unterminated: [u8; 4] = [QUOTE, b'a', b'b', b'c'];
        let mut cursor: &[u8] = &unterminated;
        assert_eq!(str_quotedword(&mut cursor, 32), Err(StrError::EndQuote));
        assert_eq!(cursor, &unterminated[..]);

        // An embedded zero ends the scan the way the C's terminator does, so
        // the quote that follows it is never reached.
        let zeroed: [u8; 5] = [QUOTE, b'a', 0, b'b', QUOTE];
        let mut cursor: &[u8] = &zeroed;
        assert_eq!(str_quotedword(&mut cursor, 32), Err(StrError::EndQuote));
    }

    /// The span is the RAW bytes between the quotes, backslashes retained.
    ///
    /// The behaviour most at risk of being "improved". The input is the six
    /// bytes of `"a\"b"` and the answer is the four bytes `a\"b` -- an
    /// unescaping implementation would answer with the three bytes `a"b` and
    /// would re-emit different bytes than curl does.
    #[test]
    fn quotedword_does_not_unescape() {
        let input: [u8; 6] = [QUOTE, b'a', BACKSLASH, QUOTE, b'b', QUOTE];
        let mut cursor: &[u8] = &input;

        let span = str_quotedword(&mut cursor, 32);
        assert_eq!(span, Ok(&[b'a', BACKSLASH, QUOTE, b'b'][..]));
        assert_eq!(
            span.map(<[u8]>::len),
            Ok(4),
            "four raw bytes, not three unescaped ones"
        );
        assert!(cursor.is_empty(), "the cursor lands past the closing quote");
    }

    /// An escape pair counts two toward `max`, so `max` bounds the raw length.
    #[test]
    fn quotedword_counts_an_escape_pair_as_two_bytes() {
        let input: [u8; 6] = [QUOTE, b'a', BACKSLASH, QUOTE, b'b', QUOTE];

        // Four raw bytes fit in a bound of four.
        let mut cursor: &[u8] = &input;
        assert_eq!(
            str_quotedword(&mut cursor, 4),
            Ok(&[b'a', BACKSLASH, QUOTE, b'b'][..])
        );

        // They do not fit in three, even though the unescaped form would.
        let mut cursor: &[u8] = &input;
        assert_eq!(str_quotedword(&mut cursor, 3), Err(StrError::Big));
        assert_eq!(cursor, &input[..]);
    }

    /// The cursor lands past the closing quote, not on it.
    #[test]
    fn quotedword_consumes_its_closing_quote() {
        let input: [u8; 6] = [QUOTE, b'a', b'b', QUOTE, b',', b'c'];
        let mut cursor: &[u8] = &input;

        assert_eq!(str_quotedword(&mut cursor, 32), Ok(&b"ab"[..]));
        assert_eq!(cursor, b",c", "the quote is gone, the comma remains");
    }

    /// A lone backslash before the closing quote swallows it.
    ///
    /// The C's look-ahead tests only that the next byte is not the terminator,
    /// and a quote is not the terminator, so the pair is consumed and the word
    /// is left unterminated. Faithful rather than convenient: a caller relying
    /// on this input being accepted would diverge from curl.
    #[test]
    fn quotedword_lets_a_trailing_backslash_swallow_the_closing_quote() {
        let input: [u8; 4] = [QUOTE, b'a', BACKSLASH, QUOTE];
        let mut cursor: &[u8] = &input;

        assert_eq!(str_quotedword(&mut cursor, 32), Err(StrError::EndQuote));
        assert_eq!(cursor, &input[..]);
    }

    /// An empty pair of quotes yields an empty span rather than an error.
    ///
    /// The one extractor that admits an empty result, because the C's body has
    /// no `STRE_SHORT` path. Recorded by test so that the asymmetry with
    /// [`str_until`] is deliberate rather than discovered.
    #[test]
    fn quotedword_accepts_an_empty_pair_of_quotes() {
        let input: [u8; 3] = [QUOTE, QUOTE, b'!'];
        let mut cursor: &[u8] = &input;

        assert_eq!(str_quotedword(&mut cursor, 32), Ok(&[][..]));
        assert_eq!(cursor, b"!");
    }

    // -----------------------------------------------------------------------
    // `str_cspn`. `:270-286`.
    // -----------------------------------------------------------------------

    /// The cursor lands on the first rejected byte.
    #[test]
    fn cspn_stops_on_the_first_rejected_byte() {
        let mut cursor: &[u8] = b"token;charset=utf-8";
        assert_eq!(str_cspn(&mut cursor, b";="), Ok(&b"token"[..]));
        assert_eq!(cursor, b";charset=utf-8");

        // The second run stops on the other member of the reject set.
        assert_eq!(str_single(&mut cursor, b';'), Ok(()));
        assert_eq!(str_cspn(&mut cursor, b";="), Ok(&b"charset"[..]));
        assert_eq!(cursor, b"=utf-8");
    }

    /// A zero-length result is [`StrError::Short`].
    #[test]
    fn cspn_refuses_an_empty_result() {
        let mut cursor: &[u8] = b";leading";
        assert_eq!(str_cspn(&mut cursor, b";="), Err(StrError::Short));
        assert_eq!(cursor, b";leading");

        let mut cursor: &[u8] = b"";
        assert_eq!(str_cspn(&mut cursor, b";="), Err(StrError::Short));
    }

    /// An empty reject set takes everything, and a zero byte still stops it.
    ///
    /// `strcspn(s, "")` is `strlen(s)`, and both halves of that are asserted:
    /// nothing is rejected, and the scan still ends at the terminator.
    #[test]
    fn cspn_with_an_empty_reject_set_takes_the_whole_string() {
        let mut cursor: &[u8] = b"everything";
        assert_eq!(str_cspn(&mut cursor, b""), Ok(&b"everything"[..]));
        assert!(cursor.is_empty());

        let zeroed: [u8; 5] = [b'a', b'b', 0, b'c', b'd'];
        let mut cursor: &[u8] = &zeroed;
        assert_eq!(str_cspn(&mut cursor, b""), Ok(&b"ab"[..]));
        assert_eq!(cursor.first(), Some(&0));
    }

    // -----------------------------------------------------------------------
    // `str_single`, `str_singlespace`, `str_newline`. `:125-139`, `:226-234`.
    // -----------------------------------------------------------------------

    /// A match consumes exactly one byte.
    #[test]
    fn single_consumes_exactly_one_byte() {
        let mut cursor: &[u8] = b"::rest";
        assert_eq!(str_single(&mut cursor, b':'), Ok(()));
        assert_eq!(cursor, b":rest");
        assert_eq!(str_single(&mut cursor, b':'), Ok(()));
        assert_eq!(cursor, b"rest");
    }

    /// A mismatch is [`StrError::Byte`] and the cursor does not move.
    #[test]
    fn single_refuses_another_byte_without_moving() {
        let mut cursor: &[u8] = b";rest";
        assert_eq!(str_single(&mut cursor, b':'), Err(StrError::Byte));
        assert_eq!(cursor, b";rest");
    }

    /// An empty cursor is a refusal, and nothing panics.
    ///
    /// The C dereferences unconditionally here and relies on a terminator
    /// existing. A slice has no terminator, so the absent byte has to match
    /// nothing -- including when the byte asked for is itself zero, which
    /// is the one input where the C would step out of bounds.
    #[test]
    fn single_refuses_an_empty_cursor_rather_than_panicking() {
        let mut cursor: &[u8] = b"";
        assert_eq!(str_single(&mut cursor, b':'), Err(StrError::Byte));
        assert!(cursor.is_empty());

        let mut cursor: &[u8] = b"";
        assert_eq!(str_single(&mut cursor, 0), Err(StrError::Byte));
        assert!(cursor.is_empty());
    }

    /// The space variant is the general one with a space.
    #[test]
    fn singlespace_takes_one_space_and_nothing_else() {
        let mut cursor: &[u8] = b"  two";
        assert_eq!(str_singlespace(&mut cursor), Ok(()));
        assert_eq!(cursor, b" two");

        let mut cursor: &[u8] = b"\tabc";
        assert_eq!(str_singlespace(&mut cursor), Err(StrError::Byte));
        assert_eq!(cursor, b"\tabc", "a tab is not the space it asked for");
    }

    /// Each line ending is one byte, so a two-byte ending needs two calls.
    #[test]
    fn newline_consumes_one_byte_at_a_time() {
        let mut cursor: &[u8] = b"\n";
        assert_eq!(str_newline(&mut cursor), Ok(()));
        assert!(cursor.is_empty());

        let mut cursor: &[u8] = b"\r";
        assert_eq!(str_newline(&mut cursor), Ok(()));
        assert!(cursor.is_empty());

        // A two-byte ending: one call each.
        let mut cursor: &[u8] = b"\r\nrest";
        assert_eq!(str_newline(&mut cursor), Ok(()));
        assert_eq!(cursor, b"\nrest", "only the carriage return was taken");
        assert_eq!(str_newline(&mut cursor), Ok(()));
        assert_eq!(cursor, b"rest");
    }

    /// Anything else is [`StrError::Newline`], including nothing.
    #[test]
    fn newline_refuses_every_other_byte() {
        for byte in [b' ', b'\t', 0x0b, 0x0c, b'a', 0, 0xff] {
            let input: [u8; 1] = [byte];
            let mut cursor: &[u8] = &input;
            assert_eq!(
                str_newline(&mut cursor),
                Err(StrError::Newline),
                "{byte:#04x} must not read as a line ending"
            );
            assert_eq!(cursor, &input[..]);
        }

        let mut cursor: &[u8] = b"";
        assert_eq!(str_newline(&mut cursor), Err(StrError::Newline));
    }

    // -----------------------------------------------------------------------
    // `str_passblanks`, `str_trimblanks` and `str_nudge`. `:255-304`.
    // -----------------------------------------------------------------------

    /// Blanks are skipped; a line ending stops the walk.
    #[test]
    fn passblanks_skips_spaces_and_tabs_only() {
        let mut cursor: &[u8] = b" \t value";
        str_passblanks(&mut cursor);
        assert_eq!(cursor, b"value");

        // A carriage return is not a blank, so nothing moves.
        let mut cursor: &[u8] = b"\r\n";
        str_passblanks(&mut cursor);
        assert_eq!(cursor, b"\r\n");

        // Skipping nothing is a valid outcome, and so is skipping everything.
        let mut cursor: &[u8] = b"";
        str_passblanks(&mut cursor);
        assert!(cursor.is_empty());

        let mut cursor: &[u8] = b"   ";
        str_passblanks(&mut cursor);
        assert!(cursor.is_empty());
    }

    /// Both ends are trimmed of blanks, and line endings are left alone.
    #[test]
    fn trimblanks_removes_blanks_from_both_ends_only() {
        assert_eq!(str_trimblanks(b" \tvalue \t"), b"value");

        // A carriage return and a line feed survive at both ends.
        assert_eq!(str_trimblanks(b"\r val \n"), b"\r val \n");

        // An all-blank span trims to empty, which is the C's `len` reaching
        // zero and stopping the second loop before it looks at anything.
        assert!(str_trimblanks(b" \t ").is_empty());

        // An empty span is already trimmed.
        assert!(str_trimblanks(b"").is_empty());

        // Interior blanks are untouched.
        assert_eq!(str_trimblanks(b" a b "), b"a b");
    }

    /// Dropping the whole span is legal; dropping more is
    /// [`StrError::Overflow`].
    #[test]
    fn nudge_accepts_the_whole_length_and_refuses_more() {
        let span: &[u8] = b"abcde";

        assert_eq!(str_nudge(span, 0), Ok(&b"abcde"[..]));
        assert_eq!(str_nudge(span, 2), Ok(&b"cde"[..]));

        let all = str_nudge(span, 5);
        assert_eq!(all, Ok(&[][..]), "num == len is legal");
        assert_eq!(all.map(<[u8]>::is_empty), Ok(true));

        assert_eq!(str_nudge(span, 6), Err(StrError::Overflow));
        assert_eq!(str_nudge(b"", 1), Err(StrError::Overflow));
        assert_eq!(str_nudge(b"", 0), Ok(&[][..]));
    }

    // -----------------------------------------------------------------------
    // The number parsers. `:157-222`.
    // -----------------------------------------------------------------------

    /// Zero, and leading zeroes, parse as the C parses them.
    #[test]
    fn number_accepts_zero_and_leading_zeroes() {
        let mut cursor: &[u8] = b"0";
        assert_eq!(str_number(&mut cursor, 100), Ok(0));
        assert!(cursor.is_empty());

        let mut cursor: &[u8] = b"007";
        assert_eq!(str_number(&mut cursor, 100), Ok(7));
        assert!(cursor.is_empty());

        let mut cursor: &[u8] = b"0000000000000000001rest";
        assert_eq!(str_number(&mut cursor, i64::MAX), Ok(1));
        assert_eq!(cursor, b"rest");
    }

    /// Anything that is not a digit of the base is [`StrError::NoNum`], and the
    /// cursor does not move.
    #[test]
    fn number_refuses_a_non_digit_without_moving() {
        for input in [&b""[..], &b"x"[..], &b"-1"[..], &b"+1"[..], &b" 1"[..]] {
            let mut cursor: &[u8] = input;
            assert_eq!(
                str_number(&mut cursor, i64::MAX),
                Err(StrError::NoNum),
                "input {input:?}"
            );
            assert_eq!(cursor, input, "a refusal must not move the cursor");
        }
    }

    /// There is no `0x` prefix: the `0` parses and the `x` is left behind.
    ///
    /// A successful parse of zero rather than an error, which is what lets a
    /// caller look at what follows and decide for itself.
    #[test]
    fn number_does_not_understand_an_0x_prefix() {
        let mut cursor: &[u8] = b"0x10";
        assert_eq!(str_number(&mut cursor, i64::MAX), Ok(0));
        assert_eq!(cursor, b"x10", "the cursor stops at the x");
    }

    /// Hexadecimal accepts both letter cases and no prefix.
    #[test]
    fn hex_accepts_both_cases_and_refuses_a_non_digit() {
        let mut cursor: &[u8] = b"ff";
        assert_eq!(str_hex(&mut cursor, i64::MAX), Ok(255));
        assert!(cursor.is_empty());

        let mut cursor: &[u8] = b"FF";
        assert_eq!(str_hex(&mut cursor, i64::MAX), Ok(255));

        let mut cursor: &[u8] = b"aBcDeF;rest";
        assert_eq!(str_hex(&mut cursor, i64::MAX), Ok(0x00ab_cdef));
        assert_eq!(cursor, b";rest");

        let mut cursor: &[u8] = b"g";
        assert_eq!(str_hex(&mut cursor, i64::MAX), Err(StrError::NoNum));
        assert_eq!(cursor, b"g");
    }

    /// Octal stops at `7`, so `8` and `9` are not digits of this base.
    #[test]
    fn octal_admits_only_the_eight_octal_digits() {
        let mut cursor: &[u8] = b"777";
        assert_eq!(str_octal(&mut cursor, i64::MAX), Ok(511));
        assert!(cursor.is_empty());

        let mut cursor: &[u8] = b"8";
        assert_eq!(str_octal(&mut cursor, i64::MAX), Err(StrError::NoNum));
        assert_eq!(cursor, b"8");

        // `9` ends the number rather than joining it.
        let mut cursor: &[u8] = b"179";
        assert_eq!(str_octal(&mut cursor, i64::MAX), Ok(0o17));
        assert_eq!(cursor, b"9");

        // Upper-case hexadecimal letters are above `7`, so the bound alone
        // refuses them in this base and in base ten.
        let mut cursor: &[u8] = b"A";
        assert_eq!(str_octal(&mut cursor, i64::MAX), Err(StrError::NoNum));
        let mut cursor: &[u8] = b"A";
        assert_eq!(str_number(&mut cursor, i64::MAX), Err(StrError::NoNum));
    }

    /// The low-`max` overflow arm, where the product is tested after the
    /// multiplication.
    ///
    /// `max` below the base selects the arm. A single digit larger than `max`
    /// is rejected, one equal to it is accepted, and the cursor does not
    /// move on the rejection.
    #[test]
    fn the_low_max_overflow_arm_tests_after_multiplying() {
        // Selected because 5 < 10.
        let mut cursor: &[u8] = b"9";
        assert_eq!(str_number(&mut cursor, 5), Err(StrError::Overflow));
        assert_eq!(cursor, b"9");

        let mut cursor: &[u8] = b"5";
        assert_eq!(str_number(&mut cursor, 5), Ok(5), "max is inclusive");

        // Two digits overflow even when each fits.
        let mut cursor: &[u8] = b"11";
        assert_eq!(str_number(&mut cursor, 5), Err(StrError::Overflow));
        assert_eq!(cursor, b"11");

        // The arm is reachable in every base: 5 < 8 and 5 < 16 too.
        let mut cursor: &[u8] = b"7";
        assert_eq!(str_octal(&mut cursor, 5), Err(StrError::Overflow));
        let mut cursor: &[u8] = b"f";
        assert_eq!(str_hex(&mut cursor, 5), Err(StrError::Overflow));

        // `max == 0` admits exactly one value, and that value is zero.
        let mut cursor: &[u8] = b"0";
        assert_eq!(str_number(&mut cursor, 0), Ok(0));
        let mut cursor: &[u8] = b"1";
        assert_eq!(str_number(&mut cursor, 0), Err(StrError::Overflow));
    }

    /// The general overflow arm, where the test precedes the multiplication.
    ///
    /// Twenty digits cannot fit in an `i64` whatever they are, so the pre-test
    /// has to catch it -- and it has to catch it without the multiplication
    /// happening first, which in a debug build would abort the test run rather
    /// than fail it.
    #[test]
    fn the_general_overflow_arm_tests_before_multiplying() {
        let mut cursor: &[u8] = b"99999999999999999999";
        assert_eq!(str_number(&mut cursor, i64::MAX), Err(StrError::Overflow));
        assert_eq!(cursor, b"99999999999999999999");

        // The largest value that does fit, digit for digit.
        let mut cursor: &[u8] = b"9223372036854775807";
        assert_eq!(str_number(&mut cursor, i64::MAX), Ok(i64::MAX));
        assert!(cursor.is_empty());

        // One more than that overflows.
        let mut cursor: &[u8] = b"9223372036854775808";
        assert_eq!(str_number(&mut cursor, i64::MAX), Err(StrError::Overflow));

        // The arm is also selected by any `max` at or above the base, so a
        // bound of exactly the base exercises it at its own boundary.
        let mut cursor: &[u8] = b"10";
        assert_eq!(str_number(&mut cursor, 10), Ok(10));
        let mut cursor: &[u8] = b"11";
        assert_eq!(str_number(&mut cursor, 10), Err(StrError::Overflow));

        // And in the other two bases, at their own widest values.
        let mut cursor: &[u8] = b"7777777777777777777777";
        assert_eq!(str_octal(&mut cursor, i64::MAX), Err(StrError::Overflow));
        let mut cursor: &[u8] = b"7fffffffffffffff";
        assert_eq!(str_hex(&mut cursor, i64::MAX), Ok(i64::MAX));
        let mut cursor: &[u8] = b"8000000000000000";
        assert_eq!(str_hex(&mut cursor, i64::MAX), Err(StrError::Overflow));
    }

    /// The blank-skipping variant skips spaces and tabs, and nothing else.
    #[test]
    fn numblanks_skips_blanks_before_the_number() {
        let mut cursor: &[u8] = b" \t 42!";
        assert_eq!(str_numblanks(&mut cursor), Ok(42));
        assert_eq!(cursor, b"!");

        // A line ending is not a blank, so it is not skipped and the parse
        // fails on it.
        let mut cursor: &[u8] = b"\r\n42";
        assert_eq!(str_numblanks(&mut cursor), Err(StrError::NoNum));
        assert_eq!(cursor, b"\r\n42");
    }

    /// The blanks are consumed even when the number then fails.
    ///
    /// The one failure in this module that leaves the cursor moved, asserted so
    /// that a caller cannot be surprised by it. `str_passblanks` runs first and
    /// unconditionally, exactly as the C's two-line body does.
    #[test]
    fn numblanks_consumes_the_blanks_even_when_no_number_follows() {
        let mut cursor: &[u8] = b"   x";
        assert_eq!(str_numblanks(&mut cursor), Err(StrError::NoNum));
        assert_eq!(cursor, b"x", "the three spaces were consumed");
    }

    /// The unbounded maximum is the C's `CURL_OFF_T_MAX`.
    ///
    /// `lib/curl_setup.h:599` defines it as `0x7FFFFFFFFFFFFFFF` on a 64-bit
    /// target, and all four targets of this work are 64-bit. Transcribed here
    /// as a literal and compared, so that the equivalence [`str_numblanks`]
    /// relies on is asserted rather than assumed.
    #[test]
    fn the_unbounded_maximum_is_curl_off_t_max() {
        let curl_off_t_max: i64 = 0x7fff_ffff_ffff_ffff;
        assert_eq!(i64::MAX, curl_off_t_max);

        // And the parser really does reach it through the unbounded entry
        // point, which is the property the constant exists for.
        let mut cursor: &[u8] = b"9223372036854775807";
        assert_eq!(str_numblanks(&mut cursor), Ok(curl_off_t_max));
    }

    /// A zero byte ends a number exactly as the end of the input does.
    #[test]
    fn a_number_stops_at_an_embedded_zero() {
        let input: [u8; 5] = [b'4', b'2', 0, b'7', b'7'];
        let mut cursor: &[u8] = &input;
        assert_eq!(str_number(&mut cursor, i64::MAX), Ok(42));
        assert_eq!(cursor.first(), Some(&0));

        // And a leading zero byte is no number at all.
        let leading: [u8; 2] = [0, b'4'];
        let mut cursor: &[u8] = &leading;
        assert_eq!(str_number(&mut cursor, i64::MAX), Err(StrError::NoNum));
        assert_eq!(cursor, &leading[..]);
    }

    // -----------------------------------------------------------------------
    // The comparators. `:236-254`.
    // -----------------------------------------------------------------------

    /// Case folding applies to the twenty-six ASCII letter pairs and to nothing
    /// else.
    ///
    /// The negative half is the point. The two bytes 0xc3 0xa9 and 0xc3 0x89
    /// are the UTF-8 encodings of a letter in its two cases, and curl's fold
    /// does NOT relate them -- which is what makes the comparison
    /// locale-independent and what a Unicode-aware comparison would break.
    #[test]
    fn casecompare_folds_ascii_letters_and_no_other_byte() {
        assert!(str_casecompare(b"chunked", b"CHUNKED"));
        assert!(str_casecompare(b"ChUnKeD", b"cHuNkEd"));
        assert!(str_casecompare(b"", b""));

        assert!(!str_casecompare(b"chunked", b"chunk"));
        assert!(!str_casecompare(b"chunk", b"chunked"));
        assert!(!str_casecompare(b"gzip", b"gzi_"));

        // High bytes are compared, never folded.
        let lower: [u8; 2] = [0xc3, 0xa9];
        let upper: [u8; 2] = [0xc3, 0x89];
        assert!(str_casecompare(&lower, &lower));
        assert!(
            !str_casecompare(&lower, &upper),
            "curl folds ASCII letters only"
        );
    }

    /// The byte comparator is case-sensitive.
    #[test]
    fn cmp_is_case_sensitive() {
        assert!(str_cmp(b"chunked", b"chunked"));
        assert!(!str_cmp(b"chunked", b"CHUNKED"));
        assert!(!str_cmp(b"chunked", b"chunke"));
        assert!(str_cmp(b"", b""));
        assert!(!str_cmp(b"a", b""));
        assert!(!str_cmp(b"", b"a"));
    }

    /// Both comparators return true for a MATCH, which inverts the C's usual
    /// convention.
    ///
    /// Asserted rather than only documented, because the inversion is the one
    /// thing about these two functions that a reader diffing against
    /// `lib/curlx/strparse.c` will get backwards: everything else in that file
    /// returns non-zero for an error.
    #[test]
    fn the_comparators_report_true_on_a_match_not_on_a_failure() {
        assert!(str_cmp(b"same", b"same"), "true means matched");
        assert!(!str_cmp(b"same", b"other"), "false means did not match");

        assert!(str_casecompare(b"same", b"SAME"), "true means matched");
        assert!(
            !str_casecompare(b"same", b"other"),
            "false means did not match"
        );
    }

    /// An empty comparand matches an empty span, which is where the C's null
    /// arm and an empty slice part company.
    ///
    /// For [`str_casecompare`] the two agree: a null comparand gives the C a
    /// zero length, and a zero-length comparison succeeds exactly on an empty
    /// span. For [`str_cmp`] they are opposites -- the C's null arm answers
    /// `!!len`, so it matches a NON-empty span -- and a caller that needs that
    /// meaning writes `!span.is_empty()` at the call site.
    #[test]
    fn an_empty_comparand_matches_only_an_empty_span() {
        assert!(str_cmp(b"", b""));
        assert!(!str_cmp(b"something", b""));

        assert!(str_casecompare(b"", b""));
        assert!(!str_casecompare(b"something", b""));

        // The C's null arm, spelled at the call site as it must be.
        let span: &[u8] = b"something";
        assert!(!span.is_empty(), "the C's null comparand answers this");
    }

    // -----------------------------------------------------------------------
    // The text helper, and one end-to-end walk.
    // -----------------------------------------------------------------------

    /// Text conversion succeeds for text and refuses everything else.
    #[test]
    fn as_str_refuses_bytes_that_are_not_text() {
        assert_eq!(as_str(b"token"), Some("token"));
        assert_eq!(as_str(b""), Some(""));

        // A lone continuation byte is not a valid sequence.
        let malformed: [u8; 2] = [0xc3, 0x28];
        assert_eq!(as_str(&malformed), None);
    }

    /// One realistic walk, exercising the pieces together.
    ///
    /// A header value of the shape the C parses with these functions:
    /// `max-age=3600, includeSubDomains`. It alternates extraction, single-byte
    /// consumption, blank skipping and number parsing, which is the pattern
    /// every caller of this module follows, and it ends with the cursor
    /// empty -- the property that proves no step lost or double-counted a
    /// byte.
    #[test]
    fn the_pieces_compose_into_a_header_value_parse() {
        let mut cursor: &[u8] = b"max-age=3600, includeSubDomains";

        let name = str_cspn(&mut cursor, b"=,");
        assert_eq!(name, Ok(&b"max-age"[..]));
        assert!(str_casecompare(b"MAX-AGE", name.unwrap_or(b"")));

        assert_eq!(str_single(&mut cursor, b'='), Ok(()));
        assert_eq!(str_number(&mut cursor, i64::MAX), Ok(3600));

        assert_eq!(str_single(&mut cursor, b','), Ok(()));
        str_passblanks(&mut cursor);

        let flag = str_until(&mut cursor, 32, b',');
        assert_eq!(flag, Ok(&b"includeSubDomains"[..]));
        assert!(cursor.is_empty(), "every byte was accounted for");
    }
}
