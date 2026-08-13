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

// THE CONVENTIONS OF THIS DIRECTORY, APPLIED HERE.
//
// 2. `mod source_policy` in `curl-rs-lib/src/lib.rs` enforces that as an
//    executable gate, and the reason is that a root attribute would silence
//    the NEXT item somebody adds. Two items here carry one, each naming the C
//    call site that will remove it.
//
// 3. No level for the `unsafe_code` lint is set here, at any level. The crate
//    root carries `#![deny(unsafe_code)]` and grants exactly one exemption, on
//    `mod ffi`; this file is not it, needs nothing the compiler would want one
//    for, and contains no such attribute. That matters here because the C
//    original is pointer arithmetic throughout: `curl_easy_escape` walks a
//    `const char *` under a caller-supplied count, and `Curl_urldecode` reads
//    `string[1]` and `string[2]` behind a bounds test the compiler never sees.
//    Slice patterns replace both, so the bound is structural rather than
//    asserted -- see [`decode_step`].
//
// 4. No raw string literal appears below. `code_only` in `mod source_policy`
//    does not lex `r"..."`, and a raw string introduced under `curl-rs-lib/src`
//    fails that gate rather than silently costing the `unsafe` scan its
//    coverage.
//
// 5. Documentation on a `pub` item -- the module comment below, `escape` and
//    `unescape` -- names every item that is NOT `pub` in plain code spelling
//    rather than as an intra-doc link. Two measured reasons, and the second is
//    the one that is easy to miss.

//! Percent-encoding and percent-decoding -- supersedes `lib/escape.c` and
//! `lib/escape.h`.
//!
//! # This module is ABI, not an implementation detail
//!
//! Four of the 100 symbols `lib/libcurl.def` exports are backed from here, and
//! the tables below are therefore a contract rather than a style choice:
//!
//! | Exported symbol | C definition | Rust route |
//! |---|---|---|
//! | `curl_easy_escape` | `lib/escape.c:50-87` | [`escape`] |
//! | `curl_easy_unescape` | `lib/escape.c:163-184` | [`unescape`] |
//! | `curl_escape` | `lib/escape.c:36-39` | [`escape`], forwarded |
//! | `curl_unescape` | `lib/escape.c:42-45` | [`unescape`], forwarded |
//!
//! The last two are, in the C's own words at `lib/escape.c:35` and `:41`,
//! there "for ABI-compatibility with previous versions": each is a single call
//! into its `curl_easy_` counterpart with a null handle.
//!
//! # The handle parameter is ignored, and has been since 7.82.0
//!
//! All four exported functions accept a `CURL *` and use it for nothing.
//! `lib/escape.c:48` says so in a comment, `:54` and `:166` discard it with
//! `(void)data;`, and `docs/libcurl/curl_easy_escape.md:84-86` records the
//! release: "Since 7.82.0, the **curl** parameter is ignored." The engine
//! functions here therefore take no handle at all. The parameter exists only in
//! the shim's signature, where the frozen header fixes it.
//!
//! # The `(pointer, int)` marshalling belongs to `curl-rs-ffi`, not here
//!
//! `lib/escape.c:59` resolves the byte count as
//!
//! ```text
//! length = (inlength ? (size_t)inlength : strlen(string))
//! ```
//!
//! so a zero length means "measure it" and any other value is trusted
//! **absolutely**: the C reads that many bytes whether or not a NUL appears
//! first. Both halves are observable, and both are pinned by the oracle:
//!
//! ```text
//! curl_easy_escape(NULL, "",   1)  ->  "%00"      /* reads the terminator */
//! curl_easy_escape(NULL, "a",  2)  ->  "a%00"     /* same, one byte further */
//! ```
//!
//! That second row is `tests/unit/unit1396.c:79`. "Read `n` bytes from a
//! pointer" is what `core::slice::from_raw_parts` expresses and what this crate
//! may not write, and the obligation being discharged is the *caller's* promise
//! about the object it passed -- something only the C boundary is in a position
//! to state. So the shim resolves the length, forms the slice under one
//! `// SAFETY:` comment, and this module receives a slice whose bounds are
//! already someone else's guarantee. Two consequences follow, and they are the
//! reason the argument checks of `lib/escape.c:56` and `:167` are absent below:
//! a `&[u8]` can be neither null nor negatively long, so a null string and a
//! negative length are rejected before this module is reached.
//!
//! # Why the decoded length is the return value's own
//!
//! `lib/escape.c:151` reports the output size as `ns - *ostring`, a pointer
//! difference, so an embedded NUL is counted rather than terminating the count.
//! [`unescape`] therefore returns a `Vec<u8>` whose `len` carries that number:
//! no `CString`, and no truncation at the first zero. `unescape(b"a%00b")` is
//! three bytes long with a NUL in the middle, which is exactly why
//! `docs/libcurl/curl_easy_unescape.md:39-41` gives the C an out-parameter and
//! says it "allows proper handling even for strings containing %00".
//!
//! The `int` ceiling on that out-parameter is a C-signature artefact, and
//! `lib/escape.c:175-181` handles it in a way worth spelling out because it
//! looks like a bug and is not: when the length exceeds `INT_MAX` the C calls
//! `Curl_safefree(str)`, which frees the buffer *and nulls the variable*, then
//! falls through and returns the now-null pointer -- leaving `*olen`
//! **unwritten**. So a too-large result is a null return with the caller's
//! variable untouched, and `curl_unescape` (`lib/escape.c:42-45`) passes
//! `olen = NULL`, so the ceiling cannot apply to it at all. That asymmetry is
//! observable. The engine implements the length test as
//! `output_len_fits_int` so the answer is available and separately testable;
//! the conversion itself belongs to `curl-rs-ffi`, which owns the `int`.

use crate::error::CURLcode;
use crate::util::fallible;
use crate::util::strparse;

/// The uppercase hex alphabet: `Curl_udigits` at `lib/mprintf.c:39`.
///
/// Named for the C table it stands in for so that the choice of case is
/// traceable rather than looking free. Its lowercase twin is [`LDIGITS`], and
/// the two are used by different functions on purpose -- see the module
/// documentation.
const UDIGITS: [u8; 16] = *b"0123456789ABCDEF";

/// The lowercase hex alphabet: `Curl_ldigits` at `lib/mprintf.c:36`.
///
/// Indexed only by [`hexencode`], which `lib/escape.c:197-198` documents as
/// converting "binary input to lowercase hex-encoded ASCII output". This is not
/// percent-encoding and must not be confused with it: [`escape`] never reaches
/// this table.
const LDIGITS: [u8; 16] = *b"0123456789abcdef";

/// The largest input length `curl_easy_escape` accepts: `SIZE_MAX / 16`.
///
/// `lib/escape.c:63-64` refuses anything longer, returning null. The guard's
/// job is arithmetic rather than policy: the next statement asks for
/// `length * 3 + 1` bytes, and dividing by 16 rather than by 3 leaves the
/// product comfortably clear of wrapping `size_t`.
///
/// It is worth recording what this bound is **not**, because the obvious
/// dismissal is wrong in the arithmetic, and the figures are given so the
/// reader can check rather than take it on trust. A slice's length is capped at
/// `isize::MAX`, which is `usize::MAX / 2` rounded down -- 9223372036854775807,
/// exactly **eight times above** `usize::MAX / 16`, which is
/// 1152921504606846975. So the condition is perfectly representable for a
/// `&[u8]`, and the guard is reproduced rather than argued away;
/// [`escape_capacity`] is that reproduction, and a test drives it from both
/// sides without allocating anything.
///
/// What is genuinely unreachable is the C's null return, and through a
/// different route: `curl_easy_escape` takes its length as an `int`, so no
/// caller crossing the ABI can name a figure above `INT_MAX`, and this bound is
/// 536870912 times larger than that -- a factor of two to the twenty-ninth.
const MAX_ESCAPE_INPUT: usize = usize::MAX / 16;

// The correction above, pinned at compile time rather than asserted in a test,
// because it is a claim about two constants and nothing at run time can change
// it. This is the crate's idiom for a value contract -- `src/crypto/mod.rs`
// uses the same form for the digest lengths it fixes.
const _: () = assert!(MAX_ESCAPE_INPUT < usize::MAX / 2);
const _: () = assert!(MAX_ESCAPE_INPUT < usize::MAX / 3);

/// The output limit `lib/escape.c:66` gives the encode buffer, or [`None`] when
/// the input is longer than [`MAX_ESCAPE_INPUT`].
const fn escape_capacity(len: usize) -> Option<usize> {
    if len > MAX_ESCAPE_INPUT {
        return None;
    }
    match len.checked_mul(3) {
        Some(tripled) => tripled.checked_add(1),
        None => None,
    }
}

/// Which decoded bytes a percent-decode refuses.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum UrlReject {
    /// `REJECT_NADA` (2): accept every decoded byte.
    ///
    /// The mode `curl_easy_unescape` passes (`lib/escape.c:170-171`), and the
    /// reason its result is a byte string rather than a C string.
    Nada,

    /// `REJECT_CTRL` (3): refuse any decoded byte below 0x20.
    ///
    /// Note the bound: 0x7F, the delete character, is a control character by
    /// every other definition -- `ISCNTRL` at `lib/curl_ctype.h:37` includes
    /// it -- and passes this test, because `lib/escape.c:139` compares against
    /// 0x20 and nothing else.
    #[allow(dead_code)]
    Ctrl,

    /// `REJECT_ZERO` (4): refuse a decoded NUL, and nothing else.
    ///
    /// A tab or a line feed passes. `lib/escape.c:140` tests `in == 0` alone.
    #[allow(dead_code)]
    Zero,
}

impl UrlReject {
    /// Whether this mode refuses `decoded`.
    ///
    /// The whole of `lib/escape.c:139-143`, minus the buffer release that has
    /// no counterpart when the buffer is a `Vec`:
    ///
    /// ```c
    /// if(((ctrl == REJECT_CTRL) && (in < 0x20)) ||
    ///    ((ctrl == REJECT_ZERO) && (in == 0))) {
    /// ```
    pub(crate) const fn refuses(self, decoded: u8) -> bool {
        match self {
            Self::Nada => false,
            Self::Ctrl => decoded < 0x20,
            Self::Zero => decoded == 0,
        }
    }
}

/// Percent-encodes `input`, reproducing `curl_easy_escape`.
///
/// Supersedes `lib/escape.c:50-87`. Every byte is either copied verbatim,
/// when `crate::util::strparse::is_unreserved` accepts it, or replaced by `%`
/// and two **uppercase** hex digits. The result is always ASCII and can never
/// contain a NUL, which is what makes `curl_easy_escape`'s bare `char *`
/// return sufficient where `curl_easy_unescape` needs an explicit length.
///
/// `input` is the already-resolved byte range: this function has no view of a
/// terminator and applies no length convention of its own. The module
/// documentation explains why that resolution belongs to the caller, and why
/// the C's null-pointer and negative-length checks (`lib/escape.c:56`) cannot
/// be expressed against a `&[u8]`.
///
/// An empty `input` yields an empty `Vec` rather than a failure, matching
/// `lib/escape.c:60-61`, which returns a duplicate of the empty string and not
/// null. The distinction reaches the application -- one is a pointer it must
/// release, the other is an error -- so it is preserved deliberately, and
/// `tests/unit/unit1605.c` is the C test that pins it.
///
/// # The C's three failure paths, and where each one lives
///
/// `lib/escape.c` can return null from this function for three reasons.
/// The argument checks at `:56` belong to the shim, which owns the pointer and
/// the `int`. The out-of-memory arms at `:75` and `:82` are
/// [`CURLcode::OutOfMemory`] here: the output buffer is **three times a length
/// the caller chose**, which is the largest single amplification in this crate
/// -- a 700 MB string asks for 2.1 GB -- so it is allocated through
/// [`crate::util::fallible`] and a refusal is reported rather than aborting the
/// process. The length guard at `:63-64` is reproduced as `escape_capacity`,
/// which declines to name a buffer size instead of declining to encode -- the
/// C's null return there is unreachable across the ABI, because the length
/// arrives as an `int`, and `MAX_ESCAPE_INPUT` records the arithmetic.
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`], and nothing else. `curl_easy_escape` turns it
/// back into the null pointer the C returns.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::url::escape::escape;
///
/// assert_eq!(escape(b"a b~c"), Ok(b"a%20b~c".to_vec()));
/// // Uppercase hex, and no byte at or above 0x80 is ever unreserved.
/// assert_eq!(escape(b"\xc3\xa9"), Ok(b"%C3%A9".to_vec()));
/// // An interior NUL is escaped like any other reserved byte.
/// assert_eq!(escape(b"a\0b"), Ok(b"a%00b".to_vec()));
/// // Sub-delimiters are NOT unreserved, whatever RFC 3986 calls them.
/// assert_eq!(escape(b"a=b&c"), Ok(b"a%3Db%26c".to_vec()));
/// ```
pub fn escape(input: &[u8]) -> Result<Vec<u8>, CURLcode> {
    // The C's `length * 3 + 1` when the guard admits the input, and the input
    // length when it does not -- a figure that is always allocatable, because
    // the input already exists.
    let capacity = escape_capacity(input.len()).unwrap_or(input.len());
    let mut out: Vec<u8> =
        fallible::vec_with_capacity(capacity).map_err(fallible::oom)?;

    for &byte in input {
        // `lib/escape.c:70` casts to `unsigned char` before testing, so the
        // comparison is over 0..=255 and never over a sign-extended `char`.
        // A `u8` is that type already, which removes the cast rather than
        // reproducing it.
        if strparse::is_unreserved(byte) {
            out.push(byte);
        } else {
            // `lib/escape.c:79-81`: a three-byte group whose first byte is
            // fixed and whose remaining two come from `Curl_hexbyte`.
            out.push(b'%');
            out.extend_from_slice(&hexbyte(byte));
        }
    }

    Ok(out)
}

/// One iteration of the C's decode walk: the next decoded byte, and the input
/// that remains after it.
///
/// # The `alloc > 2` rule is structural here, not arithmetic
///
/// The C reads two bytes of lookahead behind a counter test:
///
/// ```c
/// if(('%' == in) && (alloc > 2) && ISXDIGIT(string[1]) && ISXDIGIT(string[2]))
/// ```
fn decode_step(rest: &[u8]) -> Option<(u8, &[u8])> {
    let (&byte, tail) = rest.split_first()?;

    if byte == b'%' {
        if let [high, low, after @ ..] = tail {
            if let (Some(high), Some(low)) =
                (strparse::hexval(*high), strparse::hexval(*low))
            {
                // `(hexval(string[1]) << 4) | hexval(string[2])`. Both values
                // are 0..=15, so the shift cannot overflow a `u8` and the
                // disjunction covers the full byte.
                return Some(((high << 4) | low, after));
            }
        }
    }

    Some((byte, tail))
}

/// Percent-decodes `input` under an explicit rejection mode.
///
/// # Length
///
/// ```text
/// urldecode(b"a%00b", UrlReject::Nada)  ->  Ok([0x61, 0x00, 0x62])   len 3
/// urldecode(b"a%00b", UrlReject::Zero)  ->  Err(CURLE_URL_MALFORMAT)
/// urldecode(b"\n",    UrlReject::Ctrl)  ->  Err(CURLE_URL_MALFORMAT)
/// ```
// The strict modes have no in-crate caller yet.
pub(crate) fn urldecode(
    input: &[u8],
    reject: UrlReject,
) -> Result<Vec<u8>, CURLcode> {
    // An exact upper bound: the result is never longer than the input, and is
    // shorter by two bytes for every escape decoded. The C asks for
    // `alloc + 1` at `:116`, the extra byte being the terminator it writes at
    // `:147` and this `Vec` does not store.
    // Fallible: the bound is the caller's own input length, and the C's
    // `curlx_malloc` failing at `:117-118` is `CURLE_OUT_OF_MEMORY`.
    let mut out: Vec<u8> =
        fallible::vec_with_capacity(input.len()).map_err(fallible::oom)?;
    let mut rest = input;

    while let Some((byte, tail)) = decode_step(rest) {
        if reject.refuses(byte) {
            return Err(CURLcode::UrlMalformat);
        }
        // Cannot grow past the capacity reserved above, so this cannot fail;
        // it is spelled fallibly anyway so that the property is enforced by
        // the type rather than by this comment.
        fallible::push(&mut out, byte).map_err(fallible::oom)?;
        rest = tail;
    }

    Ok(out)
}

/// Percent-decodes `input`, reproducing `curl_easy_unescape`.
///
/// # Total, because `REJECT_NADA` refuses nothing
///
/// `lib/escape.c:170-171` calls `Curl_urldecode` with `REJECT_NADA`, and this
/// function calls `urldecode` the same way so that the call graph matches the
/// C's. `UrlReject::Nada.refuses(_)` answers `false` for every one of the 256
/// byte values -- asserted below over all of them, not argued -- so the only
/// arm of that `Result` this call can reach is `Ok`. `unwrap_or_default` states
/// that without a panicking path: it cannot unwind towards a C caller, and the
/// value it would substitute is the same empty vector an empty input yields.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::url::escape::unescape;
///
/// assert_eq!(unescape(b"%41%42%43"), Ok(b"ABC".to_vec()));
/// // Either hex case decodes.
/// assert_eq!(unescape(b"%4a%4B"), Ok(b"JK".to_vec()));
/// // A '%' that does not introduce two hex digits stands for itself.
/// assert_eq!(unescape(b"abc%4G"), Ok(b"abc%4G".to_vec()));
/// // Two remaining bytes are not MORE than two: tests/unit/unit1396.c:60.
/// assert_eq!(unescape(b"%6"), Ok(b"%6".to_vec()));
/// // '+' is not a space: this is URL escaping, not form encoding.
/// assert_eq!(unescape(b"a+b"), Ok(b"a+b".to_vec()));
/// // NUL survives, which is why the length is the return value's own.
/// assert_eq!(unescape(b"a%00b"), Ok(vec![b'a', 0, b'b']));
/// ```
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`] for a refused output buffer -- the C's
/// `:117-118`. [`UrlReject::Nada`] admits every byte, so no other code is
/// reachable through this entry point.
pub fn unescape(input: &[u8]) -> Result<Vec<u8>, CURLcode> {
    urldecode(input, UrlReject::Nada)
}

/// Renders one byte as two **uppercase** hex digits.
///
/// ```c
/// dest[0] = Curl_udigits[val >> 4];
/// dest[1] = Curl_udigits[val & 0x0F];
/// ```
///
/// ```text
/// hexbyte(0x2f)  ->  b"2F"      hexbyte(0xff)  ->  b"FF"
/// ```
#[must_use]
pub(crate) fn hexbyte(value: u8) -> [u8; 2] {
    [
        UDIGITS[usize::from(value >> 4)],
        UDIGITS[usize::from(value & 0x0F)],
    ]
}

/// Renders bytes as **lowercase** hex ASCII, with no separators and no prefix.
///
/// # Two C parameters are deliberately dropped
///
/// The C signature is
/// `Curl_hexencode(const unsigned char *src, size_t len, unsigned char *out,
/// size_t olen)`, and its contract has three parts that an owned `String`
/// removes rather than reproduces. It requires `olen >= 3` and writes a lone
/// terminator instead of encoding when that fails (`:203-204`, `:214-215`); it
/// writes two bytes per input byte only "while `olen >= 3`", so it
/// **self-truncates** rather than overflowing (`:205`); and it always
/// NUL-terminates (`:212`). All three exist to make a caller-supplied buffer
/// safe. A value that owns its own storage is exactly as long as it needs to
/// be, so there is no buffer to size, nothing to truncate against and no
/// terminator to write -- which is why this function is infallible and takes
/// only the input.
///
/// # Why the nibble loop is written out rather than delegated
///
/// ```text
/// hexencode(&[0x2f])                    ->  "2f"       /* not "2F" */
/// hexencode(&[0xde, 0xad, 0xbe, 0xef])  ->  "deadbeef"
/// ```
// The measured C call sites are `lib/http_aws_sigv4.c:67` (arriving with
// `auth/aws_sigv4.rs`), `lib/doh.c:199` (`dns/doh.rs`, whose include at
// `lib/doh.c:38` is commented "for Curl_hexencode()") and `lib/rand.c:249`
// (`crypto/rand.rs`). The digest path reaches `crate::crypto::hex_lower`
// instead, which landed with `src/crypto/` and renders the same bytes the same
// way; that one is the digest layer's, this one is the transformation
// `lib/escape.h:39-40` declares here.
#[allow(dead_code)]
#[must_use]
pub(crate) fn hexencode(src: &[u8]) -> String {
    // Two output bytes per input byte. `saturating_mul` cannot saturate for a
    // real slice -- a length is capped at `isize::MAX`, so twice it still fits
    // a `usize` -- and is written rather than `*` so that no arithmetic here
    // behaves differently between the debug and release profiles.
    //
    // NOT routed through `crate::util::fallible`, deliberately: every caller of
    // this function hands it a FIXED-SIZE input -- a 32-byte SHA-256 digest in
    // `crate::auth::aws_sigv4`, a 16- or 32-byte secret in `lib/vtls/keylog.c`,
    // a two-byte zone identifier in `lib/urlapi.c` -- so the 64 bytes it asks
    // for are not a figure any caller chose. Sizing failing there means the
    // process could not obtain 64 bytes, which no error code makes recoverable.
    let mut out = String::with_capacity(src.len().saturating_mul(2));

    for &byte in src {
        // `out[0] = Curl_ldigits[*src >> 4]; out[1] = Curl_ldigits[*src &
        // 0x0F];` -- `lib/escape.c:206-207`. Both indices are masked into
        // 0..=15. `char::from` widens a byte to the code point of the same
        // value and cannot fail, and every digit here is ASCII, so the string
        // stays one byte per digit.
        out.push(char::from(LDIGITS[usize::from(byte >> 4)]));
        out.push(char::from(LDIGITS[usize::from(byte & 0x0F)]));
    }

    out
}

/// Whether a decoded length can be reported through `curl_easy_unescape`'s
/// `int` out-parameter.
///
/// # Where the rest of that behaviour lives, and why
///
/// The C does something specific when the answer is `false`, and it is not a
/// truncation: `Curl_safefree(str)` releases the buffer **and nulls the
/// variable**, and the function then falls through to `return str`, so the
/// caller receives null and its own `*olen` is left **unwritten**. Reproducing
/// that needs the pointer and the `int`, so it belongs to
/// `curl-rs-ffi/src/ffi/`, which owns both. This predicate is the part that
/// does not: it is the test itself, available to that shim and testable here
/// without a C type in sight.
#[allow(dead_code)]
#[must_use]
pub(crate) const fn output_len_fits_int(len: usize) -> bool {
    // A WIDENING cast, and the only one in this file: `usize` is at least 32
    // bits on every target Rust supports, so `i32::MAX` always fits and no
    // value is lost. `usize::try_from` would say the same thing without a cast
    // but is not `const` on the 1.75 floor, and this has to be usable in a
    // constant so that a caller can pin a bound at compile time.
    len <= i32::MAX as usize
}

#[cfg(test)]
mod tests {
    use super::{
        escape, escape_capacity, hexbyte, hexencode, output_len_fits_int,
        unescape, urldecode, UrlReject, LDIGITS, MAX_ESCAPE_INPUT, UDIGITS,
    };
    use crate::error::CURLcode;
    use crate::util::strparse;

    /// [`escape`] for a test input, which is always small enough to allocate.
    ///
    /// The real function reports [`CURLcode::OutOfMemory`] because its output is
    /// three times a caller-chosen length; every input in this module is a
    /// literal of a few bytes, so unwrapping states that rather than hiding it.
    /// The refusal itself is covered by `crate::util::fallible`'s own tests and
    /// by `an_escape_of_an_unservable_length_reports_out_of_memory` below.
    fn esc(input: &[u8]) -> Vec<u8> {
        escape(input).expect("a test-sized input is allocatable")
    }

    /// [`unescape`], for the same reason.
    fn unesc(input: &[u8]) -> Vec<u8> {
        unescape(input).expect("a test-sized input is allocatable")
    }

    /// The differential capture described in the module documentation.
    const ORACLE: &str = include_str!("escape_oracle.txt");

    /// A field that is present, or [`None`] for the placeholder `-`.
    fn optional(field: &str) -> Option<&str> {
        if field == "-" {
            None
        } else {
            Some(field)
        }
    }

    /// Decodes one hex field of the oracle into bytes.
    fn from_hex(field: &str) -> Vec<u8> {
        assert!(
            field.len() % 2 == 0,
            "oracle hex field has an odd length: {field:?}"
        );
        (0..field.len())
            .step_by(2)
            .map(|at| {
                u8::from_str_radix(&field[at..at + 2], 16)
                    .unwrap_or_else(|e| panic!("bad oracle hex {field:?}: {e}"))
            })
            .collect()
    }

    /// What the C produced, in the three shapes a row can report.
    #[derive(Debug, Eq, PartialEq)]
    enum Outcome {
        /// The C returned a buffer, whose bytes these are. An empty vector is a
        /// successful empty result, which is not the same thing as
        /// [`Self::Null`].
        Bytes(Vec<u8>),
        /// The C returned a null pointer.
        Null,
        /// `Curl_urldecode` returned `CURLE_URL_MALFORMAT`.
        Malformat,
    }

    /// One parsed oracle row: `TAG NAME INPUT ARG MODE OUTPUT OLEN`.
    struct Row<'a> {
        tag: &'a str,
        name: &'a str,
        /// The input object's bytes, or [`None`] when the C pointer was null.
        object: Option<Vec<u8>>,
        /// The length argument exactly as passed, where the row has one.
        arg: Option<i32>,
        /// The `urlreject` mode as the C spells it: 2, 3 or 4.
        mode: Option<u8>,
        outcome: Outcome,
        /// The length the C reported, where the row records one.
        olen: Option<usize>,
    }

    fn rows() -> Vec<Row<'static>> {
        ORACLE
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let f: Vec<&str> = line.split(' ').collect();
                assert_eq!(f.len(), 7, "unexpected oracle row shape: {line:?}");
                Row {
                    tag: f[0],
                    name: f[1],
                    object: match f[2] {
                        "NULL" => None,
                        "-" => Some(Vec::new()),
                        hex => Some(from_hex(hex)),
                    },
                    arg: optional(f[3]).map(|a| a.parse().expect("oracle arg")),
                    mode: optional(f[4])
                        .map(|m| m.parse().expect("oracle mode")),
                    outcome: match f[5] {
                        "NULL" => Outcome::Null,
                        "MALFORMAT" => Outcome::Malformat,
                        "-" => Outcome::Bytes(Vec::new()),
                        hex => Outcome::Bytes(from_hex(hex)),
                    },
                    olen: optional(f[6])
                        .map(|o| o.parse().expect("oracle olen")),
                }
            })
            .collect()
    }

    /// Applies the C's length convention and returns the slice the engine sees.
    ///
    /// This is the marshalling `curl-rs-ffi` performs, reproduced here so the
    /// differential exercises the same composition the shipped code does.
    /// [`None`] means the C rejected the arguments before doing any work, which
    /// is the argument check rather than a transformation result.
    fn resolve(row: &Row<'_>) -> Option<Vec<u8>> {
        let object = row.object.as_ref()?;
        let arg = row.arg.expect("a length-taking row carries its argument");
        if arg < 0 {
            return None;
        }
        // `lib/escape.c:59` and `:115`: zero means "measure it", anything else
        // is taken at face value. The object carries its own terminator, so its
        // strlen is one less than its recorded length.
        let resolved = if arg == 0 {
            object.len() - 1
        } else {
            usize::try_from(arg).expect("a non-negative argument")
        };
        assert!(
            resolved <= object.len(),
            "oracle row {:?} would read outside its object; the oracle, not \
             the engine, is wrong",
            row.name
        );
        Some(object[..resolved].to_vec())
    }

    /// The mode a `DEC` row selects, translated out of the C's numbering.
    fn reject_of(row: &Row<'_>) -> UrlReject {
        match row.mode.expect("a DEC row carries its mode") {
            2 => UrlReject::Nada,
            3 => UrlReject::Ctrl,
            4 => UrlReject::Zero,
            other => panic!("row {:?} names mode {other}", row.name),
        }
    }

    #[test]
    fn the_oracle_parses_and_covers_what_it_claims() {
        let rows = rows();
        assert_eq!(rows.len(), 2629, "oracle row count changed");

        let count = |tag: &str| rows.iter().filter(|r| r.tag == tag).count();
        // 256 single-byte escapes plus 19 edge cases.
        assert_eq!(count("ESC"), 275);
        // 512 exhaustive triplets, both hex cases, plus 31 edge cases.
        assert_eq!(count("UNESC"), 543);
        assert_eq!(count("UNESCN"), 2);
        // 768 triplets across three modes, 512 literal bytes across the two
        // strict ones, plus 12 edge cases.
        assert_eq!(count("DEC"), 1292);
        assert_eq!(count("HEXB"), 256);
        assert_eq!(count("HEXE"), 261);

        // Every row that reports a length agrees with the bytes it reports,
        // which is the oracle checking itself before it is used as authority.
        for row in &rows {
            let (Some(olen), Outcome::Bytes(bytes)) = (row.olen, &row.outcome)
            else {
                continue;
            };
            assert_eq!(
                olen,
                bytes.len(),
                "oracle row {:?} disagrees with its own olen",
                row.name
            );
        }
    }

    #[test]
    fn escape_matches_the_c_oracle_on_every_row() {
        let mut checked = 0usize;
        for row in &rows() {
            if row.tag != "ESC" {
                continue;
            }
            match (resolve(row), &row.outcome) {
                // The argument check rejected the call, so there is nothing for
                // this module to have produced. `resolve` reaching `None`
                // exactly when the C returned null is itself the assertion.
                (None, Outcome::Null) => {}
                (Some(input), Outcome::Bytes(expected)) => assert_eq!(
                    &esc(&input),
                    expected,
                    "escape mismatch on row {:?} (input {input:02X?})",
                    row.name
                ),
                (resolved, expected) => panic!(
                    "row {:?}: the argument check and the C disagree \
                     (resolved={}, expected={expected:?})",
                    row.name,
                    resolved.is_some()
                ),
            }
            checked += 1;
        }
        assert_eq!(checked, 275, "escape rows checked");
    }

    #[test]
    fn unescape_matches_the_c_oracle_on_every_row() {
        let mut checked = 0usize;
        for row in &rows() {
            if row.tag != "UNESC" && row.tag != "UNESCN" {
                continue;
            }
            match (resolve(row), &row.outcome) {
                (None, Outcome::Null) => {}
                (Some(input), Outcome::Bytes(expected)) => {
                    let produced = unesc(&input);
                    // `UNESC` rows carry the length the C wrote through its
                    // out-parameter, so their output field is the whole result.
                    // `UNESCN` rows pass `olen == NULL`, so the only thing a C
                    // caller can measure is `strlen` -- and that is exactly
                    // what the oracle recorded. Comparing the NUL-truncated
                    // view for those two is therefore the precise assertion
                    // rather than a weakened one: it models what the C
                    // consumer observes. The
                    // full result is still pinned, for the same bytes, by the
                    // `UNESC` rows that decode a NUL.
                    let comparable: &[u8] = if row.tag == "UNESC" {
                        &produced
                    } else {
                        let visible = produced
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(produced.len());
                        &produced[..visible]
                    };
                    assert_eq!(
                        comparable,
                        expected.as_slice(),
                        "unescape mismatch on row {:?} (input {input:02X?})",
                        row.name
                    );
                    if let Some(olen) = row.olen {
                        assert_eq!(
                            produced.len(),
                            olen,
                            "unescape length mismatch on row {:?}",
                            row.name
                        );
                    }
                }
                (resolved, expected) => panic!(
                    "row {:?}: the argument check and the C disagree \
                     (resolved={}, expected={expected:?})",
                    row.name,
                    resolved.is_some()
                ),
            }
            checked += 1;
        }
        assert_eq!(checked, 545, "unescape rows checked");
    }

    #[test]
    fn urldecode_matches_the_c_oracle_in_all_three_modes() {
        let mut checked = 0usize;
        let mut refused = 0usize;
        for row in &rows() {
            if row.tag != "DEC" {
                continue;
            }
            let input = resolve(row).expect("no DEC row rejects its arguments");
            let produced = urldecode(&input, reject_of(row));
            match &row.outcome {
                Outcome::Bytes(expected) => {
                    let bytes = produced.as_ref().unwrap_or_else(|error| {
                        panic!(
                            "row {:?} refused {input:02X?} with {error:?}; \
                             the C accepted it",
                            row.name
                        )
                    });
                    assert_eq!(
                        bytes, expected,
                        "urldecode mismatch on row {:?}",
                        row.name
                    );
                    if let Some(olen) = row.olen {
                        assert_eq!(bytes.len(), olen, "row {:?}", row.name);
                    }
                }
                Outcome::Malformat => {
                    // The code is asserted, not merely the failure: the C
                    // returns `CURLE_URL_MALFORMAT` and nothing else from this
                    // path, and that value is 3.
                    assert_eq!(
                        produced,
                        Err(CURLcode::UrlMalformat),
                        "row {:?} must be refused as CURLE_URL_MALFORMAT",
                        row.name
                    );
                    refused += 1;
                }
                Outcome::Null => {
                    panic!(
                        "row {:?}: Curl_urldecode never returns a pointer \
                            through this field",
                        row.name
                    )
                }
            }
            checked += 1;
        }
        assert_eq!(checked, 1292, "decode rows checked");
        // Discriminating rather than vacuous: the refusal path really is
        // exercised, so an implementation that never refused would fail here
        // even if every accepting row happened to pass.
        assert!(refused > 0, "no DEC row exercised a rejection");
    }

    #[test]
    fn the_two_hex_renderings_match_the_c_oracle_and_disagree_on_case() {
        let mut uppercase = 0usize;
        let mut lowercase = 0usize;
        for row in &rows() {
            if row.tag != "HEXB" && row.tag != "HEXE" {
                continue;
            }
            let object = row.object.as_ref().expect("a hex row has an input");
            let Outcome::Bytes(expected) = &row.outcome else {
                panic!("a hex row always produces bytes");
            };
            match row.tag {
                "HEXB" => {
                    assert_eq!(object.len(), 1, "row {:?}", row.name);
                    let value = object[0];
                    assert_eq!(
                        hexbyte(value).as_slice(),
                        expected.as_slice(),
                        "hexbyte({value:#04X}) mismatch"
                    );
                    uppercase += 1;
                }
                "HEXE" => {
                    assert_eq!(
                        hexencode(object).as_bytes(),
                        expected.as_slice(),
                        "hexencode mismatch on row {:?}",
                        row.name
                    );
                    lowercase += 1;
                }
                _ => continue,
            }
        }
        assert_eq!(uppercase, 256, "hexbyte rows checked");
        assert_eq!(lowercase, 261, "hexencode rows checked");

        // The point of there being two: for every byte with a letter in either
        // nibble, the two renderings differ, and they differ only in case.
        let mut differing = 0usize;
        for value in 0..=255u8 {
            let upper = hexbyte(value);
            let lower = hexencode(&[value]);
            assert_eq!(
                upper.to_ascii_lowercase(),
                lower.as_bytes(),
                "the two renderings must differ only in case at {value:#04X}"
            );
            if upper.as_slice() != lower.as_bytes() {
                differing += 1;
            }
        }
        // 256 minus the 100 bytes whose two nibbles are both decimal digits.
        assert_eq!(differing, 156, "bytes whose renderings differ in case");
    }

    #[test]
    fn the_two_digit_tables_are_the_c_tables() {
        // `Curl_udigits` at `lib/mprintf.c:39` and `Curl_ldigits` at `:36`.
        assert_eq!(&UDIGITS, b"0123456789ABCDEF");
        assert_eq!(&LDIGITS, b"0123456789abcdef");
        // Named individually so that a transposed pair in either literal is
        // caught by more than an equality against a copy of itself.
        for (index, (upper, lower)) in
            UDIGITS.iter().zip(LDIGITS.iter()).enumerate()
        {
            assert_eq!(upper.to_ascii_lowercase(), *lower);
            // Rebuilt from the arithmetic rather than compared against a
            // second copy of the literal. `index` runs 0..16, so the
            // conversion is exact and the additions cannot leave the ASCII
            // range.
            let position = u8::try_from(index).expect("an index below 16");
            let expected = if position < 10 {
                b'0' + position
            } else {
                b'A' + position - 10
            };
            assert_eq!(*upper, expected, "UDIGITS[{index}]");
        }
    }

    #[test]
    fn escape_emits_uppercase_hex_and_never_lowercase() {
        // The single most easily broken observable in this file.
        assert_eq!(esc(b"/"), b"%2F".to_vec());
        assert_ne!(esc(b"/"), b"%2f".to_vec());
        assert_eq!(esc(b" "), b"%20".to_vec());
        assert_eq!(esc(b"\xff"), b"%FF".to_vec());
        assert_eq!(esc(b"?"), b"%3F".to_vec());
        assert_eq!(esc(b"\xab\xcd\xef"), b"%AB%CD%EF".to_vec());

        // Over every byte that has to be escaped: no output byte is ever a
        // lowercase letter, because the only letters an escape can emit are hex
        // digits and those come from the uppercase table. The unreserved bytes
        // are excluded from this input precisely because `a` through `z` are
        // among them and are copied through unchanged -- which the second
        // assertion below states, so the exclusion cannot hide a defect.
        let reserved: Vec<u8> = (0..=255u8)
            .filter(|&b| !strparse::is_unreserved(b))
            .collect();
        assert_eq!(reserved.len(), 256 - 66);
        assert!(
            !esc(&reserved).iter().any(u8::is_ascii_lowercase),
            "escape emitted a lowercase byte while encoding reserved bytes"
        );
        assert_eq!(esc(b"abcdef"), b"abcdef".to_vec());
    }

    #[test]
    fn the_unreserved_set_is_exactly_the_sixty_six_bytes_c_keeps() {
        // Derived from the oracle rather than restated: a `byteNN` row whose
        // output is the single input byte is a byte the C left alone.
        let mut from_oracle = [false; 256];
        let mut seen = 0usize;
        for row in &rows() {
            if row.tag != "ESC" {
                continue;
            }
            let Some(rest) = row.name.strip_prefix("byte") else {
                continue;
            };
            let byte = u8::from_str_radix(rest, 16).expect("byte row name");
            let Outcome::Bytes(output) = &row.outcome else {
                panic!("a byte row always produces bytes");
            };
            from_oracle[usize::from(byte)] = output.as_slice() == [byte];
            seen += 1;
        }
        assert_eq!(seen, 256, "the oracle covers every byte value");

        for byte in 0..=255u8 {
            assert_eq!(
                strparse::is_unreserved(byte),
                from_oracle[usize::from(byte)],
                "is_unreserved disagrees with the C on byte {byte:#04X}"
            );
        }
        assert_eq!(
            (0..=255u8).filter(|&b| strparse::is_unreserved(b)).count(),
            66,
            "62 alphanumerics plus the four of ISURLPUNTCS"
        );

        // Every one of the 66, spelled out, because a range typo would keep the
        // count while moving the boundary.
        for byte in b'A'..=b'Z' {
            assert_eq!(esc(&[byte]), vec![byte]);
        }
        for byte in b'a'..=b'z' {
            assert_eq!(esc(&[byte]), vec![byte]);
        }
        for byte in b'0'..=b'9' {
            assert_eq!(esc(&[byte]), vec![byte]);
        }
        for byte in *b"-._~" {
            assert_eq!(esc(&[byte]), vec![byte], "ISURLPUNTCS {byte:?}");
        }

        // The sub-delimiters and generic delimiters RFC 3986 names are NOT in
        // curl's unreserved set, even though several readings of that document
        // would leave some of them alone.
        for byte in *b"+/:%&=?#@$!*'(),;" {
            assert_eq!(
                esc(&[byte]),
                escape_one_by_hand(byte),
                "byte {byte:?} must be escaped"
            );
        }
        // And the boundaries of the alphanumeric ranges, from outside.
        for byte in [b'/', b':', b'@', b'[', b'`', b'{', 0x7F, 0x80, 0xFF] {
            assert_eq!(esc(&[byte]).len(), 3, "byte {byte:#04X}");
        }
    }

    /// The expected escape of a single reserved byte, built without reusing
    /// [`hexbyte`], so that the assertion above is independent of the table
    /// under test.
    fn escape_one_by_hand(byte: u8) -> Vec<u8> {
        format!("%{byte:02X}").into_bytes()
    }

    #[test]
    fn the_escape_test_is_strictly_greater_than_two() {
        // The boundary from both sides. Three bytes remaining is an escape; two
        // is not, and a `>=` typo would decode the second row of each pair.
        assert_eq!(unesc(b"%41"), vec![0x41]);
        assert_eq!(unesc(b"%4"), b"%4".to_vec());
        assert_eq!(unesc(b"%"), b"%".to_vec());
        assert_eq!(unesc(b""), Vec::<u8>::new());
        // The same boundary reached by exhausting a longer input, which is the
        // case the counting decides rather than the initial length.
        assert_eq!(unesc(b"ab%41"), b"abA".to_vec());
        assert_eq!(unesc(b"ab%4"), b"ab%4".to_vec());
        assert_eq!(unesc(b"x%4"), b"x%4".to_vec());
        // A '%' whose lookahead is another '%' consumes only itself, so the
        // second '%' is examined again and does introduce an escape.
        assert_eq!(unesc(b"%%41"), b"%A".to_vec());
        assert_eq!(unesc(b"%%%%"), b"%%%%".to_vec());
    }

    #[test]
    fn a_malformed_escape_is_passed_through_and_is_never_an_error() {
        // None of these is a failure in any sense: the C has no error path here
        // at all, only the rejection modes.
        for (input, expected) in [
            (b"%4".as_slice(), b"%4".as_slice()),
            (b"%", b"%"),
            (b"%zz", b"%zz"),
            (b"abc%", b"abc%"),
            (b"%G0", b"%G0"),
            (b"%0G", b"%0G"),
            (b"%-2", b"%-2"),
            (b"%FG", b"%FG"),
            (b"%6 1", b"%6 1"),
            (b"%6%a", b"%6%a"),
            (b"100%", b"100%"),
        ] {
            assert_eq!(unesc(input), expected.to_vec(), "{input:02X?}");
            // And the same input under the strictest mode still succeeds,
            // because every byte involved is printable: the pass-through is not
            // quietly routed through the rejection test.
            assert_eq!(
                urldecode(input, UrlReject::Ctrl),
                Ok(expected.to_vec()),
                "{input:02X?}"
            );
        }
    }

    #[test]
    fn both_hex_cases_decode_and_agree() {
        assert_eq!(unesc(b"%2f"), b"/".to_vec());
        assert_eq!(unesc(b"%2F"), b"/".to_vec());
        for byte in 0..=255u8 {
            let upper = format!("%{byte:02X}");
            let lower = format!("%{byte:02x}");
            assert_eq!(unesc(upper.as_bytes()), vec![byte]);
            assert_eq!(unesc(lower.as_bytes()), vec![byte]);
        }
        // Mixed within one triplet, which the C admits because it classifies
        // each digit on its own.
        assert_eq!(unesc(b"%aB%Cd"), vec![0xAB, 0xCD]);
    }

    #[test]
    fn hexval_answers_for_exactly_the_bytes_the_c_classifier_admits() {
        // The module folds `ISXDIGIT` and `curlx_hexval` into one call,
        // which is sound only because the two agree.
        // `crate::util::strparse` proves that for its own pair; this re-checks
        // it at the point that depends on it, so a change there surfaces here
        // rather than as a decode divergence.
        for byte in 0..=255u8 {
            assert_eq!(
                strparse::is_xdigit(byte),
                strparse::hexval(byte).is_some(),
                "byte {byte:#04X}"
            );
        }
        assert_eq!(
            (0..=255u8).filter(|&b| strparse::is_xdigit(b)).count(),
            22,
            "ten digits plus six letters in each case"
        );
    }

    #[test]
    fn an_empty_input_is_a_successful_empty_result_not_a_failure() {
        // `lib/escape.c:60-61` returns a duplicate of the empty string rather
        // than null, and the difference reaches the application: one is a
        // pointer it must release, the other is an error.
        assert_eq!(esc(b""), Vec::<u8>::new());
        assert_eq!(unesc(b""), Vec::<u8>::new());
        assert_eq!(unesc(b"").len(), 0);
        assert_eq!(urldecode(b"", UrlReject::Nada), Ok(Vec::new()));
        assert_eq!(urldecode(b"", UrlReject::Ctrl), Ok(Vec::new()));
        assert_eq!(urldecode(b"", UrlReject::Zero), Ok(Vec::new()));
        assert_eq!(hexencode(&[]), String::new());

        let rows = rows();
        let empty = rows
            .iter()
            .find(|r| r.tag == "ESC" && r.name == "empty_len0")
            .expect("the oracle carries the empty-input row");
        assert_eq!(
            empty.outcome,
            Outcome::Bytes(Vec::new()),
            "the C returned an empty string, not null"
        );
    }

    #[test]
    fn the_rejection_modes_test_the_decoded_byte() {
        // Encoded and literal forms of the same byte are treated alike,
        // which is the whole point of the test sitting after the decode at
        // `lib/escape.c:139-143`.
        assert_eq!(urldecode(b"%0A", UrlReject::Nada), Ok(b"\n".to_vec()));
        assert_eq!(
            urldecode(b"%0A", UrlReject::Ctrl),
            Err(CURLcode::UrlMalformat)
        );
        assert_eq!(
            urldecode(b"\n", UrlReject::Ctrl),
            Err(CURLcode::UrlMalformat),
            "a literal control byte is refused, not just an encoded one"
        );
        assert_eq!(
            urldecode(b"%00", UrlReject::Zero),
            Err(CURLcode::UrlMalformat)
        );
        assert_eq!(
            urldecode(b"\0", UrlReject::Zero),
            Err(CURLcode::UrlMalformat)
        );
        let nul = urldecode(b"%00", UrlReject::Nada);
        assert_eq!(nul, Ok(vec![0x00]));
        assert_eq!(nul.expect("accepted").len(), 1);

        // `REJECT_CTRL` is strictly stronger: it refuses NUL as well, because
        // NUL is below 0x20.
        assert_eq!(
            urldecode(b"%00", UrlReject::Ctrl),
            Err(CURLcode::UrlMalformat)
        );
        // `REJECT_ZERO` refuses ONLY NUL, so a tab and a line feed pass.
        assert_eq!(urldecode(b"%09", UrlReject::Zero), Ok(b"\t".to_vec()));
        assert_eq!(urldecode(b"%0A", UrlReject::Zero), Ok(b"\n".to_vec()));
        // And the bound of `REJECT_CTRL` is 0x20 exactly: space passes, and so
        // does 0x7F, which every other definition of "control" includes.
        assert_eq!(
            urldecode(b"%1F", UrlReject::Ctrl),
            Err(CURLcode::UrlMalformat)
        );
        assert_eq!(urldecode(b"%20", UrlReject::Ctrl), Ok(b" ".to_vec()));
        assert_eq!(urldecode(b"%7F", UrlReject::Ctrl), Ok(vec![0x7F]));

        // Exhaustively, over the whole byte range and both strict modes.
        for byte in 0..=255u8 {
            let triplet = format!("%{byte:02X}");
            assert_eq!(
                urldecode(triplet.as_bytes(), UrlReject::Ctrl).is_err(),
                byte < 0x20,
                "REJECT_CTRL at {byte:#04X}"
            );
            assert_eq!(
                urldecode(triplet.as_bytes(), UrlReject::Zero).is_err(),
                byte == 0,
                "REJECT_ZERO at {byte:#04X}"
            );
            assert_eq!(
                urldecode(&[byte], UrlReject::Ctrl).is_err(),
                byte < 0x20,
                "REJECT_CTRL on a literal {byte:#04X}"
            );
        }
    }

    #[test]
    fn reject_nada_refuses_nothing_which_is_what_makes_unescape_total() {
        // The invariant behind `unescape`'s `unwrap_or_default`. Asserted over
        // every byte value rather than argued, so that a change to `refuses`
        // fails here instead of turning `unescape` silently into a function
        // that can return an empty vector for a non-empty input.
        for byte in 0..=255u8 {
            assert!(
                !UrlReject::Nada.refuses(byte),
                "REJECT_NADA refused {byte:#04X}"
            );
        }
        // And end to end: the two entry points agree on every oracle input.
        for row in &rows() {
            if row.tag != "UNESC" && row.tag != "DEC" {
                continue;
            }
            let Some(input) = resolve(row) else { continue };
            assert_eq!(
                urldecode(&input, UrlReject::Nada),
                Ok(unesc(&input)),
                "row {:?}",
                row.name
            );
        }
    }

    #[test]
    fn an_embedded_nul_is_content_and_is_counted() {
        // The decoded length is a pointer difference in the C
        // (`lib/escape.c:151`), so a NUL neither terminates the result nor is
        // dropped from the count.
        assert_eq!(unesc(b"a%00b"), vec![b'a', 0x00, b'b']);
        assert_eq!(unesc(b"a%00b").len(), 3);
        assert_eq!(unesc(b"%00%00"), vec![0x00, 0x00]);
        assert_eq!(unesc(b"%00%00").len(), 2);
        assert_eq!(unesc(b"%41%00%42"), vec![0x41, 0x00, 0x42]);
        // A literal NUL in the input survives just as an encoded one does.
        assert_eq!(unesc(b"a\0b").len(), 3);
        // And escaping is the inverse: a NUL becomes a full triple rather than
        // ending the output.
        assert_eq!(esc(b"a\0b"), b"a%00b".to_vec());
    }

    #[test]
    fn escape_and_unescape_round_trip_over_every_byte() {
        // Not a property the C documents, but one it has: the escaped form of
        // any byte string decodes back to it, because every byte is either
        // unreserved -- and so not a '%' -- or emitted as a full triple.
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(unesc(&esc(&all)), all);
        for byte in 0..=255u8 {
            assert_eq!(unesc(&esc(&[byte])), vec![byte]);
        }

        // Including the sequences most likely to confuse the walk, and the
        // non-UTF-8 ones, which must neither panic nor be re-interpreted.
        for probe in [
            b"%".as_slice(),
            b"%%",
            b"%41",
            b"100%",
            b"a+b",
            b"\0\0",
            b"%%%%",
            b"\xc3\x28",
            b"\xff\xfe\xfd",
            b"\xed\xa0\x80",
            b"-._~!#%&",
            b"1/./0",
        ] {
            assert_eq!(
                unesc(&esc(probe)),
                probe.to_vec(),
                "round trip failed for {probe:02X?}"
            );
        }
    }

    #[test]
    fn invalid_utf8_survives_both_directions_byte_for_byte() {
        // `docs/libcurl/curl_easy_escape.md:43-47`: libcurl "encodes the data
        // byte-by-byte" with no knowledge of any character encoding, so an
        // input that no decoder would accept must still round-trip.
        assert_eq!(esc(b"\xc3\x28"), b"%C3%28".to_vec());
        assert_eq!(unesc(b"%c3%28"), vec![0xC3, 0x28]);
        assert_eq!(unesc(b"%C3%28"), vec![0xC3, 0x28]);
        // A lone surrogate and an overlong form, neither of which is valid
        // UTF-8 and both of which are ordinary bytes here.
        assert_eq!(esc(b"\xed\xa0\x80"), b"%ED%A0%80".to_vec());
        assert_eq!(esc(b"\xc0\x80"), b"%C0%80".to_vec());
        // And through the strict modes, where the bytes are all above 0x20.
        assert_eq!(urldecode(b"%c3%28", UrlReject::Ctrl), Ok(vec![0xC3, 0x28]));
    }

    #[test]
    fn the_size_max_over_sixteen_guard_is_reproduced_and_not_argued_away() {
        // Tested as a predicate, never by allocating: the smallest input that
        // trips it is an exbibyte.
        assert_eq!(MAX_ESCAPE_INPUT, usize::MAX / 16);
        assert_eq!(escape_capacity(MAX_ESCAPE_INPUT + 1), None);
        assert!(escape_capacity(MAX_ESCAPE_INPUT).is_some());
        assert_eq!(escape_capacity(usize::MAX), None);

        // `length * 3 + 1`, the figure `lib/escape.c:66` computes.
        assert_eq!(escape_capacity(0), Some(1));
        assert_eq!(escape_capacity(1), Some(4));
        assert_eq!(escape_capacity(15), Some(46));

        // The arithmetic the guard exists to protect cannot wrap at the limit
        // itself, which is why the C divides by 16 and not by 3.
        let at_limit = escape_capacity(MAX_ESCAPE_INPUT).expect("admitted");
        assert!(at_limit > MAX_ESCAPE_INPUT);
        assert!(at_limit < usize::MAX);

        // That the bound is real rather than vacuous -- it sits well BELOW the
        // largest length a slice may have, so a claim that no slice could reach
        // it would be false -- is pinned at compile time beside the constant
        // itself, which is why no run-time assertion of it appears here.
        assert!(escape_capacity(usize::MAX / 2).is_none());
    }

    #[test]
    fn the_int_ceiling_on_the_reported_length_is_available_to_the_shim() {
        assert!(output_len_fits_int(0));
        assert!(output_len_fits_int(1));
        // `INT_MAX` itself fits: `lib/escape.c:176` tests `<=`.
        assert!(output_len_fits_int(i32::MAX as usize));
        assert!(!output_len_fits_int(i32::MAX as usize + 1));
        assert!(!output_len_fits_int(usize::MAX));
        // Every length this module can actually produce for a plausible input
        // is far inside the bound, which is why the C's branch is unreachable
        // in practice and reproduced anyway.
        assert!(output_len_fits_int(unesc(b"%41%41%41%41").len()));
    }

    #[test]
    fn the_reject_modes_map_to_the_behaviours_the_c_enum_selects() {
        // The C integers -- 2, 3 and 4 -- are asserted in the only direction
        // that has meaning: from the mode this module names to the behaviour
        // `lib/escape.c:139-140` gives the corresponding enumerator. The
        // discriminants themselves are deliberately not reproduced; see the
        // type's documentation.
        for byte in 0..=255u8 {
            assert!(!UrlReject::Nada.refuses(byte));
            assert_eq!(UrlReject::Ctrl.refuses(byte), byte < 0x20);
            assert_eq!(UrlReject::Zero.refuses(byte), byte == 0);
        }
        // Nesting: everything `Zero` refuses, `Ctrl` refuses too.
        for byte in 0..=255u8 {
            if UrlReject::Zero.refuses(byte) {
                assert!(UrlReject::Ctrl.refuses(byte));
            }
        }
        assert_eq!(
            (0..=255u8).filter(|&b| UrlReject::Ctrl.refuses(b)).count(),
            32
        );
        assert_eq!(
            (0..=255u8).filter(|&b| UrlReject::Zero.refuses(b)).count(),
            1
        );
    }

    #[test]
    fn the_hex_helpers_render_the_pairs_the_c_comments_promise() {
        // `lib/escape.c:220`: "a two-digit UPPERCASE hex number".
        assert_eq!(hexbyte(0x2f), *b"2F");
        assert_eq!(hexbyte(0x00), *b"00");
        assert_eq!(hexbyte(0xff), *b"FF");
        assert_eq!(hexbyte(0x0f), *b"0F");
        assert_eq!(hexbyte(0xa5), *b"A5");
        assert_eq!(hexbyte(0x10), *b"10");

        // `lib/escape.c:197`: "lowercase hex-encoded ASCII output".
        assert_eq!(hexencode(&[0x2f]), "2f");
        assert_eq!(hexencode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hexencode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hexencode(&[]), "");

        // The two disagree for the same input, which is the point.
        assert_ne!(hexbyte(0x2f).as_slice(), hexencode(&[0x2f]).as_bytes());
        assert_ne!(hexbyte(0xff).as_slice(), hexencode(&[0xff]).as_bytes());
        // But agree where no letter is involved.
        assert_eq!(hexbyte(0x42).as_slice(), hexencode(&[0x42]).as_bytes());

        // Two digits per input byte, and nothing else: no separator, no prefix,
        // no terminator. The C wrote a NUL at `:212`; an owned string does not.
        assert_eq!(hexencode(&[1, 2, 3]).len(), 6);
        assert!(hexencode(&[0; 8]).bytes().all(|b| b == b'0'));
        assert!(!hexencode(&[0x2f]).contains('\0'));
        assert!(hexencode(&[0xAB]).is_ascii());
    }

    #[test]
    fn unit1396_unescape_table() {
        // `tests/unit/unit1396.c:54-68`, every row, with its C line number.
        // The C passes a NUL-terminated object plus an explicit length, and two
        // rows deliberately pass a length shorter than the string, so the
        // slice handed over is the object truncated to that length.
        for (line, object, inlen, expected) in [
            (55, b"%61".as_slice(), 3, b"a".as_slice()),
            (56, b"%61a", 4, b"aa"),
            (57, b"%61b", 4, b"ab"),
            (58, b"%6 1", 4, b"%6 1"),
            (59, b"%61", 1, b"%"),
            (60, b"%61", 2, b"%6"),
            (61, b"%6%a", 4, b"%6%a"),
            (62, b"%6a", 0, b"j"),
            (63, b"%FF", 0, b"\xff"),
            (64, b"%FF%00%ff", 9, b"\xff\x00\xff"),
            (65, b"%-2", 0, b"%-2"),
            (66, b"%FG", 0, b"%FG"),
        ] {
            // `inlen == 0` is the C's "measure it", and the object here is the
            // measured string itself.
            let input = if inlen == 0 { object } else { &object[..inlen] };
            let produced = unesc(input);
            assert_eq!(
                produced,
                expected.to_vec(),
                "unit1396.c:{line} decoded {input:02X?} wrongly"
            );
            // The C also asserts the reported length on every row.
            assert_eq!(
                produced.len(),
                expected.len(),
                "unit1396.c:{line} reported the wrong length"
            );
        }
    }

    #[test]
    fn unit1396_escape_table() {
        // `tests/unit/unit1396.c:70-82`, every row. Three rows pass a length
        // that reaches or passes the terminator, which the C reads as data --
        // so the slice includes the terminating NUL, and the expected output
        // contains `%00`.
        for (line, object, inlen, expected) in [
            (71, b"a\0".as_slice(), 1, b"a".as_slice()),
            (72, b"/\0", 1, b"%2F"),
            (73, b"a=b\0", 3, b"a%3Db"),
            (74, b"a=b\0", 0, b"a%3Db"),
            (75, b"a=b\0", 1, b"a"),
            (76, b"a=b\0", 2, b"a%3D"),
            (77, b"1/./0\0", 5, b"1%2F.%2F0"),
            (78, b"-._~!#%&\0", 0, b"-._~%21%23%25%26"),
            (79, b"a\0", 2, b"a%00"),
            (80, b"a\xff\x01g\0", 4, b"a%FF%01g"),
        ] {
            // The object carries its own terminator, so "measure it" is one
            // byte shorter than the object.
            let resolved = if inlen == 0 { object.len() - 1 } else { inlen };
            let input = &object[..resolved];
            let produced = esc(input);
            assert_eq!(
                produced,
                expected.to_vec(),
                "unit1396.c:{line} escaped {input:02X?} wrongly"
            );
            assert_eq!(
                produced.len(),
                expected.len(),
                "unit1396.c:{line} reported the wrong length"
            );
        }
    }

    #[test]
    fn unit1605_edge_cases() {
        // `tests/unit/unit1605.c:56-60` asserts that a NEGATIVE length yields
        // null from both entry points. That check has no expression against a
        // `&[u8]`, whose length is unsigned by construction, so it lives in
        // `curl-rs-ffi`'s marshaller where the `int` does -- and the oracle
        // pins it there under the row names `neg_len`, `u1605_empty_neg` and
        // `u1605_neg`, which the differential above reads as `resolve`
        // declining exactly where the C returned null.
        let rows = rows();
        for name in ["u1605_empty_neg", "neg_len"] {
            let row = rows
                .iter()
                .find(|r| r.tag == "ESC" && r.name == name)
                .unwrap_or_else(|| panic!("the oracle carries {name}"));
            assert_eq!(row.outcome, Outcome::Null, "{name}");
            assert!(row.arg.expect("a length") < 0, "{name}");
            assert!(resolve(row).is_none(), "{name}");
        }
        let row = rows
            .iter()
            .find(|r| r.tag == "UNESC" && r.name == "u1605_neg")
            .expect("the oracle carries u1605_neg");
        assert_eq!(row.outcome, Outcome::Null);
        assert!(resolve(row).is_none());

        // What the engine CAN state about that row is the transformation the C
        // would have performed had the length been valid: `unit1605.c:59` uses
        // the same input as the positive case.
        assert_eq!(unesc(b"%41%41%41%41"), b"AAAA".to_vec());

        // A null input pointer is likewise the shim's to reject, and the oracle
        // records the C's answer for it too.
        for name in ["null_string_len5", "null_string_len0"] {
            let row = rows
                .iter()
                .find(|r| r.tag == "ESC" && r.name == name)
                .unwrap_or_else(|| panic!("the oracle carries {name}"));
            assert!(row.object.is_none(), "{name}");
            assert_eq!(row.outcome, Outcome::Null, "{name}");
        }
    }

    #[test]
    fn the_documented_examples_are_the_c_documentations_examples() {
        // `docs/libcurl/curl_easy_escape.md:72`.
        assert_eq!(esc(b"data to convert"), b"data%20to%20convert".to_vec());
        // `docs/libcurl/curl_easy_unescape.md:61`, whose expected output the
        // manual page names in its surrounding prose.
        assert_eq!(unesc(b"%63%75%72%6c"), b"curl".to_vec());
    }

    #[test]
    fn the_walk_terminates_and_allocates_nothing_it_cannot_fill() {
        // The decode result is never longer than its input, so the reservation
        // in both drivers is an upper bound rather than a guess.
        for probe in [
            b"".as_slice(),
            b"%",
            b"%41",
            b"%41%42%43",
            b"abc",
            b"%%%%%%%%",
            b"a%00b",
        ] {
            let decoded = unesc(probe);
            assert!(
                decoded.len() <= probe.len(),
                "decode grew {probe:02X?} from {} to {}",
                probe.len(),
                decoded.len()
            );
        }
        // And the encode result is never longer than three bytes per input
        // byte, which is what `escape_capacity` reserves.
        for probe in [b"".as_slice(), b"abc", b"%%%", b"\xff\xff", b"\0"] {
            let encoded = esc(probe);
            assert!(encoded.len() <= probe.len() * 3);
            assert!(encoded.len() >= probe.len());
            assert!(encoded.is_ascii(), "escape output is always ASCII");
            assert!(!encoded.contains(&0), "escape output has no NUL");
        }
    }
}
