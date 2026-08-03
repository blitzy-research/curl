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
// 1. The 23-line banner above is the block measured at `lib/escape.c:1-23`,
//    rendered as Rust line comments with the C block-comment decorations
//    stripped. Byte-identical to `src/lib.rs`, `src/error.rs`,
//    `src/util/strparse.rs`, `src/url/idn.rs` and `src/version.rs`. The
//    licence-identifier line is line 21 and is verbatim; it is the only place
//    in this file where that spelling appears, which is what `reuse lint`
//    needs. `REUSE.toml` does not list this path, so the annotation has to be
//    in-file. `scripts/spacecheck.pl`, run by the `spacecheck` step of
//    `.github/workflows/hygiene.yml`, additionally rejects tabs, trailing
//    whitespace, consecutive blank lines and any byte at or above 0x80 in a
//    tracked file, so every byte below is plain ASCII -- including the doc
//    examples, which spell a high byte as an escape rather than as a
//    character.
//
// 2. `dead_code` allowances are written at the ITEM, never on a module
//    declaration and never at a file root. `mod source_policy` in
//    `curl-rs-lib/src/lib.rs` enforces that as an executable gate, and the
//    reason is that a root attribute would silence the NEXT item somebody
//    adds. Two items here carry one, each naming the C call site that will
//    remove it.
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
//
//    A link from public documentation to a private or `pub(crate)` item
//    resolves only under `--document-private-items` and rustdoc says so:
//    "will break without". So the link is not a link for the readers who see
//    this crate's documentation.
//
//    And a link in the module comment does not resolve against THIS module's
//    scope at all. `url/mod.rs` documents this module with an outer doc comment
//    on its `mod` declaration, and rustdoc concatenates that with the inner
//    comment below, so a bare item name in the merged text is looked up in
//    `url`'s scope and reported unresolved. `util/strparse.rs` records the same
//    finding and answers it with fully spelled paths; here the affected names
//    are all non-`pub`, for which a path would not help, so plain backticks are
//    the answer instead. Measured: `cargo doc -p curl-rs-lib --no-deps` reports
//    nothing against this file.

//! Percent-encoding and percent-decoding -- supersedes `lib/escape.c` (227
//! lines) and `lib/escape.h` (45).
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
//! The last two are, in the C's own words at `lib/escape.c:35` and `:41`, there
//! "for ABI-compatibility with previous versions": each is a single call into
//! its `curl_easy_` counterpart with a null handle. Specification 0.8.2 forbids
//! dropping a deprecated export, so both survive -- as forwarders in
//! `curl-rs-ffi/src/ffi/`, not as anything of their own here.
//!
//! Nothing in this file is `extern "C"` and nothing carries `#[no_mangle]`.
//! Conflict C1 of specification 0.8.5 sanctions two `src/ffi/` locations and
//! gives each a distinct job -- `curl-rs-ffi/src/ffi/` for the public ABI,
//! `curl-rs-lib/src/ffi/` for operating-system integration -- so an exported
//! definition here would add a name to `nm` output that
//! `.github/workflows/rust-abi.yml` compares against `lib/libcurl.def`, and the
//! comparison is for equality. `curl_free` (`lib/escape.c:189-192`) belongs to
//! the same shim for the same reason, and is neither implemented nor referenced
//! below.
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
//! # The transformation this module owns, and the marshalling it does not
//!
//! This module owns every decision a caller can observe in the output: which
//! bytes survive unencoded, the case of the hex digits, the exact conditions
//! under which a `%` introduces an escape rather than standing for itself, and
//! which decoded bytes are acceptable. Specification 0.8.1 freezes all four.
//!
//! `curl-rs-ffi` owns the marshalling: turning `(pointer, int)` into the slice
//! passed here. The split is forced by the C contract rather than chosen.
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
//! # `escape`: the unreserved set, and the case of the hex digits
//!
//! `lib/escape.c:72` keeps a byte verbatim when `ISUNRESERVED(in)` holds and
//! otherwise emits `%` followed by two hex digits. `lib/curl_ctype.h:49`
//! defines that predicate as `ISALNUM(x) || ISURLPUNTCS(x)`, and
//! `lib/curl_ctype.h:47-48` defines `ISURLPUNTCS` as `-`, `.`, `_` and `~`.
//! curl's `ISALNUM` is its own ASCII table rather than `<ctype.h>`, so it is
//! locale-independent and no byte at or above 0x80 is ever alphanumeric. The
//! set is exactly the 66 bytes `[A-Za-z0-9-._~]`, which
//! `docs/libcurl/curl_easy_escape.md:31-33` states independently.
//!
//! That predicate is **not** re-derived here. `crate::util::strparse` owns
//! curl's whole byte classification, transcribed from `lib/curl_ctype.h`, and
//! this module consumes `is_unreserved` from it. One shared definition beats
//! two that can drift, and the set is observable in wire output. The same
//! applies to `hexval`, whose backing table `curlx_hexasciitable` carries an
//! index-0 sentinel of 16 that a re-derivation would get wrong.
//!
//! `percent-encoding 2.3.2` is a declared dependency and can express the
//! transformation with a custom `AsciiSet`. It is deliberately not used. The
//! uppercase spelling below is wire-observable, and writing the loop keeps the
//! choice legible at the point that makes it and traceable to the C table it
//! comes from, instead of resting on a behaviour a dependency bump could
//! change. Specification 0.1.1 settles the trade: where a choice exists between
//! a faster design and a more behaviourally faithful one, faithfulness wins.
//!
//! Which leaves that dependency's declaration looking unused, so where it does
//! belong is worth recording: the URL API of `lib/urlapi.c` carries several
//! encoding sets of its OWN, distinct from this one -- a query is escaped
//! differently from a path segment -- and it is the sibling `mod.rs` arriving
//! with that file, not this module, that has a use for a general set builder.
//! The crate keeps the dependency in its graph regardless, through `url` and
//! `form_urlencoded`, so nothing is being carried solely on that expectation.
//!
//! The digits are **uppercase**. `lib/escape.c:80` calls `Curl_hexbyte`, which
//! `lib/escape.c:222-227` implements over `Curl_udigits` --
//! `"0123456789ABCDEF"` at `lib/mprintf.c:39`. The lowercase table
//! `Curl_ldigits` (`lib/mprintf.c:36`) belongs to `Curl_hexencode`, a
//! different function with
//! different callers, reproduced here as `hexencode`. Two casings coexist in
//! one C file on purpose, and emitting the wrong one would produce output that
//! is semantically equivalent and textually wrong -- which specification 0.8.2
//! rules out, because a difference that is arguably as good has still failed.
//!
//! # `unescape`: the decode walk, and the strictness of `alloc > 2`
//!
//! `Curl_urldecode` (`lib/escape.c:105-154`) walks the input with a counter the
//! C calls `alloc`, holding the number of bytes still to be consumed. A `%`
//! introduces an escape only when **all three** of these hold
//! (`lib/escape.c:126-127`):
//!
//! ```text
//! alloc > 2  &&  ISXDIGIT(string[1])  &&  ISXDIGIT(string[2])
//! ```
//!
//! and otherwise the `%` is copied through as an ordinary byte. The comparison
//! is strictly greater, not `>=`, and the difference is observable:
//! `tests/unit/unit1396.c:60` decodes `"%61"` with an explicit length of 2 and
//! expects the two literal bytes `%6`, because two remaining bytes are not more
//! than two. `decode_step` expresses the rule as a slice pattern requiring
//! two bytes *after* the `%`, so the off-by-one cannot be written.
//!
//! A malformed escape is never a decode error. `"%"`, `"%4"`, `"%zz"`, `"%6 1"`
//! and `"%FG"` all decode to themselves -- five rows of that same C table. The
//! only errors come from the rejection modes below.
//!
//! # The three rejection modes
//!
//! `lib/escape.h:29-33` declares them, and the numbering is the point:
//!
//! ```text
//! enum urlreject {
//!   REJECT_NADA = 2,
//!   REJECT_CTRL,
//!   REJECT_ZERO
//! };
//! ```
//!
//! `lib/escape.c:101-102` explains why they start at 2: "to make the assert
//! detect legacy invokes that used TRUE/FALSE (0 and 1)". `UrlReject`
//! therefore carries no `#[repr]` and no pinned discriminants -- see its own
//! documentation for why reproducing the integers would be a mistake rather
//! than an omission.
//!
//! The test runs on the byte **after** decoding (`lib/escape.c:139-143`) and
//! applies just as much to a byte that was never encoded, so a literal `0x0a`
//! fails `REJECT_CTRL` exactly as `%0A` does. `curl_easy_unescape` passes
//! `REJECT_NADA` (`lib/escape.c:170-171`), which refuses nothing, so the public
//! decode accepts control bytes and NUL alike.
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
//!
//! # Byte transparency
//!
//! Every signature takes and returns `u8` and `&[u8]`, never `&str` and never
//! `char`. `docs/libcurl/curl_easy_escape.md:43-47` is explicit that libcurl
//! "is typically not aware of, nor does it care about, character encodings" and
//! "encodes the data byte-by-byte", so an input that is not valid UTF-8 must
//! round-trip unchanged. A `&str` boundary would reject it and a `char`
//! boundary would re-interpret one byte as a multi-byte scalar.
//! `crate::util::strparse` holds the same discipline for the same reason.
//!
//! # What the tests are measured against
//!
//! `escape_oracle.txt`, included by the test module, is a differential capture
//! rather than a transcription: every row records an input object with its own
//! NUL terminator, the exact length argument, and what the C produced. The
//! `ESC`, `UNESC` and `UNESCN` rows were taken from the frozen system libcurl
//! **and** from a verbatim transcription of this tree's `lib/escape.c`, both
//! run over the same inputs, and the generator aborts on any disagreement --
//! it reported none. `Curl_urldecode`, `Curl_hexbyte` and `Curl_hexencode` are
//! internal and unexported, so their rows come from the transcription alone;
//! the shared decode walk of the `REJECT_NADA` rows is what shows it faithful.
//!
//! The coverage that `tests/unit/unit1396.c` and `tests/unit/unit1605.c`
//! obtained by linking a debug static library is relocated into the test module
//! at the foot of this file, per specification 0.8.7. A Rust static library
//! does not export `pub(crate)` items, so those two C programs cannot link
//! whatever the quality of this implementation, and re-exporting internals to
//! rescue them would defeat the encapsulation that makes the zero-`unsafe`
//! guarantee possible. Every row of both C tables appears below, named for its
//! source line.

use crate::error::CURLcode;
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
//
// The first line is the one the previous reading of this file got backwards.
// The second records what the guard is for: `length * 3` at the limit occupies
// just under a fifth of the range, so the product cannot wrap -- which is why
// the C divides by 16 rather than by 3.
const _: () = assert!(MAX_ESCAPE_INPUT < usize::MAX / 2);
const _: () = assert!(MAX_ESCAPE_INPUT < usize::MAX / 3);

/// The output limit `lib/escape.c:66` gives the encode buffer, or [`None`] when
/// the input is longer than [`MAX_ESCAPE_INPUT`].
///
/// `curlx_dyn_init(&d, length * 3 + 1)` sets a `toobig` ceiling rather than an
/// allocation, and three bytes per input byte plus one for the C terminator is
/// the worst case exactly: every byte either survives as one byte or becomes
/// `%` and two digits. The `+ 1` has no counterpart in the returned `Vec`,
/// which stores no terminator, and is kept because it is part of the figure the
/// C computes.
///
/// Both arithmetic steps are checked, so this function has no panicking path in
/// either profile -- which is the requirement, given that a panic here could
/// unwind towards a C caller through `curl-rs-ffi`. The guard makes the checks
/// redundant on any input that passes it; they are written anyway, because
/// "provably cannot overflow" is a claim a reader has to verify and
/// `checked_mul` is one they do not.
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
///
/// Supersedes `enum urlreject` (`lib/escape.h:29-33`), whose three members are
/// declared as `REJECT_NADA = 2`, `REJECT_CTRL` and `REJECT_ZERO` -- so 2, 3
/// and 4.
///
/// # Why those integers are deliberately not reproduced
///
/// They are a debugging artefact, not a contract. `lib/escape.c:101-102` gives
/// the reason for the offset: the enumeration starts at 2 "to make the assert
/// detect legacy invokes that used TRUE/FALSE (0 and 1)", and the assert in
/// question is `DEBUGASSERT(ctrl >= REJECT_NADA)` at `lib/escape.c:113`. The
/// values exist so that a call written before the enumeration was introduced
/// crashes a debug build instead of silently selecting the wrong mode. No
/// public header declares this type, no exported function accepts it, and no
/// value of it crosses the C ABI, so pinning the discriminants would record a
/// C-era workaround as though it were part of the interface. Rust makes the
/// workaround unnecessary: a caller cannot pass a boolean where this is
/// expected. The integers are documented here so the correspondence with the C
/// remains greppable, and a test asserts the mapping in the only direction that
/// means anything -- from mode to behaviour.
///
/// # The behaviours are nested, and only look redundant
///
/// [`Self::Ctrl`] refuses every byte below 0x20, which includes NUL, so it is
/// strictly stronger than [`Self::Zero`]. `lib/escape.c:139-140` still spells
/// them as two independent tests, because a caller that objects to an embedded
/// NUL frequently has no objection to a tab.
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
    // No consumer yet; `lib/urlapi.c:590`, `:1385` and `:1980` will select it
    // when the URL API lands with `lib/urlapi.c`.
    #[allow(dead_code)]
    Ctrl,

    /// `REJECT_ZERO` (4): refuse a decoded NUL, and nothing else.
    ///
    /// A tab or a line feed passes. `lib/escape.c:140` tests `in == 0` alone.
    // No consumer yet; `lib/setopt.c:1683` and `:1688` will select it when the
    // option setters land.
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
    ///
    /// `decoded` is the byte **after** any percent-decoding, and the test
    /// applies equally to a byte that was never encoded -- which is why a
    /// literal line feed fails [`Self::Ctrl`] exactly as `%0A` does. Writing it
    /// as a method over the decoded byte makes that impossible to get wrong: a
    /// caller has nothing but the decoded byte to hand it.
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
/// # Total, and why the C's three failure paths have no counterpart
///
/// `lib/escape.c` can return null from this function for three reasons, and
/// each is discharged somewhere other than in a result type. The argument
/// checks at `:56` belong to the shim, which owns the pointer and the `int`.
/// The out-of-memory arms at `:75` and `:82` have no expression: `Vec` aborts
/// rather than reporting a failed growth, so there is no null for this function
/// to produce. The length guard at `:63-64` is reproduced as
/// `escape_capacity`, which declines to name a buffer size instead of
/// declining to encode -- the C's null return there is unreachable across the
/// ABI, because the length arrives as an `int`, and `MAX_ESCAPE_INPUT` records
/// the arithmetic.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::url::escape::escape;
///
/// assert_eq!(escape(b"a b~c"), b"a%20b~c".to_vec());
/// // Uppercase hex, and no byte at or above 0x80 is ever unreserved.
/// assert_eq!(escape(b"\xc3\xa9"), b"%C3%A9".to_vec());
/// // An interior NUL is escaped like any other reserved byte.
/// assert_eq!(escape(b"a\0b"), b"a%00b".to_vec());
/// // Sub-delimiters are NOT unreserved, whatever RFC 3986 calls them.
/// assert_eq!(escape(b"a=b&c"), b"a%3Db%26c".to_vec());
/// ```
#[must_use]
pub fn escape(input: &[u8]) -> Vec<u8> {
    // The C's `length * 3 + 1` when the guard admits the input, and the input
    // length when it does not -- a figure that is always allocatable, because
    // the input already exists. Only the number of reallocations differs; the
    // output is identical either way, and specification 0.1.1 makes performance
    // a non-goal.
    let capacity = escape_capacity(input.len()).unwrap_or(input.len());
    let mut out = Vec::with_capacity(capacity);

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

    out
}

/// One iteration of the C's decode walk: the next decoded byte, and the input
/// that remains after it.
///
/// This is the whole of `lib/escape.c:124-137`, and it is factored out because
/// it is the part that can drift. Both [`unescape`] and [`urldecode`] drive it,
/// so the rule below is stated once.
///
/// [`None`] means the input is exhausted, which is the C's `while(alloc)`.
///
/// # The `alloc > 2` rule is structural here, not arithmetic
///
/// The C reads two bytes of lookahead behind a counter test:
///
/// ```c
/// if(('%' == in) && (alloc > 2) && ISXDIGIT(string[1]) && ISXDIGIT(string[2]))
/// ```
///
/// Written as a comparison, that is one keystroke away from `>=`, and the
/// difference decides whether a trailing `%4` is a decoded byte or two literal
/// ones. Written as `if let [high, low, after @ ..] = tail` it is not a
/// comparison at all: the pattern matches only when two bytes follow the `%`,
/// which is what "more than two remaining" means, and the two lookaheads are
/// bindings from that match rather than indices into a slice. The off-by-one
/// therefore cannot be written, and no index below can be out of range.
///
/// # A malformed escape falls through rather than failing
///
/// When the two following bytes are not both hexadecimal digits, control
/// reaches the final expression, which consumes the `%` alone and leaves both
/// lookahead bytes to be examined again by the next step. That is
/// `lib/escape.c:134-137` exactly, and it is why `"%zz"` decodes to `"%zz"`
/// rather than to an error. The same expression serves the ordinary case of a
/// byte that is not a `%` at all, because the C treats the two identically.
///
/// # Why `hexval` does the classifying as well as the converting
///
/// The C tests `ISXDIGIT` at `:127` and then converts with `curlx_hexval` at
/// `:129-130`, two steps over the same byte.
/// `crate::util::strparse::hexval` answers `Some` for precisely the bytes
/// `is_xdigit` admits -- that module proves it for all 256 values rather than
/// asserting it, and a test below re-checks the agreement here -- so folding
/// them makes it impossible to convert a byte that was never classified, and
/// leaves no branch that cannot be reached.
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
/// Supersedes `Curl_urldecode` (`lib/escape.c:105-154`). Returns the decoded
/// bytes, or `CURLcode::UrlMalformat` -- the C's `CURLE_URL_MALFORMAT` -- when
/// `reject` refuses one of them.
///
/// `input` is the already-resolved byte range, so the C's
/// `alloc = length ? length : strlen(string)` at `:115` has already been
/// applied by the caller. An empty input decodes to an empty result and is not
/// an error, which is the C's loop simply not running.
///
/// # There is no partial output on failure
///
/// `lib/escape.c:141` releases the buffer with `Curl_safefree(*ostring)` before
/// returning, so a C caller sees a null pointer rather than the bytes decoded
/// up to the refusal. Returning `Err` reproduces that by construction: the
/// `Vec` built so far is dropped, and nothing partial can reach the caller.
///
/// The walk stops at the **first** refused byte, exactly as the C does, so no
/// work is done past the failure.
///
/// # Length
///
/// `lib/escape.c:151` reports the size as `ns - *ostring`, a pointer
/// difference, so an embedded NUL is content rather than a terminator. The
/// returned `Vec`'s `len` carries the same number.
///
/// ```text
/// urldecode(b"a%00b", UrlReject::Nada)  ->  Ok([0x61, 0x00, 0x62])   len 3
/// urldecode(b"a%00b", UrlReject::Zero)  ->  Err(CURLE_URL_MALFORMAT)
/// urldecode(b"\n",    UrlReject::Ctrl)  ->  Err(CURLE_URL_MALFORMAT)
/// ```
///
/// The third row is the one worth remembering: the input contains no escape at
/// all, and is still refused, because `lib/escape.c:139-143` tests the decoded
/// byte whether or not decoding changed it.
// The strict modes have no in-crate caller yet. The measured C call sites are
// `lib/urlapi.c:590`, `:1385` and `:1980` (the sibling `mod.rs`),
// `lib/setopt.c:1683` and `:1688`, `lib/url.c:1769` and `:1791`,
// `lib/file.c:160`, `lib/ftp.c:221` and `lib/vssh/vssh.c:137`; each removes
// this allowance when its module lands.
pub(crate) fn urldecode(
    input: &[u8],
    reject: UrlReject,
) -> Result<Vec<u8>, CURLcode> {
    // An exact upper bound: the result is never longer than the input, and is
    // shorter by two bytes for every escape decoded. The C asks for
    // `alloc + 1` at `:116`, the extra byte being the terminator it writes at
    // `:147` and this `Vec` does not store.
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;

    while let Some((byte, tail)) = decode_step(rest) {
        if reject.refuses(byte) {
            return Err(CURLcode::UrlMalformat);
        }
        out.push(byte);
        rest = tail;
    }

    Ok(out)
}

/// Percent-decodes `input`, reproducing `curl_easy_unescape`.
///
/// Supersedes `lib/escape.c:163-184`. A `%` introduces an escape only when at
/// least two bytes follow it and both are hexadecimal digits; in every other
/// case it is copied through literally, which is what makes `"abc%"`,
/// `"abc%4"`, `"%zz"` and `"%%41"` decode to `"abc%"`, `"abc%4"`, `"%zz"` and
/// `"%A"` rather than failing. The digits are accepted in either case, even
/// though only the uppercase spelling is ever produced.
///
/// `input` is the already-resolved byte range, exactly as for [`escape`].
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
/// The decoded bytes may therefore include NUL and control characters, and the
/// returned length is authoritative over them.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::url::escape::unescape;
///
/// assert_eq!(unescape(b"%41%42%43"), b"ABC".to_vec());
/// // Either hex case decodes.
/// assert_eq!(unescape(b"%4a%4B"), b"JK".to_vec());
/// // A '%' that does not introduce two hex digits stands for itself.
/// assert_eq!(unescape(b"abc%4G"), b"abc%4G".to_vec());
/// // Two remaining bytes are not MORE than two: tests/unit/unit1396.c:60.
/// assert_eq!(unescape(b"%6"), b"%6".to_vec());
/// // '+' is not a space: this is URL escaping, not form encoding.
/// assert_eq!(unescape(b"a+b"), b"a+b".to_vec());
/// // NUL survives, which is why the length is the return value's own.
/// assert_eq!(unescape(b"a%00b"), vec![b'a', 0, b'b']);
/// ```
#[must_use]
pub fn unescape(input: &[u8]) -> Vec<u8> {
    urldecode(input, UrlReject::Nada).unwrap_or_default()
}

/// Renders one byte as two **uppercase** hex digits.
///
/// Supersedes `Curl_hexbyte` (`lib/escape.c:222-227`), whose whole body is
///
/// ```c
/// dest[0] = Curl_udigits[val >> 4];
/// dest[1] = Curl_udigits[val & 0x0F];
/// ```
///
/// Returning an array rather than writing through a pointer discharges the C
/// contract stated in its own parameter comment at `lib/escape.c:222` --
/// "must fit two bytes" -- which the caller previously had to honour by hand.
/// Both indices are masked into 0..=15, so neither bounds check the compiler
/// inserts can fire.
///
/// [`escape`] is the in-crate caller, matching `lib/escape.c:80`. The C's other
/// call sites are `lib/urlapi.c:159` and `:1909`, which arrive with the sibling
/// `mod.rs`, and `lib/vtls/keylog.c:128` and `:135`. That last pair is served
/// today by a private copy in `curl-rs-lib/src/tls/keylog.rs`, which landed
/// before this module was completed; the copy is that module's to retire, and
/// it is recorded here so that nobody reads the duplication as accidental.
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
/// Supersedes `Curl_hexencode` (`lib/escape.c:200-216`), documented at `:197`
/// as converting "binary input to lowercase hex-encoded ASCII output". **This
/// is not percent-encoding**: it shares a C file with [`escape`] and nothing
/// else, indexes [`LDIGITS`] where [`hexbyte`] indexes [`UDIGITS`], and emits
/// no `%` at all.
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
/// The truncation is the one dropped behaviour a reader might miss, so it is
/// worth being explicit: every C call site sizes its buffer from the digest it
/// is rendering, so none of them truncates, and a `String` cannot.
///
/// # Why the nibble loop is written out rather than delegated
///
/// `hex 0.4.3` is a declared dependency and `hex::encode` is lowercase by
/// definition, so it would serve. The loop below is written anyway, for the
/// reason the module documentation gives for [`escape`]: the case is
/// wire-observable, and indexing [`LDIGITS`] two lines from [`hexbyte`]'s
/// [`UDIGITS`] puts the contrast in front of the reader instead of resting it
/// on a behaviour a dependency bump could change. The body is
/// `lib/escape.c:206-207` verbatim, so the two functions now differ in exactly
/// one identifier -- which
/// is the whole of the difference in the C as well.
///
/// `crate::crypto::hex_lower` reaches `hex::encode` for the digest path and
/// renders the same bytes the same way. That one belongs to the digest layer;
/// this one is the transformation `lib/escape.h:39-40` declares here, and the
/// oracle checks both against the C rather than against each other.
///
/// Hex *decoding* is not this module's business at all:
/// `crate::util::strparse` owns it, mirroring `curlx_hexasciitable`.
///
/// ```text
/// hexencode(&[0x2f])                    ->  "2f"       /* not "2F" */
/// hexencode(&[0xde, 0xad, 0xbe, 0xef])  ->  "deadbeef"
/// ```
// No consumer yet. The measured C call sites are `lib/http_aws_sigv4.c:67`
// (arriving with `auth/aws_sigv4.rs`), `lib/doh.c:199` (`dns/doh.rs`, whose
// include at `lib/doh.c:38` is commented "for Curl_hexencode()") and
// `lib/rand.c:249` (`crypto/rand.rs`). The digest path reaches
// `crate::crypto::hex_lower` instead, which landed with `src/crypto/` and
// renders the same bytes the same way; that one is the digest layer's, this one
// is the transformation `lib/escape.h:39-40` declares here.
#[allow(dead_code)]
#[must_use]
pub(crate) fn hexencode(src: &[u8]) -> String {
    // Two output bytes per input byte. `saturating_mul` cannot saturate for a
    // real slice -- a length is capped at `isize::MAX`, so twice it still fits
    // a `usize` -- and is written rather than `*` so that no arithmetic here
    // behaves differently between the debug and release profiles.
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
/// The engine half of `lib/escape.c:175-181`.
/// `docs/libcurl/curl_easy_unescape.md:41-43` states the ceiling: because the
/// out-parameter is "a pointer to an *int* type, it can only return a value up
/// to *INT_MAX* so no longer string can be returned in this parameter".
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
///
/// The asymmetry is worth carrying across with it. `curl_unescape`
/// (`lib/escape.c:42-45`) forwards with `olen = NULL`, so the ceiling never
/// applies to that entry point -- the same input that yields null through
/// `curl_easy_unescape` with an out-parameter yields the decoded buffer through
/// `curl_unescape`. Observable, and easy to lose.
///
/// The bound is written as `i32::MAX` rather than as a C width because the
/// engine speaks in fixed-width integers: `include/curl/curl.h` fixes these
/// sizes by ABI, not by whichever width a compiler chose, and `mod
/// source_policy` in `curl-rs-lib/src/lib.rs` enforces the distinction.
// No consumer yet. `curl-rs-ffi/src/ffi/escape.rs` currently performs the
// conversion with a direct `try_from`, which answers the same question; this is
// the engine-side statement of the test that specification section 0.6 asks to
// live here, and the shim's next revision is where the two meet.
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

    /// The differential capture described in the module documentation.
    ///
    /// Self-describing by construction: each row carries the input object's
    /// bytes -- including its NUL terminator -- and the exact length argument,
    /// so the call is reconstructed rather than transcribed. That matters more
    /// than it sounds: several rows deliberately pass a length that reaches the
    /// terminator, and a hand-written input would have to encode that intent
    /// correctly to be testing anything at all.
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
                    &escape(&input),
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
                    let produced = unescape(&input);
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
        assert_eq!(escape(b"/"), b"%2F".to_vec());
        assert_ne!(escape(b"/"), b"%2f".to_vec());
        assert_eq!(escape(b" "), b"%20".to_vec());
        assert_eq!(escape(b"\xff"), b"%FF".to_vec());
        assert_eq!(escape(b"?"), b"%3F".to_vec());
        assert_eq!(escape(b"\xab\xcd\xef"), b"%AB%CD%EF".to_vec());

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
            !escape(&reserved).iter().any(u8::is_ascii_lowercase),
            "escape emitted a lowercase byte while encoding reserved bytes"
        );
        assert_eq!(escape(b"abcdef"), b"abcdef".to_vec());
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
            assert_eq!(escape(&[byte]), vec![byte]);
        }
        for byte in b'a'..=b'z' {
            assert_eq!(escape(&[byte]), vec![byte]);
        }
        for byte in b'0'..=b'9' {
            assert_eq!(escape(&[byte]), vec![byte]);
        }
        for byte in *b"-._~" {
            assert_eq!(escape(&[byte]), vec![byte], "ISURLPUNTCS {byte:?}");
        }

        // The sub-delimiters and generic delimiters RFC 3986 names are NOT in
        // curl's unreserved set, even though several readings of that document
        // would leave some of them alone.
        for byte in *b"+/:%&=?#@$!*'(),;" {
            assert_eq!(
                escape(&[byte]),
                escape_one_by_hand(byte),
                "byte {byte:?} must be escaped"
            );
        }
        // And the boundaries of the alphanumeric ranges, from outside.
        for byte in [b'/', b':', b'@', b'[', b'`', b'{', 0x7F, 0x80, 0xFF] {
            assert_eq!(escape(&[byte]).len(), 3, "byte {byte:#04X}");
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
        assert_eq!(unescape(b"%41"), vec![0x41]);
        assert_eq!(unescape(b"%4"), b"%4".to_vec());
        assert_eq!(unescape(b"%"), b"%".to_vec());
        assert_eq!(unescape(b""), Vec::<u8>::new());
        // The same boundary reached by exhausting a longer input, which is the
        // case the counting decides rather than the initial length.
        assert_eq!(unescape(b"ab%41"), b"abA".to_vec());
        assert_eq!(unescape(b"ab%4"), b"ab%4".to_vec());
        assert_eq!(unescape(b"x%4"), b"x%4".to_vec());
        // A '%' whose lookahead is another '%' consumes only itself, so the
        // second '%' is examined again and does introduce an escape.
        assert_eq!(unescape(b"%%41"), b"%A".to_vec());
        assert_eq!(unescape(b"%%%%"), b"%%%%".to_vec());
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
            assert_eq!(unescape(input), expected.to_vec(), "{input:02X?}");
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
        assert_eq!(unescape(b"%2f"), b"/".to_vec());
        assert_eq!(unescape(b"%2F"), b"/".to_vec());
        for byte in 0..=255u8 {
            let upper = format!("%{byte:02X}");
            let lower = format!("%{byte:02x}");
            assert_eq!(unescape(upper.as_bytes()), vec![byte]);
            assert_eq!(unescape(lower.as_bytes()), vec![byte]);
        }
        // Mixed within one triplet, which the C admits because it classifies
        // each digit on its own.
        assert_eq!(unescape(b"%aB%Cd"), vec![0xAB, 0xCD]);
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
        assert_eq!(escape(b""), Vec::<u8>::new());
        assert_eq!(unescape(b""), Vec::<u8>::new());
        assert_eq!(unescape(b"").len(), 0);
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
                Ok(unescape(&input)),
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
        assert_eq!(unescape(b"a%00b"), vec![b'a', 0x00, b'b']);
        assert_eq!(unescape(b"a%00b").len(), 3);
        assert_eq!(unescape(b"%00%00"), vec![0x00, 0x00]);
        assert_eq!(unescape(b"%00%00").len(), 2);
        assert_eq!(unescape(b"%41%00%42"), vec![0x41, 0x00, 0x42]);
        // A literal NUL in the input survives just as an encoded one does.
        assert_eq!(unescape(b"a\0b").len(), 3);
        // And escaping is the inverse: a NUL becomes a full triple rather than
        // ending the output.
        assert_eq!(escape(b"a\0b"), b"a%00b".to_vec());
    }

    #[test]
    fn escape_and_unescape_round_trip_over_every_byte() {
        // Not a property the C documents, but one it has: the escaped form of
        // any byte string decodes back to it, because every byte is either
        // unreserved -- and so not a '%' -- or emitted as a full triple.
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(unescape(&escape(&all)), all);
        for byte in 0..=255u8 {
            assert_eq!(unescape(&escape(&[byte])), vec![byte]);
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
                unescape(&escape(probe)),
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
        assert_eq!(escape(b"\xc3\x28"), b"%C3%28".to_vec());
        assert_eq!(unescape(b"%c3%28"), vec![0xC3, 0x28]);
        assert_eq!(unescape(b"%C3%28"), vec![0xC3, 0x28]);
        // A lone surrogate and an overlong form, neither of which is valid
        // UTF-8 and both of which are ordinary bytes here.
        assert_eq!(escape(b"\xed\xa0\x80"), b"%ED%A0%80".to_vec());
        assert_eq!(escape(b"\xc0\x80"), b"%C0%80".to_vec());
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
        assert!(output_len_fits_int(unescape(b"%41%41%41%41").len()));
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
            let produced = unescape(input);
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
            let produced = escape(input);
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
        assert_eq!(unescape(b"%41%41%41%41"), b"AAAA".to_vec());

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
        assert_eq!(escape(b"data to convert"), b"data%20to%20convert".to_vec());
        // `docs/libcurl/curl_easy_unescape.md:61`, whose expected output the
        // manual page names in its surrounding prose.
        assert_eq!(unescape(b"%63%75%72%6c"), b"curl".to_vec());
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
            let decoded = unescape(probe);
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
            let encoded = escape(probe);
            assert!(encoded.len() <= probe.len() * 3);
            assert!(encoded.len() >= probe.len());
            assert!(encoded.is_ascii(), "escape output is always ASCII");
            assert!(!encoded.contains(&0), "escape output has no NUL");
        }
    }
}
