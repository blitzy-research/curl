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
// 1. The 23-line banner above is the block measured at `lib/urlapi.c:1-23`,
//    rendered as Rust line comments with the C block-comment decorations
//    stripped. Byte-identical to `src/lib.rs`, `src/error.rs`,
//    `src/url/escape.rs`, `src/url/idn.rs`, `src/util/strparse.rs` and
//    `src/version.rs`. The licence-identifier line is line 21 and is
//    verbatim; it is the only place in this file where that spelling
//    appears, which is what `reuse lint` needs. `REUSE.toml` does not list
//    this path, so the annotation has to be in-file.
//    `scripts/spacecheck.pl`, run by the `spacecheck` step of
//    `.github/workflows/hygiene.yml`, additionally rejects tabs, trailing
//    whitespace, consecutive blank lines and any byte at or above 0x80 in a
//    tracked file, so every byte below is plain ASCII.
//
// 2. `dead_code` allowances are written at the ITEM, never on a module
//    declaration and never at a file root. `mod source_policy` in
//    `curl-rs-lib/src/lib.rs` enforces that as an executable gate. Each one
//    below names the C call site that will remove it.
//
// 3. No level for the `unsafe_code` lint is set here, at any level. The
//    crate root carries `#![deny(unsafe_code)]` and grants exactly one
//    exemption, on `mod ffi`; this file is not it and contains no such
//    attribute. That matters here because the C original is pointer
//    arithmetic throughout -- `lib/urlapi.c` walks NUL-terminated buffers
//    with hand-carried lengths, rewrites host names in place through a
//    `char *`, and in one measured case reads past the end of its own input
//    (see [`redirect_url`]). Slices and explicit offsets replace all of it.
//
// 4. No raw string literal appears below. `code_only` in `mod source_policy`
//    does not lex `r"..."`, and a raw string introduced under
//    `curl-rs-lib/src` fails that gate rather than silently costing the
//    `unsafe` scan its coverage.
//
// 5. Nothing here calls `unwrap`, `expect` or `panic!` outside
//    `#[cfg(test)]`, and no expression can panic on a bounds check or on
//    arithmetic overflow. A panic in this module would unwind towards a C
//    caller through `curl-rs-ffi`, which is undefined behaviour. Every
//    index goes through [`at`] or a slice pattern, and every length
//    computation is checked or saturating.

//! The URL API, percent-encoding and internationalised domain names.
//!
//! Supersedes `lib/urlapi.c` (1,998 lines) and its internal header
//! `lib/urlapi-int.h` (40 lines), together with `lib/escape.c` and
//! `lib/idn.c` in the sibling modules. `pub` because it backs eight of the
//! 100 exported symbols: the six-strong URL API -- `curl_url`,
//! `curl_url_cleanup`, `curl_url_dup`, `curl_url_get`, `curl_url_set` and
//! `curl_url_strerror` (`include/curl/urlapi.h:112-149`) -- together with
//! `curl_escape` and `curl_unescape`.
//!
//! The pinned ABI is `include/curl/urlapi.h`: the 33 `CURLUcode` tokens at
//! `:34-68`, the 11 `CURLUPart` members at `:70-82`, the 16 `CURLU_*` flags
//! at `:84-105` and the handle typedef at `:107`. The error enumeration
//! itself is **not** declared here -- [`crate::error::CURLUcode`] owns it,
//! along with the message table behind `curl_url_strerror`
//! (`lib/strerror.c:420-531`).
//!
//! Nothing in this module is `extern "C"` and nothing carries
//! `#[no_mangle]`. The six exported wrappers live in
//! `curl-rs-ffi/src/ffi/url.rs`, which AAP section 0.8.5 conflict C1
//! sanctions as one of exactly two `src/ffi/` locations; a stray exported
//! symbol here would corrupt the 100-symbol `nm` parity gate against
//! `lib/libcurl.def`. This module is the safe engine those wrappers call.
//!
//! # `CURLU` is the one public handle that is a real struct
//!
//! The handle typedefs of the public headers are deliberately **not**
//! uniform, and treating them uniformly breaks consumers. `CURL`, `CURLM`
//! and `CURLSH` are `typedef void` (`include/curl/curl.h:109-110`,
//! `include/curl/multi.h:57`), so a consumer may assign any of them to a
//! `void *` and many do. `CURLU` alone is
//! `typedef struct Curl_URL CURLU` (`include/curl/urlapi.h:107`) -- a
//! genuine opaque struct. Its representation is therefore part of the
//! contract in a way the others' is not, and `curl-rs-ffi` carries it as an
//! opaque pointer to [`Url`] rather than as a `*mut c_void`, moving
//! ownership across the boundary with `Box::into_raw` and `Box::from_raw`
//! (AAP section 0.3.3, pattern P8).
//!
//! # curl's parsing quirks are preserved, not delegated
//!
//! AAP section 0.4.1 is explicit: *"curl's parsing quirks preserved rather
//! than delegated wholesale to the `url` crate"*. The `url` crate is a
//! workspace dependency and is used where it helps, but the WHATWG URL
//! Standard it implements is not the specification curl implements, and the
//! differences are directly observable -- through `curl_url_get` part by
//! part, and through the fixture corpus, whose comparison joins the expected
//! and actual protocol blocks into single strings and compares them whole
//! (AAP section 0.6.7). Where curl and a general-purpose parser disagree,
//! curl wins, and the disagreement is documented at the site that
//! implements it. The measured divergences are the scheme accept set, the
//! three scheme-guessing flags, [`UrlFlags::ALLOW_SPACE`],
//! [`UrlFlags::NO_AUTHORITY`], [`UrlFlags::PATH_AS_IS`],
//! [`UrlFlags::GET_EMPTY`]'s empty-versus-absent distinction, IPv6 zone
//! identifiers, and an IPv4 parser far more permissive than either
//! `std::net` or the `url` crate ([`ipv4_normalize`]).
//!
//! # Every part is a byte string, and that is not a stylistic choice
//!
//! The ten stored parts are `Option<Vec<u8>>`, not `Option<String>`, because
//! a host can hold bytes that are not UTF-8 at all. `tests/libtest/lib1560.c`
//! requires `https://_%c0_` to store the host `_\xC0_` and to render it back
//! raw, and requires a literal `\xFF` in a host to survive to
//! `%FF` under [`UrlFlags::URLENCODE`]. A `String` cannot hold either.
//!
//! The `Option` is equally load-bearing, and for a different reason: it
//! distinguishes a part that is absent from a part that is present and
//! empty. `https://x/?` stores an empty query **and** records
//! `query_present`, which [`UrlFlags::GET_EMPTY`] exposes;
//! `set(QUERY, "")` stores an empty query, while the same call with
//! [`UrlFlags::URLENCODE`] stores no query at all, because the C's encode
//! loop makes no append and `curlx_dyn_ptr` then answers null
//! (`lib/urlapi.c:1934`, and see [`Buf`]). `None` and `Some(vec![])` are
//! never interchangeable below.
//!
//! # The measured constants
//!
//! `MAX_SCHEME_LEN` is 40 (`lib/urlapi.c:55`), `DEFAULT_SCHEME` is
//! `"https"` (`:84`), and `CURL_MAX_INPUT_LENGTH` is 8,000,000
//! (`lib/urldata.h:131`) -- the ceiling on every input this module accepts
//! and on every buffer it fills. The struct being reproduced is at `:67-82`;
//! the `CURLcode`-to-`CURLUcode` bridge is `cc2cu` at `:120-122`; the
//! default ports come from the injected registry rather than from a table
//! here, and `lib/urldata.h:29-53` is where the C keeps them.
//!
//! Three measured quirks are reproduced deliberately and are each guarded by
//! a test, because each one looks like a defect and "fixing" it would break
//! the corpus: `curl_url_dup` does not copy `guessed_scheme`
//! (`lib/urlapi.c:1310-1332`); `allowed_in_path` admits **19** characters
//! including `/` at `:1799` where the manual page lists 18; and
//! `curl_url_set` lower-cases pre-existing percent triplets when
//! [`UrlFlags::URLENCODE`] is absent (`:1922-1932`) even though the encoder
//! it shares a directory with emits upper case.
//!
//! # The modules declared here
//!
//! [`escape`] carries percent-encoding and percent-decoding, superseding
//! `lib/escape.c`. It is `pub` because four of the 100 exported symbols are
//! backed from it -- `curl_easy_escape` and `curl_easy_unescape` together
//! with the two ABI-compatibility forwarders `curl_escape` and
//! `curl_unescape`, which `lib/escape.c:36-45` defines as nothing but calls
//! into them.
//!
//! It is a module of its own rather than part of the URL parser because the
//! transformation is independent of any parsed URL: the four exported
//! functions ignore the `CURL *` handle they accept, and have done since
//! 7.82.0 (`lib/escape.c:48`, `:161`). The parser is a consumer of the
//! module, not the other way round -- this file is the caller that retires
//! the `dead_code` allowance on its two strict `urlreject` modes, selecting
//! `REJECT_CTRL` at the three sites `lib/urlapi.c:590`, `:1385` and `:1980`
//! measure.
//!
//! [`idn`] carries internationalised domain names, superseding `lib/idn.c`
//! with the `idna` crate in place of libidn2. It is separable from the rest
//! of the URL surface because it is a pure host-name transformation with no
//! dependency on a parsed URL, and it additionally owns two capability
//! predicates that the version banner consumes -- which is why it is `pub`
//! rather than `pub(crate)`: `lib/version.c:407-416` computes `idn_present`
//! and `lib/version.c:496` registers it as `FEATURE("IDN", idn_present,
//! CURL_VERSION_IDN)`, so the answer has to be reachable from
//! [`crate::version`] and, through it, from `curl_version_info`.
//!
//! One consequence of that decoupling is recorded here because it is easy to
//! get wrong in the other direction: an `idna`-backed build advertises the
//! `IDN` feature yet reports no `libidn` version, because libidn2 is not
//! what is linked. In C those two are coupled -- `idn_present` *is*
//! `info->libidn != NULL` -- so reproducing the coupling would mean emitting
//! a `libidn2/...` token, which additionally sets `$feature{"libidn2"}` in
//! the test harness (`tests/runtests.pl:625-626`) on a false premise.
//! Truthful advertisement is the requirement (AAP section 0.6.5), and it
//! decouples them.
//!
//! Because `idna` is unconditional in this workspace and AAP section 0.5.2
//! closes the feature vocabulary at 15 names with no `idn` among them,
//! `CURLUE_LACKS_IDN` (30) is unreachable from this module. The variant
//! stays because it is ABI. In C it comes from
//! `#define host_decode(x, y) CURLUE_LACKS_IDN` at `lib/urlapi.c:1335-1336`,
//! active only when `USE_IDN` is undefined.

use core::fmt;
use core::ops::{BitOr, BitOrAssign};

use crate::error::{CURLUcode, CURLcode, UrlResult};
use crate::util::inet;
use crate::util::memrchr::memrchr;
use crate::util::strcase;
use crate::util::strparse;

/// Percent-encoding and percent-decoding: supersedes `lib/escape.c`.
///
/// Owns the unreserved-byte set, the uppercase hex digits, and the decode
/// walk's strict `alloc > 2` lookahead test, each asserted against a
/// self-describing oracle measured from the frozen library.
///
/// `pub` because [`escape::escape`] and [`escape::unescape`] back four of the
/// 100 symbols `lib/libcurl.def` exports, and `curl-rs-ffi` has no other
/// route to them.
pub mod escape;

/// Internationalised domain names: supersedes `lib/idn.c`.
///
/// Converts hostnames between their Unicode and A-label forms with the
/// `idna` crate, reproducing curl's acceptance rules and error codes, and
/// answers the two capability questions the `--version` banner asks about
/// IDN support.
///
/// `pub` for that second reason: [`idn::available`] and
/// [`idn::version_string`] are the authority behind the `IDN` feature bit
/// and the `libidn` field of `curl_version_info_data`, both of which cross
/// the C ABI.
pub mod idn;

/// The longest scheme this module accepts, in bytes.
///
/// `MAX_SCHEME_LEN` (`lib/urlapi.c:55`), whose own comment reads *"scheme is
/// not URL encoded, the longest libcurl supported ones are..."*. Consumed at
/// `:195` (the scheme scan), `:1114` (`char schemebuf[MAX_SCHEME_LEN + 1]`),
/// `:1452` (`char schemebuf[MAX_SCHEME_LEN + 5]`, the four extra bytes being
/// `"://"` and its terminator) and `:1641` (the length test on set).
///
/// Note that a scheme this long can never be *resolved*: `Curl_getn_scheme`
/// is gated `if(len && (len <= 7))` (`lib/url.c:1523`), so no registry entry
/// longer than seven bytes is reachable. Both bounds are deliberate and both
/// are reproduced -- the 40 here, and the seven in whatever implements
/// [`SchemeRegistry`].
const MAX_SCHEME_LEN: usize = 40;

/// The universal input ceiling, in bytes.
///
/// `CURL_MAX_INPUT_LENGTH` (`lib/urldata.h:131`), described there as *"a
/// precaution against abuse and to detect junk input easier and better"*.
/// Tested directly by [`junkscan`] (`lib/urlapi.c:229`) and by [`Url::set`]
/// (`:1824`), and used as the `toobig` ceiling of every dynamic buffer in
/// the C file: `:664`, `:1021`, `:1044`, `:1072`, `:1122`, `:1272`, `:1394`,
/// `:1485` and `:1944`.
///
/// `docs/libcurl/curl_url_set.md:277-278` states the consequence for the
/// public API: an input longer than eight million bytes yields
/// `CURLUE_MALFORMED_INPUT`.
const MAX_INPUT_LENGTH: usize = 8_000_000;

/// The scheme [`UrlFlags::DEFAULT_SCHEME`] supplies.
///
/// `DEFAULT_SCHEME` (`lib/urlapi.c:84`). Used when parsing a URL that has no
/// scheme at all (`:968`) and when rendering one (`:1456`).
const DEFAULT_SCHEME: &[u8] = b"https";

/// What curl's own `printf` writes for a null `%s` argument.
///
/// `nilstr` (`lib/mprintf.c:837`), and it is reachable through the public
/// API. `urlget_url` guards `u->query` and `u->fragment` with
/// `x ? x : ""` but passes `u->path` unguarded (`lib/urlapi.c:1442`), so a
/// `file:` handle with no stored path renders as `file://(nil)`. Measured
/// against a real libcurl: `curl_url_set(u, CURLUPART_URL, "file:///", 0)`
/// followed by `curl_url_get(u, CURLUPART_URL, &p, 0)` yields exactly that
/// string, while `curl_url_get(u, CURLUPART_PATH, ...)` yields `/`.
///
/// Reproduced rather than repaired. AAP section 0.8.1 freezes observable
/// behaviour and AAP section 0.8.2 rejects a refactor that produces
/// different-but-arguably-better output; a caller that has learned to
/// recognise this string would stop recognising it.
const NIL_STRING: &[u8] = b"(nil)";

/// The bytes `hostname_check` refuses in a host that is not bracketed.
///
/// Transcribed byte for byte from the second argument of the `strcspn` at
/// `lib/urlapi.c:456`. Thirty-one bytes, in the C's own order, so that a
/// diff against the source is a character-by-character comparison rather
/// than a judgement:
///
/// ```text
/// " \r\n\t/:#?!@{}[]\\$\'\"^`*<>=;,+&()%"
/// ```
///
/// The set is a denial list, not an allow list, which is why a host may hold
/// bytes at or above 0x80 -- an IDN host does, and
/// `tests/libtest/lib1560.c` requires those bytes to survive.
const HOST_REJECT: &[u8] = b" \r\n\t/:#?!@{}[]\\$'\"^`*<>=;,+&()%";

/// The bytes `ipv6_parse` accepts inside brackets before a zone identifier.
///
/// The second argument of the `strspn` at `lib/urlapi.c:401`. Both hex cases
/// are listed because the C lists both, and `.` is present because an
/// embedded dotted quad is legal in the tail of an IPv6 literal.
const IPV6_ACCEPT: &[u8] = b"0123456789abcdefABCDEF:.";

// ---------------------------------------------------------------------------
// Reading a byte string the way C reads one.
//
// `lib/urlapi.c` works on NUL-terminated buffers and carries lengths
// alongside them, so it routinely reads one byte past the extent it is
// counting -- `url[i]` after the scheme scan, `p[1]` and `p[2]` behind a
// length test, `*portptr` after a number. Every one of those reads lands on
// the terminator, and the code depends on the terminator not matching
// whatever it is looking for.
//
// The three helpers below reproduce that exactly over slices, so a read past
// the end answers zero rather than panicking, and `strspn` and `strcspn`
// treat zero as the end of the string just as the C library does. Nothing
// else in this file indexes a slice.
// ---------------------------------------------------------------------------

/// The byte at `index`, or zero past the end.
///
/// The C's `bytes[index]` on a NUL-terminated buffer. Every read in this
/// module that the C performs at or beyond its counted extent goes through
/// here, which is what makes a bounds panic unwritable.
fn at(bytes: &[u8], index: usize) -> u8 {
    match bytes.get(index) {
        Some(byte) => *byte,
        None => 0,
    }
}

/// The length of the leading run of bytes drawn from `accept`.
///
/// `strspn`. A zero byte is not a member of any set this module passes, so
/// the run stops there exactly as the C's does at the terminator.
fn spn(bytes: &[u8], accept: &[u8]) -> usize {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == 0 || !accept.contains(byte) {
            return index;
        }
    }
    bytes.len()
}

/// The length of the leading run of bytes absent from `reject`.
///
/// `strcspn`. The zero test is explicit rather than incidental: the C stops
/// at the terminator whether or not it is in the reject set, so a byte
/// string carrying an interior zero measures short here too, which is what
/// makes an embedded NUL fail [`hostname_check`] rather than pass it.
fn cspn(bytes: &[u8], reject: &[u8]) -> usize {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == 0 || reject.contains(byte) {
            return index;
        }
    }
    bytes.len()
}

/// The offset of the first `needle`, or [`None`].
///
/// `strchr`, terminator semantics included: the search stops at a zero byte,
/// so `needle` cannot be found beyond one. `needle` is never zero at any
/// call site below.
fn strchr(bytes: &[u8], needle: u8) -> Option<usize> {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == needle {
            return Some(index);
        }
        if *byte == 0 {
            return None;
        }
    }
    None
}

/// Converts a [`CURLcode`] from a buffer or an escape into a [`CURLUcode`].
///
/// The whole of `cc2cu` (`lib/urlapi.c:120-122`):
///
/// ```c
/// #define cc2cu(x) \
///   ((x) == CURLE_TOO_LARGE ? CURLUE_TOO_LARGE : CURLUE_OUT_OF_MEMORY)
/// ```
///
/// Applied by the C at `:170`, `:598`, `:623`, `:893`, `:1885`, `:1905`,
/// `:1912` and `:1920`. Every one of those sites is a buffer append, whose
/// only two failures are the ceiling and a refused allocation -- so the
/// collapse to two codes loses nothing, and any other code arriving here
/// becomes `CURLUE_OUT_OF_MEMORY` exactly as the C's conditional does.
const fn cc2cu(code: CURLcode) -> CURLUcode {
    match code {
        CURLcode::TooLarge => CURLUcode::TooLarge,
        _ => CURLUcode::OutOfMemory,
    }
}

/// An append-only byte buffer with a ceiling, distinguishing "never written"
/// from "written empty".
///
/// Supersedes the `struct dynbuf` uses of `lib/urlapi.c` -- and
/// deliberately **not** by calling [`crate::util::dynbuf::DynBuf`], which is
/// the faithful transcription of that type everywhere else in this crate.
/// The reason is one documented simplification: `DynBuf::as_slice` answers an
/// empty slice where the C answers a null pointer, on the stated grounds
/// that "an empty slice answers the only question they are really asking".
/// That is true of every other caller in the tree and false of this one.
/// `curl_url_set` stores `curlx_dyn_ptr(&enc)` **as** the part
/// (`lib/urlapi.c:1934`, `:1995`), so a buffer that was never appended to
/// stores a null pointer -- the part becomes absent -- while a buffer
/// appended with zero bytes stores an empty string. Both are reachable from
/// one line of caller code and they differ observably:
///
/// ```text
/// curl_url_set(u, CURLUPART_QUERY, "", 0)               -> query is ""
/// curl_url_set(u, CURLUPART_QUERY, "", CURLU_URLENCODE) -> query is absent
/// ```
///
/// Measured against a real libcurl, and the mechanism is exactly this: the
/// encode loop at `:1890-1914` iterates over an empty string and appends
/// nothing at all, whereas `curlx_dyn_add` at `:1918` appends unconditionally
/// and `dyn_nappend` allocates even for a zero-length append
/// (`lib/curlx/dynbuf.c:75-102`, where `fit` is `len + idx + 1` and is
/// therefore never zero).
///
/// So this type keeps the distinction in its type: the payload is an
/// [`Option`], `None` is the C's null `bufr`, and any append -- including one
/// of no bytes -- materialises it.
struct Buf {
    /// The bytes appended so far. [`None`] until the first append, which is
    /// the C's `bufr` starting as null.
    bytes: Option<Vec<u8>>,

    /// The ceiling, as `curlx_dyn_init` was given it.
    toobig: usize,
}

impl Buf {
    /// Creates an empty buffer with `toobig` as its ceiling.
    ///
    /// `curlx_dyn_init` (`lib/curlx/dynbuf.c:38-50`), which allocates
    /// nothing and cannot fail. Neither does this.
    const fn new(toobig: usize) -> Self {
        Self {
            bytes: None,
            toobig,
        }
    }

    /// Appends `mem`, or empties the buffer and reports the ceiling.
    ///
    /// `curlx_dyn_addn` by way of `dyn_nappend`
    /// (`lib/curlx/dynbuf.c:67-119`). Two behaviours of that function are
    /// load-bearing here and both are reproduced:
    ///
    /// * the ceiling test is `fit > s->toobig` where `fit` is
    ///   `len + idx + 1`, the trailing byte being the terminator the C
    ///   stores and this type does not. Dropping the `+ 1` would admit an
    ///   input the C refuses, and one call site sizes its ceiling so tightly
    ///   that the difference is reachable -- `curl_url_set` asks for
    ///   `nalloc * 3 + 1 + leadingslash` (`:1880`), which an all-escaped
    ///   input fills to the byte.
    /// * crossing the ceiling calls `curlx_dyn_free`, so the buffer is left
    ///   **null**, not merely empty. A caller that ignores the error and
    ///   reads the pointer afterwards therefore sees absence.
    ///
    /// The addition is saturating because `mem.len()` is caller-controlled;
    /// saturation can only push `fit` above the ceiling, which is the
    /// rejecting branch, so it cannot admit anything the C refuses.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] when the append would cross the ceiling. The
    /// C's other failure, a refused allocation, has no expression here:
    /// `Vec` aborts rather than reporting it.
    fn addn(&mut self, mem: &[u8]) -> Result<(), CURLcode> {
        let fit = mem.len().saturating_add(self.len()).saturating_add(1);
        if fit > self.toobig {
            self.bytes = None;
            return Err(CURLcode::TooLarge);
        }
        self.bytes
            .get_or_insert_with(Vec::new)
            .extend_from_slice(mem);
        Ok(())
    }

    /// The accumulated bytes, empty when there are none.
    ///
    /// For the C's `curlx_dyn_ptr` results that are immediately handed to a
    /// function reading a counted extent, where null and empty behave
    /// identically because the count is zero.
    fn as_slice(&self) -> &[u8] {
        match &self.bytes {
            Some(bytes) => bytes,
            None => &[],
        }
    }

    /// The accumulated bytes for in-place mutation, empty when there are
    /// none.
    ///
    /// The C mutates a buffer through the very pointer `curlx_dyn_ptr`
    /// returned, without a dedicated accessor for it. The one place this
    /// module needs that is `curl_url_set`'s percent-triplet lower-casing walk
    /// at `lib/urlapi.c:1922-1932`, which rewrites the assembled buffer in
    /// place before it is stored.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.bytes {
            Some(bytes) => bytes,
            None => &mut [],
        }
    }

    /// The number of bytes held.
    ///
    /// `curlx_dyn_len` (`lib/curlx/dynbuf.c:271-277`), which is the C's
    /// `leng` and excludes the terminator.
    fn len(&self) -> usize {
        match &self.bytes {
            Some(bytes) => bytes.len(),
            None => 0,
        }
    }

    /// Empties the buffer without releasing it.
    ///
    /// `curlx_dyn_reset` (`lib/curlx/dynbuf.c:227-235`), which zeroes the
    /// first byte and sets `leng` to zero but leaves `bufr` alone. So a
    /// buffer that had been appended to stays non-null after a reset, and one
    /// that had not stays null -- a distinction `parse_file` depends on when
    /// it resets the host buffer at `lib/urlapi.c:912`.
    fn reset(&mut self) {
        if let Some(bytes) = &mut self.bytes {
            bytes.clear();
        }
    }

    /// Truncates the buffer to `set` bytes.
    ///
    /// `curlx_dyn_setlen` (`lib/curlx/dynbuf.c:279-289`), which refuses a
    /// `set` above the current length with `CURLE_BAD_FUNCTION_ARGUMENT`.
    /// Infallible here, and equivalently so: the C's two callers --
    /// `Curl_parse_port` at `:370` and `dedotdotify` at `:787` -- both
    /// discard the return value, and `Vec::truncate` above the length is the
    /// same no-op the C performs on the field it declines to change.
    fn setlen(&mut self, set: usize) {
        if let Some(bytes) = &mut self.bytes {
            bytes.truncate(set);
        }
    }

    /// Hands the accumulated bytes to the caller, leaving the buffer null.
    ///
    /// The C's idiom of storing `curlx_dyn_ptr` into a struct field and never
    /// freeing the buffer, which transfers the allocation. `None` here is
    /// that same transfer of a null pointer.
    fn take(&mut self) -> Option<Vec<u8>> {
        self.bytes.take()
    }
}

/// Which component of a URL a get or a set addresses.
///
/// `CURLUPart` (`include/curl/urlapi.h:70-82`). Eleven members occupying
/// `0..=10` with no gaps and none of them explicit in C, so the explicit
/// discriminants below are the drift guard the C header does not have.
/// `CURLUPART_ZONEID` is annotated *"added in 7.65.0"* there.
///
/// A discriminant outside `0..=10` is not representable, which is the point:
/// [`Self::from_i32`] is the single place an unknown value from a C caller
/// becomes [`CURLUcode::UnknownPart`], and every `match` over this type below
/// is exhaustive without a fall-through arm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum UrlPart {
    /// `CURLUPART_URL` (0) -- the whole URL, assembled or parsed.
    Url = 0,
    /// `CURLUPART_SCHEME` (1).
    Scheme = 1,
    /// `CURLUPART_USER` (2).
    User = 2,
    /// `CURLUPART_PASSWORD` (3).
    Password = 3,
    /// `CURLUPART_OPTIONS` (4) -- the `;options` tail of the userinfo, which
    /// only a scheme with [`SchemeInfo::url_options`] parses out of a URL.
    Options = 4,
    /// `CURLUPART_HOST` (5).
    Host = 5,
    /// `CURLUPART_PORT` (6).
    Port = 6,
    /// `CURLUPART_PATH` (7).
    Path = 7,
    /// `CURLUPART_QUERY` (8).
    Query = 8,
    /// `CURLUPART_FRAGMENT` (9).
    Fragment = 9,
    /// `CURLUPART_ZONEID` (10) -- the IPv6 scope identifier, kept as text.
    ZoneId = 10,
}

impl UrlPart {
    /// Every member, in declaration order.
    ///
    /// Exists so that a test can walk the enumeration rather than restate
    /// it, which is how the eleven-member count stays asserted.
    pub const VARIANTS: &'static [Self] = &[
        Self::Url,
        Self::Scheme,
        Self::User,
        Self::Password,
        Self::Options,
        Self::Host,
        Self::Port,
        Self::Path,
        Self::Query,
        Self::Fragment,
        Self::ZoneId,
    ];

    /// The C enumerator's integer value.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The member with this integer value, or [`None`].
    ///
    /// The C has no counterpart because C has no such check: passing 9999 to
    /// `curl_url_get` simply falls through the `switch` to the `default:` arm
    /// at `lib/urlapi.c:1626`, which leaves `ifmissing` at its initial
    /// `CURLUE_UNKNOWN_PART`. `curl_url_set` does the same at `:1873`, and so
    /// does `urlset_clear` at `:1773`. [`Url::get_by_id`] and
    /// [`Url::set_by_id`] are where that mapping happens here, so this
    /// answering [`None`] is what stands in for all three arms.
    #[must_use]
    pub const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Url),
            1 => Some(Self::Scheme),
            2 => Some(Self::User),
            3 => Some(Self::Password),
            4 => Some(Self::Options),
            5 => Some(Self::Host),
            6 => Some(Self::Port),
            7 => Some(Self::Path),
            8 => Some(Self::Query),
            9 => Some(Self::Fragment),
            10 => Some(Self::ZoneId),
            _ => None,
        }
    }
}

/// The `CURLU_*` bitmask a get or a set is modified by.
///
/// The sixteen flags of `include/curl/urlapi.h:84-105`, which occupy
/// `1 << 0` through `1 << 15` with no gaps. A newtype over `u32` rather than
/// a `bitflags` dependency: AAP section 0.5.1 pins the dependency set and
/// nothing in it is a bitflag crate, so adding one is out of scope.
///
/// The bits are not independent. The interactions, each measured:
///
/// * [`Self::DEFAULT_SCHEME`] **overrides** [`Self::GUESS_SCHEME`] when both
///   are set, because `parse_scheme` tests it first (`lib/urlapi.c:967`) and
///   the guess at `:1151` is conditional on no scheme having been stored.
///   `docs/libcurl/curl_url_set.md:201-210` documents it.
/// * [`Self::URLENCODE`] **wins over** [`Self::PUNYCODE`] and
///   [`Self::PUNY2IDN`], because the three are the arms of one `else if`
///   chain and it is first (`:1392-1420`, `:1492-1510`).
/// * [`Self::GUESS_SCHEME`] acts on set and [`Self::NO_GUESS_SCHEME`] on
///   get. They are not opposites and both may be passed to either call.
/// * [`Self::DEFAULT_PORT`] applies only when no port is stored and
///   [`Self::NO_DEFAULT_PORT`] only when one is, so they cannot both act on
///   one call (`:1461-1475`, `:1586-1602`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct UrlFlags(u32);

impl UrlFlags {
    /// No flag at all: the C's `0`.
    pub const NONE: Self = Self(0);

    /// `CURLU_DEFAULT_PORT` (1 << 0) -- return the scheme's default port
    /// when the handle stores none.
    pub const DEFAULT_PORT: Self = Self(1 << 0);

    /// `CURLU_NO_DEFAULT_PORT` (1 << 1) -- suppress a stored port that
    /// equals the scheme's default.
    pub const NO_DEFAULT_PORT: Self = Self(1 << 1);

    /// `CURLU_DEFAULT_SCHEME` (1 << 2) -- supply [`DEFAULT_SCHEME`] when the
    /// handle stores none.
    pub const DEFAULT_SCHEME: Self = Self(1 << 2);

    /// `CURLU_NON_SUPPORT_SCHEME` (1 << 3) -- accept a scheme the registry
    /// does not know.
    pub const NON_SUPPORT_SCHEME: Self = Self(1 << 3);

    /// `CURLU_PATH_AS_IS` (1 << 4) -- leave dot segments in the path.
    pub const PATH_AS_IS: Self = Self(1 << 4);

    /// `CURLU_DISALLOW_USER` (1 << 5) -- refuse a URL carrying credentials.
    pub const DISALLOW_USER: Self = Self(1 << 5);

    /// `CURLU_URLDECODE` (1 << 6) -- percent-decode on get.
    pub const URLDECODE: Self = Self(1 << 6);

    /// `CURLU_URLENCODE` (1 << 7) -- percent-encode on set.
    pub const URLENCODE: Self = Self(1 << 7);

    /// `CURLU_APPENDQUERY` (1 << 8) -- append to the existing query rather
    /// than replace it.
    pub const APPENDQUERY: Self = Self(1 << 8);

    /// `CURLU_GUESS_SCHEME` (1 << 9) -- guess the scheme from the host name,
    /// curl's legacy command-line behaviour.
    pub const GUESS_SCHEME: Self = Self(1 << 9);

    /// `CURLU_NO_AUTHORITY` (1 << 10) -- allow an empty authority.
    pub const NO_AUTHORITY: Self = Self(1 << 10);

    /// `CURLU_ALLOW_SPACE` (1 << 11) -- allow a literal space in the URL.
    pub const ALLOW_SPACE: Self = Self(1 << 11);

    /// `CURLU_PUNYCODE` (1 << 12) -- return the host in its A-label form.
    pub const PUNYCODE: Self = Self(1 << 12);

    /// `CURLU_PUNY2IDN` (1 << 13) -- return the host in its Unicode form.
    pub const PUNY2IDN: Self = Self(1 << 13);

    /// `CURLU_GET_EMPTY` (1 << 14) -- expose a query or fragment that is
    /// present and empty.
    pub const GET_EMPTY: Self = Self(1 << 14);

    /// `CURLU_NO_GUESS_SCHEME` (1 << 15) -- on get, treat a guessed scheme
    /// as absent.
    pub const NO_GUESS_SCHEME: Self = Self(1 << 15);

    /// Wraps a raw bitmask, as `curl_url_get` and `curl_url_set` receive it.
    ///
    /// Unknown bits are preserved rather than rejected, which is the C's
    /// behaviour: it tests individual bits and never validates the mask.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw bitmask.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every bit of `other` is set here.
    ///
    /// The C's `flags & CURLU_SOMETHING`, with the caveat that `other` is a
    /// single flag at every call site below, so "every bit" and "the bit"
    /// coincide.
    #[must_use]
    pub const fn has(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// This mask with `other` added.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// This mask with `other` removed.
    ///
    /// The C's `flags &= ~CURLU_SOMETHING`, which `curl_url_get` performs on
    /// its own parameter for the scheme and the port
    /// (`lib/urlapi.c:1558`, `:1585`) and `redirect_url` performs on
    /// [`Self::PATH_AS_IS`] before re-parsing (`:1277`).
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl BitOr for UrlFlags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

impl BitOrAssign for UrlFlags {
    fn bitor_assign(&mut self, other: Self) {
        *self = self.union(other);
    }
}

/// The per-scheme facts the URL parser needs, and nothing else.
///
/// Mirrors the fields of `struct Curl_scheme` (`lib/urldata.h:515-524`) that
/// `lib/urlapi.c` actually reads. The full C struct additionally carries the
/// `CURLPROTO_*` bit, the protocol family and the remaining `PROTOPT_*`
/// flags; none of those is consulted by any line of the URL API, so none is
/// reproduced here.
///
/// This type is declared in `url/` rather than in `protocols/` on purpose.
/// AAP section 0.4.2 fixes an acyclic module graph and AAP section 0.3.3
/// pattern P12 makes the resolver, the clock and the TLS provider injected
/// rather than reached for; the same rule applies to the scheme table. If
/// `url/` imported `protocols/`, the URL API would depend on the transfer
/// engine, and every test of the parser would need the engine to exist. The
/// abstraction therefore lives with the consumer, and the concrete table is
/// supplied at construction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SchemeInfo {
    /// The scheme's name **as the registry stores it**.
    ///
    /// `const char *name` (`lib/urldata.h:516`), whose comment claims *"URL
    /// scheme name in lowercase"*. That comment is wrong for four of the 33
    /// entries: `"WS"` (`lib/ws.c:1985`), `"WSS"` (`lib/ws.c:2000`),
    /// `"SFTP"` (`lib/vssh/vssh.c:339`) and `"SCP"` (`lib/vssh/vssh.c:353`)
    /// are upper case. The table works only because
    /// `Curl_getn_scheme` folds case on both sides (`lib/url.c:1523-1538`).
    ///
    /// So **never compare this field case-sensitively**, and never assume it
    /// is lower case. Nothing in this module compares it at all: the scheme
    /// it stores comes from the input, folded to lower case by
    /// [`is_absolute_url`], and this field exists because a registry
    /// implementation needs somewhere to put the name it matched.
    pub name: &'static str,

    /// The scheme's default port.
    ///
    /// `uint16_t defport` (`lib/urldata.h:523`). Consulted only on get, at
    /// `lib/urlapi.c:1465`, `:1472`, `:1591` and `:1599`.
    ///
    /// The values are `lib/urldata.h:29-53`: HTTP 80, HTTPS 443, FTP 21,
    /// FTPS 990, SSH 22 for **both** SCP and SFTP, and zero for `file`,
    /// whose handler declares `defport 0`. That table is **not** duplicated
    /// here -- there is one source of truth for it and it is the registry.
    pub default_port: u16,

    /// Whether a `;options` tail is parsed out of this scheme's userinfo.
    ///
    /// `flags & PROTOPT_URLOPTIONS` (`lib/urldata.h:545`), set by exactly
    /// three protocol pairs: imap and imaps (`lib/imap.c:2341`, `:2359`),
    /// pop3 and pop3s (`lib/pop3.c:1730`, `:1747`) and smtp and smtps
    /// (`lib/smtp.c:2022`, `:2039`). All six are stubbed in this rewrite,
    /// which changes nothing here: the flag is consulted when extracting the
    /// options from a URL (`lib/urlapi.c:290`) and when rendering them back
    /// (`:1477`), and both must keep working for a scheme whose transfer
    /// implementation is absent.
    pub url_options: bool,

    /// Whether an implementation of this scheme is present.
    ///
    /// `h->run != NULL`. `lib/url.c:1473-1475` states the contract
    /// verbatim: *"Returns a struct scheme pointer if the name is a known
    /// scheme. Check the ->run struct field for non-NULL to figure out if an
    /// implementation is present."* A protocol disabled at build time stays
    /// in the table with `run = ZERO_NULL` -- measured at
    /// `lib/file.c:626-629`, `lib/ftp.c:4348-4351` and `:4367-4370`,
    /// `lib/http.c:5011-5014` and `:5028-5031`, `lib/ws.c:1984-1987` and
    /// `:1999-2002`, `lib/vssh/vssh.c:338-341` and `:352-355`, and
    /// `lib/smtp.c:2012-2018`.
    ///
    /// This field is why a bare port would not have been enough. **Parsing
    /// and setting disagree**: `parse_scheme` accepts any scheme in the table
    /// (`lib/urlapi.c:951`) while `set_url_scheme` additionally requires an
    /// implementation (`:1646`). So `curl_url_set(u, CURLUPART_URL,
    /// "smtp://host/", 0)` can succeed on a build where
    /// `curl_url_set(u, CURLUPART_SCHEME, "smtp", 0)` fails. Both predicates
    /// are reproduced and the asymmetry is tested.
    pub runnable: bool,
}

/// The scheme table, injected rather than imported.
///
/// # Implementing this
///
/// `lookup` must be **case-insensitive**, because `Curl_getn_scheme` folds
/// both sides (`lib/url.c:1523-1538`) and four of its entries are stored in
/// upper case. Fold with ASCII-only rules --
/// [`crate::util::strcase`] internally, or
/// `[u8]::eq_ignore_ascii_case` from outside the crate -- and never with
/// `char::to_lowercase`, which is Unicode-aware and would fold bytes curl
/// leaves alone.
///
/// `None` means "not a known scheme", the C's `h == NULL`. Answering
/// `Some(SchemeInfo { runnable: false, .. })` means something different and
/// weaker: the name is known but has no implementation. The two answers are
/// distinguished by the caller and produce different results, so a registry
/// must not collapse them.
///
/// Two measured bounds of the C's own lookup are worth preserving in an
/// implementation, and neither is enforced here because neither belongs to
/// this module. `Curl_getn_scheme` is gated `if(len && (len <= 7))`, so **no
/// scheme longer than seven bytes can ever resolve**, even though
/// [`MAX_SCHEME_LEN`] admits 40 on the way in. And the backing array is
/// declared `all_schemes[67]` (`lib/url.c:1488`) while only 33 entries are
/// defined: 67 is the modulus of the hash, **not a count**. AAP section
/// 0.3.3 pattern P4 records the same. Neither is a defect and neither should
/// be "corrected".
///
/// # The wiring contract, for the agents that land the rest of the workspace
///
/// This is a coordination item rather than an implementation note, and it is
/// written down here because nothing else in the tree states it yet.
///
/// `curl_url()` takes no arguments (`include/curl/urlapi.h:113`), so
/// `curl-rs-ffi/src/ffi/url.rs` has to obtain a registry from somewhere
/// without being handed one. The intended arrangement is:
///
/// * `curl-rs-lib/src/protocols/mod.rs`, which supersedes `lib/url.c`'s
///   33-entry `all_schemes[]`, implements this trait; and
/// * it exposes `pub fn scheme_registry() -> &'static dyn
///   crate::url::SchemeRegistry`, reachable from outside the crate.
///
/// `curl-rs-lib/src/lib.rs` declares `protocols` as `pub(crate)`, so that
/// function needs a `pub use` re-export at the crate root for `curl-rs-ffi`
/// to reach it. There is deliberately **no** global here to reach for
/// instead: no `static mut`, no lazily-initialised singleton, no
/// registration side effect. The registry is a constructor argument and
/// [`Url`] holds the borrow.
///
/// Whether the 24 out-of-scope schemes appear in that table is the
/// `protocols/` author's decision, not this module's, and this module is
/// correct either way because it reads [`SchemeInfo::runnable`] rather than
/// hard-coding a list. The recommendation is to register all 33 with
/// `runnable: false` for the 24, which is the exact analogue of the C's
/// `CURL_DISABLE_<PROTO>` builds and is what keeps `guess_scheme`'s
/// `smtp.`/`imap.`/`pop3.`/`dict.`/`ldap.` prefixes working and the
/// parse-versus-set asymmetry observable.
pub trait SchemeRegistry: Sync {
    /// The metadata for `scheme`, matched case-insensitively, or [`None`]
    /// when the name is not in the table.
    fn lookup(&self, scheme: &[u8]) -> Option<SchemeInfo>;
}

/// A parsed URL: the engine behind `CURLU`.
///
/// Supersedes `struct Curl_URL` (`lib/urlapi.c:67-82`), whose own comment is
/// *"Internal representation of CURLU. Point to URL-encoded strings."* The
/// ten byte strings, the numeric port and the three bits are the C's fields
/// one for one; the registry is this implementation's replacement for the C's
/// free-standing `Curl_get_scheme` call, and the reason is
/// [`SchemeRegistry`].
///
/// The stored parts are URL-**encoded**, with one measured exception the C
/// documents: *"When a full URL is set (parsed), the hostname component is
/// stored URL decoded"* (`docs/libcurl/curl_url_set.md:94`). That is
/// [`urldecode_host`], and it is why a host may hold bytes at or above 0x80
/// while every other part may not.
///
/// # Examples
///
/// The registry is a constructor argument, so a caller outside this crate
/// supplies its own. This is also the smallest complete statement of the
/// contract described on [`SchemeRegistry`]:
///
/// ```
/// use curl_rs_lib::url::{SchemeInfo, SchemeRegistry, Url, UrlFlags, UrlPart};
///
/// struct OneScheme;
///
/// impl SchemeRegistry for OneScheme {
///     fn lookup(&self, scheme: &[u8]) -> Option<SchemeInfo> {
///         // ASCII-only folding, as curl's own lookup folds.
///         if scheme.eq_ignore_ascii_case(b"https") {
///             Some(SchemeInfo {
///                 name: "https",
///                 default_port: 443,
///                 url_options: false,
///                 runnable: true,
///             })
///         } else {
///             None
///         }
///     }
/// }
///
/// static REGISTRY: OneScheme = OneScheme;
///
/// use curl_rs_lib::CURLUcode;
///
/// let mut url = Url::new(&REGISTRY);
/// let input = b"HTTPS://Example.COM/a/../b?q";
/// url.set(UrlPart::Url, Some(input), UrlFlags::NONE)?;
///
/// // The scheme is folded, the host is not, and dot segments are removed.
/// let host = b"Example.COM".to_vec();
/// assert_eq!(url.get(UrlPart::Scheme, UrlFlags::NONE)?, b"https".to_vec());
/// assert_eq!(url.get(UrlPart::Host, UrlFlags::NONE)?, host);
/// assert_eq!(url.get(UrlPart::Path, UrlFlags::NONE)?, b"/b".to_vec());
///
/// // The default port is the registry's, and only when asked for.
/// let asked = UrlFlags::DEFAULT_PORT;
/// assert_eq!(url.get(UrlPart::Port, UrlFlags::NONE), Err(CURLUcode::NoPort));
/// assert_eq!(url.get(UrlPart::Port, asked)?, b"443".to_vec());
/// # Ok::<(), CURLUcode>(())
/// ```
pub struct Url {
    /// `char *scheme`, folded to lower case when it came from a parsed URL.
    scheme: Option<Vec<u8>>,
    /// `char *user`.
    user: Option<Vec<u8>>,
    /// `char *password`.
    password: Option<Vec<u8>>,
    /// `char *options`, annotated *"IMAP only?"* in the C.
    options: Option<Vec<u8>>,
    /// `char *host`, stored URL-decoded when it came from a parsed URL.
    host: Option<Vec<u8>>,
    /// `char *zoneid`, annotated *"for numerical IPv6 addresses"*, and held
    /// as text: no numeric scope resolution happens here. `if_nametoindex`
    /// appears exactly once in the C tree, at `lib/url.c:1615`, and nowhere
    /// in `lib/urlapi.c` or `lib/urlapi-int.h` -- verified by grep. That
    /// conversion belongs to whoever opens a socket.
    zoneid: Option<Vec<u8>>,
    /// `char *port`, always re-rendered in canonical decimal.
    port: Option<Vec<u8>>,
    /// `char *path`.
    path: Option<Vec<u8>>,
    /// `char *query`.
    query: Option<Vec<u8>>,
    /// `char *fragment`.
    fragment: Option<Vec<u8>>,
    /// `unsigned short portnum`, annotated *"the numerical version (if
    /// 'port' is set)"*. Zero when no port is stored, and compared against
    /// [`SchemeInfo::default_port`] by [`UrlFlags::NO_DEFAULT_PORT`].
    portnum: u16,
    /// `BIT(query_present)`, annotated *"to support blank"*.
    query_present: bool,
    /// `BIT(fragment_present)`, annotated *"to support blank"*.
    fragment_present: bool,
    /// `BIT(guessed_scheme)`, annotated *"when a URL without scheme is
    /// parsed"*. Deliberately **not** carried across [`Url::dup`]; see there.
    guessed_scheme: bool,
    /// The injected scheme table. Not a C field: it replaces the C's direct
    /// calls to `Curl_get_scheme`, which this module may not make.
    registry: &'static dyn SchemeRegistry,
}

/// Reports the parts without the registry, which has no [`fmt::Debug`].
///
/// Hand-written because `#[derive(Debug)]` cannot render a trait object, and
/// requiring `SchemeRegistry: Debug` would push a formatting obligation onto
/// every implementation for no benefit. The parts are rendered with
/// [`String::from_utf8_lossy`] because a host may hold bytes that are not
/// UTF-8 and a debug format must not be the thing that fails.
impl fmt::Debug for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn show(part: Option<&Vec<u8>>) -> String {
            match part {
                Some(bytes) => {
                    format!("{:?}", String::from_utf8_lossy(bytes))
                }
                None => String::from("None"),
            }
        }

        f.debug_struct("Url")
            .field("scheme", &show(self.scheme.as_ref()))
            .field("user", &show(self.user.as_ref()))
            .field("password", &show(self.password.as_ref()))
            .field("options", &show(self.options.as_ref()))
            .field("host", &show(self.host.as_ref()))
            .field("zoneid", &show(self.zoneid.as_ref()))
            .field("port", &show(self.port.as_ref()))
            .field("path", &show(self.path.as_ref()))
            .field("query", &show(self.query.as_ref()))
            .field("fragment", &show(self.fragment.as_ref()))
            .field("portnum", &self.portnum)
            .field("query_present", &self.query_present)
            .field("fragment_present", &self.fragment_present)
            .field("guessed_scheme", &self.guessed_scheme)
            .finish()
    }
}

impl Url {
    /// An empty handle bound to `registry`.
    ///
    /// Supersedes `curl_url` (`lib/urlapi.c:1288-1291`), whose whole body is
    /// `curlx_calloc(1, sizeof(struct Curl_URL))` -- every field zero, which
    /// is every part absent, a zero port and all three bits clear. The
    /// registry is the one field a `calloc` cannot supply.
    ///
    /// `curl_url_cleanup` (`:1293-1299`) has no counterpart: it frees the ten
    /// strings and then the handle, all of which `Drop` does. The FFI
    /// wrapper's `Box::from_raw` is the whole of it.
    #[must_use]
    pub fn new(registry: &'static dyn SchemeRegistry) -> Self {
        Self {
            scheme: None,
            user: None,
            password: None,
            options: None,
            host: None,
            zoneid: None,
            port: None,
            path: None,
            query: None,
            fragment: None,
            portnum: 0,
            query_present: false,
            fragment_present: false,
            guessed_scheme: false,
            registry,
        }
    }

    /// A copy of this handle -- **without** its `guessed_scheme` bit.
    ///
    /// Supersedes `curl_url_dup` (`lib/urlapi.c:1310-1332`). The C duplicates
    /// ten strings through its `DUP` macro -- scheme, user, password,
    /// options, host, port, path, query, fragment, zoneid -- and then copies
    /// exactly three scalars:
    ///
    /// ```c
    /// u->portnum = in->portnum;
    /// u->fragment_present = in->fragment_present;
    /// u->query_present = in->query_present;
    /// ```
    ///
    /// `guessed_scheme` is not among them. **That omission is reproduced
    /// deliberately and is not an oversight in this transcription.** It is
    /// observable: [`UrlFlags::NO_GUESS_SCHEME`] treats a guessed scheme as
    /// absent on get, so the original and the duplicate answer differently
    /// for both [`UrlPart::Scheme`] and [`UrlPart::Url`]. The duplicate
    /// behaves as though the scheme had been given explicitly.
    ///
    /// This is why the type does not derive [`Clone`]: a derived clone would
    /// copy all fourteen fields and would silently "fix" a difference the
    /// fixture corpus can see. `tests::dup_does_not_carry_the_guessed_scheme`
    /// is the guard.
    ///
    /// The C can return null here, from a failed allocation. That has no
    /// expression in Rust -- `Vec` aborts rather than reporting -- so this is
    /// infallible, and the FFI wrapper's only null return is for a null
    /// input.
    #[must_use]
    pub fn dup(&self) -> Self {
        Self {
            scheme: self.scheme.clone(),
            user: self.user.clone(),
            password: self.password.clone(),
            options: self.options.clone(),
            host: self.host.clone(),
            zoneid: self.zoneid.clone(),
            port: self.port.clone(),
            path: self.path.clone(),
            query: self.query.clone(),
            fragment: self.fragment.clone(),
            portnum: self.portnum,
            query_present: self.query_present,
            fragment_present: self.fragment_present,
            // NOT copied. `lib/urlapi.c:1324-1326` copies portnum,
            // fragment_present and query_present, and stops.
            guessed_scheme: false,
            registry: self.registry,
        }
    }

    // `free_urlhandle` (`lib/urlapi.c:86-98`) has no counterpart here, and
    // deliberately so: all three of its callers express releasing the parts
    // some other way in Rust. `parseurl` at `:1190` frees a temporary handle
    // it is about to discard, which is a drop; `curl_url_cleanup` at `:1296`
    // frees the handle itself, which is also a drop, arranged by the FFI's
    // `Box::from_raw`; and `urlset_clear` at `:1736` frees the parts only to
    // `memset` over them immediately, which is the single assignment in
    // `Self::urlset_clear`. A method here would have no caller.
}

// ---------------------------------------------------------------------------
// Scanning and encoding the input -- `lib/urlapi.c:104-239`.
// ---------------------------------------------------------------------------

/// The offset of the separator that ends the host, or of the `?` that
/// replaces it.
///
/// `find_host_sep` (`lib/urlapi.c:104-118`), whose comment gives the second
/// case: *"or the '?' in cases like http://www.example.com?id=2380"*. The
/// walk skips to just past the first `//` if there is one, then to the first
/// `/` or `?`, and answers the end of the string if there is neither.
fn find_host_sep(url: &[u8]) -> usize {
    // `sep = strstr(url, "//"); if(!sep) sep = url; else sep += 2;`
    let mut sep = match url.windows(2).position(|pair| pair == b"//") {
        Some(offset) => offset + 2,
        None => 0,
    };

    // `while(*sep && *sep != '/' && *sep != '?') sep++;`
    while sep < url.len() {
        let byte = url[sep];
        if byte == 0 || byte == b'/' || byte == b'?' {
            break;
        }
        sep += 1;
    }

    sep
}

/// Appends `url` to `out`, percent-encoding what a URL may not carry raw.
///
/// Supersedes `urlencode_str` (`lib/urlapi.c:130-172`). Three rules, and none
/// of them is the ordinary percent-encoding of [`escape::escape`]:
///
/// * **The host is never encoded.** When `relative` is false the leading run
///   up to [`find_host_sep`] is copied verbatim, and the C says why at
///   `:124-128`: *"URL encoding should be skipped for hostnames, otherwise
///   IDN resolution will fail."*
/// * **A space encodes two different ways.** Before the first `?` it becomes
///   `%20`; after it, `+`. The `left` flag carries that, it starts as
///   `!query` so that a part which *is* the query begins already in
///   form-encoding mode, and it flips on the first `?` the walk emits
///   (`:135`, `:151-166`).
/// * **Only spaces and non-printables are touched.** Every other byte is
///   copied as it stands, including `%`, so an already-encoded input is not
///   double-encoded here. Bytes below 0x20 and at or above 0x7f become `%XX`
///   in **upper** case, through [`escape::hexbyte`] -- the C calls
///   `Curl_hexbyte` at `:159`.
///
/// # Errors
///
/// [`CURLUcode::TooLarge`] or [`CURLUcode::OutOfMemory`], as [`cc2cu`] maps
/// the buffer's refusal. The C returns `cc2cu(result)` at `:170`.
fn urlencode_str(
    out: &mut Buf,
    url: &[u8],
    relative: bool,
    query: bool,
) -> UrlResult<()> {
    // `bool left = !query;`
    let mut left = !query;

    // `if(!relative) { host_sep = find_host_sep(url); dyn_addn(o, url, n);
    //   len -= n; }`
    //
    // The C subtracts the copied prefix from its carried length. Here the
    // prefix is a slice split, so there is no subtraction to underflow --
    // which matters because the C's would, if `len` were ever shorter than
    // the prefix. It is not: `relative` is false at exactly one call site,
    // `redirect_url` at `:1275`, which passes `strlen(useurl)`.
    let mut rest = url;
    if !relative {
        let sep = find_host_sep(url).min(url.len());
        let (head, tail) = url.split_at(sep);
        out.addn(head).map_err(cc2cu)?;
        rest = tail;
    }

    for byte in rest {
        match *byte {
            b' ' => {
                // `:151-156`
                if left {
                    out.addn(b"%20").map_err(cc2cu)?;
                } else {
                    out.addn(b"+").map_err(cc2cu)?;
                }
            }
            // `(*iptr < ' ') || (*iptr >= 0x7f)`, spelled as the range so
            // that `clippy::manual_range_contains` is satisfied without an
            // exemption. The bound is exclusive above, so 0x7f itself is
            // escaped.
            other if !(b' '..0x7f).contains(&other) => {
                // `:157-161`. Three bytes: a literal '%' and the two
                // uppercase digits `Curl_hexbyte` writes.
                let digits = escape::hexbyte(other);
                out.addn(&[b'%', digits[0], digits[1]]).map_err(cc2cu)?;
            }
            other => {
                // `:162-166`
                out.addn(&[other]).map_err(cc2cu)?;
                if other == b'?' {
                    left = false;
                }
            }
        }
    }

    Ok(())
}

/// The scheme of `url` folded to lower case, when `url` is absolute.
///
/// Supersedes `Curl_is_absolute_url` (`lib/urlapi.c:182-220`), one of the
/// three non-unittest exports of `lib/urlapi-int.h`. The C returns the length
/// and optionally fills a caller's buffer with the folded name; returning the
/// name itself covers both, since its length is the C's return value.
///
/// The grammar is RFC 3986 section 3.1, quoted in the C at `:198-200`:
/// `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, capped at
/// [`MAX_SCHEME_LEN`]. A first byte that is not a letter means not absolute,
/// which is what rejects `1h://`, `..://`, `-ht://` and `+ftp://`.
///
/// # `guess_scheme` changes what counts as a scheme
///
/// The colon test at `:206` is
/// `if(i && (url[i] == ':') && ((url[i + 1] == '/') || !guess_scheme))`, and
/// the C explains it at `:207-209`: without guessing, any `scheme:` is a
/// scheme, so `data:` is detected; with guessing, a slash must follow,
/// because `data:1234` might be the host `data` with a port. Both readings
/// are preserved, and `tests/libtest/lib1560.c` requires both -- `boing:80`
/// parses as a host and a port under
/// [`UrlFlags::GUESS_SCHEME`] while `about:config` is an unsupported scheme
/// without it.
///
/// The Windows drive-prefix arm at `:190-193` has no counterpart: AAP section
/// 0.2.2 excludes Windows, and this module writes no
/// `STARTS_WITH_DRIVE_PREFIX`.
// The remaining C call site is `lib/transfer.c`'s redirect handling, which
// arrives with `transfer/`. `set_url` below is the in-module caller.
#[allow(dead_code)]
pub(crate) fn is_absolute_url(
    url: &[u8],
    guess_scheme: bool,
) -> Option<Vec<u8>> {
    // `size_t i = 0; if(ISALPHA(url[0])) for(i = 1; i < MAX_SCHEME_LEN; ++i)`
    let mut length = 0usize;
    if strparse::is_alpha(at(url, 0)) {
        length = 1;
        while length < MAX_SCHEME_LEN {
            let byte = at(url, length);
            let legal = byte != 0
                && (strparse::is_alnum(byte)
                    || byte == b'+'
                    || byte == b'-'
                    || byte == b'.');
            if !legal {
                break;
            }
            length += 1;
        }
    }

    // `if(i && (url[i] == ':') && ((url[i + 1] == '/') || !guess_scheme))`
    if length != 0
        && at(url, length) == b':'
        && (at(url, length + 1) == b'/' || !guess_scheme)
    {
        // `Curl_strntolower(buf, url, i); buf[i] = 0;`
        let mut folded = Vec::with_capacity(length);
        for index in 0..length {
            folded.push(strcase::raw_tolower(at(url, index)));
        }
        return Some(folded);
    }

    None
}

/// The length of `url`, once it is known to carry nothing this API refuses.
///
/// Supersedes `Curl_junkscan` (`lib/urlapi.c:223-239`), the second of
/// `lib/urlapi-int.h`'s three exports, whose comment is *"scan for byte
/// values <= 31, 127 and sometimes space"*. The whole of it:
///
/// ```c
/// size_t n = strlen(url);
/// if(n > CURL_MAX_INPUT_LENGTH) return CURLUE_MALFORMED_INPUT;
/// control = allowspace ? 0x1f : 0x20;
/// for(i = 0; i < n; i++)
///   if(p[i] <= control || p[i] == 127) return CURLUE_MALFORMED_INPUT;
/// *urllen = n;
/// ```
///
/// Two details are easy to lose and both are reproduced. **The length test
/// runs before the byte scan**, so an over-long input is refused for its
/// length whatever it contains. And the threshold is a `<=` against a
/// value that *includes* the space when spaces are not allowed, so
/// `allowspace` is expressed by lowering the bound rather than by a second
/// test -- which is why a space is refused by the same comparison that
/// refuses a tab.
///
/// # Errors
///
/// [`CURLUcode::MalformedInput`], the only code this function produces.
// The remaining C call sites are in `lib/url.c` and `lib/transfer.c`, which
// arrive with their own files.
#[allow(dead_code)]
pub(crate) fn junkscan(url: &[u8], allowspace: bool) -> UrlResult<usize> {
    if url.len() > MAX_INPUT_LENGTH {
        return Err(CURLUcode::MalformedInput);
    }

    let control: u8 = if allowspace { 0x1f } else { 0x20 };
    for byte in url {
        if *byte <= control || *byte == 127 {
            return Err(CURLUcode::MalformedInput);
        }
    }

    Ok(url.len())
}

// ---------------------------------------------------------------------------
// The authority -- `lib/urlapi.c:248-655`.
// ---------------------------------------------------------------------------

/// The three components of a userinfo field.
///
/// The out-parameters of `Curl_parse_login_details` (`lib/url.c:2466-2528`),
/// with its two measured asymmetries preserved in the types: the user is
/// **always** produced, even empty, because `curlx_memdup0(login, 0)` returns
/// an allocation rather than null; the password is produced only when a `:`
/// was present; and the options are produced only when a `;` was present
/// **and** something followed it, because the C leaves `obuf` null when
/// `olen` is zero.
struct LoginDetails {
    /// `*userp`, which the C never leaves null.
    user: Vec<u8>,
    /// `*passwdp`.
    password: Option<Vec<u8>>,
    /// `*optionsp`, requested only for a scheme with
    /// [`SchemeInfo::url_options`].
    options: Option<Vec<u8>>,
}

/// Splits a userinfo field into user, password and options.
///
/// Supersedes `Curl_parse_login_details` (`lib/url.c:2466-2528`). The C's
/// arithmetic is transcribed rather than reasoned about, because it handles
/// the two separators in **either** order and the reasoning is not obvious:
///
/// ```c
/// ulen = (psep ? (size_t)(osep && psep > osep ? osep - login : psep - login)
///              : (osep ? (size_t)(osep - login) : len));
/// plen = (psep ? (osep && osep > psep ? (size_t)(osep - psep)
///                          : (size_t)(login + len - psep)) - 1 : 0);
/// olen = (osep ? (psep && psep > osep ? (size_t)(psep - osep)
///                          : (size_t)(login + len - osep)) - 1 : 0);
/// ```
///
/// So `user;opt:pass` yields `user`, `pass` and `opt` just as
/// `user:pass;opt` does, and `tests/libtest/lib1560.c` requires the latter.
/// `want_options` is the C's decision to pass a null `optionsp`, which
/// suppresses the search for `;` entirely -- which is why
/// `http://user:pass;word@host/` keeps the semicolon **in the password**
/// while `imap://user:pass;word@host/` does not.
///
/// Every subtraction below is saturating. None can underflow -- `osep > psep`
/// makes `osep - psep` at least one, and a separator is always inside `login`
/// so `len - sep` is at least one -- and stating it in the operator means the
/// argument does not have to be re-derived to be sure.
fn parse_login_details(login: &[u8], want_options: bool) -> LoginDetails {
    let len = login.len();
    let psep = strchr(login, b':');
    let osep = if want_options {
        strchr(login, b';')
    } else {
        None
    };

    let ulen = match (psep, osep) {
        (Some(p), Some(o)) if p > o => o,
        (Some(p), _) => p,
        (None, Some(o)) => o,
        (None, None) => len,
    };

    let plen = match (psep, osep) {
        (Some(p), Some(o)) if o > p => o.saturating_sub(p).saturating_sub(1),
        (Some(p), _) => len.saturating_sub(p).saturating_sub(1),
        (None, _) => 0,
    };

    let olen = match (osep, psep) {
        (Some(o), Some(p)) if p > o => p.saturating_sub(o).saturating_sub(1),
        (Some(o), _) => len.saturating_sub(o).saturating_sub(1),
        (None, _) => 0,
    };

    // `ubuf = curlx_memdup0(login, ulen);` -- always allocated, so always
    // `Some` in the C's sense even when empty.
    let user = login.get(..ulen).unwrap_or(login).to_vec();

    // `if(psep) pbuf = curlx_memdup0(&psep[1], plen);`
    let password = psep.map(|p| {
        let from = p.saturating_add(1);
        let to = from.saturating_add(plen);
        login.get(from..to).unwrap_or(&[]).to_vec()
    });

    // `if(olen) obuf = curlx_memdup0(&osep[1], olen); *optionsp = obuf;`
    // -- note that a `;` with nothing after it yields null, not empty.
    let options = match osep {
        Some(o) if olen != 0 => {
            let from = o.saturating_add(1);
            let to = from.saturating_add(olen);
            Some(login.get(from..to).unwrap_or(&[]).to_vec())
        }
        _ => None,
    };

    LoginDetails {
        user,
        password,
        options,
    }
}

/// Strips `user:password;options@` from the front of an authority.
///
/// Supersedes `parse_hostname_login` (`lib/urlapi.c:248-333`). Answers the
/// offset at which the host name begins.
///
/// Three behaviours are load-bearing:
///
/// * **The options are extracted only for a scheme that asks for them.** The
///   C looks the scheme up at `:284` and tests `PROTOPT_URLOPTIONS` at
///   `:290`, and passes a null `optionsp` when it is not set. A handle with
///   no scheme yet -- `h` is null -- also gets no options.
/// * **Every failure clears all three parts.** The `out:` label at `:323-332`
///   is reached both by the no-`@` path and by the error paths, and it sets
///   `u->user`, `u->password` and `u->options` to null unconditionally. That
///   is visible through `Curl_url_set_authority`, which runs this against an
///   existing handle rather than a fresh one.
/// * **Only the first `@` counts**, because the C uses `memchr`. So
///   `user@host@more` leaves `host@more` as the host name, which
///   [`hostname_check`] then refuses.
///
/// # Errors
///
/// [`CURLUcode::UserNotAllowed`] when [`UrlFlags::DISALLOW_USER`] is set and
/// the authority carries a user. The C's other error here is a failed
/// allocation, which has no expression.
fn parse_hostname_login(
    u: &mut Url,
    login: &[u8],
    flags: UrlFlags,
) -> UrlResult<usize> {
    // `ptr = memchr(login, '@', len); if(!ptr) goto out;`
    let Some(at_sign) = login.iter().position(|byte| *byte == b'@') else {
        u.user = None;
        u.password = None;
        u.options = None;
        return Ok(0);
    };

    // `if(u->scheme) h = Curl_get_scheme(u->scheme);` and then
    // `(h && (h->flags & PROTOPT_URLOPTIONS)) ? &optionsp : NULL`.
    let want_options = match &u.scheme {
        Some(scheme) => u
            .registry
            .lookup(scheme)
            .is_some_and(|info| info.url_options),
        None => false,
    };

    let details = parse_login_details(
        login.get(..at_sign).unwrap_or(login),
        want_options,
    );

    // `if(userp) { if(flags & CURLU_DISALLOW_USER) { result =
    //   CURLUE_USER_NOT_ALLOWED; goto out; } ... }`
    //
    // The test is on the pointer, which is never null, so a blank user
    // triggers it too: `https://@host/` is refused under DISALLOW_USER.
    if flags.has(UrlFlags::DISALLOW_USER) {
        u.user = None;
        u.password = None;
        u.options = None;
        return Err(CURLUcode::UserNotAllowed);
    }

    u.user = Some(details.user);
    if details.password.is_some() {
        u.password = details.password;
    }
    if details.options.is_some() {
        u.options = details.options;
    }

    // `*offset = ptr - login;` where `ptr` was advanced past the '@'.
    Ok(at_sign.saturating_add(1))
}

/// Splits a trailing `:port` off the host buffer and stores it.
///
/// Supersedes `Curl_parse_port` (`lib/urlapi.c:335-387`), the one export of
/// `lib/urlapi-int.h` the C guards with `UNITTEST`. Kept private here for
/// exactly that reason -- `tests` below is a child module and reaches it
/// without any of it becoming crate API. `tests/unit/unit1653.c` is the C
/// test and every one of its eleven cases is ported.
///
/// Four behaviours, each measured:
///
/// * A bracketed host must close its bracket, or [`CURLUcode::BadIpv6`]; and
///   what follows the bracket must be a colon or nothing, or
///   [`CURLUcode::BadPortNumber`]. So `[::1]80` and `[::1];81` are both
///   refused here, before any address is validated.
/// * **A colon with no digits after it truncates the host and keeps the
///   default port -- but only when the URL had a scheme.** The C's comment at
///   `:363-369` gives both halves: *"Browser behavior adaptation... Firefox,
///   Chrome and Safari all do that. Do not do it if the URL has no scheme, to
///   make something that looks like a scheme not work!"* The second half is
///   what stops fifty `a`s followed by a colon from parsing as a host.
/// * The number is decimal, bounded at 0xffff, and **the whole tail must be
///   consumed**, so `123a` is refused rather than truncated.
/// * The stored text is **re-rendered** from the parsed number, which is what
///   strips leading zeroes: `:000000000000000000000443` becomes `443`, and
///   `docs/libcurl/curl_url_get.md:190-192` promises exactly that -- the
///   returned port *"is guaranteed to hold a valid port number in ASCII using
///   base 10"*.
///
/// # Errors
///
/// [`CURLUcode::BadIpv6`] or [`CURLUcode::BadPortNumber`].
fn parse_port(u: &mut Url, host: &mut Buf, has_scheme: bool) -> UrlResult<()> {
    let hostname = host.as_slice();

    // `if(hostname[0] == '[') { portptr = strchr(hostname, ']'); ... }
    //  else portptr = strchr(hostname, ':');`
    let portptr = if at(hostname, 0) == b'[' {
        let Some(bracket) = strchr(hostname, b']') else {
            return Err(CURLUcode::BadIpv6);
        };
        let after = bracket.saturating_add(1);
        match at(hostname, after) {
            0 => None,
            b':' => Some(after),
            _ => return Err(CURLUcode::BadPortNumber),
        }
    } else {
        strchr(hostname, b':')
    };

    let Some(colon) = portptr else {
        return Ok(());
    };

    // `keep = portptr - hostname; curlx_dyn_setlen(host, keep); portptr++;`
    //
    // The truncation happens before the number is validated, and it is not
    // undone on failure. That is only observable through the unit test, since
    // every other caller discards the buffer when this fails.
    let digits = hostname
        .get(colon.saturating_add(1)..)
        .unwrap_or(&[])
        .to_vec();
    host.setlen(colon);

    // `if(!*portptr) return has_scheme ? CURLUE_OK : CURLUE_BAD_PORT_NUMBER;`
    if digits.is_empty() {
        return if has_scheme {
            Ok(())
        } else {
            Err(CURLUcode::BadPortNumber)
        };
    }

    // `if(curlx_str_number(&portptr, &port, 0xffff) || *portptr)
    //    return CURLUE_BAD_PORT_NUMBER;`
    let mut cursor: &[u8] = &digits;
    let Ok(port) = strparse::str_number(&mut cursor, 0xffff) else {
        return Err(CURLUcode::BadPortNumber);
    };
    if !cursor.is_empty() {
        return Err(CURLUcode::BadPortNumber);
    }

    // `u->portnum = (unsigned short)port;` and then the canonical re-render.
    // The cast is safe by construction: `str_number` refused anything above
    // 0xffff, so the value fits, and `u16::try_from` states that rather than
    // asserting it.
    u.portnum = u16::try_from(port).unwrap_or(0);
    u.port = Some(u.portnum.to_string().into_bytes());
    Ok(())
}

/// Normalises a bracketed IPv6 literal and lifts out its zone identifier.
///
/// Supersedes `ipv6_parse` (`lib/urlapi.c:390-441`), which assumes its input
/// starts with `[`. The zone identifier is **entirely this module's
/// business**: [`crate::util::inet::pton6`] documents that it rejects one,
/// so it is stripped before the address is parsed and re-attached after the
/// address is rendered.
///
/// The measured rules:
///
/// * The shortest valid input is four bytes, `[::]`.
/// * The address runs while the bytes are drawn from [`IPV6_ACCEPT`]. If it
///   stops early, the next byte must be `%` -- anything else is
///   [`CURLUcode::BadIpv6`].
/// * A zone identifier is **at most fifteen bytes** and must be followed by
///   `]`. Sixteen bytes therefore fails, because the walk stops at fifteen
///   and then finds no bracket. Empty fails too.
/// * A leading `25` in the zone identifier is skipped -- it is the
///   percent-encoded `%` -- but only `if(!strncmp(h, "25", 2) && h[2] &&
///   (h[2] != ']'))`. So `%25eth0` and `%eth0` both yield `eth0`, while
///   `%25]` yields the zone identifier `25`, which renders back as `%2525`.
/// * The address is put through `inet_pton` and `inet_ntop`, so it comes back
///   canonicalised and lower-cased. `docs/libcurl/curl_url_get.md:181-182`:
///   *"IPv6 names are normalized when set, which should make them as short as
///   possible while maintaining correct syntax."*
///
/// # Two orderings that are observable
///
/// The zone identifier is stored **before** the address is validated, so a
/// zone identifier survives a failure to normalise: measured against a real
/// libcurl, `curl_url_set(u, CURLUPART_HOST, "[:::%25eth0]", 0)` answers
/// `CURLUE_BAD_HOSTNAME` and leaves the zone identifier `eth0` on the handle.
///
/// And the normalised text replaces the input **only when it is no longer**.
/// The C hands `inet_ntop` a buffer of `hlen + 1` bytes (`:435`) and
/// `curlx_inet_ntop` refuses when the result needs at least that much
/// (`lib/curlx/inet_ntop.c:186`), leaving the un-normalised text in place. So
/// the test is `rendered.len() <= hlen`, not a comparison of forms.
///
/// # Errors
///
/// [`CURLUcode::BadIpv6`].
fn ipv6_parse(u: &mut Url, host: &mut Buf) -> UrlResult<()> {
    let bytes = host.as_slice();

    // `if(hlen < 4) return CURLUE_BAD_IPV6;`
    if bytes.len() < 4 {
        return Err(CURLUcode::BadIpv6);
    }

    // `hostname++; hlen -= 2;` -- past the '[', and discounting both
    // brackets. A trailing byte that is not ']' simply makes `hlen`
    // disagree with the span below, which the `%` test then refuses.
    let inner = bytes.get(1..).unwrap_or(&[]);
    let mut hlen = bytes.len().saturating_sub(2);

    // `len = strspn(hostname, "0123456789abcdefABCDEF:.");`
    let span = spn(inner, IPV6_ACCEPT);

    let mut zone: Option<Vec<u8>> = None;
    if hlen != span {
        hlen = span;
        if at(inner, span) != b'%' {
            return Err(CURLUcode::BadIpv6);
        }

        // `char *h = &hostname[len + 1];`
        let mut cursor = span.saturating_add(1);

        // `if(!strncmp(h, "25", 2) && h[2] && (h[2] != ']')) h += 2;`
        let third = at(inner, cursor.saturating_add(2));
        if at(inner, cursor) == b'2'
            && at(inner, cursor.saturating_add(1)) == b'5'
            && third != 0
            && third != b']'
        {
            cursor = cursor.saturating_add(2);
        }

        // `while(*h && (*h != ']') && (i < 15)) zoneid[i++] = *h++;`
        let mut zoneid = Vec::with_capacity(15);
        while zoneid.len() < 15 {
            let byte = at(inner, cursor);
            if byte == 0 || byte == b']' {
                break;
            }
            zoneid.push(byte);
            cursor = cursor.saturating_add(1);
        }

        // `if(!i || (']' != *h)) return CURLUE_BAD_IPV6;`
        if zoneid.is_empty() || at(inner, cursor) != b']' {
            return Err(CURLUcode::BadIpv6);
        }
        zone = Some(zoneid);
    }

    // `hostname[hlen] = 0;` -- the address alone, without brackets.
    let address = inner.get(..hlen).unwrap_or(inner).to_vec();

    // The C stores the zone identifier here, before validating the address.
    if let Some(zoneid) = zone {
        u.zoneid = Some(zoneid);
    }

    // `if(curlx_inet_pton(AF_INET6, hostname, dest) != 1) return
    //    CURLUE_BAD_IPV6;`
    let Some(binary) = inet::pton6(&address) else {
        return Err(CURLUcode::BadIpv6);
    };

    // `if(curlx_inet_ntop(AF_INET6, dest, hostname, hlen + 1)) { ... }` --
    // and on refusal the un-normalised text stands.
    let rendered = inet::ntop6(&binary);
    let canonical: &[u8] = if rendered.len() <= hlen {
        rendered.as_bytes()
    } else {
        &address
    };

    // `hostname[hlen] = ']';` -- rebuild `[address]`.
    host.reset();
    host.addn(b"[").map_err(cc2cu)?;
    host.addn(canonical).map_err(cc2cu)?;
    host.addn(b"]").map_err(cc2cu)?;
    Ok(())
}

/// Refuses a host name that a URL may not carry.
///
/// Supersedes `hostname_check` (`lib/urlapi.c:444-461`). Three arms: an empty
/// host is [`CURLUcode::NoHost`], a bracketed host is handed to
/// [`ipv6_parse`], and anything else must contain no byte of
/// [`HOST_REJECT`] -- otherwise [`CURLUcode::BadHostname`].
///
/// The reject test is a `strcspn` compared against the length, so an interior
/// zero fails it too: `cspn` stops at a zero and the lengths then disagree.
///
/// # This function mutates, and one caller throws the mutation away
///
/// The bracketed arm normalises the host in place and may store a zone
/// identifier. `parse_authority` keeps both. `Url::set` keeps only the zone
/// identifier and the verdict, because it validates a **decoded copy** and
/// stores the input the caller gave it -- which is why
/// `curl_url_set(u, CURLUPART_HOST, "[fe80::1%25eth0]", 0)` leaves the host
/// as that exact string with `eth0` beside it, and why asking for the full
/// URL afterwards renders the zone identifier twice. Measured against a real
/// libcurl; reproduced under AAP section 0.8.1.
///
/// # Errors
///
/// [`CURLUcode::NoHost`], [`CURLUcode::BadHostname`], or [`ipv6_parse`]'s
/// [`CURLUcode::BadIpv6`].
fn hostname_check(u: &mut Url, host: &mut Buf) -> UrlResult<()> {
    let hlen = host.len();

    // `if(!hlen) return CURLUE_NO_HOST;`
    if hlen == 0 {
        return Err(CURLUcode::NoHost);
    }

    // `else if(hostname[0] == '[') return ipv6_parse(u, hostname, hlen);`
    if at(host.as_slice(), 0) == b'[' {
        return ipv6_parse(u, host);
    }

    // `len = strcspn(hostname, HOST_REJECT); if(hlen != len) return
    //    CURLUE_BAD_HOSTNAME;`
    if cspn(host.as_slice(), HOST_REJECT) != hlen {
        return Err(CURLUcode::BadHostname);
    }

    Ok(())
}

/// What [`ipv4_normalize`] decided the host is.
///
/// The C's three positive verdicts -- `HOST_NAME` 1, `HOST_IPV4` 2 and
/// `HOST_IPV6` 3 (`lib/urlapi.c:479-481`). Its fourth, `HOST_ERROR` at
/// `:477`, is a buffer failure and is the `Err` arm of the return type
/// instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostKind {
    /// `HOST_NAME` -- not a numeric address, or not a well-formed one.
    Name,
    /// `HOST_IPV4` -- rewritten as four decimal octets.
    Ipv4,
    /// `HOST_IPV6` -- bracketed, and untouched here.
    Ipv6,
}

/// Rewrites a numeric IPv4 host in canonical dotted-decimal form.
///
/// Supersedes `ipv4_normalize` (`lib/urlapi.c:483-574`), whose comment names
/// the job: *"Handle partial IPv4 numerical addresses and different bases,
/// like '16843009', '0x7f', '0x7f.1' '0177.1.1.1' etc."*
///
/// **This must not delegate to [`crate::util::inet::pton4`]**, and the reason
/// is not stylistic: that function is the transcription of curl's own
/// `inet_pton`, which is strict -- exactly four octets, decimal only, no
/// leading zero. This one accepts **one to four** parts, each in decimal,
/// `0x` hexadecimal or leading-zero octal, each up to `UINT_MAX`, and
/// re-splits them by the documented bit widths: one part is 32 bits, two are
/// 8 and 24, three are 8, 8 and 16, four are 8 apiece. Delegating would
/// refuse `0x7f000001`, `0177.1` and `127.1`, all of which curl accepts and
/// `tests/libtest/lib1560.c` requires.
///
/// **Any syntax failure answers [`HostKind::Name`]**, never an error: the
/// host falls through to name handling. That is what makes `1.2.3.4.5`,
/// `018.0.0.0` (`8` is not an octal digit), `0x.0x.0` and `4294967296` plain
/// host names rather than rejected input.
///
/// Two details worth stating because they are easy to smooth over. The
/// hexadecimal prefix is tested as `c[1] == 'x'` (`:498`), **lower case
/// only**, so `0X8` is octal `0` followed by a stray `X` and therefore a
/// name. And a part is octal whenever it begins with `0`, which is why `08`
/// is a name while `07` is the address `0.0.0.7`.
///
/// # Errors
///
/// [`CURLUcode::OutOfMemory`], which is the C's `HOST_ERROR` arm mapped by
/// `parse_authority` at `:646`. Unreachable in practice: the buffer is reset
/// before at most fifteen bytes are written into a ceiling of eight million.
fn ipv4_normalize(host: &mut Buf) -> UrlResult<HostKind> {
    // `if(*c == '[') return HOST_IPV6;`
    if at(host.as_slice(), 0) == b'[' {
        return Ok(HostKind::Ipv6);
    }

    let source = host.as_slice().to_vec();
    let mut cursor: &[u8] = &source;
    let mut parts = [0u32; 4];
    let mut n = 0usize;

    loop {
        // `if(*c == '0') { if(c[1] == 'x') { c += 2; str_hex } else str_octal }
        //  else str_number` -- each bounded by UINT_MAX.
        let parsed = if at(cursor, 0) == b'0' {
            if at(cursor, 1) == b'x' {
                cursor = cursor.get(2..).unwrap_or(&[]);
                strparse::str_hex(&mut cursor, i64::from(u32::MAX))
            } else {
                strparse::str_octal(&mut cursor, i64::from(u32::MAX))
            }
        } else {
            strparse::str_number(&mut cursor, i64::from(u32::MAX))
        };

        let Ok(value) = parsed else {
            return Ok(HostKind::Name);
        };

        // `parts[n] = (unsigned int)l;` -- in range by the bound above.
        match parts.get_mut(n) {
            Some(slot) => *slot = u32::try_from(value).unwrap_or(0),
            None => return Ok(HostKind::Name),
        }

        match at(cursor, 0) {
            b'.' => {
                // `if(n == 3) return HOST_NAME; n++; c++;`
                if n == 3 {
                    return Ok(HostKind::Name);
                }
                n += 1;
                cursor = cursor.get(1..).unwrap_or(&[]);
            }
            0 => break,
            _ => return Ok(HostKind::Name),
        }
    }

    // The four re-splits of `:530-571`, each preceded by its own range test.
    // `quad` is built rather than formatted so that the "%u.%u.%u.%u" of the
    // C is one expression here too.
    let quad = match n {
        0 => {
            let value = parts[0];
            [
                value >> 24,
                (value >> 16) & 0xff,
                (value >> 8) & 0xff,
                value & 0xff,
            ]
        }
        1 => {
            if parts[0] > 0xff || parts[1] > 0x00ff_ffff {
                return Ok(HostKind::Name);
            }
            [
                parts[0],
                (parts[1] >> 16) & 0xff,
                (parts[1] >> 8) & 0xff,
                parts[1] & 0xff,
            ]
        }
        2 => {
            if parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xffff {
                return Ok(HostKind::Name);
            }
            [parts[0], parts[1], (parts[2] >> 8) & 0xff, parts[2] & 0xff]
        }
        _ => {
            if parts[0] > 0xff
                || parts[1] > 0xff
                || parts[2] > 0xff
                || parts[3] > 0xff
            {
                return Ok(HostKind::Name);
            }
            [parts[0], parts[1], parts[2], parts[3]]
        }
    };

    host.reset();
    let text = format!("{}.{}.{}.{}", quad[0], quad[1], quad[2], quad[3]);
    host.addn(text.as_bytes())
        .map_err(|_| CURLUcode::OutOfMemory)?;
    Ok(HostKind::Ipv4)
}

/// Replaces the host with its percent-decoded form, when it has one.
///
/// Supersedes `urldecode_host` (`lib/urlapi.c:578-601`), and
/// `docs/libcurl/curl_url_set.md:94` states the resulting invariant: *"When a
/// full URL is set (parsed), the hostname component is stored URL decoded."*
///
/// Two measured details. The decode is attempted **only** when a `%` is
/// present, which is the C's `strchr` guard -- so a host with no escape is
/// not copied. And a decode failure becomes [`CURLUcode::BadHostname`], not
/// [`CURLUcode::Urldecode`]: control bytes are rejected by the decode mode,
/// and the caller reports the host as bad rather than the escaping.
///
/// # Errors
///
/// [`CURLUcode::BadHostname`], or [`cc2cu`]'s mapping of a buffer refusal.
fn urldecode_host(host: &mut Buf) -> UrlResult<()> {
    // `per = strchr(hostname, '%'); if(!per) return CURLUE_OK;`
    if strchr(host.as_slice(), b'%').is_none() {
        return Ok(());
    }

    // `Curl_urldecode(hostname, 0, &decoded, &dlen, REJECT_CTRL)`
    let decoded = escape::urldecode(host.as_slice(), escape::UrlReject::Ctrl)
        .map_err(|_| CURLUcode::BadHostname)?;

    host.reset();
    host.addn(&decoded).map_err(cc2cu)
}

/// Parses `user:password;options@host:port` into the handle and the buffer.
///
/// Supersedes `parse_authority` (`lib/urlapi.c:604-654`). The order is fixed
/// and each step depends on the last: the userinfo is stripped first, because
/// the port scan must not see a `:` that belongs to a password; the port is
/// taken next, because the address parsers must not see it; the host is then
/// classified, and only the name arm is percent-decoded and checked, since a
/// numeric address cannot contain an escape.
///
/// # Errors
///
/// Whatever the step that failed returned, unchanged. The C's `default:` arm
/// at `:648` maps an unrecognised verdict to [`CURLUcode::BadHostname`]; with
/// [`HostKind`] exhaustive there is no such arm to write.
fn parse_authority(
    u: &mut Url,
    auth: &[u8],
    flags: UrlFlags,
    host: &mut Buf,
    has_scheme: bool,
) -> UrlResult<()> {
    let offset = parse_hostname_login(u, auth, flags)?;

    host.addn(auth.get(offset..).unwrap_or(&[]))
        .map_err(cc2cu)?;

    parse_port(u, host, has_scheme)?;

    // `if(!curlx_dyn_len(host)) return CURLUE_NO_HOST;`
    if host.len() == 0 {
        return Err(CURLUcode::NoHost);
    }

    match ipv4_normalize(host)? {
        HostKind::Ipv4 => Ok(()),
        HostKind::Ipv6 => ipv6_parse(u, host),
        HostKind::Name => {
            urldecode_host(host)?;
            hostname_check(u, host)
        }
    }
}

impl Url {
    /// Replaces the host from an authority string, as HTTP/2 server push
    /// requires.
    ///
    /// Supersedes `Curl_url_set_authority` (`lib/urlapi.c:658-674`), the third
    /// non-unittest export of `lib/urlapi-int.h`, whose comment is *"used for
    /// HTTP/2 server push"*. It runs [`parse_authority`] with
    /// [`UrlFlags::DISALLOW_USER`] fixed, so a pushed authority carrying
    /// credentials is refused, and it passes `!!u->scheme` as `has_scheme` so
    /// that a bare trailing colon behaves as it would in a full URL.
    ///
    /// The host is replaced only on success; on failure the handle keeps the
    /// host it had. The three userinfo parts are **not** protected that way --
    /// [`parse_hostname_login`] clears them whatever happens, which is
    /// visible here precisely because this method runs against a populated
    /// handle.
    ///
    /// # Errors
    ///
    /// As [`parse_authority`].
    // The C's caller is `lib/http2.c`, which arrives with `protocols/http2.rs`.
    #[allow(dead_code)]
    pub(crate) fn set_authority(&mut self, authority: &[u8]) -> UrlResult<()> {
        let mut host = Buf::new(MAX_INPUT_LENGTH);
        let has_scheme = self.scheme.is_some();
        parse_authority(
            self,
            authority,
            UrlFlags::DISALLOW_USER,
            &mut host,
            has_scheme,
        )?;
        self.host = host.take();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Removing dot segments -- `lib/urlapi.c:682-821`.
// ---------------------------------------------------------------------------

/// Consumes a leading dot, spelled either way, and says whether it did.
///
/// `is_dot` (`lib/urlapi.c:682-697`). The second spelling is the point: a
/// percent-encoded dot counts as a dot, and `(p[2] | 0x20) == 'e'` accepts
/// both `%2e` and `%2E`. It is guarded by `*clen >= 3`, so a truncated escape
/// at the end of the path is not a dot.
///
/// One cursor rather than the C's pointer-and-length pair, because the slice
/// carries the length. That is not a simplification of behaviour: the C's
/// `clen` is frequently **shorter** than the NUL-terminated remainder, since
/// `handle_path` counts a path whose buffer still has the query and fragment
/// after it. A slice bounded to the counted extent reproduces that, and the
/// reads the C makes one byte past it land on [`at`]'s zero rather than on the
/// `?` -- neither of which is a dot or a slash, so no branch changes.
fn is_dot(cursor: &mut &[u8]) -> bool {
    let bytes = *cursor;

    // `if(*p == '.') { (*str)++; (*clen)--; return TRUE; }`
    if at(bytes, 0) == b'.' {
        *cursor = bytes.get(1..).unwrap_or(&[]);
        return true;
    }

    // `else if((*clen >= 3) && (p[0] == '%') && (p[1] == '2') &&
    //          ((p[2] | 0x20) == 'e'))`
    if bytes.len() >= 3
        && at(bytes, 0) == b'%'
        && at(bytes, 1) == b'2'
        && (at(bytes, 2) | 0x20) == b'e'
    {
        *cursor = bytes.get(3..).unwrap_or(&[]);
        return true;
    }

    false
}

/// Applies RFC 3986 section 5.2.4 to a path.
///
/// Supersedes `dedotdotify` (`lib/urlapi.c:716-820`), annotated
/// `@unittest: 1395` there; all 71 pairs of `tests/unit/unit1395.c` are
/// ported below. The C's lettered comments name the rules and are kept at the
/// branches they belong to.
///
/// [`None`] is the C's `*outp == NULL`, which happens for an input shorter
/// than two bytes -- the early return at `:723-724`, whose comment is *"the
/// path always starts with a slash, and a slash has not dot"*. The caller
/// then leaves the path alone. An empty [`Vec`] is a different answer, the
/// C's `curlx_strdup("")` at `:815`, and `./` produces it.
///
/// Infallible. The C's only failure is a refused allocation, and its buffer
/// ceiling of `clen + 1` cannot be crossed because the output is never longer
/// than the input.
fn dedotdotify(input: &[u8]) -> Option<Vec<u8>> {
    // `if(clen < 2) return 0;` with `*outp` left null.
    if input.len() < 2 {
        return None;
    }

    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut cursor = input;

    //  A. If the input buffer begins with a prefix of "../" or "./", then
    //     remove that prefix from the input buffer; otherwise,
    if is_dot(&mut cursor) {
        let mut probe = cursor;

        if cursor.is_empty() {
            // `.` [end]
            return Some(out);
        }

        if at(probe, 0) == b'/' {
            // one dot followed by a slash
            cursor = probe.get(1..).unwrap_or(&[]);
        }
        //  D. if the input buffer consists only of "." or "..", then remove
        //     that from the input buffer; otherwise,
        else if is_dot(&mut probe) {
            if probe.is_empty() {
                // `..` [end]
                return Some(out);
            }
            if at(probe, 0) == b'/' {
                // `../`
                cursor = probe.get(1..).unwrap_or(&[]);
            }
        }
    }

    while !cursor.is_empty() {
        if at(cursor, 0) == b'/' {
            let mut probe = cursor.get(1..).unwrap_or(&[]);

            //  B. if the input buffer begins with a prefix of "/./" or "/.",
            //     where "." is a complete path segment, then replace that
            //     prefix with "/" in the input buffer; otherwise,
            if is_dot(&mut probe) {
                if probe.is_empty() {
                    // `/.`
                    out.push(b'/');
                    break;
                }
                if at(probe, 0) == b'/' {
                    // `/./`
                    cursor = probe;
                    continue;
                }

                //  C. if the input buffer begins with a prefix of "/../" or
                //     "/..", where ".." is a complete path segment, then
                //     replace that prefix with "/" in the input buffer and
                //     remove the last segment and its preceding "/" (if any)
                //     from the output buffer; otherwise,
                let mut deeper = probe;
                if is_dot(&mut deeper)
                    && (at(deeper, 0) == b'/' || deeper.is_empty())
                {
                    // `memrchr(ptr, '/', len)` and then a truncation at it.
                    if let Some(last) = memrchr(b'/', &out) {
                        out.truncate(last);
                    }

                    if !deeper.is_empty() {
                        // `/../`
                        cursor = deeper;
                        continue;
                    }
                    // `/..`
                    out.push(b'/');
                    break;
                }
            }
        }

        //  E. move the first path segment in the input buffer to the end of
        //     the output buffer, including the initial "/" character (if any)
        //     and any subsequent characters up to, but not including, the next
        //     "/" character or the end of the input buffer.
        out.push(at(cursor, 0));
        cursor = cursor.get(1..).unwrap_or(&[]);
    }

    Some(out)
}

// ---------------------------------------------------------------------------
// Parsing a whole URL -- `lib/urlapi.c:823-1209`.
// ---------------------------------------------------------------------------

/// Parses a `file:` URL, answering where its path begins.
///
/// Supersedes `parse_file` (`lib/urlapi.c:823-932`). The path runs from the
/// returned offset to the end of the input, which is the C's
/// `pathlen = urllen - (ptr - url)` at every one of its exits.
///
/// The rules, from the C's own citation of RFC 8089 at `:842-870`:
///
/// * `file:/` and shorter is [`CURLUcode::BadFileUrl`] -- *"file:/ is not
///   enough to actually be a complete file: URL"*.
/// * The scheme is forced to `file`, whatever case the input used.
/// * An authority is accepted only when it is empty, `localhost/` or
///   `127.0.0.1/`, both matched case-insensitively and both nine bytes before
///   the slash they must be followed by. Anything else is
///   [`CURLUcode::BadFileUrl`].
/// * The host is **reset to nothing**, which is why `curl_url_get` answers
///   [`CURLUcode::NoHost`] for every `file:` URL.
///
/// # Only the non-Windows arm exists here
///
/// The C has three Windows-conditional blocks -- the UNC fallback at
/// `:879-897`, the drive-letter exception woven into the authority test at
/// `:871`, and the drive-prefix strip at `:922-928`. AAP section 0.2.2
/// excludes Windows, so this reproduces the `#else` at `:898-902` and the
/// `#if !defined(_WIN32)` at `:914-921`: a drive letter is
/// [`CURLUcode::BadFileUrl`], and there is no
/// `STARTS_WITH_URL_DRIVE_PREFIX` anywhere in this module.
///
/// # Errors
///
/// [`CURLUcode::BadFileUrl`].
fn parse_file(url: &[u8], u: &mut Url, host: &mut Buf) -> UrlResult<usize> {
    /// `STARTS_WITH_URL_DRIVE_PREFIX` (`lib/urlapi.c:48-52`), which the
    /// non-Windows build uses only to refuse what it matches: a letter, then
    /// `:` or `|`, then a slash, a backslash or the end of the string.
    fn starts_with_url_drive_prefix(bytes: &[u8]) -> bool {
        let letter = at(bytes, 0);
        let separator = at(bytes, 1);
        let after = at(bytes, 2);
        strparse::is_alpha(letter)
            && (separator == b':' || separator == b'|')
            && (after == b'/' || after == b'\\' || after == 0)
    }

    // `if(urllen <= 6) return CURLUE_BAD_FILE_URL;`
    if url.len() <= 6 {
        return Err(CURLUcode::BadFileUrl);
    }

    // `path = &url[5]; pathlen = urllen - 5;`
    let mut path_start = 5usize;
    u.scheme = Some(b"file".to_vec());

    let path = url.get(path_start..).unwrap_or(&[]);
    if at(path, 0) == b'/' && at(path, 1) == b'/' {
        // `const char *ptr = &path[2];`
        let mut ptr = path_start.saturating_add(2);
        let after = url.get(ptr..).unwrap_or(&[]);

        // `if(ptr[0] != '/' && !STARTS_WITH_URL_DRIVE_PREFIX(ptr))`
        if at(after, 0) != b'/' && !starts_with_url_drive_prefix(after) {
            // `if(checkprefix("localhost/", ptr) ||
            //     checkprefix("127.0.0.1/", ptr)) ptr += 9;`
            //
            // Nine, not ten: the slash is left in place to become the first
            // byte of the path.
            if strcase::checkprefix("localhost/", after)
                || strcase::checkprefix("127.0.0.1/", after)
            {
                ptr = ptr.saturating_add(9);
            } else {
                // The `#else` arm: *"Invalid file://hostname/, expected
                // localhost or 127.0.0.1 or none"*.
                return Err(CURLUcode::BadFileUrl);
            }
        }

        path_start = ptr;
    }

    // `if(!uncpath) curlx_dyn_reset(host);` -- `uncpath` is Windows-only, so
    // the reset is unconditional here. On a buffer that was never appended to
    // this leaves it null, which is the absent host every `file:` URL has.
    host.reset();

    // The `#if !defined(_WIN32)` arm: *"Do not allow Windows drive letters
    // when not in Windows. This catches both file:/c: and file:c:"*.
    let path = url.get(path_start..).unwrap_or(&[]);
    if (at(path, 0) == b'/'
        && starts_with_url_drive_prefix(path.get(1..).unwrap_or(&[])))
        || starts_with_url_drive_prefix(path)
    {
        return Err(CURLUcode::BadFileUrl);
    }

    Ok(path_start)
}

/// Stores the scheme and answers where the host begins.
///
/// Supersedes `parse_scheme` (`lib/urlapi.c:935-981`). `scheme` is the folded
/// name [`is_absolute_url`] produced, or [`None`] when the input carried none.
///
/// The order of the three tests is the C's and is observable: the slashes are
/// **counted first**, then the scheme is looked up, and only then is the count
/// validated. So an unknown scheme with no slashes at all answers
/// [`CURLUcode::UnsupportedScheme`] rather than [`CURLUcode::BadSlashes`] --
/// which is what makes `mailto:infobot@example.com` report an unsupported
/// scheme.
///
/// One to three slashes are accepted and the fourth is fatal:
/// `(i < 1) || (i > 3)` at `:955`. `docs/libcurl/curl_url_set.md:80-83`
/// explains why there is a lower bound -- the parser *"only understands and
/// parses the subset of URLS that are 'hierarchical' and therefore contain a
/// `://` separator"*.
///
/// **The lookup here consults table membership only**, never
/// [`SchemeInfo::runnable`]. That is the parse half of the asymmetry
/// documented on that field.
///
/// # Errors
///
/// [`CURLUcode::UnsupportedScheme`], [`CURLUcode::BadSlashes`] or
/// [`CURLUcode::BadScheme`] -- the last when there is no scheme and neither
/// [`UrlFlags::DEFAULT_SCHEME`] nor [`UrlFlags::GUESS_SCHEME`] was given.
fn parse_scheme(
    url: &[u8],
    u: &mut Url,
    scheme: Option<&[u8]>,
    flags: UrlFlags,
) -> UrlResult<usize> {
    let Some(name) = scheme else {
        // `if(!(flags & (CURLU_DEFAULT_SCHEME | CURLU_GUESS_SCHEME)))
        //    return CURLUE_BAD_SCHEME;`
        if !flags.has(UrlFlags::DEFAULT_SCHEME)
            && !flags.has(UrlFlags::GUESS_SCHEME)
        {
            return Err(CURLUcode::BadScheme);
        }

        // `if(flags & CURLU_DEFAULT_SCHEME) schemep = DEFAULT_SCHEME;` --
        // and this is where DEFAULT_SCHEME beats GUESS_SCHEME, because the
        // guess at `:1151` only runs when no scheme has been stored.
        if flags.has(UrlFlags::DEFAULT_SCHEME) {
            u.scheme = Some(DEFAULT_SCHEME.to_vec());
        }

        // `*hostpp = url;`
        return Ok(0);
    };

    // `const char *p = &url[schemelen + 1]; while((*p == '/') && (i < 4))`
    let mut offset = name.len().saturating_add(1);
    let mut slashes = 0usize;
    while at(url, offset) == b'/' && slashes < 4 {
        offset = offset.saturating_add(1);
        slashes += 1;
    }

    // `if(!Curl_get_scheme(schemep) && !(flags & CURLU_NON_SUPPORT_SCHEME))
    //    return CURLUE_UNSUPPORTED_SCHEME;`
    if u.registry.lookup(name).is_none()
        && !flags.has(UrlFlags::NON_SUPPORT_SCHEME)
    {
        return Err(CURLUcode::UnsupportedScheme);
    }

    // `if((i < 1) || (i > 3)) return CURLUE_BAD_SLASHES;`
    if !(1..=3).contains(&slashes) {
        return Err(CURLUcode::BadSlashes);
    }

    u.scheme = Some(name.to_vec());
    Ok(offset)
}

/// Guesses a scheme from the outermost label of the host name.
///
/// Supersedes `guess_scheme` (`lib/urlapi.c:984-1009`), whose comment is
/// *"legacy curl-style guess based on hostname"*. The prefix table is the C's
/// exactly, in the C's order, and `docs/libcurl/curl_url_set.md:206-210`
/// documents it.
///
/// **The table is not pruned for this rewrite.** Five of its six entries name
/// schemes whose transfer implementations are out of scope -- dict, ldap,
/// imap, smtp and pop3 -- and all five must keep being guessed, because
/// `tests/libtest/lib1560.c` requires `smtp.example.com` to become
/// `smtp://smtp.example.com/` and a request for it to fail later, at the
/// transfer, rather than earlier, at the parse.
///
/// Sets `guessed_scheme`, which is the bit [`Url::dup`] does not carry.
fn guess_scheme(u: &mut Url, host: &Buf) {
    let hostname = host.as_slice();

    let scheme: &[u8] = if strcase::checkprefix("ftp.", hostname) {
        b"ftp"
    } else if strcase::checkprefix("dict.", hostname) {
        b"dict"
    } else if strcase::checkprefix("ldap.", hostname) {
        b"ldap"
    } else if strcase::checkprefix("imap.", hostname) {
        b"imap"
    } else if strcase::checkprefix("smtp.", hostname) {
        b"smtp"
    } else if strcase::checkprefix("pop3.", hostname) {
        b"pop3"
    } else {
        b"http"
    };

    u.scheme = Some(scheme.to_vec());
    u.guessed_scheme = true;
}

/// Stores the fragment, recording that there was one even when it is blank.
///
/// Supersedes `handle_fragment` (`lib/urlapi.c:1012-1033`). `fragment`
/// includes the leading `#`, as the C's pointer does.
///
/// `fragment_present` is set **unconditionally**, before the length is even
/// looked at, and the content is stored only when something follows the `#`.
/// So `http://x/#` records a present, absent fragment -- which is exactly the
/// state [`UrlFlags::GET_EMPTY`] exists to expose, and which
/// `tests/libtest/lib1560.c` checks in both directions.
///
/// # Errors
///
/// As [`urlencode_str`], when [`UrlFlags::URLENCODE`] is set.
fn handle_fragment(
    u: &mut Url,
    fragment: &[u8],
    flags: UrlFlags,
) -> UrlResult<()> {
    u.fragment_present = true;

    // `if(fraglen > 1)` -- more than the '#' itself.
    let content = fragment.get(1..).unwrap_or(&[]);
    if content.is_empty() {
        return Ok(());
    }

    if flags.has(UrlFlags::URLENCODE) {
        let mut enc = Buf::new(MAX_INPUT_LENGTH);
        urlencode_str(&mut enc, content, true, false)?;
        u.fragment = enc.take();
    } else {
        u.fragment = Some(content.to_vec());
    }

    Ok(())
}

/// Stores the query, recording that there was one even when it is blank.
///
/// Supersedes `handle_query` (`lib/urlapi.c:1036-1063`). `query` includes the
/// leading `?`.
///
/// The blank case differs from the fragment's and the difference is measured:
/// a bare `?` stores an **empty string** rather than nothing, because the C's
/// `else` arm at `:1057-1062` is `u->query = curlx_strdup("")`. So
/// `http://x/?` has `query_present` set *and* a query, and
/// [`urlget_url`]'s `show_query` has to test the first byte to tell it from a
/// real one.
///
/// Note also that the encode is asked for a **query** part, so a space in it
/// becomes `+` rather than `%20`.
///
/// # Errors
///
/// As [`urlencode_str`], when [`UrlFlags::URLENCODE`] is set.
fn handle_query(u: &mut Url, query: &[u8], flags: UrlFlags) -> UrlResult<()> {
    u.query_present = true;

    let content = query.get(1..).unwrap_or(&[]);
    if content.is_empty() {
        // `u->query = curlx_strdup("");`
        u.query = Some(Vec::new());
        return Ok(());
    }

    if flags.has(UrlFlags::URLENCODE) {
        let mut enc = Buf::new(MAX_INPUT_LENGTH);
        urlencode_str(&mut enc, content, true, true)?;
        u.query = enc.take();
    } else {
        u.query = Some(content.to_vec());
    }

    Ok(())
}

/// Stores the path, encoded and dot-reduced as the flags ask.
///
/// Supersedes `handle_path` (`lib/urlapi.c:1066-1107`). `path` is the extent
/// left after the fragment and the query have been trimmed off.
///
/// A path of one byte or less is stored as **nothing**: `:1080-1083`, whose
/// comment is *"there is no path left or just the slash, unset"*. That is why
/// `curl_url_get` has to substitute a `/` on the way out, and why a `file:`
/// URL whose whole path is `/` renders through [`NIL_STRING`].
///
/// The encode runs **before** the length test, so a one-byte path that
/// encodes to three bytes is stored rather than dropped.
///
/// # Errors
///
/// As [`urlencode_str`].
fn handle_path(u: &mut Url, path: &[u8], flags: UrlFlags) -> UrlResult<()> {
    // `if(pathlen && (flags & CURLU_URLENCODE))`
    let encoded = if !path.is_empty() && flags.has(UrlFlags::URLENCODE) {
        let mut enc = Buf::new(MAX_INPUT_LENGTH);
        urlencode_str(&mut enc, path, true, false)?;
        enc.take()
    } else {
        None
    };

    let current: &[u8] = match &encoded {
        Some(bytes) => bytes,
        None => path,
    };

    // `if(pathlen <= 1) path = NULL;`
    if current.len() <= 1 {
        u.path = None;
        return Ok(());
    }

    // `if(!(flags & CURLU_PATH_AS_IS))` -- *"remove ../ and ./ sequences
    // according to RFC3986"*.
    if !flags.has(UrlFlags::PATH_AS_IS) {
        if let Some(reduced) = dedotdotify(current) {
            u.path = Some(reduced);
            return Ok(());
        }
    }

    u.path = Some(current.to_vec());
    Ok(())
}

/// Parses `url` into a fresh handle.
///
/// Supersedes `parseurl` (`lib/urlapi.c:1110-1191`). The order of the five
/// steps is the C's, and each depends on the last: the input is scanned for
/// bytes no URL may carry, the scheme is detected, `file:` is diverted before
/// any authority is looked for, the authority is parsed, and only then are the
/// fragment, the query and the path split off the remainder -- in that order,
/// because each is measured from the end of the one before.
///
/// `u` is always a fresh handle here, which is what makes the C's `fail:`
/// arm at `:1188-1191` -- freeing the half-built parts -- unnecessary: the
/// caller drops the whole thing.
///
/// # Errors
///
/// Whatever the step that failed returned.
fn parseurl(url: &[u8], u: &mut Url, flags: UrlFlags) -> UrlResult<()> {
    let mut host = Buf::new(MAX_INPUT_LENGTH);

    junkscan(url, flags.has(UrlFlags::ALLOW_SPACE))?;

    // `Curl_is_absolute_url(url, schemebuf, sizeof(schemebuf),
    //   flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME))` -- either bit
    // puts the scan in guessing mode.
    let guessing = flags.has(UrlFlags::GUESS_SCHEME)
        || flags.has(UrlFlags::DEFAULT_SCHEME);
    let scheme = is_absolute_url(url, guessing);

    // `if(schemelen && !strcmp(schemebuf, "file"))` -- a plain `strcmp`
    // against a name already folded to lower case.
    let is_file = matches!(&scheme, Some(name) if name.as_slice() == b"file");

    let path_start = if is_file {
        parse_file(url, u, &mut host)?
    } else {
        let host_start = parse_scheme(url, u, scheme.as_deref(), flags)?;
        let authority = url.get(host_start..).unwrap_or(&[]);

        // `hostlen = strcspn(hostp, "/?#"); path = &hostp[hostlen];`
        let hostlen = cspn(authority, b"/?#");

        if hostlen != 0 {
            let has_scheme = u.scheme.is_some();
            parse_authority(
                u,
                authority.get(..hostlen).unwrap_or(authority),
                flags,
                &mut host,
                has_scheme,
            )?;
            // `if(!result && (flags & CURLU_GUESS_SCHEME) && !u->scheme)`
            if flags.has(UrlFlags::GUESS_SCHEME) && u.scheme.is_none() {
                guess_scheme(u, &host);
            }
        } else if flags.has(UrlFlags::NO_AUTHORITY) {
            // `if(curlx_dyn_add(&host, ""))` -- an empty host that is
            // nonetheless present, which is the whole point of the flag.
            host.addn(b"").map_err(cc2cu)?;
        } else {
            return Err(CURLUcode::NoHost);
        }

        host_start.saturating_add(hostlen)
    };

    // The remainder still holds the path, the query and the fragment, and
    // they are peeled off from the back.
    let mut rest = url.get(path_start..).unwrap_or(&[]);

    // `const char *fragment = strchr(path, '#');`
    if let Some(hash) = strchr(rest, b'#') {
        handle_fragment(u, rest.get(hash..).unwrap_or(&[]), flags)?;
        rest = rest.get(..hash).unwrap_or(rest);
    }

    // `const char *query = memchr(path, '?', pathlen);`
    if let Some(mark) = rest.iter().position(|byte| *byte == b'?') {
        handle_query(u, rest.get(mark..).unwrap_or(&[]), flags)?;
        rest = rest.get(..mark).unwrap_or(rest);
    }

    handle_path(u, rest, flags)?;

    u.host = host.take();
    Ok(())
}

/// Parses `url` and, on success only, replaces everything in `u`.
///
/// Supersedes `parseurl_and_replace` (`lib/urlapi.c:1197-1208`), whose comment
/// is *"Parse the URL and, if successful, replace everything in the Curl_URL
/// struct."* The C parses into a zeroed stack temporary and assigns it whole;
/// this parses into a fresh [`Url`] carrying the same registry and moves it.
/// Either way a failed parse leaves the handle exactly as it was.
///
/// # Errors
///
/// As [`parseurl`].
fn parseurl_and_replace(
    url: &[u8],
    u: &mut Url,
    flags: UrlFlags,
) -> UrlResult<()> {
    let mut fresh = Url::new(u.registry);
    parseurl(url, &mut fresh, flags)?;
    *u = fresh;
    Ok(())
}

/// Resolves `relurl` against `base` and re-parses the result.
///
/// Supersedes `redirect_url` (`lib/urlapi.c:1214-1283`), whose comment is
/// *"Concatenate a relative URL onto a base URL making it absolute."* The
/// merge is a truncation of `base` followed by an append of `relurl`, and
/// where `base` is cut depends on the first byte of `relurl`:
///
/// * `//` -- protocol-relative, so the cut is at the host and the host
///   changes;
/// * `/` -- an absolute path, so the cut is at the first slash of the path;
/// * `#` -- a fragment, so the cut is at the existing `#`, and only if there
///   is one;
/// * anything else -- a path or a query, so any existing query or fragment
///   goes, and unless the input itself starts with `?` the cut moves back to
///   just after the **last** slash.
///
/// The re-parse drops [`UrlFlags::PATH_AS_IS`] (`:1277`), so a relative merge
/// always has its dot segments removed even when the original parse kept
/// them.
///
/// # The C reads out of bounds here, and this does not
///
/// `protsep = base + strlen(u->scheme) + 3` (`:1225`) assumes `base` begins
/// with `scheme://`. It need not. `curl_url_get(CURLUPART_URL)` omits the
/// scheme entirely when [`UrlFlags::NO_GUESS_SCHEME`] is set and the scheme
/// was guessed (`:1512-1515`), and `set_url` passes the caller's flags
/// straight through when it fetches the base. Parse `a` with
/// [`UrlFlags::GUESS_SCHEME`] and then set `b` with
/// [`UrlFlags::NO_GUESS_SCHEME`]: the base is `a/`, two bytes, and the C
/// forms a pointer seven bytes past its start.
///
/// The offset is therefore clamped to the length of `base`, which is the only
/// safe expression of it, and the clamp is not observable. Measured against a
/// real libcurl, that sequence answers `CURLUE_BAD_SCHEME`; clamping makes
/// `protsep` empty, so no cut is found, so the whole base is kept and `a/b`
/// is re-parsed -- which fails with `CURLUE_BAD_SCHEME` for want of a scheme.
/// Same code, no undefined behaviour.
///
/// # Errors
///
/// As [`parseurl`], or [`CURLUcode::OutOfMemory`] for a buffer refusal. The
/// C collapses both buffer failures into that one code at `:1280` by testing
/// only their truthiness, so a ceiling crossing here does **not** become
/// [`CURLUcode::TooLarge`].
fn redirect_url(
    base: &[u8],
    relurl: &[u8],
    u: &mut Url,
    flags: UrlFlags,
) -> UrlResult<()> {
    // `const char *protsep = base + strlen(u->scheme) + 3;`
    let scheme_len = u.scheme.as_ref().map_or(0, Vec::len);
    let protsep_at = scheme_len.saturating_add(3).min(base.len());
    let protsep = base.get(protsep_at..).unwrap_or(&[]);

    let mut host_changed = false;
    let mut useurl = relurl;
    // An offset within `protsep`, as the C's `cutoff` is a pointer into it.
    let mut cutoff: Option<usize> = None;

    match at(relurl, 0) {
        b'/' => {
            if at(relurl, 1) == b'/' {
                // protocol-relative URL: //example.com/path
                cutoff = Some(0);
                useurl = relurl.get(2..).unwrap_or(&[]);
                host_changed = true;
            } else {
                // absolute /path
                cutoff = strchr(protsep, b'/');
            }
        }
        b'#' => {
            // fragment-only change
            if u.fragment.is_some() {
                cutoff = strchr(protsep, b'#');
            }
        }
        _ => {
            // path or query-only change
            if u.query.as_ref().is_some_and(|query| !query.is_empty()) {
                // remove existing query
                cutoff = strchr(protsep, b'?');
            } else if u
                .fragment
                .as_ref()
                .is_some_and(|fragment| !fragment.is_empty())
            {
                // Remove existing fragment
                cutoff = strchr(protsep, b'#');
            }

            if at(relurl, 0) != b'?' {
                // append a relative path after the last slash
                let extent = cutoff.unwrap_or(protsep.len());
                let searched = protsep.get(..extent).unwrap_or(protsep);
                cutoff = memrchr(b'/', searched)
                    .map(|found| found.saturating_add(1));
            }
        }
    }

    // `prelen = cutoff ? (size_t)(cutoff - base) : strlen(base);`
    let prelen = match cutoff {
        Some(offset) => protsep_at.saturating_add(offset),
        None => base.len(),
    };

    let mut urlbuf = Buf::new(MAX_INPUT_LENGTH);
    if urlbuf.addn(base.get(..prelen).unwrap_or(base)).is_err()
        || urlencode_str(&mut urlbuf, useurl, !host_changed, false).is_err()
    {
        return Err(CURLUcode::OutOfMemory);
    }

    let combined = urlbuf.take().unwrap_or_default();
    parseurl_and_replace(&combined, u, flags.without(UrlFlags::PATH_AS_IS))
}

// ---------------------------------------------------------------------------
// Getting a part -- `lib/urlapi.c:1338-1634`.
// ---------------------------------------------------------------------------

/// The host in its A-label form.
///
/// `host_decode` (`lib/urlapi.c:1338-1345`), which wraps `Curl_idn_decode`
/// and maps its failure: a refused allocation stays
/// [`CURLUcode::OutOfMemory`], anything else becomes
/// [`CURLUcode::BadHostname`].
///
/// # Errors
///
/// [`CURLUcode::OutOfMemory`] or [`CURLUcode::BadHostname`].
fn host_decode(host: &[u8]) -> UrlResult<Vec<u8>> {
    match idn::to_ascii(host) {
        Ok(text) => Ok(text.into_bytes()),
        Err(CURLcode::OutOfMemory) => Err(CURLUcode::OutOfMemory),
        Err(_) => Err(CURLUcode::BadHostname),
    }
}

/// The host in its Unicode form.
///
/// `host_encode` (`lib/urlapi.c:1347-1354`), the mirror of [`host_decode`]
/// over `Curl_idn_encode`, with the same failure mapping.
///
/// # Errors
///
/// [`CURLUcode::OutOfMemory`] or [`CURLUcode::BadHostname`].
fn host_encode(host: &[u8]) -> UrlResult<Vec<u8>> {
    match idn::to_unicode(host) {
        Ok(text) => Ok(text.into_bytes()),
        Err(CURLcode::OutOfMemory) => Err(CURLUcode::OutOfMemory),
        Err(_) => Err(CURLUcode::BadHostname),
    }
}

impl Url {
    /// Applies the get-side flags to one already-selected part.
    ///
    /// Supersedes `urlget_format` (`lib/urlapi.c:1357-1422`). **The order is
    /// fixed and each step feeds the next**:
    ///
    /// 1. `plusdecode` turns every `+` into a space, across the whole part
    ///    (`:1371-1379`). Only [`UrlPart::Query`] ever asks for it.
    /// 2. `urldecode` percent-decodes with control bytes **refused**
    ///    (`:1385`). The C annotates that at `:1383-1384`: *"this
    ///    unconditional rejection of control bytes is documented API
    ///    behavior"*, and `docs/libcurl/curl_url_get.md:78-79` states it as
    ///    *"If there are byte values lower than 32 in the decoded string, the
    ///    get operation returns an error instead."* A failure is
    ///    [`CURLUcode::Urldecode`].
    /// 3. Then **one** of three conversions, as the arms of a single
    ///    `else if` chain: encode, or punycode, or de-punycode.
    ///
    /// Two consequences of that being one chain rather than three tests:
    ///
    /// * [`UrlFlags::URLENCODE`] **wins over** [`UrlFlags::PUNYCODE`] and
    ///   [`UrlFlags::PUNY2IDN`], because it is first.
    /// * The two IDN conversions apply to [`UrlPart::Host`] **only**
    ///   (`:1365-1366` includes `what == CURLUPART_HOST` in each condition),
    ///   and each gate tests **the stored host** rather than the part being
    ///   converted (`:1402`, `:1412`). For the host part those coincide; the
    ///   distinction is what makes the flags inert everywhere else.
    ///
    /// # One documented divergence, and it is a null pointer
    ///
    /// When the part is empty and [`UrlFlags::URLENCODE`] is set, the C's
    /// encode loop appends nothing, `curlx_dyn_ptr` answers null, and
    /// `curl_url_get` therefore returns **`CURLUE_OK` with `*part` left
    /// null** -- measured against a real libcurl for both an empty query and
    /// an empty fragment under `CURLU_GET_EMPTY | CURLU_URLENCODE`. This
    /// returns an empty [`Vec`] instead.
    ///
    /// The divergence is deliberate and bounded. It contradicts the C's own
    /// manual page, which promises a part on success
    /// (`docs/libcurl/curl_url_get.md:249`); it is unreachable from every
    /// in-tree caller, since the three that pass the flag ask for
    /// [`UrlPart::Path`] or [`UrlPart::Url`] and neither is ever empty
    /// (`lib/url.c:1816`, `lib/http.c:1186`, `src/tool_ipfs.c:199`); no
    /// `tests/data` fixture and no row of `tests/libtest/lib1560.c` reaches
    /// it; and a null with a success code is precisely the shape a safe
    /// engine exists to not return. `curl-rs-ffi/src/ffi/url.rs` holds both
    /// the flag word and the returned length, so the boundary can reproduce
    /// the C's null exactly if that is judged preferable -- which is where
    /// such a decision belongs.
    ///
    /// # Errors
    ///
    /// [`CURLUcode::Urldecode`], or whatever [`urlencode_str`],
    /// [`host_decode`] or [`host_encode`] returned.
    fn urlget_format(
        &self,
        what: UrlPart,
        ptr: &[u8],
        plusdecode: bool,
        flags: UrlFlags,
    ) -> UrlResult<Vec<u8>> {
        let urldecode = flags.has(UrlFlags::URLDECODE);
        let urlencode = flags.has(UrlFlags::URLENCODE);
        let punycode = flags.has(UrlFlags::PUNYCODE) && what == UrlPart::Host;
        let depunyfy = flags.has(UrlFlags::PUNY2IDN) && what == UrlPart::Host;

        // `char *part = curlx_memdup0(ptr, partlen);`
        let mut part = ptr.to_vec();

        if plusdecode {
            // `for(i = 0; i < partlen; ++plus, i++) if(*plus == '+') *plus =
            //  ' ';`
            for byte in &mut part {
                if *byte == b'+' {
                    *byte = b' ';
                }
            }
        }

        if urldecode {
            part = escape::urldecode(&part, escape::UrlReject::Ctrl)
                .map_err(|_| CURLUcode::Urldecode)?;
        }

        if urlencode {
            let mut enc = Buf::new(MAX_INPUT_LENGTH);
            urlencode_str(&mut enc, &part, true, what == UrlPart::Query)?;
            part = enc.take().unwrap_or_default();
        } else if punycode {
            if !idn::is_ascii_name(self.host.as_deref()) {
                part = host_decode(&part)?;
            }
        } else if depunyfy && idn::is_ascii_name(self.host.as_deref()) {
            part = host_encode(&part)?;
        }

        Ok(part)
    }

    /// Assembles the whole URL.
    ///
    /// Supersedes `urlget_url` (`lib/urlapi.c:1425-1538`). The assembly at
    /// `:1517-1532` is a single fifteen-argument format string and it is the
    /// **wire contract**: what this produces becomes a request line and a
    /// `Host:` header, and AAP section 0.6.7 measures those byte for byte
    /// against 1,476 fixtures. The fifteen pieces, in order:
    ///
    /// ```text
    /// scheme://  user  :password  ;options  @  host  :port
    ///            path  ?query  #fragment
    /// ```
    ///
    /// with each separator conditional on the piece it introduces -- and
    /// three of those conditions are not what they look like:
    ///
    /// * **Only the password contributes the `:`.** A user with no password
    ///   renders `user@host`, not `user:@host`.
    /// * **The `@` appears when *any* of user, password or options is
    ///   present.** So an options-only handle renders `;opt@host`, which is
    ///   reachable because options survive an unknown scheme (below).
    /// * **The path falls back to `/`**, never to nothing.
    ///
    /// # The `file` scheme short-circuits everything
    ///
    /// `:1440-1447` answers `file://` followed by the path, the query and the
    /// fragment, and nothing else. No host, no port, no userinfo, no scheme
    /// lookup, no port defaulting, no options -- and **no host check either**,
    /// so this is the one arm that cannot fail with
    /// [`CURLUcode::NoHost`]. It is also where [`NIL_STRING`] comes from.
    ///
    /// # The query and the fragment are not symmetric
    ///
    /// `show_query` additionally requires a **non-empty first byte**
    /// (`:1434-1435`) while `show_fragment` does not (`:1432-1433`). The
    /// asymmetry exists because a bare `?` stores an empty query string while
    /// a bare `#` stores no fragment at all, so the query needs the extra
    /// test to tell "present and blank" from "present and real". Its visible
    /// effect: `http://x/?` renders without the `?` unless
    /// [`UrlFlags::GET_EMPTY`] is set, and `http://x/#` likewise.
    ///
    /// # The options survive a scheme the registry does not know
    ///
    /// `if(h && !(h->flags & PROTOPT_URLOPTIONS)) options = NULL;` (`:1477`)
    /// -- the test is guarded by `h`, so a **null** `h` leaves the options in
    /// place. Measured: a handle on `custom://h/` with options set renders
    /// `custom://;opt@h/`. `docs/libcurl/curl_url_get.md:170-173` describes
    /// this as the API allowing the field *"independently of scheme when not
    /// parsing full URLs"*.
    ///
    /// # The host renders through one of four arms, in order
    ///
    /// A bracketed host takes the first arm and the remaining three are then
    /// **skipped entirely** -- so an IPv6 literal is never percent-encoded
    /// and never IDN-converted. Within that arm the zone identifier, if
    /// there is one, is spliced in as `%25`: the trailing `]` is dropped, the
    /// escape and the identifier are appended, and a `]` closes it again
    /// (`:1486-1487`). That is the whole of what
    /// `docs/libcurl/curl_url_get.md:88-89` means by *"even when not asking
    /// for URL encoding, the '%' (byte 37) is URL encoded"*: a stored host
    /// can never contain a raw `%` -- [`hostname_check`] refuses one, and a
    /// bracketed host's `%` becomes the zone identifier -- so this splice is
    /// the only `%` the renderer can emit.
    ///
    /// # Errors
    ///
    /// [`CURLUcode::NoHost`] or [`CURLUcode::NoScheme`], or whatever
    /// [`host_decode`] or [`host_encode`] returned.
    fn urlget_url(&self, flags: UrlFlags) -> UrlResult<Vec<u8>> {
        let show_fragment = self.fragment.is_some()
            || (self.fragment_present && flags.has(UrlFlags::GET_EMPTY));
        let show_query =
            self.query.as_ref().is_some_and(|query| !query.is_empty())
                || (self.query_present && flags.has(UrlFlags::GET_EMPTY));
        let punycode = flags.has(UrlFlags::PUNYCODE);
        let depunyfy = flags.has(UrlFlags::PUNY2IDN);
        let urlencode = flags.has(UrlFlags::URLENCODE);

        let mut out: Vec<u8> = Vec::new();

        // `if(u->scheme && curl_strequal("file", u->scheme))`
        let is_file = self
            .scheme
            .as_ref()
            .is_some_and(|scheme| strcase::casecompare(b"file", scheme));
        if is_file {
            out.extend_from_slice(b"file://");
            match &self.path {
                Some(path) => out.extend_from_slice(path),
                // The unguarded `%s` of `:1442`, and curl's own printf.
                None => out.extend_from_slice(NIL_STRING),
            }
            if show_query {
                out.push(b'?');
            }
            if let Some(query) = &self.query {
                out.extend_from_slice(query);
            }
            if show_fragment {
                out.push(b'#');
            }
            if let Some(fragment) = &self.fragment {
                out.extend_from_slice(fragment);
            }
            return Ok(out);
        }

        // `else if(!u->host) return CURLUE_NO_HOST;`
        let Some(host) = self.host.as_deref() else {
            return Err(CURLUcode::NoHost);
        };

        // `if(u->scheme) scheme = u->scheme; else if(flags &
        //  CURLU_DEFAULT_SCHEME) scheme = DEFAULT_SCHEME; else return
        //  CURLUE_NO_SCHEME;`
        let scheme: &[u8] = match &self.scheme {
            Some(scheme) => scheme,
            None if flags.has(UrlFlags::DEFAULT_SCHEME) => DEFAULT_SCHEME,
            None => return Err(CURLUcode::NoScheme),
        };

        let info = self.registry.lookup(scheme);

        // `:1461-1475`. Declared before `port` so that the borrow of the
        // default-port text outlives the reference to it.
        let default_port;
        let mut port: Option<&[u8]> = self.port.as_deref();
        if port.is_none() && flags.has(UrlFlags::DEFAULT_PORT) {
            if let Some(info) = info {
                default_port = info.default_port.to_string().into_bytes();
                port = Some(&default_port);
            }
        } else if port.is_some() {
            if let Some(info) = info {
                if info.default_port == self.portnum
                    && flags.has(UrlFlags::NO_DEFAULT_PORT)
                {
                    port = None;
                }
            }
        }

        // `if(h && !(h->flags & PROTOPT_URLOPTIONS)) options = NULL;`
        let mut options: Option<&[u8]> = self.options.as_deref();
        if let Some(info) = info {
            if !info.url_options {
                options = None;
            }
        }

        // The four-arm host chain of `:1480-1510`.
        let mut allochost: Option<Vec<u8>> = None;
        if at(host, 0) == b'[' {
            if let Some(zoneid) = &self.zoneid {
                // `dyn_addf("%.*s%%25%s]", (int)hostlen - 1, u->host,
                //  u->zoneid)` -- the trailing bracket is dropped and
                // rewritten after the escape and the identifier.
                let trimmed =
                    host.get(..host.len().saturating_sub(1)).unwrap_or(host);
                let mut built = Vec::with_capacity(
                    trimmed
                        .len()
                        .saturating_add(zoneid.len())
                        .saturating_add(4),
                );
                built.extend_from_slice(trimmed);
                built.extend_from_slice(b"%25");
                built.extend_from_slice(zoneid);
                built.push(b']');
                allochost = Some(built);
            }
        } else if urlencode {
            // `curl_easy_escape(NULL, u->host, 0)`
            allochost = Some(escape::escape(host));
        } else if punycode {
            if !idn::is_ascii_name(Some(host)) {
                allochost = Some(host_decode(host)?);
            }
        } else if depunyfy && idn::is_ascii_name(Some(host)) {
            allochost = Some(host_encode(host)?);
        }

        // `if(!(flags & CURLU_NO_GUESS_SCHEME) || !u->guessed_scheme)`
        if !flags.has(UrlFlags::NO_GUESS_SCHEME) || !self.guessed_scheme {
            out.extend_from_slice(scheme);
            out.extend_from_slice(b"://");
        }

        if let Some(user) = &self.user {
            out.extend_from_slice(user);
        }
        if self.password.is_some() {
            out.push(b':');
        }
        if let Some(password) = &self.password {
            out.extend_from_slice(password);
        }
        if options.is_some() {
            out.push(b';');
        }
        if let Some(options) = options {
            out.extend_from_slice(options);
        }
        if self.user.is_some() || self.password.is_some() || options.is_some() {
            out.push(b'@');
        }
        match &allochost {
            Some(rendered) => out.extend_from_slice(rendered),
            None => out.extend_from_slice(host),
        }
        if port.is_some() {
            out.push(b':');
        }
        if let Some(port) = port {
            out.extend_from_slice(port);
        }
        match &self.path {
            Some(path) => out.extend_from_slice(path),
            None => out.push(b'/'),
        }
        if show_query {
            out.push(b'?');
        }
        if let Some(query) = &self.query {
            out.extend_from_slice(query);
        }
        if show_fragment {
            out.push(b'#');
        }
        if let Some(fragment) = &self.fragment {
            out.extend_from_slice(fragment);
        }

        Ok(out)
    }

    /// Extracts one part of the URL.
    ///
    /// Supersedes `curl_url_get` (`lib/urlapi.c:1541-1633`). Its two argument
    /// checks have no counterpart: a null handle
    /// ([`CURLUcode::BadHandle`]) and a null out-pointer
    /// ([`CURLUcode::BadPartpointer`]) are both unrepresentable here, so both
    /// codes belong to `curl-rs-ffi/src/ffi/url.rs`, which is where a null
    /// pointer can still arrive.
    ///
    /// The per-part table, with the flag adjustments each arm makes:
    ///
    /// * [`UrlPart::Url`] delegates to the assembler and never returns a
    ///   missing-part code.
    /// * [`UrlPart::Scheme`] and [`UrlPart::Port`] **force
    ///   [`UrlFlags::URLDECODE`] off**, annotated *"never for schemes"* and
    ///   *"never for port"* in the C.
    ///   `docs/libcurl/curl_url_get.md:69-70` states it.
    /// * [`UrlPart::Scheme`] additionally answers [`CURLUcode::NoScheme`]
    ///   when [`UrlFlags::NO_GUESS_SCHEME`] is set and the scheme was
    ///   guessed.
    /// * [`UrlPart::Port`] substitutes the registry's default when there is
    ///   none stored and [`UrlFlags::DEFAULT_PORT`] is set, and suppresses a
    ///   stored one that equals the default when
    ///   [`UrlFlags::NO_DEFAULT_PORT`] is. The two arms are mutually
    ///   exclusive by construction.
    /// * [`UrlPart::Path`] **always succeeds**, substituting `/` when no path
    ///   is stored: *"The part is always at least a slash ('/')"*
    ///   (`docs/libcurl/curl_url_get.md:196-197`).
    /// * [`UrlPart::Query`] hides a blank query unless
    ///   [`UrlFlags::GET_EMPTY`] is set, and is the **only** part for which
    ///   [`UrlFlags::URLDECODE`] also turns `+` into a space.
    /// * [`UrlPart::Fragment`] surfaces a blank fragment as an empty string
    ///   when [`UrlFlags::GET_EMPTY`] is set.
    ///
    /// Every other part is returned as stored, or its own missing-part code:
    /// [`CURLUcode::NoUser`], [`CURLUcode::NoPassword`],
    /// [`CURLUcode::NoOptions`], [`CURLUcode::NoHost`] or
    /// [`CURLUcode::NoZoneid`].
    ///
    /// `docs/libcurl/curl_url_get.md:249` -- *"If this function returns an
    /// error, no URL part is returned"* -- is structural here: a `Result`
    /// carries either the part or the code and never both.
    ///
    /// # Errors
    ///
    /// The missing-part code for the requested part, or whatever
    /// [`Self::urlget_format`] or [`Self::urlget_url`] returned.
    pub fn get(&self, what: UrlPart, flags: UrlFlags) -> UrlResult<Vec<u8>> {
        let (source, ifmissing, plusdecode, flags) = match what {
            UrlPart::Url => return self.urlget_url(flags),

            UrlPart::Scheme => {
                let flags = flags.without(UrlFlags::URLDECODE);
                if flags.has(UrlFlags::NO_GUESS_SCHEME) && self.guessed_scheme {
                    return Err(CURLUcode::NoScheme);
                }
                (self.scheme.clone(), CURLUcode::NoScheme, false, flags)
            }

            UrlPart::User => {
                (self.user.clone(), CURLUcode::NoUser, false, flags)
            }

            UrlPart::Password => {
                (self.password.clone(), CURLUcode::NoPassword, false, flags)
            }

            UrlPart::Options => {
                (self.options.clone(), CURLUcode::NoOptions, false, flags)
            }

            UrlPart::Host => {
                (self.host.clone(), CURLUcode::NoHost, false, flags)
            }

            UrlPart::ZoneId => {
                (self.zoneid.clone(), CURLUcode::NoZoneid, false, flags)
            }

            UrlPart::Port => {
                let flags = flags.without(UrlFlags::URLDECODE);
                let mut source = self.port.clone();
                let info = self
                    .scheme
                    .as_ref()
                    .and_then(|scheme| self.registry.lookup(scheme));

                if source.is_none() && flags.has(UrlFlags::DEFAULT_PORT) {
                    if let Some(info) = info {
                        source =
                            Some(info.default_port.to_string().into_bytes());
                    }
                } else if source.is_some() {
                    if let Some(info) = info {
                        if info.default_port == self.portnum
                            && flags.has(UrlFlags::NO_DEFAULT_PORT)
                        {
                            source = None;
                        }
                    }
                }

                (source, CURLUcode::NoPort, false, flags)
            }

            UrlPart::Path => {
                // `ptr = u->path; if(!ptr) ptr = "/";` -- and `ifmissing` is
                // left at the C's initial CURLUE_UNKNOWN_PART, unreachable
                // because the substitution makes the part always present.
                let source = match &self.path {
                    Some(path) => path.clone(),
                    None => b"/".to_vec(),
                };
                (Some(source), CURLUcode::UnknownPart, false, flags)
            }

            UrlPart::Query => {
                let plusdecode = flags.has(UrlFlags::URLDECODE);
                let mut source = self.query.clone();
                // `if(ptr && !ptr[0] && !(flags & CURLU_GET_EMPTY)) ptr =
                //  NULL;`
                if source.as_ref().is_some_and(Vec::is_empty)
                    && !flags.has(UrlFlags::GET_EMPTY)
                {
                    source = None;
                }
                (source, CURLUcode::NoQuery, plusdecode, flags)
            }

            UrlPart::Fragment => {
                let mut source = self.fragment.clone();
                // `if(!ptr && u->fragment_present && flags &
                //  CURLU_GET_EMPTY) ptr = "";`
                if source.is_none()
                    && self.fragment_present
                    && flags.has(UrlFlags::GET_EMPTY)
                {
                    source = Some(Vec::new());
                }
                (source, CURLUcode::NoFragment, false, flags)
            }
        };

        match source {
            Some(bytes) => self.urlget_format(what, &bytes, plusdecode, flags),
            None => Err(ifmissing),
        }
    }

    /// [`Self::get`] over a raw `CURLUPart` value.
    ///
    /// For `curl-rs-ffi/src/ffi/url.rs`, which receives the part as an
    /// integer from C and cannot narrow it. An unrepresentable value is
    /// [`CURLUcode::UnknownPart`], which is what the C's `default:` arm at
    /// `lib/urlapi.c:1626-1628` produces by leaving `ifmissing` untouched.
    ///
    /// # Errors
    ///
    /// [`CURLUcode::UnknownPart`], or as [`Self::get`].
    pub fn get_by_id(&self, what: i32, flags: UrlFlags) -> UrlResult<Vec<u8>> {
        match UrlPart::from_i32(what) {
            Some(part) => self.get(part, flags),
            None => Err(CURLUcode::UnknownPart),
        }
    }
}

// ---------------------------------------------------------------------------
// Setting a part -- `lib/urlapi.c:1636-1997`.
// ---------------------------------------------------------------------------

/// Whether a byte survives unescaped in a path being encoded.
///
/// `allowed_in_path` (`lib/urlapi.c:1779-1802`), transcribed case by case
/// from the `switch`.
///
/// **The switch has eighteen cases and the manual page lists seventeen.** The
/// missing one is `/`, at `lib/urlapi.c:1799`, absent from the list at
/// `docs/libcurl/curl_url_set.md:190`. The code is the contract (AAP section
/// 0.8.1), and this is the single most consequential place in the module to
/// get wrong by trusting the documentation: an implementation that escapes
/// `/` turns every `curl_url_set(u, CURLUPART_PATH, "/a/b", CURLU_URLENCODE)`
/// into `/a%2Fb` and breaks every path-setting fixture.
/// `tests/libtest/lib1560.c` pins it -- `path=one /$!$&'()*+;=:@{}[]%` under
/// `CURLU_URLENCODE` must yield `/one%20/$!$&'()*+;=:@{}[]%25`, with both
/// slashes intact and only the space and the percent escaped.
///
/// Note also what is **not** here: this set is consulted in addition to
/// `ISUNRESERVED` and only when `pathmode` is on, so it widens the path's
/// accept set rather than defining it.
const fn allowed_in_path(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'{'
            | b'}'
            | b'['
            | b']'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'@'
            | b'/'
    )
}

/// Which field a set stores into.
///
/// The C carries `char **storep` -- a pointer to the struct member -- from
/// the `switch` at `lib/urlapi.c:1828-1875` down to the assignment at
/// `:1994-1995`. A borrow cannot be held across the work in between, because
/// that work also needs `&mut` access to the handle: the host check stores a
/// zone identifier, and the query append reads the existing query. Naming the
/// field and resolving it at the end is the same program without the
/// aliasing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    /// `&u->scheme`.
    Scheme,
    /// `&u->user`.
    User,
    /// `&u->password`.
    Password,
    /// `&u->options`.
    Options,
    /// `&u->host`.
    Host,
    /// `&u->zoneid`.
    ZoneId,
    /// `&u->path`.
    Path,
    /// `&u->query`.
    Query,
    /// `&u->fragment`.
    Fragment,
}

impl Url {
    /// The field `slot` names.
    fn slot_mut(&mut self, slot: Slot) -> &mut Option<Vec<u8>> {
        match slot {
            Slot::Scheme => &mut self.scheme,
            Slot::User => &mut self.user,
            Slot::Password => &mut self.password,
            Slot::Options => &mut self.options,
            Slot::Host => &mut self.host,
            Slot::ZoneId => &mut self.zoneid,
            Slot::Path => &mut self.path,
            Slot::Query => &mut self.query,
            Slot::Fragment => &mut self.fragment,
        }
    }

    /// Validates a scheme being set, and clears the guessed-scheme bit.
    ///
    /// Supersedes `set_url_scheme` (`lib/urlapi.c:1636-1663`). Three tests in
    /// this order:
    ///
    /// 1. The length is `1..=40`, or [`CURLUcode::BadScheme`].
    ///    `docs/libcurl/curl_url_set.md:102-103`: *"Scheme cannot be URL
    ///    decoded on set. libcurl only accepts setting schemes up to 40 bytes
    ///    long."*
    /// 2. Unless [`UrlFlags::NON_SUPPORT_SCHEME`] is set, the scheme must be
    ///    in the registry **and have an implementation** -- `(!h || !h->run)`
    ///    at `:1646`. This is the set half of the asymmetry documented on
    ///    [`SchemeInfo::runnable`], and it is why parsing `smtp://host/` can
    ///    succeed where setting the scheme `smtp` cannot.
    /// 3. **Only when the scheme is absent from the registry**, its syntax is
    ///    checked: a letter, then letters, digits, `+`, `-` or `.`. A known
    ///    scheme skips this, which is how the four upper-case registry names
    ///    would pass it even though `ISALPHA` would accept them anyway.
    ///
    /// # The syntax loop does not examine the last byte
    ///
    /// `while(--plen)` at `:1652` pre-decrements, so the body runs `plen - 1`
    /// times while the cursor starts at the **first** byte -- so the byte at
    /// `plen - 1` is never tested. `set(SCHEME, "ab$")` is therefore accepted
    /// under [`UrlFlags::NON_SUPPORT_SCHEME`], and measured against a real
    /// libcurl it is. Reproduced under AAP section 0.8.2's minimal-change
    /// mandate, and `tests::a_trailing_byte_of_a_scheme_is_never_examined`
    /// is the guard so that nobody "tidies" the loop into checking it.
    ///
    /// # Errors
    ///
    /// [`CURLUcode::BadScheme`] or [`CURLUcode::UnsupportedScheme`].
    fn set_url_scheme(
        &mut self,
        scheme: &[u8],
        flags: UrlFlags,
    ) -> UrlResult<()> {
        let plen = scheme.len();

        // `if((plen > MAX_SCHEME_LEN) || (plen < 1)) return
        //  CURLUE_BAD_SCHEME;`
        if !(1..=MAX_SCHEME_LEN).contains(&plen) {
            return Err(CURLUcode::BadScheme);
        }

        let info = self.registry.lookup(scheme);

        // `if(!(flags & CURLU_NON_SUPPORT_SCHEME) && (!h || !h->run))`
        if !flags.has(UrlFlags::NON_SUPPORT_SCHEME)
            && !info.is_some_and(|info| info.runnable)
        {
            return Err(CURLUcode::UnsupportedScheme);
        }

        if info.is_none() {
            // `if(ISALPHA(*s)) { ... } else return CURLUE_BAD_SCHEME;`
            if !strparse::is_alpha(at(scheme, 0)) {
                return Err(CURLUcode::BadScheme);
            }

            // `while(--plen) { if(ISALNUM(*s) || +-.) s++; else return; }`
            let mut index = 0usize;
            let mut remaining = plen;
            loop {
                remaining = remaining.saturating_sub(1);
                if remaining == 0 {
                    break;
                }
                let byte = at(scheme, index);
                if strparse::is_alnum(byte)
                    || byte == b'+'
                    || byte == b'-'
                    || byte == b'.'
                {
                    index = index.saturating_add(1);
                } else {
                    return Err(CURLUcode::BadScheme);
                }
            }
        }

        self.guessed_scheme = false;
        Ok(())
    }

    /// Stores a port from its decimal text.
    ///
    /// Supersedes `set_url_port` (`lib/urlapi.c:1666-1682`). The first byte
    /// must be a digit -- which is what refuses an empty string and a leading
    /// sign -- the value must fit in sixteen bits, and **the whole string
    /// must be consumed**, so `56 78` and `123a` are refused rather than
    /// truncated. The stored text is re-rendered from the number, so
    /// `01` becomes `1`.
    ///
    /// Note what is absent: no flag is consulted, so
    /// [`UrlFlags::URLENCODE`] has no effect on a port.
    ///
    /// # Errors
    ///
    /// [`CURLUcode::BadPortNumber`].
    fn set_url_port(&mut self, provided: &[u8]) -> UrlResult<()> {
        // `if(!ISDIGIT(provided_port[0])) return CURLUE_BAD_PORT_NUMBER;`
        if !strparse::is_digit(at(provided, 0)) {
            return Err(CURLUcode::BadPortNumber);
        }

        let mut cursor = provided;
        let Ok(port) = strparse::str_number(&mut cursor, 0xffff) else {
            return Err(CURLUcode::BadPortNumber);
        };
        if !cursor.is_empty() {
            return Err(CURLUcode::BadPortNumber);
        }

        self.portnum = u16::try_from(port).unwrap_or(0);
        self.port = Some(self.portnum.to_string().into_bytes());
        Ok(())
    }

    /// Replaces the URL, absolutely or relatively.
    ///
    /// Supersedes `set_url` (`lib/urlapi.c:1685-1729`), whose comment is
    /// *"Allow a new URL to replace the existing (if any) contents. If the
    /// existing contents is enough for a URL, allow a relative URL to replace
    /// it."*
    ///
    /// Four cases, in the C's order:
    ///
    /// 1. **An empty input** is a redirect that changes nothing, and it is
    ///    accepted only if the handle already yields a whole URL; otherwise
    ///    [`CURLUcode::MalformedInput`].
    ///    `docs/libcurl/curl_url_set.md:96-98`: *"It is considered fine to set
    ///    a blank URL ("") as a redirect, but not as a normal URL."*
    /// 2. **An absolute input** replaces everything.
    /// 3. **An incomplete handle** -- one that cannot render a whole URL --
    ///    also takes the replacement, since there is nothing to merge into.
    /// 4. Otherwise the input is merged as a relative reference.
    ///
    /// Note that cases 1 and 3 fetch the base with **the caller's flags**,
    /// which is how [`UrlFlags::NO_GUESS_SCHEME`] reaches
    /// [`redirect_url`]'s base and produces the out-of-bounds pointer
    /// documented there.
    ///
    /// # Errors
    ///
    /// [`CURLUcode::MalformedInput`], [`CURLUcode::OutOfMemory`], or as
    /// [`parseurl`] and [`redirect_url`].
    fn set_url(&mut self, url: &[u8], flags: UrlFlags) -> UrlResult<()> {
        // `if(!part_size)`
        if url.is_empty() {
            return match self.get(UrlPart::Url, flags) {
                Ok(_) => Ok(()),
                Err(CURLUcode::OutOfMemory) => Err(CURLUcode::OutOfMemory),
                Err(_) => Err(CURLUcode::MalformedInput),
            };
        }

        // `if(Curl_is_absolute_url(url, NULL, 0, flags & (CURLU_GUESS_SCHEME |
        //  CURLU_DEFAULT_SCHEME))) return parseurl_and_replace(url, u,
        //  flags);`
        let guessing = flags.has(UrlFlags::GUESS_SCHEME)
            || flags.has(UrlFlags::DEFAULT_SCHEME);
        if is_absolute_url(url, guessing).is_some() {
            return parseurl_and_replace(url, self, flags);
        }

        // `uc = curl_url_get(u, CURLUPART_URL, &oldurl, flags);`
        let oldurl = match self.get(UrlPart::Url, flags) {
            Ok(text) => text,
            Err(CURLUcode::OutOfMemory) => return Err(CURLUcode::OutOfMemory),
            Err(_) => return parseurl_and_replace(url, self, flags),
        };

        redirect_url(&oldurl, url, self, flags)
    }

    /// Clears one part, as a null `part` asks.
    ///
    /// Supersedes `urlset_clear` (`lib/urlapi.c:1732-1776`).
    /// `docs/libcurl/curl_url_set.md:54-55` states the trigger: *"Passing a
    /// NULL instead of a part string, clears that part."*
    ///
    /// Three arms do more than release a string, and one does less than a
    /// reader expects:
    ///
    /// * [`UrlPart::Url`] resets the **whole handle**: the C is
    ///   `free_urlhandle(u)` followed by `memset(u, 0, sizeof(*u))`, so the
    ///   port number and all three bits go too. One assignment here, with the
    ///   registry carried across because it is not one of the C's fields and
    ///   the handle has to stay usable.
    /// * [`UrlPart::Scheme`] also clears `guessed_scheme`.
    /// * [`UrlPart::Port`] also zeroes the port number, and
    ///   [`UrlPart::Query`] and [`UrlPart::Fragment`] clear their
    ///   present bits -- which is what makes clearing a blank query different
    ///   from setting it blank.
    /// * [`UrlPart::Host`] clears **only** the host. It does *not* clear the
    ///   zone identifier: `:1752-1754` is two lines and neither of them
    ///   mentions it. Only setting a host to a non-null value does that, at
    ///   `:1848`. Measured against a real libcurl, which keeps the zone
    ///   identifier across `curl_url_set(u, CURLUPART_HOST, NULL, 0)`.
    ///
    /// # Errors
    ///
    /// Never for a representable part. The C's `default:` arm at `:1773`
    /// answers [`CURLUcode::UnknownPart`], which [`Self::set_by_id`] produces
    /// instead.
    fn urlset_clear(&mut self, what: UrlPart) -> UrlResult<()> {
        match what {
            UrlPart::Url => *self = Self::new(self.registry),
            UrlPart::Scheme => {
                self.scheme = None;
                self.guessed_scheme = false;
            }
            UrlPart::User => self.user = None,
            UrlPart::Password => self.password = None,
            UrlPart::Options => self.options = None,
            UrlPart::Host => self.host = None,
            UrlPart::ZoneId => self.zoneid = None,
            UrlPart::Port => {
                self.portnum = 0;
                self.port = None;
            }
            UrlPart::Path => self.path = None,
            UrlPart::Query => {
                self.query = None;
                self.query_present = false;
            }
            UrlPart::Fragment => {
                self.fragment = None;
                self.fragment_present = false;
            }
        }
        Ok(())
    }

    /// Stores one part of the URL, or clears it when `part` is [`None`].
    ///
    /// Supersedes `curl_url_set` (`lib/urlapi.c:1805-1997`). `None` is the C's
    /// null pointer and delegates to [`Self::urlset_clear`]; a null handle is
    /// unrepresentable, so [`CURLUcode::BadHandle`] belongs to the FFI.
    ///
    /// `part` is the byte range the caller resolved. Across the C ABI that is
    /// `CStr::to_bytes`, which stops at the terminator exactly as the C's own
    /// `strlen(part)` at `:1823` does, so the two agree for every input a C
    /// caller can construct. A Rust caller passing an interior zero gets it
    /// stored rather than truncated, which is a boundary convention rather
    /// than a behaviour: [`Self::set`] with [`UrlPart::Url`] refuses one
    /// anyway, through [`junkscan`].
    ///
    /// The per-part table:
    ///
    /// * [`UrlPart::Scheme`] validates first and then **forces
    ///   [`UrlFlags::URLENCODE`] off** -- annotated *"never"* at `:1834`.
    /// * [`UrlPart::Host`] **also clears the zone identifier** (`:1848`) and
    ///   is the only part whose value is validated after encoding.
    /// * [`UrlPart::Path`] turns on `pathmode`, which widens the unescaped
    ///   set by [`allowed_in_path`], and **enforces a leading `/`**, which is
    ///   prepended when the input lacks one. So
    ///   `set(PATH, "")` stores `/`.
    /// * [`UrlPart::Query`] plus-encodes spaces when encoding at all, appends
    ///   rather than replaces under [`UrlFlags::APPENDQUERY`], and in that
    ///   case leaves **the first `=` unescaped** -- `equalsencode` is
    ///   initialised from `appendquery` at `:1863` and cleared on first use at
    ///   `:1900-1902`, so `name=joe=` appends as `name=joe%3D`. It also sets
    ///   `query_present`.
    /// * [`UrlPart::Fragment`] sets `fragment_present`.
    /// * [`UrlPart::Port`] and [`UrlPart::Url`] delegate and return.
    ///
    /// # The append inserts a separator only when there is something to
    /// separate
    ///
    /// `&` is inserted only when the existing query is non-empty **and** does
    /// not already end with one (`:1940-1941`), and the whole append is
    /// skipped when the existing query is empty -- in which case the new value
    /// simply replaces it.
    ///
    /// # Percent triplets are lower-cased when not encoding
    ///
    /// `:1922-1932`, under the comment *"make sure percent encoded are lower
    /// case"*. So `set(PATH, "/%2F", 0)` stores `/%2f`. This coexists with
    /// [`escape::escape`] and [`escape::hexbyte`] emitting **upper** case, and
    /// both are observable: `set(PATH, "/ ", CURLU_URLENCODE)` stores `/%20`.
    /// Three hex-casing behaviours live in this directory and all three are
    /// deliberate.
    ///
    /// # Errors
    ///
    /// [`CURLUcode::MalformedInput`] for an input longer than eight million
    /// bytes -- the test is `>`, so exactly eight million is accepted --
    /// [`CURLUcode::BadHostname`], or whatever the delegated setter returned.
    pub fn set(
        &mut self,
        what: UrlPart,
        part: Option<&[u8]>,
        flags: UrlFlags,
    ) -> UrlResult<()> {
        let Some(part) = part else {
            return self.urlset_clear(what);
        };

        // `nalloc = strlen(part); if(nalloc > CURL_MAX_INPUT_LENGTH) return
        //  CURLUE_MALFORMED_INPUT;`
        let nalloc = part.len();
        if nalloc > MAX_INPUT_LENGTH {
            return Err(CURLUcode::MalformedInput);
        }

        let mut urlencode = flags.has(UrlFlags::URLENCODE);
        let mut plusencode = false;
        let mut pathmode = false;
        let mut leadingslash = false;
        let mut appendquery = false;
        let mut equalsencode = false;

        let slot = match what {
            UrlPart::Scheme => {
                self.set_url_scheme(part, flags)?;
                urlencode = false;
                Slot::Scheme
            }
            UrlPart::User => Slot::User,
            UrlPart::Password => Slot::Password,
            UrlPart::Options => Slot::Options,
            UrlPart::Host => {
                self.zoneid = None;
                Slot::Host
            }
            UrlPart::ZoneId => Slot::ZoneId,
            UrlPart::Port => return self.set_url_port(part),
            UrlPart::Path => {
                pathmode = true;
                leadingslash = true;
                Slot::Path
            }
            UrlPart::Query => {
                plusencode = urlencode;
                appendquery = flags.has(UrlFlags::APPENDQUERY);
                equalsencode = appendquery;
                self.query_present = true;
                Slot::Query
            }
            UrlPart::Fragment => {
                self.fragment_present = true;
                Slot::Fragment
            }
            UrlPart::Url => return self.set_url(part, flags),
        };

        // `curlx_dyn_init(&enc, nalloc * 3 + 1 + leadingslash);` -- the
        // tightest ceiling in the file, and it fits an all-escaped input to
        // the byte.
        let ceiling = nalloc
            .saturating_mul(3)
            .saturating_add(1)
            .saturating_add(usize::from(leadingslash));
        let mut enc = Buf::new(ceiling);

        // `if(leadingslash && (part[0] != '/'))` -- and for an empty part
        // `part[0]` is the terminator, so the slash is prepended.
        if leadingslash && at(part, 0) != b'/' {
            enc.addn(b"/").map_err(cc2cu)?;
        }

        if urlencode {
            for byte in part {
                if *byte == b' ' && plusencode {
                    // `:1892-1896`, which reports OUT_OF_MEMORY rather than
                    // going through cc2cu as its two neighbours do. An
                    // inconsistency in the C, reproduced.
                    enc.addn(b"+").map_err(|_| CURLUcode::OutOfMemory)?;
                } else if strparse::is_unreserved(*byte)
                    || (pathmode && allowed_in_path(*byte))
                    || (*byte == b'=' && equalsencode)
                {
                    if *byte == b'=' && equalsencode {
                        // only skip the first equals sign
                        equalsencode = false;
                    }
                    enc.addn(&[*byte]).map_err(cc2cu)?;
                } else {
                    let digits = escape::hexbyte(*byte);
                    enc.addn(&[b'%', digits[0], digits[1]]).map_err(cc2cu)?;
                }
            }
        } else {
            enc.addn(part).map_err(cc2cu)?;

            // `while(*p) { if((*p == '%') && ISXDIGIT(p[1]) && ISXDIGIT(p[2])
            //  && (ISUPPER(p[1]) || ISUPPER(p[2]))) { lower; lower; p += 3; }
            //  else p++; }`
            //
            // The walk covers the prepended slash too, which is harmless: it
            // is not a percent sign. Reading `p[1]` and `p[2]` past the end
            // lands on the C's terminator, which is not a hex digit, so the
            // guard fails there; `at` answers zero for the same reason.
            let bytes = enc.as_mut_slice();
            let mut index = 0usize;
            while index < bytes.len() {
                let one = at(bytes, index.saturating_add(1));
                let two = at(bytes, index.saturating_add(2));
                if at(bytes, index) == b'%'
                    && strparse::is_xdigit(one)
                    && strparse::is_xdigit(two)
                    && (strparse::is_upper(one) || strparse::is_upper(two))
                {
                    if let Some(slot) = bytes.get_mut(index.saturating_add(1)) {
                        *slot = strcase::raw_tolower(one);
                    }
                    if let Some(slot) = bytes.get_mut(index.saturating_add(2)) {
                        *slot = strcase::raw_tolower(two);
                    }
                    index = index.saturating_add(3);
                } else {
                    index = index.saturating_add(1);
                }
            }
        }

        // `newp = curlx_dyn_ptr(&enc);` -- null when nothing was appended,
        // which is how an empty part under URLENCODE clears the field.
        let length = enc.len();
        let newp = enc.take();

        if appendquery && newp.is_some() {
            // `size_t querylen = u->query ? strlen(u->query) : 0;`
            let existing = self.query.clone().unwrap_or_default();
            if !existing.is_empty() {
                // `bool addamperand = querylen && (u->query[querylen - 1] !=
                //  '&');`
                let addamperand =
                    at(&existing, existing.len().saturating_sub(1)) != b'&';

                let mut qbuf = Buf::new(MAX_INPUT_LENGTH);
                qbuf.addn(&existing).map_err(|_| CURLUcode::OutOfMemory)?;
                if addamperand {
                    qbuf.addn(b"&").map_err(|_| CURLUcode::OutOfMemory)?;
                }
                qbuf.addn(newp.as_deref().unwrap_or(&[]))
                    .map_err(|_| CURLUcode::OutOfMemory)?;

                *self.slot_mut(slot) = qbuf.take();
                return Ok(());
            }
        } else if what == UrlPart::Host {
            // `if(!n && (flags & CURLU_NO_AUTHORITY)) { /* Skip hostname
            //  check, it is allowed to be empty. */ }`
            if !(length == 0 && flags.has(UrlFlags::NO_AUTHORITY)) {
                let mut bad = length == 0;

                if !bad {
                    let candidate = newp.as_deref().unwrap_or(&[]);
                    if urlencode {
                        // `else if(hostname_check(u, newp, n)) bad = TRUE;`
                        //
                        // The C checks the stored buffer in place, so a
                        // mutation here would survive. It cannot happen: the
                        // bracketed arm of hostname_check needs a leading
                        // '[', and '[' is neither unreserved nor allowed in a
                        // path, so encoding has already turned it into %5B --
                        // which the reject set then refuses. The scratch copy
                        // is therefore equivalent.
                        bad = check_host_candidate(self, candidate);
                    } else {
                        // The C decodes first, because a host set without
                        // encoding *arrives* encoded: *"if the hostname part
                        // was not URL encoded here, it was set ready URL
                        // encoded so we need to decode it to check"*. The
                        // decoded copy is then thrown away -- only the verdict
                        // and any zone identifier survive.
                        match escape::urldecode(
                            candidate,
                            escape::UrlReject::Ctrl,
                        ) {
                            Ok(decoded) => {
                                bad = check_host_candidate(self, &decoded);
                            }
                            Err(_) => bad = true,
                        }
                    }
                }

                if bad {
                    return Err(CURLUcode::BadHostname);
                }
            }
        }

        *self.slot_mut(slot) = newp;
        Ok(())
    }

    /// [`Self::set`] over a raw `CURLUPart` value.
    ///
    /// For `curl-rs-ffi/src/ffi/url.rs`. An unrepresentable value is
    /// [`CURLUcode::UnknownPart`], which is both the C's `default:` arm in
    /// `curl_url_set` (`lib/urlapi.c:1873`) and the one in `urlset_clear`
    /// (`:1773`) -- so a null `part` with an unknown identifier answers the
    /// same code, exactly as the C does.
    ///
    /// # Errors
    ///
    /// [`CURLUcode::UnknownPart`], or as [`Self::set`].
    pub fn set_by_id(
        &mut self,
        what: i32,
        part: Option<&[u8]>,
        flags: UrlFlags,
    ) -> UrlResult<()> {
        match UrlPart::from_i32(what) {
            Some(resolved) => self.set(resolved, part, flags),
            None => Err(CURLUcode::UnknownPart),
        }
    }
}

/// Whether `candidate` is a bad host name, keeping any zone identifier.
///
/// The `hostname_check` half of `curl_url_set`'s host validation
/// (`lib/urlapi.c:1974-1986`), which discards the specific code and keeps only
/// the verdict -- every failure becomes [`CURLUcode::BadHostname`] there,
/// including the [`CURLUcode::BadIpv6`] that [`ipv6_parse`] would have
/// reported.
///
/// The scratch buffer is sized to hold `candidate` exactly, so it introduces
/// no ceiling the C does not have: the C validates a plain allocation with no
/// limit attached.
fn check_host_candidate(u: &mut Url, candidate: &[u8]) -> bool {
    let mut scratch = Buf::new(candidate.len().saturating_add(1));
    if scratch.addn(candidate).is_err() {
        return true;
    }
    hostname_check(u, &mut scratch).is_err()
}

// ---------------------------------------------------------------------------
// Tests.
//
// AAP section 0.8.7 records the deviation these tests answer: the C programs
// under `tests/libtest/` and `tests/unit/` link a debug static libcurl and
// call internal `Curl_*` symbols, and a Rust `pub(crate)` item is genuinely
// absent from a static library's symbol table -- not merely hidden -- so no
// quality of implementation makes them link. Re-exporting internals to satisfy
// them is ruled out, because that encapsulation is what makes the
// zero-`unsafe` guarantee possible. Their coverage is relocated here instead.
//
// Three C tests cover this module and all three are ported:
//
// * `tests/libtest/lib1560.c` (2,075 lines) -- the URL API conformance
//   corpus. All seven tables and all six hand-written drivers.
// * `tests/unit/unit1395.c` (141 lines) -- 80 `dedotdotify` pairs.
// * `tests/unit/unit1653.c` (218 lines) -- 11 `Curl_parse_port` cases.
//
// The ported tables are mechanical transcriptions with the C preprocessor
// resolved for this workspace: `USE_IDN` is on, because `idna` is an
// unconditional dependency and AAP section 0.5.2's fifteen-name feature
// vocabulary has no `idn` feature; `CURL_DISABLE_WEBSOCKETS` is off; `_WIN32`
// is off, which drops the four drive-letter rows that AAP section 0.2.2
// excludes anyway.
//
// Every test is Miri-runnable: no network, no filesystem, no clock, no
// environment access, no threads, no allocation the test itself does not own.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::{
        allowed_in_path, dedotdotify, escape, guess_scheme, is_absolute_url,
        is_dot, junkscan, parse_port, strcase, urlencode_str, Buf, SchemeInfo,
        SchemeRegistry, Url, UrlFlags, UrlPart, DEFAULT_SCHEME,
        MAX_INPUT_LENGTH, MAX_SCHEME_LEN,
    };
    use crate::error::CURLUcode;

    use super::UrlFlags as F;
    use super::UrlPart as P;
    /// Shorthands, so a ported row stays legible next to its C original.
    use crate::error::CURLUcode as E;

    // -----------------------------------------------------------------------
    // The fixture scheme table.
    // -----------------------------------------------------------------------

    /// One row per scheme the ported tests reach for.
    ///
    /// `(name, default port, url_options, unconditionally runnable)`.
    ///
    /// The names and ports are `lib/urldata.h:29-53` and the handler
    /// registrations; the four upper-case names are reproduced exactly as the
    /// C stores them -- `"WS"` (`lib/ws.c:1985`), `"WSS"` (`:2000`),
    /// `"SFTP"` (`lib/vssh/vssh.c:339`) and `"SCP"` (`:353`) -- so that a
    /// case-sensitive comparison anywhere in the module would fail a test
    /// rather than pass unnoticed.
    ///
    /// The fourth column separates the nine schemes this workspace implements
    /// (AAP section 0.2.1) from the nine it stubs. A stubbed scheme's
    /// `runnable` comes from the fixture's own flag, which is what lets the
    /// same table serve both registries below.
    const SCHEMES: &[(&str, u16, bool, bool)] = &[
        ("http", 80, false, true),
        ("https", 443, false, true),
        ("ftp", 21, false, true),
        ("ftps", 990, false, true),
        ("SFTP", 22, false, true),
        ("SCP", 22, false, true),
        ("file", 0, false, true),
        ("WS", 80, false, true),
        ("WSS", 443, false, true),
        ("imap", 143, true, false),
        ("imaps", 993, true, false),
        ("pop3", 110, true, false),
        ("pop3s", 995, true, false),
        ("smtp", 25, true, false),
        ("smtps", 465, true, false),
        ("dict", 2628, false, false),
        ("ldap", 389, false, false),
        ("ldaps", 636, false, false),
    ];

    /// A scheme table for the tests, standing in for `protocols/mod.rs`.
    ///
    /// This is the injected registry AAP section 0.3.3 pattern P12 calls for,
    /// and its existence is the point: the parser is testable before the
    /// transfer engine exists, which is exactly what the dependency inversion
    /// buys.
    struct Fixture {
        /// Whether the nine stubbed schemes report an implementation.
        stubs_runnable: bool,
    }

    impl SchemeRegistry for Fixture {
        fn lookup(&self, scheme: &[u8]) -> Option<SchemeInfo> {
            // `Curl_getn_scheme` is gated `if(len && (len <= 7))`
            // (`lib/url.c:1519`), so no scheme longer than seven bytes can
            // resolve however long `MAX_SCHEME_LEN` allows on the way in.
            // Reproduced, not "fixed": the `scheme=bbb...` rows of
            // `set_parts_list` depend on a forty-byte name missing the table
            // and falling through to the syntax check.
            if scheme.is_empty() || scheme.len() > 7 {
                return None;
            }
            SCHEMES
                .iter()
                .find(|(name, _, _, _)| {
                    // Case-insensitive, because the C folds both sides.
                    let name = name.as_bytes();
                    name.len() == scheme.len()
                        && strcase::casecompare(name, scheme)
                })
                .map(|(name, port, options, always)| SchemeInfo {
                    name,
                    default_port: *port,
                    url_options: *options,
                    runnable: *always || self.stubs_runnable,
                })
        }
    }

    /// The registry the ported `lib1560.c` tables run against.
    ///
    /// `tests/data/test1560`'s own `<features>` block demands `file`,
    /// `https`, `http`, `pop3`, `smtp`, `imap`, `ldap`, `dict` and `ftp`, and
    /// `lib1560.c:24-30` says why: *"Since the URL parser by default only
    /// accepts schemes that this instance of libcurl supports, make sure that
    /// the test1560 file lists all the schemes that this test will assume to
    /// be present!"* So the expectations in those tables were written against
    /// a build where all of them are implemented, and reproducing them
    /// requires the same.
    static ENABLED: Fixture = Fixture {
        stubs_runnable: true,
    };

    /// The registry that models this workspace's own protocol set.
    ///
    /// The nine schemes AAP section 0.2.1 implements are runnable; the rest
    /// are present but not, which is the C's `run = ZERO_NULL` for a protocol
    /// disabled at build time. This is the registry the parse-versus-set
    /// asymmetry is tested against.
    static STUBBED: Fixture = Fixture {
        stubs_runnable: false,
    };

    /// A fresh handle over [`ENABLED`].
    fn handle() -> Url {
        Url::new(&ENABLED)
    }

    /// A fresh handle over [`STUBBED`].
    fn stubbed() -> Url {
        Url::new(&STUBBED)
    }

    // -----------------------------------------------------------------------
    // Helpers, ported from `lib1560.c`'s own.
    // -----------------------------------------------------------------------

    /// Renders bytes for an assertion message without losing any of them.
    fn show(bytes: &[u8]) -> String {
        let mut out = String::new();
        for byte in bytes {
            if (0x20..0x7f).contains(byte) {
                out.push(char::from(*byte));
            } else {
                out.push_str(&format!("\\x{byte:02x}"));
            }
        }
        out
    }

    /// The nine parts `checkparts` walks, in its order.
    const CHECKED: &[UrlPart] = &[
        UrlPart::Scheme,
        UrlPart::User,
        UrlPart::Password,
        UrlPart::Options,
        UrlPart::Host,
        UrlPart::Port,
        UrlPart::Path,
        UrlPart::Query,
        UrlPart::Fragment,
    ];

    /// `checkparts` (`tests/libtest/lib1560.c:37-86`).
    ///
    /// Nine parts joined with `" | "`, a failure rendered as its numeric code
    /// in brackets. The C's separator test is `buf[0] ?` rather than "anything
    /// written yet", and the two coincide because the first part is the scheme
    /// and a scheme that is present is never zero bytes long.
    fn check_parts(u: &Url, getflags: UrlFlags) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        for part in CHECKED {
            if buf.first().copied().unwrap_or(0) != 0 {
                buf.extend_from_slice(b" | ");
            }
            match u.get(*part, getflags) {
                Ok(text) => buf.extend_from_slice(&text),
                Err(code) => {
                    buf.push(b'[');
                    buf.extend_from_slice(
                        format!("{}", code as i32).as_bytes(),
                    );
                    buf.push(b']');
                }
            }
        }
        buf
    }

    /// `part2id` (`tests/libtest/lib1560.c:1152-1179`), including its
    /// deliberate `9999` for an unrecognised name -- *"bad input => bad
    /// output"*, which is how the corpus reaches the `UNKNOWN_PART` arm.
    fn part2id(name: &[u8]) -> i32 {
        match name {
            b"url" => 0,
            b"scheme" => 1,
            b"user" => 2,
            b"password" => 3,
            b"options" => 4,
            b"host" => 5,
            b"port" => 6,
            b"path" => 7,
            b"query" => 8,
            b"fragment" => 9,
            b"zoneid" => 10,
            _ => 9999,
        }
    }

    /// `updateurl` (`tests/libtest/lib1560.c:1181-1215`).
    ///
    /// Applies a comma-terminated list of `part=value` commands. Two details
    /// of the C's `sscanf(buf, "%79[^=]=%79[^,]", part, value)` are
    /// load-bearing and reproduced: both conversions need at least one byte,
    /// so an empty name or an empty value makes the whole command a **silent
    /// no-op**; and each is capped at 79 bytes.
    ///
    /// The value `NULL` clears the part and the value `""` -- two literal
    /// quote bytes -- sets it to the empty string, which is how the corpus
    /// distinguishes absent from blank.
    fn update_url(
        u: &mut Url,
        cmd: &[u8],
        setflags: UrlFlags,
    ) -> Result<(), CURLUcode> {
        let mut rest: &[u8] = cmd;
        while let Some(comma) = rest.iter().position(|byte| *byte == b',') {
            let buf = rest.get(..comma).unwrap_or(&[]);

            // `%79[^=]`, then a literal '=', then `%79[^,]`.
            let name_len = buf
                .iter()
                .position(|byte| *byte == b'=')
                .unwrap_or(buf.len())
                .min(79);
            let matched = name_len > 0
                && buf.get(name_len).copied() == Some(b'=')
                && buf.len() > name_len + 1;

            if matched {
                let name = buf.get(..name_len).unwrap_or(&[]);
                let tail = buf.get(name_len + 1..).unwrap_or(&[]);
                let value = tail.get(..tail.len().min(79)).unwrap_or(&[]);
                let what = part2id(name);
                if value == b"NULL" {
                    u.set_by_id(what, None, setflags)?;
                } else if value == b"\"\"" {
                    u.set_by_id(what, Some(b""), setflags)?;
                } else {
                    u.set_by_id(what, Some(value), setflags)?;
                }
            }

            rest = rest.get(comma + 1..).unwrap_or(&[]);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // The seven ported tables.
    //
    // Flag masks are spelled with `union` rather than `|` because these are
    // `const` items and `BitOr` is not a `const` trait on the pinned MSRV of
    // 1.75. The rows are otherwise byte-for-byte their C originals.
    //
    // Some rows run past the eighty-column guide, and deliberately: the
    // overflow is always inside a byte-string literal holding a URL, and
    // `rustfmt` cannot break one. Splitting them by hand with `\` line
    // continuations would keep the bytes but destroy the property that makes
    // these tables auditable -- that each row can be read straight across
    // against its original in `lib1560.c`. `cargo fmt --check` is clean either
    // way, so the readable form wins.
    // -----------------------------------------------------------------------

    /// `struct testcase` (`lib1560.c:117-123`): the input, the nine-part
    /// rendering, the flags for the URL set, the flags for the gets, and the
    /// code the set must return.
    type TestCase = (&'static [u8], &'static [u8], UrlFlags, UrlFlags, E);

    /// `struct urltestcase` (`lib1560.c:125-131`): the input, the full URL,
    /// the flags for the set, the flags for the get, and the code.
    type UrlTestCase = (&'static [u8], &'static [u8], UrlFlags, UrlFlags, E);

    /// `struct setgetcase` (`lib1560.c:107-115`): the URL to parse first (or
    /// [`None`] for a fresh handle), the part commands, the nine-part
    /// rendering, and three flag masks -- for the URL set, the part sets and
    /// the gets -- plus the code the part sets must return.
    type SetGetCase = (
        Option<&'static [u8]>,
        &'static [u8],
        &'static [u8],
        UrlFlags,
        UrlFlags,
        UrlFlags,
        E,
    );

    /// `struct setcase` (`lib1560.c:97-105`): as [`SetGetCase`] but the
    /// comparison is against the rendered URL, and there are two codes -- one
    /// for the initial URL set and one for the part sets.
    type SetCase = (
        Option<&'static [u8]>,
        &'static [u8],
        &'static [u8],
        UrlFlags,
        UrlFlags,
        E,
        E,
    );

    /// `struct redircase` (`lib1560.c:88-95`): the base URL, the replacement,
    /// the expected rendering, the flags for each set, and the code the first
    /// set must return.
    type RedirCase = (
        &'static [u8],
        &'static [u8],
        &'static [u8],
        UrlFlags,
        UrlFlags,
        E,
    );

    /// `struct querycase` (`lib1560.c:133-140`): the base URL, the query to
    /// append, the expected rendering, the flags for each set, and the code
    /// the append must return.
    type QueryCase = (
        &'static [u8],
        &'static [u8],
        &'static [u8],
        UrlFlags,
        UrlFlags,
        E,
    );

    /// `struct clearurlcase` (`lib1560.c:142-147`): the part, the value to
    /// set, the value expected after the whole handle is cleared, and the code
    /// the final get must return.
    type ClearCase = (P, Option<&'static [u8]>, Option<&'static [u8]>, E);

    /// `get_parts_list[]` (`lib1560.c:149`), 125 rows.
    const GET_PARTS_LIST: &[TestCase] = &[
        (b"curl.se", b"[10] | [11] | [12] | [13] | curl.se | [15] | / | [16] | [17]", F::GUESS_SCHEME, F::NO_GUESS_SCHEME, E::Ok),
        (b"https://curl.se:0/#", b"https | [11] | [12] | [13] | curl.se | 0 | / | [16] | ", F::NONE, F::GET_EMPTY, E::Ok),
        (b"https://curl.se/#", b"https | [11] | [12] | [13] | curl.se | [15] | / | [16] | ", F::NONE, F::GET_EMPTY, E::Ok),
        (b"https://curl.se/?#", b"https | [11] | [12] | [13] | curl.se | [15] | / |  | ", F::NONE, F::GET_EMPTY, E::Ok),
        (b"https://curl.se/?", b"https | [11] | [12] | [13] | curl.se | [15] | / |  | [17]", F::NONE, F::GET_EMPTY, E::Ok),
        (b"https://curl.se/?", b"https | [11] | [12] | [13] | curl.se | [15] | / | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"https://curl.se/?#", b"https | [11] | [12] | [13] | curl.se | [15] | / | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"https://curl.se/#  ", b"https | [11] | [12] | [13] | curl.se | [15] | / | [16] | %20%20", F::URLENCODE.union(F::ALLOW_SPACE), F::NONE, E::Ok),
        (b"", b"", F::NONE, F::NONE, E::MalformedInput),
        (b" ", b"", F::NONE, F::NONE, E::MalformedInput),
        (b"1h://example.net", b"", F::NONE, F::NONE, E::BadScheme),
        (b"..://example.net", b"", F::NONE, F::NONE, E::BadScheme),
        (b"-ht://example.net", b"", F::NONE, F::NONE, E::BadScheme),
        (b"+ftp://example.net", b"", F::NONE, F::NONE, E::BadScheme),
        (b"hej.hej://example.net", b"hej.hej | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]", F::NON_SUPPORT_SCHEME, F::NONE, E::Ok),
        (b"ht-tp://example.net", b"ht-tp | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]", F::NON_SUPPORT_SCHEME, F::NONE, E::Ok),
        (b"ftp+more://example.net", b"ftp+more | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]", F::NON_SUPPORT_SCHEME, F::NONE, E::Ok),
        (b"f1337://example.net", b"f1337 | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]", F::NON_SUPPORT_SCHEME, F::NONE, E::Ok),
        (b"https://user@example.net?hello# space ", b"https | user | [12] | [13] | example.net | [15] | / | hello | %20space%20", F::ALLOW_SPACE.union(F::URLENCODE), F::NONE, E::Ok),
        (b"https://test%test", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://example.com%252f%40@example.net", b"https | example.com%2f@ | [12] | [13] | example.net | [15] | / | [16] | [17]", F::NONE, F::URLDECODE, E::Ok),
        (b"https://r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se", b"https | [11] | [12] | [13] | xn--rksmrgs-5wao1o.se | [15] | / | [16] | [17]", F::NONE, F::PUNYCODE, E::Ok),
        (b"https://xn--rksmrgs-5wao1o.se", b"https | [11] | [12] | [13] | r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se | [15] | / | [16] | [17]", F::NONE, F::PUNY2IDN, E::Ok),
        (b"https://www.xn--rksmrgs-5wao1o.se", b"https | [11] | [12] | [13] | www.r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se | [15] | / | [16] | [17]", F::NONE, F::PUNY2IDN, E::Ok),
        (b"https://www.r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se", b"https | [11] | [12] | [13] | www.r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se | [15] | / | [16] | [17]", F::NONE, F::PUNY2IDN, E::Ok),
        (b"https://%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4", b"https | [11] | [12] | [13] | \xe2\x84\x82\xe1\xb5\xa4\xe2\x93\x87\xe2\x84\x92\xe3\x80\x82\xf0\x9d\x90\x92\xf0\x9f\x84\xb4 | [15] | / | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"https://%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4", b"https | [11] | [12] | [13] | %E2%84%82%E1%B5%A4%E2%93%87%E2%84%92%E3%80%82%F0%9D%90%92%F0%9F%84%B4 | [15] | / | [16] | [17]", F::NONE, F::URLENCODE, E::Ok),
        (b"https://\xe2\x84\x82\xe1\xb5\xa4\xe2\x93\x87\xe2\x84\x92\xe3\x80\x82\xf0\x9d\x90\x92\xf0\x9f\x84\xb4", b"https | [11] | [12] | [13] | %E2%84%82%E1%B5%A4%E2%93%87%E2%84%92%E3%80%82%F0%9D%90%92%F0%9F%84%B4 | [15] | / | [16] | [17]", F::NONE, F::URLENCODE, E::Ok),
        (b"https://user@example.net?he l lo", b"https | user | [12] | [13] | example.net | [15] | / | he+l+lo | [17]", F::ALLOW_SPACE, F::URLENCODE, E::Ok),
        (b"https://user@example.net?he l lo", b"https | user | [12] | [13] | example.net | [15] | / | he l lo | [17]", F::ALLOW_SPACE, F::NONE, E::Ok),
        (b"https://exam{}[]ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam{ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam}ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam]ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam\\ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam$ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam'ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam\"ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam^ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam`ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam*ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam<ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam>ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam=ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://exam;ple.net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://example,net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://example&net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://example+net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://example(net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://example)net", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://example.net/}", b"https | [11] | [12] | [13] | example.net | [15] | /} | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"https://:password@example.net", b"https |  | password | [13] | example.net | [15] | / | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"https://:@example.net", b"https |  |  | [13] | example.net | [15] | / | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"https://user@example.net", b"https | user | [12] | [13] | example.net | [15] | / | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"ws://example.com/color/?green", b"ws | [11] | [12] | [13] | example.com | [15] | /color/ | green | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"wss://example.com/color/?green", b"wss | [11] | [12] | [13] | example.com | [15] | /color/ | green | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://user:password@example.net/get?this=and#but frag then", b"", F::DEFAULT_SCHEME, F::NONE, E::MalformedInput),
        (b"https://user:password@example.net/get?this=and what", b"", F::DEFAULT_SCHEME, F::NONE, E::MalformedInput),
        (b"https://user:password@example.net/ge t?this=and-what", b"", F::DEFAULT_SCHEME, F::NONE, E::MalformedInput),
        (b"https://user:pass word@example.net/get?this=and-what", b"", F::DEFAULT_SCHEME, F::NONE, E::MalformedInput),
        (b"https://u ser:password@example.net/get?this=and-what", b"", F::DEFAULT_SCHEME, F::NONE, E::MalformedInput),
        (b"imap://user:pass;opt ion@server/path", b"", F::DEFAULT_SCHEME, F::NONE, E::MalformedInput),
        (b"htt ps://user:password@example.net/get?this=and-what", b"", F::NON_SUPPORT_SCHEME.union(F::ALLOW_SPACE), F::NONE, E::BadScheme),
        (b"https://user:password@example.net/get?this=and what", b"https | user | password | [13] | example.net | [15] | /get | this=and what | [17]", F::ALLOW_SPACE, F::NONE, E::Ok),
        (b"https://user:password@example.net/ge t?this=and-what", b"https | user | password | [13] | example.net | [15] | /ge t | this=and-what | [17]", F::ALLOW_SPACE, F::NONE, E::Ok),
        (b"https://user:pass word@example.net/get?this=and-what", b"https | user | pass word | [13] | example.net | [15] | /get | this=and-what | [17]", F::ALLOW_SPACE, F::NONE, E::Ok),
        (b"https://u ser:password@example.net/get?this=and-what", b"https | u ser | password | [13] | example.net | [15] | /get | this=and-what | [17]", F::ALLOW_SPACE, F::NONE, E::Ok),
        (b"https://user:password@example.net/ge t?this=and-what", b"https | user | password | [13] | example.net | [15] | /ge%20t | this=and-what | [17]", F::ALLOW_SPACE.union(F::URLENCODE), F::NONE, E::Ok),
        (b"[0:0:0:0:0:0:0:1]", b"http | [11] | [12] | [13] | [::1] | [15] | / | [16] | [17]", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"[::1]", b"http | [11] | [12] | [13] | [::1] | [15] | / | [16] | [17]", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"[::]", b"http | [11] | [12] | [13] | [::] | [15] | / | [16] | [17]", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"https://[::1]", b"https | [11] | [12] | [13] | [::1] | [15] | / | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"user:moo@ftp.example.com/color/#green?no-red", b"ftp | user | moo | [13] | ftp.example.com | [15] | /color/ | [16] | green?no-red", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"ftp.user:moo@example.com/color/#green?no-red", b"http | ftp.user | moo | [13] | example.com | [15] | /color/ | [16] | green?no-red", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"https://example.com/color/#green?no-red", b"https | [11] | [12] | [13] | example.com | [15] | /color/ | [16] | green?no-red", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://example.com/color/#green#no-red", b"https | [11] | [12] | [13] | example.com | [15] | /color/ | [16] | green#no-red", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://example.com/color/?green#no-red", b"https | [11] | [12] | [13] | example.com | [15] | /color/ | green | no-red", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://example.com/#color/?green#no-red", b"https | [11] | [12] | [13] | example.com | [15] | / | [16] | color/?green#no-red", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://example.#com/color/?green#no-red", b"https | [11] | [12] | [13] | example. | [15] | / | [16] | com/color/?green#no-red", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://[ab.be:1]/x", b"", F::DEFAULT_SCHEME, F::NONE, E::BadIpv6),
        (b"http://[ab.be]/x", b"", F::DEFAULT_SCHEME, F::NONE, E::BadIpv6),
        (b"http://a:b@/x", b"", F::DEFAULT_SCHEME, F::NONE, E::NoHost),
        (b"boing:80", b"https | [11] | [12] | [13] | boing | 80 | / | [16] | [17]", F::DEFAULT_SCHEME.union(F::GUESS_SCHEME), F::NONE, E::Ok),
        (b"http://[fd00:a41::50]:8080", b"http | [11] | [12] | [13] | [fd00:a41::50] | 8080 | / | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://[fd00:a41::50]/", b"http | [11] | [12] | [13] | [fd00:a41::50] | [15] | / | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://[fd00:a41::50]", b"http | [11] | [12] | [13] | [fd00:a41::50] | [15] | / | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://[::1%252]:1234", b"https | [11] | [12] | [13] | [::1] | 1234 | / | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://[fe80::20c:29ff:fe9c:409b%eth0]:1234", b"https | [11] | [12] | [13] | [fe80::20c:29ff:fe9c:409b] | 1234 | / | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://127.0.0.1:443", b"https | [11] | [12] | [13] | 127.0.0.1 | [15] | / | [16] | [17]", F::NONE, F::NO_DEFAULT_PORT, E::Ok),
        (b"http://%3a:%3a@ex4mple/%3f+?+%3f+%23#+%23%3f%g7", b"http | : | : | [13] | ex4mple | [15] | /?+ |  ? # | +#?%g7", F::NONE, F::URLDECODE, E::Ok),
        (b"http://%3a:%3a@ex4mple/%3f?%3f%35#%35%3f%g7", b"http | %3a | %3a | [13] | ex4mple | [15] | /%3f | %3f%35 | %35%3f%g7", F::NONE, F::NONE, E::Ok),
        (b"http://HO0_-st%41/", b"http | [11] | [12] | [13] | HO0_-stA | [15] | / | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"file://hello.html", b"", F::NONE, F::NONE, E::BadFileUrl),
        (b"http://HO0_-st/", b"http | [11] | [12] | [13] | HO0_-st | [15] | / | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"imap://user:pass;option@server/path", b"imap | user | pass | option | server | [15] | /path | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"http://user:pass;option@server/path", b"http | user | pass;option | [13] | server | [15] | /path | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"file:/hello.html", b"file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"file:/h", b"file | [11] | [12] | [13] | [14] | [15] | /h | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"file:/", b"file | [11] | [12] | [13] | [14] | [15] | | [16] | [17]", F::NONE, F::NONE, E::BadFileUrl),
        (b"file://127.0.0.1/hello.html", b"file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"file:////hello.html", b"file | [11] | [12] | [13] | [14] | [15] | //hello.html | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"file:///hello.html", b"file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]", F::NONE, F::NONE, E::Ok),
        (b"https://127.0.0.1", b"https | [11] | [12] | [13] | 127.0.0.1 | 443 | / | [16] | [17]", F::NONE, F::DEFAULT_PORT, E::Ok),
        (b"https://127.0.0.1", b"https | [11] | [12] | [13] | 127.0.0.1 | [15] | / | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://[::1]:1234", b"https | [11] | [12] | [13] | [::1] | 1234 | / | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://127abc.com", b"https | [11] | [12] | [13] | 127abc.com | [15] | / | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https:// example.com?check", b"", F::DEFAULT_SCHEME, F::NONE, E::MalformedInput),
        (b"https://e x a m p l e.com?check", b"", F::DEFAULT_SCHEME, F::NONE, E::MalformedInput),
        (b"https://example.com?check", b"https | [11] | [12] | [13] | example.com | [15] | / | check | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://example.com:65536", b"", F::DEFAULT_SCHEME, F::NONE, E::BadPortNumber),
        (b"https://example.com:-1#moo", b"", F::DEFAULT_SCHEME, F::NONE, E::BadPortNumber),
        (b"https://example.com:0#moo", b"https | [11] | [12] | [13] | example.com | 0 | / | [16] | moo", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://example.com:01#moo", b"https | [11] | [12] | [13] | example.com | 1 | / | [16] | moo", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://example.com:1#moo", b"https | [11] | [12] | [13] | example.com | 1 | / | [16] | moo", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://example.com#moo", b"http | [11] | [12] | [13] | example.com | [15] | / | [16] | moo", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://example.com", b"http | [11] | [12] | [13] | example.com | [15] | / | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://example.com/path/html", b"http | [11] | [12] | [13] | example.com | [15] | /path/html | [16] | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://example.com/path/html?query=name", b"http | [11] | [12] | [13] | example.com | [15] | /path/html | query=name | [17]", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://example.com/path/html?query=name#anchor", b"http | [11] | [12] | [13] | example.com | [15] | /path/html | query=name | anchor", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://example.com:1234/path/html?query=name#anchor", b"http | [11] | [12] | [13] | example.com | 1234 | /path/html | query=name | anchor", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http:///user:password@example.com:1234/path/html?query=name#anchor", b"http | user | password | [13] | example.com | 1234 | /path/html | query=name | anchor", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"https://user:password@example.com:1234/path/html?query=name#anchor", b"https | user | password | [13] | example.com | 1234 | /path/html | query=name | anchor", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://user:password@example.com:1234/path/html?query=name#anchor", b"http | user | password | [13] | example.com | 1234 | /path/html | query=name | anchor", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http:/user:password@example.com:1234/path/html?query=name#anchor", b"http | user | password | [13] | example.com | 1234 | /path/html | query=name | anchor", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http:////user:password@example.com:1234/path/html?query=name#anchor", b"", F::DEFAULT_SCHEME, F::NONE, E::BadSlashes),
    ];

    /// `get_url_list[]` (`lib1560.c:549`), 155 rows.
    const GET_URL_LIST: &[UrlTestCase] = &[
        (b"018.0.0.0", b"http://018.0.0.0/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"08", b"http://08/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0", b"http://0.0.0.0/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"01", b"http://0.0.0.1/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"02", b"http://0.0.0.2/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"03", b"http://0.0.0.3/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"04", b"http://0.0.0.4/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"05", b"http://0.0.0.5/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"06", b"http://0.0.0.6/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"07", b"http://0.0.0.7/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"07.1", b"http://7.0.0.1/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"7.1", b"http://7.0.0.1/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x7.1", b"http://7.0.0.1/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x", b"http://0x/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x1", b"http://0.0.0.1/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x2", b"http://0.0.0.2/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x3", b"http://0.0.0.3/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x4", b"http://0.0.0.4/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x5", b"http://0.0.0.5/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x6", b"http://0.0.0.6/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x7", b"http://0.0.0.7/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x8", b"http://0.0.0.8/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0x9", b"http://0.0.0.9/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0xa", b"http://0.0.0.10/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0xb", b"http://0.0.0.11/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0xc", b"http://0.0.0.12/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0xd", b"http://0.0.0.13/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0xe", b"http://0.0.0.14/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0xf", b"http://0.0.0.15/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"0xg", b"http://0xg/", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"https://0/", b"https://0.0.0.0/", F::NONE, F::NONE, E::Ok),
        (b"https://0.0x0/", b"https://0.0.0.0/", F::NONE, F::NONE, E::Ok),
        (b"https://0.000/", b"https://0.0.0.0/", F::NONE, F::NONE, E::Ok),
        (b"example.com", b"example.com/", F::GUESS_SCHEME, F::NO_GUESS_SCHEME, E::Ok),
        (b"http://user@example.com?#", b"http://user@example.com/?#", F::NONE, F::GET_EMPTY, E::Ok),
        (b"https://0x.0x.0", b"https://0x.0x.0/", F::NONE, F::NONE, E::Ok),
        (b"https://example.com:000000000000000000000443/foo", b"https://example.com/foo", F::NONE, F::NO_DEFAULT_PORT, E::Ok),
        (b"https://example.com:000000000000000000000/foo", b"https://example.com:0/foo", F::NONE, F::NO_DEFAULT_PORT, E::Ok),
        (b"https://192.0x0000A80001", b"https://192.168.0.1/", F::NONE, F::NONE, E::Ok),
        (b"https://0xffffffff", b"https://255.255.255.255/", F::NONE, F::NONE, E::Ok),
        (b"https://1.0x1000000", b"https://1.0x1000000/", F::NONE, F::NONE, E::Ok),
        (b"https://0x7f.1", b"https://127.0.0.1/", F::NONE, F::NONE, E::Ok),
        (b"https://1.2.3.256.com", b"https://1.2.3.256.com/", F::NONE, F::NONE, E::Ok),
        (b"https://10.com", b"https://10.com/", F::NONE, F::NONE, E::Ok),
        (b"https://1.2.com", b"https://1.2.com/", F::NONE, F::NONE, E::Ok),
        (b"https://1.2.3.com", b"https://1.2.3.com/", F::NONE, F::NONE, E::Ok),
        (b"https://1.2.com.99", b"https://1.2.com.99/", F::NONE, F::NONE, E::Ok),
        (b"https://[fe80::0000:20c:29ff:fe9c:409b]:80/moo", b"https://[fe80::20c:29ff:fe9c:409b]:80/moo", F::NONE, F::NONE, E::Ok),
        (b"https://[fe80::020c:29ff:fe9c:409b]:80/moo", b"https://[fe80::20c:29ff:fe9c:409b]:80/moo", F::NONE, F::NONE, E::Ok),
        (b"https://[fe80:0000:0000:0000:020c:29ff:fe9c:409b]:80/moo", b"https://[fe80::20c:29ff:fe9c:409b]:80/moo", F::NONE, F::NONE, E::Ok),
        (b"https://[fe80:0:0:0:409b::]:80/moo", b"https://[fe80::409b:0:0:0]:80/moo", F::NONE, F::NONE, E::Ok),
        (b"https://[FE80:0:A:0:409B:0:0:0]:80/moo", b"https://[fe80:0:a:0:409b::]:80/moo", F::NONE, F::NONE, E::Ok),
        (b"https://[::%25fakeit];80/moo", b"", F::NONE, F::NONE, E::BadPortNumber),
        (b"https://[fe80::20c:29ff:fe9c:409b]-80/moo", b"", F::NONE, F::NONE, E::BadPortNumber),
        (b"https://r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se/path?q#frag", b"https://xn--rksmrgs-5wao1o.se/path?q#frag", F::NONE, F::PUNYCODE, E::Ok),
        (b"data:text/html;charset=utf-8;base64,PCFET0NUWVBFIEhUTUw+PG1ldGEgY", b"", F::NONE, F::NONE, E::UnsupportedScheme),
        (b"d:anything-really", b"", F::NONE, F::NONE, E::UnsupportedScheme),
        (b"about:config", b"", F::NONE, F::NONE, E::UnsupportedScheme),
        (b"example://foo", b"", F::NONE, F::NONE, E::UnsupportedScheme),
        (b"mailto:infobot@example.com?body=send%20current-issue", b"", F::NONE, F::NONE, E::UnsupportedScheme),
        (b"about:80", b"https://about:80/", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"http://example.com%40127.0.0.1/", b"", F::NONE, F::NONE, E::BadHostname),
        (b"http://example.com%21127.0.0.1/", b"", F::NONE, F::NONE, E::BadHostname),
        (b"http://example.com%3f127.0.0.1/", b"", F::NONE, F::NONE, E::BadHostname),
        (b"http://example.com%23127.0.0.1/", b"", F::NONE, F::NONE, E::BadHostname),
        (b"http://example.com%3a127.0.0.1/", b"", F::NONE, F::NONE, E::BadHostname),
        (b"http://example.com%09127.0.0.1/", b"", F::NONE, F::NONE, E::BadHostname),
        (b"http://example.com%2F127.0.0.1/", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://%41", b"https://A/", F::NONE, F::NONE, E::Ok),
        (b"https://%20", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://%41%0D", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://%25", b"", F::NONE, F::NONE, E::BadHostname),
        (b"https://_%c0_", b"https://_\xc0_/", F::NONE, F::NONE, E::Ok),
        (b"https://_%c0_", b"https://_%C0_/", F::NONE, F::URLENCODE, E::Ok),
        (b"https://16843009", b"https://1.1.1.1/", F::NONE, F::NONE, E::Ok),
        (b"https://0177.1", b"https://127.0.0.1/", F::NONE, F::NONE, E::Ok),
        (b"https://0111.02.0x3", b"https://73.2.0.3/", F::NONE, F::NONE, E::Ok),
        (b"https://0111.02.0x3.", b"https://0111.02.0x3./", F::NONE, F::NONE, E::Ok),
        (b"https://0111.02.030", b"https://73.2.0.24/", F::NONE, F::NONE, E::Ok),
        (b"https://0111.02.030.", b"https://0111.02.030./", F::NONE, F::NONE, E::Ok),
        (b"https://0xff.0xff.0377.255", b"https://255.255.255.255/", F::NONE, F::NONE, E::Ok),
        (b"https://1.0xffffff", b"https://1.255.255.255/", F::NONE, F::NONE, E::Ok),
        (b"https://a127.0.0.1", b"https://a127.0.0.1/", F::NONE, F::NONE, E::Ok),
        (b"https://\xff.127.0.0.1", b"https://%FF.127.0.0.1/", F::NONE, F::URLENCODE, E::Ok),
        (b"https://127.-0.0.1", b"https://127.-0.0.1/", F::NONE, F::NONE, E::Ok),
        (b"https://127.0. 1", b"https://127.0.0.1/", F::NONE, F::NONE, E::MalformedInput),
        (b"https://1.2.3.256", b"https://1.2.3.256/", F::NONE, F::NONE, E::Ok),
        (b"https://1.2.3.256.", b"https://1.2.3.256./", F::NONE, F::NONE, E::Ok),
        (b"https://1.2.3.4.5", b"https://1.2.3.4.5/", F::NONE, F::NONE, E::Ok),
        (b"https://1.2.0x100.3", b"https://1.2.0x100.3/", F::NONE, F::NONE, E::Ok),
        (b"https://4294967296", b"https://4294967296/", F::NONE, F::NONE, E::Ok),
        (b"https://123host", b"https://123host/", F::NONE, F::NONE, E::Ok),
        (b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path", b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa://hostname/path", F::NON_SUPPORT_SCHEME, F::NONE, E::Ok),
        (b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path", b"", F::NON_SUPPORT_SCHEME, F::NONE, E::BadScheme),
        (b"https://[fe80::20c:29ff:fe9c:409b%]:1234", b"", F::NONE, F::NONE, E::BadIpv6),
        (b"https://[fe80::20c:29ff:fe9c:409b%25]:1234", b"https://[fe80::20c:29ff:fe9c:409b%2525]:1234/", F::NONE, F::NONE, E::Ok),
        (b"https://[fe80::20c:29ff:fe9c:409b%eth0]:1234", b"https://[fe80::20c:29ff:fe9c:409b%25eth0]:1234/", F::NONE, F::NONE, E::Ok),
        (b"https://[::%25fakeit]/moo", b"https://[::%25fakeit]/moo", F::NONE, F::NONE, E::Ok),
        (b"smtp.example.com/path/html", b"smtp://smtp.example.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"https.example.com/path/html", b"http://https.example.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"dict.example.com/path/html", b"dict://dict.example.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"pop3.example.com/path/html", b"pop3://pop3.example.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"ldap.example.com/path/html", b"ldap://ldap.example.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"imap.example.com/path/html", b"imap://imap.example.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"ftp.example.com/path/html", b"ftp://ftp.example.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"example.com/path/html", b"http://example.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"smtp.com/path/html", b"smtp://smtp.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"dict.com/path/html", b"dict://dict.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"pop3.com/path/html", b"pop3://pop3.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"ldap.com/path/html", b"ldap://ldap.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"imap.com/path/html", b"imap://imap.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"ftp.com/path/html", b"ftp://ftp.com/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"smtp/path/html", b"http://smtp/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"dict/path/html", b"http://dict/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"pop3/path/html", b"http://pop3/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"ldap/path/html", b"http://ldap/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"imap/path/html", b"http://imap/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"ftp/path/html", b"http://ftp/path/html", F::GUESS_SCHEME, F::NONE, E::Ok),
        (b"HTTP://test/", b"http://test/", F::NONE, F::NONE, E::Ok),
        (b"http://HO0_-st..~./", b"http://HO0_-st..~./", F::NONE, F::NONE, E::Ok),
        (b"http:/@example.com: 123/", b"", F::NONE, F::NONE, E::MalformedInput),
        (b"http:/@example.com:123 /", b"", F::NONE, F::NONE, E::MalformedInput),
        (b"http:/@example.com:123a/", b"", F::NONE, F::NONE, E::BadPortNumber),
        (b"http://host/file\x0d", b"", F::NONE, F::NONE, E::MalformedInput),
        (b"http://host/file\x0a\x03", b"", F::NONE, F::NONE, E::MalformedInput),
        (b"htt\x02://host/file", b"", F::NON_SUPPORT_SCHEME, F::NONE, E::MalformedInput),
        (b" http://host/file", b"", F::NONE, F::NONE, E::MalformedInput),
        (b"imap://user:pass;word@host/file", b"imap://user:pass;word@host/file", F::NONE, F::NONE, E::Ok),
        (b"http://user:pass;word@host/file", b"http://user:pass;word@host/file", F::NONE, F::NONE, E::Ok),
        (b"file:///file.txt#moo", b"file:///file.txt#moo", F::NONE, F::NONE, E::Ok),
        (b"file:////file.txt", b"file:////file.txt", F::NONE, F::NONE, E::Ok),
        (b"file:///file.txt", b"file:///file.txt", F::NONE, F::NONE, E::Ok),
        (b"file:./", b"file://", F::NONE, F::NONE, E::Ok),
        (b"http://example.com/hello/../here", b"http://example.com/hello/../here", F::PATH_AS_IS, F::NONE, E::Ok),
        (b"http://example.com/hello/../here", b"http://example.com/here", F::NONE, F::NONE, E::Ok),
        (b"http://example.com:80", b"http://example.com/", F::NONE, F::NO_DEFAULT_PORT, E::Ok),
        (b"tp://example.com/path/html", b"", F::NONE, F::NONE, E::UnsupportedScheme),
        (b"http://hello:fool@example.com", b"", F::DISALLOW_USER, F::NONE, E::UserNotAllowed),
        (b"http:/@example.com:123", b"http://@example.com:123/", F::NONE, F::NONE, E::Ok),
        (b"http:/:password@example.com", b"http://:password@example.com/", F::NONE, F::NONE, E::Ok),
        (b"http://user@example.com?#", b"http://user@example.com/", F::NONE, F::NONE, E::Ok),
        (b"http://user@example.com?", b"http://user@example.com/", F::NONE, F::NONE, E::Ok),
        (b"http://user@example.com#anchor", b"http://user@example.com/#anchor", F::NONE, F::NONE, E::Ok),
        (b"example.com/path/html", b"https://example.com/path/html", F::DEFAULT_SCHEME, F::NONE, E::Ok),
        (b"example.com/path/html", b"", F::NONE, F::NONE, E::BadScheme),
        (b"http://user:password@example.com:1234/path/html?query=name#anchor", b"http://user:password@example.com:1234/path/html?query=name#anchor", F::NONE, F::NONE, E::Ok),
        (b"http://example.com:1234/path/html?query=name#anchor", b"http://example.com:1234/path/html?query=name#anchor", F::NONE, F::NONE, E::Ok),
        (b"http://example.com/path/html?query=name#anchor", b"http://example.com/path/html?query=name#anchor", F::NONE, F::NONE, E::Ok),
        (b"http://example.com/path/html?query=name", b"http://example.com/path/html?query=name", F::NONE, F::NONE, E::Ok),
        (b"http://example.com/path/html", b"http://example.com/path/html", F::NONE, F::NONE, E::Ok),
        (b"tp://example.com/path/html", b"tp://example.com/path/html", F::NON_SUPPORT_SCHEME, F::NONE, E::Ok),
        (b"custom-scheme://host?expected=test-good", b"custom-scheme://host/?expected=test-good", F::NON_SUPPORT_SCHEME, F::NONE, E::Ok),
        (b"custom-scheme://?expected=test-bad", b"", F::NON_SUPPORT_SCHEME, F::NONE, E::NoHost),
        (b"custom-scheme://?expected=test-new-good", b"custom-scheme:///?expected=test-new-good", F::NON_SUPPORT_SCHEME.union(F::NO_AUTHORITY), F::NONE, E::Ok),
        (b"custom-scheme://host?expected=test-still-good", b"custom-scheme://host/?expected=test-still-good", F::NON_SUPPORT_SCHEME.union(F::NO_AUTHORITY), F::NONE, E::Ok),
    ];

    /// `setget_parts_list[]` (`lib1560.c:865`), 6 rows.
    const SETGET_PARTS_LIST: &[SetGetCase] = &[
        (Some(b"https://example.com/"), b"query=\"\",", b"https | [11] | [12] | [13] | example.com | [15] | / |  | [17]", F::NONE, F::NONE, F::GET_EMPTY, E::Ok),
        (Some(b"https://example.com/"), b"fragment=\"\",", b"https | [11] | [12] | [13] | example.com | [15] | / | [16] | ", F::NONE, F::NONE, F::GET_EMPTY, E::Ok),
        (Some(b"https://example.com/"), b"query=\"\",", b"https | [11] | [12] | [13] | example.com | [15] | / | [16] | [17]", F::NONE, F::NONE, F::NONE, E::Ok),
        (Some(b"https://example.com"), b"path=get,", b"https | [11] | [12] | [13] | example.com | [15] | /get | [16] | [17]", F::NONE, F::NONE, F::NONE, E::Ok),
        (Some(b"https://example.com"), b"path=/get,", b"https | [11] | [12] | [13] | example.com | [15] | /get | [16] | [17]", F::NONE, F::NONE, F::NONE, E::Ok),
        (Some(b"https://example.com"), b"path=g e t,", b"https | [11] | [12] | [13] | example.com | [15] | /g%20e%20t | [16] | [17]", F::NONE, F::URLENCODE, F::NONE, E::Ok),
    ];

    /// `set_parts_list[]` (`lib1560.c:895`), 58 rows.
    const SET_PARTS_LIST: &[SetCase] = &[
        (Some(b"https://example.com/"), b"path=one /$!$&'()*+;=:@{}[]%,", b"https://example.com/one%20/$!$&'()*+;=:@{}[]%25", F::NONE, F::URLENCODE, E::Ok, E::Ok),
        (None, b"scheme=https,path=/,url=\"\",", b"https://example.com/", F::NONE, F::NONE, E::Ok, E::MalformedInput),
        (None, b"scheme=https,host=example.com,path=/,url=\"\",", b"https://example.com/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"path=one\x0atwo,", b"https://example.com/one\x0atwo", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"path=one\x0dtwo,", b"https://example.com/one\x0dtwo", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"path=one\x0atwo,", b"https://example.com/one%0Atwo", F::NONE, F::URLENCODE, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"path=one\x0dtwo,", b"https://example.com/one%0Dtwo", F::NONE, F::URLENCODE, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"host=%43url.se,", b"https://%43url.se/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"host=%25url.se,", b"", F::NONE, F::NONE, E::Ok, E::BadHostname),
        (Some(b"https://example.com/?param=value"), b"query=\"\",", b"https://example.com/", F::NONE, F::APPENDQUERY.union(F::URLENCODE), E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"host=\"\",", b"https://example.com/", F::NONE, F::URLENCODE, E::Ok, E::BadHostname),
        (Some(b"https://example.com/"), b"host=\"\",", b"https://example.com/", F::NONE, F::NONE, E::Ok, E::BadHostname),
        (Some(b"https://example.com"), b"path=get,", b"https://example.com/get", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"scheme=ftp+-.123,", b"ftp+-.123://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"scheme=1234,", b"https://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::BadScheme),
        (Some(b"https://example.com/"), b"scheme=1http,", b"https://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::BadScheme),
        (Some(b"https://example.com/"), b"scheme=-ftp,", b"https://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::BadScheme),
        (Some(b"https://example.com/"), b"scheme=+ftp,", b"https://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::BadScheme),
        (Some(b"https://example.com/"), b"scheme=.ftp,", b"https://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::BadScheme),
        (Some(b"https://example.com/"), b"host=example.com%2fmoo,", b"", F::NONE, F::NONE, E::Ok, E::BadHostname),
        (Some(b"https://example.com/"), b"host=http://fake,", b"", F::NONE, F::NONE, E::Ok, E::BadHostname),
        (Some(b"https://example.com/"), b"host=test%,", b"", F::NONE, F::NONE, E::Ok, E::BadHostname),
        (Some(b"https://example.com/"), b"host=te st,", b"", F::NONE, F::NONE, E::Ok, E::BadHostname),
        (Some(b"https://example.com/"), b"host=0xff,", b"https://0xff/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"query=Al2cO3tDkcDZ3EWE5Lh+LX8TPHs,", b"https://example.com/?Al2cO3tDkcDZ3EWE5Lh%2BLX8TPHs", F::URLDECODE, F::URLENCODE, E::Ok, E::Ok),
        (Some(b"https://example.com/"), b"scheme=https://,", b"https://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::BadScheme),
        (Some(b"https://example.com/"), b"scheme=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc,", b"https://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::BadScheme),
        (Some(b"https://example.com/"), b"scheme=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,", b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::Ok),
        (Some(b"https://[::1%25fake]:1234/"), b"zoneid=NULL,", b"https://[::1]:1234/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://host:1234/"), b"port=NULL,", b"https://host/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://host:1234/"), b"port=\"\",", b"https://host:1234/", F::NONE, F::NONE, E::Ok, E::BadPortNumber),
        (Some(b"https://host:1234/"), b"port=56 78,", b"https://host:1234/", F::NONE, F::NONE, E::Ok, E::BadPortNumber),
        (Some(b"https://host:1234/"), b"port=0,", b"https://host:0/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://host:1234/"), b"port=65535,", b"https://host:65535/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://host:1234/"), b"port=65536,", b"https://host:1234/", F::NONE, F::NONE, E::Ok, E::BadPortNumber),
        (Some(b"https://host/"), b"path=%4A%4B%4C,", b"https://host/%4a%4b%4c", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://host/mooo?q#f"), b"path=NULL,query=NULL,fragment=NULL,", b"https://host/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"https://user:secret@host/"), b"user=NULL,password=NULL,", b"https://host/", F::NONE, F::NONE, E::Ok, E::Ok),
        (None, b"scheme=https,user=   @:,host=foobar,", b"https://%20%20%20%40%3A@foobar/", F::NONE, F::URLENCODE, E::Ok, E::Ok),
        (None, b"scheme=https,host=  ,path= ,user= ,password= ,query= ,fragment= ,", b"[nothing]", F::NONE, F::URLENCODE, E::Ok, E::BadHostname),
        (None, b"scheme=https,host=foobar,path=/this /path /is /here,", b"https://foobar/this%20/path%20/is%20/here", F::NONE, F::URLENCODE, E::Ok, E::Ok),
        (None, b"scheme=https,host=foobar,path=\xc3\xa4\xc3\xb6\xc3\xbc,", b"https://foobar/%C3%A4%C3%B6%C3%BC", F::NONE, F::URLENCODE, E::Ok, E::Ok),
        (Some(b"imap://user:secret;opt@host/"), b"options=updated,scheme=imaps,password=p4ssw0rd,", b"imaps://user:p4ssw0rd;updated@host/", F::NONE, F::NONE, E::NoHost, E::Ok),
        (Some(b"imap://user:secret;optit@host/"), b"scheme=https,", b"https://user:secret@host/", F::NONE, F::NONE, E::NoHost, E::Ok),
        (Some(b"file:///file#anchor"), b"scheme=https,host=example,", b"https://example/file#anchor", F::NONE, F::NONE, E::NoHost, E::Ok),
        (None, b"scheme=file,host=127.0.0.1,path=/no,user=anonymous,", b"file:///no", F::NONE, F::NONE, E::Ok, E::Ok),
        (None, b"scheme=ftp,host=127.0.0.1,path=/no,user=anonymous,", b"ftp://anonymous@127.0.0.1/no", F::NONE, F::NONE, E::Ok, E::Ok),
        (None, b"scheme=https,host=example.com,", b"https://example.com/", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::Ok),
        (Some(b"http://user:foo@example.com/path?query#frag"), b"fragment=changed,", b"http://user:foo@example.com/path?query#changed", F::NONE, F::NON_SUPPORT_SCHEME, E::Ok, E::Ok),
        (Some(b"http://example.com/"), b"scheme=foo,", b"http://example.com/", F::NONE, F::NONE, E::Ok, E::UnsupportedScheme),
        (Some(b"http://example.com/"), b"scheme=https,path=/hello,fragment=snippet,", b"https://example.com/hello#snippet", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"http://example.com:80"), b"user=foo,port=1922,", b"http://foo@example.com:1922/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"http://example.com:80"), b"user=foo,password=bar,", b"http://foo:bar@example.com:80/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"http://example.com:80"), b"user=foo,", b"http://foo@example.com:80/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"http://example.com"), b"host=www.example.com,", b"http://www.example.com/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"http://example.com:80"), b"scheme=ftp,", b"ftp://example.com:80/", F::NONE, F::NONE, E::Ok, E::Ok),
        (Some(b"custom-scheme://host"), b"host=\"\",", b"custom-scheme://host/", F::NON_SUPPORT_SCHEME, F::NON_SUPPORT_SCHEME, E::Ok, E::BadHostname),
        (Some(b"custom-scheme://host"), b"host=\"\",", b"custom-scheme:///", F::NON_SUPPORT_SCHEME, F::NON_SUPPORT_SCHEME.union(F::NO_AUTHORITY), E::Ok, E::Ok),
    ];

    /// `set_url_list[]` (`lib1560.c:1226`), 46 rows.
    const SET_URL_LIST: &[RedirCase] = &[
        (b"https://example.com", b"", b"https://example.com/", F::NONE, F::NONE, E::Ok),
        (b"http://firstplace.example.com/want/1314", b"//somewhere.example.com/reply/1314", b"http://somewhere.example.com/reply/1314", F::NONE, F::NONE, E::Ok),
        (b"http://127.0.0.1:46383/want?uri=http://anything/276?secondq/276", b"data/2760002.txt?coolsite=http://anotherurl/?a_second/2760002", b"http://127.0.0.1:46383/data/2760002.txt?coolsite=http://anotherurl/?a_second/2760002", F::NONE, F::NONE, E::Ok),
        (b"file:///basic#", b"#yay", b"file:///basic#yay", F::NONE, F::NONE, E::Ok),
        (b"file:///basic", b"?yay", b"file:///basic?yay", F::NONE, F::NONE, E::Ok),
        (b"file:///basic?", b"?yay", b"file:///basic?yay", F::NONE, F::NONE, E::Ok),
        (b"file:///basic?hello", b"#frag", b"file:///basic?hello#frag", F::NONE, F::NONE, E::Ok),
        (b"file:///basic?hello", b"?q", b"file:///basic?q", F::NONE, F::NONE, E::Ok),
        (b"http://example.org#without/ash", b"/moo#frag", b"http://example.org/moo#frag", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/", b"../path/././../././../moo", b"http://example.org/moo", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/", b".%2e/path/././../%2E/./../moo", b"http://example.org/moo", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/", b".%2e/path/./%2e/.%2E/%2E/./%2e%2E/moo", b"http://example.org/moo", F::NONE, F::NONE, E::Ok),
        (b"http://example.org?bar/moo", b"?weird", b"http://example.org/?weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo?bar", b"?weird", b"http://example.org/foo?weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo", b"?weird", b"http://example.org/foo?weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org", b"?weird", b"http://example.org/?weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/#original", b"?weird#moo", b"http://example.org/?weird#moo", F::NONE, F::NONE, E::Ok),
        (b"http://example.org?bar/moo#yes/path", b"#new/slash", b"http://example.org/?bar/moo#new/slash", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo?bar", b"#weird", b"http://example.org/foo?bar#weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo?bar#original", b"#weird", b"http://example.org/foo?bar#weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo#original", b"#weird", b"http://example.org/foo#weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/#original", b"#weird", b"http://example.org/#weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org#original", b"#weird", b"http://example.org/#weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo?bar", b"moo?hey#weird", b"http://example.org/moo?hey#weird", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/", b"../path/././../../moo", b"http://example.org/moo", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/", b"//example.org/../path/../../", b"http://example.org/", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/", b"///example.org/../path/../../", b"http://example.org/", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo/bar", b":23", b"http://example.org/foo/:23", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo/bar", b"\\x", b"http://example.org/foo/\\x", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo/bar", b"#/", b"http://example.org/foo/bar#/", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo/bar", b"?/", b"http://example.org/foo/bar?/", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo/bar", b"#;?", b"http://example.org/foo/bar#;?", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo/bar", b"#", b"http://example.org/foo/bar", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo/bar", b"?", b"http://example.org/foo/bar", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/foo/bar", b"?#", b"http://example.org/foo/bar", F::NONE, F::NONE, E::Ok),
        (b"http://example.com/please/../gimme/%TESTNUMBER?foobar#hello", b"http://example.net/there/it/is/../../tes t case=/%TESTNUMBER0002? yes no", b"http://example.net/there/tes%20t%20case=/%TESTNUMBER0002?+yes+no", F::NONE, F::URLENCODE.union(F::ALLOW_SPACE), E::Ok),
        (b"http://local.test?redirect=http://local.test:80?-321", b"http://local.test:80?-123", b"http://local.test:80/?-123", F::NONE, F::URLENCODE.union(F::ALLOW_SPACE), E::Ok),
        (b"http://local.test?redirect=http://local.test:80?-321", b"http://local.test:80?-123", b"http://local.test:80/?-123", F::NONE, F::NONE, E::Ok),
        (b"http://example.org/static/favicon/wikipedia.ico", b"//fake.example.com/licenses/by-sa/3.0/", b"http://fake.example.com/licenses/by-sa/3.0/", F::NONE, F::NONE, E::Ok),
        (b"https://example.org/static/favicon/wikipedia.ico", b"//fake.example.com/licenses/by-sa/3.0/", b"https://fake.example.com/licenses/by-sa/3.0/", F::NONE, F::NONE, E::Ok),
        (b"file://localhost/path?query#frag", b"foo#another", b"file:///foo#another", F::NONE, F::NONE, E::Ok),
        (b"http://example.com/path?query#frag", b"https://two.example.com/bradnew", b"https://two.example.com/bradnew", F::NONE, F::NONE, E::Ok),
        (b"http://example.com/path?query#frag", b"../../newpage#foo", b"http://example.com/newpage#foo", F::NONE, F::NONE, E::Ok),
        (b"http://user:foo@example.com/path?query#frag", b"../../newpage", b"http://user:foo@example.com/newpage", F::NONE, F::NONE, E::Ok),
        (b"http://user:foo@example.com/path?query#frag", b"../newpage", b"http://user:foo@example.com/newpage", F::NONE, F::NONE, E::Ok),
        (b"http://user:foo@example.com/path?query#frag", b"http://?hi", b"http:///?hi", F::NONE, F::NO_AUTHORITY, E::Ok),
    ];

    /// `append_list[]` (`lib1560.c:1613`), 7 rows.
    const APPEND_LIST: &[QueryCase] = &[
        (
            b"HTTP://test/?s",
            b"name=joe\x02",
            b"http://test/?s&name=joe%02",
            F::NONE,
            F::URLENCODE,
            E::Ok,
        ),
        (
            b"HTTP://test/?size=2#f",
            b"name=joe=",
            b"http://test/?size=2&name=joe%3D#f",
            F::NONE,
            F::URLENCODE,
            E::Ok,
        ),
        (
            b"HTTP://test/?size=2#f",
            b"name=joe doe",
            b"http://test/?size=2&name=joe+doe#f",
            F::NONE,
            F::URLENCODE,
            E::Ok,
        ),
        (
            b"HTTP://test/",
            b"name=joe",
            b"http://test/?name=joe",
            F::NONE,
            F::NONE,
            E::Ok,
        ),
        (
            b"HTTP://test/?size=2",
            b"name=joe",
            b"http://test/?size=2&name=joe",
            F::NONE,
            F::NONE,
            E::Ok,
        ),
        (
            b"HTTP://test/?size=2&",
            b"name=joe",
            b"http://test/?size=2&name=joe",
            F::NONE,
            F::NONE,
            E::Ok,
        ),
        (
            b"HTTP://test/?size=2#f",
            b"name=joe",
            b"http://test/?size=2&name=joe#f",
            F::NONE,
            F::NONE,
            E::Ok,
        ),
    ];

    /// `clear_url_list[]` (`lib1560.c:1862`), 11 rows.
    const CLEAR_URL_LIST: &[ClearCase] = &[
        (P::Scheme, Some(b"http"), None, E::NoScheme),
        (P::User, Some(b"user"), None, E::NoUser),
        (P::Password, Some(b"password"), None, E::NoPassword),
        (P::Options, Some(b"options"), None, E::NoOptions),
        (P::Host, Some(b"host"), None, E::NoHost),
        (P::ZoneId, Some(b"eth0"), None, E::NoZoneid),
        (P::Port, Some(b"1234"), None, E::NoPort),
        (P::Path, Some(b"/hello"), Some(b"/"), E::Ok),
        (P::Query, Some(b"a=b"), None, E::NoQuery),
        (P::Fragment, Some(b"anchor"), None, E::NoFragment),
        (P::Url, None, None, E::Ok),
    ];

    // -----------------------------------------------------------------------
    // The six drivers of `lib1560.c`, ported.
    // -----------------------------------------------------------------------

    /// `get_parts` (`lib1560.c:1576-1608`).
    #[test]
    fn get_parts_matches_the_conformance_corpus() {
        assert_eq!(GET_PARTS_LIST.len(), 125, "row count drifted");
        for (input, wanted, urlflags, getflags, ucode) in GET_PARTS_LIST {
            let mut u = handle();
            let rc = u.set(P::Url, Some(input), *urlflags);
            match rc {
                Ok(()) => assert_eq!(
                    *ucode,
                    E::Ok,
                    "in: {}\nset succeeded, wanted {ucode:?}",
                    show(input)
                ),
                Err(code) => {
                    assert_eq!(
                        code,
                        *ucode,
                        "in: {}\nset returned {code:?}, wanted {ucode:?}",
                        show(input)
                    );
                    continue;
                }
            }
            let got = check_parts(&u, *getflags);
            assert_eq!(
                show(&got),
                show(wanted),
                "in: {}\nparts mismatched",
                show(input)
            );
        }
    }

    /// `get_url` (`lib1560.c:1535-1574`).
    #[test]
    fn get_url_matches_the_conformance_corpus() {
        assert_eq!(GET_URL_LIST.len(), 155, "row count drifted");
        for (input, wanted, urlflags, getflags, ucode) in GET_URL_LIST {
            let mut u = handle();
            let rc = u.set(P::Url, Some(input), *urlflags);
            match rc {
                Ok(()) => {
                    assert_eq!(
                        *ucode,
                        E::Ok,
                        "in: {}\nset succeeded, wanted {ucode:?}",
                        show(input)
                    );
                    let got = u.get(P::Url, *getflags).unwrap_or_else(|code| {
                        panic!("in: {}\nget returned {code:?}", show(input))
                    });
                    assert_eq!(
                        show(&got),
                        show(wanted),
                        "in: {}\nURL mismatched",
                        show(input)
                    );
                }
                Err(code) => assert_eq!(
                    code,
                    *ucode,
                    "in: {}\nset returned {code:?}, wanted {ucode:?}",
                    show(input)
                ),
            }
        }
    }

    /// `setget_parts` (`lib1560.c:1429-1482`).
    #[test]
    fn setget_parts_matches_the_conformance_corpus() {
        assert_eq!(SETGET_PARTS_LIST.len(), 6, "row count drifted");
        for (input, set, wanted, urlflags, setflags, getflags, pcode) in
            SETGET_PARTS_LIST
        {
            let mut u = handle();
            if let Some(input) = input {
                u.set(P::Url, Some(input), *urlflags)
                    .unwrap_or_else(|code| {
                        panic!("in: {}\nset returned {code:?}", show(input))
                    });
            }
            match update_url(&mut u, set, *setflags) {
                Ok(()) => {
                    assert_eq!(
                        *pcode,
                        E::Ok,
                        "set: {}\nupdate succeeded, wanted {pcode:?}",
                        show(set)
                    );
                    let got = check_parts(&u, *getflags);
                    assert_eq!(
                        show(&got),
                        show(wanted),
                        "set: {}\nparts mismatched",
                        show(set)
                    );
                }
                Err(code) => assert_eq!(
                    code,
                    *pcode,
                    "set: {}\nupdate returned {code:?}, wanted {pcode:?}",
                    show(set)
                ),
            }
        }
    }

    /// `set_parts` (`lib1560.c:1484-1533`).
    #[test]
    fn set_parts_matches_the_conformance_corpus() {
        assert_eq!(SET_PARTS_LIST.len(), 58, "row count drifted");
        for (input, set, wanted, urlflags, setflags, ucode, pcode) in
            SET_PARTS_LIST
        {
            let mut u = handle();
            if let Some(input) = input {
                if let Err(code) = u.set(P::Url, Some(input), *urlflags) {
                    assert_eq!(
                        code,
                        *ucode,
                        "in: {}\nset returned {code:?}, wanted {ucode:?}",
                        show(input)
                    );
                    continue;
                }
            }
            match update_url(&mut u, set, *setflags) {
                Ok(()) => {
                    assert_eq!(
                        *pcode,
                        E::Ok,
                        "set: {}\nupdate succeeded, wanted {pcode:?}",
                        show(set)
                    );
                    let got = u.get(P::Url, F::NONE).unwrap_or_else(|code| {
                        panic!("set: {}\nget returned {code:?}", show(set))
                    });
                    assert_eq!(
                        show(&got),
                        show(wanted),
                        "set: {}\nURL mismatched",
                        show(set)
                    );
                }
                Err(code) => assert_eq!(
                    code,
                    *pcode,
                    "set: {}\nupdate returned {code:?}, wanted {pcode:?}",
                    show(set)
                ),
            }
        }
    }

    /// `set_url` (`lib1560.c:1379-1427`).
    #[test]
    fn set_url_matches_the_conformance_corpus() {
        assert_eq!(SET_URL_LIST.len(), 46, "row count drifted");
        for (input, replacement, wanted, urlflags, setflags, ucode) in
            SET_URL_LIST
        {
            let mut u = handle();
            match u.set(P::Url, Some(input), *urlflags) {
                Ok(()) => {
                    u.set(P::Url, Some(replacement), *setflags).unwrap_or_else(
                        |code| {
                            panic!(
                                "set: {}\nreturned {code:?}",
                                show(replacement)
                            )
                        },
                    );
                    let got = u.get(P::Url, F::NONE).unwrap_or_else(|code| {
                        panic!("in: {}\nget returned {code:?}", show(input))
                    });
                    assert_eq!(
                        show(&got),
                        show(wanted),
                        "in: {}\nreplacement: {}\nURL mismatched",
                        show(input),
                        show(replacement)
                    );
                }
                Err(code) => assert_eq!(
                    code,
                    *ucode,
                    "in: {}\nset returned {code:?}, wanted {ucode:?}",
                    show(input)
                ),
            }
        }
    }

    /// `append` (`lib1560.c:1631-1680`).
    #[test]
    fn append_query_matches_the_conformance_corpus() {
        assert_eq!(APPEND_LIST.len(), 7, "row count drifted");
        for (input, query, wanted, urlflags, qflags, ucode) in APPEND_LIST {
            let mut u = handle();
            u.set(P::Url, Some(input), *urlflags)
                .unwrap_or_else(|code| {
                    panic!("in: {}\nset returned {code:?}", show(input))
                });
            let rc = u.set(P::Query, Some(query), qflags.union(F::APPENDQUERY));
            match rc {
                Ok(()) => {
                    assert_eq!(
                        *ucode,
                        E::Ok,
                        "in: {}\nappend succeeded, wanted {ucode:?}",
                        show(input)
                    );
                    let got = u.get(P::Url, F::NONE).unwrap_or_else(|code| {
                        panic!("in: {}\nget returned {code:?}", show(input))
                    });
                    assert_eq!(
                        show(&got),
                        show(wanted),
                        "in: {}\nURL mismatched",
                        show(input)
                    );
                }
                Err(code) => assert_eq!(
                    code,
                    *ucode,
                    "in: {}\nappend returned {code:?}, wanted {ucode:?}",
                    show(input)
                ),
            }
        }
    }

    /// `clear_url` (`lib1560.c:1875-1908`).
    ///
    /// Each row sets one part, clears the **whole handle** with a null
    /// `CURLUPART_URL`, and then asks for that part back. Everything must be
    /// gone -- which is what pins `urlset_clear`'s `CURLUPART_URL` arm to a
    /// full reset rather than a per-part release.
    ///
    /// The table carries eleven rows and the C runs ten: its loop condition is
    /// `clear_url_list[i].in && !error` (`lib1560.c:1881`), so the eleventh --
    /// `{ CURLUPART_URL, NULL, NULL, CURLUE_OK }` -- is the sentinel that ends
    /// it, not a case. The row is kept here because it is part of the C data,
    /// and the loop stops on it for the same reason the C's does.
    #[test]
    fn clear_url_matches_the_conformance_corpus() {
        assert_eq!(CLEAR_URL_LIST.len(), 11, "row count drifted");
        let mut u = handle();
        let mut ran = 0usize;
        for (part, input, wanted, ucode) in CLEAR_URL_LIST {
            let Some(input) = input else {
                break;
            };
            ran += 1;
            u.set(*part, Some(input), F::NONE).unwrap_or_else(|code| {
                panic!("set {part:?} returned {code:?}")
            });
            u.set(P::Url, None, F::NONE)
                .unwrap_or_else(|code| panic!("clear returned {code:?}"));
            match u.get(*part, F::NONE) {
                Ok(text) => {
                    assert_eq!(*ucode, E::Ok, "get {part:?} succeeded");
                    assert_eq!(
                        Some(show(&text)),
                        wanted.map(show),
                        "get {part:?} mismatched"
                    );
                }
                Err(code) => assert_eq!(
                    code, *ucode,
                    "get {part:?} returned {code:?}, wanted {ucode:?}"
                ),
            }
        }
        assert_eq!(ran, 10, "the sentinel row must end the loop");
    }

    /// `get_nothing` (`lib1560.c:1810-1860`).
    ///
    /// A fresh handle must answer each part's own absence code -- and
    /// `CURLUPART_PATH` must answer `"/"` rather than an absence code, which
    /// `docs/libcurl/curl_url_get.md:196-197` states as *"The part is always
    /// at least a slash ('/')"*.
    #[test]
    fn get_nothing_reports_the_per_part_absence_codes() {
        let u = handle();
        assert_eq!(u.get(P::Scheme, F::NONE), Err(E::NoScheme));
        assert_eq!(u.get(P::Host, F::NONE), Err(E::NoHost));
        assert_eq!(u.get(P::User, F::NONE), Err(E::NoUser));
        assert_eq!(u.get(P::Password, F::NONE), Err(E::NoPassword));
        assert_eq!(u.get(P::Options, F::NONE), Err(E::NoOptions));
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/".to_vec()));
        assert_eq!(u.get(P::Query, F::NONE), Err(E::NoQuery));
        assert_eq!(u.get(P::Fragment, F::NONE), Err(E::NoFragment));
        assert_eq!(u.get(P::ZoneId, F::NONE), Err(E::NoZoneid));
        // The C's driver omits the port; the `ifmissing` table has it.
        assert_eq!(u.get(P::Port, F::NONE), Err(E::NoPort));
        // And the whole URL needs a host before anything else can matter.
        assert_eq!(u.get(P::Url, F::NONE), Err(E::NoHost));
    }

    /// `scopeid` (`lib1560.c:1682-1808`).
    ///
    /// The C driver checks only return codes. This one additionally pins the
    /// rendered values, because three measured behaviours live along this path
    /// and every one of them is invisible to a code-only check: the zone
    /// identifier survives a host replacement, a host set with a zone
    /// identifier stores the host **raw**, and the whole-URL rendering then
    /// emits the zone identifier twice.
    #[test]
    fn scopeid_walks_the_zone_identifier_lifecycle() {
        let mut u = handle();

        u.set(
            P::Url,
            Some(b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello.html"),
            F::NONE,
        )
        .expect("parse");
        assert_eq!(
            u.get(P::Host, F::NONE),
            Ok(b"[fe80::20c:29ff:fe9c:409b]".to_vec())
        );
        assert_eq!(u.get(P::ZoneId, F::NONE), Ok(b"eth0".to_vec()));

        // Replacing the host clears the zone identifier -- `lib/urlapi.c:1848`
        // is the only line that does, and it is on the non-null set path.
        u.set(P::Host, Some(b"[::1]"), F::NONE).expect("host");
        assert_eq!(u.get(P::ZoneId, F::NONE), Err(E::NoZoneid));
        assert_eq!(
            u.get(P::Url, F::NONE),
            Ok(b"https://[::1]/hello.html".to_vec())
        );

        u.set(P::Host, Some(b"example.com"), F::NONE).expect("host");
        assert_eq!(
            u.get(P::Url, F::NONE),
            Ok(b"https://example.com/hello.html".to_vec())
        );

        // A host set *with* a zone identifier keeps the identifier as a side
        // effect of the validation and stores the host exactly as given, so
        // the rendering doubles it. Measured against a real libcurl.
        u.set(P::Host, Some(b"[fe80::20c:29ff:fe9c:409b%25eth0]"), F::NONE)
            .expect("host");
        assert_eq!(
            u.get(P::Host, F::NONE),
            Ok(b"[fe80::20c:29ff:fe9c:409b%25eth0]".to_vec())
        );
        assert_eq!(u.get(P::ZoneId, F::NONE), Ok(b"eth0".to_vec()));
        assert_eq!(
            u.get(P::Url, F::NONE),
            Ok(b"https://[fe80::20c:29ff:fe9c:409b%25eth0%25eth0]\
                 /hello.html"
                .to_vec())
        );

        u.set(P::ZoneId, Some(b"clown"), F::NONE).expect("zoneid");
        assert_eq!(
            u.get(P::Url, F::NONE),
            Ok(b"https://[fe80::20c:29ff:fe9c:409b%25eth0%25clown]\
                 /hello.html"
                .to_vec())
        );
    }

    /// The size `huge` uses for its oversized part.
    ///
    /// The C's is 120,000 bytes (`lib1560.c:1911`). Miri interprets every one
    /// of those bytes through the encode and scan walks, so the interpreted
    /// run uses a smaller figure. Both are far above every buffer this module
    /// sizes and both cross `MAX_SCHEME_LEN`, so the branches exercised are
    /// identical; only the native run keeps the C's number.
    #[cfg(not(miri))]
    const BIGPART: usize = 120_000;
    #[cfg(miri)]
    const BIGPART: usize = 2_000;

    /// `huge` (`lib1560.c:1913-1966`).
    ///
    /// Each of seven parts is given an absurdly long value in turn, and must
    /// come back byte for byte -- except the scheme, which
    /// [`MAX_SCHEME_LEN`] refuses. In C this probes for buffer overflows; here
    /// it probes that nothing silently truncates, which is the failure mode a
    /// safe language leaves open.
    #[test]
    fn huge_parts_survive_a_round_trip() {
        // `bigpart[0] = '/'; memset(&bigpart[1], 'a', sizeof - 2);`
        let mut bigpart = vec![b'a'; BIGPART - 1];
        bigpart[0] = b'/';
        let tail = &bigpart[1..];

        let parts = [
            P::Scheme,
            P::User,
            P::Password,
            P::Host,
            P::Path,
            P::Query,
            P::Fragment,
        ];

        for (index, part) in parts.iter().enumerate() {
            let pick = |slot: usize| -> &[u8] {
                if slot == index {
                    tail
                } else {
                    b"c"
                }
            };
            let mut total: Vec<u8> = Vec::new();
            total.extend_from_slice(pick(0));
            total.extend_from_slice(b"://");
            total.extend_from_slice(pick(1));
            total.push(b':');
            total.extend_from_slice(pick(2));
            total.push(b'@');
            total.extend_from_slice(pick(3));
            total.push(b'/');
            total.extend_from_slice(pick(4));
            total.push(b'?');
            total.extend_from_slice(pick(5));
            total.push(b'#');
            total.extend_from_slice(pick(6));

            let mut u = handle();
            let rc = u.set(P::Url, Some(&total), F::NON_SUPPORT_SCHEME);
            if index == 0 {
                assert_eq!(
                    rc,
                    Err(E::BadScheme),
                    "an oversized scheme must be refused"
                );
                continue;
            }
            rc.unwrap_or_else(|code| panic!("part {index} returned {code:?}"));

            // `strcmp(partp, &bigpart[1 - (i == 4)])` -- the path alone comes
            // back with its leading slash.
            let wanted: &[u8] = if index == 4 { &bigpart } else { tail };
            let got = u.get(*part, F::NONE).unwrap_or_else(|code| {
                panic!("part {index} get returned {code:?}")
            });
            assert_eq!(got.len(), wanted.len(), "part {index} length");
            assert!(got == wanted, "part {index} content");
        }
    }

    /// `urldup` (`lib1560.c:1968-2029`).
    ///
    /// A duplicate must render identically to its original. Note the flags:
    /// the parse uses `CURLU_GUESS_SCHEME` and the two gets use none, so a
    /// guessed scheme is rendered by both and the omission
    /// [`Url::dup`] reproduces stays invisible here. Making it visible takes
    /// `CURLU_NO_GUESS_SCHEME`, which is the next test.
    #[test]
    fn urldup_renders_identically_to_its_original() {
        const URLS: &[&[u8]] = &[
            b"http://user:pwd@[2a04:4e42:e00::347%25eth0]:80\
              /path?query#fraggie",
            b"https://example.com",
            b"https://user@example.com",
            b"https://user.pwd@example.com",
            b"https://user.pwd@example.com:1234",
            b"https://example.com:1234",
            b"example.com:1234",
            b"https://user.pwd@example.com:1234/path?query#frag",
        ];
        for url in URLS {
            let mut original = handle();
            original
                .set(P::Url, Some(url), F::GUESS_SCHEME)
                .unwrap_or_else(|code| {
                    panic!("in: {}\nset returned {code:?}", show(url))
                });
            let copy = original.dup();
            let left = original.get(P::Url, F::NONE).expect("original");
            let right = copy.get(P::Url, F::NONE).expect("copy");
            assert_eq!(
                show(&left),
                show(&right),
                "in: {}\nthe duplicate rendered differently",
                show(url)
            );
        }
    }

    /// `dedotdotify` pairs, ported from `tests/unit/unit1395.c:39-110`.
    ///
    /// `None` is the C's null output with a zero return -- *"leave the path
    /// alone"*, which is how the function reports that nothing needed
    /// removing.
    const DOTDOT_PAIRS: &[(&[u8], Option<&[u8]>)] = &[
        (b"%2f%2e%2e%2f/../a", Some(b"%2f%2e%2e%2f/a")),
        (b"%2f%2e%2e%2f/../", Some(b"%2f%2e%2e%2f/")),
        (b"%2f%2e%2e%2f/.", Some(b"%2f%2e%2e%2f/")),
        (b"%2f%2e%2e%2f/", Some(b"%2f%2e%2e%2f/")),
        (b"%2f%2e%2e%2f", Some(b"%2f%2e%2e%2f")),
        (b"%2f%2e%2e%2", Some(b"%2f%2e%2e%2")),
        (b"%2f%2e%2e%", Some(b"%2f%2e%2e%")),
        (b"%2f%2e%2e", Some(b"%2f%2e%2e")),
        (b"%2f%2e%2", Some(b"%2f%2e%2")),
        (b"%2f%2e%", Some(b"%2f%2e%")),
        (b"%2f%2e", Some(b"%2f%2e")),
        (b"%2f%2", Some(b"%2f%2")),
        (b"%2f%", Some(b"%2f%")),
        (b"%2f", Some(b"%2f")),
        (b"%2", Some(b"%2")),
        (b"%", None),
        (b"2", None),
        (b"e", None),
        (b".", None),
        (b"./", Some(b"")),
        (b"..", Some(b"")),
        (b"../", Some(b"")),
        (b"../a", Some(b"a")),
        (b"///moo.", Some(b"///moo.")),
        (b".///moo.", Some(b"//moo.")),
        (b"./moo..", Some(b"moo..")),
        (b"./moo../", Some(b"moo../")),
        (b"./moo../.m", Some(b"moo../.m")),
        (b"./moo", Some(b"moo")),
        (b"../moo", Some(b"moo")),
        (b"../moo?", Some(b"moo?")),
        (b"../moo?#", Some(b"moo?#")),
        (b"../moo?#?..", Some(b"moo?#?..")),
        (b"/../moo/..", Some(b"/")),
        (b"/a/c/%2e%2E/b", Some(b"/a/b")),
        (b"/a/%2e/g", Some(b"/a/g")),
        (b"/a/b/c/./g", Some(b"/a/b/c/g")),
        (b"/a/c/../b", Some(b"/a/b")),
        (b"/a/b/c/./../../g", Some(b"/a/g")),
        (b"/a/b/c/./%2e%2E/../g", Some(b"/a/g")),
        (b"/a/b/c/./../%2e%2E/g", Some(b"/a/g")),
        (b"/a/b/c/%2E/%2e%2E/%2e%2E/g", Some(b"/a/g")),
        (b"mid/content=5/../6", Some(b"mid/6")),
        (b"/hello/../moo", Some(b"/moo")),
        (b"/1/../1", Some(b"/1")),
        (b"/1/./1", Some(b"/1/1")),
        (b"/1/%2e/1", Some(b"/1/1")),
        (b"/1/%2E/1", Some(b"/1/1")),
        (b"/1/..", Some(b"/")),
        (b"/1/.", Some(b"/1/")),
        (b"/1/%2e", Some(b"/1/")),
        (b"/1/%2E", Some(b"/1/")),
        (b"/1/./..", Some(b"/")),
        (b"/1/%2e/.%2E", Some(b"/")),
        (b"/1/./%2e.", Some(b"/")),
        (b"/1/./../2", Some(b"/2")),
        (b"/hello/1/./../2", Some(b"/hello/2")),
        (b"test/this", Some(b"test/this")),
        (b"test/this/../now", Some(b"test/now")),
        (b"/1../moo../foo", Some(b"/1../moo../foo")),
        (b"/../../moo", Some(b"/moo")),
        (b"/../../moo?", Some(b"/moo?")),
        (b"/123?", Some(b"/123?")),
        (b"/", None),
        (b"", None),
        (b"/.../", Some(b"/.../")),
        (b"/.", Some(b"/")),
        (b"/..", Some(b"/")),
        (b"/moo/..", Some(b"/")),
        (b"/..", Some(b"/")),
        (b"/.", Some(b"/")),
    ];

    /// `test_unit1395` (`tests/unit/unit1395.c:27-137`), all 71 pairs.
    #[test]
    fn dedotdotify_matches_unit1395() {
        assert_eq!(DOTDOT_PAIRS.len(), 71, "pair count drifted");
        for (input, wanted) in DOTDOT_PAIRS {
            let got = dedotdotify(input);
            assert_eq!(
                got.as_deref().map(show),
                wanted.map(show),
                "in: {}",
                show(input)
            );
        }
    }

    /// The `parse_port` wrapper of `tests/unit/unit1653.c:31-42`, which hands
    /// the function a dynbuf whose ceiling is 10,000.
    fn call_parse_port(
        u: &mut Url,
        host: &[u8],
        has_scheme: bool,
    ) -> Result<(), CURLUcode> {
        let mut buf = Buf::new(10_000);
        buf.addn(host).map_err(|_| E::OutOfMemory)?;
        parse_port(u, &mut buf, has_scheme)
    }

    /// `test_unit1653` (`tests/unit/unit1653.c:43-206`), all 11 cases.
    ///
    /// `Curl_parse_port` is `UNITTEST`-visible in C (`lib/urlapi-int.h:37`)
    /// and private here, which is why this test lives in the same file as the
    /// function rather than beside the crate.
    #[test]
    fn parse_port_matches_unit1653() {
        // Valid IPv6, no port: nothing is stored, so a get under
        // CURLU_NO_DEFAULT_PORT must fail.
        let mut u = handle();
        assert_eq!(
            call_parse_port(&mut u, b"[fe80::250:56ff:fea7:da15]", false),
            Ok(())
        );
        assert!(u.get(P::Port, F::NO_DEFAULT_PORT).is_err());

        // Invalid IPv6: an unterminated bracket.
        let mut u = handle();
        assert!(
            call_parse_port(&mut u, b"[fe80::250:56ff:fea7:da15|", false)
                .is_err()
        );

        // A malformed address is not this function's business -- it extracts
        // the port and leaves validity to `hostname_check`.
        let mut u = handle();
        assert_eq!(
            call_parse_port(&mut u, b"[fe80::250:56ff;fea7:da15]:808", false),
            Ok(())
        );
        assert_eq!(u.get(P::Port, F::NONE), Ok(b"808".to_vec()));

        // Zone index and a port.
        let mut u = handle();
        assert_eq!(
            call_parse_port(
                &mut u,
                b"[fe80::250:56ff:fea7:da15%25eth3]:80",
                false
            ),
            Ok(())
        );
        assert_eq!(u.get(P::Port, F::NONE), Ok(b"80".to_vec()));

        // Zone index, no port.
        let mut u = handle();
        assert_eq!(
            call_parse_port(
                &mut u,
                b"[fe80::250:56ff:fea7:da15%25eth3]",
                false
            ),
            Ok(())
        );

        // A port.
        let mut u = handle();
        assert_eq!(
            call_parse_port(&mut u, b"[fe80::250:56ff:fea7:da15]:81", false),
            Ok(())
        );
        assert_eq!(u.get(P::Port, F::NONE), Ok(b"81".to_vec()));

        // A semicolon where the colon should be.
        let mut u = handle();
        assert!(call_parse_port(
            &mut u,
            b"[fe80::250:56ff:fea7:da15];81",
            false
        )
        .is_err());

        // Digits with no separator at all.
        let mut u = handle();
        assert!(call_parse_port(
            &mut u,
            b"[fe80::250:56ff:fea7:da15]80",
            false
        )
        .is_err());

        // A colon with no digits is browser behaviour -- but only when the
        // input carried a scheme.
        let mut u = handle();
        assert_eq!(
            call_parse_port(&mut u, b"[fe80::250:56ff:fea7:da15]:", true),
            Ok(())
        );

        // A mangled zone index still yields its port.
        let mut u = handle();
        assert_eq!(
            call_parse_port(
                &mut u,
                b"[fe80::250:56ff:fea7:da15!25eth3]:180",
                false
            ),
            Ok(())
        );
        assert_eq!(u.get(P::Port, F::NONE), Ok(b"180".to_vec()));

        // A zone index that is not percent-encoded.
        let mut u = handle();
        assert_eq!(
            call_parse_port(
                &mut u,
                b"[fe80::250:56ff:fea7:da15%eth3]:80",
                false
            ),
            Ok(())
        );

        // No scheme and no digits after the colon is refused, and the C says
        // why: *"Because that makes (a*50):// that looks like a scheme be an
        // acceptable input."*
        let mut u = handle();
        assert_eq!(
            call_parse_port(&mut u, &[b'a'; 64], false),
            Ok(()),
            "no colon at all is simply a host"
        );
        let mut u = handle();
        let mut colon = vec![b'a'; 64];
        colon.push(b':');
        assert_eq!(
            call_parse_port(&mut u, &colon, false),
            Err(E::BadPortNumber)
        );
    }

    // -----------------------------------------------------------------------
    // The pinned ABI surface.
    // -----------------------------------------------------------------------

    /// Every `CURLUPart` member, with its integer, against
    /// `include/curl/urlapi.h:70-82`.
    ///
    /// The C declares none of these explicitly, so the values come from
    /// declaration order and a reordering there would be silent. Here they are
    /// explicit and asserted, which is the drift guard the header lacks.
    #[test]
    fn every_part_holds_its_header_integer() {
        const WANTED: &[(UrlPart, i32)] = &[
            (P::Url, 0),
            (P::Scheme, 1),
            (P::User, 2),
            (P::Password, 3),
            (P::Options, 4),
            (P::Host, 5),
            (P::Port, 6),
            (P::Path, 7),
            (P::Query, 8),
            (P::Fragment, 9),
            (P::ZoneId, 10),
        ];
        assert_eq!(UrlPart::VARIANTS.len(), 11, "CURLUPart has 11 members");
        assert_eq!(WANTED.len(), 11);
        for (part, value) in WANTED {
            assert_eq!(part.as_i32(), *value, "{part:?}");
            assert_eq!(UrlPart::from_i32(*value), Some(*part));
        }
        for (index, part) in UrlPart::VARIANTS.iter().enumerate() {
            assert_eq!(
                part.as_i32(),
                i32::try_from(index).expect("index fits"),
                "the members must occupy 0..=10 with no gaps"
            );
        }
        // Outside the range there is no member, and both raw entry points
        // turn that into the C's `default:` arm.
        for raw in [-1, 11, 9999, i32::MIN, i32::MAX] {
            assert_eq!(UrlPart::from_i32(raw), None, "{raw}");
            let mut u = handle();
            assert_eq!(u.get_by_id(raw, F::NONE), Err(E::UnknownPart));
            assert_eq!(
                u.set_by_id(raw, Some(b"x"), F::NONE),
                Err(E::UnknownPart)
            );
            // Even a null `part`, which would otherwise clear: the C's
            // `urlset_clear` has the same `default:` arm at
            // `lib/urlapi.c:1773`.
            assert_eq!(u.set_by_id(raw, None, F::NONE), Err(E::UnknownPart));
        }
    }

    /// All sixteen `CURLU_*` bits, against `include/curl/urlapi.h:84-105`.
    #[test]
    fn every_flag_holds_its_header_bit() {
        const WANTED: &[(UrlFlags, u32)] = &[
            (F::DEFAULT_PORT, 1 << 0),
            (F::NO_DEFAULT_PORT, 1 << 1),
            (F::DEFAULT_SCHEME, 1 << 2),
            (F::NON_SUPPORT_SCHEME, 1 << 3),
            (F::PATH_AS_IS, 1 << 4),
            (F::DISALLOW_USER, 1 << 5),
            (F::URLDECODE, 1 << 6),
            (F::URLENCODE, 1 << 7),
            (F::APPENDQUERY, 1 << 8),
            (F::GUESS_SCHEME, 1 << 9),
            (F::NO_AUTHORITY, 1 << 10),
            (F::ALLOW_SPACE, 1 << 11),
            (F::PUNYCODE, 1 << 12),
            (F::PUNY2IDN, 1 << 13),
            (F::GET_EMPTY, 1 << 14),
            (F::NO_GUESS_SCHEME, 1 << 15),
        ];
        assert_eq!(WANTED.len(), 16);
        let mut seen = 0u32;
        for (flag, bit) in WANTED {
            assert_eq!(flag.bits(), *bit);
            assert!(flag.has(*flag));
            assert!(!F::NONE.has(*flag));
            seen |= *bit;
        }
        assert_eq!(seen, 0xffff, "the sixteen bits must be 1<<0 .. 1<<15");
        assert_eq!(F::NONE.bits(), 0);

        // `union`, `without` and the operator agree, and an unknown bit is
        // carried rather than rejected -- the C never validates the mask.
        let both = F::URLENCODE.union(F::ALLOW_SPACE);
        assert_eq!(both, F::URLENCODE | F::ALLOW_SPACE);
        assert!(both.has(F::URLENCODE) && both.has(F::ALLOW_SPACE));
        assert_eq!(both.without(F::ALLOW_SPACE), F::URLENCODE);
        assert_eq!(F::from_bits(1 << 20).bits(), 1 << 20);
        let mut acc = F::NONE;
        acc |= F::GET_EMPTY;
        assert_eq!(acc, F::GET_EMPTY);
    }

    /// The two constants the C spells out, and the input ceiling.
    #[test]
    fn the_pinned_constants_match_their_c_definitions() {
        assert_eq!(MAX_SCHEME_LEN, 40, "lib/urlapi.c:55");
        assert_eq!(DEFAULT_SCHEME, b"https", "lib/urlapi.c:84");
        assert_eq!(MAX_INPUT_LENGTH, 8_000_000, "lib/urldata.h:131");
    }

    // -----------------------------------------------------------------------
    // Empty versus absent.
    // -----------------------------------------------------------------------

    /// A blank query is not an absent query, and `CURLU_GET_EMPTY` is what
    /// tells them apart.
    #[test]
    fn a_blank_query_is_distinct_from_an_absent_one() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/?"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Query, F::NONE), Err(E::NoQuery));
        assert_eq!(u.get(P::Query, F::GET_EMPTY), Ok(Vec::new()));
        // `show_query` additionally requires a non-empty first byte, so the
        // question mark is withheld without the flag.
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"http://x/".to_vec()));
        assert_eq!(u.get(P::Url, F::GET_EMPTY), Ok(b"http://x/?".to_vec()));

        // With no query at all, the flag changes nothing.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Query, F::GET_EMPTY), Err(E::NoQuery));
        assert_eq!(u.get(P::Url, F::GET_EMPTY), Ok(b"http://x/".to_vec()));
    }

    /// A blank fragment behaves the same way -- but `show_fragment` does
    /// **not** test a first byte, which is a one-character asymmetry with
    /// `show_query` at `lib/urlapi.c:1434-1435`.
    #[test]
    fn a_blank_fragment_is_distinct_from_an_absent_one() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/#"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Fragment, F::NONE), Err(E::NoFragment));
        assert_eq!(u.get(P::Fragment, F::GET_EMPTY), Ok(Vec::new()));
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"http://x/".to_vec()));
        assert_eq!(u.get(P::Url, F::GET_EMPTY), Ok(b"http://x/#".to_vec()));

        let mut u = handle();
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Fragment, F::GET_EMPTY), Err(E::NoFragment));
    }

    /// Setting a part blank stores a blank -- unless the encoder is asked
    /// for, in which case nothing is appended at all and the field is
    /// **cleared**.
    ///
    /// The mechanism is `curlx_dyn_ptr` returning null after zero appends
    /// (`lib/urlapi.c:1934` over a buffer the encode loop at `:1890-1914`
    /// never touched) where `curlx_dyn_add` at `:1918` materialises
    /// unconditionally. Measured against a real libcurl, and the reason the
    /// parts of this module are `Option<Vec<u8>>` rather than `Vec<u8>`.
    #[test]
    fn an_empty_set_stores_a_blank_but_an_empty_encoded_set_clears() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/?a=b"), F::NONE)
            .expect("parse");

        u.set(P::Query, Some(b""), F::NONE).expect("blank query");
        assert_eq!(u.get(P::Query, F::GET_EMPTY), Ok(Vec::new()));

        u.set(P::Query, Some(b""), F::URLENCODE).expect("cleared");
        assert_eq!(
            u.get(P::Query, F::GET_EMPTY),
            Err(E::NoQuery),
            "the encoder appended nothing, so the field is gone"
        );
        // ... yet `query_present` survives, because only `urlset_clear`
        // lowers it and this went through the ordinary set path.
        assert_eq!(u.get(P::Url, F::GET_EMPTY), Ok(b"http://x/?".to_vec()));
    }

    /// A path set blank still gets its slash, because `part[0]` is the
    /// terminator and `leadingslash` prepends whenever the first byte is not
    /// one (`lib/urlapi.c:1884-1888`).
    #[test]
    fn a_blank_path_becomes_a_slash() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/deep/path"), F::NONE)
            .expect("parse");
        u.set(P::Path, Some(b""), F::NONE).expect("blank path");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/".to_vec()));
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"http://x/".to_vec()));

        // And a path without one gets one prepended.
        u.set(P::Path, Some(b"here"), F::NONE).expect("path");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/here".to_vec()));
    }

    // -----------------------------------------------------------------------
    // Scheme handling.
    // -----------------------------------------------------------------------

    /// The lookup folds case, and the scheme is stored folded.
    ///
    /// `Curl_getn_scheme` lower-cases into its hash and compares with
    /// `curl_strnequal` (`lib/url.c:1523-1538`), and four registry names are
    /// upper case, so a case-sensitive comparison anywhere would break `ws`,
    /// `wss`, `sftp` and `scp` outright.
    #[test]
    fn scheme_lookup_and_storage_fold_case() {
        for (input, wanted) in [
            (&b"HTTP://x/"[..], &b"http://x/"[..]),
            (b"Http://x/", b"http://x/"),
            (b"hTTps://x/", b"https://x/"),
            (b"WS://x/", b"ws://x/"),
            (b"wss://x/", b"wss://x/"),
            (b"sftp://x/", b"sftp://x/"),
            (b"SFTP://x/", b"sftp://x/"),
            (b"ScP://x/", b"scp://x/"),
            (b"FTP://x/", b"ftp://x/"),
        ] {
            let mut u = handle();
            u.set(P::Url, Some(input), F::NONE).unwrap_or_else(|code| {
                panic!("in: {}\nreturned {code:?}", show(input))
            });
            assert_eq!(
                u.get(P::Url, F::NONE).map(|got| show(&got)),
                Ok(show(wanted)),
                "in: {}",
                show(input)
            );
        }
        // And on the set path, where no folding happens at all: the scheme is
        // stored exactly as given, because `CURLUPART_SCHEME` forces the
        // encoder off and nothing else touches it.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");
        u.set(P::Scheme, Some(b"HTTPS"), F::NONE).expect("scheme");
        assert_eq!(u.get(P::Scheme, F::NONE), Ok(b"HTTPS".to_vec()));
    }

    /// Parsing a scheme and setting one use **different** predicates.
    ///
    /// `parse_scheme` consults table membership alone (`lib/urlapi.c:951`);
    /// `set_url_scheme` additionally requires an implementation (`:1646`). So
    /// a scheme that is registered but unimplemented parses inside a URL and
    /// is refused as a part -- on the same build, with the same flags.
    #[test]
    fn parsing_a_scheme_and_setting_one_disagree() {
        // The stubbed registry: `smtp` is known, and has no implementation.
        let mut u = stubbed();
        u.set(P::Url, Some(b"smtp://host/"), F::NONE)
            .expect("parsing a registered scheme succeeds");
        assert_eq!(u.get(P::Scheme, F::NONE), Ok(b"smtp".to_vec()));
        assert_eq!(
            u.set(P::Scheme, Some(b"smtp"), F::NONE),
            Err(E::UnsupportedScheme),
            "setting it requires an implementation"
        );
        // `CURLU_NON_SUPPORT_SCHEME` waives the requirement.
        assert_eq!(
            u.set(P::Scheme, Some(b"smtp"), F::NON_SUPPORT_SCHEME),
            Ok(())
        );

        // On the registry where it is implemented, both succeed.
        let mut u = handle();
        u.set(P::Url, Some(b"smtp://host/"), F::NONE)
            .expect("parse");
        assert_eq!(u.set(P::Scheme, Some(b"smtp"), F::NONE), Ok(()));
    }

    /// An unknown scheme needs `CURLU_NON_SUPPORT_SCHEME` on both paths.
    #[test]
    fn an_unknown_scheme_needs_the_waiver() {
        let mut u = handle();
        assert_eq!(
            u.set(P::Url, Some(b"custom://host/"), F::NONE),
            Err(E::UnsupportedScheme)
        );
        assert_eq!(
            u.set(P::Url, Some(b"custom://host/"), F::NON_SUPPORT_SCHEME),
            Ok(())
        );
        assert_eq!(u.get(P::Scheme, F::NONE), Ok(b"custom".to_vec()));

        let mut u = handle();
        u.set(P::Url, Some(b"http://host/"), F::NONE)
            .expect("parse");
        assert_eq!(
            u.set(P::Scheme, Some(b"custom"), F::NONE),
            Err(E::UnsupportedScheme)
        );
        assert_eq!(
            u.set(P::Scheme, Some(b"custom"), F::NON_SUPPORT_SCHEME),
            Ok(())
        );
    }

    /// The scheme length bounds, and the loop that does not look at the last
    /// byte.
    #[test]
    fn a_trailing_byte_of_a_scheme_is_never_examined() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");

        // `while(--plen)` runs `plen - 1` times from index 0, so the byte at
        // `plen - 1` is never tested (`lib/urlapi.c:1652`). Measured against a
        // real libcurl; reproduced under AAP section 0.8.2.
        assert_eq!(
            u.set(P::Scheme, Some(b"ab$"), F::NON_SUPPORT_SCHEME),
            Ok(()),
            "the '$' is the last byte and is skipped"
        );
        assert_eq!(
            u.set(P::Scheme, Some(b"a$b"), F::NON_SUPPORT_SCHEME),
            Err(E::BadScheme),
            "a '$' anywhere else is examined"
        );

        // A non-letter first byte is always refused.
        assert_eq!(
            u.set(P::Scheme, Some(b"1ab"), F::NON_SUPPORT_SCHEME),
            Err(E::BadScheme)
        );

        // The length window is 1..=MAX_SCHEME_LEN.
        assert_eq!(
            u.set(P::Scheme, Some(b""), F::NON_SUPPORT_SCHEME),
            Err(E::BadScheme)
        );
        let forty = vec![b'b'; MAX_SCHEME_LEN];
        assert_eq!(
            u.set(P::Scheme, Some(&forty), F::NON_SUPPORT_SCHEME),
            Ok(())
        );
        let over = vec![b'b'; MAX_SCHEME_LEN + 1];
        assert_eq!(
            u.set(P::Scheme, Some(&over), F::NON_SUPPORT_SCHEME),
            Err(E::BadScheme)
        );

        // A space in a scheme is refused whatever `CURLU_ALLOW_SPACE` says --
        // that flag governs the junk scan, not this syntax check.
        assert_eq!(
            u.set(P::Scheme, Some(b"ht tp"), F::NON_SUPPORT_SCHEME),
            Err(E::BadScheme)
        );
        assert_eq!(
            u.set(
                P::Scheme,
                Some(b"ht tp"),
                F::NON_SUPPORT_SCHEME.union(F::ALLOW_SPACE)
            ),
            Err(E::BadScheme)
        );
        let mut u = handle();
        assert_eq!(
            u.set(P::Url, Some(b"ht tp://x/"), F::ALLOW_SPACE),
            Err(E::BadScheme),
            "and a space stops the scheme scan inside a URL too"
        );
    }

    /// The guessing table, its six prefixes and its fall-through.
    ///
    /// `guess_scheme` (`lib/urlapi.c:984-1010`). Five of the six prefixes name
    /// schemes this workspace stubs, and the table must keep working for them
    /// regardless -- nothing in the function consults the registry.
    #[test]
    fn scheme_guessing_uses_the_outermost_label() {
        for (host, wanted) in [
            (&b"ftp.example.com"[..], &b"ftp"[..]),
            (b"dict.example.com", b"dict"),
            (b"ldap.example.com", b"ldap"),
            (b"imap.example.com", b"imap"),
            (b"smtp.example.com", b"smtp"),
            (b"pop3.example.com", b"pop3"),
            (b"FTP.EXAMPLE.COM", b"ftp"),
            (b"example.com", b"http"),
            (b"ftpx.example.com", b"http"),
            (b"ftp", b"http"),
            (b"www.ftp.example.com", b"http"),
        ] {
            let mut u = handle();
            u.set(P::Url, Some(host), F::GUESS_SCHEME)
                .unwrap_or_else(|code| {
                    panic!("in: {}\nreturned {code:?}", show(host))
                });
            assert_eq!(
                u.get(P::Scheme, F::NONE).map(|got| show(&got)),
                Ok(show(wanted)),
                "in: {}",
                show(host)
            );
        }

        // The stubbed registry guesses identically, which is the point: a
        // guessed scheme is never looked up.
        let mut u = stubbed();
        u.set(P::Url, Some(b"smtp.example.com"), F::GUESS_SCHEME)
            .expect("guess");
        assert_eq!(u.get(P::Scheme, F::NONE), Ok(b"smtp".to_vec()));
    }

    /// `CURLU_NO_GUESS_SCHEME` hides a guessed scheme, on both the part and
    /// the whole URL.
    ///
    /// `docs/libcurl/curl_url_get.md:139-142` gives the round trip: the URL
    /// comes back without a scheme component and is re-parseable only with
    /// `CURLU_GUESS_SCHEME`.
    #[test]
    fn no_guess_scheme_withholds_a_guessed_scheme() {
        let mut u = handle();
        u.set(P::Url, Some(b"example.com/path"), F::GUESS_SCHEME)
            .expect("guess");
        assert_eq!(u.get(P::Scheme, F::NONE), Ok(b"http".to_vec()));
        assert_eq!(u.get(P::Scheme, F::NO_GUESS_SCHEME), Err(E::NoScheme));
        assert_eq!(
            u.get(P::Url, F::NO_GUESS_SCHEME),
            Ok(b"example.com/path".to_vec())
        );
        // Re-parsing that needs the guess flag back.
        let bare = u.get(P::Url, F::NO_GUESS_SCHEME).expect("bare");
        let mut again = handle();
        assert_eq!(again.set(P::Url, Some(&bare), F::NONE), Err(E::BadScheme));
        assert_eq!(again.set(P::Url, Some(&bare), F::GUESS_SCHEME), Ok(()));

        // An explicit scheme is never withheld.
        let mut u = handle();
        u.set(P::Url, Some(b"http://example.com/path"), F::NONE)
            .expect("parse");
        assert_eq!(u.get(P::Scheme, F::NO_GUESS_SCHEME), Ok(b"http".to_vec()));

        // And setting the scheme clears the bit, so it stops being withheld.
        let mut u = handle();
        u.set(P::Url, Some(b"example.com/path"), F::GUESS_SCHEME)
            .expect("guess");
        u.set(P::Scheme, Some(b"https"), F::NONE).expect("scheme");
        assert_eq!(u.get(P::Scheme, F::NO_GUESS_SCHEME), Ok(b"https".to_vec()));
    }

    /// `CURLU_DEFAULT_SCHEME` wins over `CURLU_GUESS_SCHEME` when both are
    /// set, and the result is not marked as guessed.
    ///
    /// `parse_scheme` stores the default itself (`lib/urlapi.c:963`), and
    /// `parseurl`'s guess only runs when no scheme is stored, so the guess
    /// never happens. `docs/libcurl/curl_url_set.md:201-210` says the same.
    #[test]
    fn a_default_scheme_overrides_a_guessed_one() {
        let mut u = handle();
        u.set(
            P::Url,
            Some(b"example.com/path"),
            F::DEFAULT_SCHEME.union(F::GUESS_SCHEME),
        )
        .expect("parse");
        assert_eq!(u.get(P::Scheme, F::NONE), Ok(b"https".to_vec()));
        assert_eq!(
            u.get(P::Scheme, F::NO_GUESS_SCHEME),
            Ok(b"https".to_vec()),
            "a default scheme is not a guessed one"
        );

        // Even where the guess would have chosen differently.
        let mut u = handle();
        u.set(
            P::Url,
            Some(b"ftp.example.com/path"),
            F::DEFAULT_SCHEME.union(F::GUESS_SCHEME),
        )
        .expect("parse");
        assert_eq!(u.get(P::Scheme, F::NONE), Ok(b"https".to_vec()));

        // Guessing alone chooses ftp, and marks it guessed.
        let mut u = handle();
        u.set(P::Url, Some(b"ftp.example.com/path"), F::GUESS_SCHEME)
            .expect("parse");
        assert_eq!(u.get(P::Scheme, F::NONE), Ok(b"ftp".to_vec()));
        assert_eq!(u.get(P::Scheme, F::NO_GUESS_SCHEME), Err(E::NoScheme));

        // With neither, a schemeless URL is refused outright.
        let mut u = handle();
        assert_eq!(
            u.set(P::Url, Some(b"example.com/path"), F::NONE),
            Err(E::BadScheme)
        );
    }

    /// Slash counting after the colon: one, two or three, and nothing else.
    ///
    /// `parse_scheme` consumes at most four and rejects `i < 1 || i > 3`
    /// (`lib/urlapi.c:945-957`). Note the ordering -- the table check runs
    /// **before** the count test, so an unknown scheme with no slashes reports
    /// `UNSUPPORTED_SCHEME` rather than `BAD_SLASHES`.
    #[test]
    fn one_two_or_three_slashes_are_accepted() {
        for (input, wanted) in [
            (
                &b"http:/example.com/p"[..],
                Ok(b"http://example.com/p".to_vec()),
            ),
            (
                b"http://example.com/p",
                Ok(b"http://example.com/p".to_vec()),
            ),
            (
                b"http:///example.com/p",
                Ok(b"http://example.com/p".to_vec()),
            ),
            (b"http:example.com/p", Err(E::BadSlashes)),
            (b"http:////example.com/p", Err(E::BadSlashes)),
        ] {
            let mut u = handle();
            let rc = u.set(P::Url, Some(input), F::NONE);
            match wanted {
                Ok(text) => {
                    rc.unwrap_or_else(|code| {
                        panic!("in: {}\nreturned {code:?}", show(input))
                    });
                    assert_eq!(
                        u.get(P::Url, F::NONE).map(|got| show(&got)),
                        Ok(show(&text)),
                        "in: {}",
                        show(input)
                    );
                }
                Err(code) => assert_eq!(rc, Err(code), "in: {}", show(input)),
            }
        }
        // The table check comes first.
        let mut u = handle();
        assert_eq!(
            u.set(P::Url, Some(b"mailto:someone@example.com"), F::NONE),
            Err(E::UnsupportedScheme)
        );
        assert_eq!(
            u.set(
                P::Url,
                Some(b"mailto:someone@example.com"),
                F::NON_SUPPORT_SCHEME
            ),
            Err(E::BadSlashes),
            "with the waiver, the count test is reached"
        );
    }

    // -----------------------------------------------------------------------
    // Paths, encoding and the three hex casings.
    // -----------------------------------------------------------------------

    /// `allowed_in_path` accepts eighteen bytes and the manual page lists
    /// seventeen -- **the missing one is `/`**.
    ///
    /// `lib/urlapi.c:1782-1799` against
    /// `docs/libcurl/curl_url_set.md:190`. This is the single most
    /// consequential place in the module to go wrong by trusting the
    /// documentation: escaping `/` would turn every path set under
    /// `CURLU_URLENCODE` into one segment.
    #[test]
    fn a_path_keeps_its_slashes_and_the_other_seventeen_bytes() {
        const ALLOWED: &[u8] = b"!$&'(){}[]*+,;=:@/";
        assert_eq!(ALLOWED.len(), 18, "the switch has eighteen cases");
        for byte in ALLOWED {
            assert!(
                allowed_in_path(*byte),
                "{} must survive a path encode",
                show(&[*byte])
            );
        }
        // Nothing else does. The predicate widens the accept set; the
        // unreserved bytes are admitted separately, so they are excluded here.
        for byte in 0u8..=255 {
            if ALLOWED.contains(&byte) {
                continue;
            }
            assert!(
                !allowed_in_path(byte),
                "{} is not in the switch",
                show(&[byte])
            );
        }

        // End to end: the slashes survive and only the space and the percent
        // are escaped. This is `set_parts_list`'s first row, restated so that
        // the intent is visible without decoding a table.
        let mut u = handle();
        u.set(P::Url, Some(b"https://example.com/"), F::NONE)
            .expect("parse");
        u.set(P::Path, Some(b"/a/b"), F::URLENCODE).expect("path");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/a/b".to_vec()));

        u.set(P::Path, Some(b"one /$!$&'()*+;=:@{}[]%"), F::URLENCODE)
            .expect("path");
        assert_eq!(
            u.get(P::Path, F::NONE).map(|got| show(&got)),
            Ok(show(b"/one%20/$!$&'()*+;=:@{}[]%25"))
        );

        // A comma survives too -- `lib1560.c` never tests it, and it is in the
        // switch at `lib/urlapi.c:1794`.
        u.set(P::Path, Some(b"/a,b"), F::URLENCODE).expect("path");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/a,b".to_vec()));

        // And bytes outside the set are escaped, in upper case.
        u.set(P::Path, Some(b"/a<b>c\"d e"), F::URLENCODE)
            .expect("path");
        assert_eq!(
            u.get(P::Path, F::NONE).map(|got| show(&got)),
            Ok(show(b"/a%3Cb%3Ec%22d%20e"))
        );
    }

    /// Three hex casings coexist in this directory and all three are
    /// observable.
    ///
    /// `curl_url_set` **lower-cases** percent triplets that were already in
    /// the input, but only when it is not encoding (`lib/urlapi.c:1922-1932`,
    /// under the comment *"make sure percent encoded are lower case"*), while
    /// the encoder itself emits **upper** case.
    #[test]
    fn percent_triplets_are_lowercased_only_when_not_encoding() {
        let mut u = handle();
        u.set(P::Url, Some(b"https://example.com/"), F::NONE)
            .expect("parse");

        u.set(P::Path, Some(b"/%2F"), F::NONE).expect("path");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/%2f".to_vec()));

        u.set(P::Path, Some(b"/%2E%2e%aB%Cd"), F::NONE)
            .expect("path");
        assert_eq!(
            u.get(P::Path, F::NONE),
            Ok(b"/%2e%2e%ab%cd".to_vec()),
            "a triplet is folded when either hex digit is upper case"
        );

        // Not a triplet, so not folded.
        u.set(P::Path, Some(b"/%ZZ/%2/A%"), F::NONE).expect("path");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/%ZZ/%2/A%".to_vec()));

        // With the encoder on, the '%' itself is escaped instead -- in upper
        // case, from `escape::hexbyte`.
        u.set(P::Path, Some(b"/%2F"), F::URLENCODE).expect("path");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/%252F".to_vec()));

        // The fold walks the prepended slash harmlessly.
        u.set(P::Path, Some(b"%2F"), F::NONE).expect("path");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/%2f".to_vec()));
    }

    /// `CURLU_PATH_AS_IS` keeps dot segments; without it they are removed.
    #[test]
    fn path_as_is_suppresses_dot_segment_removal() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/a/../b/./c"), F::PATH_AS_IS)
            .expect("parse");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/a/../b/./c".to_vec()));

        let mut u = handle();
        u.set(P::Url, Some(b"http://x/a/../b/./c"), F::NONE)
            .expect("parse");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/b/c".to_vec()));

        // A percent-encoded dot counts as a dot -- `is_dot` accepts `%2e` and
        // `%2E` (`lib/urlapi.c:690-694`). This is `unit1395.c`'s
        // `{ "/a/c/%2e%2E/b", "/a/b" }` reached through a whole URL.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/a/c/%2e%2E/b"), F::NONE)
            .expect("parse");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/a/b".to_vec()));

        // The redirect merge clears the flag before re-parsing
        // (`lib/urlapi.c:1277`), so the dots the merge introduces are removed
        // even when the caller asked for them to be kept.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/a/b/c"), F::NONE)
            .expect("parse");
        u.set(P::Url, Some(b"../d"), F::PATH_AS_IS)
            .expect("redirect");
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"http://x/a/d".to_vec()));
    }

    /// `is_dot` in isolation, including the guard that a truncated escape at
    /// the end of the counted extent is not a dot.
    #[test]
    fn is_dot_accepts_both_spellings_and_no_truncation() {
        for (input, consumed) in [
            (&b".rest"[..], Some(&b"rest"[..])),
            (b"%2erest", Some(b"rest")),
            (b"%2Erest", Some(b"rest")),
            (b"%2e", Some(b"")),
            (b"%2", None),
            (b"%", None),
            (b"", None),
            (b"x", None),
            (b"%2f", None),
        ] {
            let mut cursor: &[u8] = input;
            let took = is_dot(&mut cursor);
            match consumed {
                Some(rest) => {
                    assert!(took, "in: {}", show(input));
                    assert_eq!(show(cursor), show(rest), "in: {}", show(input));
                }
                None => {
                    assert!(!took, "in: {}", show(input));
                    assert_eq!(
                        show(cursor),
                        show(input),
                        "a refusal must not advance"
                    );
                }
            }
        }
    }

    /// `urlencode_str` in isolation: the space rule and where it flips.
    ///
    /// `lib/urlapi.c:130-171`. `left` starts as `!query`, so a space before the
    /// first `?` becomes `%20` and one after it becomes `+`; a query part
    /// starts already flipped. And with `relative` false the bytes up to
    /// `find_host_sep` are emitted **untouched**, because *"URL encoding should
    /// be skipped for hostnames, otherwise IDN resolution will fail"*.
    #[test]
    fn urlencode_str_flips_the_space_rule_at_the_question_mark() {
        let render = |input: &[u8], relative: bool, query: bool| -> String {
            let mut out = Buf::new(MAX_INPUT_LENGTH);
            urlencode_str(&mut out, input, relative, query).expect("encode");
            show(out.as_slice())
        };

        assert_eq!(render(b"a b", true, false), "a%20b");
        assert_eq!(render(b"a b", true, true), "a+b");
        assert_eq!(render(b"a b?c d", true, false), "a%20b?c+d");
        assert_eq!(render(b"a b?c d", true, true), "a+b?c+d");

        // Bytes below space and at or above 0x7f become upper-case triplets.
        assert_eq!(render(b"a\x01\x7f\xffb", true, false), "a%01%7F%FFb");

        // Not relative: everything up to the first '/' or '?' after the '//'
        // passes through, spaces and all.
        assert_eq!(render(b"http://a b/c d", false, false), "http://a b/c%20d");
        assert_eq!(render(b"a b/c d", false, false), "a b/c%20d");
    }

    // -----------------------------------------------------------------------
    // The query, and appending to it.
    // -----------------------------------------------------------------------

    /// `CURLU_APPENDQUERY` inserts a separator only when there is something to
    /// separate, and leaves the first `=` alone.
    ///
    /// `lib/urlapi.c:1936-1962`. `equalsencode` starts from `appendquery` and
    /// is cleared on first use at `:1900-1902`, so a second `=` is escaped.
    #[test]
    fn appending_a_query_separates_only_when_needed() {
        let append = |base: &[u8], query: &[u8], flags: UrlFlags| -> String {
            let mut u = handle();
            u.set(P::Url, Some(base), F::NONE).expect("parse");
            u.set(P::Query, Some(query), flags.union(F::APPENDQUERY))
                .expect("append");
            show(&u.get(P::Query, F::GET_EMPTY).expect("query"))
        };

        // Nothing to separate: the value replaces.
        assert_eq!(append(b"http://x/", b"a=b", F::NONE), "a=b");
        // A blank existing query is also nothing to separate.
        assert_eq!(append(b"http://x/?", b"a=b", F::NONE), "a=b");
        // An existing query gets an ampersand.
        assert_eq!(append(b"http://x/?s=1", b"a=b", F::NONE), "s=1&a=b");
        // Unless it already ends with one.
        assert_eq!(append(b"http://x/?s=1&", b"a=b", F::NONE), "s=1&a=b");

        // Only the FIRST '=' is left unescaped when encoding.
        assert_eq!(
            append(b"http://x/?s=1", b"a=b=c", F::URLENCODE),
            "s=1&a=b%3Dc"
        );
        // Without the append flag there is no `equalsencode` at all, so every
        // '=' is escaped.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");
        u.set(P::Query, Some(b"a=b"), F::URLENCODE).expect("query");
        assert_eq!(u.get(P::Query, F::NONE), Ok(b"a%3Db".to_vec()));

        // A space plus-encodes on the query, and decodes back on the get.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");
        u.set(P::Query, Some(b"a b"), F::URLENCODE).expect("query");
        assert_eq!(u.get(P::Query, F::NONE), Ok(b"a+b".to_vec()));
        assert_eq!(u.get(P::Query, F::URLDECODE), Ok(b"a b".to_vec()));
    }

    /// `'+'` becomes `' '` on decode for the query and for nothing else.
    ///
    /// `plusdecode` is set only in `CURLUPART_QUERY`'s arm
    /// (`lib/urlapi.c:1612`), and it is gated on `CURLU_URLDECODE`.
    #[test]
    fn plus_decoding_is_the_querys_alone() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/a+b?c+d#e+f"), F::NONE)
            .expect("parse");
        assert_eq!(u.get(P::Query, F::URLDECODE), Ok(b"c d".to_vec()));
        assert_eq!(u.get(P::Query, F::NONE), Ok(b"c+d".to_vec()));
        assert_eq!(u.get(P::Path, F::URLDECODE), Ok(b"/a+b".to_vec()));
        assert_eq!(u.get(P::Fragment, F::URLDECODE), Ok(b"e+f".to_vec()));
    }

    /// `CURLU_URLDECODE` decodes the decodable parts, rejects control bytes,
    /// and never touches the scheme or the port.
    ///
    /// `flags &= ~CURLU_URLDECODE` at `lib/urlapi.c:1558` and `:1585`, with
    /// the C's own comments *"never for schemes"* and *"never for port"*, and
    /// `docs/libcurl/curl_url_get.md:69-70` says the same. Those two clearings
    /// are **defensive rather than observable**, and this test records why: a
    /// scheme cannot hold a percent sign in the first place -- the grammar
    /// excludes it on the parse path and `set_url_scheme`'s syntax check
    /// excludes it on the set path -- and a port is re-rendered from a number.
    /// So there is nothing for either to decode, and the assertions below pin
    /// that fact rather than a decode that never happens.
    ///
    /// The rejection of control bytes is unconditional and is documented API
    /// behaviour (`lib/urlapi.c:1383-1385`).
    #[test]
    fn url_decoding_skips_the_scheme_and_the_port() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x:8080/%2f"), F::NONE)
            .expect("parse");
        assert_eq!(u.get(P::Scheme, F::URLDECODE), Ok(b"http".to_vec()));
        assert_eq!(u.get(P::Port, F::URLDECODE), Ok(b"8080".to_vec()));
        assert_eq!(u.get(P::Path, F::URLDECODE), Ok(b"//".to_vec()));
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/%2f".to_vec()));

        // A scheme cannot carry a triplet, on either path.
        assert_eq!(
            u.set(P::Scheme, Some(b"ht%74p"), F::NON_SUPPORT_SCHEME),
            Err(E::BadScheme)
        );
        let mut fresh = handle();
        assert_eq!(
            fresh.set(P::Url, Some(b"ht%74p://x/"), F::NON_SUPPORT_SCHEME),
            Err(E::BadScheme)
        );

        // Every other part decodes, and a control byte is refused.
        let mut u = handle();
        u.set(P::Url, Some(b"http://%75ser:%70ass@x/%01?%01#%01"), F::NONE)
            .expect("parse");
        assert_eq!(u.get(P::User, F::URLDECODE), Ok(b"user".to_vec()));
        assert_eq!(u.get(P::Password, F::URLDECODE), Ok(b"pass".to_vec()));
        assert_eq!(u.get(P::Path, F::URLDECODE), Err(E::Urldecode));
        assert_eq!(u.get(P::Query, F::URLDECODE), Err(E::Urldecode));
        assert_eq!(u.get(P::Fragment, F::URLDECODE), Err(E::Urldecode));
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/%01".to_vec()));
    }

    // -----------------------------------------------------------------------
    // Hosts: names, addresses and zone identifiers.
    // -----------------------------------------------------------------------

    /// Every byte of the reject set makes a bare host name invalid.
    ///
    /// The `strcspn` at `lib/urlapi.c:456`, all 31 bytes of it. A bracketed
    /// host goes to `ipv6_parse` instead and never reaches the set, which is
    /// why `[`, `]` and `:` can be in it.
    ///
    /// **Eight of the 31 cannot be tested in their raw form**, and that is not
    /// a gap in the check -- it is what the check is for. ` `, `\r`, `\n` and
    /// `\t` never survive [`junkscan`]; `/`, `:`, `#`, `?` and `@` are
    /// structural and are consumed as the path, port, fragment, query and
    /// userinfo separators before any host exists. Percent-encoded, all 31
    /// arrive at the check by way of `urldecode_host`, which is exactly how
    /// `lib1560.c:1030-1033` tests `%40`, `%21`, `%3f` and `%23`.
    #[test]
    fn every_byte_of_the_reject_set_invalidates_a_host() {
        const REJECT: &[u8] = b" \r\n\t/:#?!@{}[]\\$'\"^`*<>=;,+&()%";
        assert_eq!(REJECT.len(), 31, "the strcspn set has 31 bytes");

        // Percent-encoded: every one of the 31.
        for byte in REJECT {
            let digits = escape::hexbyte(*byte);
            let mut url = b"https://exam%".to_vec();
            url.push(digits[0]);
            url.push(digits[1]);
            url.extend_from_slice(b"ple.net");
            let mut u = handle();
            assert_eq!(
                u.set(P::Url, Some(&url), F::NONE),
                Err(E::BadHostname),
                "in: {}",
                show(&url)
            );
        }

        // Raw: the 23 that are neither control bytes nor separators. A space
        // needs the junk scan waived to get that far.
        const STRUCTURAL: &[u8] = b"\r\n\t/:#?@";
        let mut raw = 0usize;
        for byte in REJECT {
            if STRUCTURAL.contains(byte) {
                continue;
            }
            raw += 1;
            let mut url = b"https://exam".to_vec();
            url.push(*byte);
            url.extend_from_slice(b"ple.net");
            let mut u = handle();
            assert_eq!(
                u.set(P::Url, Some(&url), F::ALLOW_SPACE),
                Err(E::BadHostname),
                "in: {}",
                show(&url)
            );
            // And without the waiver a space is refused earlier still.
            if *byte == b' ' {
                let mut u = handle();
                assert_eq!(
                    u.set(P::Url, Some(&url), F::NONE),
                    Err(E::MalformedInput)
                );
            }
        }
        assert_eq!(raw, 23, "23 of the 31 are reachable raw");

        // A host with none of them is fine.
        let mut u = handle();
        u.set(P::Url, Some(b"https://exam-ple_net.9~"), F::NONE)
            .expect("parse");
        assert_eq!(u.get(P::Host, F::NONE), Ok(b"exam-ple_net.9~".to_vec()));
    }

    /// The permissive IPv4 parser, which must not be `inet_pton`.
    ///
    /// `ipv4_normalize` (`lib/urlapi.c:483-574`) accepts one to four parts in
    /// decimal, `0x` hexadecimal or leading-zero octal.
    /// [`crate::util::inet::pton4`] is the transcription of curl's strict
    /// `inet_pton` and would refuse every row below but the first, so
    /// delegating to it would have been wrong.
    #[test]
    fn the_ipv4_parser_is_permissive_where_inet_pton_is_strict() {
        for (input, wanted) in [
            (&b"http://1.2.3.4/"[..], &b"1.2.3.4"[..]),
            (b"http://0x7f000001/", b"127.0.0.1"),
            (b"http://017700000001/", b"127.0.0.1"),
            (b"http://2130706433/", b"127.0.0.1"),
            (b"http://127.1/", b"127.0.0.1"),
            (b"http://127.0.1/", b"127.0.0.1"),
            (b"http://0x7f.1/", b"127.0.0.1"),
            (b"http://07.1/", b"7.0.0.1"),
            (b"http://0xffffffff/", b"255.255.255.255"),
            // Beyond four parts, or a part out of range, or a bad digit: not
            // an error, just a name. `HOST_NAME` is the fall-through.
            (b"http://1.2.3.4.5/", b"1.2.3.4.5"),
            (b"http://018.0.0.0/", b"018.0.0.0"),
            (b"http://0xg/", b"0xg"),
            (b"http://0x/", b"0x"),
            (b"http://1.2.3.256.com/", b"1.2.3.256.com"),
            (b"http://4294967296/", b"4294967296"),
        ] {
            let mut u = handle();
            u.set(P::Url, Some(input), F::NONE).unwrap_or_else(|code| {
                panic!("in: {}\nreturned {code:?}", show(input))
            });
            assert_eq!(
                u.get(P::Host, F::NONE).map(|got| show(&got)),
                Ok(show(wanted)),
                "in: {}",
                show(input)
            );
        }
    }

    /// IPv6 literals normalise, and their zone identifiers are text.
    ///
    /// `ipv6_parse` (`lib/urlapi.c:390-441`). The identifier is at most fifteen
    /// bytes, an optional `25` prefix -- the percent sign, percent-encoded --
    /// is skipped, and the address itself round-trips through
    /// [`crate::util::inet`] rather than `std::net`, which is what keeps
    /// curl's own rendering rules.
    #[test]
    fn ipv6_literals_normalise_and_carry_a_text_zone_identifier() {
        for (input, host, zone) in [
            (&b"http://[::1]/"[..], &b"[::1]"[..], None),
            (b"http://[0:0:0:0:0:0:0:1]/", b"[::1]", None),
            (
                b"http://[fe80::1%25eth0]/",
                b"[fe80::1]",
                Some(&b"eth0"[..]),
            ),
            (b"http://[fe80::1%eth0]/", b"[fe80::1]", Some(b"eth0")),
            // Fifteen bytes is the limit.
            (
                b"http://[fe80::1%25abcdefghijklmno]/",
                b"[fe80::1]",
                Some(b"abcdefghijklmno"),
            ),
            // `%25]` leaves the "25" as the identifier, because the prefix is
            // only skipped when a byte other than ']' follows it.
            (b"http://[fe80::1%25]/", b"[fe80::1]", Some(b"25")),
        ] {
            let mut u = handle();
            u.set(P::Url, Some(input), F::NONE).unwrap_or_else(|code| {
                panic!("in: {}\nreturned {code:?}", show(input))
            });
            assert_eq!(
                u.get(P::Host, F::NONE).map(|got| show(&got)),
                Ok(show(host)),
                "in: {}",
                show(input)
            );
            match zone {
                Some(zone) => assert_eq!(
                    u.get(P::ZoneId, F::NONE).map(|got| show(&got)),
                    Ok(show(zone)),
                    "in: {}",
                    show(input)
                ),
                None => assert_eq!(
                    u.get(P::ZoneId, F::NONE),
                    Err(E::NoZoneid),
                    "in: {}",
                    show(input)
                ),
            }
        }

        // Sixteen bytes is not.
        let mut u = handle();
        assert_eq!(
            u.set(
                P::Url,
                Some(b"http://[fe80::1%25abcdefghijklmnop]/"),
                F::NONE
            ),
            Err(E::BadIpv6)
        );

        // An empty identifier, an unterminated literal and a bad address are
        // all refused.
        for input in [
            &b"http://[fe80::1%25]x/"[..],
            b"http://[fe80::1%]/",
            b"http://[::1/",
            b"http://[:::1]/",
            b"http://[]/",
        ] {
            let mut u = handle();
            assert!(
                u.set(P::Url, Some(input), F::NONE).is_err(),
                "in: {}",
                show(input)
            );
        }

        // The whole URL re-attaches the identifier with the encoded percent.
        let mut u = handle();
        u.set(P::Url, Some(b"http://[fe80::1%25eth0]/p"), F::NONE)
            .expect("parse");
        assert_eq!(
            u.get(P::Url, F::NONE).map(|got| show(&got)),
            Ok(show(b"http://[fe80::1%25eth0]/p"))
        );
    }

    /// The zone identifier is stored **before** the address is validated, so
    /// it survives a failure.
    ///
    /// Measured against a real libcurl: `curl_url_set(u, CURLUPART_HOST,
    /// "[:::%25eth0]", 0)` answers `CURLUE_BAD_HOSTNAME` and leaves `eth0` on
    /// the handle. Reproducing the ordering is the whole of it.
    #[test]
    fn a_zone_identifier_survives_a_failed_address() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://example.com/"), F::NONE)
            .expect("parse");
        assert_eq!(
            u.set(P::Host, Some(b"[:::%25eth0]"), F::NONE),
            Err(E::BadHostname),
            "every failure on the host set path becomes BAD_HOSTNAME"
        );
        assert_eq!(u.get(P::ZoneId, F::NONE), Ok(b"eth0".to_vec()));
    }

    /// A host set to null clears the host and **keeps** the zone identifier.
    ///
    /// `urlset_clear`'s `CURLUPART_HOST` arm is two lines and neither mentions
    /// it (`lib/urlapi.c:1752-1754`); only the non-null set path clears it, at
    /// `:1848`. Measured against a real libcurl. The agent brief for this file
    /// asserts the opposite, and the code is the contract (AAP section 0.8.1).
    #[test]
    fn clearing_a_host_does_not_clear_its_zone_identifier() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://[fe80::1%25eth0]/"), F::NONE)
            .expect("parse");
        assert_eq!(u.get(P::ZoneId, F::NONE), Ok(b"eth0".to_vec()));

        u.set(P::Host, None, F::NONE).expect("clear host");
        assert_eq!(u.get(P::Host, F::NONE), Err(E::NoHost));
        assert_eq!(
            u.get(P::ZoneId, F::NONE),
            Ok(b"eth0".to_vec()),
            "clearing the host leaves the identifier behind"
        );

        // Setting a host does clear it.
        u.set(P::Host, Some(b"example.com"), F::NONE).expect("host");
        assert_eq!(u.get(P::ZoneId, F::NONE), Err(E::NoZoneid));
    }

    /// A host may be blank only with `CURLU_NO_AUTHORITY`.
    #[test]
    fn a_blank_host_needs_the_no_authority_flag() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");
        assert_eq!(u.set(P::Host, Some(b""), F::NONE), Err(E::BadHostname));
        assert_eq!(u.set(P::Host, Some(b""), F::NO_AUTHORITY), Ok(()));
        assert_eq!(u.get(P::Host, F::GET_EMPTY), Ok(Vec::new()));
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"http:///".to_vec()));

        // And on the parse path.
        let mut u = handle();
        assert_eq!(u.set(P::Url, Some(b"http://"), F::NONE), Err(E::NoHost));
        let mut u = handle();
        assert_eq!(u.set(P::Url, Some(b"http://"), F::NO_AUTHORITY), Ok(()));
    }

    /// A host set without the encoder arrives already encoded, so it is
    /// decoded before checking -- and the decoded copy is then thrown away.
    ///
    /// `lib/urlapi.c:1969-1979`, whose comment says exactly that. The
    /// consequence is visible: a `%` that decodes to a rejected byte fails,
    /// while a `%` that decodes to an ordinary one is stored **encoded**.
    #[test]
    fn a_host_is_validated_decoded_and_stored_as_given() {
        let mut u = handle();
        u.set(P::Url, Some(b"https://example.com/"), F::NONE)
            .expect("parse");

        // %43 is 'C': accepted, and stored as the triplet.
        u.set(P::Host, Some(b"%43url.se"), F::NONE).expect("host");
        assert_eq!(u.get(P::Host, F::NONE), Ok(b"%43url.se".to_vec()));
        assert_eq!(u.get(P::Host, F::URLDECODE), Ok(b"Curl.se".to_vec()));

        // %25 is '%', which the reject set refuses.
        assert_eq!(
            u.set(P::Host, Some(b"%25url.se"), F::NONE),
            Err(E::BadHostname)
        );
        // %01 is a control byte, which the decode itself refuses.
        assert_eq!(
            u.set(P::Host, Some(b"%01url.se"), F::NONE),
            Err(E::BadHostname)
        );

        // With the encoder on, a bracketed literal is escaped into something
        // the reject set then refuses -- which is what
        // `docs/libcurl/curl_url_set.md:129-130` warns about.
        assert_eq!(
            u.set(P::Host, Some(b"[::1]"), F::URLENCODE),
            Err(E::BadHostname)
        );
        assert_eq!(u.set(P::Host, Some(b"[::1]"), F::NONE), Ok(()));
    }

    // -----------------------------------------------------------------------
    // Ports.
    // -----------------------------------------------------------------------

    /// Ports are re-rendered from the number, so leading zeroes vanish, and
    /// the whole string must be consumed.
    ///
    /// `set_url_port` (`lib/urlapi.c:1666-1682`) and `Curl_parse_port`
    /// (`:335-388`). `docs/libcurl/curl_url_get.md:190-192` promises the
    /// result *"is guaranteed to hold a valid port number in ASCII using base
    /// 10"*.
    #[test]
    fn ports_are_canonical_and_bounded() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");

        for (input, wanted) in [
            (&b"80"[..], Ok(&b"80"[..])),
            (b"080", Ok(b"80")),
            (b"0000080", Ok(b"80")),
            (b"0", Ok(b"0")),
            (b"65535", Ok(b"65535")),
            (b"65536", Err(E::BadPortNumber)),
            (b"", Err(E::BadPortNumber)),
            (b"-1", Err(E::BadPortNumber)),
            (b"+1", Err(E::BadPortNumber)),
            (b" 1", Err(E::BadPortNumber)),
            (b"1 ", Err(E::BadPortNumber)),
            (b"12a", Err(E::BadPortNumber)),
            (b"1.2", Err(E::BadPortNumber)),
        ] {
            let rc = u.set(P::Port, Some(input), F::NONE);
            match wanted {
                Ok(text) => {
                    rc.unwrap_or_else(|code| {
                        panic!("in: {}\nreturned {code:?}", show(input))
                    });
                    assert_eq!(
                        u.get(P::Port, F::NONE).map(|got| show(&got)),
                        Ok(show(text)),
                        "in: {}",
                        show(input)
                    );
                }
                Err(code) => assert_eq!(rc, Err(code), "in: {}", show(input)),
            }
        }

        // Inside a URL, leading zeroes are stripped the same way.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x:080/p"), F::NONE)
            .expect("parse");
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"http://x:80/p".to_vec()));

        // A trailing colon with no digits is browser behaviour -- but only
        // when the input carried a scheme (`lib/urlapi.c:352-366`).
        let mut u = handle();
        u.set(P::Url, Some(b"http://x:/p"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Port, F::NONE), Err(E::NoPort));
        assert_eq!(u.get(P::Port, F::DEFAULT_PORT), Ok(b"80".to_vec()));
        //
        // The C spells out why it declines to adapt without one: *"Do not do
        // it if the URL has no scheme, to make something that looks like a
        // scheme not work!"* (`lib/urlapi.c:363-366`). Note that `x:/p` is not
        // the case to test -- with `CURLU_GUESS_SCHEME`,
        // `Curl_is_absolute_url` accepts `x:` **because a slash follows it**,
        // so that input has a scheme and reports `UNSUPPORTED_SCHEME`.
        let mut u = handle();
        assert_eq!(
            u.set(P::Url, Some(b"x:"), F::GUESS_SCHEME),
            Err(E::BadPortNumber),
            "without a scheme the colon must carry digits"
        );
        let mut u = handle();
        assert_eq!(
            u.set(P::Url, Some(b"x:/p"), F::GUESS_SCHEME),
            Err(E::UnsupportedScheme),
            "a slash after the colon makes `x` a scheme instead"
        );
    }

    /// `CURLU_DEFAULT_PORT` supplies a missing port and
    /// `CURLU_NO_DEFAULT_PORT` suppresses a redundant one -- both only when
    /// the scheme is in the registry.
    ///
    /// `lib/urlapi.c:1586-1604` on the part and `:1461-1475` on the whole URL.
    #[test]
    fn the_default_port_is_supplied_and_suppressed_by_flag() {
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/p"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Port, F::NONE), Err(E::NoPort));
        assert_eq!(u.get(P::Port, F::DEFAULT_PORT), Ok(b"80".to_vec()));
        assert_eq!(
            u.get(P::Url, F::DEFAULT_PORT),
            Ok(b"http://x:80/p".to_vec())
        );

        u.set(P::Port, Some(b"80"), F::NONE).expect("port");
        assert_eq!(u.get(P::Port, F::NONE), Ok(b"80".to_vec()));
        assert_eq!(u.get(P::Port, F::NO_DEFAULT_PORT), Err(E::NoPort));
        assert_eq!(
            u.get(P::Url, F::NO_DEFAULT_PORT),
            Ok(b"http://x/p".to_vec())
        );

        // A port that is not the default is never suppressed.
        u.set(P::Port, Some(b"8080"), F::NONE).expect("port");
        assert_eq!(u.get(P::Port, F::NO_DEFAULT_PORT), Ok(b"8080".to_vec()));
        assert_eq!(
            u.get(P::Url, F::NO_DEFAULT_PORT),
            Ok(b"http://x:8080/p".to_vec())
        );

        // Per scheme, from the registry rather than a table in this file.
        let mut u = handle();
        u.set(P::Url, Some(b"https://x/"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Port, F::DEFAULT_PORT), Ok(b"443".to_vec()));
        let mut u = handle();
        u.set(P::Url, Some(b"ftp://x/"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Port, F::DEFAULT_PORT), Ok(b"21".to_vec()));
        let mut u = handle();
        u.set(P::Url, Some(b"sftp://x/"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Port, F::DEFAULT_PORT), Ok(b"22".to_vec()));

        // An unknown scheme has no default, and the flag is inert -- the
        // lookup returning nothing is the `if(h)` that never fires.
        let mut u = handle();
        u.set(P::Url, Some(b"custom://x/"), F::NON_SUPPORT_SCHEME)
            .expect("parse");
        assert_eq!(u.get(P::Port, F::DEFAULT_PORT), Err(E::NoPort));
        assert_eq!(u.get(P::Url, F::DEFAULT_PORT), Ok(b"custom://x/".to_vec()));
    }

    // -----------------------------------------------------------------------
    // Duplication, and the field it does not copy.
    // -----------------------------------------------------------------------

    /// `curl_url_dup` does **not** copy the guessed-scheme bit.
    ///
    /// `lib/urlapi.c:1310-1332` duplicates the ten strings and then copies
    /// `portnum`, `fragment_present` and `query_present`, and stops. The
    /// omission is observable through `CURLU_NO_GUESS_SCHEME`, which is what
    /// this test is: the original withholds its scheme and the duplicate does
    /// not.
    ///
    /// This is the guard on the quirk. Deriving `Clone` would silently "fix" a
    /// difference the corpus can see, and AAP section 0.8.2's minimal-change
    /// mandate forbids exactly that.
    #[test]
    fn a_duplicate_forgets_that_its_scheme_was_guessed() {
        let mut original = handle();
        original
            .set(P::Url, Some(b"example.com/path"), F::GUESS_SCHEME)
            .expect("guess");
        let copy = original.dup();

        // Everything the C copies is copied.
        assert_eq!(
            copy.get(P::Url, F::NONE),
            Ok(b"http://example.com/path".to_vec())
        );

        // And the one field it does not is not.
        assert_eq!(
            original.get(P::Scheme, F::NO_GUESS_SCHEME),
            Err(E::NoScheme)
        );
        assert_eq!(
            copy.get(P::Scheme, F::NO_GUESS_SCHEME),
            Ok(b"http".to_vec()),
            "the duplicate must NOT remember the guess"
        );
        assert_eq!(
            original.get(P::Url, F::NO_GUESS_SCHEME),
            Ok(b"example.com/path".to_vec())
        );
        assert_eq!(
            copy.get(P::Url, F::NO_GUESS_SCHEME),
            Ok(b"http://example.com/path".to_vec())
        );
    }

    /// A duplicate carries the two present bits and the numeric port, which
    /// the C does copy.
    #[test]
    fn a_duplicate_carries_the_present_bits_and_the_port_number() {
        let mut original = handle();
        original
            .set(P::Url, Some(b"http://x:80/p?#"), F::NONE)
            .expect("parse");
        let copy = original.dup();
        assert_eq!(
            copy.get(P::Url, F::GET_EMPTY),
            Ok(b"http://x:80/p?#".to_vec())
        );
        assert_eq!(copy.get(P::Query, F::GET_EMPTY), Ok(Vec::new()));
        assert_eq!(copy.get(P::Fragment, F::GET_EMPTY), Ok(Vec::new()));
        // The numeric port is what `CURLU_NO_DEFAULT_PORT` compares against,
        // so a duplicate that lost it would stop suppressing.
        assert_eq!(
            copy.get(P::Url, F::NO_DEFAULT_PORT),
            Ok(b"http://x/p".to_vec())
        );
        // And the registry came across, so the duplicate is still usable.
        let mut copy = copy;
        copy.set(P::Scheme, Some(b"https"), F::NONE)
            .expect("scheme");
        assert_eq!(copy.get(P::Url, F::NONE), Ok(b"https://x:80/p".to_vec()));
    }

    // -----------------------------------------------------------------------
    // `file:` URLs.
    // -----------------------------------------------------------------------

    /// `file:` accepts a blank, `localhost` or `127.0.0.1` authority and
    /// nothing else, and it renders with no host, port or userinfo at all.
    ///
    /// `parse_file` (`lib/urlapi.c:823-931`) and the short-circuit at
    /// `:1440-1447`. Only the non-Windows arm exists here: AAP section 0.2.2
    /// excludes Windows, so a drive letter is refused rather than accepted.
    #[test]
    fn file_urls_take_only_a_local_authority() {
        for (input, wanted) in [
            (&b"file:///tmp/x"[..], Ok(&b"file:///tmp/x"[..])),
            (b"file://localhost/tmp/x", Ok(b"file:///tmp/x")),
            (b"file://LocalHost/tmp/x", Ok(b"file:///tmp/x")),
            (b"file://127.0.0.1/tmp/x", Ok(b"file:///tmp/x")),
            (b"file:/tmp/x", Ok(b"file:///tmp/x")),
            (b"file://host.example.com/x", Err(E::BadFileUrl)),
            // Not enough to be a URL at all.
            (b"file:/", Err(E::BadFileUrl)),
            (b"file:", Err(E::BadFileUrl)),
            // Drive letters are Windows-only, and this is not Windows.
            (b"file:/c:", Err(E::BadFileUrl)),
            (b"file:///c:/x", Err(E::BadFileUrl)),
            (b"file://c|/x", Err(E::BadFileUrl)),
        ] {
            let mut u = handle();
            let rc = u.set(P::Url, Some(input), F::NONE);
            match wanted {
                Ok(text) => {
                    rc.unwrap_or_else(|code| {
                        panic!("in: {}\nreturned {code:?}", show(input))
                    });
                    assert_eq!(
                        u.get(P::Url, F::NONE).map(|got| show(&got)),
                        Ok(show(text)),
                        "in: {}",
                        show(input)
                    );
                    assert_eq!(
                        u.get(P::Host, F::NONE),
                        Err(E::NoHost),
                        "in: {}\na file URL keeps no host",
                        show(input)
                    );
                }
                Err(code) => assert_eq!(rc, Err(code), "in: {}", show(input)),
            }
        }

        // The short-circuit ignores the userinfo and the port entirely, which
        // is `set_parts_list`'s `scheme=file,host=127.0.0.1,path=/no,
        // user=anonymous` row restated.
        let mut u = handle();
        u.set(P::Url, Some(b"file:///no"), F::NONE).expect("parse");
        u.set(P::User, Some(b"anonymous"), F::NONE).expect("user");
        u.set(P::Port, Some(b"8080"), F::NONE).expect("port");
        u.set(P::Host, Some(b"127.0.0.1"), F::NONE).expect("host");
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"file:///no".to_vec()));
    }

    /// A `file:` URL with no path renders the literal text `(nil)`.
    ///
    /// The short-circuit at `lib/urlapi.c:1442` hands `u->path` to `%s`
    /// without a null guard, and curl's own `printf` prints `(nil)` for a null
    /// pointer (`lib/mprintf.c:837`). `file:///` reaches it, because
    /// `handle_path` leaves a one-byte path unset.
    ///
    /// Measured against a real libcurl. Reproducing a defect is the point of
    /// AAP section 0.8.1: a caller that has learned to expect `file://(nil)`
    /// must keep getting it.
    #[test]
    fn a_file_url_with_no_path_renders_the_null_marker() {
        let mut u = handle();
        u.set(P::Url, Some(b"file:///"), F::NONE).expect("parse");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/".to_vec()));
        assert_eq!(
            u.get(P::Url, F::NONE).map(|got| show(&got)),
            Ok(show(b"file://(nil)")),
            "the C's unguarded %s of a null path"
        );

        // Clearing the path of any file URL reaches the same place.
        let mut u = handle();
        u.set(P::Url, Some(b"file:///tmp/x"), F::NONE)
            .expect("parse");
        u.set(P::Path, None, F::NONE).expect("clear");
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"file://(nil)".to_vec()));

        // Any other scheme substitutes a slash instead, at `:1527`.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/tmp"), F::NONE)
            .expect("parse");
        u.set(P::Path, None, F::NONE).expect("clear");
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"http://x/".to_vec()));
    }

    // -----------------------------------------------------------------------
    // Input hygiene.
    // -----------------------------------------------------------------------

    /// [`junkscan`] rejects control bytes, `0x7f`, and space unless waived.
    ///
    /// `Curl_junkscan` (`lib/urlapi.c:223-238`). Two details are reproduced
    /// exactly: the length test runs **before** the byte scan, and the
    /// threshold is `allowspace ? 0x1f : 0x20`, which is why the comparison is
    /// `<=` and why a waived space is admitted while `0x1f` never is.
    #[test]
    fn the_junk_scan_rejects_control_bytes_and_optionally_space() {
        for byte in 0u8..=0x20 {
            let url = [b'a', byte, b'b'];
            let strict = junkscan(&url, false);
            let lenient = junkscan(&url, true);
            assert_eq!(
                strict,
                Err(E::MalformedInput),
                "{} must be refused without the waiver",
                show(&[byte])
            );
            if byte == 0x20 {
                assert_eq!(lenient, Ok(3), "a waived space is admitted");
            } else {
                assert_eq!(
                    lenient,
                    Err(E::MalformedInput),
                    "{} is refused even with the waiver",
                    show(&[byte])
                );
            }
        }
        assert_eq!(junkscan(b"a\x7fb", true), Err(E::MalformedInput));
        assert_eq!(junkscan(b"a\x80b", false), Ok(3), "0x80 is fine");
        assert_eq!(junkscan(b"a!b", false), Ok(3));
        assert_eq!(junkscan(b"", false), Ok(0));

        // End to end.
        for input in [&b"http://x/\x01"[..], b"http://x/\x7f", b"http://x /"] {
            let mut u = handle();
            assert_eq!(
                u.set(P::Url, Some(input), F::NONE),
                Err(E::MalformedInput),
                "in: {}",
                show(input)
            );
        }
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/a b"), F::ALLOW_SPACE)
            .expect("waived");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/a b".to_vec()));
        assert_eq!(
            u.get(P::Path, F::URLENCODE),
            Ok(b"/a%20b".to_vec()),
            "and the encoder turns it into a triplet"
        );
    }

    /// Eight million bytes is the ceiling on every input, and the length test
    /// comes first.
    ///
    /// `CURL_MAX_INPUT_LENGTH` (`lib/urldata.h:131`), checked at
    /// `lib/urlapi.c:229` on the way in and at `:1824` on every part.
    /// `docs/libcurl/curl_url_set.md:277-278` promises
    /// `CURLUE_MALFORMED_INPUT` for anything longer.
    #[cfg_attr(
        miri,
        ignore = "an eight-megabyte buffer is impractical to interpret"
    )]
    #[test]
    fn eight_million_bytes_is_the_input_ceiling() {
        // Exactly at the limit the byte scan runs and finds nothing wrong.
        let at_limit = vec![b'a'; MAX_INPUT_LENGTH];
        assert_eq!(junkscan(&at_limit, false), Ok(MAX_INPUT_LENGTH));

        // One byte over, and the scan is never reached -- which is why a
        // buffer of control bytes would report the same code.
        let over = vec![b'a'; MAX_INPUT_LENGTH + 1];
        assert_eq!(junkscan(&over, false), Err(E::MalformedInput));

        let mut u = handle();
        assert_eq!(u.set(P::Url, Some(&over), F::NONE), Err(E::MalformedInput));
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");
        for part in [P::Path, P::Query, P::Fragment, P::Host, P::User] {
            assert_eq!(
                u.set(part, Some(&over), F::NONE),
                Err(E::MalformedInput),
                "{part:?}"
            );
        }
    }

    /// An input under the ceiling whose encoded form exceeds it reports
    /// [`CURLUcode::TooLarge`], not `MalformedInput` -- which is the whole
    /// reason `cc2cu` exists.
    ///
    /// `cc2cu` (`lib/urlapi.c:120-122`) is the bridge from the `CURLcode` a
    /// buffer append fails with to a `CURLUcode`, and it distinguishes the
    /// ceiling from a refused allocation. Reaching it needs an input that
    /// passes `Curl_junkscan`'s direct length test at `:229` and only then
    /// overflows a `dynbuf` whose `toobig` is the same constant: a byte at or
    /// above `0x7f` survives the scan (`:235` rejects `<= 0x20` and `0x7f`
    /// only) and then triples to `%XX` in `urlencode_str` at `:157-161`.
    ///
    /// Three million such bytes are 3 MB on the way in and 9 MB encoded, so
    /// the query append at `:1044` is the site that trips, and its
    /// `return cc2cu(result)` at `:170` is the line under test.
    #[cfg_attr(
        miri,
        ignore = "a nine-megabyte buffer is impractical to interpret"
    )]
    #[test]
    fn an_encoding_that_outgrows_the_ceiling_is_too_large_not_malformed() {
        let mut url = b"http://x/?".to_vec();
        url.extend(std::iter::repeat(0xff).take(3_000_000));
        // Well under the input ceiling, so the length test at `:229` passes.
        assert!(url.len() < MAX_INPUT_LENGTH);
        // And every byte survives the scan that follows it.
        assert_eq!(junkscan(&url, false), Ok(url.len()));

        // Encoded, each 0xff becomes `%FF`, so the query alone is 9 MB.
        let mut u = handle();
        assert_eq!(u.set(P::Url, Some(&url), F::URLENCODE), Err(E::TooLarge));

        // Without the encode there is nothing to expand, so the same input is
        // stored intact -- the ceiling is the encoder's, not the input's.
        let mut plain = handle();
        plain.set(P::Url, Some(&url), F::NONE).expect("stored raw");
    }

    // -----------------------------------------------------------------------
    // Userinfo, options and the assembly order.
    // -----------------------------------------------------------------------

    /// `CURLU_DISALLOW_USER` refuses a URL that carries any userinfo -- even a
    /// blank user.
    ///
    /// `parse_hostname_login` (`lib/urlapi.c:270-280`). The blank case works
    /// because `Curl_parse_login_details` allocates its user buffer even for a
    /// zero-length name, so the pointer is never null and the test fires.
    #[test]
    fn disallow_user_refuses_any_userinfo() {
        for input in [
            &b"https://user:pass@example.net/"[..],
            b"https://user@example.net/",
            b"https://:pass@example.net/",
            b"https://@example.net/",
        ] {
            let mut u = handle();
            assert_eq!(
                u.set(P::Url, Some(input), F::DISALLOW_USER),
                Err(E::UserNotAllowed),
                "in: {}",
                show(input)
            );
            let mut u = handle();
            assert_eq!(
                u.set(P::Url, Some(input), F::NONE),
                Ok(()),
                "in: {}\nand it is fine without the flag",
                show(input)
            );
        }
        // No userinfo, no objection.
        let mut u = handle();
        assert_eq!(
            u.set(P::Url, Some(b"https://example.net/"), F::DISALLOW_USER),
            Ok(())
        );
    }

    /// The `;options` tail is parsed only for a scheme that asks for it, and
    /// **kept** on rendering when the scheme is unknown.
    ///
    /// `PROTOPT_URLOPTIONS` (`lib/urldata.h:545`) is read at
    /// `lib/urlapi.c:290` when extracting and at `:1477` when rendering, and
    /// the rendering test is `if(h && !(h->flags & PROTOPT_URLOPTIONS))` -- so
    /// a null `h` skips it and the options survive.
    /// `docs/libcurl/curl_url_get.md:170-173` describes that as the URL API
    /// allowing the field *"independently of scheme when not parsing full
    /// URLs"*.
    #[test]
    fn options_are_parsed_by_scheme_and_kept_for_an_unknown_one() {
        // imap asks for them, so the tail is split out.
        let mut u = handle();
        u.set(
            P::Url,
            Some(b"imap://user:pass;option@server/path"),
            F::NONE,
        )
        .expect("parse");
        assert_eq!(u.get(P::User, F::NONE), Ok(b"user".to_vec()));
        assert_eq!(u.get(P::Password, F::NONE), Ok(b"pass".to_vec()));
        assert_eq!(u.get(P::Options, F::NONE), Ok(b"option".to_vec()));
        assert_eq!(
            u.get(P::Url, F::NONE),
            Ok(b"imap://user:pass;option@server/path".to_vec())
        );

        // http does not, so the semicolon stays in the password.
        let mut u = handle();
        u.set(
            P::Url,
            Some(b"http://user:pass;option@server/path"),
            F::NONE,
        )
        .expect("parse");
        assert_eq!(u.get(P::Password, F::NONE), Ok(b"pass;option".to_vec()));
        assert_eq!(u.get(P::Options, F::NONE), Err(E::NoOptions));

        // Options set by hand on an http handle are readable but dropped from
        // the rendering.
        let mut u = handle();
        u.set(P::Url, Some(b"http://server/"), F::NONE)
            .expect("parse");
        u.set(P::Options, Some(b"opt"), F::NONE).expect("options");
        assert_eq!(u.get(P::Options, F::NONE), Ok(b"opt".to_vec()));
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"http://server/".to_vec()));

        // With an unknown scheme there is no `h` to consult, so they are kept.
        // Measured against a real libcurl.
        let mut u = handle();
        u.set(P::Url, Some(b"custom://server/"), F::NON_SUPPORT_SCHEME)
            .expect("parse");
        u.set(P::Options, Some(b"opt"), F::NONE).expect("options");
        assert_eq!(
            u.get(P::Url, F::NONE),
            Ok(b"custom://;opt@server/".to_vec())
        );
    }

    /// The fifteen-part assembly order, and which parts contribute a
    /// separator.
    ///
    /// `lib/urlapi.c:1517-1532`. Only the **password** contributes the `:`, so
    /// a user without one renders `user@host`; only the options contribute the
    /// `;`; and the `@` appears when any of the three is present.
    #[test]
    fn the_assembly_order_is_the_wire_contract() {
        let render = |commands: &[(UrlPart, &[u8])]| -> String {
            let mut u = handle();
            u.set(P::Url, Some(b"imap://host/p"), F::NONE)
                .expect("parse");
            for (part, value) in commands {
                u.set(*part, Some(value), F::NONE).unwrap_or_else(|code| {
                    panic!("{part:?} returned {code:?}")
                });
            }
            show(&u.get(P::Url, F::NONE).expect("url"))
        };

        assert_eq!(render(&[]), "imap://host/p");
        assert_eq!(render(&[(P::User, b"u")]), "imap://u@host/p");
        assert_eq!(
            render(&[(P::Password, b"w")]),
            "imap://:w@host/p",
            "a password alone still brings its colon"
        );
        assert_eq!(
            render(&[(P::User, b"u"), (P::Password, b"w")]),
            "imap://u:w@host/p"
        );
        assert_eq!(render(&[(P::Options, b"o")]), "imap://;o@host/p");
        assert_eq!(
            render(&[
                (P::User, b"u"),
                (P::Password, b"w"),
                (P::Options, b"o"),
                (P::Port, b"143"),
                (P::Query, b"q"),
                (P::Fragment, b"f"),
            ]),
            "imap://u:w;o@host:143/p?q#f",
            "every part, in order"
        );
    }

    // -----------------------------------------------------------------------
    // Internationalised host names.
    // -----------------------------------------------------------------------

    /// `CURLU_URLENCODE` wins over `CURLU_PUNYCODE` and `CURLU_PUNY2IDN`,
    /// because it is the first arm of an else-if chain.
    ///
    /// `lib/urlapi.c:1393-1420` on a part and `:1491-1509` on the whole URL.
    /// Both punycode gates additionally test `u->host` rather than the part
    /// being converted, and both are computed with `what == CURLUPART_HOST`, so
    /// neither ever applies to anything else.
    #[test]
    fn url_encoding_beats_both_punycode_conversions() {
        const UNICODE: &[u8] = b"r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se";
        const ASCII: &[u8] = b"xn--rksmrgs-5wao1o.se";
        const ENCODED: &[u8] = b"r%C3%A4ksm%C3%B6rg%C3%A5s.se";

        let mut u = handle();
        let mut url = b"https://".to_vec();
        url.extend_from_slice(UNICODE);
        u.set(P::Url, Some(&url), F::NONE).expect("parse");

        assert_eq!(
            u.get(P::Host, F::NONE).map(|g| show(&g)),
            Ok(show(UNICODE))
        );
        assert_eq!(
            u.get(P::Host, F::PUNYCODE).map(|g| show(&g)),
            Ok(show(ASCII))
        );
        assert_eq!(
            u.get(P::Host, F::URLENCODE).map(|g| show(&g)),
            Ok(show(ENCODED))
        );
        assert_eq!(
            u.get(P::Host, F::URLENCODE.union(F::PUNYCODE))
                .map(|g| show(&g)),
            Ok(show(ENCODED)),
            "the encoder is the first arm"
        );
        assert_eq!(
            u.get(P::Host, F::URLENCODE.union(F::PUNY2IDN))
                .map(|g| show(&g)),
            Ok(show(ENCODED))
        );
        // On the whole URL, the same chain.
        let mut wanted = b"https://".to_vec();
        wanted.extend_from_slice(ASCII);
        wanted.push(b'/');
        assert_eq!(
            u.get(P::Url, F::PUNYCODE).map(|g| show(&g)),
            Ok(show(&wanted))
        );
        let mut wanted = b"https://".to_vec();
        wanted.extend_from_slice(ENCODED);
        wanted.push(b'/');
        assert_eq!(
            u.get(P::Url, F::URLENCODE.union(F::PUNYCODE))
                .map(|g| show(&g)),
            Ok(show(&wanted))
        );

        // The reverse direction, and its gate: `CURLU_PUNY2IDN` converts only
        // an already-ASCII host.
        let mut u = handle();
        let mut url = b"https://".to_vec();
        url.extend_from_slice(ASCII);
        u.set(P::Url, Some(&url), F::NONE).expect("parse");
        assert_eq!(
            u.get(P::Host, F::PUNY2IDN).map(|g| show(&g)),
            Ok(show(UNICODE))
        );
        assert_eq!(
            u.get(P::Host, F::PUNYCODE).map(|g| show(&g)),
            Ok(show(ASCII)),
            "an ASCII host is left alone by CURLU_PUNYCODE"
        );

        // Neither conversion touches any other part, because both are gated on
        // the part being the host.
        assert_eq!(u.get(P::Path, F::PUNYCODE), Ok(b"/".to_vec()));
        assert_eq!(u.get(P::Scheme, F::PUNY2IDN), Ok(b"https".to_vec()));
    }

    // -----------------------------------------------------------------------
    // The three `pub(crate)` entry points, and the private helpers behind
    // them.
    // -----------------------------------------------------------------------

    /// [`is_absolute_url`] in isolation, including the branch the
    /// `guess_scheme` argument selects.
    ///
    /// `Curl_is_absolute_url` (`lib/urlapi.c:182-220`). Its own comment names
    /// the reason for the branch: without guessing *"the scheme always ends
    /// with the colon so that this also detects data: URLs"*, whereas in
    /// guessing mode `data:` could be the host `data` with a port.
    #[test]
    fn absolute_url_detection_depends_on_whether_a_guess_is_allowed() {
        let scheme = |input: &[u8], guess: bool| -> Option<String> {
            is_absolute_url(input, guess).map(|got| show(&got))
        };

        assert_eq!(scheme(b"http://x", false).as_deref(), Some("http"));
        assert_eq!(scheme(b"http://x", true).as_deref(), Some("http"));
        // Folded to lower case, into the C's `schemebuf`.
        assert_eq!(scheme(b"HtTp://x", false).as_deref(), Some("http"));
        // Every byte the grammar allows.
        assert_eq!(
            scheme(b"ftp+more-1.2://x", false).as_deref(),
            Some("ftp+more-1.2")
        );
        // The branch: a colon not followed by a slash.
        assert_eq!(scheme(b"data:text/html", false).as_deref(), Some("data"));
        assert_eq!(scheme(b"data:text/html", true), None);
        assert_eq!(scheme(b"data:/x", true).as_deref(), Some("data"));
        // A first byte that is not a letter, and a byte the grammar refuses.
        assert_eq!(scheme(b"1http://x", false), None);
        assert_eq!(scheme(b"ht tp://x", false), None);
        assert_eq!(scheme(b"-http://x", false), None);
        assert_eq!(scheme(b"://x", false), None);
        assert_eq!(scheme(b"", false), None);
        assert_eq!(scheme(b"relative/path", false), None);

        // Exactly `MAX_SCHEME_LEN` is found; one more is not, because the scan
        // stops before reaching the colon.
        let mut at_limit = vec![b'a'; MAX_SCHEME_LEN];
        at_limit.extend_from_slice(b"://x");
        assert_eq!(
            scheme(&at_limit, false).map(|got| got.len()),
            Some(MAX_SCHEME_LEN)
        );
        let mut over = vec![b'a'; MAX_SCHEME_LEN + 1];
        over.extend_from_slice(b"://x");
        assert_eq!(scheme(&over, false), None);
    }

    /// [`guess_scheme`] called directly, which is how `parseurl` reaches it
    /// once the authority is parsed.
    #[test]
    fn guessing_reads_the_host_buffer_it_is_handed() {
        for (host, wanted) in [
            (&b"ftp.example.com"[..], &b"ftp"[..]),
            (b"pop3.example.com", b"pop3"),
            (b"example.com", b"http"),
            (b"", b"http"),
        ] {
            let mut buf = Buf::new(MAX_INPUT_LENGTH);
            buf.addn(host).expect("host");
            let mut u = handle();
            guess_scheme(&mut u, &buf);
            assert_eq!(
                u.get(P::Scheme, F::NONE).map(|got| show(&got)),
                Ok(show(wanted)),
                "host: {}",
                show(host)
            );
            assert_eq!(
                u.get(P::Scheme, F::NO_GUESS_SCHEME),
                Err(E::NoScheme),
                "and the bit is raised"
            );
        }
    }

    /// [`Url::set_authority`], the HTTP/2 server-push entry point.
    ///
    /// `Curl_url_set_authority` (`lib/urlapi.c:658-673`) hard-codes
    /// `CURLU_DISALLOW_USER` and passes `!!u->scheme` as `has_scheme`, so a
    /// pushed authority may never carry credentials and the browser-behaviour
    /// port adaptation depends on whether the handle already has a scheme.
    #[test]
    fn setting_an_authority_refuses_credentials() {
        let mut u = handle();
        u.set(P::Url, Some(b"https://first.example/p?q"), F::NONE)
            .expect("parse");

        u.set_authority(b"second.example:8443").expect("authority");
        assert_eq!(u.get(P::Host, F::NONE), Ok(b"second.example".to_vec()));
        assert_eq!(u.get(P::Port, F::NONE), Ok(b"8443".to_vec()));
        assert_eq!(
            u.get(P::Url, F::NONE),
            Ok(b"https://second.example:8443/p?q".to_vec()),
            "the rest of the handle is untouched"
        );

        // A bracketed literal, normalised.
        u.set_authority(b"[0:0:0:0:0:0:0:1]:443")
            .expect("authority");
        assert_eq!(u.get(P::Host, F::NONE), Ok(b"[::1]".to_vec()));

        // Credentials are refused, whatever they look like.
        assert_eq!(
            u.set_authority(b"user@third.example"),
            Err(E::UserNotAllowed)
        );
        assert_eq!(u.set_authority(b"@third.example"), Err(E::UserNotAllowed));
        assert_eq!(u.get(P::Host, F::NONE), Ok(b"[::1]".to_vec()));

        // A blank authority has no host.
        assert_eq!(u.set_authority(b""), Err(E::NoHost));

        // With a scheme on the handle, a trailing colon is browser behaviour;
        // without one it is an error.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x/"), F::NONE).expect("parse");
        u.set_authority(b"y:").expect("adapted");
        assert_eq!(u.get(P::Host, F::NONE), Ok(b"y".to_vec()));
        let mut bare = handle();
        assert_eq!(bare.set_authority(b"y:"), Err(E::BadPortNumber));
    }

    /// Relative-URL merging, dispatched on the first byte of the replacement.
    ///
    /// `redirect_url` (`lib/urlapi.c:1214-1281`). Four shapes: `//` replaces
    /// the host, `/` replaces the path, `#` replaces the fragment, and
    /// anything else is appended after the last slash.
    #[test]
    fn a_relative_url_merges_by_its_first_byte() {
        for (base, relative, wanted) in [
            // `//` -- protocol relative, and the host changes.
            (
                &b"http://one.example/a/b?q#f"[..],
                &b"//two.example/c"[..],
                &b"http://two.example/c"[..],
            ),
            // `/` -- an absolute path.
            (
                b"http://one.example/a/b?q#f",
                b"/c",
                b"http://one.example/c",
            ),
            // `#` -- the fragment alone.
            (
                b"http://one.example/a/b?q#f",
                b"#g",
                b"http://one.example/a/b?q#g",
            ),
            // Anything else -- after the last slash, with the query dropped.
            (
                b"http://one.example/a/b?q#f",
                b"c",
                b"http://one.example/a/c",
            ),
            (
                b"http://one.example/a/b?q#f",
                b"../c",
                b"http://one.example/c",
            ),
            // A query-only replacement keeps the path.
            (
                b"http://one.example/a/b?q#f",
                b"?new",
                b"http://one.example/a/b?new",
            ),
            // An absolute replacement replaces everything.
            (
                b"http://one.example/a/b?q#f",
                b"https://two.example/c",
                b"https://two.example/c",
            ),
            // A blank replacement is a redirect that changes nothing.
            (
                b"http://one.example/a/b?q#f",
                b"",
                b"http://one.example/a/b?q#f",
            ),
        ] {
            let mut u = handle();
            u.set(P::Url, Some(base), F::NONE).expect("base");
            u.set(P::Url, Some(relative), F::NONE)
                .unwrap_or_else(|code| {
                    panic!(
                        "base: {}\nrelative: {}\nreturned {code:?}",
                        show(base),
                        show(relative)
                    )
                });
            assert_eq!(
                u.get(P::Url, F::NONE).map(|got| show(&got)),
                Ok(show(wanted)),
                "base: {}\nrelative: {}",
                show(base),
                show(relative)
            );
        }

        // A blank replacement on a handle that cannot render a URL is refused.
        let mut u = handle();
        u.set(P::Scheme, Some(b"https"), F::NONE).expect("scheme");
        assert_eq!(u.set(P::Url, Some(b""), F::NONE), Err(E::MalformedInput));
    }

    /// A merge whose base is shorter than `scheme://` reads past its end in C,
    /// and the clamp here reproduces the outcome.
    ///
    /// `redirect_url` computes `protsep = base + strlen(u->scheme) + 3`
    /// (`lib/urlapi.c:1225`) without checking that the base is that long. It
    /// is reachable: `CURLU_NO_GUESS_SCHEME` makes `curl_url_get` withhold a
    /// guessed scheme, so the base comes back as `a/` while `u->scheme` is
    /// still `http` -- and the pointer lands four bytes past the terminator.
    ///
    /// Rust cannot read there, so the offset saturates at the end of the base.
    /// Measured against a real libcurl, the C answers `CURLUE_BAD_SCHEME`, and
    /// so does this: the clamp leaves no cut-off point, the whole base is kept,
    /// and `a/b` then fails to parse without a guess.
    #[test]
    fn a_merge_over_a_short_base_answers_what_the_c_answers() {
        let mut u = handle();
        u.set(P::Url, Some(b"a"), F::GUESS_SCHEME).expect("guess");
        assert_eq!(u.get(P::Url, F::NO_GUESS_SCHEME), Ok(b"a/".to_vec()));
        assert_eq!(
            u.set(P::Url, Some(b"b"), F::NO_GUESS_SCHEME),
            Err(E::BadScheme)
        );
        // The handle is unchanged by the failed merge, because
        // `parseurl_and_replace` only replaces on success.
        assert_eq!(u.get(P::Url, F::NONE), Ok(b"http://a/".to_vec()));
    }

    /// Clearing each part in turn leaves the handle usable, and the three arms
    /// that clear more than a string do so.
    ///
    /// `urlset_clear` (`lib/urlapi.c:1732-1776`).
    #[test]
    fn clearing_a_part_leaves_the_handle_usable() {
        let build = || -> Url {
            let mut u = handle();
            u.set(
                P::Url,
                Some(b"imap://user:pass;opt@[fe80::1%25eth0]:143/p?q#f"),
                F::NONE,
            )
            .expect("parse");
            u
        };

        // Every part clears, and the get then reports absence.
        for (part, absent) in [
            (P::Scheme, E::NoScheme),
            (P::User, E::NoUser),
            (P::Password, E::NoPassword),
            (P::Options, E::NoOptions),
            (P::Host, E::NoHost),
            (P::ZoneId, E::NoZoneid),
            (P::Port, E::NoPort),
            (P::Query, E::NoQuery),
            (P::Fragment, E::NoFragment),
        ] {
            let mut u = build();
            u.set(part, None, F::NONE).expect("clear");
            assert_eq!(u.get(part, F::GET_EMPTY), Err(absent), "{part:?}");
        }

        // The path clears to a slash rather than to absence.
        let mut u = build();
        u.set(P::Path, None, F::NONE).expect("clear");
        assert_eq!(u.get(P::Path, F::NONE), Ok(b"/".to_vec()));

        // Clearing the scheme lowers the guessed bit, so a later get stops
        // withholding.
        let mut u = handle();
        u.set(P::Url, Some(b"example.com"), F::GUESS_SCHEME)
            .expect("guess");
        u.set(P::Scheme, None, F::NONE).expect("clear");
        u.set(P::Scheme, Some(b"http"), F::NONE).expect("scheme");
        assert_eq!(u.get(P::Scheme, F::NO_GUESS_SCHEME), Ok(b"http".to_vec()));

        // Clearing the port zeroes the number, so `CURLU_NO_DEFAULT_PORT` no
        // longer matches on a later set of a different port.
        let mut u = handle();
        u.set(P::Url, Some(b"http://x:80/"), F::NONE)
            .expect("parse");
        u.set(P::Port, None, F::NONE).expect("clear");
        u.set(P::Port, Some(b"8080"), F::NONE).expect("port");
        assert_eq!(
            u.get(P::Url, F::NO_DEFAULT_PORT),
            Ok(b"http://x:8080/".to_vec())
        );

        // Clearing the query or the fragment lowers its present bit, which a
        // blank set does not.
        let mut u = build();
        u.set(P::Query, None, F::NONE).expect("clear");
        u.set(P::Fragment, None, F::NONE).expect("clear");
        assert_eq!(
            u.get(P::Url, F::GET_EMPTY),
            Ok(b"imap://user:pass;opt@[fe80::1%25eth0]:143/p".to_vec())
        );

        // And clearing the whole URL resets everything, registry included --
        // the handle still parses afterwards.
        let mut u = build();
        u.set(P::Url, None, F::NONE).expect("clear");
        for part in UrlPart::VARIANTS {
            if *part == P::Path || *part == P::Url {
                continue;
            }
            assert!(u.get(*part, F::GET_EMPTY).is_err(), "{part:?}");
        }
        u.set(P::Url, Some(b"https://again.example/"), F::NONE)
            .expect("reusable");
        assert_eq!(
            u.get(P::Url, F::NONE),
            Ok(b"https://again.example/".to_vec())
        );
    }

    /// A fresh handle holds nothing at all.
    ///
    /// `curl_url` is a `calloc` (`lib/urlapi.c:1288-1291`), so every field is
    /// zero. The registry is the one thing a `calloc` cannot supply, and it is
    /// a constructor argument rather than a global for the reason AAP section
    /// 0.3.3 pattern P12 gives.
    #[test]
    fn a_fresh_handle_is_empty_and_prints() {
        let u = handle();
        assert_eq!(u.get(P::Url, F::GET_EMPTY), Err(E::NoHost));

        // The `Debug` rendering is lossy on purpose -- a part can hold bytes
        // that are not UTF-8 -- and it must never panic on them.
        let mut u = handle();
        u.set(P::Url, Some(b"https://_%c0_/p"), F::NONE)
            .expect("parse");
        let printed = format!("{u:?}");
        assert!(printed.starts_with("Url {"), "{printed}");
        assert!(printed.contains("guessed_scheme"), "{printed}");
        assert!(printed.contains("portnum"), "{printed}");
        // The host holds a raw 0xC0, which is why the parts are byte vectors
        // and not `String`s.
        assert_eq!(u.get(P::Host, F::NONE), Ok(b"_\xc0_".to_vec()));
    }

    /// The raw-identifier entry points the C ABI wrapper uses.
    #[test]
    fn the_raw_identifier_entry_points_agree_with_the_typed_ones() {
        let mut u = handle();
        u.set_by_id(P::Url.as_i32(), Some(b"http://x/p?q#f"), F::NONE)
            .expect("set");
        for part in UrlPart::VARIANTS {
            assert_eq!(
                u.get_by_id(part.as_i32(), F::GET_EMPTY),
                u.get(*part, F::GET_EMPTY),
                "{part:?}"
            );
        }
        u.set_by_id(P::Port.as_i32(), Some(b"8080"), F::NONE)
            .expect("port");
        assert_eq!(u.get(P::Port, F::NONE), Ok(b"8080".to_vec()));
        u.set_by_id(P::Port.as_i32(), None, F::NONE).expect("clear");
        assert_eq!(u.get(P::Port, F::NONE), Err(E::NoPort));
    }
}
