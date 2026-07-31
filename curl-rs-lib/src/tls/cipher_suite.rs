//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Jan Venekamp, <jan@venekamp.net>
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

//! Cipher-suite spellings, and the provider suite list they select.
//!
//! Supersedes `lib/vtls/cipher_suite.c` as compiled for `USE_RUSTLS`, together
//! with the selection flow at `lib/vtls/rustls.c:409-502` that consumes it.
//! The copyright above is that file's own and is preserved rather than
//! replaced: this module is a translation of Jan Venekamp's work, not new
//! work in its place.
//!
//! # Why this table exists at all
//!
//! `cipher_suite.c:30-47` states the reason verbatim, and it applies word for
//! word to rustls: `CURLOPT_SSL_CIPHER_LIST` has to be supported on a backend
//! that "does not support it natively, but does support setting a list of
//! IANA ids", so curl needs "a list of all supported cipher suite names
//! (OpenSSL and IANA) to be able to look up the IANA ids". rustls describes
//! its suites with `rustls::CipherSuite`, an IANA `u16`, and accepts a
//! selection as an ordered slice of them -- exactly the shape the C comment
//! anticipates.
//!
//! # What is deliberately NOT reproduced
//!
//! The C file compresses every row "down to 2 + 6 bytes using the C
//! preprocessor" (`cipher_suite.c:36-37`): each spelling becomes eight 6-bit
//! indexes into a shared string pool `cs_txt`, packed into `uint8_t zip[6]`
//! by `CS_ZIP_IDX`, and lookup compares packed forms with `memcmp`. That is a
//! binary-size optimisation for a table of 200-odd mbedTLS rows, and it is
//! not reproduced here, for two measured reasons.
//!
//! First, it would be optimising nothing: the `USE_RUSTLS` build compiles
//! seventeen rows, not two hundred, because everything after
//! `cipher_suite.c:180` sits behind `#ifdef USE_MBEDTLS`. Second, and this is
//! the load-bearing measurement, comparing components is *exactly* equivalent
//! to comparing whole spellings for this table. Every component in the
//! `USE_RUSTLS` vocabulary (`TLS`, `WITH`, `128`, `256`, `8`, `AES`, `AES128`,
//! `AES256`, `CCM`, `CHACHA20`, `ECDHE`, `ECDSA`, `GCM`, `POLY1305`, `RSA`,
//! `SHA256`, `SHA384`) is alphanumeric, so no component can contain either
//! separator, so a spelling splits into components in exactly one way and
//! rejoins to exactly one spelling. The names are therefore held as byte
//! literals -- the form a reader can check against the C source and against
//! `docs/cmdline-opts/ciphers.md` by eye -- and the component structure is
//! recovered by splitting when the algorithm needs it.
//!
//! Two consequences of the packed form are *behaviour*, not optimisation, and
//! those are reproduced exactly: at most eight components per spelling
//! (`cipher_suite.c:557`, `if(i == 8) return -1`), and no empty component
//! (the pool scan at `cipher_suite.c:567` starts at index 1, skipping the
//! empty string, so an empty component can never match).
//!
//! # Why ordering is a frozen contract
//!
//! The selection returned by [`select_provider_suites`] becomes the cipher
//! suite list of the TLS ClientHello, in order. The test corpus compares
//! request bytes as a single joined string with no normalisation and no
//! reordering, so every ordering decision here is observable on the wire.
//! Nothing in this module may be reordered, sorted, deduplicated differently
//! or "canonicalised" -- first-occurrence order is the specification. This is
//! also why the provider's own suite order is honoured for the default
//! prefix and suffix instead of being imposed by this module.
//!
//! # Provider neutrality
//!
//! This module never installs, builds, fetches or names a cryptographic
//! provider. The caller injects the suite list it already has -- in practice
//! `CryptoProvider::cipher_suites` from the pinned *ring* provider -- and the
//! only rustls-typed code here is the [`ProviderCipherSuite`] implementation
//! for `rustls::SupportedCipherSuite`, which reads an IANA id and a protocol
//! version and nothing else. That indirection is not decoration: it is what
//! lets the tests below drive the whole selection flow with a deterministic
//! fake suite list, and what keeps `aws_lc_rs`, `prefer-post-quantum` and
//! `platform-verifier` out of this file entirely.
//!
//! # The C surface, and its Rust counterpart
//!
//! | `cipher_suite.h`              | here                                |
//! |-------------------------------|-------------------------------------|
//! | `Curl_cipher_suite_lookup_id` | [`lookup_id`]                       |
//! | `Curl_cipher_suite_walk_str`  | [`tokens`]                          |
//! | `Curl_cipher_suite_get_str`   | [`name`] / [`get_str`] and its      |
//! |                               | bounded form [`get_str_bounded`]    |
//! | `cr_get_selected_ciphers`     | [`select_provider_suites`]          |
//!
//! The whole of that surface is translated from two spans, and every function
//! below carries the finer anchor it derives from: the table at
//! `cipher_suite.c:161-179`, and the algorithms at `cipher_suite.c:542-699`
//! (`cs_str_to_zip`, `cs_zip_to_str`, `Curl_cipher_suite_lookup_id`,
//! `cs_is_separator`, `Curl_cipher_suite_walk_str` and
//! `Curl_cipher_suite_get_str`, in that order). The consumer that turns a
//! spelling into a ClientHello is `rustls.c:409-502`.
//!
//! There is no `unsafe` here, no raw pointer, no `Any` and no downcast, and
//! no path panics on caller-supplied text: an unparsable spelling is `None`,
//! never an abort.

// `dead_code` is allowed for this module alone, and for one specific reason
// rather than as a convenience: every consumer of this contract lives in
// another module -- `tls/rustls_backend.rs` selects the suite list when it
// builds the client configuration and renders suite names into `--trace`
// output, and `tls/mod.rs` re-exports the pieces the backend trait needs --
// so until those land each item here is legitimately unreferenced inside the
// crate, and the zero-warnings gate would otherwise fail on code that is
// correct. This mirrors the same allowance, granted for the same reason, in
// `src/ffi/sys.rs`. No lint level for `unsafe_code` is set here, at any
// level, by design: the crate root's `#![deny(unsafe_code)]` governs, and
// this module has nothing to exempt.
#![allow(dead_code)]

use core::fmt;
use std::borrow::Cow;

use rustls::SupportedCipherSuite;

use crate::error::{CURLcode, CurlResult, Error};

/// The greatest number of components a cipher-suite spelling may have.
///
/// `cs_str_to_zip` packs eight 6-bit indexes into six bytes and rejects a
/// ninth component outright (`cipher_suite.c:544` declares `uint8_t
/// indexes[8]`, `cipher_suite.c:557-558` returns `-1` once `i == 8`). Eight is
/// not slack: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` uses all eight.
pub(crate) const MAX_COMPONENTS: usize = 8;

/// The destination size `cipher_suite.h:37-39` documents as sufficient.
///
/// "Caller is responsible to supply sufficiently large buffer (size of 64
/// should suffice), excess bytes are silently truncated." The longest spelling
/// in the table is 45 bytes, so 64 leaves room; `tests/unit/unit3205.c:539`
/// declares exactly `char buf[64]`. Passed to [`get_str_bounded`] this
/// reproduces the C call the C unit test makes.
pub(crate) const NAME_BUFFER_SIZE: usize = 64;

/// Every byte that separates one cipher suite from the next in a list.
///
/// `cs_is_separator` (`cipher_suite.c:650-661`) accepts these five and
/// nothing else. It is a closed set: adding a separator would accept lists
/// curl 8.x rejects, and removing one would reject lists it accepts. Both are
/// out of scope.
pub(crate) const SEPARATORS: [char; 5] = [' ', '\t', ':', ',', ';'];

/// The first component that marks an IANA (RFC) spelling.
///
/// `cs_str_to_zip` tests `curl_strnequal(cs_str, "TLS", 3)`
/// (`cipher_suite.c:553-554`) -- an ASCII case-insensitive comparison of the
/// first three bytes, not a component-aware test, which is why
/// `TLS-ECDHE-RSA-AES128-GCM-SHA256` is split on `_` and consequently
/// recognised as nothing at all.
const RFC_PREFIX: &str = "TLS";

/// The component separator of an IANA spelling: `TLS_AES_128_GCM_SHA256`.
const RFC_SEPARATOR: char = '_';

/// The component separator of an OpenSSL spelling:
/// `ECDHE-RSA-AES128-GCM-SHA256`.
const OPENSSL_SEPARATOR: char = '-';

/// One row of the cipher-suite table: an IANA id and one spelling of it.
///
/// The C row is `struct cs_entry { uint16_t id; uint8_t zip[6]; }`
/// (`cipher_suite.c:154-157`); the `zip` is the packed component list, so
/// this is the same row with the spelling held in readable form. Two rows may
/// carry the same `id`, exactly as in C: one for the IANA spelling and one for
/// the OpenSSL spelling.
struct CipherSuiteEntry {
    /// The IANA cipher suite identifier, as it appears on the wire.
    id: u16,
    /// One accepted spelling of that suite, byte for byte as curl accepts and
    /// emits it.
    name: &'static str,
}

impl CipherSuiteEntry {
    /// Whether this row carries the IANA (RFC) spelling rather than the
    /// OpenSSL one.
    ///
    /// The C test is `cs_list[i].zip[0] >> 2 != CS_TXT_IDX_TLS`
    /// (`cipher_suite.c:685`) -- it asks whether the *first component* is the
    /// pooled string `TLS`, so `TLSFOO_BAR` would not qualify even though it
    /// begins with those three bytes. Reproduced by splitting rather than by
    /// `starts_with`, so that distinction survives.
    fn is_rfc(&self) -> bool {
        let separator = separator_for(self.name);
        separator == RFC_SEPARATOR
            && self.name.split(separator).next() == Some(RFC_PREFIX)
    }
}

/// Builds one table row, mirroring the C `CS_ENTRY` macro
/// (`cipher_suite.c:143-152`).
const fn cs(id: u16, name: &'static str) -> CipherSuiteEntry {
    CipherSuiteEntry { id, name }
}

/// The cipher-suite table, exactly as `cipher_suite.c:160-179` compiles it for
/// a rustls build.
///
/// Seventeen rows: five TLS 1.3 suites with only an IANA spelling, and six
/// TLS 1.2 suites with an IANA spelling followed by an OpenSSL spelling.
/// Everything from `cipher_suite.c:180` to `:538` is `#ifdef USE_MBEDTLS` and
/// is therefore absent here -- deliberately, since claiming
/// `AES128-GCM-SHA256` or `DHE-RSA-CHACHA20-POLY1305` would map a spelling
/// this build cannot honour onto a real id.
///
/// **Row order is behaviour.** [`name`] falls back to the *first* row carrying
/// the requested id (`cipher_suite.c:689-690`), so the IANA row must precede
/// the OpenSSL row for every id. That is what makes a TLS 1.3 id render as
/// `TLS_AES_128_GCM_SHA256` even when the OpenSSL spelling is asked for --
/// there is no OpenSSL spelling to give.
///
/// Two of these ids are unreachable through the *ring* provider: neither
/// `0x1304` (`TLS_AES_128_CCM_SHA256`) nor `0x1305`
/// (`TLS_AES_128_CCM_8_SHA256`) appears in its suite list. They stay in the
/// table because [`lookup_id`] and [`name`] are name mappings and must answer
/// for every id curl 8.x answers for; [`select_provider_suites`] is where a
/// suite the provider cannot honour is dropped.
///
/// `rustfmt::skip` keeps the rows one per line, in C order, with the C
/// section comments -- and keeps the spellings byte-exact, which is the whole
/// contract of this module.
#[rustfmt::skip]
static CS_LIST: &[CipherSuiteEntry] = &[
    /* TLS 1.3 ciphers */
    cs(0x1301, "TLS_AES_128_GCM_SHA256"),
    cs(0x1302, "TLS_AES_256_GCM_SHA384"),
    cs(0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    cs(0x1304, "TLS_AES_128_CCM_SHA256"),
    cs(0x1305, "TLS_AES_128_CCM_8_SHA256"),
    /* TLS 1.2 ciphers */
    cs(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    cs(0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256"),
    cs(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    cs(0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384"),
    cs(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    cs(0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"),
    cs(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    cs(0xC030, "ECDHE-RSA-AES256-GCM-SHA384"),
    cs(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    cs(0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305"),
    cs(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
    cs(0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305"),
];

/// Whether `c` separates one cipher suite from the next in a list.
///
/// Reproduces `cs_is_separator` (`cipher_suite.c:650-661`) through
/// [`SEPARATORS`], so the set is stated once.
#[must_use]
pub(crate) fn is_separator(c: char) -> bool {
    SEPARATORS.contains(&c)
}

/// The component separator `cs_str_to_zip` would choose for `name`.
///
/// `'_'` when the first three bytes are `TLS` ASCII case-insensitively, `'-'`
/// otherwise (`cipher_suite.c:548-554`). A spelling shorter than three bytes,
/// or one whose third byte lands inside a multi-byte character, takes `'-'`;
/// neither can equal `TLS`, so this matches the C byte comparison.
#[must_use]
fn separator_for(name: &str) -> char {
    match name.get(..RFC_PREFIX.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(RFC_PREFIX) => {
            RFC_SEPARATOR
        }
        _ => OPENSSL_SEPARATOR,
    }
}

/// The part of `text` before its first NUL byte, or all of it.
///
/// The C parser treats NUL as end-of-input twice over: the component scan
/// stops at it (`cipher_suite.c:562`) and the component loop then terminates
/// (`cipher_suite.c:577`), so `"TLS_AES_128_GCM_SHA256\0EXTRA"` with a length
/// of 28 still resolves to `0x1301`. A Rust `&str` built from a C string
/// cannot hold an interior NUL -- `CString::new` rejects one -- so this is
/// unreachable through the FFI boundary, and it is reproduced anyway because
/// "unreachable" is a property of today's callers, not of this function.
#[must_use]
fn before_nul(text: &str) -> &str {
    match text.find('\0') {
        // `find` yields the byte index of an ASCII NUL, which is always a
        // character boundary, so this cannot panic.
        Some(end) => &text[..end],
        None => text,
    }
}

/// `text` truncated to at most `limit` bytes, never splitting a character.
///
/// The C helper writes through `curl_msnprintf` into a caller-owned buffer and
/// silently drops whatever does not fit (`cipher_suite.h:37-39`). Truncating a
/// borrowed spelling costs nothing and cannot corrupt anything, which is the
/// point of doing it this way instead of reproducing the buffer.
#[must_use]
fn truncate_to(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    // `is_char_boundary(0)` is true, so this terminates at or before 0 and
    // the slice below is always in bounds and always on a boundary.
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// A cipher-suite spelling split into its components.
///
/// The Rust stand-in for `uint8_t zip[6]`: the same eight slots, holding the
/// component text instead of a 6-bit pool index. Borrowed from the caller's
/// string, so splitting a list allocates nothing.
struct NameComponents<'a> {
    /// The components, low index first; slots at or past `len` are `""`.
    parts: [&'a str; MAX_COMPONENTS],
    /// How many of `parts` are in use, always `1..=MAX_COMPONENTS`.
    len: usize,
}

impl<'a> NameComponents<'a> {
    /// Splits `name` the way `cs_str_to_zip` does, or reports it unusable.
    ///
    /// `None` covers every case the C function returns `-1` for:
    ///
    /// - a ninth component (`cipher_suite.c:557-558`);
    /// - an empty component, which the C pool scan can never match because it
    ///   starts past the empty string at index 0 (`cipher_suite.c:567-574`).
    ///   This is what rejects a leading, doubled or trailing separator inside
    ///   a spelling -- `TLS_AES_128_GCM_SHA256_` is not a truncated match, it
    ///   is malformed;
    /// - an empty spelling, which `Curl_cipher_suite_lookup_id` rejects before
    ///   splitting at all (`cipher_suite.c:640`, `cs_len > 0`).
    ///
    /// A component this build has no pooled string for -- `ARIA`, `CAMELLIA`,
    /// `CBC`, `SHA` -- is *not* rejected here. C rejects it during the pool
    /// scan; this returns the components and lets the table comparison fail.
    /// Both paths yield id 0 through the only public entry point, and the
    /// distinction is invisible to every caller.
    fn parse(name: &'a str) -> Option<Self> {
        if name.is_empty() {
            return None;
        }

        let separator = separator_for(name);
        let mut parts = [""; MAX_COMPONENTS];
        let mut len = 0;

        for part in name.split(separator) {
            // Order mirrors the C loop: the ninth component is rejected at the
            // top of the body, before the component itself is examined.
            if len == MAX_COMPONENTS || part.is_empty() {
                return None;
            }
            parts[len] = part;
            len += 1;
        }

        Some(Self { parts, len })
    }

    /// The components in use.
    #[must_use]
    fn as_slice(&self) -> &[&'a str] {
        // `len <= MAX_COMPONENTS == parts.len()`, upheld by `parse`, so this
        // range is always valid.
        &self.parts[..self.len]
    }

    /// Whether these components spell `name`, ASCII case-insensitively.
    ///
    /// `name` is a table spelling and is split by its own separator, so an
    /// IANA spelling is only ever compared against underscore-separated
    /// components and an OpenSSL spelling only against hyphen-separated ones.
    /// That is precisely the C behaviour: both sides were pooled by the same
    /// `cs_str_to_zip` rule before `memcmp` compared them
    /// (`cipher_suite.c:642`).
    #[must_use]
    fn matches(&self, name: &str) -> bool {
        let separator = separator_for(name);
        let mine = self.as_slice();
        let mut count = 0;

        for part in name.split(separator) {
            match mine.get(count) {
                Some(component) if component.eq_ignore_ascii_case(part) => {
                    count += 1;
                }
                _ => return false,
            }
        }

        count == mine.len()
    }
}

/// The IANA id of `name`, or `None` if this build does not recognise it.
///
/// Reproduces `Curl_cipher_suite_lookup_id` (`cipher_suite.c:635-648`), whose
/// contract is "returns 0 if not recognized" (`cipher_suite.h:30-31`). `None`
/// is that zero: the C function cannot distinguish "malformed", "unknown
/// component" and "well-formed but absent from the table" either, and no
/// caller ever needed it to.
///
/// Both spellings of a suite resolve to the same id, and matching is ASCII
/// case-insensitive in both, because `curl_strnequal` is
/// (`cipher_suite.c:569`):
///
/// ```ignore
/// let rfc = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
/// assert_eq!(lookup_id(rfc), Some(0xC02F));
/// assert_eq!(lookup_id("ecdhe-rsa-aes128-gcm-sha256"), Some(0xC02F));
/// assert_eq!(lookup_id("AES128-GCM-SHA256"), None); // mbedTLS-only spelling
/// assert_eq!(lookup_id(""), None);
/// ```
#[must_use]
pub(crate) fn lookup_id(name: &str) -> Option<u16> {
    let name = before_nul(name);
    let components = NameComponents::parse(name)?;

    CS_LIST
        .iter()
        .find(|entry| components.matches(entry.name))
        .map(|entry| entry.id)
}

/// One cipher suite lifted out of a list, with the text it was written as.
///
/// The C walk hands back two pointers into the caller's string and an id
/// (`cipher_suite.h:33-35`); this is that pair, with the pointer arithmetic
/// replaced by a borrow. Keeping [`text`](Self::text) matters for more than
/// tidiness: `rustls.c:460-461` and `:470-471` log the *user's* spelling, not
/// a canonical one, so a diagnostic can only be faithful if the raw slice
/// survives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CipherSuiteToken<'a> {
    /// Exactly the bytes between the separators, case and all.
    ///
    /// Empty for the final token of a list that ends in separators; see
    /// [`Tokens`] for why that token exists.
    pub(crate) text: &'a str,
    /// The IANA id [`lookup_id`] resolved `text` to, if any.
    pub(crate) id: Option<u16>,
}

/// The cipher suites of a delimited list, in order.
///
/// Reproduces the loop `rustls.c:445` drives over
/// `Curl_cipher_suite_walk_str`:
///
/// ```c
/// for(ptr = ciphers; ptr[0] != '\0' && count < supported_len; ptr = end) {
///   uint16_t id = Curl_cipher_suite_walk_str(&ptr, &end);
/// ```
///
/// Each step skips any run of separators, then takes everything up to the next
/// separator or the end of the string (`cipher_suite.c:663-674`). Three
/// consequences are behaviour rather than accident, and all three are
/// reproduced:
///
/// - An empty list yields **no** token at all -- the C loop tests
///   `ptr[0] != '\0'` before the first walk.
/// - A list that ends in separators yields a final **empty** token, because
///   the walk consumed the separators and left `ptr` on the NUL while the loop
///   condition was satisfied before it ran. `tests/unit/unit3205.c` pins this
///   exactly: its list ends `":: GIBBERISH ::"` and its expectation table
///   ends `{ 0x0000, "GIBBERISH" }, { 0x0000, "" }`. It is not noise to be
///   filtered -- [`select_provider_suites`] relies on the empty token being
///   distinguishable, since `rustls.c:459` suppresses the "unknown cipher"
///   diagnostic for exactly that case.
/// - A NUL anywhere in the list ends the list, since NUL is not a separator
///   and terminates the token scan.
#[derive(Clone, Debug)]
pub(crate) struct Tokens<'a> {
    /// What is left of the list, always beginning at a separator or at the
    /// start of the next token.
    rest: &'a str,
}

/// The cipher suites named in `list`, in order.
///
/// See [`Tokens`] for the tokenization rules, which are curl's exactly.
#[must_use]
pub(crate) fn tokens(list: &str) -> Tokens<'_> {
    Tokens {
        rest: before_nul(list),
    }
}

impl<'a> Iterator for Tokens<'a> {
    type Item = CipherSuiteToken<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // The C loop condition, `ptr[0] != '\0'`.
        if self.rest.is_empty() {
            return None;
        }

        // "move string pointer to first non-separator or end of string"
        // (`cipher_suite.c:665-667`). NUL is not a separator, so a list of
        // nothing but separators leaves an empty token here, which is the
        // point.
        let start = self.rest.trim_start_matches(is_separator);

        // "move end pointer to next separator or end of string"
        // (`cipher_suite.c:669-671`). `find` reports the byte index at which a
        // separator begins, which is a character boundary, so `split_at`
        // cannot panic.
        let (text, rest) = match start.find(is_separator) {
            Some(end) => start.split_at(end),
            None => (start, ""),
        };

        // The C loop advances with `ptr = end`, leaving `ptr` ON the
        // separator; the next walk skips it. Anything else would drop a token.
        self.rest = rest;

        Some(CipherSuiteToken {
            text,
            id: lookup_id(text),
        })
    }
}

/// The spelling curl 8.x prints for `id`, or `None` for an id it has no name
/// for.
///
/// `prefer_rfc` selects between the two spellings of a suite, and the fallback
/// is the interesting part. `Curl_cipher_suite_get_str`
/// (`cipher_suite.c:682-691`) scans for a row whose spelling matches the
/// preference and remembers the first row with the right id as it goes; if the
/// preferred spelling does not exist, the remembered row wins. The five TLS
/// 1.3 suites have only an IANA spelling, so asking for OpenSSL form yields
/// the IANA one rather than nothing:
///
/// ```ignore
/// assert_eq!(name(0x1301, false), Some("TLS_AES_128_GCM_SHA256"));
/// assert_eq!(name(0xC02F, false), Some("ECDHE-RSA-AES128-GCM-SHA256"));
/// assert_eq!(name(0x009C, true), None); // mbedTLS-only id
/// ```
///
/// `None` is the C `-1` return. [`get_str`] turns it into the text C leaves in
/// the caller's buffer.
#[must_use]
pub(crate) fn name(id: u16, prefer_rfc: bool) -> Option<&'static str> {
    let mut fallback: Option<&'static str> = None;

    for entry in CS_LIST {
        if entry.id != id {
            continue;
        }
        if entry.is_rfc() == prefer_rfc {
            return Some(entry.name);
        }
        if fallback.is_none() {
            fallback = Some(entry.name);
        }
    }

    fallback
}

/// The text `Curl_cipher_suite_get_str` writes for `id`, known or not.
///
/// For a known id this is [`name`], borrowed. For an unknown one it is the
/// placeholder `cipher_suite.c:697` formats, reproduced digit for digit:
/// `TLS_UNKNOWN_0x%04x`, lower-case hexadecimal, zero-padded to four digits.
/// Rust's `{:04x}` is that format, and `u16` cannot overflow four digits:
///
/// ```ignore
/// let rfc = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
/// assert_eq!(get_str(0xCCA8, true), rfc);
/// assert_eq!(get_str(0x0000, true), "TLS_UNKNOWN_0x0000");
/// assert_eq!(get_str(0xCCAA, false), "TLS_UNKNOWN_0xccaa");
/// ```
///
/// The C signature also returns `0` or `-1` to say which branch it took. A
/// caller that needs to know asks [`name`], which is where that bit lives.
#[must_use]
pub(crate) fn get_str(id: u16, prefer_rfc: bool) -> Cow<'static, str> {
    match name(id, prefer_rfc) {
        Some(spelling) => Cow::Borrowed(spelling),
        None => Cow::Owned(format!("TLS_UNKNOWN_0x{id:04x}")),
    }
}

/// [`get_str`], bounded the way the C buffer bounds it.
///
/// `buf_size` is the C `buf_size`: the *total* size of the destination
/// including the terminating NUL, so the result holds at most
/// `buf_size - 1` bytes. `cipher_suite.h:37-39` promises that "excess bytes
/// are silently truncated" and that 64 -- [`NAME_BUFFER_SIZE`] -- suffices for
/// every spelling, which it does; the longest is 45 bytes.
///
/// The bound is derived from `lib/mprintf.c:1077-1100` rather than assumed.
/// `curl_msnprintf` stores bytes only while `length < max`, and then either
/// appends a NUL or, when the buffer filled exactly, overwrites the last byte
/// stored with one -- so a full buffer holds `max - 1` bytes of text. Both
/// truncation paths in `cs_zip_to_str` (a component clipped mid-way, or a
/// return that pushes `len` past `buf_size` and ends the loop) leave the same
/// bytes behind: the whole spelling, cut at `buf_size - 1`. A `buf_size` of 0
/// makes `curl_msnprintf` write nothing whatsoever, not even a NUL, which is
/// an empty result here.
///
/// Truncation applies to the placeholder too, exactly as in C, where
/// `curl_msnprintf(buf, buf_size, "TLS_UNKNOWN_0x%04x", id)` is bounded by the
/// same buffer.
#[must_use]
pub(crate) fn get_str_bounded(
    id: u16,
    prefer_rfc: bool,
    buf_size: usize,
) -> Cow<'static, str> {
    // One byte of the destination always belongs to the NUL terminator.
    let limit = buf_size.saturating_sub(1);

    match get_str(id, prefer_rfc) {
        Cow::Borrowed(spelling) => Cow::Borrowed(truncate_to(spelling, limit)),
        Cow::Owned(spelling) => {
            Cow::Owned(truncate_to(&spelling, limit).to_owned())
        }
    }
}

/// What [`select_provider_suites`] needs to know about one suite the injected
/// cryptographic provider offers.
///
/// The C flow asks rustls-ffi two questions and nothing else --
/// `rustls_supported_ciphersuite_get_suite` for the IANA id
/// (`rustls.c:452`) and `rustls_supported_ciphersuite_protocol_version`
/// for the version (`rustls.c:429-430`, `:487-488`) -- so those two questions
/// are the whole trait.
///
/// Narrowing the requirement to a trait rather than naming a concrete provider
/// type is what makes the selection flow testable: the tests below inject a
/// deterministic suite list and assert the exact resulting order, which is
/// otherwise only observable in a ClientHello on the wire. It is also what
/// keeps this module provider-neutral, so no cryptographic provider is ever
/// constructed, installed or fetched here.
pub(crate) trait ProviderCipherSuite: Copy {
    /// The suite's IANA identifier, as it appears on the wire.
    fn iana_id(&self) -> u16;

    /// Whether the suite belongs to TLS 1.3 rather than TLS 1.2.
    fn is_tls13(&self) -> bool;
}

impl ProviderCipherSuite for SupportedCipherSuite {
    fn iana_id(&self) -> u16 {
        // `rustls::CipherSuite` is `#[repr(u16)]` and carries the IANA value;
        // the conversion is total, `Unknown(x)` included.
        u16::from(self.suite())
    }

    fn is_tls13(&self) -> bool {
        // `tls13()` is `Some` exactly for the `Tls13` variant, which is how
        // rustls-ffi answers `..._protocol_version` too. Deliberately not
        // written as a comparison against `rustls::version::TLS13`: that
        // reaches for a second type to learn the same fact.
        self.tls13().is_some()
    }
}

/// Something [`select_provider_suites`] skipped, and the spelling it skipped.
///
/// The C flow reports these through `infof` as it goes
/// (`rustls.c:459-462`, `:468-473`); collecting them instead keeps this module
/// free of any dependency on a handle, a log sink or a trace configuration,
/// and lets the caller emit them in the order they occurred. The borrowed
/// spelling is the user's own, so a diagnostic can quote it exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SuiteDiagnostic<'a> {
    /// The spelling resolved to no id, or to an id the provider does not
    /// offer.
    ///
    /// One case, not two, and deliberately so: `rustls.c:455-456` overwrites
    /// the resolved id with `0` when the provider has no such suite, so both
    /// failures reach the same `infof` and produce the same message. Reporting
    /// them separately would say something curl 8.x does not say.
    Unknown(&'a str),
    /// The spelling repeated a suite that an *explicit* list had already
    /// selected.
    ///
    /// A spelling that merely repeats one of the automatically inserted TLS
    /// 1.3 defaults is skipped in silence, since the user did not write it
    /// twice -- the `i >= default13_count` test at `rustls.c:469`.
    Duplicate(&'a str),
}

impl<'a> SuiteDiagnostic<'a> {
    /// The spelling this diagnostic is about, exactly as the user wrote it.
    #[must_use]
    pub(crate) fn spelling(&self) -> &'a str {
        match *self {
            Self::Unknown(text) | Self::Duplicate(text) => text,
        }
    }
}

impl fmt::Display for SuiteDiagnostic<'_> {
    /// Renders the message `rustls.c` logs, byte for byte, so that a caller
    /// only has to choose where it goes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            // rustls.c:460-461
            Self::Unknown(text) => {
                write!(f, "rustls: unknown cipher in list: \"{text}\"")
            }
            // rustls.c:470-471
            Self::Duplicate(text) => {
                write!(f, "rustls: duplicate cipher in list: \"{text}\"")
            }
        }
    }
}

/// The outcome of [`provider_suite_selection`].
///
/// `suites` is the ClientHello cipher suite list, in the order it goes on the
/// wire. Nothing may reorder it.
#[derive(Clone, Debug)]
pub(crate) struct SuiteSelection<'a, S> {
    /// The selected suites, in offer order, each one an entry of the injected
    /// provider list.
    pub(crate) suites: Vec<S>,
    /// Everything skipped, in the order it was skipped, for the caller to log.
    pub(crate) diagnostics: Vec<SuiteDiagnostic<'a>>,
    /// How many leading entries of `suites` are automatically inserted TLS 1.3
    /// defaults rather than user choices.
    ///
    /// The C `default13_count` (`rustls.c:436`). Zero whenever an explicit TLS
    /// 1.3 list was given, because then no defaults were inserted. Retained
    /// because it is the boundary that decides whether a repeated spelling is
    /// worth telling the user about, and a caller re-deriving it would have to
    /// re-derive the whole flow.
    pub(crate) default_tls13_prefix: usize,
}

impl<S> SuiteSelection<'_, S> {
    /// The check the C caller performs on the selection
    /// (`rustls.c:590-594`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::SslCipher`] when nothing survived, carrying the message
    /// `rustls.c:591` fails with so that `CURLOPT_ERRORBUFFER` reads the same
    /// as curl 8.x. An empty selection is the *only* failure: a list of
    /// nothing but unusable spellings still succeeds when a default filled the
    /// selection, which is what C does and not an accident of it.
    pub(crate) fn require_supported(&self) -> CurlResult<()> {
        if self.suites.is_empty() {
            return Err(Error::with_context(
                CURLcode::SslCipher,
                "rustls: no supported cipher in list",
            ));
        }
        Ok(())
    }
}

impl<S: ProviderCipherSuite> SuiteSelection<'_, S> {
    /// The IANA ids of [`suites`](Self::suites), in offer order.
    ///
    /// The wire-visible summary of a selection: this is the sequence of
    /// `uint16` values that reaches the ClientHello.
    #[must_use]
    pub(crate) fn ids(&self) -> Vec<u16> {
        self.suites
            .iter()
            .map(ProviderCipherSuite::iana_id)
            .collect()
    }
}

/// Turns curl's two cipher-list options into the ordered suite list rustls is
/// configured with, and applies the check that rejects an empty one.
///
/// [`provider_suite_selection`] does the work; this adds the caller-side
/// `CURLE_SSL_CIPHER` test from `rustls.c:590-594`, which is where the C error
/// actually lives -- `cr_get_selected_ciphers` itself returns `void`. Prefer
/// this entry point: the suite list it yields can never be empty. Reach for
/// [`provider_suite_selection`] only when the diagnostics matter even though
/// the check failed, since C emits them through `infof` before `failf` runs.
///
/// ```ignore
/// let selection = select_provider_suites(c12, c13, &provider.cipher_suites)?;
/// for diagnostic in &selection.diagnostics {
///     infof(data, "{diagnostic}");
/// }
/// ```
///
/// # Errors
///
/// [`CURLcode::SslCipher`], and only when the final selection is empty. See
/// [`SuiteSelection::require_supported`].
pub(crate) fn select_provider_suites<'a, S: ProviderCipherSuite>(
    ciphers12: Option<&'a str>,
    ciphers13: Option<&'a str>,
    provider_suites: &[S],
) -> CurlResult<SuiteSelection<'a, S>> {
    let selection =
        provider_suite_selection(ciphers12, ciphers13, provider_suites);
    selection.require_supported()?;
    Ok(selection)
}

/// Turns curl's two cipher-list options into the ordered suite list rustls is
/// configured with.
///
/// A faithful translation of `cr_get_selected_ciphers`
/// (`rustls.c:409-502`), which returns `void`: the selection can legitimately
/// come back empty, and [`SuiteSelection::require_supported`] -- or the
/// [`select_provider_suites`] wrapper -- is what turns that into
/// `CURLE_SSL_CIPHER`. Splitting it this way keeps the diagnostics reachable on
/// the failing path, which matters because C has already logged them by the
/// time it fails.
///
/// `ciphers12` is `CURLOPT_SSL_CIPHER_LIST` and
/// `ciphers13` is `CURLOPT_TLS13_CIPHERSUITES`; `None` means the option was
/// never set, which is a different thing from an empty string and produces
/// different behaviour. Both options are genuinely wired, which is why
/// `rustls.c:1401-1402` advertises `SSLSUPP_CIPHER_LIST` and
/// `SSLSUPP_TLS13_CIPHERSUITES` together.
///
/// `provider_suites` is the injected provider's suite list, in the provider's
/// own order. It serves as both the set of *supported* suites and the set of
/// *default* suites, exactly as in C, where `supported_len` and `default_len`
/// are both `rustls_default_crypto_provider_ciphersuites_len()`
/// (`rustls.c:416-417`) and every lookup goes through the same getter.
///
/// # The four cases
///
/// | `ciphers13` | `ciphers12` | result                                       |
/// |-------------|-------------|----------------------------------------------|
/// | absent      | absent      | every provider suite, in provider order      |
/// | absent      | present     | default TLS 1.3 suites, then the parsed list |
/// | present     | absent      | the parsed list, then default TLS 1.2 suites |
/// | present     | present     | parsed 1.3 list, then parsed 1.2 list        |
///
/// The 1.3 list is always parsed before the 1.2 list -- the `goto add_ciphers`
/// at `rustls.c:478-481` -- and the defaults keep the provider's order rather
/// than being sorted here.
pub(crate) fn provider_suite_selection<'a, S: ProviderCipherSuite>(
    ciphers12: Option<&'a str>,
    ciphers13: Option<&'a str>,
    provider_suites: &[S],
) -> SuiteSelection<'a, S> {
    // `supported_len` (`rustls.c:416`). The C selection buffer is allocated
    // with exactly this many slots (`rustls.c:580`), and the loop bound below
    // is what keeps it from overflowing.
    let supported_len = provider_suites.len();

    // Selected suites paired with the provider index they came from. The index
    // is what makes duplicate detection faithful: C compares the
    // `rustls_supported_ciphersuite` *pointers* it got from the provider
    // (`rustls.c:466`, `:492`), and since every one of them is fetched from
    // that same list by index, pointer identity and index identity are the
    // same relation.
    let mut selected: Vec<(usize, S)> = Vec::new();
    let mut diagnostics: Vec<SuiteDiagnostic<'a>> = Vec::new();
    let mut default_tls13_prefix = 0;

    // Which lists to parse, in order. The C code expresses this with a
    // mutable `ciphers` pointer and a `goto`; the two-element worst case is
    // clearer as a list, and the cases it produces are identical.
    let mut passes: Vec<&'a str> = Vec::new();

    match ciphers13 {
        // "Add default TLSv1.3 ciphers to selection" (`rustls.c:425-440`).
        // Provider order, TLS 1.3 only, before anything the user asked for.
        None => {
            for (index, suite) in provider_suites.iter().enumerate() {
                if suite.is_tls13() {
                    selected.push((index, *suite));
                }
            }
            // `default13_count = count` (`rustls.c:436`), recorded before any
            // user spelling can add to the selection.
            default_tls13_prefix = selected.len();

            // `if(!ciphers) ciphers = "";` (`rustls.c:438-439`) -- the parse
            // still runs, over nothing.
            passes.push(ciphers12.unwrap_or(""));
        }
        // `else ciphers = ciphers13;` (`rustls.c:441-442`), then
        // `if(ciphers == ciphers13 && ciphers12)` (`rustls.c:478-481`) adds
        // the 1.2 list as a second pass. No defaults are inserted in this
        // case, so `default_tls13_prefix` stays 0 and every duplicate is
        // reportable.
        Some(explicit13) => {
            passes.push(explicit13);
            if let Some(explicit12) = ciphers12 {
                passes.push(explicit12);
            }
        }
    }

    'passes: for list in passes {
        for token in tokens(list) {
            // The `count < supported_len` half of the C loop condition
            // (`rustls.c:445`), checked before the token has any effect. It
            // can only bite once every provider suite is already selected,
            // and when it does it also stops further diagnostics -- as in C.
            if selected.len() >= supported_len {
                break 'passes;
            }

            // "Check if cipher is supported" (`rustls.c:448-457`): resolve the
            // spelling to an id, then find the provider entry offering it.
            // A spelling with no id and an id with no provider entry converge
            // on the same outcome, because C sets `id = 0` for the second.
            let resolved = token.id.and_then(|id| {
                provider_suites
                    .iter()
                    .position(|suite| suite.iana_id() == id)
            });

            let Some(index) = resolved else {
                // `if(ptr[0] != '\0')` (`rustls.c:459`). After the walk, that
                // condition is true exactly when the token is non-empty, so
                // the empty token a trailing separator produces is skipped in
                // silence rather than reported as an unknown cipher.
                if !token.text.is_empty() {
                    diagnostics.push(SuiteDiagnostic::Unknown(token.text));
                }
                continue;
            };

            // "No duplicates allowed (so selected cannot overflow)"
            // (`rustls.c:465-473`). First occurrence wins and keeps its
            // position; a repeat is never moved, promoted or counted twice.
            match selected.iter().position(|&(taken, _)| taken == index) {
                Some(hit) => {
                    if hit >= default_tls13_prefix {
                        diagnostics
                            .push(SuiteDiagnostic::Duplicate(token.text));
                    }
                }
                None => match provider_suites.get(index) {
                    // `position` returned this index from this slice, so the
                    // lookup always succeeds; `get` states that without
                    // asserting it.
                    Some(suite) => selected.push((index, *suite)),
                    None => continue,
                },
            }
        }
    }

    // "Add default TLSv1.2 ciphers to selection" (`rustls.c:483-499`): only
    // when the user never set `CURLOPT_SSL_CIPHER_LIST`, in provider order,
    // and never a suite already selected.
    if ciphers12.is_none() {
        for (index, suite) in provider_suites.iter().enumerate() {
            if suite.is_tls13() {
                continue;
            }
            if selected.iter().any(|&(taken, _)| taken == index) {
                continue;
            }
            selected.push((index, *suite));
        }
    }

    // `*selected_size = count;` (`rustls.c:501`). The emptiness check the C
    // caller then performs lives in `SuiteSelection::require_supported`,
    // because that is where C performs it too.
    SuiteSelection {
        suites: selected.into_iter().map(|(_, suite)| suite).collect(),
        diagnostics,
        default_tls13_prefix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One suite as the C unit test states it: `(IANA id, RFC spelling,
    /// OpenSSL spelling if the suite has one)`.
    type Spelling = (u16, &'static str, Option<&'static str>);

    /// Every spelling a rustls build recognises.
    ///
    /// Transcribed from `tests/unit/unit3205.c:40-60` -- the rows its table
    /// carries outside `#ifdef USE_MBEDTLS` -- and cross-checked against
    /// `lib/vtls/cipher_suite.c:161-179`. That C unit test cannot link against
    /// a Rust static library, because `pub(crate)` items are genuinely absent
    /// from its symbol table rather than merely hidden, so its coverage is
    /// relocated here. The two-line layout is the C file's own.
    #[rustfmt::skip]
    const SPELLINGS: &[Spelling] = &[
        (0x1301, "TLS_AES_128_GCM_SHA256", None),
        (0x1302, "TLS_AES_256_GCM_SHA384", None),
        (0x1303, "TLS_CHACHA20_POLY1305_SHA256", None),
        (0x1304, "TLS_AES_128_CCM_SHA256", None),
        (0x1305, "TLS_AES_128_CCM_8_SHA256", None),
        (0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                 Some("ECDHE-ECDSA-AES128-GCM-SHA256")),
        (0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                 Some("ECDHE-ECDSA-AES256-GCM-SHA384")),
        (0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                 Some("ECDHE-RSA-AES128-GCM-SHA256")),
        (0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                 Some("ECDHE-RSA-AES256-GCM-SHA384")),
        (0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                 Some("ECDHE-RSA-CHACHA20-POLY1305")),
        (0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                 Some("ECDHE-ECDSA-CHACHA20-POLY1305")),
    ];

    /// Spellings that resolve only when `USE_MBEDTLS` is defined, and must
    /// therefore resolve to nothing here.
    ///
    /// Taken from the `#else` arms of `tests/unit/unit3205.c:454-499`, which
    /// state the expectation as `{ 0x0000, "..." }` for exactly this build.
    /// This is the test that fails if the 200-odd mbedTLS rows of
    /// `cipher_suite.c:180-538` are ever imported: every one of these would
    /// start resolving to a real id that a rustls build cannot honour.
    #[rustfmt::skip]
    const MBEDTLS_ONLY: &[&str] = &[
        "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA256", "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES128-SHA", "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA384", "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-RSA-AES256-SHA", "DHE-RSA-AES128-SHA256",
        "DHE-RSA-AES256-SHA256", "AES128-GCM-SHA256", "AES256-GCM-SHA384",
        "AES128-SHA256", "AES256-SHA256", "AES128-SHA", "AES256-SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_PSK_WITH_AES_128_CCM_8", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    ];

    /// The list `tests/unit/unit3205.c:424-438` walks, transcribed verbatim
    /// including its tail of doubled colons and spaces.
    const WALK_LIST: &str = concat!(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:",
        "TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:",
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:",
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:",
        "ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:",
        "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:",
        "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:",
        "ECDHE-ECDSA-AES256-SHA384:",
        "ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:",
        "DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:",
        "AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:",
        "DES-CBC3-SHA:",
        ":: GIBBERISH ::",
    );

    /// What walking [`WALK_LIST`] must produce, from
    /// `tests/unit/unit3205.c:444-501` with every `#ifdef USE_MBEDTLS` arm
    /// resolved the way a rustls build resolves it.
    ///
    /// The last two rows are the point of the fixture: `GIBBERISH` is a token
    /// like any other, and the trailing `" ::"` produces one final **empty**
    /// token rather than none.
    #[rustfmt::skip]
    const WALK_FIXTURE: &[(u16, &str)] = &[
        (0x1301, "TLS_AES_128_GCM_SHA256"),
        (0x1302, "TLS_AES_256_GCM_SHA384"),
        (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
        (0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256"),
        (0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"),
        (0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384"),
        (0xC030, "ECDHE-RSA-AES256-GCM-SHA384"),
        (0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305"),
        (0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305"),
        (0x0000, "DHE-RSA-AES128-GCM-SHA256"),
        (0x0000, "DHE-RSA-AES256-GCM-SHA384"),
        (0x0000, "DHE-RSA-CHACHA20-POLY1305"),
        (0x0000, "ECDHE-ECDSA-AES128-SHA256"),
        (0x0000, "ECDHE-RSA-AES128-SHA256"),
        (0x0000, "ECDHE-ECDSA-AES128-SHA"),
        (0x0000, "ECDHE-RSA-AES128-SHA"),
        (0x0000, "ECDHE-ECDSA-AES256-SHA384"),
        (0x0000, "ECDHE-RSA-AES256-SHA384"),
        (0x0000, "ECDHE-ECDSA-AES256-SHA"),
        (0x0000, "ECDHE-RSA-AES256-SHA"),
        (0x0000, "DHE-RSA-AES128-SHA256"),
        (0x0000, "DHE-RSA-AES256-SHA256"),
        (0x0000, "AES128-GCM-SHA256"),
        (0x0000, "AES256-GCM-SHA384"),
        (0x0000, "AES128-SHA256"),
        (0x0000, "AES256-SHA256"),
        (0x0000, "AES128-SHA"),
        (0x0000, "AES256-SHA"),
        (0x0000, "DES-CBC3-SHA"),
        (0x0000, "GIBBERISH"),
        (0x0000, ""),
    ];

    /// One entry of a fake cryptographic provider's suite list.
    ///
    /// `rustls::SupportedCipherSuite` cannot be built in a test -- its two
    /// variants hold `&'static` references to values whose members are trait
    /// objects for HMAC, AEAD and PRF implementations -- so the selection flow
    /// is driven through [`ProviderCipherSuite`] instead. That is the whole
    /// reason the trait exists, and it is what makes the ClientHello suite
    /// *order* assertable without a TLS peer.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeSuite {
        id: u16,
        tls13: bool,
    }

    impl ProviderCipherSuite for FakeSuite {
        fn iana_id(&self) -> u16 {
            self.id
        }

        fn is_tls13(&self) -> bool {
            self.tls13
        }
    }

    /// A TLS 1.3 entry of a fake provider list.
    const fn tls13(id: u16) -> FakeSuite {
        FakeSuite { id, tls13: true }
    }

    /// A TLS 1.2 entry of a fake provider list.
    const fn tls12(id: u16) -> FakeSuite {
        FakeSuite { id, tls13: false }
    }

    /// The suite list of the pinned *ring* provider, in the provider's own
    /// order.
    ///
    /// Measured from `rustls-0.23.42/src/crypto/ring/mod.rs:68-89`, where
    /// `DEFAULT_CIPHER_SUITES` is `ALL_CIPHER_SUITES`: three TLS 1.3 suites,
    /// then six TLS 1.2 suites. The order is not alphabetical, not sorted by
    /// id and not curl's -- it is the provider's, and it reaches the
    /// ClientHello unchanged, which is why it is reproduced exactly here
    /// rather than tidied.
    ///
    /// Two ids in [`CS_LIST`] are deliberately absent: `0x1304` and `0x1305`,
    /// the two CCM suites, which *ring* does not implement. They are what
    /// "known spelling, unsupported by the provider" is tested with.
    #[rustfmt::skip]
    const RING_LIKE: &[FakeSuite] = &[
        tls13(0x1302), tls13(0x1301), tls13(0x1303),
        tls12(0xC02C), tls12(0xC02B), tls12(0xCCA9),
        tls12(0xC030), tls12(0xC02F), tls12(0xCCA8),
    ];

    /// The TLS 1.3 part of [`RING_LIKE`], in provider order.
    const DEFAULT_13: [u16; 3] = [0x1302, 0x1301, 0x1303];

    /// The TLS 1.2 part of [`RING_LIKE`], in provider order.
    const DEFAULT_12: [u16; 6] =
        [0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8];

    /// The selection [`RING_LIKE`] yields for the two options, as ids.
    fn selected(ciphers12: Option<&str>, ciphers13: Option<&str>) -> Vec<u16> {
        provider_suite_selection(ciphers12, ciphers13, RING_LIKE).ids()
    }

    /// The diagnostics [`RING_LIKE`] yields for the two options, rendered.
    fn reported(
        ciphers12: Option<&str>,
        ciphers13: Option<&str>,
    ) -> Vec<String> {
        provider_suite_selection(ciphers12, ciphers13, RING_LIKE)
            .diagnostics
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn every_rfc_spelling_resolves_to_its_id() {
        for &(id, rfc, _) in SPELLINGS {
            assert_eq!(lookup_id(rfc), Some(id), "lookup_id({rfc:?})");
        }
    }

    #[test]
    fn every_openssl_spelling_resolves_to_its_id() {
        let mut seen = 0;
        for &(id, _, openssl) in SPELLINGS {
            if let Some(openssl) = openssl {
                seen += 1;
                assert_eq!(lookup_id(openssl), Some(id), "{openssl:?}");
            }
        }
        // The five TLS 1.3 suites have no OpenSSL spelling; the six TLS 1.2
        // suites each have exactly one.
        assert_eq!(seen, 6);
    }

    #[test]
    fn lookup_ignores_ascii_case() {
        for &(id, rfc, openssl) in SPELLINGS {
            for spelling in [Some(rfc), openssl].into_iter().flatten() {
                assert_eq!(lookup_id(&spelling.to_lowercase()), Some(id));
                assert_eq!(lookup_id(&spelling.to_uppercase()), Some(id));

                // Alternating case, to prove the comparison is per byte and
                // not a lucky whole-string match against either extreme.
                let mixed: String = spelling
                    .chars()
                    .enumerate()
                    .map(|(index, c)| {
                        if index % 2 == 0 {
                            c.to_ascii_lowercase()
                        } else {
                            c.to_ascii_uppercase()
                        }
                    })
                    .collect();
                assert_eq!(lookup_id(&mixed), Some(id), "{mixed:?}");
            }
        }
    }

    #[test]
    fn separators_are_never_case_folded_into_each_other() {
        // Case insensitivity must not extend to the structure: the separator
        // is chosen from the spelling, so an IANA name written with hyphens
        // and an OpenSSL name written with underscores are both nothing.
        assert_eq!(lookup_id("TLS-AES-128-GCM-SHA256"), None);
        assert_eq!(lookup_id("tls-aes-128-gcm-sha256"), None);
        assert_eq!(lookup_id("ECDHE_RSA_AES128_GCM_SHA256"), None);
        assert_eq!(lookup_id("ecdhe_rsa_aes128_gcm_sha256"), None);
    }

    #[test]
    fn reverse_render_prefers_the_rfc_spelling() {
        for &(id, rfc, _) in SPELLINGS {
            assert_eq!(name(id, true), Some(rfc), "name({id:#06x}, true)");
            assert_eq!(get_str(id, true), rfc);
        }
    }

    #[test]
    fn reverse_render_prefers_openssl_and_falls_back_to_rfc() {
        for &(id, rfc, openssl) in SPELLINGS {
            // `cipher_suite.c:689-690`: with no OpenSSL spelling on record the
            // first row for the id wins, and for a TLS 1.3 suite that is the
            // RFC row.
            let expected = openssl.unwrap_or(rfc);
            assert_eq!(name(id, false), Some(expected), "{id:#06x}");
            assert_eq!(get_str(id, false), expected);
        }
    }

    #[test]
    fn mbedtls_only_spellings_are_not_recognised() {
        for spelling in MBEDTLS_ONLY {
            assert_eq!(lookup_id(spelling), None, "{spelling:?}");
        }
        // Recognised by neither backend, per `unit3205.c:500-501`.
        assert_eq!(lookup_id("DES-CBC3-SHA"), None);
        assert_eq!(lookup_id("GIBBERISH"), None);
    }

    #[test]
    fn mbedtls_only_ids_have_no_name() {
        // Ids the mbedTLS table would have named: `unit3205.c` expects
        // `TLS_UNKNOWN_*` for them in a rustls build.
        for id in [0x002F, 0x0035, 0x003C, 0x009C, 0x009D, 0xC009, 0xCCAA] {
            assert_eq!(name(id, true), None, "{id:#06x}");
            assert_eq!(name(id, false), None, "{id:#06x}");
        }
    }

    #[test]
    fn unknown_ids_render_the_exact_placeholder() {
        // `cipher_suite.c:697`: "TLS_UNKNOWN_0x%04x" -- lower case, four
        // digits, zero padded.
        assert_eq!(get_str(0x0000, true), "TLS_UNKNOWN_0x0000");
        assert_eq!(get_str(0x0000, false), "TLS_UNKNOWN_0x0000");
        assert_eq!(get_str(0x0001, true), "TLS_UNKNOWN_0x0001");
        assert_eq!(get_str(0x00FF, true), "TLS_UNKNOWN_0x00ff");
        assert_eq!(get_str(0xCCAA, true), "TLS_UNKNOWN_0xccaa");
        assert_eq!(get_str(0xABCD, true), "TLS_UNKNOWN_0xabcd");
        assert_eq!(get_str(0xFFFF, true), "TLS_UNKNOWN_0xffff");

        // Never upper case, and never fewer than four digits.
        let rendered = get_str(0x000A, true);
        assert_eq!(rendered, "TLS_UNKNOWN_0x000a");
        assert!(!rendered.contains('A'), "{rendered} must be lower case");
    }

    #[test]
    fn malformed_spellings_are_rejected() {
        for spelling in [
            "",
            "-",
            "_",
            "GIBBERISH",
            "TLS",
            "TLS_",
            "_TLS_AES_128_GCM_SHA256",
            "TLS__AES_128_GCM_SHA256",
            "TLS_AES_128_GCM_SHA256_",
            "TLS_AES_128_GCM_SHA256__",
            "-ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE--RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256-",
            "TLS_AES_128_GCM_SHA256_EXTRA",
            "ECDHE-RSA-AES128-GCM-SHA256-EXTRA",
            "TLS_AES_128_GCM",
            "ECDHE-RSA-AES128-GCM",
            " TLS_AES_128_GCM_SHA256",
            "TLS_AES_128_GCM_SHA256 ",
        ] {
            assert_eq!(lookup_id(spelling), None, "{spelling:?}");
        }
    }

    #[test]
    fn component_overflow_is_rejected() {
        // Eight components is the limit, and the longest real spelling uses
        // all eight (`cipher_suite.c:544`, `:557-558`).
        let eight = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        assert_eq!(eight.split('_').count(), MAX_COMPONENTS);
        assert_eq!(lookup_id(eight), Some(0xC02B));

        // A ninth component is rejected before it is even examined, so a
        // spelling whose first eight components are a perfect match still
        // resolves to nothing.
        let nine = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_SHA256";
        assert_eq!(nine.split('_').count(), MAX_COMPONENTS + 1);
        assert_eq!(lookup_id(nine), None);

        // Same rule on the OpenSSL side, and well past the limit too.
        assert_eq!(lookup_id("A-B-C-D-E-F-G-H-I"), None);
        assert_eq!(lookup_id("TLS_A_B_C_D_E_F_G_H_I_J_K"), None);
    }

    #[test]
    fn a_nul_terminates_a_spelling() {
        // `cipher_suite.c:562`, `:577`: NUL ends the scan, so trailing bytes
        // are not part of the spelling.
        assert_eq!(lookup_id("TLS_AES_128_GCM_SHA256\0EXTRA"), Some(0x1301));
        assert_eq!(lookup_id("ECDHE-RSA-AES128-GCM-SHA256\0-X"), Some(0xC02F));

        // A NUL inside a component truncates that component, which then
        // matches nothing.
        assert_eq!(lookup_id("TLS_AE\0S_128_GCM_SHA256"), None);
        assert_eq!(lookup_id("\0TLS_AES_128_GCM_SHA256"), None);

        // And it ends a list, exactly as it ends a spelling.
        let walked: Vec<&str> = tokens("TLS_AES_128_GCM_SHA256\0:GIBBERISH")
            .map(|token| token.text)
            .collect();
        assert_eq!(walked, ["TLS_AES_128_GCM_SHA256"]);
    }

    #[test]
    fn is_separator_matches_the_c_predicate() {
        // `cs_is_separator`, `cipher_suite.c:650-661`: exactly these five.
        for c in SEPARATORS {
            assert!(is_separator(c), "{c:?} must separate");
        }
        assert_eq!(SEPARATORS, [' ', '\t', ':', ',', ';']);

        // Everything a spelling is built from, and the near misses.
        for c in ['-', '_', 'A', 'z', '0', '.', '/', '|', '\n', '\r', '\0'] {
            assert!(!is_separator(c), "{c:?} must not separate");
        }
    }

    #[test]
    fn each_separator_splits_a_list() {
        for separator in SEPARATORS {
            let list = format!(
                "TLS_AES_128_GCM_SHA256{separator}ECDHE-RSA-AES128-GCM-SHA256"
            );
            let walked: Vec<Option<u16>> =
                tokens(&list).map(|token| token.id).collect();
            assert_eq!(
                walked,
                [Some(0x1301), Some(0xC02F)],
                "{separator:?} must separate two suites"
            );
        }
    }

    #[test]
    fn mixed_and_repeated_separators_split_a_list() {
        // Every separator at once, doubled, with leading and trailing runs.
        let list = concat!(
            " \t:TLS_AES_128_GCM_SHA256 ;TLS_AES_256_GCM_SHA384,,",
            "TLS_CHACHA20_POLY1305_SHA256\t;:ECDHE-RSA-AES128-GCM-SHA256",
        );
        let walked: Vec<Option<u16>> =
            tokens(list).map(|token| token.id).collect();
        assert_eq!(
            walked,
            [Some(0x1301), Some(0x1302), Some(0x1303), Some(0xC02F)]
        );

        // A run of separators between two suites is one boundary, not several
        // empty tokens (`cipher_suite.c:665-667`).
        let squeezed =
            tokens("TLS_AES_128_GCM_SHA256:::,, ;TLS_AES_256_GCM_SHA384")
                .count();
        assert_eq!(squeezed, 2);
    }

    #[test]
    fn an_empty_list_yields_no_token() {
        // The C loop tests `ptr[0] != '\0'` before the first walk.
        assert_eq!(tokens("").count(), 0);
        assert_eq!(tokens("\0").count(), 0);
        assert_eq!(tokens("\0:X").count(), 0);
    }

    #[test]
    fn a_list_of_separators_yields_one_empty_token() {
        // The walk consumes the separators and leaves the token empty; the
        // loop had already been entered. `unit3205.c` pins this with its
        // final `{ 0x0000, "" }` row.
        for list in [":", " ", "\t", ",", ";", ":::", " \t:,;"] {
            let walked: Vec<CipherSuiteToken<'_>> = tokens(list).collect();
            assert_eq!(walked.len(), 1, "{list:?}");
            assert_eq!(walked[0].text, "");
            assert_eq!(walked[0].id, None);
        }
    }

    #[test]
    fn a_trailing_separator_yields_a_final_empty_token() {
        let walked: Vec<&str> = tokens("TLS_AES_128_GCM_SHA256:")
            .map(|token| token.text)
            .collect();
        assert_eq!(walked, ["TLS_AES_128_GCM_SHA256", ""]);
    }

    #[test]
    fn tokens_retain_the_written_spelling() {
        // Diagnostics quote the user's own text (`rustls.c:460-461`), so the
        // slice must be the raw one -- not folded, trimmed or canonicalised.
        let list = "tls_aes_128_gcm_sha256:ECDHE-Rsa-AES128-GCM-SHA256:nope";
        let walked: Vec<(&str, Option<u16>)> =
            tokens(list).map(|token| (token.text, token.id)).collect();
        assert_eq!(
            walked,
            [
                ("tls_aes_128_gcm_sha256", Some(0x1301)),
                ("ECDHE-Rsa-AES128-GCM-SHA256", Some(0xC02F)),
                ("nope", None),
            ]
        );
    }

    #[test]
    fn the_c_unit_test_walk_fixture_is_reproduced() {
        let walked: Vec<(u16, &str)> = tokens(WALK_LIST)
            .map(|token| (token.id.unwrap_or(0), token.text))
            .collect();
        assert_eq!(walked, WALK_FIXTURE.to_vec());

        // `unit3205.c:602` also asserts no token exceeds the documented
        // buffer, which is how it proves the pointers stayed sane.
        for (_, text) in &walked {
            assert!(text.len() <= NAME_BUFFER_SIZE, "{text:?}");
        }
    }

    #[test]
    fn the_table_is_the_rustls_table() {
        // Seventeen rows: five TLS 1.3 with one spelling each, six TLS 1.2
        // with two (`cipher_suite.c:161-179`).
        assert_eq!(CS_LIST.len(), 17);
        assert_eq!(SPELLINGS.len(), 11);

        // Every row is one of the expected spellings, and every expected
        // spelling is a row. Neither direction alone would catch a stray row.
        for entry in CS_LIST {
            let known = SPELLINGS.iter().any(|&(id, rfc, openssl)| {
                id == entry.id
                    && (rfc == entry.name || openssl == Some(entry.name))
            });
            assert!(known, "unexpected row {:#06x} {}", entry.id, entry.name);
        }
        for &(id, rfc, openssl) in SPELLINGS {
            let rows: Vec<&'static str> = CS_LIST
                .iter()
                .filter(|entry| entry.id == id)
                .map(|entry| entry.name)
                .collect();
            let mut expected = vec![rfc];
            expected.extend(openssl);
            assert_eq!(rows, expected, "rows for {id:#06x}");
        }

        // Row order is behaviour: the RFC row must come first for every id,
        // because `name(id, false)` falls back to the first row it finds.
        for entry in CS_LIST {
            let first = CS_LIST.iter().find(|row| row.id == entry.id);
            assert!(
                first.is_some_and(CipherSuiteEntry::is_rfc),
                "the RFC row for {:#06x} must come first",
                entry.id
            );
        }

        // The spellings are the only things in this file that must be byte
        // exact, so they are checked as bytes.
        for entry in CS_LIST {
            assert!(
                entry.name.is_ascii() && !entry.name.is_empty(),
                "{} must be ASCII",
                entry.name
            );
            assert_eq!(
                entry.name.to_ascii_uppercase(),
                entry.name,
                "table spellings are upper case"
            );
            assert!(
                NameComponents::parse(entry.name).is_some(),
                "{} must be well formed",
                entry.name
            );
        }
    }

    #[test]
    fn name_buffer_size_holds_every_spelling() {
        // `cipher_suite.h:37-39` promises 64 suffices; the longest spelling is
        // 45 bytes, so the promise holds with room to spare.
        let longest = CS_LIST
            .iter()
            .map(|entry| entry.name.len())
            .max()
            .unwrap_or(0);
        assert_eq!(longest, 45);
        assert!(longest < NAME_BUFFER_SIZE);

        for entry in CS_LIST {
            let rendered = get_str_bounded(entry.id, true, NAME_BUFFER_SIZE);
            assert_eq!(rendered, get_str(entry.id, true), "{}", entry.name);
        }
    }

    #[test]
    fn bounded_rendering_truncates_like_the_c_buffer() {
        let full = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
        assert_eq!(full.len(), 45);

        // A buffer of `n` bytes holds `n - 1` bytes of text plus the NUL.
        assert_eq!(get_str_bounded(0xCCA9, true, 64), full);
        assert_eq!(get_str_bounded(0xCCA9, true, 46), full);
        assert_eq!(get_str_bounded(0xCCA9, true, 45), &full[..44]);
        assert_eq!(get_str_bounded(0xCCA9, true, 10), &full[..9]);
        assert_eq!(get_str_bounded(0xCCA9, true, 4), "TLS");
        assert_eq!(get_str_bounded(0xCCA9, true, 2), "T");
        assert_eq!(get_str_bounded(0xCCA9, true, 1), "");

        // `curl_msnprintf` with a size of 0 writes nothing at all, not even a
        // terminator (`lib/mprintf.c:1088`).
        assert_eq!(get_str_bounded(0xCCA9, true, 0), "");

        // Truncation keeps a prefix; it never reorders or re-spells.
        for size in 0..=full.len() + 2 {
            let rendered = get_str_bounded(0xCCA9, true, size);
            assert!(full.starts_with(rendered.as_ref()), "size {size}");
            assert!(rendered.len() < size.max(1), "size {size}");
        }
    }

    #[test]
    fn bounded_rendering_truncates_the_placeholder() {
        // The unknown form goes through the same buffer in C, so it truncates
        // the same way.
        assert_eq!(get_str_bounded(0xCCAA, true, 64), "TLS_UNKNOWN_0xccaa");
        assert_eq!(get_str_bounded(0xCCAA, true, 19), "TLS_UNKNOWN_0xccaa");
        assert_eq!(get_str_bounded(0xCCAA, true, 18), "TLS_UNKNOWN_0xcca");
        assert_eq!(get_str_bounded(0xCCAA, true, 13), "TLS_UNKNOWN_");
        assert_eq!(get_str_bounded(0xCCAA, true, 1), "");
        assert_eq!(get_str_bounded(0xCCAA, true, 0), "");
    }

    #[test]
    fn defaults_fill_both_ends_when_no_list_is_set() {
        // Neither option set: every provider suite, in provider order, TLS 1.3
        // defaults first (`rustls.c:425-440`, `:483-499`).
        let selection = provider_suite_selection(None, None, RING_LIKE);
        let mut expected = DEFAULT_13.to_vec();
        expected.extend(DEFAULT_12);
        assert_eq!(selection.ids(), expected);
        assert_eq!(selection.default_tls13_prefix, DEFAULT_13.len());
        assert!(selection.diagnostics.is_empty());
        assert_eq!(selection.suites.len(), RING_LIKE.len());
    }

    #[test]
    fn a_tls12_list_follows_the_default_tls13_prefix() {
        // TLS 1.3 defaults, then exactly what the user asked for, in the order
        // the user asked for it. No TLS 1.2 defaults are appended, because
        // `ciphers12` was set.
        let list =
            Some("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384");
        let selection = provider_suite_selection(list, None, RING_LIKE);
        assert_eq!(selection.ids(), [0x1302, 0x1301, 0x1303, 0xC02F, 0xC02C]);
        assert_eq!(selection.default_tls13_prefix, 3);
        assert!(selection.diagnostics.is_empty());
    }

    #[test]
    fn an_explicit_tls13_list_precedes_the_default_tls12_suffix() {
        // No prefix is inserted when `ciphers13` is set, and the TLS 1.2
        // defaults follow because `ciphers12` is not.
        let selection = provider_suite_selection(
            None,
            Some("TLS_AES_128_GCM_SHA256"),
            RING_LIKE,
        );
        let mut expected = vec![0x1301];
        expected.extend(DEFAULT_12);
        assert_eq!(selection.ids(), expected);
        assert_eq!(selection.default_tls13_prefix, 0);
        assert!(selection.diagnostics.is_empty());
    }

    #[test]
    fn both_lists_are_parsed_thirteen_then_twelve() {
        // `rustls.c:478-481`: the 1.3 list first, then the 1.2 list, and no
        // defaults at either end.
        let selection = provider_suite_selection(
            Some("ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256"),
            Some("TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"),
            RING_LIKE,
        );
        assert_eq!(selection.ids(), [0x1303, 0x1302, 0xCCA8, 0xC02B]);
        assert_eq!(selection.default_tls13_prefix, 0);
        assert!(selection.diagnostics.is_empty());
    }

    #[test]
    fn every_option_combination_is_covered() {
        // The four cases of the table in `select_provider_suites`, asserted as
        // shapes rather than as exact lists, so a change to any one of them
        // fails here even if the list above is edited.
        assert_eq!(selected(None, None).len(), RING_LIKE.len());
        assert_eq!(
            selected(Some("ECDHE-RSA-AES128-GCM-SHA256"), None).len(),
            4
        );
        assert_eq!(selected(None, Some("TLS_AES_128_GCM_SHA256")).len(), 7);
        assert_eq!(
            selected(
                Some("ECDHE-RSA-AES128-GCM-SHA256"),
                Some("TLS_AES_128_GCM_SHA256")
            )
            .len(),
            2
        );
    }

    #[test]
    fn duplicates_keep_first_occurrence_order() {
        // A repeat never moves, promotes or re-adds a suite
        // (`rustls.c:465-473`).
        let selection = provider_suite_selection(
            Some(
                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:\
                 ECDHE-RSA-AES256-GCM-SHA384",
            ),
            None,
            RING_LIKE,
        );
        assert_eq!(selection.ids(), [0x1302, 0x1301, 0x1303, 0xC030, 0xC02F]);

        // Both spellings of one suite are one suite.
        let selection = provider_suite_selection(
            Some(
                "ECDHE-RSA-AES128-GCM-SHA256:\
                 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ),
            None,
            RING_LIKE,
        );
        assert_eq!(selection.ids(), [0x1302, 0x1301, 0x1303, 0xC02F]);
    }

    #[test]
    fn duplicates_of_the_default_prefix_are_silent() {
        // `rustls.c:469`: a repeat inside the automatically inserted TLS 1.3
        // prefix is not the user writing something twice, so it is skipped
        // without a word.
        let selection = provider_suite_selection(
            Some("TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256"),
            None,
            RING_LIKE,
        );
        assert_eq!(selection.ids(), [0x1302, 0x1301, 0x1303, 0xC02F]);
        assert!(selection.diagnostics.is_empty(), "must stay silent");
    }

    #[test]
    fn explicit_duplicates_are_reported() {
        // With an explicit TLS 1.3 list there is no prefix, so
        // `default_tls13_prefix` is 0 and every repeat is reportable.
        let selection = provider_suite_selection(
            None,
            Some("TLS_AES_128_GCM_SHA256:TLS_AES_128_GCM_SHA256"),
            RING_LIKE,
        );
        let mut expected = vec![0x1301];
        expected.extend(DEFAULT_12);
        assert_eq!(selection.ids(), expected);
        assert_eq!(
            selection.diagnostics,
            [SuiteDiagnostic::Duplicate("TLS_AES_128_GCM_SHA256")]
        );

        // A repeat of a user-chosen TLS 1.2 suite is reported too, and the
        // report quotes the second spelling, not the first.
        let selection = provider_suite_selection(
            Some(
                "ECDHE-RSA-AES128-GCM-SHA256:\
                 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ),
            None,
            RING_LIKE,
        );
        assert_eq!(
            selection.diagnostics,
            [SuiteDiagnostic::Duplicate(
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            )]
        );
    }

    #[test]
    fn unknown_spellings_are_reported_with_their_text() {
        let selection = provider_suite_selection(
            Some("nope:ECDHE-RSA-AES128-GCM-SHA256:AES128-SHA:GIBBERISH"),
            None,
            RING_LIKE,
        );
        assert_eq!(selection.ids(), [0x1302, 0x1301, 0x1303, 0xC02F]);
        assert_eq!(
            selection.diagnostics,
            [
                SuiteDiagnostic::Unknown("nope"),
                SuiteDiagnostic::Unknown("AES128-SHA"),
                SuiteDiagnostic::Unknown("GIBBERISH"),
            ]
        );
        for diagnostic in &selection.diagnostics {
            assert!(!diagnostic.spelling().is_empty());
        }
    }

    #[test]
    fn provider_unsupported_ids_are_reported_as_unknown() {
        // 0x1304 and 0x1305 are real suites with real spellings that this
        // table knows -- and that *ring* does not implement.
        assert_eq!(lookup_id("TLS_AES_128_CCM_SHA256"), Some(0x1304));
        assert_eq!(lookup_id("TLS_AES_128_CCM_8_SHA256"), Some(0x1305));
        assert!(!RING_LIKE.iter().any(|suite| suite.id == 0x1304));

        // `rustls.c:455-456` overwrites the id with 0, so the message is the
        // same one an unrecognised spelling gets.
        let selection = provider_suite_selection(
            None,
            Some("TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"),
            RING_LIKE,
        );
        assert_eq!(selection.ids(), DEFAULT_12.to_vec());
        assert_eq!(
            selection.diagnostics,
            [
                SuiteDiagnostic::Unknown("TLS_AES_128_CCM_SHA256"),
                SuiteDiagnostic::Unknown("TLS_AES_128_CCM_8_SHA256"),
            ]
        );
    }

    #[test]
    fn an_empty_trailing_token_is_not_reported() {
        // `rustls.c:459` suppresses the diagnostic for the empty token that a
        // trailing separator produces, and only for that one.
        let trailing = reported(Some("ECDHE-RSA-AES128-GCM-SHA256:"), None);
        assert!(trailing.is_empty());
        assert!(reported(Some(":::"), None).is_empty());
        assert!(reported(Some(""), None).is_empty());
        assert_eq!(reported(Some("nope:"), None).len(), 1);
    }

    #[test]
    fn an_empty_selection_is_the_only_error() {
        // Both lists set and neither usable: nothing is left, and only then
        // does the C caller fail (`rustls.c:590-594`).
        let selection = provider_suite_selection(
            Some("GIBBERISH"),
            Some("TLS_AES_128_CCM_SHA256"),
            RING_LIKE,
        );
        assert!(selection.ids().is_empty());
        let error = selection
            .require_supported()
            .expect_err("an empty selection must fail");
        assert_eq!(error.code(), CURLcode::SslCipher);
        assert_eq!(error.message(), "rustls: no supported cipher in list");

        // The wrapper reports the same failure, and the diagnostics that
        // explain it are still reachable from the unwrapped selection.
        let failed = select_provider_suites(
            Some("GIBBERISH"),
            Some("TLS_AES_128_CCM_SHA256"),
            RING_LIKE,
        );
        assert!(failed.is_err());
        assert_eq!(
            reported(Some("GIBBERISH"), Some("TLS_AES_128_CCM_SHA256")).len(),
            2
        );

        // An empty provider list cannot select anything either.
        let empty: [FakeSuite; 0] = [];
        assert!(provider_suite_selection(None, None, &empty)
            .require_supported()
            .is_err());

        // But a list of nothing but rubbish still succeeds when a default
        // filled the selection -- C does not fail for that, and neither may
        // this.
        let survived =
            select_provider_suites(Some("GIBBERISH"), None, RING_LIKE)
                .expect("the TLS 1.3 defaults are still there");
        assert_eq!(survived.ids(), DEFAULT_13.to_vec());
        assert_eq!(
            survived.diagnostics,
            [SuiteDiagnostic::Unknown("GIBBERISH")]
        );
        assert!(survived.require_supported().is_ok());
    }

    #[test]
    fn the_selection_bound_is_the_provider_length() {
        // `rustls.c:445`: parsing stops once every provider suite is selected,
        // and stops reporting too. Here the whole provider list is named
        // explicitly, then one more spelling follows.
        let list =
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:\
                    ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:\
                    ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:\
                    GIBBERISH";
        let selection = provider_suite_selection(Some(list), None, RING_LIKE);
        assert_eq!(selection.suites.len(), RING_LIKE.len());
        assert!(
            selection.diagnostics.is_empty(),
            "the bound stops the walk before the last token"
        );
    }

    #[test]
    fn diagnostics_render_the_c_messages() {
        // `rustls.c:460-461` and `:470-471`, byte for byte, quotes included.
        assert_eq!(
            SuiteDiagnostic::Unknown("nope").to_string(),
            "rustls: unknown cipher in list: \"nope\""
        );
        assert_eq!(
            SuiteDiagnostic::Duplicate("AES128-SHA").to_string(),
            "rustls: duplicate cipher in list: \"AES128-SHA\""
        );
        assert_eq!(SuiteDiagnostic::Unknown("x").spelling(), "x");
        assert_eq!(SuiteDiagnostic::Duplicate("y").spelling(), "y");
        assert_eq!(
            reported(Some("nope"), None),
            ["rustls: unknown cipher in list: \"nope\""]
        );
    }

    #[test]
    fn the_pinned_provider_suites_map_through_the_trait() {
        // Reads the suite set the configured provider statically describes. It
        // installs nothing, builds no `CryptoProvider` and fetches no default,
        // which is what keeps this module provider-neutral.
        let provider: &[SupportedCipherSuite] =
            rustls::crypto::ring::DEFAULT_CIPHER_SUITES;

        let observed: Vec<(u16, bool)> = provider
            .iter()
            .map(|suite| (suite.iana_id(), suite.is_tls13()))
            .collect();
        let expected: Vec<(u16, bool)> =
            RING_LIKE.iter().map(|s| (s.id, s.tls13)).collect();
        assert_eq!(
            observed, expected,
            "the fake provider list must stay the measured one"
        );

        // Every suite the provider offers has a spelling in this table, in
        // both directions.
        for suite in provider {
            let id = suite.iana_id();
            let rfc = name(id, true).expect("provider suite must have a name");
            assert_eq!(lookup_id(rfc), Some(id));
            let openssl = get_str(id, false);
            assert_eq!(lookup_id(&openssl), Some(id));
        }

        // And the default selection over the real list is the real provider
        // order, which is what reaches the ClientHello.
        let selection = select_provider_suites(None, None, provider)
            .expect("the provider offers suites");
        let mut wire = DEFAULT_13.to_vec();
        wire.extend(DEFAULT_12);
        assert_eq!(selection.ids(), wire);
        assert_eq!(selection.default_tls13_prefix, 3);
    }

    #[test]
    fn a_tls12_suite_named_in_the_tls13_list_is_not_appended_twice() {
        // C never checks that a spelling belongs to the list's own TLS
        // version: `add_ciphers` resolves any spelling against the provider
        // list, so a TLS 1.2 suite written into `CURLOPT_TLS13_CIPHERS` is
        // selected there. The default TLS 1.2 suffix must then decline to
        // re-add it -- `if(j < count) continue;` (`rustls.c:493-497`) --
        // rather than emit it twice and change the ClientHello.
        let ids = selected(None, Some("ECDHE-RSA-AES128-GCM-SHA256"));

        // 0xC02F leads because it was named, and the defaults follow with
        // 0xC02F omitted. No TLS 1.3 suite appears at all: the TLS 1.3 list
        // was explicit, so no default prefix was inserted.
        assert_eq!(ids, [0xC02F, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xCCA8]);
        assert_eq!(ids.iter().filter(|&&id| id == 0xC02F).count(), 1);

        // The skip is silent. A suite the default suffix declines to repeat
        // is not a duplicate the user wrote, so nothing is reported.
        let notes = reported(None, Some("ECDHE-RSA-AES128-GCM-SHA256"));
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn the_real_provider_list_drives_the_token_loop() {
        // The same flow over `rustls::SupportedCipherSuite` rather than the
        // fake, so the monomorphisation the backend will instantiate is the
        // one under test: the token loop, the provider lookup, the duplicate
        // check and the unknown-spelling path, all with the real type.
        let provider: &[SupportedCipherSuite] =
            rustls::crypto::ring::DEFAULT_CIPHER_SUITES;

        let ciphers12 = concat!(
            "ECDHE-ECDSA-CHACHA20-POLY1305,",
            "ECDHE-RSA-AES256-GCM-SHA384;",
            "ECDHE-RSA-AES256-GCM-SHA384:GIBBERISH",
        );
        let ciphers13 = "TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_CCM_SHA256";

        let selection =
            select_provider_suites(Some(ciphers12), Some(ciphers13), provider)
                .expect("the lists name supported suites");

        // TLS 1.3 first, then TLS 1.2, each in written order. `0x1304` is a
        // real IANA name that *ring* does not implement and `GIBBERISH` is
        // not a name at all; both are skipped, and both are reported.
        assert_eq!(selection.ids(), [0x1303, 0xCCA9, 0xC030]);
        assert_eq!(selection.default_tls13_prefix, 0);

        let notes: Vec<String> = selection
            .diagnostics
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            notes,
            [
                "rustls: unknown cipher in list: \"TLS_AES_128_CCM_SHA256\"",
                concat!(
                    "rustls: duplicate cipher in list: ",
                    "\"ECDHE-RSA-AES256-GCM-SHA384\"",
                ),
                "rustls: unknown cipher in list: \"GIBBERISH\"",
            ]
        );
    }
}
