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

//! The base64 codec -- supersedes `lib/curlx/base64.c` (267 lines) and
//! `lib/curlx/base64.h` (41 lines).
//!
//! Three C entry points map onto three functions here, and the `curlx_`
//! prefix is dropped because a Rust module path already carries it:
//!
//! | C (`lib/curlx/base64.h:27-32`) | Here            |
//! |--------------------------------|-----------------|
//! | `curlx_base64_encode`          | [`encode`]      |
//! | `curlx_base64url_encode`       | [`url_encode`]  |
//! | `curlx_base64_decode`          | [`decode`]      |
//!
//! # Why every byte here is a frozen contract
//!
//! Nothing in this module is a private convenience. Its output leaves the
//! process on the wire in every one of these paths:
//!
//! * HTTP Basic, Digest, NTLM and Negotiate credentials and challenges
//!   (`lib/vauth/`, `lib/http_ntlm.c`, `lib/http_negotiate.c`).
//! * The `Sec-WebSocket-Key` request header and the `Sec-WebSocket-Accept`
//!   it is checked against (`lib/ws.c`).
//! * MIME part bodies under the `base64` transfer encoding (`lib/mime.c`).
//! * TLS certificate and public-key material (`lib/vtls/x509asn1.c`).
//! * The alt-svc and HSTS caches and the TLS session cache's serialised
//!   form (`lib/altsvc.c`, `lib/hsts.c`, `lib/vtls/vtls_scache.c`).
//!
//! 1,476 of the 1,914 fixtures under `tests/data/` carry a `<protocol>`
//! block, and the harness joins both sides into one string and compares
//! them whole (AAP 0.6.7). A codec that produced *valid* base64 rather than
//! *curl's* base64 would fail those fixtures without being wrong in any way
//! a specification would recognise, so the transcription below is
//! deliberately literal.
//!
//! The rejection behaviour is equally observable. A malformed
//! server-supplied token must yield `CURLE_BAD_CONTENT_ENCODING` and not a
//! different code and not a lenient parse, because callers compare against
//! that exact value.
//!
//! # Why the `base64` crate is not used
//!
//! `curl-rs-lib/Cargo.toml` does declare `base64 0.23.0`, so reaching for
//! it was the obvious first move. It was rejected on measurement, not on
//! taste: **curl does not require the unused trailing bits of the final
//! quantum to be zero.** The real `lib/curlx/base64.c` was compiled and
//! run, and it decodes `"AB=="` to a single `0x00` byte -- silently
//! discarding the four low bits `'B'` contributed. The crate's
//! canonical-padding decoders reject exactly that input as
//! `InvalidLastSymbol`.
//!
//! Two further inputs measured the same way: `"AAB="` and `"AAC="` both
//! decode to `[0x00, 0x00]`. Any of the three arriving from a server would
//! turn a transfer that curl 8.19.0-DEV completes into a failure. AAP 0.1.1
//! makes faithfulness the tie-breaker over every other consideration, so
//! the decoder is written out from the C rather than delegated.
//!
//! # The decoder's four rejections, and the one code they share
//!
//! Reading `lib/curlx/base64.c:60-163` there are exactly four ways in, and
//! all four leave through the same door -- `CURLE_BAD_CONTENT_ENCODING`,
//! which is [`CURLcode::BadContentEncoding`]:
//!
//! | # | Condition | C site |
//! |---|-----------|--------|
//! | a | empty input, or a length that is not a multiple of four | `:79-80` |
//! | b | more than two trailing `=` | `:83-89` |
//! | c | a symbol the lookup table calls invalid | `:116-117`, `:141-142` |
//! | d | a `=` inside the final quantum beyond the trailing run | `:135-137` |
//!
//! Splitting these into finer codes would be a behaviour change, which AAP
//! 0.8.2 prohibits, so they are not split.
//!
//! Rejection (a) is what makes canonical padding *mandatory* on input:
//! `"QQ"` is refused and `"QQ=="` accepted. Rejection (d) is the one a
//! naive implementation passes; `"A=B="` is the worked example, and
//! [`tests::a_misplaced_pad_is_rejected`] carries it.
//!
//! # base64url emits no padding at all
//!
//! `lib/curlx/base64.c:243-263` calls one static encoder twice, differing
//! in *two* arguments rather than one. The alphabet swap is the visible
//! difference; the padding byte is the consequential one. Standard
//! encoding passes `'='`, base64url passes `0`, and every pad write in the
//! encoder is guarded by `if(padbyte)` (`:202`, `:211`). A zero padding
//! byte therefore emits **nothing**: base64url output is unpadded and its
//! length is 2, 3 or 4 characters per quantum rather than always 4.
//!
//! Measured against the C: `url_encode(b"f")` is `"Zg"`, `url_encode(b"fo")`
//! is `"Zm8"`, and `url_encode(b"fooba")` is `"Zm9vYmE"`.
//!
//! # Divergences from the C, each deliberate
//!
//! * **Input length.** `curlx_base64_decode` takes a NUL-terminated
//!   `const char *` and calls `strlen`, so an embedded NUL truncates the
//!   input -- measured: `"QQ==\0QQ=="` decodes to one byte. [`decode`]
//!   takes a `&[u8]` and uses the slice's own length, because a Rust slice
//!   already carries it and no caller in the C tree passes an embedded NUL.
//!   No NUL scan is added: adding one would invent a rejection curl does
//!   not have.
//! * **No terminator.** The C allocates `rawlen + 1` and writes a NUL past
//!   the data (`:99`, `:153`), then reports `rawlen` separately. Here the
//!   `Vec` length *is* `rawlen` and there is no terminator. Nothing is lost
//!   -- the C's terminator is unreachable through the reported length.
//! * **No `goto bad`.** The C allocates before it validates and frees on
//!   the failure path (`:160-163`). Dropping a `Vec` does that, so the
//!   label has no counterpart.
//!
//! # Two stale comments in the C, recorded rather than reproduced
//!
//! Both were checked against the code rather than trusted:
//!
//! * `:57` says "When decoded data length is 0, returns NULL in `*outptr`."
//!   That is unreachable. Rejection (a) guarantees `srclen >= 4`, so
//!   `numQuantums >= 1` and `rawlen = numQuantums * 3 - padding >= 1`. No
//!   successful decode ever yields zero bytes, and no dead branch for it
//!   is written here.
//! * `:256` says "Input length of 0 indicates input buffer holds a
//!   null-terminated string." The code contradicts it two lines into the
//!   shared encoder: `if(!insize) return CURLE_OK;` (`:177-178`) returns
//!   immediately with an empty result. The measured behaviour is
//!   reproduced; the comment is not.
//!
//! # Visibility
//!
//! Everything is `pub(crate)`. `grep -i base64 lib/libcurl.def` finds
//! nothing: no exported libcurl symbol is backed from this file, so the
//! private-module / public-re-export idiom that `parsedate` and `strcase`
//! need does not apply, and AAP 0.8.7 forbids widening a surface merely so
//! that `tests/unit/unit1302.c` could link against it. That fixture's
//! coverage is relocated into [`tests`] below instead, which is where the
//! `@unittest: 1302` annotation on all three C functions now leads.

use crate::error::CURLcode;

/// The standard base64 alphabet: RFC 4648 section 4.
///
/// Transcribed from `curlx_base64encdec` (`lib/curlx/base64.c:32-33`). The
/// C spells it `extern` rather than `static` and `lib/curlx/base64.h:34`
/// declares it, because `lib/mime.c:376-379` and `:403-406` index it
/// directly: the MIME encoder streams base64 a quantum at a time instead of
/// calling the whole-buffer function, so it needs the alphabet and not the
/// codec. `pub(crate)` here for that consumer, `crate::mime`.
///
/// The type is `&[u8; 64]`, so a transcription of the wrong length is a
/// compile error rather than a test failure.
pub(crate) const BASE64_ENCDEC: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The URL and filename safe alphabet: RFC 4648 section 5.
///
/// Transcribed from `base64url` (`lib/curlx/base64.c:37-38`), which the C
/// spells `static`. It is written out in full rather than derived from
/// [`BASE64_ENCDEC`] by replacing the last two entries, even though the two
/// differ *only* at indices 62 and 63 -- `+/` against `-_`. Both are
/// wire-bearing, and a table built at run time from another table can be
/// corrupted by a refactor that looks harmless; two literals cannot.
///
/// The relationship is asserted rather than assumed:
/// [`tests::the_two_alphabets_differ_only_in_their_last_two_entries`].
pub(crate) const BASE64_URL: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The largest input [`encode`] and [`url_encode`] accept, in bytes.
///
/// `CURL_MAX_BASE64_INPUT` (`lib/curlx/base64.h:36-38`), whose comment is
/// its whole rationale: "maximum input length acceptable to base64 encode,
/// here to catch and prevent mistakes."
///
/// A decimal round number and deliberately *not* a power of two, so it is
/// written with digit separators that keep it readable as 16 million and
/// pinned by [`tests::the_input_cap_is_the_c_headers_decimal_constant`].
///
/// **The cap applies to encoding only.** `curlx_base64_decode` has no
/// equivalent check anywhere in its 103 lines, and adding one here would
/// reject input that curl 8.19.0-DEV accepts --
/// [`tests::decode_has_no_length_cap`] pins that asymmetry.
pub(crate) const CURL_MAX_BASE64_INPUT: usize = 16_000_000;

/// The lookup value that marks a byte as not a base64 symbol.
///
/// `lib/curlx/base64.c:105` fills all 256 entries with `0xff` before
/// copying the real values over part of the range, and `:116` and `:141`
/// both test `val == 0xff`. It is a sentinel inside the table's own value
/// space, which works because the alphabet only ever needs `0..=63`.
const INVALID_SYMBOL: u8 = 0xff;

/// The byte the seed table below starts at.
///
/// `lib/curlx/base64.c:106` is `memcpy(&lookup['+'], decodetable,
/// sizeof(decodetable))`, so the seed lands at the index of `+`. The value
/// is written as a literal because `usize::from` is not a `const fn` and
/// this is needed during const evaluation; the equivalence is proven by
/// [`tests::the_seed_lands_where_the_c_memcpy_puts_it`] rather than left to
/// the reader.
const FIRST_SYMBOL: usize = 43;

/// The 80 values `lib/curlx/base64.c:40-46` copies into the lookup table.
///
/// Transcribed verbatim, keeping the C's 16-values-per-row grouping so the
/// two can be read side by side, with each row annotated by the span of
/// input bytes it covers. `#[rustfmt::skip]` is not cosmetic: this table is
/// wire-bearing, and a formatter that reflowed it would destroy the only
/// property that makes the transcription reviewable.
///
/// Reading the rows against the byte values they land on:
///
/// * `'+'` is 62 and `'/'` is 63 -- the two entries base64url replaces.
/// * `'0'..='9'` are 52..=61, `'A'..='Z'` are 0..=25, `'a'..='z'` are
///   26..=51.
/// * `','`, `'-'` and `'.'` are invalid, which is why a base64url *string*
///   cannot be decoded here. The C has no base64url decoder and none is
///   added: that would be an addition, not a migration.
/// * **`'='` (0x3d) is invalid**, and that single entry is what makes
///   rejection (d) work. `=` is only ever legal in the final quantum, where
///   a separate branch handles it before the table is consulted; anywhere
///   else the table refuses it. Transcribing this entry as `0` would
///   silently accept `"A=B="`.
#[rustfmt::skip]
const DECODE_TABLE_SEED: [u8; 80] = [
    /* '+' ..= ':' */
    62,  255, 255, 255, 63,  52,  53, 54, 55, 56, 57, 58, 59, 60, 61, 255,
    /* ';' ..= 'J' */
    255, 255, 255, 255, 255, 255, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
    /* 'K' ..= 'Z' */
    10,  11,  12,  13,  14,  15,  16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    /* '[' ..= 'j' */
    255, 255, 255, 255, 255, 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    /* 'k' ..= 'z' */
    36,  37,  38,  39,  40,  41,  42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
];

/// Builds the 256-entry lookup at compile time.
///
/// Reproduces `lib/curlx/base64.c:105-106` exactly -- fill with
/// [`INVALID_SYMBOL`], then overlay [`DECODE_TABLE_SEED`] starting at
/// [`FIRST_SYMBOL`]. The C rebuilds this on the stack on *every* call to
/// `curlx_base64_decode`; doing it once in a `const fn` is the one place
/// this module differs from the C for a reason other than faithfulness, and
/// it changes no observable behaviour because the table is a pure function
/// of two constants.
///
/// Const evaluation also makes the bound a compile-time proof: the highest
/// index written is `43 + 79 = 122`, and an out-of-range write in a `const`
/// initialiser fails the build rather than the test suite.
const fn build_decode_table() -> [u8; 256] {
    let mut table = [INVALID_SYMBOL; 256];
    let mut index = 0;

    while index < DECODE_TABLE_SEED.len() {
        table[FIRST_SYMBOL + index] = DECODE_TABLE_SEED[index];
        index += 1;
    }

    table
}

/// Every byte's base64 value, or [`INVALID_SYMBOL`] when it has none.
///
/// The 256-entry `lookup` of `lib/curlx/base64.c:72`. Indexing it with any
/// `u8` widened to `usize` is total by construction, which is what lets
/// [`decode`] read attacker-controlled bytes without a bound check and
/// without a panic path.
const DECODE_TABLE: [u8; 256] = build_decode_table();

/// Appends one alphabet symbol to `out`.
///
/// `index` is always in `0..=63` because every caller masks or shifts it
/// into six bits, so the lookup cannot leave the alphabet -- the four
/// expressions are the C's own, at `lib/curlx/base64.c:190-193`,
/// `:199-201` and `:209-210`.
///
/// The symbol becomes a `char` through `From<u8> for char`, which is
/// infallible, and every alphabet entry is ASCII
/// ([`tests::both_alphabets_are_ascii`]), so exactly one byte is appended
/// per call. That is what makes [`encode`]'s `String` length equal the C's
/// `outlen` and what removes any fallible conversion from the encoder.
fn push_symbol(out: &mut String, alphabet: &[u8; 64], index: u8) {
    out.push(char::from(alphabet[usize::from(index)]));
}

/// The encoder both public entry points share.
///
/// Supersedes the static `base64_encode` (`lib/curlx/base64.c:165-226`),
/// whose two variable arguments are the two parameters here: `alphabet` is
/// the C's `table64` and `pad` is its `padbyte`, with `None` standing for
/// the C's `0`.
///
/// Modelling the padding byte as an `Option<u8>` rather than a `u8` is the
/// one shape change, and it is made because the C's zero is not a padding
/// character -- it is a flag meaning "emit none", tested by `if(padbyte)`
/// at `:202` and `:211`. `Option` says that in the type, so neither call
/// site can accidentally emit a NUL byte onto the wire.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] when `input` is longer than
/// [`CURL_MAX_BASE64_INPUT`]. That is the only error this function can
/// return: `curl_easy_setopt`-style validation happens in the caller, and
/// the C's `CURLE_OUT_OF_MEMORY` arm (`:186-187`) has no counterpart
/// because a failed Rust allocation aborts rather than returning.
fn encode_with(
    alphabet: &[u8; 64],
    pad: Option<u8>,
    input: &[u8],
) -> Result<String, CURLcode> {
    // `if(!insize) return CURLE_OK;` (:177-178). Empty input is SUCCESS,
    // not an error: the C reports it as a NULL pointer with length zero, so
    // a caller can tell "nothing to encode" from "encoding failed". An
    // empty `String` says the same thing without a second channel.
    if input.is_empty() {
        return Ok(String::new());
    }

    // The C pairs a debug-build assertion with a release-build check
    // (:181-183) rather than choosing one. Both are kept: the assertion
    // fires in this crate's own test and Miri runs and names the caller
    // that over-fed the encoder, and the check is what a release build
    // returns.
    debug_assert!(
        input.len() <= CURL_MAX_BASE64_INPUT,
        "base64 encode input exceeds CURL_MAX_BASE64_INPUT"
    );
    if input.len() > CURL_MAX_BASE64_INPUT {
        return Err(CURLcode::TooLarge);
    }

    // The C's `(insize + 2) / 3 * 4 + 1` (:185), less the `+ 1` that
    // reserved room for the terminator this module does not write.
    // `div_ceil` is the same quantum count spelled without the manual
    // rounding, and `saturating_mul` cannot saturate here because the cap
    // above bounds the product at 21,333,336 -- it is written that way so
    // the expression is total on its own terms rather than on the reader's
    // memory of a check twenty lines up.
    let capacity = input.len().div_ceil(3).saturating_mul(4);
    let mut out = String::with_capacity(capacity);

    // `while(insize >= 3)` (:189-196). `chunks_exact(3)` yields precisely
    // the groups that loop visits, and `remainder()` is precisely the
    // one or two bytes it leaves behind, so the two branches below are the
    // C's two branches and not a re-derivation of them.
    let mut groups = input.chunks_exact(3);

    for group in groups.by_ref() {
        // `chunks_exact(3)` guarantees a length of exactly three, so these
        // are the same three reads the C makes through `in[0]`, `in[1]`
        // and `in[2]`. Every index handed to `push_symbol` is masked or
        // shifted into six bits, so none can leave the 64-entry alphabet.
        push_symbol(&mut out, alphabet, group[0] >> 2);
        push_symbol(
            &mut out,
            alphabet,
            ((group[0] & 0x03) << 4) | (group[1] >> 4),
        );
        push_symbol(
            &mut out,
            alphabet,
            ((group[1] & 0x0f) << 2) | ((group[2] & 0xc0) >> 6),
        );
        push_symbol(&mut out, alphabet, group[2] & 0x3f);
    }

    // `if(insize)` (:197-214): one or two bytes are left, never three.
    let tail = groups.remainder();

    if let Some(&first) = tail.first() {
        push_symbol(&mut out, alphabet, first >> 2);

        match tail.get(1) {
            // `insize == 1` (:200-206): one symbol carrying the low two
            // bits, then TWO padding characters when padding is enabled.
            None => {
                push_symbol(&mut out, alphabet, (first & 0x03) << 4);
                if let Some(byte) = pad {
                    out.push(char::from(byte));
                    out.push(char::from(byte));
                }
            }
            // `insize == 2` (:207-213): two more symbols, then ONE padding
            // character when padding is enabled.
            Some(&second) => {
                push_symbol(
                    &mut out,
                    alphabet,
                    ((first & 0x03) << 4) | ((second & 0xf0) >> 4),
                );
                push_symbol(&mut out, alphabet, (second & 0x0f) << 2);
                if let Some(byte) = pad {
                    out.push(char::from(byte));
                }
            }
        }
    }

    Ok(out)
}

/// Encodes `input` with the standard alphabet and `=` padding.
///
/// Supersedes `curlx_base64_encode` (`lib/curlx/base64.c:241-246`), which
/// is `base64_encode(curlx_base64encdec, '=', ...)` and nothing else.
///
/// The result is always ASCII, so the `String` needs no validation and its
/// `len()` is the C's `outlen` -- the count that *excludes* the terminator
/// the C writes (`:223`).
///
/// An empty input yields an empty string and `Ok`, matching the C exactly:
/// this is not an error condition. See [`encode_with`] for why.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] when `input` exceeds [`CURL_MAX_BASE64_INPUT`].
///
/// # Examples
///
/// The RFC 4648 section 10 vectors, which are also
/// [`tests::the_rfc_4648_test_vectors_encode_and_decode`]:
///
/// ```text
/// encode(b"")       == Ok(String::new())
/// encode(b"f")      == Ok("Zg==".to_owned())
/// encode(b"fo")     == Ok("Zm8=".to_owned())
/// encode(b"foo")    == Ok("Zm9v".to_owned())
/// encode(b"foob")   == Ok("Zm9vYg==".to_owned())
/// encode(b"fooba")  == Ok("Zm9vYmE=".to_owned())
/// encode(b"foobar") == Ok("Zm9vYmFy".to_owned())
/// ```
// Every consumer of this codec is a later unit of work -- `auth/{basic,
// digest,ntlm,negotiate}`, `protocols/ws`, `mime`, `tls/session_cache`,
// `cookies/{altsvc,hsts}` -- so the allowance is written at the item, and
// removing it once the first of them lands restores the warning for
// anything still unused. A module- or crate-level attribute would instead
// silence the next unreferenced item somebody adds; `src/lib.rs`
// (`mod source_policy`) enforces that distinction as a test.
#[allow(dead_code)]
pub(crate) fn encode(input: &[u8]) -> Result<String, CURLcode> {
    encode_with(BASE64_ENCDEC, Some(b'='), input)
}

/// Encodes `input` with the URL and filename safe alphabet, **unpadded**.
///
/// Supersedes `curlx_base64url_encode` (`lib/curlx/base64.c:263-267`),
/// which is `base64_encode(base64url, 0, ...)`. The `0` is the whole
/// difference beyond the alphabet, and it means no `=` is ever appended --
/// see the module documentation. Output length is therefore
/// `input.len().div_ceil(3) * 4` minus one or two characters when the last
/// quantum is short, not always a multiple of four.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] when `input` exceeds [`CURL_MAX_BASE64_INPUT`].
///
/// # Examples
///
/// Measured against the C, including the two alphabet entries that differ:
///
/// ```text
/// url_encode(b"f")            == Ok("Zg".to_owned())
/// url_encode(b"fo")           == Ok("Zm8".to_owned())
/// url_encode(b"foo")          == Ok("Zm9v".to_owned())
/// url_encode(&[0xfb, 0xff])   == Ok("-_8".to_owned())
/// url_encode(&[0xff, 0xef])   == Ok("_-8".to_owned())
/// ```
// See the note on [`encode`]: the consumers are later units of work.
// `protocols/ws` reaches this one first, for `Sec-WebSocket-Key`.
#[allow(dead_code)]
pub(crate) fn url_encode(input: &[u8]) -> Result<String, CURLcode> {
    encode_with(BASE64_URL, None, input)
}

/// Decodes standard base64, requiring canonical padding.
///
/// Supersedes `curlx_base64_decode` (`lib/curlx/base64.c:61-163`),
/// transliterated branch for branch. The four rejections and the single
/// code they share are tabulated in the module documentation; the two
/// properties most easily lost in translation are repeated here because
/// they decide whether real traffic works:
///
/// * **Canonical padding is mandatory.** A length that is not a multiple of
///   four is refused, so `"QQ"` fails where `"QQ=="` succeeds. This is not
///   RFC 4648's permissive reading -- it is what curl does.
/// * **Non-canonical trailing bits are accepted.** The unused low bits of
///   the final quantum are *not* required to be zero, so `"AB=="` decodes
///   to `[0x00]` and `"AAB="` to `[0x00, 0x00]`. The `base64` crate rejects
///   both; see the module documentation for why that ruled the crate out.
///
/// There is **no** base64url decoder. The C has none, `-` and `_` are
/// invalid symbols in the table, and adding one would be a behaviour
/// addition rather than a migration.
///
/// The returned `Vec`'s length is the C's `rawlen`, computed the C's way as
/// `quantums * 3 - padding` (`:96`) rather than counted from the bytes that
/// happened to be written -- and then cross-checked against them.
///
/// # Errors
///
/// [`CURLcode::BadContentEncoding`], and only that, for every malformed
/// input. Callers match on this exact value.
///
/// # Examples
///
/// ```text
/// decode(b"Zm9vYmFy") == Ok(b"foobar".to_vec())
/// decode(b"Zm8=")     == Ok(b"fo".to_vec())
/// decode(b"AB==")     == Ok(vec![0x00])
/// decode(b"A=B=")     == Err(CURLcode::BadContentEncoding)
/// decode(b"QQ")       == Err(CURLcode::BadContentEncoding)
/// ```
// See the note on [`encode`]: `auth/{basic,digest,ntlm,negotiate}`,
// `protocols/ws`, `tls/session_cache` and `cookies/{altsvc,hsts}` are the
// consumers, and each is a later unit of work.
#[allow(dead_code)]
pub(crate) fn decode(input: &[u8]) -> Result<Vec<u8>, CURLcode> {
    // Rejection (a), `if(!srclen || srclen % 4)` (:79-80). The C reaches
    // this length through `strlen`; here it is the slice's own, which is
    // the one divergence the module documentation records.
    if input.is_empty() || input.len() % 4 != 0 {
        return Err(CURLcode::BadContentEncoding);
    }

    // Rejection (b), `while(src[srclen - 1 - padding] == '=')` (:83-89).
    // Walking a reversed iterator instead of indexing backwards is the same
    // walk with no arithmetic to underflow: the C's index is safe only
    // because the loop returns at three, and stating the bound in the
    // iterator rather than in a comment removes the obligation to prove it.
    let mut padding = 0usize;
    for &byte in input.iter().rev() {
        if byte != b'=' {
            break;
        }
        padding += 1;
        // "A maximum of two = padding characters is allowed" (:86-88).
        if padding > 2 {
            return Err(CURLcode::BadContentEncoding);
        }
    }

    // `:92-96`. `full_quantums` excludes the final quantum exactly when
    // there is padding to handle there, and `raw_len` is the C's own
    // expression -- not the number of bytes pushed below, which is
    // separately asserted to agree with it.
    let num_quantums = input.len() / 4;
    let full_quantums = num_quantums - usize::from(padding != 0);
    let raw_len = num_quantums * 3 - padding;

    let mut out = Vec::with_capacity(raw_len);

    for (index, quantum) in input.chunks_exact(4).enumerate() {
        if padding != 0 && index == full_quantums {
            // The final, padded quantum: `if(padding)` (:125-150). Either
            // 8 or 16 bits of output.
            let mut accumulator = 0u32;
            let mut pads_seen = 0usize;

            for &symbol in quantum {
                if symbol == b'=' {
                    // `x <<= 6` (:133): six zero bits, so the padding
                    // contributes to the shift but not to the value.
                    accumulator <<= 6;
                    pads_seen += 1;
                    // Rejection (d), `if(++padc > padding)` (:135-137).
                    // More `=` inside this quantum than the trailing run
                    // accounted for means one of them is misplaced -- the
                    // case that makes `"A=B="` invalid.
                    if pads_seen > padding {
                        return Err(CURLcode::BadContentEncoding);
                    }
                } else {
                    let value = DECODE_TABLE[usize::from(symbol)];
                    // Rejection (c), `if(val == 0xff)` (:141-142).
                    if value == INVALID_SYMBOL {
                        return Err(CURLcode::BadContentEncoding);
                    }
                    accumulator = (accumulator << 6) | u32::from(value);
                }
            }

            // `:146-149`. The C writes `pos[1]` only for a single pad and
            // `pos[0]` always, then advances by `3 - padding`. Taking the
            // big-endian bytes of the accumulator names the same three
            // shifts without a cast: element 1 is `(x >> 16) & 0xff` and
            // element 2 is `(x >> 8) & 0xff`.
            let [_, high, middle, _] = accumulator.to_be_bytes();
            out.push(high);
            if padding == 1 {
                out.push(middle);
            }
        } else {
            // A complete quantum: `:109-124`. Three bytes out of four
            // symbols, with no `=` permitted -- the table rejects it here,
            // which is what makes `"AA=A"` and `"=AAA"` invalid.
            let mut accumulator = 0u32;

            for &symbol in quantum {
                // Indexing a 256-entry table with a `u8` widened to
                // `usize` is total: every possible byte has an entry, so
                // hostile input cannot leave the table and there is no
                // bound check to get wrong.
                let value = DECODE_TABLE[usize::from(symbol)];
                if value == INVALID_SYMBOL {
                    return Err(CURLcode::BadContentEncoding);
                }
                accumulator = (accumulator << 6) | u32::from(value);
            }

            // `pos[0..3]` at `:120-122`, in ascending order. Only 24 bits
            // are ever set, so element 0 of the big-endian form is always
            // zero and the remaining three are the payload.
            let [_, high, middle, low] = accumulator.to_be_bytes();
            out.extend_from_slice(&[high, middle, low]);
        }
    }

    // The C's `rawlen` and the bytes actually written must agree:
    // `full_quantums * 3 + (3 - padding)` collapses to
    // `num_quantums * 3 - padding` for every padding in `0..=2`. Asserted
    // rather than assumed, in the same spirit as the C's own DEBUGASSERT.
    debug_assert_eq!(
        out.len(),
        raw_len,
        "decoded length disagrees with the C's rawlen expression"
    );

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        decode, encode, url_encode, BASE64_ENCDEC, BASE64_URL,
        CURL_MAX_BASE64_INPUT, DECODE_TABLE, DECODE_TABLE_SEED, FIRST_SYMBOL,
        INVALID_SYMBOL,
    };
    use crate::error::CURLcode;

    /// The single code every malformed input must produce.
    const BAD: CURLcode = CURLcode::BadContentEncoding;

    /// `curlx_base64_encode` of every one of the 256 single-byte inputs.
    ///
    /// Measured from the real `lib/curlx/base64.c`, compiled verbatim with
    /// only its two `#include` lines removed and the allocator, assertion
    /// and result-code macros supplied. Each row covers sixteen consecutive
    /// byte values at four characters each, so row `r` column `c` is the
    /// encoding of byte `r * 16 + c`.
    ///
    /// This table is exhaustive over something that matters more than its
    /// size suggests: `in[0] >> 2` ranges over all of `0..=63` as the input
    /// byte ranges over `0..=255`, so these 256 rows exercise **every entry
    /// of the alphabet**, including indices 62 and 63 -- visible as `+A==`
    /// and `/A==` at the end of the last row.
    const ORACLE_ONE_BYTE_STD: [&str; 16] = [
        "AA==AQ==Ag==Aw==BA==BQ==Bg==Bw==CA==CQ==Cg==Cw==DA==DQ==Dg==Dw==",
        "EA==EQ==Eg==Ew==FA==FQ==Fg==Fw==GA==GQ==Gg==Gw==HA==HQ==Hg==Hw==",
        "IA==IQ==Ig==Iw==JA==JQ==Jg==Jw==KA==KQ==Kg==Kw==LA==LQ==Lg==Lw==",
        "MA==MQ==Mg==Mw==NA==NQ==Ng==Nw==OA==OQ==Og==Ow==PA==PQ==Pg==Pw==",
        "QA==QQ==Qg==Qw==RA==RQ==Rg==Rw==SA==SQ==Sg==Sw==TA==TQ==Tg==Tw==",
        "UA==UQ==Ug==Uw==VA==VQ==Vg==Vw==WA==WQ==Wg==Ww==XA==XQ==Xg==Xw==",
        "YA==YQ==Yg==Yw==ZA==ZQ==Zg==Zw==aA==aQ==ag==aw==bA==bQ==bg==bw==",
        "cA==cQ==cg==cw==dA==dQ==dg==dw==eA==eQ==eg==ew==fA==fQ==fg==fw==",
        "gA==gQ==gg==gw==hA==hQ==hg==hw==iA==iQ==ig==iw==jA==jQ==jg==jw==",
        "kA==kQ==kg==kw==lA==lQ==lg==lw==mA==mQ==mg==mw==nA==nQ==ng==nw==",
        "oA==oQ==og==ow==pA==pQ==pg==pw==qA==qQ==qg==qw==rA==rQ==rg==rw==",
        "sA==sQ==sg==sw==tA==tQ==tg==tw==uA==uQ==ug==uw==vA==vQ==vg==vw==",
        "wA==wQ==wg==ww==xA==xQ==xg==xw==yA==yQ==yg==yw==zA==zQ==zg==zw==",
        "0A==0Q==0g==0w==1A==1Q==1g==1w==2A==2Q==2g==2w==3A==3Q==3g==3w==",
        "4A==4Q==4g==4w==5A==5Q==5g==5w==6A==6Q==6g==6w==7A==7Q==7g==7w==",
        "8A==8Q==8g==8w==9A==9Q==9g==9w==+A==+Q==+g==+w==/A==/Q==/g==/w==",
    ];

    /// `curlx_base64url_encode` of every one of the 256 single-byte inputs.
    ///
    /// Measured the same way as [`ORACLE_ONE_BYTE_STD`], sixteen byte
    /// values per row at **two** characters each rather than four -- which
    /// is this table's real subject. A single input byte is one short
    /// quantum, so the standard encoder emits two symbols and two `=` while
    /// base64url emits the two symbols and stops. The row lengths are the
    /// proof that no padding is written.
    ///
    /// The last row ends `-A-Q-g-w_A_Q_g_w`, which is where the two
    /// alphabets part company: indices 62 and 63 are `-` and `_` here where
    /// [`ORACLE_ONE_BYTE_STD`] has `+` and `/`.
    const ORACLE_ONE_BYTE_URL: [&str; 16] = [
        "AAAQAgAwBABQBgBwCACQCgCwDADQDgDw",
        "EAEQEgEwFAFQFgFwGAGQGgGwHAHQHgHw",
        "IAIQIgIwJAJQJgJwKAKQKgKwLALQLgLw",
        "MAMQMgMwNANQNgNwOAOQOgOwPAPQPgPw",
        "QAQQQgQwRARQRgRwSASQSgSwTATQTgTw",
        "UAUQUgUwVAVQVgVwWAWQWgWwXAXQXgXw",
        "YAYQYgYwZAZQZgZwaAaQagawbAbQbgbw",
        "cAcQcgcwdAdQdgdweAeQegewfAfQfgfw",
        "gAgQgggwhAhQhghwiAiQigiwjAjQjgjw",
        "kAkQkgkwlAlQlglwmAmQmgmwnAnQngnw",
        "oAoQogowpApQpgpwqAqQqgqwrArQrgrw",
        "sAsQsgswtAtQtgtwuAuQuguwvAvQvgvw",
        "wAwQwgwwxAxQxgxwyAyQygywzAzQzgzw",
        "0A0Q0g0w1A1Q1g1w2A2Q2g2w3A3Q3g3w",
        "4A4Q4g4w5A5Q5g5w6A6Q6g6w7A7Q7g7w",
        "8A8Q8g8w9A9Q9g9w-A-Q-g-w_A_Q_g_w",
    ];

    /// The `encode[]` table of `tests/unit/unit1302.c:43-60`.
    ///
    /// Relocated rather than rewritten. The C rows carry an input string
    /// and a separate `ilen`, and the encoder is handed the first `ilen`
    /// bytes; here the slice is already that prefix, which is the same call
    /// with the truncation done by the reader instead of at run time.
    const UNIT1302_ENCODE: [(&[u8], &str); 16] = [
        (b"i", "aQ=="),
        (b"ii", "aWk="),
        (b"iii", "aWlp"),
        (b"iiii", "aWlpaQ=="),
        (b"iiiii", "aWlpaWk="),
        (b"iiiiii", "aWlpaWlp"),
        (b"iiiiiii", "aWlpaWlpaQ=="),
        (b"iiiiiiii", "aWlpaWlpaWk="),
        (b"iiiiiiiii", "aWlpaWlpaWlp"),
        (b"iiiiiiiiii", "aWlpaWlpaWlpaQ=="),
        (b"iiiiiiiiiii", "aWlpaWlpaWlpaWk="),
        (b"iiiiiiiiiiii", "aWlpaWlpaWlpaWlp"),
        (b"\xff\x01\xfe\x02", "/wH+Ag=="),
        (b"\xff\xff\xff\xff", "/////w=="),
        (b"\x00\x00\x00\x00", "AAAAAA=="),
        (b"\x00", "AA=="),
    ];

    /// The `url[]` table of `tests/unit/unit1302.c:63-99`.
    ///
    /// All 35 rows, relocated the same way. The seventeen single-byte rows
    /// at the end are the C's own exhaustive sweep of `0x00..=0x10`, kept
    /// because they pin the two-character unpadded shape at every one of
    /// those values rather than only at a sample.
    const UNIT1302_URL: [(&[u8], &str); 35] = [
        (b"", ""),
        (b"i", "aQ"),
        (b"ii", "aWk"),
        (b"iii", "aWlp"),
        (b"iiii", "aWlpaQ"),
        (b"iiiii", "aWlpaWk"),
        (b"iiiiii", "aWlpaWlp"),
        (b"iiiiiii", "aWlpaWlpaQ"),
        (b"iiiiiiii", "aWlpaWlpaWk"),
        (b"iiiiiiiii", "aWlpaWlpaWlp"),
        (b"iiiiiiiiii", "aWlpaWlpaWlpaQ"),
        (b"iiiiiiiiiii", "aWlpaWlpaWlpaWk"),
        (b"iiiiiiiiiiii", "aWlpaWlpaWlpaWlp"),
        (b"\xff\x01\xfe\x02", "_wH-Ag"),
        (b"\xff\xff\xff\xff", "_____w"),
        (b"\xff\x00\xff\x00", "_wD_AA"),
        (b"\x00\xff\x00\xff", "AP8A_w"),
        (b"\x00\x00\x00\x00", "AAAAAA"),
        (b"\x00", "AA"),
        (b"\x01", "AQ"),
        (b"\x02", "Ag"),
        (b"\x03", "Aw"),
        (b"\x04", "BA"),
        (b"\x05", "BQ"),
        (b"\x06", "Bg"),
        (b"\x07", "Bw"),
        (b"\x08", "CA"),
        (b"\x09", "CQ"),
        (b"\x0a", "Cg"),
        (b"\x0b", "Cw"),
        (b"\x0c", "DA"),
        (b"\x0d", "DQ"),
        (b"\x0e", "Dg"),
        (b"\x0f", "Dw"),
        (b"\x10", "EA"),
    ];

    /// The `badecode[]` table of `tests/unit/unit1302.c:102-125`.
    ///
    /// Relocated with the C's own comments carried across as the second
    /// column, because they name *which* of the four rejections each row
    /// exercises and that is what makes the table a specification rather
    /// than a list. The C passes only the string -- its numeric fields are
    /// unused on this path, since `curlx_base64_decode` takes a
    /// NUL-terminated pointer -- so only the string is reproduced.
    ///
    /// Note the four identical `====` rows in the C, which differ only in
    /// an unused length field. They are kept as one row here; keeping four
    /// copies would suggest four distinct cases that do not exist.
    const UNIT1302_BAD_DECODE: [(&[u8], &str); 19] = [
        (b"", "no data means error"),
        (b"a", "data is too short"),
        (b"aQ", "data is too short"),
        (b"aQ=", "data is too short"),
        (b"====", "data is only padding characters"),
        (b"a===", "contains three padding characters"),
        (b"a=Q=", "contains a padding character mid input"),
        (b"aWlpa=Q=", "contains a padding character mid input"),
        (b"a\x1f==", "contains illegal base64 character"),
        (b"abcd ", "contains illegal base64 character"),
        (b"abcd  ", "contains illegal base64 character"),
        (b" abcd", "contains illegal base64 character"),
        (b"_abcd", "contains illegal base64 character"),
        (b"abcd-", "contains illegal base64 character"),
        (b"abcd_", "contains illegal base64 character"),
        (b"aWlpaWlpaQ==-", "bad character after padding"),
        (b"aWlpaWlpaQ==_", "bad character after padding"),
        (b"aWlpaWlpaQ== ", "bad character after padding"),
        (b"aWlpaWlpaQ=", "unaligned size, missing a padding char"),
    ];

    /// The base64 value of `byte`, derived from the ALPHABET rather than
    /// from [`DECODE_TABLE_SEED`].
    ///
    /// This is the independence that makes
    /// [`the_decode_table_is_the_alphabets_exact_inverse`] worth running: a
    /// mistyped digit anywhere in the 80-entry seed produces a table that
    /// disagrees with this function, whereas a check written against the
    /// seed itself would agree with the typo.
    fn value_from_the_alphabet(byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => INVALID_SYMBOL,
        }
    }

    /// A deterministic byte sequence for the round-trip sweeps.
    ///
    /// A 64-bit xorshift rather than a crate: the sweeps need coverage that
    /// does not repeat every few bytes and they need to be reproducible, and
    /// nothing here needs statistical quality. Seeding it per test keeps
    /// each one independent of the order the harness runs them in.
    fn pseudo_random(length: usize, mut state: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(length);
        while out.len() < length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(length);
        out
    }

    // ----------------------------------------------------------------
    // The constants, and the transcription of the two wire-bearing tables
    // ----------------------------------------------------------------

    #[test]
    fn the_input_cap_is_the_c_headers_decimal_constant() {
        assert_eq!(CURL_MAX_BASE64_INPUT, 16_000_000);
        // Stated negatively as well, because a plausible mistranscription
        // is the nearby power of two rather than a random digit.
        assert_ne!(CURL_MAX_BASE64_INPUT, 1 << 24);
        assert_ne!(CURL_MAX_BASE64_INPUT, 16 * 1024 * 1024);
    }

    #[test]
    fn both_alphabets_are_ascii() {
        // The guarantee that lets the encoder build a `String` with no
        // fallible conversion and with one byte appended per symbol.
        for (index, &byte) in BASE64_ENCDEC.iter().enumerate() {
            assert!(byte.is_ascii(), "standard index {index} is not ASCII");
            assert!(byte.is_ascii_graphic(), "standard index {index}");
        }
        for (index, &byte) in BASE64_URL.iter().enumerate() {
            assert!(byte.is_ascii(), "url index {index} is not ASCII");
            assert!(byte.is_ascii_graphic(), "url index {index}");
        }
    }

    #[test]
    fn the_two_alphabets_differ_only_in_their_last_two_entries() {
        // The length is in the type -- both are `&[u8; 64]` -- so a wrong
        // transcription length is a compile error. Asserted anyway so the
        // count appears where a reader looks for it.
        assert_eq!(BASE64_ENCDEC.len(), 64);
        assert_eq!(BASE64_URL.len(), 64);

        assert_eq!(&BASE64_ENCDEC[..62], &BASE64_URL[..62]);
        assert_eq!(&BASE64_ENCDEC[62..], b"+/");
        assert_eq!(&BASE64_URL[62..], b"-_");
    }

    #[test]
    fn neither_alphabet_repeats_a_symbol() {
        // A duplicate would make the codec lossy in a way no round-trip
        // over short inputs would necessarily reveal.
        for alphabet in [BASE64_ENCDEC, BASE64_URL] {
            let mut seen = [false; 256];
            for &byte in alphabet {
                assert!(
                    !seen[usize::from(byte)],
                    "symbol {byte:#04x} appears twice"
                );
                seen[usize::from(byte)] = true;
            }
            assert_eq!(seen.iter().filter(|&&hit| hit).count(), 64);
        }
    }

    #[test]
    fn the_seed_lands_where_the_c_memcpy_puts_it() {
        // `memcpy(&lookup['+'], decodetable, sizeof(decodetable))`
        // (lib/curlx/base64.c:106). `FIRST_SYMBOL` is written as a literal
        // because `usize::from` is not a `const fn`; this is the proof that
        // the literal is the right one.
        assert_eq!(FIRST_SYMBOL, usize::from(b'+'));
        assert_eq!(FIRST_SYMBOL, 43);
        assert_eq!(DECODE_TABLE_SEED.len(), 80);
        // The span the copy covers: '+' through 'z' inclusive.
        assert_eq!(FIRST_SYMBOL + DECODE_TABLE_SEED.len() - 1, 122);
        assert_eq!(
            FIRST_SYMBOL + DECODE_TABLE_SEED.len() - 1,
            usize::from(b'z')
        );
    }

    #[test]
    fn the_decode_table_is_the_alphabets_exact_inverse() {
        // Derived from the alphabet, not from the seed, so a mistyped seed
        // digit fails here instead of agreeing with itself.
        for index in 0u8..=255 {
            assert_eq!(
                DECODE_TABLE[usize::from(index)],
                value_from_the_alphabet(index),
                "table entry for byte {index:#04x}"
            );
        }

        // And the round trip in the other direction: every alphabet symbol
        // decodes back to its own index.
        for (index, &symbol) in BASE64_ENCDEC.iter().enumerate() {
            assert_eq!(
                usize::from(DECODE_TABLE[usize::from(symbol)]),
                index,
                "symbol {} does not invert",
                char::from(symbol)
            );
        }
    }

    #[test]
    fn the_decode_table_admits_exactly_sixty_four_symbols() {
        let valid = DECODE_TABLE
            .iter()
            .filter(|&&value| value != INVALID_SYMBOL)
            .count();
        assert_eq!(valid, 64, "the table must admit the alphabet and no more");

        // Every admitted value is a six-bit index, and every index is
        // admitted exactly once.
        let mut produced = [0usize; 64];
        for &value in &DECODE_TABLE {
            if value != INVALID_SYMBOL {
                assert!(value < 64);
                produced[usize::from(value)] += 1;
            }
        }
        assert!(produced.iter().all(|&count| count == 1));
    }

    #[test]
    fn the_pad_character_is_an_invalid_symbol() {
        // The single table entry that makes rejection (d) work. Written as
        // its own test because transcribing it as 0 would leave every other
        // assertion in this module passing while `"A=B="` silently decoded.
        assert_eq!(DECODE_TABLE[usize::from(b'=')], INVALID_SYMBOL);
        assert_eq!(usize::from(b'='), 0x3d);
    }

    #[test]
    fn the_url_only_symbols_are_invalid_for_decoding() {
        // There is no base64url decoder in the C and none here, so the two
        // symbols unique to that alphabet must be refused.
        assert_eq!(DECODE_TABLE[usize::from(b'-')], INVALID_SYMBOL);
        assert_eq!(DECODE_TABLE[usize::from(b'_')], INVALID_SYMBOL);
    }

    #[test]
    fn every_byte_outside_the_seed_span_is_invalid() {
        let span = FIRST_SYMBOL..FIRST_SYMBOL + DECODE_TABLE_SEED.len();
        for (index, &value) in DECODE_TABLE.iter().enumerate() {
            if !span.contains(&index) {
                assert_eq!(value, INVALID_SYMBOL, "byte {index:#04x}");
            }
        }
        // Every byte with the high bit set, called out separately because
        // this is the class hostile input reaches for.
        for (index, &value) in DECODE_TABLE.iter().enumerate().skip(0x80) {
            assert_eq!(value, INVALID_SYMBOL, "high byte {index:#04x}");
        }
    }

    #[test]
    fn the_spot_checks_from_the_c_lookup_dump_hold() {
        // Read straight off a dump of the C's own `lookup` array.
        assert_eq!(DECODE_TABLE[usize::from(b'A')], 0);
        assert_eq!(DECODE_TABLE[usize::from(b'Z')], 25);
        assert_eq!(DECODE_TABLE[usize::from(b'a')], 26);
        assert_eq!(DECODE_TABLE[usize::from(b'z')], 51);
        assert_eq!(DECODE_TABLE[usize::from(b'0')], 52);
        assert_eq!(DECODE_TABLE[usize::from(b'9')], 61);
        assert_eq!(DECODE_TABLE[usize::from(b'+')], 62);
        assert_eq!(DECODE_TABLE[usize::from(b'/')], 63);
        assert_eq!(DECODE_TABLE[0x80], INVALID_SYMBOL);
        // The three punctuation bytes adjacent to '+' and '/'.
        assert_eq!(DECODE_TABLE[usize::from(b',')], INVALID_SYMBOL);
        assert_eq!(DECODE_TABLE[usize::from(b'.')], INVALID_SYMBOL);
        // The seven bytes between '9' and 'A', and the six between 'Z' and
        // 'a', which the seed marks invalid as contiguous runs.
        for byte in b':'..=b'@' {
            assert_eq!(DECODE_TABLE[usize::from(byte)], INVALID_SYMBOL);
        }
        for byte in b'['..=b'`' {
            assert_eq!(DECODE_TABLE[usize::from(byte)], INVALID_SYMBOL);
        }
    }

    #[test]
    fn the_two_reachable_error_codes_hold_their_c_integers() {
        // This module can produce exactly two codes, and a caller compares
        // against their numbers rather than their names (AAP 0.6.1).
        assert_eq!(BAD.as_i32(), 61);
        assert_eq!(CURLcode::TooLarge.as_i32(), 100);
        assert_eq!(BAD.c_name(), "CURLE_BAD_CONTENT_ENCODING");
        assert_eq!(CURLcode::TooLarge.c_name(), "CURLE_TOO_LARGE");
    }

    // ----------------------------------------------------------------
    // Encoding
    // ----------------------------------------------------------------

    #[test]
    fn an_empty_encode_is_success_not_an_error() {
        // `if(!insize) return CURLE_OK;` (lib/curlx/base64.c:177-178). The
        // C reports a NULL pointer and a zero length, which a caller must
        // be able to distinguish from a failure.
        assert_eq!(encode(b""), Ok(String::new()));
        assert_eq!(url_encode(b""), Ok(String::new()));
    }

    #[test]
    fn the_rfc_4648_test_vectors_encode_and_decode() {
        const VECTORS: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];

        for (plain, encoded) in VECTORS {
            assert_eq!(
                encode(plain).as_deref(),
                Ok(encoded),
                "encoding {plain:?}"
            );
            if !plain.is_empty() {
                assert_eq!(
                    decode(encoded.as_bytes()).as_deref(),
                    Ok(plain),
                    "decoding {encoded:?}"
                );
            }
        }
    }

    #[test]
    fn unit1302_encode_rows_are_reproduced() {
        // tests/unit/unit1302.c:127-164, which encodes each row and then
        // decodes the expected output back to the input. Both halves are
        // kept, because the second is what catches an encoder and a decoder
        // that agree with each other and with nothing else.
        for (plain, encoded) in UNIT1302_ENCODE {
            let produced = encode(plain).expect("a row within the cap");
            assert_eq!(produced, encoded, "encoding {plain:?}");
            assert_eq!(produced.len(), encoded.len());
            assert_eq!(
                decode(encoded.as_bytes()).as_deref(),
                Ok(plain),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn unit1302_url_rows_are_reproduced() {
        // tests/unit/unit1302.c:166-183. The decode half is absent from
        // the C for these rows and is absent here for the same reason:
        // there is no base64url decoder.
        for (plain, encoded) in UNIT1302_URL {
            let produced = url_encode(plain).expect("a row within the cap");
            assert_eq!(produced, encoded, "url encoding {plain:?}");
            assert_eq!(produced.len(), encoded.len());
        }
    }

    #[test]
    fn base64url_output_carries_no_padding() {
        // The difference most easily missed: `padbyte` is 0, and every pad
        // write is guarded by `if(padbyte)`.
        assert_eq!(url_encode(b"f").as_deref(), Ok("Zg"));
        assert_eq!(url_encode(b"fo").as_deref(), Ok("Zm8"));
        assert_eq!(url_encode(b"foo").as_deref(), Ok("Zm9v"));
        assert_eq!(url_encode(b"foob").as_deref(), Ok("Zm9vYg"));
        assert_eq!(url_encode(b"fooba").as_deref(), Ok("Zm9vYmE"));
        assert_eq!(url_encode(b"foobar").as_deref(), Ok("Zm9vYmFy"));

        // And exhaustively over a range of lengths: no '=' ever appears,
        // and no NUL either -- a zero `padbyte` must emit nothing at all
        // rather than a zero byte.
        for length in 0usize..=64 {
            let input = pseudo_random(length, 0x5eed_0001);
            let produced = url_encode(&input).expect("within the cap");
            assert!(!produced.contains('='), "padding leaked at {length}");
            assert!(!produced.contains('\0'), "a NUL pad leaked at {length}");
            assert_eq!(
                produced.len(),
                length * 4 / 3 + usize::from(length % 3 != 0)
            );
        }
    }

    #[test]
    fn the_url_alphabet_replaces_plus_and_slash() {
        // Inputs chosen so the encoding reaches alphabet indices 62 and 63,
        // measured against the C.
        assert_eq!(encode(&[0xfb, 0xff]).as_deref(), Ok("+/8="));
        assert_eq!(url_encode(&[0xfb, 0xff]).as_deref(), Ok("-_8"));
        assert_eq!(encode(&[0xff, 0xef]).as_deref(), Ok("/+8="));
        assert_eq!(url_encode(&[0xff, 0xef]).as_deref(), Ok("_-8"));
        assert_eq!(
            encode(&[0xff, 0x01, 0xfe, 0x02]).as_deref(),
            Ok("/wH+Ag==")
        );
        assert_eq!(
            url_encode(&[0xff, 0x01, 0xfe, 0x02]).as_deref(),
            Ok("_wH-Ag")
        );
    }

    #[test]
    fn every_single_byte_encodes_exactly_as_the_c_does() {
        // Exhaustive over the input space, and therefore exhaustive over
        // the alphabet: see [`ORACLE_ONE_BYTE_STD`].
        for (row, &standard) in ORACLE_ONE_BYTE_STD.iter().enumerate() {
            assert_eq!(standard.len(), 64, "row {row} is the wrong width");
            let unpadded = ORACLE_ONE_BYTE_URL[row];
            assert_eq!(unpadded.len(), 32, "url row {row} is the wrong width");

            for column in 0..16usize {
                let byte = u8::try_from(row * 16 + column)
                    .expect("row and column stay inside a byte");

                let expected = &standard[column * 4..column * 4 + 4];
                assert_eq!(
                    encode(&[byte]).as_deref(),
                    Ok(expected),
                    "standard encoding of {byte:#04x}"
                );

                let expected_url = &unpadded[column * 2..column * 2 + 2];
                assert_eq!(
                    url_encode(&[byte]).as_deref(),
                    Ok(expected_url),
                    "url encoding of {byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn the_encoded_length_is_the_c_outlen_expression() {
        // `(size_t)(output - base64data)` (lib/curlx/base64.c:223), which
        // excludes the terminator the C writes past it.
        for length in 0usize..=96 {
            let input = pseudo_random(length, 0x5eed_0002);

            let standard = encode(&input).expect("within the cap");
            // The C's `(insize + 2) / 3 * 4`, spelled with `div_ceil` so it
            // reads as the quantum count it is.
            let expected = length.div_ceil(3) * 4;
            assert_eq!(standard.len(), expected, "standard length at {length}");

            // Every byte of the output is ASCII, so the character count and
            // the byte count agree -- the property the `String` return type
            // rests on.
            assert_eq!(standard.chars().count(), standard.len());
            assert!(standard.is_ascii());
        }
    }

    // TWO BUILD MODES, TWO ASSERTIONS. The C pairs a `DEBUGASSERT` with a
    // release-build check rather than choosing one
    // (`lib/curlx/base64.c:181-183`), so it behaves differently in each mode
    // and a single test could only ever check one of them. `cargo test`
    // builds with `debug_assertions` on and an oversized input panics;
    // `cargo test --release` builds with it off and the same input returns
    // `CURLE_TOO_LARGE`. The convention for splitting a pair like this is
    // already settled in this directory -- see the note above `mod tests` in
    // `util/mod.rs` -- and both halves must run for the cap to have been
    // checked completely:
    //
    //     cargo test -p curl-rs-lib
    //     cargo test -p curl-rs-lib --release

    #[test]
    #[should_panic(expected = "CURL_MAX_BASE64_INPUT")]
    #[cfg(debug_assertions)]
    #[cfg_attr(miri, ignore = "allocates 16 MB to stand past the limit")]
    fn one_byte_past_the_cap_trips_the_debug_assertion() {
        let oversized = vec![0u8; CURL_MAX_BASE64_INPUT + 1];
        let _ = encode(&oversized);
    }

    #[test]
    #[should_panic(expected = "CURL_MAX_BASE64_INPUT")]
    #[cfg(debug_assertions)]
    #[cfg_attr(miri, ignore = "allocates 16 MB to stand past the limit")]
    fn one_byte_past_the_cap_trips_the_assertion_for_base64url_too() {
        // The cap lives in the shared encoder, so both entry points reach
        // it. Asserted for both because a future refactor that moved the
        // check into `encode` alone would leave `url_encode` uncapped.
        let oversized = vec![0u8; CURL_MAX_BASE64_INPUT + 1];
        let _ = url_encode(&oversized);
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn one_byte_past_the_cap_returns_too_large() {
        // The comparison is `>`, so the limit itself is accepted and the
        // next byte is not; the accepting side is
        // [`the_input_cap_accepts_the_limit_itself`], which runs in both
        // modes.
        let oversized = vec![0u8; CURL_MAX_BASE64_INPUT + 1];
        assert_eq!(encode(&oversized), Err(CURLcode::TooLarge));
        assert_eq!(url_encode(&oversized), Err(CURLcode::TooLarge));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "allocates 16 MB in and 21 MB out; the boundary either \
                  side is covered by cheaper tests"
    )]
    fn the_input_cap_accepts_the_limit_itself() {
        // 16 MB in, 21,333,336 characters out. Allocated for real rather
        // than reasoned about, because an off-by-one in the comparison is
        // exactly the defect this is looking for. The debug assertion in
        // `encode_with` also runs here, so a `>=` typo would trip it.
        let at_limit = vec![0u8; CURL_MAX_BASE64_INPUT];
        let produced = encode(&at_limit).expect("the limit itself is accepted");
        assert_eq!(produced.len(), CURL_MAX_BASE64_INPUT.div_ceil(3) * 4);
        assert_eq!(produced.len(), 21_333_336);
        // 16,000,000 is 3 * 5,333,333 + 1, so the last quantum is a single
        // zero byte and the output ends in the one-byte-tail form.
        assert!(produced.ends_with("AA=="));
    }

    // ----------------------------------------------------------------
    // Decoding: the four rejections, each with its exact code
    // ----------------------------------------------------------------

    #[test]
    fn rejection_a_empty_or_unaligned_input() {
        // `if(!srclen || srclen % 4)` (lib/curlx/base64.c:79-80). Canonical
        // padding is mandatory on input as a direct consequence.
        assert_eq!(decode(b""), Err(BAD));
        assert_eq!(decode(b"Q"), Err(BAD));
        assert_eq!(decode(b"QQ"), Err(BAD));
        assert_eq!(decode(b"QQQ"), Err(BAD));
        assert_eq!(decode(b"QQQQQ"), Err(BAD));
        assert_eq!(decode(b"QQQQQQ"), Err(BAD));
        assert_eq!(decode(b"QQQQQQQ"), Err(BAD));
        // Accepted for contrast: the same payload, padded.
        assert_eq!(decode(b"QQ==").as_deref(), Ok(&b"A"[..]));

        // And exhaustively over every length that is not a multiple of four,
        // using a string made only of valid symbols so the length is the
        // only thing wrong with it.
        for length in 1usize..=64 {
            let candidate = vec![b'A'; length];
            let outcome = decode(&candidate);
            if length % 4 == 0 {
                assert!(outcome.is_ok(), "length {length} should decode");
            } else {
                assert_eq!(outcome, Err(BAD), "length {length}");
            }
        }
    }

    #[test]
    fn rejection_b_more_than_two_trailing_pads() {
        // "A maximum of two = padding characters is allowed"
        // (lib/curlx/base64.c:86-88).
        assert_eq!(decode(b"===="), Err(BAD));
        assert_eq!(decode(b"A==="), Err(BAD));
        assert_eq!(decode(b"AAAA===="), Err(BAD));
        assert_eq!(decode(b"AAAAA==="), Err(BAD));
        // Two is the most that is allowed, so these must succeed.
        assert!(decode(b"AA==").is_ok());
        assert!(decode(b"AAA=").is_ok());
        assert!(decode(b"AAAAAA==").is_ok());
        assert!(decode(b"AAAAAAA=").is_ok());
    }

    #[test]
    fn rejection_c_an_invalid_symbol_anywhere() {
        // `if(val == 0xff)` (lib/curlx/base64.c:116-117 and :141-142).
        assert_eq!(decode(b"QQ!Q"), Err(BAD));
        assert_eq!(decode(b"!QQQ"), Err(BAD));
        assert_eq!(decode(b"QQQ!"), Err(BAD));
        assert_eq!(decode(&[b'Q', b'Q', 0x80, b'Q']), Err(BAD));
        assert_eq!(decode(&[b'Q', b'Q', 0xff, b'Q']), Err(BAD));
        assert_eq!(decode(&[0x00, b'Q', b'Q', b'Q']), Err(BAD));
        // A '=' outside the trailing run is an invalid SYMBOL rather than
        // misplaced padding, because `padding` is zero for these: the last
        // byte is not '=', so the whole input is read as full quantums and
        // the table refuses the '='.
        assert_eq!(decode(b"AA=A"), Err(BAD));
        assert_eq!(decode(b"=AAA"), Err(BAD));
        assert_eq!(decode(b"A=AA"), Err(BAD));

        // Exhaustively: substituting any single byte into any one of the four
        // positions of a valid quantum succeeds if and only if the decode
        // table admits that byte -- with ONE exception, and turning that
        // exception up is why the sweep is exhaustive rather than sampled.
        // `'='` is invalid in the table, yet `"AAA="` decodes: the trailing
        // pad count is taken before the table is ever consulted (:83-89), so
        // in the final position alone a `'='` is padding rather than a
        // symbol. That is the entirety of the position-dependence in this
        // decoder, and it is stated here rather than left as a gap.
        for position in 0usize..4 {
            for candidate in 0u8..=255 {
                let mut quantum = *b"AAAA";
                quantum[position] = candidate;
                let admitted =
                    DECODE_TABLE[usize::from(candidate)] != INVALID_SYMBOL;
                let trailing_pad = candidate == b'=' && position == 3;
                assert_eq!(
                    decode(&quantum).is_ok(),
                    admitted || trailing_pad,
                    "byte {candidate:#04x} at position {position}"
                );
            }
        }

        // The exception, spelled out on its own so it is a claim and not a
        // footnote to a loop condition.
        assert_eq!(decode(b"AAA=").as_deref(), Ok(&[0x00u8, 0x00][..]));
    }

    #[test]
    fn a_misplaced_pad_is_rejected() {
        // Rejection (d), `if(++padc > padding)` (:135-137). The case a
        // naive implementation passes: `"A=B="` has `padding == 1` because
        // only the last byte is '=', so the final-quantum walk tolerates
        // one '=' and refuses the second.
        assert_eq!(decode(b"A=B="), Err(BAD));
        assert_eq!(decode(b"a=Q="), Err(BAD));
        assert_eq!(decode(b"aWlpa=Q="), Err(BAD));
        assert_eq!(decode(b"=A=="), Err(BAD));
        // `A==A` reaches the same verdict by the other route: its last byte
        // is not '=', so `padding` is zero, the whole input is read as full
        // quantums and the table refuses the pads as invalid symbols. Two
        // rejections, one code -- which is the point of them sharing it.
        assert_eq!(decode(b"A==A"), Err(BAD));
        // For contrast, the same two pads in their canonical place.
        assert_eq!(decode(b"AB==").as_deref(), Ok(&[0x00u8][..]));
    }

    #[test]
    fn every_unit1302_bad_decode_row_is_rejected() {
        // tests/unit/unit1302.c:185-198, which asserts the exact code
        // rather than merely that an error occurred. Reproduced with the
        // C's own explanation of each row so a future failure says which
        // rejection stopped working.
        for (candidate, why) in UNIT1302_BAD_DECODE {
            assert_eq!(
                decode(candidate),
                Err(BAD),
                "{why}: {candidate:?} must be CURLE_BAD_CONTENT_ENCODING"
            );
        }
    }

    #[test]
    fn non_canonical_trailing_bits_are_accepted() {
        // THE test that proves the `base64` crate's stricter canonical rule
        // was not silently adopted. All three were measured against the
        // real `lib/curlx/base64.c`: the unused low bits of the final
        // quantum are discarded without complaint.
        assert_eq!(decode(b"AB==").as_deref(), Ok(&[0x00u8][..]));
        assert_eq!(decode(b"AC==").as_deref(), Ok(&[0x00u8][..]));
        assert_eq!(decode(b"AP==").as_deref(), Ok(&[0x00u8][..]));
        assert_eq!(decode(b"AAB=").as_deref(), Ok(&[0x00u8, 0x00][..]));
        assert_eq!(decode(b"AAC=").as_deref(), Ok(&[0x00u8, 0x00][..]));
        // The whole family: for a two-pad quantum only the top two bits of
        // the second symbol survive, so all sixteen symbols whose value has
        // those bits clear decode to the same single byte.
        for &symbol in BASE64_ENCDEC {
            let value = DECODE_TABLE[usize::from(symbol)];
            let quantum = [b'A', symbol, b'=', b'='];
            let expected = (value & 0x30) >> 4;
            assert_eq!(
                decode(&quantum).as_deref(),
                Ok(&[expected][..]),
                "quantum A{}== ",
                char::from(symbol)
            );
        }
    }

    #[test]
    fn the_single_pad_path_yields_two_bytes() {
        // `if(padding == 1) pos[1] = (x >> 8) & 0xff;` (:146-147).
        assert_eq!(decode(b"Zm8=").as_deref(), Ok(&b"fo"[..]));
        assert_eq!(decode(b"Zm9vYmE=").as_deref(), Ok(&b"fooba"[..]));
        assert_eq!(decode(b"AAA=").as_deref(), Ok(&[0x00u8, 0x00][..]));
        assert_eq!(decode(b"////").as_deref(), Ok(&[0xffu8, 0xff, 0xff][..]));
        assert_eq!(decode(b"++++").as_deref(), Ok(&[0xfbu8, 0xef, 0xbe][..]));
        assert_eq!(decode(b"AAAA").as_deref(), Ok(&[0x00u8, 0x00, 0x00][..]));
    }

    #[test]
    fn the_decoded_length_is_the_c_rawlen_expression() {
        // `rawlen = (numQuantums * 3) - padding` (:96), checked against the
        // returned vector for every quantum count and padding combination
        // up to a reasonable width.
        for quantums in 1usize..=24 {
            for padding in 0usize..=2 {
                let mut candidate = vec![b'A'; quantums * 4];
                for slot in candidate.iter_mut().rev().take(padding) {
                    *slot = b'=';
                }
                let decoded =
                    decode(&candidate).expect("a well-formed candidate");
                assert_eq!(
                    decoded.len(),
                    quantums * 3 - padding,
                    "{quantums} quantums with {padding} pads"
                );
            }
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "allocates 16 MB in and 12 MB out; there is no cheaper way \
                  to stand past a 16,000,000-byte limit"
    )]
    fn decode_has_no_length_cap() {
        // The encoder's cap is encode-only: `curlx_base64_decode` has no
        // length check anywhere in its 103 lines. A decode input longer than
        // CURL_MAX_BASE64_INPUT must therefore succeed, and in particular
        // must not return CURLE_TOO_LARGE, which is what adding a symmetric
        // cap would have done.
        //
        // Sized just past the cap rather than far past it: 16,000,004
        // characters in and 12,000,003 bytes out is enough to be past it
        // and cheap enough to run in a unit test.
        let oversized = vec![b'A'; CURL_MAX_BASE64_INPUT + 4];
        assert!(oversized.len() > CURL_MAX_BASE64_INPUT);
        let decoded = decode(&oversized).expect("no cap applies to decoding");
        assert_eq!(decoded.len(), oversized.len() / 4 * 3);
        assert!(decoded.iter().all(|&byte| byte == 0));
    }

    // ----------------------------------------------------------------
    // Round trips and adversarial input
    // ----------------------------------------------------------------

    #[test]
    fn every_input_length_up_to_sixteen_round_trips() {
        for length in 0usize..=16 {
            for seed in [0x5eed_0100u64, 0x5eed_0101, 0x5eed_0102] {
                let input = pseudo_random(length, seed);
                let encoded = encode(&input).expect("within the cap");
                if length == 0 {
                    assert!(encoded.is_empty());
                    continue;
                }
                assert_eq!(
                    decode(encoded.as_bytes()).as_deref(),
                    Ok(&input[..]),
                    "length {length}, seed {seed:#x}"
                );
            }
        }
    }

    #[test]
    fn longer_buffers_round_trip() {
        for length in [17usize, 31, 32, 33, 63, 64, 65, 255, 256, 1000, 4096] {
            let input = pseudo_random(length, 0x5eed_0200);
            let encoded = encode(&input).expect("within the cap");
            assert_eq!(
                decode(encoded.as_bytes()).as_deref(),
                Ok(&input[..]),
                "length {length}"
            );
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "65,536 encode-and-decode pairs; the single-byte space is \
                  covered exhaustively by a cheaper test"
    )]
    fn every_two_byte_input_round_trips_and_is_four_characters() {
        // Exhaustive over the whole two-byte space: 65,536 inputs, each
        // exercising the `insize == 2` tail of the encoder and the
        // `padding == 1` branch of the decoder.
        let mut alphabet_hits = [false; 64];

        for high in 0u8..=255 {
            for low in 0u8..=255 {
                let input = [high, low];

                let standard = encode(&input).expect("two bytes fit");
                assert_eq!(standard.len(), 4);
                assert!(standard.ends_with('='));
                assert!(!standard[..3].contains('='));
                assert_eq!(
                    decode(standard.as_bytes()).as_deref(),
                    Ok(&input[..]),
                    "round trip of {input:?}"
                );

                // The unpadded form is the padded one with its two pads
                // dropped and the two differing alphabet entries swapped --
                // asserted over the whole space rather than at a sample.
                let unpadded = url_encode(&input).expect("two bytes fit");
                assert_eq!(unpadded.len(), 3);
                let expected_url: String = standard[..3]
                    .chars()
                    .map(|symbol| match symbol {
                        '+' => '-',
                        '/' => '_',
                        other => other,
                    })
                    .collect();
                assert_eq!(unpadded, expected_url, "url form of {input:?}");

                for &symbol in &standard.as_bytes()[..3] {
                    let value = DECODE_TABLE[usize::from(symbol)];
                    assert_ne!(value, INVALID_SYMBOL);
                    alphabet_hits[usize::from(value)] = true;
                }
            }
        }

        // Discriminating rather than vacuous: the sweep really does reach
        // every alphabet entry, so a table with a wrong symbol in any slot
        // would have been exercised.
        assert!(
            alphabet_hits.iter().all(|&hit| hit),
            "the two-byte sweep missed an alphabet entry"
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "20,736 decode calls over a probe alphabet; the \
                  single-substitution sweep covers the same table"
    )]
    fn no_hostile_four_byte_input_panics_or_leaks_a_wrong_code() {
        // Base64 decoding is fed attacker-controlled bytes -- response
        // headers, authentication challenges, cached cache files. This
        // enumerates every four-byte string over a probe alphabet chosen to
        // mix valid symbols, the padding character, the two base64url-only
        // symbols, whitespace, a control byte and a high byte: 12^4 = 20,736
        // inputs. Nothing may panic and nothing may return a code other
        // than CURLE_BAD_CONTENT_ENCODING.
        const PROBE: [u8; 12] = [
            b'A', b'B', b'z', b'0', b'+', b'/', b'=', b'-', b'_', b' ', 0x1f,
            0x80,
        ];

        let mut accepted = 0usize;
        let mut rejected = 0usize;

        for &a in &PROBE {
            for &b in &PROBE {
                for &c in &PROBE {
                    for &d in &PROBE {
                        match decode(&[a, b, c, d]) {
                            Ok(bytes) => {
                                assert!(
                                    (1..=3).contains(&bytes.len()),
                                    "a quantum decodes to one to three bytes"
                                );
                                accepted += 1;
                            }
                            Err(code) => {
                                assert_eq!(
                                    code,
                                    BAD,
                                    "{:?} produced the wrong code",
                                    [a, b, c, d]
                                );
                                rejected += 1;
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(accepted + rejected, PROBE.len().pow(4));
        // Both outcomes really occur, so neither arm is untested.
        assert!(accepted > 0 && rejected > 0);
    }

    #[test]
    fn a_decoded_value_re_encodes_canonically() {
        // A property that holds even where the input was non-canonical:
        // whatever bytes came out, encoding them and decoding again must
        // return the same bytes. This is what makes the codec usable as a
        // canonicaliser and would fail if the final-quantum branch dropped
        // or invented a byte.
        for length in 1usize..=48 {
            let input = pseudo_random(length, 0x5eed_0300);
            let encoded = encode(&input).expect("within the cap");
            let decoded = decode(encoded.as_bytes()).expect("well-formed");
            let again = encode(&decoded).expect("within the cap");
            assert_eq!(again, encoded, "length {length}");
        }

        // And starting from a deliberately non-canonical token.
        let decoded = decode(b"AB==").expect("curl accepts this");
        assert_eq!(encode(&decoded).as_deref(), Ok("AA=="));
    }

    #[test]
    fn an_interior_nul_is_data_here_rather_than_a_terminator() {
        // The documented divergence, pinned so it cannot change by
        // accident. `curlx_base64_decode` takes a `const char *` and calls
        // `strlen`, so the C reads only up to the NUL and decodes the four
        // characters before it. This function is handed a slice and honours
        // its length, so the NUL is byte four of an eight-byte input and is
        // refused as an invalid symbol.
        //
        // No caller in the C tree passes an interior NUL, which is why no
        // NUL scan is added to recreate the truncation: doing so would
        // invent a silent-truncation path in a codec that feeds
        // authentication.
        let with_nul = b"QQ==\0\0\0\0";
        assert_eq!(with_nul.len(), 8);
        assert_eq!(decode(with_nul), Err(BAD));
        // The prefix the C would have seen decodes on its own.
        assert_eq!(decode(&with_nul[..4]).as_deref(), Ok(&b"A"[..]));
    }

    #[test]
    fn the_encoders_never_emit_a_terminator() {
        // The C allocates one extra byte and writes a NUL there (:185,
        // :217). Nothing here does, so no output may contain a zero byte --
        // which also proves the `Option<u8>` padding model never lets the
        // C's `padbyte = 0` reach the output as data.
        for length in 0usize..=32 {
            let input = pseudo_random(length, 0x5eed_0400);
            for produced in [
                encode(&input).expect("within the cap"),
                url_encode(&input).expect("within the cap"),
            ] {
                assert!(!produced.as_bytes().contains(&0));
                assert!(produced.is_ascii());
            }
        }
    }
}
