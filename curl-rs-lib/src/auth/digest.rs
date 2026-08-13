// /***************************************************************************
//  *                                  _   _ ____  _
//  *  Project                     ___| | | |  _ \| |
//  *                             / __| | | | |_) | |
//  *                            | (__| |_| |  _ <| |___
//  *                             \___|\___/|_| \_\_____|
//  *
//  * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//  *
//  * This software is licensed as described in the file COPYING, which
//  * you should have received as part of this distribution. The terms
//  * are also available at https://curl.se/docs/copyright.html.
//  *
//  * You may opt to use, copy, modify, merge, publish, distribute and/or sell
//  * copies of the Software, and permit persons to whom the Software is
//  * furnished to do so, under the terms of the COPYING file.
//  *
//  * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
//  * KIND, either express or implied.
//  *
//  * SPDX-License-Identifier: curl
//  *
//  * RFC7616 DIGEST-SHA256, DIGEST-SHA512-256 authentication
//  *
//  ***************************************************************************/
//
// The banner above is `lib/vauth/digest.c:1-26` with ONE line removed. That
// file attributes two specifications: `RFC2831 DIGEST-MD5 authentication` at
// `lib/vauth/digest.c:23`, and the `RFC7616` line kept verbatim above from
// `:24`. RFC 2831 is the SASL DIGEST-MD5 mechanism, which serves SMTP, IMAP
// and POP3 -- all three out of scope -- and none of its code is reproduced
// here, so claiming its attribution would misdescribe the file. RFC 7616 is
// HTTP Digest, which is exactly what this file implements, so that line
// stays. The omission is recorded rather than silent because `reuse lint`
// runs in `.github/workflows/checksrc.yml` and `REUSE.toml` is out of scope,
// which makes this in-file annotation the licence statement for this file.

//! HTTP Digest authentication, RFC 2617 and RFC 7616.
//!
//! Supersedes three C files, together 1,260 lines: `lib/vauth/digest.c`,
//! `lib/vauth/digest.h` and `lib/http_digest.c`. The transformation row for it
//! reads *"Digest; message construction byte-exact"*, and that is meant
//! literally -- every directive name, the order the directives appear in,
//! which of them are quoted, and the case of every hexadecimal digit are
//! compared as literal bytes by the fixture corpus. `tests/getpart.pm:351+`'s
//! `compareparts` joins both sides into one string and compares them whole: no
//! per-line matching, no normalisation and no reordering, so one wrong byte
//! fails the fixture outright. 76 fixtures gate on the `digest` label and 98
//! on `crypto`.
//!
//! # There are TWO challenge parsers in `lib/vauth/digest.c`. Only one is here
//!
//! This distinction is recorded first because the two look interchangeable
//! and are not, and because a later reader who "unifies" them breaks HTTP
//! Digest without breaking a build.
//!
//! * `Curl_auth_digest_get_pair` (`lib/vauth/digest.c:59-129`) is the **HTTP**
//!   parser. It is hand-rolled, caps the key at 255 bytes and the value at
//!   1023, and is deliberately sloppy about malformed input. It is
//!   [`get_pair`] below.
//! * `auth_digest_get_key_value` (`:178-229`) is the **SASL DIGEST-MD5**
//!   parser. It is built on `curlx_str_quotedword`, caps the key at 64 bytes
//!   and the value at 256, and falls back to an unquoted-until-comma read on
//!   `STRE_BEGQUOTE`. It serves SMTP, IMAP and POP3, all three out of scope,
//!   and it is **not** reproduced anywhere in this crate.
//!
//! `Curl_auth_create_digest_md5_message` (`:333-493`) and
//! `auth_decode_digest_md5_message` (`:269-300`) are SASL-only for the same
//! reason. Two consequences of that are load-bearing here and are called out
//! again where they apply:
//!
//! * The 32-hexadecimal-character client nonce of `:352` and `:383`
//!   (`char cnonce[33]`, filled by `Curl_rand_hex`) belongs to SASL. HTTP
//!   Digest uses a **16-character base64** nonce; see [`generate_cnonce`].
//! * The four streaming MD5 contexts of `:388`, `:402`, `:425` and `:443`,
//!   which feed each `':'` as a one-byte update, belong to SASL as well. The
//!   HTTP path composes each hash input as one string and hashes it in one
//!   call (`:760`, `:774`, `:825`, `:842`), so nothing here streams and
//!   [`crate::crypto::Md5Context`] is deliberately unused.
//!
//! # State lives on the transfer, not on the connection
//!
//! `Curl_http_auth_cleanup_digest` (`lib/http_digest.c:172-176`) clears
//! `data->state.digest` and `data->state.proxydigest` -- two fields of the
//! easy handle (`lib/urldata.h:966-967`). Digest is the only mechanism whose
//! state is scoped that way; NTLM and Negotiate bind their handshakes to a
//! connection and store them in connection metadata. The distinction decides
//! when credentials are reused and is observable, so it is expressed in the
//! type system: [`DigestStates`] holds the two instances and is owned by
//! [`DigestAuth`], and [`crate::auth::state_scope`] answers
//! [`crate::auth::StateScope::Transfer`] for this scheme.

use core::fmt;

use crate::auth::{
    authorization_header, AuthContext, AuthEmission, AuthScheme,
    ChallengeDecoder, Credentials, HttpAuthMechanism,
};
use crate::crypto::{
    hex_lower, md5, rand_bytes, sha256, sha512_256, Rng, MD5_DIGEST_LEN,
    MD5_HEX_BUF_LEN, SHA256_DIGEST_LEN, SHA256_HEX_BUF_LEN,
    SHA512_256_DIGEST_LEN,
};
use crate::error::CURLcode;
use crate::util::base64;
use crate::util::dynbuf::DynBuf;
use crate::util::strcase::{casecompare, checkprefix};
use crate::util::strparse::{
    is_blank, str_casecompare, str_passblanks, str_single, str_until,
};

// LENGTH CAPS. `lib/vauth/digest.h:30-31`.

/// `#define DIGEST_MAX_VALUE_LENGTH 256` -- `lib/vauth/digest.h:30`.
///
/// The size of the C's key buffer. [`get_pair`] copies at most
/// `DIGEST_MAX_VALUE_LENGTH - 1` bytes of key, which is the C's
/// `for(c = DIGEST_MAX_VALUE_LENGTH - 1; ...; c--)` at
/// `lib/vauth/digest.c:66`.
pub(crate) const DIGEST_MAX_VALUE_LENGTH: usize = 256;

/// `#define DIGEST_MAX_CONTENT_LENGTH 1024` -- `lib/vauth/digest.h:31`.
///
/// The size of the C's value buffer, bounding the content loop at
/// `lib/vauth/digest.c:80` to `DIGEST_MAX_CONTENT_LENGTH - 1` iterations.
pub(crate) const DIGEST_MAX_CONTENT_LENGTH: usize = 1024;

/// The escaping buffer ceiling of `auth_digest_string_quoted`:
/// `curlx_dyn_init(&out, 2048)` at `lib/vauth/digest.c:156`.
const DIGEST_QUOTED_MAX: usize = 2048;

/// The response buffer ceiling of `auth_create_digest_http_message`:
/// `curlx_dyn_init(&response, 4096)` at `lib/vauth/digest.c:704`, whose own
/// comment reads "arbitrary max".
const DIGEST_RESPONSE_MAX: usize = 4096;

/// The longest qop token the challenge tokeniser will read:
/// `curlx_str_until(&token, &out, 32, ',')` at `lib/vauth/digest.c:562`.
const DIGEST_QOP_TOKEN_MAX: usize = 32;

/// The number of raw random bytes behind the client nonce:
/// `char cnoncebuf[12]` at `lib/vauth/digest.c:711`.
///
/// Twelve is not arbitrary and must not be rounded. `12 % 3 == 0`, so the
/// base64 encoding of twelve bytes is exactly sixteen characters with **no**
/// padding, and sixteen unpadded characters is what a fixture sees.
const CNONCE_RAW_LEN: usize = 12;

/// The length of the base64 client nonce that [`CNONCE_RAW_LEN`] produces.
///
/// Written out so that a test can assert the emitted `cnonce=` value is
/// exactly this long without recomputing the encoder's arithmetic.
#[allow(dead_code)] // Reached only by this file's tests, which is the point.
const CNONCE_BASE64_LEN: usize = 16;

// ALGORITHM IDENTIFIERS. `lib/vauth/digest.c:41-48`.
//
// These six values are BIT-COMPOSED, not a sequential enumeration, and the
// numeric encoding is load-bearing:
//
//     #define SESSION_ALGO 1                                 /* :41 */
//     #define ALGO_MD5 0                                     /* :43 */
//     #define ALGO_MD5SESS (ALGO_MD5 | SESSION_ALGO)         /* :44 */
//     #define ALGO_SHA256 2                                  /* :45 */
//     #define ALGO_SHA256SESS (ALGO_SHA256 | SESSION_ALGO)   /* :46 */
//     #define ALGO_SHA512_256 4                              /* :47 */
//     #define ALGO_SHA512_256SESS (... | SESSION_ALGO)        /* :48 */
//
// Two separate pieces of behaviour read those integers rather than the names:
//
//  * Session-ness is `digest->algo & SESSION_ALGO` (`:651`, `:766`). The low
//    bit IS the "-sess" flag, which is why the six values are 0..5 with the
//    session forms on the odd numbers.
//  * Hash selection is a cascade of `<=` comparisons (`:991`, `:998`,
//    `:1005`), so each pair of values must be adjacent and the pairs must be
//    ordered MD5, SHA-256, SHA-512/256.

/// `#define SESSION_ALGO 1` -- `lib/vauth/digest.c:41`, whose comment reads
/// "for algos with this bit set".
const SESSION_ALGO: u8 = 1;

/// The algorithm a challenge selected: the `uint8_t algo` field of
/// `struct digestdata` (`lib/urldata.h:305`).
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum DigestAlgo {
    /// `ALGO_MD5` -- `lib/vauth/digest.c:43`. The default, both because the
    /// specification says an absent `algorithm` directive means MD5 and
    /// because `Curl_auth_digest_cleanup` resets to it (`:1037`).
    #[default]
    Md5 = 0,
    /// `ALGO_MD5SESS` -- `lib/vauth/digest.c:44`, `ALGO_MD5 | SESSION_ALGO`.
    Md5Sess = 1,
    /// `ALGO_SHA256` -- `lib/vauth/digest.c:45`.
    Sha256 = 2,
    /// `ALGO_SHA256SESS` -- `lib/vauth/digest.c:46`.
    Sha256Sess = 3,
    /// `ALGO_SHA512_256` -- `lib/vauth/digest.c:47`.
    Sha512_256 = 4,
    /// `ALGO_SHA512_256SESS` -- `lib/vauth/digest.c:48`.
    Sha512_256Sess = 5,
}

impl DigestAlgo {
    /// The stored integer: C's `digest->algo`.
    ///
    /// One cast, in one place, wrapped in a named accessor -- the same shape
    /// [`crate::error::CURLcode`] uses for its own discriminant reads. An
    /// enum-to-integer conversion of a `#[repr(u8)]` enum is exact by
    /// construction, so there is nothing for a `TryFrom` to report.
    #[must_use]
    pub(crate) const fn bits(self) -> u8 {
        self as u8
    }

    /// Whether this is a `-sess` variant: C's
    /// `(digest->algo & SESSION_ALGO)` at `lib/vauth/digest.c:651` and
    /// `:766`.
    #[must_use]
    pub(crate) const fn is_session(self) -> bool {
        self.bits() & SESSION_ALGO != 0
    }
}

// The discriminants, pinned. Evaluated during compilation, so this costs
// nothing at run time and is inert under Miri. A renumbering fails the build
// here, beside the citation that explains why it cannot change.
const _: () = assert!(DigestAlgo::Md5.bits() == 0);
const _: () = assert!(DigestAlgo::Md5Sess.bits() == 1);
const _: () = assert!(DigestAlgo::Sha256.bits() == 2);
const _: () = assert!(DigestAlgo::Sha256Sess.bits() == 3);
const _: () = assert!(DigestAlgo::Sha512_256.bits() == 4);
const _: () = assert!(DigestAlgo::Sha512_256Sess.bits() == 5);
const _: () = assert!(!DigestAlgo::Md5.is_session());
const _: () = assert!(DigestAlgo::Md5Sess.is_session());
const _: () = assert!(!DigestAlgo::Sha256.is_session());
const _: () = assert!(DigestAlgo::Sha256Sess.is_session());
const _: () = assert!(!DigestAlgo::Sha512_256.is_session());
const _: () = assert!(DigestAlgo::Sha512_256Sess.is_session());

/// The six `algorithm` spellings a challenge may carry, and the value each
/// selects -- `lib/vauth/digest.c:594-617`.
///
/// The comparison at every one of those lines is `curl_strequal`, which folds
/// case, so a server may spell any of these in any case and it still parses.
/// The literals are nonetheless transcribed **exactly** as the C spells them,
/// including one asymmetry that a tidied table would erase: MD5's session
/// form is written `MD5-sess` with a **lower-case** suffix at `:594` while
/// all three SHA forms are written `-SESS` in **upper case** at `:600`,
/// `:602` and `:609`. Preserving it is what lets a reader diff this table
/// against the C and get no hits.
#[rustfmt::skip]
const ALGORITHM_TABLE: [(&[u8], DigestAlgo); 6] = [
    (b"MD5-sess",         DigestAlgo::Md5Sess),
    (b"MD5",              DigestAlgo::Md5),
    (b"SHA-256",          DigestAlgo::Sha256),
    (b"SHA-256-SESS",     DigestAlgo::Sha256Sess),
    (b"SHA-512-256",      DigestAlgo::Sha512_256),
    (b"SHA-512-256-SESS", DigestAlgo::Sha512_256Sess),
];

// QUALITY OF PROTECTION. `lib/vauth/digest.c:50-56`.

/// `DIGEST_QOP_VALUE_AUTH (1 << 0)` -- `lib/vauth/digest.c:50`.
#[allow(dead_code)] // Consumer would be the SASL path; all three are stubs.
pub(crate) const DIGEST_QOP_VALUE_AUTH: u8 = 1 << 0;

/// `DIGEST_QOP_VALUE_AUTH_INT (1 << 1)` -- `lib/vauth/digest.c:51`.
#[allow(dead_code)] // Consumer would be the SASL path; all three are stubs.
pub(crate) const DIGEST_QOP_VALUE_AUTH_INT: u8 = 1 << 1;

/// `DIGEST_QOP_VALUE_AUTH_CONF (1 << 2)` -- `lib/vauth/digest.c:52`.
#[allow(dead_code)] // Consumer would be the SASL path; all three are stubs.
pub(crate) const DIGEST_QOP_VALUE_AUTH_CONF: u8 = 1 << 2;

/// `DIGEST_QOP_VALUE_STRING_AUTH "auth"` -- `lib/vauth/digest.c:54`.
const DIGEST_QOP_VALUE_STRING_AUTH: &[u8] = b"auth";

/// `DIGEST_QOP_VALUE_STRING_AUTH_INT "auth-int"` --
/// `lib/vauth/digest.c:55`.
const DIGEST_QOP_VALUE_STRING_AUTH_INT: &[u8] = b"auth-int";

/// `DIGEST_QOP_VALUE_STRING_AUTH_CONF "auth-conf"` --
/// `lib/vauth/digest.c:56`.
#[allow(dead_code)] // Consumer would be the SASL path; it is a stub.
pub(crate) const DIGEST_QOP_VALUE_STRING_AUTH_CONF: &[u8] = b"auth-conf";

/// The `stale` and `userhash` affirmative, `"true"` -- compared with
/// `curl_strequal` at `lib/vauth/digest.c:537` and `:620`, so any case
/// matches.
const DIGEST_TRUE: &[u8] = b"true";

// DIGEST TO ASCII. `lib/vauth/digest.c:133-150`.
//
// LOWERCASE. Both renderers are a loop of `curl_msnprintf(dest, 3, "%02x")`,
// and `%02x` is lower case. Get this wrong and all 76 digest-gated fixtures
// fail at once, because the hexadecimal appears inside the `response=` value
// that a byte-exact `<protocol>` block compares.

/// `auth_digest_md5_to_ascii` -- `lib/vauth/digest.c:133-140`.
fn md5_to_ascii(source: &[u8; MD5_DIGEST_LEN]) -> String {
    hex_lower(source)
}

/// `auth_digest_sha256_to_ascii` -- `lib/vauth/digest.c:142-150`.
fn sha256_to_ascii(source: &[u8; SHA256_DIGEST_LEN]) -> String {
    hex_lower(source)
}

// The lengths these two renderers depend on, pinned. The third assertion is
// the coincidence the doc comment above describes: it is what makes one
// renderer correct for two algorithms, and if it ever stopped holding, the C's
// own pairing would be wrong too.
const _: () = assert!(MD5_DIGEST_LEN * 2 + 1 == MD5_HEX_BUF_LEN);
const _: () = assert!(SHA256_DIGEST_LEN * 2 + 1 == SHA256_HEX_BUF_LEN);
const _: () = assert!(SHA512_256_DIGEST_LEN == SHA256_DIGEST_LEN);

/// Which hash a challenge's algorithm selects, bound to its renderer.
///
/// # Why the C's two function pointers become one enumeration
///
/// `auth_create_digest_http_message` takes them separately
/// (`lib/vauth/digest.c:685-686`):
///
/// ```c
/// void (*convert_to_ascii)(const unsigned char *, unsigned char *),
/// CURLcode (*hash)(unsigned char *, const unsigned char *, const size_t)
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HashKind {
    /// `Curl_md5it` with `auth_digest_md5_to_ascii` --
    /// `lib/vauth/digest.c:995-996`.
    Md5,
    /// `Curl_sha256it` with `auth_digest_sha256_to_ascii` --
    /// `lib/vauth/digest.c:1002-1003`.
    Sha256,
    /// `Curl_sha512_256it` with `auth_digest_sha256_to_ascii` --
    /// `lib/vauth/digest.c:1009-1010`.
    Sha512_256,
}

impl HashKind {
    /// Hash `input` and render the result as lowercase hexadecimal: the C's
    /// `hash(hashbuf, input, len)` immediately followed by
    /// `convert_to_ascii(hashbuf, dest)`.
    fn digest_hex(self, input: &[u8]) -> String {
        match self {
            Self::Md5 => md5_to_ascii(&md5(input)),
            Self::Sha256 => sha256_to_ascii(&sha256(input)),
            // The one pairing worth staring at: SHA-512/256's bytes, rendered
            // by the SHA-256 renderer, exactly as `lib/vauth/digest.c:1009`
            // pairs them.
            Self::Sha512_256 => sha256_to_ascii(&sha512_256(input)),
        }
    }
}

/// The hash `algo` selects: `Curl_auth_create_digest_http_message`'s dispatch,
/// `lib/vauth/digest.c:983-1015`.
///
/// # Errors
///
/// `CURLcode::BadContentEncoding` for an algorithm no bucket covers.
fn hash_for(algo: DigestAlgo) -> Result<HashKind, CURLcode> {
    let algo = algo.bits();

    if algo <= DigestAlgo::Md5Sess.bits() {
        return Ok(HashKind::Md5);
    }
    if algo <= DigestAlgo::Sha256Sess.bits() {
        return Ok(HashKind::Sha256);
    }
    if algo <= DigestAlgo::Sha512_256Sess.bits() {
        return Ok(HashKind::Sha512_256);
    }

    // C: "Should be unreachable".
    Err(CURLcode::BadContentEncoding)
}

// QUOTED-STRING ESCAPING. `lib/vauth/digest.c:152-173`.

/// `auth_digest_string_quoted` -- `lib/vauth/digest.c:153-173`, whose own
/// comment reads "Perform quoted-string escaping as described in RFC2616 and
/// its errata".
///
/// # Errors
///
/// `CURLcode::TooLarge` when the escaped result would exceed
/// [`DIGEST_QUOTED_MAX`], which is the C's `curlx_dyn_init(&out, 2048)`
/// ceiling at `:156` reporting through `curlx_dyn_addn`. The C funnels that
/// into `NULL` and then into `CURLE_OUT_OF_MEMORY` at every call site; the
/// distinct code is kept here because it is the truthful one and because the
/// caller propagates whatever it receives.
fn string_quoted(source: &[u8]) -> Result<Vec<u8>, CURLcode> {
    let mut out = DynBuf::new(DIGEST_QUOTED_MAX);

    // `if(!*s)` -- the C tests the first byte of a NUL-terminated string,
    // which is emptiness.
    if source.is_empty() {
        // `return curlx_strdup("")`: an empty string, not a buffer that
        // happens to hold nothing.
        return Ok(Vec::new());
    }

    for &byte in source {
        if byte == b'"' || byte == b'\\' {
            out.addn(b"\\")?;
        }
        out.addn(&[byte])?;
    }

    Ok(out.take())
}

// STATE. The non-SSPI arm of `struct digestdata`, `lib/urldata.h:297-308`.

/// One side's Digest negotiation state: `data->state.digest` or
/// `data->state.proxydigest`.
///
/// Transcribed from `lib/urldata.h:297-308`:
///
/// ```c
/// char *nonce;  char *cnonce;  char *realm;
/// char *opaque; char *qop;     char *algorithm;
/// int nc;                 /* nonce count */
/// uint8_t algo;
/// BIT(stale);             /* set true for re-negotiation */
/// BIT(userhash);
/// ```
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct DigestData {
    /// `char *nonce` -- the server nonce. Required: a challenge without one
    /// is rejected (`lib/vauth/digest.c:647-648`).
    nonce: Option<Vec<u8>>,
    /// `char *cnonce` -- the client nonce, generated once per state and then
    /// reused (`lib/vauth/digest.c:710`).
    cnonce: Option<Vec<u8>>,
    /// `char *realm` -- optional. When absent the header still emits
    /// `realm=""`; see [`compose_response`].
    realm: Option<Vec<u8>>,
    /// `char *opaque` -- optional, echoed back quoted when present.
    opaque: Option<Vec<u8>>,
    /// `char *qop` -- the selected quality of protection, always one of the
    /// two canonical lower-case literals and never the server's spelling.
    qop: Option<Vec<u8>>,
    /// `char *algorithm` -- the server's **raw** spelling, kept because it is
    /// echoed back verbatim (`lib/vauth/digest.c:936`).
    algorithm: Option<Vec<u8>>,
    /// `int nc` -- the nonce count. `int` in the C, and `%08x` renders its
    /// two's-complement bits, which `i32` and `{:08x}` reproduce exactly.
    nc: i32,
    /// `uint8_t algo` -- see [`DigestAlgo`].
    algo: DigestAlgo,
    /// `BIT(stale)` -- "set true for re-negotiation".
    stale: bool,
    /// `BIT(userhash)` -- RFC 7616 section 3.4.4.
    userhash: bool,
}

impl fmt::Debug for DigestData {
    /// Hand-written, and the reason is narrow and specific.
    ///
    /// Nothing in this structure is a secret: a nonce, a realm, an opaque
    /// token and a client nonce all travel in cleartext in both directions,
    /// and curl prints the whole `Authorization:` header under `--verbose`
    /// anyway. What a derive would invite is the *next* field. The password is
    /// deliberately not stored here -- it reaches
    /// [`create_digest_http_message`] as a parameter, is folded into HA1 and is
    /// never retained -- and a formatter
    /// written by hand is what keeps a later field addition from quietly
    /// printing one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn text(value: &Option<Vec<u8>>) -> Option<String> {
            value
                .as_ref()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        }

        f.debug_struct("DigestData")
            .field("nonce", &text(&self.nonce))
            .field("cnonce", &text(&self.cnonce))
            .field("realm", &text(&self.realm))
            .field("opaque", &text(&self.opaque))
            .field("qop", &text(&self.qop))
            .field("algorithm", &text(&self.algorithm))
            .field("nc", &self.nc)
            .field("algo", &self.algo)
            .field("stale", &self.stale)
            .field("userhash", &self.userhash)
            .finish()
    }
}

impl DigestData {
    /// `Curl_auth_digest_cleanup` -- `lib/vauth/digest.c:1027-1040`.
    pub(crate) fn cleanup(&mut self) {
        *self = Self::default();
    }

    /// Whether a challenge has been received: C's `have_chlg = !!digest->nonce`
    /// at `lib/http_digest.c:120`.
    #[must_use]
    pub(crate) fn have_challenge(&self) -> bool {
        self.nonce.is_some()
    }

    /// The nonce count that the next emitted header will carry.
    ///
    /// Exposed so that a test can observe the `00000001` then `00000002`
    /// progression, and the `stale=true` reset to 1, without reaching into a
    /// private field.
    #[must_use]
    #[allow(dead_code)] // Consumers are this file's tests and `CURLINFO`
    pub(crate) fn nonce_count(&self) -> i32 {
        self.nc
    }

    /// The algorithm the last challenge selected.
    #[must_use]
    #[allow(dead_code)] // Consumers are this file's tests and `CURLINFO`
    pub(crate) fn algorithm(&self) -> DigestAlgo {
        self.algo
    }

    /// Whether the last challenge carried `stale=true`.
    #[must_use]
    #[allow(dead_code)] // Consumers are this file's tests and `CURLINFO`
    pub(crate) fn is_stale(&self) -> bool {
        self.stale
    }
}

// CHALLENGE PAIR EXTRACTION. `Curl_auth_digest_get_pair`,
// `lib/vauth/digest.c:59-129`.

/// One `key=value` pair lifted out of a challenge, and where the scan stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DigestPair<'a> {
    /// The C's `value` buffer -- the key, at most
    /// `DIGEST_MAX_VALUE_LENGTH - 1` bytes.
    pub(crate) key: Vec<u8>,
    /// The C's `content` buffer -- the value, at most
    /// `DIGEST_MAX_CONTENT_LENGTH - 1` bytes, unescaped.
    pub(crate) content: Vec<u8>,
    /// The C's `*endptr` -- what remains after the pair, including the byte
    /// that terminated it, which the C consumes.
    pub(crate) rest: &'a [u8],
}

/// `Curl_auth_digest_get_pair` -- `lib/vauth/digest.c:59-129`.
///
/// # The sloppiness is the specification
///
/// The C's own comment at `:93-94` says it does "sloppy" parsing when a value
/// did not start with a quote, and the whole function is written to accept
/// more than the grammar allows. Tightening any of it would reject challenges
/// curl accepts today, so each rule below is transcribed exactly:
///
/// | Byte | Inside quotes | Outside quotes |
/// |------|---------------|----------------|
/// | `\` | begins an escape; the backslash is **dropped** and the next byte is taken literally (`:83-88`) | stored literally |
/// | `,` | stored literally | **ends** the value (`:91-98`) |
/// | CR or LF | **failure** -- the C's reason is "No closing quote" (`:100-106`) | **ends** the value |
/// | `"` | **ends** the value (`:108-113`) | **failure** (`:114-115`) |
///
/// Two further rules that are easy to lose:
///
/// * A value that simply runs out of input **succeeds** (`:125-128`), even
///   when it opened with a quote that never closed. Only CR or LF inside
///   quotes is a failure.
/// * A trailing dangling backslash **fails**, because the escape flag is still
///   set when the loop ends (`:122-123`, the C's reason: "No character after
///   backslash").
pub(crate) fn get_pair(input: &[u8]) -> Option<DigestPair<'_>> {
    let mut cursor = input;

    // `for(c = DIGEST_MAX_VALUE_LENGTH - 1; (*str && (*str != '=') && c--);)
    //    *value++ = *str++;`
    //
    // The C's `c--` is evaluated after the two byte tests, so the loop runs
    // at most `DIGEST_MAX_VALUE_LENGTH - 1` times. A zero byte ends the walk
    // because it is the C's terminator.
    let mut key = Vec::new();
    while key.len() < DIGEST_MAX_VALUE_LENGTH - 1 {
        match cursor.first().copied() {
            None | Some(0) | Some(b'=') => break,
            Some(byte) => {
                key.push(byte);
                cursor = &cursor[1..];
            }
        }
    }

    // `if('=' != *str++) return FALSE;` -- "eek, no match". An empty input
    // reaches here with the cursor on its terminator, which is not `'='`, so
    // an exhausted challenge fails and the caller's loop ends.
    match cursor.first().copied() {
        Some(b'=') => cursor = &cursor[1..],
        _ => return None,
    }

    // `if('\"' == *str) { str++; starts_with_quote = TRUE; }`
    let mut starts_with_quote = false;
    if cursor.first() == Some(&b'"') {
        cursor = &cursor[1..];
        starts_with_quote = true;
    }

    // `for(c = DIGEST_MAX_CONTENT_LENGTH - 1; *str && c--; str++)`
    let mut content = Vec::new();
    let mut budget = DIGEST_MAX_CONTENT_LENGTH - 1;
    let mut escape = false;

    loop {
        // `*str` first: a zero byte or an exhausted slice ends the walk.
        let byte = match cursor.first().copied() {
            None | Some(0) => break,
            Some(byte) => byte,
        };
        // `c--` second: the counter is consulted only once the byte exists.
        if budget == 0 {
            break;
        }
        budget -= 1;

        if !escape {
            match byte {
                // `case '\\':` -- an escape only inside quotes. The backslash
                // itself is dropped; the byte after it is stored literally by
                // the next iteration, which skips this whole switch.
                b'\\' if starts_with_quote => {
                    escape = true;
                    cursor = &cursor[1..];
                    continue;
                }
                // `case ',':` -- ends the value only outside quotes.
                b',' if !starts_with_quote => {
                    cursor = &cursor[1..];
                    break;
                }
                // `case '\r': case '\n':` -- "No closing quote" inside
                // quotes; ends the value outside them.
                b'\r' | b'\n' => {
                    if starts_with_quote {
                        return None;
                    }
                    cursor = &cursor[1..];
                    break;
                }
                // `case '\"':` -- closes the value inside quotes, and is
                // malformed outside them.
                b'"' => {
                    if !starts_with_quote {
                        return None;
                    }
                    cursor = &cursor[1..];
                    break;
                }
                // The C's `default`, plus the three `break` fall-throughs of
                // the arms above whose guard did not hold: store the byte.
                _ => {}
            }
        }

        // `escape = FALSE; *content++ = *str;`
        escape = false;
        content.push(byte);
        cursor = &cursor[1..];
    }

    // `if(escape) return FALSE;` -- "No character after backslash".
    if escape {
        return None;
    }

    Some(DigestPair {
        key,
        content,
        rest: cursor,
    })
}

// CHALLENGE DECODE. `Curl_auth_decode_digest_http_message`,
// `lib/vauth/digest.c:508-655`.

/// The `qop` arm of the challenge walk -- `lib/vauth/digest.c:554-586`.
fn select_qop(content: &[u8]) -> Option<&'static [u8]> {
    let mut token = content;
    let mut found_auth = false;
    let mut found_auth_int = false;

    // `while(*token && ISBLANK(*token)) token++;`
    str_passblanks(&mut token);

    // `while(!curlx_str_until(&token, &out, 32, ','))` -- any error ends the
    // walk, which covers an empty token, a leading comma and an over-long
    // token alike.
    while let Ok(word) = str_until(&mut token, DIGEST_QOP_TOKEN_MAX, b',') {
        if str_casecompare(word, DIGEST_QOP_VALUE_STRING_AUTH) {
            found_auth = true;
        } else if str_casecompare(word, DIGEST_QOP_VALUE_STRING_AUTH_INT) {
            found_auth_int = true;
        }

        // `if(curlx_str_single(&token, ',')) break;`
        if str_single(&mut token, b',').is_err() {
            break;
        }
        // `while(*token && ISBLANK(*token)) token++;`
        str_passblanks(&mut token);
    }

    // "Select only auth or auth-int. Otherwise, ignore" -- `:574-586`.
    if found_auth {
        Some(DIGEST_QOP_VALUE_STRING_AUTH)
    } else if found_auth_int {
        Some(DIGEST_QOP_VALUE_STRING_AUTH_INT)
    } else {
        None
    }
}

/// `Curl_auth_decode_digest_http_message` -- `lib/vauth/digest.c:508-655`.
///
/// # The order of the first two statements is load-bearing
///
/// ```c
/// bool before = FALSE;
/// if(digest->nonce) before = TRUE;
/// Curl_auth_digest_cleanup(digest);
/// ```
///
/// # The three terminal validations, in this order
///
/// 1. `before && !digest->stale` (`:643-644`). A second challenge that does
///    **not** say `stale=true` means the credentials just sent were wrong, so
///    the C's comment concludes "This means we provided bad credentials in the
///    previous request" and the challenge is rejected rather than answered.
/// 2. `!digest->nonce` (`:647-648`) -- "We got this header without a nonce,
///    that is a bad Digest line!".
/// 3. `!digest->qop && (digest->algo & SESSION_ALGO)` (`:651-652`) -- a
///    `-sess` algorithm requires `auth` or `auth-int`.
///
/// # Errors
///
/// `CURLcode::BadContentEncoding` for an unknown `algorithm` value and for
/// each of the three validations above -- the same code the C returns in all
/// four places. The C's `CURLE_OUT_OF_MEMORY` arms guarded `curlx_strdup` of a
/// challenge field, which is a copy of bytes already in memory -- the same
/// order of magnitude as the input, with no amplification -- so it is not among
/// the externally sized allocations `crate::util::fallible` covers, and
/// `Box`/`String` duplication has no stable fallible spelling at the declared
/// minimum Rust version. A failure there aborts, and that is stated rather than
/// papered over.
///
/// The two `CURLE_NOT_BUILT_IN` arms at `:606` and `:613` are also absent, and
/// deliberately: they sit under `#else /* !CURL_HAVE_SHA512_256 */`, and
/// `lib/curl_sha512_256.h:32` defines that macro **unconditionally**, so the
/// arms are dead in the C tree as it stands. Reproducing them would require
/// inventing a Cargo feature to make them reachable, which the crate's fixed
/// fifteen-name vocabulary does not have.
pub(crate) fn decode_digest_http_message(
    challenge: &[u8],
    digest: &mut DigestData,
) -> Result<(), CURLcode> {
    // `bool before = FALSE; if(digest->nonce) before = TRUE;` -- FIRST.
    let before = digest.nonce.is_some();

    // `Curl_auth_digest_cleanup(digest);` -- "Clean up any former leftovers
    // and initialise to defaults". SECOND.
    digest.cleanup();

    let mut chlg = challenge;

    loop {
        // "Pass all additional spaces here" -- `:524-526`.
        str_passblanks(&mut chlg);

        // "Extract a value=content pair" -- `:528-529`. A failure is the C's
        // `else break; /* We are done here */` at `:628-629`.
        let Some(pair) = get_pair(chlg) else {
            break;
        };
        chlg = pair.rest;

        let key = pair.key.as_slice();
        let content = pair.content.as_slice();

        if casecompare(key, b"nonce") {
            digest.nonce = Some(content.to_vec());
        } else if casecompare(key, b"stale") {
            if casecompare(content, DIGEST_TRUE) {
                digest.stale = true;
                // "we make a new nonce now" -- `:539`. BOTH effects are
                // required: the flag satisfies validation 1 below, and the
                // count reset is what makes the retry send `nc=00000001`.
                digest.nc = 1;
            }
        } else if casecompare(key, b"realm") {
            digest.realm = Some(content.to_vec());
        } else if casecompare(key, b"opaque") {
            digest.opaque = Some(content.to_vec());
        } else if casecompare(key, b"qop") {
            if let Some(selected) = select_qop(content) {
                digest.qop = Some(selected.to_vec());
            }
        } else if casecompare(key, b"algorithm") {
            // The RAW spelling is stored first, because it is echoed back
            // verbatim in the emitted header (`:589-592`, then `:936`).
            digest.algorithm = Some(content.to_vec());

            // ... and then mapped to a value, in the C's own order.
            let mapped = ALGORITHM_TABLE
                .iter()
                .find(|(spelling, _)| casecompare(content, spelling))
                .map(|(_, algo)| *algo);
            match mapped {
                Some(algo) => digest.algo = algo,
                // `else return CURLE_BAD_CONTENT_ENCODING;` -- `:616-617`.
                None => return Err(CURLcode::BadContentEncoding),
            }
        } else if casecompare(key, b"userhash") {
            // Two levels, deliberately not one. The flag is only ever SET,
            // never cleared: a challenge spelling `userhash=true,
            // userhash=false` leaves it true in the C (`:619-623`), which a
            // collapsed `key && value` test would get wrong, and the inner
            // miss is the C's "ignore it" applied to a value rather than to a
            // key.
            if casecompare(content, DIGEST_TRUE) {
                digest.userhash = true;
            }
        }
        // else: "Unknown specifier, ignore it!" -- `:624-626`.

        // "Pass all additional spaces here" -- `:631-633`.
        str_passblanks(&mut chlg);

        // "Allow the list to be comma-separated" -- `:635-637`.
        if chlg.first() == Some(&b',') {
            chlg = &chlg[1..];
        }
    }

    // 1. "We had a nonce since before, and we got another one now without
    //    'stale=true'." -- `:640-644`.
    if before && !digest.stale {
        return Err(CURLcode::BadContentEncoding);
    }

    // 2. "We got this header without a nonce, that is a bad Digest line!"
    //    -- `:646-648`.
    if digest.nonce.is_none() {
        return Err(CURLcode::BadContentEncoding);
    }

    // 3. `"<algo>-sess" protocol versions require "auth" or "auth-int" qop`
    //    -- `:650-652`.
    if digest.qop.is_none() && digest.algo.is_session() {
        return Err(CURLcode::BadContentEncoding);
    }

    Ok(())
}

// RESPONSE COMPUTATION. `auth_create_digest_http_message`,
// `lib/vauth/digest.c:677-961`.

/// The C's `curl_maprintf("%s:%s"...)` over byte strings, in one place.
fn join_colon(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push(b':');
        }
        out.extend_from_slice(part);
    }
    out
}

/// Generates the client nonce: `lib/vauth/digest.c:710-725`.
///
/// ```c
/// char cnoncebuf[12];
/// result = Curl_rand_bytes(data, TRUE, cnoncebuf, sizeof(cnoncebuf));
/// if(!result)
///   result = curlx_base64_encode(cnoncebuf, sizeof(cnoncebuf),
///                                &cnonce, &cnonce_sz);
/// ```
///
/// # The random source is injected
///
/// `rng` is a `&mut dyn Rng` rather than a global, which is what makes every
/// emitted header in this file's tests reproducible and therefore assertable
/// byte for byte. [`rand_bytes`] fills four bytes per draw, low byte first,
/// reproducing `Curl_rand_bytes`'s own ordering.
///
/// # Errors
///
/// Whatever [`base64::encode`] reports. It cannot fail for twelve bytes --
/// its only failure is an input above `CURL_MAX_BASE64_INPUT` -- but the code
/// is propagated rather than discarded, exactly as the C propagates it.
fn generate_cnonce(rng: &mut dyn Rng) -> Result<Vec<u8>, CURLcode> {
    let mut raw = [0_u8; CNONCE_RAW_LEN];
    rand_bytes(rng, &mut raw);
    Ok(base64::encode(&raw)?.into_bytes())
}

/// `auth_create_digest_http_message` -- `lib/vauth/digest.c:677-961`, reached
/// through the algorithm dispatch of `Curl_auth_create_digest_http_message`
/// (`:983-1015`), which is [`hash_for`] here.
///
/// Computes this request's Digest response and returns the finished credential
/// -- the text that follows `Authorization: Digest `. [`output_digest`] wraps
/// it in the header line.
///
/// # The response, in exactly two forms
///
/// ```text
///   with qop:  H(HA1 ":" nonce ":" nc ":" cnonce ":" qop ":" HA2)   /* :832 */
///   no qop:    H(HA1 ":" nonce ":" HA2)                            /* :835 */
/// ```
///
/// # Errors
///
/// `CURLcode::BadContentEncoding` if the algorithm has no hash bucket
/// ([`hash_for`]), or -- unreachably through [`output_digest`], which returns
/// early when no challenge has been received -- if there is no nonce to quote.
/// `CURLcode::TooLarge` from [`string_quoted`] or [`compose_response`] if a
/// challenge value or the finished header exceeds its ceiling. Whatever
/// [`generate_cnonce`] and [`base64::encode`] report otherwise.
fn create_digest_http_message(
    digest: &mut DigestData,
    user: &[u8],
    password: &[u8],
    request: &[u8],
    uripath: &[u8],
    rng: &mut dyn Rng,
) -> Result<String, CURLcode> {
    let hash = hash_for(digest.algo)?;

    // `if(!digest->nc) digest->nc = 1;` -- `:707-708`. The C's
    // `memset(hashbuf, 0, sizeof(hashbuf))` at `:706` has no counterpart:
    // every hash here returns its own fixed-size array rather than writing
    // into a shared scratch buffer.
    if digest.nc == 0 {
        digest.nc = 1;
    }

    // `if(!digest->cnonce) { ... digest->cnonce = cnonce; }` -- `:710-725`.
    // Generated once per state and then reused for every subsequent request,
    // which is what keeps a multi-request exchange's `nc` sequence meaningful.
    if digest.cnonce.is_none() {
        digest.cnonce = Some(generate_cnonce(rng)?);
    }
    // Populated either by the assignment above or by a previous request, so
    // the default arm is unreachable; `unwrap_or_default` states that as a
    // total function rather than asserting it and risking a panic.
    let cnonce = digest.cnonce.clone().unwrap_or_default();

    // `Curl_output_digest` returns before reaching this function when
    // `digest->nonce` is NULL (`lib/http_digest.c:123-126`), and the decode
    // rejects a challenge without one (`lib/vauth/digest.c:647-648`), so the
    // C dereferences the pointer unconditionally at `:768` and `:832`. Both
    // guarantees are reproduced, and this arm states the resulting invariant
    // instead of asserting it: a missing nonce is a malformed challenge, which
    // is the code the decode would have returned.
    let Some(nonce) = digest.nonce.clone() else {
        return Err(CURLcode::BadContentEncoding);
    };

    // `digest->realm ? digest->realm : ""` -- `:729`, `:753-754`.
    let realm = digest.realm.as_deref().unwrap_or_default();

    // USERHASH, RFC 7616 section 3.4.4 -- `:727-740`. The hash of
    // `user ":" realm` replaces the username in the emitted header.
    let userhash = if digest.userhash {
        Some(hash.digest_hex(&join_colon(&[user, realm])))
    } else {
        None
    };

    // HA1 -- `:753-764`.
    let mut ha1 = hash.digest_hex(&join_colon(&[user, realm, password]));

    // The session variant -- `:766-779`. Overwrites the value above.
    if digest.algo.is_session() {
        ha1 = hash.digest_hex(&join_colon(&[ha1.as_bytes(), &nonce, &cnonce]));
    }

    // HA2 -- `:794-829`. The RAW `uripath`, never the escaped copy.
    let mut hashthis = join_colon(&[request, uripath]);
    if let Some(qop) = digest.qop.as_deref() {
        if casecompare(qop, DIGEST_QOP_VALUE_STRING_AUTH_INT) {
            // `hash(hashbuf, "", 0)` -- the hash of the EMPTY input.
            let hashed = hash.digest_hex(b"");
            hashthis = join_colon(&[&hashthis, hashed.as_bytes()]);
        }
    }
    let ha2 = hash.digest_hex(&hashthis);

    // The response -- `:831-846`.
    let request_digest = match digest.qop.as_deref() {
        Some(qop) => {
            // `"%s:%s:%08x:%s:%s:%s"`. The count is rendered separately
            // because it is the one non-string field in the join.
            let nc_hex = format!("{:08x}", digest.nc);
            hash.digest_hex(&join_colon(&[
                ha1.as_bytes(),
                &nonce,
                nc_hex.as_bytes(),
                &cnonce,
                qop,
                ha2.as_bytes(),
            ]))
        }
        // `"%s:%s:%s"`.
        None => hash.digest_hex(&join_colon(&[
            ha1.as_bytes(),
            &nonce,
            ha2.as_bytes(),
        ])),
    };

    // The four escaped fields -- `:794`, `:861-882`. Computed here, after the
    // hashing, exactly as the C computes them: `uri_quoted` is produced at
    // `:794` before HA2 but is used only by the header, and the other three
    // are produced at `:861-882` once every hash is done.
    let uri_quoted = string_quoted(uripath)?;

    // `auth_digest_string_quoted(digest->userhash ? userh : userp)` -- `:861`.
    // The userhash value replaces the username outright when the flag is set.
    let user_field = match userhash.as_deref() {
        Some(hashed) => string_quoted(hashed.as_bytes())?,
        None => string_quoted(user)?,
    };

    // `:866-872`. The absent-realm branch allocates one byte and stores a NUL
    // into it, so the field is an empty string rather than a missing one --
    // which is why the header always carries `realm=""`. [`string_quoted`]'s
    // own empty-input early return produces the same empty vector, so the two
    // branches converge and the emission below needs no special case.
    let realm_quoted = match digest.realm.as_deref() {
        Some(value) => string_quoted(value)?,
        None => Vec::new(),
    };

    let nonce_quoted = string_quoted(&nonce)?;

    compose_response(
        digest,
        &ResponseFields {
            user: &user_field,
            realm: &realm_quoted,
            nonce: &nonce_quoted,
            uri: &uri_quoted,
            cnonce: &cnonce,
            request_digest: &request_digest,
        },
    )
}

// EMISSION. `lib/vauth/digest.c:884-946`.

/// The six values the emission interpolates, in emission order.
struct ResponseFields<'a> {
    /// `userp_quoted` (`lib/vauth/digest.c:861`): the escaped username, or the
    /// escaped userhash value when `userhash` is set.
    user: &'a [u8],
    /// `realm_quoted` (`:866-872`): the escaped realm, empty when the
    /// challenge carried none.
    realm: &'a [u8],
    /// `nonce_quoted` (`:878`): the escaped server nonce.
    nonce: &'a [u8],
    /// `uri_quoted` (`:794`): the escaped request target. Not the value that
    /// went into HA2 -- see [`create_digest_http_message`].
    uri: &'a [u8],
    /// `digest->cnonce` (`:897`), passed **raw**. The C's own justification is
    /// that it "is generated with web-safe characters", which base64 output
    /// is, so there is nothing an escape could act on.
    cnonce: &'a [u8],
    /// `request_digest` (`:900`): the computed `response=` value.
    request_digest: &'a str,
}

/// Assembles the credential text: `lib/vauth/digest.c:884-946`.
///
/// # The directive order is the contract
///
/// With a qop, one formatted append of eight directives (`:885-900`):
///
/// ```text
/// username="{u}", realm="{r}", nonce="{n}", uri="{p}", cnonce="{c}",
/// nc={nc:08x}, qop={q}, response="{d}"
/// ```
///
/// Without one, five (`:906-915`):
///
/// ```text
/// username="{u}", realm="{r}", nonce="{n}", uri="{p}", response="{d}"
/// ```
///
/// Then up to three trailers, in exactly this order (`:920-946`):
///
/// ```text
/// , opaque="{o}"          quoted, escaped
/// , algorithm={a}         RAW and UNQUOTED, the server's own spelling
/// , userhash=true         a literal
/// ```
///
/// # Five details a plausible-looking rewrite gets wrong
///
/// * `realm` is **never** omitted. The C allocates a one-byte buffer holding a
///   NUL when the challenge carried no realm (`:868-872`), so the header emits
///   `realm=""`. A missing directive is a different header.
/// * `qop` is **unquoted** while everything around it is quoted, and `cnonce`
///   is **not escaped** while every other interpolated field is. Both are
///   deliberate and both are justified by the C's quoting-policy comment,
///   reproduced in this module's documentation.
/// * `algorithm` echoes back **whatever spelling the server sent**, unquoted.
///   A server sending `SHA-256-SESS` gets `algorithm=SHA-256-SESS`; one
///   sending `sha-256-sess` gets that back instead. This is the sole reason
///   [`DigestData::algorithm`] keeps the raw string.
/// * Neither `domain` nor `stale` is **ever** emitted. `stale` is consumed
///   from the challenge -- it sets `nc = 1` -- and never echoed, and no
///   `domain` directive is produced anywhere in the C.
/// * The separator is `", "`: a comma **and one space**, between every
///   directive and the next. No trailing comma, and no space on either side of
///   an `=`.
///
/// # Bytes throughout, text once
///
/// A challenge value or username that is not valid UTF-8 therefore becomes
/// `CURLcode::BadContentEncoding` rather than reaching the wire. That is the
/// single deviation in this file, and it is deliberately the narrowest
/// available one: the alternatives are a lossy substitution, which would
/// silently corrupt a credential and fail authentication with no diagnostic,
/// or a new error code, which would be worse. `BadContentEncoding` is already
/// this decoder's answer to every other malformed challenge, so the
/// *condition* is new but the *code* and its handling -- the
/// `"Digest authentication problem, ignoring."` diagnostic and
/// `authproblem = true` -- are not. RFC 7616 defines every directive value as
/// a US-ASCII quoted-string, so no conforming server can reach it, and no
/// fixture in the corpus does.
///
/// # Errors
///
/// `CURLcode::TooLarge` when the credential exceeds
/// [`DIGEST_RESPONSE_MAX`], which is the C's `curlx_dyn_init(&response,
/// 4096)` at `:704` reporting through `curlx_dyn_addf`.
/// `CURLcode::BadContentEncoding` for the UTF-8 condition above.
/// `CURLcode::OutOfMemory` if a formatting argument fails, which
/// [`DynBuf::addf`] reports and none of the arguments here can cause.
fn compose_response(
    digest: &mut DigestData,
    fields: &ResponseFields<'_>,
) -> Result<String, CURLcode> {
    let mut response = DynBuf::new(DIGEST_RESPONSE_MAX);

    // Taken by value up front so that the qop branch below can increment
    // `digest.nc` without holding a borrow of the same structure. The C reads
    // `digest->qop` and writes `digest->nc++` in adjacent statements, which a
    // language with aliasing rules will not allow through one shared borrow.
    let qop = digest.qop.clone();

    // The four directives both branches share, emitted identically.
    response.addn(b"username=\"")?;
    response.addn(fields.user)?;
    response.addn(b"\", realm=\"")?;
    response.addn(fields.realm)?;
    response.addn(b"\", nonce=\"")?;
    response.addn(fields.nonce)?;
    response.addn(b"\", uri=\"")?;
    response.addn(fields.uri)?;

    match qop.as_deref() {
        // `:885-900`, then `:902-903`.
        Some(qop) => {
            response.addn(b"\", cnonce=\"")?;
            response.addn(fields.cnonce)?;
            response.addn(b"\", nc=")?;
            response.addf(format_args!("{:08x}", digest.nc))?;
            response.addn(b", qop=")?;
            response.addn(qop)?;
            response.addn(b", response=\"")?;
            response.addn(fields.request_digest.as_bytes())?;
            response.addn(b"\"")?;

            // "Increment nonce-count to use another nc value for the next
            // request" -- `:902-903`. After the append, never before.
            digest.nc = digest.nc.wrapping_add(1);
        }
        // `:906-915`.
        None => {
            response.addn(b"\", response=\"")?;
            response.addn(fields.request_digest.as_bytes())?;
            response.addn(b"\"")?;
        }
    }

    // "Add the optional fields" -- `:920-946`, in this order.

    // 1. `, opaque="%s"` -- quoted, and escaped like realm and nonce.
    if let Some(opaque) = digest.opaque.as_deref() {
        let opaque_quoted = string_quoted(opaque)?;
        response.addn(b", opaque=\"")?;
        response.addn(&opaque_quoted)?;
        response.addn(b"\"")?;
    }

    // 2. `, algorithm=%s` -- RAW and UNQUOTED.
    if let Some(algorithm) = digest.algorithm.as_deref() {
        response.addn(b", algorithm=")?;
        response.addn(algorithm)?;
    }

    // 3. `, userhash=true` -- a literal, with no value taken from anywhere.
    if digest.userhash {
        response.addn(b", userhash=true")?;
    }

    String::from_utf8(response.take()).map_err(|_| CURLcode::BadContentEncoding)
}

// HTTP GLUE. `lib/http_digest.c`.
//
// Test example headers, verbatim from `lib/http_digest.c:34-39`:
//
//     WWW-Authenticate: Digest realm="testrealm", nonce="1053604598"
//     Proxy-Authenticate: Digest realm="testrealm", nonce="1053604598"

/// The scheme token `Curl_input_digest` requires, `lib/http_digest.c:56`.
const DIGEST_SCHEME: &str = "Digest";

/// `Curl_input_digest` -- `lib/http_digest.c:41-63`.
///
/// # The prefix test has two halves
///
/// ```c
/// if(!checkprefix("Digest", header) || !ISBLANK(header[6]))
///   return CURLE_BAD_CONTENT_ENCODING;
/// ```
///
/// A case-insensitive prefix match, **and** a mandatory blank at index 6.
/// Both are load-bearing and neither is redundant with
/// [`crate::auth::authcmp`], which admits any non-alphanumeric byte after the
/// token:
///
/// | `header` | Accepted | Why |
/// |----------|----------|-----|
/// | `Digest realm="x", nonce="y"` | yes | prefix matches, index 6 is a space |
/// | `digest realm="x", nonce="y"` | yes | the prefix match folds case |
/// | `Digest\trealm="x", nonce="y"` | yes | a tab is blank |
/// | `Digest` | no | index 6 is past the end, which is not a blank |
/// | `DigestX realm="x"` | no | index 6 is `X` |
/// | `Digest,` | no | a comma is not a blank, though `authcmp` admits it |
///
/// # Errors
///
/// `CURLcode::BadContentEncoding` when the prefix test fails, and whatever
/// [`decode_digest_http_message`] reports otherwise.
pub(crate) fn input_digest(
    header: &[u8],
    digest: &mut DigestData,
) -> Result<(), CURLcode> {
    if !checkprefix(DIGEST_SCHEME, header)
        || !is_blank(header.get(DIGEST_SCHEME.len()).copied().unwrap_or(0))
    {
        return Err(CURLcode::BadContentEncoding);
    }

    // `header += strlen("Digest"); curlx_str_passblanks(&header);`
    let mut rest = &header[DIGEST_SCHEME.len()..];
    str_passblanks(&mut rest);

    decode_digest_http_message(rest, digest)
}

/// `Curl_output_digest` -- `lib/http_digest.c:65-170`.
///
/// # No challenge is not an error
///
/// ```c
/// have_chlg = !!digest->nonce;
/// if(!have_chlg) {
///   authp->done = FALSE;
///   return CURLE_OK;
/// }
/// ```
///
/// Nothing is emitted and `CURLE_OK` is returned, with `done` left false. That
/// combination is [`AuthEmission::Continuing`] carrying no header -- except
/// that the variant carries a `String`, so this returns
/// [`AuthEmission::Nothing`] and the caller must not treat it as finished.
/// [`AuthEmission::is_done`] reports `true` for `Nothing`, which is right for
/// Basic and Bearer and wrong here, so the distinction is made explicit: see
/// [`DigestAuth::output`], which is the only caller and which reports the
/// no-challenge case as `Continuing` with an empty line rather than losing it.
///
/// # IE-style URI truncation
///
/// The C's own explanation, from `lib/http_digest.c:128-139`:
///
/// > So IE browsers < v7 cut off the URI part at the query part when they
/// > evaluate the MD5 and some (IIS?) servers work with them so we may need to
/// > do the Digest IE-style. Note that the different ways cause different MD5
/// > sums to get sent.
/// >
/// > Apache servers can be set to do the Digest IE-style automatically using
/// > the BrowserMatch feature:
/// > <https://httpd.apache.org/docs/2.2/mod/mod_auth_digest.html#msie>
/// >
/// > Further details on Digest implementation differences:
/// > <https://web.archive.org/web/2009/fngtps.com/2006/09/http-authentication>
///
/// The control flow is subtle and is transcribed rather than tidied:
///
/// ```c
/// if(authp->iestyle) {
///   tmp = strchr(uripath, '?');
///   if(tmp) {
///     size_t urilen = tmp - uripath;
///     path = curl_maprintf("%.*s", (int)urilen, uripath);
///   }
/// }
/// if(!tmp)
///   path = strdup(uripath);
/// ```
///
/// # Errors
///
/// Whatever [`create_digest_http_message`] reports.
fn output_digest(
    digest: &mut DigestData,
    credentials: &Credentials,
    iestyle: bool,
    request: &[u8],
    uripath: &[u8],
    rng: &mut dyn Rng,
) -> Result<Option<String>, CURLcode> {
    // "not set means empty" -- `:110-115`.
    let user = credentials.user().unwrap_or_default();
    let password = credentials.secret().unwrap_or_default();

    // `have_chlg = !!digest->nonce; if(!have_chlg) { done = FALSE; ... }`
    if !digest.have_challenge() {
        return Ok(None);
    }

    // The IE-style truncation, transcribed including the `if(!tmp)` test.
    let mut query = None;
    if iestyle {
        query = uripath.iter().position(|&byte| byte == b'?');
    }
    let path = match query {
        // `path = curl_maprintf("%.*s", (int)urilen, uripath)`.
        Some(urilen) => &uripath[..urilen],
        // `if(!tmp) path = strdup(uripath)`.
        None => uripath,
    };

    let credential =
        create_digest_http_message(digest, user, password, request, path, rng)?;

    Ok(Some(credential))
}

/// The two Digest states an easy handle carries: `data->state.digest` and
/// `data->state.proxydigest` (`lib/urldata.h:966-967`).
///
/// One structure rather than two fields on the mechanism, so that the pairing
/// -- and the selection on `bool proxy` that every C entry point performs at
/// its top -- exists in exactly one place.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DigestStates {
    /// `data->state.digest` -- the origin server's state.
    host: DigestData,
    /// `data->state.proxydigest` -- the proxy's state.
    proxy: DigestData,
}

impl DigestStates {
    /// The side `proxy` selects, for reading.
    ///
    /// `if(proxy) digest = &data->state.proxydigest; else digest =
    /// &data->state.digest;` -- `lib/http_digest.c:49-54` and `:89-106`.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet
                        // landed; reached by this file's tests meanwhile.
    pub(crate) fn select(&self, proxy: bool) -> &DigestData {
        if proxy {
            &self.proxy
        } else {
            &self.host
        }
    }

    /// The side `proxy` selects, for modification.
    pub(crate) fn select_mut(&mut self, proxy: bool) -> &mut DigestData {
        if proxy {
            &mut self.proxy
        } else {
            &mut self.host
        }
    }

    /// `Curl_http_auth_cleanup_digest` -- `lib/http_digest.c:172-176`.
    ///
    /// ```c
    /// Curl_auth_digest_cleanup(&data->state.digest);
    /// Curl_auth_digest_cleanup(&data->state.proxydigest);
    /// ```
    #[allow(dead_code)] // Consumer is `crate::transfer`, not yet landed;
                        // reached by this file's tests meanwhile.
    pub(crate) fn cleanup(&mut self) {
        self.host.cleanup();
        self.proxy.cleanup();
    }
}

/// HTTP Digest as a mechanism: the object `output_auth_headers()` and
/// `Curl_http_input_auth()` dispatch to.
///
/// # What it holds, and why each field is here rather than in the context
///
/// [`crate::auth::AuthContext`] carries what every mechanism's emitter needs in
/// common -- the side, the request method, the request target, a clock and a
/// random source. Three things Digest needs are not in it, because they are
/// not common:
///
/// * The two [`DigestData`] instances. In C they are fields of the easy
///   handle; here they belong to the mechanism that is the only reader of
///   them.
/// * The credentials for each side. C reaches them through
///   `data->state.aptr.user` and `.proxyuser` at the top of
///   `Curl_output_digest`; here the driver supplies them with
///   [`Self::set_credentials`], and [`Credentials`] keeps the secret out of
///   every formatter by construction.
/// * `authp->iestyle` for each side, set from
///   [`crate::auth::AuthMask::DIGEST_IE`] by
///   [`Self::set_iestyle`]. It is a field of `struct auth` in C, and
///   [`crate::auth::AuthState::iestyle`] is where the driver reads it from.
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct DigestAuth {
    /// The two per-side negotiation states.
    states: DigestStates,
    /// `data->state.aptr.user` and `.passwd`.
    host_credentials: Credentials,
    /// `data->state.aptr.proxyuser` and `.proxypasswd`.
    proxy_credentials: Credentials,
    /// `data->state.authhost.iestyle`.
    host_iestyle: bool,
    /// `data->state.authproxy.iestyle`.
    proxy_iestyle: bool,
}

impl fmt::Debug for DigestAuth {
    /// Hand-written even though a derive would be safe today.
    ///
    /// This adds no redaction to curl's output and removes none.
    /// `lib/http.c:2888-2895` puts the fully formed `Authorization:` header
    /// straight into the request buffer, `--verbose` prints it verbatim, and
    /// 168 fixtures compare that line byte for byte. Suppressing it would fail
    /// all 168 and would itself be a behaviour change.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestAuth")
            .field("states", &self.states)
            .field("host_credentials", &self.host_credentials)
            .field("proxy_credentials", &self.proxy_credentials)
            .field("host_iestyle", &self.host_iestyle)
            .field("proxy_iestyle", &self.proxy_iestyle)
            .finish()
    }
}

impl DigestAuth {
    /// A mechanism with no challenge, no credentials and no IE-style flag:
    /// what the `calloc()` of an easy handle leaves behind.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet
                        // landed; reached by this file's tests meanwhile.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Supplies one side's credentials, which C reads from
    /// `data->state.aptr` at `lib/http_digest.c:95-104`.
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet
                        // landed; reached by this file's tests meanwhile.
    pub(crate) fn set_credentials(
        &mut self,
        proxy: bool,
        credentials: Credentials,
    ) {
        if proxy {
            self.proxy_credentials = credentials;
        } else {
            self.host_credentials = credentials;
        }
    }

    /// Supplies one side's `authp->iestyle`, which `lib/setopt.c:243-247`
    /// derives from `CURLOPT_HTTPAUTH & CURLAUTH_DIGEST_IE`.
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet
                        // landed; reached by this file's tests meanwhile.
    pub(crate) fn set_iestyle(&mut self, proxy: bool, iestyle: bool) {
        if proxy {
            self.proxy_iestyle = iestyle;
        } else {
            self.host_iestyle = iestyle;
        }
    }

    /// The two negotiation states, for a caller that needs to inspect them --
    /// `CURLINFO` reporting, a test, or the driver deciding whether a
    /// challenge has arrived.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet
                        // landed; reached by this file's tests meanwhile.
    pub(crate) fn states(&self) -> &DigestStates {
        &self.states
    }

    /// `Curl_http_auth_cleanup_digest` -- `lib/http_digest.c:172-176`, which
    /// clears both sides. See [`DigestStates::cleanup`].
    #[allow(dead_code)] // Consumer is `crate::transfer`, not yet landed;
                        // reached by this file's tests meanwhile.
    pub(crate) fn cleanup(&mut self) {
        self.states.cleanup();
    }
}

impl HttpAuthMechanism for DigestAuth {
    fn scheme(&self) -> AuthScheme {
        AuthScheme::Digest
    }

    /// `Curl_input_digest` -- see [`input_digest`].
    fn input(&mut self, challenge: &[u8], proxy: bool) -> Result<(), CURLcode> {
        input_digest(challenge, self.states.select_mut(proxy))
    }

    /// `Curl_output_digest` -- see [`output_digest`].
    fn output(
        &mut self,
        ctx: &mut AuthContext<'_>,
    ) -> Result<AuthEmission, CURLcode> {
        let proxy = ctx.proxy;
        // C's `request` and `path` arguments, which `output_auth_headers()`
        // passes to this mechanism and to no other (`lib/http.c:673-676`).
        let request = ctx.request_method;
        let target = ctx.request_target;

        // Destructured so that the credential borrow and the state borrow are
        // of disjoint fields. Reading `self.host_credentials` and calling
        // `self.states.select_mut()` through `self` would be one shared and
        // one exclusive borrow of the same value.
        let Self {
            states,
            host_credentials,
            proxy_credentials,
            host_iestyle,
            proxy_iestyle,
        } = self;

        let (credentials, iestyle) = if proxy {
            (&*proxy_credentials, *proxy_iestyle)
        } else {
            (&*host_credentials, *host_iestyle)
        };

        let emitted = output_digest(
            states.select_mut(proxy),
            credentials,
            iestyle,
            request,
            target,
            &mut *ctx.rng,
        )?;

        match emitted {
            Some(credential) => {
                // `"%sAuthorization: Digest %s\r\n"` --
                // `lib/http_digest.c:161-162`. The scheme token is taken from
                // `AuthScheme` so that the emitted spelling and the spelling
                // `input_digest` requires cannot drift; both are `"Digest"`,
                // and the fallback is unreachable because
                // `AuthScheme::Digest::header_scheme()` is `Some`.
                let token =
                    AuthScheme::Digest.header_scheme().unwrap_or(DIGEST_SCHEME);
                Ok(AuthEmission::Final(authorization_header(
                    proxy,
                    token,
                    &credential,
                )))
            }
            None => Ok(AuthEmission::Continuing(String::new())),
        }
    }
}

impl ChallengeDecoder for DigestAuth {
    /// Routes a Digest challenge to [`input_digest`] and ignores every other
    /// scheme.
    ///
    /// [`crate::auth::input_auth`] owns the scan -- the ordering, the
    /// availability bookkeeping, the five diagnostics and the comma walk --
    /// and hands each matched challenge to the decoder it was given. A
    /// `DigestAuth` decodes Digest and nothing else, so a Negotiate or NTLM
    /// challenge is a no-op here rather than an error: the driver composes a
    /// decoder over all of its mechanisms and routes by scheme, and reporting
    /// a failure for a scheme this object does not own would set
    /// `authproblem` for a challenge that was handled correctly elsewhere.
    fn decode(
        &mut self,
        scheme: AuthScheme,
        proxy: bool,
        challenge: &[u8],
    ) -> Result<(), CURLcode> {
        match scheme {
            AuthScheme::Digest => {
                input_digest(challenge, self.states.select_mut(proxy))
            }
            AuthScheme::Basic
            | AuthScheme::Bearer
            | AuthScheme::Negotiate
            | AuthScheme::Ntlm
            | AuthScheme::AwsSigv4 => Ok(()),
        }
    }
}

// Tests
//
// Every expectation that crosses the wire is written as a LITERAL. Deriving
// one from the implementation would make the test agree with whatever the code
// does, which is the one thing a parity test must not do. The literals come
// from four independent oracles, in descending order of authority:
//
//   1. `tests/data/test64` -- a fixture from the corpus itself, whose
//      `<protocol>` block carries a complete `Authorization: Digest` line.
//   2. `lib/vauth/digest.c:848-851` -- a worked example in the C source,
//      snooped from a real Mozilla 1.3a request.
//   3. RFC 2617 section 3.5 and RFC 7616 sections 3.9.1 and 3.9.2 -- the
//      specifications' own known-answer vectors.
//   4. Values computed with an independent implementation of the RFC formula,
//      for the algorithm and qop combinations no published vector covers.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        input_auth, is_digest_supported, state_scope, AuthMask, AuthStatePair,
        ChallengeSink, StateScope, DIGEST_DUPLICATE, DIGEST_PROBLEM,
        REDACTED_PLACEHOLDER,
    };
    use crate::crypto::rand::TestRng;
    use crate::trace::{TraceConfig, TraceState, Tracer, WriterSink};
    use crate::util::timeval::{CurlTime, TestClock};

    // The scenario every emission test shares, taken from `tests/data/test64`
    // so that the values are the corpus's own rather than invented.
    const USER: &[u8] = b"testuser";
    const PASS: &[u8] = b"testpass";
    const REALM: &[u8] = b"testrealm";
    const NONCE: &[u8] = b"1053604145";
    const METHOD: &[u8] = b"GET";
    const TARGET: &[u8] = b"/64";

    /// The base64 client nonce `test_rng` produces. See the note above this
    /// module for the derivation.
    const CNONCE: &str = "bHJ1Y21ydWNucnVj";

    /// The deterministic random source every emission test injects.
    fn test_rng() -> TestRng {
        TestRng::from_entropy_string("curl")
    }

    /// The injected clock. Digest reads no clock -- see this module's
    /// documentation -- so the value is arbitrary; what matters is that the
    /// production path takes one from the context and not from the system.
    fn test_clock() -> TestClock {
        TestClock::new(CurlTime::new(1_053_604_145, 0))
    }

    /// A state as a challenge would have left it, with no client nonce yet so
    /// that the injected generator is exercised.
    fn state(
        algo: DigestAlgo,
        qop: Option<&[u8]>,
        algorithm: Option<&[u8]>,
    ) -> DigestData {
        DigestData {
            nonce: Some(NONCE.to_vec()),
            cnonce: None,
            realm: Some(REALM.to_vec()),
            opaque: None,
            qop: qop.map(<[u8]>::to_vec),
            algorithm: algorithm.map(<[u8]>::to_vec),
            nc: 0,
            algo,
            stale: false,
            userhash: false,
        }
    }

    /// Emits one credential for the shared scenario.
    fn emit(digest: &mut DigestData) -> String {
        let mut rng = test_rng();
        create_digest_http_message(digest, USER, PASS, METHOD, TARGET, &mut rng)
            .expect("the shared scenario cannot fail")
    }

    /// Decodes a challenge body into a fresh state.
    fn decode(challenge: &[u8]) -> Result<DigestData, CURLcode> {
        let mut digest = DigestData::default();
        decode_digest_http_message(challenge, &mut digest)?;
        Ok(digest)
    }

    /// Runs `body` with a verbose tracer and returns its result together with
    /// everything the sink received, as text.
    fn with_tracer<R>(body: impl FnOnce(&mut Tracer<'_>) -> R) -> (R, String) {
        let config = TraceConfig::init().expect("trace config cannot fail");
        let mut sink = WriterSink::new(Vec::new());
        let result = {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            body(&mut tracer)
        };
        let captured = sink.into_inner();
        (result, String::from_utf8_lossy(&captured).into_owned())
    }

    // -- Constants ---------------------------------------------------------

    /// `lib/vauth/digest.h:30-31`.
    #[test]
    fn the_two_length_caps_are_the_c_values() {
        assert_eq!(DIGEST_MAX_VALUE_LENGTH, 256);
        assert_eq!(DIGEST_MAX_CONTENT_LENGTH, 1024);
        // The ceilings the C passes to `curlx_dyn_init`, and the token bound
        // it passes to `curlx_str_until`.
        assert_eq!(DIGEST_QUOTED_MAX, 2048);
        assert_eq!(DIGEST_RESPONSE_MAX, 4096);
        assert_eq!(DIGEST_QOP_TOKEN_MAX, 32);
        // `char cnoncebuf[12]`, and the unpadded encoding it must produce.
        assert_eq!(CNONCE_RAW_LEN, 12);
        assert_eq!(CNONCE_BASE64_LEN, 16);
        assert_eq!(CNONCE_RAW_LEN % 3, 0);
    }

    /// `lib/vauth/digest.c:41-48`. The `const` assertions beside the type
    /// already pin these at compile time; this asserts the property those
    /// values exist for, which is that the low bit is the session flag.
    #[test]
    fn the_algorithm_discriminants_are_bit_composed() {
        assert_eq!(SESSION_ALGO, 1);
        // Written as the C's `ALGO_<x> | SESSION_ALGO` compositions, except
        // for MD5's, where `0 | SESSION_ALGO` is an identity operation clippy
        // rejects; the relationship it would have expressed is asserted by the
        // loop below instead.
        assert_eq!(DigestAlgo::Md5.bits(), 0);
        assert_eq!(DigestAlgo::Md5Sess.bits(), SESSION_ALGO);
        assert_eq!(DigestAlgo::Sha256.bits(), 2);
        assert_eq!(DigestAlgo::Sha256Sess.bits(), 2 | SESSION_ALGO);
        assert_eq!(DigestAlgo::Sha512_256.bits(), 4);
        assert_eq!(DigestAlgo::Sha512_256Sess.bits(), 4 | SESSION_ALGO);

        for algo in [
            DigestAlgo::Md5,
            DigestAlgo::Md5Sess,
            DigestAlgo::Sha256,
            DigestAlgo::Sha256Sess,
            DigestAlgo::Sha512_256,
            DigestAlgo::Sha512_256Sess,
        ] {
            assert_eq!(
                algo.is_session(),
                algo.bits() % 2 == 1,
                "session-ness is the low bit for {algo:?}"
            );
        }

        // The default is MD5, which is both the specification's default for an
        // absent `algorithm` directive and the C's cleanup value at `:1037`.
        assert_eq!(DigestAlgo::default(), DigestAlgo::Md5);
    }

    /// `lib/vauth/digest.c:50-56`.
    #[test]
    fn the_qop_bit_values_and_strings_are_the_c_values() {
        assert_eq!(DIGEST_QOP_VALUE_AUTH, 1);
        assert_eq!(DIGEST_QOP_VALUE_AUTH_INT, 2);
        assert_eq!(DIGEST_QOP_VALUE_AUTH_CONF, 4);
        assert_eq!(DIGEST_QOP_VALUE_STRING_AUTH, b"auth");
        assert_eq!(DIGEST_QOP_VALUE_STRING_AUTH_INT, b"auth-int");
        assert_eq!(DIGEST_QOP_VALUE_STRING_AUTH_CONF, b"auth-conf");
        assert_eq!(DIGEST_TRUE, b"true");
        assert_eq!(DIGEST_SCHEME, "Digest");
    }

    /// `lib/vauth/digest.c:983-1015`: the cascade buckets each algorithm with
    /// its session companion, and SHA-512/256 lands in its own bucket rather
    /// than sharing SHA-256's.
    #[test]
    fn the_hash_cascade_buckets_every_algorithm() {
        assert_eq!(hash_for(DigestAlgo::Md5), Ok(HashKind::Md5));
        assert_eq!(hash_for(DigestAlgo::Md5Sess), Ok(HashKind::Md5));
        assert_eq!(hash_for(DigestAlgo::Sha256), Ok(HashKind::Sha256));
        assert_eq!(hash_for(DigestAlgo::Sha256Sess), Ok(HashKind::Sha256));
        assert_eq!(hash_for(DigestAlgo::Sha512_256), Ok(HashKind::Sha512_256));
        assert_eq!(
            hash_for(DigestAlgo::Sha512_256Sess),
            Ok(HashKind::Sha512_256)
        );
    }

    /// The six spellings, transcribed with the C's own inconsistent casing:
    /// `MD5-sess` in lower case, the three SHA session forms in upper.
    #[test]
    fn the_algorithm_table_spells_the_c_literals_exactly() {
        assert_eq!(ALGORITHM_TABLE[0].0, b"MD5-sess");
        assert_eq!(ALGORITHM_TABLE[1].0, b"MD5");
        assert_eq!(ALGORITHM_TABLE[2].0, b"SHA-256");
        assert_eq!(ALGORITHM_TABLE[3].0, b"SHA-256-SESS");
        assert_eq!(ALGORITHM_TABLE[4].0, b"SHA-512-256");
        assert_eq!(ALGORITHM_TABLE[5].0, b"SHA-512-256-SESS");
        assert_eq!(ALGORITHM_TABLE[0].1, DigestAlgo::Md5Sess);
        assert_eq!(ALGORITHM_TABLE[5].1, DigestAlgo::Sha512_256Sess);
    }

    // -- Hexadecimal rendering ---------------------------------------------

    /// `lib/vauth/digest.c:133-150`: LOWERCASE, and the lengths the C's
    /// destination buffers are sized for.
    #[test]
    fn every_digest_is_rendered_in_lowercase_hexadecimal() {
        let md5 = HashKind::Md5.digest_hex(b"");
        let sha256 = HashKind::Sha256.digest_hex(b"");
        let sha512_256 = HashKind::Sha512_256.digest_hex(b"");

        assert_eq!(md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha512_256,
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
        );

        for rendered in [&md5, &sha256, &sha512_256] {
            assert_eq!(
                rendered.as_str(),
                rendered.to_lowercase().as_str(),
                "the renderers must not emit an upper-case digit"
            );
            assert!(rendered
                .bytes()
                .all(|byte| byte.is_ascii_digit()
                    || (b'a'..=b'f').contains(&byte)));
        }
    }

    /// The renderers produce exactly the C buffer size minus its terminator.
    #[test]
    fn the_renderers_produce_the_c_buffer_lengths() {
        let md5 = md5_to_ascii(&[0xAB; MD5_DIGEST_LEN]);
        let sha = sha256_to_ascii(&[0xCD; SHA256_DIGEST_LEN]);
        assert_eq!(md5.len(), MD5_HEX_BUF_LEN - 1);
        assert_eq!(sha.len(), SHA256_HEX_BUF_LEN - 1);
        // Lower case, and a nibble order of high-then-low per byte.
        assert!(md5.starts_with("abab"));
        assert!(sha.starts_with("cdcd"));
    }

    // -- Quoted-string escaping -------------------------------------------

    /// `lib/vauth/digest.c:153-173`: exactly two characters are escaped.
    #[test]
    fn only_the_quote_and_the_backslash_are_escaped() {
        assert_eq!(
            string_quoted(b"a\"b\\c"),
            Ok(b"a\\\"b\\\\c".to_vec()),
            "one backslash before each, and nothing else touched"
        );
        assert_eq!(string_quoted(b"plain"), Ok(b"plain".to_vec()));
        assert_eq!(string_quoted(b"\""), Ok(b"\\\"".to_vec()));
        assert_eq!(string_quoted(b"\\"), Ok(b"\\\\".to_vec()));
    }

    /// Not CR, not LF, not any other control byte. Adding an escape here would
    /// change the emitted bytes.
    #[test]
    fn a_control_byte_is_not_escaped() {
        assert_eq!(string_quoted(b"a\rb"), Ok(b"a\rb".to_vec()));
        assert_eq!(string_quoted(b"a\nb"), Ok(b"a\nb".to_vec()));
        assert_eq!(string_quoted(b"a\tb"), Ok(b"a\tb".to_vec()));
        assert_eq!(string_quoted(&[0x01, 0x7F]), Ok(vec![0x01, 0x7F]));
        // Bytes outside ASCII pass through unchanged too.
        assert_eq!(string_quoted(&[0xC3, 0xA9]), Ok(vec![0xC3, 0xA9]));
    }

    /// `if(!*s) return curlx_strdup("")` -- `:157-158`, the early return that
    /// also produces `realm=""` for a challenge with no realm.
    #[test]
    fn an_empty_value_escapes_to_an_empty_string() {
        assert_eq!(string_quoted(b""), Ok(Vec::new()));
    }

    /// The 2048-byte ceiling of `curlx_dyn_init(&out, 2048)` at `:156`. The
    /// escaping doubles every quote, so an input of half the ceiling in quotes
    /// is exactly at it and one more byte crosses it.
    #[test]
    fn the_escaping_buffer_has_a_ceiling() {
        // curl's dynbuf tests `leng + len + 1 > toobig`
        // (`lib/curlx/dynbuf.c:82-85`), reserving one byte for the terminator
        // it writes, so the usable ceiling is one below the declared one.
        let at_limit = vec![b'x'; DIGEST_QUOTED_MAX - 1];
        assert_eq!(string_quoted(&at_limit), Ok(at_limit.clone()));

        let over = vec![b'x'; DIGEST_QUOTED_MAX];
        assert_eq!(string_quoted(&over), Err(CURLcode::TooLarge));

        // The escaping doubles every quote, so half the ceiling in quotes is
        // already over it.
        let quotes = vec![b'"'; DIGEST_QUOTED_MAX / 2];
        assert_eq!(string_quoted(&quotes), Err(CURLcode::TooLarge));
        let just_under = vec![b'"'; DIGEST_QUOTED_MAX / 2 - 1];
        assert!(string_quoted(&just_under).is_ok());
    }

    // -- Pair extraction ---------------------------------------------------

    /// A comma inside a quoted value is content, not a terminator.
    #[test]
    fn a_quoted_value_may_contain_a_comma() {
        let pair = get_pair(b"qop=\"auth,auth-int\", realm=\"rlm\"")
            .expect("a well-formed pair");
        assert_eq!(pair.key, b"qop");
        assert_eq!(pair.content, b"auth,auth-int");
        assert_eq!(pair.rest, b", realm=\"rlm\"");
    }

    /// Outside quotes a comma ends the value, and it is consumed.
    #[test]
    fn an_unquoted_value_is_terminated_by_a_comma() {
        let pair = get_pair(b"stale=true,realm=\"rlm\"").expect("a pair");
        assert_eq!(pair.key, b"stale");
        assert_eq!(pair.content, b"true");
        // The comma is gone: `c = 0; continue` runs the C's `str++` first.
        assert_eq!(pair.rest, b"realm=\"rlm\"");
    }

    /// The backslash is dropped and the byte after it is taken literally.
    #[test]
    fn an_escaped_quote_inside_a_quoted_value_is_unescaped() {
        let pair = get_pair(b"realm=\"a\\\"b\"").expect("a pair");
        assert_eq!(pair.content, b"a\"b");
        assert_eq!(pair.rest, b"");

        // An escaped backslash likewise yields one backslash.
        let pair = get_pair(b"realm=\"a\\\\b\"").expect("a pair");
        assert_eq!(pair.content, b"a\\b");

        // And the escape is general, not quote-specific: the C drops the
        // backslash before whatever follows it.
        let pair = get_pair(b"realm=\"a\\nb\"").expect("a pair");
        assert_eq!(pair.content, b"anb");
    }

    /// A CR or LF inside quotes is the C's "No closing quote" failure.
    #[test]
    fn a_line_ending_inside_a_quoted_value_is_a_failure() {
        assert!(get_pair(b"realm=\"unterminated\r\n").is_none());
        assert!(get_pair(b"realm=\"unterminated\n").is_none());
    }

    /// Outside quotes the same bytes merely end the value.
    #[test]
    fn a_line_ending_outside_quotes_ends_the_value() {
        let pair = get_pair(b"stale=true\r\n").expect("a pair");
        assert_eq!(pair.content, b"true");
        assert_eq!(pair.rest, b"\n");
    }

    /// A quote inside an unquoted value is a failure.
    #[test]
    fn a_quote_inside_an_unquoted_value_is_a_failure() {
        assert!(get_pair(b"realm=abc\"def").is_none());
    }

    /// The C's "No character after backslash".
    #[test]
    fn a_trailing_backslash_is_a_failure() {
        assert!(get_pair(b"realm=\"abc\\").is_none());
    }

    /// `if('=' != *str++) return FALSE` -- "eek, no match". This is also how
    /// the decode loop terminates.
    #[test]
    fn a_key_without_an_equals_sign_is_a_failure() {
        assert!(get_pair(b"realm").is_none());
        assert!(get_pair(b"").is_none());
        assert!(get_pair(b", ").is_none());
    }

    /// The deliberate sloppiness: a quoted value that simply runs out of input
    /// succeeds, because only CR and LF are failures inside quotes.
    #[test]
    fn an_unterminated_quoted_value_succeeds() {
        let pair = get_pair(b"realm=\"never closed").expect("the C's TRUE");
        assert_eq!(pair.content, b"never closed");
        assert_eq!(pair.rest, b"");
    }

    /// An empty quoted value is a pair with empty content, not a failure --
    /// which is what lets a server send `realm=""`.
    #[test]
    fn an_empty_quoted_value_is_accepted() {
        let pair = get_pair(b"realm=\"\", nonce=\"n\"").expect("a pair");
        assert_eq!(pair.key, b"realm");
        assert_eq!(pair.content, b"");
        assert_eq!(pair.rest, b", nonce=\"n\"");
    }

    /// The key is bounded at `DIGEST_MAX_VALUE_LENGTH - 1`. A key of exactly
    /// that length followed by `'='` succeeds; one byte more fails, because the
    /// walk stops with the cursor on a byte that is not `'='`.
    #[test]
    fn the_key_length_bound_is_the_c_bound() {
        let longest = DIGEST_MAX_VALUE_LENGTH - 1;

        let mut input = vec![b'k'; longest];
        input.extend_from_slice(b"=v");
        let pair = get_pair(&input).expect("255 key bytes are admissible");
        assert_eq!(pair.key.len(), longest);
        assert_eq!(pair.content, b"v");

        let mut too_long = vec![b'k'; longest + 1];
        too_long.extend_from_slice(b"=v");
        assert!(get_pair(&too_long).is_none());
    }

    /// The content loop is bounded at `DIGEST_MAX_CONTENT_LENGTH - 1`
    /// ITERATIONS, not bytes kept: an escaped pair spends two of the budget
    /// and contributes one byte, so a value made entirely of escaped quotes
    /// yields half as much content as the budget allows.
    #[test]
    fn the_content_budget_bounds_work_and_not_only_bytes() {
        let budget = DIGEST_MAX_CONTENT_LENGTH - 1;

        let mut plain = b"k=".to_vec();
        plain.extend(core::iter::repeat(b'v').take(budget + 100));
        let pair = get_pair(&plain).expect("a pair");
        assert_eq!(pair.content.len(), budget);

        // `budget / 2` escaped pairs spend `budget - 1` of the budget, and
        // the closing quote spends the last unit.
        let mut escaped = b"k=\"".to_vec();
        for _ in 0..budget / 2 {
            escaped.extend_from_slice(b"\\\"");
        }
        escaped.extend_from_slice(b"\"");
        let pair = get_pair(&escaped).expect("a pair");
        assert_eq!(
            pair.content.len(),
            budget / 2,
            "two budget units per escaped pair"
        );

        // Exhausting the budget mid-escape leaves the escape flag set, which
        // is the C's "No character after backslash" failure at `:122-123`
        // reached through the counter rather than through the end of input.
        let mut mid_escape = b"k=\"".to_vec();
        for _ in 0..budget / 2 + 1 {
            mid_escape.extend_from_slice(b"\\\"");
        }
        assert!(get_pair(&mid_escape).is_none());
    }

    // -- Challenge decode --------------------------------------------------

    /// The C's own documented example, `lib/http_digest.c:36`.
    #[test]
    fn the_c_example_challenge_decodes() {
        let digest =
            decode(b"realm=\"testrealm\", nonce=\"1053604598\"").expect("ok");
        assert_eq!(digest.realm.as_deref(), Some(&b"testrealm"[..]));
        assert_eq!(digest.nonce.as_deref(), Some(&b"1053604598"[..]));
        assert_eq!(digest.qop, None);
        assert_eq!(digest.opaque, None);
        assert_eq!(digest.algorithm, None);
        assert_eq!(digest.algo, DigestAlgo::Md5);
        assert!(!digest.stale);
        assert!(!digest.userhash);
        assert_eq!(digest.nc, 0);
    }

    /// `curl_strequal` folds case, so every directive name does.
    #[test]
    fn directive_names_are_matched_case_insensitively() {
        let digest = decode(
            b"REALM=\"rlm\", NoNcE=\"n\", QOP=\"AUTH\", Algorithm=md5, \
              OPAQUE=\"o\", UserHash=TRUE, STALE=True",
        )
        .expect("ok");
        assert_eq!(digest.realm.as_deref(), Some(&b"rlm"[..]));
        assert_eq!(digest.nonce.as_deref(), Some(&b"n"[..]));
        assert_eq!(digest.qop.as_deref(), Some(&b"auth"[..]));
        assert_eq!(digest.opaque.as_deref(), Some(&b"o"[..]));
        assert_eq!(digest.algo, DigestAlgo::Md5);
        assert!(digest.userhash);
        assert!(digest.stale);
    }

    /// "Unknown specifier, ignore it!" -- `:624-626`. `domain` is the directive
    /// most often expected here, and it is ignored like any other.
    #[test]
    fn an_unknown_directive_is_ignored() {
        let digest = decode(
            b"realm=\"rlm\", domain=\"/a /b\", charset=UTF-8, nonce=\"n\"",
        )
        .expect("ok");
        assert_eq!(digest.realm.as_deref(), Some(&b"rlm"[..]));
        assert_eq!(digest.nonce.as_deref(), Some(&b"n"[..]));
    }

    /// `stale=true` sets the flag AND resets the count -- "we make a new nonce
    /// now", `:537-540`. Both effects are required.
    #[test]
    fn stale_true_sets_the_flag_and_resets_the_count() {
        let digest =
            decode(b"realm=\"rlm\", nonce=\"n\", stale=true").expect("ok");
        assert!(digest.is_stale());
        assert_eq!(digest.nonce_count(), 1);

        // Any other value leaves both untouched.
        let digest =
            decode(b"realm=\"rlm\", nonce=\"n\", stale=false").expect("ok");
        assert!(!digest.is_stale());
        assert_eq!(digest.nonce_count(), 0);
    }

    /// `auth` wins whenever it is offered, whatever the order or the casing,
    /// and the stored value is the canonical lower-case literal rather than the
    /// server's spelling.
    #[test]
    fn qop_prefers_auth_over_auth_int() {
        for offered in [
            &b"qop=\"auth,auth-int\""[..],
            &b"qop=\"auth-int,auth\""[..],
            &b"qop=\"AUTH\""[..],
            &b"qop=\" auth,auth-int\""[..],
            &b"qop=\"auth-int, AUTH,auth-conf\""[..],
        ] {
            let mut challenge = b"realm=\"rlm\", nonce=\"n\", ".to_vec();
            challenge.extend_from_slice(offered);
            let digest = decode(&challenge).expect("ok");
            assert_eq!(
                digest.qop.as_deref(),
                Some(&b"auth"[..]),
                "auth must win for {}",
                String::from_utf8_lossy(offered)
            );
        }
    }

    /// `auth-int` is selected only when `auth` was not offered.
    #[test]
    fn qop_selects_auth_int_when_only_it_is_offered() {
        let digest = decode(b"realm=\"rlm\", nonce=\"n\", qop=\"auth-int\"")
            .expect("ok");
        assert_eq!(digest.qop.as_deref(), Some(&b"auth-int"[..]));

        let digest = decode(b"realm=\"rlm\", nonce=\"n\", qop=\"AUTH-INT\"")
            .expect("ok");
        assert_eq!(digest.qop.as_deref(), Some(&b"auth-int"[..]));
    }

    /// A blank BEFORE a token is skipped; a blank AFTER one is not.
    #[test]
    fn a_blank_before_a_qop_token_is_skipped_but_one_after_it_is_not() {
        assert_eq!(
            select_qop(b" auth,auth-int"),
            Some(DIGEST_QOP_VALUE_STRING_AUTH)
        );
        assert_eq!(
            select_qop(b"auth , auth-int"),
            Some(DIGEST_QOP_VALUE_STRING_AUTH_INT),
            "a trailing blank defeats the auth token, so auth-int wins"
        );
        assert_eq!(
            select_qop(b" auth , auth-int "),
            None,
            "both tokens carry a trailing blank, so neither matches"
        );
        // A tab is blank too, on the leading side.
        assert_eq!(select_qop(b"\tauth"), Some(DIGEST_QOP_VALUE_STRING_AUTH));
    }

    /// The HTTP tokeniser recognises two literals and no more:
    /// `auth-conf` belongs to the SASL tokeniser at `:242` and is never
    /// selected here.
    #[test]
    fn an_auth_conf_only_qop_selects_nothing() {
        let digest = decode(b"realm=\"rlm\", nonce=\"n\", qop=\"auth-conf\"")
            .expect("ok");
        assert_eq!(digest.qop, None);

        // Nor is an unknown token selected.
        let digest =
            decode(b"realm=\"rlm\", nonce=\"n\", qop=\"future\"").expect("ok");
        assert_eq!(digest.qop, None);
    }

    /// `curlx_str_until(&token, &out, 32, ',')` -- a token longer than
    /// [`DIGEST_QOP_TOKEN_MAX`] ends the walk, so nothing after it is seen.
    #[test]
    fn the_qop_token_length_is_bounded() {
        let long = "x".repeat(DIGEST_QOP_TOKEN_MAX + 1);
        assert_eq!(select_qop(long.as_bytes()), None);

        // The over-long token stops the walk, so a following `auth` is never
        // reached -- the same as the C, whose `while(!...)` exits on STRE_BIG.
        let stopped = format!("{long},auth");
        assert_eq!(select_qop(stopped.as_bytes()), None);

        // A token of exactly the bound is still read.
        let at_bound = "x".repeat(DIGEST_QOP_TOKEN_MAX);
        assert_eq!(
            select_qop(format!("{at_bound},auth").as_bytes()),
            Some(DIGEST_QOP_VALUE_STRING_AUTH)
        );
    }

    /// All six spellings map, in any case, and none is gated on a build
    /// configuration -- `CURL_HAVE_SHA512_256` is unconditional at
    /// `lib/curl_sha512_256.h:32`.
    #[test]
    fn all_six_algorithm_spellings_map() {
        let expected = [
            (&b"MD5"[..], DigestAlgo::Md5),
            (&b"MD5-sess"[..], DigestAlgo::Md5Sess),
            (&b"SHA-256"[..], DigestAlgo::Sha256),
            (&b"SHA-256-SESS"[..], DigestAlgo::Sha256Sess),
            (&b"SHA-512-256"[..], DigestAlgo::Sha512_256),
            (&b"SHA-512-256-SESS"[..], DigestAlgo::Sha512_256Sess),
        ];

        for (spelling, algo) in expected {
            // A session form needs a qop to survive validation 3.
            let mut challenge =
                b"realm=\"rlm\", nonce=\"n\", qop=\"auth\", algorithm="
                    .to_vec();
            challenge.extend_from_slice(spelling);
            let digest = decode(&challenge).expect("ok");
            assert_eq!(digest.algorithm(), algo);

            // And the comparison folds case in both directions.
            let folded = String::from_utf8_lossy(spelling).to_lowercase();
            let mut challenge =
                b"realm=\"rlm\", nonce=\"n\", qop=\"auth\", algorithm="
                    .to_vec();
            challenge.extend_from_slice(folded.as_bytes());
            let digest = decode(&challenge).expect("ok");
            assert_eq!(digest.algorithm(), algo);
        }
    }

    /// `else return CURLE_BAD_CONTENT_ENCODING;` -- `:616-617`.
    #[test]
    fn an_unknown_algorithm_is_rejected() {
        assert_eq!(
            decode(b"realm=\"rlm\", nonce=\"n\", algorithm=SHA-1"),
            Err(CURLcode::BadContentEncoding)
        );
        assert_eq!(
            decode(b"realm=\"rlm\", nonce=\"n\", algorithm=\"\""),
            Err(CURLcode::BadContentEncoding)
        );
    }

    /// The raw spelling is kept verbatim, because the header echoes it.
    #[test]
    fn the_raw_algorithm_spelling_is_kept() {
        let digest = decode(
            b"realm=\"rlm\", nonce=\"n\", qop=\"auth\", algorithm=sha-256-sess",
        )
        .expect("ok");
        assert_eq!(digest.algorithm.as_deref(), Some(&b"sha-256-sess"[..]));
        assert_eq!(digest.algorithm(), DigestAlgo::Sha256Sess);
    }

    /// Validation 1, `:640-644`: a second challenge without `stale=true` means
    /// the credentials just sent were wrong.
    #[test]
    fn a_second_challenge_without_stale_is_rejected() {
        let mut digest = DigestData::default();
        decode_digest_http_message(b"realm=\"rlm\", nonce=\"n1\"", &mut digest)
            .expect("the first challenge is accepted");
        assert_eq!(
            decode_digest_http_message(
                b"realm=\"rlm\", nonce=\"n2\"",
                &mut digest
            ),
            Err(CURLcode::BadContentEncoding)
        );
    }

    /// ... and with `stale=true` it is accepted, with the count reset to 1.
    #[test]
    fn a_second_challenge_with_stale_is_accepted_and_resets_the_count() {
        let mut digest = DigestData::default();
        decode_digest_http_message(b"realm=\"rlm\", nonce=\"n1\"", &mut digest)
            .expect("the first challenge is accepted");
        // Emit once so that the count has moved off its initial value.
        digest.qop = Some(b"auth".to_vec());
        let _ = emit(&mut digest);
        assert_eq!(digest.nonce_count(), 2);

        decode_digest_http_message(
            b"realm=\"rlm\", nonce=\"n2\", stale=true",
            &mut digest,
        )
        .expect("a stale challenge is accepted");
        assert_eq!(digest.nonce_count(), 1);
        assert!(digest.is_stale());
        assert_eq!(digest.nonce.as_deref(), Some(&b"n2"[..]));
    }

    /// Validation 2, `:646-648`.
    #[test]
    fn a_challenge_without_a_nonce_is_rejected() {
        assert_eq!(
            decode(b"realm=\"testrealm\""),
            Err(CURLcode::BadContentEncoding)
        );
        assert_eq!(decode(b""), Err(CURLcode::BadContentEncoding));
    }

    /// Validation 3, `:650-652`: every session form needs a qop, and no
    /// non-session form does.
    #[test]
    fn a_session_algorithm_without_a_qop_is_rejected() {
        for spelling in [
            &b"MD5-sess"[..],
            &b"SHA-256-SESS"[..],
            &b"SHA-512-256-SESS"[..],
        ] {
            let mut challenge =
                b"realm=\"rlm\", nonce=\"n\", algorithm=".to_vec();
            challenge.extend_from_slice(spelling);
            assert_eq!(
                decode(&challenge),
                Err(CURLcode::BadContentEncoding),
                "{} requires a qop",
                String::from_utf8_lossy(spelling)
            );
        }

        for spelling in [&b"MD5"[..], &b"SHA-256"[..], &b"SHA-512-256"[..]] {
            let mut challenge =
                b"realm=\"rlm\", nonce=\"n\", algorithm=".to_vec();
            challenge.extend_from_slice(spelling);
            assert!(decode(&challenge).is_ok());
        }
    }

    /// `userhash` takes `true` and ignores anything else.
    #[test]
    fn userhash_true_is_recognised_and_anything_else_ignored() {
        let digest =
            decode(b"realm=\"rlm\", nonce=\"n\", userhash=TRUE").expect("ok");
        assert!(digest.userhash);

        let digest =
            decode(b"realm=\"rlm\", nonce=\"n\", userhash=maybe").expect("ok");
        assert!(!digest.userhash);

        // Only ever set, never cleared: a second occurrence saying anything
        // else leaves the flag true.
        let digest = decode(
            b"realm=\"rlm\", nonce=\"n\", userhash=true, userhash=false",
        )
        .expect("ok");
        assert!(digest.userhash);
    }

    /// The cleanup at the top of the decode wipes every field before the walk,
    /// so nothing survives a new challenge except through the `before` flag.
    #[test]
    fn the_decode_wipes_previous_state_first() {
        let mut digest = DigestData::default();
        decode_digest_http_message(
            b"realm=\"r1\", nonce=\"n1\", opaque=\"o1\", qop=\"auth\", \
              algorithm=MD5-sess, userhash=true",
            &mut digest,
        )
        .expect("ok");

        decode_digest_http_message(b"nonce=\"n2\", stale=true", &mut digest)
            .expect("ok");

        assert_eq!(digest.nonce.as_deref(), Some(&b"n2"[..]));
        assert_eq!(digest.realm, None);
        assert_eq!(digest.opaque, None);
        assert_eq!(digest.qop, None);
        assert_eq!(digest.algorithm, None);
        assert_eq!(digest.algorithm(), DigestAlgo::Md5);
        assert!(!digest.userhash);
        // The client nonce is wiped too, so a new challenge draws a new one.
        assert_eq!(digest.cnonce, None);
    }

    /// A challenge may be blank-separated rather than comma-separated, and may
    /// carry extra blanks anywhere -- `:524-526` and `:631-637`.
    #[test]
    fn blanks_and_commas_are_both_tolerated() {
        let digest = decode(b"  realm=\"rlm\"  ,   nonce=\"n\"  ").expect("ok");
        assert_eq!(digest.realm.as_deref(), Some(&b"rlm"[..]));
        assert_eq!(digest.nonce.as_deref(), Some(&b"n"[..]));

        let digest = decode(b"realm=\"rlm\" nonce=\"n\"").expect("ok");
        assert_eq!(digest.nonce.as_deref(), Some(&b"n"[..]));
    }

    // -- Emission ----------------------------------------------------------

    /// All six algorithm spellings against all three qop forms: eighteen
    /// complete headers, asserted byte for byte.
    #[test]
    fn every_algorithm_and_qop_combination_emits_the_expected_header() {
        #[rustfmt::skip]
        let cases: [(DigestAlgo, &[u8], Option<&[u8]>, &str); 18] = [
        (DigestAlgo::Md5, b"MD5", Some(b"auth"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth, response=\"aa729993c83be80694df863e6000691d\", algorithm=MD5"),
        (DigestAlgo::Md5, b"MD5", Some(b"auth-int"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth-int, response=\"3238427b2e0a9dcef39799ca3c8cee52\", algorithm=MD5"),
        (DigestAlgo::Md5, b"MD5", None,
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", response=\"c55f7f30d83d774a3d2dcacf725abaca\", algorithm=MD5"),
        (DigestAlgo::Md5Sess, b"MD5-sess", Some(b"auth"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth, response=\"d57371827981c543063a0518cd868113\", algorithm=MD5-sess"),
        (DigestAlgo::Md5Sess, b"MD5-sess", Some(b"auth-int"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth-int, response=\"dc58ca27759470659e4d15e23a27f65c\", algorithm=MD5-sess"),
        (DigestAlgo::Md5Sess, b"MD5-sess", None,
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", response=\"413335a448b79c3757b04acafd327ac5\", algorithm=MD5-sess"),
        (DigestAlgo::Sha256, b"SHA-256", Some(b"auth"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth, response=\"eb8c7f6181b451b9ed73659e884e5c1995f605dcee4e251a3d1513b46018875d\", algorithm=SHA-256"),
        (DigestAlgo::Sha256, b"SHA-256", Some(b"auth-int"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth-int, response=\"8d8fb86650dffc6f8a15515651911dcc9f7400bd00d27f3952529c0accb441dd\", algorithm=SHA-256"),
        (DigestAlgo::Sha256, b"SHA-256", None,
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", response=\"6f0389a6425f706f9e96844fbc1f63a400495a5c834fce88822e742a0cf54359\", algorithm=SHA-256"),
        (DigestAlgo::Sha256Sess, b"SHA-256-SESS", Some(b"auth"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth, response=\"18dd4ff3b6e942a5023de9f95a5aa03dda5ec1fbfd65cac766fccdf9ffbd9708\", algorithm=SHA-256-SESS"),
        (DigestAlgo::Sha256Sess, b"SHA-256-SESS", Some(b"auth-int"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth-int, response=\"897411ea1fc3d5a423c081ee3a6c16f7a4f19b789314548df54a5dea39412ceb\", algorithm=SHA-256-SESS"),
        (DigestAlgo::Sha256Sess, b"SHA-256-SESS", None,
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", response=\"59b7e0a143991619a0512f8556f10615153b9a73726788cc63c2cf03fc4a7e7c\", algorithm=SHA-256-SESS"),
        (DigestAlgo::Sha512_256, b"SHA-512-256", Some(b"auth"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth, response=\"72c83df2381075a88c682a3e4de3adc49fe92ce4db55dbe5cc7f04f349f2fa33\", algorithm=SHA-512-256"),
        (DigestAlgo::Sha512_256, b"SHA-512-256", Some(b"auth-int"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth-int, response=\"fcf2532513e2b114b2debe33d07791941279611a27062e7cfa78e93ea59bd536\", algorithm=SHA-512-256"),
        (DigestAlgo::Sha512_256, b"SHA-512-256", None,
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", response=\"55092f59e7556a09b9d3584de16f27b04654ddc4abd264290f2d6d09a7b1658a\", algorithm=SHA-512-256"),
        (DigestAlgo::Sha512_256Sess, b"SHA-512-256-SESS", Some(b"auth"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth, response=\"04579b2d0054e93fd54e875587e01286062e23c48896147d4a13f79425c57dd6\", algorithm=SHA-512-256-SESS"),
        (DigestAlgo::Sha512_256Sess, b"SHA-512-256-SESS", Some(b"auth-int"),
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth-int, response=\"743cc6b9e32975e6e508fc42814280fb0e20c206a8231a8be20885e8cacbcc31\", algorithm=SHA-512-256-SESS"),
        (DigestAlgo::Sha512_256Sess, b"SHA-512-256-SESS", None,
         "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", response=\"829c21d1c0185b9ccdd56c90f64ed8a7c4327f9d608b84d5039137664332f587\", algorithm=SHA-512-256-SESS"),
        ];

        for (algo, spelling, qop, expected) in cases {
            let mut digest = state(algo, qop, Some(spelling));
            assert_eq!(
                emit(&mut digest),
                expected,
                "{} with qop {:?}",
                String::from_utf8_lossy(spelling),
                qop.map(String::from_utf8_lossy)
            );
        }
    }

    /// `nc` is eight lowercase zero-padded hexadecimal digits, and the
    /// increment happens AFTER the emission -- `:890` and `:902-903`. So the
    /// first request carries `00000001`.
    #[test]
    fn the_nonce_count_is_eight_digits_and_increments_after_emission() {
        let mut digest = state(DigestAlgo::Md5, Some(b"auth"), Some(b"MD5"));
        assert_eq!(digest.nonce_count(), 0);

        let first = emit(&mut digest);
        assert!(first.contains(", nc=00000001, "), "{first}");
        assert_eq!(
            digest.nonce_count(),
            2,
            "the count is incremented after the append, not before"
        );

        let second = emit(&mut digest);
        assert!(second.contains(", nc=00000002, "), "{second}");
        assert_eq!(
            second,
            "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000002, qop=auth, response=\"d5114c4ccaaad2ef2a9bdf7c354a4fe7\", algorithm=MD5"
        );

        // Eight digits, lower case, zero padded -- from the count itself so
        // that a value above 15 cannot pass by accident.
        let mut digest = state(DigestAlgo::Md5, Some(b"auth"), None);
        digest.nc = 0x00AB_CDEF;
        let emitted = emit(&mut digest);
        assert!(emitted.contains(", nc=00abcdef, "), "{emitted}");
    }

    /// A no-qop branch emits no `nc` at all and never increments it.
    #[test]
    fn the_no_qop_branch_emits_no_count_and_does_not_increment() {
        let mut digest = state(DigestAlgo::Md5, None, None);
        let emitted = emit(&mut digest);
        assert!(!emitted.contains("nc="), "{emitted}");
        assert!(!emitted.contains("cnonce="), "{emitted}");
        assert!(!emitted.contains("qop="), "{emitted}");
        // `if(!digest->nc) digest->nc = 1;` still ran, and nothing after it
        // touched the field.
        assert_eq!(digest.nonce_count(), 1);
    }

    /// `tests/data/test64`'s `<protocol>` block, reproduced byte for byte.
    ///
    /// The fixture's target is `/64"` -- a quote inside the path, deliberately.
    /// So this is simultaneously the corpus oracle and the proof that the
    /// escaped target reaches the `uri=` directive while the RAW target reaches
    /// HA2: hashing the escaped form would give
    /// `eacb00efdf72fed986b32b8d42e99bb9` instead.
    #[test]
    fn test64_is_reproduced_byte_for_byte() {
        let mut digest = DigestData::default();
        input_digest(
            b"Digest realm=\"testrealm\", nonce=\"1053604145\"",
            &mut digest,
        )
        .expect("the fixture's challenge decodes");

        let mut rng = test_rng();
        let credential = create_digest_http_message(
            &mut digest,
            b"testuser",
            b"testpass",
            b"GET",
            b"/64\"",
            &mut rng,
        )
        .expect("ok");

        assert_eq!(
            credential,
            "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\\\"\", response=\"1ee14b238b3259f17602e9ce41491ef9\""
        );
    }

    /// The same point stated on its own, with a target needing both escapes.
    #[test]
    fn the_hash_uses_the_raw_target_and_the_header_the_escaped_one() {
        let mut digest = state(DigestAlgo::Md5, None, None);
        let mut rng = test_rng();
        let with_escapes = create_digest_http_message(
            &mut digest,
            USER,
            PASS,
            METHOD,
            b"/a\"b\\c",
            &mut rng,
        )
        .expect("ok");
        assert!(
            with_escapes.contains("uri=\"/a\\\"b\\\\c\""),
            "the header carries the escaped target: {with_escapes}"
        );

        // The response must equal the one computed over the RAW target, which
        // is what the same target hashed unescaped produces.
        let mut reference = state(DigestAlgo::Md5, None, None);
        let mut rng = test_rng();
        let raw_reference = create_digest_http_message(
            &mut reference,
            USER,
            PASS,
            METHOD,
            b"/a\"b\\c",
            &mut rng,
        )
        .expect("ok");
        assert_eq!(with_escapes, raw_reference);

        // ... and must NOT equal one computed over the escaped target.
        let mut wrong = state(DigestAlgo::Md5, None, None);
        let mut rng = test_rng();
        let escaped_input = create_digest_http_message(
            &mut wrong,
            USER,
            PASS,
            METHOD,
            b"/a\\\"b\\\\c",
            &mut rng,
        )
        .expect("ok");
        let response_of = |line: &str| {
            line.rsplit("response=\"")
                .next()
                .map(|tail| tail.trim_end_matches('"').to_owned())
        };
        assert_ne!(response_of(&with_escapes), response_of(&escaped_input));
    }

    /// `realm` is NEVER omitted: the C allocates a one-byte NUL when the
    /// challenge carried no realm (`:868-872`), so the header emits `realm=""`.
    #[test]
    fn an_absent_realm_still_emits_an_empty_realm() {
        let mut digest = DigestData::default();
        input_digest(b"Digest nonce=\"1053604145\"", &mut digest)
            .expect("a realmless challenge is well formed");
        assert_eq!(digest.realm, None);

        let emitted = emit(&mut digest);
        assert_eq!(
            emitted,
            "username=\"testuser\", realm=\"\", nonce=\"1053604145\", uri=\"/64\", response=\"fad56d09a099fdb83b716afa195ab131\""
        );
        assert!(emitted.contains("realm=\"\""));
    }

    /// The three trailers, in the C's order, in every combination.
    #[test]
    fn the_three_optional_trailers_appear_in_order() {
        for opaque in [false, true] {
            for algorithm in [false, true] {
                for userhash in [false, true] {
                    let mut digest = state(
                        DigestAlgo::Md5,
                        Some(b"auth"),
                        if algorithm { Some(b"MD5") } else { None },
                    );
                    if opaque {
                        digest.opaque = Some(b"opq\"e".to_vec());
                    }
                    digest.userhash = userhash;

                    let emitted = emit(&mut digest);
                    let mut expected = String::new();
                    if opaque {
                        // Quoted AND escaped, unlike `algorithm`.
                        expected.push_str(", opaque=\"opq\\\"e\"");
                    }
                    if algorithm {
                        expected.push_str(", algorithm=MD5");
                    }
                    if userhash {
                        expected.push_str(", userhash=true");
                    }

                    let at = emitted
                        .find("response=\"")
                        .expect("a response directive");
                    let tail = &emitted[at..];
                    let after =
                        tail.find("\", ").map_or("", |cut| &tail[cut + 1..]);
                    assert_eq!(
                        after, expected,
                        "opaque={opaque} algorithm={algorithm} \
                         userhash={userhash}"
                    );
                }
            }
        }
    }

    /// Neither `domain` nor `stale` is ever emitted, whatever the challenge
    /// carried.
    #[test]
    fn neither_domain_nor_stale_is_ever_emitted() {
        let mut digest = DigestData::default();
        input_digest(
            b"Digest realm=\"testrealm\", nonce=\"1053604145\", \
              domain=\"/a /b\", stale=true, opaque=\"o\", qop=\"auth\", \
              algorithm=MD5",
            &mut digest,
        )
        .expect("ok");
        assert!(digest.is_stale());

        let emitted = emit(&mut digest);
        assert!(!emitted.contains("domain"), "{emitted}");
        assert!(!emitted.contains("stale"), "{emitted}");
        // The stale directive did its only job: the count restarts at 1.
        assert!(emitted.contains(", nc=00000001, "), "{emitted}");
    }

    /// The `algorithm` trailer echoes the server's own spelling, unquoted.
    #[test]
    fn the_algorithm_is_echoed_with_the_servers_spelling() {
        for spelling in [
            &b"SHA-256-SESS"[..],
            &b"sha-256-sess"[..],
            &b"Sha-256-SeSs"[..],
        ] {
            let mut digest = DigestData::default();
            let mut challenge =
                b"Digest realm=\"testrealm\", nonce=\"1053604145\", \
                  qop=\"auth\", algorithm="
                    .to_vec();
            challenge.extend_from_slice(spelling);
            input_digest(&challenge, &mut digest).expect("ok");

            let emitted = emit(&mut digest);
            let expected =
                format!(", algorithm={}", String::from_utf8_lossy(spelling));
            assert!(emitted.ends_with(&expected), "{emitted}");
            // Unquoted: no quote immediately after the equals sign.
            assert!(!emitted.contains("algorithm=\""), "{emitted}");
        }
    }

    /// The client nonce is sixteen unpadded base64 characters derived from
    /// twelve injected bytes, and it is passed unescaped.
    #[test]
    fn the_client_nonce_is_sixteen_unpadded_base64_characters() {
        let mut rng = test_rng();
        let cnonce = generate_cnonce(&mut rng).expect("ok");
        assert_eq!(cnonce.len(), CNONCE_BASE64_LEN);
        assert_eq!(cnonce, CNONCE.as_bytes());
        assert!(!cnonce.contains(&b'='), "12 bytes need no padding");
        // Not the SASL path's 32 hexadecimal characters.
        assert_ne!(cnonce.len(), 32);
        assert!(
            cnonce.iter().any(|byte| byte.is_ascii_uppercase()),
            "base64, not hexadecimal"
        );

        // And it reaches the header raw, with no escaping applied.
        let mut digest = state(DigestAlgo::Md5, Some(b"auth"), None);
        let emitted = emit(&mut digest);
        assert!(emitted.contains(&format!(", cnonce=\"{CNONCE}\", ")));
    }

    /// `if(!digest->cnonce)` -- generated once and then reused, so a second
    /// request in the same exchange quotes the same client nonce.
    #[test]
    fn the_client_nonce_is_generated_once_and_reused() {
        let mut digest = state(DigestAlgo::Md5, Some(b"auth"), None);
        let first = emit(&mut digest);
        let stored = digest.cnonce.clone();
        let second = emit(&mut digest);

        assert_eq!(stored, digest.cnonce);
        assert!(first.contains(CNONCE));
        assert!(second.contains(CNONCE));

        // A pre-set client nonce is left alone, which is what lets a
        // known-answer vector be reproduced at all.
        let mut digest = state(DigestAlgo::Md5, Some(b"auth"), None);
        digest.cnonce = Some(b"0a4f113b".to_vec());
        let emitted = emit(&mut digest);
        assert!(emitted.contains(", cnonce=\"0a4f113b\", "), "{emitted}");
    }

    /// RFC 7616 section 3.4.4: the username is replaced by the hash of
    /// `user ":" realm`, and `userhash=true` is appended. HA1 still uses the
    /// PLAIN username -- `:753` interpolates `userp`, not `userh` -- so the
    /// response is unchanged from the non-userhash case.
    #[test]
    fn userhash_replaces_the_username_with_the_hash_of_user_and_realm() {
        let mut plain = state(DigestAlgo::Md5, Some(b"auth"), Some(b"MD5"));
        let without = emit(&mut plain);

        let mut digest = state(DigestAlgo::Md5, Some(b"auth"), Some(b"MD5"));
        digest.userhash = true;
        let with = emit(&mut digest);

        assert_eq!(
            with,
            "username=\"abae159524e517bf48f44aabfeb93740\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", cnonce=\"bHJ1Y21ydWNucnVj\", nc=00000001, qop=auth, response=\"aa729993c83be80694df863e6000691d\", algorithm=MD5, userhash=true"
        );
        // The hash of "testuser:testrealm", independently computed.
        assert_eq!(
            HashKind::Md5.digest_hex(b"testuser:testrealm"),
            "abae159524e517bf48f44aabfeb93740"
        );
        // Same response either way: only the username field changed.
        assert!(
            without.contains("response=\"aa729993c83be80694df863e6000691d\"")
        );
    }

    /// `qop=auth-int` hashes the EMPTY string for the body component --
    /// `:811`, under the C's comment "We do not support auth-int for PUT or
    /// POST". Nothing about the request body enters the digest.
    #[test]
    fn auth_int_hashes_the_empty_string() {
        // The auth-int response for the shared scenario equals the one
        // computed with H("") spliced into HA2, and differs from plain auth.
        let mut auth = state(DigestAlgo::Md5, Some(b"auth"), None);
        let mut auth_int = state(DigestAlgo::Md5, Some(b"auth-int"), None);
        let plain = emit(&mut auth);
        let integrity = emit(&mut auth_int);
        assert_ne!(plain, integrity);
        assert!(
            integrity.contains("response=\"3238427b2e0a9dcef39799ca3c8cee52\""),
            "{integrity}"
        );

        // The empty-input digest that goes into HA2, for each algorithm.
        assert_eq!(
            HashKind::Md5.digest_hex(b""),
            "d41d8cd98f00b204e9800998ecf8427e"
        );

        // Both qop forms share the with-qop response formula: they differ only
        // inside HA2, which is why both emit `cnonce`, `nc` and `qop`.
        for line in [&plain, &integrity] {
            assert!(line.contains(", cnonce=\""), "{line}");
            assert!(line.contains(", nc=00000001, "), "{line}");
        }
        assert!(plain.contains(", qop=auth, "));
        assert!(integrity.contains(", qop=auth-int, "));
    }

    /// The username, realm and nonce are escaped in the header while the
    /// response is computed over their unescaped values.
    #[test]
    fn the_username_realm_and_nonce_are_escaped_in_the_header() {
        let mut digest = DigestData::default();
        // The challenge de-escapes `\"` to `"`, and the emission re-escapes it.
        input_digest(b"Digest realm=\"r\\\"m\", nonce=\"n\\\\x\"", &mut digest)
            .expect("ok");
        assert_eq!(digest.realm.as_deref(), Some(&b"r\"m"[..]));
        assert_eq!(digest.nonce.as_deref(), Some(&b"n\\x"[..]));

        let mut rng = test_rng();
        let emitted = create_digest_http_message(
            &mut digest,
            b"a\"b\\c",
            PASS,
            METHOD,
            TARGET,
            &mut rng,
        )
        .expect("ok");

        assert_eq!(
            emitted,
            "username=\"a\\\"b\\\\c\", realm=\"r\\\"m\", nonce=\"n\\\\x\", uri=\"/64\", response=\"b80c0016d206b595df5cc804727bbf83\""
        );
    }

    /// RFC 2617 section 3.5's known-answer vector.
    #[test]
    fn the_rfc2617_known_answer_is_reproduced() {
        let mut digest = DigestData::default();
        input_digest(
            b"Digest realm=\"testrealm@host.com\", \
              qop=\"auth,auth-int\", \
              nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
              opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
            &mut digest,
        )
        .expect("ok");
        digest.cnonce = Some(b"0a4f113b".to_vec());

        let mut rng = test_rng();
        let emitted = create_digest_http_message(
            &mut digest,
            b"Mufasa",
            b"Circle Of Life",
            b"GET",
            b"/dir/index.html",
            &mut rng,
        )
        .expect("ok");

        assert!(
            emitted.contains("response=\"6629fae49393a05397450978507c4ef1\""),
            "{emitted}"
        );
        assert!(emitted.contains(", qop=auth, "), "auth wins over auth-int");
        assert!(
            emitted.ends_with(", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""),
            "{emitted}"
        );
    }

    /// RFC 7616 sections 3.9.1 and 3.9.2: the same exchange under MD5 and
    /// under SHA-256, which is the vector that proves the SHA-256 arm.
    #[test]
    fn the_rfc7616_known_answers_are_reproduced() {
        let cases = [
            (&b"MD5"[..], "8ca523f5e9506fed4657c9700eebdbec"),
            (
                &b"SHA-256"[..],
                "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
            ),
        ];

        for (spelling, expected) in cases {
            let mut digest = DigestData::default();
            let mut challenge =
                b"Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", \
                  algorithm="
                    .to_vec();
            challenge.extend_from_slice(spelling);
            challenge.extend_from_slice(
                b", nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
                  opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",
            );
            input_digest(&challenge, &mut digest).expect("ok");
            digest.cnonce =
                Some(b"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".to_vec());

            let mut rng = test_rng();
            let emitted = create_digest_http_message(
                &mut digest,
                b"Mufasa",
                b"Circle of Life",
                b"GET",
                b"/dir/index.html",
                &mut rng,
            )
            .expect("ok");

            assert!(
                emitted.contains(&format!("response=\"{expected}\"")),
                "{} : {emitted}",
                String::from_utf8_lossy(spelling)
            );
        }
    }

    /// The 4096-byte ceiling of `curlx_dyn_init(&response, 4096)`.
    #[test]
    fn the_response_buffer_has_a_ceiling() {
        let mut digest = state(DigestAlgo::Md5, Some(b"auth"), None);
        digest.opaque = Some(vec![b'o'; DIGEST_RESPONSE_MAX]);
        let mut rng = test_rng();
        assert_eq!(
            create_digest_http_message(
                &mut digest,
                USER,
                PASS,
                METHOD,
                TARGET,
                &mut rng
            ),
            Err(CURLcode::TooLarge)
        );
    }

    // -- HTTP glue ---------------------------------------------------------

    /// `if(!checkprefix("Digest", header) || !ISBLANK(header[6]))` --
    /// `lib/http_digest.c:56`. Both halves, including the cases `authcmp`
    /// would admit but this will not.
    #[test]
    fn the_scheme_token_must_be_followed_by_a_blank() {
        let accepted: [&[u8]; 4] = [
            b"Digest realm=\"testrealm\", nonce=\"1053604598\"",
            b"digest realm=\"testrealm\", nonce=\"1053604598\"",
            b"DIGEST realm=\"testrealm\", nonce=\"1053604598\"",
            b"Digest\trealm=\"testrealm\", nonce=\"1053604598\"",
        ];
        for header in accepted {
            let mut digest = DigestData::default();
            assert!(
                input_digest(header, &mut digest).is_ok(),
                "{}",
                String::from_utf8_lossy(header)
            );
            assert_eq!(digest.nonce.as_deref(), Some(&b"1053604598"[..]));
        }

        let rejected: [&[u8]; 5] = [
            b"Digest",
            b"DigestX realm=\"testrealm\"",
            b"Digest,realm=\"testrealm\"",
            b"Diges realm=\"testrealm\"",
            b"",
        ];
        for header in rejected {
            let mut digest = DigestData::default();
            assert_eq!(
                input_digest(header, &mut digest),
                Err(CURLcode::BadContentEncoding),
                "{}",
                String::from_utf8_lossy(header)
            );
        }
    }

    /// Extra blanks after the token are skipped, and a challenge that is only
    /// blanks is a nonceless challenge rather than a parse failure.
    #[test]
    fn blanks_after_the_token_are_skipped() {
        let mut digest = DigestData::default();
        input_digest(b"Digest    nonce=\"n\"", &mut digest).expect("ok");
        assert_eq!(digest.nonce.as_deref(), Some(&b"n"[..]));

        let mut digest = DigestData::default();
        assert_eq!(
            input_digest(b"Digest   ", &mut digest),
            Err(CURLcode::BadContentEncoding)
        );
    }

    /// `if(!have_chlg) { authp->done = FALSE; return CURLE_OK; }` --
    /// nothing is emitted, and the exchange is NOT finished.
    #[test]
    fn no_challenge_emits_nothing_and_is_not_done() {
        let mut auth = DigestAuth::new();
        auth.set_credentials(false, Credentials::new(Some(USER), Some(PASS)));
        assert!(!auth.states().select(false).have_challenge());

        let emission = mechanism_output(&mut auth, false)
            .expect("no challenge is not an error");
        assert_eq!(emission, AuthEmission::Continuing(String::new()));
        assert!(!emission.is_done(), "C leaves authp->done FALSE");
        assert_eq!(
            emission.header().map(str::len),
            Some(0),
            "an empty line contributes zero bytes to the request"
        );
    }

    /// Runs the mechanism's emitter with the injected clock and generator.
    fn mechanism_output(
        auth: &mut DigestAuth,
        proxy: bool,
    ) -> Result<AuthEmission, CURLcode> {
        let clock = test_clock();
        let mut rng = test_rng();
        let mut ctx = AuthContext {
            proxy,
            request_method: METHOD,
            request_target: TARGET,
            clock: &clock,
            rng: &mut rng,
        };
        auth.output(&mut ctx)
    }

    /// `"%sAuthorization: Digest %s\r\n"` -- `lib/http_digest.c:161-162`, on
    /// both sides, composed by the shared helper.
    #[test]
    fn the_emitted_line_is_the_shared_authorization_shape() {
        for proxy in [false, true] {
            let mut auth = DigestAuth::new();
            auth.set_credentials(
                proxy,
                Credentials::new(Some(USER), Some(PASS)),
            );
            auth.input(
                b"Digest realm=\"testrealm\", nonce=\"1053604145\"",
                proxy,
            )
            .expect("ok");

            let emission = mechanism_output(&mut auth, proxy).expect("ok");
            assert!(emission.is_done(), "Digest finishes in one round");

            let prefix = if proxy { "Proxy-" } else { "" };
            let expected = format!(
                "{prefix}Authorization: Digest username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"/64\", response=\"c55f7f30d83d774a3d2dcacf725abaca\"\r\n"
            );
            assert_eq!(emission, AuthEmission::Final(expected));
        }
    }

    /// The IE-style truncation, and the `if(!tmp)` control flow that decides
    /// it: the truncated copy survives only when `iestyle` is set AND a `'?'`
    /// was found.
    #[test]
    fn iestyle_truncates_only_when_both_conditions_hold() {
        // (iestyle, target, expected uri= value, expected response)
        let cases: [(bool, &[u8], &str, &str); 3] = [
            (true, b"/64?x=1", "/64", "c55f7f30d83d774a3d2dcacf725abaca"),
            (true, b"/64", "/64", "c55f7f30d83d774a3d2dcacf725abaca"),
            (
                false,
                b"/64?x=1",
                "/64?x=1",
                "bccde1ba78ddd86e23e4672f9088cd9b",
            ),
        ];

        for (iestyle, target, uri, response) in cases {
            let mut digest = DigestData::default();
            input_digest(
                b"Digest realm=\"testrealm\", nonce=\"1053604145\"",
                &mut digest,
            )
            .expect("ok");

            let mut rng = test_rng();
            let emitted = output_digest(
                &mut digest,
                &Credentials::new(Some(USER), Some(PASS)),
                iestyle,
                METHOD,
                target,
                &mut rng,
            )
            .expect("ok")
            .expect("a challenge was received");

            // The truncation feeds BOTH the directive and the hash.
            assert_eq!(
                emitted,
                format!(
                    "username=\"testuser\", realm=\"testrealm\", nonce=\"1053604145\", uri=\"{uri}\", response=\"{response}\""
                ),
                "iestyle={iestyle} target={}",
                String::from_utf8_lossy(target)
            );
        }
    }

    /// "not set means empty" -- `:110-115`. Both credentials absent still
    /// produces a well-formed response.
    #[test]
    fn missing_credentials_mean_empty_ones() {
        let mut digest = DigestData::default();
        input_digest(
            b"Digest realm=\"testrealm\", nonce=\"1053604145\"",
            &mut digest,
        )
        .expect("ok");

        let mut rng = test_rng();
        let emitted = output_digest(
            &mut digest,
            &Credentials::none(),
            false,
            METHOD,
            TARGET,
            &mut rng,
        )
        .expect("ok")
        .expect("a challenge was received");

        assert!(emitted.starts_with("username=\"\", "), "{emitted}");
        // The same response an explicit empty pair would produce.
        let mut reference = DigestData::default();
        input_digest(
            b"Digest realm=\"testrealm\", nonce=\"1053604145\"",
            &mut reference,
        )
        .expect("ok");
        let mut rng = test_rng();
        let explicit = output_digest(
            &mut reference,
            &Credentials::new(Some(b""), Some(b"")),
            false,
            METHOD,
            TARGET,
            &mut rng,
        )
        .expect("ok")
        .expect("ok");
        assert_eq!(emitted, explicit);
    }

    /// The two states are independent, and `Curl_http_auth_cleanup_digest`
    /// clears BOTH.
    #[test]
    fn the_two_states_are_independent_and_both_are_cleaned() {
        let mut auth = DigestAuth::new();
        auth.input(b"Digest realm=\"host\", nonce=\"h1\"", false)
            .expect("ok");
        assert!(auth.states().select(false).have_challenge());
        assert!(!auth.states().select(true).have_challenge());

        auth.input(b"Digest realm=\"proxy\", nonce=\"p1\"", true)
            .expect("ok");
        assert_eq!(
            auth.states().select(false).realm.as_deref(),
            Some(&b"host"[..])
        );
        assert_eq!(
            auth.states().select(true).realm.as_deref(),
            Some(&b"proxy"[..])
        );

        auth.cleanup();
        assert!(!auth.states().select(false).have_challenge());
        assert!(!auth.states().select(true).have_challenge());
    }

    /// `Curl_auth_digest_cleanup` resets the algorithm to MD5, not to an
    /// absent value -- `:1037`.
    #[test]
    fn cleanup_resets_the_algorithm_to_md5() {
        let mut digest = DigestData::default();
        input_digest(
            b"Digest realm=\"rlm\", nonce=\"n\", qop=\"auth\", \
              algorithm=SHA-512-256-SESS, opaque=\"o\", userhash=true, \
              stale=true",
            &mut digest,
        )
        .expect("ok");
        assert_eq!(digest.algorithm(), DigestAlgo::Sha512_256Sess);

        digest.cleanup();
        assert_eq!(digest.algorithm(), DigestAlgo::Md5);
        assert_eq!(digest.nonce_count(), 0);
        assert!(!digest.is_stale());
        assert!(!digest.userhash);
        assert_eq!(digest.nonce, None);
        assert_eq!(digest.cnonce, None);
        assert_eq!(digest.realm, None);
        assert_eq!(digest.opaque, None);
        assert_eq!(digest.qop, None);
        assert_eq!(digest.algorithm, None);
        assert_eq!(digest, DigestData::default());
    }

    /// `Curl_auth_is_digest_supported()` returns TRUE unconditionally
    /// (`:311-314`), and the mechanism inherits that answer rather than
    /// restating it.
    #[test]
    fn digest_is_supported_unconditionally() {
        assert!(is_digest_supported());
        assert!(DigestAuth::new().digest_supported());
    }

    /// The scheme's identity and the scope of its state.
    #[test]
    fn the_scheme_is_digest_and_its_state_is_per_transfer() {
        let auth = DigestAuth::new();
        assert_eq!(auth.scheme(), AuthScheme::Digest);
        assert_eq!(auth.scheme().label(), "Digest");
        assert_eq!(auth.scheme().header_scheme(), Some(DIGEST_SCHEME));
        assert!(auth.scheme().needs_request_target());
        assert_eq!(state_scope(AuthScheme::Digest), Some(StateScope::Transfer));
    }

    /// The decoder owns Digest and only Digest.
    #[test]
    fn the_decoder_ignores_a_scheme_it_does_not_own() {
        let mut auth = DigestAuth::new();
        for scheme in [
            AuthScheme::Basic,
            AuthScheme::Bearer,
            AuthScheme::Negotiate,
            AuthScheme::Ntlm,
            AuthScheme::AwsSigv4,
        ] {
            assert_eq!(auth.decode(scheme, false, b"anything"), Ok(()));
            assert!(!auth.states().select(false).have_challenge());
        }

        assert_eq!(
            auth.decode(
                AuthScheme::Digest,
                false,
                b"Digest realm=\"rlm\", nonce=\"n\""
            ),
            Ok(())
        );
        assert!(auth.states().select(false).have_challenge());
    }

    /// Driven through the landed scan, which is where the C's two Digest
    /// diagnostics live: a duplicate header is announced and does nothing
    /// else, and a malformed one sets `authproblem`.
    #[test]
    fn the_scan_reports_the_two_digest_diagnostics() {
        let mut pair = AuthStatePair::ZERO;
        let mut reported = AuthMask::NONE;
        let mut problem = false;
        let mut auth = DigestAuth::new();

        let ((), captured) = with_tracer(|tracer| {
            let mut sink = ChallengeSink::new(
                pair.select_mut(false),
                &mut reported,
                &mut problem,
            );
            input_auth(
                b"Digest realm=\"testrealm\", nonce=\"1053604145\"",
                false,
                &mut sink,
                &mut auth,
                tracer,
            )
            .expect("a well-formed challenge");
            // The same header again: the bit is already in `avail`, so only
            // the diagnostic happens.
            input_auth(
                b"Digest realm=\"testrealm\", nonce=\"1053604145\"",
                false,
                &mut sink,
                &mut auth,
                tracer,
            )
            .expect("a duplicate is not an error");
        });

        assert!(reported.contains(AuthMask::DIGEST));
        assert!(!problem, "a well-formed challenge is not a problem");
        assert!(captured.contains(DIGEST_DUPLICATE), "{captured}");
        assert!(auth.states().select(false).have_challenge());

        // A malformed challenge takes the other branch.
        let mut pair = AuthStatePair::ZERO;
        let mut reported = AuthMask::NONE;
        let mut problem = false;
        let mut auth = DigestAuth::new();
        let ((), captured) = with_tracer(|tracer| {
            let mut sink = ChallengeSink::new(
                pair.select_mut(false),
                &mut reported,
                &mut problem,
            );
            input_auth(
                b"Digest realm=\"testrealm\"",
                false,
                &mut sink,
                &mut auth,
                tracer,
            )
            .expect("a decode failure is reported, not propagated");
        });
        assert!(problem, "authproblem is set");
        assert!(captured.contains(DIGEST_PROBLEM), "{captured}");
    }

    /// No credential reaches a log this file wrote.
    #[test]
    fn no_credential_reaches_a_log() {
        const SECRET: &str = "correct-horse-battery-staple";

        let mut pair = AuthStatePair::ZERO;
        let mut reported = AuthMask::NONE;
        let mut problem = false;
        let mut auth = DigestAuth::new();
        auth.set_credentials(
            false,
            Credentials::new(Some(USER), Some(SECRET.as_bytes())),
        );
        auth.set_iestyle(false, false);

        let (emission, captured) = with_tracer(|tracer| {
            let mut sink = ChallengeSink::new(
                pair.select_mut(false),
                &mut reported,
                &mut problem,
            );
            input_auth(
                b"Digest realm=\"testrealm\", nonce=\"1053604145\", \
                  qop=\"auth\", algorithm=MD5-sess",
                false,
                &mut sink,
                &mut auth,
                tracer,
            )
            .expect("ok");
            mechanism_output(&mut auth, false).expect("ok")
        });

        assert!(!captured.contains(SECRET), "the password reached a log");

        // The three intermediate digests, recomputed here so the assertion
        // names what must not appear rather than only what must not.
        let ha1 = HashKind::Md5
            .digest_hex(format!("testuser:testrealm:{SECRET}").as_bytes());
        let session_ha1 = HashKind::Md5
            .digest_hex(format!("{ha1}:1053604145:{CNONCE}").as_bytes());
        let ha2 = HashKind::Md5.digest_hex(b"GET:/64");
        for intermediate in [&ha1, &session_ha1, &ha2] {
            assert!(
                !captured.contains(intermediate.as_str()),
                "an intermediate digest reached a log"
            );
        }

        // The emitted header is a different matter: it is what curl puts on
        // the wire, and it must exist.
        assert!(emission.is_done());
        let line = emission.header().expect("a header line");
        assert!(line.starts_with("Authorization: Digest "), "{line}");
        assert!(line.ends_with("\r\n"), "{line}");
        assert!(!line.contains(SECRET), "the header is not the password");

        // No formatter prints a secret either.
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        // The nonce and client nonce are not secrets and do appear, which is
        // what makes this assertion discriminating rather than vacuous.
        assert!(rendered.contains("1053604145"), "{rendered}");
        assert!(rendered.contains(CNONCE), "{rendered}");
    }

    /// The state formatter prints its own fields and no more.
    #[test]
    fn the_state_formatter_prints_no_secret() {
        let mut digest = state(DigestAlgo::Sha256Sess, Some(b"auth"), None);
        digest.opaque = Some(b"opaque-token".to_vec());
        let rendered = format!("{digest:?}");
        assert!(rendered.starts_with("DigestData {"), "{rendered}");
        assert!(rendered.contains("1053604145"), "{rendered}");
        assert!(rendered.contains("opaque-token"), "{rendered}");
        assert!(rendered.contains("Sha256Sess"), "{rendered}");
        // There is no password field to print, by design.
        assert!(!rendered.contains("password"), "{rendered}");
        assert!(!rendered.contains("secret"), "{rendered}");
    }

    /// A full two-round exchange: challenge, response, stale re-challenge,
    /// second response. The client nonce changes across the re-challenge
    /// because the cleanup wipes it, and the count restarts at 1.
    #[test]
    fn a_stale_rechallenge_restarts_the_exchange() {
        let mut auth = DigestAuth::new();
        auth.set_credentials(false, Credentials::new(Some(USER), Some(PASS)));

        auth.input(
            b"Digest realm=\"testrealm\", nonce=\"1053604145\", qop=\"auth\"",
            false,
        )
        .expect("ok");
        let first = mechanism_output(&mut auth, false).expect("ok");
        let first_line = first.header().expect("a line").to_owned();
        assert!(first_line.contains(", nc=00000001, "), "{first_line}");
        assert_eq!(auth.states().select(false).nonce_count(), 2);

        auth.input(
            b"Digest realm=\"testrealm\", nonce=\"9999999999\", \
              qop=\"auth\", stale=true",
            false,
        )
        .expect("a stale re-challenge is accepted");
        assert_eq!(auth.states().select(false).nonce_count(), 1);

        let second = mechanism_output(&mut auth, false).expect("ok");
        let second_line = second.header().expect("a line").to_owned();
        assert!(second_line.contains(", nc=00000001, "), "{second_line}");
        assert!(
            second_line.contains("nonce=\"9999999999\""),
            "{second_line}"
        );
        assert_ne!(first_line, second_line);

        // A re-challenge WITHOUT stale is the rejection instead.
        assert_eq!(
            auth.input(
                b"Digest realm=\"testrealm\", nonce=\"8888888888\", \
                  qop=\"auth\"",
                false
            ),
            Err(CURLcode::BadContentEncoding)
        );
    }
}
