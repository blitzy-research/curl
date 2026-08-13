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

//! HTTP Basic authentication: the credential, and the one header line.
//!
//! Supersedes `http_output_basic()` -- `lib/http.c:243-297`, inside
//! `#ifndef CURL_DISABLE_BASIC_AUTH`. Fifty-five lines of C that do three
//! things: join the username and the password with a colon, base64 encode
//! the result, and wrap it in one header line. Every byte of the outcome is
//! compared literally by the fixture corpus, which is what makes so small a
//! mechanism worth this much prose.
//!
//! | C | Where | Here |
//! |---|-------|------|
//! | `http_output_basic()` | `lib/http.c:243-297` | [`output_basic`] |
//! | `curl_maprintf("%s:%s", ...)` | `lib/http.c:270` | [`credential_string`] |
//! | `curlx_base64_encode()` | `lib/curlx/base64.c:241-246` | [`crate::util::base64::encode`] |
//! | `"%sAuthorization: Basic %s\r\n"` | `lib/http.c:285-287` | [`crate::auth::authorization_header`] |
//! | the Basic arm of `output_auth_headers()` | `lib/http.c:682-701` | [`crate::auth::select_emitter`] |
//! | `auth_basic()` | `lib/http.c:968-985` | `crate::auth`'s `scan_bit_only`; [`Basic::input`] is its empty counterpart |
//! | Basic's place in `pickoneauth()` | `lib/http.c:357-360` | [`crate::auth::PREFERENCE_ORDER`] |
//!
//! # What this file deliberately does not contain
//!
//! Three pieces of Basic's behaviour live in `crate::auth` rather than here,
//! and duplicating any of them would create a second place for the bytes to
//! drift:
//!
//! * **The emission guard.** `lib/http.c:685-696` admits the emitter only for
//!   `(proxy && conn->bits.proxy_user_passwd && !checkProxyheaders(...))` or
//!   `(!proxy && aptr.user && !checkheaders("Authorization"))`, and then sets
//!   `authstatus->done` **unconditionally** whether or not the guard admitted
//!   it. [`crate::auth::select_emitter`] is that arm, including the
//!   lower-case `a` of the C's `"Proxy-authorization"` literal and the fact
//!   that the Bearer arm below it is a separate `if` rather than a
//!   continuation of the chain. [`output_basic`] is therefore reached only
//!   when the guard has already admitted it, and the "no header this round"
//!   outcome is expressed by the guard returning nothing -- never by this
//!   file returning an empty string.
//! * **The challenge handler.** `auth_basic()` (`lib/http.c:968-985`) decodes
//!   nothing: it ORs the `CURLAUTH_BASIC` bit into `avail`, and if Basic was
//!   already the picked method it clears `avail` entirely, emits
//!   [`crate::auth::BASIC_PROBLEM`] and sets `authproblem`. `crate::auth`
//!   owns that in `scan_bit_only`, shared with Bearer because the two C
//!   functions are identical apart from the bit and the diagnostic.
//!   [`Basic::input`] is consequently `Ok(())`.
//! * **The header shape.** All four C emitters share one format string, so
//!   [`crate::auth::authorization_header`] owns it and this file supplies
//!   only the scheme token and the credential.
//!
//! # The nominal source is SASL, and none of it is ported
//!
//! The source for this file is `lib/vauth/cleartext.c`. Measured,
//! that file contains no HTTP Basic code at all: its entire body sits inside
//! a single preprocessor guard, `lib/vauth/cleartext.c:29-31`,
//!
//! ```text
//! #if !defined(CURL_DISABLE_IMAP) || !defined(CURL_DISABLE_SMTP) || \
//!   !defined(CURL_DISABLE_POP3) ||                                  \
//!   (!defined(CURL_DISABLE_LDAP) && defined(USE_OPENLDAP))
//! ```
//!
//! and all four of those protocols are out of scope, their command sequencing
//! living in `crate::protocols::stub` and answering
//! `CURLcode::UnsupportedProtocol`. The three functions the file defines are
//! SASL mechanisms rather than HTTP ones, and none is a colon-joined
//! credential:
//!
//! * `Curl_auth_create_plain_message()` -- RFC 4616 SASL PLAIN. Joins
//!   `authzid`, `authcid` and `passwd` with **NUL** bytes, not colons
//!   (`curl_maprintf("%s%c%s%c%s", ..., '\0', ...)`), takes its length as
//!   `zlen + clen + plen + 2` because `strlen` cannot measure a string with
//!   interior NULs, and rejects any component longer than
//!   `CURL_MAX_INPUT_LENGTH` with `CURLE_TOO_LARGE`.
//! * `Curl_auth_create_login_message()` -- the raw value, no encoding at all.
//! * `Curl_auth_create_external_message()` -- delegates to the login form.
//!
//! # Credentials are per transfer, not per connection
//!
//! `lib/http.c:253-254` states it as a comment on the selection below, and it
//! is carried verbatim because it is the reason two pairs exist rather than
//! one:
//!
//! > credentials are unique per transfer for HTTP, do not use the ones for
//! > the connection
//!
//! # The four error codes, and which of them can actually happen
//!
//! `http_output_basic()` names three failure codes and inherits a fourth.
//! All four are reproduced. Only one of the four can actually occur, and
//! saying which is more useful than dropping the other three:
//!
//! | Code | C site | Reachable here |
//! |------|--------|----------------|
//! | `CURLE_OUT_OF_MEMORY` | `:272`, `:290` | no -- both are FIXED-SIZE `curlx_maprintf` buffers whose size this module chooses, not the caller; the caller-sized allocation on this path is the base64 encoder's, which does report it (last row) |
//! | `CURLE_REMOTE_ACCESS_DENIED` | `:279-282` | no -- see below, and it is unreachable in the C too |
//! | `CURLE_NOT_BUILT_IN` | `:261` | no -- there is no `proxy` Cargo feature to remove proxy support |
//! | `CURLE_TOO_LARGE` | `lib/curlx/base64.c:182-183` | **yes** -- inherited from the encoder |
//!
//! `CURLE_REMOTE_ACCESS_DENIED` deserves its own paragraph, because the
//! obvious reading of `if(!authorization)` -- that it is an out-of-memory
//! check written with the wrong code -- is wrong, and the C distinguishes the
//! two deliberately. The only way `curlx_base64_encode` can return success
//! with a NULL output pointer is its own first statement, `if(!insize)
//! return CURLE_OK;` (`lib/curlx/base64.c:177-178`), which leaves the
//! `*outptr = NULL` it set on entry. An empty input is therefore the entire
//! condition -- and the credential string always contains at least the colon
//! separator, so `insize >= 1` always holds and the branch is unreachable in
//! the C as well as here. It is preserved as an explicit test against the
//! empty encoding, at the cost of one comparison, because the mapping is
//! part of the contract and a future change to either the separator or the
//! encoder would make it matter again.
//!
//! # Visibility
//!
//! `pub(crate)` throughout. `http_output_basic()` was `static` in C, so it
//! was not even visible to the linker; nothing here is re-exported to make
//! `tests/unit/*.c` or `tests/libtest/*.c` link, and the coverage they
//! carried is relocated into the `#[cfg(test)]` module at the foot of this
//! file. There is no `unsafe` here: the crate root's `#![deny(unsafe_code)]`
//! grants its single exemption to `mod ffi`, and this is not it.

use crate::auth::{
    authorization_header, AuthContext, AuthEmission, AuthScheme, Credentials,
    HttpAuthMechanism,
};
use crate::error::CURLcode;
use crate::util::base64;

/// The `auth-scheme` token this mechanism writes, from `lib/http.c:285`.
pub(crate) const SCHEME_TOKEN: &str = "Basic";

/// The byte between the username and the secret: the `:` of `"%s:%s"`
/// (`lib/http.c:270`).
pub(crate) const CREDENTIAL_SEPARATOR: u8 = b':';

/// Joins a username and a secret into the bytes that get base64 encoded.
///
/// `lib/http.c:270`, whose whole body is one format:
///
/// ```c
/// out = curl_maprintf("%s:%s", user ? user : "", pwd ? pwd : "");
/// ```
///
/// Three properties of that line are load-bearing, each observable in the
/// fixture corpus, and none of them is what a fresh implementation would
/// choose:
///
/// * **An absent half becomes the empty string, never an error and never a
///   skip.** C's `? :` supplies `""` for a NULL pointer on both sides, so a
///   caller that supplied only one half still gets a well-formed header:
///   `Some("user"), None` yields `user:` and `None, Some("password")` yields
///   `:password`. Both forms are in the corpus -- `tests/data/test479`
///   expects `%b64[bob:]b64%` and `tests/data/test367`, named "Empty
///   username provided in URL", expects `%b64[:example]b64%`.
/// * **A colon inside either half is neither escaped nor rejected.**
///   `Some("a:b"), Some("c")` yields exactly `a:b:c`. RFC 7617 forbids a
///   colon in the username and curl does not enforce that, so neither may
///   this: `tests/data/test1428` and `tests/data/test83` expect
///   `%b64[iam:my:;self]b64%`, a password carrying both a colon and a
///   semicolon, encoded unmodified.
/// * **The bytes are opaque.** The C encodes `(uint8_t *)out` with
///   `strlen(out)`: no charset conversion, no UTF-8 validation, nothing that
///   could alter a byte. The signature is therefore `&[u8]` rather than
///   `&str`, so a credential that is not valid UTF-8 -- which is reachable,
///   since credentials arrive from a URL, an option or a `.netrc` file --
///   cannot be rejected or replaced with a substitution character.
///   `tests/data/test1910` expects `%b64[user%0aname:pass%0aword]b64%`, whose
///   `%0a` escapes `tests/testutil.pm:136-141` expands to raw line feeds
///   before encoding.
pub(crate) fn credential_string(
    user: Option<&[u8]>,
    secret: Option<&[u8]>,
) -> Vec<u8> {
    // C's `user ? user : ""` and `pwd ? pwd : ""`. `&[u8]`'s `Default` is the
    // empty slice, which is exactly the empty C string this stands in for.
    let user = user.unwrap_or_default();
    let secret = secret.unwrap_or_default();

    // Saturating rather than `+`: the sum of two live slice lengths cannot
    // overflow in practice, but a debug build panics on arithmetic overflow
    // and a credential path must not carry a panic that depends on its
    // input. The value is a capacity hint, so saturation costs nothing even
    // in the case that cannot happen.
    let capacity = user.len().saturating_add(1).saturating_add(secret.len());
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(user);
    out.push(CREDENTIAL_SEPARATOR);
    out.extend_from_slice(secret);
    out
}

/// Composes one `Authorization:` or `Proxy-Authorization:` header line.
///
/// The returned line is complete and CRLF terminated, ready to be written
/// into a request. C stores it in `data->state.aptr.userpwd` or
/// `.proxyuserpwd`, freeing whatever was there first (`:284`); returning it
/// makes that free-then-assign a move, and makes it impossible to leave the
/// previous value in place on a failure path -- which the C's `goto fail`
/// deliberately does, leaving the stale header intact when the encoder fails.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] when the credential exceeds
/// [`crate::util::base64::CURL_MAX_BASE64_INPUT`], propagated from the
/// encoder exactly as the C's `if(result) goto fail;` propagates it.
/// [`CURLcode::RemoteAccessDenied`] for an empty encoding, which cannot
/// happen -- see the module documentation for why the branch is kept.
pub(crate) fn output_basic(
    proxy: bool,
    credentials: &Credentials,
) -> Result<String, CURLcode> {
    let out = credential_string(credentials.user(), credentials.secret());

    // `curlx_base64_encode((uint8_t *)out, strlen(out), ...)` at `:274-275`,
    // then `if(result) goto fail;` at `:276-277`. The standard alphabet with
    // `=` padding and no line wrapping: `tests/testutil.pm:141` builds every
    // fixture's expectation with `encode_base64($d, "")`, whose empty
    // end-of-line argument is the harness's own statement that the header
    // carries one unbroken run, and two fixtures make that unmissable:
    // `tests/data/test1237` expects an `Authorization:` line whose 2,003-byte
    // credential becomes 2,672 base64 characters on ONE line, and
    // `tests/data/test1178` the same for a `Proxy-Authorization:` line at
    // 1,336. Both are measured from the fixtures, not estimated.
    let authorization = base64::encode(&out)?;

    // `if(!authorization)` at `:279-282`, and the code really is
    // `CURLE_REMOTE_ACCESS_DENIED` rather than `CURLE_OUT_OF_MEMORY`.
    if authorization.is_empty() {
        return Err(CURLcode::RemoteAccessDenied);
    }

    // `"%sAuthorization: Basic %s\r\n"` with `proxy ? "Proxy-" : ""`, at
    // `:285-287`. The format shape is shared by all four C emitters and
    // therefore lives in one place.
    Ok(authorization_header(proxy, SCHEME_TOKEN, &authorization))
}

/// The Basic mechanism: the two credential pairs, and nothing else.
// The production consumer is `crate::protocols::http1`, which composes the
// request headers. The allowance is written at the item rather than on the
// module, because a module-level one would also hide the next unreferenced
// item somebody adds -- `src/lib.rs` (`mod source_policy`) enforces that
// distinction as a test.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub(crate) struct Basic {
    /// `data->state.aptr.user` and `data->state.aptr.passwd`.
    origin: Credentials,
    /// `data->state.aptr.proxyuser` and `data->state.aptr.proxypasswd`.
    proxy: Credentials,
}

impl Basic {
    /// The mechanism with both credential pairs supplied.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) const fn new(origin: Credentials, proxy: Credentials) -> Self {
        Self { origin, proxy }
    }

    /// The pair the `proxy` flag selects: C's `if(proxy)` at
    /// `lib/http.c:255-268`.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) const fn credentials(&self, proxy: bool) -> &Credentials {
        if proxy {
            &self.proxy
        } else {
            &self.origin
        }
    }
}

impl HttpAuthMechanism for Basic {
    /// Always [`AuthScheme::Basic`], so that a `&dyn HttpAuthMechanism` can be
    /// matched against `picked` without a downcast.
    fn scheme(&self) -> AuthScheme {
        AuthScheme::Basic
    }

    /// Consumes nothing: `auth_basic()` has no challenge body to decode.
    fn input(
        &mut self,
        _challenge: &[u8],
        _proxy: bool,
    ) -> Result<(), CURLcode> {
        Ok(())
    }

    /// Emits this request's header line.
    ///
    /// Always [`AuthEmission::Final`]: Basic completes in one message, and
    /// `output_auth_headers()` sets `authstatus->done` on the Basic arm
    /// unconditionally (`lib/http.c:698-700`). The two agree by construction
    /// -- [`AuthEmission::is_done`] is true for `Final` -- rather than by two
    /// assignments that could diverge, which is what C's `bool *done`
    /// out-parameter risked.
    ///
    /// # Errors
    ///
    /// As [`output_basic`].
    fn output(
        &mut self,
        ctx: &mut AuthContext<'_>,
    ) -> Result<AuthEmission, CURLcode> {
        let header = output_basic(ctx.proxy, self.credentials(ctx.proxy))?;
        Ok(AuthEmission::Final(header))
    }
}

// Tests
//
// `tests/unit/*.c` and `tests/libtest/*.c` cannot link against this crate --
// they call internal `Curl_*` symbols, and a Rust static library does not
// export `pub(crate)` items, so they are genuinely absent from the symbol
// table rather than merely hidden. Their coverage is relocated here, inside
// the module under test, which is also where a private item is reachable
// without widening its visibility to accommodate a test.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::REDACTED_PLACEHOLDER;
    use crate::crypto::rand::TestRng;
    use crate::trace::{TraceConfig, TraceState, Tracer, WriterSink};
    use crate::util::timeval::SystemClock;

    /// The stand-in password used wherever a test needs to prove that a
    /// secret did *not* appear somewhere.
    ///
    /// Deliberately self-describing rather than random: it must be
    /// distinctive enough that a substring search cannot match it by
    /// accident, and obviously fake enough that no reader or credential
    /// scanner mistakes it for a real one.
    const FAKE_SECRET: &str = "example-not-a-real-password";

    /// A context for [`HttpAuthMechanism::output`], for the given side.
    ///
    /// The tracing fixtures are also the only reason `crate::util::timeval` and
    /// `crate::crypto::rand` are named anywhere in this file:
    /// [`AuthContext`]'s own definition types those two fields, so a test
    /// that exercises the trait method -- rather than only the free function
    /// beneath it -- cannot avoid naming them. Neither is reached by any
    /// production path here.
    fn context(proxy: bool, rng: &mut TestRng) -> AuthContext<'_> {
        AuthContext {
            proxy,
            request_method: b"GET",
            request_target: b"/1",
            clock: &SystemClock,
            rng,
        }
    }

    /// The header [`output_basic`] produces for a text pair, for the origin
    /// server.
    fn origin_header(user: &str, secret: &str) -> String {
        let credentials =
            Credentials::new(Some(user.as_bytes()), Some(secret.as_bytes()));
        output_basic(false, &credentials)
            .expect("a text credential always encodes")
    }

    // -- the credential string ---------------------------------------------

    #[test]
    fn the_two_halves_are_joined_by_exactly_one_colon() {
        // `lib/http.c:270`, `"%s:%s"`.
        assert_eq!(
            credential_string(Some(b"user"), Some(b"password")),
            b"user:password".to_vec()
        );
    }

    #[test]
    fn an_absent_half_becomes_the_empty_string_and_never_an_error() {
        // C's `user ? user : ""` and `pwd ? pwd : ""`: both halves are
        // optional and neither absence is a failure.
        assert_eq!(credential_string(Some(b"user"), None), b"user:".to_vec());
        assert_eq!(
            credential_string(None, Some(b"password")),
            b":password".to_vec()
        );
        assert_eq!(credential_string(None, None), b":".to_vec());
    }

    #[test]
    fn an_absent_half_and_an_empty_half_are_indistinguishable() {
        // Asserting it here is what lets the emitter accept either without a
        // branch.
        assert_eq!(
            credential_string(None, Some(b"password")),
            credential_string(Some(b""), Some(b"password"))
        );
        assert_eq!(
            credential_string(Some(b"user"), None),
            credential_string(Some(b"user"), Some(b""))
        );
        assert_eq!(
            credential_string(None, None),
            credential_string(Some(b""), Some(b""))
        );
    }

    #[test]
    fn a_colon_inside_either_half_is_neither_escaped_nor_rejected() {
        // The separator carries no escape, so a colon in either half simply
        // lands in the joined string. In the username that produces a
        // credential RFC 7617 calls invalid, and curl does not enforce the
        // rule, so neither may this. In the password it is legal and
        // common: `tests/data/test1428` and `tests/data/test83` expect
        // `%b64[iam:my:;self]b64%`, a password carrying both a colon and a
        // semicolon.
        assert_eq!(
            credential_string(Some(b"a:b"), Some(b"c")),
            b"a:b:c".to_vec()
        );
        assert_eq!(
            credential_string(Some(b"iam"), Some(b"my:;self")),
            b"iam:my:;self".to_vec()
        );
    }

    #[test]
    fn the_credential_string_is_never_empty() {
        // The property that makes `output_basic`'s
        // `CURLE_REMOTE_ACCESS_DENIED` branch unreachable: the separator is
        // always present, so the encoder never sees the empty input that is
        // the sole producer of C's NULL output pointer
        // (`lib/curlx/base64.c:177-178`). Both halves of the argument are
        // asserted, so a future change to either one fails here rather than
        // silently making the branch reachable.
        assert!(!credential_string(None, None).is_empty());
        assert_eq!(base64::encode(b"").as_deref(), Ok(""));
        assert_eq!(
            base64::encode(&credential_string(None, None)).as_deref(),
            Ok("Og==")
        );
    }

    // -- the encoded header, byte for byte ---------------------------------

    #[test]
    fn the_canonical_pair_produces_the_expected_header() {
        assert_eq!(
            origin_header("user", "password"),
            "Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"
        );
    }

    #[test]
    fn an_empty_password_encodes_the_trailing_colon() {
        // `tests/data/test479` expects `%b64[bob:]b64%`.
        assert_eq!(
            origin_header("user", ""),
            "Authorization: Basic dXNlcjo=\r\n"
        );
        assert_eq!(
            origin_header("bob", ""),
            "Authorization: Basic Ym9iOg==\r\n"
        );

        // And a `None` password takes the same path, with no error.
        let absent = Credentials::new(Some(b"bob"), None);
        assert_eq!(
            output_basic(false, &absent),
            Ok("Authorization: Basic Ym9iOg==\r\n".to_owned())
        );
    }

    #[test]
    fn an_empty_username_encodes_the_leading_colon() {
        // `tests/data/test367`, "Empty username provided in URL", expects
        // `%b64[:example]b64%`.
        assert_eq!(
            origin_header("", "password"),
            "Authorization: Basic OnBhc3N3b3Jk\r\n"
        );
        assert_eq!(
            origin_header("", "example"),
            "Authorization: Basic OmV4YW1wbGU=\r\n"
        );

        // A `None` username behaves identically. `tests/data/test2005` and
        // `tests/data/test684` reach the same shape with a password only.
        let absent = Credentials::new(None, Some(b"5up3r53cr37"));
        assert_eq!(
            output_basic(false, &absent),
            Ok("Authorization: Basic OjV1cDNyNTNjcjM3\r\n".to_owned())
        );
    }

    #[test]
    fn both_halves_empty_encode_a_bare_colon() {
        assert_eq!(origin_header("", ""), "Authorization: Basic Og==\r\n");
        assert_eq!(
            output_basic(false, &Credentials::none()),
            Ok("Authorization: Basic Og==\r\n".to_owned())
        );
    }

    #[test]
    fn a_colon_inside_a_credential_reaches_the_wire_unmodified() {
        assert_eq!(
            origin_header("a:b", "c"),
            "Authorization: Basic YTpiOmM=\r\n"
        );
        assert_eq!(
            origin_header("iam", "my:;self"),
            "Authorization: Basic aWFtOm15OjtzZWxm\r\n"
        );
    }

    #[test]
    fn arbitrary_bytes_are_encoded_verbatim() {
        // Not valid UTF-8 in either half: `0xff 0xfe` cannot begin a UTF-8
        // sequence and `0x80 0xc3` is a stray continuation followed by a
        // truncated lead byte. The C encodes `(uint8_t *)out`, so no
        // conversion, no validation and no replacement character may occur.
        let credentials =
            Credentials::new(Some(&[0xff, 0xfe]), Some(&[0x80, 0xc3]));
        assert_eq!(
            output_basic(false, &credentials),
            Ok("Authorization: Basic //46gMM=\r\n".to_owned())
        );

        // Raw line feeds inside both halves. `tests/data/test1910` expects
        // `%b64[user%0aname:pass%0aword]b64%`, whose `%0a` escapes
        // `tests/testutil.pm:136-141` expands before encoding -- so the
        // encoded credential really does carry two 0x0a bytes.
        let newlines =
            Credentials::new(Some(b"user\nname"), Some(b"pass\nword"));
        assert_eq!(
            output_basic(false, &newlines),
            Ok("Authorization: Basic dXNlcgpuYW1lOnBhc3MKd29yZA==\r\n"
                .to_owned())
        );
    }

    #[test]
    fn a_long_credential_produces_one_unbroken_line() {
        // `tests/testutil.pm:141` builds every fixture's expectation with
        // `encode_base64($d, "")`; the empty end-of-line argument is the
        // harness's own statement that the run is unwrapped.
        // The corpus goes much further -- `tests/data/test1237` expects 2,672
        // characters on one line and `tests/data/test1178` 1,336 -- but 156 is
        // already past the 76 that MIME base64 wraps at, which is the
        // threshold this test exists to cross.
        let user = "A".repeat(57);
        let secret = "B".repeat(57);
        let header = origin_header(&user, &secret);

        let encoded = header
            .strip_prefix("Authorization: Basic ")
            .and_then(|rest| rest.strip_suffix("\r\n"))
            .expect("the header has the shape this module composes");

        assert_eq!(encoded.len(), 156);
        assert!(!encoded.contains('\n'), "encoded run is wrapped");
        assert!(!encoded.contains('\r'), "encoded run is wrapped");
        assert!(
            encoded.starts_with("QUFB") && encoded.ends_with("Qg=="),
            "unexpected encoding: {encoded}"
        );
    }

    #[test]
    fn the_line_ends_with_crlf_and_holds_no_other_break() {
        let header = origin_header("user", "password");
        assert!(header.ends_with("\r\n"));
        assert_eq!(header.matches('\r').count(), 1);
        assert_eq!(header.matches('\n').count(), 1);
        // No trailing whitespace before the terminator either: exactly one
        // space follows the colon and exactly one follows the scheme token.
        assert_eq!(header.matches(' ').count(), 2);
    }

    // -- the proxy form ----------------------------------------------------

    #[test]
    fn the_proxy_form_differs_by_exactly_the_prefix() {
        let credentials = Credentials::new(Some(b"user"), Some(b"password"));
        let origin = output_basic(false, &credentials)
            .expect("a text credential always encodes");
        let proxied = output_basic(true, &credentials)
            .expect("a text credential always encodes");

        assert_eq!(
            proxied,
            "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"
        );
        // The whole difference, stated as a transformation rather than as two
        // literals, so that a change to either form fails this too.
        assert_eq!(proxied, format!("Proxy-{origin}"));
    }

    #[test]
    fn the_mechanism_reads_the_pair_the_proxy_flag_selects() {
        // `lib/http.c:255-268`. Getting this wrong signs a proxy request with
        // origin credentials, which fails with a 407 and no diagnostic saying
        // why.
        let mechanism = Basic::new(
            Credentials::new(Some(b"user"), Some(b"password")),
            Credentials::new(Some(b"puser"), Some(b"ppass")),
        );

        assert_eq!(mechanism.credentials(false).user(), Some(&b"user"[..]));
        assert_eq!(mechanism.credentials(true).user(), Some(&b"puser"[..]));
    }

    #[test]
    fn a_proxy_pair_that_was_never_populated_still_encodes() {
        // `tests/data/test1178` and its neighbours populate the proxy pair;
        // a transfer with no proxy leaves it empty, and C's `? :` then
        // formats `:` rather than refusing to compose a header at all.
        let mechanism = Basic::new(
            Credentials::new(Some(b"user"), Some(b"password")),
            Credentials::none(),
        );
        assert_eq!(
            output_basic(true, mechanism.credentials(true)),
            Ok("Proxy-Authorization: Basic Og==\r\n".to_owned())
        );
    }

    #[test]
    fn one_mechanism_serves_both_sides_of_a_proxied_transfer() {
        // `tests/data/test346` -- "HTTP GET over proxy with credentials using
        // blank passwords" -- drives `-U puser: -u suser:` and expects BOTH
        // lines in one byte-exact `<protocol>` block. Reproducing the pair
        // from a single mechanism is what proves the two sides do not bleed
        // into one another: a single stored credential would emit the same
        // base64 twice, and the fixture would fail on its second line.
        let mut rng = TestRng::from_seed(0);
        let mut mechanism = Basic::new(
            Credentials::new(Some(b"suser"), Some(b"")),
            Credentials::new(Some(b"puser"), Some(b"")),
        );

        let proxied = mechanism
            .output(&mut context(true, &mut rng))
            .expect("a text credential always encodes");
        let origin = mechanism
            .output(&mut context(false, &mut rng))
            .expect("a text credential always encodes");

        assert_eq!(
            proxied.header(),
            Some("Proxy-Authorization: Basic cHVzZXI6\r\n")
        );
        assert_eq!(origin.header(), Some("Authorization: Basic c3VzZXI6\r\n"));
        assert_ne!(proxied.header(), origin.header());
    }

    // -- the mechanism abstraction -----------------------------------------

    #[test]
    fn the_mechanism_names_itself_basic() {
        let mechanism = Basic::default();
        assert_eq!(mechanism.scheme(), AuthScheme::Basic);
    }

    #[test]
    fn the_scheme_token_agrees_with_the_shared_vocabulary() {
        // The literal in this file and the one in `crate::auth` are two
        // spellings of one wire token; this is what stops them diverging.
        assert_eq!(AuthScheme::Basic.header_scheme(), Some(SCHEME_TOKEN));
        assert_eq!(SCHEME_TOKEN, "Basic");
        assert_eq!(CREDENTIAL_SEPARATOR, b':');
    }

    #[test]
    fn the_emission_is_final_because_basic_completes_in_one_message() {
        let mut rng = TestRng::from_seed(0);
        let mut mechanism = Basic::new(
            Credentials::new(Some(b"user"), Some(b"password")),
            Credentials::none(),
        );

        let emission = mechanism
            .output(&mut context(false, &mut rng))
            .expect("a text credential always encodes");

        assert_eq!(
            emission,
            AuthEmission::Final(
                "Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n".to_owned()
            )
        );
        // `lib/http.c:698-700` sets `done` unconditionally on this arm, and
        // `Final` is how that arrives here.
        assert!(emission.is_done());
    }

    #[test]
    fn the_emission_takes_the_proxy_pair_when_the_context_says_proxy() {
        let mut rng = TestRng::from_seed(0);
        let mut mechanism = Basic::new(
            Credentials::new(Some(b"user"), Some(b"password")),
            Credentials::new(Some(b"puser"), Some(b"")),
        );

        let emission = mechanism
            .output(&mut context(true, &mut rng))
            .expect("a text credential always encodes");

        // `tests/data/test346`, "HTTP GET over proxy with credentials using
        // blank passwords", is exactly this case: `-U puser: -u suser:` and a
        // `<protocol>` block expecting `Proxy-Authorization: Basic
        // %b64[puser:]b64%` immediately followed by
        // `Authorization: Basic %b64[suser:]b64%`.
        assert_eq!(
            emission.header(),
            Some("Proxy-Authorization: Basic cHVzZXI6\r\n")
        );
    }

    #[test]
    fn a_challenge_is_accepted_and_decodes_nothing() {
        // `auth_basic()` reads no part of the challenge, not even the realm,
        // so any bytes at all are accepted and nothing is stored.
        let mut mechanism = Basic::default();
        assert_eq!(mechanism.input(b"Basic realm=\"x\"", false), Ok(()));
        assert_eq!(mechanism.input(b"", true), Ok(()));
        assert_eq!(mechanism.input(&[0xff, 0x00, 0xfe], false), Ok(()));
    }

    #[test]
    fn the_output_is_deterministic_across_calls() {
        // Basic keeps no state and consults neither the clock nor the random
        // source, so two calls on one mechanism produce identical bytes.
        // Digest and NTLM cannot make this claim, which is why the scope
        // table in `crate::auth` distinguishes them.
        let mut rng = TestRng::from_seed(0);
        let mut mechanism = Basic::new(
            Credentials::new(Some(b"user"), Some(b"password")),
            Credentials::none(),
        );

        let first = mechanism.output(&mut context(false, &mut rng));
        let second = mechanism.output(&mut context(false, &mut rng));
        assert_eq!(first, second);
    }

    // -- credentials gain no new path to a log -----------------------------

    #[test]
    fn the_debug_form_shows_the_user_and_hides_the_secret() {
        let mechanism = Basic::new(
            Credentials::new(Some(b"alice"), Some(FAKE_SECRET.as_bytes())),
            Credentials::new(Some(b"palice"), Some(FAKE_SECRET.as_bytes())),
        );
        let shown = format!("{mechanism:?}");

        assert!(
            !shown.contains(FAKE_SECRET),
            "the derived formatter leaked a secret: {shown}"
        );
        assert!(shown.contains(REDACTED_PLACEHOLDER));
        // The username is not a secret in curl's terms -- `lib/http.c:722`
        // prints it in the `--verbose` diagnostic of every authenticated
        // request -- so its presence is the expected behaviour, and asserting
        // it keeps the test honest about what is and is not withheld.
        assert!(shown.contains("alice"));
    }

    #[test]
    fn no_credential_reaches_a_fully_enabled_tracer() {
        // This file holds no tracer and formats no diagnostic, so a tracer
        // running at full verbosity beside it must receive nothing at all --
        // a stronger property than "the secret is absent", and the one that
        // actually forbids adding a logging path curl does not have. Note
        // that no tracer is *handed* to the emitter, because none can be:
        // neither `output_basic` nor `AuthContext` accepts one. That is the
        // structural half of the guarantee, and the empty sink below is its
        // observable half.
        let config = TraceConfig::init().expect("trace config cannot fail");
        let mut sink = WriterSink::new(Vec::new());
        let header = {
            let tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            // Non-vacuity: tracing really is on, so an empty sink below is a
            // fact about this module rather than about the tracer.
            assert!(tracer.is_verbose());

            let mut rng = TestRng::from_seed(0);
            let mut mechanism = Basic::new(
                Credentials::new(Some(b"alice"), Some(FAKE_SECRET.as_bytes())),
                Credentials::none(),
            );
            let emission = mechanism
                .output(&mut context(false, &mut rng))
                .expect("a text credential always encodes");
            emission.header().map(str::to_owned)
        };

        let captured = String::from_utf8_lossy(&sink.into_inner()).into_owned();
        assert!(captured.is_empty(), "this module traced: {captured}");
        assert!(!captured.contains(FAKE_SECRET));

        // And the credential really was composed, so the empty sink is not
        // the result of having done nothing.
        assert_eq!(
            header.as_deref(),
            Some("Authorization: Basic YWxpY2U6ZXhhbXBsZS1ub3QtYS1yZWFsLXBhc3N3b3Jk\r\n")
        );
    }
}
