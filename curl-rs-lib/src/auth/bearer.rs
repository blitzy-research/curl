//**************************************************************************
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
//**************************************************************************/
//! HTTP Bearer-token authentication: the `Authorization: Bearer` header.
//!
//! Backs `CURLOPT_XOAUTH2_BEARER` and the `--oauth2-bearer <token>`
//! command-line flag. This is the smallest mechanism in the directory, and
//! the whole of its wire behaviour is one header line whose credential is
//! the token exactly as the application supplied it.
//!
//! | C | Where | Here |
//! |---|-------|------|
//! | `http_output_bearer()` | `lib/http.c:308-325` | [`BearerToken`] |
//! | the emission arm | `lib/http.c:703-716` | `super::select_emitter` |
//! | `auth_bearer()` | `lib/http.c:987-1003` | `super::input_auth` |
//! | the `authmask` narrowing | `lib/http.c:544` | `super::auth_act` |
//! | `CURLOPT_XOAUTH2_BEARER` | `lib/setopt.c:2204-2208` | [`BearerToken`] |
//! | `STRING_BEARER` | `lib/urldata.h:1231` | [`BearerToken`] |
//! | `--oauth2-bearer` | `src/tool_getparam.c:223` | [`BearerToken`] |
//!
//! # The nominal source is not this mechanism, and the difference is measured
//!
//! That file is **not** HTTP Bearer authentication, and the reason is written
//! down here so that a later reader does not conclude its contents were
//! overlooked.
//!
//! `lib/vauth/oauth2.c:28-30` guards the entire file:
//!
//! ```c
//! #if !defined(CURL_DISABLE_IMAP) || !defined(CURL_DISABLE_SMTP) || \
//!   !defined(CURL_DISABLE_POP3) ||                                  \
//!   (!defined(CURL_DISABLE_LDAP) && defined(USE_OPENLDAP))
//! ```
//!
//! Its two functions are **SASL** message generators rather than HTTP header
//! emitters, which the bytes settle beyond argument:
//!
//! * `Curl_auth_create_oauth_bearer_message()` (`:50-70`) emits
//!   `n,a=%s,\x01host=%s\x01auth=Bearer %s\x01\x01`, or the same with
//!   `port=%ld\x01` interposed when the port is neither 0 nor 80.
//! * `Curl_auth_create_xoauth_bearer_message()` (`:86-97`) emits
//!   `user=%s\x01auth=Bearer %s\x01\x01`.
//!
//! HTTP Bearer lives at `lib/http.c:308-325`, inside
//! `#ifndef CURL_DISABLE_BEARER_AUTH`, and its body is four statements:
//!
//! ```c
//! userp = &data->state.aptr.userpwd;
//! curlx_free(*userp);
//! *userp = curl_maprintf("Authorization: Bearer %s\r\n",
//!                        data->set.str[STRING_BEARER]);
//! if(!*userp) { result = CURLE_OUT_OF_MEMORY; goto fail; }
//! ```
//!
//! # The token is emitted verbatim -- there is no encoding step
//!
//! This is the single most important difference from Basic, and the one a
//! reader coming from `http_output_basic()` (`lib/http.c:243-297`) is most
//! likely to assume away. Basic composes `user:password`, base64-encodes it,
//! and can fail with `CURLE_REMOTE_ACCESS_DENIED` when the encoder yields
//! nothing. Bearer does **none** of that: the format string takes the token
//! straight from `data->set.str[STRING_BEARER]` and copies its bytes into
//! the header. So there is no base64, no percent-encoding, no quoting, no
//! escaping, no whitespace trimming, no case folding, no length limit and no
//! syntactic validation of any kind. A token containing `=`, `+`, `/`, an
//! interior space, or nothing at all reaches the wire exactly as given.
//!
//! # There is no proxy variant, and that is structural rather than checked
//!
//! curl cannot emit `Proxy-Authorization: Bearer`, and three independent
//! mechanisms in the C make it so:
//!
//! 1. `http_output_bearer()` takes **no** `proxy` parameter and always
//!    writes `data->state.aptr.userpwd`, the origin slot. Its format string
//!    has no `%s` prefix where Basic, Digest, NTLM and Negotiate all carry
//!    `proxy ? "Proxy-" : ""`.
//! 2. The emission guard at `lib/http.c:706` opens with `!proxy &&`.
//! 3. `lib/http.c:574-575` hands the proxy arbitration
//!    `authmask & ~CURLAUTH_BEARER`, so the bit cannot even be picked on
//!    that side -- reproduced by `super::proxy_auth_mask`, which is the only
//!    constructor of a proxy mask in this crate.
//!
//! # What deliberately is *not* here
//!
//! Five behaviours in which Bearer participates belong to `super` and are
//! **not** duplicated in this file. They are listed so that their absence
//! reads as a decision:
//!
//! * The five-condition early exit of `Curl_http_output_auth()`
//!   (`lib/http.c:774-789`), whose fifth disjunct is
//!   `data->set.str[STRING_BEARER]` -- `super::credentials_offered`. It is
//!   why a transfer with a token but **no username at all** still reaches
//!   the mechanisms.
//! * The `want`-to-`picked` promotion (`lib/http.c:791-801`) --
//!   `super::seed_picked_from_want`. It is what makes `--oauth2-bearer`
//!   authenticate on the *first* request with no 401 round trip.
//! * The emission guard and the unconditional `done = TRUE` that follows it
//!   (`lib/http.c:703-717`) -- `super::select_emitter`, where the Bearer arm
//!   is a separate `if` rather than a continuation of the preceding
//!   if/else-if chain, exactly as the C writes it.
//! * The challenge-side bookkeeping of `auth_bearer()`
//!   (`lib/http.c:987-1003`) and the missing `!result` term on Bearer's
//!   guard at `lib/http.c:1073` -- `super::input_auth`, with the diagnostic
//!   in `super::BEARER_PROBLEM`.
//! * The `authmask` narrowing of `lib/http.c:544` -- `super::auth_act`.
//!   [`token_is_configured`] names the predicate all four C sites test, so
//!   the callers spell the same condition, but the narrowing itself has one
//!   home.
//!
//! # Credentials gain no new path to a log
//!
//! curl has no redaction mechanism, and this module adds none:
//! `lib/http.c:2888-2895` splices the finished `Authorization:` line
//! straight into the request buffer, `--verbose` prints it verbatim, and 168
//! fixtures compare such a line inside a byte-exact `<protocol>` block.
//! Masking it would fail those fixtures and would itself be a behaviour
//! change.
//!
//! The narrower requirement that *does* bind, and that the
//! preservation mandate leaves room for, is that no secret gains a path to a
//! log curl does not already have. Nothing here formats a token into a
//! trace record -- this module emits no trace output at all -- and
//! [`BearerToken`] implements [`core::fmt::Debug`] **by hand**, printing
//! `super::REDACTED_PLACEHOLDER` in place of the token. That matters more
//! for a bearer token than for anything else in this directory, because the
//! token is a single self-contained credential: a `#[derive(Debug)]` on any
//! enclosing type, at arbitrary distance from this file, would otherwise
//! print it. Because the hand-written formatter lives on the token itself,
//! [`Bearer`] can derive its own formatter safely, and a test proves the
//! derived output carries the placeholder and not the secret.
//!
//! # The capability banner is not flipped by this module landing
//!
//! `crate::version`'s `ENGINE_AUTH_BEARER` names this file and reports
//! absent, which withholds the `bearer-auth` row from the capability
//! diagnostic. That is left alone deliberately. The row answers "can this
//! build serve `--oauth2-bearer`", and serving it end to end additionally
//! needs the emitter's consumer in `crate::protocols::http1`, which has not
//! landed. Under-reporting makes a fixture skip while over-reporting makes
//! it run and fail, so the honest answer stays `absent` until
//! the consumer exists.

use core::fmt;

use super::{
    authorization_header, AuthContext, AuthEmission, AuthScheme,
    HttpAuthMechanism, REDACTED_PLACEHOLDER,
};
use crate::error::CURLcode;

// The three constants this mechanism's bytes and its one error path rest on.

/// The `auth-scheme` token Bearer writes into an `Authorization:` header.
pub(crate) const BEARER_SCHEME_TOKEN: &str = "Bearer";

/// The header-prefix selector Bearer passes to
/// [`super::authorization_header`]: always the origin server.
///
/// Named rather than written as a bare `false` so that the one call site
/// reads as the invariant it is enforcing. `http_output_bearer()` has no
/// `proxy` parameter, its format string has no `"%s"` prefix, and
/// `super::proxy_auth_mask` clears the bit before a proxy arbitration can
/// reach it -- so `false` is not a default chosen here, it is the only value
/// the C can produce.
pub(crate) const BEARER_IS_NEVER_A_PROXY_MECHANISM: bool = false;

/// The one failure `http_output_bearer()` can report: `CURLE_OUT_OF_MEMORY`.
#[allow(dead_code)] // Reached only by this file's tests, per the note above.
pub(crate) const ALLOCATION_FAILURE: CURLcode = CURLcode::OutOfMemory;

// THE TWO COMPILE-TIME HALVES OF "BEARER IS NEVER AVAILABLE FOR A PROXY".
//
// Both are checked when this file is compiled rather than when a test runs,
// which is what makes the invariant structural: the fixtures that would
// otherwise catch an inversion (`lib/http.c:706`, `:574-575`) live outside
// this crate, and a runtime test is something somebody can invert along with
// the code it guards.
const _: () = assert!(
    !BEARER_IS_NEVER_A_PROXY_MECHANISM,
    "Bearer has no proxy form: lib/http.c:315 has no \"%s\" prefix"
);

// Second, the emitter's signature is pinned. Adding a `proxy` parameter -- or
// any other parameter -- to the one function that composes Bearer's header
// line stops compiling here, so the prefix above cannot be reintroduced as an
// argument either.
const _: fn(&BearerToken) -> String = BearerToken::header_line;

// The token: `data->set.str[STRING_BEARER]`.

/// An OAuth 2.0 bearer token, as `CURLOPT_XOAUTH2_BEARER` supplied it.
///
/// Supersedes the `STRING_BEARER` slot of `data->set.str[]`
/// (`lib/urldata.h:1231`, set by `lib/setopt.c:2204-2208`). The token is
/// **per transfer**, not per connection: `struct auth` keeps no Bearer state
/// at all -- `super::state_scope` returns `None` for
/// `AuthScheme::Bearer` -- so the credential is recomposed for every
/// request from this one owned value, exactly as C recomposes it from the
/// setting on each pass through `http_output_bearer()`.
///
/// # Why the token is text rather than bytes
///
/// C stores a NUL-terminated `char *`, so a NUL cannot appear inside the
/// token there either, and the string arrives from `argv` or from a C string
/// the application owns. Text is the representation that keeps this module's
/// error surface identical to the C's:
/// [`super::AuthEmission`] and [`super::authorization_header`] both speak
/// `String`, so a byte-oriented token would have to be converted at the
/// point of emission and would introduce a **second** failure mode --
/// "token is not representable" -- that `http_output_bearer()` does not
/// have. Keeping the conversion at the C-string boundary, where
/// `crate::easy::setopt` copies the option in and where C's
/// `Curl_setstropt()` copies it too, leaves this module with the C's single
/// allocation path and nothing else. See [`ALLOCATION_FAILURE`].
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct BearerToken {
    /// The token, byte for byte as configured.
    token: String,
}

impl BearerToken {
    /// The token `CURLOPT_XOAUTH2_BEARER` or `--oauth2-bearer` supplied.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::easy::setopt`, not yet landed.
    pub(crate) fn new(token: &str) -> Self {
        Self {
            token: token.to_owned(),
        }
    }

    /// The token itself.
    ///
    /// Named for what it returns rather than for the type it returns, so
    /// that a call site reading `token.as_str()` is visibly handling a
    /// credential.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::easy::getinfo`, not yet landed.
    pub(crate) fn as_str(&self) -> &str {
        &self.token
    }

    /// Whether the token is the empty string.
    ///
    /// Offered because emptiness is **not** a special case anywhere in the
    /// emission path and a reader is entitled to check that claim: an empty
    /// token yields `Authorization: Bearer \r\n`, which is what
    /// `curl_maprintf("Authorization: Bearer %s\r\n", "")` produces. The
    /// predicate exists for callers that want to warn or refuse on their own
    /// account, never for this module to branch on.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::config`, not yet landed.
    pub(crate) fn is_empty(&self) -> bool {
        self.token.is_empty()
    }

    /// The complete `Authorization:` header line, CRLF included.
    ///
    /// Supersedes `http_output_bearer()` (`lib/http.c:308-325`). The output
    /// is byte-for-byte what
    /// `curl_maprintf("Authorization: Bearer %s\r\n", token)` produces for
    /// every possible token:
    ///
    /// ```text
    /// Authorization: Bearer mF_9.B5f-4.1JqM\r\n
    /// ```
    ///
    /// One space after the colon, one space after the scheme token, the
    /// token verbatim, then `\r\n` and nothing further. The shape comes from
    /// [`super::authorization_header`] rather than from a format string
    /// here, because all five C emitters share it and 168 fixtures compare
    /// the result inside a byte-exact `<protocol>` block -- a second space,
    /// a lower-case scheme token or a bare `\n` would fail them.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`.
    pub(crate) fn header_line(&self) -> String {
        authorization_header(
            BEARER_IS_NEVER_A_PROXY_MECHANISM,
            BEARER_SCHEME_TOKEN,
            &self.token,
        )
    }
}

impl fmt::Debug for BearerToken {
    /// Prints a placeholder, never the token.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerToken")
            .field("token", &REDACTED_PLACEHOLDER)
            .finish()
    }
}

/// Whether a bearer token is configured: C's
/// `data->set.str[STRING_BEARER] != NULL`.
///
/// Four separate C sites test exactly this expression, and each feeds a
/// different decision:
///
/// | Site | What it decides |
/// |------|-----------------|
/// | `lib/http.c:544` | clears `CURLAUTH_BEARER` from `authmask` |
/// | `lib/http.c:554` | whether to arbitrate the origin at all |
/// | `lib/http.c:706` | whether the emission arm may run |
/// | `lib/http.c:783` | the fifth disjunct of the early exit |
///
/// The predicate is named here so that all four callers spell the same
/// condition and so that the sense cannot be inverted at one of them
/// unnoticed. It does **not** duplicate any of the four decisions: they all
/// live in `super`, which takes this predicate's answer as an input.
/// `super::auth_act` owns the first two through
/// `super::AuthActInput::have_bearer`, `super::select_emitter` the third
/// through `super::EmissionGuards::have_bearer`, and
/// `super::credentials_offered` the fourth.
#[must_use]
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) fn token_is_configured(token: Option<&BearerToken>) -> bool {
    token.is_some()
}

// The mechanism.

/// The Bearer mechanism, ready to emit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Bearer {
    /// The configured token.
    token: BearerToken,
}

impl Bearer {
    /// A mechanism over `token`.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`.
    pub(crate) fn new(token: BearerToken) -> Self {
        Self { token }
    }

    /// The mechanism for a transfer, or `None` when no token is configured.
    ///
    /// C's `if(data->set.str[STRING_BEARER])` in one place: a caller that
    /// gets `Some` needs no further test, and a caller that gets `None` has
    /// its answer for [`super::EmissionGuards::have_bearer`] and for
    /// `super::AuthActInput::have_bearer` from the same call.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`.
    pub(crate) fn from_setting(token: Option<&BearerToken>) -> Option<Self> {
        token.map(|token| Self::new(token.clone()))
    }

    /// The token this mechanism will emit.
    #[must_use]
    #[allow(dead_code)] // Reached by this file's tests until a consumer lands.
    pub(crate) fn token(&self) -> &BearerToken {
        &self.token
    }
}

impl HttpAuthMechanism for Bearer {
    fn scheme(&self) -> AuthScheme {
        AuthScheme::Bearer
    }

    /// Consumes nothing: a Bearer challenge has no body to decode.
    ///
    /// `auth_bearer()` (`lib/http.c:987-1003`) is the whole of C's
    /// challenge-side handling and it contains no parsing at all. It ORs
    /// `CURLAUTH_BEARER` into `*availp` and into `authp->avail`, and then --
    /// **only** when Bearer was the already-picked method -- clears
    /// `authp->avail`, emits `"Bearer authentication problem, ignoring."`
    /// and sets `data->state.authproblem`, because a 40x answer to a request
    /// that already carried the token means the token itself is not valid.
    ///
    /// # Errors
    ///
    /// Never. `auth_bearer()` returns `CURLE_OK` unconditionally, which is
    /// also why `lib/http.c:1073` can afford to omit the `!result` term that
    /// guards the four mechanisms tested before it.
    fn input(
        &mut self,
        _challenge: &[u8],
        _proxy: bool,
    ) -> Result<(), CURLcode> {
        Ok(())
    }

    /// Emits `Authorization: Bearer <token>\r\n`.
    ///
    /// # Errors
    ///
    /// Never, for this mechanism. The C's single error path is the header
    /// allocation ([`ALLOCATION_FAILURE`]), which Rust's allocator does not
    /// surface as a value. The signature keeps the `Result` because the
    /// trait is shared with five mechanisms that do fail.
    fn output(
        &mut self,
        _ctx: &mut AuthContext<'_>,
    ) -> Result<AuthEmission, CURLcode> {
        Ok(AuthEmission::Final(self.token.header_line()))
    }
}

// Tests
//
// `tests/libtest/*.c` and `tests/unit/*.c` cannot link against this crate --
// they call internal `Curl_*` symbols, and a Rust static library does not
// export `pub(crate)` items -- so the coverage they would have carried is
// relocated here, inside the module under test, which is also where a private
// item is reachable without widening its visibility for a test's sake.
//
// Every wire expectation below is written as a LITERAL rather than derived
// from the implementation. Deriving it would make the test agree with
// whatever the code does, which is the one thing a parity test must not do.
// The literals come from `lib/http.c:315` and from
// `docs/cmdline-opts/oauth2-bearer.md:16`, whose example token is the one
// `tests/data/test2074` puts on the wire.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        auth_act, finish_emission, proxy_auth_mask, select_emitter, AuthMask,
        AuthState, AuthStatePair, EmissionGuards, BEARER_PROBLEM,
        PREFERENCE_ORDER,
    };
    use crate::crypto::rand::TestRng;
    use crate::trace::{TraceConfig, TraceState, Tracer, WriterSink};
    use crate::util::timeval::{CurlTime, TestClock};

    /// The token `docs/cmdline-opts/oauth2-bearer.md:16` documents and
    /// `tests/data/test2074` puts on the wire.
    const EXAMPLE_TOKEN: &str = "mF_9.B5f-4.1JqM";

    /// The complete line `tests/data/test2074` compares, byte for byte.
    ///
    /// Written out in full, with the CRLF spelled as an escape, so that the
    /// expectation is readable and cannot be produced by the same code path
    /// it is checking.
    const EXAMPLE_LINE: &str = "Authorization: Bearer mF_9.B5f-4.1JqM\r\n";

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

    /// Runs `body` with an emission context whose clock and generator are the
    /// injected test implementations.
    fn with_context<R>(body: impl FnOnce(&mut AuthContext<'_>) -> R) -> R {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let mut rng = TestRng::from_seed(7);
        let mut ctx = AuthContext {
            proxy: false,
            request_method: b"GET",
            request_target: b"/2074",
            clock: &clock,
            rng: &mut rng,
        };
        body(&mut ctx)
    }

    /// The header line for `token`, through the mechanism rather than through
    /// [`BearerToken::header_line`] directly, so that the trait path is the
    /// one under test.
    fn emit(token: &str) -> String {
        let mut bearer = Bearer::new(BearerToken::new(token));
        let emission = with_context(|ctx| {
            bearer.output(ctx).expect("Bearer emission cannot fail")
        });
        assert!(
            emission.is_done(),
            "Bearer is single-pass, so its emission is Final"
        );
        emission.header().map(str::to_owned).unwrap_or_default()
    }

    // -- The bytes ---------------------------------------------------------

    #[test]
    fn the_documented_example_token_produces_the_fixture_line() {
        // `tests/data/test2074`'s `<protocol crlf="headers">` block contains
        // exactly this line, and `tests/getpart.pm:351+`'s `compareparts`
        // joins both sides into one string and compares them whole -- no
        // per-line matching, no normalization, no reordering. So this is the
        // whole of the parity requirement for this mechanism.
        assert_eq!(emit(EXAMPLE_TOKEN), EXAMPLE_LINE);
        assert_eq!(BearerToken::new(EXAMPLE_TOKEN).header_line(), EXAMPLE_LINE);
    }

    #[test]
    fn the_line_has_one_space_after_the_colon_and_one_after_the_scheme() {
        // `lib/http.c:315` is "Authorization: Bearer %s\r\n". Spelled out
        // character by character rather than by comparing against the
        // constant, because a doubled space is exactly the defect a
        // whole-string comparison against a same-file constant would miss if
        // the constant were ever regenerated from the code.
        let line = emit("t");
        let mut bytes = line.bytes();
        for expected in b"Authorization:" {
            assert_eq!(bytes.next(), Some(*expected));
        }
        assert_eq!(bytes.next(), Some(b' '));
        for expected in b"Bearer" {
            assert_eq!(bytes.next(), Some(*expected));
        }
        assert_eq!(bytes.next(), Some(b' '));
        assert_eq!(bytes.next(), Some(b't'));
        assert_eq!(bytes.next(), Some(b'\r'));
        assert_eq!(bytes.next(), Some(b'\n'));
        assert_eq!(bytes.next(), None);
    }

    #[test]
    fn the_line_ends_in_crlf_and_contains_no_other_line_break() {
        for token in ["a", EXAMPLE_TOKEN, "", "x y z", "=+/"] {
            let line = emit(token);
            assert!(line.ends_with("\r\n"), "{line:?}");
            assert_eq!(
                line.matches('\r').count(),
                1,
                "exactly one CR, in the terminator: {line:?}"
            );
            assert_eq!(
                line.matches('\n').count(),
                1,
                "exactly one LF, in the terminator: {line:?}"
            );
            // Not a bare LF anywhere: a fixture comparing `\r\n` would fail
            // on one, and `crlf="headers"` in test2074 makes the ending part
            // of the compared text rather than something the harness fixes.
            assert!(!line.trim_end_matches("\r\n").contains('\n'));
        }
    }

    #[test]
    fn the_scheme_token_matches_the_shared_vocabulary() {
        // The literal here and `AuthScheme::header_scheme` are two
        // independent spellings of `lib/http.c:315` and `:1073`. Asserting
        // they agree is what stops one from drifting; asserting the literal
        // separately is what stops both from drifting together.
        assert_eq!(BEARER_SCHEME_TOKEN, "Bearer");
        assert_eq!(
            AuthScheme::Bearer.header_scheme(),
            Some(BEARER_SCHEME_TOKEN)
        );
        assert_eq!(AuthScheme::Bearer.label(), "Bearer");
    }

    // -- No encoding, no validation, no normalization ----------------------

    #[test]
    fn the_token_is_never_base64_encoded() {
        // The single most important difference from Basic. A token that IS
        // valid base64 must not be re-encoded, and a token containing the
        // base64 alphabet's own punctuation must not be mistaken for
        // something needing a transformation.
        assert_eq!(
            emit("dXNlcjpwYXNz"),
            "Authorization: Bearer dXNlcjpwYXNz\r\n"
        );
        assert_eq!(emit("=+/"), "Authorization: Bearer =+/\r\n");
        assert_eq!(emit("a=="), "Authorization: Bearer a==\r\n");
        assert_eq!(emit("a+b/c="), "Authorization: Bearer a+b/c=\r\n");

        // And the inverse direction: base64-encoding `user:pass` yields
        // `dXNlcjpwYXNz`, which is what Basic would emit for those
        // credentials (`lib/http.c:274-287`). Bearer given the CLEARTEXT
        // must emit the cleartext, so the two are distinguishable.
        assert_eq!(emit("user:pass"), "Authorization: Bearer user:pass\r\n");
    }

    #[test]
    fn the_token_is_not_trimmed_escaped_or_validated() {
        // `curl_maprintf("...%s...", token)` inspects nothing, so every one
        // of these reaches the wire unchanged. Each row is a transformation
        // some other authentication scheme performs and Bearer does not.
        let cases: [(&str, &str); 8] = [
            ("", "Authorization: Bearer \r\n"),
            (" ", "Authorization: Bearer  \r\n"),
            ("  leading", "Authorization: Bearer   leading\r\n"),
            ("trailing  ", "Authorization: Bearer trailing  \r\n"),
            ("two words", "Authorization: Bearer two words\r\n"),
            ("a\tb", "Authorization: Bearer a\tb\r\n"),
            ("\"quoted\"", "Authorization: Bearer \"quoted\"\r\n"),
            ("a%20b", "Authorization: Bearer a%20b\r\n"),
        ];
        for (token, expected) in cases {
            assert_eq!(emit(token), expected, "token {token:?}");
        }
    }

    #[test]
    fn a_non_ascii_token_is_emitted_without_transcoding() {
        // No case folding, no normalization, no re-encoding: the bytes out
        // are the bytes in. Compared as BYTES rather than as text, because
        // byte equality is what the fixture corpus compares and text
        // equality would tolerate a normalizing transformation.
        let token = "t\u{f6}k\u{e9}n-\u{5b57}";
        let line = emit(token);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"Authorization: Bearer ");
        expected.extend_from_slice(token.as_bytes());
        expected.extend_from_slice(b"\r\n");
        assert_eq!(line.as_bytes(), expected.as_slice());

        // Non-normalization, stated as its own assertion: the composed and
        // decomposed spellings of the same character are different tokens
        // and must stay different lines.
        assert_ne!(emit("\u{e9}"), emit("e\u{301}"));
    }

    #[test]
    fn an_empty_token_is_emitted_and_is_not_a_special_case() {
        // `--oauth2-bearer ""` is accepted by `ARG_STRG`, and
        // `Curl_setstropt()` stores it, so the emitter sees an empty string
        // and prints a header whose credential is empty. Nothing refuses it,
        // and the predicate that reports it exists for callers rather than
        // for a branch here.
        let token = BearerToken::new("");
        assert!(token.is_empty());
        assert_eq!(token.as_str(), "");
        assert_eq!(token.header_line(), "Authorization: Bearer \r\n");
        assert!(!BearerToken::new(EXAMPLE_TOKEN).is_empty());
    }

    #[test]
    fn the_token_round_trips_through_the_accessor() {
        for token in ["", " ", EXAMPLE_TOKEN, "=+/", "t\u{f6}k\u{e9}n"] {
            assert_eq!(BearerToken::new(token).as_str(), token);
            assert_eq!(
                Bearer::new(BearerToken::new(token)).token().as_str(),
                token
            );
        }
    }

    // -- There is no proxy variant ----------------------------------------

    #[test]
    fn no_emission_can_ever_be_a_proxy_authorization_header() {
        // Three independent statements of the same invariant.
        //
        // 1. The prefix selector this module passes is the origin one, and
        //    it is the only value in the module. That half is asserted at
        //    COMPILE time beside the constant, together with the emitter's
        //    signature, so there is nothing left to check at run time here
        //    -- and nothing a test could weaken.

        // 2. No output begins with the prefix, for any token -- including
        //    one that itself starts with "Proxy-", which could only appear
        //    after the scheme token.
        for token in ["", EXAMPLE_TOKEN, "Proxy-Authorization", "\u{e9}"] {
            let line = emit(token);
            assert!(line.starts_with("Authorization: Bearer "), "{line:?}");
            assert!(!line.starts_with("Proxy-"), "{line:?}");
        }

        // 3. `super::proxy_auth_mask` is the only constructor of a proxy
        //    mask in the crate and it clears the bit unconditionally, so
        //    arbitration cannot select Bearer for a proxy even if the
        //    application asked for it and the proxy offered it.
        //    `lib/http.c:574-575`.
        for base in [
            AuthMask::ANY,
            AuthMask::BEARER,
            AuthMask::from_bits(u32::MAX),
            AuthMask::BEARER.union(AuthMask::BASIC),
        ] {
            let narrowed = proxy_auth_mask(base);
            assert!(!narrowed.intersects(AuthMask::BEARER));
        }
        // Non-vacuity: the mask keeps everything else it was given.
        assert!(proxy_auth_mask(AuthMask::ANY).intersects(AuthMask::BASIC));
    }

    #[test]
    fn the_emission_arm_declines_the_proxy_side() {
        // `lib/http.c:706`'s guard opens with `!proxy &&`, and
        // `super::select_emitter` reproduces it. With `proxy` true the arm
        // chooses nothing yet still sets `done`, which is
        // `lib/http.c:714-716`'s unconditional assignment.
        let guards = EmissionGuards {
            have_bearer: true,
            ..EmissionGuards::default()
        };

        let mut state = AuthState::ZERO;
        state.picked = AuthMask::BEARER;
        assert_eq!(select_emitter(&mut state, true, &guards), None);
        assert!(state.is_done());

        let mut state = AuthState::ZERO;
        state.picked = AuthMask::BEARER;
        assert_eq!(
            select_emitter(&mut state, false, &guards),
            Some(AuthScheme::Bearer)
        );
        assert!(state.is_done());
    }

    // -- The option plumbing ----------------------------------------------

    #[test]
    fn the_authmask_clears_bearer_when_no_token_is_configured() {
        // `lib/http.c:544`: `if(!data->set.str[STRING_BEARER]) authmask &=
        // ~CURLAUTH_BEARER;`. The narrowing lives in `super::auth_act`; this
        // asserts the consequence that makes the emission arm safe -- a pick
        // can never land on Bearer without a token.
        let offered_and_wanted = |have_bearer: bool| {
            let mut pair = AuthStatePair::ZERO;
            pair.host.want = AuthMask::BEARER.union(AuthMask::BASIC);
            pair.host.avail = AuthMask::BEARER.union(AuthMask::BASIC);
            let input = crate::auth::AuthActInput {
                httpcode: 401,
                have_user: true,
                have_bearer,
                ..crate::auth::AuthActInput::default()
            };
            let mut problem = false;
            let (outcome, _trace) = with_tracer(|tracer| {
                auth_act(&mut pair, &input, &mut problem, false, tracer)
            });
            let outcome = outcome.expect("no failure is configured");
            assert!(outcome.picked_host);
            pair.host.picked
        };

        // Without a token the bit is gone from the mask, so the next
        // preference -- Basic, per `PREFERENCE_ORDER` -- is taken instead.
        assert_eq!(offered_and_wanted(false), AuthMask::BASIC);
        // With one, Bearer wins: it is second in preference and Basic fifth.
        assert_eq!(offered_and_wanted(true), AuthMask::BEARER);
        assert_eq!(PREFERENCE_ORDER[1], AuthScheme::Bearer);
        assert_eq!(PREFERENCE_ORDER[4], AuthScheme::Basic);
    }

    #[test]
    fn the_configured_predicate_reports_the_c_expression() {
        // `data->set.str[STRING_BEARER] != NULL`, which four C sites test.
        assert!(!token_is_configured(None));
        let token = BearerToken::new(EXAMPLE_TOKEN);
        assert!(token_is_configured(Some(&token)));
        // The empty token is CONFIGURED. C tests the pointer, not the
        // length, so `--oauth2-bearer ""` reaches the emitter.
        let empty = BearerToken::new("");
        assert!(token_is_configured(Some(&empty)));
    }

    #[test]
    fn a_mechanism_exists_exactly_when_a_token_does() {
        // The absent-token branch is removed by construction rather than
        // handled: `from_setting` is the one place the test lives.
        assert!(Bearer::from_setting(None).is_none());
        let token = BearerToken::new(EXAMPLE_TOKEN);
        let bearer =
            Bearer::from_setting(Some(&token)).expect("a token was supplied");
        assert_eq!(bearer.token().as_str(), EXAMPLE_TOKEN);
        assert_eq!(bearer.scheme(), AuthScheme::Bearer);
    }

    // -- The challenge side, and the error surface -------------------------

    #[test]
    fn consuming_a_challenge_decodes_nothing_and_cannot_fail() {
        // `auth_bearer()` (`lib/http.c:987-1003`) has no parsing step and
        // returns `CURLE_OK` unconditionally -- which is what lets
        // `lib/http.c:1073` omit the `!result` term its four predecessors
        // carry. Both sides and every input shape.
        let mut bearer = Bearer::new(BearerToken::new(EXAMPLE_TOKEN));
        for challenge in [
            &b""[..],
            &b"Bearer"[..],
            &b"Bearer realm=\"x\""[..],
            &b"Bearer error=\"invalid_token\""[..],
            &b"\xff\xfe"[..],
        ] {
            assert_eq!(bearer.input(challenge, false), Ok(()));
            assert_eq!(bearer.input(challenge, true), Ok(()));
        }
        // The token is untouched by a challenge: Bearer keeps no per-request
        // state, which `super::state_scope` records as `None`.
        assert_eq!(bearer.token().as_str(), EXAMPLE_TOKEN);
        assert!(crate::auth::state_scope(AuthScheme::Bearer).is_none());
    }

    #[test]
    fn the_only_error_code_the_c_can_report_is_out_of_memory() {
        // `lib/http.c:319`. The integer is written as a literal because it
        // crosses the ABI: `CURLE_OUT_OF_MEMORY` is 27 in
        // `include/curl/curl.h` and a consumer compiled against curl 8.x
        // holds that number.
        assert_eq!(ALLOCATION_FAILURE, CURLcode::OutOfMemory);
        assert_eq!(ALLOCATION_FAILURE as i32, 27);

        // And emission does not, in fact, produce it -- for any input. The
        // path is unreachable rather than unimplemented; see the constant's
        // documentation.
        for token in ["", EXAMPLE_TOKEN, "=+/", "t\u{f6}k\u{e9}n", "a b c"] {
            let mut bearer = Bearer::new(BearerToken::new(token));
            let emission = with_context(|ctx| bearer.output(ctx));
            assert!(emission.is_ok(), "token {token:?}");
        }
    }

    #[test]
    fn the_diagnostic_text_is_curls_own() {
        // `lib/http.c:998`, reproduced verbatim by `super::BEARER_PROBLEM`
        // and reachable from here so that a change to it fails a test in the
        // module that owns the mechanism as well as in the module that owns
        // the scan.
        assert_eq!(BEARER_PROBLEM, "Bearer authentication problem, ignoring.");
    }

    // -- The credential gains no path to a log ----------------------------

    #[test]
    fn the_token_formatter_prints_a_placeholder_and_not_the_secret() {
        let token = BearerToken::new(EXAMPLE_TOKEN);
        let rendered = format!("{token:?}");
        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        assert!(!rendered.contains(EXAMPLE_TOKEN), "{rendered}");
        // Nor the length, which is a weak oracle and is not needed.
        assert!(!rendered.contains("15"), "{rendered}");

        // The containment property: a DERIVED formatter on a holder cannot
        // leak the token, because the hand-written one is on the token
        // itself. `Bearer` derives its `Debug`, which is what makes this
        // assertion about a real holder rather than a hypothetical one.
        let holder = Bearer::new(BearerToken::new(EXAMPLE_TOKEN));
        let rendered = format!("{holder:?}");
        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        assert!(!rendered.contains(EXAMPLE_TOKEN), "{rendered}");

        // And at one further remove, which is the case a review convention
        // would miss: a structure declared elsewhere that happens to hold
        // one and derives its own formatter.
        #[derive(Debug)]
        struct Enclosing {
            bearer: Bearer,
        }
        let enclosing = Enclosing {
            bearer: Bearer::new(BearerToken::new(EXAMPLE_TOKEN)),
        };
        let rendered = format!("{enclosing:?}");
        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        assert!(!rendered.contains(EXAMPLE_TOKEN), "{rendered}");
        // The field really does hold the token, so the formatter above had
        // something to leak and chose not to.
        assert_eq!(enclosing.bearer.token().as_str(), EXAMPLE_TOKEN);
    }

    #[test]
    fn a_full_emission_puts_no_credential_into_the_trace_log() {
        // The whole chain, with tracing at its most verbose: arbitrate,
        // emit, then run the trailing bookkeeping that DOES write a
        // diagnostic (`lib/http.c:720-733`). The captured sink must contain
        // curl's own line and not one byte of the token.
        let guards = EmissionGuards {
            have_bearer: true,
            ..EmissionGuards::default()
        };
        let mut state = AuthState::ZERO;
        state.picked = AuthMask::BEARER;

        let chosen = select_emitter(&mut state, false, &guards);
        assert_eq!(chosen, Some(AuthScheme::Bearer));

        let mut bearer = Bearer::new(BearerToken::new(EXAMPLE_TOKEN));
        let emission = with_context(|ctx| {
            bearer.output(ctx).expect("Bearer emission cannot fail")
        });
        assert_eq!(emission.header(), Some(EXAMPLE_LINE));

        let ((), captured) = with_tracer(|tracer| {
            finish_emission(
                &mut state,
                false,
                chosen,
                Some(&emission),
                None,
                tracer,
            );
        });

        assert!(
            captured.contains("Server auth using Bearer with user ''"),
            "the sink must carry curl's own diagnostic: {captured:?}"
        );
        assert!(
            !captured.contains(EXAMPLE_TOKEN),
            "the token must not reach the trace log: {captured:?}"
        );
        // Nor any part of it long enough to matter, and nor the header line
        // this module composed: emitting THAT is `crate::protocols::http1`'s
        // job through `CURLINFO_HEADER_OUT`, not this directory's.
        assert!(!captured.contains("mF_9"), "{captured:?}");
        assert!(!captured.contains("Authorization:"), "{captured:?}");
        assert!(!state.is_multipass(), "Bearer is single-pass");
    }

    #[test]
    fn this_module_emits_no_trace_output_of_its_own() {
        // Composing a header and consuming a challenge must write nothing at
        // all, at the most verbose setting there is. Adding a `tracing` or
        // `log` call that printed the token would fail here.
        let ((), captured) = with_tracer(|_tracer| {
            let mut bearer = Bearer::new(BearerToken::new(EXAMPLE_TOKEN));
            let _line = bearer.token().header_line();
            let _ = with_context(|ctx| bearer.output(ctx));
            let _ = bearer.input(b"Bearer realm=\"x\"", false);
        });
        assert!(captured.is_empty(), "{captured:?}");
    }
}
