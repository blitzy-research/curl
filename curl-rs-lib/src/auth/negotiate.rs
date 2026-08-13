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
// RFC4178 Simple and Protected GSS-API Negotiation Mechanism
//
//***************************************************************************

//! SPNEGO (Negotiate) authentication over GSS-API, behind a default-off
//! feature.
//!
//! Supersedes `lib/vauth/spnego_gssapi.c` in full, `lib/http_negotiate.c` in
//! full, and the HTTP-relevant plumbing of `lib/curl_gssapi.c`. The per-item
//! citations below name the exact C locators, because every observable string
//! and every branch order in this file is transcribed rather than derived:
//!
//! - `lib/urldata.h:312-318`, `curlnegotiate`'s five states ->
//!   [`NegotiateState`]
//! - `lib/vauth/vauth.h:295-324`, `struct negotiatedata` ->
//!   [`NegotiateData`]
//! - `lib/vauth/vauth.c:238-248`, `Curl_auth_nego_get` and its two metadata
//!   keys -> [`ConnectionNegotiate`]
//! - `lib/vauth/vauth.c:48-63`, `Curl_auth_build_spn` ->
//!   [`crate::auth::build_spn`]
//! - `lib/vauth/spnego_gssapi.c:49-52`, `Curl_auth_is_spnego_supported` ->
//!   [`is_spnego_supported`]
//! - `lib/vauth/spnego_gssapi.c:72-201`,
//!   `Curl_auth_decode_spnego_message` ->
//!   [`NegotiateData::decode_spnego_message`]
//! - `lib/vauth/spnego_gssapi.c:219-247`,
//!   `Curl_auth_create_spnego_message` ->
//!   [`NegotiateData::create_spnego_message`]
//! - `lib/vauth/spnego_gssapi.c:259-289`, `Curl_auth_cleanup_spnego` ->
//!   [`NegotiateData::cleanup_spnego`]
//! - `lib/http_negotiate.c:37-47`, `http_auth_nego_reset` ->
//!   [`ConnectionNegotiate::auth_nego_reset`]
//! - `lib/http_negotiate.c:49-149`, `Curl_input_negotiate` ->
//!   [`Negotiate::input_negotiate`]
//! - `lib/http_negotiate.c:151-260`, `Curl_output_negotiate` ->
//!   [`Negotiate::output_negotiate`]
//! - `lib/curl_gssapi.c:63-68`, the two mechanism OIDs ->
//!   `crate::ffi::Mechanism`
//! - `lib/curl_gssapi.c:313-371`, the `req_flags` composition ->
//!   `crate::ffi::request_flags`
//! - `lib/curl_gssapi.c:387-442`, the GSS error-text assembler ->
//!   `crate::ffi::gss`
//! - `lib/http.c:876-905`, `auth_spnego`'s state effect ->
//!   [`ConnectionNegotiate::token_received`]
//! - `lib/http.c:4028-4035`, the `AUTHDONE` to `AUTHSUCC` promotion ->
//!   [`ConnectionNegotiate::settle_after_response`]
//!
//! # The coupling to `crate::version`, stated so the two cannot drift
//!
//! [`is_spnego_supported`] is this module's successor to
//! `Curl_auth_is_spnego_supported()`, and it is a pure forward to
//! `crate::ffi::gss_available()` -- the one blessed, cached, total probe.
//! `crate::auth::is_spnego_supported` is a pure forward to the same probe with
//! a `false` arm for a build without the feature, and
//! `crate::version::gss_present` is a third. All three are forwards with no
//! logic of their own, so they cannot disagree; a test in this file asserts
//! the agreement rather than assuming it.
//!
//! `crate::version::ENGINE_GSS` names this very file and is still `absent`,
//! which is correct and is not an oversight. The three banner tokens
//! `GSS-API`, `Kerberos` and `SPNEGO` are gated on `ENGINE_GSS` **and**
//! `ENGINE_AUTH` **and** the runtime probe, and a Negotiate exchange needs an
//! HTTP driver -- `crate::protocols::http1` -- to carry it.
//! `crate::version::supports_negotiate` and `crate::version::negotiate_usable`
//! are the two predicates that consume `ENGINE_GSS`; flipping it is a one-word
//! change in `crate::version` once the driver exists, and nothing in this file
//! has to move for it.
//!
//! # Credentials come from the CONNECTION, not the transfer
//!
//! This is a genuine asymmetry with every other mechanism in this directory
//! and is easy to get wrong by copying `basic.rs`.
//! `lib/http_negotiate.c:78-79` reads `conn->user` and `conn->passwd`, and
//! `:67-68` reads `conn->http_proxy.user` and `conn->http_proxy.passwd`.
//! Basic, Bearer and Digest read the **per-transfer**
//! `data->state.aptr.{user,passwd}` instead, under an explicit C comment at
//! `lib/http.c:253-254`: "credentials are unique per transfer for HTTP, do not
//! use the ones for the connection". Negotiate deliberately does the opposite,
//! because its handshake is bound to the connection
//! (`crate::auth::StateScope::Connection`) and `lib/url.c:1191-1197` will only
//! reuse a Negotiate connection whose *connection* credentials match.
//! [`NegotiateEndpoint`] carries the connection-level pair for that reason.
//!
//! And then `Curl_auth_decode_spnego_message()` **discards both**:
//! `lib/vauth/spnego_gssapi.c:93-94` is `(void)user; (void)password;`. The
//! identity comes from the Kerberos credentials cache, not from the URL. Both
//! are still threaded through [`NegotiateData::decode_spnego_message`] so the
//! signature stays faithful and so the discard is visible at the point where
//! the C performs it. The same fact is why
//! `crate::auth::user_contains_domain` accepts an absent username under this
//! feature, and why `CURLAUTH_NEGOTIATE` is one of the five disjuncts in
//! `Curl_http_output_auth`'s early exit (`lib/http.c:774-789`) -- Negotiate
//! may proceed with no username at all.

use core::fmt;

use crate::auth::{
    authorization_header, build_spn, AuthContext, AuthEmission, AuthScheme,
    Credentials, HttpAuthMechanism, MechanismSlots,
};
use crate::error::CURLcode;
use crate::ffi::{
    Delegation, Diagnostics, HandshakeState, Mechanism, SecurityContext,
    StepOptions, TargetName,
};
use crate::trace::{infof, Tracer};
use crate::util::base64;

// The compile-time half of every availability answer in this file.
const _: () = assert!(cfg!(feature = "negotiate"));

// THE FROZEN OBSERVABLE STRINGS.
//
// Every literal below is either wire bytes or `--verbose` output, so all of
// them are transcribed character for character and none may be reformatted.
// They are named constants rather than inline literals so that a test can
// assert the exact text without restating it.

/// The `auth-scheme` token, in the spelling curl writes and matches.
///
/// `lib/http_negotiate.c:98` advances by `strlen("Negotiate")` and `:200`
/// passes the same literal back into the input path. It is also the argument
/// `Curl_http_input_auth()` hands `authcmp()` (`lib/http.c:1057`), which is
/// why `crate::auth::AuthScheme::header_scheme` spells it identically.
const NEGOTIATE_SCHEME: &str = "Negotiate";

/// The service name both endpoints default to.
///
/// `lib/http_negotiate.c:69-70` and `:80-81`: `STRING_PROXY_SERVICE_NAME` and
/// `STRING_SERVICE_NAME` respectively, each falling back to `"HTTP"`. Upper
/// case, and it reaches a KDC as half of the service principal name, so the
/// casing is not cosmetic.
pub(crate) const DEFAULT_SERVICE_NAME: &str = "HTTP";

/// `"Negotiate auth restarted"` -- `lib/http_negotiate.c:105`.
pub(crate) const AUTH_RESTARTED: &str = "Negotiate auth restarted";

/// The no-persistence cleanup notice -- `lib/http_negotiate.c:195-196`.
///
/// The C splits it across two source lines, so the concatenated result is what
/// reaches the user: one space after the comma, one space after the colon, and
/// no other whitespace anywhere.
pub(crate) const NO_PERSISTENT_AUTH: &str =
    "Curl_output_negotiate, no persistent authentication: cleanup existing \
     context";

/// `"SPNEGO handshake failure (empty challenge message)"` --
/// `lib/vauth/spnego_gssapi.c:142`.
pub(crate) const EMPTY_CHALLENGE: &str =
    "SPNEGO handshake failure (empty challenge message)";

/// The bytes an absent username or password is replaced with.
///
/// `lib/http_negotiate.c:90-95`, whose comment is "Not set means empty". The
/// substitution is preserved even though the values are then discarded, so
/// that the discard is the only reason they go unused.
const NOT_SET_MEANS_EMPTY: &[u8] = b"";

// CAPABILITY ADVERTISEMENT.

/// Whether SPNEGO is usable **in this process, right now**.
#[must_use]
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) fn is_spnego_supported() -> bool {
    crate::ffi::gss_available()
}

// THE FIVE-STATE MACHINE.

/// The Negotiate handshake position, per connection and per endpoint.
///
/// # Why an enum and not an integer
///
/// `match` is exhaustive, so a state added here forces every decision site to
/// acknowledge it. The C's `if(*state == GSS_AUTHRECV) ... else if(*state ==
/// GSS_AUTHSUCC)` chain (`lib/http_negotiate.c:180-189`) silently falls through
/// for the other three, and a sixth state would join them unnoticed.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum NegotiateState {
    /// `GSS_AUTHNONE`: no handshake has begun on this endpoint.
    ///
    /// The `calloc` default in C, and therefore this type's [`Default`].
    /// `lib/url.c:1196` and `:1215` refuse to reuse a connection for a
    /// transfer that does *not* want Negotiate whenever the state has left
    /// this value.
    #[default]
    AuthNone,
    /// `GSS_AUTHRECV`: a challenge token arrived and was consumed.
    ///
    /// Set by the challenge handler, not by this module's own transitions --
    /// `lib/http.c:897-898`, "we received a GSS auth token and we dealt with
    /// it fine". While an endpoint sits here the connection must not be
    /// discarded mid-handshake (`lib/multi.c:573-574`).
    AuthRecv,
    /// `GSS_AUTHSENT`: a response token was emitted and more are expected.
    AuthSent,
    /// `GSS_AUTHDONE`: a response token was emitted and the GSS status says
    /// the client's part is finished.
    ///
    /// `lib/http_negotiate.c:236-240`. Still provisional: the server has not
    /// yet answered, so a further 401 or 407 restarts the exchange.
    AuthDone,
    /// `GSS_AUTHSUCC`: the server accepted the authentication.
    ///
    /// Promoted from [`Self::AuthDone`] by the response path
    /// (`lib/http.c:4028-4035`) once a status code other than 401 (origin) or
    /// 407 (proxy) arrives. See [`ConnectionNegotiate::settle_after_response`].
    AuthSucc,
}

impl NegotiateState {
    /// The C enumerator's own spelling.
    ///
    /// Present so that a diagnostic or a test names the state as
    /// `lib/urldata.h:312-318` names it, instead of restating a Rust variant
    /// name that a reader would then have to map back.
    #[must_use]
    pub(crate) const fn as_c_name(self) -> &'static str {
        match self {
            Self::AuthNone => "GSS_AUTHNONE",
            Self::AuthRecv => "GSS_AUTHRECV",
            Self::AuthSent => "GSS_AUTHSENT",
            Self::AuthDone => "GSS_AUTHDONE",
            Self::AuthSucc => "GSS_AUTHSUCC",
        }
    }

    /// Whether a header must be withheld from future requests on this
    /// connection.
    #[must_use]
    const fn is_settled(self) -> bool {
        matches!(self, Self::AuthDone | Self::AuthSucc)
    }

    /// Whether a handshake has begun on this endpoint: `!= GSS_AUTHNONE`.
    ///
    /// The test at `lib/http.c:430-431` ("The NEGOTIATE-negotiation has
    /// started, keep on sending"), at `lib/url.c:1196` and `:1215`
    /// (connection reuse), and at `lib/url.c:1226-1228` (`force_reuse`).
    #[must_use]
    const fn is_negotiating(self) -> bool {
        !matches!(self, Self::AuthNone)
    }
}

impl fmt::Debug for NegotiateState {
    /// Hand-written so the output is the C enumerator's spelling.
    ///
    /// A derived formatter would print `AuthRecv`, which is not a name that
    /// appears anywhere in the C tree or in any fixture. Nothing here is a
    /// secret -- a handshake position carries no credential -- but the
    /// formatter is still written by hand rather than derived, because this
    /// module's convention is that no type reachable from a Negotiate exchange
    /// gets an inherited formatter it did not choose.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_c_name())
    }
}

// THE SUBSTITUTABLE GSS SEAM.

/// The GSS-API operations one SPNEGO exchange performs, as a seam.
///
/// # Why the seam exists at all
///
/// `crate::ffi::SecurityContext` is a concrete type over the real library and
/// is deliberately not substitutable from outside `crate::ffi::gss` -- that
/// module keeps its own provider seam private, which is what lets *it* be
/// tested. This module needs the same freedom one layer up, for two reasons
/// that are not about convenience:
///
/// * The state machine below is the part of Negotiate that has historically
///   gone wrong, and it is entirely independent of any real Kerberos
///   deployment. Testing it against a scripted engine tests the logic; testing
///   it against a KDC tests the network.
/// * `crate::ffi::gss_available()` answers `false` under Miri, which
///   interprets rather than links, so a Miri run cannot reach a real
///   handshake.
pub(crate) trait SpnegoEngine {
    /// Whether a service principal has already been imported.
    ///
    /// C's `if(!nego->spn)` at `lib/vauth/spnego_gssapi.c:104`: the SPN is
    /// built and imported at most once per connection, because the target does
    /// not change across the token exchange.
    fn has_target(&self) -> bool;

    /// `gss_import_name` with `GSS_C_NT_HOSTBASED_SERVICE`, if no target is
    /// held yet.
    ///
    /// `lib/vauth/spnego_gssapi.c:117-127`. The library's own diagnosis
    /// reaches `diagnostics` under the verbatim `"gss_import_name() failed: "`
    /// prefix before the error returns; that prefix lives in
    /// `crate::ffi::gss` (`lib/curl_gssapi.c:387-442` is the assembler behind
    /// it) and is asserted there, so this module must not restate it.
    ///
    /// # Errors
    ///
    /// [`CURLcode::AuthError`], which is `CURLE_AUTH_ERROR` at
    /// `lib/vauth/spnego_gssapi.c:126`.
    fn import_target(
        &mut self,
        spn: &[u8],
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<(), CURLcode>;

    /// One handshake step: `Curl_gss_init_sec_context()`
    /// (`lib/curl_gssapi.c:313-371`) reached through
    /// `lib/vauth/spnego_gssapi.c:162-171`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::AuthError`] when the library reports `GSS_ERROR`, having
    /// first sent the rendered major and minor statuses to `diagnostics` under
    /// the verbatim `"gss_init_sec_context() failed: "` prefix, or
    /// [`CURLcode::OutOfMemory`] if the output token cannot be copied into
    /// owned storage.
    fn step(
        &mut self,
        input_token: Option<&[u8]>,
        delegation: Delegation,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<crate::ffi::HandshakeOutcome, CURLcode>;

    /// Whether the library has handed back a context handle.
    ///
    /// The `nego->context` half of `lib/vauth/spnego_gssapi.c:96` and the
    /// whole of the `if(!neg_ctx->context)` test at
    /// `lib/http_negotiate.c:199`.
    fn context_exists(&self) -> bool;

    /// Whether a handshake completed successfully on this context.
    ///
    /// Both halves of `lib/vauth/spnego_gssapi.c:96`:
    /// `nego->context && nego->status == GSS_S_COMPLETE`.
    fn context_established(&self) -> bool;

    /// The handshake position the most recent step reported, or `None` when
    /// that step failed.
    fn handshake_state(&self) -> Option<HandshakeState>;

    /// Delete the context and the imported name, returning to the
    /// pre-handshake state.
    fn reset(&mut self);
}

/// The production [`SpnegoEngine`]: the real GSS-API library, through
/// `crate::ffi`.
struct SystemSpnego {
    /// C's `gss_ctx_id_t context` together with its `OM_uint32 status`.
    context: SecurityContext,
    /// C's `gss_name_t spn`. `None` is `GSS_C_NO_NAME`.
    target: Option<TargetName>,
}

impl SystemSpnego {
    /// A fresh engine: no context, no imported name.
    ///
    /// Allocates nothing in the library and calls nothing, so constructing one
    /// on a host with no GSS-API implementation is harmless -- which matters,
    /// because [`NegotiateData::default`] builds one before anything has
    /// decided that a Negotiate exchange will happen.
    fn new() -> Self {
        Self {
            context: SecurityContext::new(),
            target: None,
        }
    }
}

impl SpnegoEngine for SystemSpnego {
    fn has_target(&self) -> bool {
        self.target.is_some()
    }

    fn import_target(
        &mut self,
        spn: &[u8],
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<(), CURLcode> {
        // `GSS_C_NT_HOSTBASED_SERVICE` is the name type the `"service@host"`
        // spelling requires -- see the SPN note on
        // `NegotiateData::decode_spnego_message`. C frees the SPN string
        // immediately after the import (`lib/vauth/spnego_gssapi.c:129`); here
        // the caller's `String` is dropped at the end of its scope, and
        // nothing retains a copy.
        self.target = Some(TargetName::import(
            spn,
            crate::ffi::NameType::HostBasedService,
            diagnostics,
        )?);
        Ok(())
    }

    fn step(
        &mut self,
        input_token: Option<&[u8]>,
        delegation: Delegation,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<crate::ffi::HandshakeOutcome, CURLcode> {
        // A step without a target cannot happen: the caller imports one first
        // (`lib/vauth/spnego_gssapi.c:104-130` precedes `:162`). Answering
        // `CURLE_AUTH_ERROR` rather than asserting keeps the function total
        // for a caller that gets the order wrong, and matches the code the
        // library itself would report for an unusable target.
        let target = match self.target.as_ref() {
            Some(target) => target,
            None => return Err(CURLcode::AuthError),
        };

        let options = StepOptions {
            delegation,
            input_token,
            // `channel_binding_data` stays at the `None` that
            // `StepOptions::new` sets: `GSS_C_NO_CHANNEL_BINDINGS`. See the
            // module documentation.
            ..StepOptions::new(target, Mechanism::Spnego)
        };

        self.context.step(&options, diagnostics)
    }

    fn context_exists(&self) -> bool {
        self.context.exists()
    }

    fn context_established(&self) -> bool {
        self.context.is_established()
    }

    fn handshake_state(&self) -> Option<HandshakeState> {
        self.context.status().state()
    }

    fn reset(&mut self) {
        // `gss_delete_sec_context` plus the status reset to `GSS_S_COMPLETE`.
        self.context.reset();
        // `gss_release_name`: the wrapper's `Drop` performs the call, so
        // taking the option out is the release.
        drop(self.target.take());
    }
}

// `struct negotiatedata`.

/// One endpoint's Negotiate state on one connection.
///
/// - `OM_uint32 status` and `gss_ctx_id_t context` -> both owned by the
///   [`SpnegoEngine`], because `crate::ffi::SecurityContext` already carries
///   the status beside the handle. One owner, so they cannot disagree, and
///   `Drop` deletes the context exactly once.
/// - `gss_name_t spn` -> an owning name inside the engine, released by taking
///   it out of its [`Option`].
/// - `gss_buffer_desc output_token` -> [`Self::output_token`], an owned
///   `Vec<u8>`. Length and capacity are the vector's business rather than two
///   fields a caller must keep in step.
/// - `struct dynbuf channel_binding_data` -> omitted; see the module
///   documentation.
pub(crate) struct NegotiateData {
    /// The GSS-API operations, behind the seam that makes them testable.
    engine: Box<dyn SpnegoEngine>,
    /// C's `output_token`: the token to base64-encode into the next
    /// `Authorization:` header. Empty means "nothing to send".
    output_token: Vec<u8>,
    /// C's `BIT(noauthpersist)`: this connection must not keep its
    /// authentication across requests, so the context is torn down and rebuilt
    /// each time (`lib/http_negotiate.c:187`, read at `:191` and `:194`).
    noauthpersist: bool,
    /// C's `BIT(havenoauthpersist)`: [`Self::noauthpersist`] was decided
    /// elsewhere and must not be recomputed (`lib/http_negotiate.c:186`).
    havenoauthpersist: bool,
    /// C's `BIT(havenegdata)`: the challenge just consumed carried a payload.
    ///
    /// Set from the payload length on every input (`:102`) and cleared
    /// unconditionally at the end of every output (`:257`).
    havenegdata: bool,
    /// C's `BIT(havemultiplerequests)`: this server sent more than one
    /// challenge, so authentication does persist (`:182`).
    havemultiplerequests: bool,
}

impl Default for NegotiateData {
    /// The `calloc`ed state of `Curl_auth_nego_get()`
    /// (`lib/vauth/vauth.c:243`): no context, no name, no token, and four
    /// false booleans.
    fn default() -> Self {
        Self {
            engine: Box::new(SystemSpnego::new()),
            output_token: Vec::new(),
            noauthpersist: false,
            havenoauthpersist: false,
            havenegdata: false,
            havemultiplerequests: false,
        }
    }
}

impl fmt::Debug for NegotiateData {
    /// Hand-written, and deliberately not derived.
    ///
    /// Suppressing that would fail those fixtures and is itself a prohibited
    /// behaviour change. The narrower invariant this formatter enforces is the
    /// one that binds: **no secret gains a path to a log that curl does not
    /// already have.**
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NegotiateData")
            .field("context_exists", &self.engine.context_exists())
            .field("context_established", &self.engine.context_established())
            .field("handshake_state", &self.engine.handshake_state())
            .field("output_token_len", &self.output_token.len())
            .field("noauthpersist", &self.noauthpersist)
            .field("havenoauthpersist", &self.havenoauthpersist)
            .field("havenegdata", &self.havenegdata)
            .field("havemultiplerequests", &self.havemultiplerequests)
            .finish()
    }
}

impl NegotiateData {
    /// Clears the SPNEGO-specific state: `Curl_auth_cleanup_spnego()`
    /// (`lib/vauth/spnego_gssapi.c:259-289`).
    ///
    /// The C performs six things in this order, and all six are here:
    ///
    /// 1. `gss_delete_sec_context` when the context is not
    ///    `GSS_C_NO_CONTEXT`, passing `GSS_C_NO_BUFFER` for the output token
    ///    it does not want, then storing the sentinel back (`:263-268`).
    /// 2. `gss_release_buffer` on `output_token` when its value is non-NULL,
    ///    then zeroing both value and length (`:270-275`).
    /// 3. `gss_release_name` when the SPN is not `GSS_C_NO_NAME`, then storing
    ///    the sentinel back (`:277-281`).
    /// 4. `status = 0`, which is `GSS_S_COMPLETE` (`:284`).
    /// 5. and 6. **All four booleans** to `FALSE` (`:285-288`).
    pub(crate) fn cleanup_spnego(&mut self) {
        self.engine.reset();
        self.release_output_token();
        self.noauthpersist = false;
        self.havenoauthpersist = false;
        self.havenegdata = false;
        self.havemultiplerequests = false;
    }

    /// `gss_release_buffer(&minor, &nego->output_token)` followed by
    /// `value = NULL; length = 0`.
    fn release_output_token(&mut self) {
        self.output_token = Vec::new();
    }

    /// Decodes a base64 SPNEGO challenge and produces the response token:
    /// `Curl_auth_decode_spnego_message()`
    /// (`lib/vauth/spnego_gssapi.c:72-201`).
    ///
    /// # Errors
    ///
    /// - [`CURLcode::LoginDenied`] when a context is already established and a
    ///   fresh challenge arrives anyway (`:96-102`).
    /// - [`CURLcode::OutOfMemory`] when the SPN cannot be built, which is
    ///   `!spn` at `:109-110`. Reachable exactly when `host` is `None`, since
    ///   `build_spn` with neither host nor realm has no form to produce.
    /// - [`CURLcode::BadContentEncoding`] for a challenge that is present but
    ///   yields no decoded bytes (`:141-144`), and whatever the base64 decoder
    ///   reports for a malformed one (`:135-137`).
    /// - [`CURLcode::AuthError`] for a failed name import (`:126`), a failed
    ///   handshake step (`:184`), or a step that succeeded while producing an
    ///   absent or zero-length token (`:187-192`).
    fn decode_spnego_message(
        &mut self,
        user: &[u8],
        password: &[u8],
        service: &str,
        host: Option<&str>,
        challenge: &[u8],
        delegation: Delegation,
        tracer: &mut Tracer<'_>,
    ) -> Result<(), CURLcode> {
        // `(void)user; (void)password;` -- see the note above. Binding them
        // here is the Rust spelling of the C's discard and keeps the two
        // parameters from reading as an oversight.
        let _ = (user, password);

        // FIRST, BEFORE ANYTHING ELSE (`:96-102`). C's own justification: "We
        // finished successfully our part of authentication, but server
        // rejected it (since we are again here). Exit with an error since we
        // cannot invent anything better".
        if self.engine.context_established() {
            self.cleanup_spnego();
            return Err(CURLcode::LoginDenied);
        }

        // `if(!nego->spn)` (`:104-130`). Built and imported once per
        // connection.
        if !self.engine.has_target() {
            // The host goes in the REALM slot. This is not a mistake; see the
            // trap note on this function.
            let spn =
                build_spn(service, None, host).ok_or(CURLcode::OutOfMemory)?;
            self.engine.import_target(
                spn.as_bytes(),
                &mut TracerDiagnostics::new(tracer),
            )?;
            // C's `curlx_free(spn)` at `:129`; here the `String` is dropped.
        }

        // `if(chlg64 && *chlg64)` (`:132-149`).
        //
        // THE `'='` CASE IS AN ERROR, NOT A SKIP, and the C is unambiguous
        // about it. `:134` guards only the DECODE: a payload whose first byte
        // is `'='` leaves `chlg` NULL, and control then falls into the
        // `if(!chlg)` test at `:141`, which reports the verbatim message and
        // `CURLE_BAD_CONTENT_ENCODING`. What is "treated as absent" is the
        // decoded BUFFER, not the header payload -- reading it the other way
        // would let a malformed challenge start a fresh handshake as though no
        // challenge had been offered.
        let decoded = if challenge.is_empty() {
            None
        } else {
            let bytes = if challenge.first() == Some(&b'=') {
                None
            } else {
                Some(base64::decode(challenge)?)
            };

            // `if(!chlg)` (`:141-144`). The emptiness test stands in for C's
            // NULL-pointer test: this crate's decoder never returns `Ok` with
            // an empty vector, so an empty result and an absent one are the
            // same condition, and treating them alike keeps the branch
            // reachable and asserted instead of dead.
            match bytes {
                Some(bytes) if !bytes.is_empty() => Some(bytes),
                _ => {
                    infof!(tracer, "{}", EMPTY_CHALLENGE);
                    return Err(CURLcode::BadContentEncoding);
                }
            }
        };

        // `Curl_gss_init_sec_context(...)` (`:162-171`), with mutual
        // authentication requested, the SPNEGO mechanism OID, no channel
        // bindings and no `ret_flags`. The status the library reports is
        // stored by the engine before any error surfaces, exactly as `:176`
        // assigns `nego->status` ahead of its `GSS_ERROR` check, so
        // `handshake_state()` stays readable on the failure path.
        let outcome = self.engine.step(
            decoded.as_deref(),
            delegation,
            &mut TracerDiagnostics::new(tracer),
        )?;
        // C frees the decoded challenge at `:174` once the call has consumed
        // it; here `decoded` is dropped at the end of this function, and the
        // engine copied whatever it needed.

        // `if(!output_token.value || !output_token.length)` (`:187-192`). An
        // empty token is NOT success: there would be nothing to put in the
        // header, and C answers `CURLE_AUTH_ERROR` rather than emitting an
        // empty credential.
        if outcome.token.is_empty() {
            return Err(CURLcode::AuthError);
        }

        // `if(nego->output_token.length && nego->output_token.value)
        //    gss_release_buffer(...)` then `nego->output_token = output_token`
        // (`:194-198`). The previous token is released BEFORE the new one is
        // stored, which `mem::replace` expresses exactly: the field holds the
        // new token and the old one is returned here to be dropped.
        let previous =
            core::mem::replace(&mut self.output_token, outcome.token);
        drop(previous);

        Ok(())
    }

    /// Base64-encodes the pending response token:
    /// `Curl_auth_create_spnego_message()`
    /// (`lib/vauth/spnego_gssapi.c:219-247`).
    ///
    /// Private, like [`Self::decode_spnego_message`], and deliberately so.
    /// `lib/vauth/vauth.h:331-343` declares both `extern` for one caller each,
    /// and that caller is `lib/http_negotiate.c` -- whose successor is this
    /// same file. `Curl_auth_cleanup_spnego` is different --
    /// `lib/vauth/vauth.c:234` calls it from the connection destructor --
    /// which is why [`Self::cleanup_spnego`] is `pub(crate)` while these two
    /// are not.
    ///
    /// # Errors
    ///
    /// Whatever `crate::util::base64::encode` reports (`:230-236`), or
    /// [`CURLcode::RemoteAccessDenied`] when the encoding is empty
    /// (`:238-244`) -- which happens precisely when the token is empty, since
    /// this crate's encoder maps an empty input to an empty output and calls
    /// that success.
    fn create_spnego_message(&mut self) -> Result<String, CURLcode> {
        match base64::encode(&self.output_token) {
            Err(error) => {
                self.release_output_token();
                Err(error)
            }
            // `if(!*outptr || !*outlen)`: one condition here, because an empty
            // `String` is C's NULL pointer and its zero length at once.
            Ok(encoded) if encoded.is_empty() => {
                self.release_output_token();
                Err(CURLcode::RemoteAccessDenied)
            }
            Ok(encoded) => Ok(encoded),
        }
    }
}

// THE DIAGNOSTICS BRIDGE.

/// Routes `crate::ffi::gss`'s messages into this crate's trace machinery.
///
/// C threads a `struct Curl_easy *data` into every GSS helper
/// (`lib/curl_gssapi.c:313`, `:429`) and calls `infof()` on it directly. The
/// Rust session handle belongs to `crate::easy`, and `crate::ffi` must not
/// depend upward on it, so `crate::ffi::gss` inverts the dependency and asks
/// its caller for a sink. This is that sink, and it is what makes a GSS-API
/// failure appear under `--verbose` exactly where and as C's `infof("%s%s",
/// prefix, buf)` (`lib/curl_gssapi.c:440`) puts it.
struct TracerDiagnostics<'a, 'sink> {
    tracer: &'a mut Tracer<'sink>,
}

impl<'a, 'sink> TracerDiagnostics<'a, 'sink> {
    /// Borrows `tracer` for the duration of one GSS call.
    fn new(tracer: &'a mut Tracer<'sink>) -> Self {
        Self { tracer }
    }
}

impl Diagnostics for TracerDiagnostics<'_, '_> {
    fn infof(&mut self, message: &str) {
        // `{}` rather than the message as a format string: the text comes from
        // a GSS-API library and may contain a brace, which a literal-position
        // interpretation would try to expand.
        infof!(self.tracer, "{}", message);
    }
}

// THE PER-CONNECTION STATE, ORIGIN AND PROXY.

/// Both endpoints' Negotiate state for one connection.
///
/// The keys are deliberately not reproduced: `crate::auth::MechanismSlots`
/// exists for exactly this and replaces the `void *` entry value and its cast
/// with a typed field per side, which is the transformation that makes this
/// crate's zero-`unsafe` invariant reachable. It also removes C's
/// `nego_conn_dtor` -- ownership runs the destructor when the connection is
/// dropped.
#[derive(Debug, Default)]
pub(crate) struct ConnectionNegotiate {
    /// C's `conn->http_negotiate_state`.
    origin_state: NegotiateState,
    /// C's `conn->proxy_negotiate_state`.
    proxy_state: NegotiateState,
    /// C's two `struct negotiatedata` metadata entries.
    ///
    /// A `Debug` here is safe: [`NegotiateData`]'s own formatter is
    /// hand-written and reports the token's length rather than its bytes, so
    /// nothing derived from it can print a credential.
    data: MechanismSlots<NegotiateData>,
}

impl ConnectionNegotiate {
    /// A connection on which no Negotiate exchange has begun.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::conn`, not yet landed.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// One endpoint's handshake position.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn state(&self, proxy: bool) -> NegotiateState {
        if proxy {
            self.proxy_state
        } else {
            self.origin_state
        }
    }

    /// Whether an exchange has begun on either endpoint: C's
    /// `(conn->http_negotiate_state != GSS_AUTHNONE) ||
    /// (conn->proxy_negotiate_state != GSS_AUTHNONE)`.
    #[must_use]
    #[allow(dead_code)] // Consumers are `crate::protocols::http1` and `crate::conn`.
    pub(crate) fn is_negotiating(&self) -> bool {
        self.origin_state.is_negotiating() || self.proxy_state.is_negotiating()
    }

    /// Whether either endpoint is waiting to answer a token it has consumed:
    /// C's `state == GSS_AUTHRECV` on either side.
    #[must_use]
    #[allow(dead_code)] // Consumers are `crate::multi` and `crate::protocols::http1`.
    pub(crate) fn is_awaiting_response(&self) -> bool {
        self.origin_state == NegotiateState::AuthRecv
            || self.proxy_state == NegotiateState::AuthRecv
    }

    /// Records that a challenge token was consumed successfully:
    /// `*negstate = GSS_AUTHRECV` (`lib/http.c:897-898`), whose comment is "we
    /// received a GSS auth token and we dealt with it fine".
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn token_received(&mut self, proxy: bool) {
        *self.state_mut(proxy) = NegotiateState::AuthRecv;
    }

    /// Promotes a finished handshake to accepted, once the response says so.
    ///
    /// `lib/http.c:4028-4035`:
    ///
    /// ```text
    /// if((conn->http_negotiate_state == GSS_AUTHDONE) &&
    ///    (data->req.httpcode != 401))
    ///   conn->http_negotiate_state = GSS_AUTHSUCC;
    /// if((conn->proxy_negotiate_state == GSS_AUTHDONE) &&
    ///    (data->req.httpcode != 407))
    ///   conn->proxy_negotiate_state = GSS_AUTHSUCC;
    /// ```
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn settle_after_response(
        &mut self,
        proxy: bool,
        http_code: u32,
    ) -> bool {
        let rejecting = if proxy { 407 } else { 401 };
        let state = self.state_mut(proxy);
        if *state == NegotiateState::AuthDone && http_code != rejecting {
            *state = NegotiateState::AuthSucc;
            return true;
        }
        false
    }

    /// Returns one endpoint to the pre-handshake state:
    /// `http_auth_nego_reset()` (`lib/http_negotiate.c:37-47`).
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn auth_nego_reset(&mut self, proxy: bool) {
        let (state, data) = self.parts(proxy);
        *state = NegotiateState::AuthNone;
        data.cleanup_spnego();
    }

    /// The mutable state field for one endpoint.
    fn state_mut(&mut self, proxy: bool) -> &mut NegotiateState {
        if proxy {
            &mut self.proxy_state
        } else {
            &mut self.origin_state
        }
    }

    /// One endpoint's state field and its data together.
    ///
    /// Both C functions that matter touch both -- `http_auth_nego_reset()`
    /// writes the state and cleans the data, and `Curl_output_negotiate()`
    /// reads the state while updating the booleans -- so handing them out as a
    /// pair is what lets those transcriptions read as the C does. The two
    /// borrows are of disjoint fields, which is why the compiler accepts them
    /// simultaneously.
    fn parts(
        &mut self,
        proxy: bool,
    ) -> (&mut NegotiateState, &mut NegotiateData) {
        let state = if proxy {
            &mut self.proxy_state
        } else {
            &mut self.origin_state
        };
        (state, self.data.get_or_default(proxy))
    }

    /// One endpoint's data, if it has ever been created.
    ///
    /// The read-only counterpart of [`Self::parts`], for a caller that wants
    /// to observe the bookkeeping without bringing an endpoint into existence.
    #[must_use]
    #[allow(dead_code)] // Reached by this file's tests until a driver lands.
    pub(crate) fn data(&self, proxy: bool) -> Option<&NegotiateData> {
        self.data.peek(proxy)
    }
}

// THE ENDPOINT INPUTS.

/// The credentials, service name and host for one endpoint.
///
/// **The credentials are the CONNECTION's, not the transfer's.** See the module
/// documentation: this is the one mechanism in this directory that reads them
/// from there, and it is deliberate.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NegotiateEndpoint<'a> {
    /// The connection-level username and password. Both may be absent, and
    /// both are discarded by the handshake; see the module documentation.
    pub(crate) credentials: &'a Credentials,
    /// `CURLOPT_SERVICE_NAME` or `CURLOPT_PROXY_SERVICE_NAME`. `None` selects
    /// [`DEFAULT_SERVICE_NAME`].
    pub(crate) service: Option<&'a str>,
    /// The hostname the service principal is built for.
    pub(crate) host: Option<&'a str>,
}

impl<'a> NegotiateEndpoint<'a> {
    /// The service name, with C's `"HTTP"` fallback applied.
    #[must_use]
    fn service_name(self) -> &'a str {
        self.service.unwrap_or(DEFAULT_SERVICE_NAME)
    }

    /// The username, with C's "Not set means empty" substitution applied
    /// (`lib/http_negotiate.c:90-92`).
    #[must_use]
    fn user(self) -> &'a [u8] {
        self.credentials.user().unwrap_or(NOT_SET_MEANS_EMPTY)
    }

    /// The password, with the same substitution (`:94-95`).
    #[must_use]
    fn password(self) -> &'a [u8] {
        self.credentials.secret().unwrap_or(NOT_SET_MEANS_EMPTY)
    }
}

/// Both endpoints' inputs, selected by the `proxy` flag every C entry point
/// takes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NegotiateEndpoints<'a> {
    /// The origin server's endpoint.
    pub(crate) origin: NegotiateEndpoint<'a>,
    /// The HTTP proxy's endpoint.
    pub(crate) proxy: NegotiateEndpoint<'a>,
}

impl<'a> NegotiateEndpoints<'a> {
    /// The endpoint for one side: C's `if(proxy) { ... } else { ... }` prelude,
    /// which both `Curl_input_negotiate()` and `Curl_output_negotiate()` open
    /// with.
    #[must_use]
    fn select(self, proxy: bool) -> NegotiateEndpoint<'a> {
        if proxy {
            self.proxy
        } else {
            self.origin
        }
    }
}

// THE HTTP GLUE.

/// The payload of a `Negotiate` challenge: everything after the scheme token
/// and the blanks that follow it.
///
/// `lib/http_negotiate.c:98-101`:
///
/// ```text
/// header += strlen("Negotiate");
/// curlx_str_passblanks(&header);
/// len = strlen(header);
/// ```
fn payload_after_scheme(header: &[u8]) -> &[u8] {
    let after_token = header.get(NEGOTIATE_SCHEME.len()..).unwrap_or(&[]);
    let blanks = after_token
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(after_token.len());
    // `position` bounds the index by the slice length, so this cannot fail;
    // `get` keeps the expression total anyway rather than resting on that.
    after_token.get(blanks..).unwrap_or(&[])
}

/// The Negotiate mechanism, over one connection and one trace sink.
pub(crate) struct Negotiate<'a, 'sink> {
    /// The connection's Negotiate state, both endpoints.
    conn: &'a mut ConnectionNegotiate,
    /// The credentials, service names and hosts.
    endpoints: NegotiateEndpoints<'a>,
    /// `data->set.gssapi_delegation`, the `CURLOPT_GSSAPI_DELEGATION` mask.
    delegation: Delegation,
    /// Where `infof()` goes.
    tracer: &'a mut Tracer<'sink>,
}

impl<'a, 'sink> Negotiate<'a, 'sink> {
    /// A mechanism over one connection.
    ///
    /// `delegation` is `crate::ffi::Delegation::NONE` for the default
    /// `CURLGSSAPI_DELEGATION_NONE`; pass
    /// `crate::ffi::Delegation::from_option_value(value)` to carry the option
    /// through.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn new(
        conn: &'a mut ConnectionNegotiate,
        endpoints: NegotiateEndpoints<'a>,
        delegation: Delegation,
        tracer: &'a mut Tracer<'sink>,
    ) -> Self {
        Self {
            conn,
            endpoints,
            delegation,
            tracer,
        }
    }

    /// Consumes a `Negotiate` challenge: `Curl_input_negotiate()`
    /// (`lib/http_negotiate.c:49-149`).
    ///
    /// # The order of the four steps is the C's, and each one matters
    ///
    /// 1. The payload is isolated ([`payload_after_scheme`]).
    /// 2. `havenegdata` is set from its length **unconditionally**, before any
    ///    branch (`:102`). Missing this is how the persistence bookkeeping in
    ///    [`Self::output_negotiate`] silently stops working, because that is
    ///    the only field carrying "the server spoke again" from one request to
    ///    the next.
    /// 3. The no-payload branches run (`:103-114`), and only the middle one
    ///    returns.
    /// 4. The decode runs -- **including** when there is no payload, which is
    ///    how a pre-emptive `--negotiate` starts a handshake with nothing to
    ///    answer, and how the restart at step 3 immediately begins a fresh one.
    ///
    /// # Errors
    ///
    /// [`CURLcode::LoginDenied`] when the server withdrew the offer mid-exchange
    /// (`:108-113`), or whatever [`NegotiateData::decode_spnego_message`]
    /// reports. Every failure resets the endpoint first (`:145-146`).
    pub(crate) fn input_negotiate(
        &mut self,
        header: &[u8],
        proxy: bool,
    ) -> Result<(), CURLcode> {
        // C's `if(proxy) {...} else {...}` prelude (`:65-84`). The credentials
        // are the CONNECTION's; see the module documentation.
        let endpoint = self.endpoints.select(proxy);
        let user = endpoint.user();
        let password = endpoint.password();
        let service = endpoint.service_name();
        let host = endpoint.host;

        let payload = payload_after_scheme(header);

        // `neg_ctx->havenegdata = len != 0;` (`:102`).
        {
            let (state, data) = self.conn.parts(proxy);
            data.havenegdata = !payload.is_empty();

            // `if(!len)` (`:103-114`).
            if payload.is_empty() {
                match *state {
                    // `:104-107`. Note there is no return: the exchange
                    // restarts, and the decode below begins the new one.
                    NegotiateState::AuthSucc => {
                        infof!(self.tracer, "{}", AUTH_RESTARTED);
                        self.conn.auth_nego_reset(proxy);
                    }
                    // `:108-113`. C's comment: "The server rejected our
                    // authentication and has not supplied any more
                    // negotiation mechanisms".
                    NegotiateState::AuthRecv
                    | NegotiateState::AuthSent
                    | NegotiateState::AuthDone => {
                        self.conn.auth_nego_reset(proxy);
                        return Err(CURLcode::LoginDenied);
                    }
                    // No handshake has begun, so there is nothing to withdraw
                    // and nothing to reset. C reaches the end of the `if` with
                    // neither branch taken; the arm is written out because
                    // `match` is exhaustive and a fall-through would hide it.
                    NegotiateState::AuthNone => {}
                }
            }
        }

        // Channel binding would be fetched here (`:121-135`). It is omitted in
        // full; see the module documentation for why, and note that omitting it
        // is exactly what the C does when `GSS_C_CHANNEL_BOUND_FLAG` is
        // undefined.

        // `Curl_auth_decode_spnego_message(...)` (`:138-139`), then
        // `if(result) http_auth_nego_reset(...)` (`:145-146`).
        let delegation = self.delegation;
        let result = {
            let (_, data) = self.conn.parts(proxy);
            data.decode_spnego_message(
                user,
                password,
                service,
                host,
                payload,
                delegation,
                self.tracer,
            )
        };

        if result.is_err() {
            self.conn.auth_nego_reset(proxy);
        }
        result
    }

    /// Produces this request's `Authorization: Negotiate` line:
    /// `Curl_output_negotiate()` (`lib/http_negotiate.c:151-260`).
    ///
    /// # Errors
    ///
    /// Whatever [`NegotiateData::create_spnego_message`] reports, or whatever
    /// [`Self::input_negotiate`] reports other than [`CURLcode::AuthError`],
    /// which is swallowed -- see below.
    pub(crate) fn output_negotiate(
        &mut self,
        proxy: bool,
    ) -> Result<AuthEmission, CURLcode> {
        // `authp->done = FALSE;` (`:178`) is the FIRST statement, and here it
        // is the initial value of the readiness this function returns. Every
        // path below either leaves it false -- `Continuing` -- or sets it.
        let mut done = false;

        // The persistence bookkeeping (`:180-189`), transcribed in the C's
        // exact shape. The two arms are mutually exclusive on the state, and
        // neither runs for the other three states.
        {
            let (state, data) = self.conn.parts(proxy);
            if *state == NegotiateState::AuthRecv {
                if data.havenegdata {
                    // The server challenged us more than once, so its
                    // authentication does persist across requests.
                    data.havemultiplerequests = true;
                }
            } else if *state == NegotiateState::AuthSucc
                && !data.havenoauthpersist
            {
                data.noauthpersist = !data.havemultiplerequests;
            }
        }

        // The guard (`:191-192`): run the emitter when authentication does not
        // persist, OR when the handshake has not finished. Read AFTER the
        // bookkeeping above, which may just have changed `noauthpersist`.
        let (noauthpersist, state) = {
            let (state, data) = self.conn.parts(proxy);
            (data.noauthpersist, *state)
        };

        let mut emitted: Option<String> = None;

        if noauthpersist || !state.is_settled() {
            // `:194-198`. A connection that must not persist its
            // authentication and has already succeeded starts over.
            if noauthpersist && state == NegotiateState::AuthSucc {
                infof!(self.tracer, "{}", NO_PERSISTENT_AUTH);
                self.conn.auth_nego_reset(proxy);
            }

            // `if(!neg_ctx->context)` (`:199-209`). Read AFTER the reset
            // above, which deletes the context, so a restarted exchange
            // re-enters the input path here.
            let needs_context = {
                let (_, data) = self.conn.parts(proxy);
                !data.engine.context_exists()
            };

            if needs_context {
                // The literal `"Negotiate"` is the header C passes at `:200`:
                // there is no challenge to answer, so the scheme token alone
                // stands in for one and the payload is empty.
                match self.input_negotiate(NEGOTIATE_SCHEME.as_bytes(), proxy) {
                    Ok(()) => {}
                    // C's justification, verbatim: "negotiate auth failed,
                    // let's continue unauthenticated to stay compatible with
                    // the behavior before curl-7_64_0-158-g6c6035532"
                    // (`:201-206`). `CURLE_AUTH_ERROR` -- and only that code
                    // -- is swallowed: `done` is set and `CURLE_OK` returned,
                    // with no header. Note what this skips: the two
                    // statements at the foot of the function (`:251-257`) are
                    // NOT reached on this path in the C either, because it
                    // returns early.
                    Err(CURLcode::AuthError) => {
                        return Ok(AuthEmission::Nothing);
                    }
                    Err(error) => return Err(error),
                }
            }

            // `Curl_auth_create_spnego_message(...)` (`:211-213`), then the
            // header (`:215-216`). `crate::auth::authorization_header` is the
            // shared home of the format shape all five C emitters use, so the
            // bytes cannot drift between mechanisms:
            // `"%sAuthorization: Negotiate %s\r\n"` with `"Proxy-"` or the
            // empty string for the prefix.
            let encoded = {
                let (_, data) = self.conn.parts(proxy);
                data.create_spnego_message()?
            };
            emitted =
                Some(authorization_header(proxy, NEGOTIATE_SCHEME, &encoded));
            // C's `if(!userp) return CURLE_OUT_OF_MEMORY;` at `:231-233`
            // guards the `curl_maprintf` above it.

            // `*state = GSS_AUTHSENT;` then the `HAVE_GSSAPI` upgrade
            // (`:235-240`): `GSS_AUTHDONE` when the status is `GSS_S_COMPLETE`
            // or `GSS_S_CONTINUE_NEEDED`. The `USE_WINDOWS_SSPI` arm at
            // `:242-247` (`SEC_E_OK` / `SEC_I_CONTINUE_NEEDED`) is out of
            // scope.
            let (state, data) = self.conn.parts(proxy);
            *state = NegotiateState::AuthSent;
            match data.engine.handshake_state() {
                Some(HandshakeState::Complete)
                | Some(HandshakeState::ContinueNeeded) => {
                    *state = NegotiateState::AuthDone;
                }
                // `GSS_ERROR(status)`: neither of the C's two equality tests
                // matches, so the state stays `GSS_AUTHSENT`.
                None => {}
            }
        }

        // `:251-255`, with C's comment: "connection is already authenticated,
        // do not send a header in future requests". Outside the guard, so it
        // also fires on the path where no header was produced at all.
        if self.conn.state(proxy).is_settled() {
            done = true;
        }

        // `neg_ctx->havenegdata = FALSE;` (`:257`) -- UNCONDITIONALLY, outside
        // the guard, as the last statement before the return. Easy to miss,
        // and losing it makes `havemultiplerequests` latch on the first
        // challenge and never clear.
        {
            let (_, data) = self.conn.parts(proxy);
            data.havenegdata = false;
        }

        Ok(match (emitted, done) {
            (Some(header), true) => AuthEmission::Final(header),
            (Some(header), false) => AuthEmission::Continuing(header),
            // No header this round. C leaves `aptr.userpwd` untouched and
            // returns `CURLE_OK`; `Nothing` reports `is_done() == true`, which
            // is the same `authp->done` the settled state just produced.
            (None, _) => AuthEmission::Nothing,
        })
    }
}

impl HttpAuthMechanism for Negotiate<'_, '_> {
    fn scheme(&self) -> AuthScheme {
        AuthScheme::Negotiate
    }

    fn input(&mut self, challenge: &[u8], proxy: bool) -> Result<(), CURLcode> {
        self.input_negotiate(challenge, proxy)
    }

    fn output(
        &mut self,
        ctx: &mut AuthContext<'_>,
    ) -> Result<AuthEmission, CURLcode> {
        // `request` and `path` are Digest's alone
        // (`crate::auth::AuthScheme::needs_request_target`), and the clock and
        // the random source are Digest's and NTLM's. Negotiate reads none of
        // them: its token comes from the credentials cache by way of the
        // GSS-API library, so there is nothing here to seed or to time.
        self.output_negotiate(ctx.proxy)
    }
}

impl fmt::Debug for Negotiate<'_, '_> {
    /// Hand-written because [`Tracer`] and the endpoints are borrowed state
    /// whose formatters would each pull in more than is useful, and because a
    /// derived formatter on a type that reaches [`Credentials`] is exactly the
    /// shape that puts a password in a log. The connection state is printed
    /// through [`NegotiateData`]'s own redacting formatter; the endpoints are
    /// reported by *name* only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Negotiate")
            .field("conn", &self.conn)
            .field("origin_host", &self.endpoints.origin.host)
            .field("origin_service", &self.endpoints.origin.service_name())
            .field("proxy_host", &self.endpoints.proxy.host)
            .field("proxy_service", &self.endpoints.proxy.service_name())
            .field("delegation", &self.delegation)
            .finish_non_exhaustive()
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        is_spnego_supported as crate_is_spnego_supported, AuthMask,
        CHALLENGE_ORDER, CURLGSSAPI_DELEGATION_FLAG,
        CURLGSSAPI_DELEGATION_NONE, CURLGSSAPI_DELEGATION_POLICY_FLAG,
        EMISSION_ORDER, PREFERENCE_ORDER,
    };
    use crate::ffi::{ContextFlags, HandshakeOutcome};
    use crate::trace::{TraceConfig, TraceState, WriterSink};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// The password every test uses, so that
    /// [`no_credential_reaches_the_trace_sink`] has one string to hunt for.
    const SECRET: &[u8] = b"s3cr3t-negotiate-password";

    /// One scripted answer from [`FakeSpnego::step`].
    struct StepScript {
        /// The token to hand back, or the failure to report.
        outcome: Result<Vec<u8>, CURLcode>,
        /// What [`SpnegoEngine::handshake_state`] reports afterwards: C's
        /// `nego->status`, assigned at `lib/vauth/spnego_gssapi.c:176` before
        /// the error check and read back at `lib/http_negotiate.c:237-238`.
        reported: Option<HandshakeState>,
        /// A line the real library would have written to the diagnostics sink.
        diagnostic: Option<String>,
    }

    impl StepScript {
        /// A successful step producing `token` and reporting `reported`.
        fn ok(reported: HandshakeState, token: &[u8]) -> Self {
            Self {
                outcome: Ok(token.to_vec()),
                reported: Some(reported),
                diagnostic: None,
            }
        }

        /// A step that fails, with the diagnostic the library would emit.
        fn failing(code: CURLcode, diagnostic: &str) -> Self {
            Self {
                outcome: Err(code),
                reported: None,
                diagnostic: Some(diagnostic.to_owned()),
            }
        }
    }

    /// The scripted behaviour and the recorded observations of a
    /// [`FakeSpnego`], shared with the test through an [`Rc`].
    #[derive(Default)]
    struct Script {
        /// A failure for `import_target` to report.
        import_error: Option<CURLcode>,
        /// Every SPN handed to `import_target`, in order.
        imported: Vec<Vec<u8>>,
        /// The answers `step` gives, consumed front to back.
        steps: VecDeque<StepScript>,
        /// Every input token `step` received; `None` is C's
        /// `GSS_C_EMPTY_BUFFER`.
        inputs: Vec<Option<Vec<u8>>>,
        /// The delegation mask each step received.
        delegations: Vec<Delegation>,
        /// Whether a context handle is held.
        context: bool,
        /// The position the last step reported.
        handshake: Option<HandshakeState>,
        /// How many times `reset` ran.
        resets: usize,
    }

    /// A [`SpnegoEngine`] that answers from a script and records what it saw.
    struct FakeSpnego {
        shared: Rc<RefCell<Script>>,
        target: Option<Vec<u8>>,
    }

    impl FakeSpnego {
        fn new(shared: &Rc<RefCell<Script>>) -> Self {
            Self {
                shared: Rc::clone(shared),
                target: None,
            }
        }
    }

    impl SpnegoEngine for FakeSpnego {
        fn has_target(&self) -> bool {
            self.target.is_some()
        }

        fn import_target(
            &mut self,
            spn: &[u8],
            diagnostics: &mut dyn Diagnostics,
        ) -> Result<(), CURLcode> {
            let mut script = self.shared.borrow_mut();
            script.imported.push(spn.to_vec());
            if let Some(code) = script.import_error {
                // The real wrapper emits the verbatim prefix before returning;
                // reproducing that here is what lets
                // `the_import_diagnostic_reaches_the_trace_sink` prove the
                // sink is wired, without this file restating a literal that
                // `crate::ffi::gss` owns and asserts.
                diagnostics.infof("gss_import_name() failed: scripted");
                return Err(code);
            }
            drop(script);
            self.target = Some(spn.to_vec());
            Ok(())
        }

        fn step(
            &mut self,
            input_token: Option<&[u8]>,
            delegation: Delegation,
            diagnostics: &mut dyn Diagnostics,
        ) -> Result<HandshakeOutcome, CURLcode> {
            let mut script = self.shared.borrow_mut();
            script.inputs.push(input_token.map(<[u8]>::to_vec));
            script.delegations.push(delegation);
            let scripted = script
                .steps
                .pop_front()
                .expect("the test scripted a step for every call");
            script.handshake = scripted.reported;
            // A real library hands back a context even on some failures, and
            // `crate::ffi::SecurityContext` adopts it before the error
            // surfaces, so the fake does the same.
            script.context = true;
            drop(script);

            if let Some(text) = scripted.diagnostic {
                diagnostics.infof(&text);
            }

            match scripted.outcome {
                Ok(token) => Ok(HandshakeOutcome {
                    state: scripted
                        .reported
                        .unwrap_or(HandshakeState::ContinueNeeded),
                    token,
                    flags: ContextFlags::default(),
                }),
                Err(code) => Err(code),
            }
        }

        fn context_exists(&self) -> bool {
            self.shared.borrow().context
        }

        fn context_established(&self) -> bool {
            let script = self.shared.borrow();
            script.context && script.handshake == Some(HandshakeState::Complete)
        }

        fn handshake_state(&self) -> Option<HandshakeState> {
            self.shared.borrow().handshake
        }

        fn reset(&mut self) {
            let mut script = self.shared.borrow_mut();
            script.resets += 1;
            script.context = false;
            // C's `nego->status = 0`, which is `GSS_S_COMPLETE`.
            script.handshake = Some(HandshakeState::Complete);
            drop(script);
            self.target = None;
        }
    }

    /// Installs a scripted engine for one endpoint.
    ///
    /// Reaches the private `data` slot and the private `engine` field
    /// directly, which is what a child test module is for.
    fn install(
        conn: &mut ConnectionNegotiate,
        proxy: bool,
        script: &Rc<RefCell<Script>>,
    ) {
        conn.data.get_or_default(proxy).engine =
            Box::new(FakeSpnego::new(script));
    }

    /// A script that answers `steps` in order, starting from no context.
    fn scripted(steps: Vec<StepScript>) -> Rc<RefCell<Script>> {
        Rc::new(RefCell::new(Script {
            steps: steps.into(),
            // A fresh `negotiatedata` is `calloc`ed, so `status` is 0, which is
            // `GSS_S_COMPLETE`. `context_established()` is still false because
            // its other half, the context handle, is absent.
            handshake: Some(HandshakeState::Complete),
            ..Script::default()
        }))
    }

    /// Runs `body` with a verbose tracer and returns its result together with
    /// everything the sink received, as text.
    ///
    /// `WriterSink::new` rather than a terminal-shaped one, because an
    /// assertion on exact text needs the byte-faithful form.
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

    /// A clock that fails the test if anything reads it.
    ///
    /// `crate::auth::AuthContext` carries an injected clock and an injected
    /// random source because Digest and NTLM need them
    /// (`crate::auth::AuthScheme::needs_request_target` is the related
    /// predicate). Negotiate needs neither: its token comes from the Kerberos
    /// credentials cache by way of the GSS-API library, so there is nothing to
    /// seed and nothing to time. These two types turn that from a claim into an
    /// assertion -- and they are written here rather than borrowed from
    /// `crate::util::timeval` and `crate::crypto::rand` so that this module's
    /// only reason to name either of those paths is the one
    /// `crate::auth::AuthContext`'s own field types force on it.
    #[derive(Debug)]
    struct NeverClock;

    impl crate::util::timeval::Clock for NeverClock {
        fn now(&self) -> crate::util::timeval::CurlTime {
            unreachable!("Negotiate must not read the clock")
        }

        fn epoch_secs(&self) -> i64 {
            unreachable!("Negotiate must not read the clock")
        }
    }

    /// A random source that fails the test if anything draws from it.
    struct NeverRng;

    impl crate::crypto::rand::Rng for NeverRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!("Negotiate must not draw randomness")
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            unreachable!("Negotiate must not draw randomness")
        }
    }

    /// The credentials every endpoint in these tests carries.
    fn credentials() -> Credentials {
        Credentials::new(Some(b"alice"), Some(SECRET))
    }

    /// Both endpoints, pointed at `example.com` and `proxy.example.net`, with
    /// the default `"HTTP"` service on each.
    fn endpoints(creds: &Credentials) -> NegotiateEndpoints<'_> {
        NegotiateEndpoints {
            origin: NegotiateEndpoint {
                credentials: creds,
                service: None,
                host: Some("example.com"),
            },
            proxy: NegotiateEndpoint {
                credentials: creds,
                service: None,
                host: Some("proxy.example.net"),
            },
        }
    }

    /// `Curl_input_negotiate()` over a scripted engine.
    fn run_input(
        conn: &mut ConnectionNegotiate,
        ends: NegotiateEndpoints<'_>,
        header: &[u8],
        proxy: bool,
    ) -> (Result<(), CURLcode>, String) {
        with_tracer(|tracer| {
            Negotiate::new(conn, ends, Delegation::NONE, tracer)
                .input_negotiate(header, proxy)
        })
    }

    /// `Curl_output_negotiate()` over a scripted engine.
    fn run_output(
        conn: &mut ConnectionNegotiate,
        ends: NegotiateEndpoints<'_>,
        proxy: bool,
    ) -> (Result<AuthEmission, CURLcode>, String) {
        run_output_with(conn, ends, proxy, Delegation::NONE)
    }

    /// `Curl_output_negotiate()` with an explicit delegation mask.
    fn run_output_with(
        conn: &mut ConnectionNegotiate,
        ends: NegotiateEndpoints<'_>,
        proxy: bool,
        delegation: Delegation,
    ) -> (Result<AuthEmission, CURLcode>, String) {
        with_tracer(|tracer| {
            Negotiate::new(conn, ends, delegation, tracer)
                .output_negotiate(proxy)
        })
    }

    // Capability advertisement.

    /// The availability predicates agree, and the one that is deliberately
    /// STRICTER says so.
    #[test]
    fn the_three_availability_predicates_agree() {
        let probe = crate::ffi::gss_available();
        assert_eq!(is_spnego_supported(), probe);
        assert_eq!(crate_is_spnego_supported(), probe);
        assert_eq!(
            crate::version::negotiate_usable(),
            crate::version::supports_negotiate() && probe
        );
    }

    /// Repeated calls cannot report different answers: `crate::ffi::gss`
    /// caches the probe, which matters because the banner is assembled more
    /// than once.
    #[test]
    fn availability_is_stable_across_calls() {
        let first = is_spnego_supported();
        for _ in 0..4 {
            assert_eq!(is_spnego_supported(), first);
        }
    }

    // The five states.

    /// The C enumerator spellings, in the C's declaration order
    /// (`lib/urldata.h:312-318`). Literals, not derived.
    #[test]
    fn the_five_states_carry_their_c_names_in_order() {
        let order = [
            NegotiateState::AuthNone,
            NegotiateState::AuthRecv,
            NegotiateState::AuthSent,
            NegotiateState::AuthDone,
            NegotiateState::AuthSucc,
        ];
        let names: Vec<&str> =
            order.iter().map(|state| state.as_c_name()).collect();
        assert_eq!(
            names,
            vec![
                "GSS_AUTHNONE",
                "GSS_AUTHRECV",
                "GSS_AUTHSENT",
                "GSS_AUTHDONE",
                "GSS_AUTHSUCC",
            ]
        );
        // The formatter prints the C spelling, not the Rust variant name.
        assert_eq!(format!("{:?}", NegotiateState::AuthRecv), "GSS_AUTHRECV");
    }

    /// `GSS_AUTHNONE` is the `calloc` default.
    #[test]
    fn the_default_state_is_authnone() {
        assert_eq!(NegotiateState::default(), NegotiateState::AuthNone);
        let conn = ConnectionNegotiate::new();
        assert_eq!(conn.state(false), NegotiateState::AuthNone);
        assert_eq!(conn.state(true), NegotiateState::AuthNone);
        assert!(!conn.is_negotiating());
        assert!(!conn.is_awaiting_response());
        // No endpoint has been mentioned, so no slot exists yet.
        assert!(conn.data(false).is_none());
        assert!(conn.data(true).is_none());
    }

    /// `is_settled` is `*state == GSS_AUTHDONE || *state == GSS_AUTHSUCC`
    /// (`lib/http_negotiate.c:192`, `:251`) and `is_negotiating` is
    /// `!= GSS_AUTHNONE` (`lib/http.c:430-431`, `lib/url.c:1196`).
    #[test]
    fn the_two_state_predicates_match_their_c_conditions() {
        for state in [
            NegotiateState::AuthNone,
            NegotiateState::AuthRecv,
            NegotiateState::AuthSent,
            NegotiateState::AuthDone,
            NegotiateState::AuthSucc,
        ] {
            let settled = matches!(
                state,
                NegotiateState::AuthDone | NegotiateState::AuthSucc
            );
            assert_eq!(state.is_settled(), settled, "{state:?}");
            assert_eq!(
                state.is_negotiating(),
                state != NegotiateState::AuthNone,
                "{state:?}"
            );
        }
    }

    // The service principal name.

    /// THE ARGUMENT-ORDER TRAP, pinned as a string.
    #[test]
    fn the_spn_is_service_at_host_not_service_slash_host() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![StepScript::ok(
            HandshakeState::ContinueNeeded,
            b"token",
        )]);
        install(&mut conn, false, &script);

        let (result, _) = run_input(&mut conn, ends, b"Negotiate", false);
        assert_eq!(result, Ok(()));

        let imported = script.borrow().imported.clone();
        assert_eq!(imported, vec![b"HTTP@example.com".to_vec()]);
        // Emphatically NOT the Digest form, which the same helper's second
        // branch would have produced from `build_spn(service, host, None)`.
        assert_ne!(imported[0], b"HTTP/example.com".to_vec());
    }

    /// The proxy endpoint builds its own SPN from its own host, and
    /// `CURLOPT_PROXY_SERVICE_NAME` overrides the `"HTTP"` default
    /// (`lib/http_negotiate.c:69-71`).
    #[test]
    fn the_proxy_spn_uses_the_proxy_host_and_service() {
        let creds = credentials();
        let mut ends = endpoints(&creds);
        ends.proxy.service = Some("khttp");
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![StepScript::ok(
            HandshakeState::ContinueNeeded,
            b"token",
        )]);
        install(&mut conn, true, &script);

        let (result, _) = run_input(&mut conn, ends, b"Negotiate", true);
        assert_eq!(result, Ok(()));
        assert_eq!(
            script.borrow().imported,
            vec![b"khttp@proxy.example.net".to_vec()]
        );
    }

    /// The SPN is imported once per connection: `if(!nego->spn)`
    /// (`lib/vauth/spnego_gssapi.c:104`).
    #[test]
    fn the_spn_is_imported_once_per_connection() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![
            StepScript::ok(HandshakeState::ContinueNeeded, b"one"),
            StepScript::ok(HandshakeState::ContinueNeeded, b"two"),
        ]);
        install(&mut conn, false, &script);

        assert_eq!(run_input(&mut conn, ends, b"Negotiate", false).0, Ok(()));
        assert_eq!(
            run_input(&mut conn, ends, b"Negotiate YWJjZA==", false).0,
            Ok(())
        );
        assert_eq!(script.borrow().imported.len(), 1);
    }

    /// `if(!spn) return CURLE_OUT_OF_MEMORY;`
    /// (`lib/vauth/spnego_gssapi.c:109-110`), reachable exactly when there is
    /// no host for `build_spn` to place in the realm slot.
    #[test]
    fn a_missing_host_answers_out_of_memory_as_the_c_does() {
        let creds = credentials();
        let mut ends = endpoints(&creds);
        ends.origin.host = None;
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        install(&mut conn, false, &script);

        let (result, _) = run_input(&mut conn, ends, b"Negotiate", false);
        assert_eq!(result, Err(CURLcode::OutOfMemory));
        assert!(script.borrow().imported.is_empty());
        // Every failure resets the endpoint first (`:145-146`).
        assert_eq!(conn.state(false), NegotiateState::AuthNone);
        assert_eq!(script.borrow().resets, 1);
    }

    /// A failed `gss_import_name` is `CURLE_AUTH_ERROR` (`:126`), and the
    /// library's own text reaches `--verbose`.
    ///
    /// The verbatim `"gss_import_name() failed: "` prefix belongs to
    /// `crate::ffi::gss`, which assembles and asserts it; what this file owns
    /// -- and what is checked here -- is that the sink is wired, so whatever
    /// the library says arrives in the trace.
    #[test]
    fn the_import_diagnostic_reaches_the_trace_sink() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        script.borrow_mut().import_error = Some(CURLcode::AuthError);
        install(&mut conn, false, &script);

        let (result, captured) =
            run_input(&mut conn, ends, b"Negotiate", false);
        assert_eq!(result, Err(CURLcode::AuthError));
        assert!(
            captured.contains("gss_import_name() failed: "),
            "the GSS diagnostic must reach the sink: {captured}"
        );
    }

    // Challenge decoding.

    /// The payload walk: `header += strlen("Negotiate")` then
    /// `curlx_str_passblanks` (`lib/http_negotiate.c:98-101`), where blank is
    /// space or tab and nothing else (`lib/curl_ctype.h:45`).
    #[test]
    fn the_payload_starts_after_the_scheme_token_and_its_blanks() {
        assert_eq!(payload_after_scheme(b"Negotiate"), b"");
        assert_eq!(payload_after_scheme(b"Negotiate abc"), b"abc");
        assert_eq!(payload_after_scheme(b"Negotiate\t \tabc"), b"abc");
        assert_eq!(payload_after_scheme(b"Negotiate   "), b"");
        // A CR or an LF is NOT a blank, so it survives the walk.
        assert_eq!(payload_after_scheme(b"Negotiate \r\n"), b"\r\n");
        // Shorter than the token: C's pointer arithmetic would run past the
        // terminator; here the result is empty rather than a panic.
        assert_eq!(payload_after_scheme(b"Neg"), b"");
        assert_eq!(payload_after_scheme(b""), b"");
    }

    /// A base64 challenge is decoded and handed to the step as the input
    /// token; the first step of an exchange has none
    /// (`lib/vauth/spnego_gssapi.c:132-149`, `:168`).
    #[test]
    fn a_challenge_is_decoded_into_the_input_token() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![
            StepScript::ok(HandshakeState::ContinueNeeded, b"first"),
            StepScript::ok(HandshakeState::Complete, b"second"),
        ]);
        install(&mut conn, false, &script);

        // No payload: `GSS_C_EMPTY_BUFFER`, i.e. `None`.
        assert_eq!(run_input(&mut conn, ends, b"Negotiate", false).0, Ok(()));
        // `YWJjZA==` is `abcd`.
        assert_eq!(
            run_input(&mut conn, ends, b"Negotiate YWJjZA==", false).0,
            Ok(())
        );
        assert_eq!(script.borrow().inputs, vec![None, Some(b"abcd".to_vec())]);
    }

    /// An empty decoded challenge is `if(!chlg)`
    /// (`lib/vauth/spnego_gssapi.c:141-144`): the verbatim message, then
    /// `CURLE_BAD_CONTENT_ENCODING`.
    ///
    /// Driven through a payload the decoder rejects outright, which is the
    /// reachable form of "no decoded bytes".
    #[test]
    fn an_undecodable_challenge_answers_bad_content_encoding() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        install(&mut conn, false, &script);

        // Three base64 symbols, so `srclen % 4` is non-zero and the decoder
        // refuses it -- C's `curlx_base64_decode` failure at `:135-137`, whose
        // code the input path propagates unchanged.
        let (result, _) = run_input(&mut conn, ends, b"Negotiate YWJ", false);
        assert_eq!(result, Err(CURLcode::BadContentEncoding));
        // No step was attempted, and the failure reset the endpoint.
        assert!(script.borrow().inputs.is_empty());
        assert_eq!(script.borrow().resets, 1);
    }

    /// A `'='`-LEADING PAYLOAD IS AN ERROR, NOT A SKIP.
    ///
    /// `lib/vauth/spnego_gssapi.c:134` guards only the decode, so a payload
    /// starting with `'='` leaves `chlg` NULL and control falls into
    /// `if(!chlg)` at `:141` -- the verbatim message and
    /// `CURLE_BAD_CONTENT_ENCODING`. What is "treated as absent" is the
    /// decoded BUFFER, not the header payload: no step is attempted, and the
    /// exchange does not restart as though nothing had been offered.
    #[test]
    fn an_equals_leading_payload_is_treated_as_an_absent_decode() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        install(&mut conn, false, &script);

        let (result, captured) =
            run_input(&mut conn, ends, b"Negotiate =YWJjZA==", false);
        assert_eq!(result, Err(CURLcode::BadContentEncoding));
        assert!(
            captured.contains(EMPTY_CHALLENGE),
            "the verbatim message must reach the sink: {captured}"
        );
        assert_eq!(
            EMPTY_CHALLENGE,
            "SPNEGO handshake failure (empty challenge message)"
        );
        // No handshake step was attempted, and the SPN import that preceded
        // the decode was rolled back by the reset.
        assert!(script.borrow().steps.is_empty());
        assert_eq!(script.borrow().resets, 1);
    }

    /// `if(nego->context && nego->status == GSS_S_COMPLETE)`
    /// (`lib/vauth/spnego_gssapi.c:96-102`). C's justification: "We finished
    /// successfully our part of authentication, but server rejected it (since
    /// we are again here). Exit with an error since we cannot invent anything
    /// better".
    #[test]
    fn an_already_established_context_answers_login_denied_and_cleans_up() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script =
            scripted(vec![StepScript::ok(HandshakeState::Complete, b"token")]);
        install(&mut conn, false, &script);

        // One successful round establishes the context with a COMPLETE status.
        assert_eq!(run_input(&mut conn, ends, b"Negotiate", false).0, Ok(()));
        assert!(conn
            .data(false)
            .expect("the endpoint exists")
            .engine
            .context_established());

        // A second challenge on the same established context is the rejection.
        let (result, _) =
            run_input(&mut conn, ends, b"Negotiate YWJjZA==", false);
        assert_eq!(result, Err(CURLcode::LoginDenied));
        // Cleaned up: once by the first-check cleanup, once by the reset the
        // input path performs on any failure.
        assert_eq!(script.borrow().resets, 2);
        assert!(!script.borrow().context);
        assert_eq!(conn.state(false), NegotiateState::AuthNone);
    }

    /// A failed step is `CURLE_AUTH_ERROR` (`:177-185`) and the library's text
    /// reaches `--verbose`.
    #[test]
    fn a_failed_step_answers_auth_error_and_traces_the_library_text() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![StepScript::failing(
            CURLcode::AuthError,
            "gss_init_sec_context() failed: No credentials cache found. ",
        )]);
        install(&mut conn, false, &script);

        let (result, captured) =
            run_input(&mut conn, ends, b"Negotiate", false);
        assert_eq!(result, Err(CURLcode::AuthError));
        assert!(
            captured.contains("gss_init_sec_context() failed: "),
            "the GSS diagnostic must reach the sink: {captured}"
        );
        assert_eq!(script.borrow().resets, 1);
    }

    /// `if(!output_token.value || !output_token.length)`
    /// (`lib/vauth/spnego_gssapi.c:187-192`): a step that SUCCEEDS while
    /// producing nothing is still `CURLE_AUTH_ERROR`. An empty token is not
    /// success, because there would be no credential to put in the header.
    #[test]
    fn a_zero_length_output_token_answers_auth_error() {
        for reported in
            [HandshakeState::Complete, HandshakeState::ContinueNeeded]
        {
            let creds = credentials();
            let ends = endpoints(&creds);
            let mut conn = ConnectionNegotiate::new();
            let script = scripted(vec![StepScript::ok(reported, b"")]);
            install(&mut conn, false, &script);

            let (result, _) = run_input(&mut conn, ends, b"Negotiate", false);
            assert_eq!(
                result,
                Err(CURLcode::AuthError),
                "an empty token must not be accepted for {reported:?}"
            );
        }
    }

    /// The previous token is released BEFORE the new one is stored
    /// (`:194-198`), so the second round's header carries the second token and
    /// nothing of the first.
    #[test]
    fn a_second_round_replaces_the_stored_token() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![
            StepScript::ok(HandshakeState::ContinueNeeded, b"first"),
            StepScript::ok(HandshakeState::ContinueNeeded, b"second"),
        ]);
        install(&mut conn, false, &script);

        assert_eq!(run_input(&mut conn, ends, b"Negotiate", false).0, Ok(()));
        assert_eq!(
            conn.data(false).expect("exists").output_token,
            b"first".to_vec()
        );
        assert_eq!(
            run_input(&mut conn, ends, b"Negotiate YWJjZA==", false).0,
            Ok(())
        );
        assert_eq!(
            conn.data(false).expect("exists").output_token,
            b"second".to_vec()
        );
    }

    /// The username and password are accepted and discarded
    /// (`lib/vauth/spnego_gssapi.c:93-94`), so an exchange with neither is a
    /// working configuration -- the identity comes from the credentials cache.
    #[test]
    fn an_absent_username_and_password_still_authenticate() {
        let creds = Credentials::none();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script =
            scripted(vec![StepScript::ok(HandshakeState::Complete, b"token")]);
        install(&mut conn, false, &script);

        assert_eq!(run_input(&mut conn, ends, b"Negotiate", false).0, Ok(()));
        assert_eq!(
            script.borrow().imported,
            vec![b"HTTP@example.com".to_vec()]
        );
        // "Not set means empty" (`lib/http_negotiate.c:90-95`).
        assert_eq!(ends.origin.user(), b"");
        assert_eq!(ends.origin.password(), b"");
    }

    // The three no-payload branches, `lib/http_negotiate.c:103-114`.

    /// `havenegdata = len != 0` is set from the payload length
    /// UNCONDITIONALLY, before any branch (`:102`).
    #[test]
    fn havenegdata_is_set_from_the_payload_length() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![
            StepScript::ok(HandshakeState::ContinueNeeded, b"a"),
            StepScript::ok(HandshakeState::ContinueNeeded, b"b"),
        ]);
        install(&mut conn, false, &script);

        assert_eq!(run_input(&mut conn, ends, b"Negotiate", false).0, Ok(()));
        assert!(!conn.data(false).expect("exists").havenegdata);

        assert_eq!(
            run_input(&mut conn, ends, b"Negotiate YWJjZA==", false).0,
            Ok(())
        );
        assert!(conn.data(false).expect("exists").havenegdata);
    }

    /// From `GSS_AUTHSUCC` a payload-less challenge RESTARTS the exchange
    /// (`:104-107`): the verbatim message, a reset, and then -- crucially, with
    /// no `return` in the C -- a fresh handshake begins immediately.
    #[test]
    fn no_payload_from_authsucc_restarts_the_exchange() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![StepScript::ok(
            HandshakeState::ContinueNeeded,
            b"restarted",
        )]);
        install(&mut conn, false, &script);
        // Place the endpoint in `GSS_AUTHSUCC`, which only the response path
        // can reach in production.
        *conn.state_mut(false) = NegotiateState::AuthSucc;

        let (result, captured) =
            run_input(&mut conn, ends, b"Negotiate", false);
        assert_eq!(result, Ok(()));
        assert!(
            captured.contains(AUTH_RESTARTED),
            "the verbatim message must reach the sink: {captured}"
        );
        assert_eq!(AUTH_RESTARTED, "Negotiate auth restarted");
        assert_eq!(script.borrow().resets, 1);
        // The reset returned the state to `GSS_AUTHNONE` and the fresh
        // handshake then ran: one step consumed, one token stored.
        assert_eq!(conn.state(false), NegotiateState::AuthNone);
        assert!(script.borrow().steps.is_empty());
        assert_eq!(
            conn.data(false).expect("exists").output_token,
            b"restarted".to_vec()
        );
    }

    /// From any state other than `GSS_AUTHNONE` and `GSS_AUTHSUCC`, a
    /// payload-less challenge is the server withdrawing the offer
    /// (`:108-113`): reset, then `CURLE_LOGIN_DENIED`. C's comment is "The
    /// server rejected our authentication and has not supplied any more
    /// negotiation mechanisms".
    #[test]
    fn no_payload_from_a_mid_handshake_state_answers_login_denied() {
        for state in [
            NegotiateState::AuthRecv,
            NegotiateState::AuthSent,
            NegotiateState::AuthDone,
        ] {
            let creds = credentials();
            let ends = endpoints(&creds);
            let mut conn = ConnectionNegotiate::new();
            let script = scripted(Vec::new());
            install(&mut conn, false, &script);
            *conn.state_mut(false) = state;

            let (result, _) = run_input(&mut conn, ends, b"Negotiate", false);
            assert_eq!(
                result,
                Err(CURLcode::LoginDenied),
                "withdrawal from {state:?}"
            );
            assert_eq!(conn.state(false), NegotiateState::AuthNone);
            assert_eq!(script.borrow().resets, 1);
            // It returned before any handshake step: no script was needed.
            assert!(script.borrow().inputs.is_empty());
        }
    }

    /// From `GSS_AUTHNONE` a payload-less challenge does nothing special
    /// (`:103-114` falls through both arms) and the decode below it starts the
    /// handshake -- which is how a pre-emptive `--negotiate` gets going with
    /// nothing to answer.
    #[test]
    fn no_payload_from_authnone_starts_the_handshake() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![StepScript::ok(
            HandshakeState::ContinueNeeded,
            b"opening",
        )]);
        install(&mut conn, false, &script);

        let (result, captured) =
            run_input(&mut conn, ends, b"Negotiate", false);
        assert_eq!(result, Ok(()));
        // Neither of the other two arms ran.
        assert!(!captured.contains(AUTH_RESTARTED));
        assert_eq!(script.borrow().resets, 0);
        // The handshake did start, with `GSS_C_EMPTY_BUFFER` for its input.
        assert_eq!(script.borrow().inputs, vec![None]);
        assert_eq!(
            conn.data(false).expect("exists").output_token,
            b"opening".to_vec()
        );
    }

    // Cleanup and reset.

    /// `Curl_auth_cleanup_spnego()` (`lib/vauth/spnego_gssapi.c:259-289`)
    /// clears the context, the name, the token, the status AND **all four**
    /// booleans. The four are easy to lose in a refactor, so each is asserted
    /// by name.
    #[test]
    fn cleanup_resets_all_four_booleans_and_the_status() {
        let script = scripted(Vec::new());
        let mut data = NegotiateData {
            engine: Box::new(FakeSpnego::new(&script)),
            output_token: b"a token".to_vec(),
            noauthpersist: true,
            havenoauthpersist: true,
            havenegdata: true,
            havemultiplerequests: true,
        };
        script.borrow_mut().context = true;
        script.borrow_mut().handshake = None;

        data.cleanup_spnego();

        assert!(data.output_token.is_empty());
        assert!(!data.noauthpersist);
        assert!(!data.havenoauthpersist);
        assert!(!data.havenegdata);
        assert!(!data.havemultiplerequests);
        // The engine deleted its context and its name, and the status returned
        // to `GSS_S_COMPLETE`, which is C's `nego->status = 0`.
        assert_eq!(script.borrow().resets, 1);
        assert!(!script.borrow().context);
        assert_eq!(script.borrow().handshake, Some(HandshakeState::Complete));
        assert!(!data.engine.has_target());
        // Idempotent, exactly as C's guarded frees are.
        data.cleanup_spnego();
        assert_eq!(script.borrow().resets, 2);
    }

    /// `http_auth_nego_reset()` (`lib/http_negotiate.c:37-47`) writes the
    /// endpoint's state field AND cleans its data, and touches only that
    /// endpoint.
    #[test]
    fn auth_nego_reset_clears_one_endpoint_only() {
        let origin = scripted(Vec::new());
        let proxy = scripted(Vec::new());
        let mut conn = ConnectionNegotiate::new();
        install(&mut conn, false, &origin);
        install(&mut conn, true, &proxy);
        *conn.state_mut(false) = NegotiateState::AuthDone;
        *conn.state_mut(true) = NegotiateState::AuthDone;
        conn.data.get_or_default(true).havemultiplerequests = true;

        conn.auth_nego_reset(false);

        assert_eq!(conn.state(false), NegotiateState::AuthNone);
        assert_eq!(conn.state(true), NegotiateState::AuthDone);
        assert_eq!(origin.borrow().resets, 1);
        assert_eq!(proxy.borrow().resets, 0);
        assert!(conn.data(true).expect("exists").havemultiplerequests);
    }

    /// The two externally driven transitions: `*negstate = GSS_AUTHRECV`
    /// (`lib/http.c:897-898`) and the `GSS_AUTHDONE` to `GSS_AUTHSUCC`
    /// promotion (`lib/http.c:4028-4035`), whose rejecting status is 401 for
    /// the origin and 407 for a proxy.
    #[test]
    fn the_externally_driven_transitions_follow_their_c_conditions() {
        let mut conn = ConnectionNegotiate::new();

        conn.token_received(false);
        assert_eq!(conn.state(false), NegotiateState::AuthRecv);
        assert_eq!(conn.state(true), NegotiateState::AuthNone);
        assert!(conn.is_awaiting_response());
        assert!(conn.is_negotiating());

        // A promotion needs `GSS_AUTHDONE`; from any other state nothing
        // happens.
        assert!(!conn.settle_after_response(false, 200));
        assert_eq!(conn.state(false), NegotiateState::AuthRecv);

        *conn.state_mut(false) = NegotiateState::AuthDone;
        // 401 is the origin's rejection, so no promotion.
        assert!(!conn.settle_after_response(false, 401));
        assert_eq!(conn.state(false), NegotiateState::AuthDone);
        // 407 is the PROXY's rejection and means nothing to the origin.
        assert!(conn.settle_after_response(false, 407));
        assert_eq!(conn.state(false), NegotiateState::AuthSucc);

        *conn.state_mut(true) = NegotiateState::AuthDone;
        assert!(!conn.settle_after_response(true, 407));
        assert_eq!(conn.state(true), NegotiateState::AuthDone);
        assert!(conn.settle_after_response(true, 401));
        assert_eq!(conn.state(true), NegotiateState::AuthSucc);
    }

    // Token creation.

    /// `Curl_auth_create_spnego_message()`
    /// (`lib/vauth/spnego_gssapi.c:219-247`) base64-encodes the stored token,
    /// and an empty encoding is `CURLE_REMOTE_ACCESS_DENIED` with the token
    /// released.
    #[test]
    fn create_spnego_message_encodes_or_denies() {
        let script = scripted(Vec::new());
        let mut data = NegotiateData {
            engine: Box::new(FakeSpnego::new(&script)),
            ..NegotiateData::default()
        };

        // An empty token encodes to an empty string, which C reports as
        // `!*outlen` at `:238`.
        assert_eq!(
            data.create_spnego_message(),
            Err(CURLcode::RemoteAccessDenied)
        );
        assert!(data.output_token.is_empty());

        // `abcd` is `YWJjZA==`; a literal, not a round trip through the
        // encoder under test.
        data.output_token = b"abcd".to_vec();
        assert_eq!(data.create_spnego_message(), Ok("YWJjZA==".to_owned()));
        // Success leaves the token in place: C only releases it on failure.
        assert_eq!(data.output_token, b"abcd".to_vec());
    }

    // `Curl_output_negotiate()`, `lib/http_negotiate.c:151-260`.

    /// THE EMITTED HEADER IS BYTE-EXACT, for both endpoints.
    #[test]
    fn the_emitted_header_is_byte_exact_for_both_endpoints() {
        for (proxy, expected) in [
            (false, "Authorization: Negotiate YWJjZA==\r\n"),
            (true, "Proxy-Authorization: Negotiate YWJjZA==\r\n"),
        ] {
            let creds = credentials();
            let ends = endpoints(&creds);
            let mut conn = ConnectionNegotiate::new();
            let script = scripted(vec![StepScript::ok(
                HandshakeState::ContinueNeeded,
                b"abcd",
            )]);
            install(&mut conn, proxy, &script);

            let (result, _) = run_output(&mut conn, ends, proxy);
            // `*state` reached `GSS_AUTHDONE`, so `authp->done` is true and the
            // emission is `Final`.
            assert_eq!(
                result,
                Ok(AuthEmission::Final(expected.to_owned())),
                "proxy = {proxy}"
            );
        }
    }

    /// The full multi-round-trip walk, with every documented transition.
    #[test]
    fn the_state_machine_walks_none_recv_done_succ() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![
            StepScript::ok(HandshakeState::ContinueNeeded, b"one"),
            StepScript::ok(HandshakeState::Complete, b"two"),
        ]);
        install(&mut conn, false, &script);

        // Round one: pre-emptive, from `GSS_AUTHNONE`. No context, so the
        // output path re-enters the input path with the bare `"Negotiate"`.
        assert_eq!(conn.state(false), NegotiateState::AuthNone);
        let (first, _) = run_output(&mut conn, ends, false);
        assert_eq!(
            first,
            Ok(AuthEmission::Final(
                "Authorization: Negotiate b25l\r\n".to_owned()
            ))
        );
        assert_eq!(conn.state(false), NegotiateState::AuthDone);
        assert_eq!(script.borrow().inputs, vec![None]);

        // The server answers 401 with a challenge; the scan consumes it and the
        // driver applies `GSS_AUTHRECV`.
        assert!(!conn.settle_after_response(false, 401));
        let (consumed, _) =
            run_input(&mut conn, ends, b"Negotiate YWJjZA==", false);
        assert_eq!(consumed, Ok(()));
        conn.token_received(false);
        assert_eq!(conn.state(false), NegotiateState::AuthRecv);
        assert!(conn.data(false).expect("exists").havenegdata);

        // Round two: from `GSS_AUTHRECV`, with a context already in place, so
        // the input path is NOT re-entered and the stored token is encoded.
        let (second, _) = run_output(&mut conn, ends, false);
        assert_eq!(
            second,
            Ok(AuthEmission::Final(
                "Authorization: Negotiate dHdv\r\n".to_owned()
            ))
        );
        assert_eq!(conn.state(false), NegotiateState::AuthDone);
        // The challenge carried data, so authentication persists.
        assert!(conn.data(false).expect("exists").havemultiplerequests);
        assert_eq!(script.borrow().inputs.len(), 2);

        // The server answers 200: the handshake is accepted.
        assert!(conn.settle_after_response(false, 200));
        assert_eq!(conn.state(false), NegotiateState::AuthSucc);

        // Round three: settled and persistent, so no header at all.
        let (third, _) = run_output(&mut conn, ends, false);
        assert_eq!(third, Ok(AuthEmission::Nothing));
        assert!(third.expect("ok").is_done());
        assert!(!conn.data(false).expect("exists").noauthpersist);
        assert_eq!(conn.state(false), NegotiateState::AuthSucc);
    }

    /// A single-round Kerberos exchange: one token, a 200, and nothing more.
    ///
    /// The common production shape, and the one that proves `authp->done` is
    /// true on the FIRST header -- `*state` becomes `GSS_AUTHDONE` at `:239`
    /// and `:251-255` then sets `done`.
    #[test]
    fn a_single_round_exchange_is_final_on_its_first_header() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script =
            scripted(vec![StepScript::ok(HandshakeState::Complete, b"abcd")]);
        install(&mut conn, false, &script);

        let (result, _) = run_output(&mut conn, ends, false);
        let emission = result.expect("the exchange succeeds");
        assert!(emission.is_done());
        assert_eq!(
            emission.header(),
            Some("Authorization: Negotiate YWJjZA==\r\n")
        );

        assert!(conn.settle_after_response(false, 200));
        assert_eq!(conn.state(false), NegotiateState::AuthSucc);
    }

    /// The `GSS_AUTHSENT` branch, reachable only through the seam.
    #[test]
    fn a_step_with_an_unreadable_status_leaves_the_state_at_authsent() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = Rc::new(RefCell::new(Script {
            steps: vec![StepScript {
                outcome: Ok(b"abcd".to_vec()),
                reported: None,
                diagnostic: None,
            }]
            .into(),
            handshake: Some(HandshakeState::Complete),
            ..Script::default()
        }));
        install(&mut conn, false, &script);

        let (result, _) = run_output(&mut conn, ends, false);
        assert_eq!(
            result,
            Ok(AuthEmission::Continuing(
                "Authorization: Negotiate YWJjZA==\r\n".to_owned()
            ))
        );
        assert_eq!(conn.state(false), NegotiateState::AuthSent);
        assert!(!conn.state(false).is_settled());
    }

    /// `CURLE_AUTH_ERROR` FROM THE RE-ENTERED INPUT PATH IS SWALLOWED.
    ///
    /// `:199-208`, with C's justification verbatim: "negotiate auth failed,
    /// let's continue unauthenticated to stay compatible with the behavior
    /// before curl-7_64_0-158-g6c6035532". `authp->done` is set and `CURLE_OK`
    /// returned, with no header -- which is [`AuthEmission::Nothing`], whose
    /// `is_done()` is true.
    #[test]
    fn auth_error_from_the_re_entered_input_path_is_swallowed() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![StepScript::failing(
            CURLcode::AuthError,
            "gss_init_sec_context() failed: No credentials cache found. ",
        )]);
        install(&mut conn, false, &script);

        let (result, captured) = run_output(&mut conn, ends, false);
        let emission = result.expect("the AUTH_ERROR must not escape");
        assert_eq!(emission, AuthEmission::Nothing);
        assert!(emission.is_done(), "authp->done must be TRUE");
        assert!(emission.header().is_none());
        // The library's own diagnosis still reaches the user.
        assert!(captured.contains("gss_init_sec_context() failed: "));
    }

    /// Every OTHER error from the re-entered input path propagates
    /// (`:207-208`). `CURLE_AUTH_ERROR` is the only swallowed code.
    #[test]
    fn other_errors_from_the_re_entered_input_path_propagate() {
        let creds = credentials();
        let mut ends = endpoints(&creds);
        // No host, so the SPN cannot be built: `CURLE_OUT_OF_MEMORY`.
        ends.origin.host = None;
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        install(&mut conn, false, &script);

        let (result, _) = run_output(&mut conn, ends, false);
        assert_eq!(result, Err(CURLcode::OutOfMemory));
    }

    /// A challenge the server withdrew mid-handshake propagates
    /// `CURLE_LOGIN_DENIED` out of the output path too, because the re-entered
    /// input call raises it and only `CURLE_AUTH_ERROR` is swallowed.
    #[test]
    fn a_withdrawn_offer_propagates_login_denied_through_the_output_path() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        install(&mut conn, false, &script);
        // `GSS_AUTHSENT` with no context: the guard is entered, the context is
        // absent, and the re-entered input path finds a mid-handshake state
        // with no payload.
        *conn.state_mut(false) = NegotiateState::AuthSent;

        let (result, _) = run_output(&mut conn, ends, false);
        assert_eq!(result, Err(CURLcode::LoginDenied));
    }

    /// THE PERSISTENCE BOOKKEEPING, `:180-189`, both arms.
    #[test]
    fn the_persistence_bookkeeping_follows_the_c_exactly() {
        // Arm one: `GSS_AUTHRECV` with `havenegdata` sets
        // `havemultiplerequests`.
        for havenegdata in [false, true] {
            let creds = credentials();
            let ends = endpoints(&creds);
            let mut conn = ConnectionNegotiate::new();
            let script = scripted(Vec::new());
            script.borrow_mut().context = true;
            install(&mut conn, false, &script);
            *conn.state_mut(false) = NegotiateState::AuthRecv;
            conn.data.get_or_default(false).havenegdata = havenegdata;
            conn.data.get_or_default(false).output_token = b"abcd".to_vec();

            let (result, _) = run_output(&mut conn, ends, false);
            assert_eq!(
                result,
                Ok(AuthEmission::Final(
                    "Authorization: Negotiate YWJjZA==\r\n".to_owned()
                )),
                "havenegdata = {havenegdata}"
            );
            assert_eq!(
                conn.data(false).expect("exists").havemultiplerequests,
                havenegdata,
                "havenegdata = {havenegdata}"
            );
        }

        // Arm two: `GSS_AUTHSUCC` without `havenoauthpersist` computes
        // `noauthpersist = !havemultiplerequests`.
        for multiple in [false, true] {
            let creds = credentials();
            let ends = endpoints(&creds);
            let mut conn = ConnectionNegotiate::new();
            let script = scripted(vec![StepScript::ok(
                HandshakeState::Complete,
                b"abcd",
            )]);
            install(&mut conn, false, &script);
            *conn.state_mut(false) = NegotiateState::AuthSucc;
            conn.data.get_or_default(false).havemultiplerequests = multiple;

            let (result, _) = run_output(&mut conn, ends, false);
            assert!(result.is_ok());
            // When `noauthpersist` becomes true the context is torn down and
            // rebuilt, and the cleanup clears both booleans -- so the observable
            // consequence is the reset, not the flag.
            assert_eq!(script.borrow().resets > 0, !multiple);
        }

        // Arm two, suppressed: `havenoauthpersist` means the decision was made
        // elsewhere and must not be recomputed, so no teardown happens.
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        install(&mut conn, false, &script);
        *conn.state_mut(false) = NegotiateState::AuthSucc;
        conn.data.get_or_default(false).havenoauthpersist = true;

        let (result, _) = run_output(&mut conn, ends, false);
        assert_eq!(result, Ok(AuthEmission::Nothing));
        assert!(!conn.data(false).expect("exists").noauthpersist);
        assert_eq!(script.borrow().resets, 0);
    }

    /// `if(neg_ctx->noauthpersist && *state == GSS_AUTHSUCC)`
    /// (`:194-198`): the verbatim two-line message, joined precisely, then a
    /// teardown and a fresh handshake.
    #[test]
    fn a_non_persistent_connection_tears_down_and_says_so() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script =
            scripted(vec![StepScript::ok(HandshakeState::Complete, b"abcd")]);
        install(&mut conn, false, &script);
        *conn.state_mut(false) = NegotiateState::AuthSucc;
        // `havemultiplerequests` false, so the bookkeeping computes
        // `noauthpersist = true` and the teardown arm fires.

        let (result, captured) = run_output(&mut conn, ends, false);
        assert_eq!(
            result,
            Ok(AuthEmission::Final(
                "Authorization: Negotiate YWJjZA==\r\n".to_owned()
            ))
        );
        assert!(
            captured.contains(NO_PERSISTENT_AUTH),
            "the verbatim message must reach the sink: {captured}"
        );
        // The concatenation of the C's two source lines: one space after the
        // comma, one space after the colon, and nothing else.
        assert_eq!(
            NO_PERSISTENT_AUTH,
            "Curl_output_negotiate, no persistent authentication: cleanup \
             existing context"
        );
        assert_eq!(script.borrow().resets, 1);
    }

    /// `neg_ctx->havenegdata = FALSE;` (`:257`) -- UNCONDITIONALLY, on every
    /// path that returns from the output function.
    #[test]
    fn havenegdata_is_cleared_on_every_output_path() {
        // Exit one: a header was emitted. `GSS_AUTHRECV` with a context and a
        // stored token is the production second-round shape.
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        script.borrow_mut().context = true;
        install(&mut conn, false, &script);
        *conn.state_mut(false) = NegotiateState::AuthRecv;
        conn.data.get_or_default(false).havenegdata = true;
        conn.data.get_or_default(false).output_token = b"abcd".to_vec();
        assert!(run_output(&mut conn, ends, false).0.is_ok());
        assert!(!conn.data(false).expect("exists").havenegdata);

        // Exit two: settled and persistent, so no header at all.
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        install(&mut conn, false, &script);
        *conn.state_mut(false) = NegotiateState::AuthSucc;
        conn.data.get_or_default(false).havenoauthpersist = true;
        conn.data.get_or_default(false).havenegdata = true;
        assert_eq!(
            run_output(&mut conn, ends, false).0,
            Ok(AuthEmission::Nothing)
        );
        assert!(!conn.data(false).expect("exists").havenegdata);

        // Exit three: the swallowed `CURLE_AUTH_ERROR`. C returns early at
        // `:205`, so `:257` is NOT reached -- but the reset the input path
        // performed on the failure cleared the flag already, which is why the
        // early return is harmless. Asserting the outcome rather than the
        // mechanism is what keeps this honest.
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![StepScript::failing(
            CURLcode::AuthError,
            "gss_init_sec_context() failed: scripted",
        )]);
        install(&mut conn, false, &script);
        conn.data.get_or_default(false).havenegdata = true;
        assert_eq!(
            run_output(&mut conn, ends, false).0,
            Ok(AuthEmission::Nothing)
        );
        assert!(!conn.data(false).expect("exists").havenegdata);

        // Exit four: a propagated error, cleared by the same reset.
        let mut no_host = endpoints(&creds);
        no_host.origin.host = None;
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        install(&mut conn, false, &script);
        conn.data.get_or_default(false).havenegdata = true;
        assert_eq!(
            run_output(&mut conn, no_host, false).0,
            Err(CURLcode::OutOfMemory)
        );
        assert!(!conn.data(false).expect("exists").havenegdata);
    }

    /// The two endpoints are independent: a proxy exchange leaves the origin
    /// untouched and vice versa.
    #[test]
    fn the_two_endpoints_do_not_interfere() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let origin =
            scripted(vec![StepScript::ok(HandshakeState::Complete, b"origin")]);
        let proxy =
            scripted(vec![StepScript::ok(HandshakeState::Complete, b"proxy")]);
        let mut conn = ConnectionNegotiate::new();
        install(&mut conn, false, &origin);
        install(&mut conn, true, &proxy);

        assert_eq!(
            run_output(&mut conn, ends, true).0,
            Ok(AuthEmission::Final(
                "Proxy-Authorization: Negotiate cHJveHk=\r\n".to_owned()
            ))
        );
        assert_eq!(conn.state(true), NegotiateState::AuthDone);
        assert_eq!(conn.state(false), NegotiateState::AuthNone);
        assert!(origin.borrow().inputs.is_empty());

        assert_eq!(
            run_output(&mut conn, ends, false).0,
            Ok(AuthEmission::Final(
                "Authorization: Negotiate b3JpZ2lu\r\n".to_owned()
            ))
        );
        assert_eq!(conn.state(false), NegotiateState::AuthDone);
        assert_eq!(conn.state(true), NegotiateState::AuthDone);
        assert_eq!(
            origin.borrow().imported,
            vec![b"HTTP@example.com".to_vec()]
        );
        assert_eq!(
            proxy.borrow().imported,
            vec![b"HTTP@proxy.example.net".to_vec()]
        );
    }

    // Delegation, the mechanism trait, and the orderings.

    /// The `CURLOPT_GSSAPI_DELEGATION` mask reaches the handshake unchanged.
    ///
    /// `lib/curl_gssapi.c:329` and `:338` test the two bits independently, so
    /// both may be set at once. The composition itself --
    /// `req_flags` seeded at `GSS_C_REPLAY_FLAG` rather than zero -- belongs to
    /// `crate::ffi::request_flags` and is asserted there; what this file owns is
    /// that the option value arrives.
    #[test]
    fn the_delegation_mask_reaches_the_handshake_unchanged() {
        let masks = [
            CURLGSSAPI_DELEGATION_NONE,
            CURLGSSAPI_DELEGATION_POLICY_FLAG,
            CURLGSSAPI_DELEGATION_FLAG,
            CURLGSSAPI_DELEGATION_POLICY_FLAG | CURLGSSAPI_DELEGATION_FLAG,
        ];
        for value in masks {
            let creds = credentials();
            let ends = endpoints(&creds);
            let mut conn = ConnectionNegotiate::new();
            let script = scripted(vec![StepScript::ok(
                HandshakeState::Complete,
                b"abcd",
            )]);
            install(&mut conn, false, &script);
            let delegation = Delegation::from_option_value(value);

            let (result, _) =
                run_output_with(&mut conn, ends, false, delegation);
            assert!(result.is_ok(), "delegation = {value}");
            assert_eq!(script.borrow().delegations, vec![delegation]);
        }

        // The three constants are `include/curl/curl.h:861-863` and their
        // integers are public ABI, so they are pinned as literals.
        assert_eq!(CURLGSSAPI_DELEGATION_NONE, 0);
        assert_eq!(CURLGSSAPI_DELEGATION_POLICY_FLAG, 1);
        assert_eq!(CURLGSSAPI_DELEGATION_FLAG, 2);
        assert!(Delegation::from_option_value(
            CURLGSSAPI_DELEGATION_POLICY_FLAG
        )
        .policy());
        assert!(
            Delegation::from_option_value(CURLGSSAPI_DELEGATION_FLAG).always()
        );
    }

    /// The `crate::auth::HttpAuthMechanism` implementation forwards to the two
    /// functions above and reports the right scheme.
    ///
    /// `crate::auth::AuthContext`'s clock, random source, method and target are
    /// all unread by Negotiate: its token comes from the credentials cache, so
    /// there is nothing to seed or to time.
    #[test]
    fn the_mechanism_trait_forwards_to_the_two_entry_points() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script =
            scripted(vec![StepScript::ok(HandshakeState::Complete, b"abcd")]);
        install(&mut conn, false, &script);

        // Both injected sources fail the test if they are touched, which is how
        // "Negotiate reads neither" is asserted rather than asserted about.
        let clock = NeverClock;
        let mut rng = NeverRng;
        let (result, _) = with_tracer(|tracer| {
            let mut mechanism =
                Negotiate::new(&mut conn, ends, Delegation::NONE, tracer);
            assert_eq!(mechanism.scheme(), AuthScheme::Negotiate);
            let mut ctx = AuthContext {
                proxy: false,
                request_method: b"GET",
                request_target: b"/index.html",
                clock: &clock,
                rng: &mut rng,
            };
            mechanism.output(&mut ctx)
        });
        assert_eq!(
            result,
            Ok(AuthEmission::Final(
                "Authorization: Negotiate YWJjZA==\r\n".to_owned()
            ))
        );

        // The input direction, through the trait.
        let script =
            scripted(vec![StepScript::ok(HandshakeState::Complete, b"more")]);
        let mut conn = ConnectionNegotiate::new();
        install(&mut conn, false, &script);
        let (input, _) = with_tracer(|tracer| {
            Negotiate::new(&mut conn, ends, Delegation::NONE, tracer)
                .input(b"Negotiate YWJjZA==", false)
        });
        assert_eq!(input, Ok(()));
        assert_eq!(script.borrow().inputs, vec![Some(b"abcd".to_vec())]);
    }

    /// This module's position in the three orderings `crate::auth` defines, and
    /// the `CURLAUTH_NEGOTIATE` integer with its two ABI aliases.
    #[test]
    fn negotiate_occupies_its_place_in_the_three_orderings() {
        assert_eq!(PREFERENCE_ORDER[0], AuthScheme::Negotiate);
        assert_eq!(EMISSION_ORDER[1], AuthScheme::Negotiate);
        assert_eq!(CHALLENGE_ORDER[0], AuthScheme::Negotiate);
        assert_eq!(EMISSION_ORDER[0], AuthScheme::AwsSigv4);
        assert_eq!(CHALLENGE_ORDER[1], AuthScheme::Ntlm);

        // `CURLAUTH_NEGOTIATE = 1 << 2`, with two aliases that must resolve to
        // the same integer (`include/curl/curl.h:833`, `:835`).
        assert_eq!(AuthMask::NEGOTIATE.bits(), 4);
        assert_eq!(crate::auth::CURLAUTH_GSSNEGOTIATE, AuthMask::NEGOTIATE);
        assert_eq!(crate::auth::CURLAUTH_GSSAPI, AuthMask::NEGOTIATE);
        assert_eq!(AuthScheme::Negotiate.mask(), AuthMask::NEGOTIATE);

        // The scheme token, outbound and inbound, is the one this file writes.
        assert_eq!(AuthScheme::Negotiate.header_scheme(), Some("Negotiate"));
        assert_eq!(AuthScheme::Negotiate.label(), "Negotiate");
        assert_eq!(NEGOTIATE_SCHEME, "Negotiate");
        assert_eq!(DEFAULT_SERVICE_NAME, "HTTP");
    }

    #[test]
    fn a_proxy_disabled_build_would_answer_not_built_in() {
        // The code itself, so the mapping is written down somewhere executable.
        assert_eq!(CURLcode::NotBuiltIn.as_i32(), 4);
        // And the proxy path is reachable, which is why the arm is unreachable.
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script =
            scripted(vec![StepScript::ok(HandshakeState::Complete, b"abcd")]);
        install(&mut conn, true, &script);
        assert_ne!(
            run_output(&mut conn, ends, true).0,
            Err(CURLcode::NotBuiltIn)
        );
    }

    // Secrecy.

    /// NO CREDENTIAL REACHES THE TRACE SINK.
    ///
    /// A complete exchange runs with tracing fully on, and the captured sink
    /// is searched for the password. This adds no redaction to curl's own
    /// output and removes none: `lib/http.c:2888-2895` puts the fully formed
    /// `Authorization:` header into the request buffer, where `--verbose`
    /// prints it verbatim and 168 fixtures compare it byte for byte.
    /// Suppressing that would fail those fixtures and is itself a prohibited
    /// behaviour change. What is asserted is the narrower invariant that
    /// actually binds: **no secret gains a path to a log that curl does not
    /// already have.** This module never emits the header itself -- it returns
    /// it -- so nothing it writes may contain a credential.
    #[test]
    fn no_credential_reaches_the_trace_sink() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(vec![
            StepScript::ok(HandshakeState::ContinueNeeded, b"one"),
            StepScript::ok(HandshakeState::Complete, b"two"),
        ]);
        install(&mut conn, false, &script);

        let mut everything = String::new();

        let (first, captured) = run_output(&mut conn, ends, false);
        assert!(first.is_ok());
        everything.push_str(&captured);

        let (consumed, captured) =
            run_input(&mut conn, ends, b"Negotiate YWJjZA==", false);
        assert_eq!(consumed, Ok(()));
        everything.push_str(&captured);
        conn.token_received(false);

        let (second, captured) = run_output(&mut conn, ends, false);
        assert!(second.is_ok());
        everything.push_str(&captured);

        let secret = String::from_utf8_lossy(SECRET).into_owned();
        assert!(
            !everything.contains(&secret),
            "the password must not appear in the trace: {everything}"
        );
        // Nor its base64 encoding, which is how a Basic-shaped mistake would
        // look.
        let encoded =
            base64::encode(SECRET).expect("the encoder cannot fail here");
        assert!(!everything.contains(&encoded));
    }

    /// The formatters print no secret.
    ///
    /// [`NegotiateData`]'s reports the token's LENGTH, never its bytes, and
    /// [`Negotiate`]'s names the endpoints without reaching into
    /// [`Credentials`] -- whose own formatter redacts the secret in any case.
    #[test]
    fn the_formatters_print_no_secret() {
        let creds = credentials();
        let ends = endpoints(&creds);
        let mut conn = ConnectionNegotiate::new();
        let script = scripted(Vec::new());
        install(&mut conn, false, &script);
        conn.data.get_or_default(false).output_token = SECRET.to_vec();

        let data = format!("{:?}", conn.data(false).expect("exists"));
        let secret = String::from_utf8_lossy(SECRET).into_owned();
        assert!(!data.contains(&secret), "{data}");
        assert!(data.contains("output_token_len"), "{data}");
        assert!(data.contains("havemultiplerequests"), "{data}");

        let (rendered, _) = with_tracer(|tracer| {
            format!(
                "{:?}",
                Negotiate::new(&mut conn, ends, Delegation::NONE, tracer)
            )
        });
        assert!(!rendered.contains(&secret), "{rendered}");
        assert!(rendered.contains("example.com"), "{rendered}");
        assert!(rendered.contains("proxy.example.net"), "{rendered}");
    }
}
