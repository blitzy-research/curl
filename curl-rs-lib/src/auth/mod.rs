//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Steve Holme, <steve_holme@hotmail.com>.
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
// RFC2617 Basic and Digest Access Authentication
// RFC6749 OAuth 2.0 Authorization Framework
//
//***************************************************************************

//! Authentication mechanism selection, vocabulary and shared plumbing.
//!
//! Supersedes all of `lib/vauth/vauth.c` (249 lines) with
//! `lib/vauth/vauth.h` (349 lines) as its declaration contract, the
//! mechanism-arbitration logic of `lib/http.c`, and the HTTP-relevant slice
//! -- and only that slice -- of `lib/curl_sasl.c` (934 lines). The six
//! sibling modules of this directory build the messages; this file decides
//! *which* message, *in what order*, and *whether at all*.
//!
//! | C                                  | Where                       | Here |
//! |------------------------------------|-----------------------------|------|
//! | `CURLAUTH_*`                       | `include/curl/curl.h:828-848` | [`AuthMask`] |
//! | `CURLGSSAPI_DELEGATION_*`          | `include/curl/curl.h:861-863` | [`CURLGSSAPI_DELEGATION_NONE`] and siblings |
//! | `CURLAUTH_PICKNONE`                | `lib/http.h:135`            | [`AuthMask::PICKNONE`] |
//! | `struct auth`                      | `lib/urldata.h:849-861`     | [`AuthState`] |
//! | `pickoneauth()`                    | `lib/http.c:336-372`        | [`pick_one_auth`] |
//! | `output_auth_headers()`            | `lib/http.c:627-740`        | [`select_emitter`], [`finish_emission`] |
//! | `Curl_http_output_auth()`          | `lib/http.c:756-842`        | [`credentials_offered`], [`seed_picked_from_want`], [`negotiation_probe_wanted`] |
//! | `Curl_http_auth_act()`             | `lib/http.c:536-620`        | [`auth_act`] |
//! | `authcmp()`                        | `lib/http.c:867-872`        | [`authcmp`] |
//! | `auth_spnego()` .. `auth_bearer()` | `lib/http.c:876-1002`       | [`input_auth`] |
//! | `Curl_http_input_auth()`           | `lib/http.c:1012-1096`      | [`input_auth`] |
//! | `Curl_auth_build_spn()`            | `lib/vauth/vauth.c:47-63`   | [`build_spn`] |
//! | `Curl_auth_user_contains_domain()` | `lib/vauth/vauth.c:114-132` | [`user_contains_domain`] |
//! | `Curl_auth_allowed_to_host()`      | `lib/vauth/vauth.c:138-147` | [`allowed_to_host`] |
//! | `Curl_auth_ntlm_get()`, `_remove()`, `Curl_auth_nego_get()` | `lib/vauth/vauth.c:160-176`, `:238-248` | [`MechanismSlots`] |
//! | `Curl_auth_is_digest_supported()`  | `lib/vauth/digest.c:311-314` | [`is_digest_supported`] |
//! | `Curl_auth_is_ntlm_supported()`    | `lib/vauth/ntlm.c:315-318`  | [`is_ntlm_supported`] |
//! | `Curl_auth_is_spnego_supported()`  | `lib/vauth/spnego_gssapi.c:49-52` | [`is_spnego_supported`] |
//! | `SASL_MECH_*`, `SASL_AUTH_*`       | `lib/curl_sasl.h:32-47`     | [`SaslMech`] |
//! | `SASL_MECH_STRING_*`, `mechtable[]` | `lib/curl_sasl.h:50-60`, `lib/curl_sasl.c:53-66` | [`MECHTABLE`] |
//! | `Curl_sasl_decode_mech()`          | `lib/curl_sasl.c:81-103`    | [`decode_mech`] |
//! | `Curl_sasl_init()` translation     | `lib/curl_sasl.c:157-175`   | [`curlauth_to_sasl_mechs`], [`sasl_preferred_mechs`] |
//!
//! # THREE ORDERINGS OF THE SAME SIX MECHANISMS, AND THEY ARE NOT ONE
//!
//! This is the part of this file most easily got wrong, because the natural
//! assumption -- that one ordering serves all three purposes -- is false, and
//! each of the three is externally observable. `lib/http.c` contains all
//! three, and none of them is the numeric order of the bits:
//!
//! ```text
//! bit value      BASIC 1  DIGEST 2  NEGOTIATE 4  NTLM 8  BEARER 64  AWS 128
//! preference     Negotiate  Bearer  Digest  NTLM  Basic  AWS_SIGV4
//! emission       AWS_SIGV4  Negotiate  NTLM  Digest  |  Basic  Bearer
//! challenge      Negotiate  NTLM  Digest  Basic  Bearer
//! ```
//!
//! [`PREFERENCE_ORDER`] carries the first, [`EMISSION_ORDER`] the second and
//! [`CHALLENGE_ORDER`] the third, each as its own table.
//!
//! What the relationship between the three actually is, measured against the
//! C rather than assumed, because the assumption is easy to state wrongly in
//! either direction:
//!
//! * **Preference differs from both others in five of its six positions.**
//!   It is the only one of the three that reorders mechanisms relative to the
//!   other two, and it is the one whose order decides what a server is
//!   answered with. `Bearer` is second here and last but one there; `NTLM`
//!   and `Digest` swap; `AWS_SIGV4` moves from first to last.
//! * **Emission and challenge agree on the relative order of the five
//!   mechanisms they share**, and the tests at the foot of this file assert
//!   that agreement rather than a difference. They stay two tables anyway,
//!   for two reasons that are not tidiness: the challenge order has no
//!   `AWS_SIGV4` entry at all, because AWS SigV4 signs a request instead of
//!   answering a challenge; and they are two different contracts -- emission
//!   is an arm sequence tested with equality against a single bit, challenge
//!   is a match sequence tested with a case-insensitive prefix predicate. A
//!   later change to one must not silently move the other.
//!
//! So the count of *tables* is three and the count of distinct *orders* is
//! two. Unifying preference with either of the others changes which mechanism
//! a server sees; collapsing emission into challenge changes nothing today
//! and removes the place a divergence would be recorded.
//!
//! Two details of the preference order are worth stating separately because
//! they read like mistakes and are not:
//!
//! * `AWS_SIGV4` sits **below** `BASIC`, so a server offering both gets
//!   Basic.
//! * `DIGEST_IE` appears in **none** of the three. It is a behaviour
//!   modifier on Digest -- `struct auth`'s `iestyle` bit -- and never a
//!   mechanism in its own right, which is also why
//!   [`AuthMask::ANY`] masks it out.
//!
//! # The `->picked` protocol
//!
//! `lib/http.c:1047-1052` states it, and the statement is carried here
//! rather than paraphrased because it is the clearest description of the
//! two-phase life of the field:
//!
//! > `->picked` is first set to the `want` value (one or more bits) before
//! > the request is sent, and then it is again set *after* all response
//! > 401/407 headers have been received but then only to a single preferred
//! > method (bit).
//!
//! So `picked` is a *set* before the first round trip and a *single bit*
//! after arbitration. Both phases are reproduced: the first by
//! [`seed_picked_from_want`], the second by [`pick_one_auth`]. Code that
//! reads `picked` must therefore test membership, not equality -- except
//! where C itself tests equality, which [`select_emitter`] does, deliberately
//! and for the reason recorded there.
//!
//! # Two independent instances, always
//!
//! Every transfer carries two of these, `data->state.authhost` and
//! `data->state.authproxy`, and they never share a value. [`AuthStatePair`]
//! is that pair, and the `proxy: bool` threaded through this module is the
//! selector C passes to the same functions.
//!
//! One consequence is a hard structural invariant rather than a runtime
//! check: **Bearer is never available to a proxy.**
//! `lib/http.c:574-575` passes `authmask & ~CURLAUTH_BEARER` when it
//! arbitrates the proxy, and `http_output_bearer()`
//! (`lib/http.c:308-325`) has no proxy branch at all -- its format string is
//! `"Authorization: Bearer %s\r\n"` with no `%s` prefix, where every other
//! emitter carries one. [`proxy_auth_mask`] is the only way to build a proxy
//! mask here, and it clears the bit unconditionally.
//!
//! # The `lib/curl_sasl.c` split boundary
//!
//! `lib/curl_sasl.c` sits astride this crate's scope boundary: it serves
//! SMTP, IMAP and POP3, which are out of scope, while `lib/vauth/` serves
//! HTTP authentication, which is in scope. The mechanism is therefore
//! **split** rather than migrated or dropped wholesale, and the split is
//! written down here so that a later reader does not "finish" it.
//!
//! Ported: the mechanism-name vocabulary ([`SaslMech`]), the name table and
//! its prefix matcher ([`MECHTABLE`], [`decode_mech`]), and the
//! `CURLAUTH_*` to `SASL_MECH_*` translation of `lib/curl_sasl.c:157-175`
//! ([`curlauth_to_sasl_mechs`]) -- which is the one genuine cross-boundary
//! piece, because it is HTTP option state deciding a SASL default.
//!
//! Deliberately absent: the SASL **command sequencing**. The 18-state
//! `saslstate` enumeration, the `saslprogress` enumeration, the
//! `struct SASLproto` vtable, `struct SASL`, `Curl_sasl_start`,
//! `Curl_sasl_continue`, `Curl_sasl_parse_url_auth_option`,
//! `Curl_sasl_can_authenticate`, `Curl_sasl_is_blocked` and the
//! `sasl_mech_equal` macro all exist to drive SMTP, IMAP and POP3 command
//! exchanges, and all three of those protocols are stubs that return
//! `CURLE_UNSUPPORTED_PROTOCOL`. A state machine with nothing to sequence
//! would be unreachable code, and unreachable code cannot be validated.
//!
//! `CRAM-MD5`, `SCRAM-SHA-1` and `SCRAM-SHA-256` keep their **bits** for
//! vocabulary completeness and have no implementation anywhere: the first
//! is `lib/vauth/cram.c`, which is excluded, and the other two came from
//! libgsasl, which is dropped. `decode_mech` still resolves all three
//! names, exactly as the C table does, because the table is the vocabulary.
//!
//! # Where mechanism state lives, and why the distinction matters
//!
//! C keeps per-mechanism state in a per-connection metadata map keyed by
//! string, with one destructor per entry. Six keys exist, and two of them
//! carry an upstream typo -- `"meta:auth:ntml:conn"` and
//! `"meta:auth:ntml-proxy:conn"` (`lib/vauth/vauth.h:159,161`) spell it
//! `ntml`, not `ntlm`. That is recorded here as a curiosity so that a
//! future reader does not think it was overlooked; **neither the keys nor
//! the map are reproduced.** They are purely internal, never on the wire
//! and never in the ABI, and they are replaced by typed, separately-owned
//! origin and proxy fields ([`MechanismSlots`]). This is the
//! untyped-`void *`-context-to-typed-field transformation that makes the
//! crate's zero-`unsafe` invariant reachable, and the four file-private C
//! destructors become ordinary Rust ownership.
//!
//! The scope of each mechanism's state is **not** uniform, and getting it
//! wrong changes when credentials are reused:
//!
//! | Mechanism | Scope           | C storage |
//! |-----------|-----------------|-----------|
//! | NTLM      | per-CONNECTION  | two connection meta keys |
//! | Negotiate | per-CONNECTION  | two connection meta keys |
//! | Digest    | per-TRANSFER    | `data->state.digest`, `data->state.proxydigest` |
//! | Basic, Bearer, AWS SigV4 | none | recomputed per request |
//!
//! That is why `Curl_http_auth_cleanup_digest()` clears two easy-handle
//! fields while `Curl_auth_ntlm_remove()` removes connection metadata.
//! [`state_scope`] is the machine-readable form of the table, so the
//! distinction is testable rather than merely documented.
//!
//! # Credentials gain no new path to a log
//!
//! curl has **no** redaction mechanism -- `grep -rn REDACTED lib/ src/`
//! finds nothing -- and `lib/http.c:2888-2895` inserts the fully formed
//! `Authorization:` header straight into the request buffer, from where it
//! reaches `Curl_debug(data, CURLINFO_HEADER_OUT, ...)` verbatim under
//! `--verbose`. 168 fixtures contain a literal `Authorization: ` line
//! inside a byte-exact `<protocol>` comparison block, so suppressing or
//! masking it would fail those fixtures and would itself be a prohibited
//! behaviour change. curl's existing diagnostics are therefore reproduced
//! exactly, including the five `infof()` strings of [`input_auth`].
//!
//! What is prohibited is *adding* a path curl does not have. No secret is
//! ever formatted into a trace record by this directory, and
//! [`Credentials`] implements [`core::fmt::Debug`] by hand so that a
//! structure holding one cannot leak it through a derived formatter --
//! which a `#[derive(Debug)]` on any enclosing type otherwise would, at
//! arbitrary distance from this file.
//!
//! # Visibility
//!
//! `pub(crate)` throughout. `lib/vauth/`'s internal contracts were `extern`
//! declarations under a `Curl_` prefix -- private by convention and visible
//! to the linker -- and they become private by enforcement here. Nothing is
//! re-exported to make `tests/unit/*.c` or `tests/libtest/*.c` link against
//! internal symbols; their inability to do so is a documented consequence
//! of that enforcement, and the coverage they carried is relocated into the
//! `#[cfg(test)]` module at the foot of this file.
//!
//! There is no `unsafe` here, and the crate root's `#![deny(unsafe_code)]`
//! makes any that appeared a hard error: the single exemption that root
//! grants is on `mod ffi`, and this is not it.

// Items whose only consumers are modules that have not landed yet carry
// `#[allow(dead_code)]` individually. The allowance is never set on this
// module's root, because that would also hide the next unreferenced item
// somebody adds -- and because the crate's own policy test in `lib.rs`
// (`mod source_policy`) fails the build if it is.

// THE SIX SIBLING MODULES ARE NOT DECLARED HERE YET, AND THAT IS DELIBERATE.
//
// The target design places `basic`, `bearer`, `digest`, `ntlm`, `aws_sigv4`
// and -- behind the default-off `negotiate` feature -- `negotiate` beside this
// file. None of the six exists on disk at this checkpoint, and a `mod` item
// naming an absent file is `error[E0583]: file not found for module`, which
// would take the whole crate down rather than leave one capability missing.
//
// So the convention this crate already applies elsewhere applies here: a
// module root declares exactly the children present on disk, and each child's
// declaration lands with the child. `curl-rs-lib/src/tls/mod.rs` declares
// `cipher_suite` and `keylog` and not the three planned modules absent beside
// them; `curl-rs-lib/src/url/mod.rs` says so in as many words. The
// declarations to add, verbatim, when the files arrive:
//
//     pub(crate) mod aws_sigv4;
//     pub(crate) mod basic;
//     pub(crate) mod bearer;
//     pub(crate) mod digest;
//     #[cfg(feature = "negotiate")]
//     pub(crate) mod negotiate;
//     pub(crate) mod ntlm;
//
// `negotiate` is the only gated one. Nothing else in this file is contingent
// on their arrival: every item below is complete, exercised by the tests at
// the foot of the file, and reachable by a sibling the moment it is declared.
//
// The capability banner already reflects the same absence and needs no edit
// when they land beyond flipping its own markers: `crate::version`'s
// `ENGINE_AUTH`, `ENGINE_AUTH_BASIC`, `ENGINE_AUTH_BEARER` and `ENGINE_GSS`
// name `auth/ntlm.rs`, `auth/basic.rs`, `auth/bearer.rs` and
// `auth/negotiate.rs` respectively and all four report absent, so `NTLM`,
// `GSS-API`, `Kerberos` and `SPNEGO` are withheld from `Features:`. That is
// under-reporting, which is the safe direction: a withheld capability makes a
// fixture skip, while a claimed one makes it run and fail.

use core::fmt;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

use crate::error::CURLcode;
use crate::trace::{infof, Tracer};
use crate::util::strcase::{casecompare, checkprefix};
use crate::util::strparse::{is_alnum, str_passblanks};

// ---------------------------------------------------------------------------
// The `CURLAUTH_*` bit vocabulary. Public ABI, integer-exact.
// `include/curl/curl.h:828-848`, plus `CURLAUTH_PICKNONE` from `lib/http.h:135`.
// ---------------------------------------------------------------------------

/// A set of HTTP authentication methods: the `CURLAUTH_*` bitmask.
///
/// Transcribed from `include/curl/curl.h:828-848`. Every value below is
/// **public ABI**: `CURLOPT_HTTPAUTH`, `CURLOPT_PROXYAUTH`,
/// `CURLOPT_SOCKS5_AUTH`, `CURLINFO_HTTPAUTH_AVAIL` and
/// `CURLINFO_PROXYAUTH_AVAIL` all carry these integers across the C boundary,
/// and a program compiled against curl 8.19.0-DEV holds them in its
/// instruction stream. They are therefore literals here, never inferred.
///
/// # Why a bitmask newtype and not an enumeration
///
/// The values are OR-able and routinely combined -- `--anyauth` sets
/// [`Self::ANY`], and `CURLOPT_HTTPAUTH` accepts any union -- so an
/// enumeration would be the wrong shape. The newtype exists so that a
/// [`SaslMech`] cannot be passed where an `AuthMask` is expected: the two
/// vocabularies overlap numerically (both give bit 6 a meaning) and
/// [`curlauth_to_sasl_mechs`] is the only sanctioned way to cross between
/// them.
///
/// # The representation is `u32`, matching C's `struct auth`
///
/// `include/curl/curl.h` declares the constants as `unsigned long`, but the
/// fields that hold them are `uint32_t` (`lib/urldata.h:849-861`), and the
/// two composite masks are explicitly `& ((unsigned long)0xffffffff)`. So 32
/// bits is the width the values actually live in, and [`Self::complement`]
/// reproduces C's masked `~` exactly rather than approximately.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub(crate) struct AuthMask(u32);

impl AuthMask {
    /// `CURLAUTH_NONE` -- no method at all.
    pub(crate) const NONE: Self = Self(0);

    /// `CURLAUTH_BASIC` = `1 << 0`. RFC 2617 Basic.
    pub(crate) const BASIC: Self = Self(1 << 0);

    /// `CURLAUTH_DIGEST` = `1 << 1`. RFC 2617 Digest.
    pub(crate) const DIGEST: Self = Self(1 << 1);

    /// `CURLAUTH_NEGOTIATE` = `1 << 2`. SPNEGO, over GSS-API here.
    pub(crate) const NEGOTIATE: Self = Self(1 << 2);

    /// `CURLAUTH_NTLM` = `1 << 3`.
    pub(crate) const NTLM: Self = Self(1 << 3);

    /// `CURLAUTH_DIGEST_IE` = `1 << 4`: Digest with the
    /// Internet-Explorer-compatible quirk.
    ///
    /// This is a **modifier on Digest**, not a mechanism, which is why it
    /// appears in none of [`PREFERENCE_ORDER`], [`EMISSION_ORDER`] or
    /// [`CHALLENGE_ORDER`], and why both [`Self::ANY`] and [`Self::ANYSAFE`]
    /// mask it out. Its effect is carried by [`AuthState::iestyle`].
    pub(crate) const DIGEST_IE: Self = Self(1 << 4);

    /// `CURLAUTH_NTLM_WB` = `1 << 5`. **Vocabulary only.**
    ///
    /// The constant lives inside `#ifndef CURL_NO_OLDIES` and the header
    /// annotates it "functionality removed since 8.8.0". It is defined here
    /// so that the bit stays occupied -- an application may still name it and
    /// must still get 32 -- and nothing whatsoever is implemented behind it.
    /// `NTLM_WB` is one of the 52 names `tests/runtests.pl` recognises in the
    /// `Features:` banner and it is never advertised there.
    pub(crate) const NTLM_WB: Self = Self(1 << 5);

    /// `CURLAUTH_BEARER` = `1 << 6`. RFC 6749 OAuth 2.0 bearer tokens.
    ///
    /// Never available to a proxy; see [`proxy_auth_mask`].
    pub(crate) const BEARER: Self = Self(1 << 6);

    /// `CURLAUTH_AWS_SIGV4` = `1 << 7`. AWS Signature Version 4.
    ///
    /// Also never available to a proxy, and for a second, independent
    /// reason: `lib/http.c:643-644` guards its emission arm with `&& !proxy`
    /// and comments "this method is never for proxy".
    pub(crate) const AWS_SIGV4: Self = Self(1 << 7);

    /// `CURLAUTH_ONLY` = `1 << 31`.
    ///
    /// A modifier meaning "use together with a single other type to force no
    /// authentication or just that single type". It is a member of both
    /// composite masks below, which is deliberate on C's part and preserved.
    pub(crate) const ONLY: Self = Self(1 << 31);

    /// `CURLAUTH_ANY` = `(~CURLAUTH_DIGEST_IE) & 0xffffffff` = `0xFFFF_FFEF`.
    ///
    /// Every bit except `DIGEST_IE`, which necessarily includes
    /// [`Self::ONLY`] and all 22 currently-undefined bits. **This is not an
    /// enumerated union and must not be "cleaned up" into one**: the integer
    /// is ABI, `--anyauth` sets exactly it, and narrowing it would change
    /// which methods a future curl could negotiate through an unchanged
    /// application.
    #[allow(dead_code)] // Consumer is `--anyauth` in `crate::easy::setopt`.
    pub(crate) const ANY: Self = Self::DIGEST_IE.complement();

    /// `CURLAUTH_ANYSAFE` =
    /// `(~(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE)) & 0xffffffff` =
    /// `0xFFFF_FFEE`.
    ///
    /// [`Self::ANY`] without Basic, which sends the password in a reversible
    /// encoding. The same warning applies: the value is ABI.
    #[allow(dead_code)] // Consumer is `--anyauth` in `crate::easy::setopt`.
    pub(crate) const ANYSAFE: Self =
        Self::BASIC.union(Self::DIGEST_IE).complement();

    /// `CURLAUTH_PICKNONE` = `1 << 30`. **Internal, not public ABI.**
    ///
    /// `lib/http.h:135`, whose comment is the definition: "If only the
    /// PICKNONE bit is set, there has been a round-trip and we selected to
    /// use no auth at all. Ie, we actively select no auth, as opposed to not
    /// having one selected."
    ///
    /// It is deliberately absent from `include/curl/curl.h`, so it is
    /// `pub(crate)` like everything else here and never reaches the ABI
    /// shim. It occupies bit 30, which no public constant claims.
    pub(crate) const PICKNONE: Self = Self(1 << 30);

    /// The raw integer, for the ABI boundary and for assertions.
    #[must_use]
    #[allow(dead_code)] // Consumer is the ABI shim, through `crate::easy`.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// Adopt a raw integer, unknown bits and all.
    ///
    /// Unknown bits are preserved rather than rejected because C preserves
    /// them: `CURLOPT_HTTPAUTH` stores whatever it is given and the
    /// arbitration masks decide what is reachable. Rejecting them would make
    /// an application that sets a bit from a newer header fail where curl
    /// silently ignores it.
    #[must_use]
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every bit of `other` is set here.
    ///
    /// `Self::NONE` is contained in everything, which is the vacuous truth
    /// `0 & x == 0` and matches how C's `avail & CURLAUTH_x` reads when `x`
    /// is zero -- so callers must test a *specific* bit, never `NONE`.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any bit of `other` is set here: C's `avail & CURLAUTH_x`.
    #[must_use]
    pub(crate) const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Whether no bit at all is set: C's `!authp->want`.
    #[must_use]
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether exactly one bit is set.
    ///
    /// The condition `Curl_http_output_auth()` relies on without naming:
    /// `lib/http.c:791-795` seeds `picked` from `want` and comments "if this
    /// is one single bit it will be used instantly".
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) const fn is_single(self) -> bool {
        self.0.count_ones() == 1
    }

    /// Set union: C's `|`. A `const fn` because the composite masks above are
    /// built from it, and operator traits are not callable in a `const`.
    #[must_use]
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Set intersection: C's `&`.
    #[must_use]
    pub(crate) const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The bits of `self` that are not in `other`: C's `x & ~y`.
    #[must_use]
    pub(crate) const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// The 32-bit complement: C's `(~x) & 0xffffffff`.
    ///
    /// The mask C writes is not decoration -- `CURLAUTH_*` are
    /// `unsigned long`, which is 64 bits wide on every mandated target, so
    /// an unmasked `~` there would set the upper 32 bits too. Here the
    /// representation is exactly 32 bits, so `!` *is* the masked form.
    #[must_use]
    pub(crate) const fn complement(self) -> Self {
        Self(!self.0)
    }
}

impl BitOr for AuthMask {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

impl BitOrAssign for AuthMask {
    fn bitor_assign(&mut self, other: Self) {
        *self = self.union(other);
    }
}

impl BitAnd for AuthMask {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        self.intersection(other)
    }
}

impl BitAndAssign for AuthMask {
    fn bitand_assign(&mut self, other: Self) {
        *self = self.intersection(other);
    }
}

impl Not for AuthMask {
    type Output = Self;

    fn not(self) -> Self {
        self.complement()
    }
}

impl fmt::Debug for AuthMask {
    /// Renders the set as its C constant names, so a failing assertion names
    /// methods rather than a hexadecimal integer.
    ///
    /// Hand-written rather than derived for legibility only -- there is no
    /// secret in a bitmask. The residue of bits that no constant claims is
    /// printed in hexadecimal so that nothing is silently dropped, which
    /// matters for [`Self::ANY`], whose 22 undefined bits are part of its
    /// value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("CURLAUTH_NONE");
        }

        let mut residue = self.0;
        let mut first = true;
        for (mask, name) in NAMED_BITS {
            if self.0 & mask.0 == 0 {
                continue;
            }
            residue &= !mask.0;
            if !first {
                f.write_str("|")?;
            }
            f.write_str(name)?;
            first = false;
        }

        if residue != 0 {
            if !first {
                f.write_str("|")?;
            }
            write!(f, "{residue:#010x}")?;
        }
        Ok(())
    }
}

/// Every named bit, in ascending bit order, for [`AuthMask`]'s formatter.
///
/// `NTLM_WB` is listed because the bit exists and must be *named* if an
/// application sets it -- printing `0x20` instead would hide which bit it
/// was. Listing it here advertises nothing: the `Features:` banner is built
/// in `crate::version` and never consults this table. `PICKNONE` is listed
/// for the same reason and is marked so, since it is not a public constant.
#[rustfmt::skip]
const NAMED_BITS: [(AuthMask, &str); 10] = [
    (AuthMask::BASIC,     "CURLAUTH_BASIC"),
    (AuthMask::DIGEST,    "CURLAUTH_DIGEST"),
    (AuthMask::NEGOTIATE, "CURLAUTH_NEGOTIATE"),
    (AuthMask::NTLM,      "CURLAUTH_NTLM"),
    (AuthMask::DIGEST_IE, "CURLAUTH_DIGEST_IE"),
    (AuthMask::NTLM_WB,   "CURLAUTH_NTLM_WB"),
    (AuthMask::BEARER,    "CURLAUTH_BEARER"),
    (AuthMask::AWS_SIGV4, "CURLAUTH_AWS_SIGV4"),
    (AuthMask::PICKNONE,  "CURLAUTH_PICKNONE"),
    (AuthMask::ONLY,      "CURLAUTH_ONLY"),
];

/// `CURLAUTH_GSSNEGOTIATE` -- an alias for [`AuthMask::NEGOTIATE`].
///
/// `include/curl/curl.h:833`, annotated "Deprecated since the advent of
/// CURLAUTH_NEGOTIATE". It must resolve to the same integer, 4; an
/// application compiled against either spelling holds that value.
#[allow(dead_code)] // Consumer is the ABI shim's option table.
pub(crate) const CURLAUTH_GSSNEGOTIATE: AuthMask = AuthMask::NEGOTIATE;

/// `CURLAUTH_GSSAPI` -- a second alias for [`AuthMask::NEGOTIATE`].
///
/// `include/curl/curl.h:835`, annotated "Used for CURLOPT_SOCKS5_AUTH to
/// stay terminologically correct". Also 4.
pub(crate) const CURLAUTH_GSSAPI: AuthMask = AuthMask::NEGOTIATE;

/// `CURLGSSAPI_DELEGATION_NONE` = `0` -- the `CURLOPT_GSSAPI_DELEGATION`
/// default.
///
/// `include/curl/curl.h:861`. The three delegation constants sit thirteen
/// lines below the `CURLAUTH_*` block in the same header and are declared
/// here for the same reason: this module owns the authentication *option*
/// vocabulary. The typed form that consumes them is
/// `crate::ffi::gss::Delegation`, which is where the flag translation into
/// `GSS_C_DELEG_*` lives; these are the raw integers the easy handle stores,
/// and a test asserts the two agree.
#[allow(dead_code)] // Consumer is `crate::auth::negotiate`, not yet landed.
pub(crate) const CURLGSSAPI_DELEGATION_NONE: i64 = 0;

/// `CURLGSSAPI_DELEGATION_POLICY_FLAG` = `1 << 0`: delegate if policy
/// permits.
///
/// `include/curl/curl.h:862`.
#[allow(dead_code)] // Consumer is `crate::auth::negotiate`, not yet landed.
pub(crate) const CURLGSSAPI_DELEGATION_POLICY_FLAG: i64 = 1 << 0;

/// `CURLGSSAPI_DELEGATION_FLAG` = `1 << 1`: delegate always.
///
/// `include/curl/curl.h:863`. A bitmask with the previous constant, tested
/// independently at `lib/curl_gssapi.c:329` and `:338`, so both may be set.
#[allow(dead_code)] // Consumer is `crate::auth::negotiate`, not yet landed.
pub(crate) const CURLGSSAPI_DELEGATION_FLAG: i64 = 1 << 1;

// ---------------------------------------------------------------------------
// The scheme vocabulary: one enumeration, three orderings.
// `lib/http.c:336-372`, `:627-740` and `:1012-1096`.
// ---------------------------------------------------------------------------

/// One HTTP authentication mechanism, as a single choice rather than a set.
///
/// [`AuthMask`] answers "which methods are in play"; this answers "which one
/// is running". C conflates the two -- `authstatus->picked` is a bitmask that
/// arbitration narrows to one bit -- and the narrowing is exactly where a
/// mistake becomes invisible, so the narrowed form gets its own type.
///
/// `DIGEST_IE` and `NTLM_WB` have no variant: the first is a modifier on
/// [`Self::Digest`] and the second has no implementation at all.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum AuthScheme {
    /// Basic, `lib/http.c:238-297`.
    Basic,
    /// Digest, `lib/http_digest.c`.
    Digest,
    /// Negotiate/SPNEGO, `lib/http_negotiate.c`.
    Negotiate,
    /// NTLM, `lib/http_ntlm.c`.
    Ntlm,
    /// OAuth 2.0 bearer token, `lib/http.c:302-325`.
    Bearer,
    /// AWS Signature Version 4, `lib/http_aws_sigv4.c`.
    AwsSigv4,
}

impl AuthScheme {
    /// The single [`AuthMask`] bit this scheme occupies.
    #[must_use]
    pub(crate) const fn mask(self) -> AuthMask {
        match self {
            Self::Basic => AuthMask::BASIC,
            Self::Digest => AuthMask::DIGEST,
            Self::Negotiate => AuthMask::NEGOTIATE,
            Self::Ntlm => AuthMask::NTLM,
            Self::Bearer => AuthMask::BEARER,
            Self::AwsSigv4 => AuthMask::AWS_SIGV4,
        }
    }

    /// The label `output_auth_headers()` records for the trailing diagnostic.
    ///
    /// `lib/http.c:645`, `:654`, `:663`, `:672`, `:692` and `:708`, verbatim.
    /// These reach the user through `--verbose`, so they are frozen output
    /// and **not** the same strings as [`Self::header_scheme`]: note
    /// `"AWS_SIGV4"` here, in upper case with an underscore, where no header
    /// scheme token is ever spelled that way.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::AwsSigv4 => "AWS_SIGV4",
            Self::Negotiate => "Negotiate",
            Self::Ntlm => "NTLM",
            Self::Digest => "Digest",
            Self::Basic => "Basic",
            Self::Bearer => "Bearer",
        }
    }

    /// The `auth-scheme` token this mechanism writes into, and matches in,
    /// an authentication header.
    ///
    /// Both directions use the same spelling. Outbound it is the token after
    /// the colon in `"%sAuthorization: Digest %s\r\n"`
    /// (`lib/http_digest.c:161`) and its three siblings; inbound it is the
    /// argument `Curl_http_input_auth()` hands [`authcmp`]
    /// (`lib/http.c:1057-1074`).
    ///
    /// AWS SigV4 has no token because it emits no `Authorization:` scheme of
    /// its own name and answers no challenge -- it signs the request instead
    /// -- which is why it appears in [`EMISSION_ORDER`] but not in
    /// [`CHALLENGE_ORDER`].
    #[must_use]
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) const fn header_scheme(self) -> Option<&'static str> {
        match self {
            Self::Basic => Some("Basic"),
            Self::Digest => Some("Digest"),
            Self::Negotiate => Some("Negotiate"),
            Self::Ntlm => Some("NTLM"),
            Self::Bearer => Some("Bearer"),
            Self::AwsSigv4 => None,
        }
    }

    /// Whether this mechanism's emitter needs the request method and target.
    ///
    /// True for [`Self::Digest`] alone. `lib/http.c:673-676` passes `request`
    /// and `path` to `Curl_output_digest()` and to nothing else, because the
    /// Digest response digests both. Modelling that honestly -- one predicate
    /// and one context field -- is preferred over giving every emitter two
    /// parameters it ignores.
    #[must_use]
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) const fn needs_request_target(self) -> bool {
        matches!(self, Self::Digest)
    }
}

/// PREFERENCE order: which method wins when the server offers several.
///
/// `pickoneauth()`, `lib/http.c:343-364`, whose own comment is the warning
/// this table exists to preserve:
///
/// > The order of these checks is highly relevant, as this will be the order
/// > of preference in case of the existence of multiple accepted types.
///
/// [`pick_one_auth`] does **not** iterate this table -- it is an explicit
/// if/else-if chain, for the reason recorded there -- so the table's job is
/// to make the order assertable and to keep it in one place. A test compares
/// the chain against it for all 64 subsets.
#[allow(dead_code)] // Reached only by this file's tests until a consumer lands.
#[rustfmt::skip]
pub(crate) const PREFERENCE_ORDER: [AuthScheme; 6] = [
    AuthScheme::Negotiate,
    AuthScheme::Bearer,
    AuthScheme::Digest,
    AuthScheme::Ntlm,
    AuthScheme::Basic,
    AuthScheme::AwsSigv4,
];

/// EMISSION order: the arm sequence of `output_auth_headers()`.
///
/// `lib/http.c:642-718`. Different from [`PREFERENCE_ORDER`] in the position
/// of all but one entry; the same as [`CHALLENGE_ORDER`] on the five
/// mechanisms the two share, which is recorded there.
///
/// Since arbitration has already narrowed `picked` to one bit by the time
/// this runs, the order is not a preference -- it is the order in which the
/// arms are tested, and it is reproduced because the structure is what a
/// reader checks this file against.
#[allow(dead_code)] // Reached only by this file's tests until a consumer lands.
#[rustfmt::skip]
pub(crate) const EMISSION_ORDER: [AuthScheme; 6] = [
    AuthScheme::AwsSigv4,
    AuthScheme::Negotiate,
    AuthScheme::Ntlm,
    AuthScheme::Digest,
    AuthScheme::Basic,
    AuthScheme::Bearer,
];

/// CHALLENGE-PARSING order: the sequence `Curl_http_input_auth()` tests a
/// `WWW-Authenticate:` or `Proxy-Authenticate:` line against.
///
/// `lib/http.c:1056-1075`. Five entries, not six: AWS SigV4 answers no
/// challenge, so it has no entry here at all.
///
/// On its five shared mechanisms this is the same relative order as
/// [`EMISSION_ORDER`] -- measured, and asserted by the tests rather than
/// assumed either way. It is nonetheless a separate table, because the two are
/// separate contracts: an emission arm is selected by equality against a
/// single bit, a challenge is matched by [`authcmp`]'s case-insensitive prefix
/// predicate, and only one of the two admits `AWS_SIGV4`. Keeping them apart
/// is what gives a future divergence somewhere to be recorded.
///
/// The order is observable in a subtler way than the other two. A single
/// header line may name several schemes, and the loop tests all five against
/// the same offset before advancing to the next comma
/// (`lib/http.c:1080-1086`), so for a line naming two schemes the order
/// decides which is decoded first -- and Digest's duplicate-header rule
/// (`lib/http.c:944-945`) makes "first" visible in the trace log.
#[allow(dead_code)] // Reached only by this file's tests until a consumer lands.
#[rustfmt::skip]
pub(crate) const CHALLENGE_ORDER: [AuthScheme; 5] = [
    AuthScheme::Negotiate,
    AuthScheme::Ntlm,
    AuthScheme::Digest,
    AuthScheme::Basic,
    AuthScheme::Bearer,
];

// ---------------------------------------------------------------------------
// `struct auth` -- `lib/urldata.h:849-861`.
// ---------------------------------------------------------------------------

/// The authentication state of one endpoint: C's `struct auth`.
///
/// `lib/urldata.h:849-861`. Two of these exist per transfer and never share a
/// value -- see [`AuthStatePair`].
///
/// # The `picked` field has two phases
///
/// `lib/http.c:1047-1052`, carried verbatim because it is the clearest
/// statement of the protocol:
///
/// > `->picked` is first set to the `want` value (one or more bits) before
/// > the request is sent, and then it is again set *after* all response
/// > 401/407 headers have been received but then only to a single preferred
/// > method (bit).
///
/// A third value is possible and is neither of those: [`AuthMask::PICKNONE`]
/// alone, which [`pick_one_auth`] writes when nothing in `avail & want &
/// mask` is usable. It means "a round trip happened and we actively chose no
/// authentication", which is not the same as "nothing chosen yet"
/// ([`AuthMask::NONE`]).
///
/// # Fields are private
///
/// C reads and writes these members directly from `lib/http.c`,
/// `lib/http_ntlm.c`, `lib/http_digest.c`, `lib/http_negotiate.c` and
/// `lib/transfer.c`. Here the sibling modules of this directory reach them as
/// descendants of the defining module, and everything further out goes
/// through the accessors -- so the two-phase `picked` rule above has one
/// place to be enforced rather than five.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuthState {
    /// Bits the application asked for, through `CURLOPT_HTTPAUTH` or
    /// `CURLOPT_PROXYAUTH`.
    want: AuthMask,
    /// Bits currently in force: a set before the first round trip, a single
    /// bit after arbitration.
    picked: AuthMask,
    /// Bits the server reported for this resource. Cleared by every
    /// [`pick_one_auth`] call.
    avail: AuthMask,
    /// `TRUE` when the authentication phase is finished and the actual
    /// request can be made.
    done: bool,
    /// `TRUE` when this is not yet authenticated but is inside a multi-pass
    /// negotiation -- NTLM's three-message exchange, or Negotiate's.
    multipass: bool,
    /// `TRUE` when Digest is to be done Internet-Explorer-style rather than
    /// RFC-compliant: the effect of [`AuthMask::DIGEST_IE`].
    iestyle: bool,
}

impl AuthState {
    /// The state a freshly initialised easy handle carries: all zero.
    ///
    /// C gets this from the `calloc()` of the handle itself, which is why
    /// there is no initialiser to transcribe.
    #[allow(dead_code)] // Consumer is `crate::transfer`, not yet landed.
    pub(crate) const ZERO: Self = Self {
        want: AuthMask::NONE,
        picked: AuthMask::NONE,
        avail: AuthMask::NONE,
        done: false,
        multipass: false,
        iestyle: false,
    };

    /// The state produced by an application asking for `want`.
    ///
    /// `iestyle` is derived here rather than left to the caller because it is
    /// not independent: it is `want & CURLAUTH_DIGEST_IE`, and
    /// `lib/vauth/digest.c` consults the bit through this field only.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::transfer`, not yet landed.
    pub(crate) const fn wanting(want: AuthMask) -> Self {
        Self {
            want,
            picked: AuthMask::NONE,
            avail: AuthMask::NONE,
            done: false,
            multipass: false,
            iestyle: want.intersects(AuthMask::DIGEST_IE),
        }
    }

    /// The bits the application asked for.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) const fn want(&self) -> AuthMask {
        self.want
    }

    /// Replace the wanted set, re-deriving [`Self::iestyle`] with it.
    #[allow(dead_code)] // Consumer is `crate::transfer`, not yet landed.
    pub(crate) fn set_want(&mut self, want: AuthMask) {
        self.want = want;
        self.iestyle = want.intersects(AuthMask::DIGEST_IE);
    }

    /// The bits currently in force. See the two-phase rule on the type.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) const fn picked(&self) -> AuthMask {
        self.picked
    }

    /// The bits the server reported.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) const fn avail(&self) -> AuthMask {
        self.avail
    }

    /// Add server-reported bits: C's `authp->avail |= CURLAUTH_x`.
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) fn add_avail(&mut self, offered: AuthMask) {
        self.avail |= offered;
    }

    /// Whether the authentication phase is finished.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) const fn is_done(&self) -> bool {
        self.done
    }

    /// Set or clear the finished flag.
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn set_done(&mut self, done: bool) {
        self.done = done;
    }

    /// Whether a multi-pass negotiation is in progress.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::transfer`, not yet landed.
    pub(crate) const fn is_multipass(&self) -> bool {
        self.multipass
    }

    /// Whether Digest is to be done Internet-Explorer-style.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::auth::digest`, not yet landed.
    pub(crate) const fn iestyle(&self) -> bool {
        self.iestyle
    }

    /// The single scheme in force, or `None` when `picked` is empty, is
    /// [`AuthMask::PICKNONE`], or still holds more than one bit.
    ///
    /// This is the safe reading of `picked` after arbitration, and the
    /// `None` for a multi-bit value is the point: C's emission arms compare
    /// with `==`, so a two-bit `picked` matches no arm there either.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn picked_scheme(&self) -> Option<AuthScheme> {
        EMISSION_ORDER
            .iter()
            .copied()
            .find(|scheme| self.picked == scheme.mask())
    }
}

/// The two independent authentication states every transfer carries.
///
/// C's `data->state.authhost` and `data->state.authproxy`
/// (`lib/urldata.h`). They are modelled as two fields and never as one
/// shared value: the origin server and the proxy negotiate separately, may
/// settle on different mechanisms, and finish at different times.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuthStatePair {
    /// `data->state.authhost`: the origin server.
    pub(crate) host: AuthState,
    /// `data->state.authproxy`: the proxy.
    pub(crate) proxy: AuthState,
}

impl AuthStatePair {
    /// Both states zeroed.
    #[allow(dead_code)] // Consumer is `crate::transfer`, not yet landed.
    pub(crate) const ZERO: Self = Self {
        host: AuthState::ZERO,
        proxy: AuthState::ZERO,
    };

    /// The state selected by C's `proxy` boolean argument.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn select(&self, proxy: bool) -> &AuthState {
        if proxy {
            &self.proxy
        } else {
            &self.host
        }
    }

    /// The state selected by C's `proxy` boolean argument, mutably.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn select_mut(&mut self, proxy: bool) -> &mut AuthState {
        if proxy {
            &mut self.proxy
        } else {
            &mut self.host
        }
    }
}

// ---------------------------------------------------------------------------
// ORDERING 1 of 3 -- PREFERENCE. `pickoneauth()`, `lib/http.c:336-372`.
// ---------------------------------------------------------------------------

/// Selects the most favourable method from the ones available and the ones
/// wanted, narrowing `picked` to a single bit.
///
/// Supersedes `pickoneauth()` (`lib/http.c:336-372`) exactly, and its own
/// comment states the constraint this function is written to preserve:
///
/// > The order of these checks is highly relevant, as this will be the order
/// > of preference in case of the existence of multiple accepted types.
///
/// Returns `true` when a method was picked. On `false`, `pick.picked` is
/// [`AuthMask::PICKNONE`] -- "we select to use nothing" -- and the caller
/// sets `authproblem`.
///
/// # Three things here are easy to get wrong, and all three are observable
///
/// 1. **The intersection is three-way**, `avail & want & mask`
///    (`lib/http.c:340`), not two. `mask` is the caller's restriction: it
///    clears `BEARER` when no token was set, and clears it a second time for
///    a proxy. A bit present in both `avail` and `want` but absent from
///    `mask` must not be picked.
/// 2. **It is an if/else-if chain, not a loop over the set bits.** Iterating
///    would silently order by bit value -- `BASIC`(1), `DIGEST`(2),
///    `NEGOTIATE`(4), `NTLM`(8), `BEARER`(64), `AWS_SIGV4`(128) -- which is
///    a *different* preference from the one above in five of six positions.
///    [`PREFERENCE_ORDER`] records the correct order for assertion; the
///    chain below is the implementation, and a test proves they agree over
///    all 64 subsets.
/// 3. **`avail` is cleared on every call, including the failure path.**
///    `lib/http.c:369` is the last statement before the return and sits
///    outside the chain: `pick->avail = CURLAUTH_NONE; /* clear it here */`.
///    A server's offer is consumed by being considered, so the next 401 on
///    the same handle starts from an empty offer.
///
/// `DIGEST_IE` is absent from the chain, exactly as in C. It reaches Digest
/// through [`AuthState::iestyle`] instead.
#[allow(dead_code)] // Consumer is `crate::transfer`, not yet landed.
pub(crate) fn pick_one_auth(pick: &mut AuthState, mask: AuthMask) -> bool {
    // Only deal with authentication we want. `lib/http.c:340`.
    let avail = pick.avail & pick.want & mask;
    let mut picked = true;

    // The order of these checks is highly relevant, as this will be the
    // order of preference in case of the existence of multiple accepted
    // types. `lib/http.c:343-364`.
    if avail.intersects(AuthMask::NEGOTIATE) {
        pick.picked = AuthMask::NEGOTIATE;
    } else if avail.intersects(AuthMask::BEARER) {
        pick.picked = AuthMask::BEARER;
    } else if avail.intersects(AuthMask::DIGEST) {
        pick.picked = AuthMask::DIGEST;
    } else if avail.intersects(AuthMask::NTLM) {
        pick.picked = AuthMask::NTLM;
    } else if avail.intersects(AuthMask::BASIC) {
        pick.picked = AuthMask::BASIC;
    } else if avail.intersects(AuthMask::AWS_SIGV4) {
        pick.picked = AuthMask::AWS_SIGV4;
    } else {
        // We select to use nothing. `lib/http.c:366-367`.
        pick.picked = AuthMask::PICKNONE;
        picked = false;
    }

    // Clear it here -- outside the chain, so this runs on the failure path
    // too. `lib/http.c:369`.
    pick.avail = AuthMask::NONE;

    picked
}

/// The mask a proxy arbitration may use: `base` with `BEARER` removed.
///
/// `lib/http.c:574-575` passes `authmask & ~CURLAUTH_BEARER` when it
/// arbitrates `data->state.authproxy`, and this is the only constructor of a
/// proxy mask in this crate. Encoding the rule as the sole path to the value
/// makes "Bearer is never available to a proxy" a structural invariant rather
/// than a check somebody can forget, which is why [`pick_one_auth`] itself
/// has no proxy parameter.
///
/// The invariant has independent corroboration in the emitter:
/// `http_output_bearer()` (`lib/http.c:308-325`) writes
/// `"Authorization: Bearer %s\r\n"` with no proxy prefix conversion, where
/// Basic, Digest, NTLM and Negotiate all carry one -- so even reaching that
/// arm with `proxy` true could not produce a `Proxy-Authorization:` header.
#[must_use]
pub(crate) const fn proxy_auth_mask(base: AuthMask) -> AuthMask {
    base.difference(AuthMask::BEARER)
}

// ---------------------------------------------------------------------------
// ORDERING 2 of 3 -- EMISSION. `output_auth_headers()`, `lib/http.c:627-740`.
// ---------------------------------------------------------------------------

/// The header line one mechanism produced, and whether it finished.
///
/// This is where C's `bool *done` out-parameter goes. `Curl_output_ntlm()`,
/// `Curl_output_negotiate()`, `Curl_output_digest()` and
/// `Curl_output_aws_sigv4()` each write `authp->done` through a pointer they
/// were handed (`lib/http_ntlm.c:167,232,246`,
/// `lib/http_negotiate.c:178,204,254`, `lib/http_digest.c:124,167`,
/// `lib/http_aws_sigv4.c:1111`); readiness is expressed by the returned value
/// here instead, so it cannot be forgotten and cannot be written twice.
///
/// [`finish_emission`] applies it, and the mapping is exact:
/// `done = !matches!(self, Self::Continuing(_))`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
pub(crate) enum AuthEmission {
    /// A header line, and the exchange is finished after it.
    ///
    /// Basic and Digest always land here; NTLM and Negotiate do on their
    /// final message.
    Final(String),
    /// A header line, and at least one further round trip is required.
    ///
    /// NTLM's type-1 message and Negotiate's first token: C leaves
    /// `authp->done` false there, and `output_auth_headers()` then computes
    /// `multipass = !done` as true.
    Continuing(String),
    /// No header this round, and the mechanism considers itself finished.
    ///
    /// The Basic and Bearer arms reach this when the application has supplied
    /// its own `Authorization:` header: `lib/http.c:685-701` skips the
    /// emitter but still sets `done` unconditionally, with the comment "this
    /// function should set 'done' TRUE, as the other auth functions work
    /// that way".
    Nothing,
}

impl AuthEmission {
    /// The header line, if one was produced.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn header(&self) -> Option<&str> {
        match self {
            Self::Final(line) | Self::Continuing(line) => Some(line),
            Self::Nothing => None,
        }
    }

    /// Whether the mechanism considers the exchange finished: C's
    /// `authp->done` after the emitter returns.
    #[must_use]
    pub(crate) const fn is_done(&self) -> bool {
        !matches!(self, Self::Continuing(_))
    }
}

/// The guard inputs `output_auth_headers()` tests before running an arm.
///
/// Each field is one term of a condition in `lib/http.c:642-712`, named after
/// the C expression it stands for so that the call site reads as the C does.
/// They are gathered into a structure rather than passed as five bare
/// booleans because five positional booleans at one call site is a defect
/// waiting to happen.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EmissionGuards {
    /// `conn->bits.proxy_user_passwd` -- proxy credentials were supplied.
    pub(crate) proxy_user_passwd: bool,
    /// `data->state.aptr.user` is non-NULL -- origin credentials exist.
    pub(crate) have_user: bool,
    /// `data->set.str[STRING_BEARER]` is non-NULL.
    pub(crate) have_bearer: bool,
    /// `Curl_checkheaders(data, "Authorization")` -- the application supplied
    /// its own origin authorization header, so curl must not overwrite it.
    pub(crate) authorization_overridden: bool,
    /// `Curl_checkProxyheaders(data, conn, "Proxy-authorization")` -- the
    /// application supplied its own proxy authorization header.
    ///
    /// The C literal is spelled with a lower-case `a` in `authorization`
    /// (`lib/http.c:688`) where the origin-side literal at `:691` is
    /// `"Authorization"`. The comparison is case-insensitive so the
    /// difference cannot change behaviour, and the literal is preserved
    /// verbatim in [`PROXY_AUTHORIZATION_HEADER`] regardless, because a
    /// transcription that "corrects" the source is a transcription a reader
    /// can no longer check.
    pub(crate) proxy_authorization_overridden: bool,
}

/// The header name `output_auth_headers()` checks for a user override on the
/// proxy side, verbatim from `lib/http.c:688`.
///
/// Lower-case `a`. See [`EmissionGuards::proxy_authorization_overridden`].
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) const PROXY_AUTHORIZATION_HEADER: &str = "Proxy-authorization";

/// The header name checked on the origin side, from `lib/http.c:691`.
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) const AUTHORIZATION_HEADER: &str = "Authorization";

/// Chooses which mechanism emits this request's authorization header, and
/// applies the two `done` assignments the arms themselves make.
///
/// Supersedes the arm-selection half of `output_auth_headers()`
/// (`lib/http.c:642-718`). The other half -- calling the chosen mechanism --
/// belongs to the sibling modules, and the bookkeeping that follows it is
/// [`finish_emission`].
///
/// Returns the scheme whose emitter must run, or `None` when no arm applies,
/// which is C's `auth == NULL`.
///
/// # The structure is reproduced, including one inert asymmetry
///
/// Arms 1 to 5 (`AWS_SIGV4`, `Negotiate`, `NTLM`, `Digest`, `Basic`) form a
/// single if/else-if chain; the `Bearer` arm at `lib/http.c:704` is a
/// **separate** `if` statement rather than a continuation of it. That
/// asymmetry is transcribed rather than tidied, and it is also *inert*, which
/// is stated here so that a reader does not mistake it for load-bearing: all
/// six tests are equality tests against a single-bit constant, so at most one
/// can be true whatever the chaining. Saying so is more useful than either
/// hiding the shape or implying it matters.
///
/// # Why equality and not membership
///
/// C writes `authstatus->picked == CURLAUTH_BASIC`, and a `picked` still
/// holding several bits -- which happens between
/// [`seed_picked_from_want`] and the first server round trip -- therefore
/// matches no arm and emits nothing. That is deliberate on C's part: with
/// two mechanisms still in play there is no way to choose, so the request
/// goes out unauthenticated and the 401 that follows drives
/// [`pick_one_auth`]. [`AuthState::picked_scheme`] is the same test in
/// reusable form.
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) fn select_emitter(
    state: &mut AuthState,
    proxy: bool,
    guards: &EmissionGuards,
) -> Option<AuthScheme> {
    let picked = state.picked;
    let mut chosen = None;

    if picked == AuthMask::AWS_SIGV4 && !proxy {
        // This method is never for proxy. `lib/http.c:643-644`.
        chosen = Some(AuthScheme::AwsSigv4);
    } else if cfg!(feature = "negotiate") && picked == AuthMask::NEGOTIATE {
        // C guards this arm with `#ifdef USE_SPNEGO`, which becomes the
        // default-off `negotiate` feature. The predicate is written as
        // `cfg!()` rather than as an attribute on the arm so that the
        // remaining arms keep their chaining when the feature is off, which
        // is precisely what removing an `#ifdef`-guarded `if ... else` does
        // to the C.
        chosen = Some(AuthScheme::Negotiate);
    } else if picked == AuthMask::NTLM {
        chosen = Some(AuthScheme::Ntlm);
    } else if picked == AuthMask::DIGEST {
        chosen = Some(AuthScheme::Digest);
    } else if picked == AuthMask::BASIC {
        let proxy_side = proxy
            && guards.proxy_user_passwd
            && !guards.proxy_authorization_overridden;
        let origin_side =
            !proxy && guards.have_user && !guards.authorization_overridden;
        if proxy_side || origin_side {
            chosen = Some(AuthScheme::Basic);
        }
        // `lib/http.c:698-700`: "NOTE: this function should set 'done' TRUE,
        // as the other auth functions work that way". Unconditional -- it
        // runs whether or not the guard above admitted the emitter.
        state.done = true;
    }

    // A SEPARATE `if`, not an `else if`. `lib/http.c:704`.
    if picked == AuthMask::BEARER {
        if !proxy && guards.have_bearer && !guards.authorization_overridden {
            chosen = Some(AuthScheme::Bearer);
        }
        state.done = true;
    }

    chosen
}

/// Applies the trailing bookkeeping of `output_auth_headers()`: the
/// diagnostic and `multipass`.
///
/// `lib/http.c:720-737`. Call it once per `output_auth_headers()`
/// equivalent, after the chosen mechanism has emitted, with `emitted` as
/// [`select_emitter`] returned it and `emission` as the mechanism produced
/// it -- or both `None` when no arm ran.
///
/// Three effects, in C's order:
///
/// 1. The mechanism's own `done` is stored. C has the emitter write
///    `authp->done` directly; here it arrives in the return value, so this
///    is where it lands. Basic and Bearer already set `done` in their arm and
///    report [`AuthEmission::is_done`] true, so the two agree.
/// 2. The diagnostic is emitted, verbatim:
///    `"%s auth using %s with user '%s'"` with `"Proxy"` or `"Server"`, the
///    mechanism [`AuthScheme::label`], and the username or `""` when there is
///    none. This reaches `--verbose` output, so its bytes are frozen.
/// 3. `multipass = !done` when a mechanism ran, and `multipass = FALSE` when
///    none did (`lib/http.c:734-737`).
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) fn finish_emission(
    state: &mut AuthState,
    proxy: bool,
    emitted: Option<AuthScheme>,
    emission: Option<&AuthEmission>,
    user: Option<&str>,
    tracer: &mut Tracer<'_>,
) {
    if let Some(result) = emission {
        state.done = result.is_done();
    }

    match emitted {
        Some(scheme) => {
            let side = if proxy { "Proxy" } else { "Server" };
            infof!(
                tracer,
                "{} auth using {} with user '{}'",
                side,
                scheme.label(),
                user.unwrap_or("")
            );
            state.multipass = !state.done;
        }
        None => state.multipass = false,
    }
}

/// The `"Proxy-"` prefix, or the empty string for the origin server.
///
/// C's `proxy ? "Proxy-" : ""`, the first argument of every
/// `"%sAuthorization: ..."` format string in the tree.
#[must_use]
pub(crate) const fn header_prefix(proxy: bool) -> &'static str {
    if proxy {
        "Proxy-"
    } else {
        ""
    }
}

/// Composes an authorization header line: the emission convention every
/// mechanism in this directory shares.
///
/// One space after the colon, one space after the scheme token, CRLF
/// terminated, and nothing else. Confirmed identical in all four C emitters,
/// which is why it is written once here rather than five times in five
/// siblings:
///
/// ```text
/// lib/http.c:285            "%sAuthorization: Basic %s\r\n"
/// lib/http_digest.c:161     "%sAuthorization: Digest %s\r\n"
/// lib/http_ntlm.c:207,225   "%sAuthorization: NTLM %s\r\n"
/// lib/http_negotiate.c:215  "%sAuthorization: Negotiate %s\r\n"
/// ```
///
/// The fifth, `http_output_bearer()` at `lib/http.c:315`, is
/// `"Authorization: Bearer %s\r\n"` -- with no `%s` prefix at all. That is
/// not a different convention: Bearer can never be a proxy mechanism
/// ([`proxy_auth_mask`]), so its prefix is unconditionally empty and the two
/// forms produce identical bytes. Passing `proxy = false` for Bearer is
/// therefore not a special case but the only reachable one, and a test
/// asserts the mask makes it so.
///
/// These bytes are compared literally: 168 fixtures carry an
/// `Authorization: ` line inside a byte-exact `<protocol>` block, joined and
/// compared as one string with no normalisation. A second space, a lower-case
/// scheme token or an `\n` line ending would fail them.
#[must_use]
#[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
pub(crate) fn authorization_header(
    proxy: bool,
    scheme: &str,
    credentials: &str,
) -> String {
    format!(
        "{}Authorization: {} {}\r\n",
        header_prefix(proxy),
        scheme,
        credentials
    )
}

// ---------------------------------------------------------------------------
// ORDERING 3 of 3 -- CHALLENGE PARSING.
// `authcmp()` and the five input handlers, `lib/http.c:867-1096`.
// ---------------------------------------------------------------------------

/// Whether `line` begins with the authentication scheme `scheme`.
///
/// Supersedes `authcmp()` (`lib/http.c:867-872`), whose body is two
/// conditions and whose comment names the second: "the auth string must not
/// have an alnum following".
///
/// ```c
/// size_t n = strlen(auth);
/// return curl_strnequal(auth, line, n) && !ISALNUM(line[n]);
/// ```
///
/// So: a **case-insensitive prefix match** that must **not** be followed by
/// an alphanumeric byte. The second condition is not a whitespace test and
/// must not be replaced by one -- the C admits every non-alphanumeric byte,
/// which includes the comma that separates two schemes on one header line and
/// the end of the line itself.
///
/// | `line`         | Matches `"Negotiate"` | Why |
/// |----------------|-----------------------|-----|
/// | `Negotiate `   | yes | space is not alphanumeric |
/// | `Negotiate,`   | yes | comma is not alphanumeric |
/// | `negotiate,`   | yes | the prefix match folds case |
/// | `Negotiate`    | yes | C reads the NUL terminator, which is not alnum |
/// | `Negotiate2`   | no  | `2` is alphanumeric |
/// | `NegotiateX`   | no  | `X` is alphanumeric |
/// | `Negotiat`     | no  | shorter than the prefix |
///
/// The fourth row is why the byte past the end is treated as zero here: C
/// indexes `line[n]` on a NUL-terminated string, and reading its terminator
/// is well-defined and returns a byte that `ISALNUM` rejects. A Rust slice
/// has no terminator, so `line.get(n)` standing in for it must map absence to
/// the same answer, which `unwrap_or(0)` does -- and 0 is not alphanumeric,
/// so a line that is exactly the scheme name matches, as it must.
#[must_use]
pub(crate) fn authcmp(scheme: &str, line: &[u8]) -> bool {
    // `curl_strnequal(auth, line, strlen(auth))`: `checkprefix` is that
    // comparison, with the same fold and the same length rule.
    if !checkprefix(scheme, line) {
        return false;
    }
    let following = line.get(scheme.len()).copied().unwrap_or(0);
    !is_alnum(following)
}

/// Decodes the challenge body of one mechanism: C's `Curl_input_*` family.
///
/// The three mechanisms that carry challenge data implement this --
/// `Curl_input_negotiate()`, `Curl_input_ntlm()` and `Curl_input_digest()` --
/// and [`input_auth`] calls it exactly where C calls them. Basic and Bearer
/// have no challenge body to decode: `auth_basic()` and `auth_bearer()`
/// (`lib/http.c:969-1002`) only set bits, so `decode` is never called for
/// them and an implementation may treat those schemes as unreachable.
///
/// The trait exists so that this file owns the *scan* -- the ordering, the
/// availability bookkeeping, the five diagnostics, the comma walk -- while
/// the siblings own the *decoding*, and so that the scan is testable without
/// any of them.
pub(crate) trait ChallengeDecoder {
    /// Decode `challenge`, which starts at the scheme token exactly as C's
    /// `auth` pointer does -- the handlers are passed the same pointer
    /// `authcmp` matched, not the text after the token.
    ///
    /// `Err(CURLcode::OutOfMemory)` is propagated to the caller unchanged and
    /// aborts the scan; every other error is reported through the mechanism's
    /// own diagnostic and sets `authproblem`, exactly as in C.
    fn decode(
        &mut self,
        scheme: AuthScheme,
        proxy: bool,
        challenge: &[u8],
    ) -> Result<(), CURLcode>;

    /// Whether SPNEGO is usable: `Curl_auth_is_spnego_supported()`.
    ///
    /// Part of the trait rather than a free function because
    /// `lib/http.c:882` consults it inside the scan, and a test needs to
    /// drive both answers without a GSS-API library present.
    /// [`is_spnego_supported`] is the production value.
    fn spnego_supported(&self) -> bool {
        is_spnego_supported()
    }

    /// Whether NTLM is usable: `Curl_auth_is_ntlm_supported()`
    /// (`lib/http.c:916`).
    fn ntlm_supported(&self) -> bool {
        is_ntlm_supported()
    }

    /// Whether Digest is usable: `Curl_auth_is_digest_supported()`
    /// (`lib/http.c:946`).
    fn digest_supported(&self) -> bool {
        is_digest_supported()
    }
}

/// `"NTLM authentication problem, ignoring."` -- `lib/http.c:928`.
///
/// The five diagnostics below reach the user through `--verbose`, so their
/// bytes are frozen output. They are named constants rather than inline
/// literals so that a test can assert on the exact text without restating it,
/// and so that a sibling module reporting the same condition cannot drift
/// from this file by a comma.
pub(crate) const NTLM_PROBLEM: &str = "NTLM authentication problem, ignoring.";

/// `"Ignoring duplicate digest auth header."` -- `lib/http.c:945`.
pub(crate) const DIGEST_DUPLICATE: &str =
    "Ignoring duplicate digest auth header.";

/// `"Digest authentication problem, ignoring."` -- `lib/http.c:960`.
pub(crate) const DIGEST_PROBLEM: &str =
    "Digest authentication problem, ignoring.";

/// `"Basic authentication problem, ignoring."` -- `lib/http.c:980`.
pub(crate) const BASIC_PROBLEM: &str =
    "Basic authentication problem, ignoring.";

/// `"Bearer authentication problem, ignoring."` -- `lib/http.c:998`.
pub(crate) const BEARER_PROBLEM: &str =
    "Bearer authentication problem, ignoring.";

/// What a challenge scan asks the caller to do beyond updating [`AuthState`].
///
/// Two of C's effects live on the easy handle and the connection rather than
/// in `struct auth`, so they are recorded here instead of reached for. Both
/// come from `auth_spnego()` (`lib/http.c:886-902`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChallengeOutcome {
    /// `data->req.newurl` must be freed and re-cloned from
    /// `data->state.url`.
    ///
    /// `lib/http.c:892-895`. The free-then-clone is not redundant: the field
    /// may already hold an allocation from a previous GSS round, and
    /// `lib/http.c:588-590` cites bug #2284386 for exactly that.
    pub(crate) refresh_url: bool,
    /// The per-connection Negotiate state advances to `GSS_AUTHRECV`:
    /// "we received a GSS auth token and we dealt with it fine"
    /// (`lib/http.c:897-898`).
    ///
    /// Which of `conn->http_negotiate_state` and
    /// `conn->proxy_negotiate_state` is meant follows from the `proxy`
    /// argument the scan was called with.
    pub(crate) negotiate_received: bool,
}

/// The mutable state one challenge scan touches, gathered in one place.
///
/// C reaches four separate places: `data->state.authhost` or
/// `authproxy`, `data->info.httpauthavail` or `proxyauthavail`,
/// `data->state.authproblem`, and `data->req.newurl` with the connection's
/// Negotiate state. Passing four `&mut` arguments plus a decoder plus a
/// tracer to one function is how a positional-argument mistake happens, so
/// they travel together.
///
/// The [`ChallengeOutcome`] is held **inside** the sink rather than returned,
/// and that is a fidelity requirement rather than a convenience: C applies
/// each handler's side effects as it goes, so a `CURLE_OUT_OF_MEMORY` raised
/// by a later mechanism on the same header line does not undo what an earlier
/// one already did. Returning the outcome would discard it on exactly that
/// path.
#[derive(Debug)]
pub(crate) struct ChallengeSink<'a> {
    /// The endpoint's `struct auth`.
    pub(crate) state: &'a mut AuthState,
    /// `data->info.httpauthavail` or `data->info.proxyauthavail`, which back
    /// `CURLINFO_HTTPAUTH_AVAIL` and `CURLINFO_PROXYAUTH_AVAIL`.
    ///
    /// Distinct from [`AuthState::avail`] and not a duplicate of it: this one
    /// accumulates across the whole transfer for the application to query,
    /// while `avail` is cleared by every [`pick_one_auth`] call.
    pub(crate) reported: &'a mut AuthMask,
    /// `data->state.authproblem`.
    pub(crate) auth_problem: &'a mut bool,
    /// The side effects the caller must apply, accumulated.
    pub(crate) outcome: ChallengeOutcome,
}

impl<'a> ChallengeSink<'a> {
    /// A sink over one endpoint's state, with no side effects recorded yet.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn new(
        state: &'a mut AuthState,
        reported: &'a mut AuthMask,
        auth_problem: &'a mut bool,
    ) -> Self {
        Self {
            state,
            reported,
            auth_problem,
            outcome: ChallengeOutcome::default(),
        }
    }
}

/// Parses one `WWW-Authenticate:` or `Proxy-Authenticate:` header line.
///
/// Supersedes `Curl_http_input_auth()` (`lib/http.c:1012-1096`) together with
/// all five of its per-mechanism handlers (`:876-1002`). `line` is the first
/// non-space byte of the header value and, as C's comment at `:1010` says,
/// "ends with a null byte without CR or LF present" -- here it is simply a
/// slice with no terminator and no line ending.
///
/// # The scan is not uniform, and the differences are all deliberate
///
/// * **The order is [`CHALLENGE_ORDER`]**, which is neither the preference
///   order nor the emission order.
/// * **Bearer's guard has no `!result` term.** `lib/http.c:1057-1074` chains
///   Negotiate, NTLM, Digest and Basic with `if(!result && authcmp(...))`;
///   Bearer at `:1073` is a bare `if(authcmp(...))`. Two consequences follow
///   and both are reproduced: a failure recorded by an earlier mechanism does
///   not stop Bearer from being tested at the same offset, and because
///   `auth_bearer()` always returns `CURLE_OK`, a Bearer match *discards* that
///   earlier failure. Measured, not assumed, and transcribed rather than
///   regularised.
/// * **Digest's duplicate rule short-circuits.** `lib/http.c:944-946` is
///   `if(avail & DIGEST) infof(duplicate); else if(supported) { ... }` -- an
///   `else if`, so on a duplicate the bit is not re-set, the decoder is not
///   called and nothing else happens.
/// * **Basic and Bearer treat "picked" as failure.** They OR their bit in
///   unconditionally, and then, if that mechanism was the one already picked,
///   they clear `avail` to [`AuthMask::NONE`] entirely and set
///   `authproblem`: we asked for it and still got a 40x, so the credentials
///   are wrong (`lib/http.c:975-982`, `:994-1000`).
/// * **`CURLE_OUT_OF_MEMORY` is the one error that propagates.** Every
///   handler returns it directly and every other failure becomes a
///   diagnostic plus `authproblem` (`lib/http.c:926-929`, `:958-961`).
///
/// # Multiple schemes on one line
///
/// `lib/http.c:1080-1086`: after testing all five at the current offset, the
/// walk advances past the next comma and skips blanks. A line with no further
/// comma ends the loop.
///
/// # Errors
///
/// `CURLcode::OutOfMemory` when a decoder reports it. Side effects already
/// recorded in `sink` survive, exactly as they do in C -- see
/// [`ChallengeSink`].
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) fn input_auth<D: ChallengeDecoder + ?Sized>(
    line: &[u8],
    proxy: bool,
    sink: &mut ChallengeSink<'_>,
    decoder: &mut D,
    tracer: &mut Tracer<'_>,
) -> Result<(), CURLcode> {
    let mut cursor = line;

    // `while(*auth)`: C stops at the terminator, so an empty remainder ends
    // the walk.
    while !cursor.is_empty() {
        let mut result: Result<(), CURLcode> = Ok(());

        if cfg!(feature = "negotiate") && authcmp("Negotiate", cursor) {
            result = scan_negotiate(cursor, proxy, sink, decoder);
        }

        if result.is_ok() && authcmp("NTLM", cursor) {
            result = scan_ntlm(cursor, proxy, sink, decoder, tracer);
        }

        if result.is_ok() && authcmp("Digest", cursor) {
            result = scan_digest(cursor, proxy, sink, decoder, tracer);
        }

        if result.is_ok() && authcmp("Basic", cursor) {
            scan_bit_only(AuthScheme::Basic, sink, BASIC_PROBLEM, tracer);
        }

        // NO `result.is_ok()` term, and the assignment that follows is not
        // redundant: `auth_bearer()` returns `CURLE_OK`, so C's
        // `result = auth_bearer(...)` overwrites any earlier failure.
        // `lib/http.c:1073-1074`.
        if authcmp("Bearer", cursor) {
            scan_bit_only(AuthScheme::Bearer, sink, BEARER_PROBLEM, tracer);
            result = Ok(());
        }

        result?;

        // There may be multiple methods on one line, so keep reading.
        // `lib/http.c:1080-1086`.
        match cursor.iter().position(|byte| *byte == b',') {
            Some(comma) => cursor = &cursor[comma + 1..],
            None => break,
        }
        str_passblanks(&mut cursor);
    }

    Ok(())
}

/// `auth_spnego()` -- `lib/http.c:876-905`.
///
/// The gate is `(authp->avail & CURLAUTH_NEGOTIATE) ||
/// Curl_auth_is_spnego_supported()`: an offer already recorded keeps the
/// mechanism live even where the runtime probe says no, which matters because
/// the probe is cached and the offer is per-response.
///
/// This handler has no diagnostic of its own. On success it clears
/// `authproblem` -- the only handler that clears it -- and records the two
/// side effects in [`ChallengeOutcome`]; on failure it sets it. Neither path
/// emits text.
fn scan_negotiate<D: ChallengeDecoder + ?Sized>(
    challenge: &[u8],
    proxy: bool,
    sink: &mut ChallengeSink<'_>,
    decoder: &mut D,
) -> Result<(), CURLcode> {
    if !(sink.state.avail.intersects(AuthMask::NEGOTIATE)
        || decoder.spnego_supported())
    {
        return Ok(());
    }

    *sink.reported |= AuthMask::NEGOTIATE;
    sink.state.avail |= AuthMask::NEGOTIATE;

    if sink.state.picked == AuthMask::NEGOTIATE {
        match decoder.decode(AuthScheme::Negotiate, proxy, challenge) {
            Ok(()) => {
                sink.outcome.refresh_url = true;
                *sink.auth_problem = false;
                sink.outcome.negotiate_received = true;
            }
            // C sets `authproblem` and returns CURLE_OK -- the scan
            // continues. The one error that escapes `auth_spnego()` is the
            // allocation failure of the URL clone at `lib/http.c:894-895`,
            // and that clone is the caller's to perform.
            Err(_) => *sink.auth_problem = true,
        }
    }
    Ok(())
}

/// `auth_ntlm()` -- `lib/http.c:909-934`.
///
/// C's comment at `:915` reads "NTLM support requires the SSL crypto libs".
/// It does not any more, and the reason is worth recording because it changes
/// what the gate means: NTLM here is pure Rust over `des`, `md4`, `md-5` and
/// `hmac`, all of them unconditional dependencies of this crate, so
/// [`is_ntlm_supported`] has no library to be unavailable and returns `true`
/// exactly as the C function does.
fn scan_ntlm<D: ChallengeDecoder + ?Sized>(
    challenge: &[u8],
    proxy: bool,
    sink: &mut ChallengeSink<'_>,
    decoder: &mut D,
    tracer: &mut Tracer<'_>,
) -> Result<(), CURLcode> {
    if !(sink.state.avail.intersects(AuthMask::NTLM)
        || decoder.ntlm_supported())
    {
        return Ok(());
    }

    *sink.reported |= AuthMask::NTLM;
    sink.state.avail |= AuthMask::NTLM;

    if sink.state.picked == AuthMask::NTLM {
        // NTLM authentication is picked and activated.
        match decoder.decode(AuthScheme::Ntlm, proxy, challenge) {
            Ok(()) => *sink.auth_problem = false,
            Err(CURLcode::OutOfMemory) => return Err(CURLcode::OutOfMemory),
            Err(_) => {
                infof!(tracer, "{}", NTLM_PROBLEM);
                *sink.auth_problem = true;
            }
        }
    }
    Ok(())
}

/// `auth_digest()` -- `lib/http.c:938-965`.
///
/// Carries C's comment at `:952-955` because it explains why the decoder runs
/// even when Digest is not the picked mechanism: "We call this function on
/// input Digest headers even if Digest authentication is not activated yet,
/// as we need to store the incoming data from this header in case we are
/// going to use Digest". The nonce and realm of a challenge that arrives
/// before arbitration are still the ones a later Digest response must quote.
///
/// Note what the duplicate branch does *not* do: it is an `else if`, so on a
/// second Digest header the bit is not re-set, the decoder is not called, and
/// the only effect is the diagnostic.
fn scan_digest<D: ChallengeDecoder + ?Sized>(
    challenge: &[u8],
    proxy: bool,
    sink: &mut ChallengeSink<'_>,
    decoder: &mut D,
    tracer: &mut Tracer<'_>,
) -> Result<(), CURLcode> {
    if sink.state.avail.intersects(AuthMask::DIGEST) {
        infof!(tracer, "{}", DIGEST_DUPLICATE);
    } else if decoder.digest_supported() {
        *sink.reported |= AuthMask::DIGEST;
        sink.state.avail |= AuthMask::DIGEST;

        match decoder.decode(AuthScheme::Digest, proxy, challenge) {
            Ok(()) => {}
            Err(CURLcode::OutOfMemory) => return Err(CURLcode::OutOfMemory),
            Err(_) => {
                infof!(tracer, "{}", DIGEST_PROBLEM);
                *sink.auth_problem = true;
            }
        }
    }
    Ok(())
}

/// `auth_basic()` and `auth_bearer()` -- `lib/http.c:969-1002`.
///
/// The two functions are byte-for-byte identical apart from the bit and the
/// diagnostic, so they are one function here with both as parameters. Neither
/// decodes anything: there is no challenge body to read, which is why
/// [`ChallengeDecoder::decode`] is never called for these two schemes.
///
/// The bit is ORed in unconditionally. Then, if this mechanism was already
/// the picked one, C's comment states the inference: "We asked for Basic
/// authentication but got a 40X back anyway, which basically means our
/// name+password is not valid" -- so `avail` is cleared *entirely*, not just
/// of this bit, the diagnostic is emitted and `authproblem` is set. Clearing
/// all of `avail` is what stops [`pick_one_auth`] from falling back to
/// another mechanism the same response offered.
fn scan_bit_only(
    scheme: AuthScheme,
    sink: &mut ChallengeSink<'_>,
    problem: &'static str,
    tracer: &mut Tracer<'_>,
) {
    let bit = scheme.mask();
    *sink.reported |= bit;
    sink.state.avail |= bit;

    if sink.state.picked == bit {
        sink.state.avail = AuthMask::NONE;
        infof!(tracer, "{}", problem);
        *sink.auth_problem = true;
    }
}

// ---------------------------------------------------------------------------
// ARBITRATION. `Curl_http_auth_act()`, `lib/http.c:536-620`, and the outer
// driver `Curl_http_output_auth()`, `lib/http.c:756-842`.
// ---------------------------------------------------------------------------

/// The response facts arbitration reads.
///
/// Each field is one term of `Curl_http_auth_act()`'s conditions, named for
/// the C expression it stands for. `httpcode` is `int` in C
/// (`data->req.httpcode`) and `i32` here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuthActInput {
    /// `data->req.httpcode`: the status code of the response just parsed.
    pub(crate) httpcode: i32,
    /// `data->req.authneg`: this request was a zero-length probe sent purely
    /// to learn which methods the endpoint offers.
    pub(crate) authneg: bool,
    /// `data->state.aptr.user` is non-NULL.
    pub(crate) have_user: bool,
    /// `data->set.str[STRING_BEARER]` is non-NULL.
    pub(crate) have_bearer: bool,
    /// `conn->bits.proxy_user_passwd`.
    pub(crate) proxy_user_passwd: bool,
    /// `data->set.http_fail_on_error`, from `--fail`.
    pub(crate) fail_on_error: bool,
    /// `data->req.httpversion_sent`, in C's tens-and-units encoding: 11 is
    /// HTTP/1.1, 20 is HTTP/2, 30 is HTTP/3.
    ///
    /// `lib/http.c:563` tests `> 11`, so the encoding is load-bearing and is
    /// carried rather than converted.
    pub(crate) httpversion_sent: u32,
    /// `data->state.authhost.done`, read by the no-authentication-needed
    /// branch at `lib/http.c:597-599`.
    pub(crate) host_done: bool,
    /// Whether `data->state.httpreq` is `HTTPREQ_GET` or `HTTPREQ_HEAD`.
    ///
    /// C compares against the two enumerators directly
    /// (`lib/http.c:604-605`); the distinction auth makes is only "can this
    /// request be replaced by a zero-length probe", so the predicate is
    /// carried rather than a copy of `Curl_HttpReq`, which belongs to the
    /// transfer layer.
    pub(crate) is_get_or_head: bool,
}

/// What arbitration decided, for the caller to apply.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuthActOutcome {
    /// A method was picked for the origin server.
    pub(crate) picked_host: bool,
    /// A method was picked for the proxy.
    pub(crate) picked_proxy: bool,
    /// `data->info.httpauthpicked`, set only when a host method was picked.
    pub(crate) host_picked: Option<AuthMask>,
    /// `data->info.proxyauthpicked`, set only when a proxy method was picked.
    pub(crate) proxy_picked: Option<AuthMask>,
    /// The request must be rewound and re-sent: `http_perhapsrewind()` then
    /// free `data->req.newurl` and clone `data->state.url` into it.
    ///
    /// `lib/http.c:583-596`. The clone is separate from the free for the
    /// reason C records at `:588-590`: with GSS authentication the field is
    /// already allocated, "as figured out in bug #2284386".
    pub(crate) rewind_and_refresh_url: bool,
    /// `data->req.newurl` must be cloned, and `authhost.done` set, without a
    /// rewind: the no-known-authentication branch at `lib/http.c:597-612`.
    pub(crate) refresh_url_only: bool,
    /// NTLM was picked over a connection already speaking better than
    /// HTTP/1.1, so the connection must be closed and renegotiated.
    ///
    /// See [`NTLM_FORCE_HTTP11`] and [`NTLM_FORCE_CLOSE_REASON`].
    pub(crate) force_http11: bool,
}

/// `"Forcing HTTP/1.1 for NTLM"` -- `lib/http.c:564`, an `infof()` string and
/// therefore frozen `--verbose` output.
pub(crate) const NTLM_FORCE_HTTP11: &str = "Forcing HTTP/1.1 for NTLM";

/// `"Force HTTP/1.1 connection"` -- `lib/http.c:565`, the reason string
/// `connclose()` records.
///
/// Reasons reach the trace log through the connection-shutdown path rather
/// than through `infof()` directly, which is why it is a separate constant
/// from [`NTLM_FORCE_HTTP11`] even though the two are always emitted
/// together.
#[allow(dead_code)] // Consumer is `crate::conn::pool`, not yet landed.
pub(crate) const NTLM_FORCE_CLOSE_REASON: &str = "Force HTTP/1.1 connection";

/// C's tens-and-units encoding of HTTP/1.1, the threshold
/// `lib/http.c:563` compares against.
pub(crate) const HTTP_VERSION_1_1: u32 = 11;

/// Decides which authentication methods to use once every response header has
/// been received.
///
/// Supersedes `Curl_http_auth_act()` (`lib/http.c:536-620`). It runs after
/// the headers are parsed, arbitrates the origin and the proxy independently,
/// and reports what the caller must then do to the request.
///
/// # Errors
///
/// `CURLcode::HttpReturnedError` in two cases, and they are distinct:
///
/// 1. `authproblem` was already set on entry *and* `--fail` is in force
///    (`lib/http.c:551-552`). Note the asymmetry -- without `--fail` this is
///    `Ok(())` and arbitration is skipped entirely, so a pre-existing problem
///    suppresses a fresh pick either way.
/// 2. `http_should_fail()` says the response is terminal
///    (`lib/http.c:613-617`), which the caller evaluates and passes back in;
///    that predicate reads resume state and the request method and so belongs
///    to the transfer layer, not here.
///
/// `CURLcode::OutOfMemory` is *not* raised here even though C can return it
/// at `:594` and `:608`: both come from the URL clone, which this function
/// requests through [`AuthActOutcome`] rather than performing.
///
/// # The mask is narrowed twice, and the second narrowing is the invariant
///
/// `authmask` starts as every bit set and loses `BEARER` when no token was
/// configured (`lib/http.c:542-545`). The proxy arbitration then loses it
/// again, unconditionally, through [`proxy_auth_mask`]. Bearer is therefore
/// unreachable for a proxy whatever the application asked for.
///
/// # 1xx responses are not authentication events
///
/// `lib/http.c:547-549` returns early for 100 through 199, commented "this is
/// a transient response code, ignore". An `Expect: 100-continue` handshake
/// must not consume the server's offer or clear `avail`.
#[allow(dead_code)] // Consumer is `crate::transfer`, not yet landed.
pub(crate) fn auth_act(
    pair: &mut AuthStatePair,
    input: &AuthActInput,
    auth_problem: &mut bool,
    should_fail: bool,
    tracer: &mut Tracer<'_>,
) -> Result<AuthActOutcome, CURLcode> {
    let mut outcome = AuthActOutcome::default();

    // `unsigned long authmask = ~0UL;` then clear BEARER when no token.
    // `lib/http.c:542-545`.
    let mut authmask = AuthMask::from_bits(u32::MAX);
    if !input.have_bearer {
        authmask = authmask.difference(AuthMask::BEARER);
    }

    // This is a transient response code, ignore. `lib/http.c:547-549`.
    if (100..=199).contains(&input.httpcode) {
        return Ok(outcome);
    }

    if *auth_problem {
        return if input.fail_on_error {
            Err(CURLcode::HttpReturnedError)
        } else {
            Ok(outcome)
        };
    }

    // Host. `lib/http.c:554-569`.
    if (input.have_user || input.have_bearer)
        && (input.httpcode == 401 || (input.authneg && input.httpcode < 300))
    {
        outcome.picked_host = pick_one_auth(&mut pair.host, authmask);
        if outcome.picked_host {
            outcome.host_picked = Some(pair.host.picked);
        } else {
            *auth_problem = true;
        }

        // NTLM does not work over a multiplexed connection, so the version
        // is clamped and the connection is closed rather than reused.
        // `lib/http.c:562-568`. Note that C tests this OUTSIDE the
        // pick-succeeded branch, on `picked` rather than on the return
        // value, so a `PICKNONE` result reaches it too -- and cannot match,
        // because `PICKNONE` is bit 30.
        if pair.host.picked == AuthMask::NTLM
            && input.httpversion_sent > HTTP_VERSION_1_1
        {
            infof!(tracer, "{}", NTLM_FORCE_HTTP11);
            outcome.force_http11 = true;
        }
    }

    // Proxy. `lib/http.c:571-580`.
    if input.proxy_user_passwd
        && (input.httpcode == 407 || (input.authneg && input.httpcode < 300))
    {
        outcome.picked_proxy =
            pick_one_auth(&mut pair.proxy, proxy_auth_mask(authmask));
        if outcome.picked_proxy {
            outcome.proxy_picked = Some(pair.proxy.picked);
        } else {
            *auth_problem = true;
        }
    }

    if outcome.picked_host || outcome.picked_proxy {
        outcome.rewind_and_refresh_url = true;
    } else if input.httpcode < 300 && !input.host_done && input.authneg {
        // No (known) authentication available, authentication is not "done"
        // yet and no authentication seems to be required and we did not try
        // HEAD or GET. `lib/http.c:597-612`.
        if !input.is_get_or_head {
            outcome.refresh_url_only = true;
            pair.host.done = true;
        }
    }

    if should_fail {
        return Err(CURLcode::HttpReturnedError);
    }

    Ok(outcome)
}

/// Whether `Curl_http_output_auth()` has anything to do at all.
///
/// `lib/http.c:774-789`. When every term is false C marks **both** states
/// done and returns: "no authentication with no user or password". The
/// Negotiate terms are part of the disjunction because a Kerberos credentials
/// cache supplies the identity, so `want & CURLAUTH_NEGOTIATE` is sufficient
/// on its own with no username configured anywhere -- which is also why
/// [`user_contains_domain`] accepts an absent username under the same
/// feature.
#[must_use]
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) fn credentials_offered(
    pair: &AuthStatePair,
    httpproxy: bool,
    guards: &EmissionGuards,
) -> bool {
    if httpproxy && guards.proxy_user_passwd {
        return true;
    }
    if guards.have_user || guards.have_bearer {
        return true;
    }
    cfg!(feature = "negotiate")
        && (pair.host.want.intersects(AuthMask::NEGOTIATE)
            || pair.proxy.want.intersects(AuthMask::NEGOTIATE))
}

/// Seeds `picked` from `want` before the first round trip.
///
/// `lib/http.c:791-801`, whose comment is the whole rule: "The app has
/// selected one or more methods, but none has been picked so far by a server
/// round-trip. Then we set the picked one to the want one, and if this is one
/// single bit it will be used instantly."
///
/// So a single-bit `want` skips negotiation entirely -- the request carries
/// the credentials on its first attempt -- while a multi-bit `want` produces
/// a `picked` that matches no emission arm, sends nothing, and waits for the
/// 401 that drives [`pick_one_auth`]. [`AuthMask::is_single`] is that test.
///
/// The guard is `want && !picked`: an already-picked state is never
/// re-seeded, which is what stops a completed arbitration from being undone
/// on the next request over the same handle.
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) fn seed_picked_from_want(pair: &mut AuthStatePair) {
    for state in [&mut pair.host, &mut pair.proxy] {
        if !state.want.is_empty() && state.picked.is_empty() {
            state.picked = state.want;
        }
    }
}

/// Whether the next request must be a zero-length probe: C's
/// `data->req.authneg`.
///
/// `lib/http.c:830-839`. When a multi-pass negotiation is in progress on
/// either endpoint and the request would otherwise carry a body, curl sends
/// "a PUT or POST with content-length zero as a 'probe'" instead, so that the
/// body is not uploaded once per negotiation round. `GET` and `HEAD` never
/// need it because they carry no body to repeat.
#[must_use]
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) fn negotiation_probe_wanted(
    pair: &AuthStatePair,
    is_get_or_head: bool,
) -> bool {
    let host_pending = pair.host.multipass && !pair.host.done;
    let proxy_pending = pair.proxy.multipass && !pair.proxy.done;
    (host_pending || proxy_pending) && !is_get_or_head
}

// ---------------------------------------------------------------------------
// SHARED PLUMBING. `lib/vauth/vauth.c` in full.
// ---------------------------------------------------------------------------

/// The endpoint the transfer *started* at: C's `data->state.first_*` fields.
///
/// `lib/urldata.h:956-958`. Recorded before the first redirect is followed and
/// never updated afterwards, which is what makes it usable as the comparison
/// point in [`allowed_to_host`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FirstEndpoint<'a> {
    /// `data->state.first_host`, `NULL` until the first request has a host.
    pub(crate) host: Option<&'a [u8]>,
    /// `data->state.first_remote_port`, an `int` in C.
    pub(crate) port: i32,
    /// `data->state.first_remote_protocol`, a `curl_prot_t` -- which is
    /// `uint32_t` under the `PROTO_TYPE_SMALL` that `lib/urldata.h:80-87`
    /// defines, so `u32` here is the width C actually compiles with. It holds
    /// a single `CURLPROTO_*` bit, not a set.
    pub(crate) protocol: u32,
}

/// The endpoint the transfer is about to talk to: C's `conn->host.name`,
/// `conn->remote_port` and `conn->scheme->protocol`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CurrentEndpoint<'a> {
    /// `conn->host.name`.
    pub(crate) host: &'a [u8],
    /// `conn->remote_port`.
    pub(crate) port: i32,
    /// `conn->scheme->protocol`.
    pub(crate) protocol: u32,
}

/// Whether authentication, cookies or other sensitive data may (still) be sent
/// to this host.
///
/// Supersedes `Curl_auth_allowed_to_host()` (`lib/vauth/vauth.c:138-147`),
/// whose own summary is carried because it states the scope precisely: it
/// "tells if authentication, cookies or other 'sensitive data' can (still) be
/// sent to this host".
///
/// ```text
/// !this_is_a_follow
///   || allow_auth_to_other_hosts
///   || (first_host && curl_strequal(first_host, conn->host.name)
///       && first_remote_port == conn->remote_port
///       && first_remote_protocol == conn->scheme->protocol)
/// ```
///
/// # All three of host, port and protocol must match
///
/// This is a security boundary, not a convenience check. A redirect that
/// changes **only** the port, or **only** the scheme, must not carry the
/// credentials across -- an `https://` to `http://` downgrade on the same host
/// and port would otherwise put the `Authorization:` header on the wire in
/// clear. Dropping any one of the three comparisons is a credential leak and a
/// behaviour change, and the tests assert each of the three independently.
///
/// The host comparison is case-insensitive (`curl_strequal`, which is
/// `crate::util::strcase::casecompare`) because DNS names are; the port and
/// protocol comparisons are exact.
///
/// A `first_host` of `None` makes the third term false. That is C's
/// short-circuit on a NULL pointer and it is the conservative answer: with no
/// recorded origin there is nothing to prove the current host is the same one.
#[must_use]
#[allow(dead_code)] // Consumers are `crate::protocols::http1` and the cookie
                    // engine, neither landed.
pub(crate) fn allowed_to_host(
    this_is_a_follow: bool,
    allow_auth_to_other_hosts: bool,
    first: &FirstEndpoint<'_>,
    current: &CurrentEndpoint<'_>,
) -> bool {
    if !this_is_a_follow || allow_auth_to_other_hosts {
        return true;
    }

    match first.host {
        Some(host) => {
            casecompare(host, current.host)
                && first.port == current.port
                && first.protocol == current.protocol
        }
        None => false,
    }
}

/// Builds a service principal name.
///
/// Supersedes `Curl_auth_build_spn()` (`lib/vauth/vauth.c:47-63`). Three
/// forms, in this order, each with C's own annotation:
///
/// ```text
/// host && realm  ->  "{service}/{host}@{realm}"   (Not currently used)
/// host           ->  "{service}/{host}"           (Not used by GSS-API)
/// realm          ->  "{service}@{realm}"          (Not used by Windows SSPI)
/// neither        ->  None
/// ```
///
/// # THE ARGUMENT ORDER IS A TRAP, AND THE TRAP IS LOAD-BEARING
///
/// The Negotiate and Kerberos-5 call sites pass the **host in the realm
/// slot**:
///
/// ```text
/// lib/vauth/spnego_gssapi.c:108   Curl_auth_build_spn(service, NULL, host)
/// lib/vauth/krb5_gssapi.c:100     Curl_auth_build_spn(service, NULL, host)
/// ```
///
/// so the *third* branch fires and the SPN is `"<service>@<host>"`, which is
/// then imported with `GSS_C_NT_HOSTBASED_SERVICE` -- the name type that
/// expects exactly that spelling. Digest and the SSPI backends pass the host
/// in the host slot instead (`lib/vauth/digest.c:420` and friends) and get
/// `"<service>/<host>"`.
///
/// A reader who "corrects" either call site, or who folds the three branches
/// into a single `service/host` form, breaks Kerberos against every real KDC
/// -- and breaks it at the point of ticket acquisition, far from this
/// function. The three-branch shape and the odd call order are therefore both
/// preserved, and `negotiate.rs` is to repeat the reason at its call site.
///
/// The `USE_WINDOWS_SSPI` arm (`lib/vauth/vauth.c:65-90`), which formulates a
/// UTF-8 SPN and converts it to `TCHAR`, is out of scope: SSPI is a Windows
/// mechanism and no mandated target is Windows.
#[must_use]
#[allow(dead_code)] // Consumer is `crate::auth::negotiate`, not yet landed.
pub(crate) fn build_spn(
    service: &str,
    host: Option<&str>,
    realm: Option<&str>,
) -> Option<String> {
    match (host, realm) {
        // service/host@realm -- not currently used by any call site.
        (Some(host), Some(realm)) => Some(format!("{service}/{host}@{realm}")),
        // service/host -- not used by GSS-API.
        (Some(host), None) => Some(format!("{service}/{host}")),
        // service@realm -- not used by Windows SSPI. This is the branch the
        // GSS-API call sites reach, with the host in the realm slot.
        (None, Some(realm)) => Some(format!("{service}@{realm}")),
        (None, None) => None,
    }
}

/// The separators that introduce a Windows domain in a username.
///
/// `strpbrk(user, "\\/@")` at `lib/vauth/vauth.c:120`. Three forms are
/// recognised, and C names each: `Domain\User` (down-level logon name),
/// `Domain/User` ("curl Down-level format - for compatibility with existing
/// code") and `User@Domain` (user principal name).
/// Spelled as a byte-string literal so that it reads as C's argument does; the
/// leading `\\` is one backslash, escaped, exactly as in the C source.
const DOMAIN_SEPARATORS: [u8; 3] = *b"\\/@";

/// Whether `user` carries a Windows domain name or a user principal name.
///
/// Supersedes `Curl_auth_user_contains_domain()`
/// (`lib/vauth/vauth.c:114-132`).
///
/// A separator from [`DOMAIN_SEPARATORS`] must be present and must be
/// **neither the first nor the last byte**. C spells the bound as pointer
/// arithmetic:
///
/// ```c
/// const char *p = strpbrk(user, "\\/@");
/// valid = (p != NULL && p > user && p < user + strlen(user) - 1);
/// ```
///
/// `p > user` excludes a leading separator -- there would be no domain before
/// it -- and `p < user + strlen(user) - 1` excludes a trailing one, which
/// would leave no user after it. Only the **first** separator is examined,
/// because that is what `strpbrk` returns.
///
/// # An absent or empty username is valid under `negotiate`
///
/// C's `#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)` arm returns
/// `TRUE` for an empty username, and its comment gives the reason: "User and
/// domain are obtained from the GSS-API credentials cache or the currently
/// logged in user from Windows". So with a Kerberos credentials cache present
/// there is nothing for the caller to supply, and demanding a domain in a
/// username that will not be used would refuse a working configuration.
///
/// `HAVE_GSSAPI` becomes the default-off `negotiate` feature; the Windows SSPI
/// half of the same condition has no target. Without the feature the answer
/// for an absent username is `false`, which is C's behaviour in a build with
/// neither.
#[must_use]
#[allow(dead_code)] // Consumer is `crate::auth::ntlm`, not yet landed.
pub(crate) fn user_contains_domain(user: Option<&[u8]>) -> bool {
    match user {
        Some(user) if !user.is_empty() => {
            let found = user
                .iter()
                .position(|byte| DOMAIN_SEPARATORS.contains(byte));
            match found {
                // `p > user`: not the first byte. `p < user + len - 1`: not
                // the last. Written as `at + 1 < len` so that a one-byte
                // username needs no special case -- `0 + 1 < 1` is false,
                // and C's `p < user + 0` is false for the same input.
                Some(at) => at > 0 && at + 1 < user.len(),
                None => false,
            }
        }
        // NULL or empty: the GSS-API credentials cache supplies the identity.
        _ => cfg!(feature = "negotiate"),
    }
}

/// Where a mechanism's negotiation state lives.
///
/// The distinction is not decorative: it decides when credentials are reused,
/// and it is visible. `Curl_auth_ntlm_remove()` removes *connection* metadata
/// while `Curl_http_auth_cleanup_digest()` clears two *easy-handle* fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
pub(crate) enum StateScope {
    /// Per CONNECTION, with separate origin and proxy instances.
    ///
    /// NTLM and Negotiate. Both bind their handshake to the TCP connection --
    /// NTLM's three-message exchange and SPNEGO's token sequence are
    /// meaningless across a new one -- which is why C stores them under two
    /// connection metadata keys each and why NTLM forces HTTP/1.1
    /// ([`NTLM_FORCE_HTTP11`]).
    Connection,
    /// Per TRANSFER, with separate origin and proxy instances.
    ///
    /// Digest alone: `data->state.digest` and `data->state.proxydigest`. The
    /// challenge is a nonce and a realm, not a bound handshake, so it
    /// survives a new connection and must not survive a new easy handle.
    Transfer,
}

/// The scope of a scheme's negotiation state, or `None` when it keeps none.
///
/// Basic, Bearer and AWS SigV4 store nothing: each recomputes its credential
/// from the configured secret on every request, which is why they have no
/// metadata key in `lib/vauth/vauth.h` and no cleanup function anywhere.
#[must_use]
#[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
pub(crate) const fn state_scope(scheme: AuthScheme) -> Option<StateScope> {
    match scheme {
        AuthScheme::Ntlm | AuthScheme::Negotiate => {
            Some(StateScope::Connection)
        }
        AuthScheme::Digest => Some(StateScope::Transfer),
        AuthScheme::Basic | AuthScheme::Bearer | AuthScheme::AwsSigv4 => None,
    }
}

/// The origin and proxy instances of one mechanism's negotiation state.
///
/// Supersedes the string-keyed metadata map of `lib/vauth/vauth.c`:
/// `Curl_auth_ntlm_get()` and `Curl_auth_ntlm_remove()` (`:160-176`) and
/// `Curl_auth_nego_get()` (`:238-248`), each selecting between two keys on a
/// `bool proxy` argument.
///
/// # The keys are deliberately not reproduced
///
/// Six exist, and two carry an upstream typo -- `"meta:auth:ntml:conn"` and
/// `"meta:auth:ntml-proxy:conn"` (`lib/vauth/vauth.h:159,161`) spell it
/// `ntml`. The typo is recorded so that a future reader knows it was seen
/// rather than missed; it is also entirely harmless, because the keys are
/// internal to one process -- never on the wire, never in the ABI, never in a
/// file format -- so nothing observable depends on their spelling.
///
/// What replaces them is a typed field per side. That removes the `void *`
/// entry value and the cast at every retrieval, which is the transformation
/// that makes this crate's zero-`unsafe` invariant reachable rather than
/// aspirational, and it removes the four file-private destructors with it:
/// `ntlm_conn_dtor`, `krb5_conn_dtor`, `gsasl_conn_dtor` and `nego_conn_dtor`
/// all become ordinary Rust ownership, running when the owner is dropped.
///
/// Kerberos-5 and GSASL have one key each and no proxy instance
/// (`lib/vauth/vauth.h:126,237`); both are out of scope -- GSASL was dropped
/// with libgsasl and Kerberos-5 serves the SASL protocols -- so this type is
/// deliberately a pair rather than a map keyed by scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // Consumers are `crate::auth::ntlm` and `::negotiate`, not yet landed.
pub(crate) struct MechanismSlots<T> {
    /// The origin-server instance: C's key without the `-proxy` infix.
    origin: Option<T>,
    /// The proxy instance.
    proxy: Option<T>,
}

impl<T> MechanismSlots<T> {
    /// Both slots empty.
    ///
    /// C has no equivalent: an absent metadata entry *is* the empty state, and
    /// `Curl_auth_*_get()` creates one on first use.
    #[must_use]
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) const fn empty() -> Self {
        Self {
            origin: None,
            proxy: None,
        }
    }

    /// The instance for one side, if it has been created.
    #[must_use]
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) fn peek(&self, proxy: bool) -> Option<&T> {
        if proxy {
            self.proxy.as_ref()
        } else {
            self.origin.as_ref()
        }
    }

    /// Discards one side's instance: `Curl_auth_ntlm_remove()`.
    ///
    /// Returns it rather than dropping it in place so that a caller which
    /// needs to observe the discarded state can, and so that the drop happens
    /// at the call site where its timing is visible. C's
    /// `Curl_conn_meta_remove()` runs the destructor immediately; dropping the
    /// returned value does the same thing at the same point.
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) fn remove(&mut self, proxy: bool) -> Option<T> {
        if proxy {
            self.proxy.take()
        } else {
            self.origin.take()
        }
    }

    /// The instance for one side, creating a default one if absent.
    ///
    /// This is `Curl_auth_ntlm_get()` and `Curl_auth_nego_get()`, whose
    /// `calloc()`-then-`Curl_conn_meta_set()` becomes an
    /// [`Option::get_or_insert_with`]. C returns `NULL` when either the
    /// allocation or the insertion fails; neither can fail here, so the
    /// return type is not an `Option` and the `CURLE_OUT_OF_MEMORY` its
    /// callers raise on `NULL` has no path to reach.
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) fn get_or_default(&mut self, proxy: bool) -> &mut T
    where
        T: Default,
    {
        if proxy {
            self.proxy.get_or_insert_with(T::default)
        } else {
            self.origin.get_or_insert_with(T::default)
        }
    }
}

/// Whether Digest authentication is usable.
///
/// `Curl_auth_is_digest_supported()` (`lib/vauth/digest.c:311-314`) returns
/// `TRUE` unconditionally, and so does this. Digest here is MD5 and
/// SHA-256/512-256 over RustCrypto crates that are unconditional dependencies
/// of this crate, so there is nothing to be unavailable.
///
/// `lib/vauth/vauth.h:120` collapses the declaration to `#define ... FALSE`
/// under `CURL_DISABLE_DIGEST_AUTH`. **That is not translated into a Cargo
/// feature.** The crate's feature vocabulary is fixed at fifteen names and
/// none of them is `digest`; inventing one would add a build configuration
/// nothing tests and a `Features:` banner row nothing earns.
#[must_use]
pub(crate) const fn is_digest_supported() -> bool {
    true
}

/// Whether NTLM authentication is usable.
///
/// `Curl_auth_is_ntlm_supported()` (`lib/vauth/ntlm.c:315-318`) returns `TRUE`
/// unconditionally. The C build reaches that function only under `USE_NTLM`,
/// which required an SSL library for DES and MD4; here those come from the
/// `des`, `md4`, `md-5` and `hmac` crates, which are unconditional, so the
/// predicate is unconditionally true and `USE_NTLM` has no successor.
#[must_use]
pub(crate) const fn is_ntlm_supported() -> bool {
    true
}

/// Whether SPNEGO (Negotiate) authentication is usable **in this process**.
///
/// `Curl_auth_is_spnego_supported()` (`lib/vauth/spnego_gssapi.c:49-52`)
/// returns `TRUE` unconditionally, but that answer is only as good as the
/// build's `#ifdef USE_SPNEGO`: the C function does not exist at all without
/// it. Two things must hold here, and neither is sufficient alone.
///
/// 1. The default-off `negotiate` feature is enabled. Without it there is no
///    GSS-API binding compiled in.
/// 2. A GSS-API library is actually usable, which `cfg!()` cannot see -- the
///    library resolves at load time and a host may have none.
///    `crate::ffi::gss::available()` probes it once and caches the answer.
///
/// The second is why this is not a `const fn` and why the value must not be
/// hoisted into a constant. It is also what makes the answer honest rather
/// than optimistic: `crate::version` withholds the `GSS-API`, `Kerberos` and
/// `SPNEGO` banner tokens on the same basis, and over-reporting a capability
/// turns a cleanly skipped fixture into a failing one.
#[must_use]
pub(crate) fn is_spnego_supported() -> bool {
    #[cfg(feature = "negotiate")]
    {
        crate::ffi::gss::available()
    }

    #[cfg(not(feature = "negotiate"))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// THE `lib/curl_sasl.c` SPLIT BOUNDARY.
// Vocabulary, name matching and the CURLAUTH translation only. The command
// state machine is deliberately absent -- see the module documentation.
// ---------------------------------------------------------------------------

/// A set of SASL authentication mechanisms: the `SASL_MECH_*` bitmask.
///
/// `lib/curl_sasl.h:32-47`. A separate type from [`AuthMask`] because the two
/// vocabularies are different and numerically overlapping -- bit 6 is
/// `SASL_MECH_NTLM` here and `CURLAUTH_BEARER` there -- so passing one where
/// the other belongs must not compile. [`curlauth_to_sasl_mechs`] is the only
/// crossing.
///
/// The representation is `u16` because C's is: `struct SASL`'s `authmechs`,
/// `prefmech` and `authused` are `unsigned short`
/// (`lib/curl_sasl.h:122-124`), `Curl_sasl_decode_mech()` returns
/// `unsigned short`, and `SASL_AUTH_ANY` is `0xffff`, which fills the type
/// exactly. Eleven of the sixteen bits are named.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub(crate) struct SaslMech(u16);

impl SaslMech {
    /// `SASL_MECH_LOGIN` = `1 << 0`.
    pub(crate) const LOGIN: Self = Self(1 << 0);
    /// `SASL_MECH_PLAIN` = `1 << 1`.
    pub(crate) const PLAIN: Self = Self(1 << 1);
    /// `SASL_MECH_CRAM_MD5` = `1 << 2`. **Vocabulary only**: the
    /// implementation was `lib/vauth/cram.c`, which is out of scope.
    pub(crate) const CRAM_MD5: Self = Self(1 << 2);
    /// `SASL_MECH_DIGEST_MD5` = `1 << 3`.
    pub(crate) const DIGEST_MD5: Self = Self(1 << 3);
    /// `SASL_MECH_GSSAPI` = `1 << 4`.
    pub(crate) const GSSAPI: Self = Self(1 << 4);
    /// `SASL_MECH_EXTERNAL` = `1 << 5`. The one mechanism
    /// [`Self::AUTH_DEFAULT`] excludes.
    pub(crate) const EXTERNAL: Self = Self(1 << 5);
    /// `SASL_MECH_NTLM` = `1 << 6`.
    pub(crate) const NTLM: Self = Self(1 << 6);
    /// `SASL_MECH_XOAUTH2` = `1 << 7`.
    pub(crate) const XOAUTH2: Self = Self(1 << 7);
    /// `SASL_MECH_OAUTHBEARER` = `1 << 8`.
    pub(crate) const OAUTHBEARER: Self = Self(1 << 8);
    /// `SASL_MECH_SCRAM_SHA_1` = `1 << 9`. **Vocabulary only**: SCRAM came
    /// from libgsasl, which is dropped.
    pub(crate) const SCRAM_SHA_1: Self = Self(1 << 9);
    /// `SASL_MECH_SCRAM_SHA_256` = `1 << 10`. **Vocabulary only.**
    pub(crate) const SCRAM_SHA_256: Self = Self(1 << 10);

    /// `SASL_AUTH_NONE` = `0` (`lib/curl_sasl.h:45`).
    pub(crate) const AUTH_NONE: Self = Self(0);

    /// `SASL_AUTH_ANY` = `0xffff` (`lib/curl_sasl.h:46`).
    ///
    /// Every bit of the type, named and unnamed alike -- not the union of the
    /// eleven constants. Preserved as the literal for the same reason
    /// [`AuthMask::ANY`] is: narrowing it would change which mechanisms a
    /// later vocabulary could reach.
    #[allow(dead_code)] // Consumer would be a SASL protocol; all three are stubs.
    pub(crate) const AUTH_ANY: Self = Self(0xffff);

    /// `SASL_AUTH_DEFAULT` = `SASL_AUTH_ANY & ~SASL_MECH_EXTERNAL` = `0xffdf`
    /// (`lib/curl_sasl.h:47`).
    ///
    /// `EXTERNAL` is excluded from the default because it authenticates out of
    /// band -- through a client certificate -- so offering it unasked would
    /// change what an unconfigured transfer attempts.
    #[allow(dead_code)] // Consumer would be a SASL protocol; all three are stubs.
    pub(crate) const AUTH_DEFAULT: Self =
        Self::AUTH_ANY.difference(Self::EXTERNAL);

    /// The raw integer.
    #[must_use]
    #[allow(dead_code)] // Consumer would be a SASL protocol; all three are stubs.
    pub(crate) const fn bits(self) -> u16 {
        self.0
    }

    /// Adopt a raw integer.
    #[must_use]
    #[allow(dead_code)] // Consumer would be a SASL protocol; all three are stubs.
    pub(crate) const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Whether any bit of `other` is set here: C's `mechs & SASL_MECH_x`.
    #[must_use]
    #[allow(dead_code)] // Consumer would be a SASL protocol; all three are stubs.
    pub(crate) const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Whether no bit is set: C's `mechs == SASL_AUTH_NONE`.
    #[must_use]
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Set union: C's `|`.
    #[must_use]
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The bits of `self` that are not in `other`: C's `x & ~y`.
    #[must_use]
    #[allow(dead_code)] // Consumer would be a SASL protocol; all three are stubs.
    pub(crate) const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl fmt::Debug for SaslMech {
    /// Renders the set as its `SASL_MECH_*` names, with any unnamed residue in
    /// hexadecimal so that [`Self::AUTH_ANY`]'s five unnamed bits stay visible.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("SASL_AUTH_NONE");
        }

        let mut residue = self.0;
        let mut first = true;
        for row in MECHTABLE {
            if self.0 & row.bit.0 == 0 {
                continue;
            }
            residue &= !row.bit.0;
            if !first {
                f.write_str("|")?;
            }
            f.write_str(row.name)?;
            first = false;
        }

        if residue != 0 {
            if !first {
                f.write_str("|")?;
            }
            write!(f, "{residue:#06x}")?;
        }
        Ok(())
    }
}

/// One row of C's `mechtable[]`.
///
/// The `len` field is redundant with `name.len()` and is kept because C keeps
/// it: `Curl_sasl_decode_mech()` uses it as the comparison bound and as the
/// index of the byte it inspects afterwards, so removing it would move a
/// decision out of the table and into the code. A test asserts the redundancy
/// is consistent for all eleven rows, which is the check C cannot make.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SaslMechRow {
    /// The wire spelling, from the `SASL_MECH_STRING_*` macros
    /// (`lib/curl_sasl.h:50-60`). Upper case, hyphenated.
    pub(crate) name: &'static str,
    /// The name length: C's `len` member.
    pub(crate) len: usize,
    /// The bit this name decodes to.
    pub(crate) bit: SaslMech,
}

/// The supported mechanisms, in C's declaration order.
///
/// `lib/curl_sasl.c:53-66`, transcribed row for row. C's trailing
/// `{ ZERO_NULL, 0, 0 }` sentinel is dropped: it terminates a `for` loop over
/// a bare array, and a Rust slice carries its own length.
///
/// # `LOGIN` and `PLAIN` are both five bytes long
///
/// So a dispatch keyed on length is ambiguous, and [`decode_mech`] therefore
/// matches the **name** first and uses `len` only as a bound -- exactly as the
/// C does. The two names collide in nothing but their length, which is why
/// this is a trap only for an implementation that reorders the table or
/// indexes it by size.
///
/// `#[rustfmt::skip]` because the rows are data: the names are wire bytes and
/// the column alignment makes a transcription error visible.
#[rustfmt::skip]
pub(crate) const MECHTABLE: [SaslMechRow; 11] = [
    SaslMechRow { name: "LOGIN",         len: 5,  bit: SaslMech::LOGIN },
    SaslMechRow { name: "PLAIN",         len: 5,  bit: SaslMech::PLAIN },
    SaslMechRow { name: "CRAM-MD5",      len: 8,  bit: SaslMech::CRAM_MD5 },
    SaslMechRow { name: "DIGEST-MD5",    len: 10, bit: SaslMech::DIGEST_MD5 },
    SaslMechRow { name: "GSSAPI",        len: 6,  bit: SaslMech::GSSAPI },
    SaslMechRow { name: "EXTERNAL",      len: 8,  bit: SaslMech::EXTERNAL },
    SaslMechRow { name: "NTLM",          len: 4,  bit: SaslMech::NTLM },
    SaslMechRow { name: "XOAUTH2",       len: 7,  bit: SaslMech::XOAUTH2 },
    SaslMechRow { name: "OAUTHBEARER",   len: 11, bit: SaslMech::OAUTHBEARER },
    SaslMechRow { name: "SCRAM-SHA-1",   len: 11, bit: SaslMech::SCRAM_SHA_1 },
    SaslMechRow { name: "SCRAM-SHA-256", len: 13, bit: SaslMech::SCRAM_SHA_256 },
];

/// Converts a SASL mechanism name into its bit, with the effective name
/// length.
///
/// Supersedes `Curl_sasl_decode_mech()` (`lib/curl_sasl.c:81-103`). `span` is
/// C's `ptr` bounded by its `maxlen`: the C function never reads past
/// `maxlen`, so a slice of exactly that length is the same input, and
/// `span.len()` plays the role of `maxlen` throughout. The returned length is
/// C's `*len` out-parameter, which callers compare against their own token
/// length -- `lib/curl_sasl.c:128` accepts a mechanism only when
/// `mechlen == len`.
///
/// Returns `None` where C returns `0`, which it can do for two different
/// reasons: no name matched, or a name matched but the byte after it says the
/// token continues.
///
/// # The delimiter test is NOT `ISALNUM`
///
/// This is the one place where a reader who has just written [`authcmp`] will
/// get it wrong. `lib/curl_sasl.c:97` is:
///
/// ```c
/// if(!ISUPPER(c) && !ISDIGIT(c) && c != '-' && c != '_')
///   return mechtable[i].bit;
/// ```
///
/// The set that *continues* a mechanism name is upper case, digits, hyphen and
/// underscore -- so a **lower-case** letter terminates it. `"LOGINx"` decodes
/// as `LOGIN`, where the corresponding HTTP scheme test would reject
/// `"Basicx"`. The two grammars genuinely differ: SASL mechanism names are
/// upper case by registration (RFC 4422), so a lower-case byte cannot be part
/// of one, while an HTTP `auth-scheme` token is case-insensitive.
///
/// The exact-length case returns before reading anything further
/// (`lib/curl_sasl.c:93-94`), which is what makes a bare `"LOGIN"` decode.
#[must_use]
#[allow(dead_code)] // Consumer would be a SASL protocol; all three are stubs.
pub(crate) fn decode_mech(span: &[u8]) -> Option<(SaslMech, usize)> {
    for row in MECHTABLE {
        if span.len() < row.len {
            continue;
        }
        if !casecompare(&span[..row.len], row.name.as_bytes()) {
            continue;
        }

        // An exact-length match resolves without inspecting anything else.
        if span.len() == row.len {
            return Some((row.bit, row.len));
        }

        // `c = ptr[mechtable[i].len]` -- in bounds, because the length test
        // above and the equality test just now leave `span.len() > row.len`.
        let next = span[row.len];
        let continues = next.is_ascii_uppercase()
            || next.is_ascii_digit()
            || next == b'-'
            || next == b'_';
        if !continues {
            return Some((row.bit, row.len));
        }
    }

    None
}

/// Translates HTTP authentication options into SASL mechanisms.
///
/// The `CURLAUTH_*` to `SASL_MECH_*` mapping of `Curl_sasl_init()`
/// (`lib/curl_sasl.c:162-171`) -- the one genuinely cross-boundary piece of
/// `lib/curl_sasl.c`, and the reason that file is split rather than dropped:
/// it is HTTP option state (`data->set.httpauth`) deciding a SASL default.
///
/// ```text
/// CURLAUTH_BASIC   ->  SASL_MECH_PLAIN | SASL_MECH_LOGIN
/// CURLAUTH_DIGEST  ->  SASL_MECH_DIGEST_MD5
/// CURLAUTH_NTLM    ->  SASL_MECH_NTLM
/// CURLAUTH_BEARER  ->  SASL_MECH_OAUTHBEARER | SASL_MECH_XOAUTH2
/// CURLAUTH_GSSAPI  ->  SASL_MECH_GSSAPI
/// ```
///
/// The mapping is deliberately not a bijection. `CURLAUTH_BASIC` produces two
/// mechanisms because SASL has two ways to send a cleartext password, and
/// `CURLAUTH_BEARER` produces two because `XOAUTH2` is Google's predecessor to
/// the registered `OAUTHBEARER` and curl offers both. `CURLAUTH_GSSAPI` is
/// [`AuthMask::NEGOTIATE`] under its other name -- the same bit, 4 -- which is
/// why the SOCKS5 spelling of the constant is the one C uses here.
///
/// Four `CURLAUTH_*` bits map to nothing: `DIGEST_IE` is a Digest modifier
/// rather than a mechanism, `AWS_SIGV4` signs an HTTP request and has no SASL
/// analogue, `NTLM_WB` has no implementation, and `ONLY` is a modifier.
#[must_use]
#[allow(dead_code)] // Consumer would be a SASL protocol; all three are stubs.
pub(crate) fn curlauth_to_sasl_mechs(auth: AuthMask) -> SaslMech {
    let mut mechs = SaslMech::AUTH_NONE;

    if auth.intersects(AuthMask::BASIC) {
        mechs = mechs.union(SaslMech::PLAIN).union(SaslMech::LOGIN);
    }
    if auth.intersects(AuthMask::DIGEST) {
        mechs = mechs.union(SaslMech::DIGEST_MD5);
    }
    if auth.intersects(AuthMask::NTLM) {
        mechs = mechs.union(SaslMech::NTLM);
    }
    if auth.intersects(AuthMask::BEARER) {
        mechs = mechs.union(SaslMech::OAUTHBEARER).union(SaslMech::XOAUTH2);
    }
    if auth.intersects(CURLAUTH_GSSAPI) {
        mechs = mechs.union(SaslMech::GSSAPI);
    }

    mechs
}

/// The preferred SASL mechanisms for a transfer, given the protocol's default
/// set and the application's HTTP authentication options.
///
/// The whole of `Curl_sasl_init()`'s preference logic
/// (`lib/curl_sasl.c:157-175`), which is two guards around
/// [`curlauth_to_sasl_mechs`] and neither is redundant:
///
/// 1. **`if(auth != CURLAUTH_BASIC)`** -- an exact equality against the single
///    `BASIC` bit. So an application that asked for Basic *and nothing else*
///    keeps the protocol's own default set untouched. `BASIC | DIGEST` does
///    **not** match and does enter the block, and neither does
///    `CURLAUTH_NONE`: the C compares the option value, not a membership.
///    That reading is the counter-intuitive one and it is the C's.
/// 2. **`if(mechs != SASL_AUTH_NONE)`** -- the translation may map every bit
///    the application set to nothing at all (`AWS_SIGV4` alone, say), and an
///    empty override would leave the transfer with no mechanism to offer. C
///    keeps the default in that case rather than producing an unusable state.
///
/// `defaults` is `params->defmechs`, the `SASLproto` vtable member each of
/// SMTP, IMAP and POP3 fills in. All three are stubs here, which is why this
/// function has no caller in-tree; it is ported because the mapping is the
/// documented bridge between the two vocabularies and because reconstructing
/// it later from a stub protocol would mean reconstructing it from nothing.
#[must_use]
#[allow(dead_code)] // Consumer would be a SASL protocol; all three are stubs.
pub(crate) fn sasl_preferred_mechs(
    auth: AuthMask,
    defaults: SaslMech,
) -> SaslMech {
    if auth == AuthMask::BASIC {
        return defaults;
    }

    let mechs = curlauth_to_sasl_mechs(auth);
    if mechs.is_empty() {
        defaults
    } else {
        mechs
    }
}

// ---------------------------------------------------------------------------
// THE MECHANISM ABSTRACTION.
// C has no vtable for HTTP authentication -- the dispatch is the `switch` of
// `output_auth_headers()` -- so the trait is defined here and the six sibling
// modules implement it.
// ---------------------------------------------------------------------------

/// A username and the secret that goes with it.
///
/// C keeps these as `char *` members of `data->state.aptr`
/// (`user`, `passwd`, `proxyuser`, `proxypasswd`) and
/// `data->set.str[STRING_BEARER]`. They are gathered into one type here for a
/// single reason, and it is not tidiness: so that the hand-written
/// [`core::fmt::Debug`] below cannot be bypassed.
///
/// # Why the formatter is hand-written
///
/// A `#[derive(Debug)]` on *any* enclosing structure, at arbitrary distance
/// from this file, would print every field of every field -- so a derived
/// formatter on a mechanism state that happens to hold one of these would
/// write a password into a log that nobody wrote a logging call for. Writing
/// the formatter here makes that impossible for every present and future
/// holder at once, which no review convention can.
///
/// This adds no redaction to curl's own output and removes none.
/// `lib/http.c:2888-2895` inserts the fully formed `Authorization:` header
/// straight into the request buffer, from where `--verbose` prints it
/// verbatim, and 168 fixtures compare that line byte for byte. The rule this
/// type enforces is narrower and is the one that actually binds: **no secret
/// gains a path to a log that curl does not already have.**
///
/// Memory is not scrubbed on drop. curl does not scrub these either, doing so
/// would need a dependency this workspace does not carry, and the guarantee
/// would be nominal in any case -- the credential is copied into a base64
/// encoding, a header line and a request buffer, none of which this type owns.
#[derive(Clone, Default, Eq, PartialEq)]
#[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
pub(crate) struct Credentials {
    /// The username, or `None` when C's pointer is `NULL`.
    ///
    /// Bytes rather than text: a username reaches curl from a URL or an
    /// option and is not required to be UTF-8, and the mechanisms that consume
    /// it -- NTLM's UCS-2 conversion, Digest's quoted string -- work in bytes.
    user: Option<Vec<u8>>,
    /// The password or token. Never formatted, never logged.
    secret: Option<Vec<u8>>,
}

impl Credentials {
    /// No username and no secret: C's two `NULL` pointers.
    #[must_use]
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) const fn none() -> Self {
        Self {
            user: None,
            secret: None,
        }
    }

    /// A username and secret pair, either of which may be absent.
    #[must_use]
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) fn new(user: Option<&[u8]>, secret: Option<&[u8]>) -> Self {
        Self {
            user: user.map(<[u8]>::to_vec),
            secret: secret.map(<[u8]>::to_vec),
        }
    }

    /// The username, if one was supplied.
    #[must_use]
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) fn user(&self) -> Option<&[u8]> {
        self.user.as_deref()
    }

    /// The secret, if one was supplied.
    ///
    /// Named `secret` rather than `password` because the same field carries an
    /// OAuth 2.0 bearer token, and naming it for one of its two uses would
    /// invite a formatter that "only" prints the other.
    #[must_use]
    #[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
    pub(crate) fn secret(&self) -> Option<&[u8]> {
        self.secret.as_deref()
    }

    /// The username as C's `%s` argument renders it: the text, or `""` when
    /// absent.
    ///
    /// `lib/http.c:722-732` prints the username in the
    /// `"%s auth using %s with user '%s'"` diagnostic, so the username is not
    /// a secret in curl's terms and this accessor exists to feed exactly that
    /// line. Lossy conversion is correct here for the same reason the C is
    /// safe: the byte string goes to a diagnostic, so a non-UTF-8 byte must
    /// become a replacement character rather than an error or a panic.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn user_for_diagnostic(&self) -> String {
        match &self.user {
            Some(user) => String::from_utf8_lossy(user).into_owned(),
            None => String::new(),
        }
    }
}

impl fmt::Debug for Credentials {
    /// Prints the username and a placeholder for the secret.
    ///
    /// The username is printed because curl prints it itself, in the
    /// `--verbose` diagnostic of every authenticated request; the secret never
    /// is, anywhere, by anything.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user.as_deref().map(String::from_utf8_lossy))
            .field(
                "secret",
                &self.secret.as_ref().map(|_| REDACTED_PLACEHOLDER),
            )
            .finish()
    }
}

/// What [`Credentials`]'s formatter prints in place of a secret.
///
/// A constant so that a test can assert the placeholder appears *and* that the
/// secret does not, without restating either.
#[allow(dead_code)] // Reached only by this file's tests until a consumer lands.
pub(crate) const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// Everything a mechanism's emitter needs that is not its own state.
///
/// `output_auth_headers()` passes `request` and `path` to every arm and only
/// Digest reads them (`lib/http.c:673-676`); the clock and the random source
/// are C globals reached through `curlx_now()` and `Curl_rand()`. All four
/// arrive here as fields instead, for two different reasons.
///
/// `request` and `path` are fields rather than extra parameters on
/// [`HttpAuthMechanism::output`] because only one of six implementors reads
/// them -- [`AuthScheme::needs_request_target`] is the predicate -- and giving
/// the other five two parameters to ignore is how an argument gets passed in
/// the wrong order.
///
/// The clock and the random source are injected because a global is untestable
/// and this crate forbids reaching for one: `crate::util::timeval` documents
/// that it offers no global default, no `static` and no `thread_local`, and
/// `crate::crypto::rand` the same. Digest needs both -- a client nonce from
/// the random source, and `nc`/timestamp material -- and NTLM needs the random
/// source for its type-3 challenge. A mechanism that needs neither simply does
/// not read them.
#[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
pub(crate) struct AuthContext<'a> {
    /// Whether this header is for the proxy: C's `bool proxy`, which selects
    /// both the `struct auth` and the `"Proxy-"` prefix.
    pub(crate) proxy: bool,
    /// C's `request`: the method token, `"GET"`, `"POST"` and so on.
    ///
    /// Read only by Digest, which digests it into the response.
    pub(crate) request_method: &'a [u8],
    /// C's `path`: the request target, query part included.
    ///
    /// `lib/http.c:750` says so explicitly -- "pointer to the requested path;
    /// should include query part" -- and it matters, because the Digest
    /// response covers the whole target and a stripped query produces a
    /// response the server rejects with no diagnostic that says why.
    pub(crate) request_target: &'a [u8],
    /// The injected clock: the successor of `curlx_now()` and `time(NULL)`.
    pub(crate) clock: &'a dyn crate::util::timeval::Clock,
    /// The injected random source: the successor of `Curl_rand()`.
    pub(crate) rng: &'a mut dyn crate::crypto::rand::Rng,
}

impl fmt::Debug for AuthContext<'_> {
    /// Hand-written because [`crate::crypto::rand::Rng`] has no
    /// [`core::fmt::Debug`] bound -- deliberately, since a random source has
    /// no meaningful printable state -- so the structure cannot derive one.
    ///
    /// Nothing here is a secret: the method and target both go on the wire in
    /// the request line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthContext")
            .field("proxy", &self.proxy)
            .field(
                "request_method",
                &String::from_utf8_lossy(self.request_method),
            )
            .field(
                "request_target",
                &String::from_utf8_lossy(self.request_target),
            )
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

/// One HTTP authentication mechanism.
///
/// The trait C does not have. `lib/vauth/` has no vtable for HTTP
/// authentication -- the dispatch is the equality chain of
/// `output_auth_headers()` and the `authcmp` chain of
/// `Curl_http_input_auth()` -- so this is the trait those two chains imply,
/// and the six sibling modules implement it.
///
/// Two directions, matching C's two families:
///
/// * [`Self::input`] is `Curl_input_negotiate()`, `Curl_input_ntlm()` and
///   `Curl_input_digest()`. Basic and Bearer have no challenge to consume and
///   their implementations say so by returning `Ok(())`.
/// * [`Self::output`] is `Curl_output_negotiate()`, `Curl_output_ntlm()`,
///   `Curl_output_digest()`, `http_output_basic()`, `http_output_bearer()` and
///   `Curl_output_aws_sigv4()`.
///
/// # `bool *done` is gone
///
/// Every C emitter writes readiness through a pointer it was handed. Here it
/// is in the return type -- [`AuthEmission`] distinguishes
/// [`AuthEmission::Final`] from [`AuthEmission::Continuing`] -- so it cannot
/// be forgotten, cannot be written twice, and cannot disagree with the header
/// it accompanies. [`finish_emission`] is the single place it lands in
/// [`AuthState`].
///
/// # The header is composed with [`authorization_header`]
///
/// Implementors must not format the line themselves. All five C emitters share
/// one format shape and the fixture corpus compares the result byte for byte,
/// so the shape has exactly one home.
#[allow(dead_code)] // Consumers are the six sibling modules, not yet landed.
pub(crate) trait HttpAuthMechanism {
    /// Which mechanism this is.
    ///
    /// Present so that a `&dyn HttpAuthMechanism` can be matched against
    /// `picked` without a downcast, and so that [`AuthScheme::label`] and
    /// [`AuthScheme::header_scheme`] are reachable from the object.
    fn scheme(&self) -> AuthScheme;

    /// Consume a challenge from a `WWW-Authenticate:` or
    /// `Proxy-Authenticate:` header.
    ///
    /// `challenge` starts at the scheme token, as C's `auth` pointer does.
    ///
    /// # Errors
    ///
    /// `CURLcode::OutOfMemory` aborts the whole scan; every other code becomes
    /// a diagnostic and sets `authproblem`, leaving the scan running. See
    /// [`input_auth`], which is what enforces the distinction.
    fn input(&mut self, challenge: &[u8], proxy: bool) -> Result<(), CURLcode>;

    /// Produce this request's authorization header line.
    ///
    /// # Errors
    ///
    /// Whatever the mechanism's own failure is. `Curl_output_ntlm()` and
    /// `Curl_output_negotiate()` return `CURLE_OUT_OF_MEMORY` or the
    /// `CURLE_AUTH_ERROR` of a failed GSS-API step; `http_output_basic()`
    /// returns `CURLE_REMOTE_ACCESS_DENIED` when the base64 encoder yields
    /// nothing (`lib/http.c:281-283`) and `CURLE_NOT_BUILT_IN` for a proxy in
    /// a build without proxy support (`lib/http.c:261`).
    fn output(
        &mut self,
        ctx: &mut AuthContext<'_>,
    ) -> Result<AuthEmission, CURLcode>;
}

// Tests
//
// `tests/unit/*.c` and `tests/libtest/*.c` cannot link against this crate --
// they call internal `Curl_*` symbols, and a Rust static library does not
// export `pub(crate)` items, so they are genuinely absent from the symbol
// table rather than merely hidden. Their coverage is relocated here, inside
// the module under test, which is also where a private item is reachable
// without widening its visibility to accommodate a test.
//
// The C oracle is cited for each assertion. Where an expectation is an
// integer or a string that crosses the ABI or the wire, it is written as a
// LITERAL rather than derived from the implementation: deriving it would make
// the test agree with whatever the code does, which is the one thing a parity
// test must not do.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rand::Rng;
    use crate::trace::{TraceConfig, TraceState, WriterSink};
    use crate::util::timeval::CurlTime;

    /// Runs `body` with a verbose tracer and returns its result together with
    /// everything the sink received, as text.
    ///
    /// `WriterSink::new` rather than `new_for_terminal`, because the
    /// byte-faithful form is what an assertion on exact text needs -- the
    /// terminal form escapes control bytes.
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

    /// A [`ChallengeDecoder`] that records what it was asked to decode.
    ///
    /// Stands in for the three sibling modules that own decoding, so that the
    /// scan -- the ordering, the availability bookkeeping, the diagnostics and
    /// the comma walk -- is testable on its own, which is the point of the
    /// trait.
    struct FakeDecoder {
        /// Every `(scheme, proxy, challenge)` the scan handed over, in order.
        seen: Vec<(AuthScheme, bool, Vec<u8>)>,
        /// A failure to report for one scheme.
        fail: Option<(AuthScheme, CURLcode)>,
        spnego: bool,
        ntlm: bool,
        digest: bool,
    }

    impl Default for FakeDecoder {
        fn default() -> Self {
            Self {
                seen: Vec::new(),
                fail: None,
                // All three C predicates return TRUE unconditionally, so the
                // default here is the production answer -- except SPNEGO,
                // whose production answer depends on a GSS-API library. The
                // test drives both.
                spnego: true,
                ntlm: true,
                digest: true,
            }
        }
    }

    impl FakeDecoder {
        fn failing(scheme: AuthScheme, code: CURLcode) -> Self {
            Self {
                fail: Some((scheme, code)),
                ..Self::default()
            }
        }

        fn schemes(&self) -> Vec<AuthScheme> {
            self.seen.iter().map(|(scheme, _, _)| *scheme).collect()
        }
    }

    impl ChallengeDecoder for FakeDecoder {
        fn decode(
            &mut self,
            scheme: AuthScheme,
            proxy: bool,
            challenge: &[u8],
        ) -> Result<(), CURLcode> {
            self.seen.push((scheme, proxy, challenge.to_vec()));
            match self.fail {
                Some((failing, code)) if failing == scheme => Err(code),
                _ => Ok(()),
            }
        }

        fn spnego_supported(&self) -> bool {
            self.spnego
        }

        fn ntlm_supported(&self) -> bool {
            self.ntlm
        }

        fn digest_supported(&self) -> bool {
            self.digest
        }
    }

    /// A decoder that overrides nothing but [`ChallengeDecoder::decode`].
    ///
    /// [`FakeDecoder`] replaces all three support predicates so that a test can
    /// drive both answers; this one leaves them at their defaults, which is how
    /// the six sibling modules will implement the trait. Without it the default
    /// bodies -- the production wiring to [`is_ntlm_supported`],
    /// [`is_digest_supported`] and [`is_spnego_supported`] -- would never run.
    #[derive(Default)]
    struct DefaultDecoder {
        seen: Vec<AuthScheme>,
    }

    impl ChallengeDecoder for DefaultDecoder {
        fn decode(
            &mut self,
            scheme: AuthScheme,
            _proxy: bool,
            _challenge: &[u8],
        ) -> Result<(), CURLcode> {
            self.seen.push(scheme);
            Ok(())
        }
    }

    /// A sink for the three `&mut` outputs of a scan, so a test can look at
    /// each afterwards.
    #[derive(Default)]
    struct ScanState {
        state: AuthState,
        reported: AuthMask,
        problem: bool,
        outcome: ChallengeOutcome,
    }

    impl ScanState {
        fn with(picked: AuthMask, avail: AuthMask) -> Self {
            Self {
                state: AuthState {
                    picked,
                    avail,
                    ..AuthState::ZERO
                },
                ..Self::default()
            }
        }

        /// Runs one scan and captures the trace text.
        fn scan(
            &mut self,
            line: &[u8],
            proxy: bool,
            decoder: &mut FakeDecoder,
        ) -> (Result<(), CURLcode>, String) {
            let mut sink = ChallengeSink::new(
                &mut self.state,
                &mut self.reported,
                &mut self.problem,
            );
            let (result, log) = with_tracer(|tracer| {
                input_auth(line, proxy, &mut sink, decoder, tracer)
            });
            self.outcome = sink.outcome;
            (result, log)
        }
    }

    // -- The `CURLAUTH_*` vocabulary. `include/curl/curl.h:828-848`. --------

    #[test]
    fn curlauth_integers_are_the_public_header_values() {
        // Literals from the header, not `1 << n` recomputed from the code.
        assert_eq!(AuthMask::NONE.bits(), 0);
        assert_eq!(AuthMask::BASIC.bits(), 1);
        assert_eq!(AuthMask::DIGEST.bits(), 2);
        assert_eq!(AuthMask::NEGOTIATE.bits(), 4);
        assert_eq!(AuthMask::NTLM.bits(), 8);
        assert_eq!(AuthMask::DIGEST_IE.bits(), 16);
        assert_eq!(AuthMask::NTLM_WB.bits(), 32);
        assert_eq!(AuthMask::BEARER.bits(), 64);
        assert_eq!(AuthMask::AWS_SIGV4.bits(), 128);
        assert_eq!(AuthMask::ONLY.bits(), 0x8000_0000);
    }

    #[test]
    fn the_two_composite_masks_are_their_header_literals() {
        // `(~CURLAUTH_DIGEST_IE) & 0xffffffff` and
        // `(~(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE)) & 0xffffffff`. Asserted as
        // literals because these are the integers `--anyauth` puts into
        // `CURLOPT_HTTPAUTH`.
        assert_eq!(AuthMask::ANY.bits(), 0xFFFF_FFEF);
        assert_eq!(AuthMask::ANYSAFE.bits(), 0xFFFF_FFEE);

        // Both deliberately include ONLY and every undefined bit. A "cleaned
        // up" enumerated union would be a different, smaller integer, and
        // this is the assertion that catches that edit.
        assert!(AuthMask::ANY.intersects(AuthMask::ONLY));
        assert!(AuthMask::ANYSAFE.intersects(AuthMask::ONLY));
        assert!(!AuthMask::ANY.intersects(AuthMask::DIGEST_IE));
        assert!(!AuthMask::ANYSAFE.intersects(AuthMask::DIGEST_IE));
        assert!(!AuthMask::ANYSAFE.intersects(AuthMask::BASIC));
        assert!(AuthMask::ANY.intersects(AuthMask::BASIC));

        let named = NAMED_BITS
            .iter()
            .filter(|(mask, _)| *mask != AuthMask::PICKNONE)
            .fold(AuthMask::NONE, |acc, (mask, _)| acc | *mask);
        assert_ne!(
            AuthMask::ANY,
            named.difference(AuthMask::DIGEST_IE),
            "ANY is the 32-bit complement, not the union of the named bits"
        );
    }

    #[test]
    fn the_two_negotiate_aliases_are_the_same_integer() {
        // `include/curl/curl.h:833` and `:835`. An application compiled
        // against any of the three spellings holds the value 4.
        assert_eq!(AuthMask::NEGOTIATE.bits(), 4);
        assert_eq!(CURLAUTH_GSSNEGOTIATE.bits(), 4);
        assert_eq!(CURLAUTH_GSSAPI.bits(), 4);
        assert_eq!(AuthMask::NEGOTIATE, CURLAUTH_GSSNEGOTIATE);
        assert_eq!(AuthMask::NEGOTIATE, CURLAUTH_GSSAPI);
    }

    #[test]
    fn picknone_is_bit_thirty_and_claimed_by_no_public_constant() {
        // `lib/http.h:135`.
        assert_eq!(AuthMask::PICKNONE.bits(), 1 << 30);
        assert_eq!(AuthMask::PICKNONE.bits(), 0x4000_0000);

        // Internal only: it must not collide with anything the header
        // defines, or an application setting CURLAUTH_ANY would appear to
        // have actively selected no authentication.
        for scheme in EMISSION_ORDER {
            assert!(!AuthMask::PICKNONE.intersects(scheme.mask()));
        }
        assert!(!AuthMask::PICKNONE.intersects(AuthMask::ONLY));
        assert!(!AuthMask::PICKNONE.intersects(AuthMask::DIGEST_IE));
        assert!(!AuthMask::PICKNONE.intersects(AuthMask::NTLM_WB));
    }

    #[test]
    fn the_delegation_constants_are_the_public_header_values() {
        // `include/curl/curl.h:861-863`.
        assert_eq!(CURLGSSAPI_DELEGATION_NONE, 0);
        assert_eq!(CURLGSSAPI_DELEGATION_POLICY_FLAG, 1);
        assert_eq!(CURLGSSAPI_DELEGATION_FLAG, 2);
    }

    #[cfg(feature = "negotiate")]
    #[test]
    fn the_delegation_constants_agree_with_the_typed_form() {
        // One vocabulary, two representations: these integers and
        // `crate::ffi::gss::Delegation`, which translates them into
        // `GSS_C_DELEG_*` flags. If they disagreed, a `--gssapi-delegation`
        // setting would be silently ignored.
        use crate::ffi::gss::Delegation;

        let none = Delegation::from_option_value(CURLGSSAPI_DELEGATION_NONE);
        assert!(!none.policy());
        assert!(!none.always());

        let policy =
            Delegation::from_option_value(CURLGSSAPI_DELEGATION_POLICY_FLAG);
        assert!(policy.policy());
        assert!(!policy.always());

        let always = Delegation::from_option_value(CURLGSSAPI_DELEGATION_FLAG);
        assert!(!always.policy());
        assert!(always.always());

        let both = Delegation::from_option_value(
            CURLGSSAPI_DELEGATION_POLICY_FLAG | CURLGSSAPI_DELEGATION_FLAG,
        );
        assert!(both.policy());
        assert!(both.always());
    }

    #[test]
    fn mask_algebra_matches_the_c_operators() {
        let both = AuthMask::BASIC | AuthMask::DIGEST;
        assert_eq!(both.bits(), 3);
        assert!(both.contains(AuthMask::BASIC));
        assert!(both.contains(both));
        assert!(!both.contains(AuthMask::NTLM));
        assert!(both.intersects(AuthMask::DIGEST));
        assert!(!both.is_single());
        assert!(AuthMask::DIGEST.is_single());
        assert!(AuthMask::NONE.is_empty());
        assert!(!AuthMask::NONE.is_single());
        assert_eq!(both & AuthMask::BASIC, AuthMask::BASIC);
        assert_eq!(both.difference(AuthMask::BASIC), AuthMask::DIGEST);

        // The complement is the 32-bit one: C masks `~` with 0xffffffff
        // because its constants are `unsigned long`, and a 64-bit result
        // would not equal the header's value.
        assert_eq!((!AuthMask::NONE).bits(), u32::MAX);
        assert_eq!(!AuthMask::from_bits(u32::MAX), AuthMask::NONE);

        let mut acc = AuthMask::BASIC;
        acc |= AuthMask::NTLM;
        assert_eq!(acc.bits(), 9);
        acc &= AuthMask::NTLM;
        assert_eq!(acc, AuthMask::NTLM);

        // Unknown bits survive a round trip: C stores whatever
        // `CURLOPT_HTTPAUTH` was given.
        let unknown = AuthMask::from_bits(0x0100_0000);
        assert_eq!(unknown.bits(), 0x0100_0000);
    }

    #[test]
    fn the_mask_formatter_names_bits_and_keeps_the_residue() {
        assert_eq!(format!("{:?}", AuthMask::NONE), "CURLAUTH_NONE");
        assert_eq!(format!("{:?}", AuthMask::BASIC), "CURLAUTH_BASIC");
        assert_eq!(
            format!("{:?}", AuthMask::BASIC | AuthMask::NTLM),
            "CURLAUTH_BASIC|CURLAUTH_NTLM"
        );
        // NTLM_WB is named rather than printed as a bare integer: naming it
        // reports which bit an application set. Naming it here advertises
        // nothing -- the `Features:` banner is built in `crate::version`.
        assert_eq!(format!("{:?}", AuthMask::NTLM_WB), "CURLAUTH_NTLM_WB");
        assert_eq!(
            format!("{:?}", AuthMask::from_bits(0x0100_0000)),
            "0x01000000"
        );
        assert_eq!(
            format!("{:?}", AuthMask::BASIC | AuthMask::from_bits(1 << 24)),
            "CURLAUTH_BASIC|0x01000000"
        );
        // ANY's 22 unnamed bits stay visible rather than being dropped.
        let rendered = format!("{:?}", AuthMask::ANY);
        assert!(rendered.contains("CURLAUTH_BASIC"), "{rendered}");
        assert!(rendered.contains("CURLAUTH_ONLY"), "{rendered}");
        assert!(!rendered.contains("CURLAUTH_DIGEST_IE"), "{rendered}");
        assert!(rendered.contains("0x"), "{rendered}");
    }

    // -- The three orderings are three. -----------------------------------

    #[test]
    fn preference_differs_from_the_other_two_orderings() {
        // Preference is the ordering that reorders: it decides what a server
        // is answered with when several methods are on offer, and it agrees
        // with neither of the others.
        assert_ne!(PREFERENCE_ORDER, EMISSION_ORDER);
        assert_eq!(PREFERENCE_ORDER.len(), 6);
        assert_eq!(EMISSION_ORDER.len(), 6);

        // Five of six positions differ, and only `Digest` happens to land in
        // the same place in both -- stated as a count so that a reordering of
        // either table is caught even if it preserves inequality.
        let differing = PREFERENCE_ORDER
            .iter()
            .zip(EMISSION_ORDER.iter())
            .filter(|(left, right)| left != right)
            .count();
        assert_eq!(differing, 5);

        // None of the three is the numeric order of the bits, which is what a
        // loop over set bits would produce.
        let mut by_bit = EMISSION_ORDER;
        by_bit.sort_by_key(|scheme| scheme.mask().bits());
        assert_ne!(by_bit, PREFERENCE_ORDER);
        assert_ne!(by_bit, EMISSION_ORDER);
    }

    #[test]
    fn emission_and_challenge_agree_on_their_shared_mechanisms() {
        // MEASURED, not assumed, and asserted in the direction the
        // measurement went: `output_auth_headers()`'s arm order and
        // `Curl_http_input_auth()`'s match order are the same sequence once
        // AWS SigV4 -- which answers no challenge -- is removed.
        //
        // They remain two tables because they are two contracts: emission is
        // tested with equality against a single bit and includes AWS SigV4,
        // challenge is tested with `authcmp` and does not. This assertion is
        // what would fail, loudly and in one place, if a later change moved
        // one of them.
        assert_eq!(CHALLENGE_ORDER.len(), 5);
        assert!(!CHALLENGE_ORDER.contains(&AuthScheme::AwsSigv4));

        let emission_minus_aws: Vec<AuthScheme> = EMISSION_ORDER
            .iter()
            .copied()
            .filter(|scheme| *scheme != AuthScheme::AwsSigv4)
            .collect();
        assert_eq!(emission_minus_aws.as_slice(), &CHALLENGE_ORDER[..]);

        // AWS SigV4 is the only member of one and not the other.
        for scheme in EMISSION_ORDER {
            assert_eq!(
                CHALLENGE_ORDER.contains(&scheme),
                scheme != AuthScheme::AwsSigv4,
                "{scheme:?}"
            );
        }
    }

    #[test]
    fn every_ordering_is_a_permutation_without_repeats() {
        for table in [&PREFERENCE_ORDER[..], &EMISSION_ORDER[..]] {
            for scheme in EMISSION_ORDER {
                assert_eq!(
                    table.iter().filter(|entry| **entry == scheme).count(),
                    1,
                    "{scheme:?} must appear exactly once"
                );
            }
        }
        for scheme in CHALLENGE_ORDER {
            assert_eq!(
                CHALLENGE_ORDER
                    .iter()
                    .filter(|entry| **entry == scheme)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn scheme_labels_and_header_tokens_are_the_c_literals() {
        // Labels reach `--verbose`; tokens reach the wire. They differ for
        // AWS SigV4, which has a label and no token at all.
        assert_eq!(AuthScheme::AwsSigv4.label(), "AWS_SIGV4");
        assert_eq!(AuthScheme::Negotiate.label(), "Negotiate");
        assert_eq!(AuthScheme::Ntlm.label(), "NTLM");
        assert_eq!(AuthScheme::Digest.label(), "Digest");
        assert_eq!(AuthScheme::Basic.label(), "Basic");
        assert_eq!(AuthScheme::Bearer.label(), "Bearer");

        assert_eq!(AuthScheme::Basic.header_scheme(), Some("Basic"));
        assert_eq!(AuthScheme::Digest.header_scheme(), Some("Digest"));
        assert_eq!(AuthScheme::Negotiate.header_scheme(), Some("Negotiate"));
        assert_eq!(AuthScheme::Ntlm.header_scheme(), Some("NTLM"));
        assert_eq!(AuthScheme::Bearer.header_scheme(), Some("Bearer"));
        assert_eq!(AuthScheme::AwsSigv4.header_scheme(), None);

        // Digest alone digests the method and target.
        for scheme in EMISSION_ORDER {
            assert_eq!(
                scheme.needs_request_target(),
                scheme == AuthScheme::Digest,
                "{scheme:?}"
            );
        }
    }

    // -- ORDERING 1: `pickoneauth()`. `lib/http.c:336-372`. ---------------

    /// The preference order, computed from [`PREFERENCE_ORDER`] rather than
    /// from the chain, so the two are independent statements of the same rule.
    fn expected_pick(avail: AuthMask) -> AuthMask {
        PREFERENCE_ORDER
            .iter()
            .find(|scheme| avail.intersects(scheme.mask()))
            .map_or(AuthMask::PICKNONE, |scheme| scheme.mask())
    }

    #[test]
    fn the_preference_chain_agrees_with_the_table_over_every_subset() {
        // All 64 subsets of the six mechanisms, wanted and available in full.
        // This is the test that catches a `for` loop over set bits: iterating
        // would order by bit value and disagree here for 43 of the 64.
        for subset in 0u32..64 {
            let mut offered = AuthMask::NONE;
            for (index, scheme) in EMISSION_ORDER.iter().enumerate() {
                if subset & (1 << index) != 0 {
                    offered |= scheme.mask();
                }
            }

            let mut state = AuthState {
                want: AuthMask::ANY,
                avail: offered,
                ..AuthState::ZERO
            };
            let picked = pick_one_auth(&mut state, AuthMask::ANY);

            let expected = expected_pick(offered);
            assert_eq!(
                state.picked, expected,
                "subset {subset:#04b} offered {offered:?}"
            );
            assert_eq!(picked, expected != AuthMask::PICKNONE);
            // Cleared on EVERY call, success and failure alike.
            assert_eq!(state.avail, AuthMask::NONE);
        }
    }

    #[test]
    fn aws_sigv4_loses_to_basic() {
        // The one ordering that reads like a mistake: AWS SigV4 is LAST, below
        // Basic. `lib/http.c:357-364`.
        let mut state = AuthState {
            want: AuthMask::ANY,
            avail: AuthMask::AWS_SIGV4 | AuthMask::BASIC,
            ..AuthState::ZERO
        };
        assert!(pick_one_auth(&mut state, AuthMask::ANY));
        assert_eq!(state.picked, AuthMask::BASIC);
    }

    #[test]
    fn negotiate_wins_over_everything_and_bearer_over_the_rest() {
        let everything = EMISSION_ORDER
            .iter()
            .fold(AuthMask::NONE, |acc, scheme| acc | scheme.mask());

        let mut state = AuthState {
            want: AuthMask::ANY,
            avail: everything,
            ..AuthState::ZERO
        };
        assert!(pick_one_auth(&mut state, AuthMask::ANY));
        assert_eq!(state.picked, AuthMask::NEGOTIATE);

        let mut state = AuthState {
            want: AuthMask::ANY,
            avail: everything.difference(AuthMask::NEGOTIATE),
            ..AuthState::ZERO
        };
        assert!(pick_one_auth(&mut state, AuthMask::ANY));
        assert_eq!(state.picked, AuthMask::BEARER);
    }

    #[test]
    fn digest_ie_alone_picks_nothing() {
        // DIGEST_IE appears in none of the three orderings: it modifies
        // Digest rather than being a mechanism. A server offering only it has
        // offered nothing pickable.
        let mut state = AuthState {
            want: AuthMask::from_bits(u32::MAX),
            avail: AuthMask::DIGEST_IE,
            ..AuthState::ZERO
        };
        assert!(!pick_one_auth(&mut state, AuthMask::from_bits(u32::MAX)));
        assert_eq!(state.picked, AuthMask::PICKNONE);
        assert_eq!(state.avail, AuthMask::NONE);
    }

    #[test]
    fn ntlm_wb_alone_picks_nothing() {
        // The bit exists for vocabulary completeness and has no
        // implementation, so it must never be selected even when a server
        // offers it and an application asks for it.
        let mut state = AuthState {
            want: AuthMask::from_bits(u32::MAX),
            avail: AuthMask::NTLM_WB,
            ..AuthState::ZERO
        };
        assert!(!pick_one_auth(&mut state, AuthMask::from_bits(u32::MAX)));
        assert_eq!(state.picked, AuthMask::PICKNONE);
    }

    #[test]
    fn the_intersection_is_three_way() {
        // `avail & want & mask`, `lib/http.c:340`. A bit present in avail and
        // want but absent from mask must not be picked -- which is exactly
        // how the Bearer restriction works.
        let mut state = AuthState {
            want: AuthMask::BEARER,
            avail: AuthMask::BEARER,
            ..AuthState::ZERO
        };
        let mask = AuthMask::from_bits(u32::MAX).difference(AuthMask::BEARER);
        assert!(!pick_one_auth(&mut state, mask));
        assert_eq!(state.picked, AuthMask::PICKNONE);

        // Wanted but not offered: also nothing.
        let mut state = AuthState {
            want: AuthMask::DIGEST,
            avail: AuthMask::BASIC,
            ..AuthState::ZERO
        };
        assert!(!pick_one_auth(&mut state, AuthMask::ANY));
        assert_eq!(state.picked, AuthMask::PICKNONE);

        // Offered but not wanted: also nothing.
        let mut state = AuthState {
            want: AuthMask::DIGEST,
            avail: AuthMask::DIGEST | AuthMask::BASIC,
            ..AuthState::ZERO
        };
        assert!(pick_one_auth(&mut state, AuthMask::ANY));
        assert_eq!(state.picked, AuthMask::DIGEST);
    }

    #[test]
    fn avail_is_cleared_even_when_nothing_is_picked() {
        // `lib/http.c:369` sits OUTSIDE the chain, so it runs on the failure
        // path. A server's offer is consumed by being considered.
        let mut state = AuthState {
            want: AuthMask::NONE,
            avail: AuthMask::BASIC | AuthMask::DIGEST,
            ..AuthState::ZERO
        };
        assert!(!pick_one_auth(&mut state, AuthMask::ANY));
        assert_eq!(state.avail, AuthMask::NONE);
        assert_eq!(state.picked, AuthMask::PICKNONE);
    }

    #[test]
    fn the_proxy_mask_can_never_carry_bearer() {
        // A structural invariant, not a runtime check: this is the only
        // constructor of a proxy mask in the crate.
        for base in [
            AuthMask::from_bits(u32::MAX),
            AuthMask::ANY,
            AuthMask::ANYSAFE,
            AuthMask::BEARER,
            AuthMask::BEARER | AuthMask::BASIC,
        ] {
            let mask = proxy_auth_mask(base);
            assert!(!mask.intersects(AuthMask::BEARER), "{base:?}");
        }

        // And therefore no proxy arbitration can pick it, however configured.
        let mut state = AuthState {
            want: AuthMask::from_bits(u32::MAX),
            avail: AuthMask::BEARER,
            ..AuthState::ZERO
        };
        assert!(!pick_one_auth(
            &mut state,
            proxy_auth_mask(AuthMask::from_bits(u32::MAX))
        ));
        assert_eq!(state.picked, AuthMask::PICKNONE);
    }

    #[test]
    fn a_state_knows_its_single_picked_scheme() {
        for scheme in EMISSION_ORDER {
            let state = AuthState {
                picked: scheme.mask(),
                ..AuthState::ZERO
            };
            assert_eq!(state.picked_scheme(), Some(scheme));
        }

        // Multi-bit, empty and PICKNONE all resolve to no single scheme --
        // which is the same answer C's equality-tested arms give.
        let multi = AuthState {
            picked: AuthMask::BASIC | AuthMask::DIGEST,
            ..AuthState::ZERO
        };
        assert_eq!(multi.picked_scheme(), None);
        assert_eq!(AuthState::ZERO.picked_scheme(), None);
        let none = AuthState {
            picked: AuthMask::PICKNONE,
            ..AuthState::ZERO
        };
        assert_eq!(none.picked_scheme(), None);
    }

    #[test]
    fn wanting_derives_the_iestyle_bit() {
        let plain = AuthState::wanting(AuthMask::DIGEST);
        assert!(!plain.iestyle());
        let ie = AuthState::wanting(AuthMask::DIGEST | AuthMask::DIGEST_IE);
        assert!(ie.iestyle());
        assert_eq!(ie.want(), AuthMask::DIGEST | AuthMask::DIGEST_IE);

        let mut state = AuthState::ZERO;
        state.set_want(AuthMask::DIGEST_IE);
        assert!(state.iestyle());
        state.set_want(AuthMask::BASIC);
        assert!(!state.iestyle());

        // The accessors and the two flags round-trip.
        assert!(!state.is_done());
        state.set_done(true);
        assert!(state.is_done());
        assert!(!state.is_multipass());
        state.add_avail(AuthMask::NTLM);
        assert_eq!(state.avail(), AuthMask::NTLM);
        assert_eq!(state.picked(), AuthMask::NONE);
    }

    #[test]
    fn the_two_endpoint_states_are_independent() {
        // Origin and proxy never share a value: C carries
        // `data->state.authhost` and `data->state.authproxy` separately.
        let mut pair = AuthStatePair::ZERO;
        pair.select_mut(false).set_want(AuthMask::DIGEST);
        pair.select_mut(true).set_want(AuthMask::BASIC);
        assert_eq!(pair.host.want(), AuthMask::DIGEST);
        assert_eq!(pair.proxy.want(), AuthMask::BASIC);
        assert_eq!(pair.select(false).want(), AuthMask::DIGEST);
        assert_eq!(pair.select(true).want(), AuthMask::BASIC);
        assert_ne!(pair.host, pair.proxy);
    }

    // -- ORDERING 2: `output_auth_headers()`. `lib/http.c:627-740`. --------

    /// Guards with credentials on both sides and no user override, which is
    /// the ordinary case.
    fn open_guards() -> EmissionGuards {
        EmissionGuards {
            proxy_user_passwd: true,
            have_user: true,
            have_bearer: true,
            authorization_overridden: false,
            proxy_authorization_overridden: false,
        }
    }

    #[test]
    fn each_single_bit_pick_selects_its_own_emitter() {
        for scheme in EMISSION_ORDER {
            // AWS SigV4 and Bearer are origin-only arms.
            let sides: &[bool] = match scheme {
                AuthScheme::AwsSigv4 | AuthScheme::Bearer => &[false],
                _ => &[false, true],
            };
            for &proxy in sides {
                let mut state = AuthState {
                    picked: scheme.mask(),
                    ..AuthState::ZERO
                };
                let chosen = select_emitter(&mut state, proxy, &open_guards());
                if scheme == AuthScheme::Negotiate
                    && !cfg!(feature = "negotiate")
                {
                    // C removes the arm with `#ifdef USE_SPNEGO`; without the
                    // feature there is no GSS-API binding to drive.
                    assert_eq!(chosen, None);
                } else {
                    assert_eq!(chosen, Some(scheme), "{scheme:?} {proxy}");
                }
            }
        }
    }

    #[test]
    fn aws_sigv4_is_never_selected_for_a_proxy() {
        // `lib/http.c:643-644`: "this method is never for proxy".
        let mut state = AuthState {
            picked: AuthMask::AWS_SIGV4,
            ..AuthState::ZERO
        };
        assert_eq!(select_emitter(&mut state, true, &open_guards()), None);
        // And with the arm skipped, `done` is untouched: only the Basic and
        // Bearer arms set it unconditionally.
        assert!(!state.is_done());
    }

    #[test]
    fn bearer_is_never_selected_for_a_proxy() {
        let mut state = AuthState {
            picked: AuthMask::BEARER,
            ..AuthState::ZERO
        };
        assert_eq!(select_emitter(&mut state, true, &open_guards()), None);
        // Its arm still ran, so `done` IS set -- `lib/http.c:716`, whose
        // comment says the arm "should set 'done' TRUE, as the other auth
        // functions work that way".
        assert!(state.is_done());
    }

    #[test]
    fn basic_and_bearer_set_done_even_when_their_guard_refuses() {
        // The application supplied its own `Authorization:` header, so curl
        // must not overwrite it -- and still considers authentication done.
        let overridden = EmissionGuards {
            authorization_overridden: true,
            proxy_authorization_overridden: true,
            ..open_guards()
        };

        for (picked, scheme) in [
            (AuthMask::BASIC, AuthScheme::Basic),
            (AuthMask::BEARER, AuthScheme::Bearer),
        ] {
            let mut state = AuthState {
                picked,
                ..AuthState::ZERO
            };
            assert_eq!(select_emitter(&mut state, false, &overridden), None);
            assert!(state.is_done(), "{scheme:?} must still finish");
        }

        // Basic on the proxy side, with the proxy header overridden.
        let mut state = AuthState {
            picked: AuthMask::BASIC,
            ..AuthState::ZERO
        };
        assert_eq!(select_emitter(&mut state, true, &overridden), None);
        assert!(state.is_done());
    }

    #[test]
    fn basic_needs_credentials_on_the_side_it_is_emitting_for() {
        // `lib/http.c:685-696`: the proxy term tests
        // `conn->bits.proxy_user_passwd`, the origin term tests
        // `data->state.aptr.user`, and neither substitutes for the other.
        let no_proxy_creds = EmissionGuards {
            proxy_user_passwd: false,
            ..open_guards()
        };
        let mut state = AuthState {
            picked: AuthMask::BASIC,
            ..AuthState::ZERO
        };
        assert_eq!(select_emitter(&mut state, true, &no_proxy_creds), None);

        let no_user = EmissionGuards {
            have_user: false,
            ..open_guards()
        };
        let mut state = AuthState {
            picked: AuthMask::BASIC,
            ..AuthState::ZERO
        };
        assert_eq!(select_emitter(&mut state, false, &no_user), None);

        // But the proxy side is unaffected by a missing origin username.
        let mut state = AuthState {
            picked: AuthMask::BASIC,
            ..AuthState::ZERO
        };
        assert_eq!(
            select_emitter(&mut state, true, &no_user),
            Some(AuthScheme::Basic)
        );
    }

    #[test]
    fn bearer_needs_a_token() {
        let no_token = EmissionGuards {
            have_bearer: false,
            ..open_guards()
        };
        let mut state = AuthState {
            picked: AuthMask::BEARER,
            ..AuthState::ZERO
        };
        assert_eq!(select_emitter(&mut state, false, &no_token), None);
        assert!(state.is_done());
    }

    #[test]
    fn a_multi_bit_pick_selects_no_emitter() {
        // C's arms test `picked == CURLAUTH_x` with equality, so a `picked`
        // still holding several bits matches nothing, the request goes out
        // unauthenticated, and the 401 that follows drives arbitration.
        let mut state = AuthState {
            picked: AuthMask::BASIC | AuthMask::DIGEST,
            ..AuthState::ZERO
        };
        assert_eq!(select_emitter(&mut state, false, &open_guards()), None);
        assert!(!state.is_done());

        // PICKNONE likewise: it is bit 30 and matches no mechanism.
        let mut state = AuthState {
            picked: AuthMask::PICKNONE,
            ..AuthState::ZERO
        };
        assert_eq!(select_emitter(&mut state, false, &open_guards()), None);
    }

    #[test]
    fn the_emission_diagnostic_is_the_c_string() {
        // `lib/http.c:722-732`, verbatim: "%s auth using %s with user '%s'".
        let mut state = AuthState::ZERO;
        let (_, log) = with_tracer(|tracer| {
            finish_emission(
                &mut state,
                false,
                Some(AuthScheme::Digest),
                Some(&AuthEmission::Final("x".to_owned())),
                Some("alice"),
                tracer,
            );
        });
        assert!(
            log.contains("Server auth using Digest with user 'alice'"),
            "{log}"
        );

        let mut state = AuthState::ZERO;
        let (_, log) = with_tracer(|tracer| {
            finish_emission(
                &mut state,
                true,
                Some(AuthScheme::Ntlm),
                Some(&AuthEmission::Continuing("x".to_owned())),
                Some("bob"),
                tracer,
            );
        });
        assert!(
            log.contains("Proxy auth using NTLM with user 'bob'"),
            "{log}"
        );

        // No username: C prints `""`, so the quotes are empty and present.
        let mut state = AuthState::ZERO;
        let (_, log) = with_tracer(|tracer| {
            finish_emission(
                &mut state,
                false,
                Some(AuthScheme::AwsSigv4),
                Some(&AuthEmission::Final("x".to_owned())),
                None,
                tracer,
            );
        });
        assert!(
            log.contains("Server auth using AWS_SIGV4 with user ''"),
            "{log}"
        );
    }

    #[test]
    fn multipass_is_the_negation_of_done_only_when_a_mechanism_ran() {
        // `lib/http.c:734-737`.
        let mut state = AuthState::ZERO;
        with_tracer(|tracer| {
            finish_emission(
                &mut state,
                false,
                Some(AuthScheme::Ntlm),
                Some(&AuthEmission::Continuing("h".to_owned())),
                Some("u"),
                tracer,
            );
        });
        assert!(!state.is_done());
        assert!(state.is_multipass());

        let mut state = AuthState::ZERO;
        with_tracer(|tracer| {
            finish_emission(
                &mut state,
                false,
                Some(AuthScheme::Digest),
                Some(&AuthEmission::Final("h".to_owned())),
                Some("u"),
                tracer,
            );
        });
        assert!(state.is_done());
        assert!(!state.is_multipass());

        // No mechanism ran: multipass is cleared and nothing is logged.
        let mut state = AuthState {
            multipass: true,
            ..AuthState::ZERO
        };
        let (_, log) = with_tracer(|tracer| {
            finish_emission(&mut state, false, None, None, Some("u"), tracer);
        });
        assert!(!state.is_multipass());
        assert!(log.is_empty(), "{log}");
    }

    #[test]
    fn an_emission_reports_its_own_readiness() {
        // C's `bool *done` out-parameter, now in the return type.
        let final_header = AuthEmission::Final("a".to_owned());
        assert!(final_header.is_done());
        assert_eq!(final_header.header(), Some("a"));

        let continuing = AuthEmission::Continuing("b".to_owned());
        assert!(!continuing.is_done());
        assert_eq!(continuing.header(), Some("b"));

        assert!(AuthEmission::Nothing.is_done());
        assert_eq!(AuthEmission::Nothing.header(), None);
    }

    // -- The emission convention. -----------------------------------------

    #[test]
    fn the_authorization_header_is_byte_exact() {
        // One space after the colon, one after the scheme, CRLF terminated.
        // 168 fixtures compare this line as part of a joined, unnormalised
        // string, so every byte is specification.
        assert_eq!(
            authorization_header(false, "Basic", "dXNlcjpwYXNz"),
            "Authorization: Basic dXNlcjpwYXNz\r\n"
        );
        assert_eq!(
            authorization_header(true, "Basic", "dXNlcjpwYXNz"),
            "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
        );
        assert_eq!(
            authorization_header(false, "Digest", "username=\"u\""),
            "Authorization: Digest username=\"u\"\r\n"
        );
        assert_eq!(
            authorization_header(true, "NTLM", "TlRMTVNTUAAB"),
            "Proxy-Authorization: NTLM TlRMTVNTUAAB\r\n"
        );
        assert_eq!(
            authorization_header(false, "Negotiate", "YIIC"),
            "Authorization: Negotiate YIIC\r\n"
        );
        // `http_output_bearer()` writes no prefix at all, and because Bearer
        // can never be a proxy mechanism the general form produces the same
        // bytes.
        assert_eq!(
            authorization_header(false, "Bearer", "tok"),
            "Authorization: Bearer tok\r\n"
        );

        assert_eq!(header_prefix(true), "Proxy-");
        assert_eq!(header_prefix(false), "");
    }

    #[test]
    fn the_override_header_names_are_the_c_literals() {
        // The proxy literal is spelled with a lower-case `a`
        // (`lib/http.c:688`) where the origin one is not (`:691`). The
        // comparison is case-insensitive so it cannot matter -- and the
        // literal is preserved anyway, because a transcription that silently
        // corrects its source cannot be checked against it.
        assert_eq!(PROXY_AUTHORIZATION_HEADER, "Proxy-authorization");
        assert_eq!(AUTHORIZATION_HEADER, "Authorization");
        assert!(checkprefix(
            PROXY_AUTHORIZATION_HEADER,
            b"Proxy-Authorization: Basic x"
        ));
    }

    // -- ORDERING 3: `authcmp()` and the scan. `lib/http.c:867-1096`. ------

    #[test]
    fn authcmp_is_a_prefix_match_not_followed_by_an_alphanumeric() {
        // `lib/http.c:867-872`: `curl_strnequal(auth, line, n) &&
        // !ISALNUM(line[n])`.
        assert!(authcmp("Negotiate", b"Negotiate "));
        assert!(authcmp("Negotiate", b"Negotiate,"));
        assert!(authcmp("Negotiate", b"negotiate,"));
        assert!(authcmp("Negotiate", b"NEGOTIATE token"));
        // Exactly the scheme name: C reads the NUL terminator, which
        // `ISALNUM` rejects, so it matches.
        assert!(authcmp("Negotiate", b"Negotiate"));
        // An alphanumeric follows: not this scheme.
        assert!(!authcmp("Negotiate", b"Negotiate2"));
        assert!(!authcmp("Negotiate", b"NegotiateX"));
        assert!(!authcmp("Negotiate", b"Negotiate0"));
        // Shorter than the prefix.
        assert!(!authcmp("Negotiate", b"Negotiat"));
        assert!(!authcmp("Negotiate", b""));
        // A different scheme entirely.
        assert!(!authcmp("Negotiate", b"NTLM abc"));

        // The second condition is NOT a whitespace test: every
        // non-alphanumeric byte is admitted, which is what lets the scan see
        // a scheme immediately followed by `=`, `-` or `/`.
        for tail in *b"-=/;\t. " {
            let mut line = b"Basic".to_vec();
            line.push(tail);
            assert!(authcmp("Basic", &line), "tail {tail:?}");
        }
        for tail in *b"aZ7" {
            let mut line = b"Basic".to_vec();
            line.push(tail);
            assert!(!authcmp("Basic", &line), "tail {tail:?}");
        }
    }

    #[test]
    fn a_basic_challenge_sets_the_bit_on_both_state_and_info() {
        let mut scan = ScanState::default();
        let mut decoder = FakeDecoder::default();
        let (result, log) =
            scan.scan(b"Basic realm=\"x\"", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert_eq!(scan.state.avail(), AuthMask::BASIC);
        assert_eq!(scan.reported, AuthMask::BASIC);
        assert!(!scan.problem);
        // Basic carries no challenge body to decode.
        assert!(decoder.seen.is_empty());
        assert!(log.is_empty(), "{log}");
    }

    #[test]
    fn a_picked_basic_that_is_challenged_again_is_a_failure() {
        // `lib/http.c:975-982`: we asked for Basic and got a 40x anyway, so
        // the credentials are wrong. `avail` is cleared ENTIRELY, not just of
        // the Basic bit, which is what stops a fallback to another mechanism
        // the same response offered.
        let mut scan = ScanState::with(AuthMask::BASIC, AuthMask::DIGEST);
        let mut decoder = FakeDecoder::default();
        let (result, log) =
            scan.scan(b"Basic realm=\"x\"", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert_eq!(scan.state.avail(), AuthMask::NONE);
        assert!(scan.problem);
        assert!(log.contains(BASIC_PROBLEM), "{log}");
        assert_eq!(BASIC_PROBLEM, "Basic authentication problem, ignoring.");
        // The transfer-wide report still records the offer.
        assert!(scan.reported.intersects(AuthMask::BASIC));
    }

    #[test]
    fn a_picked_bearer_that_is_challenged_again_is_a_failure() {
        let mut scan = ScanState::with(AuthMask::BEARER, AuthMask::NONE);
        let mut decoder = FakeDecoder::default();
        let (result, log) =
            scan.scan(b"Bearer realm=\"x\"", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert_eq!(scan.state.avail(), AuthMask::NONE);
        assert!(scan.problem);
        assert!(log.contains(BEARER_PROBLEM), "{log}");
        assert_eq!(BEARER_PROBLEM, "Bearer authentication problem, ignoring.");
    }

    #[test]
    fn a_duplicate_digest_header_is_ignored_and_says_so() {
        // `lib/http.c:944-946` is an `else if`, so on a duplicate the bit is
        // not re-set, the decoder is not called, and the diagnostic is the
        // only effect.
        let mut scan = ScanState::with(AuthMask::DIGEST, AuthMask::DIGEST);
        let mut decoder = FakeDecoder::default();
        let (result, log) =
            scan.scan(b"Digest realm=\"x\", nonce=\"y\"", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert!(log.contains(DIGEST_DUPLICATE), "{log}");
        assert_eq!(DIGEST_DUPLICATE, "Ignoring duplicate digest auth header.");
        assert!(decoder.seen.is_empty(), "the decoder must not be called");
        assert_eq!(scan.reported, AuthMask::NONE);
    }

    #[test]
    fn digest_is_decoded_even_when_it_is_not_the_picked_mechanism() {
        // C's comment at `lib/http.c:952-955`: the nonce and realm of a
        // challenge that arrives before arbitration are the ones a later
        // Digest response must quote.
        let mut scan = ScanState::with(AuthMask::NONE, AuthMask::NONE);
        let mut decoder = FakeDecoder::default();
        let challenge = b"Digest realm=\"r\", nonce=\"n\"";
        let (result, _) = scan.scan(challenge, false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert_eq!(decoder.schemes(), vec![AuthScheme::Digest]);
        // The decoder receives the pointer `authcmp` matched -- the scheme
        // token included, exactly as C's `auth` pointer.
        assert_eq!(decoder.seen[0].2, challenge.to_vec());
        assert_eq!(scan.state.avail(), AuthMask::DIGEST);
    }

    #[test]
    fn a_digest_decode_failure_is_a_diagnostic_not_an_error() {
        let mut scan = ScanState::with(AuthMask::DIGEST, AuthMask::NONE);
        let mut decoder = FakeDecoder::failing(
            AuthScheme::Digest,
            CURLcode::BadContentEncoding,
        );
        let (result, log) =
            scan.scan(b"Digest realm=\"r\"", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert!(scan.problem);
        assert!(log.contains(DIGEST_PROBLEM), "{log}");
        assert_eq!(DIGEST_PROBLEM, "Digest authentication problem, ignoring.");
    }

    #[test]
    fn out_of_memory_is_the_one_error_that_propagates() {
        // `lib/http.c:926-929` and `:958-961` return it directly and turn
        // every other failure into a diagnostic.
        for (scheme, token) in [
            (AuthScheme::Digest, &b"Digest realm=\"r\""[..]),
            (AuthScheme::Ntlm, &b"NTLM abc"[..]),
        ] {
            let mut scan = ScanState::with(scheme.mask(), AuthMask::NONE);
            let mut decoder =
                FakeDecoder::failing(scheme, CURLcode::OutOfMemory);
            let (result, log) = scan.scan(token, false, &mut decoder);
            assert_eq!(result, Err(CURLcode::OutOfMemory), "{scheme:?}");
            // No diagnostic: C returns before emitting one.
            assert!(log.is_empty(), "{scheme:?}: {log}");
        }
    }

    #[test]
    fn an_ntlm_decode_failure_is_a_diagnostic_not_an_error() {
        let mut scan = ScanState::with(AuthMask::NTLM, AuthMask::NONE);
        let mut decoder =
            FakeDecoder::failing(AuthScheme::Ntlm, CURLcode::AuthError);
        let (result, log) =
            scan.scan(b"NTLM TlRMTVNTUAAC", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert!(scan.problem);
        assert!(log.contains(NTLM_PROBLEM), "{log}");
        assert_eq!(NTLM_PROBLEM, "NTLM authentication problem, ignoring.");
    }

    #[test]
    fn a_successful_ntlm_decode_clears_a_previous_problem() {
        let mut scan = ScanState::with(AuthMask::NTLM, AuthMask::NONE);
        scan.problem = true;
        let mut decoder = FakeDecoder::default();
        let (result, _) = scan.scan(b"NTLM TlRMTVNTUAAC", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert!(!scan.problem);
        assert_eq!(decoder.schemes(), vec![AuthScheme::Ntlm]);
        assert_eq!(scan.state.avail(), AuthMask::NTLM);
    }

    #[test]
    fn an_unsupported_mechanism_is_skipped_unless_already_offered() {
        // The gate is `(avail & bit) || supported()`: an offer already
        // recorded keeps the mechanism live even where the probe says no.
        let mut scan = ScanState::default();
        let mut decoder = FakeDecoder {
            ntlm: false,
            ..FakeDecoder::default()
        };
        let (result, _) = scan.scan(b"NTLM abc", false, &mut decoder);
        assert_eq!(result, Ok(()));
        assert_eq!(scan.state.avail(), AuthMask::NONE);
        assert_eq!(scan.reported, AuthMask::NONE);

        let mut scan = ScanState::with(AuthMask::NONE, AuthMask::NTLM);
        let (result, _) = scan.scan(b"NTLM abc", false, &mut decoder);
        assert_eq!(result, Ok(()));
        assert_eq!(scan.state.avail(), AuthMask::NTLM);
        assert_eq!(scan.reported, AuthMask::NTLM);

        // Digest's gate is a plain `else if supported()`, with no
        // already-offered escape -- and it is reached only when the bit is
        // NOT already set, because the duplicate branch takes precedence.
        let mut scan = ScanState::default();
        let mut decoder = FakeDecoder {
            digest: false,
            ..FakeDecoder::default()
        };
        let (result, log) =
            scan.scan(b"Digest realm=\"r\"", false, &mut decoder);
        assert_eq!(result, Ok(()));
        assert_eq!(scan.state.avail(), AuthMask::NONE);
        assert!(log.is_empty(), "{log}");
    }

    #[test]
    fn several_schemes_on_one_line_are_all_recorded() {
        // `lib/http.c:1080-1086`: the walk advances past each comma and skips
        // blanks. The whole line is offered, in one response.
        let mut scan = ScanState::default();
        let mut decoder = FakeDecoder::default();
        let (result, _) = scan.scan(
            b"Digest realm=\"r\", nonce=\"n\", Basic realm=\"r\"",
            false,
            &mut decoder,
        );

        assert_eq!(result, Ok(()));
        assert!(scan.state.avail().contains(AuthMask::DIGEST));
        assert!(scan.state.avail().contains(AuthMask::BASIC));
        assert_eq!(scan.reported, AuthMask::DIGEST | AuthMask::BASIC);
    }

    #[test]
    fn the_bearer_arm_has_no_failure_guard() {
        // `lib/http.c:1073` is a bare `if(authcmp(...))` where the four
        // preceding arms are `if(!result && authcmp(...))`. Two consequences,
        // both asserted: Bearer is still tested after an earlier failure, and
        // because `auth_bearer()` returns CURLE_OK it DISCARDS that failure.
        //
        // The line puts Bearer at the same offset as the failing Digest is
        // not possible, so the failure and the Bearer match are on successive
        // offsets: Digest fails on the first, Bearer matches on the second,
        // and the scan continues rather than stopping.
        let mut scan = ScanState::with(AuthMask::DIGEST, AuthMask::NONE);
        let mut decoder =
            FakeDecoder::failing(AuthScheme::Digest, CURLcode::AuthError);
        let (result, log) = scan.scan(
            b"Digest realm=\"r\",Bearer realm=\"r\"",
            false,
            &mut decoder,
        );

        assert_eq!(result, Ok(()));
        assert!(log.contains(DIGEST_PROBLEM), "{log}");
        assert!(scan.state.avail().contains(AuthMask::BEARER));
        assert!(scan.reported.contains(AuthMask::BEARER));
    }

    #[test]
    fn an_out_of_memory_failure_does_not_undo_earlier_side_effects() {
        // C applies each handler's effects as it goes, so a later
        // CURLE_OUT_OF_MEMORY leaves what an earlier handler already did.
        // This is why `ChallengeOutcome` lives in the sink rather than being
        // returned.
        let mut scan = ScanState::with(AuthMask::NTLM, AuthMask::NONE);
        let mut decoder =
            FakeDecoder::failing(AuthScheme::Ntlm, CURLcode::OutOfMemory);
        let (result, _) =
            scan.scan(b"Basic realm=\"r\",NTLM abc", false, &mut decoder);

        assert_eq!(result, Err(CURLcode::OutOfMemory));
        // The Basic bit, recorded before the failure, survives.
        assert!(scan.reported.contains(AuthMask::BASIC));
    }

    #[test]
    fn an_empty_or_unrecognised_line_changes_nothing() {
        let mut scan = ScanState::default();
        let mut decoder = FakeDecoder::default();

        let (result, log) = scan.scan(b"", false, &mut decoder);
        assert_eq!(result, Ok(()));
        assert_eq!(scan.reported, AuthMask::NONE);
        assert!(log.is_empty(), "{log}");

        let (result, _) = scan.scan(b"Kerberos token", false, &mut decoder);
        assert_eq!(result, Ok(()));
        assert_eq!(scan.reported, AuthMask::NONE);
        assert_eq!(scan.state.avail(), AuthMask::NONE);

        // A trailing comma with nothing after it terminates the walk rather
        // than looping: `str_passblanks` leaves an empty remainder and
        // `while(*auth)` stops.
        let (result, _) =
            scan.scan(b"Basic realm=\"r\", ", false, &mut decoder);
        assert_eq!(result, Ok(()));
        assert!(scan.reported.contains(AuthMask::BASIC));
    }

    #[test]
    fn the_proxy_flag_reaches_the_decoder_unchanged() {
        let mut scan = ScanState::with(AuthMask::NTLM, AuthMask::NONE);
        let mut decoder = FakeDecoder::default();
        let (result, _) = scan.scan(b"NTLM abc", true, &mut decoder);
        assert_eq!(result, Ok(()));
        assert_eq!(decoder.seen.len(), 1);
        assert!(decoder.seen[0].1, "the proxy flag must be forwarded");
    }

    #[cfg(feature = "negotiate")]
    #[test]
    fn a_picked_negotiate_challenge_asks_for_the_url_clone() {
        // `lib/http.c:886-902`: on success the handler frees and re-clones
        // `data->req.newurl`, clears `authproblem` and advances the
        // connection's Negotiate state to GSS_AUTHRECV.
        let mut scan = ScanState::with(AuthMask::NEGOTIATE, AuthMask::NONE);
        scan.problem = true;
        let mut decoder = FakeDecoder::default();
        let (result, log) = scan.scan(b"Negotiate YIIC", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert!(!scan.problem);
        assert!(scan.outcome.refresh_url);
        assert!(scan.outcome.negotiate_received);
        assert_eq!(decoder.schemes(), vec![AuthScheme::Negotiate]);
        // This handler has no diagnostic of its own, on either path.
        assert!(log.is_empty(), "{log}");
    }

    #[cfg(feature = "negotiate")]
    #[test]
    fn a_failed_negotiate_challenge_sets_the_problem_without_a_diagnostic() {
        let mut scan = ScanState::with(AuthMask::NEGOTIATE, AuthMask::NONE);
        let mut decoder =
            FakeDecoder::failing(AuthScheme::Negotiate, CURLcode::AuthError);
        let (result, log) = scan.scan(b"Negotiate YIIC", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert!(scan.problem);
        assert!(!scan.outcome.refresh_url);
        assert!(!scan.outcome.negotiate_received);
        assert!(log.is_empty(), "{log}");
    }

    #[cfg(feature = "negotiate")]
    #[test]
    fn an_unusable_spnego_skips_the_negotiate_arm_unless_already_offered() {
        // The gate is `(avail & CURLAUTH_NEGOTIATE) ||
        // Curl_auth_is_spnego_supported()` (`lib/http.c:882`). With no GSS-API
        // library the probe is false, so a first Negotiate offer is skipped
        // entirely -- which is the withholding that keeps the capability
        // banner honest.
        let mut scan = ScanState::with(AuthMask::NEGOTIATE, AuthMask::NONE);
        let mut decoder = FakeDecoder {
            spnego: false,
            ..FakeDecoder::default()
        };
        let (result, log) = scan.scan(b"Negotiate YIIC", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert_eq!(scan.state.avail(), AuthMask::NONE);
        assert_eq!(scan.reported, AuthMask::NONE);
        assert!(decoder.seen.is_empty());
        assert!(!scan.outcome.refresh_url);
        assert!(!scan.outcome.negotiate_received);
        assert!(log.is_empty(), "{log}");

        // An offer already recorded keeps the mechanism live even so, because
        // the probe is cached for the process while the offer is per-response.
        let mut scan =
            ScanState::with(AuthMask::NEGOTIATE, AuthMask::NEGOTIATE);
        let (result, _) = scan.scan(b"Negotiate YIIC", false, &mut decoder);
        assert_eq!(result, Ok(()));
        assert_eq!(scan.state.avail(), AuthMask::NEGOTIATE);
        assert_eq!(scan.reported, AuthMask::NEGOTIATE);
        assert!(scan.outcome.negotiate_received);
    }

    #[cfg(not(feature = "negotiate"))]
    #[test]
    fn without_the_feature_a_negotiate_challenge_is_not_even_examined() {
        // C's `#ifdef USE_SPNEGO` removes the arm entirely, so the bit is
        // never offered and the mechanism can never be picked. Under-reporting
        // is the safe direction: the fixtures that need Negotiate skip.
        let mut scan = ScanState::with(AuthMask::NEGOTIATE, AuthMask::NONE);
        let mut decoder = FakeDecoder::default();
        let (result, log) = scan.scan(b"Negotiate YIIC", false, &mut decoder);

        assert_eq!(result, Ok(()));
        assert_eq!(scan.state.avail(), AuthMask::NONE);
        assert_eq!(scan.reported, AuthMask::NONE);
        assert!(decoder.seen.is_empty());
        assert!(!scan.outcome.refresh_url);
        assert!(log.is_empty(), "{log}");
    }

    #[test]
    fn spnego_support_follows_the_feature_and_the_runtime_probe() {
        // Two conditions, and the second is not a `cfg!`: the GSS-API library
        // resolves at load time. `crate::ffi::gss::available()` answers false
        // under Miri, which is the accurate answer there as well as the
        // conservative one.
        if cfg!(not(feature = "negotiate")) {
            assert!(!is_spnego_supported());
        }
        // Digest and NTLM are unconditional here: both are pure Rust over
        // dependencies this crate always links, so C's `#define ... FALSE`
        // collapses have no Cargo feature to translate into.
        assert!(is_digest_supported());
        assert!(is_ntlm_supported());
    }

    // -- Arbitration. `Curl_http_auth_act()`, `lib/http.c:536-620`. --------

    /// A 401 on a handle that has credentials and has not yet failed.
    fn challenged() -> AuthActInput {
        AuthActInput {
            httpcode: 401,
            authneg: false,
            have_user: true,
            have_bearer: false,
            proxy_user_passwd: false,
            fail_on_error: false,
            httpversion_sent: 11,
            host_done: false,
            is_get_or_head: true,
        }
    }

    fn arbitrate(
        pair: &mut AuthStatePair,
        input: &AuthActInput,
        problem: &mut bool,
    ) -> (Result<AuthActOutcome, CURLcode>, String) {
        with_tracer(|tracer| auth_act(pair, input, problem, false, tracer))
    }

    #[test]
    fn a_1xx_response_is_not_an_authentication_event() {
        // `lib/http.c:547-549`: "this is a transient response code, ignore".
        // An `Expect: 100-continue` handshake must not consume the offer.
        for code in [100, 101, 150, 199] {
            let mut pair = AuthStatePair::ZERO;
            pair.host = AuthState {
                want: AuthMask::ANY,
                avail: AuthMask::BASIC,
                ..AuthState::ZERO
            };
            let mut problem = false;
            let input = AuthActInput {
                httpcode: code,
                ..challenged()
            };
            let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
            let outcome = outcome.expect("1xx returns Ok");
            assert!(!outcome.picked_host, "{code}");
            assert!(!problem);
            // The offer is untouched: `avail` was NOT cleared.
            assert_eq!(pair.host.avail(), AuthMask::BASIC, "{code}");
        }
    }

    #[test]
    fn an_existing_problem_short_circuits_and_only_fails_under_dash_dash_fail()
    {
        // `lib/http.c:551-552`. Without `--fail` this is Ok and arbitration is
        // skipped; with it the transfer fails. Either way no pick happens.
        let mut pair = AuthStatePair::ZERO;
        pair.host.avail = AuthMask::BASIC;
        let mut problem = true;
        let (outcome, _) = arbitrate(&mut pair, &challenged(), &mut problem);
        assert_eq!(outcome, Ok(AuthActOutcome::default()));
        assert_eq!(pair.host.avail(), AuthMask::BASIC);

        let mut problem = true;
        let input = AuthActInput {
            fail_on_error: true,
            ..challenged()
        };
        let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
        assert_eq!(outcome, Err(CURLcode::HttpReturnedError));
    }

    #[test]
    fn a_401_with_credentials_arbitrates_the_host() {
        let mut pair = AuthStatePair::ZERO;
        pair.host = AuthState {
            want: AuthMask::ANY,
            avail: AuthMask::BASIC | AuthMask::DIGEST,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let (outcome, _) = arbitrate(&mut pair, &challenged(), &mut problem);
        let outcome = outcome.expect("a pick succeeds");

        assert!(outcome.picked_host);
        assert!(!outcome.picked_proxy);
        // Digest beats Basic.
        assert_eq!(outcome.host_picked, Some(AuthMask::DIGEST));
        assert_eq!(pair.host.picked(), AuthMask::DIGEST);
        assert!(outcome.rewind_and_refresh_url);
        assert!(!problem);
    }

    #[test]
    fn a_401_with_nothing_pickable_records_a_problem() {
        let mut pair = AuthStatePair::ZERO;
        pair.host = AuthState {
            want: AuthMask::DIGEST,
            avail: AuthMask::BASIC,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let (outcome, _) = arbitrate(&mut pair, &challenged(), &mut problem);
        let outcome = outcome.expect("no pick is not an error by itself");

        assert!(!outcome.picked_host);
        assert_eq!(outcome.host_picked, None);
        assert!(problem);
        assert_eq!(pair.host.picked(), AuthMask::PICKNONE);
        assert!(!outcome.rewind_and_refresh_url);
    }

    #[test]
    fn a_bearer_token_alone_is_enough_to_arbitrate_the_host() {
        // `lib/http.c:554`: the condition is `aptr.user || STRING_BEARER`.
        let mut pair = AuthStatePair::ZERO;
        pair.host = AuthState {
            want: AuthMask::BEARER,
            avail: AuthMask::BEARER,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let input = AuthActInput {
            have_user: false,
            have_bearer: true,
            ..challenged()
        };
        let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
        let outcome = outcome.expect("a pick succeeds");
        assert_eq!(outcome.host_picked, Some(AuthMask::BEARER));
    }

    #[test]
    fn without_a_token_the_bearer_bit_is_masked_out_entirely() {
        // `lib/http.c:542-545` clears it from `authmask` before either
        // arbitration, so an application that asked for Bearer without setting
        // one gets nothing rather than an unusable pick.
        let mut pair = AuthStatePair::ZERO;
        pair.host = AuthState {
            want: AuthMask::from_bits(u32::MAX),
            avail: AuthMask::BEARER,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let input = AuthActInput {
            have_bearer: false,
            ..challenged()
        };
        let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
        assert!(!outcome.expect("Ok").picked_host);
        assert!(problem);
    }

    #[test]
    fn a_407_arbitrates_the_proxy_and_never_offers_bearer() {
        let mut pair = AuthStatePair::ZERO;
        pair.proxy = AuthState {
            want: AuthMask::from_bits(u32::MAX),
            avail: AuthMask::BEARER | AuthMask::BASIC,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let input = AuthActInput {
            httpcode: 407,
            have_user: false,
            have_bearer: true,
            proxy_user_passwd: true,
            ..challenged()
        };
        let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
        let outcome = outcome.expect("a pick succeeds");

        assert!(outcome.picked_proxy);
        assert!(!outcome.picked_host);
        // Bearer was offered, wanted and available -- and excluded anyway.
        assert_eq!(outcome.proxy_picked, Some(AuthMask::BASIC));
        assert_eq!(pair.proxy.picked(), AuthMask::BASIC);
    }

    #[test]
    fn a_407_with_nothing_pickable_records_a_problem() {
        // The proxy half of `lib/http.c:576-579`, which is a separate branch
        // from the host half and sets the same flag.
        let mut pair = AuthStatePair::ZERO;
        pair.proxy = AuthState {
            want: AuthMask::DIGEST,
            avail: AuthMask::BASIC,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let input = AuthActInput {
            httpcode: 407,
            have_user: false,
            proxy_user_passwd: true,
            ..challenged()
        };
        let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
        let outcome = outcome.expect("no pick is not an error by itself");

        assert!(!outcome.picked_proxy);
        assert_eq!(outcome.proxy_picked, None);
        assert!(problem);
        assert_eq!(pair.proxy.picked(), AuthMask::PICKNONE);
        assert!(!outcome.rewind_and_refresh_url);
        // The host was never consulted: a 407 is not a 401.
        assert_eq!(pair.host.picked(), AuthMask::NONE);
    }

    #[test]
    fn a_probe_response_below_300_arbitrates_both_endpoints() {
        // `lib/http.c:556` and `:573`: `data->req.authneg && httpcode < 300`.
        // The zero-length probe learned what is on offer, so the real request
        // can now be authenticated.
        let mut pair = AuthStatePair::ZERO;
        pair.host = AuthState {
            want: AuthMask::ANY,
            avail: AuthMask::NTLM,
            ..AuthState::ZERO
        };
        pair.proxy = AuthState {
            want: AuthMask::ANY,
            avail: AuthMask::BASIC,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let input = AuthActInput {
            httpcode: 200,
            authneg: true,
            proxy_user_passwd: true,
            ..challenged()
        };
        let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
        let outcome = outcome.expect("both picks succeed");
        assert_eq!(outcome.host_picked, Some(AuthMask::NTLM));
        assert_eq!(outcome.proxy_picked, Some(AuthMask::BASIC));
        assert!(outcome.rewind_and_refresh_url);
    }

    #[test]
    fn ntlm_over_a_multiplexed_connection_forces_http11() {
        // `lib/http.c:562-568`. Observable twice over: in `--verbose` and in
        // connection reuse, because the connection is marked for close.
        let mut pair = AuthStatePair::ZERO;
        pair.host = AuthState {
            want: AuthMask::ANY,
            avail: AuthMask::NTLM,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let input = AuthActInput {
            httpversion_sent: 20,
            ..challenged()
        };
        let (outcome, log) = arbitrate(&mut pair, &input, &mut problem);
        let outcome = outcome.expect("a pick succeeds");

        assert!(outcome.force_http11);
        assert!(log.contains(NTLM_FORCE_HTTP11), "{log}");
        assert_eq!(NTLM_FORCE_HTTP11, "Forcing HTTP/1.1 for NTLM");
        assert_eq!(NTLM_FORCE_CLOSE_REASON, "Force HTTP/1.1 connection");

        // Already on HTTP/1.1: nothing to force. The threshold is `> 11`, so
        // 11 itself does not trigger it.
        let mut pair = AuthStatePair::ZERO;
        pair.host = AuthState {
            want: AuthMask::ANY,
            avail: AuthMask::NTLM,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let (outcome, log) = arbitrate(&mut pair, &challenged(), &mut problem);
        assert!(!outcome.expect("Ok").force_http11);
        assert!(!log.contains(NTLM_FORCE_HTTP11), "{log}");
    }

    #[test]
    fn only_ntlm_forces_http11() {
        for scheme in EMISSION_ORDER {
            if scheme == AuthScheme::Ntlm {
                continue;
            }
            let mut pair = AuthStatePair::ZERO;
            pair.host = AuthState {
                want: AuthMask::from_bits(u32::MAX),
                avail: scheme.mask(),
                ..AuthState::ZERO
            };
            let mut problem = false;
            let input = AuthActInput {
                httpversion_sent: 30,
                have_bearer: true,
                ..challenged()
            };
            let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
            assert!(
                !outcome.expect("Ok").force_http11,
                "{scheme:?} must not force HTTP/1.1"
            );
        }
    }

    #[test]
    fn a_probe_that_needed_no_authentication_finishes_the_host() {
        // `lib/http.c:597-612`: nothing was picked, the response is below 300,
        // the host is not done and this was a probe -- so a non-GET/HEAD
        // request is re-issued once, for real, and the host is marked done.
        let mut pair = AuthStatePair::ZERO;
        let mut problem = false;
        let input = AuthActInput {
            httpcode: 200,
            authneg: true,
            have_user: false,
            is_get_or_head: false,
            ..challenged()
        };
        let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
        let outcome = outcome.expect("Ok");
        assert!(outcome.refresh_url_only);
        assert!(!outcome.rewind_and_refresh_url);
        assert!(pair.host.is_done());

        // GET and HEAD carry no body to repeat, so there is nothing to
        // re-issue and `done` is left alone.
        let mut pair = AuthStatePair::ZERO;
        let mut problem = false;
        let input = AuthActInput {
            is_get_or_head: true,
            ..input
        };
        let (outcome, _) = arbitrate(&mut pair, &input, &mut problem);
        assert!(!outcome.expect("Ok").refresh_url_only);
        assert!(!pair.host.is_done());
    }

    #[test]
    fn a_terminal_response_is_reported_after_arbitration() {
        // `lib/http.c:613-617`: `http_should_fail()` is consulted last, so a
        // pick still happens and the state it left behind is intact.
        let mut pair = AuthStatePair::ZERO;
        pair.host = AuthState {
            want: AuthMask::ANY,
            avail: AuthMask::BASIC,
            ..AuthState::ZERO
        };
        let mut problem = false;
        let (outcome, _) = with_tracer(|tracer| {
            auth_act(&mut pair, &challenged(), &mut problem, true, tracer)
        });
        assert_eq!(outcome, Err(CURLcode::HttpReturnedError));
        assert_eq!(pair.host.picked(), AuthMask::BASIC);
    }

    // -- The outer driver. `Curl_http_output_auth()`, `lib/http.c:756-842`. --

    #[test]
    fn nothing_to_do_without_credentials_anywhere() {
        // `lib/http.c:774-789`: "no authentication with no user or password".
        let pair = AuthStatePair::ZERO;
        let empty = EmissionGuards::default();
        assert!(!credentials_offered(&pair, false, &empty));
        assert!(!credentials_offered(&pair, true, &empty));

        let with_user = EmissionGuards {
            have_user: true,
            ..EmissionGuards::default()
        };
        assert!(credentials_offered(&pair, false, &with_user));

        let with_token = EmissionGuards {
            have_bearer: true,
            ..EmissionGuards::default()
        };
        assert!(credentials_offered(&pair, false, &with_token));

        // Proxy credentials count only when there IS an HTTP proxy.
        let with_proxy = EmissionGuards {
            proxy_user_passwd: true,
            ..EmissionGuards::default()
        };
        assert!(credentials_offered(&pair, true, &with_proxy));
        assert!(!credentials_offered(&pair, false, &with_proxy));
    }

    #[test]
    fn wanting_negotiate_is_sufficient_without_any_username() {
        // A Kerberos credentials cache supplies the identity, so
        // `want & CURLAUTH_NEGOTIATE` alone continues -- and only with the
        // feature, because without it there is no binding to drive.
        let mut pair = AuthStatePair::ZERO;
        pair.host.want = AuthMask::NEGOTIATE;
        let empty = EmissionGuards::default();
        assert_eq!(
            credentials_offered(&pair, false, &empty),
            cfg!(feature = "negotiate")
        );

        let mut pair = AuthStatePair::ZERO;
        pair.proxy.want = AuthMask::NEGOTIATE;
        assert_eq!(
            credentials_offered(&pair, false, &empty),
            cfg!(feature = "negotiate")
        );
    }

    #[test]
    fn picked_is_seeded_from_want_before_the_first_round_trip() {
        // `lib/http.c:791-801`, and the comment's own consequence: "if this is
        // one single bit it will be used instantly".
        let mut pair = AuthStatePair::ZERO;
        pair.host.want = AuthMask::DIGEST;
        pair.proxy.want = AuthMask::BASIC | AuthMask::NTLM;
        seed_picked_from_want(&mut pair);

        assert_eq!(pair.host.picked(), AuthMask::DIGEST);
        assert!(pair.host.picked().is_single());
        assert_eq!(pair.host.picked_scheme(), Some(AuthScheme::Digest));

        assert_eq!(pair.proxy.picked(), AuthMask::BASIC | AuthMask::NTLM);
        assert!(!pair.proxy.picked().is_single());
        // Multi-bit: no emitter matches, so the request goes out
        // unauthenticated and the 401 drives arbitration.
        assert_eq!(pair.proxy.picked_scheme(), None);
    }

    #[test]
    fn an_already_picked_state_is_never_reseeded() {
        // The guard is `want && !picked`. Re-seeding would undo a completed
        // arbitration on the next request over the same handle.
        let mut pair = AuthStatePair::ZERO;
        pair.host.want = AuthMask::ANY;
        pair.host.picked = AuthMask::DIGEST;
        seed_picked_from_want(&mut pair);
        assert_eq!(pair.host.picked(), AuthMask::DIGEST);

        // And an empty `want` seeds nothing at all.
        let mut pair = AuthStatePair::ZERO;
        seed_picked_from_want(&mut pair);
        assert_eq!(pair.host.picked(), AuthMask::NONE);
        assert_eq!(pair.proxy.picked(), AuthMask::NONE);
    }

    #[test]
    fn a_probe_is_wanted_only_mid_negotiation_and_only_with_a_body() {
        // `lib/http.c:830-839`.
        let mut pair = AuthStatePair::ZERO;
        assert!(!negotiation_probe_wanted(&pair, false));

        pair.host.multipass = true;
        assert!(negotiation_probe_wanted(&pair, false));
        // GET and HEAD have no body to repeat.
        assert!(!negotiation_probe_wanted(&pair, true));
        // Finished: no further round trip to protect.
        pair.host.done = true;
        assert!(!negotiation_probe_wanted(&pair, false));

        // Either endpoint suffices.
        let mut pair = AuthStatePair::ZERO;
        pair.proxy.multipass = true;
        assert!(negotiation_probe_wanted(&pair, false));
    }

    // -- `lib/vauth/vauth.c` plumbing. -------------------------------------

    #[test]
    fn build_spn_has_three_branches_and_a_none() {
        // `lib/vauth/vauth.c:53-59`, in C's own order.
        assert_eq!(
            build_spn("HTTP", Some("example.com"), Some("EXAMPLE.COM")),
            Some("HTTP/example.com@EXAMPLE.COM".to_owned())
        );
        assert_eq!(
            build_spn("HTTP", Some("example.com"), None),
            Some("HTTP/example.com".to_owned())
        );
        assert_eq!(
            build_spn("HTTP", None, Some("EXAMPLE.COM")),
            Some("HTTP@EXAMPLE.COM".to_owned())
        );
        assert_eq!(build_spn("HTTP", None, None), None);
    }

    #[test]
    fn the_gssapi_call_form_yields_a_host_based_service_name() {
        // THE ARGUMENT-ORDER TRAP. `lib/vauth/spnego_gssapi.c:108` and
        // `lib/vauth/krb5_gssapi.c:100` pass the HOST IN THE REALM SLOT, so
        // the third branch fires and the name is `service@host` -- which is
        // what `GSS_C_NT_HOSTBASED_SERVICE` expects. A "corrected"
        // `service/host` here breaks Kerberos against every real KDC.
        let service = "HTTP";
        let host = "www.example.com";
        assert_eq!(
            build_spn(service, None, Some(host)),
            Some("HTTP@www.example.com".to_owned())
        );
        // The Digest and SSPI call form, for contrast
        // (`lib/vauth/digest.c:420`).
        assert_eq!(
            build_spn(service, Some(host), None),
            Some("HTTP/www.example.com".to_owned())
        );
        assert_ne!(
            build_spn(service, None, Some(host)),
            build_spn(service, Some(host), None),
            "the two call forms must not produce the same name"
        );
    }

    #[test]
    fn user_contains_domain_recognises_the_three_forms() {
        // `lib/vauth/vauth.c:114-132`: a separator from `\/@` that is neither
        // the first nor the last byte.
        assert!(user_contains_domain(Some(b"d\\u")));
        assert!(user_contains_domain(Some(b"d/u")));
        assert!(user_contains_domain(Some(b"u@d")));
        assert!(user_contains_domain(Some(b"DOMAIN\\Administrator")));
        assert!(user_contains_domain(Some(b"alice@EXAMPLE.COM")));

        // Leading separator: no domain before it.
        assert!(!user_contains_domain(Some(b"\\u")));
        assert!(!user_contains_domain(Some(b"@u")));
        assert!(!user_contains_domain(Some(b"/u")));
        // Trailing separator: no user after it.
        assert!(!user_contains_domain(Some(b"d\\")));
        assert!(!user_contains_domain(Some(b"d@")));
        assert!(!user_contains_domain(Some(b"d/")));
        // A separator that is the only byte fails both bounds.
        assert!(!user_contains_domain(Some(b"\\")));
        // No separator at all.
        assert!(!user_contains_domain(Some(b"u")));
        assert!(!user_contains_domain(Some(b"plainuser")));

        // Only the FIRST separator is examined, because that is what
        // `strpbrk` returns -- and here it is at index 0, so a later valid one
        // does not rescue it.
        assert!(!user_contains_domain(Some(b"@d\\u")));
    }

    #[test]
    fn an_absent_username_is_valid_only_where_a_credentials_cache_exists() {
        // C's `#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)` arm:
        // "User and domain are obtained from the GSS-API credentials cache".
        let expected = cfg!(feature = "negotiate");
        assert_eq!(user_contains_domain(None), expected);
        assert_eq!(user_contains_domain(Some(b"")), expected);
    }

    #[test]
    fn credentials_survive_a_redirect_only_to_the_identical_endpoint() {
        // `lib/vauth/vauth.c:138-147`. All three of host, port and protocol
        // must match; each is asserted independently below, because dropping
        // any one of them is a credential leak.
        let first = FirstEndpoint {
            host: Some(b"example.com"),
            port: 443,
            protocol: 2,
        };
        let same = CurrentEndpoint {
            host: b"example.com",
            port: 443,
            protocol: 2,
        };

        // Not a follow at all: always allowed.
        assert!(allowed_to_host(false, false, &first, &same));
        // The application opted in explicitly.
        assert!(allowed_to_host(
            true,
            true,
            &first,
            &CurrentEndpoint {
                host: b"elsewhere.example",
                port: 80,
                protocol: 1,
            }
        ));
        // Identical endpoint.
        assert!(allowed_to_host(true, false, &first, &same));
        // DNS names are case-insensitive, so the host comparison is too.
        assert!(allowed_to_host(
            true,
            false,
            &first,
            &CurrentEndpoint {
                host: b"EXAMPLE.COM",
                ..same
            }
        ));

        // ONLY the host differs.
        assert!(!allowed_to_host(
            true,
            false,
            &first,
            &CurrentEndpoint {
                host: b"evil.example",
                ..same
            }
        ));
        // ONLY the port differs.
        assert!(!allowed_to_host(
            true,
            false,
            &first,
            &CurrentEndpoint { port: 8443, ..same }
        ));
        // ONLY the protocol differs -- an https-to-http downgrade would
        // otherwise put the credentials on the wire in clear.
        assert!(!allowed_to_host(
            true,
            false,
            &first,
            &CurrentEndpoint {
                protocol: 1,
                ..same
            }
        ));

        // No recorded origin: nothing proves the current host is the same one.
        assert!(!allowed_to_host(
            true,
            false,
            &FirstEndpoint {
                host: None,
                ..first
            },
            &same
        ));
    }

    // -- State ownership. --------------------------------------------------

    #[test]
    fn state_scope_distinguishes_connection_from_transfer() {
        // The distinction decides when credentials are reused and is visible:
        // `Curl_auth_ntlm_remove()` removes connection metadata while
        // `Curl_http_auth_cleanup_digest()` clears easy-handle fields.
        assert_eq!(state_scope(AuthScheme::Ntlm), Some(StateScope::Connection));
        assert_eq!(
            state_scope(AuthScheme::Negotiate),
            Some(StateScope::Connection)
        );
        assert_eq!(state_scope(AuthScheme::Digest), Some(StateScope::Transfer));
        // Basic, Bearer and AWS SigV4 recompute per request and store nothing,
        // which is why none of them has a metadata key or a cleanup function.
        assert_eq!(state_scope(AuthScheme::Basic), None);
        assert_eq!(state_scope(AuthScheme::Bearer), None);
        assert_eq!(state_scope(AuthScheme::AwsSigv4), None);

        // Exactly the two multi-pass mechanisms are connection-scoped, and
        // they are exactly the two that need a stable connection: NTLM's
        // three-message exchange and SPNEGO's token sequence.
        let connection: Vec<AuthScheme> = EMISSION_ORDER
            .iter()
            .copied()
            .filter(|s| state_scope(*s) == Some(StateScope::Connection))
            .collect();
        assert_eq!(connection, vec![AuthScheme::Negotiate, AuthScheme::Ntlm]);
    }

    #[test]
    fn the_two_mechanism_slots_are_independent() {
        // C's two metadata keys per mechanism, as two typed fields. The keys
        // themselves -- including the upstream `ntml` typo -- are not
        // reproduced: they are internal, and nothing observable depends on
        // their spelling.
        let mut slots: MechanismSlots<u32> = MechanismSlots::empty();
        assert_eq!(slots.peek(false), None);
        assert_eq!(slots.peek(true), None);

        *slots.get_or_default(false) = 7;
        assert_eq!(slots.peek(false), Some(&7));
        assert_eq!(slots.peek(true), None, "the proxy slot is separate");

        *slots.get_or_default(true) = 9;
        assert_eq!(slots.peek(false), Some(&7));
        assert_eq!(slots.peek(true), Some(&9));

        // `get_or_default` is idempotent: it creates once, then returns.
        assert_eq!(*slots.get_or_default(false), 7);

        // `Curl_auth_ntlm_remove()` on one side leaves the other alone.
        assert_eq!(slots.remove(false), Some(7));
        assert_eq!(slots.peek(false), None);
        assert_eq!(slots.peek(true), Some(&9));
        assert_eq!(slots.remove(false), None);
        assert_eq!(slots.remove(true), Some(9));
    }

    // -- The SASL slice. `lib/curl_sasl.h` and `lib/curl_sasl.c`. -----------

    #[test]
    fn sasl_mech_integers_are_the_header_values() {
        // `lib/curl_sasl.h:32-42`, as literals.
        assert_eq!(SaslMech::LOGIN.bits(), 1);
        assert_eq!(SaslMech::PLAIN.bits(), 2);
        assert_eq!(SaslMech::CRAM_MD5.bits(), 4);
        assert_eq!(SaslMech::DIGEST_MD5.bits(), 8);
        assert_eq!(SaslMech::GSSAPI.bits(), 16);
        assert_eq!(SaslMech::EXTERNAL.bits(), 32);
        assert_eq!(SaslMech::NTLM.bits(), 64);
        assert_eq!(SaslMech::XOAUTH2.bits(), 128);
        assert_eq!(SaslMech::OAUTHBEARER.bits(), 256);
        assert_eq!(SaslMech::SCRAM_SHA_1.bits(), 512);
        assert_eq!(SaslMech::SCRAM_SHA_256.bits(), 1024);

        // `lib/curl_sasl.h:45-47`.
        assert_eq!(SaslMech::AUTH_NONE.bits(), 0);
        assert_eq!(SaslMech::AUTH_ANY.bits(), 0xffff);
        assert_eq!(SaslMech::AUTH_DEFAULT.bits(), 0xffdf);
        // The same derivation at run time as the constant performs at compile
        // time, so `difference` is exercised rather than only const-evaluated.
        assert_eq!(
            SaslMech::AUTH_ANY.difference(SaslMech::EXTERNAL),
            SaslMech::AUTH_DEFAULT
        );
        assert_eq!(
            SaslMech::LOGIN
                .union(SaslMech::PLAIN)
                .difference(SaslMech::LOGIN),
            SaslMech::PLAIN
        );
        assert!(!SaslMech::AUTH_DEFAULT.intersects(SaslMech::EXTERNAL));
        assert!(SaslMech::AUTH_ANY.intersects(SaslMech::EXTERNAL));
        assert!(SaslMech::AUTH_NONE.is_empty());
        assert_eq!(
            SaslMech::from_bits(3),
            SaslMech::LOGIN.union(SaslMech::PLAIN)
        );

        // The two vocabularies overlap numerically and must not be confused:
        // bit 6 is SASL NTLM and CURLAUTH Bearer.
        assert_eq!(SaslMech::NTLM.bits(), 64);
        assert_eq!(AuthMask::BEARER.bits(), 64);
    }

    #[test]
    fn the_mechanism_table_is_self_consistent() {
        // C carries `len` beside `name`; nothing checks that they agree, so
        // this does. The redundancy is kept because `decode_mech` uses `len`
        // as both the comparison bound and the index it inspects afterwards.
        assert_eq!(MECHTABLE.len(), 11);
        for row in MECHTABLE {
            assert_eq!(
                row.len,
                row.name.len(),
                "{} declares length {}",
                row.name,
                row.len
            );
            assert!(
                row.name.bytes().all(|b| b.is_ascii_uppercase()
                    || b.is_ascii_digit()
                    || b == b'-'),
                "{} must be spelled in the registered alphabet",
                row.name
            );
        }

        // The declared lengths, from `lib/curl_sasl.c:54-64`, as literals.
        let lengths: Vec<usize> = MECHTABLE.iter().map(|row| row.len).collect();
        assert_eq!(lengths, vec![5, 5, 8, 10, 6, 8, 4, 7, 11, 11, 13]);

        // Every bit is distinct, and every one is a single bit.
        let mut union = SaslMech::AUTH_NONE;
        for row in MECHTABLE {
            assert!(!union.intersects(row.bit), "{} repeats a bit", row.name);
            union = union.union(row.bit);
        }
        assert_eq!(union.bits(), 0x07ff);
    }

    #[test]
    fn decode_mech_resolves_login_and_plain_despite_their_equal_lengths() {
        // Both are five bytes, so a length-keyed dispatch is ambiguous. The C
        // matches the NAME first and uses the length only as a bound.
        assert_eq!(decode_mech(b"LOGIN"), Some((SaslMech::LOGIN, 5)));
        assert_eq!(decode_mech(b"PLAIN"), Some((SaslMech::PLAIN, 5)));
        assert_eq!(decode_mech(b"LOGIN "), Some((SaslMech::LOGIN, 5)));
        assert_eq!(decode_mech(b"PLAIN "), Some((SaslMech::PLAIN, 5)));
        assert_ne!(decode_mech(b"LOGIN"), decode_mech(b"PLAIN"));
    }

    #[test]
    fn decode_mech_resolves_every_row() {
        for row in MECHTABLE {
            assert_eq!(
                decode_mech(row.name.as_bytes()),
                Some((row.bit, row.len)),
                "{}",
                row.name
            );
            // Case-insensitive: `curl_strnequal`.
            let lowered = row.name.to_ascii_lowercase();
            assert_eq!(
                decode_mech(lowered.as_bytes()),
                Some((row.bit, row.len)),
                "{lowered}"
            );
        }
        // Vocabulary-only rows still decode, because the table IS the
        // vocabulary -- none of the three has an implementation.
        assert_eq!(decode_mech(b"CRAM-MD5"), Some((SaslMech::CRAM_MD5, 8)));
        assert_eq!(
            decode_mech(b"SCRAM-SHA-1"),
            Some((SaslMech::SCRAM_SHA_1, 11))
        );
        assert_eq!(
            decode_mech(b"SCRAM-SHA-256"),
            Some((SaslMech::SCRAM_SHA_256, 13))
        );
    }

    #[test]
    fn the_sasl_delimiter_set_is_not_the_http_one() {
        // `lib/curl_sasl.c:97`: a name CONTINUES on upper case, a digit, `-`
        // or `_`, so anything else terminates it -- INCLUDING a lower-case
        // letter, where the HTTP scheme test would reject one. SASL mechanism
        // names are upper case by registration, so a lower-case byte cannot be
        // part of one.
        assert_eq!(decode_mech(b"LOGINx"), Some((SaslMech::LOGIN, 5)));
        assert!(!authcmp("Basic", b"Basicx"));

        // The four continuation bytes.
        assert_eq!(decode_mech(b"LOGINX"), None);
        assert_eq!(decode_mech(b"LOGIN2"), None);
        assert_eq!(decode_mech(b"LOGIN-"), None);
        assert_eq!(decode_mech(b"LOGIN_"), None);
        // And a few that terminate.
        assert_eq!(decode_mech(b"LOGIN,"), Some((SaslMech::LOGIN, 5)));
        assert_eq!(decode_mech(b"LOGIN="), Some((SaslMech::LOGIN, 5)));
        assert_eq!(decode_mech(b"LOGIN\t"), Some((SaslMech::LOGIN, 5)));

        // Shorter than any name, and a name that is not in the table.
        assert_eq!(decode_mech(b"LOG"), None);
        assert_eq!(decode_mech(b""), None);
        assert_eq!(decode_mech(b"ANONYMOUS"), None);

        // `SCRAM-SHA-1` is a prefix of `SCRAM-SHA-256`, and the table's order
        // puts the shorter first -- so the longer must still resolve, which it
        // does because `-` and the digits continue the name.
        assert_eq!(
            decode_mech(b"SCRAM-SHA-256"),
            Some((SaslMech::SCRAM_SHA_256, 13))
        );
    }

    #[test]
    fn the_sasl_formatter_names_bits_and_keeps_the_residue() {
        assert_eq!(format!("{:?}", SaslMech::AUTH_NONE), "SASL_AUTH_NONE");
        assert_eq!(format!("{:?}", SaslMech::LOGIN), "LOGIN");
        assert_eq!(
            format!("{:?}", SaslMech::LOGIN.union(SaslMech::PLAIN)),
            "LOGIN|PLAIN"
        );
        assert_eq!(format!("{:?}", SaslMech::from_bits(0x0800)), "0x0800");
        // AUTH_ANY's five unnamed bits stay visible.
        let rendered = format!("{:?}", SaslMech::AUTH_ANY);
        assert!(rendered.contains("LOGIN"), "{rendered}");
        assert!(rendered.contains("0xf800"), "{rendered}");
    }

    #[test]
    fn the_curlauth_translation_maps_the_five_documented_bits() {
        // `lib/curl_sasl.c:162-171`, one assertion per mapping.
        assert_eq!(
            curlauth_to_sasl_mechs(AuthMask::BASIC),
            SaslMech::PLAIN.union(SaslMech::LOGIN)
        );
        assert_eq!(
            curlauth_to_sasl_mechs(AuthMask::DIGEST),
            SaslMech::DIGEST_MD5
        );
        assert_eq!(curlauth_to_sasl_mechs(AuthMask::NTLM), SaslMech::NTLM);
        assert_eq!(
            curlauth_to_sasl_mechs(AuthMask::BEARER),
            SaslMech::OAUTHBEARER.union(SaslMech::XOAUTH2)
        );
        assert_eq!(curlauth_to_sasl_mechs(CURLAUTH_GSSAPI), SaslMech::GSSAPI);
        // The GSSAPI spelling is CURLAUTH_NEGOTIATE under its other name.
        assert_eq!(
            curlauth_to_sasl_mechs(AuthMask::NEGOTIATE),
            SaslMech::GSSAPI
        );

        // Four bits map to nothing.
        for unmapped in [
            AuthMask::DIGEST_IE,
            AuthMask::AWS_SIGV4,
            AuthMask::NTLM_WB,
            AuthMask::ONLY,
        ] {
            assert_eq!(
                curlauth_to_sasl_mechs(unmapped),
                SaslMech::AUTH_NONE,
                "{unmapped:?}"
            );
        }

        // Unions translate termwise.
        assert_eq!(
            curlauth_to_sasl_mechs(AuthMask::BASIC | AuthMask::NTLM),
            SaslMech::PLAIN.union(SaslMech::LOGIN).union(SaslMech::NTLM)
        );
    }

    #[test]
    fn basic_alone_leaves_the_protocol_default_untouched() {
        // `lib/curl_sasl.c:157` guards the whole override with
        // `if(auth != CURLAUTH_BASIC)` -- an EQUALITY against the single bit.
        let defaults = SaslMech::AUTH_DEFAULT;
        assert_eq!(sasl_preferred_mechs(AuthMask::BASIC, defaults), defaults);

        // `BASIC | DIGEST` does NOT equal `BASIC`, so it does override -- the
        // counter-intuitive reading, and the C's.
        assert_eq!(
            sasl_preferred_mechs(AuthMask::BASIC | AuthMask::DIGEST, defaults),
            SaslMech::PLAIN
                .union(SaslMech::LOGIN)
                .union(SaslMech::DIGEST_MD5)
        );

        // An option value that translates to nothing keeps the default, rather
        // than leaving the transfer with no mechanism to offer.
        assert_eq!(
            sasl_preferred_mechs(AuthMask::AWS_SIGV4, defaults),
            defaults
        );
        assert_eq!(sasl_preferred_mechs(AuthMask::NONE, defaults), defaults);

        // And a genuine single-mechanism selection replaces it.
        assert_eq!(
            sasl_preferred_mechs(AuthMask::NTLM, defaults),
            SaslMech::NTLM
        );
    }

    // -- Credentials and the mechanism abstraction. ------------------------

    #[test]
    fn the_credentials_formatter_prints_the_user_and_hides_the_secret() {
        const SECRET: &str = "s3cr3t-p4ssw0rd";
        let creds = Credentials::new(Some(b"alice"), Some(SECRET.as_bytes()));
        let rendered = format!("{creds:?}");

        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        // The username IS printed, because curl prints it itself in the
        // `--verbose` diagnostic of every authenticated request.
        assert!(rendered.contains("alice"), "{rendered}");
        assert_eq!(REDACTED_PLACEHOLDER, "<redacted>");

        // The accessors still return it -- the formatter is the boundary, not
        // the storage.
        assert_eq!(creds.user(), Some(&b"alice"[..]));
        assert_eq!(creds.secret(), Some(SECRET.as_bytes()));
        assert_eq!(creds.user_for_diagnostic(), "alice");

        // Absent halves print as absent rather than as an empty secret.
        let empty = Credentials::none();
        let rendered = format!("{empty:?}");
        assert!(!rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        assert_eq!(empty.user(), None);
        assert_eq!(empty.secret(), None);
        assert_eq!(empty.user_for_diagnostic(), "");

        // A non-UTF-8 username reaches a diagnostic lossily rather than
        // panicking: C hands the bytes to `%s` and this must not be the one
        // place a transfer dies.
        let odd = Credentials::new(Some(&[0xff, b'a']), None);
        assert_eq!(odd.user_for_diagnostic(), "\u{fffd}a");
        let _ = format!("{odd:?}");
    }

    #[test]
    fn no_secret_reaches_the_trace_sink() {
        // The binding form of the credential-handling requirement: curl has NO
        // redaction mechanism, and 168 fixtures compare a literal
        // `Authorization: ` line byte for byte, so the header must carry the
        // credential. What must never happen is a NEW logging path.
        const SECRET: &str = "correct-horse-battery-staple";
        // Deliberately shaped so that it carries none of the vendor prefixes
        // that credential scanners key on. The test needs a distinctive needle
        // to search the captured logs for, not a realistic-looking token.
        const TOKEN: &str = "not-a-real-bearer-token-0000";

        let creds = Credentials::new(Some(b"alice"), Some(SECRET.as_bytes()));

        // Drive a full flow: a challenge scan, an arm selection, and the
        // trailing diagnostic, all with tracing at its most verbose.
        let mut state = AuthState {
            want: AuthMask::ANY,
            picked: AuthMask::DIGEST,
            ..AuthState::ZERO
        };
        let mut reported = AuthMask::NONE;
        let mut problem = false;
        let mut decoder = FakeDecoder::default();

        let (_, scan_log) = {
            let mut sink =
                ChallengeSink::new(&mut state, &mut reported, &mut problem);
            with_tracer(|tracer| {
                input_auth(
                    b"Digest realm=\"r\", nonce=\"n\", Basic realm=\"r\"",
                    false,
                    &mut sink,
                    &mut decoder,
                    tracer,
                )
            })
        };

        let header = authorization_header(
            false,
            AuthScheme::Digest
                .header_scheme()
                .expect("Digest has a token"),
            "username=\"alice\", response=\"deadbeef\"",
        );
        let emission = AuthEmission::Final(header.clone());

        let (_, emit_log) = with_tracer(|tracer| {
            finish_emission(
                &mut state,
                false,
                Some(AuthScheme::Digest),
                Some(&emission),
                Some(&creds.user_for_diagnostic()),
                tracer,
            );
        });

        let (_, arb_log) = {
            let mut pair = AuthStatePair::ZERO;
            pair.host = AuthState {
                want: AuthMask::ANY,
                avail: AuthMask::NTLM,
                ..AuthState::ZERO
            };
            let mut problem = false;
            let input = AuthActInput {
                httpversion_sent: 20,
                have_bearer: true,
                ..challenged()
            };
            with_tracer(|tracer| {
                auth_act(&mut pair, &input, &mut problem, false, tracer)
            })
        };

        for log in [&scan_log, &emit_log, &arb_log] {
            assert!(!log.contains(SECRET), "secret leaked: {log}");
            assert!(!log.contains(TOKEN), "token leaked: {log}");
        }

        // The username IS in the log, because curl puts it there.
        assert!(emit_log.contains("alice"), "{emit_log}");
        // And the header line DOES carry the credential material, because the
        // fixtures require it -- the rule is "no new logging", not "redact".
        assert!(header.contains("response=\"deadbeef\""));
        assert!(emission.header().is_some());
    }

    #[test]
    fn the_context_formatter_reveals_only_wire_visible_material() {
        // The method and the target both go on the wire in the request line,
        // so printing them adds nothing; the random source has no `Debug`
        // bound at all, which is why this formatter is hand-written.
        //
        // Both sources are the INJECTED test implementations, not the host's.
        // That is the point of the injection rather than an accommodation of
        // it: a deterministic clock and a seeded generator make the assertions
        // below exact, and they keep this test runnable under Miri, which
        // cannot call `clock_gettime` with isolation enabled and whose gate
        // deliberately passes no flags to relax that.
        let clock =
            crate::util::timeval::TestClock::new(CurlTime::new(1_000, 0));
        clock.set_epoch_secs(1_700_000_000);
        let mut rng = crate::crypto::rand::TestRng::from_seed(7);
        let ctx = AuthContext {
            proxy: false,
            request_method: b"GET",
            request_target: b"/index.html?q=1",
            clock: &clock,
            rng: &mut rng,
        };

        let rendered = format!("{ctx:?}");
        assert!(rendered.contains("GET"), "{rendered}");
        assert!(rendered.contains("/index.html?q=1"), "{rendered}");
        assert!(rendered.contains(".."), "must be non-exhaustive");

        // The injected sources are usable THROUGH the context, which is what
        // keeps the siblings testable without a global -- Digest needs a
        // client nonce and a timestamp, NTLM needs the generator.
        assert_eq!(ctx.clock.epoch_secs(), 1_700_000_000);
        assert_eq!(ctx.clock.now(), CurlTime::new(1_000, 0));
        let mut first = [0u8; 8];
        ctx.rng.fill_bytes(&mut first);
        let mut second = [0u8; 8];
        ctx.rng.fill_bytes(&mut second);
        assert_ne!(first, second, "a generator must advance");

        // A second context over an identically seeded generator reproduces the
        // same bytes, which is what makes a mechanism's output assertable.
        let mut replay = crate::crypto::rand::TestRng::from_seed(7);
        let mut again = [0u8; 8];
        replay.fill_bytes(&mut again);
        assert_eq!(first, again);

        assert_eq!(ctx.request_method, b"GET");
        assert!(!ctx.proxy);
    }

    #[test]
    fn the_trait_default_predicates_are_the_production_wiring() {
        // The three support predicates have DEFAULT bodies on the trait, and
        // those bodies are what the six sibling modules will inherit. A
        // decoder that overrides them -- as `FakeDecoder` does, so that both
        // answers are drivable -- never executes them, so this decoder does
        // not override them.
        let decoder = DefaultDecoder::default();
        assert_eq!(decoder.digest_supported(), is_digest_supported());
        assert_eq!(decoder.ntlm_supported(), is_ntlm_supported());
        assert_eq!(decoder.spnego_supported(), is_spnego_supported());
        assert!(decoder.digest_supported());
        assert!(decoder.ntlm_supported());

        // And it drives a real scan through those defaults: Digest and NTLM
        // are unconditionally supported, so both bits are offered.
        let mut state = AuthState {
            picked: AuthMask::DIGEST,
            ..AuthState::ZERO
        };
        let mut reported = AuthMask::NONE;
        let mut problem = false;
        let mut decoder = DefaultDecoder::default();
        let (result, log) = {
            let mut sink =
                ChallengeSink::new(&mut state, &mut reported, &mut problem);
            with_tracer(|tracer| {
                input_auth(
                    b"Digest realm=\"r\", nonce=\"n\", NTLM abc",
                    false,
                    &mut sink,
                    &mut decoder,
                    tracer,
                )
            })
        };

        assert_eq!(result, Ok(()));
        assert!(log.is_empty(), "{log}");
        assert_eq!(reported, AuthMask::DIGEST | AuthMask::NTLM);
        // Only Digest was picked, so only Digest was decoded.
        assert_eq!(decoder.seen, vec![AuthScheme::Digest]);
        assert!(!problem);
    }
}
