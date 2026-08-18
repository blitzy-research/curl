//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// Copyright (C) Markus Moeller, <markus_moeller@compuserve.com>
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

//! SOCKS5 GSS-API authentication and protection-level negotiation, RFC 1961.
//!
//! Supersedes `lib/socks_gssapi.c` (533 lines) in full. The C file is guarded
//! by `#if defined(HAVE_GSSAPI) && !defined(CURL_DISABLE_PROXY)`
//! (`lib/socks_gssapi.c:27`); the successor of that guard is the default-off
//! `negotiate` Cargo feature, which `proxy/mod.rs` applies to this module's
//! declaration. Nothing here is gated a second time.
//!
//! # Every byte and every line of text here is frozen
//!
//! This is a binary framed sub-negotiation. Both directions carry
//!
//! ```text
//!     +-----+------+-----+------------------+
//!     | VER | MTYP | LEN |      TOKEN       |
//!     +-----+------+-----+------------------+
//!     |  1  |  1   |  2  |  up to 2^16 - 1  |
//!     +-----+------+-----+------------------+
//! ```
//!
//! with `VER` = 1 -- the GSS-API sub-negotiation version, **not** the SOCKS
//! version 5 -- `MTYP` one of 1 (authentication), 2 (protection level) or 255
//! (rejection), and `LEN` a 16-bit count in network byte order.
//!
//! The harness compares wire bytes literally: `compareparts`
//! (`tests/getpart.pm:351-401`) joins the actual and the expected arrays into
//! two strings and compares them with Perl `ne`, so there is no per-line
//! matching, no normalisation and no reordering. The same discipline covers
//! the text: every `failf` line reaches `CURLOPT_ERRORBUFFER` and every
//! `infof` line reaches `--verbose`, so each one lives exactly once, in
//! [`msg`], beside the C line it is transcribed from. AAP section 0.8.1 places
//! all of it outside this migration's authority to change -- including
//! `"Failed to initial GSS-API token."`, whose wording is the C's and is
//! reproduced verbatim rather than corrected.
//!
//! # There is no blocking-mode toggle here, and none must be added
//!
//! The C function opens by clearing the socket's non-blocking flag
//! (`lib/socks_gssapi.c:169`) and closes by setting it again (`:515`): the
//! socket is switched to BLOCKING for the whole handshake and back afterwards,
//! which is why `Curl_blockread_all` exists at all (`lib/socks.h:30-39`,
//! *"This is STUPID BLOCKING behavior"*).
//!
//! That blocking-mode toggle has no successor. This module expresses the
//! exchange as a plain sequential series of sends and read-exactlys, and the
//! waiting, the deadline and the would-block retry all live in
//! [`SocksProxy::blockread_all`] -- which manipulates no socket flag either,
//! because a readiness wait plus a would-block retry do between them exactly
//! what the C's blocking read did. The *observable wire bytes and their
//! ordering are identical*; only the local flag manipulation disappears. A
//! future reader must not "restore" it.
//!
//! # Why the entry point is synchronous
//!
//! [`GssapiNegotiator::negotiate`] takes `&self` and returns
//! [`CurlResult<()>`]. That is the contract `crate::proxy::socks` declares and
//! this module consumes rather than redefines, and it is the same shape as
//! every other seam in that module: [`SocksConn`] answers connection facts
//! synchronously, [`DestinationResolver`] polls a lookup in two calls, and
//! [`ConnFilter`] itself is synchronous exactly as `struct Curl_cftype` is.
//! The asynchrony sits one level down, behind [`GssWire`], whose sole intended
//! implementor is the `"SOCKS"` filter: `blockread_all` awaits
//! `conn::select::socket_readable` and takes its budget from
//! [`SocksConn::time_left_ms`], whose three-way convention is that zero means
//! no limit, a negative reading means the deadline has already passed and a
//! positive one is the milliseconds remaining.
//!
//! # What the seams replace
//!
//! Nothing here reads a god struct, and nothing here holds a GSS-API handle.
//! The four facts the C reaches for through `data` and `cf->conn` arrive
//! through [`GssConn`]; the two byte operations through [`GssWire`]; the two
//! diagnostic calls through [`Reporter`]; and the six GSS-API calls through
//! [`GssSession`], whose platform implementation is the only thing in this
//! file that touches `crate::ffi`. That is what lets the whole exchange be
//! tested byte-for-byte with no KDC, no network and no clock, which is the
//! entire reason the seams exist.
//!
//! # The deliberate dead end
//!
//! A negotiation that settles on integrity or confidentiality succeeds here
//! and is then refused by the caller: `lib/socks.c:1166-1171`, reproduced at
//! `crate::proxy::socks`'s `SOCKS5_ST_REQ1_SEND` arm, answers a non-zero
//! `conn->socks5_gssapi_enctype` with *"SOCKS5 GSS-API protection not yet
//! implemented."* and [`CURLproxycode::GssapiProtection`]. That is the state
//! of curl 8.19.0-DEV: per-message protection is negotiated and then declined.
//! Under AAP section 0.8.1 it is reproduced exactly -- not implemented, not
//! improved, and not quietly downgraded to level 0 to dodge the failure.
//!
//! Link targets are written out below rather than inline, for the reason
//! `crate::proxy::socks` records: `proxy/mod.rs` carries OUTER documentation on
//! its `mod socks_gss;` declaration, rustdoc merges that with this inner block
//! and then resolves the whole of it in the PARENT module's scope, where none
//! of these names is visible.
//!
//! [`msg`]: crate::proxy::socks_gss::msg
//! [`GssConn`]: crate::proxy::socks_gss::GssConn
//! [`GssWire`]: crate::proxy::socks_gss::GssWire
//! [`GssSession`]: crate::proxy::socks_gss::GssSession
//! [`Reporter`]: crate::proxy::socks_gss::Reporter
//! [`CurlResult<()>`]: crate::error::CurlResult
//! [`ConnFilter`]: crate::conn::filters::ConnFilter
//! [`SocksConn`]: crate::proxy::socks::SocksConn
//! [`SocksConn::time_left_ms`]: crate::proxy::socks::SocksConn::time_left_ms
//! [`DestinationResolver`]: crate::proxy::socks::DestinationResolver
//! [`SocksProxy::blockread_all`]: crate::proxy::socks::SocksProxy::blockread_all
//! [`GssapiNegotiator::negotiate`]: crate::proxy::socks::GssapiNegotiator::negotiate
//! [`CURLproxycode::GssapiProtection`]: crate::proxy::CURLproxycode::GssapiProtection

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use crate::error::{CURLcode, CurlResult, Error};
use crate::ffi::{
    Delegation, Diagnostics, HandshakeState, Mechanism, NameType,
    SecurityContext, StepOptions, TargetName,
    SOCKS5_PROTECTION_CONFIDENTIALITY, SOCKS5_PROTECTION_INTEGRITY,
    SOCKS5_PROTECTION_NONE,
};
use crate::proxy::socks::GssapiNegotiator;
use crate::util::dynbuf::DynBuf;

// The frozen protocol constants
//
// Transcribed from `lib/socks_gssapi.c` rather than derived. Each one is a
// number a SOCKS5 server compares against, so AAP section 0.8.1 places it
// outside this migration's authority.

/// `#define MAX_GSS_LEN 1024` (`lib/socks_gssapi.c:43`).
///
/// The ceiling of the `struct dynbuf` that [`check_gss_err`] assembles its
/// message in -- `curlx_dyn_init(&dbuf, MAX_GSS_LEN)` (`:59`). It is a *limit*,
/// not a capacity: an append that would cross it fails, and the C answers that
/// failure by returning 1 with no message emitted at all (`:69`, `:76`). That
/// silent path is reproduced.
///
/// [`check_gss_err`]: crate::proxy::socks_gss::check_gss_err
const MAX_GSS_LEN: usize = 1024;

/// The `VER` byte: the GSS-API sub-negotiation version, `1`
/// (`lib/socks_gssapi.c:201`, `:326`).
///
/// **Not 5.** The SOCKS version and the sub-negotiation version are different
/// numbers in different fields, and RFC 1961 fixes this one at 1.
const SUBNEGOTIATION_VERSION: u8 = 1;

/// `MTYP` 1: an authentication message (`lib/socks_gssapi.c:202`).
const MTYP_AUTHENTICATION: u8 = 1;

/// `MTYP` 2: a protection-level negotiation message
/// (`lib/socks_gssapi.c:327`).
const MTYP_PROTECTION: u8 = 2;

/// `MTYP` 255: the server rejected the user (`lib/socks_gssapi.c:250`,
/// `:439`).
///
/// Read at both response sites and never written.
const MTYP_REJECTION: u8 = 255;

/// `unsigned char socksreq[4]` (`lib/socks_gssapi.c:121`), *"room for GSS-API
/// exchange header only"*: `VER`, `MTYP` and the two `LEN` bytes.
const EXCHANGE_HEADER_LEN: usize = 4;

/// The largest token the 16-bit `LEN` field can announce, `0xffff`
/// (`lib/socks_gssapi.c:192`).
const MAX_TOKEN_LEN: usize = 0xffff;

/// The service name used when `CURLOPT_PROXY_SERVICE_NAME` is unset:
/// `"rcmd"` (`lib/socks_gssapi.c:123`).
const DEFAULT_SERVICE_NAME: &str = "rcmd";

/// The `LEN` a protection-level message carries on the NEC-compatibility path:
/// `us_length = htons((short)1)` (`lib/socks_gssapi.c:372`).
///
/// One byte, in clear. See [`Socks5Gssapi::exchange_protection_level`].
///
/// [`Socks5Gssapi::exchange_protection_level`]: crate::proxy::socks_gss::Socks5Gssapi::exchange_protection_level
const NEC_PROTECTION_LEN: u16 = 1;

/// The separator `check_gss_err` writes between the major-status text and the
/// minor-status text: `curlx_dyn_addn(&dbuf, ".\n", 2)`
/// (`lib/socks_gssapi.c:75`).
const STATUS_SEPARATOR: &[u8] = b".\n";

/// The `function` argument each [`check_gss_err`] call site passes, spelled
/// exactly as the C spells it.
///
/// Only the first carries parentheses. That is not a transcription slip: the C
/// writes `"gss_import_name()"` at `:163` and the bare name at the other five
/// sites (`:190`, `:302`, `:311`, `:387`, `:478`), and the strings reach
/// `CURLOPT_ERRORBUFFER`.
///
/// [`check_gss_err`]: crate::proxy::socks_gss::check_gss_err
mod gss_fn {
    /// `lib/socks_gssapi.c:163` -- the only one with parentheses.
    pub(super) const IMPORT_NAME: &str = "gss_import_name()";

    /// `lib/socks_gssapi.c:190`.
    pub(super) const INIT_SEC_CONTEXT: &str = "gss_init_sec_context";

    /// `lib/socks_gssapi.c:302`.
    pub(super) const INQUIRE_CONTEXT: &str = "gss_inquire_context";

    /// `lib/socks_gssapi.c:311`.
    pub(super) const DISPLAY_NAME: &str = "gss_display_name";

    /// `lib/socks_gssapi.c:387`.
    pub(super) const WRAP: &str = "gss_wrap";

    /// `lib/socks_gssapi.c:478`.
    pub(super) const UNWRAP: &str = "gss_unwrap";

    /// Every name above, for the test that pins them against the C.
    #[cfg(test)]
    pub(super) const ALL: [&str; 6] = [
        IMPORT_NAME,
        INIT_SEC_CONTEXT,
        INQUIRE_CONTEXT,
        DISPLAY_NAME,
        WRAP,
        UNWRAP,
    ];
}

/// Every diagnostic this module emits, transcribed from `lib/socks_gssapi.c`.
///
/// One place per line, so that the frozen token appears exactly once and a
/// test can compare it against the C without a second hand-maintained list.
/// The constants are the fixed lines; the functions are the ones the C
/// formats, and each reproduces its conversions exactly -- `(%d %d)` for the
/// two header bytes, `(%zu)` for a length, `%.*s` for a token that is not
/// NUL-terminated, and the `with%s` splice that assembles three complete
/// sentences from one format string.
pub(crate) mod msg {
    use super::{
        SOCKS5_PROTECTION_CONFIDENTIALITY, SOCKS5_PROTECTION_INTEGRITY,
    };

    /// `"Failed to create service name."` (`lib/socks_gssapi.c:164`).
    pub(crate) const SERVICE_NAME_FAILED: &str =
        "Failed to create service name.";

    /// `"Failed to initial GSS-API token."` (`lib/socks_gssapi.c:196`).
    ///
    /// **The wording is the C's.** "Failed to initial" is not a typo
    /// introduced here and must not be corrected: the line reaches
    /// `CURLOPT_ERRORBUFFER`, which AAP section 0.8.1 freezes. One line covers
    /// two causes -- a library error, and a token too large for the 16-bit
    /// `LEN` field (`:189-192`).
    pub(crate) const INITIAL_TOKEN: &str = "Failed to initial GSS-API token.";

    /// `"Failed to send GSS-API authentication request."`
    /// (`lib/socks_gssapi.c:208`) -- the four-byte header.
    pub(crate) const SEND_AUTH_REQUEST: &str =
        "Failed to send GSS-API authentication request.";

    /// `"Failed to send GSS-API authentication token."`
    /// (`lib/socks_gssapi.c:219`) -- the token that follows it.
    pub(crate) const SEND_AUTH_TOKEN: &str =
        "Failed to send GSS-API authentication token.";

    /// `"Failed to receive GSS-API authentication response."`
    /// (`lib/socks_gssapi.c:243`).
    pub(crate) const RECV_AUTH_RESPONSE: &str =
        "Failed to receive GSS-API authentication response.";

    /// `"Could not allocate memory for GSS-API authentication response
    /// token."` (`lib/socks_gssapi.c:272-274`).
    ///
    /// The C splits the literal across two source lines; the assembled string
    /// has exactly one space between `"authentication"` and `"response"`.
    pub(crate) const TOKEN_ALLOC_FAILED: &str =
        "Could not allocate memory for GSS-API authentication response token.";

    /// `"Failed to receive GSS-API authentication token."`
    /// (`lib/socks_gssapi.c:284`).
    pub(crate) const RECV_AUTH_TOKEN: &str =
        "Failed to receive GSS-API authentication token.";

    /// `"Failed to determine username."` (`lib/socks_gssapi.c:305`, `:315`).
    ///
    /// One line for two different failures -- `gss_inquire_context` and
    /// `gss_display_name` -- which the library's own diagnosis distinguishes.
    pub(crate) const DETERMINE_USERNAME: &str = "Failed to determine username.";

    /// `"Failed to wrap GSS-API encryption value into token."`
    /// (`lib/socks_gssapi.c:392`).
    pub(crate) const WRAP_FAILED: &str =
        "Failed to wrap GSS-API encryption value into token.";

    /// `"Failed to send GSS-API encryption request."`
    /// (`lib/socks_gssapi.c:404`) -- the four-byte header.
    pub(crate) const SEND_ENCRYPTION_REQUEST: &str =
        "Failed to send GSS-API encryption request.";

    /// `"Failed to send GSS-API encryption type."`
    /// (`lib/socks_gssapi.c:414`, `:423`).
    ///
    /// One line for both encodings: the single clear byte of the NEC path and
    /// the wrapped token of the standard one.
    pub(crate) const SEND_ENCRYPTION_TYPE: &str =
        "Failed to send GSS-API encryption type.";

    /// `"Failed to receive GSS-API encryption response."`
    /// (`lib/socks_gssapi.c:433`).
    pub(crate) const RECV_ENCRYPTION_RESPONSE: &str =
        "Failed to receive GSS-API encryption response.";

    /// `"Failed to receive GSS-API encryption type."`
    /// (`lib/socks_gssapi.c:466`).
    pub(crate) const RECV_ENCRYPTION_TYPE: &str =
        "Failed to receive GSS-API encryption type.";

    /// `"Failed to unwrap GSS-API encryption value into token."`
    /// (`lib/socks_gssapi.c:483`).
    pub(crate) const UNWRAP_FAILED: &str =
        "Failed to unwrap GSS-API encryption value into token.";

    /// `failf(data, "User was rejected by the SOCKS5 server (%d %d).",
    /// socksreq[0], socksreq[1])` (`lib/socks_gssapi.c:251-252`,
    /// `:440-441`).
    ///
    /// **Byte-identical at both read sites.** The C emits the same literal for
    /// a rejected authentication message and a rejected protection-level
    /// message, and the two bytes are the ones just read -- including the
    /// `VER` byte, which is otherwise ignored but is still reported.
    pub(crate) fn user_rejected(version: u8, message_type: u8) -> String {
        format!(
            "User was rejected by the SOCKS5 server ({version} \
             {message_type})."
        )
    }

    /// `"Invalid GSS-API authentication response type (%d %d)."`
    /// (`lib/socks_gssapi.c:259-260`).
    pub(crate) fn invalid_auth_response_type(
        version: u8,
        message_type: u8,
    ) -> String {
        format!(
            "Invalid GSS-API authentication response type ({version} \
             {message_type})."
        )
    }

    /// `"Invalid GSS-API encryption response type (%d %d)."`
    /// (`lib/socks_gssapi.c:447-448`).
    pub(crate) fn invalid_encryption_response_type(
        version: u8,
        message_type: u8,
    ) -> String {
        format!(
            "Invalid GSS-API encryption response type ({version} \
             {message_type})."
        )
    }

    /// `"Invalid GSS-API encryption response length (%zu)."`
    /// (`lib/socks_gssapi.c:490-491`, `:502-503`).
    ///
    /// Emitted from two places with one wording: the unwrapped payload of the
    /// standard path and the clear payload of the NEC path must each be
    /// exactly one byte.
    pub(crate) fn invalid_encryption_response_length(length: usize) -> String {
        format!("Invalid GSS-API encryption response length ({length}).")
    }

    /// `infof(data, "SOCKS5 server authenticated user %.*s with GSS-API.",
    /// (int)gss_send_token.length, (const char *)gss_send_token.value)`
    /// (`lib/socks_gssapi.c:319-320`).
    ///
    /// `%.*s` prints exactly `length` bytes and does **not** require a
    /// terminator, because `gss_display_name` does not promise one. The
    /// successor takes the whole slice and converts it lossily, which is the
    /// only total reading of bytes a mechanism chose.
    pub(crate) fn authenticated_user(name: &[u8]) -> String {
        format!(
            "SOCKS5 server authenticated user {} with GSS-API.",
            String::from_utf8_lossy(name)
        )
    }

    /// `infof(data, "SOCKS5 server supports GSS-API %s data protection.", ..)`
    /// (`lib/socks_gssapi.c:337-339`).
    ///
    /// The three words are `"no"`, `"integrity"` and `"confidentiality"`,
    /// selected by the level the context reported.
    pub(crate) fn protection_supported(level: u8) -> String {
        let word = match level {
            SOCKS5_PROTECTION_INTEGRITY => "integrity",
            SOCKS5_PROTECTION_CONFIDENTIALITY => "confidentiality",
            _ => "no",
        };
        format!("SOCKS5 server supports GSS-API {word} data protection.")
    }

    /// `infof(data, "SOCKS5 access with%s protection granted.", ..)`
    /// (`lib/socks_gssapi.c:517-520`).
    ///
    /// The `with%s` splice is intentional and the three substitutions are
    /// `"out GSS-API data"`, `" GSS-API integrity"` and
    /// `" GSS-API confidentiality"` -- note the leading space on the latter
    /// two. The complete sentences are therefore
    ///
    /// ```text
    /// SOCKS5 access without GSS-API data protection granted.
    /// SOCKS5 access with GSS-API integrity protection granted.
    /// SOCKS5 access with GSS-API confidentiality protection granted.
    /// ```
    pub(crate) fn access_granted(level: u8) -> String {
        let spliced = match level {
            SOCKS5_PROTECTION_INTEGRITY => " GSS-API integrity",
            SOCKS5_PROTECTION_CONFIDENTIALITY => " GSS-API confidentiality",
            _ => "out GSS-API data",
        };
        format!("SOCKS5 access with{spliced} protection granted.")
    }

    /// `failf(data, "GSS-API error: %s failed: %s", function,
    /// curlx_dyn_ptr(&dbuf))` (`lib/socks_gssapi.c:92-93`).
    pub(crate) fn gss_api_error(function: &str, detail: &str) -> String {
        format!("GSS-API error: {function} failed: {detail}")
    }
}

// The injected seams -- what replaces `struct Curl_easy *data` and `cf->conn`

/// Where `failf()` and `infof()` go.
///
/// The C threads `struct Curl_easy *data` through the whole file and calls the
/// two macros on it. There is no `data` here, and there is no
/// `crate::conn::filters::CallCtx` either: [`GssapiNegotiator::negotiate`]
/// takes `&self` and nothing else, so the destination has to travel with the
/// negotiator rather than with the call. The implementor routes both methods
/// through `crate::trace`'s `failf!` and `infof!` macros, which is what keeps
/// `CURLOPT_ERRORBUFFER`, `--verbose` and `--trace` behaving for these lines
/// exactly as they do for every other diagnostic in the crate.
///
/// `&self` rather than `&mut self` for the same reason: the tracer is reached
/// through the implementor's own interior mutability, as
/// `crate::proxy::socks`'s [`SocksConn`] reaches connection state.
///
/// [`GssapiNegotiator::negotiate`]: crate::proxy::socks::GssapiNegotiator::negotiate
/// [`SocksConn`]: crate::proxy::socks::SocksConn
pub(crate) trait Reporter: fmt::Debug + Send + Sync {
    /// `failf(data, ...)`: state why the transfer failed. The message carries
    /// no trailing newline; the emitter appends one.
    fn failf(&self, message: &str);

    /// `infof(data, ...)`: one informational line, subject to `--verbose`.
    fn infof(&self, message: &str);
}

/// The two byte operations the exchange performs, as a contract.
///
/// # The sole intended implementor is the `"SOCKS"` filter
///
/// [`Self::send`] is `Curl_conn_cf_send(cf->next, data, buf, len, FALSE,
/// &nwritten)` and [`Self::blockread_all`] is `Curl_blockread_all(cf, data,
/// buf, blen, &actualread)`, whose Rust successor is
/// [`SocksProxy::blockread_all`]. Both are declared here rather than reached
/// for because the negotiation cannot hold the filter: the filter owns the
/// negotiator through `SocksSeams`, so the reverse direction would be a cycle,
/// and `blockread_all` is `async fn` on `&mut self` while this entry point is
/// synchronous on `&self`.
///
/// That division is deliberate and load-bearing. **The fill loop, the
/// readiness wait, the deadline and the would-block retry all belong to
/// `blockread_all` and none of them is reproduced in this module.** What this
/// module does reproduce is the C's own short-count test at every call site --
/// `if(code || (nwritten != 4))`, `if(result || (actualread != 4))` -- which is
/// why both methods report a count rather than just success.
///
/// [`SocksProxy::blockread_all`]: crate::proxy::socks::SocksProxy::blockread_all
pub(crate) trait GssWire: fmt::Debug + Send + Sync {
    /// `Curl_conn_cf_send(cf->next, data, buf, len, FALSE, &nwritten)`.
    ///
    /// The `FALSE` is `eos`: a sub-negotiation never ends the stream.
    ///
    /// # Errors
    ///
    /// Whatever the filter below reports. The caller treats an error and a
    /// short count identically, exactly as the C does.
    fn send(&self, bytes: &[u8]) -> CurlResult<usize>;

    /// `Curl_blockread_all(cf, data, buf, blen, &actualread)`: fill `buf`
    /// completely, or report how far it got.
    ///
    /// # Errors
    ///
    /// `CURLcode::OperationTimedout` when the deadline passes,
    /// `CURLcode::RecvError` on a short end of stream, or whatever the filter
    /// below reports.
    fn blockread_all(&self, buf: &mut [u8]) -> CurlResult<usize>;
}

/// The connection and transfer facts the exchange reads, as a contract.
///
/// Four reads and one write, each naming the C member it stands for. A
/// snapshot would not do: `CURLOPT_PROXY_SERVICE_NAME` and
/// `CURLOPT_SOCKS5_GSSAPI_NEC` can both be changed between two connects on one
/// handle, so the negotiation asks at the moment it needs the answer -- the
/// same reasoning `crate::proxy::socks`'s [`SocksConn`] records.
///
/// [`SocksConn`]: crate::proxy::socks::SocksConn
pub(crate) trait GssConn: fmt::Debug + Send + Sync {
    /// `data->set.str[STRING_PROXY_SERVICE_NAME]` (`lib/urldata.h:1168`,
    /// `lib/socks_gssapi.c:122`), the option `--proxy-service-name` sets.
    ///
    /// [`None`] when unset, which selects [`DEFAULT_SERVICE_NAME`].
    ///
    /// [`DEFAULT_SERVICE_NAME`]: crate::proxy::socks_gss::DEFAULT_SERVICE_NAME
    fn proxy_service_name(&self) -> Option<String>;

    /// `conn->socks_proxy.host.name` (`lib/urldata.h:628`,
    /// `lib/socks_gssapi.c:147`).
    ///
    /// **The SOCKS proxy's own host, not the destination.** The service
    /// principal names the proxy being authenticated to, so reading the origin
    /// here would build a name for the wrong host.
    fn socks_proxy_host(&self) -> String;

    /// `data->set.socks5_gssapi_nec` (`lib/urldata.h:1557`,
    /// `lib/socks_gssapi.c:371`, `:410`, `:473`), the flag
    /// `--socks5-gssapi-nec` sets.
    ///
    /// Read at three places and it must answer the same way at all three: it
    /// selects the encoding of the protection-level message, of its payload,
    /// and of the reply's payload.
    fn socks5_gssapi_nec(&self) -> bool;

    /// `data->set.gssapi_delegation`, which `Curl_gss_init_sec_context()`
    /// reads for itself (`lib/curl_gssapi.c:324-339`) from the `data` this
    /// path hands it (`lib/socks_gssapi.c:174`).
    ///
    /// The raw `CURLOPT_GSSAPI_DELEGATION` mask. It is honoured here because
    /// the C honours it: the SOCKS5 path passes `data`, so whatever the
    /// application set applies to this handshake too.
    fn gssapi_delegation(&self) -> i64;

    /// `conn->socks5_gssapi_enctype = socksreq[0]` (`lib/urldata.h:704`,
    /// `lib/socks_gssapi.c:522`).
    ///
    /// A write to the CONNECTION that outlives this exchange, which is why it
    /// is a seam method and not a return value: `crate::proxy::socks` reads it
    /// back one state later through [`SocksConn::socks5_gssapi_enctype`] and
    /// refuses the handshake when it is non-zero.
    ///
    /// [`SocksConn::socks5_gssapi_enctype`]: crate::proxy::socks::SocksConn::socks5_gssapi_enctype
    fn set_socks5_gssapi_enctype(&self, level: i32);
}

// The GSS-API seam -- six calls, no handles

/// What one failed GSS-API call reported: a curl code and the library's own
/// rendering of its major and minor status.
///
/// The text is what C's `check_gss_err` assembles by looping
/// `gss_display_status` (`lib/socks_gssapi.c:61-91`). That loop cannot live
/// here: `gss_display_status` is bound in `crate::ffi::gss`, which AAP section
/// 0.6.9 makes the sole island permitted to call it, and the binding renders
/// the status for its caller instead of exposing the entry point. So the
/// rendering arrives with the failure and [`check_gss_err`] frames it.
///
/// [`check_gss_err`]: crate::proxy::socks_gss::check_gss_err
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GssFailure {
    /// The code the binding mapped the failure to. Recorded for completeness
    /// and deliberately not returned to the caller: every GSS-API failure on
    /// this path answers `CURLE_COULDNT_CONNECT`, because that is what
    /// `lib/socks_gssapi.c` returns at each of its check sites.
    code: CURLcode,
    /// The rendered major and minor status, with no framing.
    diagnosis: String,
}

impl GssFailure {
    /// A failure carrying a code and the library's rendering of it.
    pub(crate) fn new(code: CURLcode, diagnosis: impl Into<String>) -> Self {
        Self {
            code,
            diagnosis: diagnosis.into(),
        }
    }

    /// The code the binding reported.
    #[allow(dead_code)] // read by the tests; see the field's own note
    pub(crate) fn code(&self) -> CURLcode {
        self.code
    }

    /// The rendered status text -- C's `buf`.
    pub(crate) fn diagnosis(&self) -> &str {
        &self.diagnosis
    }
}

/// What one `Curl_gss_init_sec_context()` step produced
/// (`lib/socks_gssapi.c:174-183`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct GssStep {
    /// `gss_major_status == GSS_S_CONTINUE_NEEDED` (`:228`): another token
    /// must be exchanged before the context is established.
    pub(crate) continue_needed: bool,
    /// `gss_send_token`: the token to send, owned. May be empty, and the C
    /// tests for exactly that before sending anything (`:200`).
    pub(crate) token: Vec<u8>,
    /// `gss_ret_flags & GSS_C_CONF_FLAG` (`:331`).
    ///
    /// Two booleans rather than a flags word, for a reason worth recording:
    /// `crate::ffi::ContextFlags` has no public constructor, so a scripted
    /// double could not produce one, and a seam a test cannot drive is not a
    /// seam. The platform implementation fills these from
    /// `ContextFlags::has_confidentiality` and `has_integrity`, and the
    /// CONF-before-INTEG precedence stays where the C puts it -- in the
    /// negotiation, not in the binding.
    pub(crate) confidentiality: bool,
    /// `gss_ret_flags & GSS_C_INTEG_FLAG` (`:334`).
    pub(crate) integrity: bool,
}

/// The six GSS-API calls the exchange makes, as a substitutable interface.
///
/// One method per C call site, in the order the C reaches them, so that each
/// [`check_gss_err`] call site here names the same function the C names there.
/// No method mentions a handle, a status integer or an object identifier:
/// `Self::Name` is opaque to this module and the implementor keeps the context
/// to itself.
///
/// # Why there is no `Send`, `Sync` or `Debug` bound
///
/// `crate::ffi::SecurityContext` and `TargetName` own raw GSS-API handles and
/// are therefore neither [`Send`] nor [`Sync`], and neither is [`fmt::Debug`].
/// That is not a limitation to work around: C's own context is a LOCAL of
/// `Curl_SOCKS5_gssapi_negotiate` (`lib/socks_gssapi.c:125`), created and
/// destroyed inside one call, and a session here is exactly the same. The
/// value that *is* held across calls is the [`GssSessionProvider`], which is
/// `Send + Sync` because the negotiator it lives in must be.
///
/// [`check_gss_err`]: crate::proxy::socks_gss::check_gss_err
pub(crate) trait GssSession {
    /// An imported GSS-API name, opaque here.
    type Name;

    /// `gss_import_name` (`lib/socks_gssapi.c:142-143`, `:155-156`).
    ///
    /// # Errors
    ///
    /// The library's diagnosis, which the caller frames with
    /// `"gss_import_name()"`.
    fn import_name(
        &mut self,
        name: &[u8],
        kind: NameType,
    ) -> Result<Self::Name, GssFailure>;

    /// `Curl_gss_init_sec_context(data, .., &Curl_krb5_mech_oid, NULL,
    /// gss_token, &gss_send_token, TRUE, &gss_ret_flags)`
    /// (`lib/socks_gssapi.c:174-183`).
    ///
    /// The `TRUE` requests mutual authentication and the mechanism is
    /// Kerberos 5, never SPNEGO. `input` is the peer's previous token, or
    /// [`None`] on the first step -- C's `GSS_C_NO_BUFFER`.
    ///
    /// # Errors
    ///
    /// The library's diagnosis, framed with `"gss_init_sec_context"`.
    fn init_sec_context(
        &mut self,
        target: &Self::Name,
        input: Option<&[u8]>,
    ) -> Result<GssStep, GssFailure>;

    /// `gss_inquire_context`'s `src_name` (`lib/socks_gssapi.c:298-300`).
    ///
    /// The C asks for the source name and passes `NULL` for the other seven
    /// out-parameters.
    ///
    /// # Errors
    ///
    /// The library's diagnosis, framed with `"gss_inquire_context"`.
    fn inquire_source_name(&mut self) -> Result<Self::Name, GssFailure>;

    /// `gss_display_name` (`lib/socks_gssapi.c:308-309`).
    ///
    /// The returned bytes are not NUL-terminated, which is why the C prints
    /// them with `%.*s`.
    ///
    /// # Errors
    ///
    /// The library's diagnosis, framed with `"gss_display_name"`.
    fn display_name(
        &mut self,
        name: &Self::Name,
    ) -> Result<Vec<u8>, GssFailure>;

    /// `gss_wrap(.., 0, GSS_C_QOP_DEFAULT, ..)`
    /// (`lib/socks_gssapi.c:383-385`).
    ///
    /// **`conf_req_flag` is 0 even when confidentiality was negotiated.** RFC
    /// 1961 says the protection level is sealed with `conf_req` FALSE, and the
    /// C passes 0 unconditionally; the flag is therefore not a parameter of
    /// this method, because a caller has no choice to make.
    ///
    /// # Errors
    ///
    /// The library's diagnosis, framed with `"gss_wrap"`.
    fn wrap(&mut self, plain: &[u8]) -> Result<Vec<u8>, GssFailure>;

    /// `gss_unwrap(.., 0, GSS_C_QOP_DEFAULT)`
    /// (`lib/socks_gssapi.c:474-476`).
    ///
    /// # Errors
    ///
    /// The library's diagnosis, framed with `"gss_unwrap"`.
    fn unwrap(&mut self, sealed: &[u8]) -> Result<Vec<u8>, GssFailure>;

    /// `Curl_gss_delete_sec_context(&gss_status, &gss_context, NULL)`
    /// (`lib/socks_gssapi.c:524`).
    ///
    /// Called at exactly one place: after a protection level of 0 was granted.
    /// Every other C call site is an error path, and those are covered by the
    /// implementor's own [`Drop`] -- see [`GssapiNegotiator::negotiate`].
    ///
    /// [`GssapiNegotiator::negotiate`]: crate::proxy::socks::GssapiNegotiator::negotiate
    fn delete_sec_context(&mut self);
}

/// Where a [`GssSession`] comes from.
///
/// The negotiator is built once and negotiates once per connection attempt, so
/// the context cannot be a field of it -- see [`GssSession`]'s note on the
/// missing [`Send`] bound. This is the `Send + Sync` half that can be held,
/// and `open` is the `gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;`
/// declaration at `lib/socks_gssapi.c:125`.
pub(crate) trait GssSessionProvider: fmt::Debug + Send + Sync {
    /// The session this provider opens.
    type Session: GssSession;

    /// A fresh, unestablished security context.
    ///
    /// `reporter` is the `data` C hands to `Curl_gss_init_sec_context()`, and
    /// it is needed for one reason: that function emits an `infof()` line of
    /// its own when the delegation-policy flag was asked for and the platform
    /// cannot express it (`lib/curl_gssapi.c:333-334`). Without a destination
    /// the warning would be silently dropped.
    ///
    /// `delegation` is the other thing that function reads off `data`, the raw
    /// `CURLOPT_GSSAPI_DELEGATION` mask (`lib/curl_gssapi.c:329`, `:338`). It
    /// is passed as the option's own integer rather than as a `crate::ffi`
    /// type, so that this seam names no type from the FFI island beyond
    /// [`NameType`] and a scripted double needs nothing from it.
    fn open(
        &self,
        reporter: Arc<dyn Reporter>,
        delegation: i64,
    ) -> Self::Session;
}

// The platform implementation of that seam

/// The GSS-API `crate::ffi` binds -- MIT Kerberos on Linux, Apple's
/// GSS.framework on macOS.
///
/// A zero-sized type: it holds no state, because the state a handshake needs is
/// the context, and the context belongs to the session.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PlatformGss;

impl GssSessionProvider for PlatformGss {
    type Session = PlatformGssSession;

    fn open(
        &self,
        reporter: Arc<dyn Reporter>,
        delegation: i64,
    ) -> Self::Session {
        PlatformGssSession {
            context: SecurityContext::new(),
            delegation: Delegation::from_option_value(delegation),
            reporter,
        }
    }
}

/// One security context and the two things `data` supplied.
///
/// No [`fmt::Debug`], no [`Send`] and no [`Sync`], because
/// `crate::ffi::SecurityContext` has none of them: the handle inside it is a
/// raw pointer. This value lives inside one [`GssapiNegotiator::negotiate`]
/// call and nowhere else, exactly as C's `gss_ctx_id_t gss_context` lives
/// inside one `Curl_SOCKS5_gssapi_negotiate` call.
///
/// # What [`Drop`] covers, and why that is not a deviation
///
/// The C calls `Curl_gss_delete_sec_context()` on **fourteen** paths through
/// this file, one per early return, because a partially established context
/// must not be leaked. Every one of them is covered here by
/// `SecurityContext`'s own guard, which deletes on drop -- so an added `?`
/// cannot skip one. The single non-error call site, the `if(socksreq[0] == 0)`
/// at `lib/socks_gssapi.c:523-524`, is still made explicitly, because it is a
/// decision rather than a cleanup: see [`GssSession::delete_sec_context`].
///
/// [`GssapiNegotiator::negotiate`]: crate::proxy::socks::GssapiNegotiator::negotiate
/// [`GssSession::delete_sec_context`]: crate::proxy::socks_gss::GssSession::delete_sec_context
pub(crate) struct PlatformGssSession {
    /// `gss_ctx_id_t gss_context` (`lib/socks_gssapi.c:125`).
    context: SecurityContext,
    /// `data->set.gssapi_delegation`, as the binding's own type.
    delegation: Delegation,
    /// Where the binding's `infof()` lines go.
    reporter: Arc<dyn Reporter>,
}

impl PlatformGssSession {
    /// Sorts the lines one binding call produced and turns its code into a
    /// [`GssFailure`].
    ///
    /// `crate::ffi` reports a library failure two ways at once: it returns
    /// `Err(code)` and it pushes the rendered major and minor status to the
    /// injected sink. C's `check_gss_err` wants that rendering as its `buf`, so
    /// the LAST line of a failed call is taken as the diagnosis and the rest
    /// are forwarded as the informational lines they are -- the
    /// delegation-policy warning of `lib/curl_gssapi.c:333-334` being the one
    /// that actually occurs. A successful call forwards everything, which is
    /// what stops that warning from vanishing when the handshake works.
    fn finish<T>(
        &self,
        mut lines: Vec<String>,
        outcome: Result<T, CURLcode>,
    ) -> Result<T, GssFailure> {
        match outcome {
            Ok(value) => {
                for line in lines {
                    self.reporter.infof(&line);
                }
                Ok(value)
            }
            Err(code) => {
                let diagnosis = lines.pop().unwrap_or_default();
                for line in lines {
                    self.reporter.infof(&line);
                }
                Err(GssFailure::new(code, status_text(&diagnosis)))
            }
        }
    }
}

/// The status text inside one `crate::ffi` diagnosis line.
///
/// The binding renders a failure as `"<function>() failed: <status text>"`,
/// which is `Curl_gss_log_error()`'s shape (`lib/curl_gssapi.c:429-441`).
/// `check_gss_err` frames the status text with a header of its own -- `"GSS-API
/// error: %s failed: %s"` -- so repeating the binding's prefix inside it would
/// name the same function twice. The prefix is therefore removed here, in the
/// adapter that knows the binding's format, rather than in the negotiation.
///
/// A line that does not have that shape is returned unchanged, so a future
/// change in the binding degrades to a slightly longer message rather than to
/// a lost one.
fn status_text(line: &str) -> &str {
    const MARKER: &str = " failed: ";
    match line.split_once(MARKER) {
        Some((head, tail)) if head.ends_with("()") && !head.contains(' ') => {
            tail
        }
        _ => line,
    }
}

/// A `crate::ffi::Diagnostics` sink that keeps what it is given.
///
/// The binding takes `&mut dyn Diagnostics` and writes through it during the
/// call; this collects the lines so [`PlatformGssSession::finish`] can decide
/// what each one was for once the call's outcome is known.
#[derive(Debug, Default)]
struct CapturedDiagnosis(Vec<String>);

impl Diagnostics for CapturedDiagnosis {
    fn infof(&mut self, message: &str) {
        self.0.push(message.to_string());
    }
}

impl GssSession for PlatformGssSession {
    type Name = TargetName;

    fn import_name(
        &mut self,
        name: &[u8],
        kind: NameType,
    ) -> Result<Self::Name, GssFailure> {
        let mut captured = CapturedDiagnosis::default();
        let outcome = TargetName::import(name, kind, &mut captured);
        self.finish(captured.0, outcome)
    }

    fn init_sec_context(
        &mut self,
        target: &Self::Name,
        input: Option<&[u8]>,
    ) -> Result<GssStep, GssFailure> {
        // `&Curl_krb5_mech_oid` (`:178`), `NULL` channel bindings (`:179`),
        // `TRUE` for mutual authentication (`:182`) and `&gss_ret_flags`
        // (`:183`) -- SOCKS5 is the one caller in the C tree that asks for the
        // returned flags, because it is the one that has to choose a
        // protection level from them.
        let options = StepOptions {
            target,
            mechanism: Mechanism::Krb5,
            mutual_auth: true,
            delegation: self.delegation,
            channel_binding_data: None,
            input_token: input,
            want_return_flags: true,
        };
        let mut captured = CapturedDiagnosis::default();
        let outcome = self.context.step(&options, &mut captured);
        let outcome = self.finish(captured.0, outcome)?;
        Ok(GssStep {
            continue_needed: outcome.state == HandshakeState::ContinueNeeded,
            token: outcome.token,
            confidentiality: outcome.flags.has_confidentiality(),
            integrity: outcome.flags.has_integrity(),
        })
    }

    fn inquire_source_name(&mut self) -> Result<Self::Name, GssFailure> {
        let mut captured = CapturedDiagnosis::default();
        let outcome = self.context.source_name(&mut captured);
        self.finish(captured.0, outcome)
    }

    fn display_name(
        &mut self,
        name: &Self::Name,
    ) -> Result<Vec<u8>, GssFailure> {
        let mut captured = CapturedDiagnosis::default();
        let outcome = name.display(&mut captured);
        self.finish(captured.0, outcome)
    }

    fn wrap(&mut self, plain: &[u8]) -> Result<Vec<u8>, GssFailure> {
        let mut captured = CapturedDiagnosis::default();
        // `conf_req_flag` is the literal 0 of `lib/socks_gssapi.c:383`. The
        // `conf_state` the library reports back is collected by the C into
        // `gss_conf_state` and then never read, so the successor discards it
        // here rather than pretending it is consulted.
        let outcome = self.context.wrap(false, plain, &mut captured);
        self.finish(captured.0, outcome).map(|sealed| sealed.token)
    }

    fn unwrap(&mut self, sealed: &[u8]) -> Result<Vec<u8>, GssFailure> {
        let mut captured = CapturedDiagnosis::default();
        let outcome = self.context.unwrap(sealed, &mut captured);
        self.finish(captured.0, outcome)
    }

    fn delete_sec_context(&mut self) {
        // `SecurityContext::reset` deletes the handle and returns to
        // `GSS_C_NO_CONTEXT`, so the guard's own `Drop` afterwards is a no-op
        // on a null handle -- exactly as the C's second call would be.
        self.context.reset();
    }
}

// `check_gss_err()` -- the diagnostic assembler

/// `check_gss_err()` (`lib/socks_gssapi.c:48-99`).
///
/// Returns **true** exactly when the call reported `GSS_ERROR(major_status)`,
/// which is the C's own contract, and emits nothing at all when it did not.
/// Passing [`None`] is therefore the successful case and is what makes the
/// predicate testable in both directions.
///
/// # What the C does and where each part now lives
///
/// The C loops `gss_display_status` over the major status with
/// `GSS_C_GSS_CODE`, appends the literal [`STATUS_SEPARATOR`], loops again over
/// the minor status with `GSS_C_MECH_CODE`, and emits `failf(data, "GSS-API
/// error: %s failed: %s", function, buf)`.
///
/// Both loops now live in `crate::ffi::gss`, which AAP section 0.6.9 makes the
/// sole island permitted to call GSS-API, and which renders major then minor in
/// one pass before handing the result to its caller. So the rendering arrives
/// in [`GssFailure::diagnosis`] already joined, the separator terminates it
/// here, and this function contributes what remains: the `MAX_GSS_LEN` ceiling
/// and the frozen header.
///
/// The ceiling is not decoration. `curlx_dyn_addn` fails once an append would
/// cross `MAX_GSS_LEN`, and the C answers that by `return 1` **with no message
/// emitted at all** (`:69`, `:76`). That silent path is reproduced: an
/// over-long diagnosis is reported as an error with nothing written, rather
/// than truncated into something that reads as complete.
fn check_gss_err(
    reporter: &dyn Reporter,
    function: &str,
    outcome: Option<&GssFailure>,
) -> bool {
    // `if(GSS_ERROR(major_status))` -- nothing to say otherwise.
    let Some(failure) = outcome else {
        return false;
    };

    // `curlx_dyn_init(&dbuf, MAX_GSS_LEN)`.
    let mut assembled = DynBuf::new(MAX_GSS_LEN);
    if assembled.addn(failure.diagnosis().as_bytes()).is_err() {
        return true;
    }
    if assembled.addn(STATUS_SEPARATOR).is_err() {
        return true;
    }

    // GSS-API status strings are ASCII by RFC 2743, but a mechanism is not
    // obliged to prove it, and the separator makes the buffer bytes rather
    // than text either way. Lossy conversion keeps this total.
    let detail = String::from_utf8_lossy(assembled.as_slice());
    reporter.failf(&msg::gss_api_error(function, &detail));
    true
}

// The negotiation

/// `curlx_malloc(gss_recv_token.length)`, fallibly
/// (`lib/socks_gssapi.c:270`, `:457`).
///
/// `length` came out of a 16-bit field and so is at most 65,535; this is
/// nonetheless a fallible allocation, because the C's `if(!gss_recv_token.
/// value)` is a real branch with its own return code, and an infallible
/// `vec![0; length]` would delete it and abort where curl reports.
fn allocate_token(length: usize) -> Result<Vec<u8>, CURLcode> {
    let mut token: Vec<u8> = Vec::new();
    token
        .try_reserve_exact(length)
        .map_err(|_| CURLcode::OutOfMemory)?;
    // The reservation above is the only allocation this performs: `resize`
    // reaches the allocator through `reserve`, which is documented to do
    // nothing when the capacity already suffices.
    token.resize(length, 0);
    Ok(token)
}

/// The RFC 1961 protection level a context's returned flags select
/// (`lib/socks_gssapi.c:329-335`).
///
/// **Confidentiality is tested first and integrity only `else if`.** A context
/// that offers both selects confidentiality, and reversing the two tests would
/// silently negotiate the weaker level.
fn protection_level(confidentiality: bool, integrity: bool) -> u8 {
    if confidentiality {
        SOCKS5_PROTECTION_CONFIDENTIALITY
    } else if integrity {
        SOCKS5_PROTECTION_INTEGRITY
    } else {
        SOCKS5_PROTECTION_NONE
    }
}

/// `Curl_SOCKS5_gssapi_negotiate(cf, data)` (`lib/socks.h:45-46`,
/// `lib/socks_gssapi.c:101-527`), as the negotiator
/// `crate::proxy::socks::SocksSeams` is injected with.
///
/// The four seams stand for the C's `cf` and `data`: [`GssConn`] for the facts,
/// [`GssWire`] for the bytes, [`Reporter`] for the diagnostics and the
/// [`GssSessionProvider`] for the security context. Every one of them is
/// substitutable, which is what lets the whole exchange be driven byte-for-byte
/// with no GSS-API library, no proxy and no socket.
///
/// [`GssConn`]: crate::proxy::socks_gss::GssConn
/// [`GssWire`]: crate::proxy::socks_gss::GssWire
/// [`Reporter`]: crate::proxy::socks_gss::Reporter
/// [`GssSessionProvider`]: crate::proxy::socks_gss::GssSessionProvider
#[derive(Debug)]
pub(crate) struct Socks5Gssapi<P: GssSessionProvider> {
    /// The facts the C reads off `data` and `cf->conn`.
    conn: Arc<dyn GssConn>,
    /// The two byte operations, i.e. the filter below.
    wire: Arc<dyn GssWire>,
    /// Where `failf()` and `infof()` go.
    reporter: Arc<dyn Reporter>,
    /// Where each negotiation's security context comes from.
    provider: P,
}

/// The production shape, for the filter factory that wires a SOCKS proxy up.
///
/// `SocksSeams::with_gssapi(Arc::new(PlatformSocks5Gssapi::new(..)))` is the
/// whole of the integration: `crate::proxy::socks` reaches this through
/// `dyn GssapiNegotiator` and knows nothing else about it.
// The consumer is crate::conn's filter factory, once Kerberos is configured.
#[allow(dead_code)]
pub(crate) type PlatformSocks5Gssapi = Socks5Gssapi<PlatformGss>;

impl<P: GssSessionProvider> Socks5Gssapi<P> {
    /// A negotiator over the four given seams.
    #[allow(dead_code)] // consumer: crate::conn's filter factory
    pub(crate) fn new(
        conn: Arc<dyn GssConn>,
        wire: Arc<dyn GssWire>,
        reporter: Arc<dyn Reporter>,
        provider: P,
    ) -> Self {
        Self {
            conn,
            wire,
            reporter,
            provider,
        }
    }

    /// `failf(data, ..)` and then the code the C returns from that site.
    ///
    /// One helper, because every failure here does exactly these two things and
    /// because the [`Error`] then carries the same text the reporter was
    /// given -- so `CURLOPT_ERRORBUFFER` and the internal `Result` cannot
    /// disagree.
    fn failed(
        &self,
        message: impl Into<Cow<'static, str>>,
        code: CURLcode,
    ) -> Error {
        let error = Error::with_context(code, message);
        self.reporter.failf(error.message());
        error
    }

    /// `Curl_conn_cf_send(cf->next, ..)` plus the C's own short-write test,
    /// `if(code || (nwritten != len))`.
    ///
    /// The two conditions collapse into one answer because every call site
    /// treats them identically: an error and a partial write produce the same
    /// diagnosis and the same return code.
    fn sent_fully(&self, bytes: &[u8]) -> bool {
        matches!(self.wire.send(bytes), Ok(sent) if sent == bytes.len())
    }

    /// `Curl_blockread_all(cf, ..)` plus `if(result || (actualread != blen))`.
    fn read_fully(&self, buf: &mut [u8]) -> bool {
        let wanted = buf.len();
        matches!(self.wire.blockread_all(buf), Ok(read) if read == wanted)
    }

    /// The four-byte header both message types share.
    ///
    /// `socksreq[0] = 1; socksreq[1] = <mtyp>; us_length = htons(len);
    /// memcpy(socksreq + 2, &us_length, sizeof(short))`. The C reaches for
    /// `htons`; the successor uses [`u16::to_be_bytes`], which says the same
    /// thing without depending on the host's byte order being asked about.
    fn exchange_header(
        message_type: u8,
        length: u16,
    ) -> [u8; EXCHANGE_HEADER_LEN] {
        let mut header = [0_u8; EXCHANGE_HEADER_LEN];
        header[0] = SUBNEGOTIATION_VERSION;
        header[1] = message_type;
        header[2..].copy_from_slice(&length.to_be_bytes());
        header
    }

    /// The service principal to import, and how to import it
    /// (`lib/socks_gssapi.c:135-157`).
    ///
    /// A name that already contains a `/` is a fully qualified principal and
    /// goes in verbatim under `GSS_C_NULL_OID`. Anything else is a bare service
    /// name, is joined to the SOCKS proxy's own host as `service@host`, and
    /// goes in as `GSS_C_NT_HOSTBASED_SERVICE`. The host is
    /// `conn->socks_proxy.host.name` -- the proxy being authenticated to, never
    /// the destination.
    fn service_name(&self) -> (Vec<u8>, NameType) {
        let service = self
            .conn
            .proxy_service_name()
            .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());

        if service.contains('/') {
            (service.into_bytes(), NameType::Unspecified)
        } else {
            let host = self.conn.socks_proxy_host();
            (
                format!("{service}@{host}").into_bytes(),
                NameType::HostBasedService,
            )
        }
    }

    /// The `MTYP` 1 token loop (`lib/socks_gssapi.c:171-293`).
    ///
    /// Returns the confidentiality and integrity flags of the step that ended
    /// the loop. That is what `gss_ret_flags` holds when the C reads it at
    /// `:331`: every call overwrites it, so the value that survives is the last
    /// one's.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] for every failure the C reports from this
    /// stretch, or [`CURLcode::OutOfMemory`] when the response token cannot be
    /// allocated. Each carries the C's own line, already emitted through
    /// [`Reporter::failf`].
    ///
    /// [`Reporter::failf`]: crate::proxy::socks_gss::Reporter::failf
    fn authenticate<S: GssSession>(
        &self,
        session: &mut S,
        server: &S::Name,
    ) -> CurlResult<(bool, bool)> {
        // `gss_buffer_desc *gss_token = GSS_C_NO_BUFFER` (`:117`): there is no
        // peer token on the first pass.
        let mut input: Option<Vec<u8>> = None;

        // `for(;;)` -- *"As long as we need to keep sending some context info,
        // and there is no errors, keep sending it..."*
        loop {
            // Moved out for the call, so that the release below is the release
            // and not merely a reassignment.
            let received = input.take();
            let outcome = session.init_sec_context(server, received.as_deref());

            // `if(gss_token != GSS_C_NO_BUFFER) { Curl_safefree(gss_recv_token
            // .value); gss_recv_token.length = 0; }` (`:185-188`) -- released
            // immediately after the call and BEFORE the error check, so a pass
            // that receives nothing new starts from `GSS_C_NO_BUFFER` again.
            drop(received);

            let step = match outcome {
                Err(failure) => {
                    check_gss_err(
                        &*self.reporter,
                        gss_fn::INIT_SEC_CONTEXT,
                        Some(&failure),
                    );
                    return Err(self
                        .failed(msg::INITIAL_TOKEN, CURLcode::CouldntConnect));
                }
                // The second half of `if(check_gss_err(..) ||
                // (gss_send_token.length > 0xffff))` (`:189-192`): one
                // diagnosis, two causes. `||` short-circuits, so this test is
                // reached only when the library itself was content.
                Ok(step) if step.token.len() > MAX_TOKEN_LEN => {
                    return Err(self
                        .failed(msg::INITIAL_TOKEN, CURLcode::CouldntConnect));
                }
                Ok(step) => step,
            };

            // `if(gss_send_token.length)` (`:200`) -- an empty token is not
            // sent, and no header is sent for it either.
            if !step.token.is_empty() {
                // `htons((unsigned short)gss_send_token.length)`: the guard
                // above has already rejected anything the field cannot hold,
                // so this conversion cannot lose information.
                let header = Self::exchange_header(
                    MTYP_AUTHENTICATION,
                    step.token.len() as u16,
                );
                if !self.sent_fully(&header) {
                    return Err(self.failed(
                        msg::SEND_AUTH_REQUEST,
                        CURLcode::CouldntConnect,
                    ));
                }
                if !self.sent_fully(&step.token) {
                    return Err(self.failed(
                        msg::SEND_AUTH_TOKEN,
                        CURLcode::CouldntConnect,
                    ));
                }
            }

            // `gss_release_buffer(&gss_status, &gss_send_token)` (`:227`) --
            // `step` owns the token and drops it at the end of this iteration.
            //
            // `if(gss_major_status != GSS_S_CONTINUE_NEEDED) break;` (`:228`).
            if !step.continue_needed {
                return Ok((step.confidentiality, step.integrity));
            }

            // Analyse the response, which has the same four-byte header.
            let mut header = [0_u8; EXCHANGE_HEADER_LEN];
            if !self.read_fully(&mut header) {
                return Err(self.failed(
                    msg::RECV_AUTH_RESPONSE,
                    CURLcode::CouldntConnect,
                ));
            }

            // `/* ignore the first (VER) byte */` (`:249`). It is still
            // REPORTED in both diagnostics below, but it is never validated,
            // because implementations get it wrong and curl tolerates that.
            if header[1] == MTYP_REJECTION {
                return Err(self.failed(
                    msg::user_rejected(header[0], header[1]),
                    CURLcode::CouldntConnect,
                ));
            }
            if header[1] != MTYP_AUTHENTICATION {
                return Err(self.failed(
                    msg::invalid_auth_response_type(header[0], header[1]),
                    CURLcode::CouldntConnect,
                ));
            }

            // `memcpy(&us_length, socksreq + 2, sizeof(short)); us_length =
            // ntohs(us_length);`
            let announced =
                usize::from(u16::from_be_bytes([header[2], header[3]]));
            let mut token = match allocate_token(announced) {
                Ok(token) => token,
                Err(code) => {
                    return Err(self.failed(msg::TOKEN_ALLOC_FAILED, code))
                }
            };
            if !self.read_fully(&mut token) {
                return Err(
                    self.failed(msg::RECV_AUTH_TOKEN, CURLcode::CouldntConnect)
                );
            }

            // `gss_token = &gss_recv_token;` (`:292`).
            input = Some(token);
        }
    }

    /// *"Everything is good so far, user was authenticated!"*
    /// (`lib/socks_gssapi.c:295-323`).
    ///
    /// Two library calls with two [`check_gss_err`] sites and one shared line.
    /// The name the first produces is released when this returns, which is the
    /// `gss_release_name(&gss_status, &gss_client_name)` of `:322`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] with `"Failed to determine username."`
    /// after either call fails.
    ///
    /// [`check_gss_err`]: crate::proxy::socks_gss::check_gss_err
    fn report_peer_identity<S: GssSession>(
        &self,
        session: &mut S,
    ) -> CurlResult<()> {
        let client = match session.inquire_source_name() {
            Ok(client) => client,
            Err(failure) => {
                check_gss_err(
                    &*self.reporter,
                    gss_fn::INQUIRE_CONTEXT,
                    Some(&failure),
                );
                return Err(self.failed(
                    msg::DETERMINE_USERNAME,
                    CURLcode::CouldntConnect,
                ));
            }
        };

        let displayed = match session.display_name(&client) {
            Ok(displayed) => displayed,
            Err(failure) => {
                check_gss_err(
                    &*self.reporter,
                    gss_fn::DISPLAY_NAME,
                    Some(&failure),
                );
                return Err(self.failed(
                    msg::DETERMINE_USERNAME,
                    CURLcode::CouldntConnect,
                ));
            }
        };

        self.reporter.infof(&msg::authenticated_user(&displayed));
        Ok(())
    }

    /// The `MTYP` 2 exchange (`lib/socks_gssapi.c:325-513`), returning the
    /// level the server granted.
    ///
    /// # Two mutually exclusive encodings, and both are preserved
    ///
    /// `data->set.socks5_gssapi_nec` selects between them:
    ///
    /// * **NEC compatibility.** `LEN` is 1 and the single level byte goes out
    ///   IN CLEAR, unwrapped, and the reply's byte comes back in clear too.
    /// * **Standard.** The level byte is sealed with `gss_wrap` and `LEN` is
    ///   the sealed token's length; the reply is unsealed with `gss_unwrap`.
    ///
    /// The C says of the first form, at `:341-345`, that sending the encryption
    /// type in clear *"seems wrong"* and that *"the NEC reference
    /// implementations on which this is based is therefore at fault"* -- and
    /// then keeps it, for interoperability. Both paths are reproduced exactly.
    /// Neither is corrected, unified with the other, or dropped.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] for every failure the C reports from this
    /// stretch, or [`CURLcode::OutOfMemory`] when the reply token cannot be
    /// allocated -- and that one alone is returned SILENTLY, with no `failf`,
    /// because `:457-461` has none where `:271-278` does.
    fn exchange_protection_level<S: GssSession>(
        &self,
        session: &mut S,
        level: u8,
    ) -> CurlResult<u8> {
        let nec = self.conn.socks5_gssapi_nec();

        let (header, payload) = if nec {
            // `us_length = htons((short)1)` (`:372`), then `memcpy(socksreq,
            // &gss_enc, 1)` and a one-byte send (`:411-412`). `gss_enc` is an
            // `int` there and the `memcpy` takes its first byte, which on every
            // mandated target is the value itself.
            (
                Self::exchange_header(MTYP_PROTECTION, NEC_PROTECTION_LEN),
                vec![level],
            )
        } else {
            let sealed = match session.wrap(&[level]) {
                Ok(sealed) => sealed,
                Err(failure) => {
                    check_gss_err(
                        &*self.reporter,
                        gss_fn::WRAP,
                        Some(&failure),
                    );
                    return Err(
                        self.failed(msg::WRAP_FAILED, CURLcode::CouldntConnect)
                    );
                }
            };
            // `htons((unsigned short)gss_w_token.length)` (`:398`) with NO
            // size guard on this path, unlike the authentication token's at
            // `:192`. The C truncates a sealed token longer than 0xffff rather
            // than diagnosing it, and the truncation is preserved rather than
            // silently improved into a new error the corpus has never seen.
            (
                Self::exchange_header(MTYP_PROTECTION, sealed.len() as u16),
                sealed,
            )
        };

        if !self.sent_fully(&header) {
            return Err(self.failed(
                msg::SEND_ENCRYPTION_REQUEST,
                CURLcode::CouldntConnect,
            ));
        }
        if !self.sent_fully(&payload) {
            return Err(self
                .failed(msg::SEND_ENCRYPTION_TYPE, CURLcode::CouldntConnect));
        }

        let mut header = [0_u8; EXCHANGE_HEADER_LEN];
        if !self.read_fully(&mut header) {
            return Err(self.failed(
                msg::RECV_ENCRYPTION_RESPONSE,
                CURLcode::CouldntConnect,
            ));
        }

        // `/* ignore the first (VER) byte */` (`:438`) -- for the second time,
        // and the rejection line below is byte-identical to the one at `:251`.
        if header[1] == MTYP_REJECTION {
            return Err(self.failed(
                msg::user_rejected(header[0], header[1]),
                CURLcode::CouldntConnect,
            ));
        }
        if header[1] != MTYP_PROTECTION {
            return Err(self.failed(
                msg::invalid_encryption_response_type(header[0], header[1]),
                CURLcode::CouldntConnect,
            ));
        }

        let announced = usize::from(u16::from_be_bytes([header[2], header[3]]));
        // The C's SECOND allocation failure returns `CURLE_OUT_OF_MEMORY` with
        // no `failf` at all (`:457-461`), where the first one emits a line
        // (`:271-278`). The asymmetry is the C's; `Error::new` carries the
        // code with no message and nothing is reported.
        let mut received = allocate_token(announced).map_err(Error::new)?;
        if !self.read_fully(&mut received) {
            return Err(self
                .failed(msg::RECV_ENCRYPTION_TYPE, CURLcode::CouldntConnect));
        }

        let granted = if nec {
            // *"the NEC reference implementations"* send the byte in clear, so
            // there is nothing to unwrap (`:500-513`).
            received
        } else {
            match session.unwrap(&received) {
                Ok(plain) => plain,
                Err(failure) => {
                    check_gss_err(
                        &*self.reporter,
                        gss_fn::UNWRAP,
                        Some(&failure),
                    );
                    return Err(self
                        .failed(msg::UNWRAP_FAILED, CURLcode::CouldntConnect));
                }
            }
        };

        // The C writes this check twice, once per path -- `:489-495` and
        // `:501-508` -- with the same wording and the same code. One site here,
        // reached from both, because the two are the same test over the same
        // value: the payload the server granted, however it was encoded.
        if granted.len() != 1 {
            return Err(self.failed(
                msg::invalid_encryption_response_length(granted.len()),
                CURLcode::CouldntConnect,
            ));
        }

        // `memcpy(socksreq, gss_w_token.value, gss_w_token.length)`.
        Ok(granted[0])
    }
}

impl<P: GssSessionProvider> GssapiNegotiator for Socks5Gssapi<P> {
    /// `Curl_SOCKS5_gssapi_negotiate(cf, data)`
    /// (`lib/socks_gssapi.c:101-527`), start to finish.
    ///
    /// The five stages are the C's, in the C's order: import the service name,
    /// exchange authentication tokens until the context is established, report
    /// who was authenticated, choose a protection level from the context's
    /// flags and agree it with the server, then record what was granted.
    ///
    /// There is no blocking-mode toggle at either end -- see this module's
    /// documentation, and `lib/socks_gssapi.c:169` and `:515` for the two calls
    /// that have no successor. The exchange is a sequence of sends and
    /// read-exactlys and nothing here touches a socket flag.
    fn negotiate(&self) -> CurlResult<()> {
        let (name, kind) = self.service_name();

        // `gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;` (`:125`), created here
        // and destroyed when this call returns, by whichever route it returns.
        let mut session = self
            .provider
            .open(Arc::clone(&self.reporter), self.conn.gssapi_delegation());

        let server = match session.import_name(&name, kind) {
            Ok(server) => server,
            Err(failure) => {
                check_gss_err(
                    &*self.reporter,
                    gss_fn::IMPORT_NAME,
                    Some(&failure),
                );
                return Err(self.failed(
                    msg::SERVICE_NAME_FAILED,
                    CURLcode::CouldntConnect,
                ));
            }
        };

        let (confidentiality, integrity) =
            self.authenticate(&mut session, &server)?;

        // `gss_release_name(&gss_status, &server);` (`:295`) -- released
        // explicitly at the point the C releases it, rather than at the end of
        // the enclosing scope, because the C's placement is a statement about
        // when the name stops being needed.
        drop(server);

        self.report_peer_identity(&mut session)?;

        let level = protection_level(confidentiality, integrity);
        self.reporter.infof(&msg::protection_supported(level));

        let granted = self.exchange_protection_level(&mut session, level)?;

        // The C restores the socket's non-blocking flag here (`:515`). There
        // is no counterpart, because there was no toggle to undo.
        self.reporter.infof(&msg::access_granted(granted));

        // `conn->socks5_gssapi_enctype = socksreq[0];` (`:522`). The caller
        // reads this back one state later and refuses the handshake when it is
        // non-zero -- `lib/socks.c:1166-1171`, reproduced at
        // `crate::proxy::socks`'s `SOCKS5_ST_REQ1_SEND` arm, which answers
        // `CURLPX_GSSAPI_PROTECTION`. That dead end is the state of curl
        // 8.19.0-DEV and is reproduced rather than repaired.
        self.conn.set_socks5_gssapi_enctype(i32::from(granted));

        // `if(socksreq[0] == 0) Curl_gss_delete_sec_context(..);` (`:523-524`).
        //
        // Only at level 0. The C retains the context for levels 1 and 2 because
        // per-message protection would need it -- and then never uses it, so
        // the local handle is leaked. Rust reclaims it when `session` drops at
        // the end of this function, which is a strict improvement with no
        // wire-observable difference: the caller refuses the connection
        // immediately afterwards either way. The explicit call is kept because
        // the CONDITION is a decision the C makes, not a cleanup.
        if granted == SOCKS5_PROTECTION_NONE {
            session.delete_sec_context();
        }

        Ok(())
    }
}

// Tests
//
// The transport is `conn/filters.rs`'s own in-memory one, which is what makes
// these tests byte-level: `state.output` is every byte the exchange sent and
// `state.input` is every byte it will be given. The GSS-API side is a scripted
// double, so no KDC, no credential cache and no network is involved.
//
// The gate is `all(test, feature = "negotiate")` even though `proxy/mod.rs`
// already gates the module: the pair is a single effective condition, and
// spelling the feature here records that these tests cannot exist without it.

#[cfg(all(test, feature = "negotiate"))]
mod tests {
    use super::*;
    use crate::conn::filters::tests::{new_log, InMemory, TransportHandle};
    use crate::conn::filters::{
        link, CallCtx, ConnFilter, ConnId, SocketIndex,
    };
    use crate::dns::IpVersion;
    use crate::proxy::socks::{
        DestinationResolver, ResolveProgress, SocksConn, SocksProxy, SocksSeams,
    };
    use crate::proxy::{CURLproxycode, SOCKS5_AUTH_DEFAULT};
    use crate::util::sync_cell::SyncCell;
    use crate::util::timediff::TimeDiff;
    use crate::util::timeval::{CurlTime, TestClock};
    use std::sync::{Mutex, PoisonError};

    // -- the connection facts, as a double -------------------------------

    /// Everything [`GssConn`] answers, all settable.
    ///
    /// The same value also backs [`SocksConn`] for the integration test at the
    /// foot of this module, which is the whole point: the negotiation writes
    /// `socks5_gssapi_enctype` and the SOCKS filter reads the very same field
    /// back, so the dead end of `lib/socks.c:1166-1171` is exercised end to
    /// end rather than asserted twice from two sides.
    #[derive(Debug)]
    struct Facts {
        service_name: Option<String>,
        proxy_host: String,
        nec: bool,
        delegation: i64,
        enctype: i32,
        proxy_code: Option<CURLproxycode>,
    }

    impl Default for Facts {
        fn default() -> Self {
            Self {
                service_name: None,
                proxy_host: "proxy.example".to_string(),
                nec: false,
                delegation: 0,
                enctype: 0,
                proxy_code: None,
            }
        }
    }

    #[derive(Debug)]
    struct TestConn {
        facts: SyncCell<Facts>,
    }

    impl TestConn {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                facts: SyncCell::new(Facts::default()),
            })
        }

        fn set(&self, body: impl FnOnce(&mut Facts)) {
            body(&mut self.facts.borrow_mut());
        }

        fn enctype(&self) -> i32 {
            self.facts.borrow().enctype
        }

        fn proxy_code(&self) -> Option<CURLproxycode> {
            self.facts.borrow().proxy_code
        }
    }

    impl GssConn for TestConn {
        fn proxy_service_name(&self) -> Option<String> {
            self.facts.borrow().service_name.clone()
        }

        fn socks_proxy_host(&self) -> String {
            self.facts.borrow().proxy_host.clone()
        }

        fn socks5_gssapi_nec(&self) -> bool {
            self.facts.borrow().nec
        }

        fn gssapi_delegation(&self) -> i64 {
            self.facts.borrow().delegation
        }

        fn set_socks5_gssapi_enctype(&self, level: i32) {
            self.facts.borrow_mut().enctype = level;
        }
    }

    impl SocksConn for TestConn {
        fn proxy_type(&self) -> i32 {
            // `CURLPROXY_SOCKS5_HOSTNAME`, so the filter asks the proxy to
            // resolve and never reaches the injected resolver.
            7
        }

        fn proxy_user(&self) -> Option<String> {
            None
        }

        fn proxy_password(&self) -> Option<String> {
            None
        }

        fn socks5_auth(&self) -> u8 {
            SOCKS5_AUTH_DEFAULT
        }

        fn is_http_proxy(&self) -> bool {
            false
        }

        fn http_proxy_host(&self) -> Option<String> {
            None
        }

        fn http_proxy_port(&self) -> u16 {
            0
        }

        fn connect_to_host(&self) -> Option<String> {
            None
        }

        fn connect_to_port(&self) -> Option<u16> {
            None
        }

        fn secondary_host(&self) -> Option<String> {
            None
        }

        fn secondary_port(&self) -> u16 {
            0
        }

        fn host_name(&self) -> String {
            "h".to_string()
        }

        fn remote_port(&self) -> u16 {
            80
        }

        fn ip_version(&self) -> IpVersion {
            IpVersion::Whatever
        }

        fn set_ip_version(&self, _ip_version: IpVersion) {}

        fn requested_ip_version(&self) -> IpVersion {
            IpVersion::Whatever
        }

        fn is_ipv6_ip(&self) -> bool {
            false
        }

        fn socks5_gssapi_enctype(&self) -> i32 {
            self.facts.borrow().enctype
        }

        fn set_proxy_code(&self, code: CURLproxycode) {
            self.facts.borrow_mut().proxy_code = Some(code);
        }

        fn time_left_ms(&self) -> TimeDiff {
            0
        }
    }

    /// A resolver that is never consulted: the integration test drives
    /// `CURLPROXY_SOCKS5_HOSTNAME`, where the proxy resolves the destination.
    #[derive(Debug)]
    struct UnusedResolver;

    impl DestinationResolver for UnusedResolver {
        fn start(
            &self,
            _hostname: &str,
            _port: i32,
            _ip_version: IpVersion,
        ) -> ResolveProgress {
            unreachable!("SOCKS5h resolves at the proxy");
        }

        fn check(&self) -> ResolveProgress {
            unreachable!("SOCKS5h resolves at the proxy");
        }
    }

    // -- the diagnostics sink, as a double -------------------------------

    /// Records every `failf` and `infof` line, tagged and in order.
    #[derive(Debug, Default)]
    struct RecordingReporter {
        lines: SyncCell<Vec<String>>,
    }

    impl RecordingReporter {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        /// Only the `failf` lines, untagged.
        fn failures(&self) -> Vec<String> {
            self.tagged("failf:")
        }

        /// Only the `infof` lines, untagged.
        fn infos(&self) -> Vec<String> {
            self.tagged("infof:")
        }

        fn tagged(&self, tag: &str) -> Vec<String> {
            self.lines
                .borrow()
                .iter()
                .filter_map(|line| {
                    line.strip_prefix(tag).map(std::string::ToString::to_string)
                })
                .collect()
        }
    }

    impl Reporter for RecordingReporter {
        fn failf(&self, message: &str) {
            self.lines.borrow_mut().push(format!("failf:{message}"));
        }

        fn infof(&self, message: &str) {
            self.lines.borrow_mut().push(format!("infof:{message}"));
        }
    }

    // -- the wire, over conn/filters.rs's in-memory transport -------------

    /// [`GssWire`] over [`InMemory`], the transport `conn/filters.rs` provides.
    ///
    /// Nothing is reimplemented here: both methods call the filter's own
    /// [`ConnFilter::send`] and [`ConnFilter::recv`], so a transport that is
    /// not writable answers `CURLE_AGAIN` and one that has fewer bytes queued
    /// than were asked for answers a short count -- which is exactly what the
    /// C's `if(code || (nwritten != 4))` and `if(result || (actualread != 4))`
    /// tests are there to catch.
    ///
    /// A [`Mutex`] and not a [`SyncCell`]: `FilterBase` holds
    /// `Pin<Box<dyn ConnFilter>>`, which is [`Send`] but not [`Sync`], and
    /// `Mutex<T>: Sync` needs only `T: Send` where `RwLock<T>: Sync` needs
    /// both.
    #[derive(Debug)]
    struct FilterWire {
        transport: Mutex<InMemory>,
        clock: TestClock,
    }

    impl FilterWire {
        fn new() -> (Arc<Self>, TransportHandle) {
            let log = new_log();
            let (transport, state) = InMemory::new("TRANSPORT", &log);
            let wire = Arc::new(Self {
                transport: Mutex::new(transport),
                clock: TestClock::new(CurlTime::new(1, 0)),
            });
            (wire, state)
        }
    }

    impl GssWire for FilterWire {
        fn send(&self, bytes: &[u8]) -> CurlResult<usize> {
            let mut transport = self
                .transport
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let mut cx = CallCtx::new(&self.clock);
            transport.send(&mut cx, bytes, false)
        }

        fn blockread_all(&self, buf: &mut [u8]) -> CurlResult<usize> {
            let mut transport = self
                .transport
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let mut cx = CallCtx::new(&self.clock);
            transport.recv(&mut cx, buf)
        }
    }

    /// [`GssWire`] over a transport handle somebody else owns, with a fault
    /// schedule.
    ///
    /// Two jobs [`FilterWire`] cannot do. The integration test hands the
    /// [`InMemory`] filter to a [`SocksProxy`], so the negotiation cannot also
    /// hold it and shares the same two byte buffers instead -- the same stream
    /// in the same order. And `InMemory` writes every byte it is given, so a
    /// send that fails or writes short is unreachable through it; the two
    /// counters below reach the four distinct send diagnoses the C has.
    #[derive(Debug)]
    struct ScheduledWire {
        state: TransportHandle,
        /// How many sends have been attempted, so a fault can name one.
        sends: SyncCell<usize>,
        /// The one-based send that reports an error -- the `code` half of the
        /// C's `if(code || (nwritten != len))`.
        fail_send_at: Option<usize>,
        /// The one-based send that writes one byte short -- the `nwritten !=
        /// len` half of the same test.
        short_send_at: Option<usize>,
    }

    impl ScheduledWire {
        /// A wire sharing a fresh in-memory transport's buffers. The filter
        /// itself is dropped: only the two byte buffers are wanted.
        fn new(
            fail_send_at: Option<usize>,
            short_send_at: Option<usize>,
        ) -> (Arc<Self>, TransportHandle) {
            let log = new_log();
            let (_transport, state) = InMemory::new("SHARED", &log);
            let wire = Arc::new(Self {
                state: Arc::clone(&state),
                sends: SyncCell::new(0),
                fail_send_at,
                short_send_at,
            });
            (wire, state)
        }

        /// A wire over an existing transport's buffers, with no faults.
        fn sharing(state: &TransportHandle) -> Arc<Self> {
            Arc::new(Self {
                state: Arc::clone(state),
                sends: SyncCell::new(0),
                fail_send_at: None,
                short_send_at: None,
            })
        }
    }

    impl GssWire for ScheduledWire {
        fn send(&self, bytes: &[u8]) -> CurlResult<usize> {
            let attempt = self.sends.get() + 1;
            self.sends.set(attempt);
            if self.fail_send_at == Some(attempt) {
                return Err(Error::new(CURLcode::SendError));
            }
            if self.short_send_at == Some(attempt) {
                let short = bytes.len().saturating_sub(1);
                self.state
                    .borrow_mut()
                    .output
                    .extend_from_slice(&bytes[..short]);
                return Ok(short);
            }
            self.state.borrow_mut().output.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn blockread_all(&self, buf: &mut [u8]) -> CurlResult<usize> {
            let mut state = self.state.borrow_mut();
            let take = buf.len().min(state.input.len());
            buf[..take].copy_from_slice(&state.input[..take]);
            state.input.drain(..take);
            Ok(take)
        }
    }

    // -- the GSS-API side, as a scripted double --------------------------

    /// One reply per call, consumed in order.
    #[derive(Debug, Default)]
    struct Script {
        import: Vec<Result<&'static str, GssFailure>>,
        steps: Vec<Result<GssStep, GssFailure>>,
        inquire: Vec<Result<&'static str, GssFailure>>,
        display: Vec<Result<Vec<u8>, GssFailure>>,
        wrap: Vec<Result<Vec<u8>, GssFailure>>,
        unwrap: Vec<Result<Vec<u8>, GssFailure>>,
    }

    /// What the double was asked to do.
    #[derive(Debug, Default)]
    struct Journal {
        imported: Vec<(Vec<u8>, NameType)>,
        step_inputs: Vec<Option<Vec<u8>>>,
        wrapped: Vec<Vec<u8>>,
        unwrapped: Vec<Vec<u8>>,
        deletes: usize,
        delegation: Vec<i64>,
    }

    #[derive(Clone, Debug)]
    struct ScriptedGss {
        script: Arc<SyncCell<Script>>,
        journal: Arc<SyncCell<Journal>>,
    }

    impl GssSessionProvider for ScriptedGss {
        type Session = ScriptedSession;

        fn open(
            &self,
            _reporter: Arc<dyn Reporter>,
            delegation: i64,
        ) -> Self::Session {
            self.journal.borrow_mut().delegation.push(delegation);
            ScriptedSession {
                script: Arc::clone(&self.script),
                journal: Arc::clone(&self.journal),
            }
        }
    }

    struct ScriptedSession {
        script: Arc<SyncCell<Script>>,
        journal: Arc<SyncCell<Journal>>,
    }

    /// The next scripted reply, or a failed assertion naming the call that ran
    /// off the end of the script.
    fn scripted<T>(
        queue: &mut Vec<Result<T, GssFailure>>,
        what: &str,
    ) -> Result<T, GssFailure> {
        assert!(!queue.is_empty(), "the script has no reply left for {what}");
        queue.remove(0)
    }

    impl GssSession for ScriptedSession {
        type Name = &'static str;

        fn import_name(
            &mut self,
            name: &[u8],
            kind: NameType,
        ) -> Result<Self::Name, GssFailure> {
            self.journal
                .borrow_mut()
                .imported
                .push((name.to_vec(), kind));
            scripted(&mut self.script.borrow_mut().import, "import_name")
        }

        fn init_sec_context(
            &mut self,
            _target: &Self::Name,
            input: Option<&[u8]>,
        ) -> Result<GssStep, GssFailure> {
            self.journal
                .borrow_mut()
                .step_inputs
                .push(input.map(<[u8]>::to_vec));
            scripted(&mut self.script.borrow_mut().steps, "init_sec_context")
        }

        fn inquire_source_name(&mut self) -> Result<Self::Name, GssFailure> {
            scripted(
                &mut self.script.borrow_mut().inquire,
                "inquire_source_name",
            )
        }

        fn display_name(
            &mut self,
            _name: &Self::Name,
        ) -> Result<Vec<u8>, GssFailure> {
            scripted(&mut self.script.borrow_mut().display, "display_name")
        }

        fn wrap(&mut self, plain: &[u8]) -> Result<Vec<u8>, GssFailure> {
            self.journal.borrow_mut().wrapped.push(plain.to_vec());
            scripted(&mut self.script.borrow_mut().wrap, "wrap")
        }

        fn unwrap(&mut self, sealed: &[u8]) -> Result<Vec<u8>, GssFailure> {
            self.journal.borrow_mut().unwrapped.push(sealed.to_vec());
            scripted(&mut self.script.borrow_mut().unwrap, "unwrap")
        }

        fn delete_sec_context(&mut self) {
            self.journal.borrow_mut().deletes += 1;
        }
    }

    // -- fixtures --------------------------------------------------------

    /// One `init_sec_context` reply.
    fn step(
        token: &[u8],
        continue_needed: bool,
        confidentiality: bool,
        integrity: bool,
    ) -> Result<GssStep, GssFailure> {
        Ok(GssStep {
            continue_needed,
            token: token.to_vec(),
            confidentiality,
            integrity,
        })
    }

    /// The failure a scripted library call reports.
    fn failure(detail: &str) -> GssFailure {
        GssFailure::new(CURLcode::AuthError, detail)
    }

    /// A script whose context establishes in one step, offering no protection.
    fn one_step(token: &[u8]) -> Script {
        Script {
            import: vec![Ok("service")],
            steps: vec![step(token, false, false, false)],
            inquire: vec![Ok("client")],
            display: vec![Ok(b"alice".to_vec())],
            ..Script::default()
        }
    }

    /// The negotiator plus every handle a test needs to drive and observe it.
    struct Harness {
        conn: Arc<TestConn>,
        reporter: Arc<RecordingReporter>,
        state: TransportHandle,
        journal: Arc<SyncCell<Journal>>,
        negotiator: Socks5Gssapi<ScriptedGss>,
    }

    impl Harness {
        /// The ordinary case: the exchange runs over `conn/filters.rs`'s own
        /// in-memory transport, so every assertion below is on real bytes.
        fn new(script: Script) -> Self {
            let (wire, state) = FilterWire::new();
            Self::over(script, wire as Arc<dyn GssWire>, state)
        }

        /// The same, over a wire with a send-fault schedule.
        fn faulty(
            script: Script,
            fail_send_at: Option<usize>,
            short_send_at: Option<usize>,
        ) -> Self {
            let (wire, state) = ScheduledWire::new(fail_send_at, short_send_at);
            Self::over(script, wire as Arc<dyn GssWire>, state)
        }

        fn over(
            script: Script,
            wire: Arc<dyn GssWire>,
            state: TransportHandle,
        ) -> Self {
            let conn = TestConn::new();
            let reporter = RecordingReporter::new();
            let journal = Arc::new(SyncCell::new(Journal::default()));
            let provider = ScriptedGss {
                script: Arc::new(SyncCell::new(script)),
                journal: Arc::clone(&journal),
            };
            let negotiator = Socks5Gssapi::new(
                Arc::clone(&conn) as Arc<dyn GssConn>,
                wire,
                Arc::clone(&reporter) as Arc<dyn Reporter>,
                provider,
            );
            Self {
                conn,
                reporter,
                state,
                journal,
                negotiator,
            }
        }

        /// Queues bytes as though the proxy had sent them.
        fn feed(&self, bytes: &[u8]) -> &Self {
            self.state.borrow_mut().input.extend_from_slice(bytes);
            self
        }

        fn run(&self) -> CurlResult<()> {
            self.negotiator.negotiate()
        }

        /// Every byte the exchange wrote, in order.
        fn sent(&self) -> Vec<u8> {
            self.state.borrow().output.clone()
        }

        /// The one `failf` line a failing run produced.
        fn only_failure(&self) -> String {
            let failures = self.reporter.failures();
            assert_eq!(
                failures.len(),
                1,
                "expected exactly one failf line, got {failures:?}"
            );
            failures[0].clone()
        }

        /// Runs, requires failure, and returns the code and the last `failf`
        /// line -- the one the C emits from the site that failed.
        fn must_fail(&self) -> (CURLcode, String) {
            let error = self.run().expect_err("the exchange must fail");
            let failures = self.reporter.failures();
            let last = failures
                .last()
                .expect("a failure always emits at least one line")
                .clone();
            (error.code(), last)
        }
    }

    // -- 1. the frozen constants ------------------------------------------

    /// Every number transcribed from `lib/socks_gssapi.c`.
    #[test]
    fn the_protocol_constants_match_the_c_exactly() {
        assert_eq!(MAX_GSS_LEN, 1024, "lib/socks_gssapi.c:43");
        // The GSS-API sub-negotiation version, NOT the SOCKS version.
        assert_eq!(SUBNEGOTIATION_VERSION, 1, "lib/socks_gssapi.c:201");
        assert_ne!(SUBNEGOTIATION_VERSION, 5, "5 is the SOCKS version");
        assert_eq!(MTYP_AUTHENTICATION, 1, "lib/socks_gssapi.c:202");
        assert_eq!(MTYP_PROTECTION, 2, "lib/socks_gssapi.c:327");
        assert_eq!(MTYP_REJECTION, 255, "lib/socks_gssapi.c:250");
        assert_eq!(EXCHANGE_HEADER_LEN, 4, "lib/socks_gssapi.c:121");
        assert_eq!(MAX_TOKEN_LEN, 0xffff, "lib/socks_gssapi.c:192");
        assert_eq!(DEFAULT_SERVICE_NAME, "rcmd", "lib/socks_gssapi.c:123");
        assert_eq!(NEC_PROTECTION_LEN, 1, "lib/socks_gssapi.c:372");
        assert_eq!(STATUS_SEPARATOR, b".\n", "lib/socks_gssapi.c:75");
        // The three protection levels are consumed from the FFI island rather
        // than re-spelled, so there is one definition of 0, 1 and 2.
        assert_eq!(SOCKS5_PROTECTION_NONE, 0);
        assert_eq!(SOCKS5_PROTECTION_INTEGRITY, 1);
        assert_eq!(SOCKS5_PROTECTION_CONFIDENTIALITY, 2);
    }

    /// The six `function` strings `check_gss_err` is called with, and the fact
    /// that exactly one of them carries parentheses.
    #[test]
    fn the_check_gss_err_function_names_match_the_c_exactly() {
        assert_eq!(gss_fn::IMPORT_NAME, "gss_import_name()");
        assert_eq!(gss_fn::INIT_SEC_CONTEXT, "gss_init_sec_context");
        assert_eq!(gss_fn::INQUIRE_CONTEXT, "gss_inquire_context");
        assert_eq!(gss_fn::DISPLAY_NAME, "gss_display_name");
        assert_eq!(gss_fn::WRAP, "gss_wrap");
        assert_eq!(gss_fn::UNWRAP, "gss_unwrap");

        let parenthesised: Vec<&&str> = gss_fn::ALL
            .iter()
            .filter(|name| name.ends_with("()"))
            .collect();
        assert_eq!(
            parenthesised,
            vec![&gss_fn::IMPORT_NAME],
            "only gss_import_name() carries parentheses in the C"
        );
    }

    /// Every fixed diagnostic line, verbatim.
    #[test]
    fn the_frozen_lines_match_the_c_exactly() {
        assert_eq!(msg::SERVICE_NAME_FAILED, "Failed to create service name.");
        // The C's own wording. "Failed to initial" is not corrected here.
        assert_eq!(msg::INITIAL_TOKEN, "Failed to initial GSS-API token.");
        assert!(msg::INITIAL_TOKEN.starts_with("Failed to initial"));
        assert_eq!(
            msg::SEND_AUTH_REQUEST,
            "Failed to send GSS-API authentication request."
        );
        assert_eq!(
            msg::SEND_AUTH_TOKEN,
            "Failed to send GSS-API authentication token."
        );
        assert_eq!(
            msg::RECV_AUTH_RESPONSE,
            "Failed to receive GSS-API authentication response."
        );
        assert_eq!(
            msg::TOKEN_ALLOC_FAILED,
            "Could not allocate memory for GSS-API authentication response \
             token."
        );
        assert_eq!(
            msg::RECV_AUTH_TOKEN,
            "Failed to receive GSS-API authentication token."
        );
        assert_eq!(msg::DETERMINE_USERNAME, "Failed to determine username.");
        assert_eq!(
            msg::WRAP_FAILED,
            "Failed to wrap GSS-API encryption value into token."
        );
        assert_eq!(
            msg::SEND_ENCRYPTION_REQUEST,
            "Failed to send GSS-API encryption request."
        );
        assert_eq!(
            msg::SEND_ENCRYPTION_TYPE,
            "Failed to send GSS-API encryption type."
        );
        assert_eq!(
            msg::RECV_ENCRYPTION_RESPONSE,
            "Failed to receive GSS-API encryption response."
        );
        assert_eq!(
            msg::RECV_ENCRYPTION_TYPE,
            "Failed to receive GSS-API encryption type."
        );
        assert_eq!(
            msg::UNWRAP_FAILED,
            "Failed to unwrap GSS-API encryption value into token."
        );
    }

    /// The formatted lines, including every conversion the C performs.
    #[test]
    fn the_formatted_lines_match_the_c_exactly() {
        assert_eq!(
            msg::user_rejected(1, 255),
            "User was rejected by the SOCKS5 server (1 255)."
        );
        assert_eq!(
            msg::invalid_auth_response_type(1, 2),
            "Invalid GSS-API authentication response type (1 2)."
        );
        assert_eq!(
            msg::invalid_encryption_response_type(1, 1),
            "Invalid GSS-API encryption response type (1 1)."
        );
        assert_eq!(
            msg::invalid_encryption_response_length(0),
            "Invalid GSS-API encryption response length (0)."
        );
        assert_eq!(
            msg::invalid_encryption_response_length(2),
            "Invalid GSS-API encryption response length (2)."
        );
        // `%.*s` over a token with no terminator, and one that is not UTF-8.
        assert_eq!(
            msg::authenticated_user(b"alice@EXAMPLE.COM"),
            "SOCKS5 server authenticated user alice@EXAMPLE.COM with GSS-API."
        );
        assert_eq!(
            msg::authenticated_user(&[0xff, 0xfe]),
            "SOCKS5 server authenticated user \u{fffd}\u{fffd} with GSS-API."
        );
        assert_eq!(
            msg::gss_api_error("gss_wrap", "no credentials.\n"),
            "GSS-API error: gss_wrap failed: no credentials.\n"
        );
    }

    /// The three protection words, and the three complete sentences the
    /// `with%s` splice assembles.
    #[test]
    fn the_protection_words_and_the_spliced_sentences_are_frozen() {
        assert_eq!(
            msg::protection_supported(SOCKS5_PROTECTION_NONE),
            "SOCKS5 server supports GSS-API no data protection."
        );
        assert_eq!(
            msg::protection_supported(SOCKS5_PROTECTION_INTEGRITY),
            "SOCKS5 server supports GSS-API integrity data protection."
        );
        assert_eq!(
            msg::protection_supported(SOCKS5_PROTECTION_CONFIDENTIALITY),
            "SOCKS5 server supports GSS-API confidentiality data protection."
        );

        assert_eq!(
            msg::access_granted(SOCKS5_PROTECTION_NONE),
            "SOCKS5 access without GSS-API data protection granted."
        );
        assert_eq!(
            msg::access_granted(SOCKS5_PROTECTION_INTEGRITY),
            "SOCKS5 access with GSS-API integrity protection granted."
        );
        assert_eq!(
            msg::access_granted(SOCKS5_PROTECTION_CONFIDENTIALITY),
            "SOCKS5 access with GSS-API confidentiality protection granted."
        );
    }

    /// Confidentiality wins over integrity (`lib/socks_gssapi.c:329-335`).
    #[test]
    fn the_protection_level_prefers_confidentiality() {
        assert_eq!(
            protection_level(true, true),
            SOCKS5_PROTECTION_CONFIDENTIALITY,
            "CONF is tested first, so both bits select confidentiality"
        );
        assert_eq!(
            protection_level(true, false),
            SOCKS5_PROTECTION_CONFIDENTIALITY
        );
        assert_eq!(protection_level(false, true), SOCKS5_PROTECTION_INTEGRITY);
        assert_eq!(protection_level(false, false), SOCKS5_PROTECTION_NONE);
    }

    /// The four-byte header, big-endian `LEN`, `VER` always 1.
    #[test]
    fn the_exchange_header_is_version_one_and_big_endian() {
        type Header = Socks5Gssapi<ScriptedGss>;

        assert_eq!(
            Header::exchange_header(MTYP_AUTHENTICATION, 4),
            [1, 1, 0, 4]
        );
        assert_eq!(Header::exchange_header(MTYP_PROTECTION, 1), [1, 2, 0, 1]);
        // 0x0102 must be written most significant byte first.
        assert_eq!(
            Header::exchange_header(MTYP_AUTHENTICATION, 0x0102),
            [1, 1, 0x01, 0x02]
        );
        assert_eq!(
            Header::exchange_header(MTYP_PROTECTION, 0xffff),
            [1, 2, 0xff, 0xff]
        );
    }

    // -- 2. the complete exchange, byte for byte --------------------------

    /// One authentication token, then the standard (wrapped) protection-level
    /// exchange, with level 0 granted.
    #[test]
    fn the_complete_handshake_is_byte_exact() {
        let mut script = one_step(b"AUTH");
        script.wrap = vec![Ok(b"SEALED".to_vec())];
        script.unwrap = vec![Ok(vec![SOCKS5_PROTECTION_NONE])];
        let harness = Harness::new(script);
        // The proxy's protection-level reply: header then a three-byte token.
        harness.feed(&[1, 2, 0, 3]).feed(b"RPL");

        harness.run().expect("the handshake must succeed");

        assert_eq!(
            harness.sent(),
            vec![
                // VER, MTYP=1, LEN=4, then the token.
                1, 1, 0, 4, b'A', b'U', b'T', b'H',
                // VER, MTYP=2, LEN=6, then the sealed level byte.
                1, 2, 0, 6, b'S', b'E', b'A', b'L', b'E', b'D',
            ]
        );
        assert_eq!(
            harness.reporter.infos(),
            vec![
                "SOCKS5 server authenticated user alice with GSS-API."
                    .to_string(),
                "SOCKS5 server supports GSS-API no data protection."
                    .to_string(),
                "SOCKS5 access without GSS-API data protection granted."
                    .to_string(),
            ]
        );
        assert!(harness.reporter.failures().is_empty());

        let journal = harness.journal.borrow();
        // The level byte was sealed, and the reply token was unsealed.
        assert_eq!(journal.wrapped, vec![vec![SOCKS5_PROTECTION_NONE]]);
        assert_eq!(journal.unwrapped, vec![b"RPL".to_vec()]);
        // `if(socksreq[0] == 0) Curl_gss_delete_sec_context(..)`.
        assert_eq!(journal.deletes, 1, "level 0 deletes the context");
        drop(journal);

        assert_eq!(harness.conn.enctype(), 0);
    }

    /// A multi-round `GSS_S_CONTINUE_NEEDED` exchange: every token out, every
    /// token back in, and the reply of one round is the input of the next.
    #[test]
    fn a_multi_round_exchange_is_byte_exact() {
        let script = Script {
            import: vec![Ok("service")],
            steps: vec![
                step(b"T1", true, false, false),
                // The flags of the LAST step are the ones that count.
                step(b"T2", false, false, true),
            ],
            inquire: vec![Ok("client")],
            display: vec![Ok(b"bob".to_vec())],
            wrap: vec![Ok(b"W".to_vec())],
            unwrap: vec![Ok(vec![SOCKS5_PROTECTION_INTEGRITY])],
        };
        let harness = Harness::new(script);
        harness
            // The authentication response of round one.
            .feed(&[1, 1, 0, 2])
            .feed(b"S1")
            // The protection-level reply.
            .feed(&[1, 2, 0, 1])
            .feed(b"Z");

        harness.run().expect("the handshake must succeed");

        assert_eq!(
            harness.sent(),
            vec![
                1, 1, 0, 2, b'T', b'1', // round one
                1, 1, 0, 2, b'T', b'2', // round two
                1, 2, 0, 1, b'W', // the protection level
            ]
        );

        let journal = harness.journal.borrow();
        assert_eq!(
            journal.step_inputs,
            vec![None, Some(b"S1".to_vec())],
            "the first step has no input token; the second gets the reply"
        );
        assert_eq!(journal.unwrapped, vec![b"Z".to_vec()]);
        assert_eq!(
            journal.deletes, 0,
            "a non-zero level retains the context, as the C does"
        );
        drop(journal);

        assert_eq!(
            harness.reporter.infos().last().map(String::as_str),
            Some("SOCKS5 access with GSS-API integrity protection granted.")
        );
        assert_eq!(harness.conn.enctype(), 1);
    }

    /// The NEC-compatibility path: `LEN` is 1 and the level byte goes out in
    /// clear, with no `gss_wrap` and no `gss_unwrap` anywhere.
    #[test]
    fn the_nec_path_sends_one_clear_byte() {
        let mut script = one_step(b"A");
        script.steps = vec![step(b"A", false, true, false)];
        let harness = Harness::new(script);
        harness.conn.set(|facts| facts.nec = true);
        // The reply's payload is in clear too.
        harness.feed(&[1, 2, 0, 1, SOCKS5_PROTECTION_CONFIDENTIALITY]);

        harness.run().expect("the handshake must succeed");

        assert_eq!(
            harness.sent(),
            vec![
                1, 1, 0, 1, b'A', // the authentication token
                1, 2, 0, 1, // LEN is exactly 1 ...
                2, // ... and this is the level, unwrapped
            ]
        );

        let journal = harness.journal.borrow();
        assert!(
            journal.wrapped.is_empty(),
            "the NEC path must not call gss_wrap"
        );
        assert!(
            journal.unwrapped.is_empty(),
            "the NEC path must not call gss_unwrap"
        );
        drop(journal);

        assert_eq!(
            harness.reporter.infos(),
            vec![
                "SOCKS5 server authenticated user alice with GSS-API."
                    .to_string(),
                "SOCKS5 server supports GSS-API confidentiality data \
                 protection."
                    .to_string(),
                "SOCKS5 access with GSS-API confidentiality protection \
                 granted."
                    .to_string(),
            ]
        );
        assert_eq!(harness.conn.enctype(), 2);
    }

    /// Every request header this module writes carries `VER` = 1.
    #[test]
    fn every_request_header_is_version_one_never_five() {
        let mut script = one_step(b"AB");
        script.steps = vec![step(b"AB", false, false, true)];
        let harness = Harness::new(script);
        harness.conn.set(|facts| facts.nec = true);
        harness.feed(&[1, 2, 0, 1, SOCKS5_PROTECTION_INTEGRITY]);
        harness.run().expect("the handshake must succeed");

        let sent = harness.sent();
        // The two headers sit at offsets 0 and 4 + 2.
        assert_eq!(sent[0], 1, "the authentication header's VER");
        assert_eq!(sent[6], 1, "the protection header's VER");
        assert_ne!(sent[0], 5);
        assert_ne!(sent[6], 5);
    }

    /// The default service name is `"rcmd"`, joined to the SOCKS proxy's host.
    #[test]
    fn the_default_service_name_is_rcmd_at_the_socks_proxy_host() {
        let mut script = one_step(b"A");
        script.wrap = vec![Ok(b"W".to_vec())];
        script.unwrap = vec![Ok(vec![0])];
        let harness = Harness::new(script);
        harness.feed(&[1, 2, 0, 1, 0]);
        harness.run().expect("the handshake must succeed");

        assert_eq!(
            harness.journal.borrow().imported,
            vec![(b"rcmd@proxy.example".to_vec(), NameType::HostBasedService)]
        );
    }

    /// A configured bare service name takes the same `service@host` form.
    #[test]
    fn a_bare_service_name_is_joined_to_the_host() {
        let mut script = one_step(b"A");
        script.wrap = vec![Ok(b"W".to_vec())];
        script.unwrap = vec![Ok(vec![0])];
        let harness = Harness::new(script);
        harness.conn.set(|facts| {
            facts.service_name = Some("afs".to_string());
            facts.proxy_host = "socks.example.org".to_string();
        });
        harness.feed(&[1, 2, 0, 1, 0]);
        harness.run().expect("the handshake must succeed");

        assert_eq!(
            harness.journal.borrow().imported,
            vec![(
                b"afs@socks.example.org".to_vec(),
                NameType::HostBasedService
            )]
        );
    }

    /// A service name containing a `/` is a full principal and goes in
    /// verbatim, under `GSS_C_NULL_OID`.
    #[test]
    fn a_service_name_with_a_slash_is_imported_verbatim() {
        let mut script = one_step(b"A");
        script.wrap = vec![Ok(b"W".to_vec())];
        script.unwrap = vec![Ok(vec![0])];
        let harness = Harness::new(script);
        harness.conn.set(|facts| {
            facts.service_name = Some("host/socks.example.org".to_string());
        });
        harness.feed(&[1, 2, 0, 1, 0]);
        harness.run().expect("the handshake must succeed");

        assert_eq!(
            harness.journal.borrow().imported,
            vec![(b"host/socks.example.org".to_vec(), NameType::Unspecified)],
            "no @host is appended and the name type is GSS_C_NULL_OID"
        );
    }

    /// `CURLOPT_GSSAPI_DELEGATION` reaches the binding, as it does in the C
    /// through the `data` handed to `Curl_gss_init_sec_context()`.
    #[test]
    fn the_delegation_mask_reaches_the_binding() {
        let mut script = one_step(b"A");
        script.wrap = vec![Ok(b"W".to_vec())];
        script.unwrap = vec![Ok(vec![0])];
        let harness = Harness::new(script);
        harness.conn.set(|facts| facts.delegation = 3);
        harness.feed(&[1, 2, 0, 1, 0]);
        harness.run().expect("the handshake must succeed");

        assert_eq!(harness.journal.borrow().delegation, vec![3]);
    }

    /// An empty token is not sent, and no header is sent for it either
    /// (`lib/socks_gssapi.c:200`).
    #[test]
    fn an_empty_authentication_token_is_not_sent() {
        let mut script = one_step(b"");
        script.wrap = vec![Ok(b"W".to_vec())];
        script.unwrap = vec![Ok(vec![0])];
        let harness = Harness::new(script);
        harness.feed(&[1, 2, 0, 1, 0]);
        harness.run().expect("the handshake must succeed");

        assert_eq!(
            harness.sent(),
            vec![1, 2, 0, 1, b'W'],
            "only the protection-level message reaches the wire"
        );
    }

    // -- 3. the response header, at both read sites -----------------------

    /// A script that reaches the authentication RESPONSE, i.e. one round that
    /// asks to continue.
    fn reaching_the_auth_reply() -> Script {
        Script {
            import: vec![Ok("service")],
            steps: vec![step(b"A", true, false, false)],
            ..Script::default()
        }
    }

    /// A script that reaches the protection-level reply over the standard path.
    fn reaching_the_protection_reply() -> Script {
        let mut script = one_step(b"A");
        script.wrap = vec![Ok(b"W".to_vec())];
        script
    }

    /// `MTYP` 255 is the same line at both read sites, and the `VER` byte is
    /// reported even though it is never validated.
    #[test]
    fn a_rejection_is_the_same_line_at_both_read_sites() {
        let auth = Harness::new(reaching_the_auth_reply());
        // A VER of 5 -- wrong, and deliberately tolerated.
        auth.feed(&[5, 255, 0, 0]);
        let (code, line) = auth.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::user_rejected(5, 255));
        assert_eq!(line, "User was rejected by the SOCKS5 server (5 255).");

        let protection = Harness::new(reaching_the_protection_reply());
        protection.feed(&[5, 255, 0, 0]);
        let (code, other) = protection.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(
            other, line,
            "the C emits one literal from both sites, byte for byte"
        );
    }

    /// A `VER` byte the server got wrong does NOT fail the exchange: it is
    /// ignored at both read sites (`lib/socks_gssapi.c:249`, `:438`).
    #[test]
    fn a_wrong_version_byte_in_a_response_is_ignored() {
        let mut script = one_step(b"A");
        script.wrap = vec![Ok(b"W".to_vec())];
        script.unwrap = vec![Ok(vec![0])];
        let harness = Harness::new(script);
        // VER 99, which RFC 1961 does not permit and curl accepts anyway.
        harness.feed(&[99, 2, 0, 1]).feed(b"Z");

        harness
            .run()
            .expect("the VER byte of a response is not validated");
        assert!(harness.reporter.failures().is_empty());
    }

    /// The wrong `MTYP` is diagnosed differently at each site.
    #[test]
    fn a_wrong_message_type_names_its_own_site() {
        let auth = Harness::new(reaching_the_auth_reply());
        // A protection-level message where an authentication one was due.
        auth.feed(&[1, 2, 0, 0]);
        let (code, line) = auth.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::invalid_auth_response_type(1, 2));
        assert_eq!(
            auth.only_failure(),
            line,
            "a wrong type is one line, with no library diagnosis before it"
        );

        let protection = Harness::new(reaching_the_protection_reply());
        // An authentication message where a protection-level one was due.
        protection.feed(&[1, 1, 0, 0]);
        let (code, line) = protection.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::invalid_encryption_response_type(1, 1));
    }

    // -- 4. short reads, one per read site --------------------------------

    /// The C performs exactly four `Curl_blockread_all` calls -- `:241`,
    /// `:280`, `:431` and `:462` -- and each has its own diagnosis. All four
    /// are exercised here with a transport that has fewer bytes than were
    /// asked for.
    #[test]
    fn a_short_read_names_the_site_that_was_reading() {
        // 1. The authentication response header (`:241-247`).
        let harness = Harness::new(reaching_the_auth_reply());
        harness.feed(&[1, 1, 0]);
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::RECV_AUTH_RESPONSE);

        // 2. The authentication token itself (`:280-290`).
        let harness = Harness::new(reaching_the_auth_reply());
        harness.feed(&[1, 1, 0, 4]).feed(b"XY");
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::RECV_AUTH_TOKEN);

        // 3. The protection-level response header (`:431-436`).
        let harness = Harness::new(reaching_the_protection_reply());
        harness.feed(&[1, 2, 0]);
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::RECV_ENCRYPTION_RESPONSE);

        // 4. The protection-level payload (`:462-471`).
        let harness = Harness::new(reaching_the_protection_reply());
        harness.feed(&[1, 2, 0, 4]).feed(b"XY");
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::RECV_ENCRYPTION_TYPE);
    }

    // -- 5. short and failed sends, one per send site ---------------------

    /// The four `Curl_conn_cf_send` sites and their four distinct lines.
    ///
    /// The order of sends through one full exchange is: the authentication
    /// header, the authentication token, the protection-level header, the
    /// protection-level payload.
    #[test]
    fn a_failed_send_names_the_site_that_was_sending() {
        let expected = [
            (1_usize, msg::SEND_AUTH_REQUEST),
            (2, msg::SEND_AUTH_TOKEN),
            (3, msg::SEND_ENCRYPTION_REQUEST),
            (4, msg::SEND_ENCRYPTION_TYPE),
        ];
        for (attempt, line) in expected {
            let mut script = one_step(b"AB");
            script.wrap = vec![Ok(b"W".to_vec())];
            script.unwrap = vec![Ok(vec![0])];
            let harness = Harness::faulty(script, Some(attempt), None);
            harness.feed(&[1, 2, 0, 1]).feed(b"Z");
            let (code, emitted) = harness.must_fail();
            assert_eq!(code, CURLcode::CouldntConnect, "send {attempt}");
            assert_eq!(emitted, line, "send {attempt}");
        }
    }

    /// A send that succeeds but writes short is the other half of the C's
    /// `if(code || (nwritten != len))`, and produces the same line.
    #[test]
    fn a_short_send_is_treated_exactly_as_a_failed_one() {
        let mut script = one_step(b"AB");
        script.wrap = vec![Ok(b"W".to_vec())];
        script.unwrap = vec![Ok(vec![0])];
        let harness = Harness::faulty(script, None, Some(1));
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::SEND_AUTH_REQUEST);
        assert_eq!(
            harness.sent(),
            vec![1, 1, 0],
            "three of the four header bytes went out before the short write"
        );
    }

    // -- 6. the 16-bit ceiling and the payload length ---------------------

    /// A token the `LEN` field cannot express shares the `"Failed to initial"`
    /// line with a library error (`lib/socks_gssapi.c:189-198`).
    #[test]
    fn a_token_larger_than_the_length_field_is_refused() {
        let mut script = one_step(b"");
        script.steps =
            vec![step(&vec![0_u8; MAX_TOKEN_LEN + 1], false, false, false)];
        let harness = Harness::new(script);
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::INITIAL_TOKEN);
        assert!(
            harness.sent().is_empty(),
            "the guard fires before anything reaches the wire"
        );
    }

    /// A token of exactly `0xffff` bytes is accepted, which is what makes the
    /// bound `>` rather than `>=`.
    #[test]
    fn a_token_of_exactly_the_maximum_length_is_accepted() {
        let mut script = one_step(b"");
        script.steps =
            vec![step(&vec![7_u8; MAX_TOKEN_LEN], false, false, false)];
        script.wrap = vec![Ok(b"W".to_vec())];
        script.unwrap = vec![Ok(vec![0])];
        let harness = Harness::new(script);
        harness.feed(&[1, 2, 0, 1]).feed(b"Z");
        harness.run().expect("0xffff fits the field");

        let sent = harness.sent();
        assert_eq!(&sent[..4], &[1, 1, 0xff, 0xff]);
        assert_eq!(sent.len(), 4 + MAX_TOKEN_LEN + 5);
    }

    /// The granted protection level must be exactly one byte, on both paths.
    #[test]
    fn a_protection_payload_that_is_not_one_byte_is_refused() {
        // Standard path, an empty unwrapped payload.
        let mut script = reaching_the_protection_reply();
        script.unwrap = vec![Ok(Vec::new())];
        let harness = Harness::new(script);
        harness.feed(&[1, 2, 0, 1]).feed(b"Z");
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::invalid_encryption_response_length(0));

        // Standard path, two bytes.
        let mut script = reaching_the_protection_reply();
        script.unwrap = vec![Ok(vec![0, 1])];
        let harness = Harness::new(script);
        harness.feed(&[1, 2, 0, 1]).feed(b"Z");
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::invalid_encryption_response_length(2));

        // NEC path, where the payload arrives in clear and is two bytes.
        let harness = Harness::new(one_step(b"A"));
        harness.conn.set(|facts| facts.nec = true);
        harness.feed(&[1, 2, 0, 2]).feed(&[0, 1]);
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::invalid_encryption_response_length(2));
    }

    // -- 7. the six library-failure sites ---------------------------------

    /// Each `check_gss_err` site frames the library's diagnosis with its own
    /// function name, and the frozen line follows it.
    #[test]
    fn each_library_failure_names_its_own_gss_function() {
        // 1. `gss_import_name()` -> "Failed to create service name."
        let script = Script {
            import: vec![Err(failure("bad name"))],
            ..Script::default()
        };
        let harness = Harness::new(script);
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::SERVICE_NAME_FAILED);
        assert_eq!(
            harness.reporter.failures()[0],
            msg::gss_api_error(gss_fn::IMPORT_NAME, "bad name.\n")
        );

        // 2. `gss_init_sec_context` -> "Failed to initial GSS-API token."
        let script = Script {
            import: vec![Ok("service")],
            steps: vec![Err(failure("no credentials"))],
            ..Script::default()
        };
        let harness = Harness::new(script);
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::INITIAL_TOKEN);
        assert_eq!(
            harness.reporter.failures()[0],
            msg::gss_api_error(gss_fn::INIT_SEC_CONTEXT, "no credentials.\n")
        );

        // 3. `gss_inquire_context` -> "Failed to determine username."
        let script = Script {
            import: vec![Ok("service")],
            steps: vec![step(b"A", false, false, false)],
            inquire: vec![Err(failure("no context"))],
            ..Script::default()
        };
        let harness = Harness::new(script);
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::DETERMINE_USERNAME);
        assert_eq!(
            harness.reporter.failures()[0],
            msg::gss_api_error(gss_fn::INQUIRE_CONTEXT, "no context.\n")
        );

        // 4. `gss_display_name` -> the SAME line as the previous site.
        let script = Script {
            import: vec![Ok("service")],
            steps: vec![step(b"A", false, false, false)],
            inquire: vec![Ok("client")],
            display: vec![Err(failure("unprintable"))],
            ..Script::default()
        };
        let harness = Harness::new(script);
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::DETERMINE_USERNAME);
        assert_eq!(
            harness.reporter.failures()[0],
            msg::gss_api_error(gss_fn::DISPLAY_NAME, "unprintable.\n")
        );

        // 5. `gss_wrap` -> "Failed to wrap GSS-API encryption value ..."
        let mut script = one_step(b"A");
        script.wrap = vec![Err(failure("cannot seal"))];
        let harness = Harness::new(script);
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::WRAP_FAILED);
        assert_eq!(
            harness.reporter.failures()[0],
            msg::gss_api_error(gss_fn::WRAP, "cannot seal.\n")
        );

        // 6. `gss_unwrap` -> "Failed to unwrap GSS-API encryption value ..."
        let mut script = reaching_the_protection_reply();
        script.unwrap = vec![Err(failure("bad token"))];
        let harness = Harness::new(script);
        harness.feed(&[1, 2, 0, 1]).feed(b"Z");
        let (code, line) = harness.must_fail();
        assert_eq!(code, CURLcode::CouldntConnect);
        assert_eq!(line, msg::UNWRAP_FAILED);
        assert_eq!(
            harness.reporter.failures()[0],
            msg::gss_api_error(gss_fn::UNWRAP, "bad token.\n")
        );
    }

    /// A `gss_wrap` failure must not reach the wire: the C emits the diagnosis
    /// before any send.
    #[test]
    fn a_wrap_failure_sends_no_protection_message() {
        let mut script = one_step(b"A");
        script.wrap = vec![Err(failure("cannot seal"))];
        let harness = Harness::new(script);
        harness.must_fail();
        assert_eq!(
            harness.sent(),
            vec![1, 1, 0, 1, b'A'],
            "only the authentication message went out"
        );
    }

    // -- 8. check_gss_err in isolation ------------------------------------

    /// A call that did not fail says nothing and answers false.
    #[test]
    fn check_gss_err_is_silent_when_there_was_no_error() {
        let reporter = RecordingReporter::new();
        assert!(!check_gss_err(reporter.as_ref(), gss_fn::WRAP, None));
        assert!(reporter.failures().is_empty());
        assert!(reporter.infos().is_empty());
    }

    /// The frozen header, the six function names and the `".\n"` separator.
    #[test]
    fn check_gss_err_frames_the_diagnosis_with_the_separator() {
        for function in gss_fn::ALL {
            let reporter = RecordingReporter::new();
            let outcome = failure("Miscellaneous failure");
            assert!(check_gss_err(reporter.as_ref(), function, Some(&outcome)));
            assert_eq!(
                reporter.failures(),
                vec![format!(
                    "GSS-API error: {function} failed: Miscellaneous \
                     failure.\n"
                )]
            );
        }
    }

    /// A diagnosis that would cross `MAX_GSS_LEN` produces NO message at all,
    /// which is the C's `return 1` before the `failf` (`:69`, `:76`).
    #[test]
    fn check_gss_err_emits_nothing_when_the_ceiling_is_crossed() {
        let reporter = RecordingReporter::new();
        let outcome = failure(&"x".repeat(MAX_GSS_LEN * 2));
        assert!(
            check_gss_err(reporter.as_ref(), gss_fn::UNWRAP, Some(&outcome)),
            "an over-long diagnosis is still an error"
        );
        assert!(
            reporter.failures().is_empty(),
            "the C emits nothing on this path"
        );
    }

    /// The ceiling admits a diagnosis that fits it with the separator, and the
    /// bound is the C's `fit > toobig` on `length + index + 1`.
    #[test]
    fn check_gss_err_admits_a_diagnosis_that_fits_the_ceiling() {
        // MAX_GSS_LEN - 3 leaves room for the two separator bytes and the C's
        // terminator slot.
        let reporter = RecordingReporter::new();
        let outcome = failure(&"y".repeat(MAX_GSS_LEN - 3));
        assert!(check_gss_err(
            reporter.as_ref(),
            gss_fn::WRAP,
            Some(&outcome)
        ));
        assert_eq!(reporter.failures().len(), 1);
    }

    /// [`GssFailure`] carries the code the binding reported alongside the text.
    #[test]
    fn a_gss_failure_carries_both_halves() {
        let outcome = GssFailure::new(CURLcode::OutOfMemory, "no memory");
        assert_eq!(outcome.code(), CURLcode::OutOfMemory);
        assert_eq!(outcome.diagnosis(), "no memory");
    }

    // -- 9. the binding adapter -------------------------------------------

    /// The binding's `"<function>() failed: "` prefix is removed so that
    /// `check_gss_err`'s own header does not name the function twice.
    #[test]
    fn the_bindings_prefix_is_stripped_from_a_diagnosis() {
        assert_eq!(
            status_text("gss_init_sec_context() failed: No credentials. "),
            "No credentials. "
        );
        assert_eq!(
            status_text("gss_import_name() failed: Bad name. "),
            "Bad name. "
        );
        // Nothing that does not have the shape is touched.
        assert_eq!(
            status_text("Miscellaneous failure"),
            "Miscellaneous failure"
        );
        assert_eq!(
            status_text("the handshake failed: badly"),
            "the handshake failed: badly",
            "a prefix with a space is prose, not a function name"
        );
        assert_eq!(
            status_text("gss_wrap failed: no parens"),
            "gss_wrap failed: no parens",
            "the binding always writes the parentheses"
        );
    }

    /// A session over the real `crate::ffi` types, with no library call made.
    ///
    /// `SecurityContext::new()` stores `GSS_C_NO_CONTEXT` and its drop
    /// short-circuits on a null handle, so constructing one performs no foreign
    /// call at all -- which is what lets this test run under Miri too.
    fn platform_session(
        reporter: &Arc<RecordingReporter>,
    ) -> PlatformGssSession {
        PlatformGss.open(Arc::clone(reporter) as Arc<dyn Reporter>, 0)
    }

    /// A successful call forwards every line the binding produced, so an
    /// informational warning is not swallowed.
    #[test]
    fn a_successful_binding_call_forwards_every_line() {
        let reporter = RecordingReporter::new();
        let session = platform_session(&reporter);
        let value: Result<u8, GssFailure> = session.finish(
            vec![
                "WARNING: support for CURLGSSAPI_DELEGATION_POLICY_FLAG not \
                 compiled in"
                    .to_string(),
            ],
            Ok(7_u8),
        );
        assert_eq!(value.expect("the call succeeded"), 7);
        assert_eq!(
            reporter.infos(),
            vec![
                "WARNING: support for CURLGSSAPI_DELEGATION_POLICY_FLAG not \
                 compiled in"
                    .to_string()
            ]
        );
        assert!(reporter.failures().is_empty());
    }

    /// A failed call keeps the LAST line as the diagnosis and forwards the
    /// rest, with the binding's prefix stripped.
    #[test]
    fn a_failed_binding_call_keeps_the_last_line_as_the_diagnosis() {
        let reporter = RecordingReporter::new();
        let session = platform_session(&reporter);
        let outcome: Result<u8, GssFailure> = session.finish(
            vec![
                "an earlier note".to_string(),
                "gss_wrap() failed: Miscellaneous failure. ".to_string(),
            ],
            Err(CURLcode::AuthError),
        );
        let outcome = outcome.expect_err("the call failed");
        assert_eq!(outcome.code(), CURLcode::AuthError);
        assert_eq!(outcome.diagnosis(), "Miscellaneous failure. ");
        assert_eq!(reporter.infos(), vec!["an earlier note".to_string()]);
    }

    /// A failure with no captured line at all still produces a usable failure.
    #[test]
    fn a_failed_binding_call_with_no_lines_still_reports() {
        let reporter = RecordingReporter::new();
        let session = platform_session(&reporter);
        let outcome: Result<u8, GssFailure> =
            session.finish(Vec::new(), Err(CURLcode::OutOfMemory));
        let outcome = outcome.expect_err("the call failed");
        assert_eq!(outcome.code(), CURLcode::OutOfMemory);
        assert_eq!(outcome.diagnosis(), "");
        assert!(reporter.infos().is_empty());
    }

    // -- 10. the token allocation ----------------------------------------

    /// `curlx_malloc(us_length)` for every length the 16-bit field can carry,
    /// including the zero the C also permits.
    #[test]
    fn a_token_allocation_covers_the_whole_length_field() {
        assert_eq!(allocate_token(0).expect("zero is legal"), Vec::new());
        assert_eq!(allocate_token(3).expect("three bytes"), vec![0, 0, 0]);
        assert_eq!(
            allocate_token(MAX_TOKEN_LEN)
                .expect("the largest announceable token")
                .len(),
            MAX_TOKEN_LEN
        );
    }

    /// An announced length of zero is read as zero bytes and does not fail:
    /// `malloc(0)` succeeds on every mandated target.
    #[test]
    fn a_zero_length_response_token_is_accepted() {
        let script = Script {
            import: vec![Ok("service")],
            steps: vec![
                step(b"A", true, false, false),
                step(b"", false, false, false),
            ],
            inquire: vec![Ok("client")],
            display: vec![Ok(b"alice".to_vec())],
            wrap: vec![Ok(b"W".to_vec())],
            unwrap: vec![Ok(vec![0])],
        };
        let harness = Harness::new(script);
        harness
            // An authentication response announcing an empty token.
            .feed(&[1, 1, 0, 0])
            .feed(&[1, 2, 0, 1])
            .feed(b"Z");
        harness.run().expect("an empty response token is legal");
        assert_eq!(
            harness.journal.borrow().step_inputs,
            vec![None, Some(Vec::new())]
        );
    }

    // -- 11. the dead end, end to end with proxy::socks -------------------

    /// A granted protection level of 1 or 2 is negotiated here and then refused
    /// by the SOCKS filter with [`CURLproxycode::GssapiProtection`]
    /// (`lib/socks.c:1166-1171`).
    ///
    /// The two halves share one [`TestConn`], so this really is the round trip:
    /// [`GssConn::set_socks5_gssapi_enctype`] writes the field and
    /// [`SocksConn::socks5_gssapi_enctype`] reads it back one state later.
    #[test]
    fn a_granted_protection_level_is_refused_by_the_socks_filter() {
        for level in [
            SOCKS5_PROTECTION_INTEGRITY,
            SOCKS5_PROTECTION_CONFIDENTIALITY,
        ] {
            let log = new_log();
            let (transport, state) = InMemory::new("TRANSPORT", &log);
            let conn = TestConn::new();
            let reporter = RecordingReporter::new();
            let journal = Arc::new(SyncCell::new(Journal::default()));
            let mut script = one_step(b"A");
            script.wrap = vec![Ok(b"W".to_vec())];
            script.unwrap = vec![Ok(vec![level])];
            let provider = ScriptedGss {
                script: Arc::new(SyncCell::new(script)),
                journal: Arc::clone(&journal),
            };
            let negotiator = Socks5Gssapi::new(
                Arc::clone(&conn) as Arc<dyn GssConn>,
                ScheduledWire::sharing(&state) as Arc<dyn GssWire>,
                Arc::clone(&reporter) as Arc<dyn Reporter>,
                provider,
            );

            let seams = SocksSeams::new(
                Arc::clone(&conn) as Arc<dyn SocksConn>,
                Arc::new(UnusedResolver) as Arc<dyn DestinationResolver>,
            )
            .with_gssapi(Arc::new(negotiator));
            let mut proxy = SocksProxy::new(
                SocketIndex::First,
                Some(ConnId::new(7)),
                seams,
            );
            proxy.base_mut().set_next(Some(link(transport)));

            {
                let mut queued = state.borrow_mut();
                // The proxy chooses method 1, GSS-API.
                queued.input.extend_from_slice(&[5, 1]);
                // The protection-level reply the negotiation reads.
                queued.input.extend_from_slice(&[1, 2, 0, 1]);
                queued.input.extend_from_slice(b"Z");
                // A CONNECT reply, which must never be reached.
                queued
                    .input
                    .extend_from_slice(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);
            }

            let clock = TestClock::new(CurlTime::new(1, 0));
            let mut cx = CallCtx::new(&clock);
            let error = proxy
                .connect(&mut cx)
                .expect_err("per-message protection is refused");

            assert_eq!(error.code(), CURLcode::Proxy);
            assert_eq!(
                conn.proxy_code(),
                Some(CURLproxycode::GssapiProtection),
                "level {level}"
            );
            assert_eq!(conn.enctype(), i32::from(level));
            // The negotiation itself succeeded: it emitted no failure.
            assert!(
                reporter.failures().is_empty(),
                "the refusal is the filter's, not the negotiation's"
            );
            // And the CONNECT reply was never consumed.
            assert_eq!(
                state.borrow().input,
                vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 80]
            );
        }
    }

    /// A protection level of 0 lets the SOCKS handshake continue to the
    /// request, which is the only path curl 8.19.0-DEV completes.
    #[test]
    fn a_protection_level_of_zero_lets_the_handshake_continue() {
        let log = new_log();
        let (transport, state) = InMemory::new("TRANSPORT", &log);
        let conn = TestConn::new();
        let reporter = RecordingReporter::new();
        let journal = Arc::new(SyncCell::new(Journal::default()));
        let mut script = one_step(b"A");
        script.wrap = vec![Ok(b"W".to_vec())];
        script.unwrap = vec![Ok(vec![SOCKS5_PROTECTION_NONE])];
        let provider = ScriptedGss {
            script: Arc::new(SyncCell::new(script)),
            journal: Arc::clone(&journal),
        };
        let negotiator = Socks5Gssapi::new(
            Arc::clone(&conn) as Arc<dyn GssConn>,
            ScheduledWire::sharing(&state) as Arc<dyn GssWire>,
            Arc::clone(&reporter) as Arc<dyn Reporter>,
            provider,
        );
        let seams = SocksSeams::new(
            Arc::clone(&conn) as Arc<dyn SocksConn>,
            Arc::new(UnusedResolver) as Arc<dyn DestinationResolver>,
        )
        .with_gssapi(Arc::new(negotiator));
        let mut proxy =
            SocksProxy::new(SocketIndex::First, Some(ConnId::new(7)), seams);
        proxy.base_mut().set_next(Some(link(transport)));

        {
            let mut queued = state.borrow_mut();
            queued.input.extend_from_slice(&[5, 1]);
            queued.input.extend_from_slice(&[1, 2, 0, 1]);
            queued.input.extend_from_slice(b"Z");
            queued
                .input
                .extend_from_slice(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);
        }

        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        assert!(
            proxy.connect(&mut cx).expect("the handshake must complete"),
            "level 0 is the only completing path"
        );
        assert_eq!(conn.enctype(), 0);
        assert_eq!(journal.borrow().deletes, 1);
        assert_eq!(conn.proxy_code(), None);

        // The whole conversation, in order: the method-selection request, the
        // GSS-API exchange, then the CONNECT request.
        assert_eq!(
            state.borrow().output,
            vec![
                5, 2, 0, 1, // offer no-auth and GSS-API
                1, 1, 0, 1, b'A', // the authentication token
                1, 2, 0, 1, b'W', // the sealed protection level
                5, 1, 0, 3, 1, b'h', 0, 80, // CONNECT h:80
            ]
        );
    }
}
