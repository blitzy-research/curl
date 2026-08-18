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

//! The `"SOCKS"` connection filter -- SOCKS4, SOCKS4a, SOCKS5 and SOCKS5h.
//!
//! Supersedes `lib/socks.c` (1,415 lines) and `lib/socks.h` (56 lines).
//!
//! # Everything here is a fixed binary wire protocol
//!
//! This module writes and reads bytes whose positions and values are settled
//! by SOCKS4 (`https://www.openssh.com/txt/socks4.protocol`), RFC 1928 and
//! RFC 1929, and the harness compares them literally: `compareparts`
//! (`tests/getpart.pm:351-401`) joins the actual and expected arrays into two
//! strings and compares them with Perl `ne`, so there is no per-line matching,
//! no normalisation, no reordering and no whitespace tolerance. Twenty-six
//! fixtures name a `socks4`, `socks5` or `socks5unix` server, seven of them
//! over FTP, which exercises the SECONDARY socket. Every constant below is
//! therefore transcribed from the C rather than derived, and AAP section 0.8.1
//! places all of it outside this migration's authority to change.
//!
//! The same discipline covers the strings. The eighteen state names in
//! [`STATE_NAMES`] reach `--trace` output, and every `failf` line reaches
//! `CURLOPT_ERRORBUFFER`, so each lives once in [`msg`] and is asserted
//! against the C there.
//!
//! # What the translation changes, and what it must not
//!
//! `struct Curl_cftype` (`lib/cfilters.h:210-226`) carries fourteen function
//! pointers beside a `void *ctx` that every implementation casts to its own
//! type. AAP section 0.1.2 names that cast the largest source of unsound
//! patterns in the C tree, and it is gone here: [`SocksProxy`] holds its
//! handshake state in an ordinary typed field, so no cast exists at any
//! boundary. `Option` carries the one thing the pointer said that a type
//! cannot -- `Curl_cf_socks_proxy_insert_after` creates the filter with a NULL
//! context (`lib/socks.c:1409`) and the first connect allocates it
//! (`:1234-1260`), which [`SocksProxy::state`] reproduces exactly.
//!
//! The C's `switch` with its `FALLTHROUGH()` and `goto process_state` becomes
//! a `loop` over an exhaustive `match`. That is the one structural liberty
//! taken, and it is behaviour-preserving: each fallthrough is preceded by
//! `sxstate()` setting the state the next arm handles, so re-entering the
//! match lands on that same arm. Exhaustiveness is the gain -- a state nobody
//! handles is a compile error rather than a silent fall through the default.
//!
//! # Where the connection's facts come from
//!
//! Nothing here reads a god struct. `struct connectdata` has upwards of ninety
//! members and `lib/urldata.h` is included by nearly every translation unit;
//! the eighteen facts this filter actually needs arrive through
//! [`SocksConn`], and the destination lookup through
//! [`DestinationResolver`], both injected.
//! That is what makes the handshake testable byte-for-byte without a network,
//! a resolver or a clock, which is the whole reason the seams exist.
//!
//! Link targets are written out below rather than inline. `proxy/mod.rs`
//! carries OUTER documentation on its `pub(crate) mod socks;` declaration,
//! and rustdoc merges that with this inner block and then resolves the whole
//! of it in the PARENT module's scope -- where none of these names is
//! visible. An explicit path resolves from either scope.
//!
//! [`STATE_NAMES`]: crate::proxy::socks::STATE_NAMES
//! [`msg`]: crate::proxy::socks::msg
//! [`SocksProxy`]: crate::proxy::socks::SocksProxy
//! [`SocksProxy::state`]: crate::proxy::socks::SocksProxy::state
//! [`SocksConn`]: crate::proxy::socks::SocksConn
//! [`DestinationResolver`]: crate::proxy::socks::DestinationResolver

use std::fmt;
use std::sync::Arc;

use crate::conn::filters::{
    link, CallCtx, CfQuery, CfQueryValue, CfType, ConnFilter, ConnId,
    FilterBase, FilterChain, IpQuadruple, CF_TYPE_IP_CONNECT, CF_TYPE_PROXY,
};
use crate::conn::select::{
    socket_readable, EasyPollset, Socket, CURL_SOCKET_BAD,
};
use crate::conn::SocketIndex;
use crate::dns::{AddressFamily, DnsEntryRef, IpVersion};
use crate::error::{CURLcode, CurlResult, Error};
use crate::proxy::{CURLproxycode, SOCKS5_AUTH_BASIC, SOCKS5_AUTH_GSSAPI};
use crate::trace::{failf, infof, trc_cf, TraceFilter};
use crate::util::bufq::{BufQ, BufqOpts};
use crate::util::inet::{pton4, pton6};
// `TimeDiff` and its ceiling are named by the signatures this module consumes
// -- `conn::select::socket_readable` takes one and `conn::timeleft_ms` returns
// one -- so they come from the module that defines them rather than being
// re-spelled here.
use crate::util::timediff::{TimeDiff, TIMEDIFF_T_MAX};

/// The filter type's `name` member: `"SOCKS"` (`lib/socks.c:1385`).
///
/// **Not `"SOCKS-PROXY"`.** The literal is what `--trace-config` matches and
/// what every trace line from this filter is labelled with, and
/// `crate::trace::TraceFilter::SocksProxy` renders the same five characters.
pub(crate) const SOCKS_FILTER_NAME: &str = "SOCKS";

/// `SOCKS_CHUNK_SIZE` (`lib/socks.c:93`).
///
/// One chunk holds any request or response this protocol can produce: the
/// longest is a SOCKS5 reply with a domain-name `BND.ADDR`, at
/// `4 + 1 + 255 + 2` = 262 bytes.
const SOCKS_CHUNK_SIZE: usize = 1024;

/// `SOCKS_CHUNKS` (`lib/socks.c:94`).
const SOCKS_CHUNKS: usize = 1;

/// The SOCKS4 version byte, `buf[0] = 4` (`lib/socks.c:268`).
const SOCKS4_VERSION: u8 = 4;

/// The SOCKS5 version byte, `req[0] = 5` (`lib/socks.c:615`, `:777`).
const SOCKS5_VERSION: u8 = 5;

/// `CONNECT`, which is command 1 in both versions (`:269`, `:778`).
const CMD_CONNECT: u8 = 1;

/// The RFC 1929 username/password sub-negotiation version, `buf[0] = 1`
/// (`lib/socks.c:718`).
///
/// **One, not five.** The sub-negotiation carries its own version number, and
/// writing the SOCKS5 version here is the classic implementation mistake.
const SOCKS5_AUTH_SUBNEGOTIATION_VERSION: u8 = 1;

/// Method 0: no authentication (`lib/socks.c:617`).
const SOCKS5_METHOD_NONE: u8 = 0;

/// Method 1: GSS-API (`lib/socks.c:621`).
const SOCKS5_METHOD_GSSAPI: u8 = 1;

/// Method 2: username and password (`lib/socks.c:626`).
const SOCKS5_METHOD_USERPASS: u8 = 2;

/// Method 255: the server accepted none of the offered methods (`:679`).
const SOCKS5_METHOD_NONE_ACCEPTABLE: u8 = 255;

/// `ATYP` 1: a four-byte IPv4 address (`lib/socks.c:800`, `:895`).
const ATYP_IPV4: u8 = 1;

/// `ATYP` 3: a length byte followed by a domain name (`lib/socks.c:806`).
const ATYP_DOMAIN: u8 = 3;

/// `ATYP` 4: a sixteen-byte IPv6 address (`lib/socks.c:791`, `:905`).
const ATYP_IPV6: u8 = 4;

/// The longest field the protocol can length-prefix with one byte.
///
/// Used as the cap on the SOCKS5 domain name (RFC 1928 chapter 5), on both
/// sub-negotiation credentials (RFC 1929), on the SOCKS4a hostname and on the
/// SOCKS4 user id. The last of those has no protocol limit at all; curl caps
/// it anyway, *"since SOCKS5 limits the proxy user field to 255 bytes and it
/// seems likely that a longer field is either a mistake or malicious input"*
/// (`lib/socks.c:288-290`).
const MAX_FIELD_LEN: usize = 255;

/// The fixed eight-byte SOCKS4 reply (`lib/socks.c:389`, `:398-401`).
const SOCKS4_RESPONSE_LEN: usize = 8;

/// The two-byte SOCKS5 method-selection and sub-negotiation replies
/// (`lib/socks.c:645`, `:750`).
const SOCKS5_SHORT_RESPONSE_LEN: usize = 2;

/// One chunk must hold the longest reply the protocol can produce, because
/// [`SOCKS_CHUNKS`] is 1 and [`crate::util::bufq::BufQ::peek`] returns the HEAD
/// CHUNK ONLY -- a reply split across two chunks would be read short.
///
/// The worst case is a SOCKS5 `CONNECT` reply carrying a domain-name
/// `BND.ADDR`: four fixed bytes, the one-byte length, up to [`MAX_FIELD_LEN`]
/// of name and the two-byte port (`lib/socks.c:1017`). Asserted at compile
/// time -- anonymous, because a named constant of unit type is dead code --
/// so no build can widen a field past what the buffer holds.
const _: () = assert!(4 + 1 + MAX_FIELD_LEN + 2 < SOCKS_CHUNK_SIZE);

/// The minimum SOCKS5 `CONNECT` reply -- `size_t resp_len = 8` at
/// `lib/socks.c:953`, described there as the *"minimum response length"*.
const SOCKS5_MIN_RESPONSE_LEN: usize = 8;

/// SOCKS4 reply code 90: *"request granted"* (`lib/socks.c:406`).
const SOCKS4_GRANTED: u8 = 90;

/// SOCKS4 reply code 91: *"request rejected or failed"* (`:407`).
const SOCKS4_REJECTED: u8 = 91;

/// SOCKS4 reply code 92: the server could not reach identd on the client
/// (`:408-409`).
const SOCKS4_NO_IDENTD: u8 = 92;

/// SOCKS4 reply code 93: the client and identd disagree about the user id
/// (`:410-411`).
const SOCKS4_IDENTD_MISMATCH: u8 = 93;

/// The SOCKS4a placeholder address, `unsigned char buf[4] = { 0, 0, 0, 1 }`
/// (`lib/socks.c:518`).
///
/// A deliberately invalid address: it tells a SOCKS4a server that the hostname
/// follows the user id instead. `0.0.0.1` is the protocol's own signal and not
/// an address that is ever connected to.
const SOCKS4A_PLACEHOLDER_ADDRESS: [u8; 4] = [0, 0, 0, 1];

/// The RFC 1928 section 6 reply codes, in the order the C table lists them
/// (`lib/socks.c:993-1003`).
///
/// **Indexed by the reply byte**, which is why the order is frozen and why
/// index 0 holds [`CURLproxycode::Ok`]: the C only consults the table for a
/// non-zero code, so slot zero exists to keep every other slot at its own
/// number. A code of 9 or more is not in the table and stays at
/// [`CURLproxycode::ReplyUnassigned`], which is the `if(code < 9)` bound at
/// `:991`.
const RFC1928_REPLIES: [CURLproxycode; 9] = [
    CURLproxycode::Ok,
    CURLproxycode::ReplyGeneralServerFailure,
    CURLproxycode::ReplyNotAllowed,
    CURLproxycode::ReplyNetworkUnreachable,
    CURLproxycode::ReplyHostUnreachable,
    CURLproxycode::ReplyConnectionRefused,
    CURLproxycode::ReplyTtlExpired,
    CURLproxycode::ReplyCommandNotSupported,
    CURLproxycode::ReplyAddressTypeNotSupported,
];

// Every frozen line this module can emit

/// The `failf`, `infof` and trace strings, each built exactly once.
///
/// Two reasons this is a module of functions rather than `format!` at the call
/// sites. A `failf` line reaches an application through
/// `CURLOPT_ERRORBUFFER`, so it is observable output and frozen by AAP section
/// 0.8.1; and a string built in one place can be asserted against the C in one
/// place, which is what the tests at the foot of this file do. The C's
/// `printf` conversions are reproduced as they render: `%u` and `%d` over a
/// byte print the byte's value, and `%s` over a NUL-terminated string prints
/// its text.
pub(crate) mod msg {
    /// `"Failed to send SOCKS request: %s"` (`lib/socks.c:217`), whose argument
    /// is `curl_easy_strerror(result)`.
    pub(crate) fn send_failed(reason: &str) -> String {
        format!("Failed to send SOCKS request: {reason}")
    }

    /// `"Failed to receive SOCKS response: %s"` (`lib/socks.c:243`).
    pub(crate) fn recv_failed(reason: &str) -> String {
        format!("Failed to receive SOCKS response: {reason}")
    }

    /// `"Failed to receive SOCKS response, proxy closed connection"`
    /// (`lib/socks.c:249-250`), two adjoining C literals and therefore one
    /// line with a single space where they join.
    pub(crate) const RECV_CLOSED: &str =
        "Failed to receive SOCKS response, proxy closed connection";

    /// `"Too long SOCKS proxy username"` (`lib/socks.c:291`).
    pub(crate) const LONG_SOCKS_USERNAME: &str =
        "Too long SOCKS proxy username";

    /// `"Failed to resolve \"%s\" for SOCKS4 connect."` (`lib/socks.c:343`).
    ///
    /// The quotation marks around the host are part of the message.
    pub(crate) fn socks4_resolve_failed(host: &str) -> String {
        format!("Failed to resolve \"{host}\" for SOCKS4 connect.")
    }

    /// `"SOCKS4 connection to %s not supported"` (`lib/socks.c:374`) -- emitted
    /// when the name resolved but no IPv4 address was among the answers.
    pub(crate) fn socks4_unsupported(host: &str) -> String {
        format!("SOCKS4 connection to {host} not supported")
    }

    /// `"SOCKS4 reply is incomplete."` (`lib/socks.c:390`).
    pub(crate) const SOCKS4_REPLY_INCOMPLETE: &str =
        "SOCKS4 reply is incomplete.";

    /// `"SOCKS4 reply has wrong version, version should be 0."`
    /// (`lib/socks.c:416`).
    pub(crate) const SOCKS4_BAD_VERSION: &str =
        "SOCKS4 reply has wrong version, version should be 0.";

    /// `"SOCKS4: too long hostname"` (`lib/socks.c:522`).
    pub(crate) const SOCKS4_LONG_HOSTNAME: &str = "SOCKS4: too long hostname";

    /// The shared head of all four SOCKS4 rejection lines
    /// (`lib/socks.c:428-431`), which every arm of the `switch` repeats
    /// verbatim before adding its own tail.
    ///
    /// `"[SOCKS] cannot complete SOCKS4 connection to %u.%u.%u.%u:%u. (%u)"`
    /// over `resp[4..8]`, `(resp[2] << 8) | resp[3]` and `resp[1]`. Note what
    /// the numbers are: the address and port are the ones the SERVER echoed in
    /// its reply, not the ones the request carried.
    fn socks4_rejection(resp: &[u8; 8]) -> String {
        let port = (u16::from(resp[2]) << 8) | u16::from(resp[3]);
        format!(
            "[SOCKS] cannot complete SOCKS4 connection to \
             {}.{}.{}.{}:{}. ({})",
            resp[4], resp[5], resp[6], resp[7], port, resp[1]
        )
    }

    /// Reply 91: `", request rejected or failed."` (`lib/socks.c:429`).
    pub(crate) fn socks4_rejected(resp: &[u8; 8]) -> String {
        format!("{}, request rejected or failed.", socks4_rejection(resp))
    }

    /// Reply 92: `", request rejected because SOCKS server cannot connect to
    /// identd on the client."` (`lib/socks.c:436-437`).
    pub(crate) fn socks4_no_identd(resp: &[u8; 8]) -> String {
        format!(
            "{}, request rejected because SOCKS server cannot connect to \
             identd on the client.",
            socks4_rejection(resp)
        )
    }

    /// Reply 93: `", request rejected because the client program and identd
    /// report different user-ids."` (`lib/socks.c:444-445`).
    pub(crate) fn socks4_identd_mismatch(resp: &[u8; 8]) -> String {
        format!(
            "{}, request rejected because the client program and identd \
             report different user-ids.",
            socks4_rejection(resp)
        )
    }

    /// Any other reply: `", Unknown."` (`lib/socks.c:452`).
    pub(crate) fn socks4_unknown(resp: &[u8; 8]) -> String {
        format!("{}, Unknown.", socks4_rejection(resp))
    }

    /// `"SOCKS5: the destination hostname is too long to be resolved remotely
    /// by the proxy."` (`lib/socks.c:603-604`) -- the RFC 1928 chapter 5 cap.
    pub(crate) const SOCKS5_LONG_HOSTNAME: &str =
        "SOCKS5: the destination hostname is too long to be resolved \
         remotely by the proxy.";

    /// `"warning: unsupported value passed to CURLOPT_SOCKS5_AUTH: %u"`
    /// (`lib/socks.c:609-610`). An `infof`, not a `failf`: the unsupported bits
    /// are reported and then ignored.
    pub(crate) fn unsupported_socks5_auth(auth: u8) -> String {
        format!(
            "warning: unsupported value passed to CURLOPT_SOCKS5_AUTH: {auth}"
        )
    }

    /// `"SOCKS5 initial reply is incomplete."` (`lib/socks.c:646`).
    pub(crate) const SOCKS5_REPLY0_INCOMPLETE: &str =
        "SOCKS5 initial reply is incomplete.";

    /// `"Received invalid version in initial SOCKS5 response."`
    /// (`lib/socks.c:651`).
    pub(crate) const SOCKS5_BAD_VERSION0: &str =
        "Received invalid version in initial SOCKS5 response.";

    /// `"SOCKS5 GSSAPI per-message authentication is not enabled."`
    /// (`lib/socks.c:669`) -- the server chose GSS-API but
    /// `CURLOPT_SOCKS5_AUTH` does not permit it.
    pub(crate) const SOCKS5_GSSAPI_NOT_ENABLED: &str =
        "SOCKS5 GSSAPI per-message authentication is not enabled.";

    /// `"BASIC authentication proposed but not enabled."`
    /// (`lib/socks.c:677`).
    pub(crate) const SOCKS5_BASIC_NOT_ENABLED: &str =
        "BASIC authentication proposed but not enabled.";

    /// `"No authentication method was acceptable."` (`lib/socks.c:680`) --
    /// reply 255.
    pub(crate) const SOCKS5_NO_ACCEPTABLE_METHOD: &str =
        "No authentication method was acceptable.";

    /// `"Unknown SOCKS5 mode attempted to be used by server."`
    /// (`lib/socks.c:683`).
    pub(crate) const SOCKS5_UNKNOWN_MODE: &str =
        "Unknown SOCKS5 mode attempted to be used by server.";

    /// `"Excessive username length for proxy auth"` (`lib/socks.c:702`).
    pub(crate) const EXCESSIVE_USERNAME: &str =
        "Excessive username length for proxy auth";

    /// `"Excessive password length for proxy auth"` (`lib/socks.c:706`).
    pub(crate) const EXCESSIVE_PASSWORD: &str =
        "Excessive password length for proxy auth";

    /// `"SOCKS5 sub-negotiation response incomplete."` (`lib/socks.c:751`).
    pub(crate) const SOCKS5_AUTH_REPLY_INCOMPLETE: &str =
        "SOCKS5 sub-negotiation response incomplete.";

    /// `"User was rejected by the SOCKS5 server (%d %d)."`
    /// (`lib/socks.c:758-759`), over both reply bytes -- the version byte the
    /// check itself ignores is still printed.
    pub(crate) fn user_rejected(version: u8, status: u8) -> String {
        format!("User was rejected by the SOCKS5 server ({version} {status}).")
    }

    /// `"Failed to resolve \"%s\" for SOCKS5 connect."`
    /// (`lib/socks.c:869`, and again at `:886` after the family scan).
    pub(crate) fn socks5_resolve_failed(host: &str) -> String {
        format!("Failed to resolve \"{host}\" for SOCKS5 connect.")
    }

    /// `"SOCKS5 connection to %s not supported"` (`lib/socks.c:915`).
    ///
    /// Its argument is `dest`, the PRINTABLE ADDRESS the resolver produced,
    /// where the SOCKS4 counterpart prints the hostname. The asymmetry is in
    /// the C and is preserved.
    pub(crate) fn socks5_unsupported(dest: &str) -> String {
        format!("SOCKS5 connection to {dest} not supported")
    }

    /// `"SOCKS5 response is incomplete."` (`lib/socks.c:963`, `:1033`).
    pub(crate) const SOCKS5_RESPONSE_INCOMPLETE: &str =
        "SOCKS5 response is incomplete.";

    /// `"SOCKS5 reply has wrong version, version should be 5."`
    /// (`lib/socks.c:983`).
    pub(crate) const SOCKS5_BAD_VERSION1: &str =
        "SOCKS5 reply has wrong version, version should be 5.";

    /// `"cannot complete SOCKS5 connection to %s. (%d)"`
    /// (`lib/socks.c:989-990`) -- the hostname, then the reply code.
    pub(crate) fn socks5_connect_failed(host: &str, code: u8) -> String {
        format!("cannot complete SOCKS5 connection to {host}. ({code})")
    }

    /// `"SOCKS5 reply has wrong address type."` (`lib/socks.c:1021`).
    pub(crate) const SOCKS5_BAD_ADDRESS_TYPE: &str =
        "SOCKS5 reply has wrong address type.";

    /// `"Unable to negotiate SOCKS5 GSS-API context."` (`lib/socks.c:1097`).
    // Emitted only by the `negotiate` build, and asserted by the tests in both
    // configurations so that the string cannot drift in the one that is off.
    #[allow(dead_code)]
    pub(crate) const SOCKS5_GSSAPI_FAILED: &str =
        "Unable to negotiate SOCKS5 GSS-API context.";

    /// `"SOCKS5 GSSAPI per-message authentication is not supported."`
    /// (`lib/socks.c:1103-1104`) -- the message for a build with no GSS-API at
    /// all, which is why it says "supported" where `:669` says "enabled".
    pub(crate) const SOCKS5_GSSAPI_UNSUPPORTED: &str =
        "SOCKS5 GSSAPI per-message authentication is not supported.";

    /// `"SOCKS5 GSS-API protection not yet implemented."`
    /// (`lib/socks.c:1168`).
    ///
    /// Deliberate in curl 8.19.0-DEV: per-message integrity and
    /// confidentiality are negotiable but unimplemented, so selecting either
    /// fails here rather than sending unprotected bytes.
    pub(crate) const SOCKS5_GSSAPI_PROTECTION: &str =
        "SOCKS5 GSS-API protection not yet implemented.";

    /// `"unknown proxytype option given"` (`lib/socks.c:1274`) -- the filter
    /// was installed for a proxy type that is not a SOCKS one.
    pub(crate) const UNKNOWN_PROXYTYPE: &str = "unknown proxytype option given";

    /// `"Opened %sSOCKS connection from %s port %u to %s port %u (via %s port
    /// %u)"` (`lib/socks.c:1292-1297`), the verbose success line.
    ///
    /// The leading `%s` is `"2nd "` for the secondary socket and empty
    /// otherwise, so the line reads *"Opened 2nd SOCKS connection"* for an FTP
    /// data connection.
    pub(crate) fn opened(
        second: bool,
        local_ip: &str,
        local_port: u16,
        host: &str,
        remote_port: i32,
        proxy_ip: &str,
        proxy_port: u16,
    ) -> String {
        format!(
            "Opened {}SOCKS connection from {local_ip} port {local_port} \
             to {host} port {remote_port} (via {proxy_ip} port {proxy_port})",
            second_prefix(second)
        )
    }

    /// `"Opened %sSOCKS connection"` (`lib/socks.c:1299-1300`), the fallback
    /// when the filter below could not report its addresses.
    pub(crate) fn opened_short(second: bool) -> String {
        format!("Opened {}SOCKS connection", second_prefix(second))
    }

    /// `(sockindex == SECONDARYSOCKET) ? "2nd " : ""`, including its trailing
    /// space.
    fn second_prefix(second: bool) -> &'static str {
        if second {
            "2nd "
        } else {
            ""
        }
    }
}

// The state machine -- `enum socks_state_t` and `cf_socks_statename[]`

/// The eighteen states of the SOCKS handshake -- `enum socks_state_t`
/// (`lib/socks.c:46-68`).
///
/// Declared in the C's order, with the two terminal states last, because
/// [`STATE_NAMES`] is indexed by that order.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum HandshakeState {
    /// `SOCKS_ST_INIT`: nothing chosen yet. The state a freshly allocated
    /// context is in, which in the C is the zero a `calloc` leaves.
    #[default]
    Init,
    /// `SOCKS4_ST_START`.
    Socks4Start,
    /// `SOCKS4_ST_RESOLVING`.
    Socks4Resolving,
    /// `SOCKS4_ST_SEND`.
    Socks4Send,
    /// `SOCKS4_ST_RECV`.
    Socks4Recv,
    /// `SOCKS5_ST_START`.
    Socks5Start,
    /// `SOCKS5_ST_REQ0_SEND`: the method-selection request is buffered.
    Socks5Req0Send,
    /// `SOCKS5_ST_RESP0_RECV` -- *"set up read"*.
    Socks5Resp0Recv,
    /// `SOCKS5_ST_GSSAPI_INIT`.
    Socks5GssapiInit,
    /// `SOCKS5_ST_AUTH_INIT` -- *"setup outgoing auth buffer"*.
    Socks5AuthInit,
    /// `SOCKS5_ST_AUTH_SEND` -- *"send auth"*.
    Socks5AuthSend,
    /// `SOCKS5_ST_AUTH_RECV` -- *"read auth response"*.
    Socks5AuthRecv,
    /// `SOCKS5_ST_REQ1_INIT` -- *"init SOCKS \"request\""*.
    Socks5Req1Init,
    /// `SOCKS5_ST_RESOLVING`.
    Socks5Resolving,
    /// `SOCKS5_ST_REQ1_SEND`.
    Socks5Req1Send,
    /// `SOCKS5_ST_RESP1_RECV`.
    Socks5Resp1Recv,
    /// `SOCKS_ST_SUCCESS`: terminal, both versions.
    Success,
    /// `SOCKS_ST_FAILED`: terminal, both versions, with the reason in
    /// [`SocksState::presult`].
    Failed,
}

/// The display names of [`HandshakeState`] -- `cf_socks_statename[]`
/// (`lib/socks.c:71-90`), in the enumeration's own order.
///
/// **Frozen strings.** They appear in `--trace` output, so they are observable
/// and cannot be regenerated from the identifiers: every name DROPS the `_ST_`
/// infix its enumerator carries, so `SOCKS_ST_INIT` prints as `SOCKS_INIT` and
/// `SOCKS4_ST_START` as `SOCKS4_START`. Deriving one from the other is exactly
/// the mistake this table exists to prevent, which is why it is written out and
/// asserted character-for-character by
/// `the_eighteen_state_names_are_the_frozen_strings`.
pub(crate) const STATE_NAMES: [&str; 18] = [
    "SOCKS_INIT",
    "SOCKS4_START",
    "SOCKS4_RESOLVING",
    "SOCKS4_SEND",
    "SOCKS4_RECV",
    "SOCKS5_START",
    "SOCKS5_REQ0_SEND",
    "SOCKS5_RESP0_RECV",
    "SOCKS5_GSSAPI_INIT",
    "SOCKS5_AUTH_INIT",
    "SOCKS5_AUTH_SEND",
    "SOCKS5_AUTH_RECV",
    "SOCKS5_REQ1_INIT",
    "SOCKS5_RESOLVING",
    "SOCKS5_REQ1_SEND",
    "SOCKS5_RESP1_RECV",
    "SOCKS_SUCCESS",
    "SOCKS_FAILED",
];

impl HandshakeState {
    /// Every state, in the C's declaration order.
    pub(crate) const ALL: [Self; 18] = [
        Self::Init,
        Self::Socks4Start,
        Self::Socks4Resolving,
        Self::Socks4Send,
        Self::Socks4Recv,
        Self::Socks5Start,
        Self::Socks5Req0Send,
        Self::Socks5Resp0Recv,
        Self::Socks5GssapiInit,
        Self::Socks5AuthInit,
        Self::Socks5AuthSend,
        Self::Socks5AuthRecv,
        Self::Socks5Req1Init,
        Self::Socks5Resolving,
        Self::Socks5Req1Send,
        Self::Socks5Resp1Recv,
        Self::Success,
        Self::Failed,
    ];

    /// This state's position in the C enumeration, which is what
    /// `CURL_TRC_CF(... "adjust pollset in (%d)", sx->state)` prints.
    pub(crate) fn as_index(self) -> usize {
        // A linear search over eighteen entries rather than a cast: the
        // enumeration has no `#[repr]`, deliberately, because nothing outside
        // this crate observes these values and pinning them would suggest
        // otherwise. Performance is an explicit non-goal (AAP section 0.1.1).
        Self::ALL
            .iter()
            .position(|state| *state == self)
            .unwrap_or_default()
    }

    /// The frozen display name, from [`STATE_NAMES`].
    ///
    /// An exhaustive `match` rather than an index, so that a state added
    /// without a name is a compile error rather than a wrong trace line.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Init => STATE_NAMES[0],
            Self::Socks4Start => STATE_NAMES[1],
            Self::Socks4Resolving => STATE_NAMES[2],
            Self::Socks4Send => STATE_NAMES[3],
            Self::Socks4Recv => STATE_NAMES[4],
            Self::Socks5Start => STATE_NAMES[5],
            Self::Socks5Req0Send => STATE_NAMES[6],
            Self::Socks5Resp0Recv => STATE_NAMES[7],
            Self::Socks5GssapiInit => STATE_NAMES[8],
            Self::Socks5AuthInit => STATE_NAMES[9],
            Self::Socks5AuthSend => STATE_NAMES[10],
            Self::Socks5AuthRecv => STATE_NAMES[11],
            Self::Socks5Req1Init => STATE_NAMES[12],
            Self::Socks5Resolving => STATE_NAMES[13],
            Self::Socks5Req1Send => STATE_NAMES[14],
            Self::Socks5Resp1Recv => STATE_NAMES[15],
            Self::Success => STATE_NAMES[16],
            Self::Failed => STATE_NAMES[17],
        }
    }

    /// Whether this state is one of the four the filter waits to WRITE in.
    ///
    /// The `case` labels of `socks_cf_adjust_pollset`
    /// (`lib/socks.c:1323-1326`). Every other state waits to read, which is
    /// that `switch`'s `default`.
    pub(crate) fn is_sending(self) -> bool {
        matches!(
            self,
            Self::Socks4Send
                | Self::Socks5Req0Send
                | Self::Socks5AuthSend
                | Self::Socks5Req1Send
        )
    }
}

impl fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// The handshake context -- `struct socks_state`

/// Everything one SOCKS handshake carries -- `struct socks_state`
/// (`lib/socks.c:97-109`).
///
/// Allocated on the FIRST connect and released on success, which is the C's
/// `cf->ctx` lifecycle exactly (`:1234-1260` and `:1303`). It is a typed field
/// of [`SocksProxy`] rather than a `void *`, so no cast exists anywhere in this
/// module.
#[derive(Debug)]
pub(crate) struct SocksState {
    /// `enum socks_state_t state`.
    state: HandshakeState,
    /// `struct bufq iobuf`: the one buffer both directions pass through,
    /// sized by [`SOCKS_CHUNK_SIZE`] and [`SOCKS_CHUNKS`] with
    /// [`BufqOpts::SOFT_LIMIT`] (`lib/socks.c:1258-1259`).
    iobuf: BufQ,
    /// `const char *hostname`: the DESTINATION, chosen by the first of the two
    /// asymmetric chains in [`SocksProxy::destination_host`].
    hostname: String,
    /// `int remote_port`: the destination's port, chosen by the second chain.
    ///
    /// An `i32` and not a `u16`, because the C member is an `int` and the
    /// verbose success line prints it with `%u` after the connect has finished.
    /// The two bytes on the wire are taken from its low sixteen bits, exactly
    /// as `(port >> 8) & 0xff` and `port & 0xff` do.
    remote_port: i32,
    /// `const char *proxy_user`, absent when no proxy credentials are set.
    ///
    /// Cleared by `socks5_req0_init` when `CURLOPT_SOCKS5_AUTH` withholds
    /// `CURLAUTH_BASIC` (`lib/socks.c:611-613`), which is why it lives here
    /// rather than being read from the connection each time it is needed.
    proxy_user: Option<String>,
    /// `const char *proxy_password`.
    proxy_password: Option<String>,
    /// `CURLproxycode presult`: why the handshake failed, read back when the
    /// machine is re-entered in [`HandshakeState::Failed`].
    presult: CURLproxycode,
    /// `unsigned char version`: 4 or 5, set by the `SOCKS_ST_INIT` arm.
    version: u8,
    /// `BIT(resolve_local)`: whether THIS end resolves the destination.
    ///
    /// `CURLPROXY_SOCKS5` resolves locally and `CURLPROXY_SOCKS5_HOSTNAME`
    /// (`socks5h`) does not; for version 4 it is the negation of
    /// [`Self::socks4a`]. The distinction is command-line visible and must not
    /// be normalised away.
    resolve_local: bool,
    /// `BIT(start_resolving)`: the next resolving pass should START a lookup
    /// rather than poll one already running.
    start_resolving: bool,
    /// `BIT(socks4a)`: the proxy type is `CURLPROXY_SOCKS4A`.
    socks4a: bool,
}

impl SocksState {
    /// The context `curlx_calloc(1, sizeof(*sx))` plus `Curl_bufq_init2`
    /// produce (`lib/socks.c:1235-1259`).
    fn new(
        hostname: String,
        remote_port: i32,
        proxy_user: Option<String>,
        proxy_password: Option<String>,
    ) -> Self {
        Self {
            // The `calloc` zero, which is `SOCKS_ST_INIT`.
            state: HandshakeState::Init,
            iobuf: BufQ::with_opts(
                SOCKS_CHUNK_SIZE,
                SOCKS_CHUNKS,
                BufqOpts::SOFT_LIMIT,
            ),
            hostname,
            remote_port,
            proxy_user,
            proxy_password,
            presult: CURLproxycode::Ok,
            version: 0,
            resolve_local: false,
            start_resolving: false,
            socks4a: false,
        }
    }

    /// The state the handshake is in.
    pub(crate) fn state(&self) -> HandshakeState {
        self.state
    }

    /// The destination host -- what `CF_QUERY_HOST_PORT` reports.
    #[allow(dead_code)] // consumers: crate::proxy::socks_gss and the tests
    pub(crate) fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The destination port -- what `CF_QUERY_HOST_PORT` reports.
    #[allow(dead_code)] // consumers: crate::proxy::socks_gss and the tests
    pub(crate) fn remote_port(&self) -> i32 {
        self.remote_port
    }

    /// `sx->version`: 4 once SOCKS4 has started, 5 once SOCKS5 has.
    #[allow(dead_code)] // consumers: crate::proxy::socks_gss and the tests
    pub(crate) fn version(&self) -> u8 {
        self.version
    }

    /// Appends `bytes` to the outgoing buffer.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::SendRequest`], which is what every one of the C's
    /// `if(result || (nwritten != n))` guards returns. A short write is folded
    /// in for the same reason the C folds it: the buffer holds a whole request
    /// with room to spare, so a partial one means the queue is in a state no
    /// caller can recover from.
    fn write(&mut self, bytes: &[u8]) -> Result<(), CURLproxycode> {
        match self.iobuf.write(bytes) {
            Ok(written) if written == bytes.len() => Ok(()),
            _ => Err(CURLproxycode::SendRequest),
        }
    }
}

// The injected seams -- what replaces reaching into `conn` and `data`

/// The connection and transfer facts this filter reads, as a contract.
///
/// # Why a trait and not a struct
///
/// The C reads eighteen members off `cf->conn` and `data`, and it reads several
/// of them FRESH on every pass: `data->set.socks5auth` can be changed between
/// two connects on the same handle, and `conn->ip_version` is WRITTEN by the
/// SOCKS4 path and read afterwards by the resolver. A snapshot taken when the
/// filter was built would answer for a state that no longer holds, so the
/// filter asks instead -- the same reasoning `crate::conn::ResolvedPresence`
/// records for the setup filter.
///
/// # The `Send + Sync` supertraits
///
/// The connection pool holds filters as boxed trait objects and
/// `crate::share::Share` holds the pool, so everything a filter reaches must be
/// `Send`; an [`Arc`] handle is `Send` only when what it points at is
/// `Send + Sync`. AAP section 0.8.3's multi-thread runtime for the multi handle
/// requires the same.
pub(crate) trait SocksConn: fmt::Debug + Send + Sync {
    /// `cf->conn->socks_proxy.proxytype` (`lib/socks.c:489`, `:1056`,
    /// `:1262`) as the public ABI integer, which is a `CURLPROXY_*` value.
    ///
    /// The raw integer rather than an enumeration, because the C's `switch`
    /// has a `default` arm that reports
    /// [`CURLcode::CouldntConnect`] for anything that is not one of the four
    /// SOCKS types (`:1273-1276`), and that arm is reachable: the filter can be
    /// installed while `CURLOPT_PROXYTYPE` names an HTTP proxy. A pre-narrowed
    /// type would make it unreachable and silently delete the diagnosis.
    fn proxy_type(&self) -> i32;

    /// `conn->socks_proxy.user` (`lib/socks.c:1256`).
    fn proxy_user(&self) -> Option<String>;

    /// `conn->socks_proxy.passwd` (`lib/socks.c:1257`).
    fn proxy_password(&self) -> Option<String>;

    /// `data->set.socks5auth` (`lib/socks.c:594`), a `uint8_t` bitmask of
    /// `CURLAUTH_BASIC` and `CURLAUTH_GSSAPI`.
    ///
    /// The default is `crate::proxy::SOCKS5_AUTH_DEFAULT` -- BOTH bits
    /// (`lib/url.c:388`) -- and an implementor that has no configuration of its
    /// own must report exactly that.
    fn socks5_auth(&self) -> u8;

    /// `conn->bits.httpproxy` (`lib/socks.c:497`, `:1061`, `:1245`): an HTTP
    /// proxy sits BEYOND this SOCKS proxy, so the SOCKS destination is that
    /// HTTP proxy rather than the origin.
    fn is_http_proxy(&self) -> bool;

    /// `conn->http_proxy.host.name` (`lib/socks.c:1246`).
    fn http_proxy_host(&self) -> Option<String>;

    /// `conn->http_proxy.port` (`lib/socks.c:1252`).
    fn http_proxy_port(&self) -> u16;

    /// `conn->conn_to_host.name`, present exactly when
    /// `conn->bits.conn_to_host` is set (`lib/socks.c:1247-1248`).
    fn connect_to_host(&self) -> Option<String>;

    /// `conn->conn_to_port`, present exactly when `conn->bits.conn_to_port` is
    /// set (`lib/socks.c:1254`).
    fn connect_to_port(&self) -> Option<u16>;

    /// `conn->secondaryhostname` (`lib/socks.c:1250`), the FTP data
    /// connection's host.
    fn secondary_host(&self) -> Option<String>;

    /// `conn->secondary_port` (`lib/socks.c:1253`).
    fn secondary_port(&self) -> u16;

    /// `conn->host.name` (`lib/socks.c:1250`), the origin.
    fn host_name(&self) -> String;

    /// `conn->remote_port` (`lib/socks.c:1255`).
    fn remote_port(&self) -> u16;

    /// `cf->conn->ip_version` (`lib/socks.c:327`, `:853`), which is what the
    /// destination lookup is restricted to.
    fn ip_version(&self) -> IpVersion;

    /// `cf->conn->ip_version = CURL_IPRESOLVE_V4` (`lib/socks.c:494`).
    ///
    /// Written by the SOCKS4 path alone, whose comment is *"SOCKS4 can only do
    /// IPv4, insist!"*. It is a write to the CONNECTION and outlives this
    /// filter's pass, which is why it is a seam method rather than a local.
    fn set_ip_version(&self, ip_version: IpVersion);

    /// `data->set.ipver` (`lib/socks.c:877-878`): what the APPLICATION asked
    /// for, which is not always what the connection settled on.
    ///
    /// Read only by `socks5_resolving`, to pick the first address of the
    /// requested family out of the answer.
    fn requested_ip_version(&self) -> IpVersion;

    /// `conn->bits.ipv6_ip` (`lib/socks.c:790`): the destination as written is
    /// a numeric IPv6 address.
    fn is_ipv6_ip(&self) -> bool;

    /// `conn->socks5_gssapi_enctype` (`lib/socks.c:1167`): non-zero when
    /// per-message integrity or confidentiality was negotiated.
    fn socks5_gssapi_enctype(&self) -> i32;

    /// `data->info.pxcode = pxresult` (`lib/socks.c:1281`), which
    /// `CURLINFO_PROXY_ERROR` reports (`lib/getinfo.c:318`).
    fn set_proxy_code(&self, code: CURLproxycode);

    /// `Curl_timeleft_ms(data)` (`lib/socks.c:129`).
    ///
    /// The three-way convention of `crate::conn::timeleft_ms` holds: zero means
    /// no limit, a negative reading means the deadline has already passed, and
    /// a positive one is the milliseconds remaining. Only
    /// [`SocksProxy::blockread_all`] reads it, because that is the only
    /// operation in this module that waits.
    #[allow(dead_code)] // read by SocksProxy::blockread_all
    fn time_left_ms(&self) -> TimeDiff;
}

/// How far the destination lookup has got -- the two-call protocol of
/// `Curl_resolv` and `Curl_resolv_check`.
///
/// Four variants and not three, because the C branches on the CODE and the
/// ENTRY separately and the four combinations do not collapse: on the pass that
/// starts a lookup, `CURLE_AGAIN` waits while success-with-no-entry is
/// diagnosed as a failure, and on a polling pass the two swap roles
/// (`lib/socks.c:321-345`). Folding them into one "pending" would make a
/// resolver that answers success with nothing wait for ever instead of
/// reporting [`CURLproxycode::ResolveHost`].
#[derive(Clone, Debug)]
#[allow(dead_code)] // constructed by the injected DestinationResolver
pub(crate) enum ResolveProgress {
    /// `CURLE_OK` with a non-NULL entry: the addresses are ready, in the order
    /// the resolver produced them.
    ///
    /// **The order is behaviour.** `socks4_resolving` takes the first `AF_INET`
    /// entry and `socks5_resolving` the first of the requested family, so a
    /// reordered list is a different destination address on the wire.
    Ready(DnsEntryRef),
    /// `CURLE_AGAIN`: the lookup was accepted and is running elsewhere.
    Again,
    /// `CURLE_OK` with a NULL entry -- what `Curl_resolv_check` reports while
    /// an asynchronous lookup has not finished.
    NoEntry,
    /// Any other code.
    Failed(CURLcode),
}

/// The destination lookup, as a contract.
///
/// # Why this is not `crate::dns::Resolver`
///
/// That trait is asynchronous -- `fn resolve(..) -> ResolveFuture<..>` -- while
/// [`ConnFilter`] is synchronous, exactly as `Curl_cftype` is. The C bridges
/// the same gap with a pair of calls: `Curl_resolv` starts the lookup and may
/// answer `CURLE_AGAIN`, and `Curl_resolv_check` polls it on later passes. This
/// trait is that pair, so the owner of the lookup decides how it is driven --
/// a thread, the tokio runtime, or a table of answers in a test -- and this
/// module needs to know nothing about it.
///
/// # Releasing the entry
///
/// C ends both resolving functions with `Curl_resolv_unlink(data, &dns)`, which
/// drops the cache entry's reference. [`DnsEntryRef`] is an [`Arc`], so
/// dropping the value IS that unlink, and it happens on every path -- including
/// the early returns that the C reaches through its `out:` label.
pub(crate) trait DestinationResolver: fmt::Debug + Send + Sync {
    /// `Curl_resolv(data, hostname, port, ip_version, TRUE, &dns)`
    /// (`lib/socks.c:326-327`, `:852-853`). The `TRUE` is `allowDOH`.
    fn start(
        &self,
        hostname: &str,
        port: i32,
        ip_version: IpVersion,
    ) -> ResolveProgress;

    /// `Curl_resolv_check(data, &dns)` (`lib/socks.c:337`, `:863`).
    fn check(&self) -> ResolveProgress;
}

/// The SOCKS5 GSS-API negotiation, as a contract.
///
/// `Curl_SOCKS5_gssapi_negotiate(cf, data)` (`lib/socks.h:45-46`), which
/// `lib/socks_gssapi.c` implements and which the C declares in a header guarded
/// by `#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)`. The
/// default-off `negotiate` feature is that guard.
///
/// # Why a seam rather than a call into the sibling module
///
/// The negotiation is not a pure function of its arguments: it exchanges
/// several messages over the same socket, using the blocking read this filter
/// exposes as [`SocksProxy::blockread_all`] precisely so that it can. Reaching
/// it through a trait keeps the direction of knowledge one-way -- this module
/// says WHEN the negotiation happens, `crate::proxy::socks_gss` says what it
/// consists of -- and it is what lets the state machine be tested with no
/// GSS-API library present at all.
#[cfg(feature = "negotiate")]
pub(crate) trait GssapiNegotiator: fmt::Debug + Send + Sync {
    /// Runs the negotiation to completion.
    ///
    /// # Errors
    ///
    /// Any code the exchange failed with. The caller reports it as
    /// [`CURLproxycode::Gssapi`] without inspecting it, exactly as
    /// `lib/socks.c:1096-1099` does.
    fn negotiate(&self) -> CurlResult<()>;
}

/// Everything [`SocksProxy`] is injected with.
///
/// One value rather than several constructor arguments, so a caller states its
/// seams once and a test substitutes one of them by rebuilding the bundle.
#[derive(Clone, Debug)]
pub(crate) struct SocksSeams {
    /// The connection's and transfer's own facts.
    pub(crate) conn: Arc<dyn SocksConn>,
    /// The destination lookup, used only when
    /// [`SocksState::resolve_local`] is set.
    pub(crate) resolver: Arc<dyn DestinationResolver>,
    /// The GSS-API negotiation, when this build has one AND a caller supplied
    /// it.
    ///
    /// The two conditions are separate on purpose. The feature decides whether
    /// the CODE exists, which is the C's `#ifdef`; the [`Option`] decides
    /// whether this connection can actually negotiate, and it governs whether
    /// method 1 is OFFERED at all (`socks5_req0_init`). Offering a method that
    /// cannot then be honoured would turn a clean fallback to
    /// username/password into a failed handshake.
    #[cfg(feature = "negotiate")]
    pub(crate) gssapi: Option<Arc<dyn GssapiNegotiator>>,
}

impl SocksSeams {
    /// A bundle with no GSS-API negotiator.
    #[allow(dead_code)] // consumer: crate::conn, which builds the chain
    pub(crate) fn new(
        conn: Arc<dyn SocksConn>,
        resolver: Arc<dyn DestinationResolver>,
    ) -> Self {
        Self {
            conn,
            resolver,
            #[cfg(feature = "negotiate")]
            gssapi: None,
        }
    }

    /// The same bundle with a GSS-API negotiator attached.
    #[cfg(feature = "negotiate")]
    #[must_use]
    #[allow(dead_code)] // consumer: crate::conn, when Kerberos is configured
    pub(crate) fn with_gssapi(
        mut self,
        gssapi: Arc<dyn GssapiNegotiator>,
    ) -> Self {
        self.gssapi = Some(gssapi);
        self
    }

    /// Whether this build and this connection can negotiate GSS-API.
    ///
    /// The successor of the C's `#if defined(HAVE_GSSAPI) ||
    /// defined(USE_WINDOWS_SSPI)` around the method-1 offer
    /// (`lib/socks.c:618-623`).
    fn can_negotiate_gssapi(&self) -> bool {
        #[cfg(feature = "negotiate")]
        {
            self.gssapi.is_some()
        }
        #[cfg(not(feature = "negotiate"))]
        {
            false
        }
    }
}

// The filter -- `Curl_cft_socks_proxy`

/// The `"SOCKS"` connection filter -- `Curl_cft_socks_proxy`
/// (`lib/socks.c:1384-1400`).
///
/// Five of the twelve operations are overridden -- destroy, connect, close,
/// adjust_pollset and query -- and the other seven are left at the trait's
/// defaults, which are the `Curl_cf_def_*` pass-throughs the C names in the
/// same slots. That includes [`ConnFilter::send`] and [`ConnFilter::recv`]:
/// once the handshake has finished this filter is transparent, and every byte
/// of the tunnelled protocol passes straight through it.
#[derive(Debug)]
pub(crate) struct SocksProxy {
    /// The chain link, socket index and the two state flags.
    base: FilterBase,
    /// `cf->ctx`, as a typed field.
    ///
    /// [`None`] until the first connect, because `Curl_cf_create(&cf,
    /// &Curl_cft_socks_proxy, NULL)` (`lib/socks.c:1409`) passes a NULL context
    /// and `socks_proxy_cf_connect` allocates it (`:1234`). It returns to
    /// [`None`] on success, on close and on destroy, all three through
    /// [`Self::free_state`], which is `socks_proxy_cf_free`.
    state: Option<SocksState>,
    /// The injected seams.
    seams: SocksSeams,
}

impl SocksProxy {
    /// `Curl_cf_create(&cf, &Curl_cft_socks_proxy, NULL)`
    /// (`lib/socks.c:1409`): a filter with NO handshake context.
    #[allow(dead_code)] // consumer: crate::conn's filter factory
    pub(crate) fn new(
        sockindex: SocketIndex,
        conn: Option<ConnId>,
        seams: SocksSeams,
    ) -> Self {
        let mut base = FilterBase::new(sockindex);
        base.set_conn(conn);
        Self {
            base,
            state: None,
            seams,
        }
    }

    /// The handshake context, once the first connect has allocated it.
    #[allow(dead_code)] // consumers: crate::proxy::socks_gss and the tests
    pub(crate) fn state(&self) -> Option<&SocksState> {
        self.state.as_ref()
    }

    /// `socks_proxy_cf_free(cf)` (`lib/socks.c:1198-1206`): release the bufq
    /// and the context, and leave `cf->ctx` NULL.
    ///
    /// Dropping the value frees the queue's chunks, which is what
    /// `Curl_bufq_free` does; the explicit `free` call exists in the C only
    /// because the struct is released by a second, separate call.
    fn free_state(&mut self) {
        self.state = None;
    }

    /// `sxstate()` (`lib/socks.c:165-190`): move to `next`, tracing the move.
    ///
    /// **Returns early when the state is unchanged** -- *"do not bother when
    /// the new state is the same as the old state"* (`:176-178`) -- so a
    /// re-entered pass that lands on its own state emits nothing.
    ///
    /// The trace line is `[<old>] -> [<new>]`. The C appends `(line %d)`, but
    /// only under `DEBUGBUILD && CURLVERBOSE`, where the whole name table also
    /// lives; the `__LINE__` it prints is a line number in `lib/socks.c` and
    /// therefore says nothing about this file. The `[old] -> [new]` shape,
    /// which is what a reader and a test look for, is preserved exactly.
    fn set_state(&mut self, cx: &mut CallCtx<'_, '_>, next: HandshakeState) {
        let Some(sx) = self.state.as_mut() else {
            return;
        };
        let old = sx.state;
        if old == next {
            return;
        }
        sx.state = next;
        if let Some(tracer) = cx.tracer_mut() {
            trc_cf!(
                tracer,
                TraceFilter::SocksProxy,
                self.base.sockindex().as_i32(),
                "[{}] -> [{}]",
                old.name(),
                next.name()
            );
        }
    }

    /// `socks_failed()` (`lib/socks.c:192-200`): enter
    /// [`HandshakeState::Failed`], remember why, and hand the reason back.
    fn failed(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        presult: CURLproxycode,
    ) -> CURLproxycode {
        self.set_state(cx, HandshakeState::Failed);
        if let Some(sx) = self.state.as_mut() {
            sx.presult = presult;
        }
        presult
    }

    /// `if(presult) return socks_failed(sx, cf, data, presult);` -- the guard
    /// that follows almost every call in the two state machines.
    ///
    /// Written as a combinator over the outcome rather than repeated by hand at
    /// every call site, and it does exactly what the C's two lines do: a
    /// failure enters [`HandshakeState::Failed`] and carries the same code
    /// outward. The three call sites that DO NOT wrap their failure this way --
    /// `socks_recv`'s own error paths (`:245`, `:251`) and the terminal
    /// `SOCKS_ST_FAILED` arm -- do not use it, which is why the wrapper is
    /// explicit at each site instead of being folded into the helpers.
    fn or_failed<T>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        outcome: Result<T, CURLproxycode>,
    ) -> Result<T, CURLproxycode> {
        match outcome {
            Ok(value) => Ok(value),
            Err(presult) => Err(self.failed(cx, presult)),
        }
    }

    /// One filter-attributed trace line, `CURL_TRC_CF(data, cf, ...)`.
    ///
    /// Takes the text already built, because [`trc_cf`] needs a literal format
    /// string and the lines this module emits are built in [`msg`] or from a
    /// state name. The level test still happens before anything is written --
    /// the macro checks `is_filter_verbose` -- but the text is built first,
    /// which is the one place this module spends work the C would not. That is
    /// acceptable and deliberate: AAP section 0.1.1 makes performance an
    /// explicit non-goal, and having every frozen string in one testable place
    /// is worth more than a suppressed allocation.
    fn trace(&self, cx: &mut CallCtx<'_, '_>, line: &str) {
        let sockindex = self.base.sockindex().as_i32();
        if let Some(tracer) = cx.tracer_mut() {
            trc_cf!(tracer, TraceFilter::SocksProxy, sockindex, "{}", line);
        }
    }

    /// `failf(data, ...)`: the line an application reads back through
    /// `CURLOPT_ERRORBUFFER`.
    ///
    /// Deliberately NOT level-guarded, matching `#define failf Curl_failf`
    /// (`lib/curl_trc.h:62`): the gate is `verbose || errorbuffer` and lives
    /// inside the tracer, so a failure still reaches the buffer when tracing is
    /// off.
    fn fail_line(cx: &mut CallCtx<'_, '_>, line: &str) {
        if let Some(tracer) = cx.tracer_mut() {
            failf!(tracer, "{}", line);
        }
    }

    /// `infof(data, ...)`.
    fn info_line(cx: &mut CallCtx<'_, '_>, line: &str) {
        if let Some(tracer) = cx.tracer_mut() {
            infof!(tracer, "{}", line);
        }
    }
}

// The two I/O helpers, and the one blocking read the GSS-API path needs

impl SocksProxy {
    /// `socks_flush()` (`lib/socks.c:202-224`): drain the buffer into the
    /// filter below.
    ///
    /// Returns whether the buffer emptied. A would-block leaves the remainder
    /// buffered and reports `Ok(false)`, which is the C's `CURLPX_OK` with
    /// `*done` still false -- the state machine then returns and the pollset
    /// asks for writability.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::SendConnect`] for any real send failure, after
    /// entering [`HandshakeState::Failed`]. This is one of the two helpers that
    /// calls `socks_failed` itself (`:219`), so a caller must not wrap it
    /// again.
    fn flush(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<bool, CURLproxycode> {
        loop {
            // Both borrows are of DIFFERENT fields, so one destructuring here
            // lets the buffer and the filter below be held at once. The C gets
            // this for free because `sx` and `cf->next` are unrelated pointers.
            let Self { base, state, .. } = self;
            let Some(sx) = state.as_mut() else {
                return Ok(true);
            };
            if sx.iobuf.is_empty() {
                return Ok(true);
            }
            let outcome = match base.next_mut() {
                Some(next) => sx.iobuf.pass(|bytes| {
                    next.send(cx, bytes, false).map_err(CURLcode::from)
                }),
                // `Curl_cf_send_bufq(cf->next, ...)` with no filter below is
                // `!cf`, which the C reports as a bad argument.
                None => Err(CURLcode::BadFunctionArgument),
            };
            match outcome {
                Ok(_) => {}
                // `if(result == CURLE_AGAIN) return CURLPX_OK;` with `*done`
                // left false.
                Err(CURLcode::Again) => return Ok(false),
                Err(code) => {
                    Self::fail_line(cx, &msg::send_failed(code.message()));
                    return Err(self.failed(cx, CURLproxycode::SendConnect));
                }
            }
        }
    }

    /// `socks_recv()` (`lib/socks.c:226-258`): fill the buffer to at least
    /// `min_bytes`.
    ///
    /// Returns whether that many bytes are available. A would-block reports
    /// `Ok(false)` with whatever arrived still buffered, so the next pass
    /// resumes rather than restarting -- which is what makes a response split
    /// across two reads work.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::RecvConnect`] for a receive failure or for a proxy that
    /// closed the connection mid-response. **This helper does NOT call
    /// `socks_failed`** (`:245`, `:251` return the code directly), so its
    /// callers wrap it -- the asymmetry against [`Self::flush`] is in the C and
    /// is preserved.
    fn recv(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        min_bytes: usize,
    ) -> Result<bool, CURLproxycode> {
        loop {
            let Self { base, state, .. } = self;
            let Some(sx) = state.as_mut() else {
                return Ok(false);
            };
            let buffered = sx.iobuf.len();
            if buffered >= min_bytes {
                return Ok(true);
            }
            let wanted = min_bytes - buffered;
            let outcome = match base.next_mut() {
                Some(next) => sx.iobuf.sipn(wanted, |buf| {
                    next.recv(cx, buf).map_err(CURLcode::from)
                }),
                None => Err(CURLcode::BadFunctionArgument),
            };
            match outcome {
                // `else if(!nread) { ... break; }` -- end of stream. The break
                // is not an error by itself: it is only a failure when the
                // buffer is still short, which the test below decides.
                Ok(0) => {
                    let short = sx.iobuf.len() < min_bytes;
                    if short {
                        Self::fail_line(cx, msg::RECV_CLOSED);
                        return Err(CURLproxycode::RecvConnect);
                    }
                    return Ok(true);
                }
                Ok(_) => {}
                Err(CURLcode::Again) => return Ok(false),
                Err(code) => {
                    Self::fail_line(cx, &msg::recv_failed(code.message()));
                    return Err(CURLproxycode::RecvConnect);
                }
            }
        }
    }

    /// The socket the chain below is using -- `Curl_conn_cf_get_socket(cf,
    /// data)` (`lib/socks.c:1321`), which asks `CF_QUERY_SOCKET` down the
    /// chain.
    ///
    /// [`CURL_SOCKET_BAD`] when nothing answered, which is what the C's own
    /// query helper substitutes for an unanswered question.
    fn socket(&mut self, cx: &mut CallCtx<'_, '_>) -> Socket {
        match self.base.next_mut() {
            Some(next) => match next.query(cx, CfQuery::Socket) {
                Ok(CfQueryValue::Socket(sock)) => sock,
                _ => CURL_SOCKET_BAD,
            },
            None => CURL_SOCKET_BAD,
        }
    }

    /// `Curl_blockread_all()` (`lib/socks.c:118-155`), declared for the
    /// GSS-API path alone (`lib/socks.h:35-39`).
    ///
    /// Fills `buf` completely or fails. The C's own header calls this *"STUPID
    /// BLOCKING behavior. Only used by the SOCKS GSSAPI functions."*, and it is
    /// reproduced rather than improved because `Curl_SOCKS5_gssapi_negotiate`
    /// is written against exactly this contract: it reads a fixed-size header,
    /// then a token of the length that header announced, as two sequential
    /// reads with no state machine between them.
    ///
    /// `crate::proxy::socks_gss` is the only intended caller, which is why this
    /// is the one method of this filter that its sibling module reaches.
    ///
    /// # Why this one is `async` when the filter is not
    ///
    /// The C blocks on `SOCKET_READABLE(sock, timeout_ms)` before every read.
    /// The successor of that call, [`socket_readable`], is asynchronous, so the
    /// wait is expressed with `.await` and the timeout comes from the injected
    /// [`SocksConn::time_left_ms`] rather than from a global clock. There is no
    /// blocking-mode toggle to reproduce: nothing here changes the socket's
    /// non-blocking flag, because the readiness wait and a would-block retry do
    /// between them exactly what the C's blocking read did.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::OperationTimedout`] when the deadline has already passed
    ///   or the socket does not become readable within it.
    /// * [`CURLcode::RecvError`] on end of stream with the buffer still short
    ///   -- `if(!nread) return CURLE_RECV_ERROR;` (`:148-149`).
    /// * [`CURLcode::BadFunctionArgument`] with no filter below, which is the
    ///   C's unreachable `!cf` case.
    /// * Whatever the filter below reports for a real receive failure.
    #[allow(dead_code)] // consumer: crate::proxy::socks_gss
    pub(crate) async fn blockread_all(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        let mut filled = 0_usize;
        let sock = self.socket(cx);
        loop {
            // `timediff_t timeout_ms = Curl_timeleft_ms(data);`
            let mut timeout_ms = self.seams.conn.time_left_ms();
            if timeout_ms < 0 {
                // `we already got the timeout`
                return Err(Error::with_context(
                    CURLcode::OperationTimedout,
                    "SOCKS blocking read: the transfer deadline has passed",
                ));
            }
            if timeout_ms == 0 {
                // `if(!timeout_ms) timeout_ms = TIMEDIFF_T_MAX;` -- zero means
                // no limit, so the wait is unbounded rather than instantaneous.
                timeout_ms = TIMEDIFF_T_MAX;
            }
            // `if(SOCKET_READABLE(sock, timeout_ms) <= 0) return
            //  CURLE_OPERATION_TIMEDOUT;` -- both the zero (timed out) and the
            //  negative (select failed) answers become the same code, as in the
            //  C.
            match socket_readable(sock, timeout_ms).await {
                Ok(ready) if ready > 0 => {}
                _ => {
                    return Err(Error::with_context(
                        CURLcode::OperationTimedout,
                        "SOCKS blocking read: the socket never became \
                         readable",
                    ))
                }
            }

            let remaining = buf.len() - filled;
            let nread = match self.base.next_mut() {
                Some(next) => match next.recv(cx, &mut buf[filled..]) {
                    Ok(nread) => nread,
                    // `if(result == CURLE_AGAIN) continue;`
                    Err(error) if error.code() == CURLcode::Again => continue,
                    Err(error) => return Err(error),
                },
                None => {
                    return Err(Error::with_context(
                        CURLcode::BadFunctionArgument,
                        "SOCKS blocking read: no filter below",
                    ))
                }
            };

            // `if(blen == nread) { *pnread += nread; return CURLE_OK; }`
            if nread == remaining {
                return Ok(filled + nread);
            }
            // `if(!nread) return CURLE_RECV_ERROR;` -- end of stream short of
            // the amount asked for.
            if nread == 0 {
                return Err(Error::with_context(
                    CURLcode::RecvError,
                    "SOCKS blocking read: the proxy closed the connection",
                ));
            }
            filled += nread;
        }
    }
}

// SOCKS4 and SOCKS4a
//
// Request format (`lib/socks.c:503-508`):
//
//     +----+----+----+----+----+----+----+----+----+----+....+----+
//     | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
//     +----+----+----+----+----+----+----+----+----+----+....+----+
//        1    1      2              4             variable      1

impl SocksProxy {
    /// `socks4_req_add_hd()` (`lib/socks.c:260-277`): version, command and the
    /// destination port.
    ///
    /// The port is written MOST significant byte first, taken from the low
    /// sixteen bits of the `int` member -- `(port >> 8) & 0xff` then
    /// `port & 0xff`.
    fn socks4_add_header(&mut self) -> Result<(), CURLproxycode> {
        let Some(sx) = self.state.as_mut() else {
            return Err(CURLproxycode::SendRequest);
        };
        let port = sx.remote_port;
        let head = [
            SOCKS4_VERSION,
            CMD_CONNECT,
            u8::try_from((port >> 8) & 0xff).unwrap_or_default(),
            u8::try_from(port & 0xff).unwrap_or_default(),
        ];
        sx.write(&head)
    }

    /// `socks4_req_add_user()` (`lib/socks.c:279-308`): the user id field.
    ///
    /// The user id is written **with its trailing NUL**, so a set user costs
    /// `len + 1` bytes; an unset one is a single zero byte, which is the empty
    /// user id the protocol requires rather than an omission.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::LongUser`] past [`MAX_FIELD_LEN`]. SOCKS4 sets no limit
    /// on this field, and the C explains the cap as a defence: SOCKS5 limits it
    /// to 255 and *"it seems likely that a longer field is either a mistake or
    /// malicious input"*.
    fn socks4_add_user(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        let Some(sx) = self.state.as_mut() else {
            return Err(CURLproxycode::SendRequest);
        };
        match sx.proxy_user.clone() {
            Some(user) => {
                if user.len() > MAX_FIELD_LEN {
                    Self::fail_line(cx, msg::LONG_SOCKS_USERNAME);
                    return Err(CURLproxycode::LongUser);
                }
                // `Curl_bufq_cwrite(&sx->iobuf, sx->proxy_user, plen + 1, ..)`
                // -- the C counts the terminator into the length it writes.
                let mut field = user.into_bytes();
                field.push(0);
                sx.write(&field)
            }
            // `unsigned char b = 0;` -- the empty user id.
            None => sx.write(&[0]),
        }
    }

    /// `socks4_resolving()` (`lib/socks.c:310-380`): resolve the destination
    /// locally and append its address.
    ///
    /// Reports `Ok(false)` while the lookup is still running, which is the
    /// non-blocking resolve the C traces and returns from.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::ResolveHost`] when the lookup failed or produced no
    /// IPv4 address at all, and [`CURLproxycode::SendRequest`] if the four
    /// bytes could not be buffered.
    fn socks4_resolving(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<bool, CURLproxycode> {
        let (hostname, port, ip_version, starting) = {
            let Some(sx) = self.state.as_mut() else {
                return Err(CURLproxycode::ResolveHost);
            };
            let starting = sx.start_resolving;
            if starting {
                // `sx->start_resolving = FALSE;` before the call, so a second
                // pass polls rather than starting the lookup again.
                sx.start_resolving = false;
                debug_assert!(
                    !sx.hostname.is_empty(),
                    "DEBUGASSERT(sx->hostname && *sx->hostname)"
                );
            }
            (
                sx.hostname.clone(),
                sx.remote_port,
                self.seams.conn.ip_version(),
                starting,
            )
        };

        let progress = if starting {
            self.seams.resolver.start(&hostname, port, ip_version)
        } else {
            self.seams.resolver.check()
        };

        // The four outcomes, and what each means on each of the two passes.
        // Every arm below is one branch of `lib/socks.c:321-345`.
        let dns = match (starting, progress) {
            (_, ResolveProgress::Ready(dns)) => dns,
            // `if(result == CURLE_AGAIN) { CURL_TRC_CF(..); return CURLPX_OK;
            // }` -- traced on the pass that STARTED the lookup, not on every
            // poll.
            (true, ResolveProgress::Again) => {
                let line = format!("SOCKS4 non-blocking resolve of {hostname}");
                self.trace(cx, &line);
                return Ok(false);
            }
            // `else if(result) return CURLPX_RESOLVE_HOST;` -- no diagnosis, so
            // whatever the resolver already reported stands.
            (true, ResolveProgress::Failed(_)) => {
                return Err(CURLproxycode::ResolveHost)
            }
            // `if(!result && !dns) return CURLPX_OK;` -- the polling pass waits
            // silently.
            (false, ResolveProgress::NoEntry) => return Ok(false),
            // Everything else reaches `if(result || !dns)`: success with no
            // entry on the starting pass, and a code or a missing entry on the
            // polling pass.
            (_, _) => {
                Self::fail_line(cx, &msg::socks4_resolve_failed(&hostname));
                return Err(CURLproxycode::ResolveHost);
            }
        };

        // `while(hp && (hp->ai_family != AF_INET)) hp = hp->ai_next;` -- the
        // FIRST IPv4 address in resolver order, and nothing else will do.
        let found = dns
            .addrs
            .iter()
            .find(|addr| addr.family() == AddressFamily::Inet)
            .and_then(|addr| match addr.socket_addr() {
                Some(std::net::SocketAddr::V4(v4)) => {
                    Some((addr.printable_address(), v4.ip().octets()))
                }
                _ => None,
            });

        let Some((printable, octets)) = found else {
            Self::fail_line(cx, &msg::socks4_unsupported(&hostname));
            return Err(CURLproxycode::ResolveHost);
        };

        let line =
            format!("SOCKS4 connect to IPv4 {printable} (locally resolved)");
        self.trace(cx, &line);

        let Some(sx) = self.state.as_mut() else {
            return Err(CURLproxycode::SendRequest);
        };
        sx.write(&octets)?;
        Ok(true)
    }

    /// `socks4_check_resp()` (`lib/socks.c:382-457`): read the eight-byte
    /// reply.
    ///
    /// Response format (`:398-401`): `VN | CD | DSTPORT(2) | DSTIP(4)`, where
    /// `VN` must be zero -- **not 4**, which is the request's version.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::RecvConnect`] for a short reply,
    /// [`CURLproxycode::BadVersion`] for a non-zero version byte, and one of
    /// [`CURLproxycode::RequestFailed`], [`CURLproxycode::Identd`],
    /// [`CURLproxycode::IdentdDiffer`] or [`CURLproxycode::UnknownFail`] for
    /// reply codes 91, 92, 93 and anything else.
    fn socks4_check_response(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        let (resp, socks4a) = {
            let Some(sx) = self.state.as_mut() else {
                return Err(CURLproxycode::RecvConnect);
            };
            let socks4a = sx.socks4a;
            let peeked = sx.iobuf.peek().and_then(|bytes| {
                <[u8; SOCKS4_RESPONSE_LEN]>::try_from(
                    bytes.get(..SOCKS4_RESPONSE_LEN)?,
                )
                .ok()
            });
            let Some(resp) = peeked else {
                Self::fail_line(cx, msg::SOCKS4_REPLY_INCOMPLETE);
                return Err(CURLproxycode::RecvConnect);
            };
            (resp, socks4a)
        };

        // `if(resp[0]) { ... }` -- the reply version must be zero.
        if resp[0] != 0 {
            Self::fail_line(cx, msg::SOCKS4_BAD_VERSION);
            return Err(CURLproxycode::BadVersion);
        }

        match resp[1] {
            SOCKS4_GRANTED => {
                // `CURL_TRC_CF(data, cf, "SOCKS4%s request granted.",
                //  sx->socks4a ? "a" : "")`.
                let line = format!(
                    "SOCKS4{} request granted.",
                    if socks4a { "a" } else { "" }
                );
                self.trace(cx, &line);
                if let Some(sx) = self.state.as_mut() {
                    sx.iobuf.skip(SOCKS4_RESPONSE_LEN);
                }
                Ok(())
            }
            SOCKS4_REJECTED => {
                Self::fail_line(cx, &msg::socks4_rejected(&resp));
                Err(CURLproxycode::RequestFailed)
            }
            SOCKS4_NO_IDENTD => {
                Self::fail_line(cx, &msg::socks4_no_identd(&resp));
                Err(CURLproxycode::Identd)
            }
            SOCKS4_IDENTD_MISMATCH => {
                Self::fail_line(cx, &msg::socks4_identd_mismatch(&resp));
                Err(CURLproxycode::IdentdDiffer)
            }
            _ => {
                Self::fail_line(cx, &msg::socks4_unknown(&resp));
                Err(CURLproxycode::UnknownFail)
            }
        }
    }

    /// `socks4_connect()` (`lib/socks.c:470-588`): the SOCKS4 and SOCKS4a state
    /// machine.
    ///
    /// The C's `switch` with `FALLTHROUGH()` and `goto process_state` is a
    /// `loop` over an exhaustive `match`; each fallthrough is a `continue` onto
    /// the state the preceding arm just set, which is the same arm the C would
    /// have fallen into.
    ///
    /// # Errors
    ///
    /// Whatever the step reached reports, always after entering
    /// [`HandshakeState::Failed`] so a later pass answers the same way.
    fn socks4_connect(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        loop {
            let Some(current) = self.state.as_ref().map(SocksState::state)
            else {
                return Err(CURLproxycode::SendRequest);
            };
            match current {
                HandshakeState::Init => {
                    if let Some(sx) = self.state.as_mut() {
                        sx.version = SOCKS4_VERSION;
                    }
                    self.set_state(cx, HandshakeState::Socks4Start);
                    // `FALLTHROUGH();`
                    continue;
                }

                HandshakeState::Socks4Start => {
                    self.socks4_start(cx)?;
                    continue;
                }

                HandshakeState::Socks4Resolving => {
                    let outcome = self.socks4_resolving(cx);
                    let done = self.or_failed(cx, outcome)?;
                    if !done {
                        return Ok(());
                    }
                    // `/* append user */` -- for the LOCALLY resolving path the
                    // user id follows the address, which is why this call is
                    // here and not in the start arm.
                    let outcome = self.socks4_add_user(cx);
                    self.or_failed(cx, outcome)?;
                    self.set_state(cx, HandshakeState::Socks4Send);
                    continue;
                }

                HandshakeState::Socks4Send => {
                    // `socks_flush` fails through `socks_failed` itself, so its
                    // error is returned unwrapped.
                    if !self.flush(cx)? {
                        return Ok(());
                    }
                    self.set_state(cx, HandshakeState::Socks4Recv);
                    continue;
                }

                HandshakeState::Socks4Recv => {
                    let outcome = self.recv(cx, SOCKS4_RESPONSE_LEN);
                    let done = self.or_failed(cx, outcome)?;
                    if !done {
                        return Ok(());
                    }
                    let outcome = self.socks4_check_response(cx);
                    self.or_failed(cx, outcome)?;
                    self.set_state(cx, HandshakeState::Success);
                    continue;
                }

                HandshakeState::Success => return Ok(()),

                HandshakeState::Failed => {
                    // `DEBUGASSERT(sx->presult); return sx->presult;`
                    let presult = self
                        .state
                        .as_ref()
                        .map_or(CURLproxycode::SendRequest, |sx| sx.presult);
                    debug_assert!(
                        !presult.is_ok(),
                        "SOCKS_ST_FAILED without a reason"
                    );
                    return Err(presult);
                }

                // The C's `default: DEBUGASSERT(0);` -- every SOCKS5 state is
                // unreachable here, and reaching one is a programming error
                // rather than a protocol failure. Written out one by one so the
                // `match` is exhaustive and a new state cannot be absorbed
                // silently.
                HandshakeState::Socks5Start
                | HandshakeState::Socks5Req0Send
                | HandshakeState::Socks5Resp0Recv
                | HandshakeState::Socks5GssapiInit
                | HandshakeState::Socks5AuthInit
                | HandshakeState::Socks5AuthSend
                | HandshakeState::Socks5AuthRecv
                | HandshakeState::Socks5Req1Init
                | HandshakeState::Socks5Resolving
                | HandshakeState::Socks5Req1Send
                | HandshakeState::Socks5Resp1Recv => {
                    debug_assert!(false, "{current} is not a SOCKS4 state");
                    return Err(self.failed(cx, CURLproxycode::SendRequest));
                }
            }
        }
    }

    /// The `SOCKS4_ST_START` arm (`lib/socks.c:486-539`), which composes the
    /// whole request for SOCKS4a and everything but the address for SOCKS4.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::LongHostname`] past [`MAX_FIELD_LEN`], plus whatever
    /// the header and user-id writers report. Every failure has already entered
    /// [`HandshakeState::Failed`].
    fn socks4_start(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        let socks4a = self.seams.conn.proxy_type()
            == crate::conn::ProxyType::Socks4a.as_i32();
        let (hostname, port) = {
            let Some(sx) = self.state.as_mut() else {
                return Err(CURLproxycode::SendRequest);
            };
            // `Curl_bufq_reset(&sx->iobuf);` -- SOCKS4 restarts its buffer
            // here. The SOCKS5 machine deliberately does not; see
            // `socks5_connect`.
            sx.iobuf.reset();
            sx.start_resolving = false;
            sx.socks4a = socks4a;
            sx.resolve_local = !socks4a;
            sx.presult = CURLproxycode::Ok;
            (sx.hostname.clone(), sx.remote_port)
        };

        // `cf->conn->ip_version = CURL_IPRESOLVE_V4;` -- *"SOCKS4 can only do
        // IPv4, insist!"*. A write to the CONNECTION, so it outlives this pass
        // and governs the lookup the resolving arm starts.
        self.seams.conn.set_ip_version(IpVersion::V4);

        let line = format!(
            "SOCKS4{} communication to{} {}:{}",
            if socks4a { "a" } else { "" },
            if self.seams.conn.is_http_proxy() {
                " HTTP proxy"
            } else {
                ""
            },
            hostname,
            port
        );
        self.trace(cx, &line);

        let outcome = self.socks4_add_header();
        self.or_failed(cx, outcome)?;

        let resolve_local =
            self.state.as_ref().is_some_and(|sx| sx.resolve_local);
        if !resolve_local {
            // SOCKS4a: an invalid address, then the user id, then the hostname.
            // `hlen` counts the terminator, so the cap applies to the name plus
            // its NUL exactly as the C computes it.
            let hlen = hostname.len() + 1;
            if hlen > MAX_FIELD_LEN {
                Self::fail_line(cx, msg::SOCKS4_LONG_HOSTNAME);
                return Err(self.failed(cx, CURLproxycode::LongHostname));
            }
            let outcome = self
                .state
                .as_mut()
                .map_or(Err(CURLproxycode::SendRequest), |sx| {
                    sx.write(&SOCKS4A_PLACEHOLDER_ADDRESS)
                });
            self.or_failed(cx, outcome)?;
            let outcome = self.socks4_add_user(cx);
            self.or_failed(cx, outcome)?;
            let outcome = self.state.as_mut().map_or(
                Err(CURLproxycode::SendRequest),
                |sx| {
                    let mut field = hostname.into_bytes();
                    field.push(0);
                    sx.write(&field)
                },
            );
            self.or_failed(cx, outcome)?;
            // `/* request complete */`
            self.set_state(cx, HandshakeState::Socks4Send);
            return Ok(());
        }

        if let Some(sx) = self.state.as_mut() {
            sx.start_resolving = true;
        }
        self.set_state(cx, HandshakeState::Socks4Resolving);
        Ok(())
    }
}

// SOCKS5 -- RFC 1928, with the RFC 1929 username/password sub-negotiation

impl SocksProxy {
    /// `socks5_req0_init()` (`lib/socks.c:590-635`): the method-selection
    /// request.
    ///
    /// Wire form is `VER | NMETHODS | METHODS...`, and **the method order is
    /// frozen**: 0 (none), then 1 (GSS-API), then 2 (username/password). The C
    /// builds it by appending, so the order follows the source and a server
    /// choosing by position sees the same offer it would from curl.
    ///
    /// GSS-API is offered only where the build has it, which here is the
    /// default-off `negotiate` feature -- the counterpart of the C's
    /// `#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)`.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::LongHostname`] when the proxy must resolve a name
    /// longer than [`MAX_FIELD_LEN`] (RFC 1928 chapter 5), and
    /// [`CURLproxycode::SendRequest`] if the request could not be buffered.
    fn socks5_req0_init(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        // `const unsigned char auth = data->set.socks5auth;`
        let auth = self.seams.conn.socks5_auth();

        let (resolve_local, hostname_len) = {
            let Some(sx) = self.state.as_ref() else {
                return Err(CURLproxycode::SendRequest);
            };
            (sx.resolve_local, sx.hostname.len())
        };

        // `if(!sx->resolve_local && strlen(sx->hostname) > 255)` -- the cap
        // applies ONLY when the proxy is the one doing the lookup, because only
        // then does the name travel in a packet with a one-byte length.
        if !resolve_local && hostname_len > MAX_FIELD_LEN {
            Self::fail_line(cx, msg::SOCKS5_LONG_HOSTNAME);
            return Err(CURLproxycode::LongHostname);
        }

        // `if(auth & ~(CURLAUTH_BASIC | CURLAUTH_GSSAPI))` -- reported and then
        // ignored, so an unsupported bit never changes what is offered.
        if auth & !(SOCKS5_AUTH_BASIC | SOCKS5_AUTH_GSSAPI) != 0 {
            Self::info_line(cx, &msg::unsupported_socks5_auth(auth));
        }
        // `if(!(auth & CURLAUTH_BASIC)) sx->proxy_user = NULL;` -- withholding
        // BASIC disables username/password for the rest of the handshake, which
        // is why the context's own copy is cleared rather than the test being
        // repeated later.
        if auth & SOCKS5_AUTH_BASIC == 0 {
            if let Some(sx) = self.state.as_mut() {
                sx.proxy_user = None;
            }
        }

        let has_user = self
            .state
            .as_ref()
            .is_some_and(|sx| sx.proxy_user.is_some());

        // `req[0] = 5; nauths = 1; req[1 + nauths] = 0;` -- no-auth is always
        // offered and always first. The order below IS the wire order: 0, then
        // 1, then 2.
        let mut methods = vec![SOCKS5_METHOD_NONE];
        if self.seams.can_negotiate_gssapi() && auth & SOCKS5_AUTH_GSSAPI != 0 {
            methods.push(SOCKS5_METHOD_GSSAPI);
        }
        if has_user {
            methods.push(SOCKS5_METHOD_USERPASS);
        }

        let mut req = Vec::with_capacity(2 + methods.len());
        req.push(SOCKS5_VERSION);
        // `req[1] = nauths;` -- written last in the C, because the count is not
        // known until the methods have been appended.
        req.push(u8::try_from(methods.len()).unwrap_or(u8::MAX));
        req.extend_from_slice(&methods);

        let Some(sx) = self.state.as_mut() else {
            return Err(CURLproxycode::SendRequest);
        };
        sx.write(&req)
    }

    /// `socks5_check_resp0()` (`lib/socks.c:637-686`): the method the server
    /// chose, and the state that follows from it.
    ///
    /// **This function sets the next state itself**, which is why its caller
    /// re-enters the machine immediately rather than falling through to a fixed
    /// successor (`:1089-1090`).
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::RecvConnect`] for a short reply,
    /// [`CURLproxycode::BadVersion`] for a version other than 5,
    /// [`CURLproxycode::GssapiPermsg`] or [`CURLproxycode::NoAuth`] for a
    /// method the configuration withholds, [`CURLproxycode::NoAuth`] for reply
    /// 255 and [`CURLproxycode::UnknownMode`] for anything else.
    fn socks5_check_resp0(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        let resp = {
            let Some(sx) = self.state.as_mut() else {
                return Err(CURLproxycode::RecvConnect);
            };
            let peeked = sx.iobuf.peek().and_then(|bytes| {
                <[u8; SOCKS5_SHORT_RESPONSE_LEN]>::try_from(
                    bytes.get(..SOCKS5_SHORT_RESPONSE_LEN)?,
                )
                .ok()
            });
            let Some(resp) = peeked else {
                Self::fail_line(cx, msg::SOCKS5_REPLY0_INCOMPLETE);
                return Err(CURLproxycode::RecvConnect);
            };
            resp
        };

        if resp[0] != SOCKS5_VERSION {
            Self::fail_line(cx, msg::SOCKS5_BAD_VERSION0);
            return Err(CURLproxycode::BadVersion);
        }

        // `auth_mode = resp[1]; Curl_bufq_skip(&sx->iobuf, 2);` -- the two
        // bytes go before the method is acted on, so no arm below has to
        // remember to consume them.
        let auth_mode = resp[1];
        if let Some(sx) = self.state.as_mut() {
            sx.iobuf.skip(SOCKS5_SHORT_RESPONSE_LEN);
        }

        let auth = self.seams.conn.socks5_auth();
        match auth_mode {
            SOCKS5_METHOD_NONE => {
                // `/* DONE! No authentication needed. Send request. */`
                self.set_state(cx, HandshakeState::Socks5Req1Init);
                Ok(())
            }
            SOCKS5_METHOD_GSSAPI => {
                if auth & SOCKS5_AUTH_GSSAPI != 0 {
                    self.set_state(cx, HandshakeState::Socks5GssapiInit);
                    return Ok(());
                }
                Self::fail_line(cx, msg::SOCKS5_GSSAPI_NOT_ENABLED);
                Err(CURLproxycode::GssapiPermsg)
            }
            SOCKS5_METHOD_USERPASS => {
                // `/* regular name + password authentication */`
                if auth & SOCKS5_AUTH_BASIC != 0 {
                    self.set_state(cx, HandshakeState::Socks5AuthInit);
                    return Ok(());
                }
                Self::fail_line(cx, msg::SOCKS5_BASIC_NOT_ENABLED);
                Err(CURLproxycode::NoAuth)
            }
            SOCKS5_METHOD_NONE_ACCEPTABLE => {
                Self::fail_line(cx, msg::SOCKS5_NO_ACCEPTABLE_METHOD);
                Err(CURLproxycode::NoAuth)
            }
            _ => {
                Self::fail_line(cx, msg::SOCKS5_UNKNOWN_MODE);
                Err(CURLproxycode::UnknownMode)
            }
        }
    }

    /// `socks5_auth_init()` (`lib/socks.c:688-739`): the RFC 1929
    /// username/password sub-negotiation request.
    ///
    /// Wire form is `VER | ULEN | UNAME | PLEN | PASSWD`, where **`VER` is 1**
    /// -- the sub-negotiation carries its own version, not the SOCKS5 version.
    ///
    /// The two lengths are computed only when BOTH credentials are present
    /// (`:697`), so a user with no password sends `ULEN = 0` and `PLEN = 0`
    /// rather than the user's name with an empty password. That is what the C
    /// does and a server's answer to it is the server's business.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::LongUser`] or [`CURLproxycode::LongPasswd`] past
    /// [`MAX_FIELD_LEN`], which is the width of the single length byte.
    fn socks5_auth_init(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        let (user, password) = {
            let Some(sx) = self.state.as_ref() else {
                return Err(CURLproxycode::SendRequest);
            };
            match (sx.proxy_user.clone(), sx.proxy_password.clone()) {
                // `if(sx->proxy_user && sx->proxy_password)` -- both, or
                // neither counts.
                (Some(user), Some(password)) => (user, password),
                _ => (String::new(), String::new()),
            }
        };

        if user.len() > MAX_FIELD_LEN {
            Self::fail_line(cx, msg::EXCESSIVE_USERNAME);
            return Err(CURLproxycode::LongUser);
        }
        if password.len() > MAX_FIELD_LEN {
            Self::fail_line(cx, msg::EXCESSIVE_PASSWORD);
            return Err(CURLproxycode::LongPasswd);
        }

        let ulen = u8::try_from(user.len()).unwrap_or_default();
        let plen = u8::try_from(password.len()).unwrap_or_default();

        {
            let Some(sx) = self.state.as_mut() else {
                return Err(CURLproxycode::SendRequest);
            };
            // The C writes this in four calls -- two bytes, the name, one byte,
            // the password -- and each `if(ulen)` guard exists only because
            // `Curl_bufq_cwrite` of zero bytes would be a pointless call. The
            // bytes on the wire are the same either way.
            sx.write(&[SOCKS5_AUTH_SUBNEGOTIATION_VERSION, ulen])?;
            if ulen > 0 {
                sx.write(user.as_bytes())?;
            }
            sx.write(&[plen])?;
            if plen > 0 {
                sx.write(password.as_bytes())?;
            }
        }

        self.set_state(cx, HandshakeState::Socks5AuthSend);
        Ok(())
    }

    /// `socks5_check_auth_resp()` (`lib/socks.c:741-764`): the
    /// sub-negotiation's two-byte answer.
    ///
    /// **The version byte is ignored** -- `/* ignore the first (VER) byte */`
    /// -- and only the status decides. Both bytes are still printed in the
    /// failure line, and the two bytes are consumed ONLY on success, which is
    /// the order the C writes and is left alone.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::RecvConnect`] for a short reply and
    /// [`CURLproxycode::UserRejected`] for a non-zero status.
    fn socks5_check_auth_resp(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        let Some(sx) = self.state.as_mut() else {
            return Err(CURLproxycode::RecvConnect);
        };
        let peeked = sx.iobuf.peek().and_then(|bytes| {
            <[u8; SOCKS5_SHORT_RESPONSE_LEN]>::try_from(
                bytes.get(..SOCKS5_SHORT_RESPONSE_LEN)?,
            )
            .ok()
        });
        let Some(resp) = peeked else {
            Self::fail_line(cx, msg::SOCKS5_AUTH_REPLY_INCOMPLETE);
            return Err(CURLproxycode::RecvConnect);
        };

        if resp[1] != 0 {
            Self::fail_line(cx, &msg::user_rejected(resp[0], resp[1]));
            return Err(CURLproxycode::UserRejected);
        }
        sx.iobuf.skip(SOCKS5_SHORT_RESPONSE_LEN);
        Ok(())
    }

    /// `socks5_req1_init()` (`lib/socks.c:766-829`): the `CONNECT` request.
    ///
    /// Wire form is `VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT`. When this
    /// end resolves the destination, **only the first three bytes are written
    /// here** and the rest is appended by [`Self::socks5_resolving`]; when the
    /// PROXY resolves it, the whole request is composed at once.
    ///
    /// The address-type byte decides whether a length byte follows:
    /// `hdlen = (desttype == 3) ? 5 : 4`, so a domain name carries its length
    /// and an IP address does not.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::BadAddressType`] when the destination is marked as a
    /// numeric IPv6 address but does not parse as one, and
    /// [`CURLproxycode::SendRequest`] if the request could not be buffered.
    fn socks5_req1_init(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        let (resolve_local, hostname, port) = {
            let Some(sx) = self.state.as_ref() else {
                return Err(CURLproxycode::SendRequest);
            };
            (sx.resolve_local, sx.hostname.clone(), sx.remote_port)
        };

        let head = [SOCKS5_VERSION, CMD_CONNECT, 0];
        if resolve_local {
            // `/* rest of request is added after resolving */`
            let Some(sx) = self.state.as_mut() else {
                return Err(CURLproxycode::SendRequest);
            };
            return sx.write(&head);
        }

        // `/* remote resolving, send what type+addr/string to resolve */`
        let (desttype, destination) = if self.seams.conn.is_ipv6_ip() {
            // `if(curlx_inet_pton(AF_INET6, sx->hostname, ipbuf) != 1) return
            //  CURLPX_BAD_ADDRESS_TYPE;`
            match pton6(hostname.as_bytes()) {
                Some(octets) => (ATYP_IPV6, octets.to_vec()),
                None => return Err(CURLproxycode::BadAddressType),
            }
        } else if let Some(octets) = pton4(hostname.as_bytes()) {
            (ATYP_IPV4, octets.to_vec())
        } else {
            // `destlen = (unsigned char)hostname_len; /* one byte length */`
            (ATYP_DOMAIN, hostname.as_bytes().to_vec())
        };

        let destlen = u8::try_from(destination.len()).unwrap_or_default();
        {
            let Some(sx) = self.state.as_mut() else {
                return Err(CURLproxycode::SendRequest);
            };
            // `hdlen = (desttype == 3) ? 5 : 4;` -- *"no length byte for ip
            // addresses"*.
            if desttype == ATYP_DOMAIN {
                sx.write(&[head[0], head[1], head[2], desttype, destlen])?;
            } else {
                sx.write(&[head[0], head[1], head[2], desttype])?;
            }
            sx.write(&destination)?;
            // `/* PORT MSB+LSB */`
            sx.write(&Self::port_bytes(port))?;
        }

        let line =
            format!("SOCKS5 connect to {hostname}:{port} (remotely resolved)");
        self.trace(cx, &line);
        Ok(())
    }

    /// The two port bytes, most significant first.
    ///
    /// `req[0] = (port >> 8) & 0xff; req[1] = port & 0xff;` -- written by hand
    /// in three places in the C. `u16::to_be_bytes` is the same two bytes, and
    /// no `htons` or byte-order crate is involved.
    fn port_bytes(port: i32) -> [u8; 2] {
        u16::try_from(port & 0xffff)
            .unwrap_or_default()
            .to_be_bytes()
    }

    /// `socks5_resolving()` (`lib/socks.c:831-945`): resolve locally, then
    /// append the address type, the address and the port.
    ///
    /// The address family decides both the type byte and the trace line's
    /// shape: an IPv6 address is printed **in square brackets** and an IPv4 one
    /// is not.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::ResolveHost`] when the lookup failed or produced
    /// nothing usable, and [`CURLproxycode::SendRequest`] if the bytes could
    /// not be buffered.
    fn socks5_resolving(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<bool, CURLproxycode> {
        let (hostname, port, ip_version, starting) = {
            let Some(sx) = self.state.as_mut() else {
                return Err(CURLproxycode::ResolveHost);
            };
            let starting = sx.start_resolving;
            if starting {
                sx.start_resolving = false;
                debug_assert!(
                    !sx.hostname.is_empty(),
                    "DEBUGASSERT(sx->hostname && *sx->hostname)"
                );
            }
            (
                sx.hostname.clone(),
                sx.remote_port,
                self.seams.conn.ip_version(),
                starting,
            )
        };

        let progress = if starting {
            self.seams.resolver.start(&hostname, port, ip_version)
        } else {
            self.seams.resolver.check()
        };

        // The same four-way reading as the SOCKS4 path; see there.
        let dns = match (starting, progress) {
            (_, ResolveProgress::Ready(dns)) => dns,
            (true, ResolveProgress::Again) => {
                let line = format!("SOCKS5 non-blocking resolve of {hostname}");
                self.trace(cx, &line);
                return Ok(false);
            }
            (true, ResolveProgress::Failed(_)) => {
                return Err(CURLproxycode::ResolveHost)
            }
            (false, ResolveProgress::NoEntry) => return Ok(false),
            (_, _) => {
                Self::fail_line(cx, &msg::socks5_resolve_failed(&hostname));
                return Err(CURLproxycode::ResolveHost);
            }
        };

        // `if(data->set.ipver != CURL_IPRESOLVE_WHATEVER) { while(hp &&
        //  (hp->ai_family != wanted_family)) hp = hp->ai_next; }` -- what the
        //  APPLICATION asked for, which is not `conn->ip_version`.
        let wanted = match self.seams.conn.requested_ip_version() {
            IpVersion::Whatever => None,
            IpVersion::V4 => Some(AddressFamily::Inet),
            IpVersion::V6 => Some(AddressFamily::Inet6),
        };
        let chosen = dns.addrs.iter().find(|addr| match wanted {
            Some(family) => addr.family() == family,
            None => true,
        });

        // `if(!hp) { failf("Failed to resolve ..."); }` -- the SECOND place
        // this line is emitted, reached when the scan consumed the whole list.
        let Some(addr) = chosen else {
            Self::fail_line(cx, &msg::socks5_resolve_failed(&hostname));
            return Err(CURLproxycode::ResolveHost);
        };

        // `Curl_printable_address(hp, dest, sizeof(dest))` into a
        // `char dest[MAX_IPADR_LEN]`, which is empty for a family that is
        // neither IPv4 nor IPv6 -- and that emptiness is what the C's
        // `!destination` test then reports.
        let printable = addr.printable_address();
        let described = match addr.socket_addr() {
            Some(std::net::SocketAddr::V4(v4)) => {
                let line = format!(
                    "SOCKS5 connect to {printable}:{port} (locally resolved)"
                );
                Some((ATYP_IPV4, v4.ip().octets().to_vec(), line))
            }
            Some(std::net::SocketAddr::V6(v6)) => {
                // The IPv6 line brackets the address; the IPv4 one does not.
                let line = format!(
                    "SOCKS5 connect to [{printable}]:{port} (locally resolved)"
                );
                Some((ATYP_IPV6, v6.ip().octets().to_vec(), line))
            }
            None => None,
        };

        let Some((desttype, destination, line)) = described else {
            Self::fail_line(cx, &msg::socks5_unsupported(&printable));
            return Err(CURLproxycode::ResolveHost);
        };
        self.trace(cx, &line);

        let Some(sx) = self.state.as_mut() else {
            return Err(CURLproxycode::SendRequest);
        };
        sx.write(&[desttype])?;
        sx.write(&destination)?;
        sx.write(&Self::port_bytes(port))?;
        Ok(true)
    }

    /// `socks5_recv_resp1()` (`lib/socks.c:947-1039`): the `CONNECT` reply,
    /// read to its end.
    ///
    /// Reply form is `VER | REP | RSV | ATYP | BND.ADDR | BND.PORT`, and
    /// `BND.ADDR` is **variable length**: the reply *"MUST be read until the
    /// end to avoid errors at subsequent protocol level"* (`:967-969`). Leaving
    /// a byte of it buffered desynchronises everything the tunnel carries
    /// afterwards, which is why the length is recomputed from `ATYP` and a
    /// second receive follows.
    ///
    /// This step does its own receiving -- the C calls `socks_recv` twice from
    /// inside it -- so its caller does not read before calling it.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::BadVersion`], [`CURLproxycode::BadAddressType`],
    /// [`CURLproxycode::RecvConnect`], or the RFC 1928 section 6 code the reply
    /// carried.
    fn socks5_recv_resp1(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<bool, CURLproxycode> {
        if !self.recv(cx, SOCKS5_MIN_RESPONSE_LEN)? {
            return Ok(false);
        }

        let (head, hostname) = {
            let Some(sx) = self.state.as_mut() else {
                return Err(CURLproxycode::RecvConnect);
            };
            let hostname = sx.hostname.clone();
            let peeked = sx.iobuf.peek().and_then(|bytes| {
                <[u8; SOCKS5_MIN_RESPONSE_LEN]>::try_from(
                    bytes.get(..SOCKS5_MIN_RESPONSE_LEN)?,
                )
                .ok()
            });
            let Some(head) = peeked else {
                Self::fail_line(cx, msg::SOCKS5_RESPONSE_INCOMPLETE);
                return Err(CURLproxycode::RecvConnect);
            };
            (head, hostname)
        };

        if head[0] != SOCKS5_VERSION {
            Self::fail_line(cx, msg::SOCKS5_BAD_VERSION1);
            return Err(CURLproxycode::BadVersion);
        }
        if head[1] != 0 {
            // `/* Anything besides 0 is an error */`
            let code = head[1];
            Self::fail_line(cx, &msg::socks5_connect_failed(&hostname, code));
            return Err(Self::rfc1928_reply(code));
        }

        // `/* Calculate real packet size */` -- from `ATYP`, and the
        // domain-name form reads its own length byte out of the reply.
        let resp_len = match head[3] {
            ATYP_IPV4 => 4 + 4 + 2,
            ATYP_DOMAIN => 4 + 1 + usize::from(head[4]) + 2,
            ATYP_IPV6 => 4 + 16 + 2,
            _ => {
                Self::fail_line(cx, msg::SOCKS5_BAD_ADDRESS_TYPE);
                return Err(CURLproxycode::BadAddressType);
            }
        };

        // `/* receive the rest of the response */`
        if !self.recv(cx, resp_len)? {
            return Ok(false);
        }
        let buffered = self.state.as_ref().map_or(0, |sx| sx.iobuf.len());
        if buffered < resp_len {
            Self::fail_line(cx, msg::SOCKS5_RESPONSE_INCOMPLETE);
            return Err(CURLproxycode::RecvConnect);
        }
        // `/* got it all */`
        //
        // The C leaves the reply in the buffer, and so does this: the buffer is
        // released whole when the handshake succeeds, so nothing downstream can
        // read a stray byte of it.
        Ok(true)
    }

    /// The RFC 1928 section 6 reply code, as a [`CURLproxycode`]
    /// (`lib/socks.c:987-1006`).
    ///
    /// Anything from 9 upward is unassigned by the RFC and stays at
    /// [`CURLproxycode::ReplyUnassigned`], which is the `if(code < 9)` bound
    /// the C tests before indexing its table.
    fn rfc1928_reply(code: u8) -> CURLproxycode {
        match RFC1928_REPLIES.get(usize::from(code)) {
            Some(mapped) => *mapped,
            None => CURLproxycode::ReplyUnassigned,
        }
    }

    /// `socks5_connect()` (`lib/socks.c:1045-1196`): the SOCKS5 and SOCKS5h
    /// state machine.
    ///
    /// # Errors
    ///
    /// Whatever the step reached reports, always after entering
    /// [`HandshakeState::Failed`].
    fn socks5_connect(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        loop {
            let Some(current) = self.state.as_ref().map(SocksState::state)
            else {
                return Err(CURLproxycode::SendRequest);
            };
            match current {
                HandshakeState::Init => {
                    // `sx->resolve_local = (cf->conn->socks_proxy.proxytype ==
                    //  CURLPROXY_SOCKS5);` -- so `socks5h`
                    //  (`CURLPROXY_SOCKS5_HOSTNAME`) hands the NAME to the
                    //  proxy and `socks5` resolves it here. The distinction is
                    //  command-line visible and is not normalised away.
                    let resolve_local = self.seams.conn.proxy_type()
                        == crate::conn::ProxyType::Socks5.as_i32();
                    if let Some(sx) = self.state.as_mut() {
                        sx.version = SOCKS5_VERSION;
                        sx.resolve_local = resolve_local;
                    }
                    self.set_state(cx, HandshakeState::Socks5Start);
                    continue;
                }

                HandshakeState::Socks5Start => {
                    // Note what is NOT here: the SOCKS4 machine resets the
                    // buffer in its own start arm and this one does not. The
                    // asymmetry is in the C and is preserved.
                    if self.seams.conn.is_http_proxy() {
                        let (host, port) = self
                            .state
                            .as_ref()
                            .map_or((String::new(), 0), |sx| {
                                (sx.hostname.clone(), sx.remote_port)
                            });
                        let line = format!(
                            "SOCKS5: connecting to HTTP proxy {host} port \
                             {port}"
                        );
                        self.trace(cx, &line);
                    }
                    let outcome = self.socks5_req0_init(cx);
                    self.or_failed(cx, outcome)?;
                    self.set_state(cx, HandshakeState::Socks5Req0Send);
                    continue;
                }

                HandshakeState::Socks5Req0Send => {
                    if !self.flush(cx)? {
                        return Ok(());
                    }
                    // `/* done sending! */`
                    self.set_state(cx, HandshakeState::Socks5Resp0Recv);
                    continue;
                }

                HandshakeState::Socks5Resp0Recv => {
                    let outcome = self.recv(cx, SOCKS5_SHORT_RESPONSE_LEN);
                    let done = self.or_failed(cx, outcome)?;
                    if !done {
                        return Ok(());
                    }
                    let outcome = self.socks5_check_resp0(cx);
                    self.or_failed(cx, outcome)?;
                    // `/* socks5_check_resp0() sets next socks state */` --
                    // `goto process_state`, so the machine re-enters at
                    // whichever state that was.
                    continue;
                }

                HandshakeState::Socks5GssapiInit => {
                    self.socks5_gssapi_init(cx)?;
                    continue;
                }

                HandshakeState::Socks5AuthInit => {
                    let outcome = self.socks5_auth_init(cx);
                    self.or_failed(cx, outcome)?;
                    self.set_state(cx, HandshakeState::Socks5AuthSend);
                    continue;
                }

                HandshakeState::Socks5AuthSend => {
                    if !self.flush(cx)? {
                        return Ok(());
                    }
                    self.set_state(cx, HandshakeState::Socks5AuthRecv);
                    continue;
                }

                HandshakeState::Socks5AuthRecv => {
                    let outcome = self.recv(cx, SOCKS5_SHORT_RESPONSE_LEN);
                    let done = self.or_failed(cx, outcome)?;
                    if !done {
                        return Ok(());
                    }
                    let outcome = self.socks5_check_auth_resp(cx);
                    self.or_failed(cx, outcome)?;
                    // `/* Everything is good so far, user was authenticated!
                    // */`
                    self.set_state(cx, HandshakeState::Socks5Req1Init);
                    continue;
                }

                HandshakeState::Socks5Req1Init => {
                    let outcome = self.socks5_req1_init(cx);
                    self.or_failed(cx, outcome)?;
                    let resolve_local =
                        self.state.as_ref().is_some_and(|sx| sx.resolve_local);
                    if !resolve_local {
                        // `/* we do not resolve, request is complete */`
                        self.set_state(cx, HandshakeState::Socks5Req1Send);
                        continue;
                    }
                    if let Some(sx) = self.state.as_mut() {
                        sx.start_resolving = true;
                    }
                    self.set_state(cx, HandshakeState::Socks5Resolving);
                    continue;
                }

                HandshakeState::Socks5Resolving => {
                    let outcome = self.socks5_resolving(cx);
                    let done = self.or_failed(cx, outcome)?;
                    if !done {
                        return Ok(());
                    }
                    self.set_state(cx, HandshakeState::Socks5Req1Send);
                    continue;
                }

                HandshakeState::Socks5Req1Send => {
                    if !self.flush(cx)? {
                        return Ok(());
                    }
                    // `if(cf->conn->socks5_gssapi_enctype) { failf(..); return
                    //  CURLPX_GSSAPI_PROTECTION; }` -- deliberate in curl
                    //  8.19.0-DEV: per-message protection is negotiable and
                    //  unimplemented, so selecting it fails HERE, after the
                    //  request has gone out, rather than sending unprotected
                    //  bytes afterwards.
                    if self.seams.conn.socks5_gssapi_enctype() != 0 {
                        Self::fail_line(cx, msg::SOCKS5_GSSAPI_PROTECTION);
                        return Err(CURLproxycode::GssapiProtection);
                    }
                    self.set_state(cx, HandshakeState::Socks5Resp1Recv);
                    continue;
                }

                HandshakeState::Socks5Resp1Recv => {
                    let outcome = self.socks5_recv_resp1(cx);
                    let done = self.or_failed(cx, outcome)?;
                    if !done {
                        return Ok(());
                    }
                    self.trace(cx, "SOCKS5 request granted.");
                    self.set_state(cx, HandshakeState::Success);
                    continue;
                }

                HandshakeState::Success => return Ok(()),

                HandshakeState::Failed => {
                    let presult = self
                        .state
                        .as_ref()
                        .map_or(CURLproxycode::SendRequest, |sx| sx.presult);
                    debug_assert!(
                        !presult.is_ok(),
                        "SOCKS_ST_FAILED without a reason"
                    );
                    return Err(presult);
                }

                // The C's `default: DEBUGASSERT(0);` -- the SOCKS4 states.
                HandshakeState::Socks4Start
                | HandshakeState::Socks4Resolving
                | HandshakeState::Socks4Send
                | HandshakeState::Socks4Recv => {
                    debug_assert!(false, "{current} is not a SOCKS5 state");
                    return Err(self.failed(cx, CURLproxycode::SendRequest));
                }
            }
        }
    }

    /// The `SOCKS5_ST_GSSAPI_INIT` arm (`lib/socks.c:1092-1107`), whose two
    /// halves are selected by whether the build has GSS-API at all.
    ///
    /// With the default-off `negotiate` feature the negotiation runs and, on
    /// success, the machine moves to `SOCKS5_ST_REQ1_INIT`; without it the
    /// method the server chose cannot be honoured and the handshake fails.
    ///
    /// # Errors
    ///
    /// [`CURLproxycode::Gssapi`] when the negotiation itself failed, or
    /// [`CURLproxycode::GssapiPermsg`] in a build without GSS-API.
    /// The `#else` half (`:1102-1106`) is reached when this build has no
    /// GSS-API, and also when it has one but no negotiator was injected. Its
    /// message says *"not supported"* where the enabled build's refusal at
    /// `:669` says *"not enabled"*; the two are different lines and are kept
    /// apart. Unlike the enabled half, that refusal goes through `socks_failed`
    /// (`:1105`).
    fn socks5_gssapi_init(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Result<(), CURLproxycode> {
        // `CURLcode result = Curl_SOCKS5_gssapi_negotiate(cf, data);` -- the
        // exchange itself belongs to `crate::proxy::socks_gss`, reached through
        // the injected negotiator, which drives this filter's own
        // `blockread_all` for its reads.
        #[cfg(feature = "negotiate")]
        if let Some(gssapi) = self.seams.gssapi.clone() {
            return match gssapi.negotiate() {
                Ok(()) => {
                    self.set_state(cx, HandshakeState::Socks5Req1Init);
                    Ok(())
                }
                Err(_) => {
                    Self::fail_line(cx, msg::SOCKS5_GSSAPI_FAILED);
                    Err(CURLproxycode::Gssapi)
                }
            };
        }

        Self::fail_line(cx, msg::SOCKS5_GSSAPI_UNSUPPORTED);
        Err(self.failed(cx, CURLproxycode::GssapiPermsg))
    }
}

// The destination the handshake asks for -- two chains that differ on purpose

impl SocksProxy {
    /// The destination hostname (`lib/socks.c:1244-1250`).
    ///
    /// ```text
    /// httpproxy      ? http_proxy.host.name
    /// : conn_to_host ? conn_to_host.name
    /// : SECONDARY    ? secondaryhostname
    /// :                host.name
    /// ```
    ///
    /// **Read the order against [`Self::destination_port`]'s.** This chain
    /// tests `conn_to_host` BEFORE the secondary socket and the port chain
    /// tests the secondary socket first, which is not an oversight: the C's
    /// comment is *"for the secondary socket (FTP), use the 'connect to host'
    /// but ignore the 'connect to port' (use the secondary port)"*. So an FTP
    /// data connection through `--connect-to` goes to the redirected HOST on
    /// the server's chosen PORT. The two chains are deliberately not unified,
    /// and neither is unified with `Curl_http_proxy_get_destination`, which has
    /// a third order of its own.
    fn destination_host(&self) -> String {
        let conn = &self.seams.conn;
        if conn.is_http_proxy() {
            return conn.http_proxy_host().unwrap_or_default();
        }
        if let Some(host) = conn.connect_to_host() {
            return host;
        }
        if self.base.sockindex() == SocketIndex::Secondary {
            if let Some(host) = conn.secondary_host() {
                return host;
            }
            // `conn->secondaryhostname` is a fixed-size array in the C and is
            // therefore never NULL, but it is empty until an FTP data
            // connection has been set up. An absent name here is that
            // emptiness, and the C would send it verbatim.
            return String::new();
        }
        conn.host_name()
    }

    /// The destination port (`lib/socks.c:1251-1255`).
    ///
    /// ```text
    /// httpproxy      ? http_proxy.port
    /// : SECONDARY    ? secondary_port
    /// : conn_to_port ? conn_to_port
    /// :                remote_port
    /// ```
    ///
    /// See [`Self::destination_host`] for why the two orders differ. Returned
    /// as an `i32` because `sx->remote_port` is an `int` and the verbose
    /// success line prints it after the handshake.
    fn destination_port(&self) -> i32 {
        let conn = &self.seams.conn;
        if conn.is_http_proxy() {
            return i32::from(conn.http_proxy_port());
        }
        if self.base.sockindex() == SocketIndex::Secondary {
            return i32::from(conn.secondary_port());
        }
        if let Some(port) = conn.connect_to_port() {
            return i32::from(port);
        }
        i32::from(conn.remote_port())
    }

    /// The verbose success line (`lib/socks.c:1287-1302`).
    ///
    /// Emitted only while tracing, and only after the handshake has succeeded.
    /// The long form needs the addresses from the filter below; when that query
    /// goes unanswered the C falls back to the short form rather than printing
    /// blanks, and so does this.
    fn report_opened(&mut self, cx: &mut CallCtx<'_, '_>) {
        let verbose = cx.tracer_mut().is_some_and(|tracer| tracer.is_verbose());
        if !verbose {
            return;
        }
        let second = self.base.sockindex() == SocketIndex::Secondary;
        let (host, port) =
            self.state.as_ref().map_or((String::new(), 0), |sx| {
                (sx.hostname.clone(), sx.remote_port)
            });
        // `Curl_conn_cf_get_ip_info(cf->next, data, &is_ipv6, &ipquad)`.
        let quad = match self.base.next_mut() {
            Some(next) => match next.query(cx, CfQuery::IpInfo) {
                Ok(CfQueryValue::IpInfo { quad, .. }) => Some(quad),
                _ => None,
            },
            None => None,
        };
        let line = match quad {
            Some(IpQuadruple {
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                ..
            }) => msg::opened(
                second,
                &local_ip,
                local_port,
                &host,
                port,
                &remote_ip,
                remote_port,
            ),
            None => msg::opened_short(second),
        };
        Self::info_line(cx, &line);
    }
}

// The twelve operations -- five overridden, seven left at the C's defaults

impl ConnFilter for SocksProxy {
    /// The `name` member: `"SOCKS"` (`lib/socks.c:1385`).
    fn trace_name(&self) -> &'static str {
        SOCKS_FILTER_NAME
    }

    /// The `flags` member: `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY`
    /// (`lib/socks.c:1386`).
    ///
    /// `CF_TYPE_IP_CONNECT` because a connected SOCKS filter means the chain
    /// has reached the network, and `CF_TYPE_PROXY` because it is one. The C's
    /// `log_level` member, `0` at `:1387`, has no counterpart: the level lives
    /// in `crate::trace::TraceConfig` and the identity in
    /// [`ConnFilter::trace_filter`].
    fn cf_type(&self) -> CfType {
        CF_TYPE_IP_CONNECT | CF_TYPE_PROXY
    }

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    /// `socks_proxy_cf_destroy` (`lib/socks.c:1349-1354`): release the context.
    ///
    /// Does NOT chain, and must not: the caller has already severed the link
    /// and owns the rest of the chain.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        let _ = cx;
        self.free_state();
    }

    /// `socks_proxy_cf_connect` (`lib/socks.c:1215-1309`): drive the handshake.
    ///
    /// The order of the first three steps is load-bearing. An already connected
    /// filter answers at once; otherwise **the filter below is connected
    /// FIRST**, because there is no point negotiating with a proxy that has no
    /// socket; and only then is the context allocated, which is why its
    /// allocation is also where the destination is decided.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Proxy`] for any handshake failure, with the specific
    /// [`CURLproxycode`] published through [`SocksConn::set_proxy_code`] so
    /// that `CURLINFO_PROXY_ERROR` can report it -- `result = CURLE_PROXY;
    /// data->info.pxcode = pxresult;` (`:1280-1281`).
    ///
    /// [`CURLcode::CouldntConnect`] when this filter was installed for a proxy
    /// type that is not a SOCKS one (`:1273-1276`).
    ///
    /// Whatever the filter below reports for its own connect.
    ///
    /// The C also writes `*done = cf->connected` on its way out of an error,
    /// which a `Result` cannot carry. Nothing is lost: `cf->connected` is set
    /// only at the very end of a SUCCESSFUL handshake, so the value it would
    /// have written is always false, and the C's own caller tests the code
    /// before it reads `*done` (`lib/cfilters.c`, `if(result || !*done)`).
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if self.base.is_connected() {
            return Ok(true);
        }

        // `result = cf->next->cft->do_connect(cf->next, data, done); if(result
        //  || !*done) return result;`
        match self.base.next_mut() {
            Some(next) => {
                if !next.connect(cx)? {
                    return Ok(false);
                }
            }
            None => {
                return Err(Error::with_context(
                    CURLcode::CouldntConnect,
                    "SOCKS: no filter below to connect through",
                ))
            }
        }

        // `if(!sx) { cf->ctx = sx = curlx_calloc(1, sizeof(*sx)); ... }` -- the
        // context, and with it the destination, is settled once per connect
        // cycle rather than re-derived on every pass.
        if self.state.is_none() {
            let host = self.destination_host();
            let port = self.destination_port();
            self.state = Some(SocksState::new(
                host,
                port,
                self.seams.conn.proxy_user(),
                self.seams.conn.proxy_password(),
            ));
        }

        let proxy_type = self.seams.conn.proxy_type();
        let outcome = if proxy_type == crate::conn::ProxyType::Socks5.as_i32()
            || proxy_type == crate::conn::ProxyType::Socks5Hostname.as_i32()
        {
            self.socks5_connect(cx)
        } else if proxy_type == crate::conn::ProxyType::Socks4.as_i32()
            || proxy_type == crate::conn::ProxyType::Socks4a.as_i32()
        {
            self.socks4_connect(cx)
        } else {
            // `default: failf(data, "unknown proxytype option given"); result =
            //  CURLE_COULDNT_CONNECT;` -- NOT a proxy code, so `pxcode` is left
            //  alone and `CURLINFO_PROXY_ERROR` keeps whatever it held.
            Self::fail_line(cx, msg::UNKNOWN_PROXYTYPE);
            return Err(Error::with_context(
                CURLcode::CouldntConnect,
                msg::UNKNOWN_PROXYTYPE,
            ));
        };

        if let Err(pxresult) = outcome {
            self.seams.conn.set_proxy_code(pxresult);
            return Err(Error::with_context(
                CURLcode::Proxy,
                format!("SOCKS handshake failed ({})", pxresult.as_i32()),
            ));
        }

        // `else if(sx->state != SOCKS_ST_SUCCESS) goto out;` -- the handshake
        // made progress without finishing, so this pass reports "not done" and
        // keeps every byte it has buffered.
        if self.state.as_ref().map(SocksState::state)
            != Some(HandshakeState::Success)
        {
            return Ok(self.base.is_connected());
        }

        self.report_opened(cx);
        // `socks_proxy_cf_free(cf);` -- ON SUCCESS. The handshake is over, so
        // the buffer and every credential copy in it go now rather than living
        // as long as the connection.
        self.free_state();
        self.base.set_connected(true);
        Ok(true)
    }

    /// `socks_proxy_cf_close` (`lib/socks.c:1339-1347`).
    ///
    /// Chains, and must: the C calls only the head of the chain and relies on
    /// each filter to pass the close down. The context goes first so that a
    /// half-finished handshake cannot be resumed against a closed socket, and
    /// the filter stays installed and may be connected again.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        debug_assert!(
            self.base.has_next(),
            "DEBUGASSERT(cf->next) -- a SOCKS filter is never the bottom"
        );
        self.base.set_connected(false);
        self.free_state();
        if let Some(next) = self.base.next_mut() {
            next.close(cx);
        }
    }

    /// `socks_cf_adjust_pollset` (`lib/socks.c:1311-1337`): what this filter is
    /// waiting for.
    ///
    /// Only while UNCONNECTED and only once the context exists -- *"If we are
    /// not connected, the filter below is and has nothing to wait on, we
    /// determine what to wait for."* The four states with a buffered request
    /// wait to WRITE; **every other state waits to read**, which is the C's
    /// `default` arm and includes the two resolving states and the terminal
    /// ones.
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset`] reports, which is
    /// [`CURLcode::BadFunctionArgument`] for a socket that is not a descriptor.
    fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        if self.base.is_connected() {
            return Ok(());
        }
        let Some(state) = self.state.as_ref().map(SocksState::state) else {
            return Ok(());
        };
        let sock = self.socket(cx);
        let sending = state.is_sending();
        // `CURL_TRC_CF(data, cf, "adjust pollset out (%d)", sx->state)`, whose
        // `%d` is the state's position in the C enumeration.
        let line = format!(
            "adjust pollset {} ({})",
            if sending { "out" } else { "in" },
            state.as_index()
        );
        self.trace(cx, &line);
        let outcome = if sending {
            ps.set_out_only(sock, cx.tracer_mut())
        } else {
            ps.set_in_only(sock, cx.tracer_mut())
        };
        outcome.map_err(Error::from)
    }

    /// `socks_cf_query` (`lib/socks.c:1356-1382`).
    ///
    /// `CF_QUERY_HOST_PORT` reports **the DESTINATION** -- the host and port
    /// the tunnel leads to -- and not the proxy's own. That is the opposite of
    /// `Curl_cf_http_proxy_query`, which reports the proxy, and the two must
    /// not be unified: a caller asking a SOCKS chain who it is talking to means
    /// the far end. Before the context exists there is no answer, so the
    /// question goes down the chain.
    ///
    /// `CF_QUERY_ALPN_NEGOTIATED` answers NOTHING rather than declining, which
    /// is a real answer: a SOCKS tunnel negotiates no application protocol, and
    /// letting the question fall through would report whatever the socket
    /// filter below happened to say.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] at the bottom of the chain, which every
    /// caller reads as "use the default" rather than as a failure.
    fn query(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        match query {
            CfQuery::HostPort => {
                if let Some(sx) = self.state.as_ref() {
                    return Ok(CfQueryValue::HostPort {
                        host: sx.hostname.clone(),
                        // `*pres1 = sx->remote_port` is an `int` that only ever
                        // holds a port; the query's own type says so.
                        port: u16::try_from(sx.remote_port & 0xffff)
                            .unwrap_or_default(),
                    });
                }
                // `break;` -- falls through to the chain.
            }
            CfQuery::AlpnNegotiated => {
                return Ok(CfQueryValue::AlpnNegotiated(None))
            }
            _ => {}
        }
        match self.base.next_mut() {
            Some(next) => next.query(cx, query),
            None => Err(Error::new(CURLcode::UnknownOption)),
        }
    }
}

/// `Curl_cf_socks_proxy_insert_after(cf_at, data)` (`lib/socks.c:1402-1413`):
/// build the filter and link it in below the one at `index`.
///
/// The C creates it with a NULL context and inserts it; both halves are here,
/// and the context stays [`None`] until the first connect just as it does
/// there.
///
/// The filter is built UNATTACHED -- no connection identity -- because
/// `Curl_cf_create` leaves `cf->conn` NULL and `conn_cf_insert_after` stamps it
/// from the insertion point (`lib/cfilters.c:371-379`). Insertion here does the
/// same, so handing a connection identity in beforehand would both duplicate
/// that step and trip the debug assertion that guards against inserting a
/// filter twice. [`SocksProxy::new`] still takes one, for the factory path that
/// builds a link and stamps it itself.
///
/// # Errors
///
/// Whatever [`FilterChain::insert_after`] reports, which is
/// [`CURLcode::BadFunctionArgument`] when no filter is installed at `index`.
/// The C cannot fail this way because it is handed the filter itself rather
/// than a position; `Curl_cf_create`'s own failure, `CURLE_OUT_OF_MEMORY`, has
/// no counterpart because the box is a fixed-size allocation.
#[allow(dead_code)] // consumer: crate::conn, which builds the chain
pub(crate) fn insert_after(
    chain: &mut FilterChain,
    cx: &mut CallCtx<'_, '_>,
    index: usize,
    seams: SocksSeams,
) -> CurlResult<()> {
    let filter = SocksProxy::new(chain.sockindex(), None, seams);
    chain.insert_after(cx, index, link(filter))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::tests::{
        events, new_log, EventLog, InMemory, TransportHandle,
    };
    use crate::conn::filters::{link, ConnId};
    use crate::conn::ProxyType;
    use crate::dns::{DnsEntry, ResolvedAddr};
    use crate::proxy::SOCKS5_AUTH_DEFAULT;
    use crate::trace::{TraceConfig, TraceLevel, Tracer, WriterSink};
    // `conn::filters`'s transport is consumed, not rebuilt, and its
    // `TransportHandle` IS an `Arc<SyncCell<_>>`. The seams below are
    // `Send + Sync`, so a `RefCell` will not serve; this is the same
    // interior mutability `conn/happy_eyeballs.rs` uses for the same
    // reason.
    use crate::util::sync_cell::SyncCell;
    use crate::util::timeval::{CurlTime, TestClock};
    use std::net::{
        Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
    };

    // -- the injected seams, as test doubles -----------------------------

    /// Everything a [`SocksConn`] answers, all settable.
    ///
    /// Behind a [`SyncCell`] because the trait takes `&self` -- a connection
    /// fact is read while the filter is borrowed mutably, exactly as the C
    /// reads through `cf->conn` -- and because the trait is `Send + Sync`.
    #[derive(Debug)]
    struct ConnFacts {
        proxy_type: i32,
        proxy_user: Option<String>,
        proxy_password: Option<String>,
        socks5_auth: u8,
        http_proxy: bool,
        http_proxy_host: Option<String>,
        http_proxy_port: u16,
        connect_to_host: Option<String>,
        connect_to_port: Option<u16>,
        secondary_host: Option<String>,
        secondary_port: u16,
        host_name: String,
        remote_port: u16,
        ip_version: IpVersion,
        requested_ip_version: IpVersion,
        ipv6_ip: bool,
        gssapi_enctype: i32,
        proxy_code: Option<CURLproxycode>,
        time_left_ms: TimeDiff,
    }

    impl Default for ConnFacts {
        /// A plain SOCKS5 proxy to `example.com:80` with no credentials.
        fn default() -> Self {
            Self {
                proxy_type: ProxyType::Socks5.as_i32(),
                proxy_user: None,
                proxy_password: None,
                // The frozen default of `lib/url.c:388`.
                socks5_auth: SOCKS5_AUTH_DEFAULT,
                http_proxy: false,
                http_proxy_host: None,
                http_proxy_port: 0,
                connect_to_host: None,
                connect_to_port: None,
                secondary_host: None,
                secondary_port: 0,
                host_name: "example.com".to_string(),
                remote_port: 80,
                ip_version: IpVersion::Whatever,
                requested_ip_version: IpVersion::Whatever,
                ipv6_ip: false,
                gssapi_enctype: 0,
                proxy_code: None,
                time_left_ms: 0,
            }
        }
    }

    #[derive(Debug)]
    struct TestConn {
        facts: SyncCell<ConnFacts>,
    }

    impl TestConn {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                facts: SyncCell::new(ConnFacts::default()),
            })
        }

        /// Mutates the facts in place, as a caller's configuration would.
        fn set(&self, body: impl FnOnce(&mut ConnFacts)) {
            body(&mut self.facts.borrow_mut());
        }

        /// What `CURLINFO_PROXY_ERROR` would report.
        fn proxy_code(&self) -> Option<CURLproxycode> {
            self.facts.borrow().proxy_code
        }
    }

    impl SocksConn for TestConn {
        fn proxy_type(&self) -> i32 {
            self.facts.borrow().proxy_type
        }

        fn proxy_user(&self) -> Option<String> {
            self.facts.borrow().proxy_user.clone()
        }

        fn proxy_password(&self) -> Option<String> {
            self.facts.borrow().proxy_password.clone()
        }

        fn socks5_auth(&self) -> u8 {
            self.facts.borrow().socks5_auth
        }

        fn is_http_proxy(&self) -> bool {
            self.facts.borrow().http_proxy
        }

        fn http_proxy_host(&self) -> Option<String> {
            self.facts.borrow().http_proxy_host.clone()
        }

        fn http_proxy_port(&self) -> u16 {
            self.facts.borrow().http_proxy_port
        }

        fn connect_to_host(&self) -> Option<String> {
            self.facts.borrow().connect_to_host.clone()
        }

        fn connect_to_port(&self) -> Option<u16> {
            self.facts.borrow().connect_to_port
        }

        fn secondary_host(&self) -> Option<String> {
            self.facts.borrow().secondary_host.clone()
        }

        fn secondary_port(&self) -> u16 {
            self.facts.borrow().secondary_port
        }

        fn host_name(&self) -> String {
            self.facts.borrow().host_name.clone()
        }

        fn remote_port(&self) -> u16 {
            self.facts.borrow().remote_port
        }

        fn ip_version(&self) -> IpVersion {
            self.facts.borrow().ip_version
        }

        fn set_ip_version(&self, ip_version: IpVersion) {
            self.facts.borrow_mut().ip_version = ip_version;
        }

        fn requested_ip_version(&self) -> IpVersion {
            self.facts.borrow().requested_ip_version
        }

        fn is_ipv6_ip(&self) -> bool {
            self.facts.borrow().ipv6_ip
        }

        fn socks5_gssapi_enctype(&self) -> i32 {
            self.facts.borrow().gssapi_enctype
        }

        fn set_proxy_code(&self, code: CURLproxycode) {
            self.facts.borrow_mut().proxy_code = Some(code);
        }

        fn time_left_ms(&self) -> TimeDiff {
            self.facts.borrow().time_left_ms
        }
    }

    /// A scripted [`DestinationResolver`]: each call consumes one answer.
    ///
    /// Scripted rather than computed so that a test states the exact sequence
    /// the C would have seen -- an immediate answer, a pending pass followed by
    /// an answer, or a failure -- and so that address ORDER, which decides
    /// which address reaches the wire, is under the test's control.
    #[derive(Debug)]
    struct TestResolver {
        script: SyncCell<Vec<ResolveProgress>>,
        starts: SyncCell<Vec<(String, i32, IpVersion)>>,
    }

    impl TestResolver {
        fn new(script: Vec<ResolveProgress>) -> Arc<Self> {
            Arc::new(Self {
                script: SyncCell::new(script),
                starts: SyncCell::new(Vec::new()),
            })
        }

        /// A resolver that answers with these addresses at once.
        fn ready(addrs: Vec<ResolvedAddr>) -> Arc<Self> {
            Self::new(vec![ResolveProgress::Ready(entry(addrs))])
        }

        fn next(&self) -> ResolveProgress {
            let mut script = self.script.borrow_mut();
            if script.is_empty() {
                return ResolveProgress::NoEntry;
            }
            script.remove(0)
        }
    }

    impl DestinationResolver for TestResolver {
        fn start(
            &self,
            hostname: &str,
            port: i32,
            ip_version: IpVersion,
        ) -> ResolveProgress {
            self.starts.borrow_mut().push((
                hostname.to_string(),
                port,
                ip_version,
            ));
            self.next()
        }

        fn check(&self) -> ResolveProgress {
            self.next()
        }
    }

    /// A GSS-API negotiator that answers as told.
    #[cfg(feature = "negotiate")]
    #[derive(Debug)]
    struct TestNegotiator {
        outcome: SyncCell<Option<CURLcode>>,
    }

    #[cfg(feature = "negotiate")]
    impl TestNegotiator {
        fn succeeding() -> Arc<Self> {
            Arc::new(Self {
                outcome: SyncCell::new(None),
            })
        }

        fn failing(code: CURLcode) -> Arc<Self> {
            Arc::new(Self {
                outcome: SyncCell::new(Some(code)),
            })
        }
    }

    #[cfg(feature = "negotiate")]
    impl GssapiNegotiator for TestNegotiator {
        fn negotiate(&self) -> CurlResult<()> {
            match *self.outcome.borrow() {
                Some(code) => Err(Error::new(code)),
                None => Ok(()),
            }
        }
    }

    // -- fixtures --------------------------------------------------------

    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1, 0))
    }

    /// One DNS answer, in the order given.
    fn entry(addrs: Vec<ResolvedAddr>) -> DnsEntryRef {
        Arc::new(DnsEntry {
            addrs,
            timestamp: CurlTime::ZERO,
            hostport: 80,
            hostname: "example.com".to_string(),
            hinfo: None,
        })
    }

    fn v4(octets: [u8; 4], port: u16) -> ResolvedAddr {
        ResolvedAddr::tcp(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)),
            None,
        )
    }

    fn v6(text: &str, port: u16) -> ResolvedAddr {
        let ip: Ipv6Addr = text.parse().expect("a literal IPv6 address");
        ResolvedAddr::tcp(
            SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
            None,
        )
    }

    /// A filter with an in-memory transport linked below it.
    ///
    /// The transport is `conn/filters.rs`'s own, which is what makes these
    /// tests byte-level: `state.output` is every byte the handshake sent and
    /// `state.input` is every byte it will be given.
    fn filter(
        conn: &Arc<TestConn>,
        resolver: &Arc<TestResolver>,
        sockindex: SocketIndex,
    ) -> (SocksProxy, TransportHandle, EventLog) {
        let log = new_log();
        let (transport, state) = InMemory::new("TRANSPORT", &log);
        let seams = SocksSeams::new(
            Arc::clone(conn) as Arc<dyn SocksConn>,
            Arc::clone(resolver) as Arc<dyn DestinationResolver>,
        );
        let mut proxy = SocksProxy::new(sockindex, Some(ConnId::new(7)), seams);
        proxy.base_mut().set_next(Some(link(transport)));
        (proxy, state, log)
    }

    /// The ordinary case: a primary-socket filter over a ready transport.
    fn primary(
        conn: &Arc<TestConn>,
        resolver: &Arc<TestResolver>,
    ) -> (SocksProxy, TransportHandle, EventLog) {
        filter(conn, resolver, SocketIndex::First)
    }

    /// Feeds `bytes` to the transport as though the proxy had sent them.
    fn feed(state: &TransportHandle, bytes: &[u8]) {
        state.borrow_mut().input.extend_from_slice(bytes);
    }

    /// Every byte the handshake has written so far.
    fn sent(state: &TransportHandle) -> Vec<u8> {
        state.borrow().output.clone()
    }

    /// Bytes the transport still holds, i.e. what a tunnelled protocol would
    /// read next.
    fn unread(state: &TransportHandle) -> Vec<u8> {
        state.borrow().input.clone()
    }

    /// Drives one connect pass with no tracing.
    fn connect(proxy: &mut SocksProxy, clock: &TestClock) -> CurlResult<bool> {
        let mut cx = CallCtx::new(clock);
        proxy.connect(&mut cx)
    }

    /// Drives one connect pass, returning the trace and error text as well.
    fn connect_traced(
        proxy: &mut SocksProxy,
        clock: &TestClock,
    ) -> (CurlResult<bool>, String) {
        let mut config = TraceConfig::new();
        config.set_filter_level(TraceFilter::SocksProxy, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let outcome = {
            let mut cx = CallCtx::new(clock).with_tracer(&mut tracer);
            proxy.connect(&mut cx)
        };
        let rendered =
            String::from_utf8(sink.into_inner()).expect("trace output is text");
        (outcome, rendered)
    }

    /// Drives one `adjust_pollset` with tracing on, returning what was
    /// rendered, so a frozen trace line can be asserted as bytes.
    fn pollset_traced(
        proxy: &mut SocksProxy,
        clock: &TestClock,
        sock: Socket,
    ) -> String {
        let mut config = TraceConfig::new();
        config.set_filter_level(TraceFilter::SocksProxy, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        {
            let mut cx = CallCtx::new(clock).with_tracer(&mut tracer);
            let mut ps = EasyPollset::new();
            proxy
                .adjust_pollset(&mut cx, &mut ps)
                .expect("a valid socket");
            assert!(!ps.is_empty(), "an unconnected filter registers {sock}");
        }
        String::from_utf8(sink.into_inner()).expect("trace output is text")
    }

    /// The proxy code a failed handshake published.
    fn failed_with(
        proxy: &mut SocksProxy,
        clock: &TestClock,
        conn: &Arc<TestConn>,
    ) -> (CURLproxycode, String) {
        let (outcome, rendered) = connect_traced(proxy, clock);
        let error = outcome.expect_err("the handshake must fail");
        assert_eq!(
            error.code(),
            CURLcode::Proxy,
            "a handshake failure is CURLE_PROXY: {}",
            error.message()
        );
        let code = conn.proxy_code().expect("pxcode must be published");
        (code, rendered)
    }

    // -- 1. the frozen registration ---------------------------------------

    /// `struct Curl_cftype Curl_cft_socks_proxy` (`lib/socks.c:1384-1400`).
    #[test]
    fn the_filter_registration_matches_the_c_exactly() {
        let conn = TestConn::new();
        let resolver = TestResolver::new(Vec::new());
        let (proxy, _state, _log) = primary(&conn, &resolver);

        // `.name` is "SOCKS", NOT "SOCKS-PROXY".
        assert_eq!(proxy.trace_name(), "SOCKS");
        assert_eq!(SOCKS_FILTER_NAME, "SOCKS");
        // `--trace-config socks` resolves to this filter's registry entry.
        assert_eq!(proxy.trace_filter(), Some(TraceFilter::SocksProxy));
        // `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY` = (1 << 0) | (1 << 3).
        assert_eq!(proxy.cf_type(), CF_TYPE_IP_CONNECT | CF_TYPE_PROXY);
        assert!(proxy.cf_type().contains(CF_TYPE_IP_CONNECT));
        assert!(proxy.cf_type().contains(CF_TYPE_PROXY));
        assert!(!proxy.cf_type().contains(crate::conn::filters::CF_TYPE_SSL));
        // `Curl_cf_create(&cf, &Curl_cft_socks_proxy, NULL)`: no context yet.
        assert!(proxy.state().is_none(), "the context is allocated lazily");
    }

    /// The eighteen display names of `cf_socks_statename[]`
    /// (`lib/socks.c:71-90`), character for character.
    #[test]
    fn the_eighteen_state_names_are_the_frozen_strings() {
        const FROZEN: [&str; 18] = [
            "SOCKS_INIT",
            "SOCKS4_START",
            "SOCKS4_RESOLVING",
            "SOCKS4_SEND",
            "SOCKS4_RECV",
            "SOCKS5_START",
            "SOCKS5_REQ0_SEND",
            "SOCKS5_RESP0_RECV",
            "SOCKS5_GSSAPI_INIT",
            "SOCKS5_AUTH_INIT",
            "SOCKS5_AUTH_SEND",
            "SOCKS5_AUTH_RECV",
            "SOCKS5_REQ1_INIT",
            "SOCKS5_RESOLVING",
            "SOCKS5_REQ1_SEND",
            "SOCKS5_RESP1_RECV",
            "SOCKS_SUCCESS",
            "SOCKS_FAILED",
        ];
        assert_eq!(STATE_NAMES, FROZEN);
        assert_eq!(HandshakeState::ALL.len(), 18);
        for (index, state) in HandshakeState::ALL.iter().enumerate() {
            assert_eq!(state.name(), FROZEN[index]);
            assert_eq!(state.as_index(), index);
            // The name DROPS the `_ST_` infix the enumerator carries, so no
            // name may contain it.
            assert!(
                !state.name().contains("_ST_"),
                "{} must not carry the enum infix",
                state.name()
            );
        }
        // The default state is the C's zeroed `calloc`.
        assert_eq!(HandshakeState::default(), HandshakeState::Init);
    }

    /// The four states that wait to WRITE (`lib/socks.c:1323-1326`), and the
    /// fourteen that wait to read.
    #[test]
    fn only_the_four_send_states_wait_to_write() {
        let sending: Vec<&str> = HandshakeState::ALL
            .iter()
            .filter(|state| state.is_sending())
            .map(|state| state.name())
            .collect();
        assert_eq!(
            sending,
            vec![
                "SOCKS4_SEND",
                "SOCKS5_REQ0_SEND",
                "SOCKS5_AUTH_SEND",
                "SOCKS5_REQ1_SEND",
            ]
        );
    }

    // -- 2. SOCKS4 and SOCKS4a, byte for byte ------------------------------

    /// A whole SOCKS4 handshake: request bytes, then the grant.
    ///
    /// `VN | CD | DSTPORT(2) | DSTIP(4) | USERID | NUL`
    /// (`lib/socks.c:503-508`).
    #[test]
    fn socks4_writes_the_request_byte_for_byte() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks4.as_i32();
            facts.remote_port = 8080;
            facts.proxy_user = Some("bob".to_string());
        });
        let resolver = TestResolver::ready(vec![v4([192, 168, 0, 7], 8080)]);
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);

        // The grant: version 0, code 90, then the echoed port and address.
        feed(&state, &[0, 90, 0x1f, 0x90, 192, 168, 0, 7]);
        assert!(connect(&mut proxy, &clock).expect("SOCKS4 must connect"));

        assert_eq!(
            sent(&state),
            vec![
                4, // VN: SOCKS4
                1, // CD: CONNECT
                0x1f, 0x90, // DSTPORT 8080, MSB first
                192, 168, 0, 7, // DSTIP, from the local lookup
                b'b', b'o', b'b', 0, // USERID with its NUL
            ]
        );
        // `socks_proxy_cf_free(cf)` on success.
        assert!(proxy.state().is_none(), "the context is freed on success");
        assert!(proxy.base().is_connected());
    }

    /// SOCKS4 insists on IPv4 -- `cf->conn->ip_version = CURL_IPRESOLVE_V4`
    /// (`lib/socks.c:494`) -- and takes the FIRST IPv4 answer, skipping IPv6.
    #[test]
    fn socks4_insists_on_ipv4_and_takes_the_first_such_address() {
        let conn = TestConn::new();
        conn.set(|facts| facts.proxy_type = ProxyType::Socks4.as_i32());
        let resolver = TestResolver::ready(vec![
            v6("2001:db8::1", 80),
            v4([10, 0, 0, 1], 80),
            v4([10, 0, 0, 2], 80),
        ]);
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[0, 90, 0, 80, 0, 0, 0, 0]);
        assert!(connect(&mut proxy, &clock).expect("SOCKS4 must connect"));

        assert_eq!(
            sent(&state),
            vec![4, 1, 0, 80, 10, 0, 0, 1, 0],
            "the first IPv4 address, and an empty user id"
        );
        assert_eq!(
            conn.facts.borrow().ip_version,
            IpVersion::V4,
            "SOCKS4 can only do IPv4, insist!"
        );
        // The lookup was started with the connection's own restriction.
        let starts = resolver.starts.borrow().clone();
        assert_eq!(starts.len(), 1);
        assert_eq!(starts[0].0, "example.com");
        assert_eq!(starts[0].1, 80);
    }

    /// SOCKS4a: the `{0,0,0,1}` placeholder, then the USER, then the HOSTNAME.
    ///
    /// The ordering is the C's (`lib/socks.c:518-533`) and is the one part of
    /// the two SOCKS4 paths that differs beyond the address itself.
    #[test]
    fn socks4a_sends_the_placeholder_then_user_then_hostname() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks4a.as_i32();
            facts.host_name = "far.example".to_string();
            facts.remote_port = 1080;
            facts.proxy_user = Some("u".to_string());
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[0, 90, 4, 56, 0, 0, 0, 0]);
        assert!(connect(&mut proxy, &clock).expect("SOCKS4a must connect"));

        let mut expected: Vec<u8> = vec![4, 1, 0x04, 0x38, 0, 0, 0, 1];
        expected.extend_from_slice(b"u\0");
        expected.extend_from_slice(b"far.example\0");
        assert_eq!(sent(&state), expected);
        // No lookup was started at all: the proxy resolves the name.
        assert!(resolver.starts.borrow().is_empty());
    }

    /// An unset proxy user is a single zero byte, not an omission
    /// (`lib/socks.c:300-306`).
    #[test]
    fn socks4_writes_one_zero_byte_for_an_absent_user() {
        let conn = TestConn::new();
        conn.set(|facts| facts.proxy_type = ProxyType::Socks4a.as_i32());
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[0, 90, 0, 0, 0, 0, 0, 0]);
        assert!(connect(&mut proxy, &clock).is_ok());

        let bytes = sent(&state);
        assert_eq!(&bytes[..8], &[4, 1, 0, 80, 0, 0, 0, 1]);
        assert_eq!(bytes[8], 0, "the empty user id");
        assert_eq!(&bytes[9..], b"example.com\0");
    }

    /// Each of the four SOCKS4 rejection codes, with its verbatim message tail
    /// (`lib/socks.c:426-456`).
    #[test]
    fn every_socks4_reply_code_maps_to_its_code_and_message() {
        // `resp[4..8]` is the address the SERVER echoed and `resp[2..4]` its
        // port, which is what the message prints -- not the request's.
        let reply = [0_u8, 0, 0x00, 0x50, 10, 20, 30, 40];
        let cases: [(u8, CURLproxycode, &str); 4] = [
            (
                91,
                CURLproxycode::RequestFailed,
                ", request rejected or failed.",
            ),
            (
                92,
                CURLproxycode::Identd,
                ", request rejected because SOCKS server cannot connect to \
                 identd on the client.",
            ),
            (
                93,
                CURLproxycode::IdentdDiffer,
                ", request rejected because the client program and identd \
                 report different user-ids.",
            ),
            (99, CURLproxycode::UnknownFail, ", Unknown."),
        ];
        for (code, expected, tail) in cases {
            let conn = TestConn::new();
            conn.set(|facts| facts.proxy_type = ProxyType::Socks4a.as_i32());
            let resolver = TestResolver::new(Vec::new());
            let clock = clock();
            let (mut proxy, state, _log) = primary(&conn, &resolver);
            let mut bytes = reply;
            bytes[1] = code;
            feed(&state, &bytes);

            let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
            assert_eq!(px, expected, "reply {code}");
            let head = format!(
                "[SOCKS] cannot complete SOCKS4 connection to \
                 10.20.30.40:80. ({code})"
            );
            assert!(
                rendered.contains(&head),
                "reply {code} must print the echoed quad: {rendered}"
            );
            assert!(
                rendered.contains(tail),
                "reply {code} must print its own tail: {rendered}"
            );
        }
    }

    /// A SOCKS4 reply whose version byte is not zero
    /// (`lib/socks.c:415-418`).
    #[test]
    fn a_socks4_reply_version_other_than_zero_is_refused() {
        let conn = TestConn::new();
        conn.set(|facts| facts.proxy_type = ProxyType::Socks4a.as_i32());
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        // Version 4 rather than 0 -- the classic confusion, and an error.
        feed(&state, &[4, 90, 0, 0, 0, 0, 0, 0]);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::BadVersion);
        assert!(rendered.contains(msg::SOCKS4_BAD_VERSION), "{rendered}");
    }

    /// The SOCKS4a hostname cap counts the terminator
    /// (`lib/socks.c:519-524`).
    #[test]
    fn socks4a_refuses_a_hostname_that_would_not_fit_a_length_byte() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks4a.as_i32();
            // 255 characters plus the NUL is 256, one past the cap.
            facts.host_name = "h".repeat(MAX_FIELD_LEN);
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::LongHostname);
        assert!(rendered.contains(msg::SOCKS4_LONG_HOSTNAME), "{rendered}");
        assert!(sent(&state).len() <= 4, "nothing past the header went out");
    }

    /// The SOCKS4 user-id cap (`lib/socks.c:287-293`).
    #[test]
    fn socks4_refuses_an_over_long_user_id() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks4a.as_i32();
            facts.proxy_user = Some("u".repeat(MAX_FIELD_LEN + 1));
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, _state, _log) = primary(&conn, &resolver);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::LongUser);
        assert!(rendered.contains(msg::LONG_SOCKS_USERNAME), "{rendered}");
    }

    /// A name that resolves to IPv6 only cannot be reached over SOCKS4
    /// (`lib/socks.c:373-376`).
    #[test]
    fn socks4_refuses_a_destination_with_no_ipv4_address() {
        let conn = TestConn::new();
        conn.set(|facts| facts.proxy_type = ProxyType::Socks4.as_i32());
        let resolver = TestResolver::ready(vec![v6("2001:db8::2", 80)]);
        let clock = clock();
        let (mut proxy, _state, _log) = primary(&conn, &resolver);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::ResolveHost);
        assert!(
            rendered.contains(&msg::socks4_unsupported("example.com")),
            "{rendered}"
        );
    }

    /// A lookup that has not finished suspends the handshake and resumes it
    /// (`lib/socks.c:328-340`).
    #[test]
    fn socks4_resumes_after_a_pending_lookup() {
        let conn = TestConn::new();
        conn.set(|facts| facts.proxy_type = ProxyType::Socks4.as_i32());
        let resolver = TestResolver::new(vec![
            ResolveProgress::Again,
            ResolveProgress::NoEntry,
            ResolveProgress::Ready(entry(vec![v4([1, 2, 3, 4], 80)])),
        ]);
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[0, 90, 0, 0, 0, 0, 0, 0]);

        // Pass one starts the lookup and traces it.
        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        assert!(!outcome.expect("a pending lookup is not an error"));
        assert!(
            rendered.contains("SOCKS4 non-blocking resolve of example.com"),
            "{rendered}"
        );
        assert!(sent(&state).is_empty(), "nothing is sent while resolving");
        // Pass two polls and is told nothing yet; still no bytes.
        assert!(!connect(&mut proxy, &clock).expect("still resolving"));
        assert!(sent(&state).is_empty());
        // Pass three gets the address and completes.
        assert!(connect(&mut proxy, &clock).expect("must connect"));
        assert_eq!(sent(&state), vec![4, 1, 0, 80, 1, 2, 3, 4, 0]);
    }

    // -- 3. SOCKS5, byte for byte ------------------------------------------

    /// A whole no-auth SOCKS5 handshake with a locally resolved destination.
    #[test]
    fn socks5_writes_the_no_auth_handshake_byte_for_byte() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5.as_i32();
            facts.remote_port = 443;
            // No credentials, so method 2 is not offered; the default auth mask
            // permits GSS-API but no negotiator is injected, so method 1 is not
            // offered either.
        });
        let resolver = TestResolver::ready(vec![v4([203, 0, 113, 9], 443)]);
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);

        // The method selection, then a granted CONNECT reply bound to an IPv4
        // address.
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90]);
        assert!(connect(&mut proxy, &clock).expect("SOCKS5 must connect"));

        assert_eq!(
            sent(&state),
            vec![
                // `VER | NMETHODS | METHODS` -- one method, "no auth".
                5, 1, 0,
                // `VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT`
                5, 1, 0, 1, 203, 0, 113, 9, 0x01, 0xbb,
            ]
        );
        assert!(
            unread(&state).is_empty(),
            "the whole reply must be drained from the transport"
        );
        assert!(proxy.state().is_none(), "the context is freed on success");
    }

    /// `socks5h` hands the NAME to the proxy; `socks5` resolves it here
    /// (`lib/socks.c:1056`).
    #[test]
    fn socks5h_sends_a_domain_name_where_socks5_sends_an_address() {
        // `CURLPROXY_SOCKS5_HOSTNAME`: ATYP 3 with a length byte and the name.
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "remote.example".to_string();
            facts.remote_port = 70;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 70]);
        assert!(connect(&mut proxy, &clock).expect("socks5h must connect"));

        let mut expected: Vec<u8> = vec![5, 1, 0];
        expected.extend_from_slice(&[5, 1, 0, 3, 14]);
        expected.extend_from_slice(b"remote.example");
        expected.extend_from_slice(&[0, 70]);
        assert_eq!(sent(&state), expected);
        assert!(
            resolver.starts.borrow().is_empty(),
            "socks5h must not resolve locally"
        );

        // `CURLPROXY_SOCKS5`: the same request, but ATYP 1 and an address.
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5.as_i32();
            facts.host_name = "remote.example".to_string();
            facts.remote_port = 70;
        });
        let resolver = TestResolver::ready(vec![v4([198, 51, 100, 4], 70)]);
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 70]);
        assert!(connect(&mut proxy, &clock).expect("socks5 must connect"));
        assert_eq!(
            sent(&state),
            vec![5, 1, 0, 5, 1, 0, 1, 198, 51, 100, 4, 0, 70]
        );
        assert_eq!(resolver.starts.borrow().len(), 1, "socks5 resolves here");
    }

    /// A numeric IPv6 destination the proxy resolves: ATYP 4, sixteen bytes and
    /// **no length byte** (`lib/socks.c:789-796`, `:813`).
    #[test]
    fn socks5_remote_ipv6_uses_atyp_four_with_no_length_byte() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "2001:db8::1".to_string();
            facts.ipv6_ip = true;
            facts.remote_port = 8443;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 4]);
        feed(&state, &[0; 16]);
        feed(&state, &[0x20, 0xfb]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));

        let mut expected: Vec<u8> = vec![5, 1, 0, 5, 1, 0, 4];
        expected.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        expected.extend_from_slice(&[0x20, 0xfb]);
        assert_eq!(sent(&state), expected);
        assert!(unread(&state).is_empty(), "a 22-byte reply is drained");
    }

    /// A numeric IPv4 destination the proxy resolves: ATYP 1 and no length
    /// byte.
    #[test]
    fn socks5_remote_ipv4_uses_atyp_one_with_no_length_byte() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "192.0.2.10".to_string();
            facts.remote_port = 21;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 21]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));

        assert_eq!(
            sent(&state),
            vec![5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 10, 0, 21]
        );
    }

    /// A marked-IPv6 destination that does not parse as one
    /// (`lib/socks.c:794-795`).
    #[test]
    fn socks5_refuses_a_malformed_numeric_ipv6_destination() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "not:an:address".to_string();
            facts.ipv6_ip = true;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);

        let (px, _rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::BadAddressType);
        assert_eq!(
            sent(&state),
            vec![5, 1, 0],
            "only the method selection went out"
        );
    }

    /// The RFC 1929 sub-negotiation, whose version byte is **1**
    /// (`lib/socks.c:718`).
    #[test]
    fn socks5_username_password_subnegotiation_is_version_one() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h.example".to_string();
            facts.remote_port = 1080;
            facts.proxy_user = Some("alice".to_string());
            facts.proxy_password = Some("secret".to_string());
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        // Method 2 chosen, credentials accepted, then a granted CONNECT.
        feed(&state, &[5, 2]);
        feed(&state, &[1, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 4, 56]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));

        let bytes = sent(&state);
        // The offer carries "no auth" and "username/password", in that order.
        assert_eq!(&bytes[..4], &[5, 2, 0, 2]);
        // `VER | ULEN | UNAME | PLEN | PASSWD`, with VER = 1.
        let auth_start = 4;
        assert_eq!(bytes[auth_start], 1, "the sub-negotiation version is 1");
        assert_eq!(bytes[auth_start + 1], 5, "ULEN");
        assert_eq!(&bytes[auth_start + 2..auth_start + 7], b"alice");
        assert_eq!(bytes[auth_start + 7], 6, "PLEN");
        assert_eq!(&bytes[auth_start + 8..auth_start + 14], b"secret");
        // Then the CONNECT request.
        let mut expected: Vec<u8> = vec![5, 1, 0, 3, 9];
        expected.extend_from_slice(b"h.example");
        expected.extend_from_slice(&[0x04, 0x38]);
        assert_eq!(&bytes[auth_start + 14..], expected.as_slice());
    }

    /// All three methods, in the frozen wire order 0, 1, 2
    /// (`lib/socks.c:615-629`).
    #[cfg(feature = "negotiate")]
    #[test]
    fn socks5_offers_the_three_methods_in_wire_order() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
            facts.proxy_user = Some("u".to_string());
            facts.proxy_password = Some("p".to_string());
        });
        let resolver = TestResolver::new(Vec::new());
        let log = new_log();
        let (transport, state) = InMemory::new("TRANSPORT", &log);
        let seams = SocksSeams::new(
            Arc::clone(&conn) as Arc<dyn SocksConn>,
            Arc::clone(&resolver) as Arc<dyn DestinationResolver>,
        )
        .with_gssapi(TestNegotiator::succeeding());
        let mut proxy = SocksProxy::new(SocketIndex::First, None, seams);
        proxy.base_mut().set_next(Some(link(transport)));

        let clock = clock();
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));
        assert_eq!(
            &sent(&state)[..5],
            &[5, 3, 0, 1, 2],
            "three methods: none, GSS-API, username/password"
        );
    }

    /// Every SOCKS5 method-selection failure (`lib/socks.c:650-685`).
    #[test]
    fn socks5_method_selection_failures_map_to_their_codes() {
        struct Case {
            reply: [u8; 2],
            auth: u8,
            code: CURLproxycode,
            line: &'static str,
        }
        let cases = [
            Case {
                reply: [4, 0],
                auth: SOCKS5_AUTH_DEFAULT,
                code: CURLproxycode::BadVersion,
                line: msg::SOCKS5_BAD_VERSION0,
            },
            Case {
                reply: [5, 1],
                auth: SOCKS5_AUTH_BASIC,
                code: CURLproxycode::GssapiPermsg,
                line: msg::SOCKS5_GSSAPI_NOT_ENABLED,
            },
            Case {
                reply: [5, 2],
                auth: SOCKS5_AUTH_GSSAPI,
                code: CURLproxycode::NoAuth,
                line: msg::SOCKS5_BASIC_NOT_ENABLED,
            },
            Case {
                reply: [5, 255],
                auth: SOCKS5_AUTH_DEFAULT,
                code: CURLproxycode::NoAuth,
                line: msg::SOCKS5_NO_ACCEPTABLE_METHOD,
            },
            Case {
                reply: [5, 7],
                auth: SOCKS5_AUTH_DEFAULT,
                code: CURLproxycode::UnknownMode,
                line: msg::SOCKS5_UNKNOWN_MODE,
            },
        ];
        for case in cases {
            let conn = TestConn::new();
            conn.set(|facts| {
                facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
                facts.host_name = "h".to_string();
                facts.socks5_auth = case.auth;
            });
            let resolver = TestResolver::new(Vec::new());
            let clock = clock();
            let (mut proxy, state, _log) = primary(&conn, &resolver);
            feed(&state, &case.reply);

            let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
            assert_eq!(px, case.code, "reply {:?}", case.reply);
            assert!(
                rendered.contains(case.line),
                "reply {:?}: {rendered}",
                case.reply
            );
        }
    }

    /// A rejected user prints BOTH reply bytes, including the version byte the
    /// check itself ignores (`lib/socks.c:755-761`).
    #[test]
    fn a_rejected_user_prints_both_reply_bytes() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
            facts.proxy_user = Some("u".to_string());
            facts.proxy_password = Some("p".to_string());
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 2]);
        // Version 9 -- ignored -- and status 1, a refusal.
        feed(&state, &[9, 1]);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::UserRejected);
        assert!(rendered.contains(&msg::user_rejected(9, 1)), "{rendered}");
        assert!(rendered.contains("(9 1)"), "both bytes: {rendered}");
    }

    /// Both sub-negotiation length caps (`lib/socks.c:701-708`).
    #[test]
    fn the_subnegotiation_refuses_credentials_past_one_byte() {
        for (user, password, code, line) in [
            (
                "u".repeat(MAX_FIELD_LEN + 1),
                "p".to_string(),
                CURLproxycode::LongUser,
                msg::EXCESSIVE_USERNAME,
            ),
            (
                "u".to_string(),
                "p".repeat(MAX_FIELD_LEN + 1),
                CURLproxycode::LongPasswd,
                msg::EXCESSIVE_PASSWORD,
            ),
        ] {
            let conn = TestConn::new();
            conn.set(|facts| {
                facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
                facts.host_name = "h".to_string();
                facts.proxy_user = Some(user.clone());
                facts.proxy_password = Some(password.clone());
            });
            let resolver = TestResolver::new(Vec::new());
            let clock = clock();
            let (mut proxy, state, _log) = primary(&conn, &resolver);
            feed(&state, &[5, 2]);

            let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
            assert_eq!(px, code);
            assert!(rendered.contains(line), "{rendered}");
        }
    }

    /// A user with no password sends two zero lengths, because the C computes
    /// them only when both are present (`lib/socks.c:697`).
    #[test]
    fn a_user_without_a_password_sends_two_zero_lengths() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
            facts.proxy_user = Some("alice".to_string());
            facts.proxy_password = None;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 2]);
        feed(&state, &[1, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));

        let bytes = sent(&state);
        assert_eq!(&bytes[..4], &[5, 2, 0, 2], "method 2 is still offered");
        assert_eq!(
            &bytes[4..7],
            &[1, 0, 0],
            "VER 1, ULEN 0, PLEN 0 -- no credentials on the wire"
        );
    }

    /// Withholding `CURLAUTH_BASIC` withdraws method 2 from the offer
    /// (`lib/socks.c:611-613`).
    #[test]
    fn withholding_basic_stops_the_username_method_being_offered() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
            facts.proxy_user = Some("alice".to_string());
            facts.proxy_password = Some("secret".to_string());
            facts.socks5_auth = SOCKS5_AUTH_GSSAPI;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));
        assert_eq!(&sent(&state)[..3], &[5, 1, 0], "only \"no auth\" offered");
    }

    /// An unsupported `CURLOPT_SOCKS5_AUTH` bit is reported and then ignored
    /// (`lib/socks.c:608-610`).
    #[test]
    fn an_unsupported_socks5_auth_bit_is_reported_not_honoured() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
            // `CURLAUTH_DIGEST` = 1 << 1, which SOCKS5 has no method for.
            facts.socks5_auth = SOCKS5_AUTH_DEFAULT | (1 << 1);
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);

        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        assert!(outcome.expect("the handshake still succeeds"));
        assert!(
            rendered.contains(&msg::unsupported_socks5_auth(7)),
            "{rendered}"
        );
        assert_eq!(&sent(&state)[..3], &[5, 1, 0]);
    }

    /// A destination the PROXY must resolve is capped at one length byte
    /// (`lib/socks.c:601-606`), and a locally resolved one is not.
    #[test]
    fn only_a_remotely_resolved_hostname_is_capped() {
        let long = "h".repeat(MAX_FIELD_LEN + 1);
        // socks5h: the name travels, so it must fit.
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = long.clone();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::LongHostname);
        assert!(rendered.contains(msg::SOCKS5_LONG_HOSTNAME), "{rendered}");
        assert!(sent(&state).is_empty(), "not even the offer went out");

        // socks5: the name never travels, so its length does not matter.
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5.as_i32();
            facts.host_name = long;
        });
        let resolver = TestResolver::ready(vec![v4([10, 0, 0, 9], 80)]);
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));
        assert_eq!(sent(&state), vec![5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 9, 0, 80]);
    }

    /// A locally resolved IPv6 destination: ATYP 4, and the trace line brackets
    /// the address (`lib/socks.c:903-911`).
    #[test]
    fn a_local_ipv6_resolve_brackets_the_address_in_its_trace() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5.as_i32();
            facts.remote_port = 80;
            facts.requested_ip_version = IpVersion::V6;
        });
        let resolver = TestResolver::ready(vec![
            v4([10, 0, 0, 1], 80),
            v6("2001:db8::5", 80),
        ]);
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);

        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        assert!(outcome.expect("must connect"));
        let mut expected: Vec<u8> = vec![5, 1, 0, 5, 1, 0, 4];
        expected.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
        ]);
        expected.extend_from_slice(&[0, 80]);
        assert_eq!(sent(&state), expected, "the requested family was chosen");
        assert!(
            rendered.contains(
                "SOCKS5 connect to [2001:db8::5]:80 (locally resolved)"
            ),
            "the IPv6 line brackets the address: {rendered}"
        );
        assert!(
            !rendered.contains("connect to 2001:db8::5:80"),
            "an unbracketed IPv6 line would be the C's IPv4 form: {rendered}"
        );
    }

    /// The IPv4 local-resolve line does NOT bracket its address
    /// (`lib/socks.c:899-900`).
    #[test]
    fn a_local_ipv4_resolve_does_not_bracket_its_address() {
        let conn = TestConn::new();
        conn.set(|facts| facts.proxy_type = ProxyType::Socks5.as_i32());
        let resolver = TestResolver::ready(vec![v4([198, 51, 100, 7], 80)]);
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);

        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        assert!(outcome.expect("must connect"));
        assert!(
            rendered.contains(
                "SOCKS5 connect to 198.51.100.7:80 (locally resolved)"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains("[198.51.100.7]"), "{rendered}");
    }

    /// The requested family is honoured even when another comes first
    /// (`lib/socks.c:877-883`), and an answer with none of it fails.
    #[test]
    fn the_requested_family_selects_the_address_and_can_fail() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5.as_i32();
            facts.requested_ip_version = IpVersion::V6;
        });
        let resolver = TestResolver::ready(vec![v4([10, 0, 0, 1], 80)]);
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::ResolveHost);
        assert!(
            rendered.contains(&msg::socks5_resolve_failed("example.com")),
            "{rendered}"
        );
    }

    // -- 4. the CONNECT reply, and draining it -----------------------------

    /// Each RFC 1928 section 6 reply code, and the unassigned range beyond it
    /// (`lib/socks.c:986-1006`).
    #[test]
    fn every_rfc1928_reply_code_maps_to_its_proxy_code() {
        let expected = [
            (1, CURLproxycode::ReplyGeneralServerFailure),
            (2, CURLproxycode::ReplyNotAllowed),
            (3, CURLproxycode::ReplyNetworkUnreachable),
            (4, CURLproxycode::ReplyHostUnreachable),
            (5, CURLproxycode::ReplyConnectionRefused),
            (6, CURLproxycode::ReplyTtlExpired),
            (7, CURLproxycode::ReplyCommandNotSupported),
            (8, CURLproxycode::ReplyAddressTypeNotSupported),
            // `if(code < 9)` -- nine and beyond are unassigned.
            (9, CURLproxycode::ReplyUnassigned),
            (10, CURLproxycode::ReplyUnassigned),
            (255, CURLproxycode::ReplyUnassigned),
        ];
        for (code, mapped) in expected {
            assert_eq!(
                SocksProxy::rfc1928_reply(code),
                mapped,
                "reply code {code}"
            );
        }
        // Slot zero exists only to keep every other slot at its own number.
        assert_eq!(RFC1928_REPLIES[0], CURLproxycode::Ok);
        assert_eq!(RFC1928_REPLIES.len(), 9);
    }

    /// A refused CONNECT carries its code and its message
    /// (`lib/socks.c:986-1007`).
    #[test]
    fn a_refused_connect_reports_the_code_and_the_host() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "denied.example".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        // Reply 2: connection not allowed by ruleset.
        feed(&state, &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::ReplyNotAllowed);
        assert!(
            rendered.contains(&msg::socks5_connect_failed("denied.example", 2)),
            "{rendered}"
        );
    }

    /// A domain-name `BND.ADDR` is drained in full, so nothing leaks into the
    /// tunnel (`lib/socks.c:967-969`, `:1014-1015`).
    #[test]
    fn a_long_bound_address_is_drained_before_the_tunnel_starts() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        // ATYP 3 with a 200-byte name: `4 + 1 + 200 + 2` = 207 bytes.
        let name = vec![b'x'; 200];
        let mut reply: Vec<u8> = vec![5, 0, 0, 3, 200];
        reply.extend_from_slice(&name);
        reply.extend_from_slice(&[0x1f, 0x90]);
        feed(&state, &reply);
        // What the tunnelled protocol will send next, which must survive.
        feed(&state, b"HTTP/1.1 200 OK\r\n");

        assert!(connect(&mut proxy, &clock).expect("must connect"));
        assert_eq!(
            unread(&state),
            b"HTTP/1.1 200 OK\r\n".to_vec(),
            "exactly the reply was consumed, no more and no less"
        );
    }

    /// The three `ATYP` lengths of the reply (`lib/socks.c:1010-1023`), and the
    /// refusal of a fourth.
    #[test]
    fn the_reply_length_follows_the_address_type() {
        // ATYP 1: 4 + 4 + 2.
        let cases: [(u8, Vec<u8>); 3] = [
            (1, vec![5, 0, 0, 1, 1, 2, 3, 4, 0, 80]),
            (4, {
                let mut reply = vec![5, 0, 0, 4];
                reply.extend_from_slice(&[0; 16]);
                reply.extend_from_slice(&[0, 80]);
                reply
            }),
            (3, vec![5, 0, 0, 3, 3, b'a', b'b', b'c', 0, 80]),
        ];
        for (atyp, reply) in cases {
            let conn = TestConn::new();
            conn.set(|facts| {
                facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
                facts.host_name = "h".to_string();
            });
            let resolver = TestResolver::new(Vec::new());
            let clock = clock();
            let (mut proxy, state, _log) = primary(&conn, &resolver);
            feed(&state, &[5, 0]);
            feed(&state, &reply);
            feed(&state, b"tail");
            assert!(
                connect(&mut proxy, &clock).expect("must connect"),
                "ATYP {atyp}"
            );
            assert_eq!(unread(&state), b"tail".to_vec(), "ATYP {atyp}");
        }

        // ATYP 2 is not a thing.
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 2, 0, 0, 0, 0]);
        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::BadAddressType);
        assert!(
            rendered.contains(msg::SOCKS5_BAD_ADDRESS_TYPE),
            "{rendered}"
        );
    }

    /// A CONNECT reply whose version is not 5 (`lib/socks.c:982-985`).
    #[test]
    fn a_connect_reply_version_other_than_five_is_refused() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[4, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::BadVersion);
        assert!(rendered.contains(msg::SOCKS5_BAD_VERSION1), "{rendered}");
    }

    // -- 5. GSS-API -------------------------------------------------------

    /// `conn->socks5_gssapi_enctype` fails the handshake AFTER the request has
    /// gone out (`lib/socks.c:1166-1171`).
    #[test]
    fn per_message_protection_is_a_hard_failure_after_the_request() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
            facts.gssapi_enctype = 1;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::GssapiProtection);
        assert!(
            rendered.contains(msg::SOCKS5_GSSAPI_PROTECTION),
            "{rendered}"
        );
        // The CONNECT request really did go out before the refusal.
        assert_eq!(
            sent(&state),
            vec![5, 1, 0, 5, 1, 0, 3, 1, b'h', 0, 80],
            "the request is sent, and only then refused"
        );
    }

    /// Without a negotiator the GSS-API method cannot be honoured, and the
    /// message is the *"not supported"* one (`lib/socks.c:1102-1106`).
    #[test]
    fn a_server_choosing_gssapi_without_a_negotiator_fails() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        // The server picks method 1 even though it was never offered.
        feed(&state, &[5, 1]);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::GssapiPermsg);
        assert!(
            rendered.contains(msg::SOCKS5_GSSAPI_UNSUPPORTED),
            "the \"not supported\" line, not the \"not enabled\" one: \
             {rendered}"
        );
    }

    /// A negotiation that fails reports [`CURLproxycode::Gssapi`]
    /// (`lib/socks.c:1095-1099`).
    #[cfg(feature = "negotiate")]
    #[test]
    fn a_failed_gssapi_negotiation_reports_gssapi() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let log = new_log();
        let (transport, state) = InMemory::new("TRANSPORT", &log);
        let seams = SocksSeams::new(
            Arc::clone(&conn) as Arc<dyn SocksConn>,
            Arc::clone(&resolver) as Arc<dyn DestinationResolver>,
        )
        .with_gssapi(TestNegotiator::failing(CURLcode::RecvError));
        let mut proxy = SocksProxy::new(SocketIndex::First, None, seams);
        proxy.base_mut().set_next(Some(link(transport)));
        let clock = clock();
        feed(&state, &[5, 1]);

        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::Gssapi);
        assert!(rendered.contains(msg::SOCKS5_GSSAPI_FAILED), "{rendered}");
    }

    /// A successful negotiation continues into the CONNECT request.
    #[cfg(feature = "negotiate")]
    #[test]
    fn a_successful_gssapi_negotiation_continues_to_the_request() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let log = new_log();
        let (transport, state) = InMemory::new("TRANSPORT", &log);
        let seams = SocksSeams::new(
            Arc::clone(&conn) as Arc<dyn SocksConn>,
            Arc::clone(&resolver) as Arc<dyn DestinationResolver>,
        )
        .with_gssapi(TestNegotiator::succeeding());
        let mut proxy = SocksProxy::new(SocketIndex::First, None, seams);
        proxy.base_mut().set_next(Some(link(transport)));
        let clock = clock();
        feed(&state, &[5, 1]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);

        assert!(connect(&mut proxy, &clock).expect("must connect"));
        assert_eq!(sent(&state), vec![5, 2, 0, 1, 5, 1, 0, 3, 1, b'h', 0, 80]);
    }

    // -- 6. suspension and resumption --------------------------------------

    /// A blocked send leaves the request buffered and resumes it
    /// (`lib/socks.c:214-215`).
    #[test]
    fn a_blocked_send_resumes_without_resending() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        state.borrow_mut().writable = false;

        // Pass one buffers the offer and cannot write it.
        assert!(!connect(&mut proxy, &clock).expect("a block is not an error"));
        assert!(sent(&state).is_empty());
        assert_eq!(
            proxy.state().map(SocksState::state),
            Some(HandshakeState::Socks5Req0Send),
            "the machine waits in the SEND state"
        );

        // Pass two writes it exactly once.
        state.borrow_mut().writable = true;
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));
        assert_eq!(sent(&state), vec![5, 1, 0, 5, 1, 0, 3, 1, b'h', 0, 80]);
    }

    /// A blocked read suspends the handshake and resumes it without repeating a
    /// single byte (`lib/socks.c:240-241`).
    #[test]
    fn a_blocked_read_resumes_without_repeating_the_request() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);

        // Pass one writes the offer and finds nothing to read.
        state.borrow_mut().readable = false;
        assert!(!connect(&mut proxy, &clock).expect("a block is not an error"));
        assert_eq!(sent(&state), vec![5, 1, 0]);
        assert_eq!(
            proxy.state().map(SocksState::state),
            Some(HandshakeState::Socks5Resp0Recv),
            "the machine waits where it stopped"
        );

        // Pass two reads the answer and finishes, and the offer is NOT sent
        // again: the buffer was drained, not rewound.
        state.borrow_mut().readable = true;
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));
        assert_eq!(sent(&state), vec![5, 1, 0, 5, 1, 0, 3, 1, b'h', 0, 80]);
        assert_eq!(state.borrow().sends, 2, "one send per request, no repeat");
    }

    /// Bytes already received survive a pass that could not read the rest.
    ///
    /// Driven against [`SocksProxy::recv`] directly, because that is the
    /// property `socks_recv`'s `while(Curl_bufq_len(&sx->iobuf) < min_bytes)`
    /// loop exists for: a response arriving in pieces is assembled across as
    /// many passes as it takes.
    #[test]
    fn a_partial_response_is_kept_across_passes() {
        let conn = TestConn::new();
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        proxy.state = Some(SocksState::new("h".to_string(), 80, None, None));
        let mut cx = CallCtx::new(&clock);

        // Three bytes arrive and are consumed from the transport.
        feed(&state, &[1, 2, 3]);
        assert!(proxy.recv(&mut cx, 3).expect("three bytes are there"));
        assert!(unread(&state).is_empty());

        // Five are wanted and the transport blocks, so the three are kept.
        state.borrow_mut().readable = false;
        assert!(!proxy.recv(&mut cx, 5).expect("a block is not an error"));
        assert_eq!(
            proxy.state.as_ref().map(|sx| sx.iobuf.len()),
            Some(3),
            "the bytes already read must not be discarded"
        );

        // The remainder arrives and the whole response is in order.
        state.borrow_mut().readable = true;
        feed(&state, &[4, 5]);
        assert!(proxy.recv(&mut cx, 5).expect("all five are there now"));
        let sx = proxy.state.as_mut().expect("the context");
        assert_eq!(sx.iobuf.peek(), Some(&[1_u8, 2, 3, 4, 5][..]));
    }

    /// A proxy that closes mid-response (`lib/socks.c:247-252`).
    #[test]
    fn a_proxy_that_closes_mid_response_reports_recv_connect() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        // One byte, then end of stream: the transport reports zero for ever.
        feed(&state, &[5]);
        let (px, rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(px, CURLproxycode::RecvConnect);
        assert!(rendered.contains(msg::RECV_CLOSED), "{rendered}");
    }

    /// The filter below is connected FIRST, and nothing is negotiated until it
    /// is (`lib/socks.c:1230-1232`).
    #[test]
    fn the_filter_below_is_connected_before_anything_is_negotiated() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        // Two steps: the first pass leaves the transport connecting, the
        // second completes it and only then may a SOCKS byte be written.
        state.borrow_mut().connect_steps = 2;

        assert!(
            !connect(&mut proxy, &clock).expect("below is still connecting")
        );
        assert!(sent(&state).is_empty(), "no SOCKS byte before the socket");
        assert!(proxy.state().is_none(), "no context allocated either");
        assert_eq!(state.borrow().connects, 1);

        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));
        assert_eq!(state.borrow().connects, 2, "the transport was asked twice");
        assert_eq!(sent(&state), vec![5, 1, 0, 5, 1, 0, 3, 1, b'h', 0, 80]);
    }

    /// An already connected filter answers at once (`lib/socks.c:1225-1228`).
    #[test]
    fn a_connected_filter_short_circuits() {
        let conn = TestConn::new();
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        proxy.base_mut().set_connected(true);
        assert!(connect(&mut proxy, &clock).expect("already connected"));
        assert!(sent(&state).is_empty());
        assert_eq!(state.borrow().connects, 0, "below was not even asked");
    }

    // -- 7. the destination, and the two asymmetric chains ------------------

    /// The hostname chain tests `conn_to_host` BEFORE the secondary socket, and
    /// the port chain tests the secondary socket first
    /// (`lib/socks.c:1241-1255`).
    #[test]
    fn the_secondary_socket_takes_the_connect_to_host_and_its_own_port() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "origin.example".to_string();
            facts.remote_port = 21;
            facts.connect_to_host = Some("redirected.example".to_string());
            facts.connect_to_port = Some(2121);
            facts.secondary_host = Some("data.example".to_string());
            facts.secondary_port = 30_000;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) =
            filter(&conn, &resolver, SocketIndex::Secondary);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));

        // The host is the "connect to" one -- NOT `secondaryhostname` -- and
        // the port is the secondary one -- NOT `conn_to_port`.
        let mut expected: Vec<u8> = vec![5, 1, 0, 5, 1, 0, 3, 18];
        expected.extend_from_slice(b"redirected.example");
        expected.extend_from_slice(&30_000_u16.to_be_bytes());
        assert_eq!(sent(&state), expected);
    }

    /// With no `--connect-to`, the secondary socket uses its own host and port.
    #[test]
    fn the_secondary_socket_falls_back_to_its_own_host() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "origin.example".to_string();
            facts.remote_port = 21;
            facts.secondary_host = Some("data.example".to_string());
            facts.secondary_port = 40_000;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) =
            filter(&conn, &resolver, SocketIndex::Secondary);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(connect(&mut proxy, &clock).expect("must connect"));

        let mut expected: Vec<u8> = vec![5, 1, 0, 5, 1, 0, 3, 12];
        expected.extend_from_slice(b"data.example");
        expected.extend_from_slice(&40_000_u16.to_be_bytes());
        assert_eq!(sent(&state), expected);
    }

    /// An HTTP proxy beyond the SOCKS proxy is the destination
    /// (`lib/socks.c:1245-1252`).
    #[test]
    fn an_http_proxy_beyond_the_socks_proxy_is_the_destination() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "origin.example".to_string();
            facts.remote_port = 80;
            facts.http_proxy = true;
            facts.http_proxy_host = Some("gw.example".to_string());
            facts.http_proxy_port = 3128;
            // Both of these must be ignored while `httpproxy` is set.
            facts.connect_to_host = Some("ignored.example".to_string());
            facts.connect_to_port = Some(9999);
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        assert!(outcome.expect("must connect"));
        let mut expected: Vec<u8> = vec![5, 1, 0, 5, 1, 0, 3, 10];
        expected.extend_from_slice(b"gw.example");
        expected.extend_from_slice(&3128_u16.to_be_bytes());
        assert_eq!(sent(&state), expected);
        assert!(
            rendered.contains(
                "SOCKS5: connecting to HTTP proxy gw.example \
                               port 3128"
            ),
            "{rendered}"
        );
    }

    /// The SOCKS4 variant of the same line names the HTTP proxy
    /// (`lib/socks.c:495-498`).
    #[test]
    fn the_socks4_banner_names_an_http_proxy_when_there_is_one() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks4a.as_i32();
            facts.http_proxy = true;
            facts.http_proxy_host = Some("gw".to_string());
            facts.http_proxy_port = 8080;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[0, 90, 0, 0, 0, 0, 0, 0]);

        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        assert!(outcome.expect("must connect"));
        assert!(
            rendered.contains("SOCKS4a communication to HTTP proxy gw:8080"),
            "{rendered}"
        );
    }

    /// A proxy type that is not a SOCKS one (`lib/socks.c:1273-1276`).
    #[test]
    fn a_non_socks_proxy_type_is_refused_with_couldnt_connect() {
        let conn = TestConn::new();
        conn.set(|facts| facts.proxy_type = ProxyType::Http.as_i32());
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, _state, _log) = primary(&conn, &resolver);

        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        let error = outcome.expect_err("an HTTP proxy is not a SOCKS one");
        // NOT `CURLE_PROXY`, so `CURLINFO_PROXY_ERROR` is left untouched.
        assert_eq!(error.code(), CURLcode::CouldntConnect);
        assert_eq!(conn.proxy_code(), None, "pxcode must not be published");
        assert!(rendered.contains(msg::UNKNOWN_PROXYTYPE), "{rendered}");
    }

    // -- 8. the other three overridden operations --------------------------

    /// `socks_cf_adjust_pollset` (`lib/socks.c:1311-1337`).
    #[test]
    fn the_pollset_asks_to_write_in_the_four_send_states() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        // A descriptor the pollset will accept, and a blocked write so the
        // machine stops in `SOCKS5_ST_REQ0_SEND`.
        state.borrow_mut().socket = 9;
        state.borrow_mut().writable = false;
        assert!(!connect(&mut proxy, &clock).expect("a block is not an error"));

        let mut cx = CallCtx::new(&clock);
        let mut ps = EasyPollset::new();
        proxy
            .adjust_pollset(&mut cx, &mut ps)
            .expect("a valid socket");
        assert_eq!(
            ps.action_of(9),
            crate::conn::select::PollAction::OUT,
            "a buffered request waits to write"
        );

        // Once the request is out and the answer has not arrived, the machine
        // waits to READ -- which is the `default` arm, and covers every state
        // that is not one of the four.
        state.borrow_mut().writable = true;
        state.borrow_mut().readable = false;
        assert!(!connect(&mut proxy, &clock).expect("a blocked read"));
        assert_eq!(
            proxy.state().map(SocksState::state),
            Some(HandshakeState::Socks5Resp0Recv)
        );
        let mut ps = EasyPollset::new();
        proxy
            .adjust_pollset(&mut cx, &mut ps)
            .expect("a valid socket");
        assert_eq!(ps.action_of(9), crate::conn::select::PollAction::IN);
    }

    /// The pollset's own trace line, asserted as RENDERED BYTES against
    /// `CURL_TRC_CF(data, cf, "adjust pollset out (%d)", sx->state)` and its
    /// `in` counterpart (`lib/socks.c:1325`, `:1332`).
    ///
    /// The literal here is `"adjust pollset {} ({})"` with the direction passed
    /// in, where the C carries two separate literals. That is only legitimate
    /// if the rendered bytes agree, and the `%d` is the state's position in the
    /// C enumeration -- so the number is asserted too, not just the wording.
    #[test]
    fn the_pollset_trace_line_matches_the_c_byte_for_byte() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        state.borrow_mut().socket = 9;
        state.borrow_mut().writable = false;
        assert!(!connect(&mut proxy, &clock).expect("a block is not an error"));

        // `SOCKS5_REQ0_SEND` is index 6 of the frozen table, so the C prints
        // exactly "adjust pollset out (6)".
        assert_eq!(HandshakeState::Socks5Req0Send.as_index(), 6);
        let rendered = pollset_traced(&mut proxy, &clock, 9);
        assert!(
            rendered.contains("adjust pollset out (6)"),
            "the C prints `adjust pollset out (%d)`: {rendered}"
        );

        // And "adjust pollset in (7)" for `SOCKS5_RESP0_RECV`, the default arm
        // that covers every state which is not one of the four.
        state.borrow_mut().writable = true;
        state.borrow_mut().readable = false;
        assert!(!connect(&mut proxy, &clock).expect("a blocked read"));
        assert_eq!(HandshakeState::Socks5Resp0Recv.as_index(), 7);
        let rendered = pollset_traced(&mut proxy, &clock, 9);
        assert!(
            rendered.contains("adjust pollset in (7)"),
            "the C prints `adjust pollset in (%d)`: {rendered}"
        );
    }

    /// A connected filter, and one with no context, adjust nothing
    /// (`lib/socks.c:1318`).
    #[test]
    fn the_pollset_is_untouched_when_connected_or_uninitialised() {
        let conn = TestConn::new();
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        state.borrow_mut().socket = 11;
        let mut cx = CallCtx::new(&clock);

        // No context yet.
        let mut ps = EasyPollset::new();
        proxy.adjust_pollset(&mut cx, &mut ps).expect("no context");
        assert!(ps.is_empty());

        // Connected.
        proxy.base_mut().set_connected(true);
        let mut ps = EasyPollset::new();
        proxy.adjust_pollset(&mut cx, &mut ps).expect("connected");
        assert!(ps.is_empty());
    }

    /// `socks_cf_query` (`lib/socks.c:1356-1382`).
    #[test]
    fn the_query_reports_the_destination_and_no_alpn() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "target.example".to_string();
            facts.remote_port = 8080;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        state.borrow_mut().writable = false;
        assert!(!connect(&mut proxy, &clock).expect("a block is not an error"));

        let mut cx = CallCtx::new(&clock);
        // The DESTINATION, not the proxy -- the opposite of the HTTP proxy
        // filter's answer to the same question.
        match proxy.query(&mut cx, CfQuery::HostPort) {
            Ok(CfQueryValue::HostPort { host, port }) => {
                assert_eq!(host, "target.example");
                assert_eq!(port, 8080);
            }
            other => panic!("expected the destination, got {other:?}"),
        }
        // A SOCKS tunnel negotiates no application protocol, and says so.
        match proxy.query(&mut cx, CfQuery::AlpnNegotiated) {
            Ok(CfQueryValue::AlpnNegotiated(None)) => {}
            other => panic!("expected no ALPN, got {other:?}"),
        }
        // Anything else goes down the chain, which answers for the socket.
        match proxy.query(&mut cx, CfQuery::Socket) {
            Ok(CfQueryValue::Socket(_)) => {}
            other => panic!("expected the chain's answer, got {other:?}"),
        }
    }

    /// With no context the host-and-port question falls through to the chain
    /// (`lib/socks.c:1364-1369`).
    #[test]
    fn the_host_port_query_falls_through_without_a_context() {
        let conn = TestConn::new();
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        state.borrow_mut().answers.push((
            CfQuery::HostPort,
            CfQueryValue::HostPort {
                host: "below.example".to_string(),
                port: 443,
            },
        ));
        let mut cx = CallCtx::new(&clock);
        match proxy.query(&mut cx, CfQuery::HostPort) {
            Ok(CfQueryValue::HostPort { host, port }) => {
                assert_eq!(host, "below.example");
                assert_eq!(port, 443);
            }
            other => panic!("expected the chain's answer, got {other:?}"),
        }
    }

    /// `socks_proxy_cf_close` (`lib/socks.c:1339-1347`): clear, then chain.
    #[test]
    fn close_clears_the_context_and_chains_downward() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, log) = primary(&conn, &resolver);
        state.borrow_mut().writable = false;
        assert!(!connect(&mut proxy, &clock).expect("a block is not an error"));
        assert!(proxy.state().is_some());

        let mut cx = CallCtx::new(&clock);
        proxy.close(&mut cx);
        assert!(proxy.state().is_none(), "the context is released");
        assert!(!proxy.base().is_connected());
        assert_eq!(state.borrow().closes, 1, "the close reached the transport");
        assert!(events(&log).contains(&"TRANSPORT:close".to_string()));
    }

    /// `socks_proxy_cf_destroy` (`lib/socks.c:1349-1354`): release, and do NOT
    /// chain.
    #[test]
    fn destroy_releases_the_context_without_chaining() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, log) = primary(&conn, &resolver);
        state.borrow_mut().writable = false;
        assert!(!connect(&mut proxy, &clock).expect("a block is not an error"));

        let mut cx = CallCtx::new(&clock);
        proxy.destroy(&mut cx);
        assert!(proxy.state().is_none());
        assert!(
            !events(&log).contains(&"TRANSPORT:destroy".to_string()),
            "destroy must NOT chain -- the caller owns the rest"
        );
    }

    // -- 9. state transitions, and the terminal states ---------------------

    /// `socksstate()` traces `[old] -> [new]` and returns early when the state
    /// is unchanged (`lib/socks.c:174-189`).
    #[test]
    fn a_state_transition_traces_old_to_new_and_skips_a_repeat() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 80]);

        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        assert!(outcome.expect("must connect"));
        for expected in [
            "[SOCKS_INIT] -> [SOCKS5_START]",
            "[SOCKS5_START] -> [SOCKS5_REQ0_SEND]",
            "[SOCKS5_REQ0_SEND] -> [SOCKS5_RESP0_RECV]",
            "[SOCKS5_RESP0_RECV] -> [SOCKS5_REQ1_INIT]",
            "[SOCKS5_REQ1_INIT] -> [SOCKS5_REQ1_SEND]",
            "[SOCKS5_REQ1_SEND] -> [SOCKS5_RESP1_RECV]",
            "[SOCKS5_RESP1_RECV] -> [SOCKS_SUCCESS]",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected}: {rendered}"
            );
        }
        // A transition to the state already held emits nothing, so no line ever
        // names the same state twice.
        for state in HandshakeState::ALL {
            let repeat = format!("[{0}] -> [{0}]", state.name());
            assert!(!rendered.contains(&repeat), "{repeat} was traced");
        }
    }

    /// A failed handshake answers the same way on every later pass
    /// (`lib/socks.c:580-582`, `:1188-1190`).
    #[test]
    fn a_failed_handshake_reports_the_same_reason_again() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 255]);

        let (first, _rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(first, CURLproxycode::NoAuth);
        assert_eq!(
            proxy.state().map(SocksState::state),
            Some(HandshakeState::Failed)
        );
        // The C's `case SOCKS_ST_FAILED: return sx->presult;`.
        let (again, _rendered) = failed_with(&mut proxy, &clock, &conn);
        assert_eq!(again, CURLproxycode::NoAuth);
    }

    /// The version byte the context records (`lib/socks.c:482`, `:1055`).
    #[test]
    fn the_context_records_which_version_is_in_play() {
        for (proxy_type, version) in
            [(ProxyType::Socks4a, 4_u8), (ProxyType::Socks5Hostname, 5)]
        {
            let conn = TestConn::new();
            conn.set(|facts| {
                facts.proxy_type = proxy_type.as_i32();
                facts.host_name = "h".to_string();
            });
            let resolver = TestResolver::new(Vec::new());
            let clock = clock();
            let (mut proxy, state, _log) = primary(&conn, &resolver);
            state.borrow_mut().writable = false;
            assert!(!connect(&mut proxy, &clock).expect("a block"));
            assert_eq!(
                proxy.state().map(SocksState::version),
                Some(version),
                "{proxy_type:?}"
            );
            assert_eq!(proxy.state().map(SocksState::hostname), Some("h"));
            assert_eq!(proxy.state().map(SocksState::remote_port), Some(80));
        }
    }

    // -- 10. the buffer, and the verbose success line ----------------------

    /// The buffer is sized as `lib/socks.c:93-94` and `:1258-1259` size it.
    #[test]
    fn the_io_buffer_is_one_soft_limited_chunk_of_1024_bytes() {
        assert_eq!(SOCKS_CHUNK_SIZE, 1024);
        assert_eq!(SOCKS_CHUNKS, 1);
        let sx = SocksState::new("h".to_string(), 80, None, None);
        assert_eq!(sx.iobuf.chunk_size(), SOCKS_CHUNK_SIZE);
        assert_eq!(sx.iobuf.max_chunks(), SOCKS_CHUNKS);
        assert!(
            sx.iobuf.opts().contains(BufqOpts::SOFT_LIMIT),
            "BUFQ_OPT_SOFT_LIMIT"
        );
        // The one-chunk-holds-the-longest-reply invariant is asserted at
        // COMPILE time next to the constants themselves, so every build checks
        // it rather than only a test run.
    }

    /// The verbose success line, in both its forms
    /// (`lib/socks.c:1287-1302`).
    #[test]
    fn the_success_line_reports_the_quadruple_when_the_chain_knows_it() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "origin.example".to_string();
            facts.remote_port = 21;
            // A SECONDARY filter's destination is the secondary host and port,
            // which is the FTP data connection the server named.
            facts.secondary_host = Some("target.example".to_string());
            facts.secondary_port = 8080;
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) =
            filter(&conn, &resolver, SocketIndex::Secondary);
        state.borrow_mut().answers.push((
            CfQuery::IpInfo,
            CfQueryValue::IpInfo {
                is_ipv6: false,
                quad: IpQuadruple {
                    remote_ip: "10.0.0.1".to_string(),
                    local_ip: "10.0.0.2".to_string(),
                    remote_port: 1080,
                    local_port: 54_321,
                    transport: crate::conn::Transport::Tcp,
                },
            },
        ));
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        assert!(outcome.expect("must connect"));
        assert!(
            rendered.contains(
                "Opened 2nd SOCKS connection from 10.0.0.2 port 54321 to \
                 target.example port 8080 (via 10.0.0.1 port 1080)"
            ),
            "{rendered}"
        );

        // With no answer from below, the short form.
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let (outcome, rendered) = connect_traced(&mut proxy, &clock);
        assert!(outcome.expect("must connect"));
        assert!(rendered.contains("Opened SOCKS connection"), "{rendered}");
        assert!(
            !rendered.contains("Opened SOCKS connection from"),
            "the short form carries no addresses: {rendered}"
        );
    }

    /// Nothing is written when the transfer is not tracing
    /// (`lib/socks.c:1288`).
    #[test]
    fn the_success_line_is_suppressed_when_not_verbose() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Socks5Hostname.as_i32();
            facts.host_name = "h".to_string();
        });
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, state, _log) = primary(&conn, &resolver);
        feed(&state, &[5, 0]);
        feed(&state, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        let mut config = TraceConfig::new();
        config.set_filter_level(TraceFilter::SocksProxy, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        // Deliberately NOT verbose.
        {
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            assert!(proxy.connect(&mut cx).expect("must connect"));
        }
        let rendered =
            String::from_utf8(sink.into_inner()).expect("trace is text");
        assert!(
            !rendered.contains("Opened"),
            "the success line is verbose-only: {rendered}"
        );
    }

    /// Every frozen message, against the C's own text.
    #[test]
    fn the_frozen_messages_read_exactly_as_the_c_writes_them() {
        assert_eq!(
            msg::send_failed("Failure when receiving data from the peer"),
            "Failed to send SOCKS request: Failure when receiving data from \
             the peer"
        );
        assert_eq!(
            msg::recv_failed("Send failure"),
            "Failed to receive SOCKS response: Send failure"
        );
        assert_eq!(
            msg::RECV_CLOSED,
            "Failed to receive SOCKS response, proxy closed connection"
        );
        assert_eq!(
            msg::socks4_resolve_failed("a.example"),
            "Failed to resolve \"a.example\" for SOCKS4 connect."
        );
        assert_eq!(
            msg::socks5_resolve_failed("a.example"),
            "Failed to resolve \"a.example\" for SOCKS5 connect."
        );
        assert_eq!(
            msg::socks4_unsupported("a.example"),
            "SOCKS4 connection to a.example not supported"
        );
        assert_eq!(
            msg::socks5_unsupported("10.0.0.1"),
            "SOCKS5 connection to 10.0.0.1 not supported"
        );
        assert_eq!(
            msg::SOCKS5_LONG_HOSTNAME,
            "SOCKS5: the destination hostname is too long to be resolved \
             remotely by the proxy."
        );
        assert_eq!(
            msg::unsupported_socks5_auth(5),
            "warning: unsupported value passed to CURLOPT_SOCKS5_AUTH: 5"
        );
        assert_eq!(
            msg::socks5_connect_failed("a.example", 4),
            "cannot complete SOCKS5 connection to a.example. (4)"
        );
        assert_eq!(
            msg::user_rejected(1, 2),
            "User was rejected by the SOCKS5 server (1 2)."
        );
        assert_eq!(
            msg::socks4_rejected(&[0, 91, 0, 80, 1, 2, 3, 4]),
            "[SOCKS] cannot complete SOCKS4 connection to 1.2.3.4:80. (91), \
             request rejected or failed."
        );
        assert_eq!(
            msg::opened(false, "127.0.0.1", 1, "h", 80, "10.0.0.1", 1080),
            "Opened SOCKS connection from 127.0.0.1 port 1 to h port 80 \
             (via 10.0.0.1 port 1080)"
        );
        assert_eq!(msg::opened_short(true), "Opened 2nd SOCKS connection");
        // The two GSS-API refusals are different lines and must stay so.
        assert_ne!(
            msg::SOCKS5_GSSAPI_NOT_ENABLED,
            msg::SOCKS5_GSSAPI_UNSUPPORTED
        );
        assert!(msg::SOCKS5_GSSAPI_NOT_ENABLED.ends_with("not enabled."));
        assert!(msg::SOCKS5_GSSAPI_UNSUPPORTED.ends_with("not supported."));
    }

    /// The port bytes are big-endian, from the low sixteen bits.
    #[test]
    fn the_port_is_written_most_significant_byte_first() {
        assert_eq!(SocksProxy::port_bytes(80), [0x00, 0x50]);
        assert_eq!(SocksProxy::port_bytes(8080), [0x1f, 0x90]);
        assert_eq!(SocksProxy::port_bytes(65_535), [0xff, 0xff]);
        assert_eq!(SocksProxy::port_bytes(0), [0x00, 0x00]);
    }

    /// `Curl_blockread_all` fills its buffer, and reports the deadline it was
    /// given (`lib/socks.c:129-137`).
    #[tokio::test]
    async fn the_blocking_read_refuses_an_expired_deadline() {
        let conn = TestConn::new();
        conn.set(|facts| facts.time_left_ms = -1);
        let resolver = TestResolver::new(Vec::new());
        let clock = clock();
        let (mut proxy, _state, _log) = primary(&conn, &resolver);
        let mut cx = CallCtx::new(&clock);
        let mut buf = [0_u8; 4];
        let error = proxy
            .blockread_all(&mut cx, &mut buf)
            .await
            .expect_err("an elapsed deadline is a timeout");
        assert_eq!(error.code(), CURLcode::OperationTimedout);
    }
}
