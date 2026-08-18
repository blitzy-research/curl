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

//! Proxy support: tunnelling, SOCKS, the PROXY protocol header, and the
//! no-proxy predicate.
//!
//! Supersedes `lib/http_proxy.c` with `lib/cf-h1-proxy.c` and
//! `lib/cf-h2-proxy.c` (CONNECT tunnelling over HTTP/1 and HTTP/2),
//! `lib/socks.c` (SOCKS4 and SOCKS5), `lib/socks_gssapi.c` (behind the
//! default-off `negotiate` feature), `lib/cf-haproxy.c` (the PROXY protocol
//! header) and `lib/noproxy.c` (`NO_PROXY` matching) -- the six files the
//! transformation map assigns to this directory's six modules.
//!
//! # Five filters and one predicate
//!
//! Every other module here is a connection filter in the chain that
//! [`crate::conn`] owns, which is why proxying needs no special case in the
//! protocol layer: a tunnelled connection and a direct one present the same
//! interface to the scheme above them. `lib/cfilters.h` gives the C's filters
//! `CF_TYPE_PROXY` in their type bitmap for exactly that reason.
//!
//! [`noproxy`] is the exception and is deliberately not a filter. It is a
//! pure predicate over two byte strings, consulted BEFORE any filter is
//! inserted, and its answer decides whether the proxy filters are built at
//! all. That ordering is the whole of the proxy-bypass mechanism, and it is
//! why the module that implements it owns no state, no socket and no place in
//! the chain.
//!
//! `pub(crate)`, and so is everything it declares: a proxy is configured
//! through options -- `CURLOPT_PROXY`, `CURLOPT_NOPROXY`,
//! `CURLOPT_PROXYTYPE` and their relatives -- and observed through
//! `CURLINFO_*`, so no exported symbol of `lib/libcurl.def` is backed from
//! this directory directly.

/// `NO_PROXY` and `--noproxy` host matching -- supersedes `lib/noproxy.c` and
/// `lib/noproxy.h`.
///
/// The first module of this directory to land, and the only one with no
/// dependency on the filter chain: `grep -n 'cfilters\.h\|Curl_cf' lib/
/// noproxy.c lib/noproxy.h` returns nothing, and its two includes are
/// `curlx/inet_pton.h` and `curlx/strparse.h`. So it rests on
/// [`crate::util`] alone and can be built and tested before anything else
/// here exists.
///
/// No `#[allow(dead_code)]` on this declaration, deliberately: a lint level
/// for `dead_code` on a module root would also silence the next unreferenced
/// item somebody adds. The allowance belongs on the ITEM whose consumer has
/// yet to land, which is where `noproxy::check_noproxy` carries it.
pub(crate) mod noproxy;

/// SOCKS4, SOCKS4a, SOCKS5 and SOCKS5h -- supersedes `lib/socks.c` and
/// `lib/socks.h`.
///
/// The `"SOCKS"` connection filter (`lib/socks.c:1385`), and the first module
/// of this directory that takes a place in the chain. It reaches
/// [`CURLproxycode`] below for every handshake failure it reports, which is
/// why that type is declared here rather than inside it: `lib/socks_gssapi.c`
/// returns the same codes, so one directory-level declaration serves both
/// modules and neither can drift from the other.
pub(crate) mod socks;

/// The PROXY protocol version 1 header -- supersedes `lib/cf-haproxy.c` and
/// `lib/cf-haproxy.h`.
///
/// The smallest filter of this directory and the only one that negotiates
/// nothing: it writes one ASCII line at the head of the connection and is then
/// transparent, which is why it overrides four of the twelve filter operations
/// and leaves the other eight to [`crate::conn::filters::ConnFilter`]'s
/// pass-through defaults.
///
/// No feature gate, deliberately. `lib/cf-haproxy.h` is guarded by
/// `#ifndef CURL_DISABLE_PROXY` and by no HTTP guard, because the PROXY
/// protocol precedes FTP and raw TCP as readily as HTTP -- so a `cfg` feature
/// attribute here would delete a protocol-agnostic filter from builds that
/// need it.
pub(crate) mod haproxy;

/// `CURLAUTH_BASIC` (`include/curl/curl.h:829`) = `1 << 0`, narrowed to the
/// width the SOCKS5 option actually occupies.
///
/// # Why this is a `u8` and not [`crate::auth::AuthMask`]
///
/// `struct UserDefined::socks5auth` is declared `uint8_t`
/// (`lib/urldata.h:1362`) and `socks5_req0_init` reads it into an
/// `unsigned char` (`lib/socks.c:594`). The whole `CURLAUTH_*` space is
/// `unsigned long` and holds ten named bits, but the two below are the only
/// ones `CURLOPT_SOCKS5_AUTH` can carry, and anything else is diagnosed
/// rather than honoured -- see `socks::msg::unsupported_socks5_auth`. Modelling
/// the field at its real width keeps that diagnosis exact: a value that would
/// not fit the C field cannot reach this code in the first place.
pub(crate) const SOCKS5_AUTH_BASIC: u8 = 1 << 0;

/// `CURLAUTH_GSSAPI` = `CURLAUTH_NEGOTIATE` = `1 << 2`
/// (`include/curl/curl.h:831`, `:835`), at the SOCKS5 option's width.
///
/// The alias is deliberate on curl's side and matters here: `#define
/// CURLAUTH_GSSAPI CURLAUTH_NEGOTIATE` means the GSS-API bit IS the Negotiate
/// bit, so `1 << 1` is skipped and the two SOCKS5 bits are 1 and 4 -- never 1
/// and 2.
pub(crate) const SOCKS5_AUTH_GSSAPI: u8 = 1 << 2;

/// The default `CURLOPT_SOCKS5_AUTH`: **both** mechanisms enabled.
///
/// `set->socks5auth = CURLAUTH_BASIC | CURLAUTH_GSSAPI` (`lib/url.c:388`),
/// numerically 5. Frozen by AAP section 0.8.1, which places default option
/// values outside this migration's authority, so the value is stated once here
/// and consumed rather than recomputed at a call site.
#[allow(dead_code)] // consumer: the SocksConn implementor in crate::conn
pub(crate) const SOCKS5_AUTH_DEFAULT: u8 =
    SOCKS5_AUTH_BASIC | SOCKS5_AUTH_GSSAPI;

/// Every failure a proxy handshake can report -- `CURLproxycode`
/// (`include/curl/curl.h`), surfaced to an application through
/// `CURLINFO_PROXY_ERROR`.
///
/// # Why the discriminants are written out
///
/// The C enumeration assigns no value to any member, so every one of the
/// thirty-five takes its integer from declaration order, and
/// `getinfo.c:318` hands that integer straight to an application as a `long`.
/// A member inserted, removed or reordered would therefore change the meaning
/// of a number a caller has already compiled against. Each discriminant is
/// stated explicitly for the same reason `CURLcode`'s are
/// (`crate::error::CURLcode`): ordinal inference is what makes such a change
/// silent, and writing the integer makes it impossible.
///
/// # Naming
///
/// The type keeps its ABI name and the members take Rust-idiomatic ones, which
/// is the convention `crate::error` established for the four exported code
/// families. The C spelling of each member is recoverable through
/// [`Self::c_name`], so the frozen token appears exactly once per member and a
/// test can compare this table against the header without a second
/// hand-maintained list. `curl-rs-ffi`'s own `CURLproxycode` carries the C
/// spellings as its member names, for the header cbindgen generates; the two
/// are checked against each other by the integers, which is the only thing an
/// application can observe.
///
/// `CURLPX_LAST` is included because it is part of the frozen enumeration and
/// omitting it would make this table an incomplete description of the header.
/// It is never returned; `lib/socks.c` never names it.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(i32)]
#[allow(dead_code)] // Members are used as the SOCKS handshake reaches them.
pub(crate) enum CURLproxycode {
    /// `CURLPX_OK` = 0. The success member, and the only one that is not a
    /// failure.
    #[default]
    Ok = 0,
    /// `CURLPX_BAD_ADDRESS_TYPE` = 1.
    BadAddressType = 1,
    /// `CURLPX_BAD_VERSION` = 2.
    BadVersion = 2,
    /// `CURLPX_CLOSED` = 3.
    Closed = 3,
    /// `CURLPX_GSSAPI` = 4.
    Gssapi = 4,
    /// `CURLPX_GSSAPI_PERMSG` = 5.
    GssapiPermsg = 5,
    /// `CURLPX_GSSAPI_PROTECTION` = 6.
    GssapiProtection = 6,
    /// `CURLPX_IDENTD` = 7.
    Identd = 7,
    /// `CURLPX_IDENTD_DIFFER` = 8.
    IdentdDiffer = 8,
    /// `CURLPX_LONG_HOSTNAME` = 9.
    LongHostname = 9,
    /// `CURLPX_LONG_PASSWD` = 10.
    LongPasswd = 10,
    /// `CURLPX_LONG_USER` = 11.
    LongUser = 11,
    /// `CURLPX_NO_AUTH` = 12.
    NoAuth = 12,
    /// `CURLPX_RECV_ADDRESS` = 13.
    RecvAddress = 13,
    /// `CURLPX_RECV_AUTH` = 14.
    RecvAuth = 14,
    /// `CURLPX_RECV_CONNECT` = 15.
    RecvConnect = 15,
    /// `CURLPX_RECV_REQACK` = 16.
    RecvReqack = 16,
    /// `CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED` = 17.
    ReplyAddressTypeNotSupported = 17,
    /// `CURLPX_REPLY_COMMAND_NOT_SUPPORTED` = 18.
    ReplyCommandNotSupported = 18,
    /// `CURLPX_REPLY_CONNECTION_REFUSED` = 19.
    ReplyConnectionRefused = 19,
    /// `CURLPX_REPLY_GENERAL_SERVER_FAILURE` = 20.
    ReplyGeneralServerFailure = 20,
    /// `CURLPX_REPLY_HOST_UNREACHABLE` = 21.
    ReplyHostUnreachable = 21,
    /// `CURLPX_REPLY_NETWORK_UNREACHABLE` = 22.
    ReplyNetworkUnreachable = 22,
    /// `CURLPX_REPLY_NOT_ALLOWED` = 23.
    ReplyNotAllowed = 23,
    /// `CURLPX_REPLY_TTL_EXPIRED` = 24.
    ReplyTtlExpired = 24,
    /// `CURLPX_REPLY_UNASSIGNED` = 25.
    ReplyUnassigned = 25,
    /// `CURLPX_REQUEST_FAILED` = 26.
    RequestFailed = 26,
    /// `CURLPX_RESOLVE_HOST` = 27.
    ResolveHost = 27,
    /// `CURLPX_SEND_AUTH` = 28.
    SendAuth = 28,
    /// `CURLPX_SEND_CONNECT` = 29.
    SendConnect = 29,
    /// `CURLPX_SEND_REQUEST` = 30.
    SendRequest = 30,
    /// `CURLPX_UNKNOWN_FAIL` = 31.
    UnknownFail = 31,
    /// `CURLPX_UNKNOWN_MODE` = 32.
    UnknownMode = 32,
    /// `CURLPX_USER_REJECTED` = 33.
    UserRejected = 33,
    /// `CURLPX_LAST` = 34 -- *"never use"*.
    Last = 34,
}

impl CURLproxycode {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The one place a test reads, so the comparison against the frozen header
    /// needs no second list that could drift on its own.
    #[allow(dead_code)] // Read by this module's own tests.
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLPX_OK", 0),
        ("CURLPX_BAD_ADDRESS_TYPE", 1),
        ("CURLPX_BAD_VERSION", 2),
        ("CURLPX_CLOSED", 3),
        ("CURLPX_GSSAPI", 4),
        ("CURLPX_GSSAPI_PERMSG", 5),
        ("CURLPX_GSSAPI_PROTECTION", 6),
        ("CURLPX_IDENTD", 7),
        ("CURLPX_IDENTD_DIFFER", 8),
        ("CURLPX_LONG_HOSTNAME", 9),
        ("CURLPX_LONG_PASSWD", 10),
        ("CURLPX_LONG_USER", 11),
        ("CURLPX_NO_AUTH", 12),
        ("CURLPX_RECV_ADDRESS", 13),
        ("CURLPX_RECV_AUTH", 14),
        ("CURLPX_RECV_CONNECT", 15),
        ("CURLPX_RECV_REQACK", 16),
        ("CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED", 17),
        ("CURLPX_REPLY_COMMAND_NOT_SUPPORTED", 18),
        ("CURLPX_REPLY_CONNECTION_REFUSED", 19),
        ("CURLPX_REPLY_GENERAL_SERVER_FAILURE", 20),
        ("CURLPX_REPLY_HOST_UNREACHABLE", 21),
        ("CURLPX_REPLY_NETWORK_UNREACHABLE", 22),
        ("CURLPX_REPLY_NOT_ALLOWED", 23),
        ("CURLPX_REPLY_TTL_EXPIRED", 24),
        ("CURLPX_REPLY_UNASSIGNED", 25),
        ("CURLPX_REQUEST_FAILED", 26),
        ("CURLPX_RESOLVE_HOST", 27),
        ("CURLPX_SEND_AUTH", 28),
        ("CURLPX_SEND_CONNECT", 29),
        ("CURLPX_SEND_REQUEST", 30),
        ("CURLPX_UNKNOWN_FAIL", 31),
        ("CURLPX_UNKNOWN_MODE", 32),
        ("CURLPX_USER_REJECTED", 33),
        ("CURLPX_LAST", 34),
    ];

    /// Every member, in the header's declaration order.
    #[allow(dead_code)] // Read by this module's own tests.
    pub(crate) const VARIANTS: &'static [Self] = &[
        Self::Ok,
        Self::BadAddressType,
        Self::BadVersion,
        Self::Closed,
        Self::Gssapi,
        Self::GssapiPermsg,
        Self::GssapiProtection,
        Self::Identd,
        Self::IdentdDiffer,
        Self::LongHostname,
        Self::LongPasswd,
        Self::LongUser,
        Self::NoAuth,
        Self::RecvAddress,
        Self::RecvAuth,
        Self::RecvConnect,
        Self::RecvReqack,
        Self::ReplyAddressTypeNotSupported,
        Self::ReplyCommandNotSupported,
        Self::ReplyConnectionRefused,
        Self::ReplyGeneralServerFailure,
        Self::ReplyHostUnreachable,
        Self::ReplyNetworkUnreachable,
        Self::ReplyNotAllowed,
        Self::ReplyTtlExpired,
        Self::ReplyUnassigned,
        Self::RequestFailed,
        Self::ResolveHost,
        Self::SendAuth,
        Self::SendConnect,
        Self::SendRequest,
        Self::UnknownFail,
        Self::UnknownMode,
        Self::UserRejected,
        Self::Last,
    ];

    /// The pinned integer, as `CURLINFO_PROXY_ERROR` reports it.
    #[allow(dead_code)] // curl-rs-ffi converts through it.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Whether this is the success member, mirroring the C's `if(presult)`.
    #[allow(dead_code)] // Read by the SOCKS state machine.
    pub(crate) const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// The member with this integer, or [`None`] for anything undefined.
    #[allow(dead_code)] // Read by this module's own tests.
    pub(crate) fn from_i32(raw: i32) -> Option<Self> {
        Self::VARIANTS
            .iter()
            .copied()
            .find(|code| code.as_i32() == raw)
    }

    /// The C identifier for this member.
    ///
    /// Derived from [`Self::ABI_VARIANTS`] by position, so the frozen spelling
    /// exists once. The index is in range by construction -- both tables are
    /// generated from the same declaration order and a test asserts their
    /// lengths agree -- and the fallback is the empty string rather than a
    /// panic, because a name is diagnostic output and must not be able to take
    /// a transfer down.
    #[allow(dead_code)] // Read by this module's own tests.
    pub(crate) fn c_name(self) -> &'static str {
        match Self::ABI_VARIANTS.get(self as usize) {
            Some((name, _)) => name,
            None => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The integers `CURLINFO_PROXY_ERROR` reports, against the header.
    ///
    /// Spot-checked at both ends and across the RFC 1928 reply block, which is
    /// the run `lib/socks.c:993-1003` indexes by reply code: an insertion
    /// anywhere in it would silently retarget that lookup.
    #[test]
    fn proxy_code_integers_are_pinned_to_the_header() {
        assert_eq!(CURLproxycode::Ok.as_i32(), 0);
        assert_eq!(CURLproxycode::BadAddressType.as_i32(), 1);
        assert_eq!(CURLproxycode::GssapiProtection.as_i32(), 6);
        assert_eq!(CURLproxycode::LongHostname.as_i32(), 9);
        assert_eq!(CURLproxycode::NoAuth.as_i32(), 12);
        assert_eq!(CURLproxycode::RecvConnect.as_i32(), 15);
        assert_eq!(CURLproxycode::ReplyUnassigned.as_i32(), 25);
        assert_eq!(CURLproxycode::RequestFailed.as_i32(), 26);
        assert_eq!(CURLproxycode::SendRequest.as_i32(), 30);
        assert_eq!(CURLproxycode::UserRejected.as_i32(), 33);
        assert_eq!(CURLproxycode::Last.as_i32(), 34);
    }

    /// The two tables describe the same enumeration.
    #[test]
    fn the_variant_tables_agree_with_each_other() {
        assert_eq!(
            CURLproxycode::VARIANTS.len(),
            CURLproxycode::ABI_VARIANTS.len(),
            "one table gained a member the other did not"
        );
        assert_eq!(CURLproxycode::VARIANTS.len(), 35);
        for (index, code) in CURLproxycode::VARIANTS.iter().enumerate() {
            let (name, value) = CURLproxycode::ABI_VARIANTS[index];
            assert_eq!(
                code.as_i32(),
                value,
                "{name} sits at a different integer in the two tables"
            );
            assert_eq!(code.c_name(), name);
            assert_eq!(CURLproxycode::from_i32(value), Some(*code));
        }
        assert_eq!(CURLproxycode::from_i32(35), None);
        assert_eq!(CURLproxycode::from_i32(-1), None);
    }

    /// Only the success member is success, and it is also the default.
    #[test]
    fn only_the_ok_member_is_success() {
        assert!(CURLproxycode::Ok.is_ok());
        assert_eq!(CURLproxycode::default(), CURLproxycode::Ok);
        for code in CURLproxycode::VARIANTS.iter().skip(1) {
            assert!(!code.is_ok(), "{} is not success", code.c_name());
        }
    }

    /// `CURLAUTH_GSSAPI` aliases `CURLAUTH_NEGOTIATE`, so the default is 5.
    #[test]
    fn the_socks5_auth_default_is_both_mechanisms() {
        assert_eq!(SOCKS5_AUTH_BASIC, 1);
        assert_eq!(SOCKS5_AUTH_GSSAPI, 4, "1 << 2, never 1 << 1");
        assert_eq!(SOCKS5_AUTH_DEFAULT, 5, "lib/url.c:388");
        assert_ne!(SOCKS5_AUTH_DEFAULT & SOCKS5_AUTH_BASIC, 0);
        assert_ne!(SOCKS5_AUTH_DEFAULT & SOCKS5_AUTH_GSSAPI, 0);
    }
}
