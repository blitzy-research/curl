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
//! This module is `pub(crate)`, and so is everything it declares: a proxy is
//! configured through options -- `CURLOPT_PROXY`, `CURLOPT_NOPROXY`,
//! `CURLOPT_PROXYTYPE` and their relatives -- and observed through
//! `CURLINFO_*`, so no exported symbol of `lib/libcurl.def` is backed from
//! this directory directly.
//!
//! # The six `CF_TYPE_PROXY` filters, and the one that lives elsewhere
//!
//! `CF_TYPE_PROXY` is `1 << 3` (`lib/cfilters.h:206`) and six registered
//! filter types carry it. They form ONE set -- a chain can hold several at
//! once -- but only five are implemented in this directory. Each `name`
//! literal below was read out of the C and is reproduced verbatim, because
//! `--trace-config` matches on it and `--trace` prints it, so a changed
//! spelling is an OBSERVABLE change and AAP section 0.8.1 places those
//! outside this migration's authority. [`crate::trace::TraceFilter`] holds the
//! same six strings and a test there compares them.
//!
//! Each entry is `name` -- C type, `flags`, `log_level`, and the module that
//! implements it. `IP_CONNECT`, `SSL` and `PROXY` abbreviate the
//! `CF_TYPE_` constants of `lib/cfilters.h:203-207`.
//!
//! * `"SOCKS"` -- `Curl_cft_socks_proxy` (`lib/socks.c:1384`),
//!   `IP_CONNECT | PROXY`, `0`, in [`socks`].
//! * `"HAPROXY"` -- `Curl_cft_haproxy` (`lib/cf-haproxy.c:186`),
//!   `PROXY`, `0`, in [`haproxy`].
//! * `"H1-PROXY"` -- `Curl_cft_h1_proxy` (`lib/cf-h1-proxy.c:757`),
//!   `IP_CONNECT | PROXY`, `0`, in [`http_connect`].
//! * `"H2-PROXY"` -- `Curl_cft_h2_proxy` (`lib/cf-h2-proxy.c:1461`),
//!   `IP_CONNECT | PROXY`, `CURL_LOG_LVL_NONE`, in [`http_connect`].
//! * `"HTTP-PROXY"` -- `Curl_cft_http_proxy` (`lib/http_proxy.c:395`),
//!   `IP_CONNECT | PROXY`, `0`, in [`http_connect`].
//! * `"SSL-PROXY"` -- `Curl_cft_ssl_proxy` (`lib/vtls/vtls.c:1687`),
//!   `SSL | PROXY`, `CURL_LOG_LVL_NONE`, in `crate::tls` and NOT here.
//!
//! Two entries in that list are routinely got wrong, so both are recorded
//! as measurements rather than as recollections:
//!
//! * The SOCKS filter is named `"SOCKS"`, NOT `"SOCKS-PROXY"`. It is the one
//!   proxy filter whose label omits the word, and `lib/socks.c:1385` is the
//!   whole of the evidence.
//! * `"H2-PROXY"` does NOT carry `CF_TYPE_MULTIPLEX`, even though it speaks
//!   HTTP/2. Its flags are `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY` and nothing
//!   more, because what it multiplexes is the tunnel's own stream and not the
//!   easy handles above it -- the origin connection layered on top is a
//!   single stream carried as HTTP/2 `DATA`.
//!
//! `"SSL-PROXY"` is the one entry naming another directory, and deliberately
//! so. It is `lib/vtls/vtls.c`'s filter, not a proxy one: TLS to the proxy is
//! the SAME state machine as TLS to the origin, differing only in which
//! hostname is verified and which credential set is used, so duplicating it
//! here would duplicate the TLS backend. What this directory owns is the
//! DECISION that it is needed -- [`crate::conn::ProxyType::is_https`], the
//! successor of `IS_HTTPS_PROXY` -- and what it does with the encrypted
//! transport once it exists.
//!
//! # The chain, top to bottom
//!
//! `SetupFilter` (`crate::conn`) installs every stage IMMEDIATELY BELOW
//! itself, so the chain reads in the REVERSE of the order the stages run.
//! That inversion is the single fact about proxying here most likely to be
//! misread, so it is written out. The seven states are `Init`,
//! `CnnctEyeballs`, `CnnctSocks`, `CnnctHttpProxy`, `CnnctHaproxy`,
//! `CnnctSsl`, `Done` (`cf_setup_state`, `lib/connect.c:324-332`), and the
//! chain they leave behind is:
//!
//! ```text
//! SETUP
//!   -> SSL             origin TLS          crate::tls
//!   -> HAPROXY         PROXY protocol      proxy::haproxy
//!   -> HTTP-PROXY      CONNECT tunnel      proxy::http_connect
//!   -> SSL-PROXY       TLS to the proxy    crate::tls
//!   -> SOCKS           SOCKS handshake     proxy::socks
//!   -> HAPPY-EYEBALLS  address racing      crate::conn::happy_eyeballs
//!   -> TCP | UDP | UNIX | QUIC             the winning transport
//! ```
//!
//! Read downwards that is the order bytes travel outbound, which is why
//! `"SSL-PROXY"` sits BELOW `"HTTP-PROXY"`: the `CONNECT` request is written
//! into an already-encrypted transport when the proxy speaks HTTPS. Read
//! upwards it is the order the stages were run. `crate::conn` refuses one
//! combination outright rather than ordering it -- the PROXY protocol on a
//! chain that is already TLS-protected -- with the frozen diagnostic
//! `crate::conn::HAPROXY_AFTER_SSL`.
//!
//! # What this directory does NOT declare
//!
//! Four proxy facts belong to the module that first needed them, and are
//! consumed from there rather than restated here. Naming them once matters:
//! a second declaration of any of them would be a second source of truth for
//! a value the public ABI pins, and the two could then disagree. AAP section
//! 0.1.2 states that requirement for the option table, in the same terms and
//! for the same reason -- *"a single Rust module is the sole source of truth"*
//! -- and it applies here unchanged.
//!
//! * `curl_proxytype` (`include/curl/curl.h:790-807`) is
//!   [`crate::conn::ProxyType`]. Its integers are public ABI, because
//!   `CURLOPT_PROXYTYPE` takes them from an application: `CURLPROXY_HTTP` 0,
//!   `HTTP_1_0` 1, `HTTPS` 2, `HTTPS2` 3, `SOCKS4` 4, `SOCKS5` 5, `SOCKS4A`
//!   6, `SOCKS5_HOSTNAME` 7, with `CURLPROXY_LAST` 8 rejected. Note the
//!   ordering: `SOCKS5` sits BETWEEN `SOCKS4` and `SOCKS4A`, because 4 and 5
//!   were the two original values and 6 was added later.
//! * `IS_HTTPS_PROXY(t)` (`lib/http_proxy.h:61-62`) is
//!   [`crate::conn::ProxyType::is_https`], with
//!   [`http_connect::is_https_proxy`] as the free-function spelling the
//!   tunnel reads. Exactly two types satisfy it, `CURLPROXY_HTTPS` and
//!   `CURLPROXY_HTTPS2`; `CURLPROXY_HTTP_1_0` does not, since it pins the
//!   `CONNECT` request's HTTP version and says nothing about transport
//!   security. The C declares the macro OUTSIDE its
//!   `!CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP` guard -- the guard closes at
//!   `lib/http_proxy.h:59` and the macro follows it -- so the predicate is
//!   unconditional, and nothing in this directory may gate it on a feature.
//! * `PROXY_TIMEOUT` (`lib/http_proxy.h:48`), `3600 * 1000` milliseconds, is
//!   [`http_connect::PROXY_TIMEOUT`]. One hour, and it bounds the `CONNECT`
//!   exchange rather than the transfer.
//! * `enum Curl_proxy_use` (`lib/http_proxy.h:32-36`) is
//!   [`http_connect::ProxyUse`]. Its three members select which custom-header
//!   list is injected, and the selection is ASYMMETRIC: `HEADER_SERVER` takes
//!   the ordinary list; `HEADER_PROXY` takes the ordinary list AND the proxy
//!   list when `CURLOPT_HEADEROPT` separated them; `HEADER_CONNECT` takes
//!   exactly ONE list, the proxy list if they were separated and the ordinary
//!   list otherwise.
//!
//! Two scheme-registry options are likewise consumed and never redefined.
//! Both are bits of [`crate::conn::ProtocolOptions`], set per scheme by
//! `crate::protocols`:
//!
//! * `PROTOPT_PROXY_AS_HTTP` = `1 << 11` (`lib/urldata.h:547`), "allow this
//!   non-HTTP scheme over a HTTP proxy". FTP sets it, which is what makes an
//!   `ftp://` URL through an HTTP proxy an HTTP request rather than an FTP
//!   session, and [`http_connect`] is where that is acted on.
//! * `PROTOPT_NOTCPPROXY` = `1 << 14` (`lib/urldata.h:554`), "this protocol
//!   cannot proxy over TCP". [`http_connect`] enforces it when the tunnel
//!   initialises, reporting `"%s cannot be done over CONNECT"` with
//!   [`crate::error::CURLcode::UnsupportedProtocol`].
//!
//! # The state a proxied connection carries
//!
//! `struct connectdata` holds TWO proxy descriptors at once -- `socks_proxy`
//! (`lib/urldata.h:628`) and `http_proxy` (`:629`), each a
//! `struct proxy_info { struct hostname host; uint16_t port;
//! uint8_t proxytype; char *user; char *passwd; }` (`:586-592`) -- plus
//! `socks5_gssapi_enctype` (`:704`). Both being present simultaneously is not
//! redundancy; it is what makes SOCKS-through-an-HTTP-proxy expressible, and
//! it is why the chain above can hold `"SOCKS"` and `"HTTP-PROXY"` together.
//!
//! Five `ConnectBits` members describe the arrangement, in the C's
//! declaration order: `httpproxy`, `socksproxy`, `proxy_user_passwd`,
//! `tunnel_proxy` -- implicit whenever a TLS scheme goes through a proxy, and
//! settable outright by an application -- and `proxy`, meaning a proxy of any
//! type at all, which is what `CONN_IS_PROXIED(x)` reads.
//! `CURL_CONN_HOST_DISPNAME(c)` (`:732-736`) picks the name a diagnostic
//! prints, preferring `socksproxy`, then `httpproxy`, then `conn_to_host`,
//! then `host`.
//!
//! None of that is reproduced as one struct here. Each filter holds the facts
//! it reads, injected as a seam at construction, which is why
//! [`socks::SocksConn`] and [`http_connect::TunnelConn`] exist and why no
//! module in this directory can reach the connection that owns it.
//!
//! # How a proxy failure is reported
//!
//! Two codes travel together and neither replaces the other. A SOCKS
//! handshake failure returns [`crate::error::CURLcode::Proxy`] -- `CURLE_PROXY`
//! = 97, which is what `curl_easy_perform` reports -- while the specific
//! [`CURLproxycode`] is stored for `CURLINFO_PROXY_ERROR`
//! (`CURLINFO_LONG + 59`, `include/curl/curl.h:2983`) to retrieve. The C
//! writes both in the same two lines -- `result = CURLE_PROXY;
//! data->info.pxcode = pxresult;` (`lib/socks.c:1280-1281`) -- and
//! [`socks::SocksConn::set_proxy_code`] is the second of them here.
//!
//! One asymmetry in the C is worth recording because it looks like an
//! oversight and is not: the `default:` arm that rejects a non-SOCKS proxy
//! type returns `CURLE_COULDNT_CONNECT` and does NOT touch `pxcode`
//! (`lib/socks.c:1273-1276`), so `CURLINFO_PROXY_ERROR` keeps whatever it
//! held. [`socks`] reproduces that.
//!
//! # `HTTPS-proxy` is advertised only if it is true
//!
//! `SSLSUPP_HTTPS_PROXY` is `1 << 4` (`lib/vtls/vtls.h:39`) and curl's own
//! rustls backend sets it (`lib/vtls/rustls.c:1397-1406`), so tunnelling
//! through a TLS-protected proxy is a supported path here rather than an
//! aspiration. The banner entry is nevertheless COMPUTED and not static:
//! `FEATURE("HTTPS-proxy", https_proxy_present, CURL_VERSION_HTTPS_PROXY)`
//! (`lib/version.c:490`) names a function, and that function is
//! `return Curl_ssl_supports(NULL, SSLSUPP_HTTPS_PROXY);` (`:420-424`).
//! [`crate::version`] keeps that shape: the claim is held behind a predicate
//! of its own rather than behind a constant, so the TLS backend's answer has
//! exactly one place to be given and this directory does not assert it.
//!
//! That distinction is worth the words because `tests/runtests.pl` parses
//! `curl --version` and gates fixtures on what it finds, and the asymmetry is
//! decisive (AAP section 0.6.5): under-reporting a capability makes a fixture
//! SKIP, while over-reporting makes it RUN and FAIL. Withholding a claim is
//! therefore always safe and asserting one never is.

use core::fmt;

use crate::conn::filters::{link, CallCtx, ConnId, FilterLink, SocketIndex};
use crate::conn::ProxyType;
use crate::error::{CURLcode, CurlResult, Error};
use crate::proxy::haproxy::{Haproxy, HaproxyConfig};
use crate::proxy::http_connect::{HttpProxy, TunnelSeams};
use crate::proxy::socks::{SocksProxy, SocksSeams};

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

/// SOCKS5 GSS-API authentication, RFC 1961 -- supersedes
/// `lib/socks_gssapi.c`.
///
/// Not a filter: the exchange is a helper the `"SOCKS"` filter runs from inside
/// its own connect path, reached through the [`socks::GssapiNegotiator`] seam
/// so that neither module has to know how the other is built.
///
/// The feature gate IS the C's `#if defined(HAVE_GSSAPI) &&
/// !defined(CURL_DISABLE_PROXY)` (`lib/socks_gssapi.c:27`), and `negotiate` is
/// **off by default** (AAP sections 0.5.2 and 0.8.3): the default build links no
/// C security library at all, and `crate::version` withholds `GSS-API`,
/// `SPNEGO` and `Kerberos` from the `Features:` banner accordingly, so the
/// fixtures that gate on them skip legitimately rather than run and fail.
/// AAP section 0.8.5's conflict C2 records why that does not breach the
/// no-C-TLS mandate: GSS-API is an authentication mechanism, not a TLS library.
///
/// The gate is applied here, once. The module itself is not gated internally.
#[cfg(feature = "negotiate")]
pub(crate) mod socks_gss;

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

/// HTTP `CONNECT` tunnelling -- supersedes `lib/http_proxy.c`,
/// `lib/http_proxy.h`, `lib/cf-h1-proxy.c`, `lib/cf-h1-proxy.h`,
/// `lib/cf-h2-proxy.c` and `lib/cf-h2-proxy.h`.
///
/// Three filters live there, not one, because the C registers three:
/// `"HTTP-PROXY"` dispatches on the negotiated ALPN and then installs either
/// `"H1-PROXY"` -- a six-state machine that reads the `CONNECT` response one
/// byte at a time -- or `"H2-PROXY"`, a five-state machine that carries the
/// tunnelled traffic as HTTP/2 DATA for the life of the connection. They share
/// the request builder and the `CF_QUERY_HOST_PORT` answer, which is why they
/// share a module.
///
/// No feature gate on the module. `lib/http_proxy.h` is guarded by
/// `#ifndef CURL_DISABLE_PROXY` alone, and HTTPS-proxy support is
/// unconditional here because rustls is the only TLS backend. Only the HTTP/2
/// tunnel is gated, on `http2`, mirroring the C's `USE_NGHTTP2`.
pub(crate) mod http_connect;

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

/// Whether a proxy type is one the SOCKS filter can speak.
///
/// The four SOCKS members of [`ProxyType`], and only those. This is the
/// question `lib/socks.c:1262-1277` asks before dispatching:
/// `CURLPROXY_SOCKS5` and `CURLPROXY_SOCKS5_HOSTNAME` reach
/// `socks5_connect`, `CURLPROXY_SOCKS4` and `CURLPROXY_SOCKS4A` reach
/// `socks4_connect`, and anything else falls to the `default:` arm that
/// reports *"unknown proxytype option given"*.
///
/// That arm is REACHABLE and must stay so: the filter can be installed while
/// `CURLOPT_PROXYTYPE` names an HTTP proxy, so a false answer here is a real
/// configuration to diagnose rather than an impossible one. It is also why
/// [`socks::SocksConn::proxy_type`] hands back a raw `i32` and compares it
/// against [`ProxyType::as_i32`] instead of taking this narrowed type: a
/// pre-narrowed seam could not carry the value that needs diagnosing.
#[allow(dead_code)] // Read by this module's own tests.
pub(crate) const fn is_socks_proxy(proxy_type: ProxyType) -> bool {
    matches!(
        proxy_type,
        ProxyType::Socks4
            | ProxyType::Socks5
            | ProxyType::Socks4a
            | ProxyType::Socks5Hostname
    )
}

/// Which end resolves the destination hostname, for a SOCKS proxy.
///
/// [`Some(true)`](Some) means THIS end resolves it and sends an address;
/// [`Some(false)`](Some) means the name goes to the proxy and the proxy
/// resolves it. [`None`] is not a SOCKS proxy at all, where the question has
/// no answer -- see below for why that is a third case and not a `false`.
///
/// # The distinction is command-line visible
///
/// | type | scheme | resolved by |
/// |---|---|---|
/// | `CURLPROXY_SOCKS4` | `socks4://` | this end |
/// | `CURLPROXY_SOCKS4A` | `socks4a://` | the proxy |
/// | `CURLPROXY_SOCKS5` | `socks5://` | this end |
/// | `CURLPROXY_SOCKS5_HOSTNAME` | `socks5h://` | the proxy |
///
/// `socks5` and `socks5h` differ in nothing else, and the difference is the
/// user's to make: it decides whether the destination name is ever looked up
/// locally, which is exactly what somebody proxying to reach a name their own
/// resolver cannot see is choosing. So the two are never normalised together.
///
/// The C states each half separately and this function is their union:
/// `sx->resolve_local = (cf->conn->socks_proxy.proxytype == CURLPROXY_SOCKS5)`
/// for the SOCKS5 machine, and `sx->socks4a = (... == CURLPROXY_SOCKS4A)` with
/// `sx->resolve_local = !sx->socks4a` for the SOCKS4 one.
///
/// # Why the non-SOCKS answer is `None`
///
/// An HTTP proxy resolves nothing on the client's behalf, so neither `true`
/// nor `false` describes it, and the C never asks: it reaches the assignment
/// only after the version dispatch has already established a SOCKS type.
/// Returning [`None`] keeps that ordering in the type instead of leaving a
/// meaningless `false` for a caller to act on.
#[allow(dead_code)] // Read by this module's own tests.
pub(crate) const fn socks_resolves_locally(
    proxy_type: ProxyType,
) -> Option<bool> {
    match proxy_type {
        ProxyType::Socks4 | ProxyType::Socks5 => Some(true),
        ProxyType::Socks4a | ProxyType::Socks5Hostname => Some(false),
        ProxyType::Http
        | ProxyType::Http10
        | ProxyType::Https
        | ProxyType::Https2 => None,
    }
}

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

/// The proxy side of [`crate::conn::ConnectionFilterFactories`].
///
/// `crate::conn`'s setup filter builds a chain through an INJECTED factory
/// rather than by calling filter constructors, so that it needs no knowledge
/// of any protocol or proxy module. Three of that trait's seven methods build
/// a proxy filter, and this type answers exactly those three:
///
/// * [`Self::socks_proxy`] builds `"SOCKS"`, for
///   `Curl_cf_socks_proxy_insert_after` (`lib/socks.c:1402`).
/// * [`Self::http_proxy_tunnel`] builds `"HTTP-PROXY"`, for
///   `Curl_cf_http_proxy_insert_after` (`lib/http_proxy.c:413`).
/// * [`Self::haproxy`] builds `"HAPROXY"`, for
///   `Curl_cf_haproxy_insert_after` (`lib/cf-haproxy.c:231`).
///
/// The signatures are the trait's, not a convenient approximation of it, so a
/// production factory delegates one method to one call and adds nothing. That
/// is the whole purpose: without a single place holding the proxy seams, every
/// implementor of the trait would assemble them again and they could disagree.
///
/// # The four it deliberately does not answer
///
/// `proxy_tls` builds `"SSL-PROXY"`, which is `lib/vtls/vtls.c`'s filter and
/// belongs to `crate::tls` -- see this module's documentation for why TLS to a
/// proxy is not a proxy-module concern. `happy_eyeballs`, `origin_tls` and
/// `https_setup` are not proxy concerns at all. A factory therefore composes
/// this type with the TLS and transport providers; it does not subclass it.
///
/// # Why the result is fallible and yet never fails on construction
///
/// The C returns `CURLcode` from all five `insert_after` entry points because
/// two allocations can fail: `Curl_cf_create` itself, and a `curlx_calloc`
/// for the filter's `void *ctx` before it. The five split three-to-two on that
/// second one, and the split is worth recording because it is easy to assume
/// uniform. Eager, allocating the context up front and freeing it if the
/// create fails: `"HAPROXY"` (`cf_haproxy_create`, `lib/cf-haproxy.c:212`),
/// `"HTTP-PROXY"` (`lib/http_proxy.c:421`) and `"H2-PROXY"`
/// (`lib/cf-h2-proxy.c:1487`). Lazy, passing `NULL` and allocating the state
/// on first connect: `"SOCKS"` (`lib/socks.c:1409`) and `"H1-PROXY"`
/// (`lib/cf-h1-proxy.c:782`).
///
/// Neither failure exists here: a filter's state travels INSIDE the value, so
/// there is no `void *ctx` to allocate separately, and the box is infallible
/// at the declared minimum Rust version. The eager-versus-lazy distinction
/// survives all the same, in whether a filter's state field starts as an
/// [`Option`] -- see [`Self::socks_proxy`].
///
/// The signature keeps [`CurlResult`] regardless, for two reasons. It is the
/// shape the trait declares, and delegation must be exact. And the error is
/// reachable for a different cause: a provider asked for a filter whose seam
/// it was never given. That is diagnosed rather than fabricated -- see
/// [`Self::socks_proxy`].
///
/// # Why `cx` is accepted and not read
///
/// Construction consults neither the tracer nor the clock, so `cx` is
/// discarded with `let _ = cx;`. This is not an oversight but the C's own
/// behaviour: every one of the five entry points opens with a literal
/// `(void)data;` -- `lib/socks.c:1408`, `lib/cf-h1-proxy.c:781`,
/// `lib/cf-h2-proxy.c:1486`, `lib/http_proxy.c:420` and, one frame in,
/// `lib/cf-haproxy.c:211`. Not one of them reads the easy handle it is
/// handed. A filter reads the clock when it CONNECTS, through the [`CallCtx`]
/// passed to it then.
///
/// # The seams
///
/// [`SocksSeams`] and [`TunnelSeams`] carry behaviour -- a resolver, a
/// connection's facts, optionally a GSS-API negotiator or an HTTP/2 session
/// factory -- so neither has a meaningful default and both are [`Option`].
/// A connection may legitimately have one, the other, or BOTH: `connectdata`
/// holds `socks_proxy` and `http_proxy` simultaneously, which is what makes
/// SOCKS through an HTTP proxy expressible.
///
/// [`HaproxyConfig`] is different and is not optional. It is plain data whose
/// default -- no `CURLOPT_HAPROXY_CLIENT_IP`, not a Unix socket -- is exactly
/// the configuration `--haproxy-protocol` alone produces, so a caller that
/// says nothing has said something true.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)] // consumer: a production ConnectionFilterFactories
pub(crate) struct ProxyFilterProvider {
    /// What `"SOCKS"` is built over, when this connection has a SOCKS proxy.
    socks: Option<SocksSeams>,
    /// What `"HTTP-PROXY"` is built over, when this connection tunnels.
    tunnel: Option<TunnelSeams>,
    /// What `"HAPROXY"` is built over. Always present; see the type's
    /// documentation for why this one needs no [`Option`].
    haproxy: HaproxyConfig,
}

impl ProxyFilterProvider {
    /// A provider with no proxy seams and a default PROXY-protocol header.
    ///
    /// Every builder below returns a new value, so a caller states only what
    /// the connection actually has. Identical to [`Default::default`], which
    /// is derived so that the two spellings cannot drift.
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            socks: None,
            tunnel: None,
            haproxy: HaproxyConfig::new(),
        }
    }

    /// Supplies what a `"SOCKS"` filter is built over.
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    #[must_use]
    pub(crate) fn with_socks(mut self, seams: SocksSeams) -> Self {
        self.socks = Some(seams);
        self
    }

    /// Supplies what a `"HTTP-PROXY"` filter is built over.
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    #[must_use]
    pub(crate) fn with_tunnel(mut self, seams: TunnelSeams) -> Self {
        self.tunnel = Some(seams);
        self
    }

    /// Replaces the PROXY-protocol configuration.
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    #[must_use]
    pub(crate) fn with_haproxy(mut self, config: HaproxyConfig) -> Self {
        self.haproxy = config;
        self
    }

    /// Whether a `"SOCKS"` filter can be built.
    ///
    /// `crate::conn` gates the SOCKS stage on its own configuration and never
    /// consults this, so it exists for a factory that wants to answer the
    /// question before the chain asks it.
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    pub(crate) const fn has_socks(&self) -> bool {
        self.socks.is_some()
    }

    /// Whether a `"HTTP-PROXY"` filter can be built.
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    pub(crate) const fn has_tunnel(&self) -> bool {
        self.tunnel.is_some()
    }

    /// The PROXY-protocol configuration a `"HAPROXY"` filter would carry.
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    pub(crate) const fn haproxy_config(&self) -> &HaproxyConfig {
        &self.haproxy
    }

    /// `Curl_cf_socks_proxy_insert_after` (`lib/socks.c:1402`), as the factory
    /// trait shapes it: build the `"SOCKS"` filter, do not install it.
    ///
    /// Installation is `crate::conn`'s: it splices the returned link below its
    /// own position and restamps the identity, which is why the filter is
    /// built holding the `conn` it was given rather than reaching for one.
    /// The C's `Curl_cf_create(&cf, &Curl_cft_socks_proxy, NULL)` passes a
    /// `NULL` context and the handshake state is allocated on first connect;
    /// [`SocksProxy::new`] reproduces that laziness with an [`Option`].
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when no [`SocksSeams`] was supplied. Nothing
    /// in a correct chain reaches that: `crate::conn` runs the SOCKS stage
    /// only when the connection is configured for a SOCKS proxy, and a
    /// provider for such a connection carries the seams. It is diagnosed
    /// rather than defaulted because a fabricated seam would connect
    /// somewhere, and connecting somewhere unintended is worse than refusing.
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    pub(crate) fn socks_proxy(
        &self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
    ) -> CurlResult<FilterLink> {
        // `(void)data;` -- construction reads neither tracer nor clock.
        let _ = cx;
        let Some(seams) = self.socks.as_ref() else {
            return Err(Error::with_context(
                CURLcode::FailedInit,
                "proxy: a SOCKS filter was requested from a provider built \
                 without SOCKS seams",
            ));
        };
        Ok(link(SocksProxy::new(sockindex, conn, seams.clone())))
    }

    /// `Curl_cf_http_proxy_insert_after` (`lib/http_proxy.c:413`): build the
    /// `"HTTP-PROXY"` dispatch filter.
    ///
    /// One filter, not three. `"HTTP-PROXY"` installs `"H1-PROXY"` or
    /// `"H2-PROXY"` itself once ALPN has settled, because the choice cannot be
    /// made before the transport beneath it has negotiated -- which is also
    /// why the C registers three types and exposes only this one to
    /// `lib/connect.c`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when no [`TunnelSeams`] was supplied, for the
    /// reason given on [`Self::socks_proxy`].
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    pub(crate) fn http_proxy_tunnel(
        &self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
    ) -> CurlResult<FilterLink> {
        // `(void)data;` -- as above.
        let _ = cx;
        let Some(seams) = self.tunnel.as_ref() else {
            return Err(Error::with_context(
                CURLcode::FailedInit,
                "proxy: a CONNECT tunnel was requested from a provider built \
                 without tunnel seams",
            ));
        };
        Ok(link(HttpProxy::new(sockindex, conn, seams.clone())))
    }

    /// `Curl_cf_haproxy_insert_after` (`lib/cf-haproxy.c:231`): build the
    /// `"HAPROXY"` filter.
    ///
    /// Infallible in practice as well as in the C, since the configuration is
    /// plain data that is always present. `crate::conn` has already refused
    /// the one arrangement that cannot work -- the PROXY protocol over a chain
    /// that is already TLS-protected, reported with
    /// `crate::conn::HAPROXY_AFTER_SSL` -- before it calls this, so no check
    /// for it belongs here.
    ///
    /// # Errors
    ///
    /// None are produced. [`CurlResult`] is kept so that the method delegates
    /// to the trait exactly, as this type's documentation records.
    #[allow(dead_code)] // consumer: a production ConnectionFilterFactories
    pub(crate) fn haproxy(
        &self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
    ) -> CurlResult<FilterLink> {
        // `Curl_cf_haproxy_insert_after` is the one entry point that passes
        // `data` on rather than discarding it inline -- and `cf_haproxy_create`
        // then discards it too, with its own `(void)data;`
        // (`lib/cf-haproxy.c:211`). The two values the PROXY header needs are
        // read later, while it is being composed, by
        // `cf_haproxy_date_out_set`. Both arrive here inside `HaproxyConfig`
        // and are fixed for the filter's lifetime, which is faithful: neither
        // can change during a connect.
        let _ = cx;
        Ok(link(Haproxy::new(sockindex, conn, self.haproxy.clone())))
    }
}

impl fmt::Display for ProxyFilterProvider {
    /// Which filters this provider can build, for a diagnostic.
    ///
    /// `"HAPROXY"` is always listed, because it is always buildable -- a
    /// provider given nothing at all can still write a PROXY-protocol header.
    /// So the list is never empty, and nothing here needs to say "none".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("proxy filters:")?;
        if self.has_socks() {
            f.write_str(" SOCKS")?;
        }
        if self.has_tunnel() {
            f.write_str(" HTTP-PROXY")?;
        }
        f.write_str(" HAPROXY")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::conn::filters::{FilterChain, Transport};
    use crate::conn::{ConnectionFilterFactories, ProtocolOptions};
    use crate::dns::IpVersion;
    use crate::proxy::http_connect::TunnelConn;
    use crate::proxy::socks::{
        DestinationResolver, ResolveProgress, SocksConn,
    };
    use crate::transfer::chunked::Chunker;
    use crate::util::timediff::TimeDiff;
    use crate::util::timeval::{CurlTime, TestClock};

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

    // -- the proxy-type predicates ----------------------------------------

    /// The four SOCKS members, and no others.
    ///
    /// Exhaustive over [`ProxyType::ALL`] rather than spot-checked, so that a
    /// member added to that type cannot slip through unclassified.
    #[test]
    fn exactly_four_proxy_types_are_socks_types() {
        let socks: Vec<ProxyType> = ProxyType::ALL
            .into_iter()
            .filter(|kind| is_socks_proxy(*kind))
            .collect();
        assert_eq!(
            socks,
            vec![
                ProxyType::Socks4,
                ProxyType::Socks5,
                ProxyType::Socks4a,
                ProxyType::Socks5Hostname,
            ],
            "the SOCKS set, in include/curl/curl.h declaration order"
        );

        // The header's ordering is the trap: 5 sits between 4 and 6.
        assert_eq!(ProxyType::Socks4.as_i32(), 4);
        assert_eq!(ProxyType::Socks5.as_i32(), 5);
        assert_eq!(ProxyType::Socks4a.as_i32(), 6);
        assert_eq!(ProxyType::Socks5Hostname.as_i32(), 7);
    }

    /// `socks5` resolves here; `socks5h` and `socks4a` resolve at the proxy.
    #[test]
    fn the_resolution_end_matches_the_scheme() {
        assert_eq!(socks_resolves_locally(ProxyType::Socks4), Some(true));
        assert_eq!(socks_resolves_locally(ProxyType::Socks5), Some(true));
        assert_eq!(socks_resolves_locally(ProxyType::Socks4a), Some(false));
        assert_eq!(
            socks_resolves_locally(ProxyType::Socks5Hostname),
            Some(false),
            "socks5h hands the NAME to the proxy"
        );

        // Not a SOCKS proxy: the question has no answer, and `None` says so
        // rather than a `false` a caller could act on.
        for kind in ProxyType::ALL {
            assert_eq!(
                socks_resolves_locally(kind).is_some(),
                is_socks_proxy(kind),
                "{kind:?} answers the resolution question iff it is SOCKS"
            );
        }
    }

    /// `IS_HTTPS_PROXY` is two members, and it is not this directory's to own.
    ///
    /// Asserted here as well as in `crate::conn` because this module's
    /// documentation states the pairing, and a claim in prose that nothing
    /// checks is a claim that can rot. `CURLPROXY_HTTP_1_0` is the member most
    /// likely to be miscounted into the set.
    #[test]
    fn https_proxy_is_two_members_and_excludes_http_1_0() {
        let https: Vec<ProxyType> = ProxyType::ALL
            .into_iter()
            .filter(|kind| kind.is_https())
            .collect();
        assert_eq!(https, vec![ProxyType::Https, ProxyType::Https2]);
        assert!(!ProxyType::Http10.is_https(), "1.0 is a version, not TLS");

        // No type is both, so the SSL-PROXY and SOCKS stages never contend.
        for kind in ProxyType::ALL {
            assert!(!(kind.is_https() && is_socks_proxy(kind)));
        }
    }

    // -- the filter-factory provider --------------------------------------

    /// A clock for a `CallCtx`. Construction reads it, so its value is
    /// immaterial; it is fixed rather than sampled because nothing in
    /// `crate::proxy` may call `Instant::now`.
    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    /// Everything [`SocksSeams`] wants of a connection, answered with fixed
    /// facts. Only [`SocksConn::proxy_type`] is ever read here.
    #[derive(Debug)]
    struct TestSocksConn;

    impl SocksConn for TestSocksConn {
        fn proxy_type(&self) -> i32 {
            ProxyType::Socks5.as_i32()
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
            "example.com".to_owned()
        }
        fn remote_port(&self) -> u16 {
            80
        }
        fn ip_version(&self) -> IpVersion {
            IpVersion::Whatever
        }
        fn set_ip_version(&self, ip_version: IpVersion) {
            let _ = ip_version;
        }
        fn requested_ip_version(&self) -> IpVersion {
            IpVersion::Whatever
        }
        fn is_ipv6_ip(&self) -> bool {
            false
        }
        fn socks5_gssapi_enctype(&self) -> i32 {
            0
        }
        fn set_proxy_code(&self, code: CURLproxycode) {
            let _ = code;
        }
        fn time_left_ms(&self) -> TimeDiff {
            0
        }
    }

    /// A resolver that resolves nothing. No test here connects, so the answer
    /// is never consumed; it exists because [`SocksSeams`] requires one.
    #[derive(Debug)]
    struct TestResolver;

    impl DestinationResolver for TestResolver {
        fn start(
            &self,
            hostname: &str,
            port: i32,
            ip_version: IpVersion,
        ) -> ResolveProgress {
            let _ = (hostname, port, ip_version);
            ResolveProgress::NoEntry
        }
        fn check(&self) -> ResolveProgress {
            ResolveProgress::NoEntry
        }
    }

    /// Everything [`TunnelSeams`] wants of a connection, answered with fixed
    /// facts. Nothing here is read during construction.
    #[derive(Debug)]
    struct TestTunnelConn;

    impl TunnelConn for TestTunnelConn {
        fn sockindex(&self) -> SocketIndex {
            SocketIndex::First
        }
        fn connect_to_host(&self) -> Option<String> {
            None
        }
        fn connect_to_port(&self) -> Option<u16> {
            None
        }
        fn secondary_host(&self) -> String {
            String::new()
        }
        fn secondary_port(&self) -> u16 {
            0
        }
        fn host_name(&self) -> String {
            "example.com".to_owned()
        }
        fn remote_port(&self) -> u16 {
            443
        }
        fn is_ipv6_ip(&self) -> bool {
            false
        }
        fn proxy_host(&self) -> String {
            "proxy.example".to_owned()
        }
        fn proxy_port(&self) -> u16 {
            1080
        }
        fn proxy_type(&self) -> ProxyType {
            ProxyType::Http
        }
        fn scheme_name(&self) -> String {
            "https".to_owned()
        }
        fn scheme_flags(&self) -> ProtocolOptions {
            ProtocolOptions::NONE
        }
        fn connection_close_requested(&self) -> bool {
            false
        }
        fn user_agent(&self) -> Option<String> {
            None
        }
        fn custom_headers(&self) -> Vec<String> {
            Vec::new()
        }
        fn proxy_headers(&self) -> Vec<String> {
            Vec::new()
        }
        fn separate_headers(&self) -> bool {
            false
        }
        fn output_auth(&self, method: &str, authority: &str) -> CurlResult<()> {
            let _ = (method, authority);
            Ok(())
        }
        fn proxy_user_pwd(&self) -> Option<String> {
            None
        }
        fn clear_proxy_user_pwd(&self) {}
        fn proxy_auth_enabled(&self) -> bool {
            false
        }
        fn proxy_auth_available(&self) -> bool {
            false
        }
        fn set_proxy_auth_done(&self, done: bool) {
            let _ = done;
        }
        fn set_proxy_auth_multipass(&self, multipass: bool) {
            let _ = multipass;
        }
        fn auth_problem(&self) -> bool {
            false
        }
        fn input_auth(&self, proxy: bool, challenge: &[u8]) -> CurlResult<()> {
            let _ = (proxy, challenge);
            Ok(())
        }
        fn auth_act(&self) -> CurlResult<()> {
            Ok(())
        }
        fn new_url(&self) -> Option<String> {
            None
        }
        fn clear_new_url(&self) {}
        fn http_code(&self) -> i32 {
            0
        }
        fn set_http_code(&self, code: i32) {
            let _ = code;
        }
        fn set_http_proxy_code(&self, code: i32) {
            let _ = code;
        }
        fn http_proxy_code(&self) -> i32 {
            0
        }
        fn clear_info_http_code(&self) {}
        fn req_soft_reset(&self) -> CurlResult<()> {
            Ok(())
        }
        fn client_reset(&self) {}
        fn progress_reset(&self) {}
        fn progress_update(&self) -> CurlResult<()> {
            Ok(())
        }
        fn set_reader_null(&self) -> CurlResult<()> {
            Ok(())
        }
        fn client_write(&self, flags: u32, line: &[u8]) -> CurlResult<()> {
            let _ = (flags, line);
            Ok(())
        }
        fn bump_header_size(
            &self,
            len: usize,
            connect_only: bool,
        ) -> CurlResult<()> {
            let _ = (len, connect_only);
            Ok(())
        }
        fn chunk_read(
            &self,
            chunker: &mut Chunker,
            buf: &[u8],
        ) -> CurlResult<usize> {
            let _ = (chunker, buf);
            Ok(0)
        }
        fn time_left_ms(&self) -> TimeDiff {
            0
        }
    }

    /// A provider carrying every seam -- the whole proxy filter set.
    fn full_provider() -> ProxyFilterProvider {
        ProxyFilterProvider::new()
            .with_socks(SocksSeams::new(
                Arc::new(TestSocksConn),
                Arc::new(TestResolver),
            ))
            .with_tunnel(TunnelSeams::new(Arc::new(TestTunnelConn)))
            .with_haproxy(HaproxyConfig::new())
    }

    /// `new()` and `default()` describe the same provider.
    #[test]
    fn an_empty_provider_can_build_only_the_haproxy_filter() {
        let provider = ProxyFilterProvider::new();
        assert!(!provider.has_socks());
        assert!(!provider.has_tunnel());
        assert_eq!(provider.haproxy_config(), &HaproxyConfig::new());
        assert_eq!(
            provider.haproxy_config(),
            ProxyFilterProvider::default().haproxy_config(),
            "new() and default() must not drift"
        );
        assert_eq!(provider.to_string(), "proxy filters: HAPROXY");
    }

    /// Each of the three builds the filter the C's `insert_after` creates, and
    /// each carries the identity it was handed.
    ///
    /// The names are compared as literals because `--trace-config` matches on
    /// them; `"SOCKS"` in particular is NOT `"SOCKS-PROXY"`
    /// (`lib/socks.c:1385`).
    #[test]
    fn the_provider_builds_the_whole_proxy_filter_set() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let provider = full_provider();
        let conn = Some(ConnId::new(7));

        let socks = provider
            .socks_proxy(&mut cx, SocketIndex::First, conn)
            .expect("seams were supplied");
        assert_eq!(socks.trace_name(), "SOCKS");

        let tunnel = provider
            .http_proxy_tunnel(&mut cx, SocketIndex::First, conn)
            .expect("seams were supplied");
        assert_eq!(tunnel.trace_name(), "HTTP-PROXY");

        let header = provider
            .haproxy(&mut cx, SocketIndex::Secondary, conn)
            .expect("the PROXY header needs no seam");
        assert_eq!(header.trace_name(), "HAPROXY");

        // Built, not installed: `crate::conn` splices the link and restamps
        // the identity, so each filter stands alone here.
        assert!(provider.has_socks());
        assert!(provider.has_tunnel());
        assert_eq!(
            provider.to_string(),
            "proxy filters: SOCKS HTTP-PROXY HAPROXY"
        );
    }

    /// A seam that was never supplied is diagnosed, never fabricated.
    #[test]
    fn a_missing_seam_is_refused_rather_than_invented() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let provider = ProxyFilterProvider::new();

        let socks = provider
            .socks_proxy(&mut cx, SocketIndex::First, None)
            .expect_err("no SOCKS seams were supplied");
        assert_eq!(socks.code(), CURLcode::FailedInit);

        let tunnel = provider
            .http_proxy_tunnel(&mut cx, SocketIndex::First, None)
            .expect_err("no tunnel seams were supplied");
        assert_eq!(tunnel.code(), CURLcode::FailedInit);

        // The PROXY header is always buildable, which is why its
        // configuration is not an `Option`.
        provider
            .haproxy(&mut cx, SocketIndex::First, None)
            .expect("a default HaproxyConfig is a complete one");
    }

    /// Only the filter whose seam is present becomes buildable.
    #[test]
    fn the_builders_are_independent_of_each_other() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);

        let socks_only = ProxyFilterProvider::new().with_socks(
            SocksSeams::new(Arc::new(TestSocksConn), Arc::new(TestResolver)),
        );
        assert!(socks_only.has_socks());
        assert!(!socks_only.has_tunnel());
        assert!(socks_only
            .socks_proxy(&mut cx, SocketIndex::First, None)
            .is_ok());
        assert!(socks_only
            .http_proxy_tunnel(&mut cx, SocketIndex::First, None)
            .is_err());
        assert_eq!(socks_only.to_string(), "proxy filters: SOCKS HAPROXY");

        let tunnel_only = ProxyFilterProvider::new()
            .with_tunnel(TunnelSeams::new(Arc::new(TestTunnelConn)));
        assert!(!tunnel_only.has_socks());
        assert!(tunnel_only.has_tunnel());
        assert!(tunnel_only
            .socks_proxy(&mut cx, SocketIndex::First, None)
            .is_err());
        assert!(tunnel_only
            .http_proxy_tunnel(&mut cx, SocketIndex::First, None)
            .is_ok());
        assert_eq!(
            tunnel_only.to_string(),
            "proxy filters: HTTP-PROXY HAPROXY"
        );
    }

    /// A factory whose three proxy answers are one delegation each.
    ///
    /// This exists to hold this module's central claim to a compiler rather
    /// than to prose: [`ProxyFilterProvider`]'s three methods are declared in
    /// the trait's own shape, so an implementor forwards and adds nothing. If
    /// a signature here ever diverged from
    /// [`crate::conn::ConnectionFilterFactories`], this would stop compiling.
    ///
    /// The four non-proxy answers are refused rather than stubbed with a
    /// filter, because a proxy provider genuinely cannot supply them: TLS and
    /// address racing belong to `crate::tls` and `crate::conn`, and a real
    /// factory composes those providers beside this one.
    #[derive(Debug)]
    struct DelegatingFactories {
        proxy: ProxyFilterProvider,
    }

    impl ConnectionFilterFactories for DelegatingFactories {
        fn happy_eyeballs(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
            transport: Transport,
        ) -> CurlResult<FilterLink> {
            let _ = (cx, sockindex, conn, transport);
            Err(Error::new(CURLcode::UnsupportedProtocol))
        }

        fn socks_proxy(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            self.proxy.socks_proxy(cx, sockindex, conn)
        }

        fn proxy_tls(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = (cx, sockindex, conn);
            Err(Error::new(CURLcode::UnsupportedProtocol))
        }

        fn http_proxy_tunnel(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            self.proxy.http_proxy_tunnel(cx, sockindex, conn)
        }

        fn haproxy(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            self.proxy.haproxy(cx, sockindex, conn)
        }

        fn origin_tls(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = (cx, sockindex, conn);
            Err(Error::new(CURLcode::UnsupportedProtocol))
        }

        fn https_setup(
            &self,
            cx: &mut CallCtx<'_, '_>,
            chain: &mut FilterChain,
        ) -> CurlResult<()> {
            let _ = (cx, chain);
            Ok(())
        }
    }

    /// The provider satisfies the factory trait through plain delegation, and
    /// the delegated answers are the provider's own.
    #[test]
    fn a_factory_can_forward_its_three_proxy_methods_unchanged() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let factories = DelegatingFactories {
            proxy: full_provider(),
        };

        // Reached through the TRAIT, exactly as `crate::conn` reaches it.
        let factories: &dyn ConnectionFilterFactories = &factories;
        let conn = Some(ConnId::new(11));

        let socks = factories
            .socks_proxy(&mut cx, SocketIndex::First, conn)
            .expect("delegated to a provider carrying SOCKS seams");
        assert_eq!(socks.trace_name(), "SOCKS");

        let tunnel = factories
            .http_proxy_tunnel(&mut cx, SocketIndex::First, conn)
            .expect("delegated to a provider carrying tunnel seams");
        assert_eq!(tunnel.trace_name(), "HTTP-PROXY");

        let header = factories
            .haproxy(&mut cx, SocketIndex::First, conn)
            .expect("delegated, and infallible");
        assert_eq!(header.trace_name(), "HAPROXY");

        // The four this directory does not answer, refused and not faked.
        assert!(factories
            .proxy_tls(&mut cx, SocketIndex::First, conn)
            .is_err());
        assert!(factories
            .origin_tls(&mut cx, SocketIndex::First, conn)
            .is_err());
    }

    /// The PROXY-protocol configuration a provider was given is the one its
    /// filter is built with, and cloning a provider preserves it.
    #[test]
    fn the_haproxy_configuration_is_carried_and_cloned() {
        let config = HaproxyConfig::new()
            .with_client_ip("203.0.113.7")
            .with_unix_domain_socket(true);
        let provider = ProxyFilterProvider::new().with_haproxy(config.clone());
        assert_eq!(provider.haproxy_config(), &config);

        let copy = provider.clone();
        assert_eq!(copy.haproxy_config(), &config);

        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let header = copy
            .haproxy(&mut cx, SocketIndex::First, None)
            .expect("infallible");
        assert_eq!(header.trace_name(), "HAPROXY");
    }
}
