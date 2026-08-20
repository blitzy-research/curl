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

//! `CONNECT` tunnelling through an HTTP proxy -- the `"HTTP-PROXY"`,
//! `"H1-PROXY"` and `"H2-PROXY"` connection filters.
//!
//! Supersedes six C files in full, 2,867 lines:
//!
//! * `lib/http_proxy.c` (425) -- the `"HTTP-PROXY"` dispatch filter,
//!   `Curl_http_proxy_create_CONNECT`,
//!   `Curl_http_proxy_get_destination` and the shared
//!   `Curl_cf_http_proxy_query`
//! * `lib/http_proxy.h` (64) -- `enum Curl_proxy_use`, `PROXY_TIMEOUT`,
//!   `IS_HTTPS_PROXY`
//! * `lib/cf-h1-proxy.c` (788) -- `"H1-PROXY"`, the six-state tunnel machine
//! * `lib/cf-h1-proxy.h` (37) -- its insert entry point
//! * `lib/cf-h2-proxy.c` (1,504) -- `"H2-PROXY"`, the five-state HTTP/2
//!   `CONNECT` tunnel
//! * `lib/cf-h2-proxy.h` (49) -- its insert entry point
//!
//! # Three filters, one file
//!
//! The C splits them across three translation units because a translation
//! unit is C's only unit of privacy. Rust has module privacy without file
//! granularity, and the three share `Curl_http_proxy_create_CONNECT` and
//! `Curl_cf_http_proxy_query` -- two functions whose whole point is that
//! ONE definition serves all three. Keeping them together is what stops the
//! `CONNECT` request from acquiring a second spelling.
//!
//! # The bytes are the specification
//!
//! Thirty-one fixtures in `tests/data` carry a `<verify><proxy>` block, which
//! `tests/runtests.pl` fills from `$logdir/proxy.input` -- *"what curl sent
//! the proxy"* (`tests/globalconfig.pm:137`) -- and compares as ONE joined
//! string with Perl `ne` (`tests/getpart.pm:351`). There is no per-line
//! matching, no normalisation and no reordering, so every byte this module
//! emits is frozen: the request line's shape, each header's name, spelling
//! and POSITION, and the CRLF that terminates each of them.
//!
//! Those fixtures cannot be skipped. `parseprotocols`
//! (`tests/runtests.pl:463-482`) appends `http-proxy` to the protocol list
//! unconditionally, whatever the binary's `--version` banner says, so proxy
//! eligibility never depends on an advertised capability.
//!
//! # What this module does NOT own
//!
//! * **The `"SSL-PROXY"` filter.** For an HTTPS proxy the TLS session
//!   towards the proxy is installed by `cf_setup_connect`
//!   (`lib/connect.c:384-401`), BELOW the tunnel and before it, which is
//!   [`crate::conn::SetupFilter`]'s job here. This module never installs
//!   TLS; it only tunnels over whatever is beneath it.
//! * **The non-tunnel proxy request.** A plain request through an HTTP proxy
//!   carries an absolute URI and is composed by [`crate::protocols::http1`].
//!   Its header order differs from the tunnel's -- see
//!   [`create_connect`] -- and the two emitters are deliberately separate.

use core::fmt;
use std::sync::Arc;

use crate::conn::filters::{
    link, CallCtx, CfQuery, CfQueryValue, CfType, ConnFilter, ConnId,
    FilterBase, FilterChain, FilterLink, SocketIndex, CF_TYPE_IP_CONNECT,
    CF_TYPE_PROXY, CURL_LOG_LVL_NONE,
};
// `CfControl` and `Liveness` are reached only by `"H2-PROXY"`, the one filter
// here that overrides `cntrl` and `is_alive`.
#[cfg(feature = "http2")]
use crate::conn::filters::{CfControl, Liveness};
use crate::conn::select::{EasyPollset, Socket, CURL_SOCKET_BAD};
// `"H1-PROXY"` polls unconditionally; `"H2-PROXY"` guards on a usable socket
// because its pollset update is conditional on the session's windows.
#[cfg(feature = "http2")]
use crate::conn::select::is_valid_sock;
use crate::conn::{ProtocolOptions, ProxyType};
use crate::error::{CURLcode, CurlResult, Error};
use crate::headers::{
    HeaderSet, CLIENTWRITE_CONNECT, CLIENTWRITE_HEADER, CLIENTWRITE_STATUS,
};
#[cfg(feature = "http2")]
use crate::protocols::http2::SettingsTable;
use crate::trace::{failf, infof, trc_cf, InfoType, TraceFilter};
use crate::transfer::chunked::Chunker;
#[cfg(feature = "http2")]
use crate::util::bufq::{BufQ, BufqOpts};
use crate::util::dynbuf::{
    DynBuf, DYN_HTTP_REQUEST, DYN_PROXY_CONNECT_HEADERS,
};
use crate::util::strparse::str_casecompare;
use crate::util::timediff::TimeDiff;
#[cfg(feature = "http2")]
use core::mem;

// ---------------------------------------------------------------------------
// 1. The three filter identities -- the first three members of each
//    `struct Curl_cftype`.
// ---------------------------------------------------------------------------

/// The `name` member of `Curl_cft_http_proxy` (`lib/http_proxy.c:396`).
///
/// Resolved to [`TraceFilter::HttpProxy`] by [`ConnFilter::trace_filter`]'s
/// default, so the name is stated once and `--trace-config proxy` matches it
/// through the registry rather than through a second table here.
pub(crate) const HTTP_PROXY_FILTER_NAME: &str = "HTTP-PROXY";

/// The `flags` member of `Curl_cft_http_proxy` (`lib/http_proxy.c:397`).
pub(crate) const HTTP_PROXY_FLAGS: CfType =
    CF_TYPE_IP_CONNECT.union(CF_TYPE_PROXY);

/// The `log_level` member of `Curl_cft_http_proxy` (`lib/http_proxy.c:398`):
/// `0`, which is [`CURL_LOG_LVL_NONE`].
///
/// The level itself lives in [`crate::trace::TraceConfig`], because C's is a
/// process-global that `--trace-config` writes through. This constant records
/// what the C table declares so the identity test can assert it.
#[allow(dead_code)] // Asserted by the identity test; the level lives in
                    // `TraceConfig`.
pub(crate) const HTTP_PROXY_LOG_LEVEL: i32 = CURL_LOG_LVL_NONE;

/// The `name` member of `Curl_cft_h1_proxy` (`lib/cf-h1-proxy.c:758`).
pub(crate) const H1_PROXY_FILTER_NAME: &str = "H1-PROXY";

/// The `flags` member of `Curl_cft_h1_proxy` (`lib/cf-h1-proxy.c:759`).
pub(crate) const H1_PROXY_FLAGS: CfType =
    CF_TYPE_IP_CONNECT.union(CF_TYPE_PROXY);

/// The `log_level` member of `Curl_cft_h1_proxy` (`lib/cf-h1-proxy.c:760`).
#[allow(dead_code)] // Asserted by the identity test.
pub(crate) const H1_PROXY_LOG_LEVEL: i32 = CURL_LOG_LVL_NONE;

/// The `name` member of `Curl_cft_h2_proxy` (`lib/cf-h2-proxy.c:1462`).
#[cfg(feature = "http2")]
pub(crate) const H2_PROXY_FILTER_NAME: &str = "H2-PROXY";

/// The `flags` member of `Curl_cft_h2_proxy` (`lib/cf-h2-proxy.c:1463`).
///
/// `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY` and NOT `CF_TYPE_MULTIPLEX`, even
/// though the filter speaks HTTP/2. Measured, and preserved: the multiplex
/// flag advertises that a connection can carry SEVERAL transfers, and a
/// `CONNECT` tunnel carries exactly one stream however many the session could
/// in principle hold. `Curl_cft_http2` (`lib/http2.c`) does carry it, which is
/// the contrast that makes the omission deliberate rather than an oversight.
#[cfg(feature = "http2")]
pub(crate) const H2_PROXY_FLAGS: CfType =
    CF_TYPE_IP_CONNECT.union(CF_TYPE_PROXY);

/// The `log_level` member of `Curl_cft_h2_proxy` (`lib/cf-h2-proxy.c:1464`):
/// `CURL_LOG_LVL_NONE`, spelled out in the C rather than left as `0`.
#[cfg(feature = "http2")]
#[allow(dead_code)] // Asserted by the identity test.
pub(crate) const H2_PROXY_LOG_LEVEL: i32 = CURL_LOG_LVL_NONE;

/// `PROXY_TIMEOUT` (`lib/http_proxy.h:48`): `3600 * 1000` milliseconds.
///
/// The ceiling the `CONNECT` phase is given when no shorter deadline applies.
/// Declared OUTSIDE the C header's `#if !defined(CURL_DISABLE_PROXY) &&
/// !defined(CURL_DISABLE_HTTP)` guard, so it exists in every build, and it is
/// carried here for the same reason: it describes the protocol phase rather
/// than the code that implements it.
#[allow(dead_code)] // Consumer: the transfer core's deadline arithmetic.
pub(crate) const PROXY_TIMEOUT: TimeDiff = 3600 * 1000;

// ---------------------------------------------------------------------------
// 2. `enum Curl_proxy_use` -- which custom-header list a request draws on.
// ---------------------------------------------------------------------------

/// `enum Curl_proxy_use` (`lib/http_proxy.h:32-36`): the three contexts a
/// custom header can apply to.
///
/// Also declared outside the disable-guards, and the enumeration IS the
/// selection rule that `dynhds_add_custom` (`lib/http_proxy.c:40-75`) applies:
///
/// * [`Self::Server`] -- straight to the origin: the `CURLOPT_HTTPHEADER`
///   list alone.
/// * [`Self::Proxy`] -- a plain request THROUGH a proxy: the
///   `CURLOPT_HTTPHEADER` list, plus the `CURLOPT_PROXYHEADER` list when
///   `CURLOPT_HEADEROPT` separates them, giving the only case where two lists
///   are walked.
/// * [`Self::Connect`] -- the `CONNECT` request itself: ONE list, the proxy's
///   when they are separated and otherwise the server's.
///
/// This module only ever produces [`Self::Connect`], because
/// `dynhds_add_custom(data, TRUE, ...)` is how `create_CONNECT` calls it. The
/// other two are carried because the enumeration is a definition of the
/// selection rule and a partial copy of it would read as though a `CONNECT`
/// had a choice.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum ProxyUse {
    /// `HEADER_SERVER` -- *"direct to server"*.
    #[default]
    Server,
    /// `HEADER_PROXY` -- *"regular request to proxy"*.
    Proxy,
    /// `HEADER_CONNECT` -- *"sending CONNECT to a proxy"*.
    Connect,
}

impl ProxyUse {
    /// Every context, in the C's declaration order.
    #[allow(dead_code)] // Read by this module's own tests.
    pub(crate) const ALL: [Self; 3] =
        [Self::Server, Self::Proxy, Self::Connect];

    /// The C identifier for this context.
    #[allow(dead_code)] // Read by this module's own tests.
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::Server => "HEADER_SERVER",
            Self::Proxy => "HEADER_PROXY",
            Self::Connect => "HEADER_CONNECT",
        }
    }

    /// Which list `dynhds_add_custom` walks, and whether it walks two.
    ///
    /// `sep_headers` is `CURLOPT_HEADEROPT`'s `CURLHEADER_SEPARATE`. The
    /// answer is `(server_list, proxy_list)`, each flag saying whether that
    /// list contributes, in the order the C reads them.
    #[allow(dead_code)] // Read by `create_connect` and by the tests.
    pub(crate) const fn lists(self, sep_headers: bool) -> (bool, bool) {
        match self {
            // `h[0] = data->set.headers;` and `numlists` stays 1.
            Self::Server => (true, false),
            // `h[0] = data->set.headers;` plus `h[1] =
            // data->set.proxyheaders` when separated -- BOTH.
            Self::Proxy => (true, sep_headers),
            // One list either way: the proxy's when separated, else the
            // server's.
            Self::Connect => (!sep_headers, sep_headers),
        }
    }
}

/// `IS_HTTPS_PROXY(t)` (`lib/http_proxy.h:61-62`), reached through the type
/// that owns the enumeration.
///
/// A free function rather than a re-export because the predicate belongs to
/// [`ProxyType`], where [`ProxyType::is_https`] already is it: this is the
/// C macro's NAME preserved for a reader diffing the two trees, and it must
/// not become a second implementation.
#[allow(dead_code)] // Consumer: `crate::conn`'s chain construction, which
                    // reaches `ProxyType::is_https` directly.
pub(crate) const fn is_https_proxy(proxy_type: ProxyType) -> bool {
    proxy_type.is_https()
}

/// `curl_strequal(a, b)` (`lib/curlx/strequal.c`): ASCII-case-insensitive
/// equality over two whole spans.
///
/// Delegates to [`str_casecompare`] rather than folding case itself. The
/// C reaches this through several spellings -- `curl_strequal`,
/// `curlx_str_casecompare`, `Curl_str_casecompare` -- and every one of them
/// ends in the same comparison, so a second implementation here would be a
/// second place for the ASCII-only rule to drift.
///
/// **ASCII only, deliberately.** `curl_strnequal` folds `A`-`Z` against
/// `a`-`z` and nothing else, so a locale that case-folds differently cannot
/// change which headers match -- which is what makes header matching
/// reproducible across the 1,914 fixtures.
fn casecompare(span: &[u8], check: &[u8]) -> bool {
    str_casecompare(span, check)
}

/// `checkprefix(prefix, header)` (`lib/curl_setup_once.h`): does `header`
/// BEGIN with `prefix`, ignoring ASCII case?
///
/// `#define checkprefix(a, b) curl_strnequal(b, STRCONST(a))`, so the prefix
/// length is what bounds the comparison and a longer header still matches.
/// That is what lets `on_resp_header` test `"Content-Length:"` against a whole
/// header line, colon included, without splitting it first.
///
/// Built on [`str_casecompare`] over the leading slice, for the same reason
/// [`casecompare`] is: one case-folding rule, in one place.
fn checkprefix(prefix: &str, header: &[u8]) -> bool {
    let bytes = prefix.as_bytes();
    header.len() >= bytes.len()
        && str_casecompare(&header[..bytes.len()], bytes)
}

// ---------------------------------------------------------------------------
// 3. The destination -- `Curl_http_proxy_get_destination`.
// ---------------------------------------------------------------------------

/// Where the tunnel leads: the three facts `Curl_http_proxy_get_destination`
/// writes through its out-parameters (`lib/http_proxy.c:165-190`).
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct TunnelDestination {
    /// `*phostname`.
    pub(crate) hostname: String,
    /// `*pport`, which the C keeps as an `int` and which only ever holds a
    /// port.
    pub(crate) port: u16,
    /// `*pipv6_ip` -- the hostname is a literal IPv6 address and the
    /// authority must bracket it.
    pub(crate) ipv6_ip: bool,
}

impl TunnelDestination {
    /// `curl_maprintf("%s%s%s:%d", ipv6_ip ? "[" : "", hostname,
    /// ipv6_ip ? "]" : "", port)`.
    ///
    /// The single authority formatter for all three filters -- the request
    /// target and `Host` of an HTTP/1.x `CONNECT`
    /// (`lib/http_proxy.c:318-319`), and `:authority` plus `ts->authority` of
    /// an HTTP/2 one (`lib/cf-h2-proxy.c:94-95`). All three call sites in the
    /// C use that identical format string, so a single function here is a
    /// transcription rather than a unification.
    ///
    /// Two properties are frozen:
    ///
    /// * **The port is ALWAYS present**, even when it is the scheme's
    ///   default. `CONNECT example.com HTTP/1.1` with no port is not what curl
    ///   emits and is not what a proxy is required to accept.
    /// * **Brackets appear only for a literal IPv6 address.** A registered
    ///   name that happens to contain a colon does not get them, because
    ///   `ipv6_ip` -- not the presence of a colon -- is the flag consulted.
    pub(crate) fn authority(&self) -> String {
        if self.ipv6_ip {
            format!("[{}]:{}", self.hostname, self.port)
        } else {
            format!("{}:{}", self.hostname, self.port)
        }
    }
}

/// `Curl_http_proxy_get_destination(cf, &hostname, &port, &ipv6_ip)`
/// (`lib/http_proxy.c:165-190`).
///
/// # Three independent decisions, in the C's order
///
/// The host, the port and the bracketing are chosen by three separate
/// cascades, and they do NOT agree on which condition wins:
///
/// ```text
/// host:  conn_to_host ? conn_to_host.name
///      : sockindex == SECONDARY ? secondaryhostname
///      : host.name
/// port:  sockindex == SECONDARY ? secondary_port
///      : conn_to_port ? conn_to_port
///      : remote_port
/// ipv6:  host != host.name ? (host contains ':') : bits.ipv6_ip
/// ```
///
/// Note the inversion between the first two: `conn_to_host` outranks the
/// secondary socket for the HOST, while the secondary socket outranks
/// `conn_to_port` for the PORT. That is what `--connect-to` plus an FTP data
/// connection produces, and it is transcribed rather than tidied.
///
/// The bracketing test is a POINTER comparison in the C -- `if(*phostname !=
/// cf->conn->host.name)` -- not a string one: whenever the host came from
/// anywhere other than `conn->host`, the answer is recomputed by looking for a
/// colon, because `conn->bits.ipv6_ip` describes `conn->host` alone. The
/// [`bool`] arguments below carry that provenance so the same distinction
/// survives without pointers.
///
/// # Deliberately NOT `socks.rs`'s version
///
/// `socks_proxy_cf_connect` (`lib/socks.c:1244-1258`) makes the same choice
/// with two ternary chains of its own, and the two functions do not agree:
/// SOCKS consults `conn->bits.httpproxy` first, because a SOCKS proxy may
/// have an HTTP proxy BEYOND it and must then tunnel to that. There is no
/// such case here -- this filter IS the HTTP proxy -- so the two stay
/// separate, exactly as the C keeps them.
pub(crate) fn destination(conn: &dyn TunnelConn) -> TunnelDestination {
    let secondary = conn.sockindex() == SocketIndex::Secondary;

    // `if(cf->conn->bits.conn_to_host) ... else if(cf->sockindex ==
    // SECONDARYSOCKET) ... else ...`
    let (hostname, from_conn_host) = match conn.connect_to_host() {
        Some(host) => (host, false),
        None if secondary => (conn.secondary_host(), false),
        None => (conn.host_name(), true),
    };

    // `if(cf->sockindex == SECONDARYSOCKET) ... else if(bits.conn_to_port)
    // ... else ...`
    let port = if secondary {
        conn.secondary_port()
    } else {
        conn.connect_to_port().unwrap_or_else(|| conn.remote_port())
    };

    // `if(*phostname != cf->conn->host.name) *pipv6_ip = (strchr(*phostname,
    // ':') != NULL); else *pipv6_ip = cf->conn->bits.ipv6_ip;`
    let ipv6_ip = if from_conn_host {
        conn.is_ipv6_ip()
    } else {
        hostname.as_bytes().contains(&b':')
    };

    TunnelDestination {
        hostname,
        port,
        ipv6_ip,
    }
}

// ---------------------------------------------------------------------------
// 4. The injected seam -- everything the C reaches through `cf->conn` and
//    `data`.
// ---------------------------------------------------------------------------

/// The connection and transfer facts a `CONNECT` tunnel needs, as a contract.
///
/// # Why a seam and not a struct of values
///
/// Every C function in the six files this module supersedes takes
/// `struct Curl_cfilter *cf` and `struct Curl_easy *data` and reaches into
/// both. A [`ConnFilter`] here receives neither: it gets a [`CallCtx`], which
/// carries the injected clock and the tracer and nothing else. That is the
/// deliberate consequence of removing `lib/urldata.h` -- a filter cannot
/// reach into shared mutable transfer state, so whatever it genuinely needs
/// must be named.
///
/// Naming it has three effects worth the size of the trait. The tunnel is
/// testable with no easy handle, no socket and no network, which is what makes
/// the coverage gate reachable. Every fact the tunnel consumes is enumerated,
/// so a reader can see exactly how much of `data` a `CONNECT` actually
/// touches. And the direction of knowledge is one-way: this module says WHEN
/// each operation happens, the implementor says what it consists of.
///
/// # `&self` throughout, including the setters
///
/// The C writes `data->info.httpproxycode`, `data->req.newurl` and several
/// bits of `data->state.authproxy` from inside the filter. Those writes are
/// spelled `&self` here, with interior mutability the implementor's business,
/// which is the shape [`crate::proxy::socks::SocksConn`] already established
/// for `set_proxy_code` and `set_ip_version`. Taking `&mut self` instead would
/// force the seam to be owned rather than shared, and one connection's state
/// is reached by more than one filter.
pub(crate) trait TunnelConn: fmt::Debug + Send + Sync {
    // -- `cf->sockindex` and `cf->conn` -- the connection's own facts ------

    /// `cf->sockindex` (`lib/http_proxy.c:174`): which chain this filter is
    /// installed on. [`SocketIndex::Secondary`] is the FTP data connection.
    fn sockindex(&self) -> SocketIndex;

    /// `conn->conn_to_host.name`, present exactly when
    /// `conn->bits.conn_to_host` is set (`lib/http_proxy.c:172-173`) --
    /// `--connect-to`.
    fn connect_to_host(&self) -> Option<String>;

    /// `conn->conn_to_port`, present exactly when `conn->bits.conn_to_port`
    /// is set (`lib/http_proxy.c:181-182`).
    fn connect_to_port(&self) -> Option<u16>;

    /// `conn->secondaryhostname` (`lib/http_proxy.c:175`).
    fn secondary_host(&self) -> String;

    /// `conn->secondary_port` (`lib/http_proxy.c:180`).
    fn secondary_port(&self) -> u16;

    /// `conn->host.name` (`lib/http_proxy.c:177`) -- the origin.
    fn host_name(&self) -> String;

    /// `conn->remote_port` (`lib/http_proxy.c:184`).
    fn remote_port(&self) -> u16;

    /// `conn->bits.ipv6_ip` (`lib/http_proxy.c:189`): `conn->host.name` is a
    /// literal IPv6 address.
    fn is_ipv6_ip(&self) -> bool;

    /// `conn->http_proxy.host.name` (`lib/http_proxy.c:361`) -- what
    /// `CF_QUERY_HOST_PORT` answers with.
    fn proxy_host(&self) -> String;

    /// `conn->http_proxy.port` (`lib/http_proxy.c:360`).
    fn proxy_port(&self) -> u16;

    /// `conn->http_proxy.proxytype` (`lib/cf-h1-proxy.c:223`), which decides
    /// the `CONNECT` request's minor version: `CURLPROXY_HTTP_1_0` alone
    /// yields `HTTP/1.0`.
    fn proxy_type(&self) -> ProxyType;

    /// `conn->scheme->name` (`lib/cf-h1-proxy.c:108`), for the one diagnostic
    /// that names it.
    fn scheme_name(&self) -> String;

    /// `conn->scheme->flags` (`lib/cf-h1-proxy.c:107`). Only
    /// [`ProtocolOptions::NOTCPPROXY`] is read, in [`H1Tunnel::init`].
    fn scheme_flags(&self) -> ProtocolOptions;

    /// `conn->bits.close` (`lib/cf-h1-proxy.c:618`): somebody has already
    /// decided this connection must not be reused.
    fn connection_close_requested(&self) -> bool;

    // -- request composition -- `data->set` -------------------------------

    /// `data->set.str[STRING_USERAGENT]` (`lib/http_proxy.c:247`).
    ///
    /// [`None`] and `Some("")` are DIFFERENT and both suppress the header:
    /// the C's guard is `data->set.str[STRING_USERAGENT] &&
    /// *data->set.str[STRING_USERAGENT]`, so an option set to the empty
    /// string emits nothing rather than an empty header.
    fn user_agent(&self) -> Option<String>;

    /// `data->set.headers` -- the `CURLOPT_HTTPHEADER` list, in the order the
    /// application built it.
    ///
    /// Order is behaviour: `dynhds_add_custom` appends in list order and
    /// `Curl_dynhds_h1_dprint` emits in insertion order, so a reordered list
    /// is different bytes on the wire.
    fn custom_headers(&self) -> Vec<String>;

    /// `data->set.proxyheaders` -- the `CURLOPT_PROXYHEADER` list.
    fn proxy_headers(&self) -> Vec<String>;

    /// `data->set.sep_headers` -- `CURLOPT_HEADEROPT` is
    /// `CURLHEADER_SEPARATE`.
    fn separate_headers(&self) -> bool;

    /// `data->state.aptr.host` (`lib/http_proxy.c:124`): a `Host:` header has
    /// already been composed for the origin request, so a custom `Host:` must
    /// not be passed on as well -- *"that will produce \*two\* in the same
    /// request!"*.
    ///
    /// Defaults to `false`, the state a `CONNECT` is composed in: the origin
    /// request has not been built yet on the first pass.
    fn origin_host_header_composed(&self) -> bool {
        false
    }

    /// `data->state.httpreq == HTTPREQ_POST_FORM || == HTTPREQ_POST_MIME`
    /// (`lib/http_proxy.c:129-136`): a `Content-Type` the form or MIME layer
    /// sends later must not be passed on now.
    ///
    /// Defaults to `false`.
    fn request_sends_own_content_type(&self) -> bool {
        false
    }

    /// `data->req.authneg` (`lib/http_proxy.c:137`): a zero-length
    /// authentication probe is in flight, so a custom `Content-Length` must
    /// not override the forced zero.
    ///
    /// Defaults to `false`.
    fn auth_negotiating(&self) -> bool {
        false
    }

    /// `Curl_auth_allowed_to_host(data)` (`lib/http_proxy.c:150`): whether
    /// `Authorization` and `Cookie` may be forwarded to the CURRENT host
    /// after a redirect to a different one.
    ///
    /// Defaults to `true`, which is the state of a connection that has not
    /// been redirected.
    fn auth_allowed_to_host(&self) -> bool {
        true
    }

    // -- proxy authentication -- `data->state.aptr` and `authproxy` -------

    /// `Curl_http_output_auth(data, conn, method, HTTPREQ_GET, authority,
    /// TRUE)` (`lib/http_proxy.c:226-227`).
    ///
    /// The trailing `TRUE` is `proxytunnel`, and the whole point of the call
    /// is its SIDE EFFECT: it composes `data->state.aptr.proxyuserpwd` and
    /// adds no header itself. `HTTPREQ_GET` is passed rather than the real
    /// request kind because the `CONNECT` carries no body.
    ///
    /// # Errors
    ///
    /// Whatever the authentication layer reports.
    fn output_auth(&self, method: &str, authority: &str) -> CurlResult<()>;

    /// `data->state.aptr.proxyuserpwd` -- the composed
    /// `Proxy-Authorization:` line, terminator excluded, or [`None`] when
    /// there are no proxy credentials.
    ///
    /// A whole HEADER LINE rather than a value, because the C appends it with
    /// `Curl_dynhds_h1_cadd_line` (`lib/http_proxy.c:240-241`), which splits
    /// it at the first colon.
    fn proxy_user_pwd(&self) -> Option<String>;

    /// `Curl_safefree(data->state.aptr.proxyuserpwd)`
    /// (`lib/cf-h1-proxy.c:175`, `lib/cf-h2-proxy.c:161`).
    ///
    /// Called when the tunnel reaches ESTABLISHED or FAILED, so that
    /// credentials composed for the PROXY cannot leak into the document
    /// request that follows.
    fn clear_proxy_user_pwd(&self);

    /// `data->set.proxyauth` (`lib/cf-h1-proxy.c:452`): proxy authentication
    /// was asked for.
    fn proxy_auth_enabled(&self) -> bool;

    /// `data->state.authproxy.avail` (`lib/cf-h1-proxy.c:452`): the proxy has
    /// offered at least one mechanism.
    fn proxy_auth_available(&self) -> bool;

    /// `data->state.authproxy.done = TRUE`
    /// (`lib/cf-h1-proxy.c:160`, `lib/cf-h2-proxy.c:151`).
    fn set_proxy_auth_done(&self, done: bool);

    /// `data->state.authproxy.multipass = FALSE`
    /// (`lib/cf-h1-proxy.c:161`, `lib/cf-h2-proxy.c:152`).
    fn set_proxy_auth_multipass(&self, multipass: bool);

    /// `data->state.authproblem` (`lib/cf-h1-proxy.c:381`).
    fn auth_problem(&self) -> bool;

    /// `Curl_http_input_auth(data, proxy, auth)`
    /// (`lib/cf-h1-proxy.c:290`, `lib/cf-h2-proxy.c:801`): take in one
    /// challenge.
    ///
    /// `challenge` starts at the scheme token, which is what
    /// `Curl_copy_header_value` produced from the header line.
    ///
    /// # Errors
    ///
    /// Whatever the authentication layer reports;
    /// [`CURLcode::OutOfMemory`] is the only one the C propagates from the
    /// mechanisms themselves.
    fn input_auth(&self, proxy: bool, challenge: &[u8]) -> CurlResult<()>;

    /// `Curl_http_auth_act(data)` (`lib/cf-h1-proxy.c:552`): decide what the
    /// challenges just taken in mean.
    ///
    /// This is what sets `data->req.newurl`, which is the tunnel's signal to
    /// send a second `CONNECT` carrying credentials.
    ///
    /// # Errors
    ///
    /// Whatever the authentication layer reports.
    fn auth_act(&self) -> CurlResult<()>;

    // -- the request/response state -- `data->req` and `data->info` -------

    /// `data->req.newurl` (`lib/cf-h1-proxy.c:612`): a follow-up request is
    /// required.
    ///
    /// The tunnel only ever tests whether it is SET; the URL itself belongs
    /// to the transfer.
    fn new_url(&self) -> Option<String>;

    /// `Curl_safefree(data->req.newurl)`
    /// (`lib/cf-h1-proxy.c:212`, `:646`, `lib/cf-h2-proxy.c:807`).
    fn clear_new_url(&self);

    /// `data->req.httpcode` (`lib/cf-h1-proxy.c:278`), the status of the
    /// response being read.
    fn http_code(&self) -> i32;

    /// `k->httpcode = ...` (`lib/cf-h1-proxy.c:343`).
    fn set_http_code(&self, code: i32);

    /// `data->info.httpproxycode = ...` (`lib/cf-h1-proxy.c:343`), which
    /// `CURLINFO_HTTP_CONNECTCODE` reports.
    fn set_http_proxy_code(&self, code: i32);

    /// `data->info.httpproxycode` (`lib/cf-h1-proxy.c:549`, `:644`).
    fn http_proxy_code(&self) -> i32;

    /// `data->info.httpcode = 0` (`lib/cf-h1-proxy.c:170`) -- *"clear it as
    /// it might have been used for the proxy"*.
    ///
    /// The h1 tunnel does this on entering ESTABLISHED or FAILED; the h2
    /// tunnel deliberately does NOT (`lib/cf-h2-proxy.c:154-162` has no such
    /// line), so the call site is in exactly one of the two.
    fn clear_info_http_code(&self);

    /// `data->req.ignorebody = FALSE` (`lib/cf-h2-proxy.c:125`), on LEAVING
    /// the h2 CONNECT state. The h1 tunnel has no such hook.
    ///
    /// Defaults to doing nothing, because only the HTTP/2 tunnel calls it.
    #[allow(dead_code)] // consumer: H2Proxy::go_state
    fn set_ignore_body(&self, ignore: bool) {
        let _ = ignore;
    }

    /// `Curl_req_soft_reset(&data->req, data)`
    /// (`lib/cf-h1-proxy.c:617`, `:700`, `lib/cf-h2-proxy.c:1011`).
    ///
    /// # Errors
    ///
    /// Whatever the request layer reports.
    fn req_soft_reset(&self) -> CurlResult<()>;

    /// `Curl_client_reset(data)`
    /// (`lib/cf-h1-proxy.c:701`, `lib/cf-h2-proxy.c:1012`).
    fn client_reset(&self);

    /// `Curl_pgrsReset(data)` (`lib/cf-h1-proxy.c:702`).
    ///
    /// Called by the h1 tunnel alone. `cf_h2_proxy_connect` does NOT reset
    /// the progress meter, which is measured and preserved.
    fn progress_reset(&self);

    /// `Curl_pgrsUpdate(data)` (`lib/cf-h1-proxy.c:444`, `:602`).
    ///
    /// # Errors
    ///
    /// `CURLE_ABORTED_BY_CALLBACK` when a progress callback asks to stop,
    /// which is what makes this fallible and why the C tests its return
    /// inside the byte-at-a-time read loop.
    fn progress_update(&self) -> CurlResult<()>;

    /// `Curl_creader_set_null(data)`
    /// (`lib/cf-h1-proxy.c:227`, `lib/cf-h2-proxy.c:755`): the `CONNECT`
    /// request has no body, so the reader chain must produce nothing.
    ///
    /// # Errors
    ///
    /// Whatever the reader layer reports.
    fn set_reader_null(&self) -> CurlResult<()>;

    /// `Curl_client_write(data, writetype, ptr, len)`
    /// (`lib/cf-h1-proxy.c:366`): hand one response header line to the
    /// client-writer chain.
    ///
    /// `flags` is the combination [`H1Tunnel::single_header`] composes, and
    /// it always contains [`CLIENTWRITE_CONNECT`], which is what tags the
    /// line with origin [`crate::headers::CURLH_CONNECT`] so
    /// `curl_easy_header` can filter it.
    ///
    /// # Errors
    ///
    /// Whatever the writer chain reports.
    fn client_write(&self, flags: u32, line: &[u8]) -> CurlResult<()>;

    /// `Curl_bump_headersize(data, len, TRUE)`
    /// (`lib/cf-h1-proxy.c:370`): account one header line against
    /// `CURL_MAX_HTTP_HEADER`.
    ///
    /// The trailing `TRUE` is `connect_only`, which is why the parameter is
    /// here rather than assumed.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] once the response headers exceed the ceiling.
    fn bump_header_size(
        &self,
        len: usize,
        connect_only: bool,
    ) -> CurlResult<()>;

    /// `Curl_httpchunk_read(data, ch, buf, blen, &consumed)`
    /// (`lib/cf-h1-proxy.c:486`): feed the ignored 407 body to the chunked
    /// decoder.
    ///
    /// The [`Chunker`] belongs to the tunnel, exactly as `struct
    /// Curl_chunker ch` is a member of `struct h1_tunnel_state`, and is
    /// passed in. What the implementor supplies is the
    /// [`crate::transfer::sendf::ClientCtx`] the decoder writes through --
    /// which a filter has no way to build, and which is the whole reason this
    /// is a seam method rather than a direct call.
    ///
    /// # Errors
    ///
    /// Whatever [`Chunker::read`] reports, which is
    /// [`CURLcode::RecvError`] for a framing fault.
    fn chunk_read(
        &self,
        chunker: &mut Chunker,
        buf: &[u8],
    ) -> CurlResult<usize>;

    /// `Curl_timeleft_ms(data)`
    /// (`lib/cf-h1-proxy.c:572`, `lib/cf-h2-proxy.c:995`).
    ///
    /// The three-way convention of [`crate::conn::timeleft_ms`] holds: zero
    /// means no limit, a negative reading means the deadline has already
    /// passed, and a positive one is the milliseconds remaining. Only a
    /// NEGATIVE reading aborts the `CONNECT`.
    fn time_left_ms(&self) -> TimeDiff;

    // -- HTTP/2 only ------------------------------------------------------

    /// `Curl_multi_max_concurrent_streams(data->multi)`
    /// (`lib/cf-h2-proxy.c:931`): the value the initial SETTINGS frame
    /// announces.
    ///
    /// Defaults to [`crate::protocols::http2::DEFAULT_MAX_CONCURRENT_STREAMS`],
    /// which is the multi handle's own default (`lib/http2.h:32`).
    #[cfg(feature = "http2")]
    fn max_concurrent_streams(&self) -> u32 {
        crate::protocols::http2::DEFAULT_MAX_CONCURRENT_STREAMS
    }

    /// `Curl_multi_mark_dirty(data)` (`lib/cf-h2-proxy.c:217`): there is
    /// buffered work, so the transfer must be run again even without a socket
    /// event.
    ///
    /// Defaults to doing nothing, which loses only a scheduling hint.
    #[cfg(feature = "http2")]
    fn mark_dirty(&self) {}

    /// `CURL_WANT_SEND(data)` (`lib/cf-h2-proxy.c:480`, `:515`): the transfer
    /// still has request body to send, so a SETTINGS or WINDOW_UPDATE frame
    /// should un-hold it.
    ///
    /// Defaults to `false`: a `CONNECT` itself carries no body.
    #[cfg(feature = "http2")]
    fn wants_send(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// 5. The `CONNECT` request -- `Curl_http_proxy_create_CONNECT`, and the bytes
//    it turns into.
// ---------------------------------------------------------------------------

/// The `CONNECT` request, as `struct httpreq` holds it
/// (`lib/http.h:210-218`) once `Curl_http_req_make(&req, "CONNECT", ..., NULL,
/// 0, authority, ..., NULL, 0)` has built it.
///
/// Three of the C struct's six members are reproduced and three are not:
/// `scheme` and `path` are NULL for a `CONNECT` by construction and their
/// absence is what collapses the request line (see [`write_head`]), and
/// `trailers` is never populated on this path.
#[derive(Clone, Debug)]
pub(crate) struct ConnectRequest {
    /// `req->method` -- always `"CONNECT"`, and the literal appears once.
    pub(crate) method: &'static str,
    /// `req->authority` -- `host:port`, with a literal IPv6 address
    /// bracketed.
    pub(crate) authority: String,
    /// `req->headers`, in insertion order, which IS wire order.
    pub(crate) headers: HeaderSet,
}

/// The method token, `sizeof("CONNECT") - 1` bytes of it
/// (`lib/http_proxy.c:219`).
pub(crate) const CONNECT_METHOD: &str = "CONNECT";

/// The `Host` header's name (`lib/http_proxy.c:233-234`).
const NAME_HOST: &str = "Host";

/// The `User-Agent` header's name (`lib/http_proxy.c:246-248`).
const NAME_USER_AGENT: &str = "User-Agent";

/// The `Proxy-Connection` header's name (`lib/http_proxy.c:255-256`).
const NAME_PROXY_CONNECTION: &str = "Proxy-Connection";

/// The one value `Proxy-Connection` ever takes here
/// (`lib/http_proxy.c:256`).
const KEEP_ALIVE: &str = "Keep-Alive";

/// `Curl_http_proxy_create_CONNECT(&req, cf, data, http_version_major)`
/// (`lib/http_proxy.c:197-271`).
///
/// # The emission order IS the contract
///
/// Six steps, and the order of the four that emit is frozen by the corpus.
/// `tests/data/test275`'s `<verify><proxy>` block is, byte for byte:
///
/// ```text
/// CONNECT remotesite.com.275:$PORT HTTP/1.1\r\n
/// Host: remotesite.com.275:$PORT\r\n
/// Proxy-Authorization: Basic eW91YXJlOnlvdXJzZWxm\r\n
/// User-Agent: curl/$VERSION\r\n
/// Proxy-Connection: Keep-Alive\r\n
/// \r\n
/// ```
///
/// 1. **Authentication runs first and emits nothing.**
///    [`TunnelConn::output_auth`] composes
///    `data->state.aptr.proxyuserpwd` as a side effect; the header it
///    produces is added by step 3.
/// 2. **`Host:`**, and ONLY when `http_version_major == 1`. Under HTTP/2 the
///    `:authority` pseudo-header carries the same information and a `Host`
///    field is additionally forbidden by `H2_NON_FIELD`.
/// 3. **The `Proxy-Authorization:` line**, appended whole with
///    [`HeaderSet::h1_add_line`] because that is what the C's
///    `Curl_dynhds_h1_cadd_line` does: it splits the composed line at its
///    first colon rather than taking a name and a value.
/// 4. **`User-Agent:`**, unless a custom proxy header overrides it or the
///    option is unset or empty.
/// 5. **`Proxy-Connection: Keep-Alive`**, again only under HTTP/1.
/// 6. **The application's own headers, LAST** -- `dynhds_add_custom(data,
///    TRUE, ...)`.
///
/// **There is no `Accept:` header on a `CONNECT`.** The origin request has
/// one; this does not, and adding one would break every fixture in the set.
///
/// # The asymmetry with the non-tunnel proxy request -- do NOT unify them
///
/// A plain request through an HTTP proxy carries an absolute URI and is
/// composed by [`crate::protocols::http1`] from its own slot table
/// (`H1Hd`). Its order differs in TWO ways, and `tests/data/test1630` pins
/// both:
///
/// ```text
/// GET http://host/path HTTP/1.1     <- absolute URI, not an authority
/// Host: ...
/// Proxy-Authorization: ...
/// User-Agent: curl/...
/// Accept: */*                       <- exists there, never here
/// Proxy-Connection: Keep-Alive      <- AFTER Accept there, before the
///                                      custom headers here
/// ```
///
/// The two emitters are therefore separate on purpose. Folding them into one
/// would be a "different but arguably better" change of exactly the kind the
/// preservation mandate forbids, and the fixtures would catch it as a wire
/// difference rather than as a refactor.
///
/// # `http_version_major`, and a type confusion in the C that is NOT copied
///
/// The C's final step passes `ctx->httpversion`, having opened with
/// `struct cf_proxy_ctx *ctx = cf->ctx;` (`lib/http_proxy.c:202`). But
/// `cf` here is the **H1-PROXY or H2-PROXY** filter, not the HTTP-PROXY one:
/// `start_CONNECT` calls this with its own filter (`lib/cf-h1-proxy.c:214`)
/// and so does `submit_CONNECT` (`lib/cf-h2-proxy.c:752`). Their contexts are
/// `struct h1_tunnel_state` and `struct cf_h2_proxy_ctx`, whose first members
/// are a `struct dynbuf` and an `nghttp2_session *`, so `ctx->httpversion`
/// reads the low half of a pointer rather than a version number.
///
/// That is undefined behaviour and cannot be reproduced. `httpversion` is
/// therefore DERIVED here from `http_version_major`, which is what the C
/// plainly intends, and the derivation is observably equivalent: the value's
/// only use is `(httpversion >= 20)` suppressing a custom
/// `Transfer-Encoding`, and under HTTP/2 that field is dropped anyway by
/// `H2_NON_FIELD` in [`req_to_h2`]. The garbage read can only ever cause a
/// SPURIOUS suppression on an HTTP/1 `CONNECT`, which no fixture asks for.
///
/// # Errors
///
/// Whatever [`TunnelConn::output_auth`] reports, and
/// [`CURLcode::OutOfMemory`] from [`HeaderSet::add`] when the 1 MiB string
/// ceiling `Curl_http_req_make` sets is reached --
/// `Curl_dynhds_init(&req->headers, 0, DYN_HTTP_REQUEST)`
/// (`lib/http.c:4643`), which is what [`HeaderSet::new`] is.
pub(crate) fn create_connect(
    conn: &dyn TunnelConn,
    http_version_major: u8,
) -> CurlResult<ConnectRequest> {
    let dest = destination(conn);

    // `authority = curl_maprintf("%s%s%s:%d", ipv6_ip ? "[" : "", hostname,
    //  ipv6_ip ? "]" : "", port);`
    let authority = dest.authority();

    let mut headers = HeaderSet::new();

    // Step 1: `Curl_http_output_auth(data, cf->conn, req->method,
    // HTTPREQ_GET, req->authority, TRUE)`. Adds no header; composes
    // `proxyuserpwd` for step 3.
    conn.output_auth(CONNECT_METHOD, &authority)?;

    // Step 2: `if(http_version_major == 1 && !Curl_checkProxyheaders(data,
    // conn, STRCONST("Host")))`.
    if http_version_major == 1 && check_proxy_headers(conn, NAME_HOST).is_none()
    {
        headers.add(NAME_HOST.as_bytes(), authority.as_bytes())?;
    }

    // Step 3: `if(data->state.aptr.proxyuserpwd)
    // Curl_dynhds_h1_cadd_line(&req->headers, data->state.aptr.proxyuserpwd)`.
    if let Some(line) = conn.proxy_user_pwd() {
        headers.h1_add_line(line.as_bytes())?;
    }

    // Step 4: three conditions, all of which must hold.
    let user_agent = conn.user_agent();
    if check_proxy_headers(conn, NAME_USER_AGENT).is_none() {
        if let Some(agent) = user_agent.as_deref().filter(|a| !a.is_empty()) {
            headers.add(NAME_USER_AGENT.as_bytes(), agent.as_bytes())?;
        }
    }

    // Step 5: `if(http_version_major == 1 &&
    // !Curl_checkProxyheaders(data, conn, STRCONST("Proxy-Connection")))`.
    if http_version_major == 1
        && check_proxy_headers(conn, NAME_PROXY_CONNECTION).is_none()
    {
        headers.add(NAME_PROXY_CONNECTION.as_bytes(), KEEP_ALIVE.as_bytes())?;
    }

    // Step 6: the application's headers, last. `httpversion` is derived; see
    // the type-confusion note above.
    let httpversion = if http_version_major >= 2 { 20 } else { 11 };
    add_custom_headers(conn, ProxyUse::Connect, httpversion, &mut headers)?;

    Ok(ConnectRequest {
        method: CONNECT_METHOD,
        authority,
        headers,
    })
}

/// `Curl_checkProxyheaders(data, conn, thisheader, thislen)`
/// (`lib/http.c:150-165`), as a `CONNECT` sees it.
///
/// The C selects the list with `(conn->bits.proxy && data->set.sep_headers) ?
/// data->set.proxyheaders : data->set.headers`. `conn->bits.proxy` is true by
/// construction wherever this module runs -- the filter exists because a proxy
/// is configured -- so the choice reduces to `sep_headers`, and that is the
/// only term left here. The scan itself is
/// [`crate::transfer::checkheaders`], which already carries the two
/// properties that matter: ASCII-only case folding, and the `Curl_headersep`
/// test on the byte after the name so that `Host` does not match
/// `Hostage:`.
fn check_proxy_headers(conn: &dyn TunnelConn, name: &str) -> Option<String> {
    let list = if conn.separate_headers() {
        conn.proxy_headers()
    } else {
        conn.custom_headers()
    };
    crate::transfer::checkheaders(&list, name).map(str::to_owned)
}

/// `dynhds_add_custom(data, is_connect, httpversion, hds)`
/// (`lib/http_proxy.c:40-163`): the application's own headers.
///
/// # The two quirks, both load-bearing
///
/// The C's own comment names them: *"setting only 'name:' to suppress a
/// header from being sent"* and *"setting only 'name;' to send an empty
/// (illegal) header"*. So `-H "Accept:"` removes a header and
/// `-H "Accept;"` emits `Accept: `, and anything else -- a `name;` with text
/// after it, or a header with neither separator -- is silently ignored.
///
/// # The five suppression rules, in the C's order
///
/// A header that reaches the value stage is still dropped when:
///
/// 1. it is `Host` and a `Host:` line was already composed for the origin
///    request, *"as that will produce \*two\* in the same request!"*;
/// 2. it is `Content-Type` and the form or MIME layer sends its own later;
/// 3. it is `Content-Length` while an authentication probe is forcing zero;
/// 4. it is `Transfer-Encoding` and `httpversion >= 20`, because HTTP/2 and
///    HTTP/3 have no chunked framing;
/// 5. it is `Authorization` or `Cookie` and the redirect chain has left the
///    original host -- *"be careful of sending this potentially sensitive
///    header to other hosts"*.
///
/// # Errors
///
/// Whatever [`HeaderSet::add`] reports.
fn add_custom_headers(
    conn: &dyn TunnelConn,
    proxy: ProxyUse,
    httpversion: i32,
    out: &mut HeaderSet,
) -> CurlResult<()> {
    let (server_list, proxy_list) = proxy.lists(conn.separate_headers());
    let mut lists: Vec<Vec<String>> = Vec::new();
    if server_list {
        lists.push(conn.custom_headers());
    }
    if proxy_list {
        lists.push(conn.proxy_headers());
    }

    for list in &lists {
        for header in list {
            let Some((name, value)) = split_custom_header(header) else {
                continue;
            };
            if suppressed(conn, name, httpversion) {
                continue;
            }
            out.add(name.as_bytes(), value.as_bytes())?;
        }
    }
    Ok(())
}

/// One custom header split into name and value, or [`None`] for a header the
/// C ignores.
///
/// `curlx_str_cspn(&ptr, &name, ";:")` then `curlx_str_single(&ptr, ':')` or
/// `curlx_str_single(&ptr, ';')`, with `curlx_str_passblanks` after the
/// separator (`lib/http_proxy.c:89-118`).
fn split_custom_header(header: &str) -> Option<(&str, &str)> {
    // `if(!curlx_str_cspn(&ptr, &name, ";:"))` -- a header with NEITHER
    // separator has "no name" and is skipped.
    let at = header.find([':', ';'])?;
    let (name, rest) = header.split_at(at);
    let mut chars = rest.chars();
    let separator = chars.next()?;
    // `curlx_str_passblanks(&ptr)` -- space and tab only.
    let value = chars.as_str().trim_start_matches([' ', '\t']);

    match separator {
        // `name: value` -- and `name:` alone is quirk #1, suppression.
        ':' if !value.is_empty() => Some((name, value)),
        ':' => None,
        // `name;` alone is quirk #2, an empty header. `name; something` is
        // *"this may be used for something else in the future"* and ignored.
        ';' if value.is_empty() => Some((name, "")),
        _ => None,
    }
}

/// The five conditions that drop a custom header
/// (`lib/http_proxy.c:124-151`).
fn suppressed(conn: &dyn TunnelConn, name: &str, httpversion: i32) -> bool {
    let name = name.as_bytes();
    if conn.origin_host_header_composed() && casecompare(name, b"Host") {
        return true;
    }
    if conn.request_sends_own_content_type()
        && casecompare(name, b"Content-Type")
    {
        return true;
    }
    if conn.auth_negotiating() && casecompare(name, b"Content-Length") {
        return true;
    }
    if httpversion >= 20 && casecompare(name, b"Transfer-Encoding") {
        return true;
    }
    if (casecompare(name, b"Authorization") || casecompare(name, b"Cookie"))
        && !conn.auth_allowed_to_host()
    {
        return true;
    }
    false
}

/// `Curl_h1_req_write_head(req, http_minor, dbuf)` (`lib/http1.c:317-338`),
/// for a request whose `scheme` and `path` are both NULL.
///
/// The C's format string is
///
/// ```text
/// "%s %s%s%s%s HTTP/1.%d\r\n"
///   method, scheme ?: "", scheme ? "://" : "", authority ?: "", path ?: ""
/// ```
///
/// so with no scheme and no path every empty conversion collapses and the
/// line is exactly `CONNECT <authority> HTTP/1.<minor>\r\n`. That collapse is
/// why a `CONNECT` request line has an authority where every other request
/// has a target.
///
/// Then [`HeaderSet::h1_dprint`], which emits `"%.*s: %.*s\r\n"` per entry in
/// insertion order (`lib/dynhds.c:297-316`), and then a bare `"\r\n"`.
///
/// `http_minor` is `0` only for `CURLPROXY_HTTP_1_0` -- `--proxy1.0` --
/// and `1` for every other proxy type (`lib/cf-h1-proxy.c:223`), including
/// the HTTPS ones.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] once `out`'s ceiling is reached, which for the
/// [`DYN_HTTP_REQUEST`] buffer `start_CONNECT` uses is 1 MiB.
pub(crate) fn write_head(
    req: &ConnectRequest,
    http_minor: u8,
    out: &mut DynBuf,
) -> CurlResult<()> {
    out.addf(format_args!(
        "{} {} HTTP/1.{}\r\n",
        req.method, req.authority, http_minor
    ))?;
    req.headers.h1_dprint(out)?;
    out.addn(b"\r\n")?;
    Ok(())
}

/// `http_minor` for a proxy type (`lib/cf-h1-proxy.c:223`).
pub(crate) const fn http_minor_for(proxy_type: ProxyType) -> u8 {
    match proxy_type {
        ProxyType::Http10 => 0,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// 6. `Curl_cf_http_proxy_query` -- shared by `"HTTP-PROXY"` and `"H1-PROXY"`.
// ---------------------------------------------------------------------------

/// `Curl_cf_http_proxy_query(cf, data, query, pres1, pres2)`
/// (`lib/http_proxy.c:354-375`).
///
/// ONE function in the C, named in the `.query` slot of both
/// `Curl_cft_http_proxy` (`:410`) and `Curl_cft_h1_proxy` (`:772`), and one
/// function here for the same reason: the two filters must answer the two
/// questions identically or a caller gets a different answer depending on
/// which of them it happens to reach first.
///
/// * **`CF_QUERY_HOST_PORT` answers with the PROXY's host and port.** That is
///   the OPPOSITE of `socks_cf_query` (`lib/socks.c:1356-1382`), which
///   answers with the DESTINATION. Both are measured and neither may be
///   changed: a caller asking a SOCKS chain who it is talking to means the far
///   end, while a caller asking an HTTP proxy chain means the proxy, because
///   that is the peer whose certificate and identity apply.
/// * **`CF_QUERY_ALPN_NEGOTIATED` answers NOTHING** rather than declining.
///   [`None`] is a real answer here: a `CONNECT` tunnel negotiates no
///   application protocol of its own, and letting the question fall through
///   would report whatever the TLS filter below happened to have negotiated
///   with the PROXY.
///
/// [`None`] as the return means "not answered here", which the caller turns
/// into a walk down the chain.
fn http_proxy_query(
    conn: &dyn TunnelConn,
    query: CfQuery,
) -> Option<CfQueryValue> {
    match query {
        CfQuery::HostPort => Some(CfQueryValue::HostPort {
            host: conn.proxy_host(),
            port: conn.proxy_port(),
        }),
        CfQuery::AlpnNegotiated => Some(CfQueryValue::AlpnNegotiated(None)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 7. Diagnostics -- the three emitters every filter here shares.
// ---------------------------------------------------------------------------

/// `CURL_TRC_CF(data, cf, ...)`: one filter-attributed trace line.
///
/// The identity is [`ConnFilter::trace_filter`]'s answer, so a filter with no
/// registered name traces nothing rather than guessing a label.
fn trace_line(
    cx: &mut CallCtx<'_, '_>,
    identity: Option<TraceFilter>,
    sockindex: i32,
    line: &str,
) {
    if let Some(identity) = identity {
        if let Some(tracer) = cx.tracer_mut() {
            trc_cf!(tracer, identity, sockindex, "{}", line);
        }
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

/// `Curl_debug(data, type, ptr, len)` (`lib/cf-h1-proxy.c:263`, `:361`): the
/// protocol bytes `--trace` and `CURLOPT_DEBUGFUNCTION` see.
fn debug_bytes(cx: &mut CallCtx<'_, '_>, kind: InfoType, payload: &[u8]) {
    if let Some(tracer) = cx.tracer_mut() {
        tracer.debug(kind, payload);
    }
}

// ---------------------------------------------------------------------------
// 8. `"H1-PROXY"` -- the six-state tunnel of `lib/cf-h1-proxy.c`.
// ---------------------------------------------------------------------------

/// `h1_tunnel_state` (`lib/cf-h1-proxy.c:44-51`).
///
/// Six states, and the two terminal ones are not interchangeable:
/// [`Self::Established`] means the tunnel carries traffic, while
/// [`Self::Failed`] means the filter needs *"a cfilter close and new
/// bootstrap"* -- so [`H1Proxy`]'s connect answers
/// [`CURLcode::RecvError`] for it rather than retrying in place.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum H1TunnelState {
    /// `H1_TUNNEL_INIT` -- *"init/default/no tunnel state"*.
    #[default]
    Init,
    /// `H1_TUNNEL_CONNECT` -- *"CONNECT request is being send"*.
    Connect,
    /// `H1_TUNNEL_RECEIVE` -- *"CONNECT answer is being received"*.
    Receive,
    /// `H1_TUNNEL_RESPONSE` -- *"CONNECT response received completely"*.
    Response,
    /// `H1_TUNNEL_ESTABLISHED`.
    Established,
    /// `H1_TUNNEL_FAILED`.
    Failed,
}

impl H1TunnelState {
    /// `tunnel_want_send(ts)` (`lib/cf-h1-proxy.c:196-199`), as a property of
    /// the STATE rather than of the tunnel -- which is where the C reads it
    /// from: `ts->tunnel_state == H1_TUNNEL_CONNECT` and nothing else.
    ///
    /// It decides the poll direction, so getting it wrong stalls a transfer on
    /// a socket that will never become ready in the direction being watched.
    pub(crate) const fn wants_send(self) -> bool {
        matches!(self, Self::Connect)
    }

    /// Every state, in the C's declaration order.
    #[allow(dead_code)] // Read by this module's own tests.
    pub(crate) const ALL: [Self; 6] = [
        Self::Init,
        Self::Connect,
        Self::Receive,
        Self::Response,
        Self::Established,
        Self::Failed,
    ];

    /// The trace line `h1_tunnel_go_state` emits on ENTERING this state
    /// (`lib/cf-h1-proxy.c:136-165`), character for character.
    pub(crate) const fn entry_trace(self) -> &'static str {
        match self {
            Self::Init => "new tunnel state 'init'",
            Self::Connect => "new tunnel state 'connect'",
            Self::Receive => "new tunnel state 'receive'",
            Self::Response => "new tunnel state 'response'",
            Self::Established => "new tunnel state 'established'",
            Self::Failed => "new tunnel state 'failed'",
        }
    }
}

/// `enum keeponval` (`lib/cf-h1-proxy.c:60-64`): why the read loop is still
/// running.
///
/// The C's loop condition is the bare `while(ts->keepon)`, so
/// [`Self::Done`] -- which is the enumeration's ZERO -- is what ends it. That
/// is why this type is not a `bool`: [`Self::Ignore`] also keeps the loop
/// running, but reading a body rather than headers.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum KeepOn {
    /// `KEEPON_DONE` = 0 -- the read loop stops.
    #[default]
    Done,
    /// `KEEPON_CONNECT` = 1 -- reading the `CONNECT` response headers.
    Connect,
    /// `KEEPON_IGNORE` = 2 -- draining a body that must be discarded.
    Ignore,
}

impl KeepOn {
    /// The C's `while(ts->keepon)` truth test.
    pub(crate) const fn keeps_going(self) -> bool {
        !matches!(self, Self::Done)
    }
}

/// `"CONNECT response too large"` (`lib/cf-h1-proxy.c:518`, `:524`).
///
/// TWO call sites in the C, one for the space inserted while unfolding and one
/// for the byte itself, and both are reproduced: either append can be the one
/// that crosses [`DYN_PROXY_CONNECT_HEADERS`].
pub(crate) const RESPONSE_TOO_LARGE: &str = "CONNECT response too large";

/// `"Failed sending CONNECT to proxy"` (`lib/cf-h1-proxy.c:231`, `:267`).
pub(crate) const CONNECT_SEND_FAILED: &str = "Failed sending CONNECT to proxy";

/// `"Proxy CONNECT aborted"` (`lib/cf-h1-proxy.c:461`).
pub(crate) const CONNECT_ABORTED: &str = "Proxy CONNECT aborted";

/// `"Proxy CONNECT connection closed"` (`lib/cf-h1-proxy.c:457`).
pub(crate) const CONNECT_CLOSED: &str = "Proxy CONNECT connection closed";

/// `"Proxy CONNECT aborted due to timeout"`
/// (`lib/cf-h1-proxy.c:573`, `lib/cf-h2-proxy.c:996`).
pub(crate) const CONNECT_TIMEOUT: &str = "Proxy CONNECT aborted due to timeout";

/// `"Unsupported Content-Length value"` (`lib/cf-h1-proxy.c:308`).
pub(crate) const BAD_CONTENT_LENGTH: &str = "Unsupported Content-Length value";

/// `"CONNECT phase completed"`
/// (`lib/cf-h1-proxy.c:159`, `lib/cf-h2-proxy.c:150`).
pub(crate) const CONNECT_PHASE_COMPLETED: &str = "CONNECT phase completed";

/// `"Connect me again please"` (`lib/cf-h1-proxy.c:625`).
pub(crate) const CONNECT_AGAIN: &str = "Connect me again please";

/// `"allocate connect buffer"` (`lib/cf-h1-proxy.c:116`).
pub(crate) const ALLOCATE_BUFFER: &str = "allocate connect buffer";

/// `struct h1_tunnel_state` (`lib/cf-h1-proxy.c:54-71`), as a typed field.
///
/// Every member of the C struct is here and nothing else is. `struct
/// Curl_chunker ch` stays a member, as it is there, because the decoder's
/// position has to survive between the byte-at-a-time feeds that drain an
/// ignored body.
#[derive(Debug)]
pub(crate) struct H1Tunnel {
    /// `rcvbuf` -- the response line being accumulated, at the
    /// [`DYN_PROXY_CONNECT_HEADERS`] ceiling.
    rcvbuf: DynBuf,
    /// `request_data` -- the composed `CONNECT` request, at the
    /// [`DYN_HTTP_REQUEST`] ceiling.
    request_data: DynBuf,
    /// `nsent` -- how much of `request_data` has reached the wire.
    nsent: usize,
    /// `headerlines` -- how many response lines have been seen; the FIRST is
    /// the status line.
    headerlines: usize,
    /// `ch` -- the chunked decoder for an ignored 407 body.
    ch: Chunker,
    /// `keepon`.
    keepon: KeepOn,
    /// `cl` -- *"size of content to read and ignore"*.
    cl: i64,
    /// `tunnel_state`.
    state: H1TunnelState,
    /// `chunked_encoding`.
    chunked_encoding: bool,
    /// `close_connection`.
    close_connection: bool,
    /// `maybe_folded`.
    maybe_folded: bool,
    /// `leading_unfold`.
    leading_unfold: bool,
}

impl H1Tunnel {
    /// `tunnel_init(cf, data, &ts)` (`lib/cf-h1-proxy.c:101-124`).
    ///
    /// # The scheme check comes FIRST, before anything is allocated
    ///
    /// `if(cf->conn->scheme->flags & PROTOPT_NOTCPPROXY) { failf(data, "%s
    /// cannot be done over CONNECT", cf->conn->scheme->name); return
    /// CURLE_UNSUPPORTED_PROTOCOL; }`. This is the ONE enforcement point for
    /// [`ProtocolOptions::NOTCPPROXY`] in the whole tunnel, and its position
    /// is why: a scheme that cannot be tunnelled is refused before a buffer
    /// exists, so nothing has to be released on the refusal path.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnsupportedProtocol`] for a scheme carrying
    /// [`ProtocolOptions::NOTCPPROXY`]. The C's other failure, a failed
    /// `calloc`, has no counterpart: the state is a value.
    pub(crate) fn init(
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
    ) -> CurlResult<Self> {
        if conn.scheme_flags().intersects(ProtocolOptions::NOTCPPROXY) {
            let line =
                format!("{} cannot be done over CONNECT", conn.scheme_name());
            fail_line(cx, &line);
            return Err(Error::with_context(
                CURLcode::UnsupportedProtocol,
                line,
            ));
        }

        info_line(cx, ALLOCATE_BUFFER);

        let mut tunnel = Self {
            rcvbuf: DynBuf::new(DYN_PROXY_CONNECT_HEADERS),
            request_data: DynBuf::new(DYN_HTTP_REQUEST),
            nsent: 0,
            headerlines: 0,
            // `Curl_httpchunk_init(data, &ts->ch, TRUE)` -- the TRUE is
            // `ignore_body`, so the decoder frames the 407 body without
            // writing a byte of it anywhere.
            ch: Chunker::new(true),
            keepon: KeepOn::Done,
            cl: 0,
            state: H1TunnelState::Init,
            chunked_encoding: false,
            close_connection: false,
            maybe_folded: false,
            leading_unfold: false,
        };
        // `return tunnel_reinit(cf, data, ts);`
        tunnel.reinit();
        Ok(tunnel)
    }

    /// `tunnel_reinit(cf, data, ts)` (`lib/cf-h1-proxy.c:83-99`).
    ///
    /// # What it does NOT reset, and why that matters
    ///
    /// Seven members are cleared. `nsent` and `headerlines` are NOT among
    /// them -- [`Self::start_connect`] clears those, because they describe one
    /// REQUEST rather than one tunnel attempt. Nor is `chunked_encoding`,
    /// which the C never clears anywhere: it is `FALSE` from the `calloc` and
    /// only ever set `TRUE` (`lib/cf-h1-proxy.c:328`). Both asymmetries are
    /// measured and reproduced rather than tidied, because tidying either
    /// changes what a second `CONNECT` on the same tunnel does.
    fn reinit(&mut self) {
        self.rcvbuf.reset();
        self.request_data.reset();
        self.state = H1TunnelState::Init;
        self.keepon = KeepOn::Connect;
        self.cl = 0;
        self.close_connection = false;
        self.maybe_folded = false;
        self.leading_unfold = false;
    }

    /// Where the tunnel is -- for the pollset, the tests and the trace.
    #[allow(dead_code)] // Consumers: this module's tests.
    pub(crate) const fn state(&self) -> H1TunnelState {
        self.state
    }

    /// `tunnel_is_established(ts)` (`lib/cf-h1-proxy.c:73-76`).
    const fn is_established(&self) -> bool {
        matches!(self.state, H1TunnelState::Established)
    }

    /// `tunnel_is_failed(ts)` (`lib/cf-h1-proxy.c:78-81`).
    const fn is_failed(&self) -> bool {
        matches!(self.state, H1TunnelState::Failed)
    }

    /// `tunnel_want_send(ts)` (`lib/cf-h1-proxy.c:196-199`): TRUE in exactly
    /// one state.
    const fn want_send(&self) -> bool {
        self.state.wants_send()
    }

    /// `h1_tunnel_go_state(cf, ts, new_state, data)`
    /// (`lib/cf-h1-proxy.c:126-178`).
    ///
    /// **Returns immediately when the state is unchanged**, which is what
    /// keeps the entry actions -- and their trace lines -- from running twice
    /// on a re-entrant pass.
    ///
    /// # The fall-through from ESTABLISHED into FAILED
    ///
    /// The C's `case H1_TUNNEL_ESTABLISHED:` ends in `FALLTHROUGH()` into
    /// `case H1_TUNNEL_FAILED:`, so success and failure share one body:
    /// both empty the two buffers, clear `data->info.httpcode` and free
    /// `data->state.aptr.proxyuserpwd`. Only the two lines BEFORE the
    /// fall-through are success-only. Reproducing the shared tail is not
    /// tidiness -- the credential scrub in particular must happen on BOTH
    /// paths, or a `Proxy-Authorization` composed for the proxy would be
    /// carried into the document request.
    fn go_state(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
        sockindex: i32,
        new_state: H1TunnelState,
    ) {
        if self.state == new_state {
            return;
        }
        let identity = TraceFilter::from_name(H1_PROXY_FILTER_NAME.as_bytes());
        trace_line(cx, identity, sockindex, new_state.entry_trace());

        match new_state {
            // `tunnel_reinit(cf, data, ts)`, which sets the state itself.
            H1TunnelState::Init => self.reinit(),
            H1TunnelState::Connect => {
                self.state = new_state;
                self.keepon = KeepOn::Connect;
                self.rcvbuf.reset();
            }
            H1TunnelState::Receive | H1TunnelState::Response => {
                self.state = new_state;
            }
            H1TunnelState::Established | H1TunnelState::Failed => {
                if matches!(new_state, H1TunnelState::Established) {
                    info_line(cx, CONNECT_PHASE_COMPLETED);
                    conn.set_proxy_auth_done(true);
                    conn.set_proxy_auth_multipass(false);
                }
                // The shared tail, reached by fall-through in the C.
                self.state = new_state;
                self.rcvbuf.reset();
                self.request_data.reset();
                conn.clear_info_http_code();
                conn.clear_proxy_user_pwd();
            }
        }
    }

    /// `start_CONNECT(cf, data, ts)` (`lib/cf-h1-proxy.c:201-235`).
    ///
    /// The stale `data->req.newurl` is freed FIRST -- *"This only happens if
    /// we have looped here due to authentication reasons, and we do not really
    /// use the newly cloned URL here then"* -- because the driver loop's
    /// condition is that very field, and leaving it set would loop for ever.
    ///
    /// # Errors
    ///
    /// Whatever [`create_connect`], [`write_head`] or
    /// [`TunnelConn::set_reader_null`] reports. Every one of them is
    /// announced with `failf(data, "Failed sending CONNECT to proxy")`, as
    /// the C's single `out:` label does.
    fn start_connect(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
    ) -> CurlResult<()> {
        conn.clear_new_url();

        let outcome = self.compose_connect(cx, conn);
        if outcome.is_err() {
            fail_line(cx, CONNECT_SEND_FAILED);
        }
        outcome
    }

    /// The body of [`Self::start_connect`], separated so the C's single
    /// `out:` label -- which reports one message for every failure -- has one
    /// place to report from.
    fn compose_connect(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
    ) -> CurlResult<()> {
        // `Curl_http_proxy_create_CONNECT(&req, cf, data, 1)`.
        let req = create_connect(conn, 1)?;

        let line = format!("Establish HTTP proxy tunnel to {}", req.authority);
        info_line(cx, &line);

        self.request_data.reset();
        self.nsent = 0;
        self.headerlines = 0;

        // `http_minor = (cf->conn->http_proxy.proxytype ==
        //  CURLPROXY_HTTP_1_0) ? 0 : 1;`
        let http_minor = http_minor_for(conn.proxy_type());
        write_head(&req, http_minor, &mut self.request_data)?;
        conn.set_reader_null()
    }
}

/// `MAX_HTTP_RESP_HEADER_SIZE` (`lib/http.h:169`): the ceiling every response
/// header extractor is bounded by.
///
/// Declared here rather than imported because
/// [`crate::protocols::http1`] keeps its own copy private, and a
/// `pub(crate)` re-export would put a second name on one number. The value is
/// read from the C header, and [`copy_header_value`] is the only consumer in
/// this module.
const MAX_HTTP_RESP_HEADER_SIZE: usize = 100 * 1024;

/// `Curl_copy_header_value(header)` (`lib/http.c:218-232`): the value of a
/// received header line, blank-trimmed.
///
/// The parse is `curlx_str_until(&header, &out, MAX, ':')` then
/// `curlx_str_single(&header, ':')` then `curlx_str_untilnl` and
/// `curlx_str_trimblanks`, and the C's own comment on the failure branch is
/// *"bad input, should never happen"* -- it is a `DEBUGASSERT(0)` followed by
/// `return NULL`. [`None`] is that NULL: the caller
/// ([`H1Tunnel::on_resp_header`]) has already matched the header's name with
/// `checkprefix`, so a line without a colon cannot reach it.
///
/// Distinct from [`crate::protocols::http1::copy_custom_value`], which parses
/// an APPLICATION-supplied header and therefore also accepts `;` as the
/// separator. A header off the wire has a colon or it is not a header.
fn copy_header_value(header: &[u8]) -> Option<Vec<u8>> {
    use crate::util::strparse::{
        str_single, str_trimblanks, str_until, str_untilnl,
    };

    let mut cursor = header;
    str_until(&mut cursor, MAX_HTTP_RESP_HEADER_SIZE, b':').ok()?;
    str_single(&mut cursor, b':').ok()?;
    let value =
        str_untilnl(&mut cursor, MAX_HTTP_RESP_HEADER_SIZE).unwrap_or_default();
    Some(str_trimblanks(value).to_vec())
}

impl H1Tunnel {
    /// `on_resp_header(cf, data, ts, header)` (`lib/cf-h1-proxy.c:272-347`).
    ///
    /// One `if`/`else if` chain over the header's name, in the C's order,
    /// which matters because the arms are mutually exclusive: a line matching
    /// an earlier arm is never offered to a later one.
    ///
    /// # The spellings are the C's, and they differ between the two tunnels
    ///
    /// `checkprefix` is case-insensitive, so the literals below do not decide
    /// what MATCHES. They are reproduced exactly all the same, because the
    /// h1 file writes `"Proxy-authenticate:"` with a lower-case `a` while the
    /// h2 file writes `"Proxy-Authenticate"` canonically
    /// (`lib/cf-h2-proxy.c:795`), and a reader diffing either file against
    /// this one should find its own spelling.
    ///
    /// # The status line's predicate is deliberately narrow
    ///
    /// ```text
    /// !strncmp(header, "HTTP/1.", 7) &&
    /// (header[7] == '0' || header[7] == '1') && header[8] == ' ' &&
    /// ISDIGIT(header[9]) && ISDIGIT(header[10]) && ISDIGIT(header[11]) &&
    /// !ISDIGIT(header[12])
    /// ```
    ///
    /// The trailing `!ISDIGIT(header[12])` is what rejects a four-digit code,
    /// and it reads ONE PAST the three digits -- which is safe in C because
    /// the line is NUL-terminated and is bounds-checked here instead. Only
    /// `HTTP/1.0` and `HTTP/1.1` are accepted; a `CONNECT` answered with
    /// `HTTP/2` over an HTTP/1 tunnel leaves `httpproxycode` at zero, which
    /// [`H1Proxy::h1_connect`] then reports as a failed tunnel.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`] when [`copy_header_value`] cannot allocate --
    /// which is the C's `if(!auth) return CURLE_OUT_OF_MEMORY` --
    /// [`CURLcode::WeirdServerReply`] for a `Content-Length` that is not a
    /// number, and whatever [`TunnelConn::input_auth`] reports.
    fn on_resp_header(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
        sockindex: i32,
        header: &[u8],
    ) -> CurlResult<()> {
        use crate::protocols::http1::compare_header;

        let httpcode = conn.http_code();

        // `(checkprefix("WWW-Authenticate:", header) && (401 == k->httpcode))
        //  || (checkprefix("Proxy-authenticate:", header) &&
        //      (407 == k->httpcode))`
        let is_origin_challenge =
            checkprefix("WWW-Authenticate:", header) && httpcode == 401;
        let is_proxy_challenge =
            checkprefix("Proxy-authenticate:", header) && httpcode == 407;
        if is_origin_challenge || is_proxy_challenge {
            let proxy = httpcode == 407;
            let Some(auth) = copy_header_value(header) else {
                return Err(Error::new(CURLcode::OutOfMemory));
            };
            let identity =
                TraceFilter::from_name(H1_PROXY_FILTER_NAME.as_bytes());
            let line = format!(
                "CONNECT: fwd auth header '{}'",
                String::from_utf8_lossy(header)
            );
            trace_line(cx, identity, sockindex, &line);
            return conn.input_auth(proxy, &auth);
        }

        if checkprefix("Content-Length:", header) {
            if httpcode / 100 == 2 {
                // RFC 7231 4.3.6: *"A client MUST ignore any Content-Length
                // or Transfer-Encoding header fields received in a successful
                // response to CONNECT."*
                let line = format!(
                    "Ignoring Content-Length in CONNECT {httpcode:03} response"
                );
                info_line(cx, &line);
            } else {
                // `const char *p = header + strlen("Content-Length:");` then
                // `curlx_str_numblanks(&p, &ts->cl)`.
                let mut cursor = &header["Content-Length:".len()..];
                match crate::util::strparse::str_numblanks(&mut cursor) {
                    Ok(length) => self.cl = length,
                    Err(_) => {
                        fail_line(cx, BAD_CONTENT_LENGTH);
                        return Err(Error::with_context(
                            CURLcode::WeirdServerReply,
                            BAD_CONTENT_LENGTH,
                        ));
                    }
                }
            }
            return Ok(());
        }

        if compare_header(header, "Connection:", "close") {
            self.close_connection = true;
            return Ok(());
        }

        if checkprefix("Transfer-Encoding:", header) {
            if httpcode / 100 == 2 {
                let line = format!(
                    "Ignoring Transfer-Encoding in CONNECT {httpcode:03} \
                     response"
                );
                info_line(cx, &line);
            } else if compare_header(header, "Transfer-Encoding:", "chunked") {
                info_line(cx, "CONNECT responded chunked");
                self.chunked_encoding = true;
                // `Curl_httpchunk_reset(data, &ts->ch, TRUE)` -- the TRUE is
                // `ignore_body` again, passed back in so a reset cannot
                // silently start writing the body somewhere.
                self.ch.reset(true);
            }
            return Ok(());
        }

        if compare_header(header, "Proxy-Connection:", "close") {
            self.close_connection = true;
            return Ok(());
        }

        if let Some(code) = parse_connect_status(header) {
            // `data->info.httpproxycode = k->httpcode = ...` -- BOTH, and the
            // C assigns them in one expression.
            conn.set_http_proxy_code(code);
            conn.set_http_code(code);
        }
        Ok(())
    }

    /// `single_header(cf, data, ts)` (`lib/cf-h1-proxy.c:349-416`): one
    /// complete response line.
    ///
    /// # The write flags, and what `CLIENTWRITE_CONNECT` buys
    ///
    /// ```text
    /// writetype = CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT |
    ///             (ts->headerlines == 1 ? CLIENTWRITE_STATUS : 0);
    /// ```
    ///
    /// [`CLIENTWRITE_CONNECT`] is what makes
    /// [`crate::headers::classify_origin`] tag the line
    /// [`crate::headers::CURLH_CONNECT`], so `curl_easy_header` can hand an
    /// application the tunnel's headers separately from the origin's. It is
    /// not a decoration: the classification is a FIRST-MATCH chain with
    /// `CONNECT` ahead of `1XX` and `HEADER`, so a `CONNECT`-phase `100
    /// Continue` is filed under the tunnel rather than under the response.
    /// [`CLIENTWRITE_STATUS`] additionally marks the first line, and a
    /// status line is deliberately NOT stored.
    ///
    /// # End of headers
    ///
    /// A line beginning with a newline ends the header block. A 407 with no
    /// authentication problem then switches the read loop to
    /// [`KeepOn::Ignore`] to drain the body -- but only if there IS a body to
    /// drain: with neither a `Content-Length` nor chunked framing the C bails
    /// out at once, *"since the close is the end signal"*, and the connection
    /// cannot be kept alive.
    ///
    /// # Errors
    ///
    /// Whatever [`TunnelConn::client_write`],
    /// [`TunnelConn::bump_header_size`] or [`Self::on_resp_header`] reports.
    fn single_header(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
        sockindex: i32,
    ) -> CurlResult<()> {
        let line = self.rcvbuf.as_slice().to_vec();
        self.headerlines += 1;

        debug_bytes(cx, InfoType::HeaderIn, &line);

        let mut writetype = CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT;
        if self.headerlines == 1 {
            writetype |= CLIENTWRITE_STATUS;
        }
        conn.client_write(writetype, &line)?;
        conn.bump_header_size(line.len(), true)?;

        // `if(ISNEWLINE(linep[0]))` -- the C's comment: *"Newlines are CRLF,
        // so the CR is ignored as the line is not really terminated until the
        // LF comes. Treat a following CR as end-of-headers as well."*
        if matches!(line.first(), Some(b'\r' | b'\n')) {
            if conn.http_code() == 407 && !conn.auth_problem() {
                self.keepon = KeepOn::Ignore;
                if self.cl != 0 {
                    let line =
                        format!("Ignore {} bytes of response-body", self.cl);
                    info_line(cx, &line);
                } else if self.chunked_encoding {
                    info_line(cx, "Ignore chunked response-body");
                } else {
                    let identity =
                        TraceFilter::from_name(H1_PROXY_FILTER_NAME.as_bytes());
                    trace_line(
                        cx,
                        identity,
                        sockindex,
                        "CONNECT: no content-length or chunked",
                    );
                    self.keepon = KeepOn::Done;
                }
            } else {
                self.keepon = KeepOn::Done;
            }
            // The C returns here WITHOUT resetting `rcvbuf`; the buffer is
            // emptied by the state transition that follows.
            return Ok(());
        }

        self.on_resp_header(cx, conn, sockindex, &line)?;
        self.rcvbuf.reset();
        Ok(())
    }

    /// `Curl_http_to_fold(&ts->rcvbuf)` (`lib/http.c:4340-4351`): strip the
    /// line terminator and any trailing blanks, ready for a continuation.
    ///
    /// One `\n`, then one `\r`, then every trailing space and tab -- in that
    /// order, and each conditional on the previous having found something.
    ///
    /// Named for the C function it supersedes, `Curl_http_to_fold`, and not
    /// for Rust's `to_*` conversion convention -- it converts nothing and
    /// returns nothing, it truncates the receive buffer in place.
    #[allow(clippy::wrong_self_convention)]
    fn to_fold(&mut self) {
        let slice = self.rcvbuf.as_slice();
        let mut len = slice.len();
        if len > 0 && slice[len - 1] == b'\n' {
            len -= 1;
        }
        if len > 0 && slice[len - 1] == b'\r' {
            len -= 1;
        }
        while len > 0 && matches!(slice[len - 1], b' ' | b'\t') {
            len -= 1;
        }
        // `curlx_dyn_setlen` cannot fail for a length it already holds.
        let _ = self.rcvbuf.setlen(len);
    }
}

/// The status-line predicate of `on_resp_header` (`lib/cf-h1-proxy.c:337-345`)
/// and the code it yields.
///
/// Separated so the predicate can be tested on its own: it is the one place
/// the tunnel learns what the proxy answered, and every later decision --
/// established, retry or fail -- turns on the number it produces.
///
/// The C indexes `header[12]` unconditionally, relying on the NUL terminator
/// to make a three-digit line fail the `!ISDIGIT` test. A slice has no
/// terminator, so absence is tested explicitly and means the same thing: a
/// line that ENDS after three digits is accepted.
fn parse_connect_status(header: &[u8]) -> Option<i32> {
    if !header.starts_with(b"HTTP/1.") {
        return None;
    }
    if header.len() < 12 {
        return None;
    }
    if !matches!(header[7], b'0' | b'1') || header[8] != b' ' {
        return None;
    }
    if !header[9..12].iter().all(u8::is_ascii_digit) {
        return None;
    }
    // `!ISDIGIT(header[12])`: a fourth digit disqualifies the line, and its
    // ABSENCE -- the end of the slice -- does not.
    if header.get(12).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let hundreds = i32::from(header[9] - b'0');
    let tens = i32::from(header[10] - b'0');
    let units = i32::from(header[11] - b'0');
    Some(hundreds * 100 + tens * 10 + units)
}

// ---------------------------------------------------------------------------
// 9. The injected bundle every tunnel filter is built with.
// ---------------------------------------------------------------------------

/// The seams the three filters here are constructed over.
///
/// The same shape [`crate::proxy::socks::SocksSeams`] uses, and for the same
/// reason: a filter outlives the call that built it and is reached later
/// through a [`FilterLink`], so it cannot hold a borrow of the connection.
/// Every member is an [`Arc`], so a clone is a refcount bump.
#[derive(Clone, Debug)]
pub(crate) struct TunnelSeams {
    /// The connection's and the transfer's own facts and operations.
    pub(crate) conn: Arc<dyn TunnelConn>,
    /// The HTTP/2 session this build can open, when it has one AND a caller
    /// supplied it.
    ///
    /// The two conditions are separate on purpose, exactly as
    /// `SocksSeams::gssapi` separates them. The feature decides whether the
    /// CODE exists, which is the C's `#ifdef USE_NGHTTP2`; the [`Option`]
    /// decides whether this connection can actually open a session. With no
    /// factory, an ALPN of `h2` is refused with the same diagnostic a build
    /// without nghttp2 produces -- which is the honest answer, because such a
    /// build genuinely cannot tunnel over HTTP/2.
    #[cfg(feature = "http2")]
    pub(crate) h2: Option<Arc<dyn H2SessionFactory>>,
}

impl TunnelSeams {
    /// A bundle with no HTTP/2 session factory: HTTP/1.x tunnelling only.
    #[allow(dead_code)] // Consumer: `crate::conn`'s filter factory.
    pub(crate) fn new(conn: Arc<dyn TunnelConn>) -> Self {
        Self {
            conn,
            #[cfg(feature = "http2")]
            h2: None,
        }
    }

    /// The same bundle with an HTTP/2 session factory attached.
    #[cfg(feature = "http2")]
    #[must_use]
    #[allow(dead_code)] // Consumer: `crate::conn`, when h2 is negotiable.
    pub(crate) fn with_h2(
        mut self,
        factory: Arc<dyn H2SessionFactory>,
    ) -> Self {
        self.h2 = Some(factory);
        self
    }

    /// Whether this build and this connection can tunnel over HTTP/2.
    ///
    /// The successor of the C's `#ifdef USE_NGHTTP2` around the `h2` arm of
    /// the ALPN dispatch (`lib/http_proxy.c:316-324`).
    fn can_tunnel_h2(&self) -> bool {
        #[cfg(feature = "http2")]
        {
            self.h2.is_some()
        }
        #[cfg(not(feature = "http2"))]
        {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// 10. The `"H1-PROXY"` filter -- `Curl_cft_h1_proxy`.
// ---------------------------------------------------------------------------

/// The HTTP/1.x `CONNECT` tunnel -- `Curl_cft_h1_proxy`
/// (`lib/cf-h1-proxy.c:757-773`).
///
/// FOUR of the twelve operations are overridden -- [`ConnFilter::destroy`],
/// [`ConnFilter::connect`], [`ConnFilter::close`] and
/// [`ConnFilter::adjust_pollset`] -- plus [`ConnFilter::query`], which is the
/// SHARED [`http_proxy_query`]. The remaining seven are
/// [`ConnFilter`]'s pass-through defaults, which are the `Curl_cf_def_*`
/// slots the C's table names. Notably [`ConnFilter::send`] and
/// [`ConnFilter::recv`] are NOT overridden: once the tunnel is established
/// this filter is transparent and every tunnelled byte passes straight
/// through it.
#[derive(Debug)]
pub(crate) struct H1Proxy {
    /// The chain link, socket index and two state flags.
    base: FilterBase,
    /// `cf->ctx`, as a typed field.
    ///
    /// [`None`] until the first connect, because
    /// `Curl_cf_create(&cf, &Curl_cft_h1_proxy, NULL)`
    /// (`lib/cf-h1-proxy.c:782`) passes a NULL context and
    /// `cf_h1_proxy_connect` allocates it (`:682`). It returns to [`None`] on
    /// SUCCESS as well as on close and destroy, all three through
    /// [`Self::tunnel_free`] -- the state is not needed once the tunnel
    /// carries traffic, and releasing it is what stops a 16 KiB header buffer
    /// and a chunked decoder from living as long as the connection.
    tunnel: Option<H1Tunnel>,
    /// The injected seams.
    seams: TunnelSeams,
}

impl H1Proxy {
    /// `Curl_cf_create(&cf, &Curl_cft_h1_proxy, NULL)`
    /// (`lib/cf-h1-proxy.c:782`): a filter with NO tunnel state.
    #[allow(dead_code)] // Consumer: the `"HTTP-PROXY"` dispatch below.
    pub(crate) fn new(
        sockindex: SocketIndex,
        conn: Option<ConnId>,
        seams: TunnelSeams,
    ) -> Self {
        let mut base = FilterBase::new(sockindex);
        base.set_conn(conn);
        Self {
            base,
            tunnel: None,
            seams,
        }
    }

    /// The tunnel state, once the first connect has built it.
    #[allow(dead_code)] // Consumer: this module's tests.
    pub(crate) fn tunnel(&self) -> Option<&H1Tunnel> {
        self.tunnel.as_ref()
    }

    /// `h1_tunnel_go_state`, reached through the filter that owns the state.
    fn go_state(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
        new_state: H1TunnelState,
    ) {
        let sockindex = self.base.sockindex().as_i32();
        if let Some(ts) = self.tunnel.as_mut() {
            ts.go_state(cx, conn, sockindex, new_state);
        }
    }

    /// `tunnel_free(cf, data)` (`lib/cf-h1-proxy.c:180-194`).
    ///
    /// The forced transition to [`H1TunnelState::Failed`] comes FIRST and is
    /// not incidental: it is what scrubs `data->state.aptr.proxyuserpwd`, so
    /// releasing the state also releases the credentials, on every path that
    /// releases it.
    fn tunnel_free(&mut self, cx: &mut CallCtx<'_, '_>) {
        if self.tunnel.is_none() {
            return;
        }
        let conn = Arc::clone(&self.seams.conn);
        self.go_state(cx, conn.as_ref(), H1TunnelState::Failed);
        if let Some(ts) = self.tunnel.as_mut() {
            ts.rcvbuf.free();
            ts.request_data.free();
            ts.ch.free();
        }
        self.tunnel = None;
    }

    /// One filter-attributed trace line from this filter.
    fn trace(&self, cx: &mut CallCtx<'_, '_>, line: &str) {
        trace_line(
            cx,
            self.trace_filter(),
            self.base.sockindex().as_i32(),
            line,
        );
    }

    /// `send_CONNECT(cf, data, ts, &done)` (`lib/cf-h1-proxy.c:237-270`):
    /// get the composed request out, RESUMING where the last call stopped.
    ///
    /// # The resumption is mandatory
    ///
    /// `buf += ts->nsent; blen -= ts->nsent;` -- a short write leaves the
    /// buffer whole and advances `nsent`, so the next call continues from the
    /// byte after the last one accepted. Re-sending from the start would put a
    /// duplicated prefix on the wire, which the `<verify><proxy>` comparison
    /// sees as a different request.
    ///
    /// `eos` is `FALSE`: the tunnel continues after the request.
    ///
    /// # Errors
    ///
    /// Whatever the filter below reports, EXCEPT [`CURLcode::Again`], which
    /// the C converts to `CURLE_OK` -- nothing was written, so the next pass
    /// retries and [`ConnFilter::adjust_pollset`] has already registered for
    /// writability. [`CURLcode::FailedInit`] with no filter below, where the C
    /// dereferences `cf->next` unconditionally.
    fn send_connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        let Self { base, tunnel, .. } = self;
        let Some(ts) = tunnel.as_mut() else {
            return Ok(false);
        };

        let request_len = ts.request_data.len();
        // `if(blen <= ts->nsent) goto out;` -- everything is already out.
        if request_len <= ts.nsent {
            return Ok(true);
        }

        let sent = match base.next_mut() {
            Some(next) => {
                next.send(cx, &ts.request_data.as_slice()[ts.nsent..], false)
            }
            None => Err(Error::with_context(
                CURLcode::FailedInit,
                "H1-PROXY: no filter below to send CONNECT through",
            )),
        };

        let nwritten = match sent {
            Ok(nwritten) => nwritten,
            // `if(result == CURLE_AGAIN) result = CURLE_OK;` -- and `out:`
            // then emits no message, because `result` is no longer an error.
            Err(error) if error.code() == CURLcode::Again => return Ok(false),
            Err(error) => {
                fail_line(cx, CONNECT_SEND_FAILED);
                return Err(error);
            }
        };

        let written = &ts.request_data.as_slice()
            [ts.nsent..ts.nsent.saturating_add(nwritten)];
        let written = written.to_vec();
        ts.nsent = ts.nsent.saturating_add(nwritten);
        // `Curl_debug(data, CURLINFO_HEADER_OUT, buf, nwritten)` -- the bytes
        // ACCEPTED on this call, from the resumed offset, which is what
        // `--trace` shows and what a `-v` transcript is compared against.
        debug_bytes(cx, InfoType::HeaderOut, &written);

        Ok(ts.nsent >= request_len)
    }

    /// `recv_CONNECT_resp(cf, data, ts, &done)`
    /// (`lib/cf-h1-proxy.c:418-555`): read the response ONE BYTE AT A TIME.
    ///
    /// # Why one byte, and why that is not negotiable
    ///
    /// The C's comment is explicit: *"Read one byte at a time to avoid a race
    /// condition."* The race is the tunnel handover. The moment the header
    /// block ends, every following byte belongs to the TUNNELLED protocol and
    /// must be left in the transport for the filter above to read. A buffered
    /// read would consume some of them into this filter's own buffer, where
    /// nothing can retrieve them, and the tunnelled stream would silently lose
    /// its first bytes.
    ///
    /// # Where the bytes come from
    ///
    /// The C calls `Curl_conn_recv(data, cf->sockindex, &byte, 1, &nread)`,
    /// which reads from the CHAIN HEAD rather than from `cf->next`. The two
    /// are equivalent here and the equivalence is measurable: this filter does
    /// not override `recv`, so the head's read chains straight through it to
    /// the same filter below. A filter in this crate has no path back to its
    /// chain head by design, so `next` is what it uses.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] for an unauthenticated end of stream and for
    /// either overflow of [`DYN_PROXY_CONNECT_HEADERS`], and whatever the
    /// filter below, [`TunnelConn::progress_update`],
    /// [`H1Tunnel::single_header`] or the chunked decoder reports.
    /// [`CURLcode::Again`] is NOT an error: it means the socket buffer is
    /// drained and this pass is over.
    fn recv_connect_resp(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<bool> {
        let conn = Arc::clone(&self.seams.conn);
        let sockindex = self.base.sockindex().as_i32();
        let mut select_error = false;

        while self
            .tunnel
            .as_ref()
            .is_some_and(|ts| ts.keepon.keeps_going())
        {
            let mut byte = [0_u8; 1];
            let read = match self.base.next_mut() {
                Some(next) => next.recv(cx, &mut byte),
                None => Err(Error::with_context(
                    CURLcode::FailedInit,
                    "H1-PROXY: no filter below to read the response from",
                )),
            };

            let nread = match read {
                // `if(result == CURLE_AGAIN) return CURLE_OK;` -- the socket
                // buffer is drained, so this pass ends NOT done.
                Err(error) if error.code() == CURLcode::Again => {
                    return Ok(false)
                }
                Err(error) => {
                    self.set_keepon(KeepOn::Done);
                    return Err(error);
                }
                Ok(nread) => nread,
            };

            // `if(!result) result = Curl_pgrsUpdate(data);` -- after EVERY
            // successful read, so a progress callback can abort a proxy that
            // answers one byte at a time.
            if let Err(error) = conn.progress_update() {
                self.set_keepon(KeepOn::Done);
                return Err(error);
            }

            if nread == 0 {
                // End of stream. With proxy authentication requested, offered
                // AND already attempted, this is *"mere" proxy disconnect* and
                // a retry on a fresh connection is possible.
                if conn.proxy_auth_enabled()
                    && conn.proxy_auth_available()
                    && conn.proxy_user_pwd().is_some()
                {
                    if let Some(ts) = self.tunnel.as_mut() {
                        ts.close_connection = true;
                    }
                    info_line(cx, CONNECT_CLOSED);
                } else {
                    select_error = true;
                    fail_line(cx, CONNECT_ABORTED);
                }
                self.set_keepon(KeepOn::Done);
                break;
            }

            if self.drain_ignored_body(cx, conn.as_ref(), byte[0])? {
                continue;
            }

            self.accumulate(cx, conn.as_ref(), sockindex, byte[0])?;
        }

        // `if(error) result = CURLE_RECV_ERROR;`
        if select_error {
            return Err(Error::with_context(
                CURLcode::RecvError,
                CONNECT_ABORTED,
            ));
        }

        let done = self
            .tunnel
            .as_ref()
            .is_some_and(|ts| matches!(ts.keepon, KeepOn::Done));
        // `if(!result && *done && data->info.httpproxycode / 100 != 2)
        //  result = Curl_http_auth_act(data);` -- this is what sets
        // `data->req.newurl` and so decides whether the driver loops.
        if done && conn.http_proxy_code() / 100 != 2 {
            conn.auth_act()?;
        }
        Ok(done)
    }

    /// `ts->keepon = ...` reached through the [`Option`].
    fn set_keepon(&mut self, keepon: KeepOn) {
        if let Some(ts) = self.tunnel.as_mut() {
            ts.keepon = keepon;
        }
    }

    /// The `if(ts->keepon == KEEPON_IGNORE)` arm of `recv_CONNECT_resp`
    /// (`lib/cf-h1-proxy.c:467-496`): discard one byte of a body.
    ///
    /// Answers `true` when the byte was consumed by the drain -- the C's
    /// `continue` -- and `false` when the arm does not apply and the byte must
    /// be accumulated as a header instead.
    ///
    /// The two framings are not symmetrical. A `Content-Length` body counts
    /// DOWN and stops when the counter reaches zero, which the C tests with
    /// `<= 0` after decrementing. A chunked body is fed to the decoder and
    /// stops when the decoder says so; the byte is consumed either way.
    ///
    /// # Errors
    ///
    /// Whatever [`TunnelConn::chunk_read`] reports.
    fn drain_ignored_body(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
        byte: u8,
    ) -> CurlResult<bool> {
        let Some(ts) = self.tunnel.as_mut() else {
            return Ok(false);
        };
        if !matches!(ts.keepon, KeepOn::Ignore) {
            return Ok(false);
        }

        if ts.cl != 0 {
            ts.cl -= 1;
            if ts.cl <= 0 {
                ts.keepon = KeepOn::Done;
            }
            return Ok(true);
        }

        if ts.chunked_encoding {
            conn.chunk_read(&mut ts.ch, &[byte])?;
            if ts.ch.is_done() {
                info_line(cx, "chunk reading DONE");
                if let Some(ts) = self.tunnel.as_mut() {
                    ts.keepon = KeepOn::Done;
                }
            }
        }
        // The C's `continue` is unconditional in this arm: with neither
        // framing there is nothing to count and nothing to decode, and the
        // byte is still discarded.
        Ok(true)
    }

    /// The header-accumulating tail of `recv_CONNECT_resp`
    /// (`lib/cf-h1-proxy.c:498-542`): folding, the two overflow checks, and
    /// the line-terminator test.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] with [`RESPONSE_TOO_LARGE`] from EITHER append
    /// -- the space inserted while unfolding and the byte itself are separate
    /// call sites in the C and either can be the one that crosses the ceiling
    /// -- and whatever [`H1Tunnel::single_header`] reports.
    fn accumulate(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
        sockindex: i32,
        byte: u8,
    ) -> CurlResult<()> {
        let blank = matches!(byte, b' ' | b'\t');

        // `if(ts->maybe_folded)`: the previous line ended and this byte
        // decides whether it was a header or the start of a continuation.
        let maybe_folded =
            self.tunnel.as_ref().is_some_and(|ts| ts.maybe_folded);
        if maybe_folded {
            if blank {
                if let Some(ts) = self.tunnel.as_mut() {
                    ts.to_fold();
                    ts.leading_unfold = true;
                }
            } else {
                self.single_header(cx, conn, sockindex)?;
            }
            if let Some(ts) = self.tunnel.as_mut() {
                ts.maybe_folded = false;
            }
        }

        // `if(ts->leading_unfold)`: skip the continuation's own indentation
        // and replace ALL of it with exactly one space.
        let leading_unfold =
            self.tunnel.as_ref().is_some_and(|ts| ts.leading_unfold);
        if leading_unfold {
            if blank {
                return Ok(());
            }
            let overflow = self
                .tunnel
                .as_mut()
                .is_some_and(|ts| ts.rcvbuf.addn(b" ").is_err());
            if overflow {
                fail_line(cx, RESPONSE_TOO_LARGE);
                return Err(Error::with_context(
                    CURLcode::RecvError,
                    RESPONSE_TOO_LARGE,
                ));
            }
            if let Some(ts) = self.tunnel.as_mut() {
                ts.leading_unfold = false;
            }
        }

        let overflow = self
            .tunnel
            .as_mut()
            .is_some_and(|ts| ts.rcvbuf.addn(&[byte]).is_err());
        if overflow {
            fail_line(cx, RESPONSE_TOO_LARGE);
            return Err(Error::with_context(
                CURLcode::RecvError,
                RESPONSE_TOO_LARGE,
            ));
        }

        // `if(byte != 0x0a) continue;` -- ONLY a line feed terminates a line,
        // so a lone carriage return is just another byte.
        if byte != 0x0a {
            return Ok(());
        }

        let ends_headers = self.tunnel.as_ref().is_some_and(|ts| {
            let line = ts.rcvbuf.as_slice();
            !line.is_empty() && matches!(line[0], b'\r' | b'\n')
        });
        if ends_headers {
            self.single_header(cx, conn, sockindex)?;
        } else if let Some(ts) = self.tunnel.as_mut() {
            ts.maybe_folded = true;
        }
        Ok(())
    }

    /// [`H1Tunnel::single_header`], reached through the [`Option`].
    fn single_header(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
        sockindex: i32,
    ) -> CurlResult<()> {
        match self.tunnel.as_mut() {
            Some(ts) => ts.single_header(cx, conn, sockindex),
            None => Ok(()),
        }
    }
}

impl H1Proxy {
    /// `H1_CONNECT(cf, data, ts)` (`lib/cf-h1-proxy.c:557-661`): the driver.
    ///
    /// # Two fast paths, and they are not the same answer
    ///
    /// An ESTABLISHED tunnel answers `Ok(())` and a FAILED one answers
    /// [`CURLcode::RecvError`] -- the C's comment says why: *"Need a cfilter
    /// close and new bootstrap"*. Retrying a failed tunnel in place would
    /// re-send a `CONNECT` on a stream the proxy has already answered.
    ///
    /// # The loop, and what makes it loop
    ///
    /// `do { ... } while(data->req.newurl);` -- one iteration per `CONNECT`
    /// attempt, and the condition is set by
    /// [`TunnelConn::auth_act`] having decided that a 407 is answerable. Each
    /// iteration begins with the timeout check, so a proxy that keeps
    /// answering 407 cannot loop past the deadline.
    ///
    /// # The `switch` falls through between consecutive states
    ///
    /// The C's four cases are chained with `FALLTHROUGH()`, so a fast proxy
    /// traverses INIT, CONNECT, RECEIVE and RESPONSE in ONE call -- which is
    /// what makes a single `connect` sufficient rather than four. Rust has no
    /// fall-through, so the state is re-read after each advance and the
    /// following `if` runs on the same pass; that is the same control flow
    /// spelled differently, and a translation that returned after each state
    /// would need four passes and four socket wake-ups.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OperationTimedout`] for an expired deadline,
    /// [`CURLcode::RecvError`] for a non-2xx final response, and whatever the
    /// individual steps report. Every error path leaves the tunnel in
    /// [`H1TunnelState::Failed`], which is the C's `out:` label.
    fn h1_connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        if let Some(ts) = self.tunnel.as_ref() {
            if ts.is_established() {
                return Ok(());
            }
            if ts.is_failed() {
                return Err(Error::new(CURLcode::RecvError));
            }
        }

        let conn = Arc::clone(&self.seams.conn);
        let outcome = self.drive(cx, conn.as_ref());
        // `out: if(result) h1_tunnel_go_state(cf, ts, H1_TUNNEL_FAILED,
        //  data);` -- reached by every `goto out`, but the transition is
        // conditional on there being an error, so a "not done yet" pass keeps
        // its state.
        if outcome.is_err() {
            self.go_state(cx, conn.as_ref(), H1TunnelState::Failed);
        }
        outcome
    }

    /// The `do`/`while` and the `switch` of [`Self::h1_connect`], separated so
    /// that the C's single `out:` label has one place to act.
    fn drive(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &dyn TunnelConn,
    ) -> CurlResult<()> {
        loop {
            // `if(Curl_timeleft_ms(data) < 0)` -- NEGATIVE only. Zero means no
            // limit was set, and treating it as expired would abort every
            // `CONNECT` in a transfer with no timeout.
            if conn.time_left_ms() < 0 {
                fail_line(cx, CONNECT_TIMEOUT);
                return Err(Error::with_context(
                    CURLcode::OperationTimedout,
                    CONNECT_TIMEOUT,
                ));
            }

            let mut state = self
                .tunnel
                .as_ref()
                .map_or(H1TunnelState::Init, |ts| ts.state);

            if matches!(state, H1TunnelState::Init) {
                self.trace(cx, "CONNECT start");
                match self.tunnel.as_mut() {
                    Some(ts) => ts.start_connect(cx, conn)?,
                    None => return Ok(()),
                }
                self.go_state(cx, conn, H1TunnelState::Connect);
                state = H1TunnelState::Connect; // FALLTHROUGH()
            }

            if matches!(state, H1TunnelState::Connect) {
                self.trace(cx, "CONNECT send");
                if !self.send_connect(cx)? {
                    return Ok(());
                }
                self.go_state(cx, conn, H1TunnelState::Receive);
                state = H1TunnelState::Receive; // FALLTHROUGH()
            }

            if matches!(state, H1TunnelState::Receive) {
                self.trace(cx, "CONNECT receive");
                let done = self.recv_connect_resp(cx)?;
                // `if(!result) result = Curl_pgrsUpdate(data);` -- a SECOND
                // update, after the read loop as well as inside it.
                conn.progress_update()?;
                if !done {
                    return Ok(());
                }
                self.go_state(cx, conn, H1TunnelState::Response);
                state = H1TunnelState::Response; // FALLTHROUGH()
            }

            if matches!(state, H1TunnelState::Response) {
                self.trace(cx, "CONNECT response");
                if conn.new_url().is_some() {
                    // Not the final response: a follow-up `CONNECT` carrying
                    // credentials is required.
                    conn.req_soft_reset()?;
                    let must_close = self
                        .tunnel
                        .as_ref()
                        .is_some_and(|ts| ts.close_connection)
                        || conn.connection_close_requested();
                    if must_close {
                        // Closing THIS filter resets the tunnel state, so the
                        // C returns here and expects to be called again --
                        // *"To avoid recursion, we return and expect to be
                        // called again."*
                        self.trace(cx, "CONNECT need to close+open");
                        info_line(cx, CONNECT_AGAIN);
                        ConnFilter::close(self, cx);
                        if let Some(next) = self.base.next_mut() {
                            next.connect(cx)?;
                        }
                        return Ok(());
                    }
                    self.go_state(cx, conn, H1TunnelState::Init);
                }
            }

            // `} while(data->req.newurl);`
            if conn.new_url().is_none() {
                break;
            }
        }

        // `if(data->info.httpproxycode / 100 != 2)` -- a non-2xx response with
        // no further URL to try. The message reports `data->req.httpcode`
        // while the success message below reports
        // `data->info.httpproxycode`: two different fields, and the C's choice
        // of each is preserved.
        if conn.http_proxy_code() / 100 != 2 {
            conn.clear_new_url();
            self.go_state(cx, conn, H1TunnelState::Failed);
            let line =
                format!("CONNECT tunnel failed, response {}", conn.http_code());
            fail_line(cx, &line);
            return Err(Error::with_context(CURLcode::RecvError, line));
        }

        self.go_state(cx, conn, H1TunnelState::Established);
        let line = format!(
            "CONNECT tunnel established, response {}",
            conn.http_proxy_code()
        );
        info_line(cx, &line);
        Ok(())
    }
}

impl ConnFilter for H1Proxy {
    /// The `name` member: `"H1-PROXY"` (`lib/cf-h1-proxy.c:758`).
    fn trace_name(&self) -> &'static str {
        H1_PROXY_FILTER_NAME
    }

    /// The `flags` member: [`H1_PROXY_FLAGS`] (`lib/cf-h1-proxy.c:759`).
    fn cf_type(&self) -> CfType {
        H1_PROXY_FLAGS
    }

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    /// `cf_h1_proxy_destroy` (`lib/cf-h1-proxy.c:736-741`).
    ///
    /// Does NOT chain, and must not: the caller has already severed the link
    /// and owns the rest of the chain.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.trace(cx, "destroy");
        self.tunnel_free(cx);
    }

    /// `cf_h1_proxy_connect` (`lib/cf-h1-proxy.c:663-707`).
    ///
    /// # The order of the first three steps is load-bearing
    ///
    /// An already-connected filter answers at once; then the filter BELOW is
    /// connected and its verdict returned unchanged, because there is no point
    /// composing a `CONNECT` for a proxy with no socket; and only then is the
    /// tunnel state built, which is where the `PROTOPT_NOTCPPROXY` refusal
    /// lives.
    ///
    /// # The state is released on SUCCESS
    ///
    /// `tunnel_free(cf, data)` runs inside `if(*done)`, so a tunnel that
    /// carries traffic carries no tunnel state: the 16 KiB header buffer, the
    /// composed request and the chunked decoder all go. That is the opposite
    /// of [`H2Proxy`], whose session must outlive the handshake because the
    /// tunnelled bytes travel through it as HTTP/2 DATA frames.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] with no filter below, where the C
    /// dereferences `cf->next` unconditionally, and whatever
    /// [`H1Tunnel::init`] or [`Self::h1_connect`] reports.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if self.base.is_connected() {
            return Ok(true);
        }

        self.trace(cx, "connect");
        let Some(next) = self.base.next_mut() else {
            return Err(Error::with_context(
                CURLcode::FailedInit,
                "H1-PROXY: no filter below to connect",
            ));
        };
        if !next.connect(cx)? {
            return Ok(false);
        }

        if self.tunnel.is_none() {
            let conn = Arc::clone(&self.seams.conn);
            self.tunnel = Some(H1Tunnel::init(cx, conn.as_ref())?);
        }

        let outcome = self.h1_connect(cx);
        if outcome.is_ok() {
            // `Curl_safefree(data->state.aptr.proxyuserpwd)` -- a second
            // scrub, after the one the ESTABLISHED transition already did.
            // Reproduced because it also runs on a NOT-DONE pass, where no
            // transition has happened yet.
            self.seams.conn.clear_proxy_user_pwd();
        }

        // `*done = (result == CURLE_OK) && tunnel_is_established(cf->ctx);`
        let done = outcome.is_ok()
            && self.tunnel.as_ref().is_some_and(H1Tunnel::is_established);
        if done {
            self.base.set_connected(true);
            let conn = Arc::clone(&self.seams.conn);
            conn.req_soft_reset()?;
            conn.client_reset();
            conn.progress_reset();
            self.tunnel_free(cx);
        }
        outcome.map(|()| done)
    }

    /// `cf_h1_proxy_close` (`lib/cf-h1-proxy.c:743-755`).
    ///
    /// Three steps in the C's order: clear `connected`, return the tunnel to
    /// [`H1TunnelState::INIT`](H1TunnelState::Init) -- which empties both
    /// buffers and scrubs nothing else -- and chain the close down. The state
    /// is KEPT rather than freed, because a closed filter stays installed and
    /// may be connected again.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.trace(cx, "close");
        self.base.set_connected(false);
        if self.tunnel.is_some() {
            let conn = Arc::clone(&self.seams.conn);
            self.go_state(cx, conn.as_ref(), H1TunnelState::Init);
        }
        if let Some(next) = self.base.next_mut() {
            next.close(cx);
        }
    }

    /// `cf_h1_proxy_adjust_pollset` (`lib/cf-h1-proxy.c:709-734`).
    ///
    /// Only while UNCONNECTED, and then the answer turns on
    /// [`H1Tunnel::want_send`]: the one state in which a request is still
    /// going out waits to WRITE, and every other state waits to READ.
    ///
    /// **With no tunnel state at all the answer is out-only.** That is the
    /// C's `else` branch and it is right: nothing has been sent yet, so there
    /// is nothing to read for.
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset`] reports, which is
    /// [`CURLcode::BadFunctionArgument`] for a socket that is not a
    /// descriptor.
    fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        if self.base.is_connected() {
            return Ok(());
        }
        let sock = filter_socket(self, cx);
        let want_send = self.tunnel.as_ref().map_or(true, H1Tunnel::want_send);
        if want_send {
            ps.set_out_only(sock, cx.tracer_mut()).map_err(Error::from)
        } else {
            ps.set_in_only(sock, cx.tracer_mut()).map_err(Error::from)
        }
    }

    /// The SHARED [`http_proxy_query`] -- `Curl_cf_http_proxy_query` in the
    /// C's `.query` slot (`lib/cf-h1-proxy.c:772`).
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
        if let Some(answer) = http_proxy_query(self.seams.conn.as_ref(), query)
        {
            return Ok(answer);
        }
        match self.base.next_mut() {
            Some(next) => next.query(cx, query),
            None => Err(Error::new(CURLcode::UnknownOption)),
        }
    }
}

/// `Curl_conn_cf_get_socket(cf, data)` (`lib/cfilters.c:1015-1024`): the
/// descriptor this filter's chain is using, or [`CURL_SOCKET_BAD`].
///
/// Asked through `CF_QUERY_SOCKET` rather than reached directly, because a
/// filter does not own a socket -- the transport at the bottom of the chain
/// does, and the question is how every other filter finds it.
fn filter_socket<F>(filter: &mut F, cx: &mut CallCtx<'_, '_>) -> Socket
where
    F: ConnFilter + ?Sized,
{
    match filter.query(cx, CfQuery::Socket) {
        Ok(CfQueryValue::Socket(sock)) => sock,
        _ => CURL_SOCKET_BAD,
    }
}

// ---------------------------------------------------------------------------
// 11. The `"HTTP-PROXY"` filter -- `Curl_cft_http_proxy`, the ALPN dispatch.
// ---------------------------------------------------------------------------

/// `struct cf_proxy_ctx` (`lib/http_proxy.c:192-195`), as a typed field.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct HttpProxyCtx {
    /// `int httpversion` -- *"HTTP version used to CONNECT"*, in curl's
    /// two-digit encoding: `10`, `11` or `20`.
    pub(crate) httpversion: i32,
    /// `BIT(sub_filter_installed)`.
    pub(crate) sub_filter_installed: bool,
}

/// `"CONNECT: no ALPN negotiated"` (`lib/http_proxy.c:299`).
pub(crate) const NO_ALPN_NEGOTIATED: &str = "CONNECT: no ALPN negotiated";

/// The `CONNECT` dispatch filter -- `Curl_cft_http_proxy`
/// (`lib/http_proxy.c:395-411`).
///
/// It tunnels nothing itself. Its whole job is to look at what the transport
/// below negotiated and install the tunnel that speaks it, and it is a filter
/// rather than a branch in the chain builder because the answer is not known
/// until the connection -- and, for an HTTPS proxy, the TLS handshake WITH the
/// proxy -- has completed.
///
/// # Three of the twelve operations, and one deliberate default
///
/// [`ConnFilter::destroy`], [`ConnFilter::connect`] and
/// [`ConnFilter::close`] are overridden, plus [`ConnFilter::query`] with the
/// shared [`http_proxy_query`]. Eight slots are `Curl_cf_def_*`, and
/// `adjust_pollset` is one of them -- which matters, because
/// [`ConnFilter::adjust_pollset`]'s default is a PURE NO-OP that does NOT
/// chain (`lib/cfilters.c:57-64`). That is correct here and not an oversight:
/// the sub-filter this one installs sits BELOW it and registers its own
/// readiness, so chaining would ask the same question twice while
/// no-op-ing here asks it once.
#[derive(Debug)]
pub(crate) struct HttpProxy {
    /// The chain link, socket index and two state flags.
    base: FilterBase,
    /// `cf->ctx`, typed. Allocated EAGERLY, as the C's `calloc` in
    /// `Curl_cf_http_proxy_insert_after` is (`lib/http_proxy.c:421`).
    ctx: HttpProxyCtx,
    /// The injected seams, handed on to whichever sub-filter is installed.
    seams: TunnelSeams,
}

impl HttpProxy {
    /// `Curl_cf_create(&cf, &Curl_cft_http_proxy, ctx)`
    /// (`lib/http_proxy.c:426`).
    #[allow(dead_code)] // Consumer: `crate::conn`'s filter factory.
    pub(crate) fn new(
        sockindex: SocketIndex,
        conn: Option<ConnId>,
        seams: TunnelSeams,
    ) -> Self {
        let mut base = FilterBase::new(sockindex);
        base.set_conn(conn);
        Self {
            base,
            ctx: HttpProxyCtx::default(),
            seams,
        }
    }

    /// What the dispatch settled on -- for the tests and for the trace.
    #[allow(dead_code)] // Consumer: this module's tests.
    pub(crate) const fn ctx(&self) -> HttpProxyCtx {
        self.ctx
    }

    /// One filter-attributed trace line from this filter.
    fn trace(&self, cx: &mut CallCtx<'_, '_>, line: &str) {
        trace_line(
            cx,
            self.trace_filter(),
            self.base.sockindex().as_i32(),
            line,
        );
    }

    /// `Curl_conn_cf_insert_after(cf, cf_new)` (`lib/cfilters.c:345-363`)
    /// applied to this filter: `filter` becomes the successor and the old
    /// successor is hung off the end of it.
    ///
    /// The same splice [`crate::conn::SetupFilter`] performs, and for the same
    /// reason: this filter OWNS a private sub-chain that nothing else can
    /// reach, so the insertion cannot go through
    /// [`FilterChain::insert_after`], which addresses a chain by index from a
    /// head this filter does not have.
    fn insert_below(&mut self, filter: FilterLink) {
        debug_assert!(
            !filter.base().has_next(),
            "a filter being spliced in must not already have a successor"
        );
        let tail = self.base.take_next();
        let mut inserted =
            FilterChain::new(self.base.conn(), self.base.sockindex());
        let displaced = inserted.set_chain(Some(filter));
        debug_assert!(displaced.is_none(), "a fresh chain has no head");
        let last = inserted.len().saturating_sub(1);
        if let Some(node) = inserted.nth_mut(last) {
            node.base_mut().set_next(tail);
        }
        self.base.set_next(inserted.take_chain());
    }

    /// `Curl_conn_cf_get_alpn_negotiated(cf->next, data)`
    /// (`lib/http_proxy.c:294`): what the transport below settled on.
    ///
    /// [`None`] covers both of the C's negative answers -- the query
    /// declining and the query answering `NULL` -- because both mean the same
    /// thing to the dispatch: nothing was negotiated, so assume HTTP/1.1.
    fn negotiated_alpn(&mut self, cx: &mut CallCtx<'_, '_>) -> Option<String> {
        let next = self.base.next_mut()?;
        match next.query(cx, CfQuery::AlpnNegotiated) {
            Ok(CfQueryValue::AlpnNegotiated(alpn)) => alpn,
            _ => None,
        }
    }

    /// The `if(!ctx->sub_filter_installed)` block of
    /// `http_proxy_cf_connect` (`lib/http_proxy.c:292-337`): choose the
    /// tunnel and install it.
    ///
    /// # The mapping, and the one case with no ALPN
    ///
    /// | negotiated | sub-filter | `httpversion` |
    /// |---|---|---|
    /// | `"http/1.0"` | `"H1-PROXY"` | `10` |
    /// | nothing, or `"http/1.1"` | `"H1-PROXY"` | `11` |
    /// | `"h2"` | `"H2-PROXY"` | `20` |
    /// | anything else | -- | refused |
    ///
    /// The C's comment on the no-ALPN case is *"Assume that without an ALPN,
    /// we are talking to an ancient one"* -- and it still records `11`, not
    /// `10`, because HTTP/1.1 is what the request will be written as.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] for an ALPN this build cannot tunnel over,
    /// which is the C's `failf(data, "CONNECT: negotiated ALPN '%s' not
    /// supported")`. A build without HTTP/2 -- the C's missing
    /// `USE_NGHTTP2` -- reaches the same arm for `"h2"`, which is why the
    /// diagnostic is shared rather than special-cased.
    fn install_sub_filter(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<()> {
        let alpn = self.negotiated_alpn(cx);
        match alpn.as_deref() {
            Some(name) => {
                let line = format!("CONNECT: '{name}' negotiated");
                info_line(cx, &line);
            }
            None => info_line(cx, NO_ALPN_NEGOTIATED),
        }

        let httpversion = match alpn.as_deref() {
            Some("http/1.0") => {
                self.trace(cx, "installing subfilter for HTTP/1.0");
                self.install_h1();
                10
            }
            None | Some("http/1.1") => {
                self.trace(cx, "installing subfilter for HTTP/1.1");
                self.install_h1();
                11
            }
            Some("h2") if self.seams.can_tunnel_h2() => {
                self.trace(cx, "installing subfilter for HTTP/2");
                self.install_h2()?;
                20
            }
            Some(name) => {
                let line =
                    format!("CONNECT: negotiated ALPN '{name}' not supported");
                fail_line(cx, &line);
                return Err(Error::with_context(
                    CURLcode::CouldntConnect,
                    line,
                ));
            }
        };

        self.ctx.sub_filter_installed = true;
        self.ctx.httpversion = httpversion;
        Ok(())
    }

    /// `Curl_cf_h1_proxy_insert_after(cf, data)` (`lib/cf-h1-proxy.c:775-786`).
    fn install_h1(&mut self) {
        let filter =
            H1Proxy::new(self.base.sockindex(), None, self.seams.clone());
        self.insert_below(link(filter));
    }

    /// `Curl_cf_h2_proxy_insert_after(cf, data)`
    /// (`lib/cf-h2-proxy.c:1479-1502`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when this build has HTTP/2 but no session
    /// factory was supplied. Unreachable from
    /// [`Self::install_sub_filter`], whose guard is
    /// [`TunnelSeams::can_tunnel_h2`]; stated because the constructor below
    /// needs a factory and must say what it does without one rather than
    /// panicking.
    #[cfg(feature = "http2")]
    fn install_h2(&mut self) -> CurlResult<()> {
        if self.seams.h2.is_none() {
            return Err(Error::with_context(
                CURLcode::FailedInit,
                "HTTP-PROXY: no HTTP/2 session factory for an h2 tunnel",
            ));
        }
        let filter = H2Proxy::new(self.base.sockindex(), self.seams.clone());
        self.insert_below(link(filter));
        Ok(())
    }

    /// The stand-in for [`Self::install_h2`] in a build with no HTTP/2.
    ///
    /// Unreachable: [`Self::install_sub_filter`]'s `h2` arm is guarded by
    /// [`TunnelSeams::can_tunnel_h2`], which is a compile-time `false` here,
    /// so `"h2"` falls through to the refusal arm. It exists so the dispatch
    /// compiles identically with and without the feature, which is what the
    /// C's `#ifdef USE_NGHTTP2` around one `else if` achieves.
    #[cfg(not(feature = "http2"))]
    fn install_h2(&mut self) -> CurlResult<()> {
        Err(Error::with_context(
            CURLcode::CouldntConnect,
            "HTTP-PROXY: this build cannot tunnel over HTTP/2",
        ))
    }
}

impl ConnFilter for HttpProxy {
    /// The `name` member: `"HTTP-PROXY"` (`lib/http_proxy.c:396`).
    fn trace_name(&self) -> &'static str {
        HTTP_PROXY_FILTER_NAME
    }

    /// The `flags` member: [`HTTP_PROXY_FLAGS`] (`lib/http_proxy.c:397`).
    fn cf_type(&self) -> CfType {
        HTTP_PROXY_FLAGS
    }

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    /// `http_proxy_cf_destroy` (`lib/http_proxy.c:377-384`): the trace line,
    /// then release the context.
    ///
    /// Does NOT chain. The C's `curlx_free(ctx)` has no counterpart: the
    /// context is a field and goes with the struct.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.trace(cx, "destroy");
    }

    /// `http_proxy_cf_connect` (`lib/http_proxy.c:273-352`).
    ///
    /// # The `connect_sub:` label is a loop, and it must be
    ///
    /// The C connects the sub-chain, installs a filter BELOW itself, and then
    /// `goto connect_sub` -- so the very next thing it does is connect the
    /// filter it just installed. That is how one call can both choose the
    /// tunnel and drive it to completion. Written as a loop here, with the
    /// same two exits: not-done from the sub-chain, and sub-filter already
    /// installed.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] with no filter below, where the C
    /// dereferences `cf->next` unconditionally, and whatever
    /// [`Self::install_sub_filter`] or the sub-chain reports.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if self.base.is_connected() {
            return Ok(true);
        }

        self.trace(cx, "connect");
        loop {
            // `connect_sub:` -- `result = cf->next->cft->do_connect(cf->next,
            //  data, done); if(result || !*done) return result;`
            let Some(next) = self.base.next_mut() else {
                return Err(Error::with_context(
                    CURLcode::FailedInit,
                    "HTTP-PROXY: no filter below to connect",
                ));
            };
            if !next.connect(cx)? {
                return Ok(false);
            }

            if self.ctx.sub_filter_installed {
                // *"subchain connected and we had already installed the
                // protocol filter. This means the protocol tunnel is
                // established, we are done."*
                break;
            }
            self.install_sub_filter(cx)?;
            // `goto connect_sub;`
        }

        self.base.set_connected(true);
        Ok(true)
    }

    /// `http_proxy_cf_close` (`lib/http_proxy.c:386-393`).
    ///
    /// Clears `connected` and chains. The sub-filter is NOT discarded: it
    /// stays installed with `ctx->sub_filter_installed` still set, so a
    /// reconnect drives the same tunnel implementation rather than choosing
    /// again -- which is right, because the ALPN of a reconnected transport is
    /// settled by that transport, not by this filter.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.trace(cx, "close");
        self.base.set_connected(false);
        if let Some(next) = self.base.next_mut() {
            next.close(cx);
        }
    }

    /// The SHARED [`http_proxy_query`] -- `Curl_cf_http_proxy_query` in the
    /// C's `.query` slot (`lib/http_proxy.c:410`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] at the bottom of the chain.
    fn query(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        if let Some(answer) = http_proxy_query(self.seams.conn.as_ref(), query)
        {
            return Ok(answer);
        }
        match self.base.next_mut() {
            Some(next) => next.query(cx, query),
            None => Err(Error::new(CURLcode::UnknownOption)),
        }
    }
}

/// `Curl_cf_http_proxy_insert_after(cf_at, data)`
/// (`lib/http_proxy.c:413-436`): build the dispatch filter and install it
/// immediately BELOW the filter at `index`.
///
/// The C names the position with a filter pointer, `cf_at`; a safe chain is
/// owned from its head, so the position is named by `chain` plus `index` --
/// the spelling [`crate::conn::cf_setup_insert_after`] already uses.
///
/// The filter is built UNATTACHED. `Curl_conn_cf_insert_after`
/// (`lib/cfilters.c:345-363`) stamps `cf->conn` and `cf->sockindex` onto every
/// node it splices, taking them from `cf_at`, and `Curl_cf_create` leaves both
/// zeroed for it. [`FilterChain::insert_after`] reproduces that walk and
/// asserts the filter arrives unattached, so pre-stamping here would both
/// duplicate the work and trip the assertion.
///
/// # Errors
///
/// Whatever [`FilterChain::insert_after`] reports, which is
/// [`CURLcode::BadFunctionArgument`] for a position that does not resolve.
/// Construction itself cannot fail -- the C's `CURLE_OUT_OF_MEMORY` from
/// `calloc` has no counterpart, because the context is a field.
#[allow(dead_code)] // Consumer: `crate::conn`, which builds the chain.
pub(crate) fn insert_after(
    cx: &mut CallCtx<'_, '_>,
    chain: &mut FilterChain,
    index: usize,
    seams: TunnelSeams,
) -> CurlResult<()> {
    let filter = HttpProxy::new(chain.sockindex(), None, seams);
    chain.insert_after(cx, index, link(filter))
}

// ---------------------------------------------------------------------------
// 12. HTTP/2 header projection -- `Curl_http_req_to_h2` for a `CONNECT`.
// ---------------------------------------------------------------------------

/// `H2_NON_FIELD[]` (`lib/http.c:4823-4830`): the connection-specific fields
/// RFC 9113 section 8.2.2 forbids in an HTTP/2 request.
///
/// The C's table is sorted by LENGTH -- 4, 7, 10, 10, 16, 17 -- and
/// `h2_permissible_field` exploits the sort with an early `return TRUE` as soon
/// as the candidate is shorter than the current row. That is a scan
/// optimisation over a six-row table and nothing else, so a case-insensitive
/// set-membership test is behaviourally identical and is what
/// [`h2_permissible_field`] does. The order is preserved anyway, because it is
/// how a reader checks the list against the C.
///
/// The C's own comment is worth carrying: this *"is not a complete list of
/// forbidden fields"*. It is what curl filters, which is what matters for
/// parity.
#[cfg(feature = "http2")]
pub(crate) const H2_NON_FIELD: [&str; 6] = [
    "Host",
    "Upgrade",
    "Connection",
    "Keep-Alive",
    "Proxy-Connection",
    "Transfer-Encoding",
];

/// `h2_permissible_field(e)` (`lib/http.c:4832-4844`).
#[cfg(feature = "http2")]
fn h2_permissible_field(name: &[u8]) -> bool {
    !H2_NON_FIELD
        .iter()
        .any(|forbidden| casecompare(name, forbidden.as_bytes()))
}

/// `http_TE_has_token(fvalue, token)` (`lib/http.c:4846-4872`): does this `TE`
/// value carry the named token?
///
/// The C's walk skips blanks and commas, takes one token with
/// `curlx_str_cspn(&fvalue, &name, " \t\r;,")`, compares it
/// case-insensitively, and then skips the remainder of that comma-separated
/// element -- including any quoted string, which it requires to be
/// well-formed and otherwise rejects the whole value.
#[cfg(feature = "http2")]
fn te_has_token(value: &[u8], token: &str) -> bool {
    for element in value.split(|byte| *byte == b',') {
        // The C skips blanks and commas before each token; splitting on the
        // comma leaves the blanks.
        let element = crate::util::strparse::str_trimblanks(element);
        // `curlx_str_cspn(&fvalue, &name, " \t\r;,")` -- the token ends at
        // the first of those bytes.
        let end = element
            .iter()
            .position(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b';'))
            .unwrap_or(element.len());
        if casecompare(&element[..end], token.as_bytes()) {
            return true;
        }
    }
    false
}

/// `"trailers"` -- the ONE value a `TE` field may carry in HTTP/2, RFC 9113
/// section 8.2.2 (`lib/http.c:4931`).
#[cfg(feature = "http2")]
pub(crate) const TE_TRAILERS: &str = "trailers";

/// `Curl_http_req_to_h2(&h2_headers, req, data)` (`lib/http.c:4875-4941`),
/// for a request whose method is `CONNECT`.
///
/// # Which pseudo-headers appear, and which cannot
///
/// The C emits `:method` always, then `:scheme` when it has one, then
/// `:authority`, then `:path` when it has one. For a `CONNECT` the scheme
/// branch is skipped explicitly -- `else if(strcmp("CONNECT", req->method))`
/// guards the whole fallback that would otherwise invent one from the
/// connection -- and `req->path` is NULL. So the pseudo-header set is exactly
///
/// ```text
/// :method: CONNECT
/// :authority: host:port
/// ```
///
/// and **neither `:scheme` nor `:path` may appear**. RFC 9113 section 8.5
/// requires precisely that of a `CONNECT`, so this is not merely curl's
/// choice; a proxy is entitled to reject a `CONNECT` carrying either.
///
/// # Every field name is lowercased
///
/// `Curl_dynhds_set_opts(h2_headers, DYNHDS_OPT_LOWERCASE)` folds the NAME of
/// every entry -- never the value -- on insertion, which
/// [`HeaderSet::set_opts`] reproduces. It applies to the pseudo-headers too,
/// which are already lower case, and to the application's own headers, which
/// may not be.
///
/// # Errors
///
/// Whatever [`HeaderSet::add`] reports.
#[cfg(feature = "http2")]
pub(crate) fn req_to_h2(req: &ConnectRequest) -> CurlResult<HeaderSet> {
    use crate::headers::{HTTP_PSEUDO_AUTHORITY, HTTP_PSEUDO_METHOD};

    let mut out = HeaderSet::new();
    out.set_opts(true);

    out.add(HTTP_PSEUDO_METHOD, req.method.as_bytes())?;
    out.add(HTTP_PSEUDO_AUTHORITY, req.authority.as_bytes())?;

    for (name, value) in req.headers.iter() {
        // `if(e->namelen == 2 && curl_strequal("TE", e->name))` -- `TE` is
        // permitted only when it carries `trailers`, and is then REWRITTEN to
        // exactly that token, whatever else the value held.
        if casecompare(name, b"TE") {
            if te_has_token(value, TE_TRAILERS) {
                out.add(name, TE_TRAILERS.as_bytes())?;
            }
            continue;
        }
        if h2_permissible_field(name) {
            out.add(name, value)?;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 13. The HTTP/2 session seam -- what `nghttp2_session` is asked to do.
// ---------------------------------------------------------------------------

/// One thing the HTTP/2 session reports having happened.
///
/// # Why this is not [`crate::protocols::http2::H2Event`]
///
/// That type is FRAME-level: its `HeaderBlock` variant carries an undecoded
/// HPACK payload, because the module that owns it decompresses header blocks
/// itself and needs the frame header to find the end of a CONTINUATION
/// sequence. A `CONNECT` tunnel needs the DECODED names and values -- it looks
/// for `:status` and `Proxy-Authenticate` and nothing else -- so it consumes a
/// level up. The C draws the same line: `cf-h2-proxy.c` registers
/// `proxy_h2_on_header` and never sees a frame payload.
#[cfg(feature = "http2")]
#[derive(Clone, Debug, Eq, PartialEq)]
// Constructed by the `H2TunnelSession` implementation an injected factory
// supplies, and by this module's own tests. No production factory exists yet;
// see `version.rs`'s engine registry.
#[allow(dead_code)] // consumer: H2SessionFactory implementations
pub(crate) enum H2TunnelEvent {
    /// A SETTINGS frame on stream 0 without `ACK`
    /// (`lib/cf-h2-proxy.c:474-483`).
    Settings,
    /// A GOAWAY on stream 0 (`lib/cf-h2-proxy.c:484-486`).
    Goaway {
        /// `frame->goaway.last_stream_id`.
        last_stream_id: i32,
        /// `frame->goaway.error_code`.
        error: u32,
    },
    /// A `:status` pseudo-header for the tunnel stream
    /// (`lib/cf-h2-proxy.c:560-579`).
    Status(i32),
    /// Any other header for the tunnel stream
    /// (`lib/cf-h2-proxy.c:584-591`).
    Header {
        /// The field name, as HPACK delivered it -- already lower case.
        name: Vec<u8>,
        /// The field value.
        value: Vec<u8>,
    },
    /// The end of a HEADERS frame for the tunnel stream
    /// (`lib/cf-h2-proxy.c:499-513`), which is where a response becomes
    /// final.
    HeadersComplete,
    /// A WINDOW_UPDATE (`lib/cf-h2-proxy.c:514-518`).
    WindowUpdate,
    /// A RST_STREAM carrying a NON-ZERO error code
    /// (`lib/cf-h2-proxy.c:519-522`). A zero code does not reset the tunnel.
    Reset {
        /// `frame->rst_stream.error_code`.
        error: u32,
    },
    /// A DATA frame's payload for the tunnel stream
    /// (`lib/cf-h2-proxy.c:636-663`).
    Data(Vec<u8>),
    /// The tunnel stream closed (`lib/cf-h2-proxy.c:665-686`).
    StreamClosed {
        /// `error_code`, zero for an orderly close.
        error: u32,
    },
}

/// The HTTP/2 session a `CONNECT` tunnel drives, as a contract.
///
/// The successor of `nghttp2_session *h2` and the eight `nghttp2_session_*`
/// calls `lib/cf-h2-proxy.c` makes on it. A seam rather than a direct
/// dependency on the `h2` crate for three reasons:
///
/// * **The tunnel's state machine is the part that must be byte-exact**, and
///   it is testable here with no HPACK, no sockets and no runtime.
/// * **The `h2` crate is asynchronous** while [`ConnFilter`] is synchronous,
///   exactly as `Curl_cftype` is. Bridging the two is
///   [`crate::protocols::http2`]'s business -- it already drives `h2` as a
///   sans-executor state machine -- and doing it twice would be two chances
///   to disagree about flow control.
/// * **Raw SETTINGS and window accounting are observable**, which is why the
///   workspace declares `h2` explicitly alongside hyper. This trait is the
///   list of exactly which of those operations a tunnel needs.
///
/// # The one inversion, and why it is faithful
///
/// nghttp2 PULLS request-body bytes through `tunnel_send_callback`
/// (`lib/cf-h2-proxy.c:596-634`), which reads from `ts->sendbuf` and answers
/// `NGHTTP2_ERR_DEFERRED` when it is empty. [`Self::send_body`] PUSHES
/// instead, and the two are the same protocol: accepting fewer bytes than
/// offered -- zero included -- is the deferral, and [`Self::resume_data`]
/// remains the explicit un-deferral the C also calls.
#[cfg(feature = "http2")]
pub(crate) trait H2TunnelSession: fmt::Debug + Send {
    /// `nghttp2_submit_settings(h2, NGHTTP2_FLAG_NONE, iv, 3)`
    /// (`lib/cf-h2-proxy.c:936`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`], which is what the C converts the nghttp2 failure
    /// into (`:940`).
    fn submit_settings(
        &mut self,
        table: &crate::protocols::http2::SettingsTable,
    ) -> CurlResult<()>;

    /// `nghttp2_session_set_local_window_size(h2, NGHTTP2_FLAG_NONE, 0,
    /// PROXY_HTTP2_HUGE_WINDOW_SIZE)` (`lib/cf-h2-proxy.c:945-946`): the
    /// CONNECTION-level window, stream 0.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`] (`:950`).
    fn set_local_window_size(&mut self, size: u32) -> CurlResult<()>;

    /// `nghttp2_submit_request(h2, NULL, nva, nheader, &data_prd, ts)`
    /// (`lib/cf-h2-proxy.c:721-726`) with the projected header list, and the
    /// stream identifier it allocated.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`], which is what the C reports for a negative
    /// stream identifier (`:732`).
    fn submit_connect(&mut self, headers: &HeaderSet) -> CurlResult<i32>;

    /// `nghttp2_submit_goaway(h2, NGHTTP2_FLAG_NONE, last_stream_id,
    /// error_code, debug, debuglen)` (`lib/cf-h2-proxy.c:1061-1064`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] (`:1068`).
    fn submit_goaway(
        &mut self,
        last_stream_id: i32,
        error_code: u32,
        debug: &[u8],
    ) -> CurlResult<()>;

    /// `nghttp2_session_mem_recv(h2, buf, blen)`
    /// (`lib/cf-h2-proxy.c:306`): hand network bytes to the protocol engine
    /// and report how many it took.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`], which is what the C reports for a negative
    /// return (`:312`).
    fn accept_input(&mut self, buf: &[u8]) -> CurlResult<usize>;

    /// Everything the callbacks of `cf_h2_proxy_ctx_init`
    /// (`lib/cf-h2-proxy.c:907-918`) would have reported during
    /// [`Self::accept_input`], in arrival order.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] for a protocol fault the engine detected.
    fn poll_events(&mut self) -> CurlResult<Vec<H2TunnelEvent>>;

    /// `nghttp2_session_send(h2)` (`lib/cf-h2-proxy.c:386`) with
    /// `on_session_send` collecting the bytes: the frames the session wants
    /// on the wire now.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] for a fatal serialisation failure (`:391`).
    fn take_output(&mut self) -> CurlResult<Vec<u8>>;

    /// The push half of `tunnel_send_callback`: offer tunnelled payload as
    /// DATA on `stream_id` and report how much was accepted.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] for a fatal failure.
    fn send_body(
        &mut self,
        stream_id: i32,
        body: &[u8],
        eos: bool,
    ) -> CurlResult<usize>;

    /// `nghttp2_session_resume_data(h2, stream_id)`
    /// (`lib/cf-h2-proxy.c:1278`, `:1329`): the DATA source has bytes again.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] for a fatal failure -- the C's
    /// `nghttp2_is_fatal(rv)` test, which deliberately ignores a
    /// non-fatal one.
    fn resume_data(&mut self, stream_id: i32) -> CurlResult<()>;

    /// `nghttp2_session_consume(h2, stream_id, len)`
    /// (`lib/cf-h2-proxy.c:1229`): the application has taken `len` bytes, so
    /// the flow-control window may be reopened.
    ///
    /// Infallible in the C, whose return value is discarded there.
    fn consume(&mut self, stream_id: i32, len: usize);

    /// `nghttp2_session_want_read(h2)` (`lib/cf-h2-proxy.c:263`).
    fn want_read(&self) -> bool;

    /// `nghttp2_session_want_write(h2)` (`lib/cf-h2-proxy.c:264`).
    fn want_write(&self) -> bool;

    /// `nghttp2_session_get_remote_window_size(h2)`
    /// (`lib/cf-h2-proxy.c:1123`): the CONNECTION-level send window.
    fn remote_window_size(&self) -> i32;

    /// `nghttp2_session_get_stream_remote_window_size(h2, stream_id)`
    /// (`lib/cf-h2-proxy.c:1125-1126`): the STREAM-level send window.
    fn stream_remote_window_size(&self, stream_id: i32) -> i32;
}

/// How a `CONNECT` tunnel obtains a fresh HTTP/2 session.
///
/// One session per tunnel attempt, because `cf_h2_proxy_ctx_clear` calls
/// `nghttp2_session_del` (`lib/cf-h2-proxy.c:191-193`) and a reconnect then
/// runs `cf_h2_proxy_ctx_init` again, which creates another with
/// `nghttp2_session_client_new3`. A factory rather than a single session
/// value is therefore not indirection for its own sake: it is what makes the
/// close-and-reopen path able to start from a clean protocol state.
#[cfg(feature = "http2")]
pub(crate) trait H2SessionFactory: fmt::Debug + Send + Sync {
    /// `proxy_h2_client_new(cf, cbs)` (`lib/cf-h2-proxy.c:237-259`), including
    /// its two options: `no_auto_window_update`, because this module enforces
    /// the buffer limits itself, and -- from nghttp2 1.50.0 --
    /// `no_rfc9113_leading_and_trailing_ws_validation`.
    fn new_session(&self) -> Box<dyn H2TunnelSession>;
}

// ---------------------------------------------------------------------------
// 14. `"H2-PROXY"` -- buffer geometry, tunnel state, response chain.
// ---------------------------------------------------------------------------

/// `PROXY_H2_CHUNK_SIZE (16 * 1024)` (`lib/cf-h2-proxy.c:46`): the chunk
/// granularity of every one of the four queues below.
#[cfg(feature = "http2")]
pub(crate) const PROXY_H2_CHUNK_SIZE: usize = 16 * 1024;

/// `PROXY_HTTP2_HUGE_WINDOW_SIZE (100 * 1024 * 1024)`
/// (`lib/cf-h2-proxy.c:48`): the CONNECTION-level receive window this filter
/// announces once, at session start.
///
/// It is deliberately far larger than [`H2_TUNNEL_WINDOW_SIZE`]. The stream
/// window is what actually paces the tunnel; the connection window is opened
/// wide so it never becomes the binding constraint, because
/// `no_auto_window_update` is set and this module -- not nghttp2 -- decides
/// when a window reopens.
#[cfg(feature = "http2")]
pub(crate) const PROXY_HTTP2_HUGE_WINDOW_SIZE: u32 = 100 * 1024 * 1024;

/// `H2_TUNNEL_WINDOW_SIZE (10 * 1024 * 1024)` (`lib/cf-h2-proxy.c:49`): the
/// STREAM-level window, announced in the initial SETTINGS.
#[cfg(feature = "http2")]
pub(crate) const H2_TUNNEL_WINDOW_SIZE: u32 = 10 * 1024 * 1024;

/// `PROXY_H2_NW_RECV_CHUNKS` (`lib/cf-h2-proxy.c:51`) = 10 MiB / 16 KiB =
/// **640**: the network receive queue is sized to hold a full stream window.
#[cfg(feature = "http2")]
pub(crate) const PROXY_H2_NW_RECV_CHUNKS: usize =
    H2_TUNNEL_WINDOW_SIZE as usize / PROXY_H2_CHUNK_SIZE;

/// `PROXY_H2_NW_SEND_CHUNKS 1` (`lib/cf-h2-proxy.c:52`): the network SEND
/// queue holds a single chunk.
///
/// One, not more, on purpose. Frames the session serialises are pushed at the
/// transport immediately; the queue exists only to hold the remainder of a
/// short write. Buffering more would let the session run ahead of a blocked
/// socket and defeat its own flow control.
#[cfg(feature = "http2")]
pub(crate) const PROXY_H2_NW_SEND_CHUNKS: usize = 1;

/// `H2_TUNNEL_RECV_CHUNKS` (`lib/cf-h2-proxy.c:54`) = **640**.
#[cfg(feature = "http2")]
pub(crate) const H2_TUNNEL_RECV_CHUNKS: usize =
    H2_TUNNEL_WINDOW_SIZE as usize / PROXY_H2_CHUNK_SIZE;

/// `H2_TUNNEL_SEND_CHUNKS` (`lib/cf-h2-proxy.c:55`) = 128 KiB / 16 KiB =
/// **8**.
#[cfg(feature = "http2")]
pub(crate) const H2_TUNNEL_SEND_CHUNKS: usize =
    (128 * 1024) / PROXY_H2_CHUNK_SIZE;

/// `"shutdown"` -- the GOAWAY debug payload (`lib/cf-h2-proxy.c:1063`).
///
/// The C passes `sizeof("shutdown")`, which is **9** and INCLUDES the
/// terminating NUL. That is almost certainly not what its author meant, but
/// it is what goes on the wire, so [`GOAWAY_DEBUG_DATA`] carries the NUL
/// explicitly and its length is asserted in the tests.
#[cfg(feature = "http2")]
pub(crate) const GOAWAY_DEBUG_DATA: &[u8] = b"shutdown\0";

/// `"Establish HTTP/2 proxy tunnel to %s"` (`lib/cf-h2-proxy.c:772`).
#[cfg(feature = "http2")]
const MSG_ESTABLISH_H2_TUNNEL: &str = "Establish HTTP/2 proxy tunnel to";

/// `"Failed sending CONNECT to proxy"` (`lib/cf-h2-proxy.c:774`) -- the same
/// wording the HTTP/1.x sender uses, from a different call site.
#[cfg(feature = "http2")]
const MSG_H2_SEND_FAILED: &str = CONNECT_SEND_FAILED;

/// `"Failed receiving HTTP2 proxy data"` (`lib/cf-h2-proxy.c:360`).
#[cfg(feature = "http2")]
const MSG_H2_RECV_FAILED: &str = "Failed receiving HTTP2 proxy data";

/// `"Failed sending HTTP2 data"` (`lib/cf-h2-proxy.c:416`).
#[cfg(feature = "http2")]
const MSG_H2_SEND_DATA_FAILED: &str = "Failed sending HTTP2 data";

/// `h2_tunnel_state` (`lib/cf-h2-proxy.c:58-64`) -- **FIVE** states.
///
/// There is no `RECEIVE` here, and its absence is structural rather than an
/// omission. The HTTP/1.x machine needs one because it reads the response
/// itself, one byte at a time, and must be able to suspend mid-header. HTTP/2
/// hands whole frames to the session, which reports a complete header block
/// through a callback, so `CONNECT` collapses to "sending" and "sent" and the
/// response either exists or does not.
#[cfg(feature = "http2")]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum H2TunnelState {
    /// `H2_TUNNEL_INIT` -- *"init/default/no tunnel state"*.
    #[default]
    Init,
    /// `H2_TUNNEL_CONNECT` -- *"CONNECT request is being send"*.
    Connect,
    /// `H2_TUNNEL_RESPONSE` -- *"CONNECT response received completely"*.
    Response,
    /// `H2_TUNNEL_ESTABLISHED`.
    Established,
    /// `H2_TUNNEL_FAILED`.
    Failed,
}

#[cfg(feature = "http2")]
impl H2TunnelState {
    /// The `CURL_TRC_CF` string `h2_tunnel_go_state` emits on ENTRY
    /// (`lib/cf-h2-proxy.c:132-160`).
    ///
    /// Every one carries the stream identifier -- `"[%d] new tunnel state
    /// '...'"` -- where the HTTP/1.x equivalents do not, because an HTTP/2
    /// trace has to say which stream it is talking about. Frozen strings.
    pub(crate) const fn entry_trace(self) -> &'static str {
        match self {
            Self::Init => "new tunnel state 'init'",
            Self::Connect => "new tunnel state 'connect'",
            Self::Response => "new tunnel state 'response'",
            Self::Established => "new tunnel state 'established'",
            Self::Failed => "new tunnel state 'failed'",
        }
    }
}

/// `struct http_resp` (`lib/http.h`), as much of it as a `CONNECT` tunnel
/// reads.
///
/// # Why `prev` is kept
///
/// `proxy_h2_on_header` writes `resp->prev = ctx->tunnel.resp`
/// (`lib/cf-h2-proxy.c:576`), so responses form a chain with the newest at the
/// head. An interim 1xx therefore is not discarded when the final response
/// arrives -- it is pushed down. Dropping the chain would be simpler and
/// would lose `CURLINFO` the C is able to report, so the chain stays.
#[cfg(feature = "http2")]
#[derive(Debug)]
pub(crate) struct H2Response {
    /// `int status` -- the `:status` value.
    pub(crate) status: i32,
    /// `struct dynhds headers`.
    pub(crate) headers: HeaderSet,
    /// `struct http_resp *prev` -- the response this one displaced.
    ///
    /// Read through [`H2Response::chain_len`] only. It exists because the C
    /// keeps the chain and an interim 1xx is therefore RETAINED rather than
    /// overwritten; dropping it would discard information the C preserves.
    #[allow(dead_code)] // consumer: H2Response::chain_len
    pub(crate) prev: Option<Box<H2Response>>,
}

#[cfg(feature = "http2")]
impl H2Response {
    /// `Curl_http_resp_make(&resp, status, NULL)` (`lib/http.c`), pushed in
    /// front of `prev`.
    fn new(status: i32, prev: Option<Box<Self>>) -> Self {
        Self {
            status,
            headers: HeaderSet::new(),
            prev,
        }
    }

    /// How many responses the chain holds, this one included.
    ///
    /// Exists so a test can assert that an interim 1xx was RETAINED rather
    /// than overwritten, which is the only externally checkable consequence
    /// of keeping `prev`.
    #[allow(dead_code)] // consumer: proxy::http_connect tests
    pub(crate) fn chain_len(&self) -> usize {
        let mut n = 1;
        let mut cursor = self.prev.as_deref();
        while let Some(resp) = cursor {
            n += 1;
            cursor = resp.prev.as_deref();
        }
        n
    }
}

/// `struct tunnel_stream` (`lib/cf-h2-proxy.c:66-77`).
#[cfg(feature = "http2")]
#[derive(Debug)]
pub(crate) struct TunnelStream {
    /// `struct http_resp *resp` -- the newest response, chained to the rest.
    pub(crate) resp: Option<Box<H2Response>>,
    /// `struct bufq recvbuf` -- tunnelled payload waiting for the
    /// application. SOFT-limited; see [`Self::init`].
    pub(crate) recvbuf: BufQ,
    /// `struct bufq sendbuf` -- tunnelled payload waiting for the session.
    pub(crate) sendbuf: BufQ,
    /// `char *authority` -- `host:port`, IPv6-bracketed when literal.
    pub(crate) authority: String,
    /// `int32_t stream_id`. **`-1` from [`Self::init`], `0` from
    /// [`Self::clear`]** -- see the note there.
    pub(crate) stream_id: i32,
    /// `uint32_t error` -- the HTTP/2 error code that ended the stream.
    pub(crate) error: u32,
    /// `h2_tunnel_state state`.
    pub(crate) state: H2TunnelState,
    /// `BIT(has_final_response)`.
    pub(crate) has_final_response: bool,
    /// `BIT(closed)`.
    pub(crate) closed: bool,
    /// `BIT(reset)`.
    pub(crate) reset: bool,
}

#[cfg(feature = "http2")]
impl TunnelStream {
    /// `tunnel_stream_init(cf, ts)` (`lib/cf-h2-proxy.c:79-101`).
    ///
    /// # The one asymmetric queue
    ///
    /// `recvbuf` is created with `BUFQ_OPT_SOFT_LIMIT` and the other three
    /// without it. A soft-limited queue accepts a write past its chunk
    /// ceiling rather than reporting `Again`, which matters here because the
    /// bytes being written are DATA frames the session has already
    /// acknowledged at the flow-control level: refusing them would mean
    /// dropping payload the peer is entitled to consider delivered. The
    /// window is what limits the peer; the queue merely holds what the window
    /// permitted.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`], which is what the C's single `goto out`
    /// from a failed authority allocation becomes (`:96-97`).
    fn init(dest: &TunnelDestination) -> CurlResult<Self> {
        Ok(Self {
            resp: None,
            recvbuf: BufQ::with_opts(
                PROXY_H2_CHUNK_SIZE,
                H2_TUNNEL_RECV_CHUNKS,
                BufqOpts::SOFT_LIMIT,
            ),
            sendbuf: BufQ::new(PROXY_H2_CHUNK_SIZE, H2_TUNNEL_SEND_CHUNKS),
            authority: dest.authority(),
            stream_id: -1,
            error: 0,
            state: H2TunnelState::Init,
            has_final_response: false,
            closed: false,
            reset: false,
        })
    }

    /// `tunnel_stream_clear(ts)` (`lib/cf-h2-proxy.c:103-111`).
    ///
    /// # Two measured details that a tidier implementation would get wrong
    ///
    /// **`stream_id` becomes `0`, not `-1`.** The C is
    /// `memset(ts, 0, sizeof(*ts)); ts->state = H2_TUNNEL_INIT;` -- it
    /// restores the state field by hand and nothing else, so every other
    /// field takes its all-bits-zero value and the identifier lands on `0`
    /// rather than on the `-1` that [`Self::init`] wrote. That is observable
    /// through `adjust_pollset`, whose `s_exhaust` term is guarded by
    /// `stream_id >= 0`: after a clear the guard passes where after an init it
    /// would not. Reproduced exactly.
    ///
    /// **`authority` is KEPT.** The C's `memset` nulls the pointer after
    /// `Curl_safefree` releases it, and then `H2_CONNECT` -- re-entered
    /// immediately, because its loop condition is `state == H2_TUNNEL_INIT` --
    /// asserts `ts->authority` and formats it into a trace. In a release
    /// build that reads a NULL pointer; with tracing on it reads freed
    /// memory. It is a latent defect in the C and it is not reproducible in
    /// safe Rust. Keeping the string is both sound and observably identical,
    /// because `tunnel_stream_init` derives it deterministically from the
    /// connection and would recompute the very same bytes.
    fn clear(&mut self) {
        let authority = mem::take(&mut self.authority);
        self.resp = None;
        self.recvbuf.free();
        self.sendbuf.free();
        self.stream_id = 0;
        self.error = 0;
        self.has_final_response = false;
        self.closed = false;
        self.reset = false;
        self.authority = authority;
        self.state = H2TunnelState::Init;
    }
}

// ---------------------------------------------------------------------------
// 15. `"H2-PROXY"` -- the filter.
// ---------------------------------------------------------------------------

/// `struct cf_h2_proxy_ctx` (`lib/cf-h2-proxy.c:163-178`), minus
/// `call_data`.
///
/// `cf_call_data` does not survive the translation and does not need to: it
/// exists so the nghttp2 callbacks, which receive only a `void *`, can find
/// the `Curl_easy` the current call belongs to. Here the equivalent arrives as
/// the [`CallCtx`] parameter every trait method already takes, which is the
/// same information with none of the save/restore ritual.
#[cfg(feature = "http2")]
#[derive(Debug)]
struct H2ProxyCtx {
    /// `nghttp2_session *h2`. `None` until `cf_h2_proxy_ctx_init` has run and
    /// again after `cf_h2_proxy_ctx_clear`, which is exactly what the C's
    /// nullable pointer means -- and every `if(ctx->h2)` test in
    /// `lib/cf-h2-proxy.c` reads as [`Option::is_some`] here.
    session: Option<Box<dyn H2TunnelSession>>,
    /// `struct bufq inbufq` -- *"network receive buffer"*.
    inbufq: BufQ,
    /// `struct bufq outbufq` -- *"network send buffer"*.
    outbufq: BufQ,
    /// `struct tunnel_stream tunnel` -- *"our tunnel CONNECT stream"*.
    tunnel: TunnelStream,
    /// `int32_t goaway_error`.
    goaway_error: i32,
    /// `int32_t last_stream_id`.
    last_stream_id: i32,
    /// `BIT(conn_closed)`.
    conn_closed: bool,
    /// `BIT(rcvd_goaway)`.
    rcvd_goaway: bool,
    /// `BIT(sent_goaway)`.
    sent_goaway: bool,
    /// `BIT(nw_out_blocked)`.
    nw_out_blocked: bool,
}

#[cfg(feature = "http2")]
impl H2ProxyCtx {
    /// The state `cf_h2_proxy_ctx_clear` leaves behind
    /// (`lib/cf-h2-proxy.c:185-197`) and the state
    /// `Curl_cf_h2_proxy_insert_after` allocates
    /// (`lib/cf-h2-proxy.c:1481-1500`): both are all-bits-zero apart from the
    /// tunnel state, because the C reaches both through `memset`.
    fn empty() -> Self {
        Self {
            session: None,
            inbufq: BufQ::new(PROXY_H2_CHUNK_SIZE, PROXY_H2_NW_RECV_CHUNKS),
            outbufq: BufQ::new(PROXY_H2_CHUNK_SIZE, PROXY_H2_NW_SEND_CHUNKS),
            tunnel: TunnelStream {
                resp: None,
                recvbuf: BufQ::with_opts(
                    PROXY_H2_CHUNK_SIZE,
                    H2_TUNNEL_RECV_CHUNKS,
                    BufqOpts::SOFT_LIMIT,
                ),
                sendbuf: BufQ::new(PROXY_H2_CHUNK_SIZE, H2_TUNNEL_SEND_CHUNKS),
                authority: String::new(),
                stream_id: 0,
                error: 0,
                state: H2TunnelState::Init,
                has_final_response: false,
                closed: false,
                reset: false,
            },
            goaway_error: 0,
            last_stream_id: 0,
            conn_closed: false,
            rcvd_goaway: false,
            sent_goaway: false,
            nw_out_blocked: false,
        }
    }

    /// `cf_h2_proxy_ctx_clear(ctx)` (`lib/cf-h2-proxy.c:185-197`):
    /// `nghttp2_session_del`, free both network queues, clear the tunnel, and
    /// `memset` the whole thing.
    ///
    /// Dropping [`Self::session`] IS `nghttp2_session_del` -- the C's explicit
    /// free has no counterpart because the box owns the session. That is the
    /// one place where Rust removes a step rather than translating it.
    fn clear(&mut self) {
        *self = Self::empty();
    }

    /// `proxy_h2_should_close_session(ctx)` (`lib/cf-h2-proxy.c:259-265`):
    /// *"the session wants neither to read nor to write"*, so nothing further
    /// can happen on it.
    fn should_close_session(&self) -> bool {
        match self.session.as_deref() {
            Some(session) => !session.want_read() && !session.want_write(),
            // With no session there is nothing to keep open. The C reaches
            // this only through a NULL `ctx->h2`, which its callers guard.
            None => true,
        }
    }
}

/// The HTTP/2 `CONNECT` tunnel -- `Curl_cft_h2_proxy`
/// (`lib/cf-h2-proxy.c:1461-1479`).
///
/// # It is not a multiplexing filter, and that is measured
///
/// The flags are `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY`. **`CF_TYPE_MULTIPLEX`
/// is absent** even though the transport underneath is HTTP/2, and the reason
/// is that the flag advertises a capability of the CONNECTION to the pool: a
/// multiplexing filter invites the connection cache to attach further
/// transfers to it. This filter carries exactly one stream, forever -- the
/// `CONNECT` -- and the tunnelled bytes belong to whichever single transfer
/// opened it. Advertising multiplexing would let the pool hand the same
/// tunnel to a second transfer and interleave two unrelated byte streams
/// inside it. Do not add the flag.
///
/// # It is the only proxy filter that carries traffic
///
/// `"HTTP-PROXY"`, `"H1-PROXY"`, `"SOCKS"` and `"HAPROXY"` all step aside once
/// their handshake completes: the bytes that follow pass through the default
/// `send`/`recv`, straight to the transport. This one cannot, because every
/// tunnelled byte has to be framed as HTTP/2 DATA and flow-controlled. That
/// is why it overrides eleven of the twelve operations -- everything except
/// `keep_alive` -- and why its context is NOT freed when the tunnel comes up.
#[cfg(feature = "http2")]
#[derive(Debug)]
pub(crate) struct H2Proxy {
    /// The `Curl_cfilter` fields every filter shares.
    base: FilterBase,
    /// `cf->ctx`, as a concrete typed field.
    ctx: H2ProxyCtx,
    /// The connection facts and the session factory.
    seams: TunnelSeams,
}

#[cfg(feature = "http2")]
impl H2Proxy {
    /// `Curl_cf_h2_proxy_insert_after(cf_at, data)`
    /// (`lib/cf-h2-proxy.c:1481-1500`).
    ///
    /// The context is allocated EAGERLY -- unlike `"H1-PROXY"`, which leaves
    /// `cf->ctx` NULL until its first connect. `ctx->h2` is still NULL, so the
    /// laziness that matters is preserved; only the surrounding allocation
    /// moves earlier.
    pub(crate) fn new(sockindex: SocketIndex, seams: TunnelSeams) -> Self {
        Self {
            base: FilterBase::new(sockindex),
            ctx: H2ProxyCtx::empty(),
            seams,
        }
    }

    /// The tunnel state, for tests and for [`HttpProxy`]'s dispatch record.
    #[allow(dead_code)] // consumer: proxy::http_connect tests
    pub(crate) fn tunnel_state(&self) -> H2TunnelState {
        self.ctx.tunnel.state
    }

    /// The stream identifier the session allocated, or the initial `-1`.
    #[allow(dead_code)] // consumer: proxy::http_connect tests
    pub(crate) fn stream_id(&self) -> i32 {
        self.ctx.tunnel.stream_id
    }

    /// The newest response, if one has arrived.
    #[allow(dead_code)] // consumer: proxy::http_connect tests
    pub(crate) fn response(&self) -> Option<&H2Response> {
        self.ctx.tunnel.resp.as_deref()
    }

    /// `CURL_TRC_CF(data, cf, ...)` for this filter, with `[<stream_id>] `
    /// prepended the way `lib/cf-h2-proxy.c` does throughout.
    fn trace(&self, cx: &mut CallCtx<'_, '_>, msg: &str) {
        let id = self.ctx.tunnel.stream_id;
        let sockindex = self.base.sockindex() as i32;
        if let Some(tracer) = cx.tracer_mut() {
            trc_cf!(
                tracer,
                TraceFilter::H2Proxy,
                sockindex,
                "[{}] {}",
                id,
                msg
            );
        }
    }

    /// `CURL_TRC_CF(data, cf, ...)` with no stream prefix, for the handful of
    /// messages the C emits as `"[0] ..."` or bare.
    fn trace_plain(&self, cx: &mut CallCtx<'_, '_>, msg: &str) {
        let sockindex = self.base.sockindex() as i32;
        if let Some(tracer) = cx.tracer_mut() {
            trc_cf!(tracer, TraceFilter::H2Proxy, sockindex, "{}", msg);
        }
    }

    /// `h2_tunnel_go_state(cf, ts, new_state, data)`
    /// (`lib/cf-h2-proxy.c:113-161`).
    ///
    /// # Three behaviours that are not in the HTTP/1.x equivalent
    ///
    /// * **A LEAVE hook.** Leaving `H2_TUNNEL_CONNECT` clears
    ///   `data->req.ignorebody`, which was set while the `CONNECT` was in
    ///   flight so that a non-2xx response body would be swallowed rather than
    ///   handed to the application. HTTP/1.x has no leave hook at all.
    /// * **Entering `Init` CLEARS the tunnel stream** -- see
    ///   [`TunnelStream::clear`]. HTTP/1.x's `Init` arm is a bare trace.
    /// * **`info.httpcode` is NOT reset.** The HTTP/1.x machine zeroes it on
    ///   both terminal states (`lib/cf-h1-proxy.c:180`); this one does not
    ///   touch it. Measured on both sides; the asymmetry stands.
    fn go_state(&mut self, cx: &mut CallCtx<'_, '_>, new_state: H2TunnelState) {
        // `if(ts->state == new_state) return;`
        if self.ctx.tunnel.state == new_state {
            return;
        }

        // Leaving.
        if self.ctx.tunnel.state == H2TunnelState::Connect {
            self.seams.conn.set_ignore_body(false);
        }

        // Entering.
        self.trace(cx, new_state.entry_trace());
        match new_state {
            H2TunnelState::Init => {
                self.ctx.tunnel.clear();
            }
            H2TunnelState::Connect | H2TunnelState::Response => {
                self.ctx.tunnel.state = new_state;
            }
            H2TunnelState::Established | H2TunnelState::Failed => {
                if new_state == H2TunnelState::Established {
                    info_line(cx, CONNECT_PHASE_COMPLETED);
                    self.seams.conn.set_proxy_auth_done(true);
                    self.seams.conn.set_proxy_auth_multipass(false);
                    // FALLTHROUGH() into the `H2_TUNNEL_FAILED` body.
                }
                self.ctx.tunnel.state = new_state;
                // *"If a proxy-authorization header was used for the proxy,
                // then we should make sure that it is not accidentally used
                // for the document request after we have connected."*
                self.seams.conn.clear_proxy_user_pwd();
            }
        }
    }

    /// `cf_h2_proxy_ctx_init(cf, data)` (`lib/cf-h2-proxy.c:884-961`).
    ///
    /// # The initial SETTINGS frame -- exactly three entries, in this order
    ///
    /// ```text
    /// SETTINGS_MAX_CONCURRENT_STREAMS = Curl_multi_max_concurrent_streams()
    /// SETTINGS_INITIAL_WINDOW_SIZE    = H2_TUNNEL_WINDOW_SIZE  (10 MiB)
    /// SETTINGS_ENABLE_PUSH            = 0
    /// ```
    ///
    /// The count, the identifiers and the order are all observable on the
    /// wire, and a proxy is entitled to behave differently for a client that
    /// announces a different set. `ENABLE_PUSH = 0` is not decoration: a
    /// `CONNECT` tunnel has no use for a pushed stream and
    /// `proxy_h2_on_header` rejects a PUSH_PROMISE outright
    /// (`lib/cf-h2-proxy.c:545-552`), so refusing push up front is what makes
    /// that rejection unreachable in practice.
    ///
    /// The connection window is then widened to
    /// [`PROXY_HTTP2_HUGE_WINDOW_SIZE`] with a stream-0
    /// `set_local_window_size`, which is a separate operation from the
    /// SETTINGS above and not a fourth entry in it.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::Http2`] for a SETTINGS or window-size failure
    ///   (`:940`, `:950`) -- the C converts both nghttp2 faults into that one
    ///   code.
    /// * [`CURLcode::OutOfMemory`] from [`TunnelStream::init`].
    /// * [`CURLcode::FailedInit`] when no session factory was injected, which
    ///   the dispatch in [`HttpProxy`] makes unreachable: it only installs
    ///   this filter after [`TunnelSeams::can_tunnel_h2`] has answered true.
    fn ctx_init(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        debug_assert!(self.ctx.session.is_none());

        let factory = match self.seams.h2.as_deref() {
            Some(factory) => factory,
            None => {
                return Err(Error::with_context(
                    CURLcode::FailedInit,
                    "H2-PROXY: no HTTP/2 session factory was injected",
                ))
            }
        };
        let mut session = factory.new_session();

        // `memset(&ctx->tunnel, 0, ...)` then `tunnel_stream_init`.
        let dest = destination(self.seams.conn.as_ref());
        self.ctx.inbufq =
            BufQ::new(PROXY_H2_CHUNK_SIZE, PROXY_H2_NW_RECV_CHUNKS);
        self.ctx.outbufq =
            BufQ::new(PROXY_H2_CHUNK_SIZE, PROXY_H2_NW_SEND_CHUNKS);
        self.ctx.tunnel = TunnelStream::init(&dest)?;

        let settings = SettingsTable::populate(
            self.seams.conn.max_concurrent_streams(),
            H2_TUNNEL_WINDOW_SIZE,
            false,
        );
        let result = session
            .submit_settings(&settings)
            .and_then(|()| {
                session.set_local_window_size(PROXY_HTTP2_HUGE_WINDOW_SIZE)
            })
            .map(|()| {
                self.ctx.session = Some(session);
            });

        // `CURL_TRC_CF(data, cf, "[0] init proxy ctx -> %d", result);`
        let code = match &result {
            Ok(()) => CURLcode::Ok,
            Err(err) => err.code(),
        };
        let sockindex = self.base.sockindex() as i32;
        if let Some(tracer) = cx.tracer_mut() {
            trc_cf!(
                tracer,
                TraceFilter::H2Proxy,
                sockindex,
                "[0] init proxy ctx -> {}",
                code as i32
            );
        }
        result
    }
}

#[cfg(feature = "http2")]
impl H2Proxy {
    /// `drain_tunnel(cf, data, tunnel)` (`lib/cf-h2-proxy.c:206-214`).
    ///
    /// *"data pending and no fatal error to report. Need to trigger draining
    /// to avoid stalling when no socket events happen."* The three conditions
    /// are all negative -- not closed, not reset, sendbuf NOT empty -- so an
    /// idle tunnel is never marked dirty.
    fn drain_tunnel(&self) {
        if !self.ctx.tunnel.closed
            && !self.ctx.tunnel.reset
            && !self.ctx.tunnel.sendbuf.is_empty()
        {
            self.seams.conn.mark_dirty();
        }
    }

    /// `on_session_send(h2, buf, blen, flags, userp)`
    /// (`lib/cf-h2-proxy.c:396-426`): hand serialised frames to the network
    /// queue, passing them straight through where the transport will take
    /// them.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] for anything other than a would-block, which is
    /// the C's `NGHTTP2_ERR_CALLBACK_FAILURE` plus
    /// `failf(data, "Failed sending HTTP2 data")`. A would-block is NOT an
    /// error: it raises `nw_out_blocked` and stops the send loop, exactly as
    /// `NGHTTP2_ERR_WOULDBLOCK` does.
    fn push_frames(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        frames: &[u8],
    ) -> CurlResult<()> {
        let mut offset = 0usize;
        let mut fatal: Option<CURLcode> = None;
        {
            let Self { base, ctx, .. } = self;
            while offset < frames.len() {
                let outcome = ctx.outbufq.write_pass(
                    &frames[offset..],
                    |span| match base.next_mut() {
                        Some(next) => {
                            next.send(cx, span, false).map_err(|err| err.code())
                        }
                        None => Err(CURLcode::FailedInit),
                    },
                );
                match outcome {
                    // `if(!nwritten) return NGHTTP2_ERR_WOULDBLOCK;`
                    Ok(0) => {
                        ctx.nw_out_blocked = true;
                        break;
                    }
                    Ok(nwritten) => offset += nwritten,
                    Err(CURLcode::Again) => {
                        ctx.nw_out_blocked = true;
                        break;
                    }
                    Err(code) => {
                        fatal = Some(code);
                        break;
                    }
                }
            }
        }
        match fatal {
            Some(_) => {
                fail_line(cx, MSG_H2_SEND_DATA_FAILED);
                Err(Error::with_context(
                    CURLcode::SendError,
                    MSG_H2_SEND_DATA_FAILED,
                ))
            }
            None => Ok(()),
        }
    }

    /// `proxy_h2_nw_out_flush(cf, data)` (`lib/cf-h2-proxy.c:267-288`).
    ///
    /// # Errors
    ///
    /// * [`CURLcode::Again`] when the transport blocked -- which also raises
    ///   `nw_out_blocked` -- **and also when the queue merely failed to empty**
    ///   (`:287`). The second case is the C's `return
    ///   Curl_bufq_is_empty(&ctx->outbufq) ? CURLE_OK : CURLE_AGAIN;`, and it
    ///   is why callers of the egress path test `result != CURLE_AGAIN` rather
    ///   than treating any error as fatal.
    /// * Whatever the transport reported otherwise.
    fn nw_out_flush(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        if self.ctx.outbufq.is_empty() {
            return Ok(());
        }
        let outcome = {
            let Self { base, ctx, .. } = self;
            ctx.outbufq.pass(|span| match base.next_mut() {
                Some(next) => {
                    next.send(cx, span, false).map_err(|err| err.code())
                }
                None => Err(CURLcode::FailedInit),
            })
        };
        match outcome {
            Ok(_) => {
                self.trace_plain(cx, "[0] nw send buffer flushed");
                if self.ctx.outbufq.is_empty() {
                    Ok(())
                } else {
                    Err(Error::new(CURLcode::Again))
                }
            }
            Err(CURLcode::Again) => {
                self.ctx.nw_out_blocked = true;
                self.trace_plain(cx, "[0] flush nw send buffer -> EAGAIN");
                Err(Error::new(CURLcode::Again))
            }
            Err(code) => Err(Error::new(code)),
        }
    }

    /// `proxy_h2_progress_egress(cf, data)` (`lib/cf-h2-proxy.c:376-393`).
    ///
    /// `while(!rv && !ctx->nw_out_blocked && nghttp2_session_want_write(h2))
    /// rv = nghttp2_session_send(h2);` then flush. `nw_out_blocked` is cleared
    /// at entry, not left standing from the previous call.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] for a fatal serialisation failure, or
    /// [`CURLcode::Again`] from the flush.
    fn progress_egress(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        self.ctx.nw_out_blocked = false;
        loop {
            if self.ctx.nw_out_blocked {
                break;
            }
            let wants = match self.ctx.session.as_deref() {
                Some(session) => session.want_write(),
                None => false,
            };
            if !wants {
                break;
            }
            let frames = match self.ctx.session.as_deref_mut() {
                Some(session) => session.take_output()?,
                None => break,
            };
            if frames.is_empty() {
                break;
            }
            self.push_frames(cx, &frames)?;
        }
        self.nw_out_flush(cx)
    }

    /// `proxy_h2_process_pending_input(cf, data)`
    /// (`lib/cf-h2-proxy.c:295-328`): feed the network queue to the session
    /// until it stops taking bytes or the queue empties.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] for a protocol fault, which is what the C's
    /// negative `nghttp2_session_mem_recv` becomes.
    fn process_pending_input(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<()> {
        loop {
            let offered;
            let taken;
            {
                let H2ProxyCtx {
                    inbufq, session, ..
                } = &mut self.ctx;
                let span = match inbufq.peek() {
                    Some(span) => span,
                    None => return Ok(()),
                };
                offered = span.len();
                match session.as_deref_mut() {
                    Some(session) => taken = session.accept_input(span)?,
                    None => return Ok(()),
                }
            }
            self.trace_plain(
                cx,
                &format!("[0] {offered} bytes to nghttp2 -> {taken}"),
            );
            // *"nghttp2 does not want to process more, but has no error. This
            // probably cannot happen, but be safe."*
            if taken == 0 {
                break;
            }
            self.ctx.inbufq.skip(taken);

            let events = match self.ctx.session.as_deref_mut() {
                Some(session) => session.poll_events()?,
                None => Vec::new(),
            };
            self.handle_events(cx, events)?;

            if self.ctx.inbufq.is_empty() {
                self.trace_plain(
                    cx,
                    "[0] all data in connection buffer processed",
                );
                break;
            }
            let left = self.ctx.inbufq.len();
            self.trace_plain(
                cx,
                &format!(
                    "[0] process_pending_input: {left} bytes left in \
                     connection buffer"
                ),
            );
        }
        Ok(())
    }

    /// Read from the transport into the network receive queue --
    /// `Curl_cf_recv_bufq(cf->next, data, &ctx->inbufq, 0, &nread)`
    /// (`lib/cf-h2-proxy.c:355`). A `max_len` of `0` means *"no limit besides
    /// the chunk space"*.
    ///
    /// # Errors
    ///
    /// Whatever the transport reported, [`CURLcode::Again`] included.
    fn recv_into_inbufq(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<usize> {
        let mut captured: Option<Error> = None;
        let outcome = {
            let Self { base, ctx, .. } = self;
            ctx.inbufq.sipn(0, |span| match base.next_mut() {
                Some(next) => next.recv(cx, span).map_err(|err| {
                    let code = err.code();
                    captured = Some(err);
                    code
                }),
                None => Err(CURLcode::SendError),
            })
        };
        match outcome {
            Ok(nread) => Ok(nread),
            Err(code) => Err(captured.unwrap_or_else(|| Error::new(code))),
        }
    }

    /// `proxy_h2_progress_ingress(cf, data)` (`lib/cf-h2-proxy.c:331-374`).
    ///
    /// # The four loop conditions, all negative
    ///
    /// ```text
    /// !conn_closed && !tunnel.closed && inbufq empty && !recvbuf full
    /// ```
    ///
    /// The last is the whole point of the queue's soft limit having a limit at
    /// all: the loop stops pulling from the network once the application's
    /// side is backed up, which is what turns HTTP/2 flow control into
    /// back-pressure on the tunnel rather than unbounded buffering.
    ///
    /// # Errors
    ///
    /// Whatever the transport or the session reported. A would-block breaks
    /// the loop and returns [`Ok`] -- it is not an error here.
    fn progress_ingress(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        if !self.ctx.inbufq.is_empty() {
            let pending = self.ctx.inbufq.len();
            self.trace_plain(
                cx,
                &format!("[0] process {pending} bytes in connection buffer"),
            );
            self.process_pending_input(cx)?;
        }

        while !self.ctx.conn_closed
            && !self.ctx.tunnel.closed
            && self.ctx.inbufq.is_empty()
            && !self.ctx.tunnel.recvbuf.is_full()
        {
            let nread = match self.recv_into_inbufq(cx) {
                Ok(nread) => nread,
                Err(err) if err.code() == CURLcode::Again => break,
                Err(err) => {
                    fail_line(cx, MSG_H2_RECV_FAILED);
                    return Err(err);
                }
            };
            if nread == 0 {
                self.ctx.conn_closed = true;
                break;
            }
            self.process_pending_input(cx)?;
        }
        Ok(())
    }

    /// The session's callbacks, as a single dispatch --
    /// `proxy_h2_on_frame_recv`, `proxy_h2_on_header`,
    /// `tunnel_recv_callback` and `proxy_h2_on_stream_close`
    /// (`lib/cf-h2-proxy.c:449-686`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`], which is what a
    /// `NGHTTP2_ERR_CALLBACK_FAILURE` becomes once it has travelled back out
    /// through `nghttp2_session_mem_recv`.
    fn handle_events(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        events: Vec<H2TunnelEvent>,
    ) -> CurlResult<()> {
        for event in events {
            match event {
                // Stream 0. *"Since the initial stream window is 64K, a
                // request might be on HOLD, due to exhaustion. The (initial)
                // SETTINGS may announce a much larger window and *assume*
                // that we treat this like a WINDOW_UPDATE."*
                H2TunnelEvent::Settings | H2TunnelEvent::WindowUpdate => {
                    if self.seams.conn.wants_send() {
                        self.drain_tunnel();
                    }
                }
                H2TunnelEvent::Goaway {
                    last_stream_id,
                    error,
                } => {
                    self.ctx.rcvd_goaway = true;
                    self.ctx.last_stream_id = last_stream_id;
                    // `goaway_error` is `int32_t` in the C and is assigned
                    // from a `uint32_t` error code.
                    self.ctx.goaway_error = error as i32;
                }
                H2TunnelEvent::Status(status) => {
                    // *"we do not do anything with trailers for tunnel
                    // streams"* -- the guard is BEFORE the `:status` handling,
                    // so a trailer block after the final response is dropped
                    // whole.
                    if self.ctx.tunnel.has_final_response {
                        continue;
                    }
                    // *"status: always comes first, we might get more than one
                    // response, link the previous ones for keepers"*
                    let prev = self.ctx.tunnel.resp.take();
                    self.ctx.tunnel.resp =
                        Some(Box::new(H2Response::new(status, prev)));
                    self.trace(cx, &format!("status: HTTP/2 {status:03}"));
                }
                H2TunnelEvent::Header { name, value } => {
                    if self.ctx.tunnel.has_final_response {
                        continue;
                    }
                    match self.ctx.tunnel.resp.as_deref_mut() {
                        Some(resp) => resp.headers.add(&name, &value)?,
                        // `if(!ctx->tunnel.resp) return
                        // NGHTTP2_ERR_CALLBACK_FAILURE;` -- a field before
                        // `:status` is a protocol violation.
                        None => {
                            return Err(Error::with_context(
                                CURLcode::RecvError,
                                "H2-PROXY: header before :status",
                            ))
                        }
                    }
                    self.trace(
                        cx,
                        &format!(
                            "header: {}: {}",
                            String::from_utf8_lossy(&name),
                            String::from_utf8_lossy(&value)
                        ),
                    );
                }
                H2TunnelEvent::HeadersComplete => {
                    // *"nghttp2 guarantees that :status is received"* -- but
                    // *"Fuzzing has proven this can still be reached without
                    // status code having been set"*, which is why the C tests
                    // the pointer and fails the callback.
                    let status = match self.ctx.tunnel.resp.as_deref() {
                        Some(resp) => resp.status,
                        None => {
                            return Err(Error::with_context(
                                CURLcode::RecvError,
                                "H2-PROXY: HEADERS without :status",
                            ))
                        }
                    };
                    self.trace(cx, &format!("got http status: {status}"));
                    // *"Only final status code signals the end of header"* --
                    // a 1xx leaves `has_final_response` clear, so the tunnel
                    // stays in `Connect` and waits for the real answer.
                    if !self.ctx.tunnel.has_final_response && status / 100 != 1
                    {
                        self.ctx.tunnel.has_final_response = true;
                    }
                }
                H2TunnelEvent::Reset { error } => {
                    // `if(frame->rst_stream.error_code) ctx->tunnel.reset =
                    // TRUE;` -- a ZERO code does not reset the tunnel.
                    if error != 0 {
                        self.ctx.tunnel.reset = true;
                    }
                }
                H2TunnelEvent::Data(payload) => {
                    // *"tunnel.recvbuf has soft limit, any success MUST add
                    // all data"*, which is why the queue is soft-limited:
                    // these bytes were already accounted for by flow control
                    // and cannot be refused.
                    let mut offset = 0usize;
                    while offset < payload.len() {
                        match self.ctx.tunnel.recvbuf.write(&payload[offset..])
                        {
                            Ok(0) => break,
                            Ok(nwritten) => offset += nwritten,
                            Err(CURLcode::Again) => break,
                            Err(code) => {
                                return Err(Error::with_context(
                                    code,
                                    "H2-PROXY: tunnel recv buffer write",
                                ))
                            }
                        }
                    }
                }
                H2TunnelEvent::StreamClosed { error } => {
                    self.trace(
                        cx,
                        &format!("proxy_h2_on_stream_close, (err {error})"),
                    );
                    self.ctx.tunnel.closed = true;
                    self.ctx.tunnel.error = error;
                    if error != 0 {
                        self.ctx.tunnel.reset = true;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "http2")]
impl H2Proxy {
    /// `submit_CONNECT(cf, data, ts)` (`lib/cf-h2-proxy.c:820-843`), which is
    /// `proxy_h2_submit` plus the two calls around it.
    ///
    /// The `2` handed to `Curl_http_proxy_create_CONNECT` is what suppresses
    /// `Host` and `Proxy-Connection`; see [`create_connect`] for why. Then:
    ///
    /// * **`Curl_creader_set_null(data)`** -- there is no request body on a
    ///   `CONNECT`, and the reader has to be silenced explicitly because the
    ///   session will otherwise ask for one through its DATA source.
    /// * **`infof(data, "Establish HTTP/2 proxy tunnel to %s", authority)`**
    ///   -- the HTTP/2 counterpart of `start_CONNECT`'s
    ///   `"Establish HTTP proxy tunnel to %s"`. The two wordings differ by the
    ///   `/2` and both are frozen.
    ///
    /// # Errors
    ///
    /// Whatever failed, and in every case
    /// `failf(data, "Failed sending CONNECT to proxy")` is emitted first --
    /// the C's `out:` label runs it for any non-`OK` result (`:773-774`).
    fn submit_connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        let result = self.submit_connect_inner(cx);
        if result.is_err() {
            fail_line(cx, MSG_H2_SEND_FAILED);
        }
        result
    }

    /// The body of [`Self::submit_connect`], separated so the single
    /// `failf` on the way out cannot be forgotten on a new early return.
    fn submit_connect_inner(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<()> {
        let req = create_connect(self.seams.conn.as_ref(), 2)?;
        self.seams.conn.set_reader_null()?;

        info_line(
            cx,
            &format!("{} {}", MSG_ESTABLISH_H2_TUNNEL, req.authority),
        );

        let headers = req_to_h2(&req)?;
        let stream_id = match self.ctx.session.as_deref_mut() {
            Some(session) => session.submit_connect(&headers)?,
            None => {
                return Err(Error::with_context(
                    CURLcode::SendError,
                    "H2-PROXY: no session to submit CONNECT on",
                ))
            }
        };
        self.ctx.tunnel.stream_id = stream_id;
        Ok(())
    }

    /// `inspect_response(cf, data, ts)` (`lib/cf-h2-proxy.c:776-815`).
    ///
    /// # The header name differs from the HTTP/1.x path, and deliberately so
    ///
    /// This function looks up `"Proxy-Authenticate"` in canonical casing where
    /// `on_resp_header` (`lib/cf-h1-proxy.c:508`) spells the very same field
    /// `"Proxy-authenticate:"` with a lower-case `a`. Both comparisons are
    /// case-insensitive, so the behaviour is identical and the difference is
    /// invisible on the wire -- but each file's spelling reaches trace output,
    /// and reproducing each where it belongs is what lets a reader diff this
    /// module against the C without noise.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] -- *"Seems to have failed"* -- for any
    /// non-2xx that did not yield a retry, plus whatever
    /// [`TunnelConn::input_auth`] reported.
    fn inspect_response(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        let status = match self.ctx.tunnel.resp.as_deref() {
            Some(resp) => resp.status,
            None => {
                return Err(Error::with_context(
                    CURLcode::RecvError,
                    "H2-PROXY: no response to inspect",
                ))
            }
        };

        if status / 100 == 2 {
            info_line(
                cx,
                &format!("CONNECT tunnel established, response {status}"),
            );
            self.go_state(cx, H2TunnelState::Established);
            return Ok(());
        }

        let wanted: Option<&str> = match status {
            401 => Some(NAME_WWW_AUTHENTICATE),
            407 => Some(NAME_PROXY_AUTHENTICATE),
            _ => None,
        };
        let challenge = wanted.and_then(|name| {
            self.ctx
                .tunnel
                .resp
                .as_deref()
                .and_then(|resp| resp.headers.get(name.as_bytes()))
                .map(|entry| entry.value().to_vec())
        });

        if let Some(challenge) = challenge {
            self.trace_plain(
                cx,
                &format!(
                    "[0] CONNECT: fwd auth header '{}'",
                    String::from_utf8_lossy(&challenge)
                ),
            );
            self.seams.conn.input_auth(status == 407, &challenge)?;
            if self.seams.conn.new_url().is_some() {
                // *"Indicator that we should try again"* -- on the SAME
                // session. HTTP/1.x has to weigh closing the connection here
                // (`lib/cf-h1-proxy.c:718-732`); HTTP/2 never does, because a
                // retry is simply another stream.
                self.seams.conn.clear_new_url();
                self.go_state(cx, H2TunnelState::Init);
                return Ok(());
            }
        }

        // *"Seems to have failed"*.
        Err(Error::with_context(
            CURLcode::RecvError,
            "H2-PROXY: CONNECT was refused",
        ))
    }

    /// `H2_CONNECT(cf, data, ts)` (`lib/cf-h2-proxy.c:817-871`).
    ///
    /// # The loop condition is the retry, and it is not the HTTP/1.x one
    ///
    /// `do { ... } while(ts->state == H2_TUNNEL_INIT);` -- the machine
    /// re-enters only while the state has been driven BACK to `Init`, which
    /// happens in exactly one place: [`Self::inspect_response`] doing so after
    /// a 407 produced a retry. The HTTP/1.x driver instead loops on
    /// `while(data->req.newurl)` and has to decide whether to reopen the
    /// connection. Same purpose, different mechanism, and the difference is
    /// that an HTTP/2 retry costs a stream rather than a connection.
    ///
    /// # The `out:` guard
    ///
    /// `if((result && (result != CURLE_AGAIN)) || ctx->tunnel.closed)
    /// h2_tunnel_go_state(..., H2_TUNNEL_FAILED, ...)`. Note the second
    /// disjunct: a tunnel the peer closed is failed even when no call reported
    /// an error.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] once the state is `Failed`, [`CURLcode::Again`]
    /// while the exchange is still in flight, or whatever a step reported.
    fn drive(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        let result = self.drive_states(cx);

        let failed = match &result {
            Ok(()) => self.ctx.tunnel.closed,
            Err(err) => err.code() != CURLcode::Again || self.ctx.tunnel.closed,
        };
        if failed {
            self.go_state(cx, H2TunnelState::Failed);
        }
        result
    }

    /// The `switch` of `H2_CONNECT`, with the C's two explicit
    /// `FALLTHROUGH()`s between `Init`, `Connect` and `Response`.
    fn drive_states(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        loop {
            let mut state = self.ctx.tunnel.state;
            // The C's `CURLcode result` survives the `switch` and is NOT
            // cleared on the failure path -- that is what carries an error out
            // through `out:`. Here the inner loop BREAKS WITH the value, which
            // says the same thing and leaves no path on which the code can be
            // forgotten.
            let result: CurlResult<()> = loop {
                match state {
                    H2TunnelState::Init => {
                        let authority = self.ctx.tunnel.authority.clone();
                        self.trace_plain(
                            cx,
                            &format!("[0] CONNECT start for {authority}"),
                        );
                        self.submit_connect(cx)?;
                        self.go_state(cx, H2TunnelState::Connect);
                        state = H2TunnelState::Connect;
                        // FALLTHROUGH()
                    }
                    H2TunnelState::Connect => {
                        // *"see that the request is completely sent"*
                        let progress = self
                            .progress_ingress(cx)
                            .and_then(|()| self.progress_egress(cx));
                        if let Err(err) = &progress {
                            if err.code() != CURLcode::Again {
                                self.go_state(cx, H2TunnelState::Failed);
                                // `break` out of the switch, NOT `goto out` --
                                // the C falls to the `while` condition, which
                                // is false in `Failed`, and then to `out:`
                                // with `result` still set.
                                break progress;
                            }
                        }
                        if !self.ctx.tunnel.has_final_response {
                            // `result = CURLE_OK; goto out;` -- a would-block
                            // with the response still incomplete is not a
                            // failure, so the code IS cleared here.
                            return Ok(());
                        }
                        self.go_state(cx, H2TunnelState::Response);
                        state = H2TunnelState::Response;
                        // FALLTHROUGH()
                    }
                    H2TunnelState::Response => {
                        debug_assert!(self.ctx.tunnel.has_final_response);
                        self.inspect_response(cx)?;
                        break Ok(());
                    }
                    H2TunnelState::Established => return Ok(()),
                    H2TunnelState::Failed => {
                        return Err(Error::with_context(
                            CURLcode::RecvError,
                            "H2-PROXY: tunnel failed",
                        ))
                    }
                }
            };
            // `} while(ts->state == H2_TUNNEL_INIT);`
            if self.ctx.tunnel.state != H2TunnelState::Init {
                return result;
            }
        }
    }

    /// `h2_handle_tunnel_close(cf, data, pnread)`
    /// (`lib/cf-h2-proxy.c:1153-1170`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] when the stream carried an error code, with
    /// `failf(data, "HTTP/2 stream %u reset by %s (error 0x%x %s)")` naming
    /// **`"server"` when `reset` is set and `"curl"` when it is not** -- the
    /// distinction between a RST_STREAM that arrived and one this side sent.
    /// A zero error code is an orderly close and reports zero bytes.
    fn handle_tunnel_close(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<usize> {
        if self.ctx.tunnel.error != 0 {
            let by = if self.ctx.tunnel.reset {
                "server"
            } else {
                "curl"
            };
            let line = format!(
                "HTTP/2 stream {} reset by {} (error 0x{:x})",
                self.ctx.tunnel.stream_id, by, self.ctx.tunnel.error
            );
            fail_line(cx, &line);
            return Err(Error::with_context(CURLcode::RecvError, line));
        }
        self.trace(cx, "handle_tunnel_close -> 0");
        Ok(0)
    }

    /// `tunnel_recv(cf, data, buf, len, pnread)`
    /// (`lib/cf-h2-proxy.c:1172-1199`).
    ///
    /// # The three ways an empty queue is not simply "try later"
    ///
    /// ```text
    /// closed                                   -> handle_tunnel_close
    /// reset                                    -> RecvError
    /// conn_closed && inbufq empty              -> RecvError
    /// rcvd_goaway && last_stream_id < stream_id -> RecvError
    /// otherwise                                -> Again
    /// ```
    ///
    /// The GOAWAY term is the subtle one: a peer that shut down while
    /// announcing a last stream identifier BELOW this tunnel's has declared
    /// that it never processed the `CONNECT`, so waiting is pointless. A
    /// GOAWAY whose identifier reaches this stream leaves it alive.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] per the table, or [`CURLcode::Again`].
    fn tunnel_recv(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        if !self.ctx.tunnel.recvbuf.is_empty() {
            return self.ctx.tunnel.recvbuf.read(buf).map_err(Error::new);
        }
        if self.ctx.tunnel.closed {
            return self.handle_tunnel_close(cx);
        }
        if self.ctx.tunnel.reset
            || (self.ctx.conn_closed && self.ctx.inbufq.is_empty())
            || (self.ctx.rcvd_goaway
                && self.ctx.last_stream_id < self.ctx.tunnel.stream_id)
        {
            return Err(Error::with_context(
                CURLcode::RecvError,
                "H2-PROXY: tunnel cannot deliver more data",
            ));
        }
        Err(Error::new(CURLcode::Again))
    }

    /// `cf_h2_proxy_flush(cf, data)` (`lib/cf-h2-proxy.c:1319-1349`): resume
    /// the DATA source if there is anything buffered, then run egress.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] for a fatal resume, or whatever egress
    /// reported.
    fn flush(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        if !self.ctx.tunnel.sendbuf.is_empty() {
            let stream_id = self.ctx.tunnel.stream_id;
            if let Some(session) = self.ctx.session.as_deref_mut() {
                session.resume_data(stream_id)?;
            }
        }
        self.progress_egress(cx)
    }

    /// Offer the buffered tunnel payload to the session as DATA -- the push
    /// half of `tunnel_send_callback` (`lib/cf-h2-proxy.c:596-634`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] for a fatal failure.
    fn pump_sendbuf(&mut self) -> CurlResult<()> {
        let stream_id = self.ctx.tunnel.stream_id;
        loop {
            let H2ProxyCtx {
                tunnel, session, ..
            } = &mut self.ctx;
            let session = match session.as_deref_mut() {
                Some(session) => session,
                None => return Ok(()),
            };
            let span = match tunnel.sendbuf.peek() {
                Some(span) if !span.is_empty() => span,
                _ => return Ok(()),
            };
            let taken = session.send_body(stream_id, span, false)?;
            if taken == 0 {
                return Ok(());
            }
            tunnel.sendbuf.skip(taken);
        }
    }

    /// `proxy_h2_connisalive(cf, data, input_pending)`
    /// (`lib/cf-h2-proxy.c:1351-1387`).
    ///
    /// *"This happens before we have sent off a request and the connection is
    /// not in use by any other transfer, there should not be any data here,
    /// only protocol frames."* So pending input is consumed as frames and
    /// `input_pending` is reported as FALSE either way -- what the caller
    /// learns is whether the session survived reading them.
    fn conn_is_alive(&mut self, cx: &mut CallCtx<'_, '_>) -> Liveness {
        let below = match self.base.next_mut() {
            Some(next) => next.is_alive(cx),
            None => return Liveness::DEAD,
        };
        if !below.alive {
            return Liveness::DEAD;
        }
        if !below.input_pending {
            return Liveness::alive(false);
        }

        let alive = match self.recv_into_inbufq(cx) {
            Ok(_) => match self.process_pending_input(cx) {
                // *"immediate error, considered dead"*
                Err(_) => false,
                Ok(()) => !self.ctx.should_close_session(),
            },
            // *"the read failed so let's say this is dead anyway"*
            Err(err) => err.code() == CURLcode::Again,
        };
        Liveness {
            alive,
            input_pending: false,
        }
    }
}

/// `"WWW-Authenticate"` -- the 401 challenge field, looked up by name in the
/// HTTP/2 response (`lib/cf-h2-proxy.c:794`).
#[cfg(feature = "http2")]
const NAME_WWW_AUTHENTICATE: &str = "WWW-Authenticate";

/// `"Proxy-Authenticate"` -- the 407 challenge field
/// (`lib/cf-h2-proxy.c:797`), in the canonical casing this file uses. See
/// [`H2Proxy::inspect_response`] on why the HTTP/1.x path spells it
/// differently.
#[cfg(feature = "http2")]
const NAME_PROXY_AUTHENTICATE: &str = "Proxy-Authenticate";

#[cfg(feature = "http2")]
impl ConnFilter for H2Proxy {
    fn trace_name(&self) -> &'static str {
        H2_PROXY_FILTER_NAME
    }

    fn cf_type(&self) -> CfType {
        H2_PROXY_FLAGS
    }

    fn trace_filter(&self) -> Option<TraceFilter> {
        Some(TraceFilter::H2Proxy)
    }

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    /// `cf_h2_proxy_destroy` (`lib/cf-h2-proxy.c:1051-1062`):
    /// `cf_h2_proxy_ctx_free(ctx); cf->ctx = NULL;`
    ///
    /// **Does NOT chain**, as the trait requires: the caller owns the rest of
    /// the chain.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        let _ = cx;
        self.ctx.clear();
    }

    /// `cf_h2_proxy_connect(cf, data, done)`
    /// (`lib/cf-h2-proxy.c:964-1032`).
    ///
    /// # Three departures from the HTTP/1.x filter, all measured
    ///
    /// * **The sub-chain is connected under a guard.**
    ///   `if(!cf->next->connected) Curl_conn_cf_connect(cf->next, data,
    ///   done);` where `"H1-PROXY"` and `"SOCKS"` call down
    ///   unconditionally. The effect is the same on a fresh connection and
    ///   differs on a re-entry: this filter does not re-ask a transport that
    ///   already answered.
    /// * **No `Curl_pgrsReset`.** HTTP/1.x resets the progress meter on
    ///   success (`lib/cf-h1-proxy.c:686`); this does not.
    /// * **The context is NOT freed.** HTTP/1.x calls `tunnel_free` the
    ///   moment the tunnel comes up, because from then on its bytes pass
    ///   straight through. This filter's session must stay alive to frame
    ///   every subsequent byte, so the context outlives the handshake.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OperationTimedout`] once `Curl_timeleft_ms` has gone
    /// negative, [`CURLcode::Http2`] from session initialisation, or whatever
    /// [`Self::drive`] reported.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if self.base.is_connected() {
            return Ok(true);
        }

        // *"Connect the lower filters first"* -- but only if they are not
        // already up.
        let below_connected = self
            .base
            .next_ref()
            .is_some_and(|next| next.base().is_connected());
        if !below_connected {
            let done = match self.base.next_mut() {
                Some(next) => next.connect(cx)?,
                None => {
                    return Err(Error::with_context(
                        CURLcode::CouldntConnect,
                        "H2-PROXY: no transport below the tunnel",
                    ))
                }
            };
            if !done {
                return Ok(false);
            }
        }

        if self.ctx.session.is_none() {
            self.ctx_init(cx)?;
        }
        debug_assert!(!self.ctx.tunnel.authority.is_empty());

        if self.seams.conn.time_left_ms() < 0 {
            fail_line(cx, CONNECT_TIMEOUT);
            return Err(Error::with_context(
                CURLcode::OperationTimedout,
                CONNECT_TIMEOUT,
            ));
        }

        let result = self.drive(cx);

        // `*done = (result == CURLE_OK) && (ts->state ==
        // H2_TUNNEL_ESTABLISHED);` -- note that `Again` is NOT `OK` here, so a
        // still-in-flight exchange reports not-done even though the state may
        // already have advanced.
        let done = result.is_ok()
            && self.ctx.tunnel.state == H2TunnelState::Established;
        if done {
            self.base.set_connected(true);
            // *"The real request will follow the CONNECT, reset request
            // partially"*
            self.seams.conn.req_soft_reset()?;
            self.seams.conn.client_reset();
        }
        result.map(|()| done)
    }

    /// `cf_h2_proxy_close(cf, data)` (`lib/cf-h2-proxy.c:1034-1049`):
    /// clear the context, then chain.
    ///
    /// Unlike `"H1-PROXY"`, which only walks the tunnel state back to `Init`,
    /// this discards the whole session -- there is no way to resume an HTTP/2
    /// connection whose transport went away.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.ctx.clear();
        self.base.set_connected(false);
        if let Some(next) = self.base.next_mut() {
            next.close(cx);
        }
    }

    /// `cf_h2_proxy_shutdown(cf, data, done)`
    /// (`lib/cf-h2-proxy.c:1064-1108`).
    ///
    /// # The GOAWAY, byte for byte
    ///
    /// `nghttp2_submit_goaway(h2, NGHTTP2_FLAG_NONE, 0, 0,
    /// (const uint8_t *)"shutdown", sizeof("shutdown"))`:
    ///
    /// * `last_stream_id = 0` -- **not** the tunnel's identifier. Announcing
    ///   zero says "I processed no stream you may retry elsewhere", which is
    ///   the honest claim from a client that is closing down.
    /// * `error_code = 0` -- NO_ERROR; this is an orderly shutdown.
    /// * The debug payload is `sizeof("shutdown")` = **9** bytes and therefore
    ///   INCLUDES the terminating NUL. See [`GOAWAY_DEBUG_DATA`].
    ///
    /// It is submitted at most once, guarded by `sent_goaway`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] for a failed submission, or whatever egress or
    /// ingress reported. Either way `cf->shutdown` is raised, because
    /// `cf->shutdown = (result || *done)` treats a failure as terminal.
    fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if !self.base.is_connected()
            || self.ctx.session.is_none()
            || self.base.has_shut_down()
            || self.ctx.conn_closed
        {
            return Ok(true);
        }

        if !self.ctx.sent_goaway {
            let submitted = match self.ctx.session.as_deref_mut() {
                Some(session) => session.submit_goaway(0, 0, GOAWAY_DEBUG_DATA),
                None => Ok(()),
            };
            if let Err(err) = submitted {
                self.base.set_shut_down(true);
                return Err(err);
            }
            self.ctx.sent_goaway = true;
        }

        // *"GOAWAY submitted, process egress and ingress until nghttp2 is
        // done."*
        let mut result: CurlResult<()> = Ok(());
        if self.wants_write() {
            result = self.progress_egress(cx);
        }
        if result.is_ok() && self.wants_read() {
            result = self.progress_ingress(cx);
        }

        let done = self.ctx.conn_closed
            || (result.is_ok() && !self.wants_write() && !self.wants_read());
        self.base.set_shut_down(result.is_err() || done);
        result.map(|()| done)
    }

    /// `cf_h2_proxy_adjust_pollset(cf, data, ps)`
    /// (`lib/cf-h2-proxy.c:1110-1151`).
    ///
    /// # Why exhaustion inverts the direction
    ///
    /// The interesting term is
    /// `want_recv = (want_recv || c_exhaust || s_exhaust)`: a filter that has
    /// data to SEND but whose flow-control window is closed must poll for
    /// READABILITY, because the only thing that can unblock it is a
    /// WINDOW_UPDATE arriving. Polling for writability there would spin on a
    /// socket that is writable and a window that is shut.
    ///
    /// Correspondingly `want_send` drops the session's own wish when the
    /// stream window is exhausted -- `(!s_exhaust && want_send)` -- while
    /// keeping the two BUFFER terms unconditional, because bytes already
    /// serialised into `outbufq` are past flow control and only need the
    /// socket.
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset::set`] reported.
    fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        let sock = filter_socket(self, cx);
        if !is_valid_sock(sock) {
            return Ok(());
        }

        let has_session = self.ctx.session.is_some();
        let (mut want_recv, mut want_send) =
            if !self.base.is_connected() && has_session {
                (
                    self.wants_read(),
                    self.wants_write()
                        || !self.ctx.outbufq.is_empty()
                        || !self.ctx.tunnel.sendbuf.is_empty(),
                )
            } else {
                ps.check(sock)
            };

        if has_session && (want_recv || want_send) {
            let (c_exhaust, s_exhaust) = self.window_exhaustion();
            want_recv = want_recv || c_exhaust || s_exhaust;
            want_send = (!s_exhaust && want_send)
                || (!c_exhaust && self.wants_write())
                || !self.ctx.outbufq.is_empty()
                || !self.ctx.tunnel.sendbuf.is_empty();
            let sockindex = self.base.sockindex() as i32;
            let result = ps
                .set(sock, want_recv, want_send, cx.tracer_mut())
                .map_err(|code| {
                    Error::with_context(code, "H2-PROXY: pollset update failed")
                });
            let code = match &result {
                Ok(()) => CURLcode::Ok,
                Err(err) => err.code(),
            };
            if let Some(tracer) = cx.tracer_mut() {
                trc_cf!(
                    tracer,
                    TraceFilter::H2Proxy,
                    sockindex,
                    "adjust_pollset, want_recv={} want_send={} -> {}",
                    i32::from(want_recv),
                    i32::from(want_send),
                    code as i32
                );
            }
            return result;
        }

        // *"shutdown in progress"* -- the same computation, reached only
        // because the branch above declined.
        if self.ctx.sent_goaway && !self.base.has_shut_down() {
            let want_send = self.wants_write()
                || !self.ctx.outbufq.is_empty()
                || !self.ctx.tunnel.sendbuf.is_empty();
            let want_recv = self.wants_read();
            return ps
                .set(sock, want_recv, want_send, cx.tracer_mut())
                .map_err(|code| {
                    Error::with_context(code, "H2-PROXY: pollset update failed")
                });
        }
        Ok(())
    }

    /// `cf_h2_proxy_data_pending(cf, data)`
    /// (`lib/cf-h2-proxy.c:1052-1062`): unread network frames, or tunnelled
    /// payload once the tunnel is up. The state test on the second term
    /// matters -- a response body arriving during the handshake is not
    /// application data.
    fn data_pending(&mut self, cx: &CallCtx<'_, '_>) -> bool {
        if !self.ctx.inbufq.is_empty()
            || (self.ctx.tunnel.state == H2TunnelState::Established
                && !self.ctx.tunnel.recvbuf.is_empty())
        {
            return true;
        }
        match self.base.next_mut() {
            Some(next) => next.data_pending(cx),
            None => false,
        }
    }

    /// `cf_h2_proxy_send(cf, data, buf, len, eos, pnwritten)`
    /// (`lib/cf-h2-proxy.c:1251-1317`).
    ///
    /// The application's bytes go into `tunnel.sendbuf` and the session is
    /// resumed; the framing happens during egress. `eos` is `(void)`-ed by the
    /// C and is accepted here for the same reason -- a `CONNECT` tunnel has no
    /// end of stream short of closing.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::SendError`] before the tunnel is established, after it
    ///   has closed, or when the session is done AND the stream closed.
    /// * [`CURLcode::Http2`] when the session is done but the stream is NOT
    ///   closed -- *"nothing to do in this session"*. The pair is the C's own
    ///   distinction between "the peer hung up on us" and "we have talked
    ///   ourselves into a dead session", and the two codes are not
    ///   interchangeable.
    fn send(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &[u8],
        eos: bool,
    ) -> CurlResult<usize> {
        let _ = eos;
        if self.ctx.tunnel.state != H2TunnelState::Established {
            return Err(Error::with_context(
                CURLcode::SendError,
                "H2-PROXY: send before the tunnel was established",
            ));
        }
        if self.ctx.tunnel.closed {
            return Err(Error::with_context(
                CURLcode::SendError,
                "H2-PROXY: send on a closed tunnel",
            ));
        }

        let written = match self.ctx.tunnel.sendbuf.write(buf) {
            Ok(written) => written,
            Err(CURLcode::Again) => 0,
            Err(code) => {
                return Err(Error::with_context(
                    code,
                    "H2-PROXY: tunnel send buffer write",
                ))
            }
        };

        if !self.ctx.tunnel.sendbuf.is_empty() {
            // *"req body data is buffered, resume the potentially suspended
            // stream"*
            let stream_id = self.ctx.tunnel.stream_id;
            if let Some(session) = self.ctx.session.as_deref_mut() {
                session.resume_data(stream_id)?;
            }
            self.pump_sendbuf()?;
        }

        let mut result: CurlResult<()> = self.progress_ingress(cx);
        if result.is_ok() {
            result = self.progress_egress(cx);
        }

        if result.is_ok() && self.ctx.should_close_session() {
            // *"nghttp2 thinks this session is done. If the stream has not
            // been closed, this is an error state for out transfer"*
            if self.ctx.tunnel.closed {
                return Err(Error::with_context(
                    CURLcode::SendError,
                    "H2-PROXY: session done and tunnel closed",
                ));
            }
            self.trace_plain(cx, "[0] send: nothing to do in this session");
            return Err(Error::with_context(
                CURLcode::Http2,
                "H2-PROXY: nothing to do in this session",
            ));
        }

        if !self.ctx.tunnel.recvbuf.is_empty()
            && result
                .as_ref()
                .err()
                .map_or(true, |err| err.code() == CURLcode::Again)
        {
            self.drain_tunnel();
        }

        match result {
            Ok(()) => Ok(written),
            Err(err) if err.code() == CURLcode::Again && written > 0 => {
                Ok(written)
            }
            Err(err) => Err(err),
        }
    }

    /// `cf_h2_proxy_recv(cf, data, buf, len, pnread)`
    /// (`lib/cf-h2-proxy.c:1201-1249`).
    ///
    /// # The flow-control accounting, which is the reason for the seam
    ///
    /// After bytes reach the application:
    ///
    /// ```text
    /// CURL_TRC_CF(data, cf, "[%d] increase window by %zu", stream_id, nread);
    /// nghttp2_session_consume(ctx->h2, stream_id, nread);
    /// ```
    ///
    /// The session was created with `no_auto_window_update`, so nothing
    /// reopens the window on its own: it stays shut until THIS call says the
    /// application took the data. That is what bounds memory to
    /// [`H2_TUNNEL_WINDOW_SIZE`] instead of to whatever the peer feels like
    /// sending, and it is not reachable through a high-level HTTP client --
    /// hence `h2` being declared explicitly in the workspace manifest.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] before the tunnel is established, or whatever
    /// [`Self::tunnel_recv`] reported -- [`CURLcode::Again`] included.
    fn recv(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        if self.ctx.tunnel.state != H2TunnelState::Established {
            return Err(Error::with_context(
                CURLcode::RecvError,
                "H2-PROXY: recv before the tunnel was established",
            ));
        }

        if self.ctx.tunnel.recvbuf.is_empty() {
            self.progress_ingress(cx)?;
        }

        let outcome = self.tunnel_recv(cx, buf);

        if let Ok(nread) = outcome {
            let stream_id = self.ctx.tunnel.stream_id;
            self.trace(cx, &format!("increase window by {nread}"));
            if let Some(session) = self.ctx.session.as_deref_mut() {
                session.consume(stream_id, nread);
            }
        }

        // `Curl_1st_fatal(result, proxy_h2_progress_egress(cf, data))` -- the
        // FIRST fatal code wins, so an egress failure cannot mask a delivery
        // that already succeeded.
        let egress = self.progress_egress(cx);
        let result = match (outcome, egress) {
            (Ok(nread), Ok(())) => Ok(nread),
            (Ok(nread), Err(err)) if err.code() == CURLcode::Again => Ok(nread),
            (Ok(_), Err(err)) => Err(err),
            (Err(err), _) => Err(err),
        };

        if !self.ctx.tunnel.recvbuf.is_empty()
            && result
                .as_ref()
                .err()
                .map_or(true, |err| err.code() == CURLcode::Again)
        {
            self.drain_tunnel();
        }
        result
    }

    /// `cf_h2_proxy_cntrl(cf, data, event, arg1, arg2)`
    /// (`lib/cf-h2-proxy.c:1437-1459`): **`CF_CTRL_FLUSH` and nothing else**.
    ///
    /// Every other event falls through the C's `default: break;` and is
    /// answered `CURLE_OK` without being chained -- which is the trait's
    /// default and is why the other arms are absent here rather than
    /// forwarded.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::flush`] reported.
    fn cntrl(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        event: CfControl,
    ) -> CurlResult<()> {
        match event {
            CfControl::Flush => self.flush(cx),
            _ => Ok(()),
        }
    }

    /// `cf_h2_proxy_is_alive(cf, data, input_pending)`
    /// (`lib/cf-h2-proxy.c:1389-1403`).
    fn is_alive(&mut self, cx: &mut CallCtx<'_, '_>) -> Liveness {
        let liveness = if self.ctx.session.is_some() {
            self.conn_is_alive(cx)
        } else {
            Liveness::DEAD
        };
        let sockindex = self.base.sockindex() as i32;
        if let Some(tracer) = cx.tracer_mut() {
            trc_cf!(
                tracer,
                TraceFilter::H2Proxy,
                sockindex,
                "[0] conn alive -> {}, input_pending={}",
                i32::from(liveness.alive),
                i32::from(liveness.input_pending)
            );
        }
        liveness
    }

    /// `cf_h2_proxy_query(cf, data, query, pres1, pres2)`
    /// (`lib/cf-h2-proxy.c:1405-1435`).
    ///
    /// Three questions are answered here and every other one is chained:
    ///
    /// * **`CF_QUERY_HOST_PORT` reports the PROXY**, as
    ///   [`http_proxy_query`] does and as `"SOCKS"` deliberately does not.
    /// * **`CF_QUERY_NEED_FLUSH`** is true while either send-side queue holds
    ///   bytes, and only then -- a `false` is NOT returned, it falls through
    ///   to the chain, which is what lets a lower filter still ask for a
    ///   flush.
    /// * **`CF_QUERY_ALPN_NEGOTIATED` reports NOTHING.** The tunnel is HTTP/2
    ///   towards the proxy; what the ORIGIN negotiated is a separate
    ///   question that the filters installed above this one answer, and
    ///   claiming `h2` here would make the origin connection think it had
    ///   already agreed on a version.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] at the bottom of the chain -- a sentinel,
    /// not a failure.
    fn query(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        match query {
            CfQuery::HostPort => Ok(CfQueryValue::HostPort {
                host: self.seams.conn.proxy_host(),
                port: self.seams.conn.proxy_port(),
            }),
            CfQuery::NeedFlush
                if !self.ctx.outbufq.is_empty()
                    || !self.ctx.tunnel.sendbuf.is_empty() =>
            {
                self.trace_plain(cx, "needs flush");
                Ok(CfQueryValue::NeedFlush(true))
            }
            CfQuery::AlpnNegotiated => Ok(CfQueryValue::AlpnNegotiated(None)),
            _ => match self.base.next_mut() {
                Some(next) => next.query(cx, query),
                None => Err(Error::new(CURLcode::UnknownOption)),
            },
        }
    }
}

#[cfg(feature = "http2")]
impl H2Proxy {
    /// `nghttp2_session_want_read(ctx->h2)`, with a missing session reading
    /// as `false` -- every C call site is guarded by `if(ctx->h2)`.
    fn wants_read(&self) -> bool {
        self.ctx
            .session
            .as_deref()
            .is_some_and(|session| session.want_read())
    }

    /// `nghttp2_session_want_write(ctx->h2)`.
    fn wants_write(&self) -> bool {
        self.ctx
            .session
            .as_deref()
            .is_some_and(|session| session.want_write())
    }

    /// `(c_exhaust, s_exhaust)` as `adjust_pollset` computes them
    /// (`lib/cf-h2-proxy.c:1123-1126`).
    ///
    /// The stream term is guarded by `stream_id >= 0`, and that guard is
    /// load-bearing in a way [`TunnelStream::clear`] documents: a cleared
    /// tunnel holds `0`, which PASSES the guard, while a freshly initialised
    /// one holds `-1`, which does not.
    fn window_exhaustion(&self) -> (bool, bool) {
        match self.ctx.session.as_deref() {
            Some(session) => {
                let c_exhaust = session.remote_window_size() == 0;
                let stream_id = self.ctx.tunnel.stream_id;
                let s_exhaust = stream_id >= 0
                    && session.stream_remote_window_size(stream_id) == 0;
                (c_exhaust, s_exhaust)
            }
            None => (false, false),
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::tests::{
        events, new_log, EventLog, InMemory, TransportHandle,
    };
    use crate::conn::filters::CfControl;
    use crate::headers::{HeaderStore, CURLH_CONNECT, CURLH_HEADER};
    use crate::trace::{TraceConfig, TraceLevel, Tracer, WriterSink};
    use crate::transfer::chunked::ChunkSink;
    // `Progress` and the six `sendf` types are named here because
    // `Chunker::read` -- which IS in this module's dependency set -- takes a
    // `ClientCtx`, and `ClientCtx::new` takes every one of them. They arrive
    // transitively through that signature rather than as dependencies of their
    // own, and ONLY in this test module: the production code hands the decoder
    // to `TunnelConn::chunk_read` and never builds a context itself. That is
    // the same route `transfer/chunked.rs`'s own tests document, and the
    // alternative -- a stub decoder -- would make `"chunk reading DONE"`
    // evidence of nothing.
    use crate::transfer::progress::Progress;
    use crate::transfer::sendf::{
        ClientCallbackGuard, ClientConfig, ClientWriteFlags, RequestReadState,
        RequestWriteState, TransferControl,
    };
    // The transport below is `conn/filters.rs`'s own -- consumed, never
    // rebuilt -- and its handle IS an `Arc<SyncCell<_>>`. [`TunnelConn`] is
    // `Send + Sync` and takes `&self`, so a `RefCell` will not serve; this is
    // the interior mutability `proxy/socks.rs` uses for the identical reason.
    use crate::util::sync_cell::SyncCell;
    use crate::util::timeval::{CurlTime, TestClock};
    #[cfg(feature = "http2")]
    use std::collections::VecDeque;

    // -- the connection seam, as a test double ---------------------------

    /// Everything a [`TunnelConn`] answers, all settable.
    #[derive(Debug)]
    struct ConnFacts {
        sockindex: SocketIndex,
        connect_to_host: Option<String>,
        connect_to_port: Option<u16>,
        secondary_host: Option<String>,
        secondary_port: u16,
        host_name: String,
        remote_port: u16,
        ipv6_ip: bool,
        proxy_host: String,
        proxy_port: u16,
        proxy_type: ProxyType,
        scheme_name: String,
        scheme_flags: ProtocolOptions,
        connection_close_requested: bool,
        user_agent: Option<String>,
        custom_headers: Vec<String>,
        proxy_headers: Vec<String>,
        separate_headers: bool,
        /// What [`TunnelConn::output_auth`] will install, as though the
        /// authentication layer had composed it.
        compose_proxyuserpwd: Option<String>,
        proxy_user_pwd: Option<String>,
        proxy_auth_enabled: bool,
        proxy_auth_available: bool,
        auth_problem: bool,
        /// How many further challenges the authentication layer can answer.
        ///
        /// A COUNTDOWN rather than a flag, because that is what
        /// `Curl_http_auth_act` is: it sets `data->req.newurl` only while an
        /// untried mechanism remains, and a flag would model a layer that
        /// retries for ever.
        auth_retries: u32,
        new_url: Option<String>,
        http_code: i32,
        http_proxy_code: i32,
        time_left_ms: TimeDiff,
        #[cfg(feature = "http2")]
        max_concurrent_streams: u32,
        #[cfg(feature = "http2")]
        wants_send: bool,
        /// When set, `bump_header_size` fails with it.
        header_size_error: Option<CURLcode>,
    }

    impl Default for ConnFacts {
        /// A plain HTTP proxy at `the.proxy:8080` fronting
        /// `remote.example:443`, with no credentials and no custom headers --
        /// the shape `tests/data/test275` exercises.
        fn default() -> Self {
            Self {
                sockindex: SocketIndex::First,
                connect_to_host: None,
                connect_to_port: None,
                secondary_host: None,
                secondary_port: 0,
                host_name: "remote.example".to_string(),
                remote_port: 443,
                ipv6_ip: false,
                proxy_host: "the.proxy".to_string(),
                proxy_port: 8080,
                proxy_type: ProxyType::Http,
                scheme_name: "HTTPS".to_string(),
                scheme_flags: ProtocolOptions::NONE,
                connection_close_requested: false,
                user_agent: Some("curl/8.19.0-DEV".to_string()),
                custom_headers: Vec::new(),
                proxy_headers: Vec::new(),
                separate_headers: false,
                compose_proxyuserpwd: None,
                proxy_user_pwd: None,
                proxy_auth_enabled: false,
                proxy_auth_available: false,
                auth_problem: false,
                auth_retries: 0,
                new_url: None,
                http_code: 0,
                http_proxy_code: 0,
                time_left_ms: 0,
                #[cfg(feature = "http2")]
                max_concurrent_streams: 100,
                #[cfg(feature = "http2")]
                wants_send: false,
                header_size_error: None,
            }
        }
    }

    /// Every side effect the seam was asked to perform, in order.
    #[derive(Debug, Default)]
    struct ConnCalls {
        /// `(method, authority)` of each `Curl_http_output_auth`.
        output_auth: Vec<(String, String)>,
        /// `(proxy, challenge)` of each `Curl_http_input_auth`.
        input_auth: Vec<(bool, Vec<u8>)>,
        /// `(flags, line)` of each `Curl_client_write`.
        client_write: Vec<(u32, Vec<u8>)>,
        /// `(len, connect_only)` of each `Curl_bump_headersize`.
        header_sizes: Vec<(usize, bool)>,
        auth_acts: usize,
        req_soft_resets: usize,
        client_resets: usize,
        progress_resets: usize,
        progress_updates: usize,
        reader_nulls: usize,
        proxyuserpwd_clears: usize,
        info_httpcode_clears: usize,
        #[cfg(feature = "http2")]
        dirty_marks: usize,
        /// Every `data->req.ignorebody` assignment, in order.
        ignore_body: Vec<bool>,
        /// Every `authproxy.done` assignment, in order.
        auth_done: Vec<bool>,
        /// Every `authproxy.multipass` assignment, in order.
        auth_multipass: Vec<bool>,
    }

    /// A [`ChunkSink`] that swallows everything, which is what an IGNORED
    /// response body needs: `Curl_httpchunk_init(data, ch, TRUE)` means the
    /// decoder never calls its sink at all, so a recording one would only
    /// assert that it stayed empty.
    #[derive(Debug, Default)]
    struct NullSink;

    impl ChunkSink for NullSink {
        fn chunk_write(
            &mut self,
            _ctx: &mut crate::transfer::sendf::ClientCtx<'_>,
            _flags: ClientWriteFlags,
            _buf: &[u8],
        ) -> CurlResult<()> {
            Ok(())
        }
    }

    /// The pause and close hooks a [`crate::transfer::sendf::ClientCtx`]
    /// needs, recorded but never acted on.
    #[derive(Debug, Default)]
    struct NoControl;

    impl TransferControl for NoControl {
        fn stream_close(&mut self, _reason: &'static str) {}

        fn conn_close(&mut self, _reason: &'static str) {}

        fn pause_send(&mut self, _pause: bool) -> CurlResult<()> {
            Ok(())
        }

        fn pause_recv(&mut self, _pause: bool) -> CurlResult<()> {
            Ok(())
        }
    }

    /// The in-callback flag, asserted to stay a boolean.
    #[derive(Debug, Default)]
    struct NoGuard {
        depth: i32,
    }

    impl ClientCallbackGuard for NoGuard {
        fn set_in_callback(&mut self, inside: bool) {
            self.depth += if inside { 1 } else { -1 };
            assert!(
                (0..=1).contains(&self.depth),
                "the in-callback flag is a boolean: depth {} is impossible",
                self.depth
            );
        }
    }

    /// Everything the REAL [`Chunker`] borrows, owned in one place.
    ///
    /// The chunked drain of an ignored 407 body is driven by the production
    /// decoder rather than by a stub, because `"chunk reading DONE"` is only
    /// evidence of anything if a real state machine reached it.
    #[derive(Debug)]
    struct ChunkEnv {
        write: RequestWriteState,
        read: RequestReadState,
        config: ClientConfig,
        progress: Progress,
        clock: TestClock,
        control: NoControl,
        guard: NoGuard,
        sink: NullSink,
    }

    impl Default for ChunkEnv {
        fn default() -> Self {
            Self {
                write: RequestWriteState::default(),
                read: RequestReadState::default(),
                config: ClientConfig::default(),
                progress: Progress::default(),
                clock: TestClock::new(CurlTime::new(1_000, 0)),
                control: NoControl,
                guard: NoGuard::default(),
                sink: NullSink,
            }
        }
    }

    impl ChunkEnv {
        /// One `Curl_httpchunk_read(data, ch, buf, blen, &consumed)`.
        fn feed(
            &mut self,
            chunker: &mut Chunker,
            buf: &[u8],
        ) -> CurlResult<usize> {
            let Self {
                write,
                read,
                config,
                progress,
                clock,
                control,
                guard,
                sink,
            } = self;
            let mut ctx = crate::transfer::sendf::ClientCtx::new(
                write, read, &*config, progress, &*clock, control, guard,
            );
            chunker.read(&mut ctx, sink, false, buf)
        }
    }

    #[derive(Debug)]
    struct TestConn {
        facts: SyncCell<ConnFacts>,
        calls: SyncCell<ConnCalls>,
        chunks: SyncCell<ChunkEnv>,
        /// Every header the CONNECT phase recorded, with its origin, so that
        /// `CURLH_CONNECT` can be asserted where `curl_easy_header` would read
        /// it.
        headers: SyncCell<HeaderStore>,
    }

    impl TestConn {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                facts: SyncCell::new(ConnFacts::default()),
                calls: SyncCell::new(ConnCalls::default()),
                chunks: SyncCell::new(ChunkEnv::default()),
                headers: SyncCell::new(HeaderStore::new()),
            })
        }

        /// Mutates the facts in place, as a caller's configuration would.
        fn set(&self, body: impl FnOnce(&mut ConnFacts)) {
            body(&mut self.facts.borrow_mut());
        }

        fn calls(&self) -> std::sync::RwLockReadGuard<'_, ConnCalls> {
            self.calls.borrow()
        }
    }

    impl TunnelConn for TestConn {
        fn sockindex(&self) -> SocketIndex {
            self.facts.borrow().sockindex
        }

        fn connect_to_host(&self) -> Option<String> {
            self.facts.borrow().connect_to_host.clone()
        }

        fn connect_to_port(&self) -> Option<u16> {
            self.facts.borrow().connect_to_port
        }

        fn secondary_host(&self) -> String {
            let facts = self.facts.borrow();
            facts
                .secondary_host
                .clone()
                .unwrap_or_else(|| facts.host_name.clone())
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

        fn is_ipv6_ip(&self) -> bool {
            self.facts.borrow().ipv6_ip
        }

        fn proxy_host(&self) -> String {
            self.facts.borrow().proxy_host.clone()
        }

        fn proxy_port(&self) -> u16 {
            self.facts.borrow().proxy_port
        }

        fn proxy_type(&self) -> ProxyType {
            self.facts.borrow().proxy_type
        }

        fn scheme_name(&self) -> String {
            self.facts.borrow().scheme_name.clone()
        }

        fn scheme_flags(&self) -> ProtocolOptions {
            self.facts.borrow().scheme_flags
        }

        fn connection_close_requested(&self) -> bool {
            self.facts.borrow().connection_close_requested
        }

        fn user_agent(&self) -> Option<String> {
            self.facts.borrow().user_agent.clone()
        }

        fn custom_headers(&self) -> Vec<String> {
            self.facts.borrow().custom_headers.clone()
        }

        fn proxy_headers(&self) -> Vec<String> {
            self.facts.borrow().proxy_headers.clone()
        }

        fn separate_headers(&self) -> bool {
            self.facts.borrow().separate_headers
        }

        fn output_auth(&self, method: &str, authority: &str) -> CurlResult<()> {
            self.calls
                .borrow_mut()
                .output_auth
                .push((method.to_string(), authority.to_string()));
            // The SIDE EFFECT is the whole point: the real call composes
            // `data->state.aptr.proxyuserpwd` and adds no header itself.
            let composed = self.facts.borrow().compose_proxyuserpwd.clone();
            if let Some(line) = composed {
                self.facts.borrow_mut().proxy_user_pwd = Some(line);
            }
            Ok(())
        }

        fn proxy_user_pwd(&self) -> Option<String> {
            self.facts.borrow().proxy_user_pwd.clone()
        }

        fn clear_proxy_user_pwd(&self) {
            self.calls.borrow_mut().proxyuserpwd_clears += 1;
            self.facts.borrow_mut().proxy_user_pwd = None;
        }

        fn proxy_auth_enabled(&self) -> bool {
            self.facts.borrow().proxy_auth_enabled
        }

        fn proxy_auth_available(&self) -> bool {
            self.facts.borrow().proxy_auth_available
        }

        fn set_proxy_auth_done(&self, done: bool) {
            self.calls.borrow_mut().auth_done.push(done);
        }

        fn set_proxy_auth_multipass(&self, multipass: bool) {
            self.calls.borrow_mut().auth_multipass.push(multipass);
        }

        fn auth_problem(&self) -> bool {
            self.facts.borrow().auth_problem
        }

        fn input_auth(&self, proxy: bool, challenge: &[u8]) -> CurlResult<()> {
            self.calls
                .borrow_mut()
                .input_auth
                .push((proxy, challenge.to_vec()));
            // `Curl_http_input_auth` records the mechanism as available; the
            // decision to retry is `Curl_http_auth_act`'s, which is what sets
            // `data->req.newurl`. The HTTP/2 path reads `newurl` directly
            // after `input_auth`, so this double sets it here.
            let mut facts = self.facts.borrow_mut();
            facts.proxy_auth_available = true;
            if facts.auth_retries > 0 {
                facts.auth_retries -= 1;
                facts.new_url = Some("retry".to_string());
            }
            Ok(())
        }

        fn auth_act(&self) -> CurlResult<()> {
            self.calls.borrow_mut().auth_acts += 1;
            let mut facts = self.facts.borrow_mut();
            if facts.auth_retries > 0 {
                facts.auth_retries -= 1;
                facts.new_url = Some("retry".to_string());
            }
            Ok(())
        }

        fn new_url(&self) -> Option<String> {
            self.facts.borrow().new_url.clone()
        }

        fn clear_new_url(&self) {
            self.facts.borrow_mut().new_url = None;
        }

        fn http_code(&self) -> i32 {
            self.facts.borrow().http_code
        }

        fn set_http_code(&self, code: i32) {
            self.facts.borrow_mut().http_code = code;
        }

        fn set_http_proxy_code(&self, code: i32) {
            self.facts.borrow_mut().http_proxy_code = code;
        }

        fn http_proxy_code(&self) -> i32 {
            self.facts.borrow().http_proxy_code
        }

        fn clear_info_http_code(&self) {
            self.calls.borrow_mut().info_httpcode_clears += 1;
        }

        fn set_ignore_body(&self, ignore: bool) {
            self.calls.borrow_mut().ignore_body.push(ignore);
        }

        fn req_soft_reset(&self) -> CurlResult<()> {
            self.calls.borrow_mut().req_soft_resets += 1;
            Ok(())
        }

        fn client_reset(&self) {
            self.calls.borrow_mut().client_resets += 1;
        }

        fn progress_reset(&self) {
            self.calls.borrow_mut().progress_resets += 1;
        }

        fn progress_update(&self) -> CurlResult<()> {
            self.calls.borrow_mut().progress_updates += 1;
            Ok(())
        }

        fn set_reader_null(&self) -> CurlResult<()> {
            self.calls.borrow_mut().reader_nulls += 1;
            Ok(())
        }

        fn client_write(&self, flags: u32, line: &[u8]) -> CurlResult<()> {
            self.calls
                .borrow_mut()
                .client_write
                .push((flags, line.to_vec()));
            // What `transfer/writeout.rs`'s header collector does, which is
            // where `CURLH_CONNECT` is actually stamped: only a header write
            // that is NOT a status line is stored, and its origin comes from
            // the write flags.
            if let Some(origin) = crate::headers::classify_origin(flags) {
                let _ = self.headers.borrow_mut().push(line, origin, 0);
            }
            Ok(())
        }

        fn bump_header_size(
            &self,
            len: usize,
            connect_only: bool,
        ) -> CurlResult<()> {
            self.calls
                .borrow_mut()
                .header_sizes
                .push((len, connect_only));
            match self.facts.borrow().header_size_error {
                Some(code) => Err(Error::new(code)),
                None => Ok(()),
            }
        }

        fn chunk_read(
            &self,
            chunker: &mut Chunker,
            buf: &[u8],
        ) -> CurlResult<usize> {
            self.chunks.borrow_mut().feed(chunker, buf)
        }

        fn time_left_ms(&self) -> TimeDiff {
            self.facts.borrow().time_left_ms
        }

        #[cfg(feature = "http2")]
        fn max_concurrent_streams(&self) -> u32 {
            self.facts.borrow().max_concurrent_streams
        }

        #[cfg(feature = "http2")]
        fn mark_dirty(&self) {
            self.calls.borrow_mut().dirty_marks += 1;
        }

        #[cfg(feature = "http2")]
        fn wants_send(&self) -> bool {
            self.facts.borrow().wants_send
        }
    }

    // -- a short-writing decorator over the shared transport -------------

    /// A two-line adapter over the shared transport: it clips each write and
    /// it never reports end of file.
    ///
    /// `conn/filters.rs`'s [`InMemory`] is the transport of record and is
    /// CONSUMED rather than replaced -- every byte still lands in its `output`
    /// and comes from its `input`. Two behaviours of a real socket it cannot
    /// express are load-bearing here, and both are one line:
    ///
    /// * **A SHORT write.** `InMemory::send` either takes everything offered
    ///   or reports [`CURLcode::Again`]. Resumable partial sending is the one
    ///   behaviour of `send_CONNECT` that a take-it-all transport cannot
    ///   exercise at all, and getting it wrong duplicates a prefix on the
    ///   wire.
    /// * **Empty is not closed.** `InMemory::recv` answers `Ok(0)` for an
    ///   empty buffer, which the `CONNECT` reader correctly reads as the peer
    ///   having hung up -- `nread == 0` is exactly how `recv_CONNECT_resp`
    ///   detects that. A socket with nothing pending reports `EWOULDBLOCK`
    ///   instead, and `block_on_empty` says so.
    ///
    /// It adds no state of its own beyond those two knobs.
    #[derive(Debug)]
    struct Wire {
        base: FilterBase,
        /// The most bytes one write will forward.
        write_limit: usize,
        /// When set, a zero-byte read becomes [`CURLcode::Again`] rather than
        /// end of file.
        block_on_empty: bool,
    }

    impl Wire {
        /// Clips writes to `limit` and still reports end of file, for the
        /// partial-send path where a close is not in question.
        fn clipped(limit: usize) -> Self {
            Self {
                base: FilterBase::new(SocketIndex::First),
                write_limit: limit,
                block_on_empty: false,
            }
        }

        /// Forwards writes whole and never reports end of file, for the
        /// fragmented-response path.
        fn never_closes() -> Self {
            Self {
                base: FilterBase::new(SocketIndex::First),
                write_limit: usize::MAX,
                block_on_empty: true,
            }
        }
    }

    impl ConnFilter for Wire {
        fn trace_name(&self) -> &'static str {
            "WIRE"
        }

        fn cf_type(&self) -> CfType {
            CF_TYPE_IP_CONNECT
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            let done = match self.base.next_mut() {
                Some(next) => next.connect(cx)?,
                None => true,
            };
            self.base.set_connected(done);
            Ok(done)
        }

        fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
            self.base.set_connected(false);
            if let Some(next) = self.base.next_mut() {
                next.close(cx);
            }
        }

        fn send(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            buf: &[u8],
            eos: bool,
        ) -> CurlResult<usize> {
            let take = buf.len().min(self.write_limit);
            match self.base.next_mut() {
                Some(next) => next.send(cx, &buf[..take], eos),
                None => Ok(take),
            }
        }

        fn recv(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            buf: &mut [u8],
        ) -> CurlResult<usize> {
            let nread = match self.base.next_mut() {
                Some(next) => next.recv(cx, buf)?,
                None => 0,
            };
            if nread == 0 && self.block_on_empty {
                return Err(Error::new(CURLcode::Again));
            }
            Ok(nread)
        }
    }

    // -- fixtures --------------------------------------------------------

    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1, 0))
    }

    /// The seams for a build with no HTTP/2 session factory.
    fn seams(conn: &Arc<TestConn>) -> TunnelSeams {
        TunnelSeams::new(Arc::clone(conn) as Arc<dyn TunnelConn>)
    }

    /// An `"H1-PROXY"` filter over the shared in-memory transport.
    fn h1(conn: &Arc<TestConn>) -> (H1Proxy, TransportHandle, EventLog) {
        let log = new_log();
        let (transport, state) = InMemory::new("TRANSPORT", &log);
        let mut proxy =
            H1Proxy::new(conn.sockindex(), Some(ConnId::new(7)), seams(conn));
        proxy.base_mut().set_next(Some(link(transport)));
        (proxy, state, log)
    }

    /// The same, with a [`Wire`] adapter interposed above the transport.
    fn h1_over(
        conn: &Arc<TestConn>,
        wire: Wire,
    ) -> (H1Proxy, TransportHandle, EventLog) {
        let log = new_log();
        let (transport, state) = InMemory::new("TRANSPORT", &log);
        let mut wire = wire;
        wire.base_mut().set_next(Some(link(transport)));
        let mut proxy =
            H1Proxy::new(conn.sockindex(), Some(ConnId::new(7)), seams(conn));
        proxy.base_mut().set_next(Some(link(wire)));
        (proxy, state, log)
    }

    /// Feeds bytes to the transport as though the proxy had sent them.
    fn feed(state: &TransportHandle, bytes: &[u8]) {
        state.borrow_mut().input.extend_from_slice(bytes);
    }

    /// Every byte written so far.
    fn sent(state: &TransportHandle) -> Vec<u8> {
        state.borrow().output.clone()
    }

    /// Bytes the transport still holds -- what a tunnelled protocol would read
    /// next, and therefore the check that the `CONNECT` reader stopped
    /// exactly at the end of the header block.
    fn unread(state: &TransportHandle) -> Vec<u8> {
        state.borrow().input.clone()
    }

    /// Clears the record of what was written, so a second request can be
    /// asserted on its own.
    fn clear_output(state: &TransportHandle) {
        state.borrow_mut().output.clear();
    }

    fn readable(state: &TransportHandle, yes: bool) {
        state.borrow_mut().readable = yes;
    }

    fn writable(state: &TransportHandle, yes: bool) {
        state.borrow_mut().writable = yes;
    }

    /// One `connect` pass with no tracing.
    ///
    /// The answer is reduced to its [`CURLcode`] because [`Error`] carries
    /// context and is deliberately not [`PartialEq`]: what a test asserts is
    /// the code, which IS the observable contract.
    fn connect<F: ConnFilter>(
        filter: &mut F,
        clock: &TestClock,
    ) -> Result<bool, CURLcode> {
        let mut cx = CallCtx::new(clock);
        filter.connect(&mut cx).map_err(|err| err.code())
    }

    /// One `connect` pass with every diagnostic captured as text.
    fn connect_traced<F: ConnFilter>(
        filter: &mut F,
        clock: &TestClock,
    ) -> (Result<bool, CURLcode>, String) {
        let mut config = TraceConfig::new();
        config.set_filter_level(TraceFilter::HttpProxy, TraceLevel::Info);
        config.set_filter_level(TraceFilter::H1Proxy, TraceLevel::Info);
        #[cfg(feature = "http2")]
        config.set_filter_level(TraceFilter::H2Proxy, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let outcome = {
            let mut cx = CallCtx::new(clock).with_tracer(&mut tracer);
            filter.connect(&mut cx).map_err(|err| err.code())
        };
        let rendered =
            String::from_utf8(sink.into_inner()).expect("trace output is text");
        (outcome, rendered)
    }

    /// The `CONNECT` request bytes for one configuration, built directly.
    fn request(conn: &Arc<TestConn>, major: u8) -> Vec<u8> {
        let req =
            create_connect(conn.as_ref(), major).expect("the request composes");
        let mut out = DynBuf::new(DYN_HTTP_REQUEST);
        write_head(&req, http_minor_for(conn.proxy_type()), &mut out)
            .expect("the head serialises");
        out.as_slice().to_vec()
    }

    /// A minimal 200 response with no body.
    const OK_200: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

    // -- the CONNECT request bytes ---------------------------------------

    /// The decisive assertion of this module, and the one 31 fixtures make
    /// too.
    ///
    /// `tests/data/test275`'s `<verify><proxy>` block is
    ///
    /// ```text
    /// CONNECT remotesite.com.%TESTNUMBER:%HTTPPORT HTTP/1.1
    /// Host: remotesite.com.%TESTNUMBER:%HTTPPORT
    /// Proxy-Authorization: Basic ...
    /// User-Agent: curl/%VERSION
    /// Proxy-Connection: Keep-Alive
    /// ```
    ///
    /// with `crlf="headers"`, so every line ends `\r\n` and a bare `\r\n`
    /// closes the block. This test asserts the credential-free shape as one
    /// byte slice; [`connect_request_puts_credentials_between_host_and_agent`]
    /// adds the third line.
    #[test]
    fn connect_request_is_byte_exact_for_http_1_1() {
        let conn = TestConn::new();
        assert_eq!(
            request(&conn, 1),
            b"CONNECT remote.example:443 HTTP/1.1\r\n\
              Host: remote.example:443\r\n\
              User-Agent: curl/8.19.0-DEV\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              \r\n"
                .to_vec()
        );
    }

    /// Order is the likeliest defect, so it gets its own assertion rather than
    /// riding on the full-slice comparison.
    #[test]
    fn connect_request_puts_credentials_between_host_and_agent() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.compose_proxyuserpwd = Some(
                "Proxy-Authorization: Basic eW91YXJlOnlvdXJzZWxm".to_string(),
            );
        });

        assert_eq!(
            request(&conn, 1),
            b"CONNECT remote.example:443 HTTP/1.1\r\n\
              Host: remote.example:443\r\n\
              Proxy-Authorization: Basic eW91YXJlOnlvdXJzZWxm\r\n\
              User-Agent: curl/8.19.0-DEV\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              \r\n"
                .to_vec()
        );

        // And the order as an independent claim, so a future full-slice edit
        // cannot quietly reorder these three.
        let bytes = request(&conn, 1);
        let text = String::from_utf8(bytes).expect("ASCII");
        let host = text.find("Host:").expect("Host is emitted");
        let auth = text
            .find("Proxy-Authorization:")
            .expect("the credential is emitted");
        let agent = text.find("User-Agent:").expect("the agent is emitted");
        assert!(host < auth, "Host must precede Proxy-Authorization");
        assert!(auth < agent, "Proxy-Authorization must precede User-Agent");
    }

    /// `--proxy1.0` is `CURLPROXY_HTTP_1_0`, and
    /// `http_minor = (proxytype == CURLPROXY_HTTP_1_0) ? 0 : 1`.
    ///
    /// `tests/data/test1078` expects exactly this, `Proxy-Connection:
    /// Keep-Alive` included -- the 1.0 request still carries it.
    #[test]
    fn proxy_1_0_emits_an_http_1_0_request_line() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_type = ProxyType::Http10;
            facts.host_name = "127.0.0.1".to_string();
            facts.remote_port = 8990;
        });

        assert_eq!(
            request(&conn, 1),
            b"CONNECT 127.0.0.1:8990 HTTP/1.0\r\n\
              Host: 127.0.0.1:8990\r\n\
              User-Agent: curl/8.19.0-DEV\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              \r\n"
                .to_vec()
        );
    }

    /// `curl_maprintf("%s%s%s:%d", ipv6_ip ? "[" : "", ...)` -- the brackets
    /// reach BOTH the request target and `Host`, because both are the same
    /// string.
    #[test]
    fn a_literal_ipv6_destination_is_bracketed_in_both_places() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.host_name = "2001:db8::1".to_string();
            facts.remote_port = 443;
            facts.ipv6_ip = true;
        });

        assert_eq!(
            request(&conn, 1),
            b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\
              Host: [2001:db8::1]:443\r\n\
              User-Agent: curl/8.19.0-DEV\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              \r\n"
                .to_vec()
        );
    }

    /// A registered name that happens to contain a colon is NOT bracketed:
    /// the flag consulted is `ipv6_ip`, not the presence of a colon.
    #[test]
    fn a_non_literal_host_is_never_bracketed() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.host_name = "weird:name".to_string();
            facts.ipv6_ip = false;
        });
        let text = String::from_utf8(request(&conn, 1)).expect("ASCII");
        assert!(text.starts_with("CONNECT weird:name:443 HTTP/1.1\r\n"));
    }

    /// The port is ALWAYS present, even when it is the scheme default.
    #[test]
    fn the_authority_always_carries_a_port() {
        let conn = TestConn::new();
        conn.set(|facts| facts.remote_port = 80);
        let text = String::from_utf8(request(&conn, 1)).expect("ASCII");
        assert!(text.starts_with("CONNECT remote.example:80 HTTP/1.1\r\n"));
    }

    /// There is NO `Accept:` on a `CONNECT`. The non-tunnel absolute-URI
    /// request through a proxy does carry one -- see
    /// [`create_connect`]'s note on the asymmetry -- and that request belongs
    /// to `protocols/http1.rs`, not here.
    #[test]
    fn a_connect_carries_no_accept_header() {
        let conn = TestConn::new();
        let text = String::from_utf8(request(&conn, 1)).expect("ASCII");
        assert!(
            !text.contains("Accept:"),
            "a CONNECT must not carry Accept: -- {text:?}"
        );
    }

    /// `dynhds_add_custom` runs LAST, after `Proxy-Connection`.
    ///
    /// `separate_headers` is set because `HEADER_CONNECT` reads
    /// `data->set.proxyheaders` only when `data->set.sep_headers` is on --
    /// which is what `--proxy-header` arranges, by setting
    /// `CURLOPT_HEADEROPT` to `CURLHEADER_SEPARATE`. See
    /// [`the_connect_uses_the_ordinary_header_list_when_not_separated`] for
    /// the other half.
    #[test]
    fn custom_proxy_headers_are_emitted_last() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.separate_headers = true;
            facts.proxy_headers = vec!["X-Tunnel: yes".to_string()];
        });

        assert_eq!(
            request(&conn, 1),
            b"CONNECT remote.example:443 HTTP/1.1\r\n\
              Host: remote.example:443\r\n\
              User-Agent: curl/8.19.0-DEV\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              X-Tunnel: yes\r\n\
              \r\n"
                .to_vec()
        );
    }

    /// Each of the three built-in headers is suppressed by a custom proxy
    /// header of the same name, and the custom one appears in its own place --
    /// last -- rather than in the built-in slot.
    #[test]
    fn a_custom_header_suppresses_the_builtin_of_the_same_name() {
        for (name, line) in [
            ("Host", "Host: elsewhere:1"),
            ("User-Agent", "User-Agent: mine/1"),
            ("Proxy-Connection", "Proxy-Connection: close"),
        ] {
            let conn = TestConn::new();
            conn.set(|facts| {
                facts.separate_headers = true;
                facts.proxy_headers = vec![line.to_string()];
            });
            let text = String::from_utf8(request(&conn, 1)).expect("ASCII");
            assert_eq!(
                text.matches(&format!("{name}:")).count(),
                1,
                "{name} must appear exactly once -- {text:?}"
            );
            assert!(
                text.contains(&format!("{line}\r\n")),
                "the custom {name} must be the one emitted -- {text:?}"
            );
        }
    }

    /// An EMPTY `User-Agent` is not emitted at all -- the C requires
    /// `data->set.str[STRING_USERAGENT] && *data->set.str[STRING_USERAGENT]`.
    #[test]
    fn an_empty_user_agent_emits_no_header() {
        for agent in [None, Some(String::new())] {
            let conn = TestConn::new();
            conn.set(|facts| facts.user_agent = agent.clone());
            let text = String::from_utf8(request(&conn, 1)).expect("ASCII");
            assert!(
                !text.contains("User-Agent:"),
                "an absent or empty agent emits nothing -- {text:?}"
            );
            // And the rest of the request is unaffected.
            assert!(text.contains("Proxy-Connection: Keep-Alive\r\n"));
        }
    }

    /// `Curl_http_output_auth` is called FIRST, before any header is added,
    /// with the method and the authority -- and with `HTTPREQ_GET` standing in
    /// for the request kind because a `CONNECT` carries no body.
    #[test]
    fn the_auth_layer_is_consulted_before_any_header() {
        let conn = TestConn::new();
        let _ = request(&conn, 1);
        assert_eq!(
            conn.calls().output_auth,
            vec![("CONNECT".to_string(), "remote.example:443".to_string())]
        );
    }

    // -- destination resolution ------------------------------------------

    /// `Curl_http_proxy_get_destination`'s three cascades do NOT agree on
    /// which condition wins: `conn_to_host` outranks the secondary socket for
    /// the HOST, while the secondary socket outranks `conn_to_port` for the
    /// PORT. Both halves are asserted at once, because the disagreement is the
    /// only interesting thing about the function.
    #[test]
    fn the_destination_cascades_disagree_by_design() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.sockindex = SocketIndex::Secondary;
            facts.connect_to_host = Some("via.example".to_string());
            facts.connect_to_port = Some(9999);
            facts.secondary_host = Some("secondary.example".to_string());
            facts.secondary_port = 20;
            facts.host_name = "origin.example".to_string();
            facts.remote_port = 21;
        });

        let dest = destination(conn.as_ref());
        assert_eq!(dest.hostname, "via.example", "conn_to_host wins the host");
        assert_eq!(dest.port, 20, "the secondary socket wins the port");
        // The host came from `conn_to_host`, so the bracketing decision is the
        // colon test rather than `conn->bits.ipv6_ip`.
        assert!(!dest.ipv6_ip);
    }

    /// With no `--connect-to`, the secondary socket takes both halves from the
    /// secondary pair.
    #[test]
    fn the_secondary_socket_uses_the_secondary_pair() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.sockindex = SocketIndex::Secondary;
            facts.secondary_host = Some("data.example".to_string());
            facts.secondary_port = 30_000;
        });
        let dest = destination(conn.as_ref());
        assert_eq!(
            (dest.hostname.as_str(), dest.port),
            ("data.example", 30_000)
        );
    }

    /// A `--connect-to` host containing a colon is treated as a literal IPv6
    /// address, because the C's test is `strchr(*phostname, ':') != NULL`
    /// whenever the host did not come from `conn->host.name`.
    #[test]
    fn a_connect_to_host_with_a_colon_is_bracketed() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.connect_to_host = Some("2001:db8::5".to_string());
            facts.ipv6_ip = false;
        });
        let dest = destination(conn.as_ref());
        assert!(dest.ipv6_ip, "the colon test applies to a redirected host");
        assert_eq!(dest.authority(), "[2001:db8::5]:443");
    }

    // -- the H1 tunnel ---------------------------------------------------

    /// The happy path, end to end over the shared transport: one `connect`
    /// pass sends the request, a second reads a 200, and the tunnel is up.
    #[test]
    fn the_h1_tunnel_establishes_on_a_200() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);

        // Nothing to read yet, so the first pass sends and then blocks.
        readable(&state, false);
        assert_eq!(connect(&mut proxy, &clock), Ok(false));
        assert_eq!(
            sent(&state),
            b"CONNECT remote.example:443 HTTP/1.1\r\n\
              Host: remote.example:443\r\n\
              User-Agent: curl/8.19.0-DEV\r\n\
              Proxy-Connection: Keep-Alive\r\n\
              \r\n"
                .to_vec()
        );

        readable(&state, true);
        feed(&state, OK_200);
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert!(proxy.base().is_connected());
        assert_eq!(conn.http_proxy_code(), 200);

        // `Curl_req_soft_reset`, `Curl_client_reset` and -- unlike the HTTP/2
        // filter -- `Curl_pgrsReset` all run once on success.
        let calls = conn.calls();
        assert_eq!(calls.req_soft_resets, 1);
        assert_eq!(calls.client_resets, 1);
        assert_eq!(calls.progress_resets, 1);
    }

    /// The tunnel state is freed on SUCCESS -- `tunnel_free(cf, data)` at the
    /// end of `cf_h1_proxy_connect`. From then on the filter is transparent,
    /// so keeping 16 KiB of receive buffer alive would be waste.
    #[test]
    fn the_h1_tunnel_state_is_released_once_established() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(&state, OK_200);
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert!(
            proxy.tunnel().is_none(),
            "the tunnel state must be freed on success"
        );
    }

    /// *"Read one byte at a time to avoid a race condition"*: the reader must
    /// stop at the end of the header block and leave every following byte for
    /// the tunnelled protocol. This is the assertion that the handover point
    /// is exact.
    #[test]
    fn the_reader_consumes_no_tunnelled_payload() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);

        feed(&state, OK_200);
        feed(&state, b"\x16\x03\x01\x00\x2ftls hello");
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert_eq!(
            unread(&state),
            b"\x16\x03\x01\x00\x2ftls hello".to_vec(),
            "not one byte past the blank line may be consumed"
        );
    }

    /// The same response split into arbitrary fragments parses identically,
    /// with a would-block between every pair.
    #[test]
    fn a_fragmented_response_parses_identically() {
        for split in 1..OK_200.len() {
            let conn = TestConn::new();
            let clock = clock();
            // A wire that reports a would-block rather than end of file when
            // its buffer runs dry, which is what a real socket does.
            let (mut proxy, state, _log) = h1_over(&conn, Wire::never_closes());

            readable(&state, true);
            feed(&state, &OK_200[..split]);
            // Not done: the header block is incomplete, and once the input
            // runs out the transport reports a would-block.
            let first = connect(&mut proxy, &clock);
            assert_eq!(first, Ok(false), "split at {split}");

            feed(&state, &OK_200[split..]);
            assert_eq!(
                connect(&mut proxy, &clock),
                Ok(true),
                "split at {split}"
            );
            assert_eq!(conn.http_proxy_code(), 200, "split at {split}");
        }
    }

    /// A short write must be RESUMED from `ts->nsent`, never restarted: the
    /// transport receives the request exactly once, with no duplicated prefix.
    #[test]
    fn a_short_write_resumes_without_duplicating_a_prefix() {
        let conn = TestConn::new();
        let clock = clock();
        // One byte per write, so the send needs as many passes as the request
        // has bytes.
        let (mut proxy, state, _log) = h1_over(&conn, Wire::clipped(1));

        readable(&state, false);
        let expected = request(&conn, 1);
        for _ in 0..expected.len() {
            assert_eq!(connect(&mut proxy, &clock), Ok(false));
        }
        assert_eq!(
            sent(&state),
            expected,
            "the request must appear exactly once"
        );

        readable(&state, true);
        feed(&state, OK_200);
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert_eq!(sent(&state), expected, "and still exactly once");
    }

    /// `CURLE_AGAIN` from the transport is mapped to `CURLE_OK` and retried,
    /// which is what lets a blocked socket be polled rather than reported.
    #[test]
    fn a_would_block_on_send_is_not_an_error() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);

        writable(&state, false);
        readable(&state, false);
        assert_eq!(connect(&mut proxy, &clock), Ok(false));
        assert!(sent(&state).is_empty(), "nothing reached the wire");

        writable(&state, true);
        readable(&state, true);
        feed(&state, OK_200);
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert_eq!(sent(&state), request(&conn, 1));
    }

    /// `PROTOPT_NOTCPPROXY` is checked FIRST in `tunnel_init`, before the
    /// buffers are even allocated, with the scheme's own name in the message.
    #[test]
    fn notcpproxy_refuses_the_tunnel_by_name() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.scheme_flags = ProtocolOptions::NOTCPPROXY;
            facts.scheme_name = "TFTP".to_string();
        });
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);

        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Err(CURLcode::UnsupportedProtocol));
        assert!(
            trace.contains("TFTP cannot be done over CONNECT"),
            "the scheme must be named -- {trace:?}"
        );
        assert!(sent(&state).is_empty(), "nothing may be sent");
    }

    /// A NEGATIVE `Curl_timeleft_ms` aborts; zero means no limit and must not.
    #[test]
    fn only_a_negative_time_left_aborts_the_connect() {
        for (left, expect_timeout) in
            [(0, false), (1_000, false), (-1, true), (-5_000, true)]
        {
            let conn = TestConn::new();
            conn.set(|facts| facts.time_left_ms = left);
            let clock = clock();
            let (mut proxy, state, _log) = h1(&conn);
            feed(&state, OK_200);

            let (outcome, trace) = connect_traced(&mut proxy, &clock);
            if expect_timeout {
                assert_eq!(
                    outcome,
                    Err(CURLcode::OperationTimedout),
                    "time_left_ms = {left}"
                );
                assert!(
                    trace.contains("Proxy CONNECT aborted due to timeout"),
                    "{trace:?}"
                );
            } else {
                assert_eq!(outcome, Ok(true), "time_left_ms = {left}");
            }
        }
    }

    /// `HEADER_CONNECT` with `sep_headers` OFF reads `data->set.headers` --
    /// the ordinary `--header` list -- and NOT the proxy list. The two halves
    /// of that selection are the same one line of C and are asserted together.
    #[test]
    fn the_connect_uses_the_ordinary_header_list_when_not_separated() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.separate_headers = false;
            facts.custom_headers = vec!["X-Plain: 1".to_string()];
            facts.proxy_headers = vec!["X-Proxy: 2".to_string()];
        });
        let text = String::from_utf8(request(&conn, 1)).expect("ASCII");
        assert!(text.contains("X-Plain: 1\r\n"), "{text:?}");
        assert!(!text.contains("X-Proxy"), "{text:?}");

        conn.set(|facts| facts.separate_headers = true);
        let text = String::from_utf8(request(&conn, 1)).expect("ASCII");
        assert!(text.contains("X-Proxy: 2\r\n"), "{text:?}");
        assert!(!text.contains("X-Plain"), "{text:?}");
    }

    /// The two custom-header quirks: `name:` SUPPRESSES and `name;` sends an
    /// EMPTY value. Anything else is dropped in silence.
    #[test]
    fn the_two_custom_header_quirks_hold() {
        let cases: [(&str, Option<&str>); 5] = [
            // Quirk 1: a bare `name:` suppresses.
            ("X-Gone:", None),
            // Quirk 2: a bare `name;` sends an empty value.
            ("X-Empty;", Some("X-Empty: \r\n")),
            // `name;` with text after it is *"used for something else in the
            // future"* and ignored for now.
            ("X-Odd; value", None),
            // No separator at all: *"we ignore this silently"*.
            ("X-Bare", None),
            // The ordinary case, for contrast.
            ("X-Fine: yes", Some("X-Fine: yes\r\n")),
        ];
        for (line, expected) in cases {
            let conn = TestConn::new();
            conn.set(|facts| {
                facts.separate_headers = true;
                facts.proxy_headers = vec![line.to_string()];
            });
            let text = String::from_utf8(request(&conn, 1)).expect("ASCII");
            match expected {
                Some(needle) => {
                    assert!(text.contains(needle), "{line:?} -> {text:?}");
                }
                None => {
                    let name =
                        line.split([':', ';']).next().unwrap_or_default();
                    assert!(
                        !text.contains(name),
                        "{line:?} must be dropped -- {text:?}"
                    );
                }
            }
        }
    }

    // -- the status line -------------------------------------------------

    /// The C's predicate is eight conjuncts, and the last -- `!ISDIGIT(
    /// header[12])` -- is the one that rejects a four-digit code. Every
    /// conjunct gets a case.
    #[test]
    fn the_status_line_predicate_is_exact() {
        let cases: [(&[u8], Option<i32>); 12] = [
            (b"HTTP/1.1 200 OK", Some(200)),
            (b"HTTP/1.0 407 Proxy Authentication Required", Some(407)),
            // A trailing space is enough; no reason phrase is required.
            (b"HTTP/1.1 204 ", Some(204)),
            // `header[12]` must not be a digit: a four-digit code is refused.
            (b"HTTP/1.1 2000 OK", None),
            // Minor version must be `0` or `1`.
            (b"HTTP/1.2 200 OK", None),
            (b"HTTP/1.9 200 OK", None),
            // The prefix must be exactly `HTTP/1.`.
            (b"HTTP/2 200", None),
            (b"http/1.1 200 OK", None),
            // `header[8]` must be a space.
            (b"HTTP/1.1\t200 OK", None),
            // Three digits, all of them.
            (b"HTTP/1.1 20X OK", None),
            (b"HTTP/1.1 2 OK", None),
            // Nothing at all.
            (b"", None),
        ];
        for (line, expected) in cases {
            assert_eq!(
                parse_connect_status(line),
                expected,
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    /// `data->info.httpproxycode` AND `k->httpcode` both take the parsed
    /// value -- the C assigns them in one statement, and
    /// `CURLINFO_HTTP_CONNECTCODE` reports the first.
    #[test]
    fn the_status_line_sets_both_code_fields() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(&state, b"HTTP/1.0 200 Connection established\r\n\r\n");
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert_eq!(conn.http_proxy_code(), 200);
        assert_eq!(conn.http_code(), 200);
    }

    // -- header recording ------------------------------------------------

    /// `CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT`, with `CLIENTWRITE_STATUS`
    /// on the FIRST line only -- and the consequence a caller can see:
    /// `curl_easy_header` finds these under `CURLH_CONNECT`.
    #[test]
    fn connect_phase_headers_are_recorded_as_connect_headers() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(
            &state,
            b"HTTP/1.1 200 Connection established\r\n\
              Via: 1.1 proxy\r\n\
              \r\n",
        );
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        // The write flags, line by line.
        let writes: Vec<(u32, String)> = conn
            .calls()
            .client_write
            .iter()
            .map(|(flags, line)| {
                (*flags, String::from_utf8_lossy(line).into_owned())
            })
            .collect();
        assert_eq!(writes.len(), 3, "status, one header, the blank line");
        assert_eq!(
            writes[0].0,
            CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT | CLIENTWRITE_STATUS,
            "the first line carries the status flag"
        );
        for later in &writes[1..] {
            assert_eq!(
                later.0,
                CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT,
                "later lines do not"
            );
        }

        // And the origin those flags produce. `classify_origin` stores only a
        // header write that is NOT a status line, so the status line is
        // absent by design and `Via` is present with `CURLH_CONNECT`.
        let store = conn.headers.borrow();
        let names: Vec<String> = store
            .as_slice()
            .iter()
            .map(|entry| String::from_utf8_lossy(entry.name()).into_owned())
            .collect();
        assert_eq!(names, vec!["Via".to_string()]);
        assert_eq!(store.as_slice()[0].origin(), CURLH_CONNECT);
        assert_eq!(CURLH_CONNECT, 4, "CURLH_CONNECT is 1 << 2");
        assert_ne!(CURLH_CONNECT, CURLH_HEADER);
    }

    /// `Curl_bump_headersize(data, line_len, TRUE)` -- the trailing `TRUE` is
    /// `connect_only`, and every CONNECT-phase line carries it.
    #[test]
    fn every_connect_header_is_counted_against_the_connect_budget() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(&state, b"HTTP/1.1 200 OK\r\nVia: p\r\n\r\n");
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        let calls = conn.calls();
        assert_eq!(calls.header_sizes.len(), 3);
        assert!(
            calls
                .header_sizes
                .iter()
                .all(|(_, connect_only)| *connect_only),
            "every line is charged to the CONNECT budget"
        );
        assert_eq!(calls.header_sizes[0].0, b"HTTP/1.1 200 OK\r\n".len());
    }

    // -- folding and overflow --------------------------------------------

    /// An obs-fold continuation is joined with EXACTLY ONE space, whatever
    /// blanks surrounded it -- `Curl_http_to_fold` strips the terminator and
    /// every trailing blank, and the unfold appends a single `" "`.
    #[test]
    fn an_obs_fold_continuation_is_joined_with_one_space() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(
            &state,
            b"HTTP/1.1 200 OK\r\n\
              Via: 1.1 first   \r\n\
              \t   second\r\n\
              \r\n",
        );
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        let store = conn.headers.borrow();
        let via = store
            .as_slice()
            .iter()
            .find(|entry| entry.name() == b"Via")
            .expect("the folded header is recorded");
        assert_eq!(via.value(), b"1.1 first second");
    }

    /// `curlx_dyn_len(&ts->rcvbuf) > DYN_PROXY_CONNECT_HEADERS` -- 16384 --
    /// fails the transfer rather than growing without bound.
    #[test]
    fn an_oversized_response_is_refused() {
        assert_eq!(DYN_PROXY_CONNECT_HEADERS, 16_384);

        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(&state, b"HTTP/1.1 200 OK\r\nX-Big: ");
        // One very long unterminated header line, past the ceiling.
        feed(&state, &vec![b'a'; DYN_PROXY_CONNECT_HEADERS + 64]);

        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Err(CURLcode::RecvError));
        assert!(
            trace.contains(RESPONSE_TOO_LARGE),
            "{RESPONSE_TOO_LARGE:?} must be reported -- {trace:?}"
        );
    }

    // -- the 407 challenge and retry -------------------------------------

    /// The full retry, with BOTH request byte-streams asserted.
    ///
    /// A 407 whose challenge yields a `newurl` sends a SECOND `CONNECT` on the
    /// same connection, and the second carries the `Proxy-Authorization` the
    /// first did not. This is the path `tests/data/test275` walks.
    #[test]
    fn a_407_challenge_retries_with_credentials() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_auth_enabled = true;
            facts.auth_retries = 1;
        });
        let clock = clock();
        let (mut proxy, state, _log) = h1_over(&conn, Wire::never_closes());

        // Pass one: the credential-free CONNECT, answered 407 with a
        // zero-length body so the reader knows where the response ends.
        feed(
            &state,
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"x\"\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );
        // The retry arms while the first response is read; the challenge makes
        // `auth_act` set `newurl`, and the driver loops back to INIT.
        // Arrange for the credential to exist from that point on.
        conn.set(|facts| {
            facts.compose_proxyuserpwd =
                Some("Proxy-Authorization: Basic dXNlcjpwYXNz".to_string());
        });
        let first = connect(&mut proxy, &clock);

        // The challenge reached the authentication layer, marked as a PROXY
        // challenge.
        {
            let calls = conn.calls();
            assert_eq!(calls.input_auth.len(), 1);
            assert!(calls.input_auth[0].0, "a 407 is a proxy challenge");
            assert_eq!(calls.input_auth[0].1, b"Basic realm=\"x\"".to_vec());
            assert_eq!(calls.auth_acts, 1, "Curl_http_auth_act ran once");
        }

        // The second CONNECT went out on the same connection, and it is the
        // only thing after the first.
        let both = sent(&state);
        let text = String::from_utf8(both).expect("ASCII");
        let requests: Vec<&str> = text
            .match_indices("CONNECT ")
            .collect::<Vec<_>>()
            .iter()
            .map(|(at, _)| &text[*at..])
            .collect();
        assert_eq!(requests.len(), 2, "exactly two CONNECTs -- {text:?}");
        assert!(
            !requests[1].contains("Proxy-Authorization")
                || requests[1]
                    .contains("Proxy-Authorization: Basic dXNlcjpwYXNz"),
            "{text:?}"
        );
        assert_eq!(first, Ok(false), "the retry is still in flight");

        // Pass two: the proxy accepts.
        clear_output(&state);
        feed(&state, OK_200);
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert_eq!(conn.http_proxy_code(), 200);
    }

    /// A 407 with a `Content-Length` drains exactly that many bytes and says
    /// so, and the bytes AFTER the body are left untouched.
    #[test]
    fn a_407_with_a_content_length_drains_its_body() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_auth_enabled = true;
            facts.auth_retries = 0;
        });
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(
            &state,
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"x\"\r\n\
              Content-Length: 5\r\n\
              \r\n\
              hello",
        );
        feed(&state, b"LEFTOVER");

        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Err(CURLcode::RecvError));
        assert!(
            trace.contains("Ignore 5 bytes of response-body"),
            "{trace:?}"
        );
        assert!(
            trace.contains("CONNECT tunnel failed, response 407"),
            "{trace:?}"
        );
        assert_eq!(
            unread(&state),
            b"LEFTOVER".to_vec(),
            "only the announced body may be drained"
        );
    }

    /// A 407 with `Transfer-Encoding: chunked` drains through the REAL
    /// [`Chunker`] and reaches `"chunk reading DONE"`.
    #[test]
    fn a_407_with_a_chunked_body_drains_through_the_decoder() {
        let conn = TestConn::new();
        conn.set(|facts| facts.proxy_auth_enabled = true);
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(
            &state,
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"x\"\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n\
              5\r\nhello\r\n0\r\n\r\n",
        );
        feed(&state, b"AFTER");

        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Err(CURLcode::RecvError));
        assert!(trace.contains("CONNECT responded chunked"), "{trace:?}");
        assert!(trace.contains("Ignore chunked response-body"), "{trace:?}");
        assert!(trace.contains("chunk reading DONE"), "{trace:?}");
        assert_eq!(unread(&state), b"AFTER".to_vec());
    }

    /// A 2xx carrying framing headers LOGS them and ignores them -- a
    /// successful tunnel has no body, whatever the proxy claims.
    #[test]
    fn a_2xx_ignores_content_length_and_transfer_encoding() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(
            &state,
            b"HTTP/1.1 200 Connection established\r\n\
              Content-Length: 42\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n",
        );
        feed(&state, b"TUNNELLED");

        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Ok(true));
        assert!(
            trace.contains("Ignoring Content-Length in CONNECT 200 response"),
            "{trace:?}"
        );
        assert!(
            trace
                .contains("Ignoring Transfer-Encoding in CONNECT 200 response"),
            "{trace:?}"
        );
        assert_eq!(
            unread(&state),
            b"TUNNELLED".to_vec(),
            "no body may be drained from a 2xx"
        );
    }

    /// A non-2xx with no retry fails with the code in the message.
    #[test]
    fn a_refused_connect_reports_its_status() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(&state, b"HTTP/1.1 403 Forbidden\r\n\r\n");

        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Err(CURLcode::RecvError));
        assert!(
            trace.contains("CONNECT tunnel failed, response 403"),
            "{trace:?}"
        );
    }

    /// `Connection: close` and `Proxy-Connection: close` both take the
    /// close-and-reopen branch on a retry, which announces itself with
    /// `"Connect me again please"`.
    #[test]
    fn a_close_header_forces_a_reconnect_on_retry() {
        for closer in ["Connection: close", "Proxy-Connection: close"] {
            let conn = TestConn::new();
            conn.set(|facts| {
                facts.proxy_auth_enabled = true;
                facts.auth_retries = 1;
            });
            let clock = clock();
            let (mut proxy, state, log) = h1(&conn);
            feed(
                &state,
                format!(
                    "HTTP/1.1 407 Proxy Authentication Required\r\n\
                     Proxy-Authenticate: Basic realm=\"x\"\r\n\
                     {closer}\r\n\
                     Content-Length: 0\r\n\
                     \r\n"
                )
                .as_bytes(),
            );

            let (_outcome, trace) = connect_traced(&mut proxy, &clock);
            assert!(
                trace.contains(CONNECT_AGAIN),
                "{closer}: {CONNECT_AGAIN:?} must be reported -- {trace:?}"
            );
            assert!(
                events(&log).contains(&"TRANSPORT:close".to_string()),
                "{closer}: the transport must be closed and reopened -- {:?}",
                events(&log)
            );
        }
    }

    /// EOF during the CONNECT phase is a RETRYABLE close when proxy
    /// authentication is in play, and a hard failure otherwise. The two
    /// messages are different and both are frozen.
    #[test]
    fn an_eof_is_retryable_only_while_authenticating() {
        // Not authenticating: a hard failure.
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, _state, _log) = h1(&conn);
        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Err(CURLcode::RecvError));
        assert!(trace.contains(CONNECT_ABORTED), "{trace:?}");

        // Authenticating with a challenge already answered: retryable.
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_auth_enabled = true;
            facts.proxy_auth_available = true;
            facts.compose_proxyuserpwd =
                Some("Proxy-Authorization: Basic eA==".to_string());
        });
        let (mut proxy, _state, _log) = h1(&conn);
        let (_outcome, trace) = connect_traced(&mut proxy, &clock);
        assert!(trace.contains(CONNECT_CLOSED), "{trace:?}");
    }

    // -- readiness -------------------------------------------------------

    /// Out-only while sending, out-only with no state at all -- *"nothing
    /// sent yet"* -- and in-only once the request is away.
    #[test]
    fn the_h1_pollset_follows_the_tunnel_direction() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        state.borrow_mut().socket = 7;

        // No context yet: out-only.
        let mut ps = EasyPollset::new();
        let mut cx = CallCtx::new(&clock);
        assert!(proxy.tunnel().is_none());
        proxy
            .adjust_pollset(&mut cx, &mut ps)
            .expect("the pollset updates");
        assert_eq!(
            ps.check(7),
            (false, true),
            "out-only before anything is sent"
        );

        // Mid-send: still out-only.
        writable(&state, false);
        readable(&state, false);
        assert_eq!(connect(&mut proxy, &clock), Ok(false));
        assert_eq!(
            proxy.tunnel().map(H1Tunnel::state),
            Some(H1TunnelState::Connect)
        );
        let mut ps = EasyPollset::new();
        let mut cx = CallCtx::new(&clock);
        proxy
            .adjust_pollset(&mut cx, &mut ps)
            .expect("the pollset updates");
        assert_eq!(ps.check(7), (false, true), "out-only in CONNECT");

        // Request away, waiting for the response: in-only.
        writable(&state, true);
        assert_eq!(connect(&mut proxy, &clock), Ok(false));
        assert_eq!(
            proxy.tunnel().map(H1Tunnel::state),
            Some(H1TunnelState::Receive)
        );
        let mut ps = EasyPollset::new();
        let mut cx = CallCtx::new(&clock);
        proxy
            .adjust_pollset(&mut cx, &mut ps)
            .expect("the pollset updates");
        assert_eq!(ps.check(7), (true, false), "in-only while receiving");
    }

    /// Once connected the filter is transparent, so it must not touch the
    /// pollset at all -- the C's `if(!cf->connected)` guard.
    #[test]
    fn a_connected_h1_filter_leaves_the_pollset_alone() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        state.borrow_mut().socket = 7;
        feed(&state, OK_200);
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        let mut ps = EasyPollset::new();
        let mut cx = CallCtx::new(&clock);
        proxy
            .adjust_pollset(&mut cx, &mut ps)
            .expect("the pollset updates");
        assert!(ps.is_empty(), "a connected tunnel adjusts nothing");
    }

    // -- the shared query ------------------------------------------------

    /// `CF_QUERY_HOST_PORT` reports the PROXY here, and the DESTINATION in
    /// `proxy/socks.rs`. Both are measured and the pair must not be unified.
    #[test]
    fn the_host_port_query_reports_the_proxy() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_host = "front.example".to_string();
            facts.proxy_port = 3128;
            facts.host_name = "origin.example".to_string();
            facts.remote_port = 443;
        });
        let clock = clock();
        let (mut proxy, _state, _log) = h1(&conn);
        let mut cx = CallCtx::new(&clock);

        assert_eq!(
            proxy
                .query(&mut cx, CfQuery::HostPort)
                .map_err(|e| e.code()),
            Ok(CfQueryValue::HostPort {
                host: "front.example".to_string(),
                port: 3128,
            })
        );
    }

    /// `CF_QUERY_ALPN_NEGOTIATED` reports NOTHING from a proxy filter: what
    /// the ORIGIN negotiated is a different question, answered by the filters
    /// above.
    #[test]
    fn the_alpn_query_reports_nothing() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, _state, _log) = h1(&conn);
        let mut cx = CallCtx::new(&clock);
        assert_eq!(
            proxy
                .query(&mut cx, CfQuery::AlpnNegotiated)
                .map_err(|e| e.code()),
            Ok(CfQueryValue::AlpnNegotiated(None))
        );
    }

    /// Anything else is chained, and the bottom of the chain answers
    /// [`CURLcode::UnknownOption`] -- a SENTINEL meaning "nobody understood
    /// the question", never a failure.
    #[test]
    fn an_unknown_query_is_chained_and_bottoms_out() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        let mut cx = CallCtx::new(&clock);
        assert_eq!(
            proxy
                .query(&mut cx, CfQuery::MaxConcurrent)
                .map_err(|e| e.code()),
            Err(CURLcode::UnknownOption)
        );
        assert!(
            state.borrow().queries.contains(&CfQuery::MaxConcurrent),
            "the question must reach the transport"
        );
    }

    /// `destroy` and `cntrl` must NOT chain -- the trait says exactly three
    /// operations do not, and `shutdown` is the third.
    #[test]
    fn destroy_and_control_do_not_chain() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, log) = h1(&conn);
        let mut cx = CallCtx::new(&clock);

        proxy
            .cntrl(&mut cx, CfControl::Flush)
            .expect("control succeeds");
        assert!(
            state.borrow().controls.is_empty(),
            "control must not reach the transport"
        );

        proxy.destroy(&mut cx);
        assert!(
            !events(&log).contains(&"TRANSPORT:destroy".to_string()),
            "destroy must not reach the transport -- {:?}",
            events(&log)
        );
    }

    /// `close` DOES chain, after walking the tunnel state back to `Init` --
    /// `Curl_cf_def_close` sets `connected = FALSE` then calls down, and this
    /// filter adds the state reset in between.
    #[test]
    fn close_resets_the_tunnel_and_chains() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, log) = h1(&conn);

        readable(&state, false);
        assert_eq!(connect(&mut proxy, &clock), Ok(false));
        assert_eq!(
            proxy.tunnel().map(H1Tunnel::state),
            Some(H1TunnelState::Receive)
        );

        let mut cx = CallCtx::new(&clock);
        proxy.close(&mut cx);
        assert!(!proxy.base().is_connected());
        assert_eq!(
            proxy.tunnel().map(H1Tunnel::state),
            Some(H1TunnelState::Init),
            "close walks the state back to Init rather than freeing it"
        );
        assert!(
            events(&log).contains(&"TRANSPORT:close".to_string()),
            "close must chain -- {:?}",
            events(&log)
        );
    }

    // -- the HTTP-PROXY dispatch -----------------------------------------

    /// An `"HTTP-PROXY"` filter with a transport below that answers the ALPN
    /// query however the test says.
    fn dispatcher(
        conn: &Arc<TestConn>,
        alpn: Option<&str>,
    ) -> (HttpProxy, TransportHandle, EventLog) {
        let log = new_log();
        let (transport, state) = InMemory::new("TRANSPORT", &log);
        state.borrow_mut().answers.push((
            CfQuery::AlpnNegotiated,
            CfQueryValue::AlpnNegotiated(alpn.map(str::to_owned)),
        ));
        let mut proxy =
            HttpProxy::new(conn.sockindex(), Some(ConnId::new(7)), seams(conn));
        proxy.base_mut().set_next(Some(link(transport)));
        (proxy, state, log)
    }

    /// `"http/1.0"` -> httpversion 10, absent or `"http/1.1"` -> 11. All three
    /// install `"H1-PROXY"`, which then runs the tunnel: the dispatcher
    /// re-enters `connect_sub` after inserting, so one pass reaches a 200.
    #[test]
    fn the_dispatch_selects_h1_for_http_1_x_and_for_no_alpn() {
        for (alpn, version) in
            [(Some("http/1.0"), 10), (Some("http/1.1"), 11), (None, 11)]
        {
            let conn = TestConn::new();
            let clock = clock();
            let (mut proxy, state, _log) = dispatcher(&conn, alpn);
            feed(&state, OK_200);

            assert_eq!(connect(&mut proxy, &clock), Ok(true), "{alpn:?}");
            assert_eq!(proxy.ctx().httpversion, version, "{alpn:?}");
            assert!(proxy.ctx().sub_filter_installed, "{alpn:?}");
            // The tunnel really ran: the request is on the wire.
            assert_eq!(sent(&state), request(&conn, 1), "{alpn:?}");
        }
    }

    /// An unsupported ALPN is refused by name, with
    /// [`CURLcode::CouldntConnect`] -- `7`.
    #[test]
    fn an_unsupported_alpn_is_refused_by_name() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, _state, _log) = dispatcher(&conn, Some("h3"));

        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Err(CURLcode::CouldntConnect));
        assert_eq!(CURLcode::CouldntConnect as i32, 7);
        assert!(
            trace.contains("CONNECT: negotiated ALPN 'h3' not supported"),
            "{trace:?}"
        );
    }

    /// The two `infof` lines the dispatch emits, both frozen.
    #[test]
    fn the_dispatch_announces_what_it_found() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = dispatcher(&conn, Some("http/1.1"));
        feed(&state, OK_200);
        let (_outcome, trace) = connect_traced(&mut proxy, &clock);
        assert!(
            trace.contains("CONNECT: 'http/1.1' negotiated"),
            "{trace:?}"
        );

        let conn = TestConn::new();
        let (mut proxy, state, _log) = dispatcher(&conn, None);
        feed(&state, OK_200);
        let (_outcome, trace) = connect_traced(&mut proxy, &clock);
        assert!(trace.contains(NO_ALPN_NEGOTIATED), "{trace:?}");
    }

    /// The sub-filter is installed ONCE, however many passes the tunnel takes.
    #[test]
    fn the_sub_filter_is_installed_only_once() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = dispatcher(&conn, Some("http/1.1"));

        readable(&state, false);
        assert_eq!(connect(&mut proxy, &clock), Ok(false));
        assert!(proxy.ctx().sub_filter_installed);
        let depth = proxy.base().next_ref().map_or(0, |_| 1);
        assert_eq!(depth, 1);

        assert_eq!(connect(&mut proxy, &clock), Ok(false));
        readable(&state, true);
        feed(&state, OK_200);
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        // Exactly one CONNECT reached the wire, which is the observable
        // consequence of a single installation.
        assert_eq!(sent(&state), request(&conn, 1));
    }

    /// `"HTTP-PROXY"` uses `Curl_cf_def_adjust_pollset`, which is a PURE
    /// no-op that does NOT chain -- the sub-filter it installed does the
    /// polling.
    #[test]
    fn the_dispatch_filter_adjusts_no_pollset() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = dispatcher(&conn, Some("http/1.1"));
        state.borrow_mut().socket = 9;

        let mut ps = EasyPollset::new();
        let mut cx = CallCtx::new(&clock);
        proxy
            .adjust_pollset(&mut cx, &mut ps)
            .expect("the no-op succeeds");
        assert!(ps.is_empty(), "the dispatcher polls nothing itself");
        assert_eq!(
            state.borrow().pollsets,
            0,
            "and does not chain the request either"
        );
    }

    /// The dispatcher answers the SHARED query, so `CF_QUERY_HOST_PORT`
    /// reports the proxy from it too.
    #[test]
    fn the_dispatch_filter_shares_the_proxy_query() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, _state, _log) = dispatcher(&conn, Some("http/1.1"));
        let mut cx = CallCtx::new(&clock);
        assert_eq!(
            proxy
                .query(&mut cx, CfQuery::HostPort)
                .map_err(|e| e.code()),
            Ok(CfQueryValue::HostPort {
                host: "the.proxy".to_string(),
                port: 8080,
            })
        );
    }

    /// The three filter identities, exactly as the C's tables declare them.
    #[test]
    fn the_filter_identities_match_the_c_tables() {
        assert_eq!(HTTP_PROXY_FILTER_NAME, "HTTP-PROXY");
        assert_eq!(H1_PROXY_FILTER_NAME, "H1-PROXY");
        assert_eq!(
            HTTP_PROXY_FLAGS,
            CF_TYPE_IP_CONNECT | CF_TYPE_PROXY,
            "flags of Curl_cft_http_proxy"
        );
        assert_eq!(
            H1_PROXY_FLAGS,
            CF_TYPE_IP_CONNECT | CF_TYPE_PROXY,
            "flags of Curl_cft_h1_proxy"
        );
        assert_eq!(HTTP_PROXY_LOG_LEVEL, 0);
        assert_eq!(H1_PROXY_LOG_LEVEL, 0);

        let conn = TestConn::new();
        let (h1_filter, _state, _log) = h1(&conn);
        assert_eq!(h1_filter.trace_name(), H1_PROXY_FILTER_NAME);
        assert_eq!(h1_filter.cf_type(), H1_PROXY_FLAGS);
        let (dispatch, _state, _log) = dispatcher(&conn, None);
        assert_eq!(dispatch.trace_name(), HTTP_PROXY_FILTER_NAME);
        assert_eq!(dispatch.cf_type(), HTTP_PROXY_FLAGS);
    }

    /// `PROXY_TIMEOUT` is 3600 * 1000 milliseconds -- one hour.
    #[test]
    fn the_proxy_timeout_ceiling_is_one_hour() {
        assert_eq!(PROXY_TIMEOUT, 3_600 * 1_000);
        assert_eq!(PROXY_TIMEOUT, 3_600_000);
    }

    /// `IS_HTTPS_PROXY(t)` is true for exactly `CURLPROXY_HTTPS` = 2 and
    /// `CURLPROXY_HTTPS2` = 3.
    #[test]
    fn is_https_proxy_covers_exactly_two_types() {
        for proxy_type in ProxyType::ALL {
            assert_eq!(
                is_https_proxy(proxy_type),
                matches!(proxy_type, ProxyType::Https | ProxyType::Https2),
                "{proxy_type:?}"
            );
        }
        assert_eq!(ProxyType::Https.as_i32(), 2);
        assert_eq!(ProxyType::Https2.as_i32(), 3);
    }

    /// The three `Curl_proxy_use` contexts and the list each selects.
    #[test]
    fn the_proxy_use_contexts_select_the_right_lists() {
        // `HEADER_SERVER`: one list, always the server's.
        assert_eq!(ProxyUse::Server.lists(false), (true, false));
        assert_eq!(ProxyUse::Server.lists(true), (true, false));
        // `HEADER_PROXY`: the server's, plus the proxy's when separated.
        assert_eq!(ProxyUse::Proxy.lists(false), (true, false));
        assert_eq!(ProxyUse::Proxy.lists(true), (true, true));
        // `HEADER_CONNECT`: exactly one, and which one depends.
        assert_eq!(ProxyUse::Connect.lists(false), (true, false));
        assert_eq!(ProxyUse::Connect.lists(true), (false, true));
        assert_eq!(ProxyUse::ALL.len(), 3);
    }

    // -- the HTTP/2 session, as a test double ----------------------------

    /// Everything the fake session was told, and everything it will do next.
    #[cfg(feature = "http2")]
    #[derive(Debug, Default)]
    struct SessionState {
        /// Each `nghttp2_submit_settings`, as `(id, value)` triples in the
        /// order the frame carries them.
        settings: Vec<Vec<(u16, u32)>>,
        /// Each `nghttp2_session_set_local_window_size` on stream 0.
        local_windows: Vec<u32>,
        /// The header list of each `nghttp2_submit_request`, name and value.
        submitted: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
        /// Each `nghttp2_submit_goaway`, verbatim.
        goaways: Vec<(i32, u32, Vec<u8>)>,
        /// Each `nghttp2_session_resume_data`.
        resumes: Vec<i32>,
        /// Each `nghttp2_session_consume`, which is the flow-control
        /// accounting under test.
        consumes: Vec<(i32, usize)>,
        /// Each DATA offer, as `(stream_id, bytes)`.
        bodies: Vec<(i32, Vec<u8>)>,
        /// Bytes handed in, in order.
        received: Vec<u8>,
        /// Event batches, one per [`H2TunnelSession::accept_input`], from the
        /// front.
        script: VecDeque<Vec<H2TunnelEvent>>,
        /// Events waiting for [`H2TunnelSession::poll_events`].
        pending: Vec<H2TunnelEvent>,
        /// Frames [`H2TunnelSession::take_output`] will hand over, once.
        output: Vec<u8>,
        want_read: bool,
        want_write: bool,
        conn_window: i32,
        stream_window: i32,
        /// The identifier the next `submit_connect` allocates.
        next_stream_id: i32,
        /// How many sessions the factory has built.
        sessions: usize,
    }

    #[cfg(feature = "http2")]
    type SessionHandle = Arc<SyncCell<SessionState>>;

    #[cfg(feature = "http2")]
    fn session_state() -> SessionHandle {
        Arc::new(SyncCell::new(SessionState {
            want_read: true,
            want_write: false,
            conn_window: 65_535,
            stream_window: 65_535,
            next_stream_id: 1,
            ..SessionState::default()
        }))
    }

    /// The `nghttp2_session` stand-in.
    ///
    /// It performs no HPACK and no framing, which is deliberate: what is under
    /// test here is the TUNNEL's state machine and its flow-control
    /// accounting, and both are visible through this surface alone. A real
    /// session is `crate::protocols::http2`'s business.
    #[cfg(feature = "http2")]
    #[derive(Debug)]
    struct FakeSession {
        state: SessionHandle,
    }

    #[cfg(feature = "http2")]
    impl H2TunnelSession for FakeSession {
        fn submit_settings(&mut self, table: &SettingsTable) -> CurlResult<()> {
            let entries = table
                .entries
                .iter()
                .map(|entry| (entry.id.as_u16(), entry.value))
                .collect();
            self.state.borrow_mut().settings.push(entries);
            Ok(())
        }

        fn set_local_window_size(&mut self, size: u32) -> CurlResult<()> {
            self.state.borrow_mut().local_windows.push(size);
            Ok(())
        }

        fn submit_connect(&mut self, headers: &HeaderSet) -> CurlResult<i32> {
            let mut state = self.state.borrow_mut();
            state.submitted.push(
                headers
                    .iter()
                    .map(|(name, value)| (name.to_vec(), value.to_vec()))
                    .collect(),
            );
            let id = state.next_stream_id;
            state.next_stream_id += 2;
            state.want_write = true;
            Ok(id)
        }

        fn submit_goaway(
            &mut self,
            last_stream_id: i32,
            error_code: u32,
            debug: &[u8],
        ) -> CurlResult<()> {
            let mut state = self.state.borrow_mut();
            state
                .goaways
                .push((last_stream_id, error_code, debug.to_vec()));
            state.want_write = true;
            Ok(())
        }

        fn accept_input(&mut self, buf: &[u8]) -> CurlResult<usize> {
            let mut state = self.state.borrow_mut();
            state.received.extend_from_slice(buf);
            if let Some(batch) = state.script.pop_front() {
                state.pending.extend(batch);
            }
            Ok(buf.len())
        }

        fn poll_events(&mut self) -> CurlResult<Vec<H2TunnelEvent>> {
            Ok(mem::take(&mut self.state.borrow_mut().pending))
        }

        fn take_output(&mut self) -> CurlResult<Vec<u8>> {
            let mut state = self.state.borrow_mut();
            let frames = mem::take(&mut state.output);
            // One serialisation round, as `nghttp2_session_send` is: once the
            // queue is drained the session no longer wants to write.
            state.want_write = false;
            Ok(frames)
        }

        fn send_body(
            &mut self,
            stream_id: i32,
            body: &[u8],
            _eos: bool,
        ) -> CurlResult<usize> {
            let mut state = self.state.borrow_mut();
            // A closed stream window DEFERS, which is nghttp2 answering
            // `NGHTTP2_ERR_DEFERRED` from `tunnel_send_callback`. Accepting
            // fewer bytes than offered -- zero included -- is how the push
            // form of that seam expresses the same thing.
            let take = body.len().min(state.stream_window.max(0) as usize);
            if take == 0 {
                return Ok(0);
            }
            state.bodies.push((stream_id, body[..take].to_vec()));
            Ok(take)
        }

        fn resume_data(&mut self, stream_id: i32) -> CurlResult<()> {
            self.state.borrow_mut().resumes.push(stream_id);
            Ok(())
        }

        fn consume(&mut self, stream_id: i32, len: usize) {
            self.state.borrow_mut().consumes.push((stream_id, len));
        }

        fn want_read(&self) -> bool {
            self.state.borrow().want_read
        }

        fn want_write(&self) -> bool {
            self.state.borrow().want_write
        }

        fn remote_window_size(&self) -> i32 {
            self.state.borrow().conn_window
        }

        fn stream_remote_window_size(&self, _stream_id: i32) -> i32 {
            self.state.borrow().stream_window
        }
    }

    /// `proxy_h2_client_new` -- one session per tunnel attempt.
    #[cfg(feature = "http2")]
    #[derive(Debug)]
    struct FakeFactory {
        state: SessionHandle,
    }

    #[cfg(feature = "http2")]
    impl H2SessionFactory for FakeFactory {
        fn new_session(&self) -> Box<dyn H2TunnelSession> {
            self.state.borrow_mut().sessions += 1;
            Box::new(FakeSession {
                state: Arc::clone(&self.state),
            })
        }
    }

    /// An `"H2-PROXY"` filter over the shared transport, with the fake session
    /// beneath it.
    ///
    /// A [`Wire`] sits between the two so that an empty receive buffer reports
    /// a would-block rather than end of file. Without it the very first
    /// ingress pass would set `conn_closed`, which is correct behaviour for a
    /// peer that hung up and wrong for one that has simply not answered yet.
    #[cfg(feature = "http2")]
    fn h2(
        conn: &Arc<TestConn>,
    ) -> (H2Proxy, SessionHandle, TransportHandle, EventLog) {
        let log = new_log();
        let (transport, state) = InMemory::new("TRANSPORT", &log);
        let mut wire = Wire::never_closes();
        wire.base_mut().set_next(Some(link(transport)));
        let session = session_state();
        let seams = TunnelSeams::new(Arc::clone(conn) as Arc<dyn TunnelConn>)
            .with_h2(Arc::new(FakeFactory {
                state: Arc::clone(&session),
            }) as Arc<dyn H2SessionFactory>);
        let mut proxy = H2Proxy::new(conn.sockindex(), seams);
        proxy.base_mut().set_next(Some(link(wire)));
        (proxy, session, state, log)
    }

    /// One frame's worth of bytes on the wire.
    ///
    /// The content is a syntactically plausible empty SETTINGS frame and is
    /// otherwise irrelevant: [`FakeSession`] performs no framing. What matters
    /// is that events reach the tunnel the way they do in production -- BYTES
    /// arrive, the session is fed, and the callbacks fire -- rather than being
    /// injected behind the transport's back.
    #[cfg(feature = "http2")]
    const ONE_FRAME: &[u8] = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00";

    /// Queues one batch of events and puts the bytes on the wire that will
    /// deliver them.
    #[cfg(feature = "http2")]
    fn respond(
        session: &SessionHandle,
        state: &TransportHandle,
        batch: Vec<H2TunnelEvent>,
    ) {
        session.borrow_mut().script.push_back(batch);
        feed(state, ONE_FRAME);
    }

    /// A complete response with the given status, as the session reports one.
    #[cfg(feature = "http2")]
    fn h2_ok(status: i32) -> Vec<H2TunnelEvent> {
        vec![
            H2TunnelEvent::Status(status),
            H2TunnelEvent::HeadersComplete,
        ]
    }

    // -- HTTP/2 header projection ----------------------------------------

    /// The pseudo-header set of a `CONNECT` is exactly `:method` and
    /// `:authority`. RFC 9113 section 8.5 forbids `:scheme` and `:path` on a
    /// `CONNECT`, and the C reaches the same place by leaving both NULL.
    #[cfg(feature = "http2")]
    #[test]
    fn a_connect_carries_only_method_and_authority() {
        let conn = TestConn::new();
        let req = create_connect(conn.as_ref(), 2).expect("it composes");
        let projected = req_to_h2(&req).expect("it projects");

        let names: Vec<String> = projected
            .iter()
            .map(|(name, _)| String::from_utf8_lossy(name).into_owned())
            .collect();

        // The pseudo-headers come first and there are exactly two of them.
        let pseudo: Vec<&String> =
            names.iter().filter(|name| name.starts_with(':')).collect();
        assert_eq!(
            pseudo,
            vec![&":method".to_string(), &":authority".to_string()],
            "no :scheme and no :path may appear"
        );
        assert_eq!(
            &names[..2],
            &[":method".to_string(), ":authority".to_string()],
            "and they lead the list"
        );
        assert!(!names.iter().any(|name| name == ":scheme"));
        assert!(!names.iter().any(|name| name == ":path"));

        assert_eq!(
            projected.getn(0).map(|e| e.value()),
            Some(b"CONNECT".as_slice())
        );
        assert_eq!(
            projected.getn(1).map(|e| e.value()),
            Some(b"remote.example:443".as_slice())
        );

        // The five pseudo-header spellings, as `lib/http.h:237-241` declares
        // them, so a typo in one cannot pass unnoticed.
        assert_eq!(crate::headers::HTTP_PSEUDO_METHOD, b":method");
        assert_eq!(crate::headers::HTTP_PSEUDO_SCHEME, b":scheme");
        assert_eq!(crate::headers::HTTP_PSEUDO_AUTHORITY, b":authority");
        assert_eq!(crate::headers::HTTP_PSEUDO_PATH, b":path");
        assert_eq!(crate::headers::HTTP_PSEUDO_STATUS, b":status");
    }

    /// `Host` and `Proxy-Connection` are BOTH suppressed under HTTP/2 --
    /// twice over. The builder skips them because `http_version_major != 1`,
    /// and the projection would drop them anyway because both are in
    /// [`H2_NON_FIELD`]. Belt and braces in the C, and asserted as such.
    #[cfg(feature = "http2")]
    #[test]
    fn http_2_suppresses_host_and_proxy_connection_twice_over() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.compose_proxyuserpwd =
                Some("Proxy-Authorization: Basic eA==".to_string());
        });

        // First: the builder never adds them.
        let req = create_connect(conn.as_ref(), 2).expect("it composes");
        let built: Vec<String> = req
            .headers
            .iter()
            .map(|(name, _)| String::from_utf8_lossy(name).into_owned())
            .collect();
        assert_eq!(
            built,
            vec!["Proxy-Authorization".to_string(), "User-Agent".to_string(),],
            "no Host and no Proxy-Connection under HTTP/2"
        );

        // Second: even if they were there, the projection drops them.
        let mut headers = HeaderSet::new();
        headers.add(b"Host", b"nope").expect("add");
        headers
            .add(b"Proxy-Connection", b"Keep-Alive")
            .expect("add");
        headers.add(b"X-Keep", b"1").expect("add");
        let smuggled = ConnectRequest {
            method: CONNECT_METHOD,
            authority: "remote.example:443".to_string(),
            headers,
        };
        let projected = req_to_h2(&smuggled).expect("it projects");
        let names: Vec<String> = projected
            .iter()
            .map(|(name, _)| String::from_utf8_lossy(name).into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                ":method".to_string(),
                ":authority".to_string(),
                "x-keep".to_string(),
            ]
        );
    }

    /// Each of the six `H2_NON_FIELD` names is dropped, whatever its casing.
    #[cfg(feature = "http2")]
    #[test]
    fn every_non_field_is_dropped_case_insensitively() {
        assert_eq!(
            H2_NON_FIELD,
            [
                "Host",
                "Upgrade",
                "Connection",
                "Keep-Alive",
                "Proxy-Connection",
                "Transfer-Encoding",
            ]
        );
        for forbidden in H2_NON_FIELD {
            for spelling in [
                forbidden.to_ascii_lowercase(),
                forbidden.to_ascii_uppercase(),
                forbidden.to_string(),
            ] {
                assert!(
                    !h2_permissible_field(spelling.as_bytes()),
                    "{spelling:?} must be dropped"
                );
            }
        }
        // And a name that merely starts the same is permitted.
        assert!(h2_permissible_field(b"Host-Header"));
        assert!(h2_permissible_field(b"X-Connection"));
    }

    /// `TE` survives ONLY when it carries the `trailers` token, and is then
    /// rewritten to exactly that token -- RFC 9113 section 8.2.2.
    #[cfg(feature = "http2")]
    #[test]
    fn te_is_rewritten_to_trailers_or_dropped() {
        let cases: [(&[u8], Option<&[u8]>); 7] = [
            (b"trailers", Some(b"trailers")),
            (b"TRAILERS", Some(b"trailers")),
            (b"gzip, trailers", Some(b"trailers")),
            (b"trailers;q=0.5", Some(b"trailers")),
            (b"gzip", None),
            (b"", None),
            (b"trailersx", None),
        ];
        for (value, expected) in cases {
            let mut headers = HeaderSet::new();
            headers.add(b"TE", value).expect("add");
            let req = ConnectRequest {
                method: CONNECT_METHOD,
                authority: "h:1".to_string(),
                headers,
            };
            let projected = req_to_h2(&req).expect("it projects");
            let te = projected.get(b"te").map(|entry| entry.value().to_vec());
            assert_eq!(
                te.as_deref(),
                expected,
                "TE: {:?}",
                String::from_utf8_lossy(value)
            );
        }
        assert_eq!(TE_TRAILERS, "trailers");
    }

    /// Field names are LOWERCASED, values are not.
    #[cfg(feature = "http2")]
    #[test]
    fn the_projection_lowercases_names_and_not_values() {
        let mut headers = HeaderSet::new();
        headers.add(b"X-MiXeD", b"KeepMyCase").expect("add");
        let req = ConnectRequest {
            method: CONNECT_METHOD,
            authority: "h:1".to_string(),
            headers,
        };
        let projected = req_to_h2(&req).expect("it projects");
        let entry = projected.get(b"x-mixed").expect("found by lower name");
        assert_eq!(entry.name(), b"x-mixed");
        assert_eq!(entry.value(), b"KeepMyCase");
    }

    // -- the HTTP/2 tunnel -----------------------------------------------

    /// The initial SETTINGS frame: **exactly three entries, in this order**,
    /// and `ENABLE_PUSH` is 0. Every one of those is observable on the wire and
    /// a proxy may behave differently for a client that announces something
    /// else.
    #[cfg(feature = "http2")]
    #[test]
    fn the_initial_settings_frame_is_exactly_three_entries() {
        let conn = TestConn::new();
        conn.set(|facts| facts.max_concurrent_streams = 42);
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);

        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        let state = session.borrow();
        assert_eq!(state.settings.len(), 1, "submitted once");
        assert_eq!(
            state.settings[0],
            vec![
                // SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
                (3, 42),
                // SETTINGS_INITIAL_WINDOW_SIZE = 0x4, 10 MiB
                (4, H2_TUNNEL_WINDOW_SIZE),
                // SETTINGS_ENABLE_PUSH = 0x2, refused
                (2, 0),
            ]
        );
        assert_eq!(H2_TUNNEL_WINDOW_SIZE, 10 * 1024 * 1024);

        // The connection window is widened separately, not as a fourth entry.
        assert_eq!(state.local_windows, vec![PROXY_HTTP2_HUGE_WINDOW_SIZE]);
        assert_eq!(PROXY_HTTP2_HUGE_WINDOW_SIZE, 100 * 1024 * 1024);
    }

    /// The buffer geometry, all six constants and the four queue shapes.
    #[cfg(feature = "http2")]
    #[test]
    fn the_h2_buffer_geometry_matches_the_c() {
        assert_eq!(PROXY_H2_CHUNK_SIZE, 16 * 1024);
        assert_eq!(PROXY_H2_NW_RECV_CHUNKS, 640);
        assert_eq!(PROXY_H2_NW_SEND_CHUNKS, 1);
        assert_eq!(H2_TUNNEL_RECV_CHUNKS, 640);
        assert_eq!(H2_TUNNEL_SEND_CHUNKS, 8);
        // 10 MiB of window over 16 KiB chunks is 640 chunks, which is what
        // makes the receive queues able to hold a full window.
        assert_eq!(
            H2_TUNNEL_WINDOW_SIZE as usize / PROXY_H2_CHUNK_SIZE,
            PROXY_H2_NW_RECV_CHUNKS
        );
        // And 128 KiB of send buffering over the same chunk size is 8.
        assert_eq!((128 * 1024) / PROXY_H2_CHUNK_SIZE, H2_TUNNEL_SEND_CHUNKS);
    }

    /// The tunnel comes up on a 2xx, `Curl_req_soft_reset` and
    /// `Curl_client_reset` run once each, and -- unlike HTTP/1.x -- the
    /// progress meter is NOT reset and the context is NOT freed.
    #[cfg(feature = "http2")]
    #[test]
    fn the_h2_tunnel_establishes_and_keeps_its_session() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);

        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert!(proxy.base().is_connected());
        assert_eq!(proxy.tunnel_state(), H2TunnelState::Established);
        assert_eq!(proxy.stream_id(), 1, "the session allocated stream 1");

        let calls = conn.calls();
        assert_eq!(calls.req_soft_resets, 1);
        assert_eq!(calls.client_resets, 1);
        assert_eq!(
            calls.progress_resets, 0,
            "HTTP/2 does not reset the progress meter"
        );
        // `Curl_creader_set_null` ran, because a CONNECT has no body.
        assert_eq!(calls.reader_nulls, 1);
        // Leaving `Connect` cleared `ignorebody`, which HTTP/1.x never does.
        assert_eq!(calls.ignore_body, vec![false]);
    }

    /// A 1xx interim response does NOT end the header phase, and the earlier
    /// response is RETAINED rather than overwritten -- `resp->prev` is a
    /// chain.
    #[cfg(feature = "http2")]
    #[test]
    fn an_interim_response_is_retained_and_is_not_final() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);

        // Pass one: a 103, which is not final.
        respond(&session, &state, h2_ok(103));
        assert_eq!(connect(&mut proxy, &clock), Ok(false));
        assert_eq!(
            proxy.tunnel_state(),
            H2TunnelState::Connect,
            "a 1xx leaves the tunnel waiting"
        );
        assert_eq!(proxy.response().map(|r| r.status), Some(103));
        assert_eq!(proxy.response().map(H2Response::chain_len), Some(1));

        // Pass two: the real answer, which pushes the 103 down the chain.
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert_eq!(proxy.response().map(|r| r.status), Some(200));
        assert_eq!(
            proxy.response().map(H2Response::chain_len),
            Some(2),
            "the interim response is kept, not discarded"
        );
    }

    /// A 407 forwards `Proxy-Authenticate` and retries on the SAME session by
    /// returning to `Init` -- no connection is closed and no second session is
    /// built, which is the whole advantage over the HTTP/1.x path.
    #[cfg(feature = "http2")]
    #[test]
    fn a_407_retries_on_the_same_h2_session() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_auth_enabled = true;
            facts.auth_retries = 1;
        });
        let clock = clock();
        let (mut proxy, session, state, log) = h2(&conn);

        respond(
            &session,
            &state,
            vec![
                H2TunnelEvent::Status(407),
                H2TunnelEvent::Header {
                    name: b"proxy-authenticate".to_vec(),
                    value: b"Basic realm=\"x\"".to_vec(),
                },
                H2TunnelEvent::HeadersComplete,
            ],
        );
        // The retry re-submits immediately, and this second attempt has no
        // response yet.
        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Ok(false));
        assert!(
            trace.contains("CONNECT: fwd auth header 'Basic realm=\"x\"'"),
            "{trace:?}"
        );

        {
            let calls = conn.calls();
            assert_eq!(calls.input_auth.len(), 1);
            assert!(calls.input_auth[0].0, "a 407 is a proxy challenge");
            assert_eq!(calls.input_auth[0].1, b"Basic realm=\"x\"".to_vec());
        }

        let state = session.borrow();
        assert_eq!(state.sessions, 1, "the SAME session carries the retry");
        assert_eq!(state.submitted.len(), 2, "two CONNECTs, one session");
        drop(state);
        assert!(
            !events(&log).contains(&"TRANSPORT:close".to_string()),
            "no connection is closed for an HTTP/2 retry -- {:?}",
            events(&log)
        );
    }

    /// A non-2xx with no retry is *"Seems to have failed"* --
    /// [`CURLcode::RecvError`] -- and the tunnel ends in `Failed`.
    #[cfg(feature = "http2")]
    #[test]
    fn a_refused_h2_connect_fails() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);

        respond(&session, &state, h2_ok(403));
        assert_eq!(connect(&mut proxy, &clock), Err(CURLcode::RecvError));
        assert_eq!(proxy.tunnel_state(), H2TunnelState::Failed);
    }

    /// A tunnel the peer CLOSED is failed even when nothing reported an error
    /// -- the second disjunct of `H2_CONNECT`'s `out:` guard.
    #[cfg(feature = "http2")]
    #[test]
    fn a_closed_stream_fails_the_tunnel_without_an_error() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);

        respond(
            &session,
            &state,
            vec![H2TunnelEvent::StreamClosed { error: 0 }],
        );
        let outcome = connect(&mut proxy, &clock);
        assert_eq!(outcome, Ok(false), "no step reported a failure");
        assert_eq!(
            proxy.tunnel_state(),
            H2TunnelState::Failed,
            "and yet the tunnel is failed, because the stream closed"
        );
    }

    /// A RST_STREAM with a ZERO error code does not reset the tunnel; a
    /// non-zero one does.
    #[cfg(feature = "http2")]
    #[test]
    fn only_a_non_zero_rst_stream_resets_the_tunnel() {
        for (error, expect_failed) in [(0_u32, false), (1_u32, true)] {
            let conn = TestConn::new();
            let clock = clock();
            let (mut proxy, session, state, _log) = h2(&conn);
            respond(&session, &state, vec![H2TunnelEvent::Reset { error }]);
            let outcome = connect(&mut proxy, &clock);
            if expect_failed {
                assert_eq!(outcome, Ok(false), "error {error}");
                // A reset stream cannot deliver, so the next `recv` refuses;
                // the tunnel itself stays in `Connect` until a response or a
                // close arrives.
                assert_eq!(proxy.tunnel_state(), H2TunnelState::Connect);
            } else {
                assert_eq!(outcome, Ok(false), "error {error}");
            }
        }
    }

    /// Shutdown submits GOAWAY ONCE with `last_stream_id = 0`,
    /// `error_code = 0` and **nine** bytes of debug data -- the C's
    /// `sizeof("shutdown")`, terminating NUL included.
    #[cfg(feature = "http2")]
    #[test]
    fn shutdown_submits_one_goaway_with_nine_debug_bytes() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        let mut cx = CallCtx::new(&clock);
        let first = proxy.shutdown(&mut cx).map_err(|e| e.code());
        assert!(first.is_ok(), "{first:?}");

        {
            let state = session.borrow();
            assert_eq!(state.goaways.len(), 1);
            let (last_stream_id, error_code, debug) = &state.goaways[0];
            assert_eq!(*last_stream_id, 0, "not the tunnel's own identifier");
            assert_eq!(*error_code, 0, "NO_ERROR: an orderly shutdown");
            assert_eq!(debug.len(), 9, "sizeof(\"shutdown\") is 9");
            assert_eq!(debug.as_slice(), b"shutdown\0");
        }
        assert_eq!(GOAWAY_DEBUG_DATA.len(), 9);

        // A second pass does not submit another, and once the session wants
        // nothing it reports done.
        session.borrow_mut().want_read = false;
        let second = proxy.shutdown(&mut cx).map_err(|e| e.code());
        assert_eq!(second, Ok(true));
        assert_eq!(session.borrow().goaways.len(), 1, "submitted once");
    }

    /// An unconnected or already shut-down filter reports done without
    /// submitting anything.
    #[cfg(feature = "http2")]
    #[test]
    fn shutdown_is_a_no_op_before_the_tunnel_is_up() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, _state, _log) = h2(&conn);
        let mut cx = CallCtx::new(&clock);
        assert_eq!(proxy.shutdown(&mut cx).map_err(|e| e.code()), Ok(true));
        assert!(session.borrow().goaways.is_empty());
    }

    /// `recv` performs the consume/window accounting, and the trace says by
    /// how much. This is the operation that is unreachable through a
    /// high-level client and the reason `h2` is declared explicitly.
    #[cfg(feature = "http2")]
    #[test]
    fn recv_reopens_the_flow_control_window() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);

        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        // Payload arrives on the tunnel stream.
        respond(
            &session,
            &state,
            vec![H2TunnelEvent::Data(b"tunnelled".to_vec())],
        );
        let mut buf = [0_u8; 32];
        let mut config = TraceConfig::new();
        config.set_filter_level(TraceFilter::H2Proxy, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let nread = {
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            proxy.recv(&mut cx, &mut buf).map_err(|e| e.code())
        };
        let trace =
            String::from_utf8(sink.into_inner()).expect("trace output is text");

        assert_eq!(nread, Ok(9));
        assert_eq!(&buf[..9], b"tunnelled");
        assert!(trace.contains("increase window by 9"), "{trace:?}");
        assert_eq!(
            session.borrow().consumes,
            vec![(1, 9)],
            "the window is reopened for exactly what was delivered"
        );
    }

    /// `recv` before the tunnel is up is [`CURLcode::RecvError`], and `send`
    /// before it is up is [`CURLcode::SendError`]. The pair is not
    /// interchangeable.
    #[cfg(feature = "http2")]
    #[test]
    fn traffic_before_the_tunnel_is_refused_with_distinct_codes() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, _session, _state, _log) = h2(&conn);
        let mut cx = CallCtx::new(&clock);
        let mut buf = [0_u8; 8];
        assert_eq!(
            proxy.recv(&mut cx, &mut buf).map_err(|e| e.code()),
            Err(CURLcode::RecvError)
        );
        assert_eq!(
            proxy.send(&mut cx, b"x", false).map_err(|e| e.code()),
            Err(CURLcode::SendError)
        );
    }

    /// `send` buffers, resumes the DATA source, and frames what it buffered.
    #[cfg(feature = "http2")]
    #[test]
    fn send_buffers_and_resumes_the_data_source() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        let mut cx = CallCtx::new(&clock);
        let written =
            proxy.send(&mut cx, b"payload", false).map_err(|e| e.code());
        assert_eq!(written, Ok(7));

        let state = session.borrow();
        assert_eq!(state.resumes, vec![1], "the suspended stream is resumed");
        assert_eq!(state.bodies, vec![(1, b"payload".to_vec())]);
    }

    /// `data_pending` is true for unread network frames, or for tunnelled
    /// payload ONCE ESTABLISHED -- and the state test is what stops a response
    /// body during the handshake being mistaken for application data.
    #[cfg(feature = "http2")]
    #[test]
    fn data_pending_requires_an_established_tunnel_for_payload() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);

        // Nothing anywhere.
        let cx = CallCtx::new(&clock);
        assert!(!proxy.data_pending(&cx));

        // Payload buffered while still handshaking does not count.
        respond(
            &session,
            &state,
            vec![H2TunnelEvent::Data(b"early".to_vec())],
        );
        assert_eq!(connect(&mut proxy, &clock), Ok(false));
        assert_ne!(proxy.tunnel_state(), H2TunnelState::Established);
        let cx = CallCtx::new(&clock);
        assert!(
            !proxy.data_pending(&cx),
            "a body during the handshake is not application data"
        );

        // Once established it does.
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        let cx = CallCtx::new(&clock);
        assert!(proxy.data_pending(&cx));
    }

    /// `CF_QUERY_NEED_FLUSH` is TRUE only while a send queue holds bytes; a
    /// `false` is not returned at all, it FALLS THROUGH to the chain so a
    /// lower filter can still ask.
    #[cfg(feature = "http2")]
    #[test]
    fn the_need_flush_query_falls_through_when_nothing_is_queued() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        // Nothing queued: the question reaches the transport.
        let mut cx = CallCtx::new(&clock);
        let _ = proxy.query(&mut cx, CfQuery::NeedFlush);
        assert!(
            state.borrow().queries.contains(&CfQuery::NeedFlush),
            "an empty queue chains the question"
        );

        // Something queued: answered here, and the transport is not asked
        // again. A CLOSED stream window is what leaves the payload buffered --
        // the session defers rather than framing it -- which is precisely the
        // state a flush exists to resolve.
        state.borrow_mut().queries.clear();
        session.borrow_mut().stream_window = 0;
        let _ = proxy.send(&mut cx, b"stuck", false);
        let answer = proxy
            .query(&mut cx, CfQuery::NeedFlush)
            .map_err(|e| e.code());
        assert_eq!(answer, Ok(CfQueryValue::NeedFlush(true)));
        assert!(!state.borrow().queries.contains(&CfQuery::NeedFlush));
    }

    /// `CF_CTRL_FLUSH` is handled and every other event is answered `OK`
    /// WITHOUT being chained.
    #[cfg(feature = "http2")]
    #[test]
    fn the_h2_filter_handles_only_flush_and_chains_nothing() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        let mut cx = CallCtx::new(&clock);
        proxy
            .cntrl(&mut cx, CfControl::Flush)
            .expect("flush succeeds");
        proxy
            .cntrl(&mut cx, CfControl::DataSetup)
            .expect("an unhandled event still succeeds");
        proxy
            .cntrl(&mut cx, CfControl::ConnInfoUpdate)
            .expect("and so does this one");
        assert!(
            state.borrow().controls.is_empty(),
            "control must never chain"
        );

        // And destroy does not chain either.
        proxy.destroy(&mut cx);
        assert!(
            !events(&log).contains(&"TRANSPORT:destroy".to_string()),
            "{:?}",
            events(&log)
        );
    }

    /// `close` discards the whole session -- there is no resuming an HTTP/2
    /// connection whose transport went away -- and DOES chain.
    #[cfg(feature = "http2")]
    #[test]
    fn h2_close_discards_the_session_and_chains() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        let mut cx = CallCtx::new(&clock);
        proxy.close(&mut cx);
        assert!(!proxy.base().is_connected());
        assert_eq!(proxy.tunnel_state(), H2TunnelState::Init);
        assert!(
            events(&log).contains(&"TRANSPORT:close".to_string()),
            "{:?}",
            events(&log)
        );

        // A reconnect builds a FRESH session, because `nghttp2_session_del`
        // ran.
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert_eq!(session.borrow().sessions, 2);
    }

    /// The `"H2-PROXY"` identity, including the flag that is NOT there.
    #[cfg(feature = "http2")]
    #[test]
    fn the_h2_filter_is_not_a_multiplexing_filter() {
        assert_eq!(H2_PROXY_FILTER_NAME, "H2-PROXY");
        assert_eq!(H2_PROXY_FLAGS, CF_TYPE_IP_CONNECT | CF_TYPE_PROXY);
        assert_eq!(H2_PROXY_LOG_LEVEL, CURL_LOG_LVL_NONE);

        let conn = TestConn::new();
        let (proxy, _session, _state, _log) = h2(&conn);
        assert_eq!(proxy.trace_name(), "H2-PROXY");
        assert!(
            !proxy
                .cf_type()
                .contains(crate::conn::filters::CF_TYPE_MULTIPLEX),
            "a CONNECT tunnel carries exactly one stream, for ever"
        );
        assert!(proxy.cf_type().contains(CF_TYPE_PROXY));
        assert!(proxy.cf_type().contains(CF_TYPE_IP_CONNECT));
    }

    /// The five HTTP/2 tunnel states and their frozen trace strings. There is
    /// no `Receive`, which is the structural difference from HTTP/1.x.
    #[cfg(feature = "http2")]
    #[test]
    fn the_h2_state_trace_strings_are_frozen() {
        let all = [
            (H2TunnelState::Init, "new tunnel state 'init'"),
            (H2TunnelState::Connect, "new tunnel state 'connect'"),
            (H2TunnelState::Response, "new tunnel state 'response'"),
            (H2TunnelState::Established, "new tunnel state 'established'"),
            (H2TunnelState::Failed, "new tunnel state 'failed'"),
        ];
        for (state, expected) in all {
            assert_eq!(state.entry_trace(), expected);
        }
        assert_eq!(all.len(), 5, "five states, and no Receive");
        assert_eq!(H2TunnelState::default(), H2TunnelState::Init);
    }

    /// The trace strings really are emitted, with the stream identifier
    /// prefix.
    #[cfg(feature = "http2")]
    #[test]
    fn the_h2_traces_carry_the_stream_identifier() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Ok(true));
        assert!(
            trace.contains("[0] CONNECT start for remote.example:443"),
            "{trace:?}"
        );
        assert!(trace.contains("new tunnel state 'connect'"), "{trace:?}");
        assert!(trace.contains("new tunnel state 'response'"), "{trace:?}");
        assert!(
            trace.contains("new tunnel state 'established'"),
            "{trace:?}"
        );
        assert!(trace.contains("[1] status: HTTP/2 200"), "{trace:?}");
        assert!(trace.contains(CONNECT_PHASE_COMPLETED), "{trace:?}");
        assert!(
            trace.contains(
                "Establish HTTP/2 proxy tunnel to remote.example:443"
            ),
            "{trace:?}"
        );
    }

    /// A `TunnelStream` cleared through the state machine keeps its authority
    /// -- the C frees it and then dereferences it -- and its identifier lands
    /// on ZERO rather than on the `-1` a fresh one carries. Both are measured
    /// and both are observable through `adjust_pollset`'s `stream_id >= 0`
    /// guard.
    #[cfg(feature = "http2")]
    #[test]
    fn clearing_a_tunnel_stream_keeps_the_authority_and_zeroes_the_id() {
        let dest = TunnelDestination {
            hostname: "remote.example".to_string(),
            port: 443,
            ipv6_ip: false,
        };
        let mut stream = TunnelStream::init(&dest).expect("it initialises");
        assert_eq!(stream.stream_id, -1, "a fresh stream has no identifier");
        assert_eq!(stream.authority, "remote.example:443");

        stream.stream_id = 7;
        stream.has_final_response = true;
        stream.closed = true;
        stream.clear();

        assert_eq!(stream.stream_id, 0, "memset leaves zero, not -1");
        assert_eq!(
            stream.authority, "remote.example:443",
            "the authority survives, because H2_CONNECT reads it next"
        );
        assert_eq!(stream.state, H2TunnelState::Init);
        assert!(!stream.has_final_response);
        assert!(!stream.closed);
    }

    /// SETTINGS and WINDOW_UPDATE mark the transfer dirty ONLY while it wants
    /// to send -- `CURL_WANT_SEND(data)` -- and only while the tunnel has
    /// something buffered.
    #[cfg(feature = "http2")]
    #[test]
    fn a_window_opening_drains_only_a_sender_with_something_to_send() {
        for (wants_send, expected) in [(false, 0), (true, 0)] {
            let conn = TestConn::new();
            conn.set(|facts| facts.wants_send = wants_send);
            let clock = clock();
            let (mut proxy, session, state, _log) = h2(&conn);
            respond(
                &session,
                &state,
                vec![H2TunnelEvent::Settings, H2TunnelEvent::WindowUpdate],
            );
            assert_eq!(connect(&mut proxy, &clock), Ok(false));
            // Nothing is buffered, so `drain_tunnel`'s third condition fails
            // whatever the first says.
            assert_eq!(
                conn.calls().dirty_marks,
                expected,
                "wants_send = {wants_send}"
            );
        }

        // With payload buffered AND a wish to send, the mark happens. The
        // buffering comes from a CLOSED stream window, which is the only
        // reason a tunnel holds payload it has been handed.
        let conn = TestConn::new();
        conn.set(|facts| facts.wants_send = true);
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        session.borrow_mut().stream_window = 0;
        let mut cx = CallCtx::new(&clock);
        let _ = proxy.send(&mut cx, b"queued", false);
        assert!(
            session.borrow().bodies.is_empty(),
            "a closed window frames nothing"
        );
        respond(&session, &state, vec![H2TunnelEvent::WindowUpdate]);
        let mut buf = [0_u8; 8];
        let _ = proxy.recv(&mut cx, &mut buf);
        assert!(
            conn.calls().dirty_marks > 0,
            "a sender with buffered payload is drained"
        );
    }

    /// A header before `:status` is a protocol violation and fails the
    /// callback, which surfaces as [`CURLcode::RecvError`].
    #[cfg(feature = "http2")]
    #[test]
    fn a_header_before_status_is_a_protocol_violation() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);
        respond(
            &session,
            &state,
            vec![H2TunnelEvent::Header {
                name: b"via".to_vec(),
                value: b"1.1 p".to_vec(),
            }],
        );
        assert_eq!(connect(&mut proxy, &clock), Err(CURLcode::RecvError));
        assert_eq!(proxy.tunnel_state(), H2TunnelState::Failed);
    }

    /// Trailers after the final response are IGNORED -- *"we do not do
    /// anything with trailers for tunnel streams"*, and the guard sits BEFORE
    /// the `:status` branch so a whole trailer block is dropped.
    #[cfg(feature = "http2")]
    #[test]
    fn trailers_after_the_final_response_are_ignored() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        // A trailer block, including a second `:status`, changes nothing.
        respond(
            &session,
            &state,
            vec![
                H2TunnelEvent::Status(500),
                H2TunnelEvent::Header {
                    name: b"x-trailer".to_vec(),
                    value: b"1".to_vec(),
                },
            ],
        );
        let mut buf = [0_u8; 8];
        let mut cx = CallCtx::new(&clock);
        let _ = proxy.recv(&mut cx, &mut buf);
        assert_eq!(
            proxy.response().map(|r| r.status),
            Some(200),
            "the trailer block must not displace the response"
        );
        assert_eq!(proxy.response().map(H2Response::chain_len), Some(1));
    }

    /// `is_alive` with no session is DEAD, and with one it delegates and then
    /// reports `input_pending` as FALSE whatever the transport said -- because
    /// pending bytes were consumed as protocol frames.
    #[cfg(feature = "http2")]
    #[test]
    fn is_alive_consumes_pending_frames_and_reports_none() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);

        // No session yet.
        let mut cx = CallCtx::new(&clock);
        assert_eq!(proxy.is_alive(&mut cx), Liveness::DEAD);

        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        // Alive with nothing pending.
        let mut cx = CallCtx::new(&clock);
        assert_eq!(proxy.is_alive(&mut cx), Liveness::alive(false));

        // Alive with frames pending: they are read and accounted for, and
        // `input_pending` is still reported false.
        state.borrow_mut().input_pending = true;
        feed(&state, b"\x00\x00\x00\x04\x00\x00\x00\x00\x00");
        let liveness = proxy.is_alive(&mut cx);
        assert!(!liveness.input_pending, "frames are not application data");

        // A dead transport is dead however healthy the session.
        state.borrow_mut().alive = false;
        assert_eq!(proxy.is_alive(&mut cx), Liveness::DEAD);
    }

    /// `CF_QUERY_HOST_PORT` reports the PROXY from the HTTP/2 filter too --
    /// all three filters here agree, and all three disagree with `"SOCKS"`.
    #[cfg(feature = "http2")]
    #[test]
    fn the_h2_host_port_query_reports_the_proxy() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.proxy_host = "front.example".to_string();
            facts.proxy_port = 3128;
        });
        let clock = clock();
        let (mut proxy, _session, _state, _log) = h2(&conn);
        let mut cx = CallCtx::new(&clock);
        assert_eq!(
            proxy
                .query(&mut cx, CfQuery::HostPort)
                .map_err(|e| e.code()),
            Ok(CfQueryValue::HostPort {
                host: "front.example".to_string(),
                port: 3128,
            })
        );
    }

    /// `shutdown` must NOT chain -- one of exactly three operations that do
    /// not.
    #[cfg(feature = "http2")]
    #[test]
    fn h2_shutdown_does_not_chain() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        let mut cx = CallCtx::new(&clock);
        let _ = proxy.shutdown(&mut cx);
        assert_eq!(
            state.borrow().shutdowns,
            0,
            "shutdown must not reach the transport"
        );
    }

    /// `"H1-PROXY"` does not override `shutdown`, so it takes the trait
    /// default: reports done, and does not chain either.
    #[test]
    fn h1_shutdown_reports_done_without_chaining() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        let mut cx = CallCtx::new(&clock);
        assert_eq!(proxy.shutdown(&mut cx).map_err(|e| e.code()), Ok(true));
        assert_eq!(state.borrow().shutdowns, 0);
    }

    /// The six HTTP/1.x tunnel states and their frozen trace strings.
    #[test]
    fn the_h1_state_trace_strings_are_frozen() {
        let all = [
            (H1TunnelState::Init, "new tunnel state 'init'"),
            (H1TunnelState::Connect, "new tunnel state 'connect'"),
            (H1TunnelState::Receive, "new tunnel state 'receive'"),
            (H1TunnelState::Response, "new tunnel state 'response'"),
            (H1TunnelState::Established, "new tunnel state 'established'"),
            (H1TunnelState::Failed, "new tunnel state 'failed'"),
        ];
        for (state, expected) in all {
            assert_eq!(state.entry_trace(), expected);
        }
        assert_eq!(all.len(), 6, "six states, one more than HTTP/2's five");
        assert_eq!(H1TunnelState::default(), H1TunnelState::Init);
    }

    /// The trace strings are really emitted, in order, over one successful
    /// handshake.
    #[test]
    fn the_h1_traces_walk_the_states_in_order() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(&state, OK_200);
        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Ok(true));

        let mut cursor = 0;
        for expected in [
            "allocate connect buffer",
            "CONNECT start",
            "new tunnel state 'connect'",
            "CONNECT send",
            "new tunnel state 'receive'",
            "CONNECT receive",
            "new tunnel state 'response'",
            "CONNECT response",
            "new tunnel state 'established'",
            "CONNECT phase completed",
        ] {
            let at = trace[cursor..]
                .find(expected)
                .unwrap_or_else(|| panic!("{expected:?} missing -- {trace:?}"));
            cursor += at + expected.len();
        }
        assert!(
            trace.contains("Establish HTTP proxy tunnel to remote.example:443"),
            "{trace:?}"
        );
        assert!(
            trace.contains("CONNECT tunnel established, response 200"),
            "{trace:?}"
        );
    }

    /// Both terminal states scrub `data->state.aptr.proxyuserpwd`, *"so that
    /// it is not accidentally used for the document request after we have
    /// connected"*. HTTP/1.x additionally zeroes `data->info.httpcode`; HTTP/2
    /// does NOT, and the asymmetry is measured on both sides.
    #[test]
    fn reaching_a_terminal_state_scrubs_the_proxy_credential() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.compose_proxyuserpwd =
                Some("Proxy-Authorization: Basic eA==".to_string());
        });
        let clock = clock();
        let (mut proxy, state, _log) = h1(&conn);
        feed(&state, OK_200);
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        assert!(
            conn.proxy_user_pwd().is_none(),
            "the credential must not survive into the document request"
        );
        // THREE scrubs, and every one is in the C
        // (`lib/cf-h1-proxy.c:687-706`):
        //
        //   1. entering `H1_TUNNEL_ESTABLISHED`,
        //   2. the explicit `Curl_safefree(data->state.aptr.proxyuserpwd)`
        //      that `cf_h1_proxy_connect` runs after `H1_CONNECT` succeeds,
        //   3. `tunnel_free` forcing `H1_TUNNEL_FAILED` before releasing.
        //
        // Belt, braces and a second pair of braces -- but a credential that
        // leaked into the document request would be a real disclosure, so the
        // redundancy is preserved rather than pruned.
        let calls = conn.calls();
        assert_eq!(calls.proxyuserpwd_clears, 3);
        // Only TWO of those three touch `info.httpcode`, because the explicit
        // scrub in `cf_h1_proxy_connect` is a `safefree` and nothing more.
        assert_eq!(
            calls.info_httpcode_clears, 2,
            "HTTP/1.x zeroes info.httpcode on BOTH terminal states"
        );
        assert_eq!(calls.auth_done, vec![true]);
        assert_eq!(calls.auth_multipass, vec![false]);
    }

    /// The HTTP/2 half of that asymmetry: the credential IS scrubbed and
    /// `info.httpcode` is NOT touched.
    #[cfg(feature = "http2")]
    #[test]
    fn the_h2_terminal_state_leaves_info_httpcode_alone() {
        let conn = TestConn::new();
        conn.set(|facts| {
            facts.compose_proxyuserpwd =
                Some("Proxy-Authorization: Basic eA==".to_string());
        });
        let clock = clock();
        let (mut proxy, session, state, _log) = h2(&conn);
        respond(&session, &state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));

        assert!(conn.proxy_user_pwd().is_none());
        let calls = conn.calls();
        assert!(calls.proxyuserpwd_clears >= 1);
        assert_eq!(
            calls.info_httpcode_clears, 0,
            "HTTP/2 never clears info.httpcode"
        );
        assert_eq!(calls.auth_done, vec![true]);
        assert_eq!(calls.auth_multipass, vec![false]);
    }

    /// With no HTTP/2 in the build, `"h2"` cannot be selected and the
    /// dispatcher refuses it the same way any unsupported ALPN is refused.
    #[cfg(not(feature = "http2"))]
    #[test]
    fn without_http2_an_h2_alpn_is_refused() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, _state, _log) = dispatcher(&conn, Some("h2"));
        let (outcome, trace) = connect_traced(&mut proxy, &clock);
        assert_eq!(outcome, Err(CURLcode::CouldntConnect));
        assert!(
            trace.contains("CONNECT: negotiated ALPN 'h2' not supported"),
            "{trace:?}"
        );
    }

    /// With HTTP/2 in the build, `"h2"` installs `"H2-PROXY"` and records
    /// httpversion 20.
    #[cfg(feature = "http2")]
    #[test]
    fn with_http2_an_h2_alpn_installs_the_h2_tunnel() {
        let conn = TestConn::new();
        let log = new_log();
        let (transport, transport_state) = InMemory::new("TRANSPORT", &log);
        transport_state.borrow_mut().answers.push((
            CfQuery::AlpnNegotiated,
            CfQueryValue::AlpnNegotiated(Some("h2".to_string())),
        ));
        let mut wire = Wire::never_closes();
        wire.base_mut().set_next(Some(link(transport)));
        let session = session_state();
        let seams = TunnelSeams::new(Arc::clone(&conn) as Arc<dyn TunnelConn>)
            .with_h2(Arc::new(FakeFactory {
                state: Arc::clone(&session),
            }) as Arc<dyn H2SessionFactory>);
        let mut proxy =
            HttpProxy::new(conn.sockindex(), Some(ConnId::new(7)), seams);
        proxy.base_mut().set_next(Some(link(wire)));

        let clock = clock();
        respond(&session, &transport_state, h2_ok(200));
        assert_eq!(connect(&mut proxy, &clock), Ok(true));
        assert_eq!(proxy.ctx().httpversion, 20);
        assert!(proxy.ctx().sub_filter_installed);
        assert_eq!(
            session.borrow().submitted.len(),
            1,
            "the HTTP/2 tunnel really submitted the CONNECT"
        );
    }

    /// A build with HTTP/2 compiled in but no session factory injected cannot
    /// tunnel over it, and says so rather than panicking.
    #[cfg(feature = "http2")]
    #[test]
    fn an_h2_alpn_without_a_factory_is_refused() {
        let conn = TestConn::new();
        let clock = clock();
        let (mut proxy, _state, _log) = dispatcher(&conn, Some("h2"));
        let outcome = connect(&mut proxy, &clock);
        assert_eq!(
            outcome,
            Err(CURLcode::CouldntConnect),
            "no factory means h2 is not a negotiable option"
        );
    }

    /// `tunnel_want_send` is true in exactly ONE of the six states, which is
    /// what decides the poll direction.
    #[test]
    fn want_send_is_true_in_exactly_the_connect_state() {
        for state in H1TunnelState::ALL {
            assert_eq!(
                state.wants_send(),
                state == H1TunnelState::Connect,
                "{state:?}"
            );
        }
        assert_eq!(H1TunnelState::ALL.len(), 6);
    }

    /// The three `keeponval` values, and the truth test the read loop applies.
    #[test]
    fn the_keepon_values_are_the_three_the_c_declares() {
        assert_eq!(KeepOn::Done as i32, 0);
        assert_eq!(KeepOn::Connect as i32, 1);
        assert_eq!(KeepOn::Ignore as i32, 2);
        // `while(ts->keepon)` -- only `KEEPON_DONE` ends the read loop, which
        // is why it must be the ZERO discriminant.
        assert!(!KeepOn::Done.keeps_going());
        assert!(KeepOn::Connect.keeps_going());
        assert!(KeepOn::Ignore.keeps_going());
        assert_eq!(KeepOn::default(), KeepOn::Done);
    }
}
