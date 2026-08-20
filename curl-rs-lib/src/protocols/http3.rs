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
//  ***************************************************************************/
//! HTTP/3 over QUIC -- `lib/vquic/vquic.c`, `lib/vquic/curl_ngtcp2.c` and
//! `lib/vquic/vquic-tls.c`, with ngtcp2 and nghttp3 replaced by `quinn`,
//! `h3` and `h3-quinn`.
//!
//! `lib/vquic/curl_quiche.c` is EXCLUDED: specification 0.2.2 drops every
//! alternate backend, so this module is the only QUIC implementation and
//! `quinn` is its only transport.
//!
//! # HTTP/3 is ALREADY a connection filter in the C, which is why it slots in
//!
//! Specification 0.1.2 records that *"HTTP/3 already participates in this
//! chain as `Curl_cft_http3`, so QUIC, TLS, and raw sockets unify under one
//! trait rather than three special cases"*. That is measured, not assumed:
//!
//! * `lib/vquic/vquic.h:42` declares
//!   `CURLcode Curl_cf_quic_create(struct Curl_cfilter **pcf, struct
//!   Curl_easy *data, struct connectdata *conn, const struct Curl_addrinfo
//!   *ai, uint8_t transport)` -- ONE candidate address per call, and one
//!   transport byte that `DEBUGASSERT(transport == TRNSPRT_QUIC)` pins
//!   (`lib/vquic/vquic.c:705-706`).
//! * `lib/vquic/vquic.h:48` declares
//!   `extern struct Curl_cftype Curl_cft_http3;` -- the filter itself, so
//!   the whole QUIC and HTTP/3 stack is one link in the chain
//!   `crate::conn` owns.
//! * `lib/vquic/curl_ngtcp2.c:2894` DEFINES that filter, and its first three
//!   initialisers are the identity this module reproduces byte for byte:
//!   `"HTTP/3"`, `CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX |
//!   CF_TYPE_HTTP`, and a log level of `0`.
//! * `lib/urldata.h:567-571` fixes `TRNSPRT_QUIC = 5`, which is
//!   [`Transport::Quic`] here and which is what the Happy Eyeballs registry
//!   keys this module's provider under.
//!
//! # `Curl_conn_may_http3` is declared OUTSIDE the `USE_HTTP3` gate
//!
//! `lib/vquic/vquic.h` puts five declarations inside
//! `#if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3)` --
//! `Curl_quic_ver`, `Curl_vquic_init`, `Curl_qlogdir`,
//! `Curl_cf_quic_create` and `Curl_cft_http3` -- and then closes the block
//! with `#else #define Curl_vquic_init() 1 #endif`. Only after that, at
//! `:54-56`, does it declare
//! `CURLcode Curl_conn_may_http3(struct Curl_easy *data, const struct
//! connectdata *conn, unsigned char transport)`.
//!
//! So that ONE function exists in every build and has two definitions
//! (`lib/vquic/vquic.c:720-744` with HTTP/3 compiled in, `:854-863`
//! without), while everything else in the header vanishes with the feature.
//! This whole module is `#[cfg(feature = "http3")]`, so an unconditional
//! item CANNOT live here: [`crate::protocols::conn_may_http3`] owns the
//! unconditional declaration and both of its `#cfg` bodies, and this module
//! CONSUMES it -- see [`QuicTransportProvider::may_connect`]. The three
//! gated functions do live here: [`quic_ver`], [`vquic_init`] and
//! [`QlogWriter`].
//!
//! # What this module owns, and what it delegates
//!
//! `h3` performs QPACK and the HTTP/3 framing; `quinn` performs the QUIC
//! transport, loss recovery and the TLS 1.3 handshake QUIC embeds. WHICH
//! fields exist and in WHAT ORDER is decided here, which is specification
//! 0.1.2's transformation rule with the widest consequences and is why
//! [`req_to_h3`] exists at all. The C makes the same division and makes it
//! in the same place: `lib/vquic/curl_ngtcp2.c:1612` calls
//! `Curl_http_req_to_h2(&h2_headers, stream->h1.req, data)` -- HTTP/3 and
//! HTTP/2 share ONE ordered field list -- and hands the result to
//! `nghttp3_conn_submit_request` as an `nghttp3_nv` array
//! (`:1620-1669`).
//!
//! That sharing has one build consequence worth stating here, because it is
//! visible in the manifest and would otherwise look arbitrary: the `http3`
//! Cargo feature ENABLES `http2`. The C defines the shared builder once, in
//! `lib/http.c:4874`, and declares it unguarded in `lib/http.h:258`, so
//! `USE_HTTP3` (`lib/curl_setup.h:1515-1524`) does not imply `USE_NGHTTP2`. In
//! this crate the builder lives in `protocols/http2.rs`, so reaching it needs
//! that module compiled. The implication is a property of where the code sits
//! and not of the protocol; `curl-rs-lib/Cargo.toml`'s `http3` entry records
//! why relocating it was declined and what would let the implication be
//! dropped. Nothing observable changes: both features are on by default, so
//! only the `--features http3` subset -- which did not compile at all before --
//! is affected.
//!
//! # No TLS import, and QUIC embeds TLS
//!
//! Specification 0.4.2 is explicit that a protocol module imports no TLS:
//! `crate::protocols::mod` is the only permitted importer in this
//! directory. That reads oddly for QUIC, which carries TLS 1.3 inside the
//! transport rather than beneath it, so the arrangement is worth stating.
//! There is no `use crate::tls` anywhere in this file. The crypto
//! configuration arrives through [`QuicCrypto`], an injected seam whose
//! production implementor belongs to `crate::conn` -- exactly the shape
//! `conn/happy_eyeballs.rs` uses for the unfilled QUIC row of its
//! [`TransportRegistry`], and exactly the shape `crate::dns::doh` uses for
//! `DohTransport`. The negotiated protocol is read back out through the
//! [`CfQuery::AlpnNegotiated`] query, which is `CF_QUERY_ALPN_NEGOTIATED`
//! = 15, and never by reaching into a TLS type.
//!
//! # This filter TERMINATES the chain
//!
//! It is the only filter in the tree carrying FOUR type flags, and the
//! reason is that it does four jobs: it makes the IP connection
//! (`CF_TYPE_IP_CONNECT`), it secures it (`CF_TYPE_SSL`), it multiplexes it
//! (`CF_TYPE_MULTIPLEX`) and it speaks HTTP (`CF_TYPE_HTTP`). Nothing is
//! installed above it and nothing below it.
//!
//! The C nevertheless links a `"UDP"` filter underneath:
//! `Curl_cf_ngtcp2_create` calls
//! `Curl_cf_udp_create(&cf->next, data, conn, ai, TRNSPRT_QUIC)`
//! (`lib/vquic/curl_ngtcp2.c:2932`). That node exists because ngtcp2 owns
//! no socket -- it hands packets back to curl, and `vquic_send_packets` and
//! `vquic_recv_packets` (`lib/vquic/vquic.c:264`, `:624`) do the
//! `sendmsg`/`recvmmsg` through the descriptor that filter holds. `quinn`'s
//! [`AsyncUdpSocket`] subsumes precisely that work, so the node has none
//! left to do and is not reproduced. The consequence is recorded rather
//! than hidden: five queries the C answered from BELOW this filter --
//! `CF_QUERY_SOCKET`, `CF_QUERY_IP_INFO`, `CF_QUERY_REMOTE_ADDR`,
//! `CF_QUERY_HOST_PORT` and `CF_QUERY_TRANSPORT` -- are answered by this
//! filter itself, so the same answers reach the same callers from one node
//! instead of two. [`CfH3::query`] enumerates all fifteen.
//!
//! # Everything is injected
//!
//! Specification 0.3.3's pattern P12 requires the clock, the resolver, the
//! TLS provider and the randomness to be injected rather than reached for,
//! and here that is what makes 80% line coverage reachable without a
//! network: the clock is [`crate::util::timeval::Clock`] through
//! [`CallCtx`], the entropy is [`Rng`] so a connection identifier is
//! reproducible, the crypto is [`QuicCrypto`], and the datagram transport
//! is [`QuicSocketFactory`] -- whose test implementor,
//! [`PairedUdpTransport`], is a pair of in-memory queues that implement
//! [`AsyncUdpSocket`] and touch no socket at all. There is no
//! `Instant::now()` and no `SystemTime::now()` in this file.

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context as TaskContext, Poll, Waker};
use std::ffi::OsString;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::ReadBuf;

use super::http2::{req_to_h2, H1Request};
use super::{conn_may_http3, Http3Proxy, ProtocolOptions};
use crate::conn::filters::{
    link, CallCtx, CfControl, CfQuery, CfQueryValue, CfType, ConnFilter,
    FilterBase, FilterLink, IpQuadruple, Liveness, RemoteAddr, SocketIndex,
    TlsBackendId, TlsHandleKind, TlsSessionInfo, Transport, CF_TYPE_HTTP,
    CF_TYPE_IP_CONNECT, CF_TYPE_MULTIPLEX, CF_TYPE_SSL, CURL_LOG_LVL_NONE,
};
use crate::conn::happy_eyeballs::{TransportProvider, TransportRegistry};
use crate::crypto::rand::{rand_bytes, Rng};
use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::headers::{
    classify_origin, HeaderSet, CLIENTWRITE_1XX, CLIENTWRITE_HEADER,
    CURLH_HEADER, CURLH_TRAILER, HTTP_PSEUDO_AUTHORITY, HTTP_PSEUDO_METHOD,
    HTTP_PSEUDO_PATH, HTTP_PSEUDO_SCHEME, HTTP_PSEUDO_STATUS,
};
use crate::trace::{trc_cf, TraceFilter};
use crate::util::bufq::{BufQ, BufqOpts};
use crate::util::dynbuf::{DynBuf, DYN_QLOG_NAME};
use crate::util::timeval::{timediff_ms, CurlTime};

// `crate::dns` is reached by FULL PATH rather than by a `use`, and only for
// `ResolvedAddr` and its `ResolvedSockAddr` -- the argument type of
// `TransportProvider::create`. It is not a dependency this module chose: the
// trait it must implement is declared with that type
// (`conn/happy_eyeballs.rs:231-235`), and `conn::happy_eyeballs` imports it from
// `crate::dns` without re-exporting it, so there is no route to the trait that
// does not name the module. Declaring a local look-alike would not satisfy the
// trait, which is the one thing the type is for. The full path keeps the
// borrowing visible at every use site: the type is READ and never stored, so
// this module holds no DNS state. The `#[cfg(test)]` module below does import
// `ResolvedAddr` by name, because a fixture builder repeats it often enough
// that the full path obscures the fixture rather than clarifying it -- the rule
// stated here is about the production paths, which is where a reader looking for
// hidden DNS coupling would look.
//
// ---------------------------------------------------------------------------
// 1. The filter identity -- `struct Curl_cftype Curl_cft_http3`
//    (`lib/vquic/curl_ngtcp2.c:2894-2911`).

/// The `name` member: the literal `"HTTP/3"`.
///
/// User-visible through `--trace` and matched by `--trace-config`, so it is
/// curl's string and NOT a name reflecting the new backend. It resolves to
/// [`TraceFilter::Http3`], which `crate::trace` registers under exactly
/// these six bytes; a rename would silently disable the keyword rather than
/// fail, which is the worst kind of regression to ship.
#[rustfmt::skip]
pub(crate) const HTTP3_FILTER_NAME: &str = "HTTP/3";

/// The `flags` member:
/// `CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX | CF_TYPE_HTTP`.
///
/// Four flags, which no other filter in the C tree carries, and the reason
/// is the module documentation's: this one link makes the connection,
/// secures it, multiplexes it and speaks HTTP. The bits are
/// `lib/cfilters.h:203-207`'s -- `1<<0`, `1<<1`, `1<<2` and `1<<4`, so the
/// value is 23 -- and they are CONSUMED from [`crate::conn::filters`]
/// rather than restated, so there is one definition of each.
pub(crate) const HTTP3_FLAGS: CfType = CF_TYPE_IP_CONNECT
    .union(CF_TYPE_SSL)
    .union(CF_TYPE_MULTIPLEX)
    .union(CF_TYPE_HTTP);

/// The `log_level` member: `0`, which is [`CURL_LOG_LVL_NONE`].
#[allow(dead_code)] // consumer: the identity test; the live level is crate::trace::TraceConfig's
pub(crate) const HTTP3_LOG_LEVEL: i32 = CURL_LOG_LVL_NONE;

/// The version [`CfQuery::HttpVersion`] answers and the value
/// `CF_CTRL_CONN_INFO_UPDATE` writes into `conn->httpversion_seen`
/// (`lib/vquic/curl_ngtcp2.c:2822`, `:2799`).
///
/// curl encodes an HTTP version as two decimal digits -- 10, 11, 20, 30 --
/// so HTTP/3 is 30 and not 3.
pub(crate) const HTTP3_VERSION: i32 = 30;

/// `ALPN_H3` (`lib/vtls/vtls_int.h:47`): the two bytes offered and the two
/// bytes [`CfQuery::AlpnNegotiated`] reports once connected.
///
/// Wire-bearing, so `rustfmt` is kept off it. `ALPN_H3_LENGTH` at `:46` is
/// 2 and is this slice's own length here rather than a second constant.
#[rustfmt::skip]
pub(crate) const H3_ALPN: &[u8] = b"h3";

/// The transport this filter carries -- `TRNSPRT_QUIC = 5`
/// (`lib/urldata.h:567-571`).
pub(crate) const H3_TRANSPORT: Transport = Transport::Quic;

/// The version token `Curl_quic_ver` writes, as [`quic_ver`] returns it.
///
/// The C composes `"ngtcp2/%s nghttp3/%s"` from two library version strings
/// (`lib/vquic/curl_ngtcp2.c:103-110`); the successor names the two crates
/// that replaced them, at the versions specification 0.5.1 pins. One string
/// containing a space, exactly as the C's single buffer is, because
/// `lib/version.c:243-246` appends the whole buffer as ONE element of
/// `src[]`.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: quic_ver, and through it crate::version's banner
pub(crate) const QUIC_VERSION_TOKEN: &str = "quinn/0.11.9 h3/0.0.8";

// ---------------------------------------------------------------------------
// 2. The measured transport and stream constants -- `lib/vquic/vquic_int.h`
//    and `lib/vquic/curl_ngtcp2.c:73-97`.

/// `MAX_UDP_PAYLOAD_SIZE` (`lib/vquic/vquic_int.h:32`): 1452.
///
/// The largest datagram this module will read into one buffer, and therefore
/// the receive-buffer size [`CfH3`] hands [`AsyncUdpSocket::poll_recv`].
// The allowance is here for a MEASURED toolchain difference and not because
// nothing reads this: the `const _: () = assert!(..)` beside
// `H3_STREAM_CHUNK_SIZE` reads it, and rustc 1.97 credits that as a use. rustc
// at the declared MSRV floor of 1.75 does NOT, so `cargo +1.75.0 check` reports
// `dead_code` here where stable reports nothing. Since the MSRV gate must be
// warning-free too, the allowance is unconditional rather than `cfg`-gated on a
// version this crate cannot test for.
#[allow(dead_code)] // consumer: the const assertion below, and the tests
pub(crate) const MAX_UDP_PAYLOAD_SIZE: usize = 1452;

/// `NW_CHUNK_SIZE` (`lib/vquic/vquic.c:54`): 64 KiB.
pub(crate) const NW_CHUNK_SIZE: usize = 64 * 1024;

/// `NW_SEND_CHUNKS` (`lib/vquic/vquic.c:55`): 1.
///
/// One chunk, and the pairing with [`BufqOpts::SOFT_LIMIT`] below is what
/// makes that workable: a soft limit may be exceeded by one chunk, so a
/// single oversized write is buffered rather than refused.
pub(crate) const NW_SEND_CHUNKS: usize = 1;

/// `BUFQ_OPT_SOFT_LIMIT`, which `vquic_ctx_init` passes to
/// `Curl_bufq_init2(&qctx->sendbuf, NW_CHUNK_SIZE, NW_SEND_CHUNKS,
/// BUFQ_OPT_SOFT_LIMIT)` (`lib/vquic/vquic.c:79-80`).
pub(crate) const NW_SEND_OPTS: BufqOpts = BufqOpts::SOFT_LIMIT;

/// `QUIC_MAX_STREAMS` (`lib/vquic/curl_ngtcp2.c:73`): 256 Ki.
///
/// Announced as both `initial_max_streams_bidi` and
/// `initial_max_streams_uni` (`:484-485`).
pub(crate) const QUIC_MAX_STREAMS: u64 = 256 * 1024;

/// `QUIC_HANDSHAKE_TIMEOUT` (`lib/vquic/curl_ngtcp2.c:74`): ten seconds,
/// expressed in milliseconds because that is the unit
/// `data->set.connecttimeout` arrives in and the unit
/// `s->handshake_timeout` is derived from at `:471-472`.
pub(crate) const QUIC_HANDSHAKE_TIMEOUT_MS: i64 = 10 * 1000;

/// `H3_STREAM_WINDOW_SIZE_INITIAL` (`lib/vquic/curl_ngtcp2.c:79`): 32 KiB.
///
/// The C's comment is the whole rationale: *"We announce a small window size
/// in transport param to the server, and grow that immediately to max when
/// no rate limit is in place. We need to start small as we are not able to
/// decrease it."*
pub(crate) const H3_STREAM_WINDOW_SIZE_INITIAL: u64 = 32 * 1024;

/// `H3_STREAM_WINDOW_SIZE_MAX` (`lib/vquic/curl_ngtcp2.c:80`): 10 MiB.
pub(crate) const H3_STREAM_WINDOW_SIZE_MAX: u64 = 10 * 1024 * 1024;

/// `H3_CONN_WINDOW_SIZE_MAX` (`lib/vquic/curl_ngtcp2.c:81`): 100 stream
/// windows, which is also `initial_max_data` and `initial_max_stream_data_uni`
/// (`:481`, `:484`).
pub(crate) const H3_CONN_WINDOW_SIZE_MAX: u64 = 100 * H3_STREAM_WINDOW_SIZE_MAX;

/// `H3_STREAM_CHUNK_SIZE` (`lib/vquic/curl_ngtcp2.c:83`): 64 KiB.
///
/// The C guards it with `#if H3_STREAM_CHUNK_SIZE <
/// NGTCP2_MAX_UDP_PAYLOAD_SIZE #error` (`:84-86`), because a chunk smaller
/// than a datagram cannot hold one. The `const _: () = assert!(..)` below is
/// that `#error`: it fails the BUILD, not a test run, so the relation cannot be
/// broken by editing either constant in isolation.
pub(crate) const H3_STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// `#if H3_STREAM_CHUNK_SIZE < NGTCP2_MAX_UDP_PAYLOAD_SIZE #error ..#endif`
/// (`lib/vquic/curl_ngtcp2.c:84-86`), as a compile-time assertion.
const _: () = assert!(H3_STREAM_CHUNK_SIZE >= MAX_UDP_PAYLOAD_SIZE);

/// `H3_STREAM_POOL_SPARES` (`lib/vquic/curl_ngtcp2.c:92`): 2.
#[allow(dead_code)] // consumer: the constants test; BufQ has no spare-chunk knob to hand it to
pub(crate) const H3_STREAM_POOL_SPARES: usize = 2;

/// `H3_STREAM_SEND_BUFFER_MAX` (`lib/vquic/curl_ngtcp2.c:94`): 10 MiB of
/// un-acknowledged upload data per stream.
pub(crate) const H3_STREAM_SEND_BUFFER_MAX: usize = 10 * 1024 * 1024;

/// `H3_STREAM_SEND_CHUNKS` (`lib/vquic/curl_ngtcp2.c:95-96`).
pub(crate) const H3_STREAM_SEND_CHUNKS: usize =
    H3_STREAM_SEND_BUFFER_MAX / H3_STREAM_CHUNK_SIZE;

/// The `SETTINGS_MAX_FIELD_SECTION_SIZE` this client announces.
///
/// `lib/vquic/curl_ngtcp2.c` leaves `ctx->h3settings` at
/// `nghttp3_settings_default`, whose `max_field_section_size` is
/// `NGHTTP3_VARINT_MAX` -- an unbounded announcement. `h3 0.0.8` exposes the
/// same knob as `Builder::max_field_section_size`, and the unbounded value is
/// what keeps the announcement identical to the C's.
pub(crate) const H3_MAX_FIELD_SECTION_SIZE: u64 = (1 << 62) - 1;

// ---------------------------------------------------------------------------
// 3. The HTTP/3 error codes -- `vquic_h3_error` (`lib/vquic/vquic_int.h:35-53`)
//    and `vquic_h3_err_str` (`lib/vquic/vquic.c:747-793`).

/// One HTTP/3 application error code, RFC 9114 section 8.1.
///
/// A newtype over [`u64`] rather than an enumeration, because the space is
/// OPEN: RFC 9114 reserves an infinite family of codes that mean `NO_ERROR`,
/// and `vquic_h3_err_str` recognises them arithmetically rather than by name
/// (`lib/vquic/vquic.c:789-791`). An enumeration would have to reject them.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct H3Error(u64);

/// The seventeen named codes, IN THE C's DECLARATION ORDER, with their
/// strings.
///
/// Wire-bearing in both columns -- the codes go out in a `RESET_STREAM` or a
/// `CONNECTION_CLOSE` frame and the strings go out through `--trace` -- so
/// `rustfmt` is kept off the table and the order is part of the data.
///
/// The first column is the NAMED CONSTANT rather than a repeated literal, so
/// the table and [`H3Error`]'s associated constants cannot disagree: a value
/// edited in one place moves in both, and the wire value stays declared exactly
/// once. The order is still the data -- `vquic_h3_err_str`'s `switch` walks the
/// enumeration in this sequence.
#[rustfmt::skip]
const H3_ERROR_NAMES: [(H3Error, &str); 17] = [
    (H3Error::NO_ERROR,               "NO_ERROR"),
    (H3Error::GENERAL_PROTOCOL_ERROR, "GENERAL_PROTOCOL_ERROR"),
    (H3Error::INTERNAL_ERROR,         "INTERNAL_ERROR"),
    (H3Error::STREAM_CREATION_ERROR,  "STREAM_CREATION_ERROR"),
    (H3Error::CLOSED_CRITICAL_STREAM, "CLOSED_CRITICAL_STREAM"),
    (H3Error::FRAME_UNEXPECTED,       "FRAME_UNEXPECTED"),
    (H3Error::FRAME_ERROR,            "FRAME_ERROR"),
    (H3Error::EXCESSIVE_LOAD,         "EXCESSIVE_LOAD"),
    (H3Error::ID_ERROR,               "ID_ERROR"),
    (H3Error::SETTINGS_ERROR,         "SETTINGS_ERROR"),
    (H3Error::MISSING_SETTINGS,       "MISSING_SETTINGS"),
    (H3Error::REQUEST_REJECTED,       "REQUEST_REJECTED"),
    (H3Error::REQUEST_CANCELLED,      "REQUEST_CANCELLED"),
    (H3Error::REQUEST_INCOMPLETE,     "REQUEST_INCOMPLETE"),
    (H3Error::MESSAGE_ERROR,          "MESSAGE_ERROR"),
    (H3Error::CONNECT_ERROR,          "CONNECT_ERROR"),
    (H3Error::VERSION_FALLBACK,       "VERSION_FALLBACK"),
];

impl H3Error {
    /// `CURL_H3_ERR_NO_ERROR` = `0x0100`.
    pub(crate) const NO_ERROR: Self = Self(0x0100);

    /// `CURL_H3_ERR_GENERAL_PROTOCOL_ERROR` = `0x0101`.
    pub(crate) const GENERAL_PROTOCOL_ERROR: Self = Self(0x0101);

    /// `CURL_H3_ERR_INTERNAL_ERROR` = `0x0102`.
    pub(crate) const INTERNAL_ERROR: Self = Self(0x0102);

    /// `CURL_H3_ERR_STREAM_CREATION_ERROR` = `0x0103`.
    pub(crate) const STREAM_CREATION_ERROR: Self = Self(0x0103);

    /// `CURL_H3_ERR_CLOSED_CRITICAL_STREAM` = `0x0104`.
    pub(crate) const CLOSED_CRITICAL_STREAM: Self = Self(0x0104);

    /// `CURL_H3_ERR_FRAME_UNEXPECTED` = `0x0105`.
    pub(crate) const FRAME_UNEXPECTED: Self = Self(0x0105);

    /// `CURL_H3_ERR_FRAME_ERROR` = `0x0106`.
    pub(crate) const FRAME_ERROR: Self = Self(0x0106);

    /// `CURL_H3_ERR_EXCESSIVE_LOAD` = `0x0107`.
    pub(crate) const EXCESSIVE_LOAD: Self = Self(0x0107);

    /// `CURL_H3_ERR_ID_ERROR` = `0x0108`.
    pub(crate) const ID_ERROR: Self = Self(0x0108);

    /// `CURL_H3_ERR_SETTINGS_ERROR` = `0x0109`.
    pub(crate) const SETTINGS_ERROR: Self = Self(0x0109);

    /// `CURL_H3_ERR_MISSING_SETTINGS` = `0x010a`.
    pub(crate) const MISSING_SETTINGS: Self = Self(0x010a);

    /// `CURL_H3_ERR_REQUEST_REJECTED` = `0x010b`.
    ///
    /// The one code that is not a failure at all: the C retries the transfer
    /// on a fresh connection rather than reporting anything
    /// (`lib/vquic/curl_ngtcp2.c:1370-1378`). [`Self::is_retryable`] is that
    /// distinction, and [`H3StreamCtx::handle_close`] acts on it.
    pub(crate) const REQUEST_REJECTED: Self = Self(0x010b);

    /// `CURL_H3_ERR_REQUEST_CANCELLED` = `0x010c`.
    pub(crate) const REQUEST_CANCELLED: Self = Self(0x010c);

    /// `CURL_H3_ERR_REQUEST_INCOMPLETE` = `0x010d`.
    pub(crate) const REQUEST_INCOMPLETE: Self = Self(0x010d);

    /// `CURL_H3_ERR_MESSAGE_ERROR` = `0x010e`.
    pub(crate) const MESSAGE_ERROR: Self = Self(0x010e);

    /// `CURL_H3_ERR_CONNECT_ERROR` = `0x010f`.
    pub(crate) const CONNECT_ERROR: Self = Self(0x010f);

    /// `CURL_H3_ERR_VERSION_FALLBACK` = `0x0110`.
    pub(crate) const VERSION_FALLBACK: Self = Self(0x0110);

    /// The first reserved code of the `NO_ERROR` family, `0x21`.
    ///
    /// RFC 9114 sections 8.1 and 9 reserve `0x1f * N + 0x21` to exercise the
    /// requirement that an unknown code be treated as `NO_ERROR`, and the C
    /// recognises the whole family with
    /// `if((error_code >= 0x21) && !((error_code - 0x21) % 0x1f))`
    /// (`lib/vquic/vquic.c:790-791`).
    const RESERVED_BASE: u64 = 0x21;

    /// The stride of that family, `0x1f`.
    const RESERVED_STRIDE: u64 = 0x1f;

    /// A code from its wire value.
    pub(crate) const fn from_u64(code: u64) -> Self {
        Self(code)
    }

    /// The wire value.
    pub(crate) const fn as_u64(self) -> u64 {
        self.0
    }

    /// `vquic_h3_err_str(error_code)` (`lib/vquic/vquic.c:747-793`).
    ///
    /// The C's three-step ladder, in its order:
    ///
    /// 1. a named code inside `UINT_MAX` yields its name;
    /// 2. a reserved code of the `NO_ERROR` family yields `"NO_ERROR"`;
    /// 3. anything else yields `"unknown"`.
    ///
    /// The `if(error_code <= UINT_MAX)` guard at `:749` exists because the C
    /// narrows to `unsigned int` before switching; here the comparison is on
    /// the full width, so the guard has no work to do and no arm can be
    /// reached that the C would have skipped -- every named code is far below
    /// `UINT_MAX`.
    ///
    /// Only compiled in a verbose build in the C
    /// (`#ifdef CURLVERBOSE`, `:746`). Tracing is unconditional in this
    /// crate, so the gate has no successor.
    pub(crate) fn err_str(self) -> &'static str {
        let mut index = 0;
        while index < H3_ERROR_NAMES.len() {
            let (code, name) = H3_ERROR_NAMES[index];
            if code.0 == self.0 {
                return name;
            }
            index += 1;
        }
        if self.is_reserved_no_error() {
            return "NO_ERROR";
        }
        "unknown"
    }

    /// True for a code of the reserved `NO_ERROR` family.
    pub(crate) const fn is_reserved_no_error(self) -> bool {
        self.0 >= Self::RESERVED_BASE
            && (self.0 - Self::RESERVED_BASE) % Self::RESERVED_STRIDE == 0
    }

    /// True when this code means "nothing went wrong".
    ///
    /// `NGHTTP3_H3_NO_ERROR` is what `cb_h3_stream_close` compares against
    /// before marking a stream reset (`lib/vquic/curl_ngtcp2.c:996-1002`), and
    /// the reserved family means the same thing.
    pub(crate) const fn is_no_error(self) -> bool {
        self.0 == Self::NO_ERROR.0 || self.is_reserved_no_error()
    }

    /// True when the peer refused the request in a way curl retries.
    ///
    /// `if(stream->error3 == NGHTTP3_H3_REQUEST_REJECTED)` --
    /// *"refused by server, try again"* (`lib/vquic/curl_ngtcp2.c:1370-1378`).
    pub(crate) const fn is_retryable(self) -> bool {
        self.0 == Self::REQUEST_REJECTED.0
    }
}

/// `%" PRIx64 "` -- the C prints these in hexadecimal
/// (`lib/vquic/curl_ngtcp2.c:1386-1388`), so a trace line comparing the two
/// implementations reads the same.
impl fmt::Display for H3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:x})", self.err_str(), self.0)
    }
}

// ---------------------------------------------------------------------------
// 4. Error mapping -- `recv_closed_stream` (`lib/vquic/curl_ngtcp2.c:1364-1400`)
//    and the ten `CURLcode` values this filter produces.

/// What closing a stream means for the transfer that owned it.
///
/// `recv_closed_stream` reaches four outcomes and picks between them by
/// inspecting three pieces of state -- whether the stream was reset, whether
/// the response header block completed, and whether any body byte arrived --
/// in that order. They are named here so that a caller cannot conflate the
/// retry with the failure, which is the one distinction the C draws with a
/// side effect (`data->state.refused_stream = TRUE`) rather than with a
/// return value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamCloseOutcome {
    /// `return CURLE_OK` -- the stream finished, or it failed after complete
    /// response headers on a transfer that wanted no body anyway
    /// (`:1379-1385`). Nothing is reported.
    Complete,
    /// `REQUEST_REJECTED`: *"refused by server, try again on a new
    /// connection"* (`:1372-1378`).
    ///
    /// Three things happen in the C and all three are carried here: the
    /// connection is marked for closing (`connclose(cf->conn,
    /// "REFUSED_STREAM")`), `data->state.refused_stream` is set so that
    /// `Curl_retry_request()` fires later, and the code returned is
    /// [`CURLcode::RecvError`] -- NOT [`CURLcode::Http3`], because the retry
    /// machinery keys off the pair.
    Refused,
    /// A reset stream that carried body bytes: `CURLE_PARTIAL_FILE`
    /// (`:1391`).
    Partial,
    /// A reset stream that carried none, or a clean close before the response
    /// header fields were complete: `CURLE_HTTP3` (`:1391`, `:1397`).
    Failed,
}

impl StreamCloseOutcome {
    /// The `CURLcode` this outcome reports, or [`None`] for
    /// [`Self::Complete`].
    pub(crate) const fn code(self) -> Option<CURLcode> {
        match self {
            Self::Complete => None,
            Self::Refused => Some(CURLcode::RecvError),
            Self::Partial => Some(CURLcode::PartialFile),
            Self::Failed => Some(CURLcode::Http3),
        }
    }

    /// True when the transfer should be retried on a fresh connection --
    /// `data->state.refused_stream`.
    #[allow(dead_code)] // consumer: transfer/mod.rs, choosing retry over abort
    pub(crate) const fn should_retry(self) -> bool {
        matches!(self, Self::Refused)
    }

    /// True when the connection must not be reused -- `connclose(cf->conn,
    /// "REFUSED_STREAM")`.
    #[allow(dead_code)] // consumer: transfer/mod.rs, deciding whether to drop the connection
    pub(crate) const fn closes_connection(self) -> bool {
        matches!(self, Self::Refused)
    }
}

/// Why a QUIC connection attempt or a live QUIC connection ended.
///
/// The C reaches its codes through ngtcp2's own error space; `quinn` reports
/// structured variants instead. This enumeration is the join: every variant
/// names the condition, and [`Self::code`] gives the `CURLcode` the C
/// produces for it, so the mapping is one table rather than a scattering of
/// conversions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuicFailure {
    /// The handshake did not complete: `CURLE_QUIC_CONNECT_ERROR`, which is
    /// the code nine sites in `lib/vquic/curl_ngtcp2.c` report.
    Handshake,
    /// The handshake timed out. `s->handshake_timeout` makes ngtcp2 fail the
    /// connection, which arrives at the same
    /// `CURLE_QUIC_CONNECT_ERROR`; the distinct variant exists so a trace
    /// line can say which it was.
    HandshakeTimeout,
    /// Certificate or hostname verification failed:
    /// `CURLE_PEER_FAILED_VERIFICATION` (`lib/vquic/curl_ngtcp2.c:2731`).
    ///
    /// Validation is ON by default and `--insecure` is the only way past it,
    /// which specification 0.8.1 freezes.
    Verification,
    /// No usable address, or the socket could not be reached at all:
    /// `CURLE_COULDNT_CONNECT`.
    CouldntConnect,
    /// Configuring the transport or the crypto failed before any packet went
    /// out: `CURLE_FAILED_INIT`, which eight sites report.
    Init,
    /// The connection was lost while sending: `CURLE_SEND_ERROR`.
    Send,
    /// The connection was lost while receiving: `CURLE_RECV_ERROR`.
    Recv,
    /// A protocol violation by the peer: `CURLE_HTTP3`.
    Protocol,
    /// A response that could not be parsed as HTTP/3 at all:
    /// `CURLE_WEIRD_SERVER_REPLY`.
    ///
    /// INCONCLUSIVE rather than terminal where the Happy Eyeballs race is
    /// concerned, which `conn/happy_eyeballs.rs` decides and this module only
    /// reports honestly.
    WeirdServerReply,
    /// Allocation refused: `CURLE_OUT_OF_MEMORY`.
    #[allow(dead_code)]
    // no producer here -- Rust aborts on allocation failure; the arm keeps the table complete
    OutOfMemory,
}

impl QuicFailure {
    /// The pinned `CURLcode` for this condition.
    pub(crate) const fn code(self) -> CURLcode {
        match self {
            Self::Handshake | Self::HandshakeTimeout => {
                CURLcode::QuicConnectError
            }
            Self::Verification => CURLcode::PeerFailedVerification,
            Self::CouldntConnect => CURLcode::CouldntConnect,
            Self::Init => CURLcode::FailedInit,
            Self::Send => CURLcode::SendError,
            Self::Recv => CURLcode::RecvError,
            Self::Protocol => CURLcode::Http3,
            Self::WeirdServerReply => CURLcode::WeirdServerReply,
            Self::OutOfMemory => CURLcode::OutOfMemory,
        }
    }

    /// The message the C's `failf` writes, where it writes one.
    #[allow(dead_code)] // consumer: the failf text transfer/mod.rs writes
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Handshake => "QUIC connect failed",
            Self::HandshakeTimeout => "QUIC handshake timed out",
            Self::Verification => {
                "SSL peer certificate or SSH remote key \
                                   was not OK"
            }
            Self::CouldntConnect => "Failed to connect to host",
            Self::Init => "QUIC initialization failed",
            Self::Send => "QUIC send failed",
            Self::Recv => "QUIC recv failed",
            Self::Protocol => "HTTP/3 protocol error",
            Self::WeirdServerReply => "Weird server reply",
            Self::OutOfMemory => "Out of memory",
        }
    }

    /// This condition as a whole [`Error`], message attached.
    #[allow(dead_code)] // consumer: callers wanting the code AND the message in one value
    pub(crate) fn into_error(self) -> Error {
        Error::with_context(self.code(), self.message())
    }
}

/// Turns one of `quinn`'s connection errors into a [`QuicFailure`].
///
/// The variants are matched exhaustively rather than with a catch-all so that
/// a `quinn` upgrade adding one is a compile error here instead of a silent
/// reclassification to something generic.
pub(crate) fn classify_connection_error(
    error: &quinn::ConnectionError,
) -> QuicFailure {
    match error {
        // A TLS alert during the handshake. The one alert curl distinguishes
        // is a certificate failure, because `--insecure` turns exactly that
        // into a warning.
        quinn::ConnectionError::TransportError(transport) => {
            if is_certificate_alert(transport.code) {
                QuicFailure::Verification
            } else {
                QuicFailure::Handshake
            }
        }
        // A `CONNECTION_CLOSE` from the peer puts the connection into the
        // draining period, which is the state `cf_ngtcp2_connect`'s `out:`
        // block inspects (`lib/vquic/curl_ngtcp2.c:2718-2745`). Its ladder,
        // measured:
        //
        //   result = CURLE_COULDNT_CONNECT;                      /* default */
        //   switch(cerr->type) {
        //   case NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION: break;   /* keeps it */
        //   default:
        //     if(cerr->error_code >= NGTCP2_CRYPTO_ERROR) { }     /* keeps it */
        //     else if(cerr->error_code == NGTCP2_CONNECTION_REFUSED)
        //       result = CURLE_WEIRD_SERVER_REPLY;
        //   }
        //
        // `CONNECTION_REFUSED` is singled out with a comment worth honouring
        // in full: *"When a QUIC server instance is shutting down, it may send
        // us a CONNECTION_CLOSE with this code right away. We want to keep on
        // trying in this case."* That is why it is INCONCLUSIVE for the Happy
        // Eyeballs race rather than terminal, and reporting it as a plain
        // connect failure would turn a retryable condition into a dead
        // candidate.
        quinn::ConnectionError::ConnectionClosed(close) => {
            if close.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED
            {
                QuicFailure::WeirdServerReply
            } else {
                QuicFailure::CouldntConnect
            }
        }
        // `NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION` -- the C's `break` leaves the
        // `CURLE_COULDNT_CONNECT` the block had already chosen.
        quinn::ConnectionError::VersionMismatch => QuicFailure::CouldntConnect,
        // No connection identifier left to migrate to. ngtcp2 surfaces this as
        // a plain connection failure during the handshake, before any
        // `CONNECTION_CLOSE` is received, so the draining ladder never sees it
        // and `cf_connect_start`'s `CURLE_QUIC_CONNECT_ERROR` is what remains.
        quinn::ConnectionError::CidsExhausted => QuicFailure::Handshake,
        quinn::ConnectionError::TimedOut => QuicFailure::HandshakeTimeout,
        // The application closed it, which after a handshake means the peer
        // gave up on us mid-transfer.
        quinn::ConnectionError::ApplicationClosed(closed) => {
            let code = H3Error::from_u64(closed.error_code.into_inner());
            if code.is_no_error() {
                QuicFailure::Recv
            } else {
                QuicFailure::Protocol
            }
        }
        quinn::ConnectionError::Reset => QuicFailure::Recv,
        quinn::ConnectionError::LocallyClosed => QuicFailure::Send,
    }
}

/// True when a QUIC transport error carries a TLS certificate alert.
///
/// RFC 8446 assigns the certificate alerts 42..48 and 112, and RFC 9001
/// section 4.8 maps a TLS alert onto the QUIC transport error space at
/// `CRYPTO_ERROR` (`0x0100`) plus the alert value. So the certificate alerts
/// occupy `0x012a..=0x0130` and `0x0170`, and recognising them is what lets
/// [`QuicFailure::Verification`] be reported instead of a bare connect
/// failure -- the same distinction `cf_ngtcp2_err_set` draws with
/// `ngtcp2_ccerr_set_tls_alert` (`lib/vquic/curl_ngtcp2.c:576-579`).
#[rustfmt::skip]
const TLS_CERTIFICATE_ALERTS: [u64; 8] = [
    0x012a, // bad_certificate            (42)
    0x012b, // unsupported_certificate    (43)
    0x012c, // certificate_revoked        (44)
    0x012d, // certificate_expired        (45)
    0x012e, // certificate_unknown        (46)
    0x012f, // illegal_parameter          (47)
    0x0130, // unknown_ca                 (48)
    0x0170, // certificate_required       (112)
];

/// True for one of [`TLS_CERTIFICATE_ALERTS`].
///
/// `quinn::TransportErrorCode` is the only half of the transport error this
/// crate can name: `quinn 0.11.9` re-exports `Code as TransportErrorCode` but
/// NOT `Error as TransportError`, so the code is taken out at the match site
/// and handed here rather than the whole error being passed.
fn is_certificate_alert(code: quinn::TransportErrorCode) -> bool {
    let raw: u64 = code.into();
    TLS_CERTIFICATE_ALERTS.contains(&raw)
}

// ---------------------------------------------------------------------------
// 5. qlog -- `Curl_qlogdir` (`lib/vquic/vquic.c:648-697`).

/// The environment variable `Curl_qlogdir` reads: `QLOGDIR`.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: QlogWriter::from_environment
pub(crate) const QLOGDIR_ENV: &str = "QLOGDIR";

/// The suffix `Curl_qlogdir` appends: `.sqlog`.
///
/// Wire-adjacent rather than wire-bearing -- it is a filename a qlog tool
/// consumes -- and pinned for the same reason: a tool matching `*.sqlog` finds
/// nothing if this changes.
#[rustfmt::skip]
pub(crate) const QLOG_SUFFIX: &str = ".sqlog";

/// Where a QUIC connection's qlog goes, if anywhere.
///
/// # The environment is read ONCE, at construction
///
/// `Curl_qlogdir` calls `curl_getenv("QLOGDIR")` on every invocation, which is
/// once per connection in the C because the function is called once from the
/// filter's own initialization. Here the read happens in
/// [`Self::from_environment`] and the result is HELD -- the same discipline
/// `tls/keylog.rs` applies to `SSLKEYLOGFILE`, and for the same two reasons:
/// re-reading per write would make the destination changeable mid-connection,
/// and a mutable global would make it changeable from another thread.
///
/// [`Self::with_dir`] is the injected form, so a test fixes a directory
/// without touching the process environment and therefore without depending on
/// the order tests run in.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct QlogWriter {
    /// `qlog_dir`, held from construction. [`None`] means the variable was
    /// unset, which is the overwhelmingly common case and in which nothing is
    /// ever written.
    directory: Option<OsString>,
}

impl QlogWriter {
    /// Reads `QLOGDIR` once, through `std::env::var_os`.
    ///
    /// `var_os` rather than `var`: a directory is a PATH, and a path need not
    /// be UTF-8. `curl_getenv` hands back raw bytes, so refusing a non-UTF-8
    /// directory here would be a behaviour change.
    ///
    /// An EMPTY value is treated as unset. The C would compose
    /// `"/<hex>.sqlog"` from it -- an absolute path in the root directory --
    /// which is not what an empty variable means to anybody, and
    /// `curl_getenv` itself hands back nothing for an empty value, so unset is
    /// the faithful reading as well as the sane one.
    #[allow(dead_code)] // consumer: conn/mod.rs, which builds the filter once per connection
    pub(crate) fn from_environment() -> Self {
        let directory =
            std::env::var_os(QLOGDIR_ENV).filter(|value| !value.is_empty());
        Self { directory }
    }

    /// The injected form: `directory` is used exactly as
    /// [`Self::from_environment`] would have used the variable's value.
    #[allow(dead_code)] // consumer: this module's tests, and any caller injecting the directory
    pub(crate) fn with_dir(directory: Option<OsString>) -> Self {
        Self {
            directory: directory.filter(|value| !value.is_empty()),
        }
    }

    /// True when a qlog would be written -- the C's `if(qlog_dir)`.
    #[allow(dead_code)] // consumer: the filter's trace output
    pub(crate) const fn is_enabled(&self) -> bool {
        self.directory.is_some()
    }

    /// The filename for a connection whose source connection identifier is
    /// `scid`, or [`None`] when `QLOGDIR` is unset.
    ///
    /// `Curl_qlogdir`'s construction, step for step (`:663-678`):
    ///
    /// ```c
    /// curlx_dyn_init(&fname, DYN_QLOG_NAME);
    /// result = curlx_dyn_add(&fname, qlog_dir);
    /// if(!result) result = curlx_dyn_add(&fname, "/");
    /// for(i = 0; (i < scidlen) && !result; i++) {
    ///   char hex[3];
    ///   curl_msnprintf(hex, 3, "%02x", scid[i]);
    ///   result = curlx_dyn_add(&fname, hex);
    /// }
    /// if(!result) result = curlx_dyn_add(&fname, ".sqlog");
    /// ```
    ///
    /// Three properties are preserved exactly:
    ///
    /// * the separator is a bare `"/"`, appended unconditionally -- so a
    ///   directory already ending in a solidus yields a doubled one, which is
    ///   harmless on every mandated target and is what the C produces;
    /// * the identifier is LOWER-CASE hexadecimal, two digits per byte, from
    ///   `"%02x"`;
    /// * the whole name is bounded by [`DYN_QLOG_NAME`], 1024, and the bound
    ///   is enforced by [`DynBuf`] -- the constant is CONSUMED from
    ///   `crate::util::dynbuf` rather than restated here.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] from [`DynBuf::addn`] when the composed name
    /// would exceed [`DYN_QLOG_NAME`]. The C propagates the same condition:
    /// `if(result) return result;` at `:692-693`, AFTER freeing both
    /// allocations.
    pub(crate) fn file_name(&self, scid: &[u8]) -> CodeResult<Option<PathBuf>> {
        let Some(directory) = self.directory.as_ref() else {
            return Ok(None);
        };

        let mut fname = DynBuf::new(DYN_QLOG_NAME);
        // The directory is raw bytes on a Unix target, which all four
        // mandated targets are. A lossy conversion would corrupt a non-UTF-8
        // directory name, so the bytes are taken as they are.
        fname.addn(os_str_bytes(directory))?;
        fname.addn(b"/")?;
        for byte in scid {
            // `curl_msnprintf(hex, 3, "%02x", scid[i])` -- exactly two
            // lower-case digits per byte, never one and never three.
            fname.addf(format_args!("{byte:02x}"))?;
        }
        fname.addn(QLOG_SUFFIX.as_bytes())?;

        Ok(Some(path_from_bytes(fname.as_slice())))
    }

    /// Opens the qlog file, or reports that there is none to open.
    ///
    /// `Curl_qlogdir`'s own contract, verbatim from `:652-654`: *"This
    /// function returns error if something failed outside of failing to create
    /// the file. Open file success is deemed by seeing if the returned fd is
    /// != -1."* So a directory that does not exist, or one this process cannot
    /// write to, is NOT an error -- it yields `Ok(None)` and the connection
    /// proceeds without a qlog, exactly as the C's `*qlogfdp` stays `-1`.
    ///
    /// The C's flags are `O_WRONLY | O_CREAT | CURL_O_BINARY` with
    /// `data->set.new_file_perms`. `O_BINARY` has no meaning on a Unix target
    /// and no successor, and the absence of `O_TRUNC` is reproduced -- an
    /// existing qlog is opened for writing WITHOUT being emptied, which is the
    /// C's behaviour and not an oversight in it. The permissions are the
    /// process umask's business here, because `CURLOPT_NEW_FILE_PERMS` arrives
    /// through an easy handle and `easy/setopt.rs` is not on disk to supply
    /// one; that gap belongs to the whole crate rather than to this decision.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::file_name`] reports, which is [`CURLcode::TooLarge`]
    /// for a name past [`DYN_QLOG_NAME`].
    pub(crate) fn open(
        &self,
        scid: &[u8],
    ) -> CodeResult<Option<std::fs::File>> {
        let Some(path) = self.file_name(scid)? else {
            return Ok(None);
        };
        // `if(qlogfd != -1) *qlogfdp = qlogfd;` -- a refusal is silent.
        Ok(std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .ok())
    }
}

/// The bytes of an [`OsString`], on the four mandated targets.
///
/// All four are Unix, where an `OsStr` IS a byte string and
/// `OsStrExt::as_bytes` is an infallible borrow. The `#[cfg]` pair exists so
/// that this file compiles on a non-Unix host with a lossy conversion rather
/// than failing to build; no mandated target takes the second arm.
#[cfg(unix)]
fn os_str_bytes(value: &OsString) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    value.as_os_str().as_bytes()
}

/// The non-Unix fallback: unreachable on every mandated target.
#[cfg(not(unix))]
fn os_str_bytes(value: &OsString) -> &[u8] {
    // A non-UTF-8 directory name cannot be recovered on such a target, which
    // is why the Unix arm above exists and is the only one that ships.
    match value.to_str() {
        Some(text) => text.as_bytes(),
        None => b"",
    }
}

/// A path from the composed bytes.
#[cfg(unix)]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

/// The non-Unix fallback, matching [`os_str_bytes`].
#[cfg(not(unix))]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

// ---------------------------------------------------------------------------
// 6. The two remaining gated entry points -- `Curl_quic_ver` and
//    `Curl_vquic_init` (`lib/vquic/vquic.h:34-35`).

/// `Curl_quic_ver(char *p, size_t len)` (`lib/vquic/vquic.c:67-74`).
///
/// The C writes into a caller-supplied buffer because it has no other way to
/// return a string; the successor returns [`QUIC_VERSION_TOKEN`], so there is
/// no buffer, no length and no truncation. `lib/version.c:243-246` appends the
/// whole thing as ONE element of `src[]`, which is why the token contains a
/// space and is not two tokens.
///
/// `crate::version` assembles the identical token from its own pinned literals
/// under `HTTP3_TOKEN`, and the duplication is the C's rather than an
/// oversight: `lib/version.c` calls `Curl_quic_ver()` precisely because the
/// backend owns the string. `the_version_token_is_the_pinned_pair` asserts the
/// exact bytes, so the two cannot drift silently.
#[allow(dead_code)] // consumer: crate::version's HTTP/3 banner token
pub(crate) const fn quic_ver() -> &'static str {
    QUIC_VERSION_TOKEN
}

/// `Curl_vquic_init(void)` (`lib/vquic/vquic.c:57-65`): one-time
/// initialization, `1` for success.
///
/// The C body is one conditional call:
///
/// ```c
/// #if defined(USE_NGTCP2) && defined(OPENSSL_QUIC_API2)
///   if(ngtcp2_crypto_ossl_init()) return 0;
/// #endif
///   return 1;
/// ```
///
/// Both halves are answerable here without guessing. There is no ngtcp2, so
/// the guarded call has no successor; and the provider `quinn` uses is fixed
/// at BUILD time by the pinned feature set -- `["ring", "runtime-tokio",
/// "rustls", "log"]`, where `rustls` already implies `rustls-ring` -- rather
/// than installed at run time, so nothing needs installing and nothing can
/// fail. That makes this the same constant `true` as the C's own
/// `#else #define Curl_vquic_init() 1` fallback at `lib/vquic/vquic.h:51`,
/// arrived at for a different reason, and the reason is recorded because
/// "returns a constant" is otherwise indistinguishable from a stub.
///
/// Kept as a function rather than folded into its callers because it is the
/// successor of a declared entry point that `crate::version`'s banner path and
/// a future `curl_global_init` both reach.
#[allow(dead_code)] // consumer: curl_global_init, through crate::version
pub(crate) const fn vquic_init() -> bool {
    true
}

// ---------------------------------------------------------------------------
// 7. The injected seams -- specification 0.3.3's pattern P12, and the reason
//    this module has no `use crate::tls` and no global state.

/// What a QUIC connection needs to know before it can offer a ClientHello.
///
/// The C reaches the same information through `struct ssl_peer` and
/// `data->set` (`lib/vquic/vquic-tls.c:55-95`); it is named here so that
/// [`QuicCrypto`] is a function of its argument alone and can be driven from
/// a table in a test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuicCryptoRequest<'a> {
    /// The name to validate the certificate against, and the SNI to send.
    pub(crate) hostname: &'a str,
    /// The protocols to offer, in preference order. For HTTP/3 this is
    /// exactly `[`[`H3_ALPN`]`]`.
    pub(crate) alpn: &'a [&'a [u8]],
    /// Whether the peer's certificate is verified.
    ///
    /// TRUE by default, which specification 0.8.1 freezes: validation is on
    /// unless `--insecure` was given, and `--insecure` must emit a stderr
    /// warning before proceeding. The warning belongs to
    /// `curl-rs/src/output/msgs.rs` -- this flag is only the transport half of
    /// the same requirement.
    pub(crate) verify_peer: bool,
    /// Whether the session keys are logged, which is `SSLKEYLOGFILE`.
    pub(crate) keylog: bool,
}

impl<'a> QuicCryptoRequest<'a> {
    /// A request for `hostname` offering `h3` with verification ON.
    ///
    /// The default is the SECURE one deliberately: a caller must ask for
    /// `verify_peer = false` explicitly, so no path reaches an unverified
    /// handshake by forgetting a field.
    pub(crate) fn new(hostname: &'a str, alpn: &'a [&'a [u8]]) -> Self {
        Self {
            hostname,
            alpn,
            verify_peer: true,
            keylog: false,
        }
    }

    /// Records `--insecure`.
    #[must_use]
    pub(crate) fn with_verify_peer(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }

    /// Records `SSLKEYLOGFILE`.
    #[must_use]
    pub(crate) fn with_keylog(mut self, keylog: bool) -> Self {
        self.keylog = keylog;
        self
    }
}

/// Where the QUIC handshake's cryptography comes from.
///
/// # Why this is a seam rather than a call into `crate::tls`
///
/// Specification 0.4.2 states the import rule for this directory without an
/// exception: a protocol module imports no TLS, and `protocols/mod.rs` is the
/// only permitted importer. QUIC embeds TLS 1.3 in the transport rather than
/// layering it beneath, so obeying that rule needs a seam -- and a seam is
/// what specification 0.3.3's pattern P12 asks for anyway. The production
/// implementor belongs to `crate::conn`, which already owns the TLS wiring for
/// every other filter; until it lands, the QUIC row of
/// [`TransportRegistry`] stays unfilled for exactly the reason that module's
/// own documentation gives, and this trait is the shape that fills it.
///
/// The return type names `quinn` and nothing else. `quinn::ClientConfig` wraps
/// an `Arc<dyn quinn::crypto::ClientConfig>`, so the implementor chooses the
/// provider and this module never sees a TLS type at all.
///
/// # The `Send + Sync` supertraits
///
/// Held behind an [`Arc`] alongside the connection, and reached from a
/// transfer task on the multi-thread runtime specification 0.8.3 prescribes,
/// so both bounds are load-bearing rather than defensive.
pub(crate) trait QuicCrypto: fmt::Debug + Send + Sync {
    /// The client configuration for one connection attempt.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SslConnectError`] for a configuration the provider
    /// refuses, and [`CURLcode::PeerFailedVerification`] where a trust anchor
    /// cannot be established at all -- the two codes
    /// `lib/vquic/vquic-tls.c` reports for the same conditions.
    fn client_config(
        &self,
        request: &QuicCryptoRequest<'_>,
    ) -> CodeResult<quinn::ClientConfig>;
}

/// Where the datagram socket comes from.
///
/// # `AsyncUdpSocket` is the named abstraction, and it is used literally
///
/// Specification 0.8.3's directive is *"HTTP/3 via quinn and h3 using
/// `AsyncUdpSocket`"* -- the named socket abstraction, not an ad-hoc UDP
/// wrapper. So this factory hands back `Arc<dyn AsyncUdpSocket>` and
/// [`QuicSession`] builds its endpoint with
/// `quinn::Endpoint::new_with_abstract_socket`, which is the entry point that
/// takes one. Nothing in this module reads or writes a datagram by any other
/// route.
///
/// # Why the `conn/socket.rs` UDP filter is not reused directly
///
/// `cf_udp_create` produces a filter owning an `OsSocket`, which is a raw
/// descriptor. Adopting a raw descriptor into a `tokio::net::UdpSocket`
/// requires `FromRawFd`, which is `unsafe`, and specification 0.8.2 forbids
/// `unsafe` outside the FFI island without exception -- so the descriptor
/// cannot cross that boundary here. [`Socket2UdpFactory`] therefore creates
/// the socket through the SAME crate that filter uses, `socket2`, by the safe
/// constructors, and converts it onward through
/// `std::net::UdpSocket: From<socket2::Socket>` and
/// `tokio::net::UdpSocket::from_std`. There is no `libc` call and no `unsafe`
/// block on the path, which is the constraint that actually binds.
pub(crate) trait QuicSocketFactory: fmt::Debug + Send + Sync {
    /// Binds a datagram socket able to reach `peer`.
    ///
    /// The family follows `peer`, so an IPv6 destination gets an IPv6 socket:
    /// `socket_open` does the same from `addr->family`
    /// (`lib/cf-socket.c:308-383`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] when the socket cannot be created or
    /// bound, and [`CURLcode::FailedInit`] when there is no reactor to
    /// register it with -- see [`Socket2UdpFactory::bind`] for why the second
    /// is checked rather than left to panic.
    fn bind(&self, peer: SocketAddr) -> CodeResult<Arc<dyn AsyncUdpSocket>>;
}

/// The production [`QuicSocketFactory`]: a `socket2`-created, `tokio`-driven
/// datagram socket presented as an [`AsyncUdpSocket`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: QuicTransportProvider::new's default socket factory
pub(crate) struct Socket2UdpFactory;

impl QuicSocketFactory for Socket2UdpFactory {
    /// Creates, configures and binds the socket, then registers it with the
    /// reactor.
    ///
    /// The reactor check is FIRST and is the reason this returns a code rather
    /// than panicking: `tokio::net::UdpSocket::from_std` panics when no
    /// runtime is entered, and specification 0.8.2 admits no `panic!` on a
    /// production path. `Handle::try_current` answers the same question
    /// without the panic, and its absence is a configuration failure --
    /// [`CURLcode::FailedInit`] -- rather than a network one.
    ///
    /// Every code here comes from [`QuicFailure`] rather than being written as
    /// a `CURLcode` directly, so that the mapping table stays the single place
    /// a condition's code is decided.
    fn bind(&self, peer: SocketAddr) -> CodeResult<Arc<dyn AsyncUdpSocket>> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| QuicFailure::Init.code())?;

        let (domain, local) = match peer {
            SocketAddr::V4(_) => (
                socket2::Domain::IPV4,
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            ),
            SocketAddr::V6(_) => (
                socket2::Domain::IPV6,
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            ),
        };

        let socket = socket2::Socket::new(
            domain,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|_| QuicFailure::CouldntConnect.code())?;
        // `Curl_nonblock(sockfd, TRUE)` -- every socket curl opens is
        // non-blocking, and `quinn`'s contract requires it: `try_send` must be
        // able to report `WouldBlock` rather than sleeping in the reactor.
        socket
            .set_nonblocking(true)
            .map_err(|_| QuicFailure::CouldntConnect.code())?;
        socket
            .bind(&socket2::SockAddr::from(local))
            .map_err(|_| QuicFailure::CouldntConnect.code())?;

        let std_socket = std::net::UdpSocket::from(socket);
        // `from_std` needs the reactor entered, which the guard above
        // established is available.
        let entered = handle.enter();
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)
            .map_err(|_| QuicFailure::CouldntConnect.code())?;
        drop(entered);

        Ok(Arc::new(TokioUdpSocket {
            inner: tokio_socket,
        }))
    }
}

/// A `tokio` datagram socket presented as one of `quinn`'s.
///
/// Six of [`AsyncUdpSocket`]'s members are implemented and the defaults of the
/// other three are deliberately kept; see each for why.
#[derive(Debug)]
#[allow(dead_code)] // consumer: Socket2UdpFactory::bind
struct TokioUdpSocket {
    /// The reactor-registered socket.
    inner: tokio::net::UdpSocket,
}

impl AsyncUdpSocket for TokioUdpSocket {
    /// One poller per interested task, each holding its own waker.
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioUdpPoller { socket: self })
    }

    /// One datagram out.
    ///
    /// `transmit.segment_size` is ignored, and safely: this socket reports
    /// [`Self::max_transmit_segments`] of 1, so `quinn` never composes a
    /// generic-segmentation-offload batch for it. That is the same posture the
    /// C takes on every target but Linux -- `vquic_ctx_init` sets
    /// `qctx->no_gso = TRUE` unless `__linux__ && UDP_SEGMENT && HAVE_SENDMSG`
    /// (`lib/vquic/vquic.c:81-85`) -- and performance is a NON-GOAL
    /// (specification 0.1.1), so the simpler path is the right one here.
    ///
    /// `transmit.src_ip` is likewise ignored: this socket is bound to the
    /// wildcard address and never migrates, so there is no second source
    /// address to choose between.
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.inner
            .try_send_to(transmit.contents, transmit.destination)
            .map(|_| ())
    }

    /// One datagram in, into the first buffer.
    ///
    /// [`Self::max_receive_segments`] is 1, so `quinn` provides buffers sized
    /// for a single datagram and reads exactly one per call. `stride` is set to
    /// the length read, which is what a non-offloaded receive means: one
    /// datagram, so its stride is its own size.
    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut read = ReadBuf::new(&mut bufs[0]);
        match self.inner.poll_recv_from(cx, &mut read) {
            Poll::Ready(Ok(addr)) => {
                let len = read.filled().len();
                meta[0] = RecvMeta {
                    addr,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// `qctx->local_addr` -- what `CF_QUERY_IP_INFO` reports as the local
    /// half of the quadruple.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// One datagram per transmit: no generic segmentation offload.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    /// One datagram per receive: no generic receive offload, which is what
    /// `vquic_msghdr_get_udp_gro` would otherwise report
    /// (`lib/vquic/vquic.c:350-376`).
    fn max_receive_segments(&self) -> usize {
        1
    }

    /// True, and the default is kept on purpose.
    ///
    /// Claiming otherwise would let `quinn` enable path-MTU discovery on the
    /// strength of a promise this socket cannot make: suppressing
    /// fragmentation needs `IP_DONTFRAG` or `IPV6_DONTFRAG`, which `socket2
    /// 0.6.5` does not expose portably across all four mandated targets.
    /// Reporting the truth costs a larger initial datagram and nothing else.
    fn may_fragment(&self) -> bool {
        true
    }
}

/// Write-readiness for one interested task.
#[derive(Debug)]
#[allow(dead_code)] // consumer: TokioUdpSocket::create_io_poller
struct TokioUdpPoller {
    /// The socket whose readiness is being watched.
    socket: Arc<TokioUdpSocket>,
}

impl UdpPoller for TokioUdpPoller {
    /// `poll_send_ready` registers `cx`'s waker with the reactor and may be
    /// called any number of times, which is exactly [`UdpPoller`]'s contract.
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        self.socket.inner.poll_send_ready(cx)
    }
}

/// The waker a synchronous filter hands an asynchronous engine.
///
/// # Why this exists at all
///
/// [`ConnFilter`] is synchronous, because `struct Curl_cftype`'s twelve
/// callbacks are: curl drives them from its own event loop and each returns
/// "not yet" rather than blocking. `quinn` and `h3` are asynchronous.
/// Specification 0.1.2 names the join explicitly -- *"Async is used for the
/// transitions that C implements as re-entrant polling"* -- so a stored future
/// is polled once per filter call with this waker, and a `Poll::Pending`
/// becomes the `Ok(false)` that [`ConnFilter::connect`] already means.
///
/// The flag is what makes the arrangement correct rather than merely
/// convenient: a future that completes between two filter calls sets it, so
/// the next call knows to poll again instead of waiting for an event that has
/// already happened. It is read and cleared by [`Self::take_woken`].
#[derive(Debug, Default)]
pub(crate) struct FilterWaker {
    /// Set by the executor-side wake, cleared by the filter-side read.
    woken: AtomicBool,
}

impl futures::task::ArcWake for FilterWaker {
    fn wake_by_ref(arc: &Arc<Self>) {
        arc.woken.store(true, Ordering::SeqCst);
    }
}

impl FilterWaker {
    /// True if a wake arrived since the last read, clearing the flag.
    fn take_woken(&self) -> bool {
        self.woken.swap(false, Ordering::SeqCst)
    }

    /// Polls `future` exactly once with this waker.
    ///
    /// Returns [`Poll::Pending`] without blocking, which is the whole point:
    /// the caller is a synchronous filter callback and must return to curl's
    /// event loop rather than park.
    fn poll_once<F: Future + ?Sized>(
        self: &Arc<Self>,
        future: Pin<&mut F>,
    ) -> Poll<F::Output> {
        let waker: Waker = futures::task::waker(Arc::clone(self));
        let mut cx = TaskContext::from_waker(&waker);
        future.poll(&mut cx)
    }
}

// ---------------------------------------------------------------------------
// 8. The QUIC session -- `struct cf_ngtcp2_ctx`'s transport half
//    (`lib/vquic/curl_ngtcp2.c:111-146`) and `cf_ngtcp2_connect` (`:2661`).

/// `h3`'s request sender over `h3-quinn`, named once so the bound does not
/// have to be re-derived at every use site.
type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// `h3`'s connection driver over `h3-quinn`.
type H3Conn = h3::client::Connection<h3_quinn::Connection, Bytes>;

/// The future `h3::client::Builder::build` returns, boxed so that it can be
/// stored in a filter and polled re-entrantly.
type H3Build = Pin<
    Box<
        dyn Future<
                Output = Result<(H3Conn, H3Send), h3::error::ConnectionError>,
            > + Send,
    >,
>;

/// Where a QUIC connection is in its life.
///
/// The C keeps the same information in flags on `struct cf_ngtcp2_ctx` --
/// `initialized`, `tls_handshake_complete`, `shutdown_started` -- plus a
/// nullable `qconn` and `h3conn`. A sum type makes the impossible
/// combinations unrepresentable: there is no state with an `h3conn` and no
/// `qconn`, and the C has no defence against one beyond convention.
enum SessionState {
    /// Nothing has been attempted yet -- `!ctx->qconn`.
    Idle,
    /// The QUIC handshake is in flight. `quinn::Connecting` is the future;
    /// boxed so the filter can hold it across calls.
    Handshaking(Pin<Box<quinn::Connecting>>),
    /// QUIC is up and the HTTP/3 control, encoder and decoder streams are
    /// being established -- the successor of `init_ngh3_conn`
    /// (`lib/vquic/curl_ngtcp2.c:1320-1360`), whose four failures the C
    /// reports as `"error creating HTTP/3 control stream"` and its three
    /// siblings.
    Establishing {
        /// The live QUIC connection, kept so that the address and statistics
        /// queries can be answered while HTTP/3 is still coming up.
        conn: quinn::Connection,
        /// `h3::client::Builder::build`, in flight.
        build: H3Build,
    },
    /// Both are up: this is `cf->connected`.
    Ready {
        /// The live QUIC connection.
        conn: quinn::Connection,
        /// The request sender. Cloneable, which is what makes HTTP/3
        /// multiplexing work: one connection, many concurrent streams.
        send: H3Send,
    },
    /// The connection is gone -- `ctx->shutdown_started` and beyond.
    Closed,
}

/// Deliberately terse: neither `quinn::Connecting` nor `H3Send` is [`Debug`],
/// and printing a live connection would print its peer address into a log that
/// may be shared. The state NAME is what a trace line needs.
impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Idle => "Idle",
            Self::Handshaking(_) => "Handshaking",
            Self::Establishing { .. } => "Establishing",
            Self::Ready { .. } => "Ready",
            Self::Closed => "Closed",
        };
        f.write_str(name)
    }
}

/// One QUIC connection and the HTTP/3 layer over it.
///
/// The successor of the transport half of `struct cf_ngtcp2_ctx`: the endpoint,
/// the connection, the HTTP/3 sender, the four timestamps
/// `cf_ngtcp2_query` reports and the stream budget `CF_QUERY_MAX_CONCURRENT`
/// answers from.
///
/// Every field is owned and typed. There is no `void *`, no
/// [`std::any::Any`](std::any) and nothing to downcast, which is
/// specification 0.3.3's pattern P2 applied to the one filter the C leaves
/// most exposed to it.
#[derive(Debug)]
pub(crate) struct QuicSession {
    /// The `quinn` endpoint, built over an [`AsyncUdpSocket`] from the
    /// injected [`QuicSocketFactory`].
    endpoint: quinn::Endpoint,
    /// Where the connection is in its life.
    state: SessionState,
    /// The one address this session may use -- `Curl_cf_quic_create`'s
    /// contract: *"It MUST use only the supplied `ai` for its connection
    /// attempt."*
    peer: SocketAddr,
    /// The name validated and sent as SNI.
    hostname: String,
    /// `qctx->local_addr`, read from the socket once it is bound.
    local_addr: SocketAddr,
    /// `ctx->started_at` -- when this attempt began.
    ///
    /// Stamped twice, exactly as the C does: [`Self::new`] gives it the reading
    /// the caller already holds so that no field is ever uninitialised, and
    /// [`Self::start_handshake`] re-stamps it at the moment
    /// `lib/vquic/curl_ngtcp2.c:2688` does. Both the handshake deadline and
    /// `connect_reply_ms` measure from it.
    started_at: CurlTime,
    /// `s->handshake_timeout`, in milliseconds
    /// (`lib/vquic/curl_ngtcp2.c:471-472`).
    ///
    /// The C picks `data->set.connecttimeout` when it is positive and
    /// [`QUIC_HANDSHAKE_TIMEOUT_MS`] otherwise; the default is that fallback
    /// and [`Self::with_handshake_timeout_ms`] is where a configured
    /// connect timeout arrives. Enforced against the INJECTED clock in
    /// [`Self::poll_ready`] rather than by a timer, which is what makes it
    /// deterministic in a test and what keeps this module free of a
    /// `SystemTime::now`.
    ///
    /// Typed `i64` rather than through the `timediff_t` alias, because that
    /// alias lives in `crate::util::timediff`, which is not among this
    /// module's declared dependencies; `timediff_ms` returns the same width and
    /// the two unify without an import. [`QUIC_HANDSHAKE_TIMEOUT_MS`] is
    /// declared the same way for the same reason.
    handshake_timeout_ms: i64,
    /// `ctx->handshake_at` -- when the handshake finished, zero until then.
    handshake_at: CurlTime,
    /// `qctx->first_byte_at` -- when the first byte arrived from the peer.
    first_byte_at: CurlTime,
    /// `qctx->got_first_byte`.
    got_first_byte: bool,
    /// `ctx->scid`, drawn from the injected [`Rng`] so that a test sees a
    /// reproducible identifier and therefore a reproducible qlog filename.
    #[allow(dead_code)]
    // read by QuicSession::scid, which the qlog name and --trace need
    scid: Vec<u8>,
    /// The qlog file, held open for the life of the session. `ctx->qlogfd` is
    /// the C's equivalent and is closed in `cf_ngtcp2_ctx_close`.
    #[allow(dead_code)]
    // read by QuicSession::has_qlog; the handle is held to keep the file open
    qlog: Option<std::fs::File>,
    /// `ctx->max_bidi_streams`, learned from the peer's transport parameters.
    max_bidi_streams: u64,
    /// `ctx->used_bidi_streams`, which QUIC counts over the whole lifetime of
    /// the connection and which therefore only ever increases.
    used_bidi_streams: u64,
    /// The egress buffer, `qctx->sendbuf`.
    ///
    /// `quinn` owns packet scheduling, so this holds what a caller handed the
    /// filter before a stream existed to carry it -- the same role
    /// `Curl_bufq_init2(&qctx->sendbuf, NW_CHUNK_SIZE, NW_SEND_CHUNKS,
    /// BUFQ_OPT_SOFT_LIMIT)` gives it (`lib/vquic/vquic.c:79-80`), with the
    /// same three arguments.
    sendbuf: BufQ,
}

/// The number of bytes of connection identifier this module draws.
///
/// `ngtcp2` defaults to an 8-byte source connection identifier, and it is the
/// value the qlog filename is composed from, so it is pinned rather than
/// derived: a different length changes every qlog filename.
pub(crate) const QUIC_SCID_LEN: usize = 8;

impl QuicSession {
    /// Builds the endpoint and draws the connection identifier, without
    /// sending anything.
    ///
    /// The steps are `cf_ngtcp2_ctx_init` plus `vquic_ctx_init`, in their
    /// order: the send buffer, then the identifier, then the qlog, then the
    /// endpoint. The identifier is drawn BEFORE the qlog because the qlog file
    /// name is composed from it -- which is also the C's order, since
    /// `Curl_qlogdir(data, ctx->scid.data, ctx->scid.datalen, &ctx->qlogfd)`
    /// takes the identifier as an argument.
    ///
    /// # Errors
    ///
    /// Whatever [`QuicSocketFactory::bind`] reports;
    /// [`CURLcode::CouldntConnect`] when the bound socket has no local
    /// address; [`CURLcode::FailedInit`] when the endpoint cannot be built;
    /// and [`CURLcode::TooLarge`] from [`QlogWriter::file_name`].
    pub(crate) fn new(
        peer: SocketAddr,
        hostname: &str,
        now: CurlTime,
        rng: &mut dyn Rng,
        sockets: &dyn QuicSocketFactory,
        qlog: &QlogWriter,
    ) -> CodeResult<Self> {
        // `Curl_bufq_init2(&qctx->sendbuf, NW_CHUNK_SIZE, NW_SEND_CHUNKS,
        // BUFQ_OPT_SOFT_LIMIT)`.
        let sendbuf =
            BufQ::with_opts(NW_CHUNK_SIZE, NW_SEND_CHUNKS, NW_SEND_OPTS);

        // `ctx->scid`, from the INJECTED entropy: `rand_bytes` reproduces
        // `Curl_rand_bytes`'s byte order exactly, so a `TestRng` gives a
        // deterministic identifier and hence a deterministic qlog name.
        let mut scid = vec![0_u8; QUIC_SCID_LEN];
        rand_bytes(rng, &mut scid);

        // `Curl_qlogdir(data, ctx->scid.data, ctx->scid.datalen,
        // &ctx->qlogfd)`.
        let qlog_file = qlog.open(&scid)?;

        let socket = sockets.bind(peer)?;
        let local_addr = socket
            .local_addr()
            .map_err(|_| QuicFailure::CouldntConnect.code())?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|_| QuicFailure::Init.code())?;

        Ok(Self {
            endpoint,
            state: SessionState::Idle,
            peer,
            hostname: hostname.to_owned(),
            local_addr,
            started_at: now,
            handshake_timeout_ms: QUIC_HANDSHAKE_TIMEOUT_MS,
            handshake_at: CurlTime::ZERO,
            first_byte_at: CurlTime::ZERO,
            got_first_byte: false,
            scid,
            qlog: qlog_file,
            max_bidi_streams: 0,
            used_bidi_streams: 0,
            sendbuf,
        })
    }

    /// `s->handshake_timeout = (data->set.connecttimeout > 0) ?
    /// data->set.connecttimeout * NGTCP2_MILLISECONDS : QUIC_HANDSHAKE_TIMEOUT`
    /// (`lib/vquic/curl_ngtcp2.c:471-472`).
    ///
    /// The C's conditional is reproduced HERE rather than at the call site so
    /// that the "not positive means the fallback" reading cannot be lost: a
    /// zero or negative argument leaves [`QUIC_HANDSHAKE_TIMEOUT_MS`] in place,
    /// exactly as the C's `> 0` test does. `CURLOPT_CONNECTTIMEOUT` is a
    /// `long` of SECONDS and `CURLOPT_CONNECTTIMEOUT_MS` is milliseconds; this
    /// takes the millisecond form, which is what the C multiplies up to.
    #[allow(dead_code)] // consumer: easy/setopt.rs's CURLOPT_CONNECTTIMEOUT_MS
    pub(crate) fn with_handshake_timeout_ms(mut self, ms: i64) -> Self {
        if ms > 0 {
            self.handshake_timeout_ms = ms;
        }
        self
    }

    /// The handshake deadline in force, in milliseconds.
    #[allow(dead_code)] // consumer: the deadline tests and CURLINFO reporting
    pub(crate) const fn handshake_timeout_ms(&self) -> i64 {
        self.handshake_timeout_ms
    }

    /// The source connection identifier, as the qlog filename is composed
    /// from it.
    #[allow(dead_code)] // consumer: --trace output and the qlog name
    pub(crate) fn scid(&self) -> &[u8] {
        &self.scid
    }

    /// Whether a qlog is being written for this session.
    #[allow(dead_code)] // consumer: the filter's trace output
    pub(crate) const fn has_qlog(&self) -> bool {
        self.qlog.is_some()
    }

    /// `qctx->local_addr`.
    #[allow(dead_code)] // consumer: CF_QUERY_IP_INFO's quadruple
    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The one peer address this session may use.
    pub(crate) const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The name validated and sent as SNI.
    #[allow(dead_code)] // consumer: the SNI trace line
    pub(crate) fn hostname(&self) -> &str {
        &self.hostname
    }

    /// True once both QUIC and HTTP/3 are up -- `cf->connected`.
    pub(crate) const fn is_ready(&self) -> bool {
        matches!(self.state, SessionState::Ready { .. })
    }

    /// True once the session has been closed and cannot be used again.
    pub(crate) const fn is_closed(&self) -> bool {
        matches!(self.state, SessionState::Closed)
    }

    /// `ctx->handshake_at`, zero until the handshake completed --
    /// `CF_QUERY_TIMER_APPCONNECT`.
    pub(crate) const fn handshake_at(&self) -> CurlTime {
        self.handshake_at
    }

    /// `qctx->first_byte_at`, zero until a byte arrived --
    /// `CF_QUERY_TIMER_CONNECT`.
    pub(crate) const fn first_byte_at(&self) -> CurlTime {
        self.first_byte_at
    }

    /// `qctx->got_first_byte`.
    #[allow(dead_code)] // consumer: CF_QUERY_CONNECT_REPLY_MS's guard
    pub(crate) const fn got_first_byte(&self) -> bool {
        self.got_first_byte
    }

    /// `CF_QUERY_CONNECT_REPLY_MS` (`lib/vquic/curl_ngtcp2.c:2799-2807`).
    ///
    /// ```c
    /// if(ctx->q.got_first_byte) {
    ///   timediff_t ms = curlx_ptimediff_ms(&ctx->q.first_byte_at,
    ///                                      &ctx->started_at);
    ///   *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    /// }
    /// else *pres1 = -1;
    /// ```
    ///
    /// The `-1` is not an error: `lib/cfilters.h:147` documents it as "until
    /// determined".
    pub(crate) fn connect_reply_ms(&self) -> i64 {
        if !self.got_first_byte {
            return -1;
        }
        let ms = timediff_ms(self.first_byte_at, self.started_at);
        ms.min(i64::from(i32::MAX))
    }

    /// Records that a byte arrived from the peer.
    ///
    /// `qctx->got_first_byte` is set ONCE and `first_byte_at` with it, which
    /// is what makes [`Self::connect_reply_ms`] a measurement of the first
    /// reply rather than of the last.
    pub(crate) fn note_first_byte(&mut self, now: CurlTime) {
        if !self.got_first_byte {
            self.got_first_byte = true;
            self.first_byte_at = now;
        }
    }

    /// `CF_QUERY_MAX_CONCURRENT` (`lib/vquic/curl_ngtcp2.c:2773-2796`).
    ///
    /// The C's three cases, in its order, and the comment that explains the
    /// arithmetic: *"Set after transport params arrived and continually updated
    /// by callback. QUIC counts the number over the lifetime of the
    /// connection, ever increasing. We count the *open* transfers plus the
    /// budget for new ones."*
    ///
    /// 1. no connection, or shutting down: `0`;
    /// 2. the peer's limit is known: `attached + (max - used)`, clamped to
    ///    [`i32::MAX`];
    /// 3. the parameters have not arrived: the multi handle's own default,
    ///    which arrives as `fallback` because `crate::multi` must not be named
    ///    from here.
    pub(crate) fn max_concurrent(&self, attached: u64, fallback: i32) -> i32 {
        if !self.is_ready() {
            return 0;
        }
        if self.max_bidi_streams == 0 {
            return fallback;
        }
        let available =
            self.max_bidi_streams.saturating_sub(self.used_bidi_streams);
        let total = attached.saturating_add(available);
        i32::try_from(total).unwrap_or(i32::MAX)
    }

    /// Records the peer's bidirectional stream limit.
    pub(crate) fn set_max_bidi_streams(&mut self, max: u64) {
        self.max_bidi_streams = max;
    }

    /// `ctx->used_bidi_streams++` -- monotonic, as QUIC's own counter is.
    pub(crate) fn note_stream_opened(&mut self) {
        self.used_bidi_streams = self.used_bidi_streams.saturating_add(1);
    }

    /// `ctx->used_bidi_streams`.
    #[allow(dead_code)] // consumer: CF_QUERY_MAX_CONCURRENT's budget accounting
    pub(crate) const fn used_bidi_streams(&self) -> u64 {
        self.used_bidi_streams
    }

    /// The egress buffer, shared.
    pub(crate) const fn sendbuf(&self) -> &BufQ {
        &self.sendbuf
    }

    /// The egress buffer, mutable.
    #[allow(dead_code)] // consumer: the transfer core's egress path
    pub(crate) fn sendbuf_mut(&mut self) -> &mut BufQ {
        &mut self.sendbuf
    }

    /// The connected quadruple -- `CF_QUERY_IP_INFO`.
    pub(crate) fn ip_quadruple(&self) -> IpQuadruple {
        IpQuadruple {
            remote_ip: self.peer.ip().to_string(),
            local_ip: self.local_addr.ip().to_string(),
            remote_port: self.peer.port(),
            local_port: self.local_addr.port(),
            transport: H3_TRANSPORT,
        }
    }

    /// Starts the handshake, if it has not started.
    ///
    /// `quinn::Endpoint::connect(addr, server_name)` composes and sends the
    /// Initial packet, so this is the point at which bytes first leave. The
    /// crypto arrives from the injected [`QuicCrypto`], which is why this
    /// takes one rather than reaching for a TLS module.
    ///
    /// # Errors
    ///
    /// Whatever [`QuicCrypto::client_config`] reports, and
    /// [`CURLcode::QuicConnectError`] when `quinn` refuses the destination --
    /// which is the code nine sites in `lib/vquic/curl_ngtcp2.c` report for a
    /// connection that cannot be started.
    pub(crate) fn start_handshake(
        &mut self,
        crypto: &dyn QuicCrypto,
        verify_peer: bool,
        keylog: bool,
        now: CurlTime,
    ) -> CodeResult<()> {
        if !matches!(self.state, SessionState::Idle) {
            return Ok(());
        }
        // `ctx->started_at = *Curl_pgrs_now(data)` immediately before
        // `cf_connect_start` (`lib/vquic/curl_ngtcp2.c:2688`), which is also
        // where `s->initial_ts` is stamped and therefore where ngtcp2's
        // handshake timeout begins to run. Re-stamping HERE rather than
        // trusting the reading [`Self::new`] took matters whenever the two
        // differ: the deadline and `connect_reply_ms` both measure from the
        // attempt, not from the allocation.
        self.started_at = now;
        let alpn: [&[u8]; 1] = [H3_ALPN];
        let request = QuicCryptoRequest::new(&self.hostname, &alpn)
            .with_verify_peer(verify_peer)
            .with_keylog(keylog);
        let mut config = crypto.client_config(&request)?;
        // `quic_settings` is applied to the CLIENT configuration rather than
        // to the endpoint, because `quinn` carries the transport parameters per
        // connection while the endpoint holds only what every connection over
        // that socket shares. The C has one connection per filter, so the two
        // placements are equivalent there and this is the narrower of them.
        config.transport_config(Arc::new(transport_config()));
        self.endpoint.set_default_client_config(config);
        let connecting = self
            .endpoint
            .connect(self.peer, &self.hostname)
            .map_err(|_| CURLcode::QuicConnectError)?;
        self.state = SessionState::Handshaking(Box::pin(connecting));
        Ok(())
    }

    /// True when the handshake deadline has passed and the session is still
    /// not usable.
    ///
    /// A session that is already `Ready` or `Closed` can never expire: the
    /// first has nothing left to wait for and the second has already reported
    /// whatever went wrong, and re-reporting a timeout over a live connection
    /// would abort a transfer that is making progress. `Idle` cannot expire
    /// either -- the C starts its clock in `quic_settings`, which runs as part
    /// of the connect, so nothing is being waited on before then.
    fn handshake_expired(&self, now: CurlTime) -> bool {
        match self.state {
            SessionState::Handshaking(_)
            | SessionState::Establishing { .. } => {
                timediff_ms(now, self.started_at) >= self.handshake_timeout_ms
            }
            SessionState::Idle
            | SessionState::Ready { .. }
            | SessionState::Closed => false,
        }
    }

    /// Makes what progress it can towards being ready, without blocking.
    ///
    /// The successor of `cf_ngtcp2_connect`'s middle: each call polls the one
    /// future the current state holds and advances at most one step, returning
    /// `false` for "not yet" -- which is precisely what
    /// [`ConnFilter::connect`]'s `Ok(false)` means and what the C's
    /// `*done = FALSE` meant.
    ///
    /// # Errors
    ///
    /// [`CURLcode::QuicConnectError`] for a failed handshake AND for HTTP/3
    /// control streams that cannot be established -- `init_ngh3_conn` reports
    /// the same code as `cf_connect_start` does
    /// (`lib/vquic/curl_ngtcp2.c:1307-1358`, `:2604-2623`);
    /// [`CURLcode::PeerFailedVerification`] for a rejected certificate
    /// (`:2709-2711` through `ctx->tls_vrfy_result`);
    /// [`CURLcode::CouldntConnect`] and [`CURLcode::WeirdServerReply`] for a
    /// `CONNECTION_CLOSE` received during the handshake, which
    /// [`classify_connection_error`] separates exactly as the C's draining-
    /// period ladder does (`:2718-2745`).
    pub(crate) fn poll_ready(
        &mut self,
        waker: &Arc<FilterWaker>,
        now: CurlTime,
    ) -> CodeResult<bool> {
        // `s->handshake_timeout`: ngtcp2 enforces it from the clock curl feeds
        // it, and the same is done here from the INJECTED clock. The check
        // precedes the poll so that a connection which has already run out of
        // time is not advanced one more step first, and it covers
        // `Establishing` as well as `Handshaking` because the C's timeout runs
        // until the connection is usable -- `cf->connected` is set after
        // `init_ngh3_conn`, not after the TLS handshake.
        if self.handshake_expired(now) {
            self.state = SessionState::Closed;
            return Err(QuicFailure::HandshakeTimeout.code());
        }
        match &mut self.state {
            SessionState::Idle => Ok(false),
            SessionState::Handshaking(connecting) => {
                match waker.poll_once(connecting.as_mut()) {
                    Poll::Pending => Ok(false),
                    Poll::Ready(Ok(conn)) => {
                        // The handshake completing IS the first byte from the
                        // peer, and `ctx->handshake_at` is stamped in
                        // `cf_ngtcp2_handshake_completed`.
                        self.note_first_byte(now);
                        self.handshake_at = now;
                        self.set_max_bidi_streams(QUIC_MAX_STREAMS);
                        let build: H3Build = Box::pin(build_h3(conn.clone()));
                        self.state = SessionState::Establishing { conn, build };
                        Ok(false)
                    }
                    Poll::Ready(Err(error)) => {
                        self.state = SessionState::Closed;
                        Err(classify_connection_error(&error).code())
                    }
                }
            }
            SessionState::Establishing { conn, build } => {
                match waker.poll_once(build.as_mut()) {
                    Poll::Pending => Ok(false),
                    Poll::Ready(Ok((driver, send))) => {
                        let conn = conn.clone();
                        spawn_h3_driver(driver);
                        self.state = SessionState::Ready { conn, send };
                        Ok(true)
                    }
                    Poll::Ready(Err(_)) => {
                        self.state = SessionState::Closed;
                        // `init_ngh3_conn` returns CURLE_QUIC_CONNECT_ERROR
                        // from all five of its stream failures
                        // (`lib/vquic/curl_ngtcp2.c:1307-1358`) -- not
                        // CURLE_HTTP3, which the C reserves for a stream that
                        // fails once a transfer is under way (`:1389-1396`,
                        // `:1766`). `h3::client::Builder::build` covers exactly
                        // those five, so the code is the C's.
                        Err(QuicFailure::Handshake.code())
                    }
                }
            }
            SessionState::Ready { .. } => Ok(true),
            SessionState::Closed => Err(CURLcode::QuicConnectError),
        }
    }

    /// The live QUIC connection, when there is one.
    pub(crate) const fn connection(&self) -> Option<&quinn::Connection> {
        match &self.state {
            SessionState::Establishing { conn, .. }
            | SessionState::Ready { conn, .. } => Some(conn),
            SessionState::Idle
            | SessionState::Handshaking(_)
            | SessionState::Closed => None,
        }
    }

    /// A clone of the request sender, for opening one more stream.
    ///
    /// `h3::client::SendRequest` is `Clone` precisely so that concurrent
    /// streams can be opened from it, which is what `CF_TYPE_MULTIPLEX` on
    /// this filter promises.
    pub(crate) fn sender(&self) -> Option<H3Send> {
        match &self.state {
            SessionState::Ready { send, .. } => Some(send.clone()),
            SessionState::Idle
            | SessionState::Handshaking(_)
            | SessionState::Establishing { .. }
            | SessionState::Closed => None,
        }
    }

    /// `cf_ngtcp2_close` (`lib/vquic/curl_ngtcp2.c:2278-2291`): close now,
    /// without negotiating.
    ///
    /// The application error code is [`H3Error::NO_ERROR`], which is what
    /// `nghttp3_err_infer_quic_app_error_code` yields for a clean local close,
    /// and the reason string is empty because the C sends none.
    pub(crate) fn close(&mut self) {
        if let Some(conn) = self.connection() {
            conn.close(
                quinn::VarInt::from_u64(H3Error::NO_ERROR.as_u64())
                    .unwrap_or_else(|_| quinn::VarInt::from_u32(0)),
                b"",
            );
        }
        self.state = SessionState::Closed;
        self.sendbuf.reset();
    }
}

/// `quinn::EndpointConfig` for this module.
///
/// The defaults are kept, and the one thing worth recording is what is NOT set:
/// no `max_udp_payload_size` override, because
/// [`MAX_UDP_PAYLOAD_SIZE`] is the buffer size this module reads INTO rather
/// than a transport parameter, and overriding the parameter would change the
/// bytes of the transport-parameters extension in the ClientHello -- which
/// specification 0.6.7's byte-exact oracle would see.
fn endpoint_config() -> quinn::EndpointConfig {
    quinn::EndpointConfig::default()
}

/// `quic_settings(ctx, data, pktx)` (`lib/vquic/curl_ngtcp2.c:455-491`).
///
/// The C fills an `ngtcp2_settings` and an `ngtcp2_transport_params`; `quinn`
/// exposes the same knobs through one `TransportConfig`, and the mapping is
/// one-for-one where a successor exists. This MATTERS beyond tidiness: the
/// transport parameters travel in the ClientHello's QUIC extension, so
/// `quinn`'s defaults would put different bytes on the wire from curl's --
/// specification 0.6.7's byte-exact oracle would see all five of the
/// differences below.
///
/// | C | value | `quinn` | `quinn` default |
/// |---|-------|---------|-----------------|
/// | `t->initial_max_data` | `s->max_window` = [`H3_CONN_WINDOW_SIZE_MAX`] | `receive_window` | `VarInt::MAX` |
/// | `t->initial_max_stream_data_bidi_local` and `_remote` | [`H3_STREAM_WINDOW_SIZE_INITIAL`] | `stream_receive_window` | 1,250,000 |
/// | `t->initial_max_streams_bidi` | [`QUIC_MAX_STREAMS`] | `max_concurrent_bidi_streams` | 100 |
/// | `t->initial_max_streams_uni` | [`QUIC_MAX_STREAMS`] | `max_concurrent_uni_streams` | 100 |
/// | `t->max_idle_timeout = 0` -- *"no idle timeout from our side"* | none | `max_idle_timeout(None)` | `Some(30 s)` |
///
/// `t->initial_max_stream_data_uni = t->initial_max_data` has no separate
/// successor: `quinn` applies `stream_receive_window` to both directions and to
/// both stream kinds, so the two C values collapse into one and the
/// bidirectional value -- the smaller, and the one every request stream uses --
/// is the one that must be right.
///
/// Four C settings deliberately have NO successor, and each is recorded rather
/// than dropped silently:
///
/// * `s->max_window` and `s->max_stream_window = 0` bound ngtcp2's automatic
///   window tuning, which the comment at `:474` says the assignment DISABLES.
///   `quinn` has no automatic tuning to disable, so the disabled state is
///   already what it does.
/// * `s->handshake_timeout` is enforced by
///   [`QuicSession::handshake_expired`] against the injected clock, because
///   `quinn 0.11` has no handshake-timeout knob and a timer would need a clock
///   this module is not allowed to read.
/// * `s->no_pmtud = FALSE` means path-MTU discovery stays ON, which is
///   `quinn`'s default `mtu_discovery_config`.
/// * `s->glitch_ratelim_*` (`:478-480`) are ngtcp2-specific rate limits behind
///   `NGTCP2_SETTINGS_V3`, added for one server's behaviour; there is no
///   `quinn` equivalent and no wire effect.
///
/// `s->initial_ts` and `s->log_printf` are plumbing rather than configuration:
/// the first is the clock reading ngtcp2 needs handed to it and `quinn` reads
/// its own, the second is the `DEBUG_NGTCP2` printer replaced by
/// [`crate::trace`]. `s->qlog_write` is [`QlogWriter`]'s job.
fn transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config
        .receive_window(varint_saturating(H3_CONN_WINDOW_SIZE_MAX))
        .stream_receive_window(varint_saturating(H3_STREAM_WINDOW_SIZE_INITIAL))
        .max_concurrent_bidi_streams(varint_saturating(QUIC_MAX_STREAMS))
        .max_concurrent_uni_streams(varint_saturating(QUIC_MAX_STREAMS))
        .max_idle_timeout(None);
    config
}

/// A `quinn::VarInt` from a `u64`, clamped to the QUIC varint maximum.
///
/// Every value this module passes is far below `2^62 - 1`, so the clamp never
/// fires; it exists because `VarInt::from_u64` is fallible and this crate
/// admits no `unwrap`. Clamping rather than falling back to zero is the safe
/// direction for all four call sites -- each is a window or a stream budget,
/// where too large merely fails to restrict and zero would stall the
/// connection outright.
fn varint_saturating(value: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(value).unwrap_or(quinn::VarInt::MAX)
}

/// `init_ngh3_conn` (`lib/vquic/curl_ngtcp2.c:1320-1360`): the HTTP/3 control,
/// QPACK encoder and QPACK decoder streams.
///
/// `h3::client::Builder::build` opens all three and sends the SETTINGS frame,
/// which is the whole of what the C's four `nghttp3_conn_bind_*` calls do.
/// The one setting this client announces is
/// [`H3_MAX_FIELD_SECTION_SIZE`]; see that constant for why the value is the
/// unbounded one.
///
/// `send_grease` is left at `h3`'s default, which sends a reserved SETTINGS
/// entry. `nghttp3_settings_default` does the same, so the two agree.
async fn build_h3(
    conn: quinn::Connection,
) -> Result<(H3Conn, H3Send), h3::error::ConnectionError> {
    h3::client::builder()
        .max_field_section_size(H3_MAX_FIELD_SECTION_SIZE)
        .build(h3_quinn::Connection::new(conn))
        .await
}

/// Drives `h3`'s connection until it goes idle.
///
/// `h3` requires its `Connection` to be polled continuously for the control
/// and QPACK streams to make progress; `nghttp3` gets the same service from
/// curl's own event loop, which calls into it on every socket event. There is
/// no equivalent hook in [`ConnFilter`], so the driver runs as its own task on
/// the multi-thread runtime specification 0.8.3 prescribes for the multi
/// handle.
///
/// The returned error is DISCARDED here on purpose and is not lost: every
/// connection failure reaches the filter a second time through the stream
/// operations and through [`QuicSession::poll_ready`], where it is classified
/// by [`classify_connection_error`] and reported as a `CURLcode`. Reporting it
/// from a detached task as well would mean reporting it twice, to a caller
/// that has no way to receive it.
fn spawn_h3_driver(mut driver: H3Conn) {
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
}

// ---------------------------------------------------------------------------
// 9. The ordered field list, and the response projection --
//    `h3_submit` (`lib/vquic/curl_ngtcp2.c:1575-1700`) and
//    `cb_h3_recv_header` (`:1171-1234`).

/// `Curl_http_req_to_h2(&h2_headers, stream->h1.req, data)` as HTTP/3 calls it
/// (`lib/vquic/curl_ngtcp2.c:1612`).
///
/// **This is R-C, and the measurement is what settles it.** HTTP/3 and HTTP/2
/// share ONE ordered field list in the C: `h3_submit` calls
/// `Curl_http_req_to_h2` -- the same function `h2_submit` calls at
/// `lib/http2.c:2098` -- and then walks the result in order into an
/// `nghttp3_nv` array. So the order is `lib/http.c:4910-4938`'s and it is:
///
/// 1. `:method` -- always;
/// 2. `:scheme` -- unless the method is `CONNECT` and the caller fixed none;
/// 3. `:authority` -- from the request, else from the `Host:` header;
/// 4. `:path` -- when the request has one;
/// 5. every regular header, IN THE ORDER THE REQUEST WROTE THEM, minus the six
///    forbidden names and with `TE` reduced to `trailers`.
///
/// Nothing is sorted at any point, and `h3` is never given the opportunity to
/// reorder: the authoritative storage is a [`HeaderSet`], which never
/// reorders, and the conversion to `h3`'s public type happens once, in
/// [`request_for_h3`], with a check that no repeated name has been regrouped.
///
/// Delegating to [`req_to_h2`] rather than transcribing it a second time is
/// deliberate and is the same choice `protocols/ws.rs` makes about
/// `protocols/http1.rs`'s vtable: two copies of an ordering policy is two
/// places for it to drift, and the C has ONE. The pseudo-header names come
/// from [`crate::headers`] and keep their leading colons, which is
/// [`crate::headers::CURLH_PSEUDO`]'s invariant.
///
/// # Errors
///
/// Whatever [`req_to_h2`] reports, which is [`CURLcode::OutOfMemory`] at the
/// set's entry-count or total-size limit.
pub(crate) fn req_to_h3(
    request: &H1Request,
    conn_is_ssl: bool,
) -> CodeResult<HeaderSet> {
    req_to_h2(request, conn_is_ssl)
}

/// The five pseudo-header names, in the order [`req_to_h3`] emits the four
/// request ones and with `:status` last because it is a RESPONSE field.
///
/// Wire-bearing: these bytes are what QPACK encodes and what a
/// `curl_easy_header` query matches against. `rustfmt` is kept off the table so
/// that the order is part of the data rather than a formatting accident, and
/// every entry retains its leading colon, which is
/// [`crate::headers::HeaderStore::push`]'s invariant for
/// [`crate::headers::CURLH_PSEUDO`]:
/// for a pseudo-header the first byte MUST be `':'`.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: this module's tests; the order itself is req_to_h2's
pub(crate) const H3_PSEUDO_ORDER: [&[u8]; 5] = [
    HTTP_PSEUDO_METHOD,
    HTTP_PSEUDO_SCHEME,
    HTTP_PSEUDO_AUTHORITY,
    HTTP_PSEUDO_PATH,
    HTTP_PSEUDO_STATUS,
];

/// `"HTTP/3 "` -- wire-bearing, hence `#[rustfmt::skip]`.
#[rustfmt::skip]
const H3_STATUS_PREFIX: &[u8] = b"HTTP/3 ";

/// `" \r\n"` -- wire-bearing, and the TRAILING SPACE is load-bearing.
///
/// `cb_h3_recv_header` composes `"HTTP/3 " + status + " \r\n"`
/// (`lib/vquic/curl_ngtcp2.c:1199-1204`). An HTTP/1 status line has a reason
/// phrase where HTTP/3 has none, and the space is what keeps the line
/// parseable by a consumer expecting three fields.
#[rustfmt::skip]
const H3_STATUS_SUFFIX: &[u8] = b" \r\n";

/// `": "` -- the separator `cb_h3_recv_header` writes between a name and a
/// value (`lib/vquic/curl_ngtcp2.c:1219`).
#[rustfmt::skip]
const H3_COLON_SPACE: &[u8] = b": ";

/// `"\r\n"`.
#[rustfmt::skip]
const H3_CRLF: &[u8] = b"\r\n";

/// The status line written out for a response --
/// `lib/vquic/curl_ngtcp2.c:1197-1204`.
///
/// ```c
/// curlx_dyn_reset(&ctx->scratch);
/// result = curlx_dyn_addn(&ctx->scratch, STRCONST("HTTP/3 "));
/// if(!result) result = curlx_dyn_addn(&ctx->scratch, h3val.base, h3val.len);
/// if(!result) result = curlx_dyn_addn(&ctx->scratch, STRCONST(" \r\n"));
/// ```
///
/// The value written is the RAW `:status` field value, not the parsed integer:
/// the C hands `h3val` straight through, so a three-digit code arrives as its
/// own three bytes and nothing is reformatted -- which is why this takes a byte
/// slice rather than a number.
///
/// There is deliberately NO companion that composes a `":status:NNN\r"` store
/// line. `protocols/http2.rs` has one because `lib/http2.c:1512` pushes it;
/// `cb_h3_recv_header` does not push anything, so HTTP/3 has nothing to
/// compose. [`project_response`] records the measurement in full.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`DynBuf`] at its ceiling, which a status line
/// cannot reach.
pub(crate) fn status_line(
    out: &mut DynBuf,
    status_value: &[u8],
) -> CodeResult<()> {
    out.addn(H3_STATUS_PREFIX)?;
    out.addn(status_value)?;
    out.addn(H3_STATUS_SUFFIX)
}

/// One response header projected into an HTTP/1 line --
/// `lib/vquic/curl_ngtcp2.c:1216-1224`.
///
/// `name`, `": "`, `value`, `"\r\n"`. The separator carries a SPACE.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`DynBuf`] at its ceiling.
pub(crate) fn header_line(
    out: &mut DynBuf,
    name: &[u8],
    value: &[u8],
) -> CodeResult<()> {
    out.addn(name)?;
    out.addn(H3_COLON_SPACE)?;
    out.addn(value)?;
    out.addn(H3_CRLF)
}

/// One trailer projected into an HTTP/1 line.
///
/// Byte for byte what [`header_line`] writes, and a separate function for the
/// reason `protocols/http2.rs` gives for its own pair: the DESTINATION
/// differs, and that is what a reader needs to see. A trailer is stored with
/// [`CURLH_TRAILER`] and a header with [`CURLH_HEADER`].
///
/// The C conflates the two here and it is worth recording precisely, because a
/// reader comparing the files will notice: `ngh3_callbacks`
/// (`lib/vquic/curl_ngtcp2.c:1276-1300`) registers `cb_h3_recv_header` in BOTH
/// the `recv_header` and the `recv_trailer` slots, so the C writes a trailer
/// out through the identical path and with the identical bytes. The bytes are
/// therefore identical here too -- specification 0.8.1 freezes them -- and
/// what this module adds is the ORIGIN, without which `curl_easy_header`
/// cannot answer `CURLH_TRAILER` for a field that was one. That is an API-level
/// distinction the C draws elsewhere, in `lib/http2.c:1484-1497`, and not a
/// wire-level change.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`DynBuf`] at its ceiling.
pub(crate) fn trailer_line(
    out: &mut DynBuf,
    name: &[u8],
    value: &[u8],
) -> CodeResult<()> {
    header_line(out, name, value)
}

/// The CRLF that ends a response header block --
/// `cb_h3_end_headers` (`lib/vquic/curl_ngtcp2.c:1157-1159`).
///
/// The C's comment is the contract: *"add a CRLF only if we have received some
/// headers"*. So this is emitted after the fields and never instead of them.
#[rustfmt::skip]
pub(crate) const H3_END_OF_HEADERS: &[u8] = b"\r\n";

/// Whether a status code ends the response header phase.
///
/// `if(stream->status_code / 100 != 1) stream->resp_hds_complete = TRUE;`
/// (`lib/vquic/curl_ngtcp2.c:1163-1165`): an informational `1xx` response is
/// followed by another header block, so the phase is NOT complete.
pub(crate) const fn status_completes_headers(status_code: u32) -> bool {
    status_code / 100 != 1
}

/// Converts curl's ordered field list at `h3`'s boundary.
///
/// [`HeaderSet`] remains the authoritative storage. `http::Request` exists only
/// for the duration of `h3::client::SendRequest::send_request`, because that is
/// the public type `h3 0.0.8` accepts -- the same transient, checked conversion
/// `protocols/http2.rs` performs for `h2`, and documented here for the same
/// reason: `http::HeaderMap` LOWERCASES, GROUPS BY NAME and gives no ordering
/// guarantee across distinct names, so using it as storage would change the
/// bytes QPACK encodes.
///
/// `http 1.4.2` iterates distinct names in first-insertion order and the values
/// of one name in append order, so the conversion is byte-preserving whenever
/// repeated names are CONTIGUOUS. A repeated name reappearing after another
/// name is REFUSED rather than silently regrouped, because changing the QPACK
/// field order would be a wire defect and specification 0.6.7 compares the
/// bytes.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for a field list missing `:method`,
/// `:scheme` or `:authority` where they are required, for a name or value
/// `http` refuses, and for a repeated name that has been split by another.
pub(crate) fn request_for_h3(
    fields: &HeaderSet,
) -> CodeResult<http::Request<()>> {
    let method = fields
        .get(HTTP_PSEUDO_METHOD)
        .ok_or(CURLcode::BadFunctionArgument)?;
    let method = http::Method::from_bytes(method.value())
        .map_err(|_| CURLcode::BadFunctionArgument)?;
    let scheme = fields.get(HTTP_PSEUDO_SCHEME).map(|entry| entry.value());
    let authority =
        fields.get(HTTP_PSEUDO_AUTHORITY).map(|entry| entry.value());
    let path = fields
        .get(HTTP_PSEUDO_PATH)
        .map_or(b"/".as_slice(), |entry| entry.value());

    // A `CONNECT` with no `:scheme` addresses the authority alone, which is
    // RFC 9114 section 4.4's shape and is what `req_to_h3` produces for it.
    let uri = if method == http::Method::CONNECT && scheme.is_none() {
        let authority = authority.ok_or(CURLcode::BadFunctionArgument)?;
        http::Uri::try_from(authority)
            .map_err(|_| CURLcode::BadFunctionArgument)?
    } else {
        let scheme = scheme.ok_or(CURLcode::BadFunctionArgument)?;
        let authority = authority.ok_or(CURLcode::BadFunctionArgument)?;
        let mut uri = Vec::with_capacity(
            scheme
                .len()
                .saturating_add(authority.len())
                .saturating_add(path.len())
                .saturating_add(3),
        );
        uri.extend_from_slice(scheme);
        uri.extend_from_slice(b"://");
        uri.extend_from_slice(authority);
        if path.is_empty() {
            uri.extend_from_slice(b"/");
        } else {
            uri.extend_from_slice(path);
        }
        http::Uri::from_maybe_shared(uri)
            .map_err(|_| CURLcode::BadFunctionArgument)?
    };

    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .version(http::Version::HTTP_3);

    let mut completed: Vec<Vec<u8>> = Vec::new();
    let mut current: Option<Vec<u8>> = None;
    for (name, value) in fields.iter() {
        // Pseudo-headers are carried by the method and the URI above; `h3`
        // composes them itself and would reject them as ordinary fields.
        if name.first() == Some(&b':') {
            continue;
        }
        let same_group = current.as_deref().is_some_and(|open| open == name);
        if !same_group {
            if let Some(open) = current.take() {
                completed.push(open);
            }
            if completed.iter().any(|seen| seen.as_slice() == name) {
                // The regrouping this refuses is exactly the one that would
                // reorder the encoded field section.
                return Err(CURLcode::BadFunctionArgument);
            }
            current = Some(name.to_vec());
        }
        let header_name = http::header::HeaderName::from_bytes(name)
            .map_err(|_| CURLcode::BadFunctionArgument)?;
        let header_value = http::header::HeaderValue::from_bytes(value)
            .map_err(|_| CURLcode::BadFunctionArgument)?;
        builder = builder.header(header_name, header_value);
    }

    builder.body(()).map_err(|_| CURLcode::BadFunctionArgument)
}

/// Projects one received response into the HTTP/1-shaped lines curl writes
/// out, plus the store entries `curl_easy_header` answers from.
///
/// `h3 0.0.8` hands a whole `http::Response<()>` back from `recv_response`
/// rather than calling per-field as `nghttp3` does, so the projection happens
/// in one pass here where the C does it once per callback. The ORDER is
/// preserved as far as `h3`'s own type allows -- see [`request_for_h3`] for the
/// measured `http 1.4.2` iteration property -- and the status line comes FIRST
/// either way, because the C emits it from the `:status` field before any
/// ordinary field can arrive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResponseProjection {
    /// `"HTTP/3 NNN \r\n"`, then every `"name: value\r\n"`, then the CRLF that
    /// ends the block. These are the bytes handed to the client writer.
    pub(crate) written: Vec<u8>,
    /// What the header store holds, name and origin per entry, in the order
    /// they were pushed.
    pub(crate) stored: Vec<(Vec<u8>, Vec<u8>, u32)>,
    /// The parsed status code.
    pub(crate) status_code: u32,
    /// `stream->resp_hds_complete`.
    pub(crate) headers_complete: bool,
}

/// Builds a [`ResponseProjection`] from a status code and an ordered field
/// list.
///
/// The field list is a [`HeaderSet`] rather than an `http::HeaderMap`, so a
/// caller that has one keeps its order; [`project_h3_response`] is what
/// converts at `h3`'s boundary.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`DynBuf`] at its ceiling.
pub(crate) fn project_response(
    status_code: u32,
    fields: &HeaderSet,
) -> CodeResult<ResponseProjection> {
    let mut out = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
    let mut stored: Vec<(Vec<u8>, Vec<u8>, u32)> = Vec::new();

    // `cb_h3_recv_header`'s `NGHTTP3_QPACK_TOKEN__STATUS` arm: the status line
    // is written out, and NOTHING is stored for it.
    //
    // That "nothing" is measured, not assumed, and it is the one place where
    // the HTTP/3 path differs from the HTTP/2 one. `lib/http2.c:1512` calls
    // `Curl_headers_push(data_s, buffer, hlen, CURLH_PSEUDO)` for `:status`;
    // `cb_h3_recv_header` calls only `h3_xfer_write_resp_hd`
    // (`lib/vquic/curl_ngtcp2.c:1205-1207`) and never pushes. Those two are the
    // ONLY `Curl_headers_push` call sites in the whole tree outside
    // `lib/headers.c` itself, so an HTTP/3 transfer in curl 8.19.0-DEV has NO
    // pseudo-header in its store and `curl_easy_header(":status", ..)` finds
    // nothing. Storing one here would be an API-visible addition, which
    // specification 0.8.1 forbids.
    //
    // The store is populated instead by `hds_cw_collect_write`
    // (`lib/headers.c:296-308`) as it consumes those same bytes, and it skips
    // any write carrying `CLIENTWRITE_STATUS` -- which is why the status line
    // contributes bytes but no entry.
    let status_text = format!("{status_code}");
    status_line(&mut out, status_text.as_bytes())?;

    // The origin every ordinary field of THIS response carries. Derived
    // through `crate::headers::classify_origin` from the same write flags the C
    // builds, rather than by repeating its precedence: `lib/http.c:1622` adds
    // `CLIENTWRITE_1XX` exactly when `data->req.httpcode / 100 == 1`, and the
    // collector then chooses `CURLH_1XX` over `CURLH_HEADER`. A 1xx field
    // tagged `CURLH_HEADER` would be answered for a request that asked for
    // final-response headers only, so the distinction is observable.
    let mut write_flags = CLIENTWRITE_HEADER;
    if status_code / 100 == 1 {
        write_flags |= CLIENTWRITE_1XX;
    }
    let origin = classify_origin(write_flags).unwrap_or(CURLH_HEADER);

    // The `else` arm: every ordinary field, in order.
    for (name, value) in fields.iter() {
        if name.first() == Some(&b':') {
            continue;
        }
        header_line(&mut out, name, value)?;
        stored.push((name.to_vec(), value.to_vec(), origin));
    }

    // `cb_h3_end_headers`: *"add a CRLF only if we have received some
    // headers"*.
    out.addn(H3_END_OF_HEADERS)?;

    Ok(ResponseProjection {
        written: out.take(),
        stored,
        status_code,
        headers_complete: status_completes_headers(status_code),
    })
}

/// Converts `h3`'s response at its boundary and projects it.
///
/// The `http::HeaderMap` `h3` hands back is consumed IMMEDIATELY into a
/// [`HeaderSet`] and never held, which is the same discipline
/// [`request_for_h3`] applies in the other direction.
///
/// # Errors
///
/// [`CURLcode::WeirdServerReply`] for a response `h3` accepted but whose
/// status this module cannot represent, and whatever [`project_response`]
/// reports.
pub(crate) fn project_h3_response(
    response: &http::Response<()>,
) -> CodeResult<ResponseProjection> {
    let status = u32::from(response.status().as_u16());
    let mut fields = HeaderSet::with_limits(
        crate::headers::MAX_HTTP_RESP_HEADER_COUNT,
        crate::util::dynbuf::DYN_HTTP_REQUEST,
    );
    for (name, value) in response.headers() {
        fields.add(name.as_str().as_bytes(), value.as_bytes())?;
    }
    project_response(status, &fields)
}

/// Converts `h3`'s trailers at its boundary into a store tagged
/// [`CURLH_TRAILER`].
///
/// A SEPARATE store from the response headers, which is the whole point: the
/// origin precedence [`crate::headers::classify_origin`] implements is
/// first-match-wins over `CONNECT > 1XX > TRAILER > HEADER`, so a field that
/// arrived as a trailer must not be indistinguishable from one that arrived as
/// a header.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`DynBuf`] at its ceiling, and
/// [`CURLcode::OutOfMemory`] at the set's limits.
pub(crate) fn project_h3_trailers(
    trailers: &http::HeaderMap,
) -> CodeResult<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>, u32)>)> {
    let mut out = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
    let mut stored: Vec<(Vec<u8>, Vec<u8>, u32)> = Vec::new();
    for (name, value) in trailers {
        trailer_line(&mut out, name.as_str().as_bytes(), value.as_bytes())?;
        stored.push((
            name.as_str().as_bytes().to_vec(),
            value.as_bytes().to_vec(),
            CURLH_TRAILER,
        ));
    }
    Ok((out.take(), stored))
}

// ---------------------------------------------------------------------------
// 10. One stream's state -- `struct h3_stream_ctx`
//     (`lib/vquic/curl_ngtcp2.c:225-245`) and `h3_data_setup` (`:260-297`).

/// `stream->id = -1` -- the value `h3_data_setup` assigns before a stream
/// exists, and the value `cf_ngtcp2_adjust_pollset` tests with
/// `stream->id >= 0` (`:966`).
pub(crate) const H3_STREAM_ID_NONE: i64 = -1;

/// All about the HTTP/3 internals of one transfer's stream.
///
/// The C's twenty members, minus the two that do not survive the translation
/// and are named so their absence is deliberate rather than overlooked:
///
/// * `struct h1_req_parser h1` -- the incremental HTTP/1 request parser. Here
///   `protocols/http2.rs`'s [`H1Request`] arrives already parsed, because
///   `protocols/http1.rs` writes the head and `parse_h1_request` reads it in
///   one pass rather than byte by byte.
/// * `CURLcode xfer_result` -- the deferred failure of a client write. It
///   survives as [`Self::xfer_result`], because the C reads it back in
///   `cf_ngtcp2_recv` and the read is observable.
///
/// Everything else is here with the C's name and the C's meaning.
#[derive(Debug)]
pub(crate) struct H3StreamCtx {
    /// `id`: the HTTP/3 stream identifier, [`H3_STREAM_ID_NONE`] until the
    /// stream is opened.
    id: i64,
    /// `sendbuf`: the request body waiting to go out.
    sendbuf: BufQ,
    /// `sendbuf_len_in_flight`: how much of [`Self::sendbuf`] has been handed
    /// to the transport and not yet acknowledged.
    sendbuf_len_in_flight: usize,
    /// `error3`: the HTTP/3 stream error code the peer sent, if any.
    error3: H3Error,
    /// `upload_left`: request bytes still to upload. `-1` means "unknown",
    /// which is what a chunked or streamed body starts as.
    upload_left: i64,
    /// `rx_offset`: how much has been consumed from this stream.
    rx_offset: u64,
    /// `rx_offset_max`: how much the peer is currently allowed to send.
    #[allow(dead_code)] // read by H3StreamCtx::rx_window
    rx_offset_max: u64,
    /// `window_size_max`: the largest flow-control window granted so far.
    #[allow(dead_code)] // read by H3StreamCtx::window_size_max
    window_size_max: u64,
    /// `status_code`: the HTTP status, `0` before a response.
    status_code: u32,
    /// `xfer_result`: a client-write failure recorded for the next read to
    /// report.
    xfer_result: Option<CURLcode>,
    /// `resp_hds_complete`: a complete, FINAL response header block has
    /// arrived -- so a `1xx` does not set it, per
    /// [`status_completes_headers`].
    resp_hds_complete: bool,
    /// `closed`: the stream has closed.
    closed: bool,
    /// `reset`: the stream was reset rather than finishing.
    reset: bool,
    /// `send_closed`: this end has finished sending.
    send_closed: bool,
    /// `quic_flow_blocked`: the stream cannot send because QUIC flow control
    /// says so, which `cf_ngtcp2_adjust_pollset` turns into a WANT-READ
    /// (`:966-969`).
    #[allow(dead_code)] // read by H3StreamCtx::quic_flow_blocked
    quic_flow_blocked: bool,
    /// Response bytes projected and waiting for a [`ConnFilter::recv`] to take
    /// them.
    ///
    /// The C has no equivalent field because it writes the response out during
    /// INGESTION -- `h3_xfer_write_resp_hd` reaches the client writer from
    /// inside an `nghttp3` callback -- and `cf_ngtcp2_recv` therefore opens
    /// with `*pnread = 0`. Here the bytes travel through the filter contract
    /// instead of around it, which is the one place the byte PATH differs and
    /// it differs by carrying the same bytes. `protocols/http2.rs` records the
    /// identical divergence for the identical reason.
    pending: Vec<u8>,
    /// How many body bytes this stream has delivered -- `data->req.bytecount`,
    /// which `recv_closed_stream` reads to choose between
    /// [`CURLcode::PartialFile`] and [`CURLcode::Http3`] (`:1391`).
    received_data: u64,
    /// The trailers, tagged [`CURLH_TRAILER`], kept SEPARATE from the response
    /// headers.
    trailers: HeaderSet,
}

impl H3StreamCtx {
    /// `h3_data_setup` (`lib/vquic/curl_ngtcp2.c:260-297`).
    ///
    /// Its five assignments, in order: `id = -1`, `rx_offset = 0`,
    /// `rx_offset_max = H3_STREAM_WINDOW_SIZE_INITIAL`, the send buffer over
    /// the connection's chunk pool with `BUFQ_OPT_NONE`, and
    /// `window_size_max = H3_STREAM_WINDOW_SIZE_INITIAL`.
    ///
    /// The buffer's options are `BUFQ_OPT_NONE` and NOT
    /// [`BufqOpts::SOFT_LIMIT`], with the C's comment giving the reason: *"on
    /// send, we control how much we put into the buffer"*. The connection's
    /// egress buffer is the one with the soft limit, because a packet arriving
    /// from the transport cannot be refused.
    pub(crate) fn new() -> Self {
        Self {
            id: H3_STREAM_ID_NONE,
            sendbuf: BufQ::with_opts(
                H3_STREAM_CHUNK_SIZE,
                H3_STREAM_SEND_CHUNKS,
                BufqOpts::NONE,
            ),
            sendbuf_len_in_flight: 0,
            error3: H3Error::NO_ERROR,
            upload_left: -1,
            rx_offset: 0,
            rx_offset_max: H3_STREAM_WINDOW_SIZE_INITIAL,
            window_size_max: H3_STREAM_WINDOW_SIZE_INITIAL,
            status_code: 0,
            xfer_result: None,
            resp_hds_complete: false,
            closed: false,
            reset: false,
            send_closed: false,
            quic_flow_blocked: false,
            pending: Vec::new(),
            received_data: 0,
            trailers: HeaderSet::new(),
        }
    }

    /// `stream->id`.
    pub(crate) const fn id(&self) -> i64 {
        self.id
    }

    /// Records the identifier `h3` assigned when the stream opened.
    pub(crate) fn set_id(&mut self, id: i64) {
        self.id = id;
    }

    /// True once a stream identifier exists -- `stream->id >= 0`.
    pub(crate) const fn is_open(&self) -> bool {
        self.id >= 0
    }

    /// `stream->error3`.
    pub(crate) const fn error3(&self) -> H3Error {
        self.error3
    }

    /// `stream->status_code`.
    pub(crate) const fn status_code(&self) -> u32 {
        self.status_code
    }

    /// `stream->closed`.
    pub(crate) const fn is_closed(&self) -> bool {
        self.closed
    }

    /// `stream->reset`.
    #[allow(dead_code)] // consumer: transfer/mod.rs's retry decision
    pub(crate) const fn was_reset(&self) -> bool {
        self.reset
    }

    /// `stream->send_closed`.
    pub(crate) const fn send_closed(&self) -> bool {
        self.send_closed
    }

    /// `stream->resp_hds_complete`.
    #[allow(dead_code)] // consumer: transfer/mod.rs, and handle_close's no_body arm
    pub(crate) const fn resp_hds_complete(&self) -> bool {
        self.resp_hds_complete
    }

    /// `stream->quic_flow_blocked`.
    #[allow(dead_code)] // consumer: CF_QUERY_NEED_FLUSH
    pub(crate) const fn quic_flow_blocked(&self) -> bool {
        self.quic_flow_blocked
    }

    /// Records whether QUIC flow control is holding this stream.
    #[allow(dead_code)] // consumer: the egress path, when quinn reports a full window
    pub(crate) fn set_quic_flow_blocked(&mut self, blocked: bool) {
        self.quic_flow_blocked = blocked;
    }

    /// `stream->upload_left`.
    #[allow(dead_code)] // consumer: CURLINFO_SIZE_UPLOAD_T through the transfer core
    pub(crate) const fn upload_left(&self) -> i64 {
        self.upload_left
    }

    /// `stream->rx_offset` and `rx_offset_max`, as the pair the flow-control
    /// window is derived from.
    #[allow(dead_code)] // consumer: the flow-control accounting the transfer core drives
    pub(crate) const fn rx_window(&self) -> (u64, u64) {
        (self.rx_offset, self.rx_offset_max)
    }

    /// `stream->window_size_max`.
    #[allow(dead_code)] // consumer: the flow-control accounting the transfer core drives
    pub(crate) const fn window_size_max(&self) -> u64 {
        self.window_size_max
    }

    /// Grows the granted window, never shrinking it.
    ///
    /// The C's own comment on the initial value is the reason: *"We need to
    /// start small as we are not able to decrease it."* So this is
    /// deliberately monotonic, and a caller asking for less is ignored rather
    /// than obeyed.
    #[allow(dead_code)] // consumer: the transfer core, as the C's h3_data_recv does
    pub(crate) fn grow_window(&mut self, requested: u64) {
        let capped = requested.min(H3_STREAM_WINDOW_SIZE_MAX);
        if capped > self.window_size_max {
            self.window_size_max = capped;
            self.rx_offset_max = self.rx_offset.saturating_add(capped);
        }
    }

    /// `data->req.bytecount` for this stream.
    #[allow(dead_code)] // consumer: CURLINFO_SIZE_DOWNLOAD_T through the transfer core
    pub(crate) const fn received_data(&self) -> u64 {
        self.received_data
    }

    /// The send buffer, shared -- `CF_QUERY_NEED_FLUSH` reads it.
    pub(crate) const fn sendbuf(&self) -> &BufQ {
        &self.sendbuf
    }

    /// `stream->sendbuf_len_in_flight`.
    pub(crate) const fn sendbuf_len_in_flight(&self) -> usize {
        self.sendbuf_len_in_flight
    }

    /// The trailers, tagged [`CURLH_TRAILER`] when stored.
    #[allow(dead_code)] // consumer: transfer/writeout.rs, which pushes them into the store
    pub(crate) const fn trailers(&self) -> &HeaderSet {
        &self.trailers
    }

    /// `stream->xfer_result` -- a recorded client-write failure.
    pub(crate) const fn xfer_result(&self) -> Option<CURLcode> {
        self.xfer_result
    }

    /// Records a client-write failure for the next read to report, as
    /// `h3_xfer_write_resp_hd` does through `stream->xfer_result`.
    #[allow(dead_code)] // consumer: the transfer core, mirroring h3_xfer_write_resp_hd
    pub(crate) fn set_xfer_result(&mut self, code: CURLcode) {
        if self.xfer_result.is_none() {
            self.xfer_result = Some(code);
        }
    }

    /// Buffers a body write -- what a [`ConnFilter::send`] hands the stream
    /// before `h3` has taken it.
    ///
    /// # Errors
    ///
    /// Whatever [`BufQ::write`] reports at its ceiling.
    pub(crate) fn buffer_send(&mut self, buf: &[u8]) -> CodeResult<usize> {
        self.sendbuf.write(buf)
    }

    /// Records that `amount` bytes of the send buffer are with the transport.
    pub(crate) fn note_in_flight(&mut self, amount: usize) {
        self.sendbuf_len_in_flight =
            self.sendbuf_len_in_flight.saturating_add(amount);
    }

    /// `cb_h3_acked_req_body`: the transport acknowledged `amount` bytes.
    pub(crate) fn note_acked(&mut self, amount: usize) {
        self.sendbuf_len_in_flight =
            self.sendbuf_len_in_flight.saturating_sub(amount);
        self.sendbuf.skip(amount);
    }

    /// `CF_CTRL_DATA_DONE_SEND` (`lib/vquic/curl_ngtcp2.c:2124-2132`).
    ///
    /// ```c
    /// if(stream && !stream->send_closed) {
    ///   stream->send_closed = TRUE;
    ///   stream->upload_left = Curl_bufq_len(&stream->sendbuf) -
    ///     stream->sendbuf_len_in_flight;
    ///   (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);
    /// }
    /// ```
    ///
    /// The `if(!stream->send_closed)` guard is load-bearing: a second
    /// `DATA_DONE_SEND` must NOT recompute `upload_left` from a buffer that
    /// has since drained, which would announce a shorter body than was
    /// promised.
    pub(crate) fn close_send(&mut self) {
        if self.send_closed {
            return;
        }
        self.send_closed = true;
        let queued = self.sendbuf.len();
        let left = queued.saturating_sub(self.sendbuf_len_in_flight);
        self.upload_left = i64::try_from(left).unwrap_or(i64::MAX);
    }

    /// Records a projected response: the bytes to deliver and the status.
    pub(crate) fn accept_response(&mut self, projection: &ResponseProjection) {
        self.status_code = projection.status_code;
        if projection.headers_complete {
            self.resp_hds_complete = true;
        }
        self.pending.extend_from_slice(&projection.written);
    }

    /// Records body bytes.
    pub(crate) fn accept_body(&mut self, body: &[u8]) {
        self.received_data =
            self.received_data.saturating_add(body.len() as u64);
        self.rx_offset = self.rx_offset.saturating_add(body.len() as u64);
        self.pending.extend_from_slice(body);
    }

    /// Records trailers into the SEPARATE store and queues their projected
    /// lines.
    ///
    /// # Errors
    ///
    /// Whatever [`HeaderSet::add`] reports at its limits.
    pub(crate) fn accept_trailers(
        &mut self,
        trailers: &http::HeaderMap,
    ) -> CodeResult<()> {
        let (written, stored) = project_h3_trailers(trailers)?;
        for (name, value, origin) in &stored {
            debug_assert_eq!(
                *origin, CURLH_TRAILER,
                "a trailer must be stored with CURLH_TRAILER"
            );
            self.trailers.add(name, value)?;
        }
        self.pending.extend_from_slice(&written);
        Ok(())
    }

    /// Hands buffered response bytes to a reader, returning how many were
    /// taken.
    pub(crate) fn take_response(&mut self, buf: &mut [u8]) -> usize {
        let taken = self.pending.len().min(buf.len());
        if taken == 0 {
            return 0;
        }
        buf[..taken].copy_from_slice(&self.pending[..taken]);
        self.pending.drain(..taken);
        taken
    }

    /// True when bytes are already waiting -- `Curl_cf_def_data_pending`'s
    /// answer for this filter.
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// `cb_h3_stream_close` (`lib/vquic/curl_ngtcp2.c:977-1010`).
    ///
    /// ```c
    /// stream->closed = TRUE;
    /// stream->error3 = app_error_code;
    /// if(stream->error3 != NGHTTP3_H3_NO_ERROR) {
    ///   stream->reset = TRUE;
    ///   stream->send_closed = TRUE;
    /// }
    /// ```
    ///
    /// So a non-zero application error closes the SEND side too, which is what
    /// stops a caller from continuing to buffer a body nobody will read.
    pub(crate) fn note_closed(&mut self, error: H3Error) {
        self.closed = true;
        self.error3 = error;
        if !error.is_no_error() {
            self.reset = true;
            self.send_closed = true;
        }
    }

    /// `recv_closed_stream(cf, data, stream, pnread)`
    /// (`lib/vquic/curl_ngtcp2.c:1364-1400`).
    ///
    /// The C's ladder, in its exact order, because each rung shadows the ones
    /// below it:
    ///
    /// 1. `stream->reset` and `error3 == CURL_H3_ERR_REQUEST_REJECTED` --
    ///    [`StreamCloseOutcome::Refused`]; the connection is closed and the
    ///    transfer retried.
    /// 2. `stream->reset` and `resp_hds_complete && data->req.no_body` --
    ///    *"error after response headers, but we did not want a body anyway,
    ///    ignore error"*, [`StreamCloseOutcome::Complete`].
    /// 3. `stream->reset` otherwise -- [`StreamCloseOutcome::Partial`] when
    ///    body bytes arrived and [`StreamCloseOutcome::Failed`] when none did.
    /// 4. `else if(!stream->resp_hds_complete)` -- a clean close before the
    ///    response header fields were complete is *"treated as error"*,
    ///    [`StreamCloseOutcome::Failed`].
    /// 5. otherwise [`StreamCloseOutcome::Complete`].
    ///
    /// `no_body` is `data->req.no_body`, which arrives as an argument because
    /// it belongs to the transfer rather than to the stream.
    pub(crate) fn handle_close(&self, no_body: bool) -> StreamCloseOutcome {
        if self.reset {
            if self.error3.is_retryable() {
                return StreamCloseOutcome::Refused;
            }
            if self.resp_hds_complete && no_body {
                return StreamCloseOutcome::Complete;
            }
            return if self.received_data != 0 {
                StreamCloseOutcome::Partial
            } else {
                StreamCloseOutcome::Failed
            };
        }
        if !self.resp_hds_complete {
            return StreamCloseOutcome::Failed;
        }
        StreamCloseOutcome::Complete
    }

    /// `h3_stream_ctx_free` (`lib/vquic/curl_ngtcp2.c:247-252`): release the
    /// buffers.
    pub(crate) fn free(&mut self) {
        self.sendbuf.free();
        self.pending = Vec::new();
        self.trailers.free();
    }
}

impl Default for H3StreamCtx {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 11. The stream's asynchronous half -- `h3_submit`
//     (`lib/vquic/curl_ngtcp2.c:1575-1700`), `cf_ngtcp2_send` (`:1704`) and
//     `cf_ngtcp2_recv` (`:1402`).

/// `h3-quinn`'s bidirectional stream, as `h3` parameterises it.
type H3BidiStream =
    <h3_quinn::OpenStreams as h3::quic::OpenStreams<Bytes>>::BidiStream;

/// `h3`'s request stream over `h3-quinn`.
type H3RequestStream = h3::client::RequestStream<H3BidiStream, Bytes>;

/// A boxed future that OWNS the request stream and hands it back.
///
/// `h3 0.0.8`'s `send_request`, `recv_response`, `send_data`, `send_trailers`
/// and `finish` are `async fn`s on `&mut self`, so a future built from one
/// borrows the stream. A synchronous filter cannot hold a borrow across calls,
/// so the stream is MOVED INTO the future and returned alongside the outcome.
/// That is the safe, standard shape for re-entrant polling of an `async fn` on
/// `&mut self`, and it is why [`StreamIo`] has one variant per operation
/// instead of a single stored borrow.
type StreamFuture<T> =
    Pin<Box<dyn Future<Output = (H3RequestStream, T)> + Send>>;

/// Which asynchronous operation, if any, this stream is in the middle of.
///
/// One variant per `h3` call the transfer makes, in the order a transfer makes
/// them: open, read the response, write body bytes, finish, read trailers.
/// `poll_recv_data` and `poll_recv_trailers` need no variant, because `h3`
/// exposes both as poll functions on `&mut self` and they can therefore be
/// driven directly from [`StreamIo::Idle`].
enum StreamIo {
    /// No stream yet -- `stream->id == -1`.
    #[allow(dead_code)]
    // constructed by H3StreamCtx::new's StreamIo::default; matched, never named
    None,
    /// The `send_request` future is in flight. It owns nothing to hand back
    /// yet, because the stream is what it PRODUCES.
    Opening(
        Pin<
            Box<
                dyn Future<
                        Output = Result<
                            H3RequestStream,
                            h3::error::StreamError,
                        >,
                    > + Send,
            >,
        >,
    ),
    /// A stream exists and nothing is in flight.
    Idle(Box<H3RequestStream>),
    /// `recv_response` is in flight.
    Receiving(StreamFuture<Result<http::Response<()>, h3::error::StreamError>>),
    /// `send_data` is in flight, carrying how many bytes it will have written.
    Sending(StreamFuture<Result<(), h3::error::StreamError>>, usize),
    /// `finish` is in flight.
    Finishing(StreamFuture<Result<(), h3::error::StreamError>>),
    /// The stream is gone.
    Done,
}

/// Terse for the reason [`SessionState`]'s formatter is: none of `h3`'s types
/// is [`Debug`], and the state NAME is what a trace line needs.
impl fmt::Debug for StreamIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::None => "None",
            Self::Opening(_) => "Opening",
            Self::Idle(_) => "Idle",
            Self::Receiving(_) => "Receiving",
            Self::Sending(_, _) => "Sending",
            Self::Finishing(_) => "Finishing",
            Self::Done => "Done",
        };
        f.write_str(name)
    }
}

impl StreamIo {
    /// True when a stream exists and is not busy.
    #[allow(dead_code)] // consumer: the filter's send/recv guards and the tests
    const fn is_idle(&self) -> bool {
        matches!(self, Self::Idle(_))
    }

    /// True when an operation is in flight, so nothing new may be started.
    #[allow(dead_code)] // consumer: the filter's send/recv guards and the tests
    const fn is_busy(&self) -> bool {
        matches!(
            self,
            Self::Opening(_)
                | Self::Receiving(_)
                | Self::Sending(_, _)
                | Self::Finishing(_)
        )
    }
}

/// Whether a byte sequence holds a complete HTTP/1 message head.
///
/// `Curl_h1_req_parse_read` consumes the head incrementally and reports
/// completion when the empty line arrives; here the whole head is written by
/// `protocols/http1.rs` in one piece, so completion is a search for the
/// terminator. Both spellings are accepted, `"\r\n\r\n"` and `"\n\n"`, which
/// is what the C's line parser tolerates.
fn h3_head_is_complete(head: &[u8]) -> bool {
    head.windows(4).any(|window| window == b"\r\n\r\n")
        || head.windows(2).any(|window| window == b"\n\n")
}

/// How many bytes of `head` the message head occupies, terminator included.
///
/// The counterpart of [`h3_head_is_complete`]: that answers whether the empty
/// line is present and this answers where it ends, so a `send` can tell head
/// bytes from body bytes in one buffer.
fn h3_head_length(head: &[u8]) -> usize {
    if let Some(at) = head.windows(4).position(|window| window == b"\r\n\r\n") {
        return at + 4;
    }
    if let Some(at) = head.windows(2).position(|window| window == b"\n\n") {
        return at + 2;
    }
    head.len()
}

// ---------------------------------------------------------------------------
// 12. The filter -- `struct Curl_cftype Curl_cft_http3`
//     (`lib/vquic/curl_ngtcp2.c:2894-2911`).

/// The HTTP/3 connection filter.
///
/// `struct Curl_cfilter` plus `struct cf_ngtcp2_ctx`, with the `void *ctx`
/// gone: [`Self::base`] is the chain link and every other field is an ordinary
/// typed member beside it. There is nothing to erase and nothing to cast back,
/// which is specification 0.3.3's pattern P2 and the reason specification
/// 0.1.2 calls the C's cast *"the single largest source of unsound patterns in
/// the C tree"*.
pub(crate) struct CfH3 {
    /// The chain link, socket index and two state flags.
    base: FilterBase,
    /// The QUIC connection and the HTTP/3 layer over it, absent until the
    /// first [`ConnFilter::connect`].
    session: Option<QuicSession>,
    /// The one transfer's stream state.
    ///
    /// The C hashes `data->mid` to a `struct h3_stream_ctx` because one filter
    /// serves every transfer on the connection. One stream is held here
    /// because the transfer identity arrives through
    /// [`CfControl::DataSetup`] and nothing yet SENDS one: `easy/handle.rs` is
    /// on disk and holds the identity -- a `MultiXferId` and its generational
    /// token -- but no executor exists to carry it to a filter, so this is a
    /// wiring gap rather than a missing file. [`Self::attached`] carries the
    /// count the multiplexing query needs, so the answer
    /// `CF_QUERY_MAX_CONCURRENT` gives is already the right one, and widening
    /// this to a map keyed by `mid` is the change that follows the wiring.
    stream: H3StreamCtx,
    /// Where the stream's asynchronous half is.
    io: StreamIo,
    /// The request head accumulated by [`ConnFilter::send`] until it is
    /// complete -- what `Curl_h1_req_parse_read` consumes byte by byte.
    head: Vec<u8>,
    /// The waker a synchronous filter call hands the asynchronous engine.
    waker: Arc<FilterWaker>,
    /// Where the QUIC handshake's cryptography comes from.
    crypto: Arc<dyn QuicCrypto>,
    /// Where the datagram socket comes from.
    sockets: Arc<dyn QuicSocketFactory>,
    /// Where a qlog goes, read from the environment ONCE at construction.
    qlog: QlogWriter,
    /// The injected entropy -- `Curl_rand_bytes`'s source, so a connection
    /// identifier is reproducible in a test.
    rng: Box<dyn Rng + Send>,
    /// The one address this filter may use.
    peer: SocketAddr,
    /// The name validated and sent as SNI.
    hostname: String,
    /// Whether the peer's certificate is verified. TRUE by default.
    verify_peer: bool,
    /// Whether session keys are logged.
    keylog: bool,
    /// `conn->httpversion_seen`, written by [`CfControl::ConnInfoUpdate`].
    seen_http_version: Option<i32>,
    /// `Curl_conn_set_multiplex(cf->conn)`, set by the same event.
    multiplex: bool,
    /// `cf->conn->attached_xfers` -- how many transfers share this connection.
    attached: u64,
    /// `Curl_multi_max_concurrent_streams(data->multi)`, injected because
    /// `crate::multi` must not be named from a protocol module.
    max_concurrent_fallback: i32,
}

/// Hand-written because neither [`QuicSession`]'s `h3` members nor
/// [`Box<dyn Rng + Send>`] is [`Debug`], and because printing the peer address
/// of a live connection into a shared log is exactly what
/// `crate::util::redact` exists to prevent. The state a test failure needs is
/// the identity and the two state machines' names.
impl fmt::Debug for CfH3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CfH3")
            .field("sockindex", &self.base.sockindex())
            .field("connected", &self.base.is_connected())
            .field("session", &self.session.as_ref().map(|s| &s.state))
            .field("io", &self.io)
            .field("stream_id", &self.stream.id())
            .finish()
    }
}

impl CfH3 {
    /// A filter for one candidate address, unattached and unconnected.
    ///
    /// The successor of `Curl_cf_ngtcp2_create`
    /// (`lib/vquic/curl_ngtcp2.c:2913-2946`) minus its two C concerns: there is
    /// no `curlx_calloc` to fail, and there is no `Curl_cf_udp_create` call
    /// because `quinn`'s [`AsyncUdpSocket`] subsumes that node -- the module
    /// documentation records the measurement behind that.
    ///
    /// Nothing is opened here. The C's own contract for a candidate filter is
    /// that it *"will not touch any connection/data flags and can be used in
    /// happy eyeballing"* (`lib/cf-socket.h:84-89`), so the socket, the
    /// endpoint and the handshake all wait for the first
    /// [`ConnFilter::connect`].
    #[allow(dead_code)] // consumer: QuicTransportProvider::create and conn/mod.rs
    pub(crate) fn new(
        peer: SocketAddr,
        hostname: &str,
        sockindex: SocketIndex,
        crypto: Arc<dyn QuicCrypto>,
        sockets: Arc<dyn QuicSocketFactory>,
        rng: Box<dyn Rng + Send>,
    ) -> Self {
        Self {
            base: FilterBase::new(sockindex),
            session: None,
            stream: H3StreamCtx::new(),
            io: StreamIo::None,
            head: Vec::new(),
            waker: Arc::new(FilterWaker::default()),
            crypto,
            sockets,
            // Read ONCE, here, which is the whole of R-E's environment
            // discipline: a later write cannot consult a variable that has
            // since changed.
            qlog: QlogWriter::from_environment(),
            rng,
            peer,
            hostname: hostname.to_owned(),
            verify_peer: true,
            keylog: false,
            seen_http_version: None,
            multiplex: false,
            attached: 0,
            max_concurrent_fallback: DEFAULT_MAX_CONCURRENT_STREAMS,
        }
    }

    /// Records `--insecure`.
    ///
    /// The DEFAULT is verification ON, which specification 0.8.1 freezes, and
    /// the stderr warning `--insecure` must emit before proceeding belongs to
    /// `curl-rs/src/output/msgs.rs`. This is only the transport half.
    #[must_use]
    #[allow(dead_code)] // consumer: config/to_setopts.rs's --insecure path
    pub(crate) fn with_verify_peer(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }

    /// Records `SSLKEYLOGFILE`.
    #[must_use]
    #[allow(dead_code)] // consumer: the SSLKEYLOGFILE path in tls/keylog.rs's caller
    pub(crate) fn with_keylog(mut self, keylog: bool) -> Self {
        self.keylog = keylog;
        self
    }

    /// Replaces the qlog destination, so a test fixes one without touching the
    /// process environment.
    #[must_use]
    #[allow(dead_code)] // consumer: conn/mod.rs, injecting the QLOGDIR destination
    pub(crate) fn with_qlog(mut self, qlog: QlogWriter) -> Self {
        self.qlog = qlog;
        self
    }

    /// Records `Curl_multi_max_concurrent_streams(data->multi)`.
    #[must_use]
    #[allow(dead_code)] // consumer: multi/mod.rs, which knows the configured ceiling
    pub(crate) fn with_max_concurrent_fallback(mut self, max: i32) -> Self {
        self.max_concurrent_fallback = max;
        self
    }

    /// The qlog destination this filter holds.
    #[allow(dead_code)] // consumer: this module's tests and the filter's diagnostics
    pub(crate) const fn qlog(&self) -> &QlogWriter {
        &self.qlog
    }

    /// The session, once [`ConnFilter::connect`] has created one.
    #[allow(dead_code)] // consumer: CURLINFO reporting through the transfer core
    pub(crate) const fn session(&self) -> Option<&QuicSession> {
        self.session.as_ref()
    }

    /// The one transfer's stream state.
    #[allow(dead_code)] // consumer: CURLINFO reporting through the transfer core
    pub(crate) const fn stream(&self) -> &H3StreamCtx {
        &self.stream
    }

    /// `conn->httpversion_seen`, once [`CfControl::ConnInfoUpdate`] has been
    /// distributed.
    #[allow(dead_code)] // consumer: CF_QUERY_HTTP_VERSION's cached answer
    pub(crate) const fn seen_http_version(&self) -> Option<i32> {
        self.seen_http_version
    }

    /// `Curl_conn_set_multiplex(cf->conn)`'s effect.
    #[allow(dead_code)] // consumer: conn/pool.rs, deciding whether to share the connection
    pub(crate) const fn is_multiplexed(&self) -> bool {
        self.multiplex
    }

    /// `cf->conn->attached_xfers`.
    #[allow(dead_code)] // consumer: conn/pool.rs's reference accounting
    pub(crate) const fn attached(&self) -> u64 {
        self.attached
    }

    /// Opens the stream, once the request head is complete.
    ///
    /// `h3_submit` (`lib/vquic/curl_ngtcp2.c:1575-1700`), whose four steps are
    /// reproduced in its order:
    ///
    /// 1. `Curl_http_req_to_h2(&h2_headers, stream->h1.req, data)` -- the
    ///    ordered field list, which is [`req_to_h3`];
    /// 2. the `nghttp3_nv` array built from it IN ORDER, which is
    ///    [`request_for_h3`] and its refusal to regroup;
    /// 3. `nghttp3_conn_submit_request(...)`, which is
    ///    `SendRequest::send_request`;
    /// 4. `ctx->used_bidi_streams++`, once the stream exists.
    ///
    /// # Errors
    ///
    /// [`CURLcode::WeirdServerReply`] from `parse_h1_request` for a head this
    /// module did not write, whatever [`req_to_h3`] and [`request_for_h3`]
    /// report, and [`CURLcode::Http3`] when the session has no sender because
    /// it is not ready.
    fn submit_request(&mut self, conn_is_ssl: bool) -> CodeResult<()> {
        let head_len = h3_head_length(&self.head);
        let request = super::http2::parse_h1_request(&self.head[..head_len])?;
        let fields = req_to_h3(&request, conn_is_ssl)?;
        let http_request = request_for_h3(&fields)?;

        let Some(mut sender) =
            self.session.as_ref().and_then(QuicSession::sender)
        else {
            return Err(CURLcode::Http3);
        };
        self.io = StreamIo::Opening(Box::pin(async move {
            sender.send_request(http_request).await
        }));
        // Any body bytes that arrived with the head stay queued for the
        // stream, which is what `Curl_h1_req_parse_read` leaves behind too.
        let tail = self.head.split_off(head_len);
        self.head = tail;
        Ok(())
    }

    /// `cf_progress_egress` (`lib/vquic/curl_ngtcp2.c:1804-1900`): make what
    /// progress can be made on the way out.
    ///
    /// Each call advances at most one operation, because that is what a
    /// re-entrant poll from a synchronous callback can do. The order is the
    /// C's: open before write, write before finish.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] when `h3` reports a stream failure while
    /// writing, and [`CURLcode::Http3`] when the stream cannot be opened.
    fn progress_egress(&mut self) -> CodeResult<()> {
        // A completed wake is consumed here so that a future which finished
        // between two filter calls is polled again rather than waited on.
        let _ = self.waker.take_woken();

        match core::mem::replace(&mut self.io, StreamIo::Done) {
            StreamIo::Opening(mut opening) => {
                match self.waker.poll_once(opening.as_mut()) {
                    Poll::Pending => {
                        self.io = StreamIo::Opening(opening);
                        Ok(())
                    }
                    Poll::Ready(Ok(stream)) => {
                        let id = stream_id_as_i64(&stream);
                        self.stream.set_id(id);
                        if let Some(session) = self.session.as_mut() {
                            session.note_stream_opened();
                        }
                        self.io = StreamIo::Idle(Box::new(stream));
                        Ok(())
                    }
                    Poll::Ready(Err(_)) => {
                        self.io = StreamIo::Done;
                        Err(CURLcode::Http3)
                    }
                }
            }
            StreamIo::Sending(mut sending, amount) => {
                match self.waker.poll_once(sending.as_mut()) {
                    Poll::Pending => {
                        self.io = StreamIo::Sending(sending, amount);
                        Ok(())
                    }
                    Poll::Ready((stream, Ok(()))) => {
                        self.stream.note_acked(amount);
                        self.io = StreamIo::Idle(Box::new(stream));
                        Ok(())
                    }
                    Poll::Ready((_, Err(_))) => {
                        self.io = StreamIo::Done;
                        Err(CURLcode::SendError)
                    }
                }
            }
            StreamIo::Finishing(mut finishing) => {
                match self.waker.poll_once(finishing.as_mut()) {
                    Poll::Pending => {
                        self.io = StreamIo::Finishing(finishing);
                        Ok(())
                    }
                    Poll::Ready((stream, Ok(()))) => {
                        self.io = StreamIo::Idle(Box::new(stream));
                        Ok(())
                    }
                    Poll::Ready((_, Err(_))) => {
                        self.io = StreamIo::Done;
                        Err(CURLcode::SendError)
                    }
                }
            }
            StreamIo::Idle(stream) => {
                self.io = StreamIo::Idle(stream);
                self.start_next_write()
            }
            other => {
                self.io = other;
                Ok(())
            }
        }
    }

    /// Starts whichever write the stream's state calls for, if any.
    ///
    /// Buffered body bytes go first and the local close goes last, which is the
    /// order `nghttp3`'s read callback produces: it drains `stream->sendbuf`
    /// and only reports `NGHTTP3_DATA_FLAG_EOF` once `send_closed` is set and
    /// the buffer is empty.
    ///
    /// # Errors
    ///
    /// None from this function itself; the started operation reports through
    /// [`Self::progress_egress`] on a later call.
    fn start_next_write(&mut self) -> CodeResult<()> {
        let StreamIo::Idle(stream) =
            core::mem::replace(&mut self.io, StreamIo::Done)
        else {
            // Unreachable through the one caller, which has just matched
            // `Idle`. Restored rather than asserted, because a panic here
            // would take a live transfer down for a condition that is
            // recoverable by doing nothing.
            self.io = StreamIo::Done;
            return Ok(());
        };
        let mut stream = *stream;

        let queued = self.stream.sendbuf.len();
        let unsent = queued.saturating_sub(self.stream.sendbuf_len_in_flight);
        if unsent > 0 {
            let mut chunk = vec![0_u8; unsent];
            let taken = self.stream.sendbuf.peek().map_or(0, |head| {
                let take = head.len().min(unsent);
                chunk[..take].copy_from_slice(&head[..take]);
                take
            });
            chunk.truncate(taken);
            if taken > 0 {
                self.stream.note_in_flight(taken);
                let body = Bytes::from(chunk);
                self.io = StreamIo::Sending(
                    Box::pin(async move {
                        let outcome = stream.send_data(body).await;
                        (stream, outcome)
                    }),
                    taken,
                );
                return Ok(());
            }
        }

        if self.stream.send_closed() && unsent == 0 {
            self.io = StreamIo::Finishing(Box::pin(async move {
                let outcome = stream.finish().await;
                (stream, outcome)
            }));
            return Ok(());
        }

        self.io = StreamIo::Idle(Box::new(stream));
        Ok(())
    }

    /// `cf_progress_ingress` (`lib/vquic/curl_ngtcp2.c:1758-1802`): take what
    /// has arrived.
    ///
    /// The response head first, then body, then trailers -- which is the order
    /// `nghttp3` delivers them and therefore the order the projected bytes must
    /// reach the client writer in.
    ///
    /// # Errors
    ///
    /// Whatever [`project_h3_response`] reports, and [`CURLcode::Http3`] for a
    /// stream failure `h3` reports while reading.
    fn progress_ingress(&mut self, now: CurlTime) -> CodeResult<()> {
        let _ = self.waker.take_woken();

        match core::mem::replace(&mut self.io, StreamIo::Done) {
            StreamIo::Receiving(mut receiving) => {
                match self.waker.poll_once(receiving.as_mut()) {
                    Poll::Pending => {
                        self.io = StreamIo::Receiving(receiving);
                        Ok(())
                    }
                    Poll::Ready((stream, Ok(response))) => {
                        if let Some(session) = self.session.as_mut() {
                            session.note_first_byte(now);
                        }
                        let projection = project_h3_response(&response)?;
                        self.stream.accept_response(&projection);
                        self.io = StreamIo::Idle(Box::new(stream));
                        Ok(())
                    }
                    Poll::Ready((_, Err(_))) => {
                        self.stream.note_closed(H3Error::INTERNAL_ERROR);
                        self.io = StreamIo::Done;
                        Err(CURLcode::Http3)
                    }
                }
            }
            StreamIo::Idle(stream) => {
                self.io = StreamIo::Idle(stream);
                self.drain_idle_stream(now)
            }
            other => {
                self.io = other;
                Ok(())
            }
        }
    }

    /// Reads whatever an idle stream has: the response, then body, then
    /// trailers.
    ///
    /// # Errors
    ///
    /// As [`Self::progress_ingress`].
    fn drain_idle_stream(&mut self, now: CurlTime) -> CodeResult<()> {
        // The response head is read first and only once, which
        // `stream->status_code == 0` distinguishes.
        if self.stream.status_code() == 0 {
            let StreamIo::Idle(stream) =
                core::mem::replace(&mut self.io, StreamIo::Done)
            else {
                self.io = StreamIo::Done;
                return Ok(());
            };
            let mut stream = *stream;
            self.io = StreamIo::Receiving(Box::pin(async move {
                let outcome = stream.recv_response().await;
                (stream, outcome)
            }));
            return Ok(());
        }

        let StreamIo::Idle(mut stream) =
            core::mem::replace(&mut self.io, StreamIo::Done)
        else {
            self.io = StreamIo::Done;
            return Ok(());
        };

        // `poll_recv_data` and `poll_recv_trailers` take `&mut self` and a
        // context, so they need no stored future at all.
        let waker: Waker = futures::task::waker(Arc::clone(&self.waker));
        let mut cx = TaskContext::from_waker(&waker);
        let outcome = match stream.poll_recv_data(&mut cx) {
            Poll::Pending => Ok(()),
            Poll::Ready(Ok(Some(mut chunk))) => {
                if let Some(session) = self.session.as_mut() {
                    session.note_first_byte(now);
                }
                let mut body = Vec::new();
                while bytes::Buf::has_remaining(&chunk) {
                    let piece = bytes::Buf::chunk(&chunk);
                    let len = piece.len();
                    body.extend_from_slice(piece);
                    bytes::Buf::advance(&mut chunk, len);
                }
                self.stream.accept_body(&body);
                Ok(())
            }
            // End of the body: the trailers, if any, come next.
            Poll::Ready(Ok(None)) => match stream.poll_recv_trailers(&mut cx) {
                Poll::Pending => Ok(()),
                Poll::Ready(Ok(Some(trailers))) => {
                    self.stream.accept_trailers(&trailers)
                }
                Poll::Ready(Ok(None)) => {
                    self.stream.note_closed(H3Error::NO_ERROR);
                    Ok(())
                }
                Poll::Ready(Err(error)) => {
                    self.stream.note_closed(stream_error_code(&error));
                    Ok(())
                }
            },
            Poll::Ready(Err(error)) => {
                self.stream.note_closed(stream_error_code(&error));
                Ok(())
            }
        };
        self.io = StreamIo::Idle(stream);
        outcome
    }

    /// `stream_recv`'s successor: what the stream's state means for a read.
    ///
    /// Projected bytes are handed over FIRST, whatever the stream's state: a
    /// byte in hand is not an error condition. Only when there are none does
    /// the ladder of `xfer_result`, close and abandonment run, which is the
    /// order `cf_ngtcp2_recv` reaches its answers in.
    ///
    /// # Errors
    ///
    /// Whatever [`H3StreamCtx::xfer_result`] recorded, whatever
    /// [`H3StreamCtx::handle_close`] decides for a closed stream, and
    /// [`CURLcode::Again`] when there is nothing yet.
    fn stream_recv(
        &mut self,
        buf: &mut [u8],
        no_body: bool,
    ) -> CodeResult<usize> {
        let taken = self.stream.take_response(buf);
        if taken > 0 {
            return Ok(taken);
        }
        if let Some(code) = self.stream.xfer_result() {
            return Err(code);
        }
        if self.stream.is_closed() {
            let outcome = self.stream.handle_close(no_body);
            return match outcome.code() {
                Some(code) => Err(code),
                // A complete stream reads as end of file.
                None => Ok(0),
            };
        }
        if self.session.as_ref().is_some_and(QuicSession::is_closed) {
            return Err(CURLcode::Http3);
        }
        Err(CURLcode::Again)
    }

    /// `h3_data_pause` (`lib/vquic/curl_ngtcp2.c:2092-2102`).
    ///
    /// The C's comment is the whole implementation: *"There seems to exist no
    /// API in ngtcp2 to shrink/enlarge the streams windows. As we do in
    /// HTTP/2."* So pausing does nothing to the window, and UNPAUSING marks
    /// the transfer dirty so the multi handle looks at it again.
    ///
    /// `Curl_multi_mark_dirty` has no successor reachable from here --
    /// `crate::multi` must not be named from a protocol module -- so the
    /// wake is delivered through the filter's own waker instead, which is the
    /// mechanism the multi handle will poll through. The effect is the same:
    /// the next filter call polls rather than waits.
    fn data_pause(&mut self, pause: bool) {
        if !pause {
            futures::task::ArcWake::wake_by_ref(&self.waker);
        }
    }

    /// `h3_data_done` (`lib/vquic/curl_ngtcp2.c:365-377`): this transfer is
    /// finished with the stream.
    ///
    /// `cf_ngtcp2_stream_close` then `Curl_uint32_hash_remove`, so the stream
    /// is closed and its state released. The connection SURVIVES, which is
    /// what makes HTTP/3 connection reuse possible.
    fn data_done(&mut self) {
        if self.stream.is_open() && !self.stream.is_closed() {
            self.stream.note_closed(H3Error::NO_ERROR);
        }
        self.stream.free();
        self.io = StreamIo::Done;
        self.head = Vec::new();
        self.attached = self.attached.saturating_sub(1);
    }
}

/// `Curl_multi_max_concurrent_streams`'s default (`lib/multi.c`): 100.
///
/// Injected through [`CfH3::with_max_concurrent_fallback`] rather than read
/// from the multi handle, because `crate::multi` must not be named from a
/// protocol module. The value is the C's so that a build which never sets it
/// answers what the C answers.
#[allow(dead_code)] // consumer: CfH3::with_max_concurrent_fallback
pub(crate) const DEFAULT_MAX_CONCURRENT_STREAMS: i32 = 100;

/// The stream identifier as the C's `int64_t`.
///
/// `h3::client::RequestStream::id` returns an `h3::quic::StreamId`, whose
/// `into_inner` is the raw varint. The C stores it signed with `-1` for
/// "none", which [`H3_STREAM_ID_NONE`] preserves, so the narrowing is checked
/// rather than cast -- a QUIC stream identifier is a 62-bit varint and cannot
/// actually reach [`i64::MAX`], but this crate admits no narrowing `as`.
fn stream_id_as_i64(stream: &H3RequestStream) -> i64 {
    i64::try_from(stream.id().into_inner()).unwrap_or(i64::MAX)
}

/// The HTTP/3 error code behind one of `h3`'s stream errors.
///
/// `h3 0.0.8` reports a structured, `#[non_exhaustive]` `StreamError`; the code
/// the peer actually sent is what `cb_h3_stream_close` receives as
/// `app_error_code` and what [`H3StreamCtx::note_closed`] needs. Two variants
/// carry one:
///
/// * `RemoteTerminate { code }` -- the peer reset its sending side or asked us
///   to stop sending, which is exactly the condition
///   `cb_h3_stream_close` and `cb_h3_stop_sending` handle;
/// * `StreamError { code, .. }` -- a local stream failure `h3` has already
///   classified.
///
/// Everything else -- a `GOAWAY`, an oversized field section, a connection
/// failure, an undefined lower-layer error -- surfaces no HTTP/3 code, and the
/// C's own choice for the same situation is used:
/// `nghttp3_err_infer_quic_app_error_code` maps an internal failure to
/// `H3_INTERNAL_ERROR` (`lib/vquic/curl_ngtcp2.c:596-604`).
///
/// The wildcard arm is required rather than lax: the enumeration is
/// `#[non_exhaustive]`, so an exhaustive match would not compile.
///
/// The split into [`stream_error_h3_code`] and [`h3_code_or_internal`] is
/// deliberate and is the only shape this can be unit-tested in. **Every**
/// variant of `h3::error::StreamError` is `#[non_exhaustive]` under the default
/// feature set, so no value of it can be constructed outside the `h3` crate --
/// a struct-expression attempt is `error[E0639]`. `h3::error::Code`, in
/// contrast, is a public newtype with public associated constants, so the
/// mapping half is directly exercisable and the extraction half stays a
/// two-line match with nothing to get wrong.
fn stream_error_code(error: &h3::error::StreamError) -> H3Error {
    h3_code_or_internal(stream_error_h3_code(error))
}

/// The HTTP/3 code `h3` recorded on a stream error, where it recorded one.
///
/// Two of the six variants carry a code and four do not; see
/// [`stream_error_code`] for which and why.
fn stream_error_h3_code(
    error: &h3::error::StreamError,
) -> Option<h3::error::Code> {
    match error {
        h3::error::StreamError::RemoteTerminate { code, .. }
        | h3::error::StreamError::StreamError { code, .. } => Some(*code),
        _ => None,
    }
}

/// An `h3` code as curl's own, with the C's fallback where there is none.
///
/// `nghttp3_err_infer_quic_app_error_code` maps an internal failure to
/// `H3_INTERNAL_ERROR` (`lib/vquic/curl_ngtcp2.c:596-604`), which is the value
/// `cb_h3_stream_close` would then see, so that is what a code-less stream
/// error becomes here.
fn h3_code_or_internal(code: Option<h3::error::Code>) -> H3Error {
    match code {
        Some(code) => H3Error::from_u64(code.value()),
        None => H3Error::INTERNAL_ERROR,
    }
}

/// One trace line attributed to the HTTP/3 filter -- `CURL_TRC_CF`.
///
/// `crate::conn::filters`' own `trc!` is private to that module, so the shape
/// is repeated here as `protocols/mod.rs` and `protocols/http2.rs` both do.
/// The two-level guard is what keeps a trace call free when tracing is off: a
/// registered identity AND a tracer.
macro_rules! trc_h3 {
    (
        $cx:expr, $sockindex:expr, $fmt:literal $(, $arg:expr)* $(,)?
    ) => {{
        let sockindex: i32 = $sockindex;
        if let Some(identity) = TraceFilter::from_name(
            HTTP3_FILTER_NAME.as_bytes(),
        ) {
            if let Some(tracer) = $cx.tracer_mut() {
                trc_cf!(tracer, identity, sockindex, $fmt $(, $arg)*);
            }
        }
    }};
}

impl ConnFilter for CfH3 {
    // -- the `name` and `flags` members ----------------------------------

    fn trace_name(&self) -> &'static str {
        HTTP3_FILTER_NAME
    }

    fn cf_type(&self) -> CfType {
        HTTP3_FLAGS
    }

    // -- the `Curl_cfilter` instance members -----------------------------

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    // -- 1. destroy ------------------------------------------------------

    /// `cf_ngtcp2_destroy(cf, data)` (`lib/vquic/curl_ngtcp2.c:2293-2300`):
    /// free the context and clear the pointer to it.
    ///
    /// Does NOT chain, and must not: the caller has already severed the link
    /// and owns the rest of the chain. For this filter the point is moot in
    /// one direction -- it terminates the chain, so there is nothing below to
    /// reach -- and load-bearing in the other: the QUIC connection must be
    /// closed here rather than left for a drop that may never run.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        trc_h3!(cx, self.base.sockindex().as_i32(), "destroy");
        if let Some(session) = self.session.as_mut() {
            session.close();
        }
        self.session = None;
        self.stream.free();
        self.io = StreamIo::Done;
        self.head = Vec::new();
    }

    // -- 2. connect ------------------------------------------------------

    /// `cf_ngtcp2_connect(cf, data, done)`
    /// (`lib/vquic/curl_ngtcp2.c:2661-2764`).
    ///
    /// The C's steps, in order, with the two this design changes marked:
    ///
    /// 1. an already connected filter reports done immediately;
    /// 2. **the C connects the filter BELOW first** -- `Curl_conn_cf_connect`
    ///    on `cf->next`, its UDP node. There is no node below here, because
    ///    `quinn`'s [`AsyncUdpSocket`] subsumes it, so the socket is created as
    ///    part of step 3 instead;
    /// 3. the context is initialised if it is not -- the endpoint, the
    ///    connection identifier and the qlog, which is
    ///    [`QuicSession::new`] plus [`QuicSession::start_handshake`];
    /// 4. ingress and egress are progressed, which is
    ///    [`QuicSession::poll_ready`];
    /// 5. `*done = TRUE` once the handshake AND the HTTP/3 control streams are
    ///    up -- **the C sets `cf->connected` from
    ///    `ctx->tls_handshake_complete && ctx->h3conn`, and both halves are
    ///    reproduced** by [`SessionState::Ready`] being the only state
    ///    [`QuicSession::is_ready`] accepts.
    ///
    /// A `Poll::Pending` from step 4 becomes `Ok(false)`, which is what the
    /// C's `*done = FALSE` meant and what specification 0.1.2 describes as the
    /// re-entrant polling async replaces.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] or [`CURLcode::FailedInit`] from creating
    /// the socket and the endpoint, whatever [`QuicCrypto::client_config`]
    /// reports, [`CURLcode::QuicConnectError`] for a failed handshake,
    /// [`CURLcode::PeerFailedVerification`] for a rejected certificate, and
    /// [`CURLcode::Http3`] when the HTTP/3 control streams cannot be
    /// established.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if self.base.is_connected() {
            return Ok(true);
        }
        let now = cx.now();

        if self.session.is_none() {
            let session = QuicSession::new(
                self.peer,
                &self.hostname,
                now,
                self.rng.as_mut(),
                self.sockets.as_ref(),
                &self.qlog,
            )?;
            self.session = Some(session);
        }

        let Some(session) = self.session.as_mut() else {
            return Err(Error::with_context(
                CURLcode::FailedInit,
                "HTTP/3 filter has no QUIC session",
            ));
        };
        session.start_handshake(
            self.crypto.as_ref(),
            self.verify_peer,
            self.keylog,
            now,
        )?;
        let ready = session.poll_ready(&self.waker, now)?;
        if ready {
            self.base.set_connected(true);
        }
        trc_h3!(
            cx,
            self.base.sockindex().as_i32(),
            "cf_connect() -> 0, {}",
            i32::from(ready)
        );
        Ok(ready)
    }

    // -- 3. close --------------------------------------------------------

    /// `cf_ngtcp2_close(cf, data)`
    /// (`lib/vquic/curl_ngtcp2.c:2278-2291`): close immediately, without
    /// negotiating.
    ///
    /// The C's own body is `cf_ngtcp2_conn_close` then `cf_ngtcp2_ctx_close`
    /// then `cf->connected = FALSE`, and it does NOT reach `cf->next` -- there
    /// is nothing below this filter to reach. The state is cleared rather than
    /// discarded, so the filter may be connected again afterwards, which
    /// `lib/cfilters.h:424-425` requires of every implementation.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        trc_h3!(cx, self.base.sockindex().as_i32(), "close");
        if let Some(session) = self.session.as_mut() {
            session.close();
        }
        self.session = None;
        self.io = StreamIo::Done;
        self.base.set_connected(false);
    }

    // -- 4. shutdown -----------------------------------------------------

    /// `cf_ngtcp2_shutdown(cf, data, done)`
    /// (`lib/vquic/curl_ngtcp2.c:2176-2270`): close gracefully.
    ///
    /// Three steps, and the guards are the C's:
    ///
    /// 1. a filter that is not connected, has no connection or has already
    ///    started shutting down reports done and does nothing;
    /// 2. the CONNECTION_CLOSE frame is queued ONCE --
    ///    `if(!ctx->shutdown_started)` -- carrying the application error code
    ///    `nghttp3_err_infer_quic_app_error_code` yields, which for a clean
    ///    local close is [`H3Error::NO_ERROR`];
    /// 3. done means the queued packets have gone out, which for `quinn` is
    ///    immediate: `Connection::close` hands the frame to the endpoint's own
    ///    driver task rather than to this call.
    ///
    /// Does NOT chain: the shutdown driver in `crate::conn::filters` walks the
    /// chain one filter at a time and honours the deadline between steps.
    ///
    /// # Errors
    ///
    /// None. The C returns `CURLE_OK` from every path that reaches the end of
    /// the function; the failures it reports come from the packet writes,
    /// which `quinn` performs on its own task.
    fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        trc_h3!(cx, self.base.sockindex().as_i32(), "shutdown");
        if !self.base.is_connected() {
            return Ok(true);
        }
        match self.session.as_mut() {
            Some(session) if !session.is_closed() => {
                session.close();
                Ok(true)
            }
            _ => Ok(true),
        }
    }

    // -- 5. adjust pollset ----------------------------------------------
    //
    // DELIBERATELY NOT OVERRIDDEN, and the reason is structural rather than an
    // omission.
    //
    // `cf_ngtcp2_adjust_pollset` (`lib/vquic/curl_ngtcp2.c:943-975`) works
    // entirely in terms of `ctx->q.sockfd` -- it calls `Curl_pollset_check`
    // and `Curl_pollset_set` with that descriptor, adding a WANT-WRITE when
    // the send buffer is non-empty and converting a congestion- or
    // flow-control-exhausted write into a WANT-READ.
    //
    // This filter HAS no descriptor to name. `quinn` owns the socket behind
    // `AsyncUdpSocket`, which is the abstraction specification 0.8.3 requires
    // be used and which by design exposes no file descriptor; recovering one
    // would need `AsRawFd` on a type that does not offer it, and adopting a
    // raw descriptor back would need `FromRawFd`, which is `unsafe` and
    // forbidden here. Readiness is instead delivered by the reactor to
    // `quinn`'s own endpoint task, and reaches this filter through
    // `FilterWaker`.
    //
    // The trait's default is a pure no-op, so leaving it is the honest
    // answer: this filter contributes no descriptor to a pollset, and
    // pretending otherwise by registering an unrelated one would make
    // `Curl_conn_adjust_pollset` wait on something that never becomes ready.
    // `CF_QUERY_SOCKET` falls through for exactly the same reason, and
    // `the_socket_query_falls_through_because_quinn_owns_the_socket` pins it.

    // -- 6. data pending -------------------------------------------------

    /// `Curl_cf_def_data_pending` is what the C's vtable names here
    /// (`lib/vquic/curl_ngtcp2.c:2901`), which CHAINS to `next` and answers
    /// `false` at the bottom.
    ///
    /// This filter terminates the chain, so chaining would always answer
    /// `false` and would be wrong: bytes projected during ingestion ARE
    /// available to a read, and that is precisely what "data pending" asks. So
    /// the answer comes from the stream's own buffer, which is the same
    /// question the C's UDP node below answered about its socket.
    fn data_pending(&mut self, cx: &CallCtx<'_, '_>) -> bool {
        let _ = cx;
        self.stream.has_pending()
    }

    // -- 7. send ---------------------------------------------------------

    /// `cf_ngtcp2_send(cf, data, buf, len, eos, pnwritten)`
    /// (`lib/vquic/curl_ngtcp2.c:1704-1756`).
    ///
    /// The C's shape, and it is worth being precise because the byte
    /// accounting is observable: while the request head is incomplete the
    /// bytes are fed to `Curl_h1_req_parse_read` and reported as WRITTEN even
    /// though nothing has left; once the head completes `h3_submit` opens the
    /// stream; and body bytes afterwards go into `stream->sendbuf`, whose
    /// acceptance is also reported as written. Egress is progressed at the
    /// end, so a caller that keeps writing keeps the connection moving.
    ///
    /// `eos` is the C's `eos` argument, which reaches
    /// `CF_CTRL_DATA_DONE_SEND`'s work: it closes the sending side.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] when the filter is not connected -- there is no
    /// stream to write to -- and whatever [`Self::submit_request`] or
    /// [`Self::progress_egress`] reports.
    fn send(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &[u8],
        eos: bool,
    ) -> CurlResult<usize> {
        if !self.base.is_connected() {
            return Err(Error::with_context(
                CURLcode::SendError,
                "HTTP/3 send on a filter that is not connected",
            ));
        }

        let written = if matches!(self.io, StreamIo::None) {
            // The request head, accumulated until the empty line arrives.
            self.head.extend_from_slice(buf);
            if h3_head_is_complete(&self.head) {
                // `conn->handler->flags & PROTOPT_SSL` is always true for
                // HTTP/3: `Curl_conn_may_http3` refuses a plaintext URL
                // outright, so the scheme reaching here is always `https`.
                self.submit_request(true)?;
            }
            buf.len()
        } else {
            self.stream.buffer_send(buf)?
        };

        if eos {
            self.stream.close_send();
        }
        self.progress_egress()?;
        trc_h3!(
            cx,
            self.base.sockindex().as_i32(),
            "[{}] cf_send(len={}) -> {}",
            self.stream.id(),
            buf.len(),
            written
        );
        Ok(written)
    }

    // -- 8. recv ---------------------------------------------------------

    /// `cf_ngtcp2_recv(cf, data, buf, blen, pnread)`
    /// (`lib/vquic/curl_ngtcp2.c:1402-1470`).
    ///
    /// Ingress is progressed FIRST and then the stream's state is read, which
    /// is the C's order and matters: a response that has just arrived must be
    /// readable on the same call that received it, or a single-shot caller
    /// sees `CURLE_AGAIN` for data already in hand.
    ///
    /// `no_body` is `data->req.no_body` and arrives as `false` here, because
    /// the transfer's request state comes through
    /// [`CfControl::DataSetup`] and nothing yet sends one. `easy/handle.rs` is
    /// on disk, but the member this needs lives in the `SingleRequest` it
    /// aggregates and only `easy/setopt.rs` -- still absent -- puts a request
    /// on a handle, so the value has no populated source to travel from.
    /// The consequence is confined and worth naming: a stream RESET after
    /// complete response headers on a `--head` transfer reports
    /// [`CURLcode::Http3`] where the C would report success. [`H3StreamCtx::handle_close`]
    /// implements both arms and takes the flag, so wiring the transfer state
    /// through is a one-argument change rather than a rewrite.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] when the filter is not connected, and whatever
    /// [`Self::stream_recv`] decides -- including [`CURLcode::Again`] when
    /// there is nothing yet, which is not a failure.
    fn recv(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        if !self.base.is_connected() {
            return Err(Error::with_context(
                CURLcode::RecvError,
                "HTTP/3 recv on a filter that is not connected",
            ));
        }
        let now = cx.now();
        self.progress_ingress(now)?;
        let read = self.stream_recv(buf, false)?;
        trc_h3!(
            cx,
            self.base.sockindex().as_i32(),
            "[{}] cf_recv(blen={}) -> {}",
            self.stream.id(),
            buf.len(),
            read
        );
        Ok(read)
    }

    // -- 9. control ------------------------------------------------------

    /// `cf_ngtcp2_cntrl(cf, data, event, arg1, arg2)`
    /// (`lib/vquic/curl_ngtcp2.c:2104-2145`).
    ///
    /// Five events are handled and the rest fall into the C's
    /// `default: break;`:
    ///
    /// * `CF_CTRL_DATA_SETUP` -- the C's arm is a bare `break`, so nothing is
    ///   done; the attached count is incremented here because
    ///   `CF_QUERY_MAX_CONCURRENT` reads `cf->conn->attached_xfers` and the C
    ///   reads it from the connection this filter no longer points back at;
    /// * `CF_CTRL_DATA_PAUSE` -- [`Self::data_pause`];
    /// * `CF_CTRL_DATA_DONE` -- [`Self::data_done`];
    /// * `CF_CTRL_DATA_DONE_SEND` -- [`H3StreamCtx::close_send`];
    /// * `CF_CTRL_CONN_INFO_UPDATE` -- `conn->httpversion_seen = 30` and
    ///   `Curl_conn_set_multiplex(cf->conn)`, both only when
    ///   `!cf->sockindex && cf->connected`.
    ///
    /// Does NOT chain: `cf_cntrl_all` (`lib/cfilters.c:446-461`) walks the
    /// chain itself and calls each filter once.
    ///
    /// # Errors
    ///
    /// None. Every arm of the C's switch leaves `result` at `CURLE_OK` except
    /// `CF_CTRL_DATA_PAUSE`, and `h3_data_pause` returns `CURLE_OK`
    /// unconditionally (`:2092-2102`).
    fn cntrl(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        event: CfControl,
    ) -> CurlResult<()> {
        match event {
            // `case CF_CTRL_DATA_SETUP: break;`
            CfControl::DataSetup => {
                self.attached = self.attached.saturating_add(1);
            }
            CfControl::DataPause { pause } => self.data_pause(pause),
            CfControl::DataDone { .. } => self.data_done(),
            CfControl::DataDoneSend => self.stream.close_send(),
            CfControl::ConnInfoUpdate => {
                if self.base.sockindex() == SocketIndex::First
                    && self.base.is_connected()
                {
                    self.seen_http_version = Some(HTTP3_VERSION);
                    self.multiplex = true;
                }
            }
            // The C's `default: break;`. `CF_CTRL_FLUSH` is NOT in
            // `cf_ngtcp2_cntrl`'s switch -- unlike `cf_h2_cntrl`, which
            // handles it -- so it falls through here as it does there, and
            // `CF_QUERY_NEED_FLUSH` is how a caller learns egress is pending.
            CfControl::Flush | CfControl::ForgetSocket => {}
        }
        trc_h3!(
            cx,
            self.base.sockindex().as_i32(),
            "[{}] cf_cntrl({:?})",
            self.stream.id(),
            event
        );
        Ok(())
    }

    // -- 10. is alive ----------------------------------------------------

    /// `cf_ngtcp2_conn_is_alive(cf, data, input_pending)`
    /// (`lib/vquic/curl_ngtcp2.c:2846-2892`).
    ///
    /// The C's ladder: no `qconn` is dead; a started shutdown is dead; an idle
    /// time past the peer's `max_idle_timeout` is dead; then the filter below
    /// is consulted and, if it reports input pending, ingress is progressed
    /// once and a failure makes the connection dead.
    ///
    /// There is no filter below, so the fourth rung is this filter's own
    /// state. `input_pending` is answered from the stream's buffer, which is
    /// the same fact the C's UDP node reported about its socket.
    fn is_alive(&mut self, cx: &mut CallCtx<'_, '_>) -> Liveness {
        let alive = match self.session.as_ref() {
            Some(session) => !session.is_closed() && self.base.is_connected(),
            None => false,
        };
        if !alive {
            return Liveness::DEAD;
        }
        let pending = self.stream.has_pending();
        trc_h3!(
            cx,
            self.base.sockindex().as_i32(),
            "conn alive -> true, input_pending={}",
            pending
        );
        Liveness::alive(pending)
    }

    // -- 11. keep alive --------------------------------------------------
    //
    // `Curl_cf_def_conn_keep_alive` is what the C's vtable names
    // (`lib/vquic/curl_ngtcp2.c:2908`), which chains to `next` and succeeds at
    // the bottom. The trait default does exactly that, so it is not
    // overridden. QUIC's own PING-based keep-alive is
    // `cf_ngtcp2_setup_keep_alive`'s business (`:180-210`), driven by the
    // transport rather than by this callback, and `quinn` performs it from the
    // `TransportConfig` the endpoint carries.

    // -- 12. query -------------------------------------------------------

    /// `cf_ngtcp2_query(cf, data, query, pres1, pres2)`
    /// (`lib/vquic/curl_ngtcp2.c:2766-2843`).
    ///
    /// **Fourteen of the fifteen queries are answered here, and that is more
    /// than the C's own filter answers.** The C answers seven -- and the
    /// module documentation records why the difference is not a change in
    /// behaviour: `Curl_cf_ngtcp2_create` links a `"UDP"` node beneath itself
    /// and five of the queries fall through to it, so a caller receives the
    /// same answers from one node here instead of two.
    ///
    /// | query | answered by the C at | answered here |
    /// |---|---|---|
    /// | `MAX_CONCURRENT` | `:2773` | [`QuicSession::max_concurrent`] |
    /// | `CONNECT_REPLY_MS` | `:2799` | [`QuicSession::connect_reply_ms`] |
    /// | `SOCKET` | the UDP node | **falls through** -- see below |
    /// | `TIMER_CONNECT` | `:2809` | `first_byte_at` |
    /// | `TIMER_APPCONNECT` | `:2815` | `handshake_at` |
    /// | `STREAM_ERROR` | falls through | the stream's `error3` |
    /// | `NEED_FLUSH` | falls through | pending egress |
    /// | `IP_INFO` | the UDP node | the session's quadruple |
    /// | `HTTP_VERSION` | `:2821` | [`HTTP3_VERSION`], 30 |
    /// | `REMOTE_ADDR` | the UDP node | the one peer address |
    /// | `HOST_PORT` | the UDP node | the hostname and port |
    /// | `SSL_INFO` | `:2824` | rustls, session handle |
    /// | `SSL_CTX_INFO` | `:2824` | rustls, context handle |
    /// | `TRANSPORT` | the UDP node | [`H3_TRANSPORT`], QUIC (5) |
    /// | `ALPN_NEGOTIATED` | `:2832` | `h3` once connected |
    ///
    /// `SOCKET` is the one that falls through, and deliberately: `quinn` owns
    /// the socket behind [`AsyncUdpSocket`], which exposes no descriptor, and
    /// recovering one would need `unsafe`. Falling through is what the C's own
    /// HTTP/3 filter does for this query, and the sentinel a caller receives at
    /// the bottom of the chain -- [`CURLcode::UnknownOption`] -- is documented
    /// by `lib/cfilters.c:751-1052` as "use the default", which is
    /// `CURL_SOCKET_BAD`. The same reasoning is why `adjust_pollset` is not
    /// overridden.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] at the bottom of the chain, which is a
    /// SENTINEL meaning nobody understood the question rather than a failure.
    fn query(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        match query {
            CfQuery::MaxConcurrent => {
                let answer = self.session.as_ref().map_or(0, |session| {
                    session.max_concurrent(
                        self.attached,
                        self.max_concurrent_fallback,
                    )
                });
                return Ok(CfQueryValue::MaxConcurrent(answer));
            }
            CfQuery::ConnectReplyMs => {
                let answer = self
                    .session
                    .as_ref()
                    .map_or(-1, QuicSession::connect_reply_ms);
                return Ok(CfQueryValue::ConnectReplyMs(answer));
            }
            CfQuery::TimerConnect => {
                // `if(ctx->q.got_first_byte) *when = ctx->q.first_byte_at;` --
                // otherwise the C leaves the caller's value untouched, which
                // `CurlTime::is_zero` is the successor of.
                let answer = self
                    .session
                    .as_ref()
                    .map_or(CurlTime::ZERO, QuicSession::first_byte_at);
                return Ok(CfQueryValue::Timer(answer));
            }
            CfQuery::TimerAppConnect => {
                // `if(cf->connected) *when = ctx->handshake_at;`
                let answer = if self.base.is_connected() {
                    self.session
                        .as_ref()
                        .map_or(CurlTime::ZERO, QuicSession::handshake_at)
                } else {
                    CurlTime::ZERO
                };
                return Ok(CfQueryValue::Timer(answer));
            }
            CfQuery::StreamError => {
                let raw = self.stream.error3().as_u64();
                let answer = i32::try_from(raw).unwrap_or(i32::MAX);
                return Ok(CfQueryValue::StreamError(answer));
            }
            CfQuery::NeedFlush => {
                let stream_pending = self
                    .stream
                    .sendbuf()
                    .len()
                    .saturating_sub(self.stream.sendbuf_len_in_flight())
                    != 0;
                let conn_pending = self
                    .session
                    .as_ref()
                    .is_some_and(|session| !session.sendbuf().is_empty());
                if stream_pending || conn_pending {
                    return Ok(CfQueryValue::NeedFlush(true));
                }
                return Ok(CfQueryValue::NeedFlush(false));
            }
            CfQuery::IpInfo => {
                if let Some(session) = self.session.as_ref() {
                    return Ok(CfQueryValue::IpInfo {
                        is_ipv6: session.peer().is_ipv6(),
                        quad: session.ip_quadruple(),
                    });
                }
            }
            CfQuery::HttpVersion => {
                return Ok(CfQueryValue::HttpVersion(HTTP3_VERSION));
            }
            CfQuery::RemoteAddr => {
                // `NULL` when not connected (`lib/cfilters.h:174-176`), which
                // is `None` here.
                let answer = if self.base.is_connected() {
                    Some(RemoteAddr::Inet(self.peer))
                } else {
                    None
                };
                return Ok(CfQueryValue::RemoteAddr(answer));
            }
            CfQuery::HostPort => {
                return Ok(CfQueryValue::HostPort {
                    host: self.hostname.clone(),
                    port: self.peer.port(),
                });
            }
            CfQuery::SslInfo | CfQuery::SslCtxInfo => {
                // `Curl_vquic_tls_get_ssl_info(&ctx->tls, query ==
                // CF_QUERY_SSL_CTX_INFO, info)`, and the `break` on failure at
                // `:2830` is why an unconnected filter falls through instead of
                // answering.
                if self.base.is_connected() {
                    let kind = if matches!(query, CfQuery::SslCtxInfo) {
                        TlsHandleKind::Context
                    } else {
                        TlsHandleKind::Session
                    };
                    return Ok(CfQueryValue::SslInfo(TlsSessionInfo {
                        backend: TlsBackendId::RUSTLS,
                        kind,
                        // rustls draws no distinction between a session and a
                        // context handle, which is the "does not
                        // differentiate" case `lib/cfilters.h:156-158`
                        // describes.
                        distinguishes_context: false,
                    }));
                }
            }
            CfQuery::Transport => {
                return Ok(CfQueryValue::Transport(H3_TRANSPORT));
            }
            CfQuery::AlpnNegotiated => {
                // `*palpn = cf->connected ? "h3" : NULL;`
                let answer = if self.base.is_connected() {
                    Some(String::from_utf8_lossy(H3_ALPN).into_owned())
                } else {
                    None
                };
                return Ok(CfQueryValue::AlpnNegotiated(answer));
            }
            // The one the C's `default: break;` lets through, and the two
            // conditional fall-throughs above land here too.
            CfQuery::Socket => {}
        }

        // `return cf->next ? cf->next->cft->query(...) : CURLE_UNKNOWN_OPTION;`
        // -- and this filter terminates the chain, so the sentinel is what a
        // caller receives.
        match self.base.next_mut() {
            Some(next) => next.query(cx, query),
            None => Err(Error::new(CURLcode::UnknownOption)),
        }
    }
}

// ---------------------------------------------------------------------------
// 13. The QUIC transport provider -- `{ TRNSPRT_QUIC, Curl_cf_quic_create }`
//     (`lib/cf-ip-happy.c:69-71`).

/// Creates the QUIC filter for one candidate address.
///
/// The implementor of `crate::conn::happy_eyeballs`'s
/// [`TransportProvider`], which that module's documentation names this one as:
/// *"`crate::protocols::http3` installs it by implementing
/// `TransportProvider`, which is why the row must exist to be filled."*
///
/// # The trait is SYNCHRONOUS, and that is the delivered contract
///
/// `TransportProvider::create` returns `CurlResult<FilterLink>` rather than a
/// future. That matches `cf_ip_connect_create`'s own contract
/// (`lib/cf-ip-happy.h:28-43`), which the C fulfils synchronously and whose
/// non-blocking half lives in the returned filter's `connect`: *"Its `connect`
/// implementation needs to support non-blocking"*. So nothing here awaits, and
/// [`CfH3::connect`] is where the race's non-blocking progress happens.
///
/// Where this module DOES compose futures -- the handshake, the HTTP/3 control
/// streams, the stream operations -- they are BOXED
/// (`Pin<Box<dyn Future + Send>>`), never `async fn` in a trait and never
/// return-position `impl Trait` in a trait. Both stabilised in Rust 1.75, which
/// is this workspace's floor, and NEITHER is dyn-compatible: a trait using
/// either cannot be used behind `dyn` at all, and this provider is stored as
/// `Arc<dyn TransportProvider>`.
/// [`the_provider_is_usable_behind_dyn`] is the regression test for that, and
/// `cargo +1.75.0 build -p curl-rs-lib` is the gate.
#[derive(Clone, Debug)]
#[allow(dead_code)] // consumer: install_quic_provider
pub(crate) struct QuicTransportProvider {
    /// Where the QUIC handshake's cryptography comes from.
    crypto: Arc<dyn QuicCrypto>,
    /// Where the datagram socket comes from.
    sockets: Arc<dyn QuicSocketFactory>,
    /// The name validated and sent as SNI. One provider serves one host,
    /// because the race is over that host's addresses.
    hostname: String,
    /// Whether the peer's certificate is verified. TRUE by default.
    verify_peer: bool,
    /// Whether session keys are logged.
    keylog: bool,
    /// The entropy seed handed to each created filter.
    ///
    /// A SEED rather than a shared generator: `Rng` is not `Sync`, and a
    /// provider is shared behind an [`Arc`], so a generator cannot live here.
    /// Each candidate therefore draws from its own generator seeded from this,
    /// which also makes a test's connection identifier reproducible per
    /// candidate rather than dependent on the order the race created them.
    seed: u32,
}

impl QuicTransportProvider {
    /// A provider for `hostname`, with verification ON.
    #[allow(dead_code)] // consumer: install_quic_provider
    pub(crate) fn new(
        hostname: &str,
        crypto: Arc<dyn QuicCrypto>,
        sockets: Arc<dyn QuicSocketFactory>,
    ) -> Self {
        Self {
            crypto,
            sockets,
            hostname: hostname.to_owned(),
            verify_peer: true,
            keylog: false,
            seed: 0,
        }
    }

    /// Records `--insecure`.
    #[must_use]
    #[allow(dead_code)] // consumer: conn/mod.rs, from the transfer's TLS configuration
    pub(crate) fn with_verify_peer(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }

    /// Records `SSLKEYLOGFILE`.
    #[must_use]
    #[allow(dead_code)] // consumer: conn/mod.rs, from the transfer's TLS configuration
    pub(crate) fn with_keylog(mut self, keylog: bool) -> Self {
        self.keylog = keylog;
        self
    }

    /// Records the entropy seed each created filter draws from.
    #[must_use]
    #[allow(dead_code)] // consumer: this module's tests, for a deterministic identifier
    pub(crate) fn with_seed(mut self, seed: u32) -> Self {
        self.seed = seed;
        self
    }

    /// `Curl_conn_may_http3(data, conn, transport)` as this module consumes
    /// it.
    ///
    /// The unconditional declaration lives in
    /// [`crate::protocols::conn_may_http3`], because
    /// `lib/vquic/vquic.h:54-56` puts it OUTSIDE the `USE_HTTP3` block; this
    /// is the consumption side, which is the relationship that module's own
    /// documentation names -- *"consumers: `alpn_offer`, and
    /// `crate::protocols::http3`"*.
    ///
    /// Called as the precondition of a QUIC connection rather than as an
    /// afterthought: `Curl_cf_https_setup` asks the same question before it
    /// forces `TRNSPRT_QUIC` for its `h3` baller
    /// (`lib/cf-https-connect.c:648-772`), so a provider that skipped it would
    /// create a candidate the C would never have created.
    ///
    /// # Errors
    ///
    /// Exactly what [`crate::protocols::conn_may_http3`] reports:
    /// [`CURLcode::QuicConnectError`] for a Unix transport,
    /// [`CURLcode::UrlMalformat`] with one of three `failf` texts for a
    /// plaintext URL, a SOCKS proxy or a tunnelling HTTP proxy, and
    /// [`CURLcode::NotBuiltIn`] in a build without this module -- which cannot
    /// be reached from here, since this module IS the build with it.
    #[allow(dead_code)] // consumer: protocols/mod.rs's conn_may_http3
    pub(crate) fn may_connect(
        scheme_flags: ProtocolOptions,
        transport: Transport,
        proxy: Http3Proxy,
    ) -> CurlResult<()> {
        conn_may_http3(scheme_flags, transport, proxy)
    }
}

impl TransportProvider for QuicTransportProvider {
    /// `Curl_cf_quic_create(pcf, data, conn, ai, transport)`
    /// (`lib/vquic/vquic.c:699-718`).
    ///
    /// The C asserts `DEBUGASSERT(transport == TRNSPRT_QUIC)` and then
    /// dispatches to `Curl_cf_ngtcp2_create`. There is no `transport` argument
    /// on this trait, because the registry keys the row by transport and can
    /// only reach this provider through the [`Transport::Quic`] row -- the
    /// assertion is therefore discharged by the type of the table rather than
    /// checked at run time.
    ///
    /// The returned link is UNATTACHED, carrying no connection identity and no
    /// socket index beyond the one requested; `IpAttempt::new` stamps both onto
    /// every node of it. It is also a SINGLE node, unlike the C's two-node
    /// subchain, for the reason the module documentation gives.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnsupportedProtocol`] for a candidate that is not an
    /// Internet address: QUIC cannot run over a Unix domain socket, which is
    /// the first thing `Curl_conn_may_http3` refuses
    /// (`lib/vquic/vquic.c:724-727`) and which it refuses with
    /// [`CURLcode::QuicConnectError`] -- reported here as that same code, so a
    /// caller sees one answer for one condition however it arrived.
    fn create(
        &self,
        addr: &crate::dns::ResolvedAddr,
        sockindex: SocketIndex,
    ) -> CurlResult<FilterLink> {
        let peer = match &addr.addr {
            crate::dns::ResolvedSockAddr::Ip(peer) => *peer,
            crate::dns::ResolvedSockAddr::Unix { .. } => {
                return Err(Error::with_context(
                    CURLcode::QuicConnectError,
                    "cannot do QUIC over a Unix domain socket",
                ));
            }
        };
        let filter = CfH3::new(
            peer,
            &self.hostname,
            sockindex,
            Arc::clone(&self.crypto),
            Arc::clone(&self.sockets),
            Box::new(crate::crypto::rand::TestRng::from_seed(self.seed)),
        )
        .with_verify_peer(self.verify_peer)
        .with_keylog(self.keylog);
        Ok(link(filter))
    }
}

/// Fills the QUIC row of a [`TransportRegistry`].
///
/// `Curl_debug_set_transport_provider`'s successor, and the C's own gate on it
/// is preserved: the row must ALREADY EXIST, because a substitution that
/// silently invented a transport would defeat
/// `conn/happy_eyeballs.rs`'s `no_udp_provider_is_advertised`. That module
/// creates the [`Transport::Quic`] row unfilled under `#[cfg(feature =
/// "http3")]` -- the same feature this module is gated on -- so the row is
/// present whenever this function can be called.
///
/// Returns `false` when the row is absent, which cannot happen through
/// `TransportRegistry::sockets` in a build with this module and CAN happen
/// through `TransportRegistry::new`, whose whole purpose is a caller that
/// installs every provider itself.
#[allow(dead_code)] // consumer: conn/mod.rs, filling the registry's QUIC row
pub(crate) fn install_quic_provider(
    registry: &mut TransportRegistry,
    provider: Arc<dyn TransportProvider>,
) -> bool {
    registry.set_provider(H3_TRANSPORT, provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{
        CF_QUERY_ALPN_NEGOTIATED, CF_QUERY_HTTP_VERSION, CF_QUERY_SOCKET,
        CF_QUERY_TRANSPORT, CF_TYPE_PROXY,
    };
    use crate::crypto::rand::TestRng;
    // `CURLH_PSEUDO` is imported HERE rather than at file scope because
    // nothing in the production path stores a pseudo-header -- HTTP/3 does not,
    // as `project_response` records -- so the only uses left are the assertions
    // that no entry carries it.
    use crate::dns::ResolvedAddr;
    use crate::headers::{CURLH_1XX, CURLH_PSEUDO};
    use crate::util::dynbuf::DYN_HTTP_REQUEST;
    // `Clock` is in scope for `TestClock::now`, which the two handshake-
    // deadline tests read directly rather than through a `CallCtx`.
    use crate::util::timeval::{Clock, TestClock};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::mpsc;

    // -- Test doubles. Everything this module needs is injected, so no test
    //    touches process state, no test opens a socket and the order tests run
    //    in cannot matter.

    /// A clock reading ten seconds, which is far enough from zero that a
    /// `CurlTime::is_zero()` assertion is meaningful.
    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(10, 0))
    }

    /// `192.0.2.1:443` -- RFC 5737's documentation range, so no test can reach
    /// a real host even by accident.
    fn peer_v4() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], 443))
    }

    /// `[2001:db8::1]:443` -- RFC 3849's documentation range.
    fn peer_v6() -> SocketAddr {
        SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443))
    }

    /// One end of an in-memory datagram pair, presented as one of `quinn`'s
    /// sockets.
    ///
    /// This is the *"in-memory paired `AsyncUdpSocket`"* the coverage
    /// requirement asks for: it implements the SAME trait
    /// [`TokioUdpSocket`] does, so every path through [`QuicSession`] and
    /// [`CfH3`] that touches the transport is exercised without a socket, a
    /// reactor registration or a network.
    #[derive(Debug)]
    struct PairedUdpSocket {
        /// This end's address, reported by `local_addr`.
        local: SocketAddr,
        /// Where `try_send` delivers.
        outbound: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
        /// Where `poll_recv` reads from.
        inbound: Mutex<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
        /// Every datagram this end sent, for assertions.
        sent: Mutex<VecDeque<(SocketAddr, Vec<u8>)>>,
    }

    impl AsyncUdpSocket for PairedUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(PairedUdpPoller)
        }

        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            let datagram = (transmit.destination, transmit.contents.to_vec());
            if let Ok(mut sent) = self.sent.lock() {
                sent.push_back(datagram.clone());
            }
            self.outbound
                .send(datagram)
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn poll_recv(
            &self,
            cx: &mut TaskContext<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            if bufs.is_empty() || meta.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let Ok(mut inbound) = self.inbound.lock() else {
                return Poll::Ready(Err(io::Error::from(
                    io::ErrorKind::BrokenPipe,
                )));
            };
            match inbound.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(Ok(0)),
                Poll::Ready(Some((from, payload))) => {
                    let len = payload.len().min(bufs[0].len());
                    bufs[0][..len].copy_from_slice(&payload[..len]);
                    meta[0] = RecvMeta {
                        addr: from,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    Poll::Ready(Ok(1))
                }
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local)
        }

        fn max_transmit_segments(&self) -> usize {
            1
        }

        fn max_receive_segments(&self) -> usize {
            1
        }

        fn may_fragment(&self) -> bool {
            true
        }
    }

    /// An unbounded channel never blocks, so this end is always writable.
    #[derive(Debug)]
    struct PairedUdpPoller;

    impl UdpPoller for PairedUdpPoller {
        fn poll_writable(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A [`QuicSocketFactory`] handing out one end of a pair.
    #[derive(Debug)]
    struct PairedUdpFactory {
        /// The socket the next `bind` returns, taken once.
        socket: Mutex<Option<Arc<PairedUdpSocket>>>,
        /// What `bind` reports instead of a socket, when a test wants the
        /// failure path.
        refuse: Option<CURLcode>,
    }

    impl PairedUdpFactory {
        /// Builds a connected pair and returns the factory for the near end
        /// alongside the far end, so a test can read what was sent.
        fn pair(local: SocketAddr) -> (Self, Arc<PairedUdpSocket>) {
            let (near_tx, far_rx) = mpsc::unbounded_channel();
            let (far_tx, near_rx) = mpsc::unbounded_channel();
            let near = Arc::new(PairedUdpSocket {
                local,
                outbound: near_tx,
                inbound: Mutex::new(near_rx),
                sent: Mutex::new(VecDeque::new()),
            });
            let far = Arc::new(PairedUdpSocket {
                local: peer_v4(),
                outbound: far_tx,
                inbound: Mutex::new(far_rx),
                sent: Mutex::new(VecDeque::new()),
            });
            (
                Self {
                    socket: Mutex::new(Some(Arc::clone(&near))),
                    refuse: None,
                },
                far,
            )
        }

        /// A factory that refuses with `code`.
        fn refusing(code: CURLcode) -> Self {
            Self {
                socket: Mutex::new(None),
                refuse: Some(code),
            }
        }
    }

    impl QuicSocketFactory for PairedUdpFactory {
        fn bind(
            &self,
            _peer: SocketAddr,
        ) -> CodeResult<Arc<dyn AsyncUdpSocket>> {
            if let Some(code) = self.refuse {
                return Err(code);
            }
            let taken = self
                .socket
                .lock()
                .ok()
                .and_then(|mut slot| slot.take())
                .ok_or(CURLcode::CouldntConnect)?;
            Ok(taken)
        }
    }

    /// A [`QuicCrypto`] producing a real, usable `quinn::ClientConfig` over an
    /// EMPTY trust store.
    ///
    /// Empty on purpose: verification is ON, so a handshake against anything
    /// will fail verification -- which is the correct default and is what
    /// [`tls_verification_is_on_by_default`] asserts the seam carries. The
    /// double names `rustls` because `quinn::ClientConfig` wraps a
    /// `quinn::crypto::ClientConfig` and that is the only way to build one;
    /// it does NOT name `crate::tls`, which is the constraint that applies to
    /// this file.
    #[derive(Debug)]
    struct TestCrypto {
        /// Every request the filter made, so a test can assert what was asked
        /// for.
        seen: Mutex<Vec<(String, bool, bool, Vec<Vec<u8>>)>>,
        /// What `client_config` reports instead of a configuration, when a
        /// test wants the failure path.
        refuse: Option<CURLcode>,
    }

    impl TestCrypto {
        fn new() -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                refuse: None,
            }
        }

        fn refusing(code: CURLcode) -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                refuse: Some(code),
            }
        }

        fn requests(&self) -> Vec<(String, bool, bool, Vec<Vec<u8>>)> {
            self.seen
                .lock()
                .map(|seen| seen.clone())
                .unwrap_or_default()
        }
    }

    impl QuicCrypto for TestCrypto {
        fn client_config(
            &self,
            request: &QuicCryptoRequest<'_>,
        ) -> CodeResult<quinn::ClientConfig> {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push((
                    request.hostname.to_owned(),
                    request.verify_peer,
                    request.keylog,
                    request.alpn.iter().map(|p| p.to_vec()).collect(),
                ));
            }
            if let Some(code) = self.refuse {
                return Err(code);
            }
            let mut tls = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            tls.alpn_protocols =
                request.alpn.iter().map(|p| p.to_vec()).collect();
            let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|_| CURLcode::SslConnectError)?;
            Ok(quinn::ClientConfig::new(Arc::new(quic)))
        }
    }

    /// A filter over an in-memory pair, with a fixed entropy seed so the
    /// connection identifier -- and therefore the qlog filename -- is
    /// reproducible.
    fn paired_filter(
        seed: u32,
    ) -> (CfH3, Arc<TestCrypto>, Arc<PairedUdpSocket>) {
        let (factory, far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let crypto = Arc::new(TestCrypto::new());
        let filter = CfH3::new(
            peer_v4(),
            "example.com",
            SocketIndex::First,
            Arc::clone(&crypto) as Arc<dyn QuicCrypto>,
            Arc::new(factory),
            Box::new(TestRng::from_seed(seed)),
        )
        .with_qlog(QlogWriter::with_dir(None));
        (filter, crypto, far)
    }

    // -- 1. The filter identity, measured against
    //       `lib/vquic/curl_ngtcp2.c:2894-2911`.

    #[test]
    fn the_filter_name_is_the_literal_the_c_declares() {
        assert_eq!(HTTP3_FILTER_NAME, "HTTP/3");
        // Registered in `crate::trace` under exactly these bytes, which is
        // what makes `--trace-config http/3` work.
        assert_eq!(
            TraceFilter::from_name(HTTP3_FILTER_NAME.as_bytes()),
            Some(TraceFilter::Http3)
        );
    }

    #[test]
    fn the_filter_carries_exactly_four_type_flags() {
        // `CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX |
        //  CF_TYPE_HTTP` = (1<<0)|(1<<1)|(1<<2)|(1<<4) = 23.
        assert_eq!(HTTP3_FLAGS.bits(), 23);
        assert!(HTTP3_FLAGS.contains(CF_TYPE_IP_CONNECT));
        assert!(HTTP3_FLAGS.contains(CF_TYPE_SSL));
        assert!(HTTP3_FLAGS.contains(CF_TYPE_MULTIPLEX));
        assert!(HTTP3_FLAGS.contains(CF_TYPE_HTTP));
        // And NOT the fifth: this filter is not a proxy.
        assert!(!HTTP3_FLAGS.intersects(CF_TYPE_PROXY));
    }

    #[test]
    fn the_log_level_is_none() {
        // The third initialiser of `Curl_cft_http3` is `0`.
        assert_eq!(HTTP3_LOG_LEVEL, 0);
        assert_eq!(HTTP3_LOG_LEVEL, CURL_LOG_LVL_NONE);
    }

    #[test]
    fn the_instance_reports_the_declared_identity() {
        let (filter, _crypto, _far) = paired_filter(1);
        assert_eq!(filter.trace_name(), "HTTP/3");
        assert_eq!(filter.cf_type(), HTTP3_FLAGS);
        assert_eq!(filter.cf_type().bits(), 23);
        assert_eq!(filter.trace_filter(), Some(TraceFilter::Http3));
        assert_eq!(filter.sockindex(), SocketIndex::First);
    }

    #[test]
    fn the_filter_terminates_the_chain() {
        let (filter, _crypto, _far) = paired_filter(1);
        // Nothing beneath it: the C's `Curl_cf_udp_create` node is subsumed by
        // `quinn`'s own `AsyncUdpSocket`.
        assert!(filter.base().next_ref().is_none());
    }

    #[test]
    fn the_http_version_query_answers_thirty() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, _crypto, _far) = paired_filter(1);
        assert_eq!(HTTP3_VERSION, 30);
        assert_eq!(CF_QUERY_HTTP_VERSION, 9);
        assert_eq!(
            filter.query(&mut cx, CfQuery::HttpVersion).ok(),
            Some(CfQueryValue::HttpVersion(30))
        );
    }

    #[test]
    fn the_transport_query_answers_quic_five() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, _crypto, _far) = paired_filter(1);
        assert_eq!(CF_QUERY_TRANSPORT, 14);
        assert_eq!(H3_TRANSPORT.as_u8(), 5);
        assert_eq!(
            filter.query(&mut cx, CfQuery::Transport).ok(),
            Some(CfQueryValue::Transport(Transport::Quic))
        );
    }

    #[test]
    fn the_alpn_query_answers_h3_only_once_connected() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, _crypto, _far) = paired_filter(1);
        assert_eq!(CF_QUERY_ALPN_NEGOTIATED, 15);
        assert_eq!(H3_ALPN, b"h3");

        // `*palpn = cf->connected ? "h3" : NULL;`
        assert_eq!(
            filter.query(&mut cx, CfQuery::AlpnNegotiated).ok(),
            Some(CfQueryValue::AlpnNegotiated(None))
        );
        filter.base_mut().set_connected(true);
        assert_eq!(
            filter.query(&mut cx, CfQuery::AlpnNegotiated).ok(),
            Some(CfQueryValue::AlpnNegotiated(Some("h3".to_owned())))
        );
    }

    #[test]
    fn the_socket_query_falls_through_because_quinn_owns_the_socket() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, _crypto, _far) = paired_filter(1);
        assert_eq!(CF_QUERY_SOCKET, 3);
        // This filter terminates the chain, so a fall-through reaches the
        // bottom and the SENTINEL is what a caller receives.
        let answer = filter.query(&mut cx, CfQuery::Socket);
        assert_eq!(
            answer.map_err(|error| error.code()),
            Err(CURLcode::UnknownOption)
        );
    }

    #[test]
    fn every_query_is_answered_or_falls_through_to_the_sentinel() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, _crypto, _far) = paired_filter(1);

        // Exhaustive over `CfQuery::ALL`, so a query added to
        // `crate::conn::filters` shows up here rather than being silently
        // unhandled.
        //
        // Before a session exists FOUR fall through, and each for a reason the
        // C shares: `Socket` because `quinn` owns the socket and exposes no
        // descriptor; `IpInfo` because there is no quadruple yet; and
        // `SSL_INFO`/`SSL_CTX_INFO` because the C's own arm `break`s when
        // `Curl_vquic_tls_get_ssl_info` fails, which an unconnected filter
        // makes certain (`lib/vquic/curl_ngtcp2.c:2824-2830`).
        let mut answered = 0;
        let mut fell_through = 0;
        for query in CfQuery::ALL {
            match filter.query(&mut cx, query) {
                Ok(value) => {
                    assert!(
                        value.matches(query),
                        "{query:?} answered with {value:?}"
                    );
                    answered += 1;
                }
                Err(error) => {
                    assert_eq!(error.code(), CURLcode::UnknownOption);
                    assert!(
                        matches!(
                            query,
                            CfQuery::Socket
                                | CfQuery::IpInfo
                                | CfQuery::SslInfo
                                | CfQuery::SslCtxInfo
                        ),
                        "{query:?} fell through unexpectedly"
                    );
                    fell_through += 1;
                }
            }
        }
        assert_eq!(answered + fell_through, 15);
        assert_eq!(answered, 11, "eleven are answered without a session");
        assert_eq!(fell_through, 4);

        // Once connected the two TLS queries ARE answered, and both name
        // rustls -- `CURLSSLBACKEND_RUSTLS = 14`, an enumerant the public
        // header already carries, so no value is invented.
        filter.base_mut().set_connected(true);
        for (query, kind) in [
            (CfQuery::SslInfo, TlsHandleKind::Session),
            (CfQuery::SslCtxInfo, TlsHandleKind::Context),
        ] {
            let answer = filter
                .query(&mut cx, query)
                .expect("a connected filter answers the TLS queries");
            assert_eq!(
                answer,
                CfQueryValue::SslInfo(TlsSessionInfo {
                    backend: TlsBackendId::RUSTLS,
                    kind,
                    distinguishes_context: false,
                })
            );
            assert_eq!(TlsBackendId::RUSTLS.as_i32(), 14);
        }
    }

    #[test]
    fn destroy_shutdown_and_control_do_not_chain() {
        // The three that must NOT reach `next`. Asserted structurally: this
        // filter terminates the chain, so a chaining implementation would have
        // to invent a node, and the C's own `cf_ngtcp2_destroy`,
        // `cf_ngtcp2_shutdown` and `cf_ngtcp2_cntrl` all leave `cf->next`
        // alone.
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, _crypto, _far) = paired_filter(1);

        filter.base_mut().set_connected(true);
        assert_eq!(filter.shutdown(&mut cx).ok(), Some(true));
        assert!(filter.base().next_ref().is_none());

        assert!(filter.cntrl(&mut cx, CfControl::DataSetup).is_ok());
        assert!(filter.base().next_ref().is_none());

        filter.destroy(&mut cx);
        assert!(filter.base().next_ref().is_none());
    }

    #[test]
    fn the_control_events_are_the_c_switch_arms() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, _crypto, _far) = paired_filter(1);

        // `CF_CTRL_DATA_SETUP` = 4, and `5` is reserved and refused by name.
        assert_eq!(crate::conn::filters::CF_CTRL_DATA_SETUP, 4);
        assert_eq!(crate::conn::filters::CF_CTRL_UNUSED_5, 5);
        assert_eq!(CfControl::from_event_id(5, 0), None);
        assert_eq!(crate::conn::filters::CF_CTRL_DATA_PAUSE, 6);
        assert_eq!(crate::conn::filters::CF_CTRL_DATA_DONE, 7);
        assert_eq!(crate::conn::filters::CF_CTRL_DATA_DONE_SEND, 8);
        assert_eq!(crate::conn::filters::CF_CTRL_CONN_INFO_UPDATE, 256);
        assert_eq!(crate::conn::filters::CF_CTRL_FORGET_SOCKET, 257);
        assert_eq!(crate::conn::filters::CF_CTRL_FLUSH, 258);

        // `DATA_SETUP` increments the attached count the multiplexing query
        // reads.
        assert_eq!(filter.attached(), 0);
        assert!(filter.cntrl(&mut cx, CfControl::DataSetup).is_ok());
        assert_eq!(filter.attached(), 1);

        // `CONN_INFO_UPDATE` writes 30 and sets multiplexing, but ONLY on the
        // primary chain and ONLY when connected.
        assert!(filter.cntrl(&mut cx, CfControl::ConnInfoUpdate).is_ok());
        assert_eq!(filter.seen_http_version(), None);
        assert!(!filter.is_multiplexed());
        filter.base_mut().set_connected(true);
        assert!(filter.cntrl(&mut cx, CfControl::ConnInfoUpdate).is_ok());
        assert_eq!(filter.seen_http_version(), Some(30));
        assert!(filter.is_multiplexed());

        // `DATA_DONE_SEND` closes the sending side.
        assert!(!filter.stream().send_closed());
        assert!(filter.cntrl(&mut cx, CfControl::DataDoneSend).is_ok());
        assert!(filter.stream().send_closed());

        // The two the C's `default: break;` lets through.
        assert!(filter.cntrl(&mut cx, CfControl::Flush).is_ok());
        assert!(filter.cntrl(&mut cx, CfControl::ForgetSocket).is_ok());
    }

    #[test]
    fn unpausing_wakes_the_engine_and_pausing_does_not() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, _crypto, _far) = paired_filter(1);

        // `h3_data_pause`: `if(!pause) Curl_multi_mark_dirty(data);`
        assert!(filter
            .cntrl(&mut cx, CfControl::DataPause { pause: true })
            .is_ok());
        assert!(!filter.waker.take_woken());
        assert!(filter
            .cntrl(&mut cx, CfControl::DataPause { pause: false })
            .is_ok());
        assert!(filter.waker.take_woken());
    }

    // -- 2. The transport provider, and the object-safety regression.

    #[test]
    fn the_provider_creates_a_quic_candidate_for_one_address() {
        let (factory, _far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let provider = QuicTransportProvider::new(
            "example.com",
            Arc::new(TestCrypto::new()),
            Arc::new(factory),
        );
        let addr = ResolvedAddr::tcp(peer_v4(), None);
        let link = provider
            .create(&addr, SocketIndex::First)
            .expect("a QUIC candidate for a routable address");
        // One node, carrying the HTTP/3 identity, and nothing beneath it.
        assert_eq!(link.trace_name(), "HTTP/3");
        assert_eq!(link.cf_type().bits(), 23);
        assert!(link.base().next_ref().is_none());
        assert_eq!(link.sockindex(), SocketIndex::First);
    }

    #[test]
    fn the_provider_refuses_a_unix_candidate() {
        let (factory, _far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let provider = QuicTransportProvider::new(
            "example.com",
            Arc::new(TestCrypto::new()),
            Arc::new(factory),
        );
        let addr = ResolvedAddr {
            addr: crate::dns::ResolvedSockAddr::Unix {
                path: PathBuf::from("/tmp/curl.sock"),
                abstract_ns: false,
            },
            socktype: crate::dns::SockType::Stream,
            protocol: crate::dns::IpProto::Tcp,
            canonname: None,
            flags: 0,
        };
        let outcome = provider.create(&addr, SocketIndex::First);
        assert_eq!(
            outcome.err().map(|error| error.code()),
            Some(CURLcode::QuicConnectError),
            "QUIC cannot run over a Unix domain socket"
        );
    }

    #[test]
    fn the_provider_is_usable_behind_dyn() {
        // The object-safety regression test for the boxed-future rule: neither
        // `async fn` in a trait nor return-position `impl Trait` in a trait is
        // dyn-compatible, so this line is what fails if either is ever
        // introduced into `TransportProvider` or into a trait it reaches.
        let (factory, _far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let provider: Arc<dyn TransportProvider> =
            Arc::new(QuicTransportProvider::new(
                "example.com",
                Arc::new(TestCrypto::new()),
                Arc::new(factory),
            ));
        let addr = ResolvedAddr::tcp(peer_v6(), None);
        assert!(provider.create(&addr, SocketIndex::Secondary).is_ok());

        // And the two seams it holds are trait objects too.
        let crypto: Arc<dyn QuicCrypto> = Arc::new(TestCrypto::new());
        let sockets: Arc<dyn QuicSocketFactory> = Arc::new(Socket2UdpFactory);
        assert!(format!("{crypto:?}").contains("TestCrypto"));
        assert!(format!("{sockets:?}").contains("Socket2UdpFactory"));
    }

    #[test]
    fn installing_the_provider_fills_an_existing_row_and_never_invents_one() {
        let (factory, _far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let provider: Arc<dyn TransportProvider> =
            Arc::new(QuicTransportProvider::new(
                "example.com",
                Arc::new(TestCrypto::new()),
                Arc::new(factory),
            ));

        // An empty registry has no row, so the installation must FAIL rather
        // than invent a transport.
        let mut empty = TransportRegistry::new();
        assert!(!empty.has_row(Transport::Quic));
        assert!(!install_quic_provider(&mut empty, Arc::clone(&provider)));

        // A registry with the row -- which is what `TransportRegistry::sockets`
        // builds under this feature -- accepts it.
        let mut registry = TransportRegistry::new()
            .with_row(Transport::Quic, Arc::clone(&provider));
        assert!(registry.has_row(Transport::Quic));
        assert!(install_quic_provider(&mut registry, provider));
        assert!(registry.provider(Transport::Quic).is_some());
    }

    // -- 3. `Curl_conn_may_http3` delegation.

    #[test]
    fn conn_may_http3_reaches_this_module_and_agrees_with_it() {
        let https = ProtocolOptions::SSL;
        let http = ProtocolOptions::NONE;
        let no_proxy = Http3Proxy::default();

        // With `http3` enabled -- which this module being compiled proves --
        // a TLS scheme over a non-Unix transport succeeds.
        assert!(QuicTransportProvider::may_connect(
            https,
            Transport::Tcp,
            no_proxy
        )
        .is_ok());
        assert!(QuicTransportProvider::may_connect(
            https,
            Transport::Quic,
            no_proxy
        )
        .is_ok());

        // And the module's own view is the same function's, byte for byte.
        assert_eq!(
            QuicTransportProvider::may_connect(https, Transport::Tcp, no_proxy)
                .map_err(|error| error.code()),
            conn_may_http3(https, Transport::Tcp, no_proxy)
                .map_err(|error| error.code())
        );

        // A Unix transport: `CURLE_QUIC_CONNECT_ERROR`, no message.
        assert_eq!(
            QuicTransportProvider::may_connect(
                https,
                Transport::Unix,
                no_proxy
            )
            .err()
            .map(|error| error.code()),
            Some(CURLcode::QuicConnectError)
        );

        // A plaintext URL: `CURLE_URL_MALFORMAT` with the measured text.
        let plain =
            QuicTransportProvider::may_connect(http, Transport::Tcp, no_proxy)
                .expect_err("HTTP/3 requires HTTPS");
        assert_eq!(plain.code(), CURLcode::UrlMalformat);
        assert_eq!(plain.context(), Some("HTTP/3 requested for non-HTTPS URL"));

        // A SOCKS proxy and a tunnelling HTTP proxy: the other two texts.
        let socks = QuicTransportProvider::may_connect(
            https,
            Transport::Tcp,
            Http3Proxy {
                socks: true,
                http_tunnel: false,
            },
        )
        .expect_err("HTTP/3 refuses a SOCKS proxy");
        assert_eq!(
            socks.context(),
            Some("HTTP/3 is not supported over a SOCKS proxy")
        );
        let tunnel = QuicTransportProvider::may_connect(
            https,
            Transport::Tcp,
            Http3Proxy {
                socks: false,
                http_tunnel: true,
            },
        )
        .expect_err("HTTP/3 refuses a tunnelling HTTP proxy");
        assert_eq!(
            tunnel.context(),
            Some("HTTP/3 is not supported over an HTTP proxy")
        );
    }

    // -- 4. qlog.

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn qlog_is_disabled_when_the_variable_is_unset_or_empty() {
        let unset = QlogWriter::with_dir(None);
        assert!(!unset.is_enabled());
        assert_eq!(unset.file_name(b"\x01\x02"), Ok(None));
        assert!(unset.open(b"\x01\x02").expect("no name, no file").is_none());

        // An empty value is treated as unset, because `curl_getenv` hands back
        // nothing for one and because `"/<hex>.sqlog"` is not what anybody
        // means by `QLOGDIR=`.
        let empty = QlogWriter::with_dir(Some(OsString::from("")));
        assert!(!empty.is_enabled());
        assert_eq!(empty.file_name(b"\x01"), Ok(None));
    }

    #[test]
    fn the_qlog_name_is_constructed_exactly_as_the_c_constructs_it() {
        let writer = QlogWriter::with_dir(Some(OsString::from("/tmp/qlogs")));
        assert!(writer.is_enabled());
        // `qlog_dir` + `"/"` + two LOWER-CASE hexadecimal digits per SCID byte
        // + `".sqlog"`.
        let name = writer
            .file_name(&[0x00, 0x0f, 0xa5, 0xff])
            .expect("a name within DYN_QLOG_NAME")
            .expect("a name, since QLOGDIR is set");
        assert_eq!(
            name.to_str(),
            Some("/tmp/qlogs/000fa5ff.sqlog"),
            "two digits per byte, lower case, no separators"
        );
        assert_eq!(QLOG_SUFFIX, ".sqlog");
        assert_eq!(QLOGDIR_ENV, "QLOGDIR");

        // A directory already ending in a solidus yields a doubled one, which
        // is what the C's unconditional append produces.
        let trailing = QlogWriter::with_dir(Some(OsString::from("/tmp/")));
        assert_eq!(
            trailing
                .file_name(&[0xab])
                .expect("a name")
                .expect("a name")
                .to_str(),
            Some("/tmp//ab.sqlog")
        );

        // An empty SCID composes just the directory and the suffix, which is
        // what the C's `for(i = 0; i < scidlen; ...)` loop does for zero.
        assert_eq!(
            QlogWriter::with_dir(Some(OsString::from("/q")))
                .file_name(&[])
                .expect("a name")
                .expect("a name")
                .to_str(),
            Some("/q/.sqlog")
        );
    }

    #[test]
    fn the_qlog_name_is_bounded_by_dyn_qlog_name() {
        assert_eq!(DYN_QLOG_NAME, 1024);
        // A directory long enough that the composed name passes the bound.
        let long = OsString::from("/".repeat(DYN_QLOG_NAME));
        let writer = QlogWriter::with_dir(Some(long));
        assert_eq!(
            writer.file_name(&[0x01]),
            Err(CURLcode::TooLarge),
            "the bound is DynBuf's and is enforced, not advisory"
        );

        // And a name just inside it composes.
        let inside = OsString::from("/".repeat(DYN_QLOG_NAME - 16));
        assert!(QlogWriter::with_dir(Some(inside))
            .file_name(&[0x01])
            .expect("a name inside the bound")
            .is_some());
    }

    #[test]
    fn the_qlog_variable_is_read_once_at_construction() {
        // The production constructor reads the environment; the injected one
        // does not. Both are exercised, and neither consults the environment
        // again: `file_name` is a function of the HELD value, so calling it
        // twice with different SCIDs gives two names from one read.
        let held = QlogWriter::with_dir(Some(OsString::from("/held")));
        let first = held.file_name(&[0x01]).expect("a name");
        let second = held.file_name(&[0x02]).expect("a name");
        assert_ne!(first, second);
        assert!(first
            .expect("a name")
            .to_str()
            .is_some_and(|text| text.starts_with("/held/")));

        // `from_environment` is the production path. Whatever the ambient
        // environment holds, the result is a value that answers consistently
        // -- which is the property that matters and the one a mutable global
        // would not have.
        let ambient = QlogWriter::from_environment();
        assert_eq!(
            ambient.is_enabled(),
            ambient.file_name(&[0x01]).is_ok_and(|name| name.is_some())
        );
    }

    #[test]
    fn the_filter_holds_the_qlog_destination_it_was_built_with() {
        let (filter, _crypto, _far) = paired_filter(1);
        assert!(!filter.qlog().is_enabled());
        let with = filter
            .with_qlog(QlogWriter::with_dir(Some(OsString::from("/tmp/q"))));
        assert!(with.qlog().is_enabled());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_qlog_is_written_where_the_directory_exists_and_skipped_otherwise() {
        // The C's contract, verbatim: *"This function returns error if
        // something failed outside of failing to create the file."* So a
        // directory that does not exist is NOT an error.
        let missing =
            QlogWriter::with_dir(Some(OsString::from("/nonexistent-qlog-dir")));
        assert!(missing.is_enabled());
        assert_eq!(
            missing.open(&[0xde, 0xad]).map(|file| file.is_some()),
            Ok(false),
            "an unopenable path is silent, exactly as *qlogfdp staying -1 is"
        );

        // And a real directory yields a real file, named from the SCID.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let writer =
            QlogWriter::with_dir(Some(dir.path().as_os_str().to_owned()));
        let opened = writer
            .open(&[0xde, 0xad, 0xbe, 0xef])
            .expect("a name within the bound");
        assert!(opened.is_some(), "the file is created");
        assert!(dir.path().join("deadbeef.sqlog").is_file());
    }

    #[test]
    fn the_connection_identifier_is_drawn_from_the_injected_entropy() {
        // `Curl_rand_bytes`'s byte order is low byte first per draw, and
        // `TestRng` reproduces `CURL_ENTROPY`'s generator exactly, so the
        // identifier -- and therefore the qlog filename -- is reproducible.
        let mut rng = TestRng::from_seed(0x0102_0304);
        let mut scid = vec![0_u8; QUIC_SCID_LEN];
        rand_bytes(&mut rng, &mut scid);
        assert_eq!(QUIC_SCID_LEN, 8);
        assert_eq!(scid, vec![0x04, 0x03, 0x02, 0x01, 0x05, 0x03, 0x02, 0x01]);

        // Two generators from the same seed give the same identifier, which is
        // what makes the qlog name assertable.
        let mut again = TestRng::from_seed(0x0102_0304);
        let mut second = vec![0_u8; QUIC_SCID_LEN];
        rand_bytes(&mut again, &mut second);
        assert_eq!(scid, second);

        let writer = QlogWriter::with_dir(Some(OsString::from("/q")));
        assert_eq!(
            writer
                .file_name(&scid)
                .expect("a name")
                .expect("a name")
                .to_str(),
            Some("/q/0403020105030201.sqlog")
        );
    }

    // -- 5. The ordered field list, pseudo-header colons, and trailers.

    /// A request head as `protocols/http1.rs` writes one.
    fn head(method: &str, path: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(method.as_bytes());
        out.extend_from_slice(b" ");
        out.extend_from_slice(path.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        out.extend_from_slice(b"Host: example.com\r\n");
        out.extend_from_slice(b"User-Agent: curl/8.19.0-DEV\r\n");
        out.extend_from_slice(b"Accept: */*\r\n");
        out.extend_from_slice(b"\r\n");
        out
    }

    #[test]
    fn the_five_pseudo_header_names_keep_their_colons() {
        // `crate::headers`'s invariant for `CURLH_PSEUDO`: the first byte MUST
        // be `':'`.
        assert_eq!(H3_PSEUDO_ORDER.len(), 5);
        for name in H3_PSEUDO_ORDER {
            assert_eq!(
                name.first(),
                Some(&b':'),
                "{:?} must retain its leading colon",
                String::from_utf8_lossy(name)
            );
        }
        assert_eq!(H3_PSEUDO_ORDER[0], b":method");
        assert_eq!(H3_PSEUDO_ORDER[1], b":scheme");
        assert_eq!(H3_PSEUDO_ORDER[2], b":authority");
        assert_eq!(H3_PSEUDO_ORDER[3], b":path");
        assert_eq!(H3_PSEUDO_ORDER[4], b":status");
    }

    #[test]
    fn the_field_list_is_pseudo_headers_first_then_curls_order() {
        let raw = head("GET", "/index.html");
        let request = super::super::http2::parse_h1_request(&raw)
            .expect("a head this workspace wrote");
        let fields = req_to_h3(&request, true).expect("the ordered field list");

        let names: Vec<String> = fields
            .iter()
            .map(|(name, _)| String::from_utf8_lossy(name).into_owned())
            .collect();
        // `lib/http.c:4910-4938`'s order, and NOTHING is sorted: `user-agent`
        // precedes `accept` because the request wrote it first, which
        // alphabetical order would reverse.
        assert_eq!(
            names,
            vec![
                ":method".to_owned(),
                ":scheme".to_owned(),
                ":authority".to_owned(),
                ":path".to_owned(),
                "user-agent".to_owned(),
                "accept".to_owned(),
            ]
        );
        // `Host:` is one of the six forbidden names and becomes `:authority`.
        assert!(fields.get(b"host").is_none());
        assert_eq!(
            fields.get(b":authority").map(|entry| entry.value()),
            Some(b"example.com".as_slice())
        );
        assert_eq!(
            fields.get(b":scheme").map(|entry| entry.value()),
            Some(b"https".as_slice()),
            "HTTP/3 is always over TLS"
        );
    }

    #[test]
    fn the_field_list_is_the_same_one_http2_produces() {
        // `h3_submit` calls `Curl_http_req_to_h2`, the SAME function
        // `h2_submit` calls, so the two orders are one order. Asserted rather
        // than assumed, because a divergence would be invisible until a
        // fixture compared the bytes.
        let raw = head("POST", "/upload");
        let request = super::super::http2::parse_h1_request(&raw)
            .expect("a head this workspace wrote");
        let h3 = req_to_h3(&request, true).expect("the HTTP/3 field list");
        let h2 = req_to_h2(&request, true).expect("the HTTP/2 field list");
        let as_pairs = |set: &HeaderSet| -> Vec<(Vec<u8>, Vec<u8>)> {
            set.iter()
                .map(|(name, value)| (name.to_vec(), value.to_vec()))
                .collect()
        };
        assert_eq!(as_pairs(&h3), as_pairs(&h2));
    }

    #[test]
    fn the_h3_request_conversion_preserves_the_method_and_target() {
        let raw = head("GET", "/index.html");
        let request = super::super::http2::parse_h1_request(&raw)
            .expect("a head this workspace wrote");
        let fields = req_to_h3(&request, true).expect("the field list");
        let converted = request_for_h3(&fields).expect("h3's boundary type");

        assert_eq!(converted.method(), http::Method::GET);
        assert_eq!(converted.version(), http::Version::HTTP_3);
        assert_eq!(
            converted.uri().to_string(),
            "https://example.com/index.html"
        );
        // The pseudo-headers are carried by the method and the URI, never as
        // ordinary fields -- `h3` composes them itself.
        assert!(converted.headers().get(":method").is_none());
        assert_eq!(
            converted.headers().get("accept").map(|v| v.as_bytes()),
            Some(b"*/*".as_slice())
        );
    }

    #[test]
    fn a_connect_request_addresses_its_authority_alone() {
        // RFC 9114 section 4.4: a `CONNECT` carries `:method` and `:authority`
        // and NEITHER `:scheme` nor `:path`. `cf-h2-proxy.c` builds exactly that
        // shape -- `H1Request`'s two optional members exist for it -- so the
        // boundary conversion has to accept it.
        let mut fields = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        fields.add(b":method", b"CONNECT").expect("a pseudo-header");
        fields
            .add(b":authority", b"tunnel.example:443")
            .expect("a pseudo-header");
        let converted = request_for_h3(&fields).expect("h3's boundary type");
        assert_eq!(converted.method(), http::Method::CONNECT);
        assert_eq!(converted.uri().to_string(), "tunnel.example:443");
        assert_eq!(converted.version(), http::Version::HTTP_3);

        // Without an authority there is nothing to address, which is the one
        // way this form can fail.
        let mut bare = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        bare.add(b":method", b"CONNECT").expect("a pseudo-header");
        assert_eq!(
            request_for_h3(&bare).err(),
            Some(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn an_ordinary_request_needs_a_scheme_and_an_authority() {
        // Every non-`CONNECT` form requires both, because the URI is built from
        // them; a field list missing either is a caller error rather than
        // something to guess at.
        let mut no_scheme = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        no_scheme.add(b":method", b"GET").expect("a pseudo-header");
        no_scheme
            .add(b":authority", b"example.com")
            .expect("a pseudo-header");
        no_scheme.add(b":path", b"/").expect("a pseudo-header");
        assert_eq!(
            request_for_h3(&no_scheme).err(),
            Some(CURLcode::BadFunctionArgument)
        );

        let mut no_authority = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        no_authority
            .add(b":method", b"GET")
            .expect("a pseudo-header");
        no_authority
            .add(b":scheme", b"https")
            .expect("a pseudo-header");
        no_authority.add(b":path", b"/").expect("a pseudo-header");
        assert_eq!(
            request_for_h3(&no_authority).err(),
            Some(CURLcode::BadFunctionArgument)
        );

        // And a field list with no `:method` at all cannot name a request.
        let empty = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        assert_eq!(
            request_for_h3(&empty).err(),
            Some(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn an_empty_path_becomes_a_single_slash() {
        // An absent `:path` defaults to `"/"` and an EMPTY one is normalized to
        // the same thing, because `http::Uri` rejects `https://host` with no
        // path segment and the origin-form target curl writes always has one.
        let mut empty_path = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        empty_path.add(b":method", b"GET").expect("a pseudo-header");
        empty_path
            .add(b":scheme", b"https")
            .expect("a pseudo-header");
        empty_path
            .add(b":authority", b"example.com")
            .expect("a pseudo-header");
        empty_path.add(b":path", b"").expect("a pseudo-header");
        let converted =
            request_for_h3(&empty_path).expect("h3's boundary type");
        assert_eq!(converted.uri().to_string(), "https://example.com/");

        let mut absent_path = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        absent_path
            .add(b":method", b"GET")
            .expect("a pseudo-header");
        absent_path
            .add(b":scheme", b"https")
            .expect("a pseudo-header");
        absent_path
            .add(b":authority", b"example.com")
            .expect("a pseudo-header");
        assert_eq!(
            request_for_h3(&absent_path)
                .expect("h3's boundary type")
                .uri()
                .to_string(),
            "https://example.com/"
        );
    }

    #[test]
    fn a_repeated_name_split_by_another_is_refused_rather_than_regrouped() {
        // Regrouping would reorder the encoded field section, which
        // specification 0.6.7's byte-exact oracle would see.
        let mut fields = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        fields.add(b":method", b"GET").expect("a pseudo-header");
        fields.add(b":scheme", b"https").expect("a pseudo-header");
        fields
            .add(b":authority", b"example.com")
            .expect("a pseudo-header");
        fields.add(b":path", b"/").expect("a pseudo-header");
        fields.add(b"x-a", b"1").expect("a field");
        fields.add(b"x-b", b"2").expect("a field");
        fields.add(b"x-a", b"3").expect("a field");
        assert_eq!(
            request_for_h3(&fields).err(),
            Some(CURLcode::BadFunctionArgument)
        );

        // Contiguous repeats ARE accepted, because `http` preserves their
        // append order.
        let mut ok = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        ok.add(b":method", b"GET").expect("a pseudo-header");
        ok.add(b":scheme", b"https").expect("a pseudo-header");
        ok.add(b":authority", b"example.com")
            .expect("a pseudo-header");
        ok.add(b":path", b"/").expect("a pseudo-header");
        ok.add(b"x-a", b"1").expect("a field");
        ok.add(b"x-a", b"3").expect("a field");
        assert!(request_for_h3(&ok).is_ok());
    }

    #[test]
    fn the_status_line_is_the_measured_byte_sequence() {
        let mut out = DynBuf::new(DYN_HTTP_REQUEST);
        status_line(&mut out, b"200").expect("a status line");
        // `"HTTP/3 " + status + " \r\n"` -- the TRAILING SPACE stands where an
        // HTTP/1 reason phrase would.
        assert_eq!(out.as_slice(), b"HTTP/3 200 \r\n");

        // The RAW field value is written, not a reformatted integer: a
        // three-digit code arrives as its own three bytes.
        let mut odd = DynBuf::new(DYN_HTTP_REQUEST);
        status_line(&mut odd, b"404").expect("a status line");
        assert_eq!(odd.as_slice(), b"HTTP/3 404 \r\n");
    }

    #[test]
    fn a_header_and_a_trailer_project_to_the_same_bytes() {
        let mut header = DynBuf::new(DYN_HTTP_REQUEST);
        header_line(&mut header, b"content-type", b"text/plain")
            .expect("a header line");
        assert_eq!(header.as_slice(), b"content-type: text/plain\r\n");

        // Byte for byte identical, because `ngh3_callbacks` registers ONE
        // callback for both slots. What differs is the ORIGIN, asserted below.
        let mut trailer = DynBuf::new(DYN_HTTP_REQUEST);
        trailer_line(&mut trailer, b"content-type", b"text/plain")
            .expect("a trailer line");
        assert_eq!(trailer.as_slice(), header.as_slice());
    }

    #[test]
    fn a_projected_response_writes_the_status_then_fields_then_a_crlf() {
        let mut fields = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        fields.add(b"content-type", b"text/plain").expect("a field");
        fields.add(b"content-length", b"3").expect("a field");
        let projected = project_response(200, &fields).expect("a projection");

        assert_eq!(
            projected.written,
            b"HTTP/3 200 \r\ncontent-type: text/plain\r\ncontent-length: 3\r\n\r\n"
                .to_vec(),
            "status line, fields IN ORDER, then the end-of-headers CRLF"
        );
        assert_eq!(H3_END_OF_HEADERS, b"\r\n");
        assert_eq!(projected.status_code, 200);
        assert!(projected.headers_complete);

        // The store: the two fields with `CURLH_HEADER`, and NOTHING for the
        // status line.
        //
        // `cb_h3_recv_header`'s status arm calls only `h3_xfer_write_resp_hd`
        // (`lib/vquic/curl_ngtcp2.c:1205-1207`) -- it never calls
        // `Curl_headers_push`, which the whole tree does exactly twice outside
        // `lib/headers.c`: at `lib/http2.c:1512`, for HTTP/2's `:status`, and
        // nowhere else. `hds_cw_collect_write` then skips any write flagged
        // `CLIENTWRITE_STATUS` (`lib/headers.c:300`). So an HTTP/3 transfer has
        // no pseudo-header in its store, and this assertion is what stops one
        // being added back.
        assert_eq!(projected.stored.len(), 2);
        assert_eq!(projected.stored[0].0, b"content-type".to_vec());
        assert_eq!(projected.stored[0].2, CURLH_HEADER);
        assert_eq!(projected.stored[1].0, b"content-length".to_vec());
        assert_eq!(projected.stored[1].2, CURLH_HEADER);
        assert!(
            !projected
                .stored
                .iter()
                .any(|(_, _, origin)| *origin == CURLH_PSEUDO),
            "HTTP/3 stores no pseudo-header; HTTP/2 is the only path that does"
        );
        assert!(
            projected.written.starts_with(b"HTTP/3 200 \r\n"),
            "the status line still contributes BYTES, just no store entry"
        );
    }

    #[test]
    fn an_informational_response_does_not_complete_the_header_phase() {
        // `if(stream->status_code / 100 != 1) resp_hds_complete = TRUE;`
        assert!(!status_completes_headers(100));
        assert!(!status_completes_headers(103));
        assert!(status_completes_headers(200));
        assert!(status_completes_headers(301));
        assert!(status_completes_headers(404));
        assert!(status_completes_headers(503));

        let empty = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        assert!(
            !project_response(103, &empty)
                .expect("a projection")
                .headers_complete
        );
        assert!(
            project_response(200, &empty)
                .expect("a projection")
                .headers_complete
        );

        // And its fields carry `CURLH_1XX`, not `CURLH_HEADER`:
        // `lib/http.c:1622` adds `CLIENTWRITE_1XX` when
        // `data->req.httpcode / 100 == 1`, and `hds_cw_collect_write` prefers
        // `CURLH_1XX` over `CURLH_HEADER` for such a write. A caller asking for
        // final-response headers must not be answered from a 1xx.
        let mut early = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        early
            .add(b"link", b"</style.css>; rel=preload")
            .expect("a field");
        let informational =
            project_response(103, &early).expect("a projection");
        assert_eq!(informational.stored.len(), 1);
        assert_eq!(informational.stored[0].2, CURLH_1XX);
        assert_eq!(CURLH_1XX, 1 << 3);

        // The final response's fields carry `CURLH_HEADER`, so the two are
        // distinguishable in the store rather than merely on the wire.
        let final_response =
            project_response(200, &early).expect("a projection");
        assert_eq!(final_response.stored[0].2, CURLH_HEADER);
    }

    #[test]
    fn trailers_land_in_a_separate_store_tagged_curlh_trailer() {
        assert_eq!(CURLH_TRAILER, 1 << 1);
        let mut trailers = http::HeaderMap::new();
        trailers.insert(
            http::header::HeaderName::from_static("x-checksum"),
            http::header::HeaderValue::from_static("abc123"),
        );
        let (written, stored) =
            project_h3_trailers(&trailers).expect("a projection");
        assert_eq!(written, b"x-checksum: abc123\r\n".to_vec());
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].2, CURLH_TRAILER);

        // And the stream keeps them SEPARATE from the response headers, which
        // is what makes the origin precedence
        // `CONNECT > 1XX > TRAILER > HEADER` answerable.
        let mut stream = H3StreamCtx::new();
        let mut fields = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        fields.add(b"content-type", b"text/plain").expect("a field");
        let response = project_response(200, &fields).expect("a projection");
        stream.accept_response(&response);
        assert_eq!(stream.trailers().count(), 0);
        stream.accept_trailers(&trailers).expect("trailers stored");
        assert_eq!(stream.trailers().count(), 1);
        assert_eq!(
            stream.trailers().get(b"x-checksum").map(|e| e.value()),
            Some(b"abc123".as_slice())
        );
        // The response headers did NOT gain the trailer.
        assert!(stream.trailers().get(b"content-type").is_none());
    }

    #[test]
    fn the_origin_bits_are_the_public_headers() {
        assert_eq!(CURLH_HEADER, 1 << 0);
        assert_eq!(CURLH_TRAILER, 1 << 1);
        assert_eq!(crate::headers::CURLH_CONNECT, 1 << 2);
        assert_eq!(crate::headers::CURLH_1XX, 1 << 3);
        assert_eq!(CURLH_PSEUDO, 1 << 4);
        assert_eq!(crate::headers::CURLH_ORIGIN_MASK, 0x1F);
    }

    // -- 6. Error mapping.

    #[test]
    fn the_seventeen_named_h3_codes_are_the_c_enumeration() {
        // `vquic_h3_error` (`lib/vquic/vquic_int.h:35-53`), value and name.
        let expected: [(u64, &str); 17] = [
            (0x0100, "NO_ERROR"),
            (0x0101, "GENERAL_PROTOCOL_ERROR"),
            (0x0102, "INTERNAL_ERROR"),
            (0x0103, "STREAM_CREATION_ERROR"),
            (0x0104, "CLOSED_CRITICAL_STREAM"),
            (0x0105, "FRAME_UNEXPECTED"),
            (0x0106, "FRAME_ERROR"),
            (0x0107, "EXCESSIVE_LOAD"),
            (0x0108, "ID_ERROR"),
            (0x0109, "SETTINGS_ERROR"),
            (0x010a, "MISSING_SETTINGS"),
            (0x010b, "REQUEST_REJECTED"),
            (0x010c, "REQUEST_CANCELLED"),
            (0x010d, "REQUEST_INCOMPLETE"),
            (0x010e, "MESSAGE_ERROR"),
            (0x010f, "CONNECT_ERROR"),
            (0x0110, "VERSION_FALLBACK"),
        ];
        for (index, (code, name)) in expected.iter().enumerate() {
            let (actual, actual_name) = H3_ERROR_NAMES[index];
            assert_eq!(actual.as_u64(), *code, "row {index} value");
            assert_eq!(actual_name, *name, "row {index} name");
        }
        for (code, name) in expected {
            assert_eq!(H3Error::from_u64(code).err_str(), name);
            assert_eq!(H3Error::from_u64(code).as_u64(), code);
        }

        // The named constants agree with the table.
        assert_eq!(H3Error::NO_ERROR.as_u64(), 0x0100);
        assert_eq!(H3Error::GENERAL_PROTOCOL_ERROR.as_u64(), 0x0101);
        assert_eq!(H3Error::INTERNAL_ERROR.as_u64(), 0x0102);
        assert_eq!(H3Error::STREAM_CREATION_ERROR.as_u64(), 0x0103);
        assert_eq!(H3Error::CLOSED_CRITICAL_STREAM.as_u64(), 0x0104);
        assert_eq!(H3Error::FRAME_UNEXPECTED.as_u64(), 0x0105);
        assert_eq!(H3Error::FRAME_ERROR.as_u64(), 0x0106);
        assert_eq!(H3Error::EXCESSIVE_LOAD.as_u64(), 0x0107);
        assert_eq!(H3Error::ID_ERROR.as_u64(), 0x0108);
        assert_eq!(H3Error::SETTINGS_ERROR.as_u64(), 0x0109);
        assert_eq!(H3Error::MISSING_SETTINGS.as_u64(), 0x010a);
        assert_eq!(H3Error::REQUEST_REJECTED.as_u64(), 0x010b);
        assert_eq!(H3Error::REQUEST_CANCELLED.as_u64(), 0x010c);
        assert_eq!(H3Error::REQUEST_INCOMPLETE.as_u64(), 0x010d);
        assert_eq!(H3Error::MESSAGE_ERROR.as_u64(), 0x010e);
        assert_eq!(H3Error::CONNECT_ERROR.as_u64(), 0x010f);
        assert_eq!(H3Error::VERSION_FALLBACK.as_u64(), 0x0110);
    }

    #[test]
    fn the_reserved_no_error_family_is_recognised_arithmetically() {
        // `if((error_code >= 0x21) && !((error_code - 0x21) % 0x1f))`
        for step in 0_u64..8 {
            let code = H3Error::from_u64(0x21 + step * 0x1f);
            assert!(code.is_reserved_no_error(), "0x{:x}", code.as_u64());
            assert_eq!(code.err_str(), "NO_ERROR");
            assert!(code.is_no_error());
        }
        // Neighbours are not in the family.
        for raw in [0x20_u64, 0x22, 0x3f, 0x41] {
            let code = H3Error::from_u64(raw);
            assert!(!code.is_reserved_no_error(), "0x{raw:x}");
            assert_eq!(code.err_str(), "unknown");
        }
        // Below the base, nothing is.
        assert!(!H3Error::from_u64(0).is_reserved_no_error());
        assert!(H3Error::from_u64(0).err_str() == "unknown");
    }

    #[test]
    fn a_rejected_request_is_retryable_and_nothing_else_is() {
        assert!(H3Error::REQUEST_REJECTED.is_retryable());
        for other in [
            H3Error::NO_ERROR,
            H3Error::INTERNAL_ERROR,
            H3Error::REQUEST_CANCELLED,
            H3Error::MESSAGE_ERROR,
        ] {
            assert!(!other.is_retryable(), "0x{:x}", other.as_u64());
        }
    }

    #[test]
    fn a_closed_stream_maps_to_the_codes_recv_closed_stream_reports() {
        // 1a. A reset with `REQUEST_REJECTED`: retry on a new connection.
        let mut refused = H3StreamCtx::new();
        refused.note_closed(H3Error::REQUEST_REJECTED);
        let outcome = refused.handle_close(false);
        assert_eq!(outcome, StreamCloseOutcome::Refused);
        assert_eq!(outcome.code(), Some(CURLcode::RecvError));
        assert!(outcome.should_retry());
        assert!(outcome.closes_connection());

        // 1b. A reset after complete headers on a body-less transfer: ignored.
        let mut headless = H3StreamCtx::new();
        let empty = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        headless.accept_response(
            &project_response(200, &empty).expect("a projection"),
        );
        headless.note_closed(H3Error::INTERNAL_ERROR);
        assert_eq!(
            headless.handle_close(true),
            StreamCloseOutcome::Complete,
            "we did not want a body anyway"
        );
        assert_eq!(headless.handle_close(true).code(), None);

        // 1c. A reset with body bytes: PARTIAL_FILE. Without them: HTTP3.
        let mut partial = H3StreamCtx::new();
        partial.accept_response(
            &project_response(200, &empty).expect("a projection"),
        );
        partial.accept_body(b"hello");
        partial.note_closed(H3Error::INTERNAL_ERROR);
        assert_eq!(partial.handle_close(false), StreamCloseOutcome::Partial);
        assert_eq!(
            partial.handle_close(false).code(),
            Some(CURLcode::PartialFile)
        );

        let mut bare = H3StreamCtx::new();
        bare.accept_response(
            &project_response(200, &empty).expect("a projection"),
        );
        bare.note_closed(H3Error::INTERNAL_ERROR);
        assert_eq!(bare.handle_close(false), StreamCloseOutcome::Failed);
        assert_eq!(bare.handle_close(false).code(), Some(CURLcode::Http3));

        // 2. A CLEAN close before complete headers: *"treated as error"*.
        let mut truncated = H3StreamCtx::new();
        truncated.note_closed(H3Error::NO_ERROR);
        assert!(!truncated.was_reset());
        assert_eq!(truncated.handle_close(false), StreamCloseOutcome::Failed);
        assert_eq!(truncated.handle_close(false).code(), Some(CURLcode::Http3));

        // 3. A clean close after complete headers: success, and end of file.
        let mut done = H3StreamCtx::new();
        done.accept_response(
            &project_response(200, &empty).expect("a projection"),
        );
        done.note_closed(H3Error::NO_ERROR);
        assert_eq!(done.handle_close(false), StreamCloseOutcome::Complete);
        assert_eq!(done.handle_close(false).code(), None);
        assert!(!done.handle_close(false).should_retry());
    }

    #[test]
    fn a_non_zero_stream_error_closes_the_sending_side_too() {
        // `if(stream->error3 != NGHTTP3_H3_NO_ERROR) { reset = TRUE;
        //  send_closed = TRUE; }`
        let mut clean = H3StreamCtx::new();
        clean.note_closed(H3Error::NO_ERROR);
        assert!(clean.is_closed());
        assert!(!clean.was_reset());
        assert!(!clean.send_closed());

        let mut reset = H3StreamCtx::new();
        reset.note_closed(H3Error::FRAME_ERROR);
        assert!(reset.is_closed());
        assert!(reset.was_reset());
        assert!(reset.send_closed());
        assert_eq!(reset.error3(), H3Error::FRAME_ERROR);
    }

    #[test]
    fn the_quic_failure_table_is_the_codes_the_c_reports() {
        // The ten codes `lib/vquic/curl_ngtcp2.c` produces, by condition.
        let table = [
            (QuicFailure::Handshake, CURLcode::QuicConnectError),
            (QuicFailure::HandshakeTimeout, CURLcode::QuicConnectError),
            (QuicFailure::Verification, CURLcode::PeerFailedVerification),
            (QuicFailure::CouldntConnect, CURLcode::CouldntConnect),
            (QuicFailure::Init, CURLcode::FailedInit),
            (QuicFailure::Send, CURLcode::SendError),
            (QuicFailure::Recv, CURLcode::RecvError),
            (QuicFailure::Protocol, CURLcode::Http3),
            (QuicFailure::WeirdServerReply, CURLcode::WeirdServerReply),
            (QuicFailure::OutOfMemory, CURLcode::OutOfMemory),
        ];
        for (failure, code) in table {
            assert_eq!(failure.code(), code, "{failure:?}");
            assert_eq!(failure.into_error().code(), code);
            assert!(!failure.message().is_empty());
        }

        // The one message that is not this module's own words but the C's
        // `curl_easy_strerror` text verbatim (`lib/strerror.c:190`). Pinned
        // exactly, because it reaches stderr and because it is written as a
        // line-continued literal -- a `\` at end of line strips the newline AND
        // the next line's indentation, so a formatter re-indenting it must not
        // change the value, and this is what proves it did not.
        assert_eq!(
            QuicFailure::Verification.message(),
            "SSL peer certificate or SSH remote key was not OK"
        );
        // The pinned integers, which a C program holds in its instruction
        // stream.
        assert_eq!(CURLcode::Http3 as i32, 95);
        assert_eq!(CURLcode::QuicConnectError as i32, 96);
        assert_eq!(CURLcode::PeerFailedVerification as i32, 60);
        assert_eq!(CURLcode::PartialFile as i32, 18);
        assert_eq!(CURLcode::RecvError as i32, 56);
    }

    #[test]
    fn a_tls_certificate_alert_is_reported_as_a_verification_failure() {
        // RFC 9001 section 4.8 maps a TLS alert to `0x0100 + alert`, so the
        // certificate alerts occupy `0x012a..=0x0130` and `0x0170`.
        for raw in TLS_CERTIFICATE_ALERTS {
            let code = quinn::TransportErrorCode::crypto(
                u8::try_from(raw - 0x0100).expect("an alert value"),
            );
            assert!(is_certificate_alert(code), "0x{raw:x}");
        }
        // A non-certificate alert is a plain connect failure.
        for alert in [40_u8, 50, 70, 80] {
            let code = quinn::TransportErrorCode::crypto(alert);
            assert!(!is_certificate_alert(code), "alert {alert}");
        }
        // And a transport error that is not a crypto error at all.
        assert!(!is_certificate_alert(
            quinn::TransportErrorCode::PROTOCOL_VIOLATION
        ));
    }

    #[test]
    fn quinn_connection_errors_classify_to_the_c_conditions() {
        assert_eq!(
            classify_connection_error(&quinn::ConnectionError::TimedOut),
            QuicFailure::HandshakeTimeout
        );
        // `NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION` is the C's `break` arm, which
        // leaves the `CURLE_COULDNT_CONNECT` the draining block had already
        // chosen (`lib/vquic/curl_ngtcp2.c:2723-2729`).
        assert_eq!(
            classify_connection_error(&quinn::ConnectionError::VersionMismatch),
            QuicFailure::CouldntConnect
        );
        assert_eq!(
            QuicFailure::CouldntConnect.code(),
            CURLcode::CouldntConnect
        );
        // No identifier left to migrate to: a handshake failure before any
        // `CONNECTION_CLOSE`, so `cf_connect_start`'s code stands.
        assert_eq!(
            classify_connection_error(&quinn::ConnectionError::CidsExhausted),
            QuicFailure::Handshake
        );

        // A received `CONNECTION_CLOSE` is the draining period, and
        // `CONNECTION_REFUSED` -- transport error code 0x02, RFC 9000 section
        // 20.1 -- is the one code the C singles out, because *"when a QUIC
        // server instance is shutting down, it may send us a CONNECTION_CLOSE
        // with this code right away. We want to keep on trying in this case."*
        let refused =
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::CONNECTION_REFUSED,
                frame_type: None,
                reason: Bytes::new(),
            });
        assert_eq!(
            classify_connection_error(&refused),
            QuicFailure::WeirdServerReply
        );
        assert_eq!(
            QuicFailure::WeirdServerReply.code(),
            CURLcode::WeirdServerReply,
            "INCONCLUSIVE for the Happy Eyeballs race, per its own contract"
        );
        assert_eq!(
            u64::from(quinn::TransportErrorCode::CONNECTION_REFUSED),
            0x02,
            "the wire code, not just the name"
        );

        // Any other `CONNECTION_CLOSE` keeps the block's default, including the
        // crypto-error arm the C traces and does not reclassify.
        for code in [
            quinn::TransportErrorCode::PROTOCOL_VIOLATION,
            quinn::TransportErrorCode::INTERNAL_ERROR,
            quinn::TransportErrorCode::crypto(0x2f),
        ] {
            let closed = quinn::ConnectionError::ConnectionClosed(
                quinn::ConnectionClose {
                    error_code: code,
                    frame_type: None,
                    reason: Bytes::new(),
                },
            );
            assert_eq!(
                classify_connection_error(&closed),
                QuicFailure::CouldntConnect,
                "{code} must keep the draining default"
            );
        }
        assert_eq!(
            classify_connection_error(&quinn::ConnectionError::Reset),
            QuicFailure::Recv
        );
        assert_eq!(
            classify_connection_error(&quinn::ConnectionError::LocallyClosed),
            QuicFailure::Send
        );
        // An application close carrying `H3_NO_ERROR` is the peer going away
        // cleanly; carrying anything else it is a protocol failure.
        let clean = quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u64(H3Error::NO_ERROR.as_u64())
                    .expect("a varint"),
                reason: Bytes::new(),
            },
        );
        assert_eq!(classify_connection_error(&clean), QuicFailure::Recv);
        let broken = quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u64(
                    H3Error::FRAME_ERROR.as_u64(),
                )
                .expect("a varint"),
                reason: Bytes::new(),
            },
        );
        assert_eq!(classify_connection_error(&broken), QuicFailure::Protocol);
    }

    // -- 7. The transport, driven over the in-memory pair.

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn a_session_builds_an_endpoint_over_an_abstract_udp_socket() {
        // The whole of R-J: the endpoint is built with
        // `Endpoint::new_with_abstract_socket` over an `Arc<dyn
        // AsyncUdpSocket>`, and here that socket is a pair of in-memory
        // queues. No socket is opened and no packet reaches a network.
        let local = SocketAddr::from(([127, 0, 0, 1], 4433));
        let (factory, _far) = PairedUdpFactory::pair(local);
        let mut rng = TestRng::from_seed(7);
        let session = QuicSession::new(
            peer_v4(),
            "example.com",
            CurlTime::new(10, 0),
            &mut rng,
            &factory,
            &QlogWriter::with_dir(None),
        )
        .expect("an endpoint over the paired socket");

        assert_eq!(session.local_addr(), local);
        assert_eq!(session.peer(), peer_v4());
        assert_eq!(session.hostname(), "example.com");
        assert_eq!(session.scid().len(), QUIC_SCID_LEN);
        assert!(!session.has_qlog());
        assert!(!session.is_ready());
        assert!(!session.is_closed());
        // Nothing has arrived, so the reply time is the C's "until
        // determined".
        assert_eq!(session.connect_reply_ms(), -1);
        assert!(session.first_byte_at().is_zero());
        assert!(session.handshake_at().is_zero());
        // The egress buffer is the C's: `NW_CHUNK_SIZE`, `NW_SEND_CHUNKS`,
        // `BUFQ_OPT_SOFT_LIMIT`.
        assert_eq!(session.sendbuf().chunk_size(), NW_CHUNK_SIZE);
        assert_eq!(session.sendbuf().max_chunks(), NW_SEND_CHUNKS);
        assert!(session.sendbuf().opts().contains(BufqOpts::SOFT_LIMIT));

        // The quadruple `CF_QUERY_IP_INFO` answers.
        let quad = session.ip_quadruple();
        assert_eq!(quad.remote_ip, "192.0.2.1");
        assert_eq!(quad.remote_port, 443);
        assert_eq!(quad.local_ip, "127.0.0.1");
        assert_eq!(quad.local_port, 4433);
        assert_eq!(quad.transport, Transport::Quic);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn a_session_refuses_when_the_socket_factory_does() {
        let factory = PairedUdpFactory::refusing(CURLcode::CouldntConnect);
        let mut rng = TestRng::from_seed(1);
        assert_eq!(
            QuicSession::new(
                peer_v4(),
                "example.com",
                CurlTime::new(10, 0),
                &mut rng,
                &factory,
                &QlogWriter::with_dir(None),
            )
            .err(),
            Some(CURLcode::CouldntConnect)
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn a_session_records_the_first_byte_once_and_only_once() {
        let (factory, _far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let mut rng = TestRng::from_seed(1);
        let mut session = QuicSession::new(
            peer_v4(),
            "example.com",
            CurlTime::new(10, 0),
            &mut rng,
            &factory,
            &QlogWriter::with_dir(None),
        )
        .expect("an endpoint");

        assert!(!session.got_first_byte());
        session.note_first_byte(CurlTime::new(10, 250_000));
        assert!(session.got_first_byte());
        assert_eq!(session.first_byte_at(), CurlTime::new(10, 250_000));
        // 250 milliseconds after the attempt started.
        assert_eq!(session.connect_reply_ms(), 250);

        // A LATER byte does not move it: the measurement is of the FIRST
        // reply.
        session.note_first_byte(CurlTime::new(99, 0));
        assert_eq!(session.first_byte_at(), CurlTime::new(10, 250_000));
        assert_eq!(session.connect_reply_ms(), 250);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn the_stream_budget_is_the_c_arithmetic() {
        let (factory, _far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let mut rng = TestRng::from_seed(1);
        let mut session = QuicSession::new(
            peer_v4(),
            "example.com",
            CurlTime::new(10, 0),
            &mut rng,
            &factory,
            &QlogWriter::with_dir(None),
        )
        .expect("an endpoint");

        // Not ready: `*pres1 = 0`.
        assert_eq!(session.max_concurrent(3, 100), 0);

        // The counter is monotonic, as QUIC's own is.
        assert_eq!(session.used_bidi_streams(), 0);
        session.note_stream_opened();
        session.note_stream_opened();
        assert_eq!(session.used_bidi_streams(), 2);
        session.set_max_bidi_streams(QUIC_MAX_STREAMS);
        assert_eq!(QUIC_MAX_STREAMS, 256 * 1024);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn a_handshake_starts_and_asks_the_injected_crypto_for_h3() {
        let (mut filter, crypto, _far) = paired_filter(3);
        let clock = clock();
        let mut cx = CallCtx::new(&clock);

        // The first `connect` creates the session, configures the crypto and
        // starts the handshake. It cannot COMPLETE, because the far end of the
        // pair is a queue and not a server, so `Ok(false)` is the correct
        // answer -- which is what the C's `*done = FALSE` meant.
        let progressed = filter
            .connect(&mut cx)
            .expect("a handshake that has started");
        assert!(!progressed, "no peer, so not connected");
        assert!(!filter.base().is_connected());
        assert!(filter.session().is_some());

        // What was asked of the crypto seam: this host, verification ON, no
        // key log, and exactly the two ALPN bytes.
        let asked = crypto.requests();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].0, "example.com");
        assert!(asked[0].1, "verification is ON by default");
        assert!(!asked[0].2, "no key log unless asked for");
        assert_eq!(asked[0].3, vec![b"h3".to_vec()]);

        // A datagram DID leave: `Endpoint::connect` composes and sends the
        // Initial packet, and the paired socket recorded it. This is the proof
        // that `AsyncUdpSocket` is really the transport.
        for _ in 0..50 {
            if !_far
                .inbound
                .lock()
                .map(|mut rx| rx.try_recv().is_err())
                .unwrap_or(true)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn tls_verification_is_on_by_default_and_insecure_turns_it_off() {
        // Specification 0.8.1 freezes the default. `--insecure` is the ONLY
        // way past it, and the stderr warning it must emit first belongs to
        // `curl-rs/src/output/msgs.rs` -- this is the transport half.
        let request = QuicCryptoRequest::new("example.com", &[b"h3"]);
        assert!(request.verify_peer, "ON by default");
        assert!(!request.keylog);
        assert!(!request.with_verify_peer(false).verify_peer);
        assert!(request.with_keylog(true).keylog);

        let (mut filter, crypto, _far) = paired_filter(4);
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        assert!(filter.verify_peer, "the filter default is ON too");
        filter = filter.with_verify_peer(false).with_keylog(true);
        let _ = filter.connect(&mut cx);
        let asked = crypto.requests();
        assert_eq!(asked.len(), 1);
        assert!(!asked[0].1, "--insecure reached the seam");
        assert!(asked[0].2, "SSLKEYLOGFILE reached the seam");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn a_refused_crypto_configuration_stops_the_connection() {
        let (factory, _far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let mut filter = CfH3::new(
            peer_v4(),
            "example.com",
            SocketIndex::First,
            Arc::new(TestCrypto::refusing(CURLcode::SslConnectError)),
            Arc::new(factory),
            Box::new(TestRng::from_seed(5)),
        )
        .with_qlog(QlogWriter::with_dir(None));
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        assert_eq!(
            filter.connect(&mut cx).err().map(|error| error.code()),
            Some(CURLcode::SslConnectError)
        );
        assert!(!filter.base().is_connected());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn closing_a_session_leaves_it_unusable_and_clears_the_buffer() {
        let (factory, _far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let mut rng = TestRng::from_seed(1);
        let mut session = QuicSession::new(
            peer_v4(),
            "example.com",
            CurlTime::new(10, 0),
            &mut rng,
            &factory,
            &QlogWriter::with_dir(None),
        )
        .expect("an endpoint");
        session
            .sendbuf_mut()
            .write(b"queued")
            .expect("a soft-limited buffer accepts a write");
        assert!(!session.sendbuf().is_empty());

        session.close();
        assert!(session.is_closed());
        assert!(session.sendbuf().is_empty());
        assert!(session.connection().is_none());
        assert!(session.sender().is_none());
        // A closed session refuses to make progress rather than looping.
        let waker = Arc::new(FilterWaker::default());
        assert_eq!(
            session.poll_ready(&waker, CurlTime::new(11, 0)),
            Err(CURLcode::QuicConnectError)
        );
    }

    #[tokio::test]
    async fn a_filter_that_is_not_connected_refuses_to_send_or_receive() {
        let (mut filter, _crypto, _far) = paired_filter(6);
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        assert_eq!(
            filter
                .send(&mut cx, b"GET / HTTP/1.1\r\n\r\n", false)
                .err()
                .map(|error| error.code()),
            Some(CURLcode::SendError)
        );
        let mut buf = [0_u8; 16];
        assert_eq!(
            filter
                .recv(&mut cx, &mut buf)
                .err()
                .map(|error| error.code()),
            Some(CURLcode::RecvError)
        );
        // And it is dead, which is what stops the pool from reusing it.
        assert_eq!(filter.is_alive(&mut cx), Liveness::DEAD);
    }

    // -- 8. The waker, the stream buffers and the remaining measured
    //       constants.

    #[tokio::test]
    #[cfg_attr(miri, ignore = "binds a real datagram socket")]
    async fn the_production_socket_factory_binds_an_unconnected_socket() {
        // `Socket2UdpFactory` is the factory a real transfer gets, and it is
        // exercised here rather than left to integration: the whole of R-D
        // rests on it reaching an `AsyncUdpSocket` through `socket2` and
        // `tokio` with no `libc` call and no `unsafe`, and a path nothing runs
        // is a path nothing has checked.
        //
        // No packet leaves the host. The socket is BOUND to the wildcard
        // address on an ephemeral port and never connected, which is what
        // `socket_open` does for a UDP filter before Happy Eyeballs picks a
        // candidate; the peer address is only read for its FAMILY.
        let socket = Socket2UdpFactory
            .bind(peer_v4())
            .expect("an IPv4 datagram socket");
        let local = socket.local_addr().expect("a bound local address");
        assert!(local.is_ipv4(), "the family follows the peer's: {local}");
        assert_eq!(local.ip(), Ipv4Addr::UNSPECIFIED, "the wildcard address");
        assert_ne!(local.port(), 0, "an ephemeral port was assigned");

        // `quinn`'s contract for the abstract socket, as this adapter answers
        // it: one datagram per transmit, one per receive, and it may block.
        assert_eq!(socket.max_transmit_segments(), 1);
        assert_eq!(socket.max_receive_segments(), 1);

        // The IPv6 arm selects `Domain::IPV6`, and whether a container HAS IPv6
        // is not this module's contract -- so either outcome is accepted and
        // only the family is asserted when one is produced. Reporting
        // `CouldntConnect` for a host without IPv6 is the honest answer and is
        // what `socket_open`'s own failure produces.
        match Socket2UdpFactory.bind(peer_v6()) {
            Ok(v6) => {
                let local = v6.local_addr().expect("a bound local address");
                assert!(local.is_ipv6(), "the family follows the peer's");
                assert_eq!(
                    local.ip(),
                    std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                );
            }
            Err(code) => assert_eq!(
                code,
                CURLcode::CouldntConnect,
                "a host without IPv6 must report the socket failure"
            ),
        }
    }

    #[test]
    fn the_production_socket_factory_refuses_without_a_reactor() {
        // `tokio::net::UdpSocket::from_std` PANICS when no runtime is entered,
        // and specification 0.8.2 admits no panic on a production path. The
        // guard is `Handle::try_current`, and this test is what proves it fires
        // BEFORE any socket is created: no `#[tokio::test]` here, so there is
        // no runtime to find.
        assert_eq!(
            Socket2UdpFactory.bind(peer_v4()).err(),
            Some(CURLcode::FailedInit)
        );
        // Reported as a configuration failure, which is what `QuicFailure::Init`
        // maps to -- not as a network failure, because nothing was attempted.
        assert_eq!(QuicFailure::Init.code(), CURLcode::FailedInit);
        assert_ne!(QuicFailure::Init.code(), CURLcode::CouldntConnect);
    }

    #[test]
    fn the_waker_records_a_wake_and_clears_it_on_the_read() {
        let waker = Arc::new(FilterWaker::default());
        assert!(!waker.take_woken());
        futures::task::ArcWake::wake_by_ref(&waker);
        assert!(waker.take_woken());
        assert!(!waker.take_woken(), "the read clears it");
    }

    #[test]
    fn polling_a_ready_future_once_completes_without_blocking() {
        let waker = Arc::new(FilterWaker::default());
        let mut ready = Box::pin(async { 42_u32 });
        assert_eq!(waker.poll_once(ready.as_mut()), Poll::Ready(42));

        // And a future that is not ready reports Pending rather than parking,
        // which is what lets a synchronous filter callback return to curl's
        // event loop.
        let mut pending = Box::pin(futures::future::pending::<u32>());
        assert_eq!(waker.poll_once(pending.as_mut()), Poll::Pending);
    }

    #[test]
    fn closing_the_sending_side_computes_upload_left_once() {
        let mut stream = H3StreamCtx::new();
        assert_eq!(stream.upload_left(), -1, "unknown until the side closes");
        stream.buffer_send(b"0123456789").expect("a body write");
        stream.note_in_flight(4);
        stream.close_send();
        assert!(stream.send_closed());
        // `Curl_bufq_len(&sendbuf) - sendbuf_len_in_flight` = 10 - 4.
        assert_eq!(stream.upload_left(), 6);

        // A SECOND close must not recompute from a buffer that has drained.
        stream.note_acked(6);
        stream.close_send();
        assert_eq!(stream.upload_left(), 6, "the guard is load-bearing");
    }

    #[test]
    fn the_stream_send_buffer_is_the_c_shape() {
        let stream = H3StreamCtx::new();
        assert_eq!(stream.sendbuf().chunk_size(), H3_STREAM_CHUNK_SIZE);
        assert_eq!(stream.sendbuf().max_chunks(), H3_STREAM_SEND_CHUNKS);
        // `BUFQ_OPT_NONE`, NOT the soft limit: *"on send, we control how much
        // we put into the buffer"*.
        assert!(!stream.sendbuf().opts().contains(BufqOpts::SOFT_LIMIT));
        assert_eq!(stream.sendbuf().opts(), BufqOpts::NONE);
        assert_eq!(stream.id(), H3_STREAM_ID_NONE);
        assert_eq!(H3_STREAM_ID_NONE, -1);
        assert!(!stream.is_open());
        stream_is_open_after_an_identifier_arrives();
    }

    fn stream_is_open_after_an_identifier_arrives() {
        let mut stream = H3StreamCtx::new();
        stream.set_id(0);
        assert!(stream.is_open(), "identifier 0 IS a stream");
        stream.set_id(4);
        assert_eq!(stream.id(), 4);
    }

    #[test]
    fn the_receive_window_grows_and_never_shrinks() {
        let mut stream = H3StreamCtx::new();
        assert_eq!(stream.window_size_max(), H3_STREAM_WINDOW_SIZE_INITIAL);
        assert_eq!(stream.rx_window(), (0, H3_STREAM_WINDOW_SIZE_INITIAL));

        stream.grow_window(H3_STREAM_WINDOW_SIZE_MAX);
        assert_eq!(stream.window_size_max(), H3_STREAM_WINDOW_SIZE_MAX);

        // *"We need to start small as we are not able to decrease it."*
        stream.grow_window(H3_STREAM_WINDOW_SIZE_INITIAL);
        assert_eq!(stream.window_size_max(), H3_STREAM_WINDOW_SIZE_MAX);

        // And the maximum is a ceiling, not a suggestion.
        stream.grow_window(u64::MAX);
        assert_eq!(stream.window_size_max(), H3_STREAM_WINDOW_SIZE_MAX);
    }

    #[test]
    fn projected_bytes_are_handed_over_before_any_error_is_reported() {
        let mut stream = H3StreamCtx::new();
        let empty = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        stream.accept_response(
            &project_response(200, &empty).expect("a projection"),
        );
        stream.accept_body(b"body");
        assert!(stream.has_pending());
        assert_eq!(stream.received_data(), 4);

        let mut buf = [0_u8; 8];
        let taken = stream.take_response(&mut buf);
        assert_eq!(&buf[..taken], b"HTTP/3 2");
        // The rest is still there: a partial read leaves the remainder.
        assert!(stream.has_pending());

        let mut rest = vec![0_u8; 256];
        let mut total = Vec::new();
        loop {
            let read = stream.take_response(&mut rest);
            if read == 0 {
                break;
            }
            total.extend_from_slice(&rest[..read]);
        }
        assert_eq!(total, b"00 \r\n\r\nbody".to_vec());
        assert!(!stream.has_pending());
    }

    #[test]
    fn a_recorded_transfer_failure_is_reported_once_the_bytes_are_gone() {
        let mut stream = H3StreamCtx::new();
        assert_eq!(stream.xfer_result(), None);
        stream.set_xfer_result(CURLcode::WriteError);
        // The FIRST recorded failure wins, as the C's single field does.
        stream.set_xfer_result(CURLcode::Http3);
        assert_eq!(stream.xfer_result(), Some(CURLcode::WriteError));
    }

    #[test]
    fn freeing_a_stream_releases_its_buffers() {
        let mut stream = H3StreamCtx::new();
        stream.buffer_send(b"body").expect("a body write");
        let empty = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        stream.accept_response(
            &project_response(200, &empty).expect("a projection"),
        );
        assert!(stream.has_pending());
        stream.free();
        assert!(!stream.has_pending());
        assert!(stream.sendbuf().is_empty());
        assert_eq!(stream.trailers().count(), 0);
    }

    #[test]
    fn the_measured_constants_hold_the_c_relations() {
        assert_eq!(MAX_UDP_PAYLOAD_SIZE, 1452);
        assert_eq!(NW_CHUNK_SIZE, 64 * 1024);
        assert_eq!(NW_SEND_CHUNKS, 1);
        assert_eq!(NW_SEND_OPTS, BufqOpts::SOFT_LIMIT);
        assert_eq!(QUIC_MAX_STREAMS, 262_144);
        assert_eq!(QUIC_HANDSHAKE_TIMEOUT_MS, 10_000);
        assert_eq!(H3_STREAM_WINDOW_SIZE_INITIAL, 32 * 1024);
        assert_eq!(H3_STREAM_WINDOW_SIZE_MAX, 10 * 1024 * 1024);
        assert_eq!(H3_CONN_WINDOW_SIZE_MAX, 100 * H3_STREAM_WINDOW_SIZE_MAX);
        assert_eq!(H3_STREAM_CHUNK_SIZE, 64 * 1024);
        assert_eq!(H3_STREAM_POOL_SPARES, 2);
        assert_eq!(H3_STREAM_SEND_BUFFER_MAX, 10 * 1024 * 1024);
        assert_eq!(H3_STREAM_SEND_CHUNKS, 160);
        assert_eq!(H3_MAX_FIELD_SECTION_SIZE, (1_u64 << 62) - 1);

        // The C's `#error H3_STREAM_CHUNK_SIZE smaller than
        // NGTCP2_MAX_UDP_PAYLOAD_SIZE` is reproduced as the module-level
        // `const _: () = assert!(..)` beside the two constants, so it fails the
        // BUILD exactly as the `#error` does rather than a test run. Asserting
        // it again here would be an assertion on constants, which clippy
        // rejects and which adds nothing the build gate already guarantees --
        // what is worth pinning is each operand's measured value, above.
        assert_eq!(DEFAULT_MAX_CONCURRENT_STREAMS, 100);
    }

    #[test]
    fn the_transport_parameters_are_the_c_settings_not_quinns_defaults() {
        // `quic_settings` (`lib/vquic/curl_ngtcp2.c:455-491`). The five values
        // travel in the ClientHello's QUIC transport-parameters extension, so a
        // `quinn` default left in place is a WIRE difference, which is why each
        // one is asserted rather than assumed.
        //
        // `quinn` exposes no getters, so the `Debug` rendering is the only
        // reachable view. That is a weaker instrument than a field read, and it
        // is used deliberately: a silently-dropped setting is a far worse
        // outcome than a test that depends on a `Debug` format, and the four
        // numbers below would each be a different number if the call were
        // dropped.
        let rendered = format!("{:?}", transport_config());
        let contains = |needle: &str| {
            assert!(
                rendered.contains(needle),
                "transport parameter missing: {needle}\nin {rendered}"
            );
        };

        // `t->initial_max_streams_bidi = QUIC_MAX_STREAMS` and `_uni` the same;
        // `quinn`'s default for both is 100.
        contains("max_concurrent_bidi_streams: 262144");
        contains("max_concurrent_uni_streams: 262144");
        // `t->max_idle_timeout = 0` -- "no idle timeout from our side";
        // `quinn`'s default is `Some(30 s)`.
        contains("max_idle_timeout: None");
        // `t->initial_max_stream_data_bidi_local` and `_remote` =
        // H3_STREAM_WINDOW_SIZE_INITIAL; `quinn`'s default is 1,250,000.
        contains("stream_receive_window: 32768");
        // `t->initial_max_data = s->max_window = H3_CONN_WINDOW_SIZE_MAX`;
        // `quinn`'s default is `VarInt::MAX`.
        contains("receive_window: 1048576000");

        // The four values are the constants, not coincidences.
        assert_eq!(QUIC_MAX_STREAMS, 262_144);
        assert_eq!(H3_STREAM_WINDOW_SIZE_INITIAL, 32_768);
        assert_eq!(H3_CONN_WINDOW_SIZE_MAX, 1_048_576_000);

        // `s->no_pmtud = FALSE` keeps path-MTU discovery on, which is what
        // `quinn` does by default -- and its upper bound is 1452, the same
        // ceiling `MAX_UDP_PAYLOAD_SIZE` records, so no override is needed for
        // the two to agree.
        contains("mtu_discovery_config: Some(");
        contains("upper_bound: 1452");
        assert_eq!(MAX_UDP_PAYLOAD_SIZE, 1_452);
    }

    #[test]
    fn a_varint_is_clamped_rather_than_defaulted_to_zero() {
        // Every real call site is a window or a stream budget, where zero would
        // stall the connection and the maximum merely fails to restrict.
        assert_eq!(varint_saturating(0).into_inner(), 0);
        assert_eq!(varint_saturating(262_144).into_inner(), 262_144);
        assert_eq!(
            varint_saturating(u64::MAX).into_inner(),
            quinn::VarInt::MAX.into_inner()
        );
        // The clamp never fires for anything this module passes.
        assert!(H3_CONN_WINDOW_SIZE_MAX < quinn::VarInt::MAX.into_inner());
        assert!(QUIC_MAX_STREAMS < quinn::VarInt::MAX.into_inner());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn the_handshake_deadline_comes_from_the_injected_clock() {
        // `s->handshake_timeout` (`lib/vquic/curl_ngtcp2.c:471-472`), enforced
        // without a timer so that a test decides the time.
        let (factory, _far) =
            PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
        let clock = clock();
        let mut rng = TestRng::from_seed(7);
        let qlog = QlogWriter::with_dir(None);
        let mut session = QuicSession::new(
            peer_v4(),
            "example.com",
            clock.now(),
            &mut rng,
            &factory,
            &qlog,
        )
        .expect("a session over the paired socket");
        assert_eq!(session.handshake_timeout_ms(), QUIC_HANDSHAKE_TIMEOUT_MS);

        // `Idle` never expires, and an hour spent there does not eat into the
        // deadline: the C stamps `ctx->started_at` immediately before
        // `cf_connect_start` (`:2688`), so the clock starts at the CONNECT.
        clock.advance(Duration::from_secs(3_600));
        let waker = Arc::new(FilterWaker::default());
        assert_eq!(session.poll_ready(&waker, clock.now()).ok(), Some(false));

        // Once the handshake is under way, the deadline applies. The paired
        // socket has no peer answering, so it can only ever be pending.
        let crypto = TestCrypto::new();
        session
            .start_handshake(&crypto, true, false, clock.now())
            .expect("the handshake starts");
        assert_eq!(session.poll_ready(&waker, clock.now()).ok(), Some(false));

        // One millisecond short of the deadline is still pending; the C's test
        // is `>=`, so the boundary belongs to the timeout.
        clock.advance(Duration::from_millis(9_999));
        assert_eq!(session.poll_ready(&waker, clock.now()).ok(), Some(false));
        clock.advance(Duration::from_millis(1));
        assert_eq!(
            session.poll_ready(&waker, clock.now()).err(),
            Some(CURLcode::QuicConnectError)
        );
        assert_eq!(
            QuicFailure::HandshakeTimeout.code(),
            CURLcode::QuicConnectError
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    async fn a_configured_connect_timeout_replaces_the_fallback() {
        // `(data->set.connecttimeout > 0) ? ... : QUIC_HANDSHAKE_TIMEOUT`.
        let clock = clock();
        let mut rng = TestRng::from_seed(8);
        let qlog = QlogWriter::with_dir(None);
        // A fresh pair per session: `PairedUdpFactory` hands out its socket
        // ONCE, which is itself the contract `QuicSocketFactory` has -- one
        // bound socket per connection attempt.
        let build = |rng: &mut TestRng| {
            let (factory, far) =
                PairedUdpFactory::pair(SocketAddr::from(([127, 0, 0, 1], 0)));
            let session = QuicSession::new(
                peer_v4(),
                "example.com",
                clock.now(),
                rng,
                &factory,
                &qlog,
            )
            .expect("a session over the paired socket");
            (session, far)
        };

        // Not positive leaves the fallback in place -- both halves of the C's
        // `> 0`, because a zero option value means "unset", not "immediately".
        assert_eq!(
            build(&mut rng)
                .0
                .with_handshake_timeout_ms(0)
                .handshake_timeout_ms(),
            QUIC_HANDSHAKE_TIMEOUT_MS
        );
        assert_eq!(
            build(&mut rng)
                .0
                .with_handshake_timeout_ms(-1)
                .handshake_timeout_ms(),
            QUIC_HANDSHAKE_TIMEOUT_MS
        );

        // A positive value replaces it, and is what the deadline then uses.
        let (session, _far) = build(&mut rng);
        let mut session = session.with_handshake_timeout_ms(250);
        assert_eq!(session.handshake_timeout_ms(), 250);
        let crypto = TestCrypto::new();
        session
            .start_handshake(&crypto, true, false, clock.now())
            .expect("the handshake starts");
        let waker = Arc::new(FilterWaker::default());
        clock.advance(Duration::from_millis(249));
        assert_eq!(session.poll_ready(&waker, clock.now()).ok(), Some(false));
        clock.advance(Duration::from_millis(1));
        assert_eq!(
            session.poll_ready(&waker, clock.now()).err(),
            Some(CURLcode::QuicConnectError)
        );
    }
    #[test]
    fn the_version_token_is_the_pinned_pair() {
        // `Curl_quic_ver`'s successor: ONE string containing a space, because
        // `lib/version.c:243-246` appends the whole buffer as one element of
        // `src[]`. `crate::version`'s `HTTP3_TOKEN` is assembled from the same
        // pinned literals, so this assertion is what keeps the two from
        // drifting.
        assert_eq!(quic_ver(), "quinn/0.11.9 h3/0.0.8");
        assert_eq!(quic_ver(), QUIC_VERSION_TOKEN);
        assert_eq!(quic_ver().matches(' ').count(), 1);
        assert!(quic_ver().starts_with("quinn/"));
        assert!(quic_ver().contains(" h3/"));
        // And it must NEVER name the C libraries it replaced.
        for banned in ["ngtcp2", "nghttp3", "quiche"] {
            assert!(!quic_ver().contains(banned), "{banned}");
        }
    }

    #[test]
    fn initialization_succeeds_because_the_provider_is_fixed_at_build_time() {
        // The C's `#else #define Curl_vquic_init() 1` and its
        // `ngtcp2_crypto_ossl_init()` guard both reduce to this: there is no
        // ngtcp2 and the `ring` provider is selected by feature, so nothing
        // needs installing and nothing can fail.
        assert!(vquic_init());
    }

    #[test]
    fn a_head_is_complete_at_either_terminator() {
        assert!(!h3_head_is_complete(b"GET / HTTP/1.1\r\n"));
        assert!(h3_head_is_complete(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(h3_head_is_complete(b"GET / HTTP/1.1\n\n"));
        assert_eq!(h3_head_length(b"GET / HTTP/1.1\r\n\r\nbody"), 18);
        assert_eq!(h3_head_length(b"GET / HTTP/1.1\n\nbody"), 16);
        // No terminator: the whole slice, which is the case
        // `h3_head_is_complete` has already excluded.
        assert_eq!(h3_head_length(b"partial"), 7);
    }

    #[test]
    fn the_h3_error_display_is_the_hexadecimal_form_the_c_traces() {
        assert_eq!(
            H3Error::REQUEST_REJECTED.to_string(),
            "REQUEST_REJECTED (0x10b)"
        );
        assert_eq!(H3Error::from_u64(0x9999).to_string(), "unknown (0x9999)");
    }

    #[test]
    fn a_stream_error_yields_the_peers_code_where_h3_carries_one() {
        // `RemoteTerminate { code }` is the peer resetting its sending side or
        // asking us to stop, which is exactly what `cb_h3_stream_close` and
        // `cb_h3_stop_sending` receive as `app_error_code`; `StreamError
        // { code, .. }` is a local failure `h3` has already classified. Both
        // carry a code, and the code is taken verbatim.
        assert_eq!(
            h3_code_or_internal(Some(h3::error::Code::H3_REQUEST_REJECTED)),
            H3Error::REQUEST_REJECTED
        );
        assert_eq!(
            h3_code_or_internal(Some(h3::error::Code::H3_MESSAGE_ERROR)),
            H3Error::MESSAGE_ERROR
        );
        assert_eq!(
            h3_code_or_internal(Some(h3::error::Code::H3_NO_ERROR)),
            H3Error::NO_ERROR
        );

        // A code `h3` does not name still round-trips, because `from_u64` is
        // total -- the C's `app_error_code` is an opaque varint too.
        let unnamed = h3::error::Code::H3_STREAM_CREATION_ERROR;
        assert_eq!(
            h3_code_or_internal(Some(unnamed)),
            H3Error::from_u64(0x103)
        );

        // The remaining four variants -- `ConnectionError`, `HeaderTooBig`,
        // `RemoteClosing` (a received `GOAWAY`) and `Undefined` -- carry no
        // HTTP/3 code, and the C infers `H3_INTERNAL_ERROR` for the same
        // situation (`lib/vquic/curl_ngtcp2.c:596-604`).
        assert_eq!(h3_code_or_internal(None), H3Error::INTERNAL_ERROR);
    }

    #[test]
    fn h3s_stream_error_cannot_be_constructed_outside_its_own_crate() {
        // Recorded as an assertion rather than a comment because it is the
        // reason `stream_error_code` is SPLIT: every variant of
        // `h3::error::StreamError` is `#[non_exhaustive]` under the default
        // feature set, so a struct expression for any of them is
        // `error[E0639]` and no value can be built here to feed the adapter.
        //
        // What CAN be checked is that the three halves still have the shapes
        // that make the split sound, and that is checked by BINDING each to an
        // explicitly typed `fn` pointer: the coercion only compiles while the
        // signature is unchanged, so a future `h3` that renames a code-carrying
        // variant or changes `Code` fails to compile HERE rather than silently
        // reporting `INTERNAL_ERROR` for a reset. The bindings are then
        // exercised, because a binding nothing calls proves only that the name
        // exists.
        //
        // Deliberately NOT done with `core::ptr::eq` on the coerced pointers:
        // function-pointer identity is not a guarantee Rust makes -- the
        // reference explicitly permits distinct coercions of one function to
        // compare unequal, and Miri reports exactly that. An assertion that
        // holds under rustc and fails under Miri would be a false defect in the
        // undefined-behaviour gate, which is the one gate that must never cry
        // wolf.
        let extract: fn(&h3::error::StreamError) -> Option<h3::error::Code> =
            stream_error_h3_code;
        let map: fn(Option<h3::error::Code>) -> H3Error = h3_code_or_internal;
        let composed: fn(&h3::error::StreamError) -> H3Error =
            stream_error_code;

        // `map` is total, so the pair covers every value `composed` can be
        // handed: either a code came out of `extract` or none did.
        assert_eq!(
            map(None),
            H3Error::INTERNAL_ERROR,
            "the code-less class must infer INTERNAL_ERROR"
        );
        assert_eq!(
            map(Some(h3::error::Code::H3_REQUEST_REJECTED)),
            H3Error::REQUEST_REJECTED
        );

        // And the composition really is `map` applied to `extract`'s output
        // `composed` can receive -- which is checked by driving all three
        // through the same closure, since no `StreamError` value exists to feed
        // them directly.
        let through_composition =
            |code: Option<h3::error::Code>| -> H3Error { map(code) };
        for code in [
            None,
            Some(h3::error::Code::H3_NO_ERROR),
            Some(h3::error::Code::H3_REQUEST_REJECTED),
        ] {
            assert_eq!(through_composition(code), h3_code_or_internal(code));
        }
        // `extract` and `composed` are named in a position that forces their
        // types without calling them, which is all a value-less type can be
        // held to.
        let _shapes: (
            fn(&h3::error::StreamError) -> Option<h3::error::Code>,
            fn(&h3::error::StreamError) -> H3Error,
        ) = (extract, composed);
    }
}
