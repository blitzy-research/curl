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

// THE LICENCE BANNER ABOVE -- 23 lines, byte-identical to `lib/cfilters.c:1-23`
// with the C block comment converted to line comments. `conn/` is curl-licensed
// throughout; the ISC banner that heads `util/inet.rs` belongs to that file's
// BSD-derived original and must not be copied here.
//
// The licence tag appears exactly once, on line 21, and nowhere else in this
// file -- not even in prose. `reuse` reads every line carrying the tag's colon
// form as a licence expression, so a second mention becomes a parse error
// rather than a comment. `conn/mod.rs:25-61` and `util/mod.rs:25-61` record the
// full reasoning; it is not repeated here.
//
// `dead_code` IS NOT ALLOWED for this file as a whole, and no attribute below
// grants it at module scope. Items whose consumers have yet to land carry their
// own `#[allow(dead_code)]`, so the suppressions read as an inventory: each one
// is load-bearing, deleting any one restores a warning, and an item added later
// with no consumer is still reported. That is enforced rather than agreed --
// `mod source_policy` in `curl-rs-lib/src/lib.rs` walks the workspace at test
// time and fails on a `dead_code` level set on any crate root or module root.
//
// The allowances here are expected to be short-lived and their pattern is
// structural: this module is the COMPOSITION MECHANISM, so its consumers are
// the filters themselves -- `conn/socket.rs`, `conn/happy_eyeballs.rs`,
// `tls/`, `proxy/` and `protocols/{http2,http3}` -- together with the transfer
// loop that drives a chain. None of them exists yet. Each allowance is deleted
// when its consumer lands.
//
// No level for the `unsafe_code` lint is set here, at any level, and the
// keyword itself does not appear in any expression in this file. `src/lib.rs`
// carries `#![deny(unsafe_code)]` and grants exactly ONE exemption, on
// `mod ffi`. That matters more here than almost anywhere else in the crate: the
// C original is built out of a raw context pointer that every filter casts to
// its own type, and reproducing the same composition with a typed field is this
// module's entire reason to exist.

//! The connection filter chain -- supersedes `lib/cfilters.c` (1,104 lines) and
//! `lib/cfilters.h` (687).
//!
//! Measured against `lib/cfilters.h:36-237,239-353,470-491,620-687` and
//! `lib/cfilters.c:36-136,212-421,446-592,594-1104`, with contract context from
//! `lib/urldata.h`, `lib/curl_trc.c`, `lib/curl_trc.h`, `lib/vtls/vtls_int.h`,
//! `lib/vquic/vquic.h`, `lib/cf-haproxy.c` and `lib/select.h`.
//!
//! A filter chain is what sits between a protocol and a socket. Bytes leaving a
//! transfer enter at the top and are handed down link by link -- HTTP/2
//! framing, then TLS, then a `CONNECT` tunnel, then the socket -- and bytes
//! arriving travel back up the same way. The chain is the crate's ONLY
//! composition mechanism for raw sockets, TLS, proxies, HTTP/2 and HTTP/3;
//! there is deliberately no parallel per-protocol stack, which is what lets
//! `crate::protocols` name no TLS type at all while TLS is interposed
//! transparently beneath it.
//!
//! # What the C expresses, and how
//!
//! Two structures, quoted verbatim so the translation can be checked against
//! them:
//!
//! ```text
//! struct Curl_cftype {                       /* lib/cfilters.h:210-226 */
//!   const char *name;
//!   int flags;
//!   int log_level;
//!   Curl_cft_destroy_this *destroy;
//!   Curl_cft_connect *do_connect;
//!   Curl_cft_close *do_close;
//!   Curl_cft_shutdown *do_shutdown;
//!   Curl_cft_adjust_pollset *adjust_pollset;
//!   Curl_cft_data_pending *has_data_pending;
//!   Curl_cft_send *do_send;
//!   Curl_cft_recv *do_recv;
//!   Curl_cft_cntrl *cntrl;
//!   Curl_cft_conn_is_alive *is_alive;
//!   Curl_cft_conn_keep_alive *keep_alive;
//!   Curl_cft_query *query;
//! };
//!
//! struct Curl_cfilter {                      /* lib/cfilters.h:229-237 */
//!   const struct Curl_cftype *cft;
//!   struct Curl_cfilter *next;
//!   void *ctx;
//!   struct connectdata *conn;
//!   int sockindex;
//!   BIT(connected);
//!   BIT(shutdown);
//! };
//! ```
//!
//! `Curl_cftype` is a hand-rolled vtable: fifteen members, of which twelve are
//! function pointers. `Curl_cfilter` is one instance of it, and the `void *ctx`
//! at `lib/cfilters.h:232` is where each implementation keeps its own state.
//!
//! # The one thing that had to change
//!
//! **The untyped context disappears.** Every C filter begins its methods by
//! casting `cf->ctx` back to the type it knows it put there, and the TLS filter
//! goes a step further and casts through it twice:
//!
//! ```text
//! #define CF_CTX_CALL_DATA(cf) \             /* lib/vtls/vtls_int.h:136-137 */
//!   ((struct ssl_connect_data *)(cf)->ctx)->call_data
//! ```
//!
//! Here, an implementing struct owns a [`FilterBase`] and keeps its own state in
//! an ORDINARY CONCRETE FIELD beside it. Nothing in this chain erases a type and
//! nothing recovers one: there is no untyped context pointer, no dynamic type
//! test, no cast back to a concrete type, and no type-erased container at any
//! point. The specification names the C cast as the largest single source of
//! unsound patterns in the tree, and removing it is what makes the rest of the
//! safety guarantee reachable.
//!
//! Two C mechanisms vanish with it and have no successor under any name.
//! `struct cf_call_data` and the `CF_DATA_SAVE`/`CF_DATA_RESTORE` pair
//! (`lib/cfilters.h:620-685`) exist only so that a re-entrant call can find the
//! easy handle again after a `void *` has erased it; an explicit typed
//! [`CallCtx`] parameter carries it instead, so a nested call needs no saved
//! state and no depth counter.
//!
//! # What did NOT change
//!
//! Everything observable. The default method bodies are transcribed from
//! `lib/cfilters.c:36-116` rather than from the summary comment at
//! `lib/cfilters.h:239-244`, which is stale in two places, and the oddities they
//! contain are preserved deliberately:
//!
//! * [`ConnFilter::adjust_pollset`] is a PURE NO-OP, not a pass-through
//!   (`lib/cfilters.c:55-64`, whose body is the literal comment `/* NOP */`).
//!   The prose at `lib/cfilters.h:64-67` says implementations must call lower
//!   filters; the code says otherwise and the code wins.
//!   [`FilterChain::adjust_pollset`], the DRIVER, is what walks the chain.
//! * [`ConnFilter::send`] bottoms out at [`CURLcode::RecvError`] and
//!   [`ConnFilter::recv`] at [`CURLcode::SendError`]
//!   (`lib/cfilters.c:73-90`). The pair looks swapped because it IS swapped,
//!   and a caller comparing an error code cannot be told that it is not.
//! * Exactly three callbacks must not chain: destroy, shutdown and control
//!   (`lib/cfilters.h:36-51,129-135`).
//! * [`FilterChain::discard_chain`] severs each link BEFORE destroying it and
//!   walks front to back (`lib/cfilters.c:118-136`) -- the opposite of the
//!   tail-first destruction `crate::util::llist` reproduces for the intrusive
//!   lists elsewhere in the tree.
//!
//! # Trace integration assumes nothing about how either C structure is laid out
//!
//! The filter table and the feature table are two SEPARATE typed registries,
//! never conflated and never reinterpreted as one another.
//! `lib/curl_trc.c:503-570` defines both -- `trc_feats[]` over
//! `struct curl_trc_feat` and `trc_cfts[]` over `struct Curl_cftype` -- and the
//! two do not even agree on field order: the filter table's row carries `flags`
//! between `name` and `log_level`, and the feature table's row has no such
//! member at all. A filter here reports a stable
//! [`ConnFilter::trace_name`] and its [`ConnFilter::trace_filter`] identity,
//! and the mutable per-name level that `--trace-config` writes lives in
//! [`crate::trace::TraceConfig`], reached through
//! [`Tracer::is_filter_verbose`]. A static filter type holds no mutable level.
//!
//! # Asynchrony stops at the driver
//!
//! The twelve trait methods are SYNCHRONOUS and non-blocking, exactly as their
//! C originals are: a `connect` reports `done = false` and expects to be called
//! again. That is not a concession, it is the only shape available -- `async fn`
//! in a trait is not object-safe on the pinned MSRV, and a chain is
//! `dyn`-dispatched by construction. The asynchrony lives one level up, in
//! [`FilterChain::connect`], which awaits readiness through
//! [`crate::conn::select`] and never touches `poll` or `select` itself.

use core::fmt;
use core::pin::Pin;
use std::net::SocketAddr;

use pin_project_lite::pin_project;

use crate::conn::select::{
    is_valid_sock, EasyPollset, PollFds, Socket, CURL_SOCKET_BAD,
};
use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::trace::{trc_cf, TraceFilter, Tracer};
use crate::util::bufq::BufQ;
use crate::util::timediff::{tvtoms, TimeDiff};
use crate::util::timeval::{Clock, CurlTime};

// =========================================================================
// Socket index -- `FIRSTSOCKET` / `SECONDARYSOCKET`
// =========================================================================

/// `FIRSTSOCKET` (`lib/urldata.h:421`): the primary socket of a connection.
pub(crate) const FIRSTSOCKET: i32 = 0;

/// `SECONDARYSOCKET` (`lib/urldata.h:422`): the second socket, which only FTP
/// uses -- one chain for the control connection and one for the data
/// connection.
pub(crate) const SECONDARYSOCKET: i32 = 1;

/// Which of a connection's two filter chains a filter belongs to.
///
/// `int sockindex` (`lib/cfilters.h:234`) becomes a type, because the C value is
/// an index into `conn->cfilter[2]` (`lib/urldata.h:646`) and every C entry
/// point guards it with `CONN_SOCK_IDX_VALID(i)` -- `i >= 0 && i < 2`
/// (`lib/urldata.h:648`) -- returning `CURLE_BAD_FUNCTION_ARGUMENT` when the
/// guard fails. Making the index a two-variant type moves that guard to the
/// single place a raw integer enters, [`Self::from_i32`], and removes it from
/// every entry point after it.
///
/// The conversion is CHECKED and deliberately not lenient: an unrecognised
/// integer is [`CURLcode::BadFunctionArgument`], never a silent fall back to
/// the primary socket. That distinction matters because
/// [`FilterChains::sockindex_of`] DOES fall back to the primary, and it must be
/// possible to tell the two behaviours apart -- see that method for why the C
/// does it there and only there.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum SocketIndex {
    /// `FIRSTSOCKET`, the primary socket. The default, as C's zeroed
    /// `struct Curl_cfilter` is.
    #[default]
    First = FIRSTSOCKET as isize,
    /// `SECONDARYSOCKET`, used by FTP for the data connection.
    #[allow(dead_code)]
    Secondary = SECONDARYSOCKET as isize,
}

impl SocketIndex {
    /// How many chains a connection has: `conn->cfilter[2]`.
    #[allow(dead_code)]
    pub(crate) const COUNT: usize = 2;

    /// Both indices in `conn->cfilter[]` order, for the drivers that visit
    /// every chain (`cf_cntrl_all`, `lib/cfilters.c:446-461`, and
    /// `Curl_conn_adjust_pollset`, `:788-801`).
    #[allow(dead_code)]
    pub(crate) const ALL: [Self; Self::COUNT] = [Self::First, Self::Secondary];

    /// The index as the C integer.
    #[allow(dead_code)]
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The index as a subscript.
    #[allow(dead_code)]
    pub(crate) const fn as_usize(self) -> usize {
        self as usize
    }

    /// `CONN_SOCK_IDX_VALID(i)` (`lib/urldata.h:648`).
    #[allow(dead_code)]
    pub(crate) const fn is_valid(raw: i32) -> bool {
        raw >= FIRSTSOCKET && raw < FIRSTSOCKET + Self::COUNT as i32
    }

    /// The checked conversion every C entry point performs inline.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for anything outside `0..2`, which is
    /// what `Curl_conn_shutdown` (`lib/cfilters.c:165-166`), `Curl_conn_connect`
    /// (`:505-506`), `Curl_conn_flush` (`:967-968`), `Curl_conn_keep_alive`
    /// (`:1011-1012`), `Curl_conn_recv` (`:1067-1068`) and `Curl_conn_send`
    /// (`:1084-1085`) all return.
    #[allow(dead_code)]
    pub(crate) fn from_i32(raw: i32) -> CodeResult<Self> {
        match raw {
            FIRSTSOCKET => Ok(Self::First),
            SECONDARYSOCKET => Ok(Self::Secondary),
            _ => Err(CURLcode::BadFunctionArgument),
        }
    }
}

// =========================================================================
// Filter type flags -- `CF_TYPE_*`
// =========================================================================

/// The `flags` member of `struct Curl_cftype` (`lib/cfilters.h:212`).
///
/// A set of capabilities, held as a bitmap because the chain queries in
/// `lib/cfilters.c:615-729` test membership and stop walking at a boundary
/// expressed as a mask. The C names are kept for the individual bits --
/// [`CF_TYPE_IP_CONNECT`] and its four siblings -- so that a reader of
/// `lib/cfilters.h:203-207` finds them unchanged.
///
/// No `bitflags` crate: five bits and four operations do not justify a
/// dependency, and the specification's dependency inventory does not list one.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) struct CfType(u32);

/// `CF_TYPE_IP_CONNECT` (`lib/cfilters.h:203`): provides an IP connection or
/// something equivalent -- a `CONNECT` tunnel, an `AF_UNIX` socket, a QUIC
/// connection.
///
/// This is the bit that TERMINATES the upward capability searches: nothing
/// below a filter that provides its own IP connection can contribute to what
/// the layers above it see.
#[allow(dead_code)]
pub(crate) const CF_TYPE_IP_CONNECT: CfType = CfType(1 << 0);

/// `CF_TYPE_SSL` (`lib/cfilters.h:204`): provides TLS.
#[allow(dead_code)]
pub(crate) const CF_TYPE_SSL: CfType = CfType(1 << 1);

/// `CF_TYPE_MULTIPLEX` (`lib/cfilters.h:205`): multiplexes easy handles.
#[allow(dead_code)]
pub(crate) const CF_TYPE_MULTIPLEX: CfType = CfType(1 << 2);

/// `CF_TYPE_PROXY` (`lib/cfilters.h:206`): provides proxying.
#[allow(dead_code)]
pub(crate) const CF_TYPE_PROXY: CfType = CfType(1 << 3);

/// `CF_TYPE_HTTP` (`lib/cfilters.h:207`): implements a version of HTTP.
#[allow(dead_code)]
pub(crate) const CF_TYPE_HTTP: CfType = CfType(1 << 4);

impl CfType {
    /// No capabilities. `Curl_cft_setup`, `Curl_cft_ip_happy` and
    /// `Curl_cft_http_connect` all declare `0` (`lib/connect.c:472`,
    /// `lib/cf-ip-happy.c:905`, `lib/cf-https-connect.c:559`).
    #[allow(dead_code)]
    pub(crate) const NONE: Self = Self(0);

    /// Every bit the C defines, for the exhaustiveness tests.
    #[allow(dead_code)]
    pub(crate) const ALL: [Self; 5] = [
        CF_TYPE_IP_CONNECT,
        CF_TYPE_SSL,
        CF_TYPE_MULTIPLEX,
        CF_TYPE_PROXY,
        CF_TYPE_HTTP,
    ];

    /// The raw bitmap, as the C `int flags` holds it.
    #[allow(dead_code)]
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// A set from a raw bitmap.
    ///
    /// Total: an unrecognised bit is preserved rather than rejected, because
    /// the C stores whatever a filter type declared and this is a set, not an
    /// enumeration.
    #[allow(dead_code)]
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The union, for the composite declarations the C writes with `|` --
    /// `CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX | CF_TYPE_HTTP`
    /// is what `Curl_cft_http3` declares (`lib/vquic/curl_ngtcp2.c:2896`).
    #[allow(dead_code)]
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True when ANY bit of `other` is present -- the C's `flags & mask`.
    ///
    /// This is the test the boundary checks use:
    /// `cf->cft->flags & (CF_TYPE_IP_CONNECT | CF_TYPE_SSL)`
    /// (`lib/cfilters.c:687`, `:725`) stops a walk at EITHER bit.
    #[allow(dead_code)]
    pub(crate) const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// True when EVERY bit of `other` is present.
    ///
    /// The C writes this as an equality against the mask, and only once:
    /// `(cf->cft->flags & (CF_TYPE_IP_CONNECT | CF_TYPE_PROXY)) ==
    /// (CF_TYPE_IP_CONNECT | CF_TYPE_PROXY)` selects a TUNNELLING proxy in
    /// `Curl_conn_get_current_host` (`lib/cfilters.c:837-838`). Keeping it
    /// distinct from [`Self::intersects`] is what stops that one site from
    /// quietly matching a non-tunnelling proxy.
    #[allow(dead_code)]
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// True when no capability is declared.
    #[allow(dead_code)]
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for CfType {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// Names the bits rather than printing a number, so a trace line or an
/// assertion failure is readable.
impl fmt::Debug for CfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("CfType(NONE)");
        }
        f.write_str("CfType(")?;
        let mut first = true;
        for (bit, name) in [
            (CF_TYPE_IP_CONNECT, "IP_CONNECT"),
            (CF_TYPE_SSL, "SSL"),
            (CF_TYPE_MULTIPLEX, "MULTIPLEX"),
            (CF_TYPE_PROXY, "PROXY"),
            (CF_TYPE_HTTP, "HTTP"),
        ] {
            if self.intersects(bit) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        // Whatever is left over after the five known bits, so a stray bit is
        // visible instead of silently dropped from the rendering.
        let known = CF_TYPE_IP_CONNECT
            .union(CF_TYPE_SSL)
            .union(CF_TYPE_MULTIPLEX)
            .union(CF_TYPE_PROXY)
            .union(CF_TYPE_HTTP);
        let extra = self.0 & !known.0;
        if extra != 0 {
            if !first {
                f.write_str("|")?;
            }
            write!(f, "{extra:#x}")?;
        }
        f.write_str(")")
    }
}

// =========================================================================
// The TLS tri-state -- `CURL_CF_SSL_*`
// =========================================================================

/// `CURL_CF_SSL_DEFAULT` (`lib/cfilters.h:351`): follow the scheme's own rule.
#[allow(dead_code)]
pub(crate) const CURL_CF_SSL_DEFAULT: i32 = -1;

/// `CURL_CF_SSL_DISABLE` (`lib/cfilters.h:352`): no TLS on this chain.
#[allow(dead_code)]
pub(crate) const CURL_CF_SSL_DISABLE: i32 = 0;

/// `CURL_CF_SSL_ENABLE` (`lib/cfilters.h:353`): TLS on this chain.
#[allow(dead_code)]
pub(crate) const CURL_CF_SSL_ENABLE: i32 = 1;

/// Whether a chain being built should carry TLS.
///
/// Three states, and the third is the point: `DEFAULT` is not "off", it is "the
/// caller has no opinion, so use the scheme's". C spells the distinction with
/// `-1` and relies on every reader remembering that `-1` is truthy; a
/// three-variant type makes the collapse to a `bool` impossible to write by
/// accident.
///
/// The chain-building policy that consumes this lives in `conn/mod.rs`, which
/// owns `cf_setup_insert_after`; this module only defines the vocabulary.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum CfSslMode {
    /// `CURL_CF_SSL_DEFAULT`. The default here as well, matching the C
    /// argument that callers pass when they have no preference.
    #[default]
    Default = CURL_CF_SSL_DEFAULT as isize,
    /// `CURL_CF_SSL_DISABLE`.
    Disable = CURL_CF_SSL_DISABLE as isize,
    /// `CURL_CF_SSL_ENABLE`.
    Enable = CURL_CF_SSL_ENABLE as isize,
}

impl CfSslMode {
    /// The mode as the C integer.
    #[allow(dead_code)]
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The checked conversion.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for anything that is not one of the
    /// three defined values. The C has no such check -- it would treat `7` as
    /// "enable" -- and adding one changes no reachable behaviour, because every
    /// C call site passes a named constant.
    #[allow(dead_code)]
    pub(crate) fn from_i32(raw: i32) -> CodeResult<Self> {
        match raw {
            CURL_CF_SSL_DEFAULT => Ok(Self::Default),
            CURL_CF_SSL_DISABLE => Ok(Self::Disable),
            CURL_CF_SSL_ENABLE => Ok(Self::Enable),
            _ => Err(CURLcode::BadFunctionArgument),
        }
    }

    /// Whether TLS is wanted, given what the scheme would do by itself.
    ///
    /// The one place the tri-state legitimately becomes a `bool`, and it needs
    /// the scheme's answer to do it -- which is precisely why the collapse
    /// cannot be done anywhere else.
    #[allow(dead_code)]
    pub(crate) const fn resolve(self, scheme_wants_tls: bool) -> bool {
        match self {
            Self::Default => scheme_wants_tls,
            Self::Disable => false,
            Self::Enable => true,
        }
    }
}

// =========================================================================
// Trace levels -- `CURL_LOG_LVL_*`
// =========================================================================

/// `CURL_LOG_LVL_NONE` (`lib/curl_trc.h:69`): this component logs nothing.
#[allow(dead_code)]
pub(crate) const CURL_LOG_LVL_NONE: i32 = 0;

/// `CURL_LOG_LVL_INFO` (`lib/curl_trc.h:70`): this component logs at info
/// level.
///
/// The level is NOT stored on a filter here. In C it is the `log_level` member
/// of the process-global `struct Curl_cftype` that `--trace-config` writes
/// through (`lib/curl_trc.c:596-600`); here the mutable per-name registry is
/// [`crate::trace::TraceConfig`] and a filter contributes only its stable
/// identity. See this module's documentation for why the two C registries are
/// separate typed tables rather than one reinterpreted as the other.
#[allow(dead_code)]
pub(crate) const CURL_LOG_LVL_INFO: i32 = 1;

// =========================================================================
// Transport -- `TRNSPRT_*`
// =========================================================================

/// What a filter chain is carrying, at the bottom.
///
/// `TRNSPRT_*` (`lib/urldata.h:567-571`). The values are non-contiguous and
/// start at 3 because 1 and 2 were retired; they are written out rather than
/// inferred so that the gap cannot close by accident, exactly as the
/// specification requires of every enumeration crossing a boundary.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum Transport {
    /// `TRNSPRT_NONE` = 0. No transport, which is what `file://` uses.
    #[default]
    None = 0,
    /// `TRNSPRT_TCP` = 3.
    Tcp = 3,
    /// `TRNSPRT_UDP` = 4.
    Udp = 4,
    /// `TRNSPRT_QUIC` = 5.
    Quic = 5,
    /// `TRNSPRT_UNIX` = 6.
    Unix = 6,
}

impl Transport {
    /// The transport as the C integer.
    #[allow(dead_code)]
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The checked conversion from the C integer.
    ///
    /// Returns [`None`] for an unassigned value, including the retired 1 and 2.
    /// `Curl_conn_cf_get_transport` (`lib/cfilters.c:892-899`) casts whatever
    /// the query produced straight to `unsigned char`; rejecting an unassigned
    /// value here is stricter, and it is the strictness the typed query exists
    /// for.
    #[allow(dead_code)]
    pub(crate) const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            3 => Some(Self::Tcp),
            4 => Some(Self::Udp),
            5 => Some(Self::Quic),
            6 => Some(Self::Unix),
            _ => None,
        }
    }
}

// =========================================================================
// Connection identity
// =========================================================================

/// Which connection a filter belongs to.
///
/// `struct connectdata *conn` (`lib/cfilters.h:233`) is a back pointer, and a
/// back pointer is the one thing a safe ownership graph cannot reproduce: the
/// connection owns the chain, so the chain cannot own the connection. An
/// IDENTIFIER carries what the pointer was actually used for. Measured against
/// `lib/cfilters.c`, that is three things and no more:
///
/// 1. **A liveness test.** `Curl_conn_cf_add` asserts `!cf->conn` before adding
///    (`:335`) and `Curl_conn_cf_discard` tests `if(cf->conn)` before trying to
///    unlink (`:371`). Both are "is this filter attached?", which
///    [`FilterBase::is_attached`] answers.
/// 2. **Reaching the chain head to unlink.** `Curl_conn_cf_discard` walks
///    `cf->conn->cfilter[cf->sockindex]` (`:373`). Here the caller already holds
///    the [`FilterChain`], so the traversal starts from it and needs no pointer.
/// 3. **Connection-level facts** -- `conn->bits.close`, `conn->sock[]`,
///    `conn->host.name`, `conn->transport_wanted`. Those arrive through
///    [`ConnContext`], injected at the call that needs them.
///
/// The identifier remains because the ASSIGNMENT is observable: `insert_after`
/// must stamp it on every node it links (`:356-361`), and a test can check that
/// it did.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConnId(u64);

impl ConnId {
    /// An identifier from the connection's own number.
    ///
    /// The C's `conn->connection_id` is a `curl_off_t` assigned by the multi
    /// handle; this takes the same value unchanged.
    #[allow(dead_code)]
    pub(crate) const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The underlying number.
    #[allow(dead_code)]
    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// =========================================================================
// Typed answers a query can carry
// =========================================================================

/// The four addresses and two ports of a connected socket.
///
/// `struct ip_quadruple` (`lib/urldata.h:573-579`). The C stores the addresses
/// as `char[MAX_IPADR_LEN]`, already formatted, because that is what
/// `CURLINFO_PRIMARY_IP` hands to the application and what the "Established
/// connection to ..." trace line prints (`lib/cfilters.c:436-440`). Keeping them
/// as strings preserves the exact text, including an IPv6 scope suffix that
/// [`std::net::IpAddr`] would drop.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct IpQuadruple {
    /// The peer's address, formatted. `remote_ip` in the C.
    pub(crate) remote_ip: String,
    /// This end's address, formatted. `local_ip` in the C.
    pub(crate) local_ip: String,
    /// The peer's port. `uint16_t` in the C, and genuinely a port.
    pub(crate) remote_port: u16,
    /// This end's port.
    pub(crate) local_port: u16,
    /// Which transport the pair describes.
    pub(crate) transport: Transport,
}

/// The peer a filter is connected to.
///
/// `CF_QUERY_REMOTE_ADDR` hands back a `const struct Curl_sockaddr_ex *`, set to
/// `NULL` when not connected (`lib/cfilters.h:174-176`). The absence becomes
/// [`Option`] at the query boundary; the presence becomes this, which is a
/// sum type because the two families a filter can reach are not the same shape.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum RemoteAddr {
    /// An `AF_INET` or `AF_INET6` peer.
    Inet(SocketAddr),
    /// An `AF_UNIX` peer, named by its filesystem path.
    ///
    /// A `String` rather than a `PathBuf` because the value's only consumers
    /// are trace output and `CURLINFO_PRIMARY_IP`, both of which want text, and
    /// because `CURLOPT_UNIX_SOCKET_PATH` arrives as a C string in the first
    /// place.
    Unix(String),
}

/// Which TLS backend answered a query.
///
/// The `backend` member of `struct curl_tlssessioninfo`
/// (`include/curl/curl.h:2885-2888`), whose integers are part of the public ABI
/// and are therefore pinned in `curl-rs-ffi`. Only the one value this build can
/// report is named here; the rest of the enumeration is not this module's
/// business.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) struct TlsBackendId(i32);

impl TlsBackendId {
    /// `CURLSSLBACKEND_RUSTLS = 14` (`include/curl/curl.h:166`).
    ///
    /// The enumerant already exists in the public header, so reporting a rustls
    /// backend invents no value.
    #[allow(dead_code)]
    pub(crate) const RUSTLS: Self = Self(14);

    /// `CURLSSLBACKEND_NONE = 0`, for a chain carrying no TLS.
    #[allow(dead_code)]
    pub(crate) const NONE: Self = Self(0);

    /// The pinned integer.
    #[allow(dead_code)]
    pub(crate) const fn as_i32(self) -> i32 {
        self.0
    }
}

/// Which of the two TLS handles a query asked for.
///
/// `CF_QUERY_SSL_INFO` and `CF_QUERY_SSL_CTX_INFO` differ only in this, and
/// `lib/cfilters.h:156-158` states the rule exactly: the context query yields
/// the `SSL_CTX` "when available, or the same internal pointer when the TLS
/// stack does not differentiate".
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum TlsHandleKind {
    /// The per-connection session.
    Session,
    /// The shared context, where the backend has one distinct from the session.
    Context,
}

/// What a TLS filter reports about the session securing a chain.
///
/// The successor of `struct curl_tlssessioninfo`, and deliberately NOT a
/// translation of it: the C's second member is a `void *internals` that the
/// application casts to an `SSL *`, and a rustls-native engine has no such
/// pointer to give. What survives is the part that is engine-neutral and
/// answerable -- which backend, and which of its two handles.
///
/// This is what lets a TLS filter answer the query without any TLS type
/// appearing in this module and without a cast back through an erased context.
/// The concrete session state stays on the implementing struct, where it is an
/// ordinary typed field; `crate::tls` is not imported here, and must not be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct TlsSessionInfo {
    /// Which backend is in play.
    pub(crate) backend: TlsBackendId,
    /// Which handle this answer describes.
    pub(crate) kind: TlsHandleKind,
    /// Whether the backend distinguishes a context from a session at all.
    ///
    /// `false` means the two queries yield the same thing, which is the "does
    /// not differentiate" case the C header describes.
    pub(crate) distinguishes_context: bool,
}

/// Whether a connection is still usable, and whether it has data waiting.
///
/// `Curl_cft_conn_is_alive` (`lib/cfilters.h:102-104`) returns the first as its
/// value and writes the second through `bool *input_pending`. Returning both
/// removes the out-parameter, and the pairing is not arbitrary: a connection
/// that is alive but has bytes waiting cannot be reused for a new request,
/// because those bytes belong to the previous one. `lib/url.c:684-687` reads
/// them together for exactly that reason.
///
/// # The one C detail that does not survive, and why it costs nothing
///
/// The C's terminal case returns `FALSE` WITHOUT writing `*input_pending`
/// (`lib/cfilters.c:92-99`), leaving whatever the caller put there. Every C
/// caller initialises it to `FALSE` first (`lib/url.c:684`), so
/// [`Self::DEAD`] reporting `input_pending: false` is the same observable
/// behaviour with the uninitialised read removed.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) struct Liveness {
    /// True when the connection is still usable.
    pub(crate) alive: bool,
    /// True when readable bytes are already waiting.
    pub(crate) input_pending: bool,
}

impl Liveness {
    /// The pessimistic answer: not alive, nothing pending.
    ///
    /// "Pessimistic in absence of data" is the C's own comment on this case
    /// (`lib/cfilters.c:98`).
    #[allow(dead_code)]
    pub(crate) const DEAD: Self = Self {
        alive: false,
        input_pending: false,
    };

    /// Alive, with `input_pending` as observed.
    #[allow(dead_code)]
    pub(crate) const fn alive(input_pending: bool) -> Self {
        Self {
            alive: true,
            input_pending,
        }
    }
}

// =========================================================================
// Control events -- `CF_CTRL_*`
// =========================================================================

/// `CF_CTRL_DATA_SETUP` = 4 (`lib/cfilters.h:119`).
#[allow(dead_code)]
pub(crate) const CF_CTRL_DATA_SETUP: i32 = 4;

/// The value 5 is UNUSED and RESERVED (`lib/cfilters.h:120`, whose entire
/// content is the comment `/* unused now 5 */`).
///
/// It is named so that it stays named. A retired identifier in a numbered
/// protocol is not a free slot: some build somewhere may still send it, and
/// reusing it would give that build a different event than it asked for. The
/// same discipline the specification requires of the fifteen retired
/// `CURLE_OBSOLETE*` placeholders applies here for the same reason, and
/// [`CfControl::from_event_id`] rejects it explicitly rather than by falling
/// through.
#[allow(dead_code)]
pub(crate) const CF_CTRL_UNUSED_5: i32 = 5;

/// `CF_CTRL_DATA_PAUSE` = 6 (`lib/cfilters.h:121`).
#[allow(dead_code)]
pub(crate) const CF_CTRL_DATA_PAUSE: i32 = 6;

/// `CF_CTRL_DATA_DONE` = 7 (`lib/cfilters.h:122`).
#[allow(dead_code)]
pub(crate) const CF_CTRL_DATA_DONE: i32 = 7;

/// `CF_CTRL_DATA_DONE_SEND` = 8 (`lib/cfilters.h:123`).
#[allow(dead_code)]
pub(crate) const CF_CTRL_DATA_DONE_SEND: i32 = 8;

/// `CF_CTRL_CONN_INFO_UPDATE` = `256 + 0` (`lib/cfilters.h:125`).
#[allow(dead_code)]
pub(crate) const CF_CTRL_CONN_INFO_UPDATE: i32 = 256;

/// `CF_CTRL_FORGET_SOCKET` = `256 + 1` (`lib/cfilters.h:126`).
#[allow(dead_code)]
pub(crate) const CF_CTRL_FORGET_SOCKET: i32 = 256 + 1;

/// `CF_CTRL_FLUSH` = `256 + 2` (`lib/cfilters.h:127`).
#[allow(dead_code)]
pub(crate) const CF_CTRL_FLUSH: i32 = 256 + 2;

/// How the driver treats the results of one control event.
///
/// `lib/cfilters.h:109-117` names the two policies and every event's row states
/// which it uses. The C passes the choice as a `bool ignore_result` argument
/// (`Curl_conn_cf_cntrl`, `lib/cfilters.h:326-329`), which means a caller can
/// pass the wrong one; here it is a property OF THE EVENT, read from
/// [`CfControl::policy`], so the pairing cannot come apart.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum ControlPolicy {
    /// "first fail": the first filter returning an error aborts the
    /// distribution and determines the result.
    FirstFail,
    /// "ignored": every filter is visited and the overall result is success.
    IgnoreResult,
}

/// An event or command distributed down a filter chain.
///
/// C's `Curl_cft_cntrl(cf, data, int event, int arg1, void *arg2)`
/// (`lib/cfilters.h:133-135`) is three untyped parameters, of which `arg2` is
/// never used by any event the tree defines -- every row in
/// `lib/cfilters.h:118-127` documents it as `NULL`. Two of the seven events use
/// `arg1`, and both use it as a `bool`. A closed enumeration with the payload on
/// the variant that has one therefore loses nothing and makes the two payload
/// events impossible to confuse with the five that carry none.
///
/// The discriminants are the C values and are asserted against them, because a
/// control event identifier is observable: the same numbers appear in the trace
/// output a `--trace` comparison checks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum CfControl {
    /// `CF_CTRL_DATA_SETUP`: prepare for a transfer. First-fail.
    DataSetup,
    /// `CF_CTRL_DATA_PAUSE`: the transfer was paused or unpaused. First-fail.
    ///
    /// `arg1` is the on/off flag.
    DataPause {
        /// True to pause, false to resume.
        pause: bool,
    },
    /// `CF_CTRL_DATA_DONE`: the transfer finished. Ignored-result.
    ///
    /// `arg1` is the `premature` flag.
    DataDone {
        /// True when the transfer ended before it was complete.
        premature: bool,
    },
    /// `CF_CTRL_DATA_DONE_SEND`: the transfer finished uploading.
    /// Ignored-result.
    DataDoneSend,
    /// `CF_CTRL_CONN_INFO_UPDATE`: persist connection information now that the
    /// chain is connected. Ignored-result.
    ConnInfoUpdate,
    /// `CF_CTRL_FORGET_SOCKET`: stop tracking the socket. Ignored-result.
    ForgetSocket,
    /// `CF_CTRL_FLUSH`: write out anything buffered. First-fail.
    Flush,
}

impl CfControl {
    /// Every event, in `lib/cfilters.h:118-127` order.
    #[allow(dead_code)]
    pub(crate) const ALL: [Self; 7] = [
        Self::DataSetup,
        Self::DataPause { pause: false },
        Self::DataDone { premature: false },
        Self::DataDoneSend,
        Self::ConnInfoUpdate,
        Self::ForgetSocket,
        Self::Flush,
    ];

    /// The C `event` value.
    #[allow(dead_code)]
    pub(crate) const fn event_id(self) -> i32 {
        match self {
            Self::DataSetup => CF_CTRL_DATA_SETUP,
            Self::DataPause { .. } => CF_CTRL_DATA_PAUSE,
            Self::DataDone { .. } => CF_CTRL_DATA_DONE,
            Self::DataDoneSend => CF_CTRL_DATA_DONE_SEND,
            Self::ConnInfoUpdate => CF_CTRL_CONN_INFO_UPDATE,
            Self::ForgetSocket => CF_CTRL_FORGET_SOCKET,
            Self::Flush => CF_CTRL_FLUSH,
        }
    }

    /// The C `arg1` value.
    ///
    /// Zero for the five events whose row documents `arg1` as `0`, and the flag
    /// for the two that carry one. Retained because a filter migrated from C may
    /// still want to log the raw pair.
    #[allow(dead_code)]
    pub(crate) const fn arg1(self) -> i32 {
        match self {
            Self::DataPause { pause: true }
            | Self::DataDone { premature: true } => 1,
            Self::DataSetup
            | Self::DataPause { pause: false }
            | Self::DataDone { premature: false }
            | Self::DataDoneSend
            | Self::ConnInfoUpdate
            | Self::ForgetSocket
            | Self::Flush => 0,
        }
    }

    /// Which distribution policy this event uses.
    ///
    /// Transcribed from the `return` column of `lib/cfilters.h:118-127`. No
    /// wildcard arm, so an event added without a policy is a compile error
    /// rather than a silent `IgnoreResult`.
    #[allow(dead_code)]
    pub(crate) const fn policy(self) -> ControlPolicy {
        match self {
            Self::DataSetup | Self::DataPause { .. } | Self::Flush => {
                ControlPolicy::FirstFail
            }
            Self::DataDone { .. }
            | Self::DataDoneSend
            | Self::ConnInfoUpdate
            | Self::ForgetSocket => ControlPolicy::IgnoreResult,
        }
    }

    /// Reconstructs an event from the C pair, for a boundary that still speaks
    /// integers.
    ///
    /// Returns [`None`] for an unrecognised event, [`CF_CTRL_UNUSED_5`]
    /// included -- see that constant for why 5 is refused by name.
    #[allow(dead_code)]
    pub(crate) const fn from_event_id(event: i32, arg1: i32) -> Option<Self> {
        match event {
            CF_CTRL_DATA_SETUP => Some(Self::DataSetup),
            CF_CTRL_DATA_PAUSE => Some(Self::DataPause { pause: arg1 != 0 }),
            CF_CTRL_DATA_DONE => Some(Self::DataDone {
                premature: arg1 != 0,
            }),
            CF_CTRL_DATA_DONE_SEND => Some(Self::DataDoneSend),
            CF_CTRL_CONN_INFO_UPDATE => Some(Self::ConnInfoUpdate),
            CF_CTRL_FORGET_SOCKET => Some(Self::ForgetSocket),
            CF_CTRL_FLUSH => Some(Self::Flush),
            // 5 lands here along with every other unassigned value. Named
            // explicitly so the refusal is deliberate rather than incidental.
            CF_CTRL_UNUSED_5 => None,
            _ => None,
        }
    }
}

// =========================================================================
// Queries -- `CF_QUERY_*`
// =========================================================================

/// `CF_QUERY_MAX_CONCURRENT` = 1 (`lib/cfilters.h:165`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_MAX_CONCURRENT: i32 = 1;

/// `CF_QUERY_CONNECT_REPLY_MS` = 2 (`lib/cfilters.h:166`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_CONNECT_REPLY_MS: i32 = 2;

/// `CF_QUERY_SOCKET` = 3 (`lib/cfilters.h:167`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_SOCKET: i32 = 3;

/// `CF_QUERY_TIMER_CONNECT` = 4 (`lib/cfilters.h:168`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_TIMER_CONNECT: i32 = 4;

/// `CF_QUERY_TIMER_APPCONNECT` = 5 (`lib/cfilters.h:169`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_TIMER_APPCONNECT: i32 = 5;

/// `CF_QUERY_STREAM_ERROR` = 6 (`lib/cfilters.h:170`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_STREAM_ERROR: i32 = 6;

/// `CF_QUERY_NEED_FLUSH` = 7 (`lib/cfilters.h:171`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_NEED_FLUSH: i32 = 7;

/// `CF_QUERY_IP_INFO` = 8 (`lib/cfilters.h:172`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_IP_INFO: i32 = 8;

/// `CF_QUERY_HTTP_VERSION` = 9 (`lib/cfilters.h:173`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_HTTP_VERSION: i32 = 9;

/// `CF_QUERY_REMOTE_ADDR` = 10 (`lib/cfilters.h:176`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_REMOTE_ADDR: i32 = 10;

/// `CF_QUERY_HOST_PORT` = 11 (`lib/cfilters.h:177`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_HOST_PORT: i32 = 11;

/// `CF_QUERY_SSL_INFO` = 12 (`lib/cfilters.h:178`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_SSL_INFO: i32 = 12;

/// `CF_QUERY_SSL_CTX_INFO` = 13 (`lib/cfilters.h:179`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_SSL_CTX_INFO: i32 = 13;

/// `CF_QUERY_TRANSPORT` = 14 (`lib/cfilters.h:180`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_TRANSPORT: i32 = 14;

/// `CF_QUERY_ALPN_NEGOTIATED` = 15 (`lib/cfilters.h:181`).
#[allow(dead_code)]
pub(crate) const CF_QUERY_ALPN_NEGOTIATED: i32 = 15;

/// A property a chain can be asked for.
///
/// C's `Curl_cft_query(cf, data, int query, int *pres1, void *pres2)`
/// (`lib/cfilters.h:187-189`) answers through two out-parameters whose types
/// depend on the query, and `pres2` is a `void *` that each caller casts: a
/// `curl_socket_t *` for `CF_QUERY_SOCKET`, a `struct curltime *` for the two
/// timers, a `const char **` for `CF_QUERY_ALPN_NEGOTIATED`, and so on. Getting
/// one of those casts wrong is undetectable at the boundary.
///
/// Here the question is this enumeration and the answer is [`CfQueryValue`], so
/// the pairing is checked by the compiler. There is no `Any`, no raw pointer and
/// no recovery of an erased type anywhere in the protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum CfQuery {
    /// How many parallel transfers the chain expects to handle.
    MaxConcurrent,
    /// Milliseconds until the first sign of a server response on connect.
    ConnectReplyMs,
    /// The socket the chain is using.
    Socket,
    /// When the connection completed.
    TimerConnect,
    /// When the application-level connection completed, e.g. the TLS
    /// handshake.
    TimerAppConnect,
    /// The underlying error code for a transfer stream.
    StreamError,
    /// Whether any filter is holding unsent data.
    NeedFlush,
    /// The address family in use and the connected quadruple.
    IpInfo,
    /// The HTTP version in play: 10, 11, 20 or 30.
    HttpVersion,
    /// The connected peer address.
    RemoteAddr,
    /// The host and port this chain is talking to right now.
    HostPort,
    /// The TLS session securing the chain.
    SslInfo,
    /// The TLS context securing the chain.
    SslCtxInfo,
    /// The transport the chain is carrying.
    Transport,
    /// The protocol ALPN selected.
    AlpnNegotiated,
}

impl CfQuery {
    /// Every query, in `lib/cfilters.h:165-181` order.
    #[allow(dead_code)]
    pub(crate) const ALL: [Self; 15] = [
        Self::MaxConcurrent,
        Self::ConnectReplyMs,
        Self::Socket,
        Self::TimerConnect,
        Self::TimerAppConnect,
        Self::StreamError,
        Self::NeedFlush,
        Self::IpInfo,
        Self::HttpVersion,
        Self::RemoteAddr,
        Self::HostPort,
        Self::SslInfo,
        Self::SslCtxInfo,
        Self::Transport,
        Self::AlpnNegotiated,
    ];

    /// The C `query` value.
    #[allow(dead_code)]
    pub(crate) const fn query_id(self) -> i32 {
        match self {
            Self::MaxConcurrent => CF_QUERY_MAX_CONCURRENT,
            Self::ConnectReplyMs => CF_QUERY_CONNECT_REPLY_MS,
            Self::Socket => CF_QUERY_SOCKET,
            Self::TimerConnect => CF_QUERY_TIMER_CONNECT,
            Self::TimerAppConnect => CF_QUERY_TIMER_APPCONNECT,
            Self::StreamError => CF_QUERY_STREAM_ERROR,
            Self::NeedFlush => CF_QUERY_NEED_FLUSH,
            Self::IpInfo => CF_QUERY_IP_INFO,
            Self::HttpVersion => CF_QUERY_HTTP_VERSION,
            Self::RemoteAddr => CF_QUERY_REMOTE_ADDR,
            Self::HostPort => CF_QUERY_HOST_PORT,
            Self::SslInfo => CF_QUERY_SSL_INFO,
            Self::SslCtxInfo => CF_QUERY_SSL_CTX_INFO,
            Self::Transport => CF_QUERY_TRANSPORT,
            Self::AlpnNegotiated => CF_QUERY_ALPN_NEGOTIATED,
        }
    }

    /// Reconstructs a query from the C integer, for a boundary that still
    /// speaks integers. [`None`] for an unassigned value.
    #[allow(dead_code)]
    pub(crate) const fn from_query_id(query: i32) -> Option<Self> {
        match query {
            CF_QUERY_MAX_CONCURRENT => Some(Self::MaxConcurrent),
            CF_QUERY_CONNECT_REPLY_MS => Some(Self::ConnectReplyMs),
            CF_QUERY_SOCKET => Some(Self::Socket),
            CF_QUERY_TIMER_CONNECT => Some(Self::TimerConnect),
            CF_QUERY_TIMER_APPCONNECT => Some(Self::TimerAppConnect),
            CF_QUERY_STREAM_ERROR => Some(Self::StreamError),
            CF_QUERY_NEED_FLUSH => Some(Self::NeedFlush),
            CF_QUERY_IP_INFO => Some(Self::IpInfo),
            CF_QUERY_HTTP_VERSION => Some(Self::HttpVersion),
            CF_QUERY_REMOTE_ADDR => Some(Self::RemoteAddr),
            CF_QUERY_HOST_PORT => Some(Self::HostPort),
            CF_QUERY_SSL_INFO => Some(Self::SslInfo),
            CF_QUERY_SSL_CTX_INFO => Some(Self::SslCtxInfo),
            CF_QUERY_TRANSPORT => Some(Self::Transport),
            CF_QUERY_ALPN_NEGOTIATED => Some(Self::AlpnNegotiated),
            _ => None,
        }
    }
}

/// The answer to a [`CfQuery`].
///
/// One variant per query, so an answer cannot be attached to the wrong
/// question. [`FilterChain`] checks the pairing once, in
/// [`FilterChain::query_typed`], and every accessor built on top of it is then
/// total.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum CfQueryValue {
    /// [`CfQuery::MaxConcurrent`]. Negative means "no answer".
    ///
    /// ZERO IS LEGITIMATE and does not mean "no answer": a multiplexed
    /// connection that has received a `GOAWAY` reports zero because it will
    /// accept no further streams while it drains. `lib/cfilters.c:1031-1034`
    /// says so in as many words, and
    /// [`FilterChains::max_concurrent`] preserves it.
    MaxConcurrent(i32),
    /// [`CfQuery::ConnectReplyMs`]. `-1` until determined
    /// (`lib/cfilters.h:147`).
    ConnectReplyMs(TimeDiff),
    /// [`CfQuery::Socket`].
    Socket(Socket),
    /// [`CfQuery::TimerConnect`] or [`CfQuery::TimerAppConnect`].
    ///
    /// One variant for both, because the C uses one type for both and
    /// `conn_report_connect_stats` (`lib/cfilters.c:472-489`) distinguishes them
    /// only by which query produced the reading. [`CurlTime::is_zero`] is the
    /// "not set" test the C performs field by field at `:481` and `:486`.
    Timer(CurlTime),
    /// [`CfQuery::StreamError`]. Negative is treated as "no answer"
    /// (`lib/cfilters.c:1051`).
    StreamError(i32),
    /// [`CfQuery::NeedFlush`].
    NeedFlush(bool),
    /// [`CfQuery::IpInfo`]. The C's `res1` is the IPv6 flag and `res2` the
    /// quadruple (`lib/cfilters.h:172`).
    IpInfo {
        /// True when the connection is over IPv6.
        is_ipv6: bool,
        /// The addresses and ports.
        quad: IpQuadruple,
    },
    /// [`CfQuery::HttpVersion`]: 10, 11, 20 or 30
    /// (`lib/cfilters.h:173`).
    HttpVersion(i32),
    /// [`CfQuery::RemoteAddr`]. [`None`] when not connected
    /// (`lib/cfilters.h:174-175`).
    RemoteAddr(Option<RemoteAddr>),
    /// [`CfQuery::HostPort`].
    HostPort {
        /// The hostname being talked to.
        host: String,
        /// The port being talked to.
        port: u16,
    },
    /// [`CfQuery::SslInfo`] or [`CfQuery::SslCtxInfo`].
    SslInfo(TlsSessionInfo),
    /// [`CfQuery::Transport`].
    Transport(Transport),
    /// [`CfQuery::AlpnNegotiated`]. [`None`] when nothing was selected or the
    /// handshake has not finished (`lib/cfilters.h:159-162`).
    AlpnNegotiated(Option<String>),
}

impl CfQueryValue {
    /// The query this value is an answer to, or [`None`] where one variant
    /// serves two queries.
    ///
    /// [`Self::Timer`] and [`Self::SslInfo`] are the two ambiguous cases, for
    /// the reasons their documentation gives, so this reports [`None`] for both
    /// rather than guessing. [`FilterChain::query_typed`] checks those two
    /// against the question it asked instead.
    #[allow(dead_code)]
    pub(crate) fn answers(&self) -> Option<CfQuery> {
        match self {
            Self::MaxConcurrent(_) => Some(CfQuery::MaxConcurrent),
            Self::ConnectReplyMs(_) => Some(CfQuery::ConnectReplyMs),
            Self::Socket(_) => Some(CfQuery::Socket),
            Self::StreamError(_) => Some(CfQuery::StreamError),
            Self::NeedFlush(_) => Some(CfQuery::NeedFlush),
            Self::IpInfo { .. } => Some(CfQuery::IpInfo),
            Self::HttpVersion(_) => Some(CfQuery::HttpVersion),
            Self::RemoteAddr(_) => Some(CfQuery::RemoteAddr),
            Self::HostPort { .. } => Some(CfQuery::HostPort),
            Self::Transport(_) => Some(CfQuery::Transport),
            Self::AlpnNegotiated(_) => Some(CfQuery::AlpnNegotiated),
            Self::Timer(_) | Self::SslInfo(_) => None,
        }
    }

    /// True when this value can answer `query`.
    #[allow(dead_code)]
    pub(crate) fn matches(&self, query: CfQuery) -> bool {
        match (self, query) {
            (
                Self::Timer(_),
                CfQuery::TimerConnect | CfQuery::TimerAppConnect,
            )
            | (Self::SslInfo(_), CfQuery::SslInfo | CfQuery::SslCtxInfo) => {
                true
            }
            _ => self.answers() == Some(query),
        }
    }
}

// =========================================================================
// The call context -- what replaces `struct Curl_easy *data`
// =========================================================================

/// What every filter operation is handed alongside its own state.
///
/// C threads `struct Curl_easy *data` through all twelve callbacks, and that
/// one pointer carries three unrelated things: the trace destination, the
/// clock, and the whole transfer. Only the first two are needed to IMPLEMENT a
/// filter, so only those two are here. The transfer's own state reaches a filter
/// through [`CfControl::DataSetup`], which is exactly what that event is for.
///
/// The clock is INJECTED rather than read from the host, so that the coverage
/// gate over the time-driven paths is reachable without waiting in real time:
/// a test installs [`crate::util::timeval::TestClock`], places a chain at a
/// chosen instant and steps it forward. Nothing in this module calls the host
/// clock directly, and the module compiles with no path to one.
///
/// # Why this replaces `cf_call_data` outright
///
/// `struct cf_call_data` and the `CF_DATA_SAVE`/`CF_DATA_RESTORE` macro pair
/// (`lib/cfilters.h:620-685`) exist so that a filter which re-enters itself --
/// TLS calling down into the socket which calls back up, issue #10336 -- can
/// still find the easy handle after `void *ctx` erased it. Passing the context
/// as a typed parameter makes it available at every depth by construction, so
/// there is nothing to save, nothing to restore, and no depth counter to
/// assert on.
#[allow(dead_code)]
pub(crate) struct CallCtx<'ctx, 'trc> {
    /// Where trace lines go, when the transfer is tracing at all.
    ///
    /// [`None`] is the ordinary case: `CURLOPT_VERBOSE` is off by default, and a
    /// filter that cannot trace should not have to pretend it can.
    tracer: Option<&'ctx mut Tracer<'trc>>,
    /// The injected clock.
    clock: &'ctx dyn Clock,
}

impl<'ctx, 'trc> CallCtx<'ctx, 'trc> {
    /// A context over `clock`, tracing nothing.
    #[allow(dead_code)]
    pub(crate) fn new(clock: &'ctx dyn Clock) -> Self {
        Self {
            tracer: None,
            clock,
        }
    }

    /// Attaches the transfer's tracer.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn with_tracer(
        mut self,
        tracer: &'ctx mut Tracer<'trc>,
    ) -> Self {
        self.tracer = Some(tracer);
        self
    }

    /// The tracer, when the transfer has one.
    ///
    /// Reborrowed rather than returned by value so that a caller can trace more
    /// than once from one context.
    #[allow(dead_code)]
    pub(crate) fn tracer_mut(&mut self) -> Option<&mut Tracer<'trc>> {
        self.tracer.as_deref_mut()
    }

    /// The injected clock.
    #[allow(dead_code)]
    pub(crate) fn clock(&self) -> &dyn Clock {
        self.clock
    }

    /// A monotonic reading -- the successor of `Curl_pgrs_now(data)`.
    #[allow(dead_code)]
    pub(crate) fn now(&self) -> CurlTime {
        self.clock.now()
    }
}

/// Deliberately opaque: a context is a bundle of borrows, and printing the
/// tracer would print the whole trace buffer.
impl fmt::Debug for CallCtx<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallCtx")
            .field("tracing", &self.tracer.is_some())
            .finish()
    }
}

/// Emits one filter-attributed trace line, the successor of `CURL_TRC_CF`.
///
/// Three things have to line up before a line is emitted: the transfer must have
/// a tracer, the filter must have a registered identity, and that identity's
/// level must be verbose. The first two are [`Option`]s and the third is
/// [`Tracer::is_filter_verbose`], which [`trc_cf`] checks. Wrapping the pair of
/// [`Option`]s here keeps eleven call sites from repeating it.
///
/// A filter with no registered identity -- the in-memory transport the tests
/// build chains over -- traces nothing, which is the honest outcome: there is no
/// `--trace-config` keyword that could switch it on.
macro_rules! trc {
    (
        $cx:expr, $filter:expr, $sockindex:expr,
        $fmt:literal $(, $arg:expr)* $(,)?
    ) => {{
        let identity: Option<TraceFilter> = $filter;
        let sockindex: i32 = $sockindex;
        if let Some(identity) = identity {
            if let Some(tracer) = $cx.tracer_mut() {
                trc_cf!(tracer, identity, sockindex, $fmt $(, $arg)*);
            }
        }
    }};
}

// =========================================================================
// The injected shutdown timer
// =========================================================================

/// `DEFAULT_SHUTDOWN_TIMEOUT_MS` (`lib/connect.h:45`): two seconds.
#[allow(dead_code)]
pub(crate) const DEFAULT_SHUTDOWN_TIMEOUT_MS: TimeDiff = 2 * 1000;

/// Where a graceful shutdown's deadline is kept.
///
/// The C stores it on the connection -- `conn->shutdown.start[2]` and
/// `conn->shutdown.timeout_ms` (`lib/urldata.h:651-654`) -- and reaches it
/// through four helpers in `lib/connect.h:47-64`. The storage belongs to
/// `conn/mod.rs`, which owns the successor of `connectdata`, so this module
/// depends on the INTERFACE and creates no second timer subsystem. That split is
/// what stops the shutdown deadline from existing in two places and disagreeing.
///
/// A method per C helper, with the same names and the same meanings.
#[allow(dead_code)]
pub(crate) trait ShutdownTimer {
    /// `Curl_shutdown_started` (`lib/connect.h:64`).
    fn started(&self, sockindex: SocketIndex) -> bool;

    /// `Curl_shutdown_start` (`lib/connect.h:47-48`).
    ///
    /// `timeout_ms` of zero means "use [`DEFAULT_SHUTDOWN_TIMEOUT_MS`]", which
    /// is what `Curl_conn_shutdown` passes (`lib/cfilters.c:180`).
    fn start(&mut self, sockindex: SocketIndex, timeout_ms: TimeDiff);

    /// `Curl_shutdown_timeleft` (`lib/connect.h:52-54`).
    ///
    /// Zero means there is no limit or the shutdown has not started; NEGATIVE
    /// means the deadline has passed, which is the case
    /// [`FilterChain::shutdown`] turns into [`CURLcode::OperationTimedout`].
    fn time_left_ms(&self, sockindex: SocketIndex) -> TimeDiff;

    /// `Curl_shutdown_clear` (`lib/connect.h:61`).
    fn clear(&mut self, sockindex: SocketIndex);
}

// =========================================================================
// The filter contract -- `struct Curl_cftype`
// =========================================================================

/// One owned link in a chain.
///
/// `Pin<Box<...>>` rather than `Box<...>`, and the pinning is not decoration: a
/// filter's address must not change while it is linked, because the C
/// mechanisms this chain replaces all key on `cf` pointer identity -- the
/// unlink walk compares pointers (`lib/cfilters.c:375`), `insert_after` rewires
/// them (`:354-362`), and an implementation's own asynchronous machinery
/// registers wakers that outlive the call that created them. Owning the link as
/// a pinned box states that invariant in the type rather than in a comment.
pub(crate) type FilterLink = Pin<Box<dyn ConnFilter>>;

/// Boxes and pins a filter into a chain link.
///
/// The successor of `Curl_cf_create` (`lib/cfilters.c:309-327`), minus its two C
/// concerns: there is no allocation failure to report, because a failure to
/// allocate aborts rather than returning `CURLE_OUT_OF_MEMORY`, and there is no
/// `void *ctx` to store, because the state came in with the value.
#[allow(dead_code)]
pub(crate) fn link<F>(filter: F) -> FilterLink
where
    F: ConnFilter + 'static,
{
    Box::pin(filter)
}

/// A connection filter: one link's behaviour.
///
/// The successor of `struct Curl_cftype` (`lib/cfilters.h:210-226`). The twelve
/// callbacks appear below IN THE C's DECLARATION ORDER, which is worth
/// preserving even though nothing forces it: a reviewer comparing the two side
/// by side should not have to search.
///
/// # Two supertraits, both load-bearing
///
/// [`fmt::Debug`] so that a chain can be printed in a test failure, which for a
/// linked structure of trait objects is the difference between a diagnosable
/// assertion and an opaque one.
///
/// [`Unpin`] because every method below takes `&mut self`. A filter reached
/// through [`FilterLink`] is behind a [`Pin`], and turning that back into
/// `&mut` is only sound for a type that does not care where it lives --
/// [`Pin::get_mut`] requires exactly this bound and is then safe. The
/// alternative, `self: Pin<&mut Self>` receivers, would force every
/// implementation -- TLS, HTTP/2, HTTP/3, the proxies -- to project to reach its
/// OWN fields, and the pressure that creates is the wrong kind: the safety
/// requirement here is absolute, so the ergonomics must not push against it.
/// The bound costs nothing, because no filter is self-referential: an
/// implementation whose state machine needs to be pinned boxes it, and a boxed
/// future is itself [`Unpin`].
///
/// # What is NOT here
///
/// No `ctx`. Each implementing struct owns a [`FilterBase`] and keeps its own
/// state in an ordinary typed field beside it, so there is nothing to erase and
/// nothing to cast back. That is the whole point of the translation; see the
/// module documentation.
///
/// No mutable log level. C's `Curl_cftype::log_level` is a process-global that
/// `--trace-config` writes through; here [`Self::trace_name`] and
/// [`Self::trace_filter`] report a stable identity and the level lives in
/// [`crate::trace::TraceConfig`].
#[allow(dead_code)]
pub(crate) trait ConnFilter: fmt::Debug + Unpin {
    // -- the `name` and `flags` members ----------------------------------

    /// The `name` member (`lib/cfilters.h:211`): the label `--trace-config`
    /// matches and a trace line prints.
    ///
    /// Stable and `&'static`, exactly as the C's string literal is. The sixteen
    /// names the C registers are transcribed in
    /// [`crate::trace::TraceFilter::name`], and three of them are easy to get
    /// wrong: the SOCKS filter is `SOCKS`, not `SOCKS-PROXY`; the version
    /// negotiator is `HTTPS-CONNECT`, not `HTTP-CONNECT`; and
    /// `HAPPY-EYEBALLS` is hyphenated where the timer of nearly the same name
    /// is not.
    fn trace_name(&self) -> &'static str;

    /// The `flags` member (`lib/cfilters.h:212`).
    ///
    /// [`CfType::NONE`] by default, which is what `Curl_cft_setup`,
    /// `Curl_cft_ip_happy` and `Curl_cft_http_connect` all declare.
    fn cf_type(&self) -> CfType {
        CfType::NONE
    }

    /// This filter's entry in the trace registry, when it has one.
    ///
    /// Resolved from [`Self::trace_name`], so a filter states its name once. A
    /// filter with no registered name -- a test double -- reports [`None`] and
    /// traces nothing, which is honest: no `--trace-config` keyword could
    /// enable it.
    fn trace_filter(&self) -> Option<TraceFilter> {
        TraceFilter::from_name(self.trace_name().as_bytes())
    }

    // -- the `Curl_cfilter` instance members -----------------------------

    /// The chain link, socket index and two state flags this instance carries.
    fn base(&self) -> &FilterBase;

    /// The mutable view of [`Self::base`].
    fn base_mut(&mut self) -> &mut FilterBase;

    /// Which chain this filter is installed on -- `cf->sockindex`.
    fn sockindex(&self) -> SocketIndex {
        self.base().sockindex()
    }

    // -- 1. destroy ------------------------------------------------------

    /// `Curl_cft_destroy_this` (`lib/cfilters.h:39-40`): release this
    /// instance's own resources.
    ///
    /// MUST NOT chain (`lib/cfilters.h:37`). The caller has already severed the
    /// link and owns the rest of the chain; reaching `next` from here would
    /// destroy a filter twice.
    ///
    /// A no-op by default, which is what the C's own default does -- and note
    /// that `Curl_cf_def_destroy_this` is DECLARED at `lib/cfilters.h:240` and
    /// never defined anywhere in the tree, so "no-op" is the whole of it.
    /// Rust's own [`Drop`] handles the memory; this hook exists for the effects
    /// a `Drop` cannot have, namely tracing and notifying a peer.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        let _ = cx;
    }

    // -- 2. connect ------------------------------------------------------

    /// `Curl_cft_connect` (`lib/cfilters.h:53-55`): make progress towards being
    /// connected.
    ///
    /// Returns whether the filter is now connected -- the C's `bool *done`. A
    /// `false` is not a failure: it means call again when readiness changes, and
    /// it is how the whole non-blocking design works.
    ///
    /// REQUIRED, with no default. There is no universal C default either: every
    /// registered filter type supplies its own `do_connect`, because "connected"
    /// means something different at every layer. Inventing one here would let a
    /// filter compile as permanently unconnected.
    ///
    /// # Errors
    ///
    /// Whatever the layer's own failure is. A filter that would block reports
    /// `Ok(false)` rather than [`CURLcode::Again`].
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool>;

    // -- 3. close --------------------------------------------------------

    /// `Curl_cft_close` (`lib/cfilters.h:43-44`): close immediately, without
    /// negotiating.
    ///
    /// Chains, and MUST: `Curl_conn_close` calls only the head
    /// (`lib/cfilters.c:150-153`) and relies on each implementation to pass the
    /// close down. The filters remain in place and may be connected again
    /// afterwards (`lib/cfilters.h:424-425`), so this clears state rather than
    /// discarding it -- with one sanctioned exception: a filter that owns a
    /// PRIVATE SUBCHAIN, as the setup and Happy Eyeballs filters do, may discard
    /// that subchain here because nothing else can reach it.
    ///
    /// REQUIRED, with no default, and the C agrees: the only default close in
    /// the tree is `Curl_cf_def_close` at `lib/cfilters.c:36-44`, which is
    /// compiled only `#ifdef UNITTESTS` and exists for `unit2600.c`. There is no
    /// production `Curl_cf_def_close`. [`chain_close`] is the equivalent helper
    /// here, and it is named so that a filter using it is doing so on purpose.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>);

    // -- 4. shutdown -----------------------------------------------------

    /// `Curl_cft_shutdown` (`lib/cfilters.h:49-51`): close gracefully,
    /// non-blocking.
    ///
    /// MUST NOT chain (`lib/cfilters.h:47`). [`FilterChain::shutdown`] visits
    /// each filter in turn, so a chaining implementation would shut lower
    /// filters down before the driver had a chance to record that this one
    /// finished.
    ///
    /// Reports `true` and succeeds by default -- `Curl_cf_def_shutdown` sets
    /// `*done = TRUE` and returns `CURLE_OK` (`lib/cfilters.c:46-53`) -- which
    /// is right for every layer with nothing to say goodbye with. `HAPROXY`,
    /// `SETUP`, `TCP-ACCEPT` and the proxies all take it.
    ///
    /// # Errors
    ///
    /// Whatever the layer's own failure is; the driver aborts the whole
    /// shutdown on one.
    fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        let _ = cx;
        Ok(true)
    }

    // -- 5. adjust pollset ----------------------------------------------

    /// `Curl_cft_adjust_pollset` (`lib/cfilters.h:82-84`): say which readiness
    /// this filter is waiting for.
    ///
    /// A PURE NO-OP by default. This is the one default whose C prose and C code
    /// disagree, and the code is what runs: `Curl_cf_def_adjust_pollset`
    /// (`lib/cfilters.c:55-64`) has the literal body `/* NOP */` and returns
    /// `CURLE_OK` without touching `cf->next`, while the comment at
    /// `lib/cfilters.h:64-67` says implementations "need to call filters below".
    /// The comment is stale. Every concrete implementation adjusts and returns
    /// -- `cf_haproxy_adjust_pollset` (`lib/cf-haproxy.c:172-182`) is the
    /// clearest example -- and it is [`FilterChain::adjust_pollset`], the
    /// driver, that walks the chain.
    ///
    /// The only implementation that legitimately invokes a driver from here is
    /// one owning a private subchain, which it must drive itself because the
    /// outer walk cannot see it.
    ///
    /// A filter with no restriction of its own should leave the pollset alone,
    /// and so should a filter whose own `next` has not connected
    /// (`lib/cfilters.h:69-71`).
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
        let _ = cx;
        let _ = ps;
        Ok(())
    }

    // -- 6. data pending -------------------------------------------------

    /// `Curl_cft_data_pending` (`lib/cfilters.h:86-87`): are there bytes
    /// already buffered that a read would return?
    ///
    /// Delegates to `next`, and the bottom of the chain answers `false`
    /// (`lib/cfilters.c:66-71`). This is one of the nine callbacks that DOES
    /// chain, because a buffered byte anywhere below is a byte available above.
    fn data_pending(&mut self, cx: &CallCtx<'_, '_>) -> bool {
        match self.base_mut().next_mut() {
            Some(next) => next.data_pending(cx),
            None => false,
        }
    }

    // -- 7. send ---------------------------------------------------------

    /// `Curl_cft_send` (`lib/cfilters.h:89-94`): hand `buf` down the chain.
    ///
    /// Returns how many bytes were accepted, which may be fewer than were
    /// offered. `eos` marks the last chunk.
    ///
    /// Delegates to `next` (`lib/cfilters.c:73-81`).
    ///
    /// # Errors
    ///
    /// At the bottom of the chain, [`CURLcode::RecvError`] -- for a SEND. That
    /// is not a transcription slip: `Curl_cf_def_send` really does return
    /// `CURLE_RECV_ERROR` at `lib/cfilters.c:80`, and `Curl_cf_def_recv` really
    /// does return `CURLE_SEND_ERROR` at `:89`. The pair is preserved exactly,
    /// because an application comparing a code against `CURLE_RECV_ERROR`
    /// cannot be told the library has since decided it meant the other one.
    ///
    /// Contrast [`FilterChain::send_from_head`], which is NOT this default and
    /// reports [`CURLcode::SendError`] the way one would expect
    /// (`lib/cfilters.c:404-412`). The two are genuinely different functions
    /// with genuinely different codes.
    ///
    /// The C writes `*pnwritten = 0` alongside its error. There is no count on
    /// an [`Err`], which loses nothing: the C's own contract is that the count
    /// is meaningless once the call failed, and here it cannot be read at all.
    fn send(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &[u8],
        eos: bool,
    ) -> CurlResult<usize> {
        match self.base_mut().next_mut() {
            Some(next) => next.send(cx, buf, eos),
            None => Err(Error::with_context(
                CURLcode::RecvError,
                "send: bottom of the filter chain reached",
            )),
        }
    }

    // -- 8. recv ---------------------------------------------------------

    /// `Curl_cft_recv` (`lib/cfilters.h:96-100`): read up to `buf.len()` bytes
    /// from the chain.
    ///
    /// Returns how many bytes were read. Zero is end of stream, not "try
    /// again"; a filter with nothing available yet reports
    /// [`CURLcode::Again`].
    ///
    /// Delegates to `next` (`lib/cfilters.c:83-90`).
    ///
    /// # Errors
    ///
    /// At the bottom of the chain, [`CURLcode::SendError`] -- for a RECEIVE. See
    /// [`Self::send`] for why the pair is left swapped.
    fn recv(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        match self.base_mut().next_mut() {
            Some(next) => next.recv(cx, buf),
            None => Err(Error::with_context(
                CURLcode::SendError,
                "recv: bottom of the filter chain reached",
            )),
        }
    }

    // -- 9. control ------------------------------------------------------

    /// `Curl_cft_cntrl` (`lib/cfilters.h:133-135`): handle one event.
    ///
    /// MUST NOT chain (`lib/cfilters.h:131`). [`FilterChain::cntrl`] distributes
    /// the event top-down and applies the event's own
    /// [`ControlPolicy`]; a chaining implementation would deliver it twice.
    ///
    /// A no-op success by default (`lib/cfilters.c:854-864`).
    ///
    /// # The C optimisation that is deliberately not reproduced
    ///
    /// `Curl_conn_cf_cntrl` skips a filter whose `cntrl` member is literally
    /// `Curl_cf_def_cntrl`, comparing function pointers (`lib/cfilters.c:874`).
    /// It is a call-avoidance optimisation with no observable effect -- the
    /// function it skips does nothing -- and performance is explicitly a
    /// non-goal here. The driver calls every filter.
    ///
    /// # Errors
    ///
    /// Whatever the layer's own failure is. Whether it stops the distribution
    /// depends on the event, not on the filter.
    fn cntrl(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        event: CfControl,
    ) -> CurlResult<()> {
        let _ = cx;
        let _ = event;
        Ok(())
    }

    // -- 10. is alive ----------------------------------------------------

    /// `Curl_cft_conn_is_alive` (`lib/cfilters.h:102-104`): is the connection
    /// still usable, and does it already have bytes waiting?
    ///
    /// Delegates to `next`; the bottom of the chain is [`Liveness::DEAD`],
    /// "pessimistic in absence of data" in the C's own words
    /// (`lib/cfilters.c:92-99`). Pessimism is the safe direction: a connection
    /// wrongly declared dead is re-established, while one wrongly declared
    /// alive breaks the next request on it.
    fn is_alive(&mut self, cx: &mut CallCtx<'_, '_>) -> Liveness {
        match self.base_mut().next_mut() {
            Some(next) => next.is_alive(cx),
            None => Liveness::DEAD,
        }
    }

    // -- 11. keep alive --------------------------------------------------

    /// `Curl_cft_conn_keep_alive` (`lib/cfilters.h:106-107`): do whatever keeps
    /// an idle connection from being dropped.
    ///
    /// Delegates to `next`; the bottom succeeds (`lib/cfilters.c:101-107`).
    ///
    /// # Errors
    ///
    /// Whatever the layer's own failure is.
    fn keep_alive(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        match self.base_mut().next_mut() {
            Some(next) => next.keep_alive(cx),
            None => Ok(()),
        }
    }

    // -- 12. query -------------------------------------------------------

    /// `Curl_cft_query` (`lib/cfilters.h:187-189`): answer a question about the
    /// chain.
    ///
    /// Delegates to `next`, so a filter need only intercept the questions it
    /// knows (`lib/cfilters.c:109-116`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] at the bottom of the chain. That is a
    /// SENTINEL, not a failure: it means nobody understood the question, and
    /// every caller in `lib/cfilters.c:751-1052` reads it as "use the default"
    /// rather than propagating it.
    fn query(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        match self.base_mut().next_mut() {
            Some(next) => next.query(cx, query),
            None => Err(Error::new(CURLcode::UnknownOption)),
        }
    }
}

/// The chaining close a filter with no state of its own can delegate to.
///
/// C's equivalent is `Curl_cf_def_close` (`lib/cfilters.c:36-44`), which exists
/// only `#ifdef UNITTESTS`. It is a free function here rather than a trait
/// default for exactly that reason: [`ConnFilter::close`] has no production
/// default in the C and must not acquire one here, so a filter that wants this
/// behaviour asks for it by name.
///
/// Clears `connected` and passes the close down, in that order.
#[allow(dead_code)]
pub(crate) fn chain_close<F>(filter: &mut F, cx: &mut CallCtx<'_, '_>)
where
    F: ConnFilter + ?Sized,
{
    filter.base_mut().set_connected(false);
    if let Some(next) = filter.base_mut().next_mut() {
        next.close(cx);
    }
}

// =========================================================================
// The filter instance state -- `struct Curl_cfilter`
// =========================================================================

pin_project! {
    /// The five members every filter instance carries, whatever it implements.
    ///
    /// The successor of `struct Curl_cfilter` (`lib/cfilters.h:229-237`) minus
    /// two members that do not survive the translation. `cft` is gone because
    /// the vtable is the trait object itself, and `void *ctx` is gone because an
    /// implementation keeps its state in a typed field beside this one:
    ///
    /// ```ignore
    /// #[derive(Debug)]
    /// struct CfTls {
    ///     base: FilterBase,
    ///     session: TlsSession,   // typed, concrete, no cast anywhere
    /// }
    /// ```
    ///
    /// Destructuring `let Self { base, session } = self` then reaches both at
    /// once, which is what an implementation needs and what a `Pin<&mut Self>`
    /// receiver would have taken away.
    ///
    /// # Both flags belong to the INSTANCE
    ///
    /// `connected` and `shutdown` are `BIT()` members of `Curl_cfilter`, not of
    /// `Curl_cftype`, and every driver in `lib/cfilters.c` depends on that: the
    /// send and receive entry points skip the leading run of filters whose own
    /// `connected` is false (`:220`, `:239`), the pollset driver skips the
    /// leading run whose own `shutdown` is true (`:777-778`), and the shutdown
    /// driver sets `shutdown` on one filter at a time as each finishes (`:204`).
    /// A chain-level flag could express none of that.
    ///
    /// # Why `#[pin]`
    ///
    /// The link is structurally pinned, so a filter cannot be moved out from
    /// under a chain that is mid-traversal. [`Self::next_pin_mut`] is the only
    /// way through it and needs no `Pin::new_unchecked`; the pinning projection
    /// [`pin_project`] generates is what makes that safe. Because every filter
    /// is [`Unpin`] -- see [`ConnFilter`] for why that bound is the right
    /// trade -- the pinned reference converts back to `&mut` for free, so the
    /// guarantee costs nothing at run time.
    #[derive(Debug, Default)]
    pub(crate) struct FilterBase {
        #[pin]
        next: Option<FilterLink>,
        conn: Option<ConnId>,
        sockindex: SocketIndex,
        connected: bool,
        shutdown: bool,
    }
}

impl FilterBase {
    /// An unattached base for a chain at `sockindex`.
    ///
    /// Unattached is the state `Curl_cf_create` leaves a filter in: `calloc`
    /// zeroes `conn` and `next`, and both `Curl_conn_cf_add` and
    /// `Curl_conn_cf_insert_after` assert on it before linking
    /// (`lib/cfilters.c:335-336`, `:352`).
    ///
    /// The index is taken here as well as stamped at insertion, because a filter
    /// created for a known chain should not have to read as belonging to the
    /// primary socket until someone links it.
    #[allow(dead_code)]
    pub(crate) fn new(sockindex: SocketIndex) -> Self {
        Self {
            next: None,
            conn: None,
            sockindex,
            connected: false,
            shutdown: false,
        }
    }

    /// The next filter down, shared.
    #[allow(dead_code)]
    pub(crate) fn next_ref(&self) -> Option<&(dyn ConnFilter + 'static)> {
        self.next.as_deref()
    }

    /// The next filter down, mutable.
    ///
    /// The one conversion from the pinned link back to `&mut`, and the reason
    /// [`ConnFilter`] requires [`Unpin`]: [`Pin::get_mut`] is safe under exactly
    /// that bound, so the whole chain traversal needs no projection at any call
    /// site and no unchecked construction anywhere.
    #[allow(dead_code)]
    pub(crate) fn next_mut(
        &mut self,
    ) -> Option<&mut (dyn ConnFilter + 'static)> {
        // `Pin::new` is available because `FilterBase` is `Unpin` -- its only
        // `#[pin]` field is an `Option<Pin<Box<_>>>`, and a pinned box is
        // `Unpin` whatever it points at.
        Pin::new(self).next_pin_mut().map(Pin::get_mut)
    }

    /// The next filter down, pinned.
    ///
    /// Written through the projection [`pin_project`] generates, which is what
    /// makes reaching a structurally pinned field safe. Kept private because
    /// every consumer in this module wants [`Self::next_mut`]; a future
    /// implementation that genuinely needs the pinned form can widen it without
    /// changing anything else.
    #[allow(dead_code)]
    fn next_pin_mut(
        self: Pin<&mut Self>,
    ) -> Option<Pin<&mut (dyn ConnFilter + 'static)>> {
        // The trait object is written `+ 'static` deliberately: `Pin<&mut T>` is
        // INVARIANT in `T`, so an elided `+ '_` here does not unify with the
        // `'static` the owned link carries and the borrow checker rejects it.
        self.project()
            .next
            .as_pin_mut()
            .map(|link| link.get_mut().as_mut())
    }

    /// Detaches and returns the next link, leaving this filter as the tail.
    ///
    /// The severing step of `Curl_conn_cf_discard_chain`: `cfn = cf->next;
    /// cf->next = NULL;` before `destroy` (`lib/cfilters.c:126-130`).
    #[allow(dead_code)]
    pub(crate) fn take_next(&mut self) -> Option<FilterLink> {
        self.next.take()
    }

    /// Links `next` below this filter.
    ///
    /// # Panics
    ///
    /// Panics in a debug build if a link is already present. Overwriting one
    /// would drop a whole subchain through [`Box`]'s destructor without calling
    /// [`ConnFilter::destroy`] on any of it, which is precisely the teardown
    /// path [`discard_chain_from`] exists to keep correct -- so the mistake is
    /// caught where it is made rather than diagnosed later as a missing
    /// destructor. Call [`Self::take_next`] first. A release build replaces the
    /// link, because refusing mid-operation would leak the filter the caller has
    /// already handed over.
    #[allow(dead_code)]
    pub(crate) fn set_next(&mut self, next: Option<FilterLink>) {
        debug_assert!(
            self.next.is_none(),
            "set_next would displace a linked filter; take_next first"
        );
        self.next = next;
    }

    /// True when there is a filter below this one.
    #[allow(dead_code)]
    pub(crate) fn has_next(&self) -> bool {
        self.next.is_some()
    }

    /// Which chain this filter is installed on -- `cf->sockindex`.
    #[allow(dead_code)]
    pub(crate) fn sockindex(&self) -> SocketIndex {
        self.sockindex
    }

    /// Sets the chain index, as insertion does for every node it links.
    #[allow(dead_code)]
    pub(crate) fn set_sockindex(&mut self, sockindex: SocketIndex) {
        self.sockindex = sockindex;
    }

    /// Which connection this filter belongs to -- the identity that replaces
    /// `cf->conn`. [`None`] while unattached.
    #[allow(dead_code)]
    pub(crate) fn conn(&self) -> Option<ConnId> {
        self.conn
    }

    /// Stamps the connection identity, as insertion does for every node.
    #[allow(dead_code)]
    pub(crate) fn set_conn(&mut self, conn: Option<ConnId>) {
        self.conn = conn;
    }

    /// True once this filter has been linked into a chain.
    ///
    /// The successor of C's `if(cf->conn)` test (`lib/cfilters.c:371`) and of
    /// the `DEBUGASSERT(!cf->conn)` that guards both insertion points.
    #[allow(dead_code)]
    pub(crate) fn is_attached(&self) -> bool {
        self.conn.is_some()
    }

    /// `cf->connected`.
    #[allow(dead_code)]
    pub(crate) fn is_connected(&self) -> bool {
        self.connected
    }

    /// Sets `cf->connected`.
    #[allow(dead_code)]
    pub(crate) fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    /// `cf->shutdown`.
    #[allow(dead_code)]
    pub(crate) fn has_shut_down(&self) -> bool {
        self.shutdown
    }

    /// Sets `cf->shutdown`, as the shutdown driver does on each filter that
    /// reports it has finished (`lib/cfilters.c:204`).
    #[allow(dead_code)]
    pub(crate) fn set_shut_down(&mut self, shutdown: bool) {
        self.shutdown = shutdown;
    }
}

// =========================================================================
// The chain -- `conn->cfilter[sockindex]`
// =========================================================================

/// A walk down one chain, shared.
///
/// The C writes `for(; cf; cf = cf->next)` in eleven places
/// (`lib/cfilters.c:634`, `:684`, `:715`, `:873` among them); this is that loop,
/// once.
#[allow(dead_code)]
pub(crate) struct FilterIter<'a> {
    cursor: Option<&'a (dyn ConnFilter + 'static)>,
}

impl<'a> Iterator for FilterIter<'a> {
    type Item = &'a (dyn ConnFilter + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.cursor?;
        self.cursor = current.base().next_ref();
        Some(current)
    }
}

/// What a connect attempt reported back to its connection.
///
/// `Curl_conn_connect` writes three values through pointers it was handed --
/// two progress timers via `conn_report_connect_stats` (`lib/cfilters.c:472-489`)
/// and `conn->keepalive` (`:537`). The owners of all three are elsewhere:
/// `crate::transfer::progress` keeps the timers and `conn/mod.rs` keeps the
/// keepalive reading. Collecting them into one out-parameter hands them back
/// without this module reaching into either.
///
/// Out-parameter rather than a return value deliberately: the C reports the
/// timers on the ERROR path too (`:543`), and an [`Err`] carries no payload to
/// put them in.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ConnectReport {
    /// `TIMER_CONNECT`. [`CurlTime::is_zero`] where the chain did not answer,
    /// which is the C's own "not set" test at `:481`.
    pub(crate) connected_at: CurlTime,
    /// `TIMER_APPCONNECT`, e.g. when the TLS handshake finished. Zero where the
    /// chain did not answer (`:486`).
    pub(crate) app_connected_at: CurlTime,
    /// `conn->keepalive`, read from the injected clock once the whole chain is
    /// connected.
    pub(crate) keepalive: CurlTime,
}

/// One connection filter chain: an owned, ordered stack of filters.
///
/// The successor of one element of `conn->cfilter[2]` (`lib/urldata.h:646`)
/// together with the twenty-odd `Curl_conn_*` drivers that operate on it. The
/// C keeps the head as a bare pointer in the connection and passes it around;
/// here the chain OWNS its filters, which is what makes teardown deterministic
/// and double-destruction unrepresentable.
///
/// # Position, not pointer
///
/// The C addresses a particular filter by its pointer: `insert_after(cf_at,
/// cf_new)` and `discard(&cf)` both take one. A safe chain cannot hand out a
/// borrow of a node and then be mutated through, so the equivalent operations
/// here take a POSITION counted from the head -- [`Self::insert_after`] and
/// [`Self::discard_at`]. That is not a weakening: a caller that has just added
/// a filter knows where it put it, and the setup filter's own use of
/// `insert_after` inserts immediately below itself, which is position zero.
///
/// One C behaviour disappears entirely as a consequence, and its disappearance
/// is a guarantee rather than a gap. `Curl_conn_cf_discard` handles the case of
/// a filter pointer that MAY OR MAY NOT be linked into the chain, and reports
/// which through its return value (`lib/cfilters.c:365-387`). Here, if a caller
/// owns a [`FilterLink`] then it is not in a chain, because ownership is
/// exclusive -- so the ambiguity cannot arise. [`discard_unlinked`] covers the
/// other half of that C function, for a link the caller still holds.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct FilterChain {
    /// The topmost filter, or [`None`] for a chain that is not set up.
    head: Option<FilterLink>,
    /// Which connection this chain belongs to, stamped onto every filter linked
    /// into it.
    conn: Option<ConnId>,
    /// Which of the connection's two chains this is.
    sockindex: SocketIndex,
}

impl FilterChain {
    /// An empty chain for `sockindex` on `conn`.
    #[allow(dead_code)]
    pub(crate) fn new(conn: Option<ConnId>, sockindex: SocketIndex) -> Self {
        Self {
            head: None,
            conn,
            sockindex,
        }
    }

    /// `Curl_conn_is_setup` (`lib/cfilters.c:594-599`): does a chain exist here
    /// at all?
    #[allow(dead_code)]
    pub(crate) fn is_setup(&self) -> bool {
        self.head.is_some()
    }

    /// True when no filter is installed. The inverse of [`Self::is_setup`],
    /// spelled the way [`Self::len`] expects a companion to be.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// How many filters are installed.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.iter().count()
    }

    /// Which chain this is.
    #[allow(dead_code)]
    pub(crate) fn sockindex(&self) -> SocketIndex {
        self.sockindex
    }

    /// Which connection this chain belongs to.
    #[allow(dead_code)]
    pub(crate) fn conn(&self) -> Option<ConnId> {
        self.conn
    }

    /// Rebinds the chain to a connection, restamping every installed filter.
    ///
    /// Needed because a chain may be built before its connection has an
    /// identity, which is the situation C's `Curl_cf_create`-then-`add`
    /// sequence is in.
    #[allow(dead_code)]
    pub(crate) fn set_conn(&mut self, conn: Option<ConnId>) {
        self.conn = conn;
        let sockindex = self.sockindex;
        let mut index = 0_usize;
        while let Some(node) = self.nth_mut(index) {
            node.base_mut().set_conn(conn);
            node.base_mut().set_sockindex(sockindex);
            index += 1;
        }
    }

    /// The topmost filter, shared.
    #[allow(dead_code)]
    pub(crate) fn head_ref(&self) -> Option<&(dyn ConnFilter + 'static)> {
        self.head.as_deref()
    }

    /// The topmost filter, mutable.
    #[allow(dead_code)]
    pub(crate) fn head_mut(
        &mut self,
    ) -> Option<&mut (dyn ConnFilter + 'static)> {
        self.head.as_mut().map(|link| link.as_mut().get_mut())
    }

    /// Every filter from the top down.
    #[allow(dead_code)]
    pub(crate) fn iter(&self) -> FilterIter<'_> {
        FilterIter {
            cursor: self.head_ref(),
        }
    }

    /// The filter at `index`, counted from the head, shared.
    #[allow(dead_code)]
    pub(crate) fn nth_ref(
        &self,
        index: usize,
    ) -> Option<&(dyn ConnFilter + 'static)> {
        self.iter().nth(index)
    }

    /// The filter at `index`, counted from the head, mutable.
    #[allow(dead_code)]
    pub(crate) fn nth_mut(
        &mut self,
        index: usize,
    ) -> Option<&mut (dyn ConnFilter + 'static)> {
        let mut cursor = self.head_mut();
        let mut remaining = index;
        loop {
            let node = cursor?;
            if remaining == 0 {
                return Some(node);
            }
            remaining -= 1;
            cursor = node.base_mut().next_mut();
        }
    }

    // -- installation ----------------------------------------------------

    /// `Curl_conn_cf_add` (`lib/cfilters.c:329-343`): install `filter` at the
    /// TOP of the chain.
    ///
    /// The new filter takes the old head as its `next` and inherits the chain's
    /// connection identity and socket index. It must not already be attached,
    /// which the C asserts in a debug build (`:335-336`) and which is checked
    /// the same way here -- a release build links it anyway, exactly as the C
    /// does, because refusing would leak the filter the caller handed over.
    #[allow(dead_code)]
    pub(crate) fn add(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        mut filter: FilterLink,
    ) {
        {
            let base = filter.as_mut().get_mut().base_mut();
            debug_assert!(
                !base.is_attached(),
                "a filter being added must not already be attached"
            );
            debug_assert!(
                !base.has_next(),
                "a filter being added must not already have a successor"
            );
            base.set_conn(self.conn);
            base.set_sockindex(self.sockindex);
            base.set_next(self.head.take());
        }
        let identity = filter.trace_filter();
        let sockindex = self.sockindex.as_i32();
        self.head = Some(filter);
        trc!(cx, identity, sockindex, "added");
    }

    /// `Curl_conn_cf_insert_after` (`lib/cfilters.c:345-363`): install `filter`
    /// immediately BELOW the filter at `index`.
    ///
    /// `filter` may itself be a whole chain, and that is not a corner case --
    /// the setup filter builds a stack of several and inserts it in one go. The
    /// C walks the inserted value with a `do {} while(cf_new)` loop stamping
    /// EVERY node (`:356-361`) and only then reattaches the old successor to its
    /// tail; both are reproduced, because a node left holding a stale identity
    /// would report the wrong socket index in every trace line it ever emits.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] when no filter is installed at
    /// `index`. The C asserts `cf_at` is non-`NULL` instead, which a position
    /// cannot express.
    #[allow(dead_code)]
    pub(crate) fn insert_after(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        index: usize,
        mut filter: FilterLink,
    ) -> CurlResult<()> {
        debug_assert!(
            !filter.base().is_attached(),
            "a filter being inserted must not already be attached"
        );

        let conn = self.conn;
        let sockindex = self.sockindex;

        // Detach the old successor first, so that the stamping walk below runs
        // over the inserted chain ALONE and cannot wander into filters that are
        // already correctly stamped.
        let old_tail = match self.nth_mut(index) {
            Some(at) => at.base_mut().take_next(),
            None => {
                return Err(Error::with_context(
                    CURLcode::BadFunctionArgument,
                    "insert_after: no filter at that position",
                ))
            }
        };

        stamp_chain(filter.as_mut().get_mut(), conn, sockindex, old_tail);

        let identity = filter.trace_filter();
        match self.nth_mut(index) {
            Some(at) => at.base_mut().set_next(Some(filter)),
            None => {
                // Unreachable: the position resolved a moment ago and nothing
                // above it was touched. Reported rather than asserted, because
                // a panic here would take a live transfer down.
                return Err(Error::with_context(
                    CURLcode::FailedInit,
                    "insert_after: the chain changed underneath the insertion",
                ));
            }
        }
        trc!(cx, identity, sockindex.as_i32(), "inserted");
        Ok(())
    }

    // -- teardown --------------------------------------------------------

    /// Unlinks and destroys the filter at `index`, hoisting its successor into
    /// its place.
    ///
    /// The linked half of `Curl_conn_cf_discard` (`lib/cfilters.c:365-387`).
    /// Returns whether a filter was there -- the C's `found`.
    ///
    /// Exactly ONE filter is destroyed. The C achieves that by clearing
    /// `cf->next` before handing the node to `Curl_conn_cf_discard_chain`
    /// (`:377`); here the successor is moved into the predecessor's place
    /// first, which has the same effect and cannot be got wrong by omission.
    #[allow(dead_code)]
    pub(crate) fn discard_at(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        index: usize,
    ) -> bool {
        let mut removed = if index == 0 {
            let Some(mut head) = self.head.take() else {
                return false;
            };
            self.head = head.as_mut().get_mut().base_mut().take_next();
            head
        } else {
            let Some(prev) = self.nth_mut(index - 1) else {
                return false;
            };
            let Some(mut node) = prev.base_mut().take_next() else {
                return false;
            };
            let successor = node.as_mut().get_mut().base_mut().take_next();
            prev.base_mut().set_next(successor);
            node
        };

        // Now unlinked and owned here, so `destroy` cannot reach anything else.
        removed.as_mut().get_mut().destroy(cx);
        drop(removed);
        true
    }

    /// `Curl_conn_cf_discard_chain` / `Curl_conn_cf_discard_all`
    /// (`lib/cfilters.c:118-142`): destroy every filter and empty the chain.
    ///
    /// The head is cleared FIRST, before any destructor runs, which is the C's
    /// `*pcf = NULL` at `:124`. See [`discard_chain_from`] for the ordering that
    /// makes the walk safe.
    #[allow(dead_code)]
    pub(crate) fn discard_chain(&mut self, cx: &mut CallCtx<'_, '_>) {
        discard_chain_from(cx, self.head.take());
    }

    /// Detaches the whole chain without destroying it, leaving this empty.
    ///
    /// What a filter owning a private subchain needs in order to hand that
    /// subchain somewhere else -- the Happy Eyeballs filter promoting the winner
    /// of a race, for instance.
    #[allow(dead_code)]
    pub(crate) fn take_chain(&mut self) -> Option<FilterLink> {
        self.head.take()
    }

    /// Installs `head` as the whole chain, restamping every node.
    ///
    /// The counterpart of [`Self::take_chain`]. Anything already installed is
    /// returned rather than destroyed, so no filter is dropped by surprise.
    #[allow(dead_code)]
    pub(crate) fn set_chain(
        &mut self,
        head: Option<FilterLink>,
    ) -> Option<FilterLink> {
        let previous = core::mem::replace(&mut self.head, head);
        self.set_conn(self.conn);
        previous
    }
}

/// Stamps `conn` and `sockindex` onto every node from `head` down, then hangs
/// `tail` off the last one.
///
/// The `do {} while(cf_new)` loop of `Curl_conn_cf_insert_after`
/// (`lib/cfilters.c:356-362`), lifted out because the walk must run while the
/// inserted value is still owned -- borrowing it out of the chain first would
/// mean holding a mutable borrow of the chain across the whole walk.
#[allow(dead_code)]
fn stamp_chain(
    head: &mut (dyn ConnFilter + 'static),
    conn: Option<ConnId>,
    sockindex: SocketIndex,
    tail: Option<FilterLink>,
) {
    let mut pending = tail;
    let mut cursor: Option<&mut (dyn ConnFilter + 'static)> = Some(head);
    while let Some(node) = cursor {
        node.base_mut().set_conn(conn);
        node.base_mut().set_sockindex(sockindex);
        if node.base().has_next() {
            cursor = node.base_mut().next_mut();
        } else {
            // The tail of the inserted chain: reattach what used to follow the
            // insertion point and stop. Not walked into -- those nodes are
            // already stamped, being part of the chain the caller owns.
            node.base_mut().set_next(pending.take());
            cursor = None;
        }
    }
}

/// `Curl_conn_cf_discard_chain` (`lib/cfilters.c:118-136`) over an owned chain.
///
/// Three properties, all deliberate and all measured:
///
/// 1. **Front to back.** The head is destroyed first and the tail last. That is
///    the OPPOSITE of the tail-first order `crate::util::llist` reproduces for
///    the intrusive lists elsewhere in the tree, and it is what the C does here.
/// 2. **Severed before destroyed.** Each node's `next` is taken away before its
///    `destroy` runs, so an implementation cannot reach the filters below it --
///    the C's own comment says the severing exists to "prevent destroying filter
///    to mess with its sub-chain, since we have the reference now" (`:127-129`).
/// 3. **Not recursive.** Relying on [`Box`]'s own drop would destroy the chain
///    depth-first through nested destructors, in the wrong order, without ever
///    calling [`ConnFilter::destroy`], and would recurse once per link.
#[allow(dead_code)]
pub(crate) fn discard_chain_from(
    cx: &mut CallCtx<'_, '_>,
    head: Option<FilterLink>,
) {
    let mut current = head;
    while let Some(mut link) = current {
        let filter = link.as_mut().get_mut();
        let next = filter.base_mut().take_next();
        filter.destroy(cx);
        // The C's `curlx_free(cf)` at `:132`, explicit so the sequence reads
        // the same: sever, destroy, free, advance.
        drop(link);
        current = next;
    }
}

/// The unlinked half of `Curl_conn_cf_discard` (`lib/cfilters.c:365-387`):
/// destroys a link the caller still owns.
///
/// Always reports `false`, which is the C's `found` for a filter that was not
/// part of a chain -- and here that is not merely the usual case but the only
/// one, because owning the link proves it is not installed anywhere.
///
/// Destroys the link AND everything below it, which is also the C's behaviour:
/// only the `found` branch clears `cf->next` (`:377`), so a node that was never
/// linked reaches `discard_chain` with its subchain still attached.
#[allow(dead_code)]
pub(crate) fn discard_unlinked(
    cx: &mut CallCtx<'_, '_>,
    filter: FilterLink,
) -> bool {
    discard_chain_from(cx, Some(filter));
    false
}

// =========================================================================
// Chain drivers -- the `Curl_conn_*` and `Curl_cf_*` entry points
// =========================================================================

impl FilterChain {
    /// The first filter whose own `connected` is set, if any.
    ///
    /// The `while(cf && !cf->connected) cf = cf->next;` that heads
    /// `Curl_cf_recv` (`lib/cfilters.c:220-221`), `Curl_cf_send` (`:239-240`)
    /// and `Curl_conn_data_pending` (`:742-744`). Skipping the leading run is
    /// what lets a partially built chain still carry bytes: during a `CONNECT`
    /// tunnel negotiation the proxy filter is not connected while the socket
    /// beneath it is, and the negotiation's own bytes must go through the
    /// socket.
    #[allow(dead_code)]
    pub(crate) fn first_connected_mut(
        &mut self,
    ) -> Option<&mut (dyn ConnFilter + 'static)> {
        let mut cursor = self.head_mut();
        loop {
            let node = cursor?;
            if node.base().is_connected() {
                return Some(node);
            }
            cursor = node.base_mut().next_mut();
        }
    }

    // -- connect and close -----------------------------------------------

    /// `Curl_conn_cf_connect` (`lib/cfilters.c:389-396`): one connect step at
    /// the head.
    ///
    /// Returns whether the WHOLE chain is now connected, because the head only
    /// reports itself connected once everything beneath it is.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when no filter is installed, which is the C's
    /// answer for a `NULL` head (`:395`), plus whatever the head reports.
    #[allow(dead_code)]
    pub(crate) fn connect_head(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<bool> {
        match self.head_mut() {
            Some(head) => head.connect(cx),
            None => Err(Error::with_context(
                CURLcode::FailedInit,
                "connect: no filter chain installed",
            )),
        }
    }

    /// True when the head reports itself connected.
    ///
    /// The `*done = (bool)cf->connected` early-out of `Curl_conn_connect`
    /// (`lib/cfilters.c:514-516`), which is what makes calling connect on an
    /// already connected chain free of side effects.
    #[allow(dead_code)]
    pub(crate) fn is_head_connected(&self) -> bool {
        self.head_ref()
            .is_some_and(|head| head.base().is_connected())
    }

    /// `Curl_conn_is_connected` (`lib/cfilters.c:601-613`).
    ///
    /// `no_network` is `conn->scheme->flags & PROTOPT_NONETWORK`, passed in
    /// because the scheme table belongs to `crate::protocols`. A scheme that
    /// uses no network -- `file://` -- is connected without a chain, which is
    /// exactly why the C tests it in the `else` of the `NULL` head.
    #[allow(dead_code)]
    pub(crate) fn is_connected(&self, no_network: bool) -> bool {
        match self.head_ref() {
            Some(head) => head.base().is_connected(),
            None => no_network,
        }
    }

    /// `Curl_conn_close` minus its timer clear (`lib/cfilters.c:144-153`).
    ///
    /// Calls the HEAD ONLY and relies on each implementation to pass the close
    /// down, which is why [`ConnFilter::close`] has no default. The filters
    /// remain installed and may be connected again.
    #[allow(dead_code)]
    pub(crate) fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        if let Some(head) = self.head_mut() {
            head.close(cx);
        }
    }

    /// `Curl_conn_close` in full (`lib/cfilters.c:144-155`): the close, then
    /// `Curl_shutdown_clear`.
    ///
    /// Split from [`Self::close`] so that a caller with no timer -- a test, or a
    /// subchain owner tearing down state it alone can see -- is not obliged to
    /// invent one.
    #[allow(dead_code)]
    pub(crate) fn close_and_clear(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        timer: &mut dyn ShutdownTimer,
    ) {
        self.close(cx);
        timer.clear(self.sockindex);
    }

    /// `Curl_conn_shutdown` (`lib/cfilters.c:157-210`): shut the chain down
    /// gracefully, without blocking.
    ///
    /// Returns whether the shutdown has FINISHED. `Ok(false)` means call again.
    ///
    /// The sequence, step for step:
    ///
    /// 1. Find the first filter that is connected and has not already shut down
    ///    (`:169-171`). None means there is nothing to shut down and the answer
    ///    is `true` (`:173-176`).
    /// 2. Start the timer if it is not running; otherwise, a NEGATIVE remaining
    ///    time means the deadline has passed (`:179-189`). C reports that with
    ///    `infof` rather than `failf` because it "might be regarded as
    ///    acceptable" (`:185`), and that choice is kept.
    /// 3. Walk the rest, shutting down one filter per pass. An unfinished filter
    ///    returns success with `false` and leaves its flag clear so the next call
    ///    resumes at the same place (`:199-202`); a finished one has its
    ///    `shutdown` flag set and the walk continues (`:203-205`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::OperationTimedout`] once the deadline has passed, plus
    /// whatever a filter reports -- which aborts the whole shutdown.
    #[allow(dead_code)]
    pub(crate) fn shutdown(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        timer: &mut dyn ShutdownTimer,
    ) -> CurlResult<bool> {
        let sockindex = self.sockindex;

        let mut index = 0_usize;
        loop {
            match self.nth_ref(index) {
                None => return Ok(true),
                Some(node) => {
                    if node.base().is_connected()
                        && !node.base().has_shut_down()
                    {
                        break;
                    }
                }
            }
            index += 1;
        }

        if timer.started(sockindex) {
            if timer.time_left_ms(sockindex) < 0 {
                if let Some(tracer) = cx.tracer_mut() {
                    tracer.infof(format_args!("shutdown timeout"));
                }
                return Err(Error::with_context(
                    CURLcode::OperationTimedout,
                    "shutdown timeout",
                ));
            }
        } else {
            // Zero asks the timer for its default, as the C's
            // `Curl_shutdown_start(data, sockindex, 0)` does (`:180`).
            timer.start(sockindex, 0);
        }

        while let Some(node) = self.nth_mut(index) {
            if !node.base().has_shut_down() {
                let identity = node.trace_filter();
                let sockidx = node.sockindex().as_i32();
                match node.shutdown(cx) {
                    Err(error) => {
                        let code = error.code().as_i32();
                        trc!(
                            cx,
                            identity,
                            sockidx,
                            "shut down failed with {}",
                            code
                        );
                        return Err(error);
                    }
                    Ok(false) => {
                        trc!(cx, identity, sockidx, "shut down not done yet");
                        return Ok(false);
                    }
                    Ok(true) => {
                        trc!(cx, identity, sockidx, "shut down successfully");
                        node.base_mut().set_shut_down(true);
                    }
                }
            }
            index += 1;
        }
        Ok(true)
    }

    // -- input and output ------------------------------------------------

    /// `Curl_cf_send` (`lib/cfilters.c:230-248`): send through the first
    /// CONNECTED filter.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when no filter is connected. The C additionally
    /// asserts (`:245`), which would abort a debug build; the diagnostic is kept
    /// as the error's message instead, because a chain reaching this state is a
    /// bug worth reporting and not worth aborting a transfer for.
    #[allow(dead_code)]
    pub(crate) fn send(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &[u8],
        eos: bool,
    ) -> CurlResult<usize> {
        match self.first_connected_mut() {
            Some(filter) => filter.send(cx, buf, eos),
            None => Err(Error::with_context(
                CURLcode::FailedInit,
                "send: no filter connected",
            )),
        }
    }

    /// `Curl_cf_recv` (`lib/cfilters.c:212-228`): receive through the first
    /// CONNECTED filter.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    #[allow(dead_code)]
    pub(crate) fn recv(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        match self.first_connected_mut() {
            Some(filter) => filter.recv(cx, buf),
            None => Err(Error::with_context(
                CURLcode::FailedInit,
                "recv: no filter connected",
            )),
        }
    }

    /// `Curl_conn_cf_send` (`lib/cfilters.c:404-412`): send through the HEAD,
    /// connected or not.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] when no filter is installed -- and note that this
    /// is the OPPOSITE of [`ConnFilter::send`]'s terminal
    /// [`CURLcode::RecvError`]. Both are transcribed as found; see
    /// [`ConnFilter::send`] for why neither is corrected.
    #[allow(dead_code)]
    pub(crate) fn send_from_head(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &[u8],
        eos: bool,
    ) -> CurlResult<usize> {
        match self.head_mut() {
            Some(head) => head.send(cx, buf, eos),
            None => Err(Error::with_context(
                CURLcode::SendError,
                "send: no filter chain installed",
            )),
        }
    }

    /// `Curl_conn_cf_recv` (`lib/cfilters.c:414-421`): receive through the HEAD,
    /// connected or not.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] when no filter is installed, the mirror image of
    /// [`Self::send_from_head`].
    #[allow(dead_code)]
    pub(crate) fn recv_into_head(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        match self.head_mut() {
            Some(head) => head.recv(cx, buf),
            None => Err(Error::with_context(
                CURLcode::RecvError,
                "recv: no filter chain installed",
            )),
        }
    }

    /// `Curl_cf_recv_bufq` (`lib/cfilters.c:263-278`): read from the chain
    /// straight into `bufq`.
    ///
    /// A convenience over [`BufQ::sipn`] so that a caller does not have to write
    /// the reader closure, which is exactly what the C says its own wrapper is
    /// for (`lib/cfilters.h:511-514`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] when no filter is installed. The C
    /// tests `!cf || !data` (`:271`); a missing chain is the only one of those
    /// two that can still happen here, since a context cannot be absent.
    ///
    /// Otherwise whatever the chain or [`BufQ`] reports -- as a bare code. The
    /// context a filter attached is lost crossing [`BufQ`]'s callback boundary,
    /// which takes and returns [`CodeResult`]; the C loses it in the same place
    /// and for the same reason.
    #[allow(dead_code)]
    pub(crate) fn recv_bufq(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        bufq: &mut BufQ,
        max_len: usize,
    ) -> CurlResult<usize> {
        if self.head.is_none() {
            return Err(Error::with_context(
                CURLcode::BadFunctionArgument,
                "recv_bufq: no filter chain installed",
            ));
        }
        let chain = &mut *self;
        bufq.sipn(max_len, |buf| {
            chain.recv_into_head(cx, buf).map_err(CURLcode::from)
        })
        .map_err(Error::from)
    }

    /// `Curl_cf_send_bufq` (`lib/cfilters.c:288-307`): drain `bufq` into the
    /// chain, offering `buf` after it.
    ///
    /// With bytes to append this is [`BufQ::write_pass`], which appends then
    /// drains; with none it is [`BufQ::pass`], which only drains. That is the
    /// C's `if(buf && blen)` at `:302`.
    ///
    /// The writer ALWAYS passes `eos = false`, which is the literal `FALSE` at
    /// `lib/cfilters.c:285`. It is not an oversight: end of stream is a property
    /// of the transfer, and a buffer being drained says nothing about whether
    /// more will follow. A caller that means end of stream sends the last chunk
    /// through [`Self::send`] directly.
    ///
    /// # Errors
    ///
    /// As [`Self::recv_bufq`].
    #[allow(dead_code)]
    pub(crate) fn send_bufq(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        bufq: &mut BufQ,
        buf: &[u8],
    ) -> CurlResult<usize> {
        if self.head.is_none() {
            return Err(Error::with_context(
                CURLcode::BadFunctionArgument,
                "send_bufq: no filter chain installed",
            ));
        }
        let chain = &mut *self;
        let writer = |bytes: &[u8]| {
            chain
                .send_from_head(cx, bytes, false)
                .map_err(CURLcode::from)
        };
        if buf.is_empty() {
            bufq.pass(writer).map_err(Error::from)
        } else {
            bufq.write_pass(buf, writer).map_err(Error::from)
        }
    }

    /// `Curl_conn_data_pending` (`lib/cfilters.c:731-749`).
    #[allow(dead_code)]
    pub(crate) fn data_pending(&mut self, cx: &mut CallCtx<'_, '_>) -> bool {
        match self.first_connected_mut() {
            Some(filter) => {
                // The C hands a `const struct Curl_easy *` here, which is why
                // the trait method takes the context by shared reference.
                let shared: &CallCtx<'_, '_> = cx;
                filter.data_pending(shared)
            }
            None => false,
        }
    }

    // -- readiness -------------------------------------------------------

    /// `Curl_conn_cf_adjust_pollset` (`lib/cfilters.c:768-786`): collect what
    /// this chain is waiting for.
    ///
    /// Three phases, transcribed exactly:
    ///
    /// 1. Advance to the LOWEST not-yet-connected filter whose successor is also
    ///    not connected (`:773-775`). A filter whose `next` has connected is the
    ///    one currently negotiating, and it is the one with an opinion.
    /// 2. Skip the leading run of filters that have already shut down
    ///    (`:776-778`).
    /// 3. Visit every remaining filter in order, stopping at the first error
    ///    (`:779-785`). Lower filters are called LATER, deliberately, so that a
    ///    filter that cannot write may withdraw a write interest an upper filter
    ///    registered.
    ///
    /// The walk lives here and not in [`ConnFilter::adjust_pollset`], whose
    /// default is a pure no-op. See that method for the stale C comment that
    /// suggests otherwise.
    ///
    /// # Errors
    ///
    /// Whatever a filter reports while adjusting.
    #[allow(dead_code)]
    pub(crate) fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        // Positions rather than a moving borrow: phase 1 has to LOOK AHEAD at
        // the successor and then possibly not advance, which a consumed `&mut`
        // cannot express without giving the node back.
        let mut start = 0_usize;
        while let Some(node) = self.nth_ref(start) {
            let advance = !node.base().is_connected()
                && node
                    .base()
                    .next_ref()
                    .is_some_and(|next| !next.base().is_connected());
            if advance {
                start += 1;
            } else {
                break;
            }
        }

        while let Some(node) = self.nth_ref(start) {
            if node.base().has_shut_down() {
                start += 1;
            } else {
                break;
            }
        }

        let mut index = start;
        while let Some(node) = self.nth_mut(index) {
            node.adjust_pollset(cx, ps)?;
            index += 1;
        }
        Ok(())
    }

    // -- control ---------------------------------------------------------

    /// `Curl_conn_cf_cntrl` (`lib/cfilters.c:866-881`): distribute `event` down
    /// the chain, top-down.
    ///
    /// The event's own [`ControlPolicy`] decides what happens to the results:
    /// [`ControlPolicy::FirstFail`] stops at the first error and reports it,
    /// [`ControlPolicy::IgnoreResult`] visits every filter and succeeds. C takes
    /// that choice as a `bool ignore_result` ARGUMENT, so a caller can pass the
    /// wrong one; reading it from the event makes the pairing structural.
    ///
    /// # Errors
    ///
    /// For a first-fail event, whatever the first failing filter reports.
    #[allow(dead_code)]
    pub(crate) fn cntrl(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        event: CfControl,
    ) -> CurlResult<()> {
        let policy = event.policy();
        let mut index = 0_usize;
        while let Some(node) = self.nth_mut(index) {
            match (policy, node.cntrl(cx, event)) {
                (ControlPolicy::FirstFail, Err(error)) => return Err(error),
                (ControlPolicy::FirstFail, Ok(()))
                | (ControlPolicy::IgnoreResult, _) => {}
            }
            index += 1;
        }
        Ok(())
    }

    /// `Curl_conn_flush` (`lib/cfilters.c:965-971`): write out anything
    /// buffered.
    ///
    /// # Errors
    ///
    /// Whatever the first filter unable to flush reports --
    /// [`CfControl::Flush`] is a first-fail event.
    #[allow(dead_code)]
    pub(crate) fn flush(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        self.cntrl(cx, CfControl::Flush)
    }

    // -- queries ---------------------------------------------------------

    /// Asks the chain `query` and checks that the answer fits the question.
    ///
    /// The type check is what C's two `void *` out-parameters cannot do. It
    /// cannot fire for a correctly written filter, and a filter that answers the
    /// wrong question is a bug this reports rather than mis-reads.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] when no filter is installed or none
    /// understood the question -- the sentinel every caller below reads as "use
    /// the default". [`CURLcode::BadFunctionArgument`] for a mismatched answer.
    #[allow(dead_code)]
    pub(crate) fn query_typed(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        let value = match self.head_mut() {
            Some(head) => head.query(cx, query)?,
            None => return Err(Error::new(CURLcode::UnknownOption)),
        };
        if value.matches(query) {
            Ok(value)
        } else {
            Err(Error::with_context(
                CURLcode::BadFunctionArgument,
                "a filter answered a different query than it was asked",
            ))
        }
    }

    /// `Curl_conn_is_ip_connected` (`lib/cfilters.c:615-630`): have we reached
    /// the host at IP level?
    ///
    /// True before any TLS handshake has started. The walk stops at
    /// [`CF_TYPE_IP_CONNECT`] because a filter that PROVIDES the IP connection
    /// and is not itself connected means we have not reached the host, whatever
    /// lies below it.
    #[allow(dead_code)]
    pub(crate) fn is_ip_connected(&self) -> bool {
        for filter in self.iter() {
            if filter.base().is_connected() {
                return true;
            }
            if filter.cf_type().intersects(CF_TYPE_IP_CONNECT) {
                return false;
            }
        }
        false
    }

    /// `Curl_conn_is_ssl` via `cf_is_ssl` (`lib/cfilters.c:632-648`): is this
    /// chain TLS-protected, or about to be?
    ///
    /// False when TLS is used only towards a proxy and not for the tunnel
    /// itself, which the stop at [`CF_TYPE_IP_CONNECT`] achieves: the proxy's
    /// own TLS filter sits BELOW the filter providing the tunnel.
    #[allow(dead_code)]
    pub(crate) fn is_ssl(&self) -> bool {
        for filter in self.iter() {
            if filter.cf_type().intersects(CF_TYPE_SSL) {
                return true;
            }
            if filter.cf_type().intersects(CF_TYPE_IP_CONNECT) {
                return false;
            }
        }
        false
    }

    /// `Curl_conn_is_multiplex` (`lib/cfilters.c:676-691`).
    ///
    /// Stops at EITHER [`CF_TYPE_IP_CONNECT`] or [`CF_TYPE_SSL`] -- a wider
    /// boundary than [`Self::is_ssl`]'s, and the difference is real:
    /// multiplexing below a TLS filter belongs to a tunnelled connection, not to
    /// this one.
    #[allow(dead_code)]
    pub(crate) fn is_multiplex(&self) -> bool {
        let boundary = CF_TYPE_IP_CONNECT.union(CF_TYPE_SSL);
        for filter in self.iter() {
            if filter.cf_type().intersects(CF_TYPE_MULTIPLEX) {
                return true;
            }
            if filter.cf_type().intersects(boundary) {
                return false;
            }
        }
        false
    }

    /// `Curl_conn_http_version` (`lib/cfilters.c:707-729`): 10, 11, 20, 30 -- or
    /// 0 when unknown.
    ///
    /// Finds the first [`CF_TYPE_HTTP`] filter, stopping at the same boundary
    /// [`Self::is_multiplex`] uses, and asks it. A value outside `0..=255` is a
    /// failure in the C (`:719-720`) and every failure yields zero (`:728`);
    /// [`u8::try_from`] folds the range check and the conversion into one.
    #[allow(dead_code)]
    pub(crate) fn http_version(&mut self, cx: &mut CallCtx<'_, '_>) -> u8 {
        let boundary = CF_TYPE_IP_CONNECT.union(CF_TYPE_SSL);
        let mut index = 0_usize;
        let mut found = None;
        while let Some(filter) = self.nth_ref(index) {
            if filter.cf_type().intersects(CF_TYPE_HTTP) {
                found = Some(index);
                break;
            }
            if filter.cf_type().intersects(boundary) {
                break;
            }
            index += 1;
        }
        let Some(at) = found else {
            return 0;
        };
        let Some(filter) = self.nth_mut(at) else {
            return 0;
        };
        match filter.query(cx, CfQuery::HttpVersion) {
            Ok(CfQueryValue::HttpVersion(value)) => {
                u8::try_from(value).unwrap_or(0)
            }
            _ => 0,
        }
    }

    /// `Curl_conn_cf_needs_flush` (`lib/cfilters.c:751-759`): is any filter
    /// holding unsent data?
    ///
    /// False both when nothing is buffered and when nobody understood the
    /// question, which is the C's `(result || !pending) ? FALSE : TRUE`.
    #[allow(dead_code)]
    pub(crate) fn needs_flush(&mut self, cx: &mut CallCtx<'_, '_>) -> bool {
        matches!(
            self.query_typed(cx, CfQuery::NeedFlush),
            Ok(CfQueryValue::NeedFlush(true))
        )
    }

    /// `Curl_conn_cf_get_socket` (`lib/cfilters.c:883-890`).
    ///
    /// [`CURL_SOCKET_BAD`] when unavailable.
    #[allow(dead_code)]
    pub(crate) fn socket(&mut self, cx: &mut CallCtx<'_, '_>) -> Socket {
        match self.query_typed(cx, CfQuery::Socket) {
            Ok(CfQueryValue::Socket(sock)) => sock,
            _ => CURL_SOCKET_BAD,
        }
    }

    /// `Curl_conn_get_first_socket` (`lib/cfilters.c:936-949`).
    ///
    /// While the head has not connected, the chain is asked; once it has,
    /// `conn->sock[FIRSTSOCKET]` already holds the answer and is passed in as
    /// `conn_socket`.
    #[allow(dead_code)]
    pub(crate) fn first_socket(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn_socket: Socket,
    ) -> Socket {
        if self.is_setup() && !self.is_head_connected() {
            self.socket(cx)
        } else {
            conn_socket
        }
    }

    /// `Curl_conn_cf_get_transport` (`lib/cfilters.c:892-899`).
    ///
    /// `wanted` is `conn->transport_wanted`, the fallback when nobody answers.
    #[allow(dead_code)]
    pub(crate) fn transport(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        wanted: Transport,
    ) -> Transport {
        match self.query_typed(cx, CfQuery::Transport) {
            Ok(CfQueryValue::Transport(transport)) => transport,
            _ => wanted,
        }
    }

    /// `Curl_conn_cf_get_alpn_negotiated` (`lib/cfilters.c:901-910`).
    ///
    /// [`None`] until the handshake has selected something, and the C's
    /// "query ALPN" trace line is emitted first, as it is there.
    #[allow(dead_code)]
    pub(crate) fn alpn_negotiated(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Option<String> {
        let identity = self.head_ref().and_then(ConnFilter::trace_filter);
        trc!(cx, identity, self.sockindex.as_i32(), "query ALPN");
        match self.query_typed(cx, CfQuery::AlpnNegotiated) {
            Ok(CfQueryValue::AlpnNegotiated(alpn)) => alpn,
            _ => None,
        }
    }

    /// `cf_get_remote_addr` (`lib/cfilters.c:912-921`).
    #[allow(dead_code)]
    pub(crate) fn remote_addr(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Option<RemoteAddr> {
        match self.query_typed(cx, CfQuery::RemoteAddr) {
            Ok(CfQueryValue::RemoteAddr(addr)) => addr,
            _ => None,
        }
    }

    /// `Curl_conn_cf_get_ip_info` (`lib/cfilters.c:923-934`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] when no filter is installed or none answered,
    /// which is the C's initial value for `result` and what it returns for a
    /// `NULL` head.
    #[allow(dead_code)]
    pub(crate) fn ip_info(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<(bool, IpQuadruple)> {
        match self.query_typed(cx, CfQuery::IpInfo)? {
            CfQueryValue::IpInfo { is_ipv6, quad } => Ok((is_ipv6, quad)),
            // Unreachable: `query_typed` already checked the pairing.
            _ => Err(Error::new(CURLcode::UnknownOption)),
        }
    }

    /// `Curl_conn_get_ssl_info` (`lib/cfilters.c:650-663`).
    ///
    /// [`None`] when the chain is not TLS-protected at all, which the C tests
    /// FIRST -- so a chain carrying no TLS is never even asked. `kind` selects
    /// between the two queries, whose only difference is which handle they
    /// describe.
    #[allow(dead_code)]
    pub(crate) fn ssl_info(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        kind: TlsHandleKind,
    ) -> Option<TlsSessionInfo> {
        if !self.is_ssl() {
            return None;
        }
        let query = match kind {
            TlsHandleKind::Session => CfQuery::SslInfo,
            TlsHandleKind::Context => CfQuery::SslCtxInfo,
        };
        match self.query_typed(cx, query) {
            Ok(CfQueryValue::SslInfo(info)) => Some(info),
            _ => None,
        }
    }

    /// `Curl_conn_get_current_host` (`lib/cfilters.c:822-852`): the host and
    /// port being talked to RIGHT NOW.
    ///
    /// Once connected, or before connecting starts, that is the connection's own
    /// destination -- passed in as `conn_host` and `conn_port`. DURING a connect
    /// through a tunnelling proxy it is the proxy's interim host, because that is
    /// what authentication and certificate checks apply to.
    ///
    /// The interim host comes from the LOWEST not-yet-connected filter that is
    /// both [`CF_TYPE_IP_CONNECT`] and [`CF_TYPE_PROXY`] -- the conjunction, not
    /// the union, which is why [`CfType::contains`] exists separately from
    /// [`CfType::intersects`]. A non-tunnelling proxy filter such as `HAPROXY`
    /// declares only [`CF_TYPE_PROXY`] and must not match.
    ///
    /// The C's third case, `!data->conn` yielding `("", -1)` (`:827-832`), cannot
    /// occur here: a chain exists only as part of a connection, so there is no
    /// state in which the fallback has no host to fall back to.
    #[allow(dead_code)]
    pub(crate) fn current_host(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn_host: &str,
        conn_port: u16,
    ) -> (String, u16) {
        let tunnel = CF_TYPE_IP_CONNECT.union(CF_TYPE_PROXY);
        let mut proxy_at = None;
        let mut index = 0_usize;
        while let Some(filter) = self.nth_ref(index) {
            if filter.base().is_connected() {
                break;
            }
            if filter.cf_type().contains(tunnel) {
                proxy_at = Some(index);
            }
            index += 1;
        }

        if let Some(at) = proxy_at {
            if let Some(filter) = self.nth_mut(at) {
                if let Ok(CfQueryValue::HostPort { host, port }) =
                    filter.query(cx, CfQuery::HostPort)
                {
                    return (host, port);
                }
            }
        }
        (conn_host.to_owned(), conn_port)
    }

    /// `Curl_conn_get_max_concurrent` (`lib/cfilters.c:1017-1035`).
    ///
    /// One when nobody answered or the answer was negative. ZERO IS PRESERVED:
    /// a multiplexed connection draining after a `GOAWAY` reports zero, and
    /// collapsing that to one would hand it a stream it cannot carry. The C says
    /// so explicitly at `:1031-1034`.
    #[allow(dead_code)]
    pub(crate) fn max_concurrent(&mut self, cx: &mut CallCtx<'_, '_>) -> usize {
        match self.query_typed(cx, CfQuery::MaxConcurrent) {
            Ok(CfQueryValue::MaxConcurrent(n)) if n >= 0 => {
                usize::try_from(n).unwrap_or(1)
            }
            _ => 1,
        }
    }

    /// `Curl_conn_get_stream_error` (`lib/cfilters.c:1037-1052`).
    ///
    /// Zero when nobody answered or the answer was negative.
    #[allow(dead_code)]
    pub(crate) fn stream_error(&mut self, cx: &mut CallCtx<'_, '_>) -> i32 {
        match self.query_typed(cx, CfQuery::StreamError) {
            Ok(CfQueryValue::StreamError(code)) if code >= 0 => code,
            _ => 0,
        }
    }

    /// `CF_QUERY_CONNECT_REPLY_MS` (`lib/cfilters.h:142-147`).
    ///
    /// `-1` until determined, which is the documented "not yet" value rather
    /// than an error.
    #[allow(dead_code)]
    pub(crate) fn connect_reply_ms(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> TimeDiff {
        match self.query_typed(cx, CfQuery::ConnectReplyMs) {
            Ok(CfQueryValue::ConnectReplyMs(ms)) => ms,
            _ => -1,
        }
    }

    /// One of the two connect timers, or [`CurlTime::ZERO`] when unanswered.
    ///
    /// `conn_report_connect_stats` (`lib/cfilters.c:472-489`) zeroes its local
    /// before asking and then tests the two fields for non-zero, which is
    /// exactly "unanswered means zero".
    #[allow(dead_code)]
    pub(crate) fn timer(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        which: CfQuery,
    ) -> CurlTime {
        match self.query_typed(cx, which) {
            Ok(CfQueryValue::Timer(at)) => at,
            _ => CurlTime::ZERO,
        }
    }

    /// `Curl_conn_is_alive` (`lib/cfilters.c:997-1003`).
    ///
    /// `conn_wants_close` is `conn->bits.close`, and the gate is load-bearing:
    /// the connection pool asks this before reusing a connection, so a
    /// connection already marked for closing must report dead however healthy
    /// its socket is. Dropping the gate would put a connection back into the
    /// pool that the protocol layer has already decided to discard.
    #[allow(dead_code)]
    pub(crate) fn is_alive(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn_wants_close: bool,
    ) -> Liveness {
        if conn_wants_close {
            return Liveness::DEAD;
        }
        match self.head_mut() {
            Some(head) => head.is_alive(cx),
            None => Liveness::DEAD,
        }
    }

    /// `Curl_conn_keep_alive` (`lib/cfilters.c:1005-1015`).
    ///
    /// # Errors
    ///
    /// Whatever the head reports. An empty chain succeeds, as the C's
    /// `cf ? ... : CURLE_OK` does.
    #[allow(dead_code)]
    pub(crate) fn keep_alive(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<()> {
        match self.head_mut() {
            Some(head) => head.keep_alive(cx),
            None => Ok(()),
        }
    }
}

// =========================================================================
// Both chains of one connection -- `conn->cfilter[2]`
// =========================================================================

/// The pair of filter chains a connection owns.
///
/// `struct Curl_cfilter *cfilter[2]` (`lib/urldata.h:646`). Two rather than one
/// because FTP needs two: a control connection and a data connection, addressed
/// as [`SocketIndex::First`] and [`SocketIndex::Secondary`].
///
/// The pair exists as a type because four of the C's drivers operate on BOTH
/// chains and cannot be expressed on one. `cf_cntrl_all`
/// (`lib/cfilters.c:446-461`) distributes an event across the whole array, and
/// `Curl_conn_adjust_pollset` (`:788-801`) collects readiness from all of it --
/// so a transfer waiting on an FTP data connection also waits on its control
/// connection, which is the behaviour that lets an abort on the control channel
/// interrupt a transfer.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct FilterChains {
    chains: [FilterChain; SocketIndex::COUNT],
}

impl Default for FilterChains {
    fn default() -> Self {
        Self::new(None)
    }
}

impl FilterChains {
    /// A pair of empty chains for `conn`.
    ///
    /// Not derived from [`Default`]: a derive would give both chains
    /// [`SocketIndex::First`], and a filter would then report the wrong index in
    /// every trace line and every readiness registration.
    #[allow(dead_code)]
    pub(crate) fn new(conn: Option<ConnId>) -> Self {
        Self {
            chains: [
                FilterChain::new(conn, SocketIndex::First),
                FilterChain::new(conn, SocketIndex::Secondary),
            ],
        }
    }

    /// One chain, shared.
    #[allow(dead_code)]
    pub(crate) fn chain(&self, sockindex: SocketIndex) -> &FilterChain {
        &self.chains[sockindex.as_usize()]
    }

    /// One chain, mutable.
    #[allow(dead_code)]
    pub(crate) fn chain_mut(
        &mut self,
        sockindex: SocketIndex,
    ) -> &mut FilterChain {
        &mut self.chains[sockindex.as_usize()]
    }

    /// Rebinds both chains to a connection identity.
    #[allow(dead_code)]
    pub(crate) fn set_conn(&mut self, conn: Option<ConnId>) {
        for chain in &mut self.chains {
            chain.set_conn(conn);
        }
    }

    /// `Curl_conn_cf_discard_all` (`lib/cfilters.c:138-142`): destroy one
    /// chain's filters.
    #[allow(dead_code)]
    pub(crate) fn discard_all(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
    ) {
        self.chain_mut(sockindex).discard_chain(cx);
    }

    /// Destroys every filter on both chains.
    #[allow(dead_code)]
    pub(crate) fn discard_everything(&mut self, cx: &mut CallCtx<'_, '_>) {
        for sockindex in SocketIndex::ALL {
            self.discard_all(cx, sockindex);
        }
    }

    /// `cf_cntrl_all` (`lib/cfilters.c:446-461`): distribute `event` across BOTH
    /// chains.
    ///
    /// Chains are visited in `conn->cfilter[]` order and, for a first-fail
    /// event, the walk stops at the first error anywhere -- including partway
    /// through the second chain, which is what the C's `break` out of the array
    /// loop does.
    ///
    /// # Errors
    ///
    /// For a first-fail event, whatever the first failing filter reports.
    #[allow(dead_code)]
    pub(crate) fn cntrl_all(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        event: CfControl,
    ) -> CurlResult<()> {
        for sockindex in SocketIndex::ALL {
            self.chain_mut(sockindex).cntrl(cx, event)?;
        }
        Ok(())
    }

    /// `Curl_conn_ev_data_setup` (`lib/cfilters.c:960-963`).
    ///
    /// # Errors
    ///
    /// First-fail: whatever the first filter unable to prepare reports.
    #[allow(dead_code)]
    pub(crate) fn ev_data_setup(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<()> {
        self.cntrl_all(cx, CfControl::DataSetup)
    }

    /// `Curl_conn_ev_data_pause` (`lib/cfilters.c:991-995`).
    ///
    /// # Errors
    ///
    /// First-fail: whatever the first filter unable to pause reports.
    #[allow(dead_code)]
    pub(crate) fn ev_data_pause(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        do_pause: bool,
    ) -> CurlResult<()> {
        self.cntrl_all(cx, CfControl::DataPause { pause: do_pause })
    }

    /// `Curl_conn_ev_data_done` (`lib/cfilters.c:986-989`).
    ///
    /// Returns nothing, because the event's policy is ignored-result and the C's
    /// signature is `void` for the same reason.
    #[allow(dead_code)]
    pub(crate) fn ev_data_done(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        premature: bool,
    ) {
        self.ignore(cx, CfControl::DataDone { premature });
    }

    /// `Curl_conn_ev_data_done_send` (`lib/cfilters.c:977-980`).
    #[allow(dead_code)]
    pub(crate) fn ev_data_done_send(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.ignore(cx, CfControl::DataDoneSend);
    }

    /// `Curl_conn_forget_socket` (`lib/cfilters.h:468`).
    #[allow(dead_code)]
    pub(crate) fn ev_forget_socket(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.ignore(cx, CfControl::ForgetSocket);
    }

    /// `cf_cntrl_update_info` (`lib/cfilters.c:463-467`).
    #[allow(dead_code)]
    pub(crate) fn ev_conn_info_update(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.ignore(cx, CfControl::ConnInfoUpdate);
    }

    /// Distributes an ignored-result event, discarding the result the policy
    /// says to discard.
    ///
    /// A debug build still asserts the event really is ignored-result, so that a
    /// first-fail event routed through here -- which would silently swallow a
    /// failure the caller was supposed to see -- is caught at the mistake.
    #[allow(dead_code)]
    fn ignore(&mut self, cx: &mut CallCtx<'_, '_>, event: CfControl) {
        debug_assert!(
            matches!(event.policy(), ControlPolicy::IgnoreResult),
            "a first-fail event must not be distributed with its result ignored"
        );
        // Cannot fail: `FilterChain::cntrl` returns early only for a first-fail
        // event, and the assertion above is what keeps that true.
        let outcome = self.cntrl_all(cx, event);
        debug_assert!(outcome.is_ok(), "an ignored-result event cannot fail");
        drop(outcome);
    }

    /// `Curl_conn_adjust_pollset` (`lib/cfilters.c:788-801`): collect readiness
    /// from both chains into one pollset.
    ///
    /// # Errors
    ///
    /// The first error from either chain, which stops the walk -- the C's
    /// `for(i = 0; (i < 2) && !result; ++i)`.
    #[allow(dead_code)]
    pub(crate) fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        for sockindex in SocketIndex::ALL {
            self.chain_mut(sockindex).adjust_pollset(cx, ps)?;
        }
        Ok(())
    }

    /// `Curl_conn_sockindex` (`lib/cfilters.c:1054-1060`): which chain owns
    /// `sockfd`?
    ///
    /// # The fallback is deliberately lopsided, and it is C's
    ///
    /// [`SocketIndex::Secondary`] is returned ONLY for a descriptor that is
    /// valid and matches the secondary socket exactly. EVERYTHING else --
    /// including a descriptor belonging to neither chain -- comes back as
    /// [`SocketIndex::First`]. That is not a lookup, it is a two-way guess with
    /// a default, and it is reproduced rather than tightened for two reasons:
    /// the callers use it to pick which chain to send on, where the primary is
    /// the right guess; and an unknown descriptor reaching here is already a
    /// caller bug that a different answer would not fix.
    ///
    /// Contrast [`SocketIndex::from_i32`], which REFUSES an unrecognised index.
    /// The asymmetry is the point: an out-of-range index is a programming error
    /// and reported as one, while an unmatched descriptor is a question with a
    /// documented default.
    #[allow(dead_code)]
    pub(crate) fn sockindex_of(
        secondary_socket: Socket,
        sockfd: Socket,
    ) -> SocketIndex {
        if sockfd != CURL_SOCKET_BAD && sockfd == secondary_socket {
            SocketIndex::Secondary
        } else {
            SocketIndex::First
        }
    }

    /// `conn_report_connect_stats` (`lib/cfilters.c:472-489`): collect the two
    /// connect timers into `report`.
    ///
    /// A reading of zero leaves `report` alone, which is the C's field-by-field
    /// non-zero test at `:481` and `:486`: a filter that does not track a timer
    /// must not be able to reset one another filter already recorded.
    #[allow(dead_code)]
    fn report_connect_stats(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        report: &mut ConnectReport,
    ) {
        let chain = self.chain_mut(sockindex);
        let connected = chain.timer(cx, CfQuery::TimerConnect);
        if !connected.is_zero() {
            report.connected_at = connected;
        }
        let app_connected = chain.timer(cx, CfQuery::TimerAppConnect);
        if !app_connected.is_zero() {
            report.app_connected_at = app_connected;
        }
    }

    /// One non-blocking step of `Curl_conn_connect` (`lib/cfilters.c:491-548`).
    ///
    /// THE PRIMARY CONNECT API. Returns whether the chain is fully connected;
    /// `Ok(false)` means readiness has not arrived yet and the caller should
    /// await it -- through [`Self::connect`], or through its own reactor loop.
    ///
    /// The order of operations is the C's and matters:
    ///
    /// 1. No chain at all is [`CURLcode::FailedInit`] with `done` false
    ///    (`:509-512`).
    /// 2. An already connected head returns at once, with no side effects
    ///    (`:514-516`). This is what makes the call idempotent, which
    ///    `lib/cfilters.h:358` promises.
    /// 3. FLUSH FIRST (`:521-526`). Anything a filter still holds must go out
    ///    before it is asked to make progress, or a handshake can deadlock
    ///    waiting for a reply to a request that never left. [`CURLcode::Again`]
    ///    from the flush is tolerated -- it means "not all of it went, but
    ///    progress was made".
    /// 4. Connect the head.
    /// 5. On full success, persist connection information across BOTH chains,
    ///    collect the timers, and take the keepalive reading (`:531-540`). On
    ///    failure, collect the timers anyway (`:541-545`), because a failed
    ///    connect still has a connect time worth reporting.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] for a chain that is not set up, plus whatever
    /// the flush or the head's connect reports.
    #[allow(dead_code)]
    pub(crate) fn connect_step(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        report: &mut ConnectReport,
    ) -> CurlResult<bool> {
        let outcome = {
            let chain = self.chain_mut(sockindex);
            if !chain.is_setup() {
                return Err(Error::with_context(
                    CURLcode::FailedInit,
                    "connect: no filter chain installed",
                ));
            }
            if chain.is_head_connected() {
                return Ok(true);
            }
            if chain.needs_flush(cx) {
                match chain.flush(cx) {
                    Ok(()) => {}
                    Err(error) if error.code() == CURLcode::Again => {}
                    Err(error) => return Err(error),
                }
            }
            let identity = chain.head_ref().and_then(ConnFilter::trace_filter);
            let outcome = chain.connect_head(cx);
            let progress = match &outcome {
                Ok(done) => i32::from(*done),
                Err(_) => 0,
            };
            trc!(
                cx,
                identity,
                sockindex.as_i32(),
                "connect() -> done={}",
                progress
            );
            outcome
        };

        match outcome {
            Ok(true) => {
                // "Now that the complete filter chain is connected, let all
                // filters persist information at the connection" (`:532-534`).
                self.ev_conn_info_update(cx);
                self.report_connect_stats(cx, sockindex, report);
                report.keepalive = cx.now();
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(error) => {
                self.report_connect_stats(cx, sockindex, report);
                Err(error)
            }
        }
    }

    /// The blocking form of `Curl_conn_connect` (`lib/cfilters.c:491-592`), as
    /// an async loop.
    ///
    /// A COMPATIBILITY WRAPPER over [`Self::connect_step`], for the callers that
    /// genuinely want to wait -- FTP's second connection and `CURLOPT_CONNECT_ONLY`
    /// among them. Where the C calls `Curl_poll` directly, this awaits the
    /// reactor through [`crate::conn::select`]; nothing here touches `poll` or
    /// `select`, and `conn/` is where that boundary belongs.
    ///
    /// Each iteration mirrors `:547-585`:
    ///
    /// * The remaining time is recomputed from the INJECTED CLOCK rather than
    ///   read from the host, which is what makes this testable.
    /// * A write interest is registered on the chain's socket first, because
    ///   "in general, we want to send after connect" (`:565-567`), and the
    ///   filters then adjust it -- so a handshake waiting to READ can withdraw
    ///   the write interest the line above added.
    /// * The wait is bounded by `CURLMIN(timeout_ms, cpfds.n ? 1000 : 10)`
    ///   (`:577`), so a filter making progress without any socket readiness --
    ///   one draining an internal buffer -- is still polled promptly.
    ///
    /// # `timeout_ms` of zero
    ///
    /// Zero means NO LIMIT, which is what `Curl_timeleft_ms` reports when no
    /// timeout is configured (`lib/connect.c:122`). The C then computes
    /// `CURLMIN(0, 1000) == 0` and polls without blocking, spinning; that is
    /// unreachable in practice, because a connect always has
    /// `DEFAULT_CONNECT_TIMEOUT` in play (`lib/connect.c:113-119`). Here the
    /// no-limit case waits on the ceiling instead of spinning -- the same
    /// semantics without the busy loop.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OperationTimedout`] once the budget is spent (`:555-559`),
    /// [`CURLcode::CouldntConnect`] if the wait itself fails (`:580-582`), plus
    /// anything [`Self::connect_step`] reports.
    ///
    /// # Panics
    ///
    /// Requires a `tokio` runtime with the time driver, as every wait in
    /// [`crate::conn::select`] does.
    #[allow(dead_code)]
    pub(crate) async fn connect(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        timeout_ms: TimeDiff,
        report: &mut ConnectReport,
    ) -> CurlResult<()> {
        if timeout_ms < 0 {
            return Err(Error::with_context(
                CURLcode::OperationTimedout,
                "connect timeout",
            ));
        }
        let started = cx.now();

        // Both are owned locals, so every early return below -- including the
        // error paths -- releases them. That is the RAII guarantee this loop
        // needs and the reason no explicit cleanup appears anywhere in it: the C
        // reaches its `Curl_pollset_cleanup` through a `goto out` that one early
        // `return result` at `:525` bypasses outright.
        let mut ps = EasyPollset::new();
        let mut pfds = PollFds::new();

        loop {
            if self.connect_step(cx, sockindex, report)? {
                return Ok(());
            }

            let remaining = if timeout_ms == 0 {
                None
            } else {
                let elapsed = cx.now().checked_sub(started).map_or(0, tvtoms);
                let left = timeout_ms - elapsed;
                if left < 0 {
                    return Err(Error::with_context(
                        CURLcode::OperationTimedout,
                        "connect timeout",
                    ));
                }
                Some(left)
            };

            ps.reset();
            pfds.reset();
            let sock = self.chain_mut(sockindex).socket(cx);
            if is_valid_sock(sock) {
                ps.set_out_only(sock, cx.tracer_mut())
                    .map_err(Error::from)?;
            }
            self.adjust_pollset(cx, &mut ps)?;
            pfds.add_ps(&ps);

            let ceiling: TimeDiff = if pfds.is_empty() { 10 } else { 1000 };
            let wait = remaining.map_or(ceiling, |left| left.min(ceiling));
            if pfds.poll(wait).await.is_err() {
                return Err(Error::with_context(
                    CURLcode::CouldntConnect,
                    "failed waiting for the connection to make progress",
                ));
            }
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{TraceConfig, TraceLevel, WriterSink};
    use crate::util::timeval::TestClock;
    use std::cell::RefCell;
    use std::net::{IpAddr, Ipv4Addr};
    use std::rc::Rc;

    /// An ordered record of what happened, shared by every filter in a test.
    ///
    /// Not a convenience: a filter installed in a chain is owned as
    /// `Pin<Box<dyn ConnFilter>>`, and there is no way back to its concrete type
    /// -- deliberately, since recovering the concrete type is exactly what this
    /// module exists to abolish. A shared log is therefore the ONLY way a test
    /// can observe what a linked filter did, and it is fully typed.
    type EventLog = Rc<RefCell<Vec<String>>>;

    fn new_log() -> EventLog {
        Rc::new(RefCell::new(Vec::new()))
    }

    fn events(log: &EventLog) -> Vec<String> {
        log.borrow().clone()
    }

    // -- the test-only in-memory transport -------------------------------

    /// Everything the in-memory transport can be told to do, and everything it
    /// records having done.
    ///
    /// Shared with the test rather than owned outright, for the reason
    /// [`EventLog`] gives. A production filter owns its state as a plain field;
    /// the sharing here is what replaces the C tests' habit of reaching into
    /// `cf->ctx`.
    #[derive(Debug)]
    struct TransportState {
        /// Bytes the transport will hand upward, consumed from the front.
        input: Vec<u8>,
        /// Bytes the transport captured on the way down.
        output: Vec<u8>,
        /// Whether a read would succeed.
        readable: bool,
        /// Whether a write would succeed.
        writable: bool,
        /// How many more [`ConnFilter::connect`] calls before it reports done.
        connect_steps: usize,
        /// How many more [`ConnFilter::shutdown`] calls before it reports done.
        shutdown_steps: usize,
        /// What [`ConnFilter::is_alive`] reports.
        alive: bool,
        /// The `input_pending` half of that answer.
        input_pending: bool,
        /// What `CF_QUERY_SOCKET` reports.
        socket: Socket,
        /// When set, every control event fails with this code.
        fail_control: Option<CURLcode>,
        /// The answers this transport is prepared to give.
        answers: Vec<(CfQuery, CfQueryValue)>,
        /// Every control event received, in order.
        controls: Vec<CfControl>,
        /// Every query received, in order.
        queries: Vec<CfQuery>,
        /// The `eos` flag of every send received, in order.
        eos_seen: Vec<bool>,
        /// Call counters.
        sends: usize,
        recvs: usize,
        connects: usize,
        shutdowns: usize,
        closes: usize,
        pollsets: usize,
    }

    impl Default for TransportState {
        fn default() -> Self {
            Self {
                input: Vec::new(),
                output: Vec::new(),
                readable: true,
                writable: true,
                connect_steps: 0,
                shutdown_steps: 0,
                alive: true,
                input_pending: false,
                socket: CURL_SOCKET_BAD,
                fail_control: None,
                answers: Vec::new(),
                controls: Vec::new(),
                queries: Vec::new(),
                eos_seen: Vec::new(),
                sends: 0,
                recvs: 0,
                connects: 0,
                shutdowns: 0,
                closes: 0,
                pollsets: 0,
            }
        }
    }

    /// A handle on a transport's state that outlives the chain owning it.
    type TransportHandle = Rc<RefCell<TransportState>>;

    /// A bottom-of-chain transport over two byte buffers.
    ///
    /// The most important unit-test seam in the crate: with this at the bottom,
    /// every layer above -- TLS, the proxies, HTTP/2, HTTP/3, the transfer loop
    /// -- can be assembled and driven with no socket, no name resolution and no
    /// TLS library, which is what puts the mandated coverage of the protocol and
    /// transfer modules within reach.
    ///
    /// Note the shape: `state` is a CONCRETE TYPED FIELD beside [`FilterBase`],
    /// which is precisely the arrangement that replaces C's `void *ctx`.
    #[derive(Debug)]
    struct InMemory {
        base: FilterBase,
        state: TransportHandle,
        name: &'static str,
        flags: CfType,
        log: EventLog,
    }

    impl InMemory {
        fn new(name: &'static str, log: &EventLog) -> (Self, TransportHandle) {
            let state: TransportHandle =
                Rc::new(RefCell::new(TransportState::default()));
            let filter = Self {
                base: FilterBase::new(SocketIndex::First),
                state: Rc::clone(&state),
                name,
                flags: CF_TYPE_IP_CONNECT,
                log: Rc::clone(log),
            };
            (filter, state)
        }

        fn with_flags(mut self, flags: CfType) -> Self {
            self.flags = flags;
            self
        }

        fn note(&self, what: &str) {
            self.log.borrow_mut().push(format!("{}:{what}", self.name));
        }
    }

    impl ConnFilter for InMemory {
        fn trace_name(&self) -> &'static str {
            self.name
        }

        fn cf_type(&self) -> CfType {
            self.flags
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn destroy(&mut self, _cx: &mut CallCtx<'_, '_>) {
            self.note("destroy");
        }

        fn connect(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            let mut state = self.state.borrow_mut();
            state.connects += 1;
            if state.connect_steps > 0 {
                state.connect_steps -= 1;
            }
            let done = state.connect_steps == 0;
            drop(state);
            self.base.set_connected(done);
            Ok(done)
        }

        fn close(&mut self, _cx: &mut CallCtx<'_, '_>) {
            self.state.borrow_mut().closes += 1;
            self.base.set_connected(false);
            self.note("close");
        }

        fn shutdown(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            let mut state = self.state.borrow_mut();
            state.shutdowns += 1;
            if state.shutdown_steps > 0 {
                state.shutdown_steps -= 1;
            }
            Ok(state.shutdown_steps == 0)
        }

        fn adjust_pollset(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            ps: &mut EasyPollset,
        ) -> CurlResult<()> {
            let (sock, readable, writable) = {
                let mut state = self.state.borrow_mut();
                state.pollsets += 1;
                (state.socket, state.readable, state.writable)
            };
            self.note("pollset");
            if !is_valid_sock(sock) {
                return Ok(());
            }
            ps.set(sock, readable, writable, cx.tracer_mut())
                .map_err(Error::from)
        }

        fn data_pending(&mut self, _cx: &CallCtx<'_, '_>) -> bool {
            let state = self.state.borrow();
            state.readable && !state.input.is_empty()
        }

        fn send(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            buf: &[u8],
            eos: bool,
        ) -> CurlResult<usize> {
            let mut state = self.state.borrow_mut();
            state.sends += 1;
            state.eos_seen.push(eos);
            if !state.writable {
                return Err(Error::new(CURLcode::Again));
            }
            state.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn recv(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            buf: &mut [u8],
        ) -> CurlResult<usize> {
            let mut state = self.state.borrow_mut();
            state.recvs += 1;
            if !state.readable {
                return Err(Error::new(CURLcode::Again));
            }
            let take = buf.len().min(state.input.len());
            buf[..take].copy_from_slice(&state.input[..take]);
            state.input.drain(..take);
            Ok(take)
        }

        fn cntrl(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            event: CfControl,
        ) -> CurlResult<()> {
            let mut state = self.state.borrow_mut();
            state.controls.push(event);
            match state.fail_control {
                Some(code) => Err(Error::new(code)),
                None => Ok(()),
            }
        }

        fn is_alive(&mut self, _cx: &mut CallCtx<'_, '_>) -> Liveness {
            let state = self.state.borrow();
            if state.alive {
                Liveness::alive(state.input_pending)
            } else {
                Liveness::DEAD
            }
        }

        fn keep_alive(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
            self.note("keep_alive");
            Ok(())
        }

        fn query(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            query: CfQuery,
        ) -> CurlResult<CfQueryValue> {
            let prepared = {
                let mut state = self.state.borrow_mut();
                state.queries.push(query);
                if matches!(query, CfQuery::Socket) {
                    Some(CfQueryValue::Socket(state.socket))
                } else {
                    state
                        .answers
                        .iter()
                        .find(|(asked, _)| *asked == query)
                        .map(|(_, value)| value.clone())
                }
            };
            match prepared {
                Some(value) => Ok(value),
                // Everything unprepared falls through to the default, which is
                // what a real filter does for a question it does not know.
                None => match self.base_mut().next_mut() {
                    Some(next) => next.query(cx, query),
                    None => Err(Error::new(CURLcode::UnknownOption)),
                },
            }
        }
    }

    // -- a filter that takes every default it can --------------------------

    /// A filter implementing ONLY the two methods that have no default.
    ///
    /// Its whole purpose is to leave the other ten alone, so that a chain built
    /// out of these exercises the default bodies rather than an override --
    /// which is how the defaults get tested at all.
    #[derive(Debug)]
    struct Plain {
        base: FilterBase,
        name: &'static str,
        flags: CfType,
        log: EventLog,
    }

    impl Plain {
        fn new(name: &'static str, log: &EventLog) -> Self {
            Self {
                base: FilterBase::new(SocketIndex::First),
                name,
                flags: CfType::NONE,
                log: Rc::clone(log),
            }
        }

        fn with_flags(mut self, flags: CfType) -> Self {
            self.flags = flags;
            self
        }
    }

    impl ConnFilter for Plain {
        fn trace_name(&self) -> &'static str {
            self.name
        }

        fn cf_type(&self) -> CfType {
            self.flags
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn connect(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            self.base.set_connected(true);
            Ok(true)
        }

        fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
            self.log.borrow_mut().push(format!("{}:close", self.name));
            chain_close(self, cx);
        }
    }

    /// A filter that re-enters the chain from inside one of its own calls.
    ///
    /// The successor of what `struct cf_call_data` and the
    /// `CF_DATA_SAVE`/`CF_DATA_RESTORE` pair exist for (`lib/cfilters.h:620-685`,
    /// issue #10336). Here the nesting needs no saved state at all, because the
    /// context is a parameter: it is simply in scope at both depths.
    #[derive(Debug)]
    struct Reentrant {
        base: FilterBase,
        log: EventLog,
    }

    impl ConnFilter for Reentrant {
        fn trace_name(&self) -> &'static str {
            "REENTRANT"
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn connect(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            self.base.set_connected(true);
            Ok(true)
        }

        fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
            chain_close(self, cx);
        }

        fn send(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            buf: &[u8],
            eos: bool,
        ) -> CurlResult<usize> {
            // Depth 1: ask the layer below a question, using the same context.
            let pending = match self.base_mut().next_mut() {
                Some(next) => next.data_pending(cx),
                None => false,
            };
            self.log
                .borrow_mut()
                .push(format!("reentrant:pending={pending}"));
            // Depth 2: and now the actual send, still through the same context.
            let sent = match self.base_mut().next_mut() {
                Some(next) => next.send(cx, buf, eos)?,
                None => 0,
            };
            self.log.borrow_mut().push(format!("reentrant:sent={sent}"));
            Ok(sent)
        }
    }

    // -- the injected shutdown timer -------------------------------------

    #[derive(Debug, Default)]
    struct TestTimer {
        started: [bool; SocketIndex::COUNT],
        timeout_ms: [TimeDiff; SocketIndex::COUNT],
        left_ms: [TimeDiff; SocketIndex::COUNT],
        cleared: usize,
        starts: usize,
    }

    impl ShutdownTimer for TestTimer {
        fn started(&self, sockindex: SocketIndex) -> bool {
            self.started[sockindex.as_usize()]
        }

        fn start(&mut self, sockindex: SocketIndex, timeout_ms: TimeDiff) {
            self.starts += 1;
            self.started[sockindex.as_usize()] = true;
            self.timeout_ms[sockindex.as_usize()] = if timeout_ms == 0 {
                DEFAULT_SHUTDOWN_TIMEOUT_MS
            } else {
                timeout_ms
            };
            self.left_ms[sockindex.as_usize()] =
                self.timeout_ms[sockindex.as_usize()];
        }

        fn time_left_ms(&self, sockindex: SocketIndex) -> TimeDiff {
            self.left_ms[sockindex.as_usize()]
        }

        fn clear(&mut self, sockindex: SocketIndex) {
            self.cleared += 1;
            self.started[sockindex.as_usize()] = false;
            self.left_ms[sockindex.as_usize()] = 0;
        }
    }

    // -- helpers ----------------------------------------------------------

    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    /// A chain of `Plain` filters, top first, all marked connected.
    fn plain_chain(
        cx: &mut CallCtx<'_, '_>,
        log: &EventLog,
        names: &[&'static str],
    ) -> FilterChain {
        let mut chain =
            FilterChain::new(Some(ConnId::new(7)), SocketIndex::First);
        for name in names.iter().rev() {
            chain.add(cx, link(Plain::new(name, log)));
        }
        let mut index = 0_usize;
        while let Some(node) = chain.nth_mut(index) {
            node.base_mut().set_connected(true);
            index += 1;
        }
        chain
    }

    fn names(chain: &FilterChain) -> Vec<&'static str> {
        chain.iter().map(ConnFilter::trace_name).collect()
    }

    // -- 1. prepend order -------------------------------------------------

    /// `Curl_conn_cf_add` inserts at the TOP (`lib/cfilters.c:329-343`), so the
    /// last filter added is the first one bytes meet.
    #[test]
    fn add_installs_each_filter_at_the_top_of_the_chain() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(3)), SocketIndex::Secondary);

        chain.add(&mut cx, link(Plain::new("BOTTOM", &log)));
        chain.add(&mut cx, link(Plain::new("MIDDLE", &log)));
        chain.add(&mut cx, link(Plain::new("TOP", &log)));

        assert_eq!(names(&chain), ["TOP", "MIDDLE", "BOTTOM"]);
        assert_eq!(chain.len(), 3);
        assert!(chain.is_setup());
        assert!(!chain.is_empty());

        // Every node carries the chain's identity and index (`:339-340`).
        for filter in chain.iter() {
            assert_eq!(filter.base().conn(), Some(ConnId::new(3)));
            assert_eq!(filter.sockindex(), SocketIndex::Secondary);
            assert!(filter.base().is_attached());
        }
    }

    // -- 2. inserting a single filter after a node -------------------------

    #[test]
    fn insert_after_places_a_filter_below_the_named_position() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain = plain_chain(&mut cx, &log, &["A", "B", "C"]);

        chain
            .insert_after(&mut cx, 1, link(Plain::new("NEW", &log)))
            .expect("position 1 exists");
        assert_eq!(names(&chain), ["A", "B", "NEW", "C"]);

        // Inserting after the tail leaves the new filter as the tail.
        chain
            .insert_after(&mut cx, 3, link(Plain::new("TAIL", &log)))
            .expect("position 3 exists");
        assert_eq!(names(&chain), ["A", "B", "NEW", "C", "TAIL"]);

        // A position past the end is a caller error, not a silent append.
        let error = chain
            .insert_after(&mut cx, 99, link(Plain::new("NOPE", &log)))
            .expect_err("position 99 does not exist");
        assert_eq!(error.code(), CURLcode::BadFunctionArgument);
        assert_eq!(names(&chain), ["A", "B", "NEW", "C", "TAIL"]);
    }

    // -- 3. inserting a whole subchain ------------------------------------

    /// `Curl_conn_cf_insert_after` stamps EVERY node of the inserted value
    /// (`lib/cfilters.c:356-361`), not just its head, and reattaches the old
    /// successor to its tail.
    #[test]
    fn insert_after_stamps_every_node_of_an_inserted_subchain() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain = plain_chain(&mut cx, &log, &["A", "B"]);

        // Build a three-filter subchain by hand, unattached and with no
        // identity: exactly the shape the setup filter hands over.
        let mut sub = link(Plain::new("S1", &log));
        let mut second = link(Plain::new("S2", &log));
        second
            .as_mut()
            .get_mut()
            .base_mut()
            .set_next(Some(link(Plain::new("S3", &log))));
        sub.as_mut().get_mut().base_mut().set_next(Some(second));
        assert!(!sub.base().is_attached());

        chain.insert_after(&mut cx, 0, sub).expect("A exists");

        assert_eq!(names(&chain), ["A", "S1", "S2", "S3", "B"]);
        for filter in chain.iter() {
            assert_eq!(
                filter.base().conn(),
                Some(ConnId::new(7)),
                "{} kept a stale identity",
                filter.trace_name()
            );
            assert_eq!(filter.sockindex(), SocketIndex::First);
        }
    }

    /// The same stamping, onto the SECONDARY chain, so that a node cannot pick
    /// up the primary index by default.
    #[test]
    fn insert_after_stamps_the_secondary_socket_index() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(11)), SocketIndex::Secondary);
        chain.add(&mut cx, link(Plain::new("HEAD", &log)));

        let mut sub = link(Plain::new("S1", &log));
        sub.as_mut()
            .get_mut()
            .base_mut()
            .set_next(Some(link(Plain::new("S2", &log))));
        chain.insert_after(&mut cx, 0, sub).expect("HEAD exists");

        assert_eq!(names(&chain), ["HEAD", "S1", "S2"]);
        for filter in chain.iter() {
            assert_eq!(filter.sockindex(), SocketIndex::Secondary);
            assert_eq!(filter.base().conn(), Some(ConnId::new(11)));
        }
    }

    // -- 4. discard unlinks correctly -------------------------------------

    #[test]
    fn discard_at_removes_exactly_one_filter_and_hoists_its_successor() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain = plain_chain(&mut cx, &log, &["A", "B", "C"]);
        let (transport, _state) = InMemory::new("T", &log);
        chain
            .insert_after(&mut cx, 2, link(transport))
            .expect("C exists");
        assert_eq!(names(&chain), ["A", "B", "C", "T"]);

        assert!(chain.discard_at(&mut cx, 1), "B was linked");
        assert_eq!(names(&chain), ["A", "C", "T"]);
        // Only B went; the transport below it is untouched.
        assert!(events(&log).is_empty());

        assert!(chain.discard_at(&mut cx, 0), "the head was linked");
        assert_eq!(names(&chain), ["C", "T"]);

        assert!(!chain.discard_at(&mut cx, 9), "position 9 is not linked");
        assert_eq!(names(&chain), ["C", "T"]);

        // The transport is the tail; discarding it destroys it and nothing else.
        assert!(chain.discard_at(&mut cx, 1), "the tail was linked");
        assert_eq!(names(&chain), ["C"]);
        assert_eq!(events(&log), ["T:destroy"]);
    }

    /// The unlinked half of `Curl_conn_cf_discard` (`lib/cfilters.c:365-387`):
    /// reports `false` and destroys the node together with its subchain.
    #[test]
    fn discard_unlinked_reports_not_found_and_destroys_the_subchain() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();

        let (lower, _lower_state) = InMemory::new("LOWER", &log);
        let (upper, _upper_state) = InMemory::new("UPPER", &log);
        let mut held = link(upper);
        held.as_mut()
            .get_mut()
            .base_mut()
            .set_next(Some(link(lower)));

        assert!(
            !discard_unlinked(&mut cx, held),
            "an owned link cannot have been part of a chain"
        );
        assert_eq!(events(&log), ["UPPER:destroy", "LOWER:destroy"]);
    }

    // -- 5. discard-chain severs before destroying ------------------------

    /// `Curl_conn_cf_discard_chain` (`lib/cfilters.c:118-136`) clears the head
    /// first, then walks FRONT TO BACK, severing each link before its destructor
    /// can see it.
    #[test]
    fn discard_chain_destroys_front_to_back_after_severing() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(1)), SocketIndex::First);
        for name in ["THIRD", "SECOND", "FIRST"] {
            let (transport, _state) = InMemory::new(name, &log);
            chain.add(&mut cx, link(transport));
        }
        assert_eq!(names(&chain), ["FIRST", "SECOND", "THIRD"]);

        chain.discard_chain(&mut cx);

        // Front to back -- the OPPOSITE of `util::llist`'s tail-first order.
        assert_eq!(
            events(&log),
            ["FIRST:destroy", "SECOND:destroy", "THIRD:destroy"]
        );
        // The head was cleared before any destructor ran (`:124`).
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    /// The severing itself: a destructor that looks down finds nothing, because
    /// `cf->next` was taken away before it was called (`:127-130`).
    #[test]
    fn discard_chain_severs_each_link_before_calling_its_destructor() {
        /// A filter whose destructor reports whether it can still see below it.
        #[derive(Debug)]
        struct Looker {
            base: FilterBase,
            log: EventLog,
        }

        impl ConnFilter for Looker {
            fn trace_name(&self) -> &'static str {
                "LOOKER"
            }
            fn base(&self) -> &FilterBase {
                &self.base
            }
            fn base_mut(&mut self) -> &mut FilterBase {
                &mut self.base
            }
            fn connect(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
            ) -> CurlResult<bool> {
                Ok(true)
            }
            fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
                chain_close(self, cx);
            }
            fn destroy(&mut self, _cx: &mut CallCtx<'_, '_>) {
                let sees = self.base.has_next();
                self.log
                    .borrow_mut()
                    .push(format!("looker:sees_next={sees}"));
            }
        }

        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(2)), SocketIndex::First);
        let (transport, _state) = InMemory::new("T", &log);
        chain.add(&mut cx, link(transport));
        chain.add(
            &mut cx,
            link(Looker {
                base: FilterBase::new(SocketIndex::First),
                log: Rc::clone(&log),
            }),
        );

        chain.discard_chain(&mut cx);
        assert_eq!(events(&log), ["looker:sees_next=false", "T:destroy"]);
    }

    // -- 6. default destroy is a no-op and does not chain ------------------

    #[test]
    fn the_default_destroy_does_nothing_and_does_not_chain() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain = plain_chain(&mut cx, &log, &["PLAIN"]);
        let (transport, _state) = InMemory::new("T", &log);
        chain
            .insert_after(&mut cx, 0, link(transport))
            .expect("PLAIN exists");

        // `Plain` takes the default `destroy`.
        chain
            .head_mut()
            .expect("a head is installed")
            .destroy(&mut cx);

        assert!(
            events(&log).is_empty(),
            "the default destroy reached the filter below it"
        );
        // And the chain is intact: a no-op destroy unlinks nothing.
        assert_eq!(names(&chain), ["PLAIN", "T"]);
    }

    // -- 7. default shutdown succeeds and does not chain -------------------

    #[test]
    fn the_default_shutdown_reports_done_and_does_not_chain() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain = plain_chain(&mut cx, &log, &["PLAIN"]);
        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().shutdown_steps = 3;
        chain
            .insert_after(&mut cx, 0, link(transport))
            .expect("PLAIN exists");

        let done = chain
            .head_mut()
            .expect("a head is installed")
            .shutdown(&mut cx)
            .expect("the default shutdown cannot fail");

        assert!(done, "the default reports done immediately");
        assert_eq!(
            state.borrow().shutdowns,
            0,
            "the default shutdown reached the filter below it"
        );
    }

    // -- 8. default adjust_pollset is a pure no-op -------------------------

    /// `Curl_cf_def_adjust_pollset` (`lib/cfilters.c:55-64`) is a literal
    /// `/* NOP */`. The stale prose at `lib/cfilters.h:64-67` would have it pass
    /// through; it does not.
    #[test]
    fn the_default_adjust_pollset_is_a_pure_no_op() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain = plain_chain(&mut cx, &log, &["PLAIN"]);
        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().socket = 4;
        chain
            .insert_after(&mut cx, 0, link(transport))
            .expect("PLAIN exists");

        let mut ps = EasyPollset::new();
        chain
            .head_mut()
            .expect("a head is installed")
            .adjust_pollset(&mut cx, &mut ps)
            .expect("the default cannot fail");

        assert!(ps.is_empty(), "the default touched the pollset");
        assert_eq!(
            state.borrow().pollsets,
            0,
            "the default delegated to the filter below it"
        );
    }

    // -- 9. default data_pending chains, bottoming at false ---------------

    #[test]
    fn the_default_data_pending_chains_and_bottoms_at_false() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();

        // All defaults, nothing below: false.
        let mut bare = plain_chain(&mut cx, &log, &["A", "B"]);
        assert!(!bare.data_pending(&mut cx));

        // With a transport holding bytes, the answer travels back up.
        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().input = b"hello".to_vec();
        bare.insert_after(&mut cx, 1, link(transport))
            .expect("B exists");
        bare.nth_mut(2)
            .expect("the transport is installed")
            .base_mut()
            .set_connected(true);
        assert!(bare.data_pending(&mut cx));

        // Drained, and the answer changes back.
        state.borrow_mut().input.clear();
        assert!(!bare.data_pending(&mut cx));
    }

    // -- 10. default send chains, bottoming at zero and RecvError ---------

    /// The swapped terminal code, transcribed from `lib/cfilters.c:73-81`.
    #[test]
    fn the_default_send_chains_and_bottoms_at_recv_error() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();

        let mut bare = plain_chain(&mut cx, &log, &["A", "B"]);
        let error = bare
            .send(&mut cx, b"payload", false)
            .expect_err("nothing below B can accept bytes");
        assert_eq!(
            error.code(),
            CURLcode::RecvError,
            "the default send must report RECV error, however odd that reads"
        );

        // Nothing moved: the C writes `*pnwritten = 0` on the same path.
        let (transport, state) = InMemory::new("T", &log);
        bare.insert_after(&mut cx, 1, link(transport))
            .expect("B exists");
        assert!(state.borrow().output.is_empty());

        let sent = bare
            .send(&mut cx, b"payload", true)
            .expect("the transport accepts bytes");
        assert_eq!(sent, 7);
        assert_eq!(state.borrow().output, b"payload");
        assert_eq!(state.borrow().eos_seen, [true]);
    }

    // -- 11. default recv chains, bottoming at zero and SendError ---------

    #[test]
    fn the_default_recv_chains_and_bottoms_at_send_error() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();

        let mut bare = plain_chain(&mut cx, &log, &["A", "B"]);
        let mut buf = [0_u8; 8];
        let error = bare
            .recv(&mut cx, &mut buf)
            .expect_err("nothing below B can produce bytes");
        assert_eq!(
            error.code(),
            CURLcode::SendError,
            "the default recv must report SEND error, however odd that reads"
        );
        assert_eq!(buf, [0; 8], "nothing was written into the buffer");

        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().input = b"abcd".to_vec();
        bare.insert_after(&mut cx, 1, link(transport))
            .expect("B exists");
        let read = bare.recv(&mut cx, &mut buf).expect("bytes are available");
        assert_eq!(read, 4);
        assert_eq!(&buf[..4], b"abcd");
        assert!(state.borrow().input.is_empty());
    }

    // -- 12. default control and the two distribution policies ------------

    #[test]
    fn the_default_control_is_a_no_op_and_does_not_chain() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain = plain_chain(&mut cx, &log, &["PLAIN"]);
        let (transport, state) = InMemory::new("T", &log);
        chain
            .insert_after(&mut cx, 0, link(transport))
            .expect("PLAIN exists");

        chain
            .head_mut()
            .expect("a head is installed")
            .cntrl(&mut cx, CfControl::DataSetup)
            .expect("the default cannot fail");
        assert!(
            state.borrow().controls.is_empty(),
            "the default control reached the filter below it"
        );

        // The DRIVER is what visits every filter.
        chain
            .cntrl(&mut cx, CfControl::DataSetup)
            .expect("nothing objects");
        assert_eq!(state.borrow().controls, [CfControl::DataSetup]);
    }

    /// First-fail stops at the first error; ignored-result visits everything and
    /// succeeds (`lib/cfilters.h:109-127`, `lib/cfilters.c:873-880`).
    #[test]
    fn the_control_driver_applies_first_fail_and_ignored_result() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(5)), SocketIndex::First);

        let (lower, lower_state) = InMemory::new("LOWER", &log);
        let (upper, upper_state) = InMemory::new("UPPER", &log);
        chain.add(&mut cx, link(lower));
        chain.add(&mut cx, link(upper));
        upper_state.borrow_mut().fail_control = Some(CURLcode::Again);

        // Flush is first-fail: UPPER fails, LOWER is never asked.
        let error = chain
            .flush(&mut cx)
            .expect_err("the upper filter refuses every event");
        assert_eq!(error.code(), CURLcode::Again);
        assert_eq!(upper_state.borrow().controls, [CfControl::Flush]);
        assert!(lower_state.borrow().controls.is_empty());

        // Data-done is ignored-result: both are visited, the failure discarded.
        chain
            .cntrl(&mut cx, CfControl::DataDone { premature: true })
            .expect(
                "an ignored-result event succeeds however its filters answer",
            );
        assert_eq!(
            upper_state.borrow().controls,
            [CfControl::Flush, CfControl::DataDone { premature: true }]
        );
        assert_eq!(
            lower_state.borrow().controls,
            [CfControl::DataDone { premature: true }]
        );
    }

    // -- 13. alive, keep-alive and query defaults -------------------------

    #[test]
    fn the_alive_keep_alive_and_query_defaults_bottom_out_correctly() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut bare = plain_chain(&mut cx, &log, &["A", "B"]);

        // Pessimistic in the absence of data (`lib/cfilters.c:92-99`).
        assert_eq!(bare.is_alive(&mut cx, false), Liveness::DEAD);
        // Keep-alive succeeds at the bottom (`:101-107`).
        bare.keep_alive(&mut cx).expect("the default succeeds");
        // And an unanswered query is the UnknownOption sentinel (`:109-116`).
        let error = bare
            .query_typed(&mut cx, CfQuery::MaxConcurrent)
            .expect_err("nothing answers");
        assert_eq!(error.code(), CURLcode::UnknownOption);

        // An empty chain answers the same way.
        let mut empty =
            FilterChain::new(Some(ConnId::new(1)), SocketIndex::First);
        assert_eq!(empty.is_alive(&mut cx, false), Liveness::DEAD);
        empty.keep_alive(&mut cx).expect("an empty chain succeeds");
        assert_eq!(
            empty
                .query_typed(&mut cx, CfQuery::Socket)
                .expect_err("nothing answers")
                .code(),
            CURLcode::UnknownOption
        );

        // With a transport, the answer travels up -- and `conn->bits.close`
        // overrides it however healthy the transport is (`:1001`).
        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().input_pending = true;
        bare.insert_after(&mut cx, 1, link(transport))
            .expect("B exists");
        assert_eq!(bare.is_alive(&mut cx, false), Liveness::alive(true));
        assert_eq!(
            bare.is_alive(&mut cx, true),
            Liveness::DEAD,
            "bits.close must veto a live connection"
        );
        state.borrow_mut().alive = false;
        assert_eq!(bare.is_alive(&mut cx, false), Liveness::DEAD);

        bare.keep_alive(&mut cx).expect("the transport succeeds");
        assert_eq!(
            events(&log),
            ["T:keep_alive"],
            "the two earlier calls had no transport to reach"
        );
    }

    // -- 14. connected and shutdown state transitions ---------------------

    #[test]
    fn the_two_instance_flags_transition_independently() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(9)), SocketIndex::First);
        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().connect_steps = 2;
        chain.add(&mut cx, link(transport));

        let head = chain.head_ref().expect("a head is installed");
        assert!(!head.base().is_connected());
        assert!(!head.base().has_shut_down());

        // Two steps to connect, and only the second sets the flag.
        assert!(!chain.connect_head(&mut cx).expect("step one"));
        assert!(!chain.is_head_connected());
        assert!(chain.connect_head(&mut cx).expect("step two"));
        assert!(chain.is_head_connected());
        assert_eq!(state.borrow().connects, 2);

        // Closing clears `connected` and leaves `shutdown` alone.
        let mut timer = TestTimer::default();
        chain.close_and_clear(&mut cx, &mut timer);
        assert!(!chain.is_head_connected());
        assert_eq!(timer.cleared, 1);
        assert_eq!(state.borrow().closes, 1);
        assert!(!chain
            .head_ref()
            .expect("still installed")
            .base()
            .has_shut_down());

        // A chain that is not set up is connected only for a no-network scheme.
        let bare = FilterChain::new(None, SocketIndex::First);
        assert!(!bare.is_connected(false));
        assert!(bare.is_connected(true));
    }

    /// The shutdown driver, step for step (`lib/cfilters.c:157-210`).
    #[test]
    fn shutdown_walks_one_filter_at_a_time_and_honours_the_deadline() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut timer = TestTimer::default();

        // Nothing connected: done at once, and the timer is never started.
        let mut chain = plain_chain(&mut cx, &log, &["A"]);
        chain
            .nth_mut(0)
            .expect("A is installed")
            .base_mut()
            .set_connected(false);
        assert!(chain
            .shutdown(&mut cx, &mut timer)
            .expect("nothing to shut down"));
        assert_eq!(timer.starts, 0);

        // Two transports, the upper needing two passes.
        let mut chain =
            FilterChain::new(Some(ConnId::new(4)), SocketIndex::First);
        let (lower, lower_state) = InMemory::new("LOWER", &log);
        let (upper, upper_state) = InMemory::new("UPPER", &log);
        upper_state.borrow_mut().shutdown_steps = 2;
        chain.add(&mut cx, link(lower));
        chain.add(&mut cx, link(upper));
        let mut index = 0_usize;
        while let Some(node) = chain.nth_mut(index) {
            node.base_mut().set_connected(true);
            index += 1;
        }

        assert!(
            !chain
                .shutdown(&mut cx, &mut timer)
                .expect("the first pass makes progress"),
            "an unfinished filter reports success with done false"
        );
        assert_eq!(timer.starts, 1, "the timer starts on the first pass");
        assert_eq!(upper_state.borrow().shutdowns, 1);
        assert_eq!(lower_state.borrow().shutdowns, 0, "one filter per pass");
        assert!(!chain
            .nth_ref(0)
            .expect("UPPER installed")
            .base()
            .has_shut_down());

        assert!(chain
            .shutdown(&mut cx, &mut timer)
            .expect("the second pass finishes both"));
        assert!(chain
            .nth_ref(0)
            .expect("UPPER installed")
            .base()
            .has_shut_down());
        assert!(chain
            .nth_ref(1)
            .expect("LOWER installed")
            .base()
            .has_shut_down());

        // Already shut down: nothing left to do.
        assert!(chain
            .shutdown(&mut cx, &mut timer)
            .expect("everything has shut down"));
    }

    /// A negative remaining time is [`CURLcode::OperationTimedout`]
    /// (`lib/cfilters.c:184-188`).
    #[test]
    fn shutdown_reports_a_timeout_once_the_deadline_has_passed() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(6)), SocketIndex::First);
        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().shutdown_steps = 5;
        chain.add(&mut cx, link(transport));
        chain
            .nth_mut(0)
            .expect("installed")
            .base_mut()
            .set_connected(true);

        let mut timer = TestTimer::default();
        assert!(!chain.shutdown(&mut cx, &mut timer).expect("first pass"));
        assert_eq!(
            timer.timeout_ms[0], DEFAULT_SHUTDOWN_TIMEOUT_MS,
            "a zero timeout asks the timer for its default"
        );

        timer.left_ms[0] = -1;
        let error = chain
            .shutdown(&mut cx, &mut timer)
            .expect_err("the deadline has passed");
        assert_eq!(error.code(), CURLcode::OperationTimedout);
        assert_eq!(error.message(), "shutdown timeout");
    }

    /// A filter that fails aborts the whole shutdown (`:195-198`).
    #[test]
    fn shutdown_aborts_on_the_first_filter_that_fails() {
        /// A filter whose graceful shutdown always fails.
        #[derive(Debug)]
        struct Refuser {
            base: FilterBase,
        }

        impl ConnFilter for Refuser {
            fn trace_name(&self) -> &'static str {
                "REFUSER"
            }
            fn base(&self) -> &FilterBase {
                &self.base
            }
            fn base_mut(&mut self) -> &mut FilterBase {
                &mut self.base
            }
            fn connect(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
            ) -> CurlResult<bool> {
                Ok(true)
            }
            fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
                chain_close(self, cx);
            }
            fn shutdown(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
            ) -> CurlResult<bool> {
                Err(Error::new(CURLcode::RecvError))
            }
        }

        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(8)), SocketIndex::First);
        let (lower, lower_state) = InMemory::new("LOWER", &log);
        chain.add(&mut cx, link(lower));
        chain.add(
            &mut cx,
            link(Refuser {
                base: FilterBase::new(SocketIndex::First),
            }),
        );
        let mut index = 0_usize;
        while let Some(node) = chain.nth_mut(index) {
            node.base_mut().set_connected(true);
            index += 1;
        }

        let mut timer = TestTimer::default();
        let error = chain
            .shutdown(&mut cx, &mut timer)
            .expect_err("the refuser fails");
        assert_eq!(error.code(), CURLcode::RecvError);
        assert_eq!(lower_state.borrow().shutdowns, 0, "the walk stopped");
    }

    // -- 15. each CF_TYPE query and its stop boundary ----------------------

    /// The five capability searches and the three different boundaries they
    /// stop at (`lib/cfilters.c:615-691`, `:707-729`).
    #[test]
    fn the_capability_searches_stop_at_the_boundaries_the_c_uses() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();

        // An empty chain has no capability at all.
        let empty = FilterChain::new(None, SocketIndex::First);
        assert!(!empty.is_ip_connected());
        assert!(!empty.is_ssl());
        assert!(!empty.is_multiplex());

        // HTTP over TLS over a socket: TLS is visible, and so is multiplexing
        // because the HTTP filter sits ABOVE the TLS one.
        let mut chain =
            FilterChain::new(Some(ConnId::new(1)), SocketIndex::First);
        chain.add(
            &mut cx,
            link(Plain::new("SOCKET", &log).with_flags(CF_TYPE_IP_CONNECT)),
        );
        chain.add(
            &mut cx,
            link(Plain::new("TLS", &log).with_flags(CF_TYPE_SSL)),
        );
        chain.add(
            &mut cx,
            link(
                Plain::new("H2", &log)
                    .with_flags(CF_TYPE_MULTIPLEX.union(CF_TYPE_HTTP)),
            ),
        );
        assert!(chain.is_ssl());
        assert!(chain.is_multiplex());
        assert!(!chain.is_ip_connected(), "nothing has connected yet");

        // SSL stops at IP_CONNECT: a TLS filter BELOW the tunnel provider
        // secures the proxy hop, not this connection (`:632-641`).
        let mut proxied =
            FilterChain::new(Some(ConnId::new(2)), SocketIndex::First);
        proxied.add(
            &mut cx,
            link(
                Plain::new("PROXY-TLS", &log)
                    .with_flags(CF_TYPE_SSL.union(CF_TYPE_PROXY)),
            ),
        );
        proxied.add(
            &mut cx,
            link(
                Plain::new("TUNNEL", &log)
                    .with_flags(CF_TYPE_IP_CONNECT.union(CF_TYPE_PROXY)),
            ),
        );
        assert!(
            !proxied.is_ssl(),
            "TLS below the tunnel provider is the proxy's, not ours"
        );

        // Multiplex stops at IP_CONNECT *or* SSL -- a wider boundary.
        let mut hidden =
            FilterChain::new(Some(ConnId::new(3)), SocketIndex::First);
        hidden.add(
            &mut cx,
            link(Plain::new("H2-BELOW", &log).with_flags(CF_TYPE_MULTIPLEX)),
        );
        hidden.add(
            &mut cx,
            link(Plain::new("TLS", &log).with_flags(CF_TYPE_SSL)),
        );
        assert!(hidden.is_ssl());
        assert!(
            !hidden.is_multiplex(),
            "multiplexing below TLS belongs to a tunnelled connection"
        );

        // IP-connected turns true as soon as a filter above the IP provider is
        // connected, and false while the provider itself is not (`:615-630`).
        let mut racing =
            FilterChain::new(Some(ConnId::new(4)), SocketIndex::First);
        racing.add(
            &mut cx,
            link(Plain::new("SOCKET", &log).with_flags(CF_TYPE_IP_CONNECT)),
        );
        racing.add(
            &mut cx,
            link(Plain::new("TLS", &log).with_flags(CF_TYPE_SSL)),
        );
        assert!(!racing.is_ip_connected());
        racing
            .nth_mut(1)
            .expect("SOCKET installed")
            .base_mut()
            .set_connected(true);
        assert!(racing.is_ip_connected());

        // HTTP version: found above the boundary, ignored below it.
        let mut versioned =
            FilterChain::new(Some(ConnId::new(5)), SocketIndex::First);
        let (transport, state) = InMemory::new("H2", &log);
        state
            .borrow_mut()
            .answers
            .push((CfQuery::HttpVersion, CfQueryValue::HttpVersion(20)));
        versioned.add(
            &mut cx,
            link(transport.with_flags(CF_TYPE_HTTP.union(CF_TYPE_MULTIPLEX))),
        );
        assert_eq!(versioned.http_version(&mut cx), 20);

        versioned.add(
            &mut cx,
            link(Plain::new("TLS", &log).with_flags(CF_TYPE_SSL)),
        );
        assert_eq!(
            versioned.http_version(&mut cx),
            0,
            "the search stops at the TLS filter above the HTTP one"
        );

        // A version outside 0..=255 is a failure, and every failure is zero.
        let mut bogus =
            FilterChain::new(Some(ConnId::new(6)), SocketIndex::First);
        let (odd, odd_state) = InMemory::new("ODD", &log);
        odd_state
            .borrow_mut()
            .answers
            .push((CfQuery::HttpVersion, CfQueryValue::HttpVersion(1_000)));
        bogus.add(&mut cx, link(odd.with_flags(CF_TYPE_HTTP)));
        assert_eq!(bogus.http_version(&mut cx), 0);
    }

    /// The flags newtype itself: the two membership tests are genuinely
    /// different, which is what `Curl_conn_get_current_host` depends on.
    #[test]
    fn the_filter_type_flags_hold_the_c_bit_values() {
        assert_eq!(CF_TYPE_IP_CONNECT.bits(), 1);
        assert_eq!(CF_TYPE_SSL.bits(), 2);
        assert_eq!(CF_TYPE_MULTIPLEX.bits(), 4);
        assert_eq!(CF_TYPE_PROXY.bits(), 8);
        assert_eq!(CF_TYPE_HTTP.bits(), 16);
        assert!(CfType::NONE.is_empty());
        assert_eq!(CfType::ALL.len(), 5);

        let tunnel = CF_TYPE_IP_CONNECT | CF_TYPE_PROXY;
        assert_eq!(tunnel.bits(), 9);
        assert!(tunnel.intersects(CF_TYPE_PROXY));
        assert!(tunnel.contains(CF_TYPE_PROXY));
        assert!(tunnel.contains(tunnel));

        // A plain proxy INTERSECTS the tunnel mask but does not CONTAIN it, and
        // that distinction is why `HAPROXY` must not answer CF_QUERY_HOST_PORT.
        assert!(CF_TYPE_PROXY.intersects(tunnel));
        assert!(!CF_TYPE_PROXY.contains(tunnel));

        assert_eq!(CfType::from_bits(9), tunnel);
        assert_eq!(format!("{:?}", CfType::NONE), "CfType(NONE)");
        assert_eq!(format!("{tunnel:?}"), "CfType(IP_CONNECT|PROXY)");
        // An unknown bit is rendered rather than silently dropped.
        assert_eq!(
            format!("{:?}", CfType::from_bits(0x21)),
            "CfType(IP_CONNECT|0x20)"
        );
    }

    // -- 16. the checked socket-index conversion ---------------------------

    #[test]
    fn the_socket_index_conversion_refuses_anything_out_of_range() {
        assert_eq!(FIRSTSOCKET, 0);
        assert_eq!(SECONDARYSOCKET, 1);
        assert_eq!(SocketIndex::First.as_i32(), 0);
        assert_eq!(SocketIndex::Secondary.as_i32(), 1);
        assert_eq!(SocketIndex::First.as_usize(), 0);
        assert_eq!(SocketIndex::Secondary.as_usize(), 1);
        assert_eq!(SocketIndex::default(), SocketIndex::First);
        assert_eq!(SocketIndex::COUNT, 2);
        assert_eq!(
            SocketIndex::ALL,
            [SocketIndex::First, SocketIndex::Secondary]
        );

        // `CONN_SOCK_IDX_VALID` (`lib/urldata.h:648`).
        assert!(SocketIndex::is_valid(0));
        assert!(SocketIndex::is_valid(1));
        assert!(!SocketIndex::is_valid(2));
        assert!(!SocketIndex::is_valid(-1));

        assert_eq!(SocketIndex::from_i32(0), Ok(SocketIndex::First));
        assert_eq!(SocketIndex::from_i32(1), Ok(SocketIndex::Secondary));
        for bad in [-1, 2, 7, i32::MIN, i32::MAX] {
            assert_eq!(
                SocketIndex::from_i32(bad),
                Err(CURLcode::BadFunctionArgument),
                "{bad} must not resolve to a chain"
            );
        }
    }

    /// The TLS tri-state, whose `DEFAULT` must never collapse into a `bool`
    /// without the scheme's own answer (`lib/cfilters.h:351-353`).
    #[test]
    fn the_tls_mode_tri_state_keeps_its_three_values() {
        assert_eq!(CURL_CF_SSL_DEFAULT, -1);
        assert_eq!(CURL_CF_SSL_DISABLE, 0);
        assert_eq!(CURL_CF_SSL_ENABLE, 1);
        assert_eq!(CfSslMode::Default.as_i32(), -1);
        assert_eq!(CfSslMode::Disable.as_i32(), 0);
        assert_eq!(CfSslMode::Enable.as_i32(), 1);
        assert_eq!(CfSslMode::default(), CfSslMode::Default);

        assert_eq!(CfSslMode::from_i32(-1), Ok(CfSslMode::Default));
        assert_eq!(CfSslMode::from_i32(0), Ok(CfSslMode::Disable));
        assert_eq!(CfSslMode::from_i32(1), Ok(CfSslMode::Enable));
        assert_eq!(
            CfSslMode::from_i32(2),
            Err(CURLcode::BadFunctionArgument),
            "a value the C would have treated as `enable` is refused"
        );

        assert!(CfSslMode::Default.resolve(true));
        assert!(!CfSslMode::Default.resolve(false));
        assert!(!CfSslMode::Disable.resolve(true));
        assert!(CfSslMode::Enable.resolve(false));
    }

    /// The trace-level constants and the transport enumeration, both of which
    /// have non-obvious values.
    #[test]
    fn the_trace_level_and_transport_constants_match_the_c() {
        assert_eq!(CURL_LOG_LVL_NONE, 0);
        assert_eq!(CURL_LOG_LVL_INFO, 1);

        // `TRNSPRT_*` starts at 3: 1 and 2 were retired (`lib/urldata.h:567`).
        assert_eq!(Transport::None.as_u8(), 0);
        assert_eq!(Transport::Tcp.as_u8(), 3);
        assert_eq!(Transport::Udp.as_u8(), 4);
        assert_eq!(Transport::Quic.as_u8(), 5);
        assert_eq!(Transport::Unix.as_u8(), 6);
        assert_eq!(Transport::default(), Transport::None);

        assert_eq!(Transport::from_u8(3), Some(Transport::Tcp));
        assert_eq!(Transport::from_u8(1), None, "1 is retired, not TCP");
        assert_eq!(Transport::from_u8(2), None, "2 is retired");
        assert_eq!(Transport::from_u8(7), None);
    }

    // -- 17. every control identifier, including the reserved 5 -------------

    #[test]
    fn every_control_identifier_matches_the_c_and_five_stays_reserved() {
        assert_eq!(CF_CTRL_DATA_SETUP, 4);
        assert_eq!(CF_CTRL_UNUSED_5, 5);
        assert_eq!(CF_CTRL_DATA_PAUSE, 6);
        assert_eq!(CF_CTRL_DATA_DONE, 7);
        assert_eq!(CF_CTRL_DATA_DONE_SEND, 8);
        assert_eq!(CF_CTRL_CONN_INFO_UPDATE, 256);
        assert_eq!(CF_CTRL_FORGET_SOCKET, 257);
        assert_eq!(CF_CTRL_FLUSH, 258);

        assert_eq!(CfControl::ALL.len(), 7);
        let expected = [
            (CfControl::DataSetup, 4, 0, ControlPolicy::FirstFail),
            (
                CfControl::DataPause { pause: false },
                6,
                0,
                ControlPolicy::FirstFail,
            ),
            (
                CfControl::DataDone { premature: false },
                7,
                0,
                ControlPolicy::IgnoreResult,
            ),
            (CfControl::DataDoneSend, 8, 0, ControlPolicy::IgnoreResult),
            (
                CfControl::ConnInfoUpdate,
                256,
                0,
                ControlPolicy::IgnoreResult,
            ),
            (CfControl::ForgetSocket, 257, 0, ControlPolicy::IgnoreResult),
            (CfControl::Flush, 258, 0, ControlPolicy::FirstFail),
        ];
        for (event, id, arg1, policy) in expected {
            assert_eq!(event.event_id(), id, "{event:?} has the wrong id");
            assert_eq!(event.arg1(), arg1, "{event:?} has the wrong arg1");
            assert_eq!(
                event.policy(),
                policy,
                "{event:?} has the wrong policy"
            );
            assert_eq!(
                CfControl::from_event_id(id, arg1),
                Some(event),
                "{event:?} does not round-trip"
            );
        }

        // The two events carrying a flag put it in `arg1`, as the C does.
        assert_eq!(CfControl::DataPause { pause: true }.arg1(), 1);
        assert_eq!(CfControl::DataDone { premature: true }.arg1(), 1);
        assert_eq!(
            CfControl::from_event_id(CF_CTRL_DATA_PAUSE, 1),
            Some(CfControl::DataPause { pause: true })
        );
        assert_eq!(
            CfControl::from_event_id(CF_CTRL_DATA_DONE, 1),
            Some(CfControl::DataDone { premature: true })
        );

        // Five is refused BY NAME. A retired identifier in a numbered protocol
        // is not a free slot (`lib/cfilters.h:120`).
        assert_eq!(CfControl::from_event_id(CF_CTRL_UNUSED_5, 0), None);
        for unassigned in [0, 1, 2, 3, 9, 255, 259, -1] {
            assert_eq!(
                CfControl::from_event_id(unassigned, 0),
                None,
                "{unassigned} must not resolve to an event"
            );
        }
    }

    /// The two whole-connection distribution helpers, over both chains
    /// (`lib/cfilters.c:446-461`, `:960-995`).
    #[test]
    fn the_event_helpers_reach_both_chains_of_a_connection() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chains = FilterChains::new(Some(ConnId::new(12)));

        let (primary, primary_state) = InMemory::new("PRIMARY", &log);
        let (secondary, secondary_state) = InMemory::new("SECONDARY", &log);
        chains
            .chain_mut(SocketIndex::First)
            .add(&mut cx, link(primary));
        chains
            .chain_mut(SocketIndex::Secondary)
            .add(&mut cx, link(secondary));

        chains.ev_data_setup(&mut cx).expect("nothing objects");
        chains
            .ev_data_pause(&mut cx, true)
            .expect("nothing objects");
        chains.ev_data_done(&mut cx, false);
        chains.ev_data_done_send(&mut cx);
        chains.ev_forget_socket(&mut cx);
        chains.ev_conn_info_update(&mut cx);

        let expected = [
            CfControl::DataSetup,
            CfControl::DataPause { pause: true },
            CfControl::DataDone { premature: false },
            CfControl::DataDoneSend,
            CfControl::ForgetSocket,
            CfControl::ConnInfoUpdate,
        ];
        assert_eq!(primary_state.borrow().controls, expected);
        assert_eq!(secondary_state.borrow().controls, expected);

        // The secondary chain really is index 1 everywhere.
        assert_eq!(
            chains.chain(SocketIndex::Secondary).sockindex(),
            SocketIndex::Secondary
        );
        assert_eq!(
            chains
                .chain(SocketIndex::Secondary)
                .head_ref()
                .expect("installed")
                .sockindex(),
            SocketIndex::Secondary
        );

        // A first-fail event stops partway through the second chain.
        secondary_state.borrow_mut().fail_control = Some(CURLcode::RecvError);
        let error = chains
            .cntrl_all(&mut cx, CfControl::Flush)
            .expect_err("the secondary chain refuses");
        assert_eq!(error.code(), CURLcode::RecvError);
    }

    /// `FilterChains::sockindex_of` (`lib/cfilters.c:1054-1060`): the lopsided
    /// fallback, preserved.
    #[test]
    fn sockindex_of_answers_secondary_only_on_an_exact_match() {
        assert_eq!(
            FilterChains::sockindex_of(9, 9),
            SocketIndex::Secondary,
            "an exact match is the only route to the secondary chain"
        );
        assert_eq!(
            FilterChains::sockindex_of(9, 4),
            SocketIndex::First,
            "an unknown descriptor falls back to the primary chain"
        );
        assert_eq!(
            FilterChains::sockindex_of(CURL_SOCKET_BAD, CURL_SOCKET_BAD),
            SocketIndex::First,
            "a bad descriptor must not match a bad secondary socket"
        );
        assert_eq!(
            FilterChains::sockindex_of(9, CURL_SOCKET_BAD),
            SocketIndex::First
        );
    }

    // -- 18. all fifteen typed query variants ------------------------------

    #[test]
    fn every_query_identifier_matches_the_c() {
        assert_eq!(CF_QUERY_MAX_CONCURRENT, 1);
        assert_eq!(CF_QUERY_CONNECT_REPLY_MS, 2);
        assert_eq!(CF_QUERY_SOCKET, 3);
        assert_eq!(CF_QUERY_TIMER_CONNECT, 4);
        assert_eq!(CF_QUERY_TIMER_APPCONNECT, 5);
        assert_eq!(CF_QUERY_STREAM_ERROR, 6);
        assert_eq!(CF_QUERY_NEED_FLUSH, 7);
        assert_eq!(CF_QUERY_IP_INFO, 8);
        assert_eq!(CF_QUERY_HTTP_VERSION, 9);
        assert_eq!(CF_QUERY_REMOTE_ADDR, 10);
        assert_eq!(CF_QUERY_HOST_PORT, 11);
        assert_eq!(CF_QUERY_SSL_INFO, 12);
        assert_eq!(CF_QUERY_SSL_CTX_INFO, 13);
        assert_eq!(CF_QUERY_TRANSPORT, 14);
        assert_eq!(CF_QUERY_ALPN_NEGOTIATED, 15);

        assert_eq!(CfQuery::ALL.len(), 15);
        for (position, query) in CfQuery::ALL.iter().enumerate() {
            let id = i32::try_from(position + 1).expect("fifteen fits");
            assert_eq!(query.query_id(), id, "{query:?} has the wrong id");
            assert_eq!(
                CfQuery::from_query_id(id),
                Some(*query),
                "{query:?} does not round-trip"
            );
        }
        for unassigned in [0, 16, 99, -1] {
            assert_eq!(CfQuery::from_query_id(unassigned), None);
        }
    }

    /// Every query answered by a real filter, through the chain, with the type
    /// pairing checked -- which is what C's two `void *` out-parameters cannot
    /// do.
    #[test]
    fn every_query_variant_travels_through_the_chain_typed() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(15)), SocketIndex::First);
        let (transport, state) = InMemory::new("T", &log);

        let quad = IpQuadruple {
            remote_ip: "203.0.113.7".to_owned(),
            local_ip: "198.51.100.4".to_owned(),
            remote_port: 443,
            local_port: 51_000,
            transport: Transport::Tcp,
        };
        let peer = RemoteAddr::Inet(std::net::SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            443,
        ));
        let session = TlsSessionInfo {
            backend: TlsBackendId::RUSTLS,
            kind: TlsHandleKind::Session,
            distinguishes_context: false,
        };
        let at = CurlTime::new(1_234, 5_000);

        {
            let mut prepared = state.borrow_mut();
            prepared.socket = 12;
            prepared.answers.extend([
                (CfQuery::MaxConcurrent, CfQueryValue::MaxConcurrent(100)),
                (CfQuery::ConnectReplyMs, CfQueryValue::ConnectReplyMs(42)),
                (CfQuery::TimerConnect, CfQueryValue::Timer(at)),
                (CfQuery::TimerAppConnect, CfQueryValue::Timer(at)),
                (CfQuery::StreamError, CfQueryValue::StreamError(7)),
                (CfQuery::NeedFlush, CfQueryValue::NeedFlush(true)),
                (
                    CfQuery::IpInfo,
                    CfQueryValue::IpInfo {
                        is_ipv6: false,
                        quad: quad.clone(),
                    },
                ),
                (CfQuery::HttpVersion, CfQueryValue::HttpVersion(11)),
                (
                    CfQuery::RemoteAddr,
                    CfQueryValue::RemoteAddr(Some(peer.clone())),
                ),
                (
                    CfQuery::HostPort,
                    CfQueryValue::HostPort {
                        host: "proxy.example".to_owned(),
                        port: 8080,
                    },
                ),
                (CfQuery::SslInfo, CfQueryValue::SslInfo(session)),
                (CfQuery::SslCtxInfo, CfQueryValue::SslInfo(session)),
                (CfQuery::Transport, CfQueryValue::Transport(Transport::Quic)),
                (
                    CfQuery::AlpnNegotiated,
                    CfQueryValue::AlpnNegotiated(Some("h2".to_owned())),
                ),
            ]);
        }
        chain.add(&mut cx, link(transport.with_flags(CF_TYPE_SSL)));

        assert_eq!(chain.max_concurrent(&mut cx), 100);
        assert_eq!(chain.connect_reply_ms(&mut cx), 42);
        assert_eq!(chain.socket(&mut cx), 12);
        assert_eq!(chain.timer(&mut cx, CfQuery::TimerConnect), at);
        assert_eq!(chain.timer(&mut cx, CfQuery::TimerAppConnect), at);
        assert_eq!(chain.stream_error(&mut cx), 7);
        assert!(chain.needs_flush(&mut cx));
        assert_eq!(chain.ip_info(&mut cx).expect("answered"), (false, quad));
        assert_eq!(
            chain
                .query_typed(&mut cx, CfQuery::HttpVersion)
                .expect("the transport answers"),
            CfQueryValue::HttpVersion(11)
        );
        assert_eq!(
            chain.http_version(&mut cx),
            0,
            "the ACCESSOR finds no HTTP filter, so it never asks"
        );
        assert_eq!(chain.remote_addr(&mut cx), Some(peer));
        assert_eq!(
            chain
                .query_typed(&mut cx, CfQuery::HostPort)
                .expect("the transport answers"),
            CfQueryValue::HostPort {
                host: "proxy.example".to_owned(),
                port: 8080,
            }
        );
        assert_eq!(
            chain.current_host(&mut cx, "origin.example", 443),
            ("origin.example".to_owned(), 443),
            "the ACCESSOR asks only a TUNNELLING proxy, which this is not"
        );
        assert_eq!(
            chain.ssl_info(&mut cx, TlsHandleKind::Session),
            Some(session)
        );
        assert_eq!(
            chain.ssl_info(&mut cx, TlsHandleKind::Context),
            Some(session)
        );
        assert_eq!(
            chain.transport(&mut cx, Transport::Tcp),
            Transport::Quic,
            "the filter's answer beats the connection's wish"
        );
        assert_eq!(chain.alpn_negotiated(&mut cx), Some("h2".to_owned()));

        // Every one of the fifteen really was asked.
        let asked = state.borrow().queries.clone();
        for query in CfQuery::ALL {
            assert!(asked.contains(&query), "{query:?} was never asked");
        }
    }

    /// The pairing check itself: a filter answering the wrong question is
    /// reported rather than mis-read.
    #[test]
    fn a_mismatched_query_answer_is_reported() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(16)), SocketIndex::First);
        let (transport, state) = InMemory::new("LIAR", &log);
        state
            .borrow_mut()
            .answers
            .push((CfQuery::NeedFlush, CfQueryValue::HttpVersion(11)));
        chain.add(&mut cx, link(transport));

        let error = chain
            .query_typed(&mut cx, CfQuery::NeedFlush)
            .expect_err("the answer does not fit the question");
        assert_eq!(error.code(), CURLcode::BadFunctionArgument);

        // And the two variants that legitimately serve two questions do fit
        // both, so the check cannot reject a correct filter.
        let at = CurlTime::new(5, 0);
        assert!(CfQueryValue::Timer(at).matches(CfQuery::TimerConnect));
        assert!(CfQueryValue::Timer(at).matches(CfQuery::TimerAppConnect));
        assert!(!CfQueryValue::Timer(at).matches(CfQuery::Socket));
        assert_eq!(CfQueryValue::Timer(at).answers(), None);

        let session = TlsSessionInfo {
            backend: TlsBackendId::RUSTLS,
            kind: TlsHandleKind::Context,
            distinguishes_context: true,
        };
        assert!(CfQueryValue::SslInfo(session).matches(CfQuery::SslInfo));
        assert!(CfQueryValue::SslInfo(session).matches(CfQuery::SslCtxInfo));
        assert_eq!(CfQueryValue::SslInfo(session).answers(), None);
        assert_eq!(CfQueryValue::Socket(3).answers(), Some(CfQuery::Socket));

        // The public backend identifiers are the pinned ABI values.
        assert_eq!(TlsBackendId::RUSTLS.as_i32(), 14);
        assert_eq!(TlsBackendId::NONE.as_i32(), 0);
    }

    /// The fallbacks every query accessor applies when NOBODY answers
    /// (`lib/cfilters.c:751-1052`).
    #[test]
    fn every_query_accessor_falls_back_the_way_the_c_does() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut bare = plain_chain(&mut cx, &log, &["A"]);

        assert_eq!(bare.max_concurrent(&mut cx), 1, "unanswered means one");
        assert_eq!(
            bare.connect_reply_ms(&mut cx),
            -1,
            "-1 means not yet known"
        );
        assert_eq!(bare.socket(&mut cx), CURL_SOCKET_BAD);
        assert_eq!(bare.timer(&mut cx, CfQuery::TimerConnect), CurlTime::ZERO);
        assert_eq!(bare.stream_error(&mut cx), 0);
        assert!(!bare.needs_flush(&mut cx));
        assert_eq!(
            bare.ip_info(&mut cx).expect_err("nothing answers").code(),
            CURLcode::UnknownOption
        );
        assert_eq!(bare.http_version(&mut cx), 0);
        assert_eq!(bare.remote_addr(&mut cx), None);
        assert_eq!(
            bare.transport(&mut cx, Transport::Udp),
            Transport::Udp,
            "the connection's wish is the fallback"
        );
        assert_eq!(bare.alpn_negotiated(&mut cx), None);
        assert_eq!(
            bare.ssl_info(&mut cx, TlsHandleKind::Session),
            None,
            "a chain carrying no TLS is never even asked"
        );
        assert_eq!(
            bare.current_host(&mut cx, "origin.example", 8443),
            ("origin.example".to_owned(), 8443)
        );

        // The first socket: asked while the head has not connected, taken from
        // the connection once it has (`lib/cfilters.c:936-949`).
        assert_eq!(bare.first_socket(&mut cx, 17), 17, "the head is connected");
        bare.nth_mut(0)
            .expect("A installed")
            .base_mut()
            .set_connected(false);
        assert_eq!(
            bare.first_socket(&mut cx, 17),
            CURL_SOCKET_BAD,
            "an unconnected head is asked, and answers nothing"
        );
        let empty = FilterChain::new(None, SocketIndex::First);
        assert!(empty.is_empty());
        let mut empty = empty;
        assert_eq!(empty.first_socket(&mut cx, 21), 21);
    }

    /// `Curl_conn_get_current_host` (`lib/cfilters.c:822-852`): during a connect
    /// through a tunnelling proxy, the interim host wins.
    #[test]
    fn current_host_prefers_the_lowest_unconnected_tunnelling_proxy() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(17)), SocketIndex::First);

        let (proxy, proxy_state) = InMemory::new("HTTP-PROXY", &log);
        proxy_state.borrow_mut().answers.push((
            CfQuery::HostPort,
            CfQueryValue::HostPort {
                host: "proxy.example".to_owned(),
                port: 3128,
            },
        ));
        chain.add(
            &mut cx,
            link(proxy.with_flags(CF_TYPE_IP_CONNECT.union(CF_TYPE_PROXY))),
        );
        // A non-tunnelling proxy ABOVE it, which must not be chosen.
        chain.add(
            &mut cx,
            link(Plain::new("HAPROXY", &log).with_flags(CF_TYPE_PROXY)),
        );

        assert_eq!(
            chain.current_host(&mut cx, "origin.example", 443),
            ("proxy.example".to_owned(), 3128)
        );

        // Once the top filter has connected, the walk stops before reaching the
        // proxy and the connection's own destination is the answer.
        chain
            .nth_mut(0)
            .expect("HAPROXY installed")
            .base_mut()
            .set_connected(true);
        assert_eq!(
            chain.current_host(&mut cx, "origin.example", 443),
            ("origin.example".to_owned(), 443)
        );
    }

    // -- 19. max-concurrent preserves a legitimate zero --------------------

    /// Zero means "draining after a GOAWAY", not "no answer"
    /// (`lib/cfilters.c:1031-1034`).
    #[test]
    fn max_concurrent_preserves_a_legitimate_zero() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(18)), SocketIndex::First);
        let (transport, state) = InMemory::new("H2", &log);
        state
            .borrow_mut()
            .answers
            .push((CfQuery::MaxConcurrent, CfQueryValue::MaxConcurrent(0)));
        chain.add(&mut cx, link(transport));

        assert_eq!(
            chain.max_concurrent(&mut cx),
            0,
            "a draining multiplexed connection accepts no new stream"
        );

        // A NEGATIVE answer is "no answer", and becomes the default of one.
        state.borrow_mut().answers.clear();
        state
            .borrow_mut()
            .answers
            .push((CfQuery::MaxConcurrent, CfQueryValue::MaxConcurrent(-1)));
        assert_eq!(chain.max_concurrent(&mut cx), 1);

        // And so is a negative stream error (`:1051`).
        state.borrow_mut().answers.clear();
        state
            .borrow_mut()
            .answers
            .push((CfQuery::StreamError, CfQueryValue::StreamError(-5)));
        assert_eq!(chain.stream_error(&mut cx), 0);
    }

    // -- 20. the pollset driver's two skip phases --------------------------

    /// `Curl_conn_cf_adjust_pollset` (`lib/cfilters.c:768-786`): advance to the
    /// lowest not-connected filter whose successor is also not connected, skip
    /// the shut-down prefix, then visit the rest in order.
    #[test]
    fn the_pollset_driver_skips_the_prefixes_the_c_skips() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(19)), SocketIndex::First);

        // BOTTOM connected, the two above it not: the C's first loop stops at
        // MIDDLE, because MIDDLE's successor HAS connected.
        let (bottom, _bottom_state) = InMemory::new("BOTTOM", &log);
        let (middle, _middle_state) = InMemory::new("MIDDLE", &log);
        let (top, _top_state) = InMemory::new("TOP", &log);
        chain.add(&mut cx, link(bottom));
        chain.add(&mut cx, link(middle));
        chain.add(&mut cx, link(top));
        chain
            .nth_mut(2)
            .expect("BOTTOM installed")
            .base_mut()
            .set_connected(true);

        let mut ps = EasyPollset::new();
        chain
            .adjust_pollset(&mut cx, &mut ps)
            .expect("no filter objects");
        assert_eq!(
            events(&log),
            ["MIDDLE:pollset", "BOTTOM:pollset"],
            "TOP is above the lowest unconnected pair and is skipped"
        );

        // Nothing connected at all: the first loop walks to the TAIL, because
        // every successor is also unconnected.
        let log2 = new_log();
        let mut idle =
            FilterChain::new(Some(ConnId::new(20)), SocketIndex::First);
        for name in ["C", "B", "A"] {
            let (transport, _state) = InMemory::new(name, &log2);
            idle.add(&mut cx, link(transport));
        }
        assert_eq!(names(&idle), ["A", "B", "C"]);
        idle.adjust_pollset(&mut cx, &mut ps)
            .expect("no filter objects");
        assert_eq!(events(&log2), ["C:pollset"]);

        // Everything connected: the first loop does not advance at all, so every
        // filter is visited, lower ones LAST so they can override.
        let log3 = new_log();
        let mut live =
            FilterChain::new(Some(ConnId::new(21)), SocketIndex::First);
        for name in ["C", "B", "A"] {
            let (transport, _state) = InMemory::new(name, &log3);
            live.add(&mut cx, link(transport));
        }
        let mut index = 0_usize;
        while let Some(node) = live.nth_mut(index) {
            node.base_mut().set_connected(true);
            index += 1;
        }
        live.adjust_pollset(&mut cx, &mut ps)
            .expect("no filter objects");
        assert_eq!(events(&log3), ["A:pollset", "B:pollset", "C:pollset"]);

        // A shut-down prefix is skipped (`:776-778`).
        let log4 = new_log();
        let mut closing =
            FilterChain::new(Some(ConnId::new(22)), SocketIndex::First);
        for name in ["C", "B", "A"] {
            let (transport, _state) = InMemory::new(name, &log4);
            closing.add(&mut cx, link(transport));
        }
        let mut index = 0_usize;
        while let Some(node) = closing.nth_mut(index) {
            node.base_mut().set_connected(true);
            index += 1;
        }
        closing
            .nth_mut(0)
            .expect("A installed")
            .base_mut()
            .set_shut_down(true);
        closing
            .nth_mut(1)
            .expect("B installed")
            .base_mut()
            .set_shut_down(true);
        closing
            .adjust_pollset(&mut cx, &mut ps)
            .expect("no filter objects");
        assert_eq!(events(&log4), ["C:pollset"]);
    }

    /// A filter really can register readiness, and both chains contribute
    /// (`lib/cfilters.c:788-801`).
    #[test]
    fn the_pollset_driver_collects_readiness_from_both_chains() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chains = FilterChains::new(Some(ConnId::new(23)));

        let (primary, primary_state) = InMemory::new("PRIMARY", &log);
        primary_state.borrow_mut().socket = 30;
        primary_state.borrow_mut().writable = false;
        let (secondary, secondary_state) = InMemory::new("SECONDARY", &log);
        secondary_state.borrow_mut().socket = 31;
        secondary_state.borrow_mut().readable = false;

        chains
            .chain_mut(SocketIndex::First)
            .add(&mut cx, link(primary));
        chains
            .chain_mut(SocketIndex::Secondary)
            .add(&mut cx, link(secondary));

        let mut ps = EasyPollset::new();
        chains
            .adjust_pollset(&mut cx, &mut ps)
            .expect("no filter objects");

        assert_eq!(ps.len(), 2);
        assert_eq!(ps.check(30), (true, false));
        assert_eq!(ps.check(31), (false, true));

        // An error from either chain stops the walk.
        /// A filter whose pollset adjustment always fails.
        #[derive(Debug)]
        struct Refuser {
            base: FilterBase,
        }

        impl ConnFilter for Refuser {
            fn trace_name(&self) -> &'static str {
                "REFUSER"
            }
            fn base(&self) -> &FilterBase {
                &self.base
            }
            fn base_mut(&mut self) -> &mut FilterBase {
                &mut self.base
            }
            fn connect(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
            ) -> CurlResult<bool> {
                Ok(true)
            }
            fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
                chain_close(self, cx);
            }
            fn adjust_pollset(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
                _ps: &mut EasyPollset,
            ) -> CurlResult<()> {
                Err(Error::new(CURLcode::BadFunctionArgument))
            }
        }

        chains.chain_mut(SocketIndex::First).add(
            &mut cx,
            link(Refuser {
                base: FilterBase::new(SocketIndex::First),
            }),
        );
        // The filter BELOW the refuser must be connected, or the driver's first
        // skip loop walks straight past the refuser -- which is itself the
        // behaviour `the_pollset_driver_skips_the_prefixes_the_c_skips` pins.
        chains
            .chain_mut(SocketIndex::First)
            .nth_mut(1)
            .expect("PRIMARY sits below the refuser")
            .base_mut()
            .set_connected(true);
        let mut ps = EasyPollset::new();
        assert_eq!(
            chains
                .adjust_pollset(&mut cx, &mut ps)
                .expect_err("the refuser objects")
                .code(),
            CURLcode::BadFunctionArgument
        );
    }

    // -- 21. send and receive skip the disconnected prefix ------------------

    /// `Curl_cf_send` and `Curl_cf_recv` skip the leading run of unconnected
    /// filters (`lib/cfilters.c:212-248`), which is what lets a `CONNECT`
    /// negotiation reach the socket beneath it.
    #[test]
    fn send_and_recv_start_at_the_first_connected_filter() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(24)), SocketIndex::First);

        let (socket, socket_state) = InMemory::new("SOCKET", &log);
        socket_state.borrow_mut().input = b"greeting".to_vec();
        chain.add(&mut cx, link(socket));
        chain.add(&mut cx, link(Plain::new("TUNNEL", &log)));
        assert_eq!(names(&chain), ["TUNNEL", "SOCKET"]);

        // Nothing connected yet: no filter can carry bytes.
        let error = chain
            .send(&mut cx, b"CONNECT", false)
            .expect_err("nothing is connected");
        assert_eq!(error.code(), CURLcode::FailedInit);
        assert_eq!(error.message(), "send: no filter connected");
        let mut buf = [0_u8; 16];
        assert_eq!(
            chain
                .recv(&mut cx, &mut buf)
                .expect_err("nothing is connected")
                .code(),
            CURLcode::FailedInit
        );
        assert!(!chain.data_pending(&mut cx));

        // The socket connects while the tunnel above it has not: the
        // negotiation's own bytes go straight to the socket.
        chain
            .nth_mut(1)
            .expect("SOCKET installed")
            .base_mut()
            .set_connected(true);
        assert_eq!(
            chain
                .send(&mut cx, b"CONNECT", false)
                .expect("the socket accepts bytes"),
            7
        );
        assert_eq!(socket_state.borrow().output, b"CONNECT");
        assert!(chain.data_pending(&mut cx));
        assert_eq!(
            chain.recv(&mut cx, &mut buf).expect("bytes are available"),
            8
        );
        assert_eq!(&buf[..8], b"greeting");

        // `Curl_conn_cf_send` and `_recv` go through the HEAD instead, and their
        // terminal codes are the MIRROR of the trait defaults'
        // (`lib/cfilters.c:404-421`).
        let mut empty = FilterChain::new(None, SocketIndex::First);
        assert_eq!(
            empty
                .send_from_head(&mut cx, b"x", false)
                .expect_err("no chain")
                .code(),
            CURLcode::SendError
        );
        assert_eq!(
            empty
                .recv_into_head(&mut cx, &mut buf)
                .expect_err("no chain")
                .code(),
            CURLcode::RecvError
        );
        assert_eq!(
            empty.connect_head(&mut cx).expect_err("no chain").code(),
            CURLcode::FailedInit
        );
    }

    // -- 22. the bufq adapters, and the pinned eos = false -----------------

    /// `Curl_cf_recv_bufq` and `Curl_cf_send_bufq` (`lib/cfilters.c:263-307`).
    #[test]
    fn the_bufq_adapters_move_bytes_and_always_send_eos_false() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(25)), SocketIndex::First);
        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().input = b"downstream".to_vec();
        chain.add(&mut cx, link(transport));

        let mut inbound = BufQ::new(64, 4);
        let read = chain
            .recv_bufq(&mut cx, &mut inbound, 64)
            .expect("bytes are available");
        assert_eq!(read, 10);
        assert_eq!(inbound.len(), 10);

        // With bytes to append the adapter is `Curl_bufq_write_pass`, which
        // BUFFERS and only drains once the queue is full (`bufq.c:514-550`). A
        // small payload into a roomy queue therefore reports itself accepted
        // without anything reaching the wire, which is the C's behaviour and the
        // whole reason the queue exists.
        let mut outbound = BufQ::new(64, 4);
        let written = chain
            .send_bufq(&mut cx, &mut outbound, b"upstream")
            .expect("the queue accepts bytes");
        assert_eq!(written, 8);
        assert_eq!(outbound.len(), 8);
        assert!(state.borrow().output.is_empty());
        assert!(state.borrow().eos_seen.is_empty(), "nothing was sent yet");

        // With nothing to append, the adapter only DRAINS -- `Curl_bufq_pass`
        // rather than `Curl_bufq_write_pass` (`lib/cfilters.c:302-306`).
        let drained = chain
            .send_bufq(&mut cx, &mut outbound, b"")
            .expect("the transport accepts bytes");
        assert_eq!(drained, 8);
        assert_eq!(state.borrow().output, b"upstream");
        assert!(outbound.is_empty());
        assert_eq!(
            state.borrow().eos_seen,
            [false],
            "the bufq writer always passes eos = false (`lib/cfilters.c:285`)"
        );

        // A second round, to show the flag is pinned rather than incidental.
        chain
            .send_bufq(&mut cx, &mut outbound, b"more")
            .expect("the queue accepts bytes");
        chain
            .send_bufq(&mut cx, &mut outbound, b"")
            .expect("the transport accepts bytes");
        assert_eq!(state.borrow().output, b"upstreammore");
        assert_eq!(state.borrow().eos_seen, [false, false]);

        // A chain with no filter is a caller error, as the C's `!cf` test is.
        let mut empty = FilterChain::new(None, SocketIndex::First);
        let mut spare = BufQ::new(16, 2);
        assert_eq!(
            empty
                .recv_bufq(&mut cx, &mut spare, 16)
                .expect_err("no chain")
                .code(),
            CURLcode::BadFunctionArgument
        );
        assert_eq!(
            empty
                .send_bufq(&mut cx, &mut spare, b"x")
                .expect_err("no chain")
                .code(),
            CURLcode::BadFunctionArgument
        );
    }

    // -- 23. the in-memory transport itself --------------------------------

    #[test]
    fn the_in_memory_transport_reads_writes_connects_and_shuts_down() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(26)), SocketIndex::First);
        let (transport, state) = InMemory::new("T", &log);
        {
            let mut prepared = state.borrow_mut();
            prepared.input = b"server says hello".to_vec();
            prepared.connect_steps = 3;
            prepared.shutdown_steps = 2;
            prepared.socket = 42;
        }
        chain.add(&mut cx, link(transport));

        // Connect takes exactly the configured number of steps.
        assert!(!chain.connect_head(&mut cx).expect("step one"));
        assert!(!chain.connect_head(&mut cx).expect("step two"));
        assert!(chain.connect_head(&mut cx).expect("step three"));
        assert_eq!(state.borrow().connects, 3);
        assert!(chain.is_head_connected());

        // Reads are served from the input buffer, in order and in pieces.
        let mut buf = [0_u8; 6];
        assert_eq!(chain.recv(&mut cx, &mut buf).expect("bytes"), 6);
        assert_eq!(&buf, b"server");
        assert_eq!(chain.recv(&mut cx, &mut buf).expect("bytes"), 6);
        assert_eq!(&buf, b" says ");
        assert_eq!(chain.recv(&mut cx, &mut buf).expect("bytes"), 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(chain.recv(&mut cx, &mut buf).expect("drained"), 0);

        // Writes accumulate in the output buffer.
        assert_eq!(chain.send(&mut cx, b"GET /", false).expect("accepted"), 5);
        assert_eq!(chain.send(&mut cx, b" HTTP", true).expect("accepted"), 5);
        assert_eq!(state.borrow().output, b"GET / HTTP");
        assert_eq!(state.borrow().eos_seen, [false, true]);

        // Readiness is configurable, and an unready transport reports Again.
        state.borrow_mut().readable = false;
        assert_eq!(
            chain
                .recv(&mut cx, &mut buf)
                .expect_err("not readable")
                .code(),
            CURLcode::Again
        );
        state.borrow_mut().writable = false;
        assert_eq!(
            chain
                .send(&mut cx, b"x", false)
                .expect_err("not writable")
                .code(),
            CURLcode::Again
        );

        // Liveness is configurable both ways.
        state.borrow_mut().input_pending = true;
        assert_eq!(chain.is_alive(&mut cx, false), Liveness::alive(true));
        state.borrow_mut().alive = false;
        assert_eq!(chain.is_alive(&mut cx, false), Liveness::DEAD);

        // Shutdown takes exactly the configured number of passes.
        let mut timer = TestTimer::default();
        assert!(!chain.shutdown(&mut cx, &mut timer).expect("pass one"));
        assert!(chain.shutdown(&mut cx, &mut timer).expect("pass two"));
        assert_eq!(state.borrow().shutdowns, 2);

        // And the destruction log records the teardown.
        chain.discard_chain(&mut cx);
        assert_eq!(events(&log), ["T:destroy"]);
    }

    // -- 24. trace identity is independent of the mutable level ------------

    /// A filter reports a STABLE name; the level `--trace-config` writes lives
    /// in [`TraceConfig`]. The two C registries are separate typed tables
    /// (`lib/curl_trc.c:503-570`).
    #[test]
    fn a_filters_trace_identity_is_independent_of_the_mutable_level() {
        let log = new_log();

        // Every name the C registers resolves, including the three that a
        // tidying pass would get wrong.
        for filter in TraceFilter::ALL {
            let probe = Plain::new(filter.name(), &log);
            assert_eq!(
                probe.trace_filter(),
                Some(*filter),
                "{} did not resolve",
                filter.name()
            );
            assert_eq!(probe.trace_name(), filter.name());
        }
        assert_eq!(
            Plain::new("SOCKS", &log).trace_filter(),
            Some(TraceFilter::SocksProxy)
        );
        assert_eq!(
            Plain::new("HTTPS-CONNECT", &log).trace_filter(),
            Some(TraceFilter::HttpConnect)
        );
        assert_eq!(
            Plain::new("HAPPY-EYEBALLS", &log).trace_filter(),
            Some(TraceFilter::IpHappy)
        );

        // An unregistered filter -- the test transport -- resolves to nothing
        // and traces nothing, which is the honest answer.
        let (transport, _state) = InMemory::new("IN-MEMORY", &log);
        assert_eq!(transport.trace_filter(), None);
        assert_eq!(transport.trace_name(), "IN-MEMORY");

        // Changing a level changes NOTHING about the identity.
        let mut config = TraceConfig::new();
        assert_eq!(config.filter_level(TraceFilter::Tcp), TraceLevel::None);
        config.set_filter_level(TraceFilter::Tcp, TraceLevel::Info);
        assert_eq!(config.filter_level(TraceFilter::Tcp), TraceLevel::Info);
        let tcp = Plain::new("TCP", &log);
        assert_eq!(tcp.trace_name(), "TCP");
        assert_eq!(tcp.trace_filter(), Some(TraceFilter::Tcp));
    }

    /// A trace line really is emitted, attributed to the filter's name and
    /// socket index -- the whole of `CURL_TRC_CF`
    /// (`lib/curl_trc.c:269-279`).
    #[test]
    fn a_chain_emits_filter_attributed_trace_lines() {
        let clock = clock();
        let log = new_log();
        let mut config = TraceConfig::new();
        config.set_filter_level(TraceFilter::Tcp, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);

        let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
        let mut chain =
            FilterChain::new(Some(ConnId::new(27)), SocketIndex::Secondary);
        chain.add(&mut cx, link(Plain::new("TCP", &log)));

        let rendered = String::from_utf8(sink.into_inner())
            .expect("the trace output is text");
        assert!(
            rendered.contains("[TCP-1]"),
            "the line must name the filter AND its socket index: {rendered}"
        );
        assert!(
            rendered.contains("added"),
            "missing the message: {rendered}"
        );
    }

    // -- 25. re-entrancy needs no saved call state -------------------------

    /// The successor of `struct cf_call_data` and the
    /// `CF_DATA_SAVE`/`CF_DATA_RESTORE` pair (`lib/cfilters.h:620-685`).
    ///
    /// A filter that calls down twice from inside one of its own methods finds
    /// the context available at both depths, because it is a parameter. There is
    /// nothing to save, nothing to restore, and no depth counter.
    #[test]
    fn a_nested_call_needs_no_saved_context() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(28)), SocketIndex::First);

        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().input = b"pending".to_vec();
        chain.add(&mut cx, link(transport));
        chain.add(
            &mut cx,
            link(Reentrant {
                base: FilterBase::new(SocketIndex::First),
                log: Rc::clone(&log),
            }),
        );
        let mut index = 0_usize;
        while let Some(node) = chain.nth_mut(index) {
            node.base_mut().set_connected(true);
            index += 1;
        }

        let sent = chain
            .send(&mut cx, b"payload", false)
            .expect("the transport accepts bytes");
        assert_eq!(sent, 7);
        assert_eq!(
            events(&log),
            ["reentrant:pending=true", "reentrant:sent=7"],
            "both depths reached the layer below with the same context"
        );
        assert_eq!(state.borrow().output, b"payload");
    }

    // -- the connect drivers -----------------------------------------------

    /// The non-blocking step, which is the PRIMARY connect API
    /// (`lib/cfilters.c:491-548`).
    #[test]
    fn connect_step_flushes_first_and_reports_on_completion() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chains = FilterChains::new(Some(ConnId::new(29)));
        let mut report = ConnectReport::default();

        // No chain at all: FailedInit, and nothing is reported.
        assert_eq!(
            chains
                .connect_step(&mut cx, SocketIndex::First, &mut report)
                .expect_err("no chain")
                .code(),
            CURLcode::FailedInit
        );
        assert_eq!(report, ConnectReport::default());

        let connected_at = CurlTime::new(900, 0);
        let app_connected_at = CurlTime::new(950, 0);
        let (transport, state) = InMemory::new("T", &log);
        {
            let mut prepared = state.borrow_mut();
            prepared.connect_steps = 2;
            prepared.answers.extend([
                (CfQuery::NeedFlush, CfQueryValue::NeedFlush(true)),
                (CfQuery::TimerConnect, CfQueryValue::Timer(connected_at)),
                (
                    CfQuery::TimerAppConnect,
                    CfQueryValue::Timer(app_connected_at),
                ),
            ]);
        }
        chains
            .chain_mut(SocketIndex::First)
            .add(&mut cx, link(transport));

        // First step: the flush happens BEFORE the connect (`:521-526`), so the
        // transport sees a Flush control before it is asked to connect.
        assert!(!chains
            .connect_step(&mut cx, SocketIndex::First, &mut report)
            .expect("step one"));
        assert_eq!(state.borrow().controls, [CfControl::Flush]);
        assert_eq!(state.borrow().connects, 1);
        // Timers are reported only once the chain is fully connected, and the
        // keepalive reading not at all yet.
        assert!(report.keepalive.is_zero());

        // Second step completes it, and everything is reported at once.
        assert!(chains
            .connect_step(&mut cx, SocketIndex::First, &mut report)
            .expect("step two"));
        assert_eq!(report.connected_at, connected_at);
        assert_eq!(report.app_connected_at, app_connected_at);
        assert_eq!(
            report.keepalive,
            clock.now(),
            "the keepalive reading comes from the INJECTED clock"
        );
        assert!(state.borrow().controls.contains(&CfControl::ConnInfoUpdate));

        // A third call is a no-op with no side effects (`:514-516`).
        let before = state.borrow().connects;
        assert!(chains
            .connect_step(&mut cx, SocketIndex::First, &mut report)
            .expect("already connected"));
        assert_eq!(state.borrow().connects, before);
    }

    /// A failing connect still reports the timers (`lib/cfilters.c:541-545`).
    #[test]
    fn a_failing_connect_still_reports_its_timers() {
        /// A filter whose connect always fails.
        #[derive(Debug)]
        struct Broken {
            base: FilterBase,
            at: CurlTime,
        }

        impl ConnFilter for Broken {
            fn trace_name(&self) -> &'static str {
                "BROKEN"
            }
            fn base(&self) -> &FilterBase {
                &self.base
            }
            fn base_mut(&mut self) -> &mut FilterBase {
                &mut self.base
            }
            fn connect(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
            ) -> CurlResult<bool> {
                Err(Error::new(CURLcode::CouldntConnect))
            }
            fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
                chain_close(self, cx);
            }
            fn query(
                &mut self,
                cx: &mut CallCtx<'_, '_>,
                query: CfQuery,
            ) -> CurlResult<CfQueryValue> {
                match query {
                    CfQuery::TimerConnect => Ok(CfQueryValue::Timer(self.at)),
                    _ => match self.base_mut().next_mut() {
                        Some(next) => next.query(cx, query),
                        None => Err(Error::new(CURLcode::UnknownOption)),
                    },
                }
            }
        }

        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let mut chains = FilterChains::new(Some(ConnId::new(30)));
        let at = CurlTime::new(500, 0);
        chains.chain_mut(SocketIndex::First).add(
            &mut cx,
            link(Broken {
                base: FilterBase::new(SocketIndex::First),
                at,
            }),
        );

        let mut report = ConnectReport::default();
        assert_eq!(
            chains
                .connect_step(&mut cx, SocketIndex::First, &mut report)
                .expect_err("the filter fails")
                .code(),
            CURLcode::CouldntConnect
        );
        assert_eq!(
            report.connected_at, at,
            "a failed connect still has a connect time worth reporting"
        );
        assert!(
            report.keepalive.is_zero(),
            "the keepalive reading is taken only on success"
        );
    }

    /// The async wrapper drives [`FilterChains::connect_step`] to completion
    /// (`lib/cfilters.c:547-585`).
    ///
    /// The timer is PAUSED, so the per-pass ceiling the C bounds its poll with
    /// costs no real time and the test is deterministic.
    #[tokio::test(start_paused = true)]
    async fn the_async_connect_wrapper_drives_the_chain_to_completion() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chains = FilterChains::new(Some(ConnId::new(31)));
        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().connect_steps = 4;
        chains
            .chain_mut(SocketIndex::First)
            .add(&mut cx, link(transport));

        let mut report = ConnectReport::default();
        // No socket is registered, so each pass waits on the 10 ms ceiling the C
        // uses for an empty descriptor set (`:577`).
        chains
            .connect(&mut cx, SocketIndex::First, 0, &mut report)
            .await
            .expect("the chain connects");
        assert_eq!(state.borrow().connects, 4);
        assert!(chains.chain(SocketIndex::First).is_head_connected());
        assert_eq!(report.keepalive, clock.now());
    }

    /// A negative budget is spent before the first step (`:555-559`).
    #[tokio::test]
    async fn the_async_connect_wrapper_reports_an_expired_budget() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chains = FilterChains::new(Some(ConnId::new(32)));
        let (transport, state) = InMemory::new("T", &log);
        state.borrow_mut().connect_steps = 9;
        chains
            .chain_mut(SocketIndex::First)
            .add(&mut cx, link(transport));

        let mut report = ConnectReport::default();
        let error = chains
            .connect(&mut cx, SocketIndex::First, -1, &mut report)
            .await
            .expect_err("the budget is already spent");
        assert_eq!(error.code(), CURLcode::OperationTimedout);
        assert_eq!(error.message(), "connect timeout");
        assert_eq!(
            state.borrow().connects,
            0,
            "the deadline is checked before any work"
        );
    }

    /// A budget that runs out mid-loop, measured against the INJECTED clock.
    ///
    /// The clock is advanced by the FILTER rather than by the test, which is the
    /// only way to model time passing during a connect: a [`TestClock`] moves
    /// only when something moves it, and the loop reads it once per pass.
    #[tokio::test(start_paused = true)]
    async fn the_async_connect_wrapper_times_out_against_the_injected_clock() {
        /// A filter that never finishes connecting and burns `step_ms` of the
        /// injected clock on every attempt.
        #[derive(Debug)]
        struct Stalling {
            base: FilterBase,
            clock: Rc<TestClock>,
            step_ms: u64,
            attempts: Rc<RefCell<usize>>,
        }

        impl ConnFilter for Stalling {
            fn trace_name(&self) -> &'static str {
                "STALLING"
            }
            fn base(&self) -> &FilterBase {
                &self.base
            }
            fn base_mut(&mut self) -> &mut FilterBase {
                &mut self.base
            }
            fn connect(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
            ) -> CurlResult<bool> {
                *self.attempts.borrow_mut() += 1;
                self.clock
                    .advance(std::time::Duration::from_millis(self.step_ms));
                Ok(false)
            }
            fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
                chain_close(self, cx);
            }
        }

        let clock = Rc::new(TestClock::new(CurlTime::new(10, 0)));
        let attempts = Rc::new(RefCell::new(0_usize));
        let mut cx = CallCtx::new(clock.as_ref());
        let mut chains = FilterChains::new(Some(ConnId::new(33)));
        chains.chain_mut(SocketIndex::First).add(
            &mut cx,
            link(Stalling {
                base: FilterBase::new(SocketIndex::First),
                clock: Rc::clone(&clock),
                step_ms: 15,
                attempts: Rc::clone(&attempts),
            }),
        );

        // A 20 ms budget against a filter that burns 15 ms a pass: the first
        // pass leaves 5 ms, the second overruns.
        let mut report = ConnectReport::default();
        let error = chains
            .connect(&mut cx, SocketIndex::First, 20, &mut report)
            .await
            .expect_err("the budget runs out");
        assert_eq!(error.code(), CURLcode::OperationTimedout);
        assert_eq!(error.message(), "connect timeout");
        assert_eq!(*attempts.borrow(), 2);
        assert!(
            report.keepalive.is_zero(),
            "a connect that never completed reports no keepalive reading"
        );
    }

    // -- chain ownership handover ------------------------------------------

    /// [`FilterChain::take_chain`] and [`FilterChain::set_chain`], which are what
    /// a filter owning a private subchain needs -- the Happy Eyeballs filter
    /// promoting the winner of a race.
    #[test]
    fn a_whole_chain_can_be_detached_and_reinstalled_with_restamping() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut source = plain_chain(&mut cx, &log, &["A", "B"]);
        let detached = source.take_chain().expect("a chain was installed");
        assert!(source.is_empty());

        let mut target =
            FilterChain::new(Some(ConnId::new(99)), SocketIndex::Secondary);
        assert!(target.set_chain(Some(detached)).is_none());
        assert_eq!(names(&target), ["A", "B"]);
        for filter in target.iter() {
            assert_eq!(filter.base().conn(), Some(ConnId::new(99)));
            assert_eq!(filter.sockindex(), SocketIndex::Secondary);
        }

        // Reinstalling returns what was there rather than dropping it silently.
        let previous = target
            .set_chain(Some(link(Plain::new("NEW", &log))))
            .expect("the old chain comes back");
        assert_eq!(previous.trace_name(), "A");
        assert_eq!(names(&target), ["NEW"]);
        discard_chain_from(&mut cx, Some(previous));

        // Rebinding a whole connection restamps both chains.
        let mut chains = FilterChains::new(Some(ConnId::new(1)));
        chains
            .chain_mut(SocketIndex::First)
            .add(&mut cx, link(Plain::new("P", &log)));
        chains
            .chain_mut(SocketIndex::Secondary)
            .add(&mut cx, link(Plain::new("S", &log)));
        chains.set_conn(Some(ConnId::new(2)));
        for sockindex in SocketIndex::ALL {
            assert_eq!(
                chains
                    .chain(sockindex)
                    .head_ref()
                    .expect("installed")
                    .base()
                    .conn(),
                Some(ConnId::new(2))
            );
            assert_eq!(chains.chain(sockindex).conn(), Some(ConnId::new(2)));
        }

        // And both chains can be torn down at once.
        let log2 = new_log();
        let mut pair = FilterChains::new(Some(ConnId::new(3)));
        for sockindex in SocketIndex::ALL {
            let (transport, _state) = InMemory::new("T", &log2);
            pair.chain_mut(sockindex).add(&mut cx, link(transport));
        }
        pair.discard_everything(&mut cx);
        assert_eq!(events(&log2), ["T:destroy", "T:destroy"]);
        for sockindex in SocketIndex::ALL {
            assert!(pair.chain(sockindex).is_empty());
        }

        // `discard_all` reaches one chain only.
        let log3 = new_log();
        let mut one = FilterChains::new(Some(ConnId::new(4)));
        for sockindex in SocketIndex::ALL {
            let (transport, _state) = InMemory::new("T", &log3);
            one.chain_mut(sockindex).add(&mut cx, link(transport));
        }
        one.discard_all(&mut cx, SocketIndex::Secondary);
        assert!(one.chain(SocketIndex::Secondary).is_empty());
        assert!(one.chain(SocketIndex::First).is_setup());
        assert_eq!(events(&log3).len(), 1);
        assert_eq!(
            FilterChains::default().chain(SocketIndex::First).conn(),
            None
        );
    }

    /// `Curl_conn_close` reaches the head only and relies on each filter to
    /// chain (`lib/cfilters.c:144-155`).
    #[test]
    fn close_reaches_the_head_only_and_the_filters_chain_it_down() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(34)), SocketIndex::First);
        let (transport, state) = InMemory::new("BOTTOM", &log);
        chain.add(&mut cx, link(transport));
        chain.add(&mut cx, link(Plain::new("MIDDLE", &log)));
        chain.add(&mut cx, link(Plain::new("TOP", &log)));
        let mut index = 0_usize;
        while let Some(node) = chain.nth_mut(index) {
            node.base_mut().set_connected(true);
            index += 1;
        }

        chain.close(&mut cx);

        // Every filter saw it, top down, because `chain_close` passes it on.
        assert_eq!(events(&log), ["TOP:close", "MIDDLE:close", "BOTTOM:close"]);
        assert_eq!(state.borrow().closes, 1);
        // And every one cleared its own `connected` flag.
        for filter in chain.iter() {
            assert!(
                !filter.base().is_connected(),
                "{} stayed connected",
                filter.trace_name()
            );
        }
        // The filters remain installed and may be connected again
        // (`lib/cfilters.h:424-425`).
        assert_eq!(names(&chain), ["TOP", "MIDDLE", "BOTTOM"]);
    }

    // -- the remaining vocabulary -------------------------------------------

    #[test]
    fn the_call_context_carries_the_injected_clock_and_nothing_global() {
        let clock = TestClock::new(CurlTime::new(7, 500_000));
        let cx = CallCtx::new(&clock);
        assert_eq!(cx.now(), CurlTime::new(7, 500_000));
        assert_eq!(cx.clock().epoch_secs(), clock.epoch_secs());
        assert_eq!(format!("{cx:?}"), "CallCtx { tracing: false }");

        clock.advance(std::time::Duration::from_secs(3));
        assert_eq!(
            cx.now(),
            CurlTime::new(10, 500_000),
            "the context reads the clock rather than caching it"
        );

        let mut config = TraceConfig::new();
        config.set_filter_level(TraceFilter::Ssl, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        let mut traced = CallCtx::new(&clock).with_tracer(&mut tracer);
        assert_eq!(format!("{traced:?}"), "CallCtx { tracing: true }");
        assert!(traced.tracer_mut().is_some());
    }

    #[test]
    fn the_connection_identity_and_the_query_carriers_round_trip() {
        let id = ConnId::new(4_242);
        assert_eq!(id.get(), 4_242);
        assert_eq!(id.to_string(), "4242");
        assert_eq!(format!("{id:?}"), "ConnId(4242)");

        assert_eq!(Liveness::default(), Liveness::DEAD);
        // Compared against a value rather than asserted field by field: the
        // fields of a `const` are const-evaluable, and `assert!` over one is a
        // tautology clippy rightly refuses.
        assert_eq!(
            Liveness::DEAD,
            Liveness {
                alive: false,
                input_pending: false,
            }
        );
        assert_eq!(
            Liveness::alive(false),
            Liveness {
                alive: true,
                input_pending: false,
            }
        );
        assert_eq!(
            Liveness::alive(true),
            Liveness {
                alive: true,
                input_pending: true,
            }
        );

        let quad = IpQuadruple::default();
        assert!(quad.remote_ip.is_empty());
        assert_eq!(quad.remote_port, 0);
        assert_eq!(quad.transport, Transport::None);

        let unix = RemoteAddr::Unix("/run/curl.sock".to_owned());
        assert_eq!(unix, RemoteAddr::Unix("/run/curl.sock".to_owned()));
        let inet = RemoteAddr::Inet(std::net::SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
        ));
        assert_ne!(inet, unix);

        let session = TlsSessionInfo {
            backend: TlsBackendId::RUSTLS,
            kind: TlsHandleKind::Session,
            distinguishes_context: false,
        };
        let context = TlsSessionInfo {
            kind: TlsHandleKind::Context,
            ..session
        };
        assert_ne!(session, context);
        assert_eq!(session.backend, TlsBackendId::RUSTLS);
    }

    /// [`FilterBase`] on its own: the two flags and the link, which is the whole
    /// of `struct Curl_cfilter`'s surviving state.
    #[test]
    fn the_filter_base_starts_unattached_with_both_flags_clear() {
        let base = FilterBase::new(SocketIndex::Secondary);
        assert!(!base.is_attached());
        assert!(!base.has_next());
        assert!(!base.is_connected());
        assert!(!base.has_shut_down());
        assert_eq!(base.sockindex(), SocketIndex::Secondary);
        assert_eq!(base.conn(), None);
        assert!(base.next_ref().is_none());

        let mut base = FilterBase::default();
        assert_eq!(
            base.sockindex(),
            SocketIndex::First,
            "a zeroed Curl_cfilter is the primary socket"
        );
        base.set_connected(true);
        base.set_shut_down(true);
        base.set_conn(Some(ConnId::new(5)));
        base.set_sockindex(SocketIndex::Secondary);
        assert!(base.is_connected());
        assert!(base.has_shut_down());
        assert!(base.is_attached());
        assert_eq!(base.sockindex(), SocketIndex::Secondary);

        let log = new_log();
        base.set_next(Some(link(Plain::new("BELOW", &log))));
        assert!(base.has_next());
        assert_eq!(base.next_ref().map(ConnFilter::trace_name), Some("BELOW"));
        assert_eq!(
            base.next_mut().map(|next| next.trace_name()),
            Some("BELOW")
        );
        let taken = base.take_next().expect("a link was installed");
        assert_eq!(taken.trace_name(), "BELOW");
        assert!(!base.has_next());
    }
}
