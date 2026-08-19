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
//! HTTP/2 -- `lib/http2.c` (3,011 lines) and `lib/http2.h`, with nghttp2
//! replaced by the `h2` crate.
//!
//! This is a CONNECTION FILTER, not a [`Protocol`] implementor. `http` and
//! `https` share one `Curl_protocol_http` (`lib/http.c:5011` and `:5028` both
//! name `&Curl_protocol_http`), and HTTP/2 slots into the filter chain
//! BENEATH it -- exactly as `struct Curl_cftype Curl_cft_nghttp2`
//! (`lib/http2.c:2773-2789`) does in the C.
//!
//! [`Protocol`]: super::Protocol
//!
//! # The trace name is the literal `"HTTP/2"`, and it stays that way
//!
//! The C symbol is `Curl_cft_nghttp2` but the `name` member it declares is
//! the string `"HTTP/2"` (`lib/http2.c:2774`), which is what
//! `--trace-config` matches and what every trace line prints
//! (`lib/curl_trc.c` registers the filter under that same string). **Nothing
//! in a curl trace log ever said `nghttp2`, and nothing here will either.**
//! That decision is recorded explicitly because `--trace` output is
//! user-visible: renaming the filter to advertise the new backend would
//! change bytes an application may be parsing, so the emitted string is
//! frozen even though the library behind it changed.
//! [`crate::trace::TraceFilter::Http2`] carries the same string and
//! `TraceFilter::from_name(b"nghttp2")` answers [`None`], which is the
//! assertion that keeps the two spellings from being confused.
//!
//! # What this module decides, and what `h2` performs
//!
//! Specification 0.1.2 is explicit -- *"Header serialisation is ours, not the
//! library's"* -- and 0.8.5's conflict resolution C4 gives the reason both
//! `hyper` and `h2` are declared: *"raw SETTINGS and flow-control
//! manipulation is observable in curl 8.x fixture expectations and is not
//! reachable through hyper's surface."* The division that follows is sharp:
//!
//! * **`h2` performs HPACK and the HEADERS/DATA framing.** Every frame
//!   carrying a header block is its business, and no HPACK table, Huffman
//!   tree or header-block codec appears in this file.
//! * **This module decides everything whose bytes curl chooses**: the
//!   SETTINGS payload and its ENTRY ORDER, the connection and stream window
//!   sizes, when a `WINDOW_UPDATE` goes out and how large it is, the
//!   `RST_STREAM` / `PING` / `GOAWAY` frames, the `h2c` upgrade headers, and
//!   the ORDERED field list handed to HPACK.
//!
//! The reason the SETTINGS frame is built here rather than by `h2`'s builder
//! is measured rather than assumed. `h2 0.4.15` emits its settings in the
//! order HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS,
//! INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE,
//! ENABLE_CONNECT_PROTOCOL (its `Settings::for_each`), and its `frame` module
//! is private unless the crate's `unstable` feature is on. curl sends three
//! entries in a different order (§ below), that order is wire-observable, and
//! specification 0.3.1's instruction for exactly this case is to *"construct
//! and send the SETTINGS frame explicitly"*. [`pack_settings_payload`] is
//! that construction.
//!
//! The same division is what `protocols/http1.rs` arrived at for `hyper`, and
//! for the same reason: a library that cannot be made to emit curl's exact
//! bytes supplies the parts where it can, and the bytes stay ours.
//!
//! # The measured anchors
//!
//! Every number in this file came from reading the C, and the five that carry
//! the most weight are cited here so a reviewer can check them without
//! searching:
//!
//! | Anchor | What it fixes |
//! |---|---|
//! | `lib/http2.c:222` | `populate_settings` -- three entries, in order |
//! | `lib/http2.c:209` | `cf_h2_initial_win_size` -- the rate-limit branch |
//! | `lib/http2.c:60-88` | the nine window and buffering constants |
//! | `lib/http2.c:1478` | the push-header string, `"name:value"` |
//! | `lib/http2.c:2773` | `Curl_cft_nghttp2` -- the filter's identity |
//!
//! # Wire behaviour is frozen
//!
//! Specification 0.8.1 freezes protocol wire behaviour and 0.6.7 records why
//! that is a design constraint rather than a testing detail: 1,476 of the
//! 1,914 fixtures carry a `<protocol>` block, and `compareparts`
//! (`tests/getpart.pm:351`) joins both arrays into ONE string before
//! comparing -- *"no per-line matching, no normalisation, and no
//! reordering"*. For HTTP/2 that reaches the base64 `HTTP2-Settings` value of
//! an `h2c` upgrade and the order of the fields in a header frame. A fixture
//! that disagrees with this file is a defect here; editing the fixture is
//! prohibited.
//!
//! # Feature gate
//!
//! `#[cfg(feature = "http2")]`, default ON, matching the C's
//! `#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGHTTP2)`
//! (`lib/http2.c:26`). The gate is on the module DECLARATION in
//! `protocols/mod.rs`, so a build without the feature omits this file
//! entirely while the scheme registry keeps all 33 of its rows and `https`
//! still works over HTTP/1.1.

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context as TaskContext, Poll};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Uri, Version};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::http1::{NoUpgrades, RequestState, UpgradeWriter};
use super::HttpNegotiation;
use crate::conn::filters::{
    link, CallCtx, CfControl, CfQuery, CfQueryValue, CfType, ConnFilter,
    ConnId, FilterBase, FilterChain, Liveness, SocketIndex, CF_TYPE_HTTP,
    CF_TYPE_MULTIPLEX, CURL_LOG_LVL_NONE,
};
use crate::conn::select::{
    is_valid_sock, EasyPollset, Socket, CURL_SOCKET_BAD,
};
use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::headers::{
    HeaderSet, PushHeaders, CURLH_PSEUDO, CURLH_TRAILER, HTTP_PSEUDO_AUTHORITY,
    HTTP_PSEUDO_METHOD, HTTP_PSEUDO_PATH, HTTP_PSEUDO_SCHEME,
    HTTP_PSEUDO_STATUS,
};
use crate::trace::{trc_cf, TraceFilter};
use crate::transfer::ratelimit::RateLimit;
use crate::transfer::request::Upgrade101;
use crate::util::base64;
use crate::util::bufq::{BufQ, BufqOpts};
use crate::util::dynbuf::{DynBuf, DYN_HTTP_REQUEST};
use crate::util::timeval::CurlTime;

/// ASCII case-insensitive equality, local so this file imports only from its
/// declared dependency whitelist.
fn casecompare(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

// ---------------------------------------------------------------------------
// 1. The filter's identity -- the first three members of `Curl_cft_nghttp2`.

/// The `name` member (`lib/http2.c:2774`).
///
/// Written as a `#[rustfmt::skip]` item because it is a WIRE-BEARING literal
/// in the sense that matters here: it appears verbatim in `--trace` output
/// and in `--trace-config` matching, so a formatter must never be in a
/// position to rewrite it. See the module documentation for why it is not
/// spelled `nghttp2`.
#[rustfmt::skip]
pub(crate) const HTTP2_FILTER_NAME: &str = "HTTP/2";

/// The `flags` member (`lib/http2.c:2775`): `CF_TYPE_MULTIPLEX |
/// CF_TYPE_HTTP`, and nothing else.
///
/// Measured, and both halves matter. `CF_TYPE_MULTIPLEX` is what
/// [`crate::conn::filters::FilterChain`] looks for when it decides a
/// connection can carry more than one transfer, and `CF_TYPE_HTTP` is what
/// marks the filter as implementing a version of HTTP. `CF_TYPE_IP_CONNECT`
/// is deliberately ABSENT: this filter multiplexes over a connection somebody
/// else established, so it provides no IP connectivity and must not claim
/// any.
///
/// The bit values are consumed from [`crate::conn::filters`] rather than
/// redeclared, so `(1 << 2) | (1 << 4)` is stated in exactly one place in the
/// crate.
///
/// [`CfType::union`] rather than `|`: the `BitOr` implementation is not a
/// `const fn`, so `CF_TYPE_MULTIPLEX | CF_TYPE_HTTP` in a `const` item is
/// `error[E0015]`. The `union` method exists for exactly this, and its own
/// documentation cites `Curl_cft_http3`'s four-bit composite as the case that
/// motivated it.
pub(crate) const HTTP2_FLAGS: CfType = CF_TYPE_MULTIPLEX.union(CF_TYPE_HTTP);

/// The `log_level` member (`lib/http2.c:2776`): `CURL_LOG_LVL_NONE`.
///
/// C's is a process-global that `--trace-config` writes through; here the
/// level lives in [`crate::trace::TraceConfig`] and this constant records
/// what the C declares so the identity test can assert it.
// The allowance is on this ITEM and never on the module: `mod source_policy`
// in the crate root rejects a `dead_code` lint level on any module root.
#[allow(dead_code)] // Asserted by the identity test; the level lives in
                    // `crate::trace::TraceConfig`.
pub(crate) const HTTP2_LOG_LEVEL: i32 = CURL_LOG_LVL_NONE;

/// `DEFAULT_MAX_CONCURRENT_STREAMS` (`lib/http2.h:32`).
///
/// The C's comment is the whole contract: *"value for
/// MAX_CONCURRENT_STREAMS we use until we get an updated setting from the
/// peer"*. `cf_h2_ctx_open` assigns it at `lib/http2.c:2409`, and
/// `on_frame_recv` replaces it from the peer's SETTINGS at `:1173`.
pub(crate) const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

/// The HTTP/2 connection preface -- RFC 9113 section 3.4.
///
/// A wire-bearing literal, and the first 24 bytes any HTTP/2 client sends
/// over a connection it did not reach through an `h2c` upgrade. `h2` writes
/// this itself for a connection it owns; the constant is here because the
/// `via_h1_upgrade` path must NOT send it -- `nghttp2_session_upgrade2`
/// (`lib/http2.c:2433`) opens stream 1 implicitly and the preface has already
/// been superseded by the HTTP/1.1 request -- and stating both halves in one
/// place is what keeps that asymmetry visible.
#[rustfmt::skip]
pub(crate) const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The `Upgrade:` token for cleartext HTTP/2 --
/// `NGHTTP2_CLEARTEXT_PROTO_VERSION_ID` as `lib/http2.c:1664` passes it.
///
/// Wire-bearing, hence `#[rustfmt::skip]`.
#[rustfmt::skip]
pub(crate) const H2C_PROTO_ID: &[u8] = b"h2c";

/// The header name whose value is the base64url SETTINGS payload.
///
/// Wire-bearing, hence `#[rustfmt::skip]`. `lib/http.c:2799-2801` also emits
/// this exact spelling as a `Connection:` token, which is why the two must
/// never drift: see [`request_upgrade`].
#[rustfmt::skip]
pub(crate) const H2_SETTINGS_HEADER: &[u8] = b"HTTP2-Settings";

/// The single byte that separates a name from a value in a stored push
/// header, and the byte a pseudo-header name begins with.
///
/// Wire-bearing, hence `#[rustfmt::skip]`. `lib/http2.c:1478` builds
/// `"%s:%s"` with exactly this and NO following space.
#[rustfmt::skip]
pub(crate) const H2_COLON: &[u8] = b":";

// ---------------------------------------------------------------------------
// 2. Buffer dimensioning and window sizes -- `lib/http2.c:59-90`.
//
// Every one of the nine is written as the ARITHMETIC the C writes rather than
// as the product, so the relationships between them stay visible: three of
// them are quotients of two others, and a reader checking
// `H2_NW_RECV_CHUNKS` against the C should see `H2_CONN_WINDOW_SIZE /
// H2_CHUNK_SIZE` and not the number 640.

/// `H2_CHUNK_SIZE` (`lib/http2.c:61`).
///
/// The C's comment: *"use 16K as chunk size, as that fits H2 DATA frames
/// well"*.
pub(crate) const H2_CHUNK_SIZE: usize = 16 * 1024;

/// `H2_CONN_WINDOW_SIZE` (`lib/http2.c:63`) -- the connection window size.
pub(crate) const H2_CONN_WINDOW_SIZE: usize = 10 * 1024 * 1024;

/// `H2_NW_RECV_CHUNKS` (`lib/http2.c:65`).
///
/// The C's comment: *"on receiving from TLS, we prep for holding a full
/// stream window"*.
pub(crate) const H2_NW_RECV_CHUNKS: usize = H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE;

/// `H2_NW_SEND_CHUNKS` (`lib/http2.c:67`).
///
/// The C's comment: *"on send into TLS, we just want to accumulate small
/// frames"*. One chunk, deliberately.
pub(crate) const H2_NW_SEND_CHUNKS: usize = 1;

/// `H2_STREAM_WINDOW_SIZE_MAX` (`lib/http2.c:69`).
///
/// The C's comment: *"this is how much we want 'in flight' for a stream,
/// unthrottled"*.
pub(crate) const H2_STREAM_WINDOW_SIZE_MAX: usize = 10 * 1024 * 1024;

/// `H2_STREAM_WINDOW_SIZE_INITIAL` (`lib/http2.c:73`).
///
/// The C selects between this and [`H2_STREAM_WINDOW_SIZE_MAX`] on
/// `NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE`, which `lib/http2.c:54-56` defines for
/// every nghttp2 at or past 1.12 -- and `:50-52` makes anything older a hard
/// `#error`. The capability is therefore unconditional in any build that
/// compiles, so the `#if` collapses to this branch and the 64 KiB value is
/// the only reachable one.
pub(crate) const H2_STREAM_WINDOW_SIZE_INITIAL: usize = 64 * 1024;

/// `H2_STREAM_SEND_CHUNKS` (`lib/http2.c:79`).
///
/// The C's comment: *"keep smaller stream upload buffer (default h2 window
/// size) to have our progress bars and 'upload done' reporting closer to
/// reality"*. The C spells the numerator `(64 * 1024)` literally rather than
/// naming [`H2_STREAM_WINDOW_SIZE_INITIAL`]; the two are the same number and
/// the named form is used here because it is the same QUANTITY -- the default
/// h2 window size -- which is what the comment says.
pub(crate) const H2_STREAM_SEND_CHUNKS: usize =
    H2_STREAM_WINDOW_SIZE_INITIAL / H2_CHUNK_SIZE;

/// `H2_STREAM_POOL_SPARES` (`lib/http2.c:81`) -- *"spare chunks we keep for a
/// full window"*.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
pub(crate) const H2_STREAM_POOL_SPARES: usize =
    H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE;

/// `HTTP2_HUGE_WINDOW_SIZE` (`lib/http2.c:87`).
///
/// The C's comment records both the reason and the bug report: *"We need to
/// accommodate the max number of streams with their window sizes on the
/// overall connection. Streams might become PAUSED which will block their
/// received QUOTA in the connection window. If we run out of space, the
/// server is blocked from sending us any data. See #10988"*.
///
/// `cf_h2_ctx_open` applies it to stream 0 -- the connection -- at
/// `lib/http2.c:2467`, which is why [`CfH2::connect`] queues a connection
/// `WINDOW_UPDATE` of exactly this size minus the protocol default.
pub(crate) const HTTP2_HUGE_WINDOW_SIZE: usize =
    100 * H2_STREAM_WINDOW_SIZE_MAX;

/// The flow-control window every HTTP/2 endpoint starts with -- RFC 9113
/// section 6.9.2, 65,535 octets.
///
/// Not one of the nine, and not a curl constant: it is the protocol's own
/// default, and it is needed because a `WINDOW_UPDATE` carries an INCREMENT
/// rather than a target. The increment `cf_h2_ctx_open`'s
/// `nghttp2_session_set_local_window_size(..., 0, HTTP2_HUGE_WINDOW_SIZE)`
/// produces is therefore [`HTTP2_HUGE_WINDOW_SIZE`] minus this.
pub(crate) const H2_DEFAULT_WINDOW_SIZE: usize = 65_535;

// ---------------------------------------------------------------------------
// 3. Frame primitives -- RFC 9113 section 4.1.
//
// `h2`'s `frame` module is private unless its `unstable` feature is on, and
// enabling that feature would put an unstable API in the dependency graph of
// a library whose whole purpose is a frozen ABI. The five control frames curl
// itself decides to emit -- SETTINGS, WINDOW_UPDATE, RST_STREAM, PING and
// GOAWAY -- carry no header block, so serialising them needs no HPACK and is
// a dozen lines of big-endian writing. That is what this section is.

/// The fixed frame header: 24-bit length, 8-bit type, 8-bit flags, 32-bit
/// stream identifier.
pub(crate) const FRAME_HEADER_LEN: usize = 9;

/// The largest payload a 24-bit length field can express, and therefore the
/// largest this module will serialise -- RFC 9113 section 4.2.
pub(crate) const FRAME_MAX_PAYLOAD_LEN: usize = 0x00ff_ffff;

/// A frame type, as the `type` field of a frame header encodes it.
///
/// Only the eleven RFC 9113 types are named. The enum is `u8`-valued rather
/// than opaque because a frame header is read and written byte by byte, and
/// [`FrameType::from_u8`] answers [`None`] for an extension type -- which
/// RFC 9113 section 5.5 requires a receiver to DISCARD rather than reject,
/// and which [`H2ConnCtx::ingest`] therefore skips.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum FrameType {
    /// `DATA` -- 0x00.
    Data,
    /// `HEADERS` -- 0x01. Carries an HPACK block, so `h2` owns it.
    Headers,
    /// `PRIORITY` -- 0x02.
    Priority,
    /// `RST_STREAM` -- 0x03.
    RstStream,
    /// `SETTINGS` -- 0x04.
    Settings,
    /// `PUSH_PROMISE` -- 0x05. Carries an HPACK block, so `h2` owns it.
    PushPromise,
    /// `PING` -- 0x06.
    Ping,
    /// `GOAWAY` -- 0x07.
    Goaway,
    /// `WINDOW_UPDATE` -- 0x08.
    WindowUpdate,
    /// `CONTINUATION` -- 0x09. Carries an HPACK block, so `h2` owns it.
    Continuation,
}

impl FrameType {
    /// Every type, in the order RFC 9113 section 6 defines them.
    #[allow(dead_code)] // consumer: this module's tests
    pub(crate) const ALL: [Self; 10] = [
        Self::Data,
        Self::Headers,
        Self::Priority,
        Self::RstStream,
        Self::Settings,
        Self::PushPromise,
        Self::Ping,
        Self::Goaway,
        Self::WindowUpdate,
        Self::Continuation,
    ];

    /// The `type` byte.
    pub(crate) const fn as_u8(self) -> u8 {
        match self {
            Self::Data => 0x00,
            Self::Headers => 0x01,
            Self::Priority => 0x02,
            Self::RstStream => 0x03,
            Self::Settings => 0x04,
            Self::PushPromise => 0x05,
            Self::Ping => 0x06,
            Self::Goaway => 0x07,
            Self::WindowUpdate => 0x08,
            Self::Continuation => 0x09,
        }
    }

    /// The type a `type` byte names, or [`None`] for an extension type.
    pub(crate) const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Headers),
            0x02 => Some(Self::Priority),
            0x03 => Some(Self::RstStream),
            0x04 => Some(Self::Settings),
            0x05 => Some(Self::PushPromise),
            0x06 => Some(Self::Ping),
            0x07 => Some(Self::Goaway),
            0x08 => Some(Self::WindowUpdate),
            0x09 => Some(Self::Continuation),
            _ => None,
        }
    }

    /// Whether a frame of this type carries an HPACK header block, and is
    /// therefore `h2`'s to build and to parse rather than this module's.
    #[allow(dead_code)] // exercised by the frame-parser conformance tests
    pub(crate) const fn carries_header_block(self) -> bool {
        matches!(self, Self::Headers | Self::PushPromise | Self::Continuation)
    }
}

/// `FLAG_NONE` -- what `NGHTTP2_FLAG_NONE` names at every submit call site in
/// `lib/http2.c`.
pub(crate) const FRAME_FLAG_NONE: u8 = 0x00;

/// `FLAG_ACK`, shared by SETTINGS and PING -- RFC 9113 sections 6.5.3 and
/// 6.7.
pub(crate) const FRAME_FLAG_ACK: u8 = 0x01;

/// `END_HEADERS` on HEADERS, PUSH_PROMISE and CONTINUATION frames.
const FRAME_FLAG_END_HEADERS: u8 = 0x04;

/// The mask that clears a stream identifier's reserved high bit -- RFC 9113
/// section 4.1, *"a reserved 1-bit field \[whose\] value MUST be ignored when
/// receiving"*.
const STREAM_ID_MASK: u32 = 0x7fff_ffff;

/// One parsed frame header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FrameHead {
    /// The payload length the 24-bit field carried.
    pub(crate) length: usize,
    /// The `type` byte, kept raw so an extension type survives the round
    /// trip. [`FrameType::from_u8`] interprets it.
    pub(crate) kind: u8,
    /// The `flags` byte.
    pub(crate) flags: u8,
    /// The stream identifier, with the reserved bit already cleared.
    pub(crate) stream_id: u32,
}

impl FrameHead {
    /// Reads a header from the first [`FRAME_HEADER_LEN`] bytes of `buf`, or
    /// [`None`] when fewer are available.
    pub(crate) fn parse(buf: &[u8]) -> Option<Self> {
        let head = buf.get(..FRAME_HEADER_LEN)?;
        // Indexing is replaced by explicit `get`s so that this function has
        // no panicking path at all -- the slice above already proves the
        // length, but a later edit to `FRAME_HEADER_LEN` should not be able to
        // introduce one.
        let byte =
            |at: usize| -> u32 { head.get(at).copied().unwrap_or(0).into() };
        let length = ((byte(0) << 16) | (byte(1) << 8) | byte(2)) as usize;
        let raw_id =
            (byte(5) << 24) | (byte(6) << 16) | (byte(7) << 8) | byte(8);
        Some(Self {
            length,
            kind: head.get(3).copied().unwrap_or(0),
            flags: head.get(4).copied().unwrap_or(0),
            stream_id: raw_id & STREAM_ID_MASK,
        })
    }

    /// The type this header names, or [`None`] for an extension type.
    pub(crate) const fn frame_type(self) -> Option<FrameType> {
        FrameType::from_u8(self.kind)
    }

    /// Whether the `ACK` flag is set.
    pub(crate) const fn is_ack(self) -> bool {
        (self.flags & FRAME_FLAG_ACK) != 0
    }

    /// How many bytes the whole frame occupies, header included.
    pub(crate) const fn total_len(self) -> usize {
        FRAME_HEADER_LEN + self.length
    }
}

/// Serialises one frame -- a nine-byte header followed by `payload`.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] when `payload` will not fit a 24-bit length field.
/// The condition is unreachable for every frame this module builds -- the
/// largest is a GOAWAY carrying an eight-byte reason -- and is checked anyway
/// because the alternative is a silently truncated length field, which is a
/// protocol error the peer diagnoses rather than we do.
pub(crate) fn frame(
    kind: FrameType,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> CodeResult<Vec<u8>> {
    if payload.len() > FRAME_MAX_PAYLOAD_LEN {
        return Err(CURLcode::TooLarge);
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    let length = payload.len() as u32;
    out.push((length >> 16) as u8);
    out.push((length >> 8) as u8);
    out.push(length as u8);
    out.push(kind.as_u8());
    out.push(flags);
    out.extend_from_slice(&(stream_id & STREAM_ID_MASK).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

// ---------------------------------------------------------------------------
// 4. SETTINGS -- `populate_settings` (`lib/http2.c:222-237`).

/// `H2_SETTINGS_IV_LEN` (`lib/http2.c:89`): how many entries
/// [`populate_settings`] writes.
///
/// The C declares `nghttp2_settings_entry iv[H2_SETTINGS_IV_LEN]` and
/// `populate_settings` fills `iv[0]`, `iv[1]` and `iv[2]` before returning 3,
/// so the array length and the return value are the same fact stated twice.
/// Here it is stated once, as the length of [`SettingsTable::entries`].
pub(crate) const H2_SETTINGS_IV_LEN: usize = 3;

/// `H2_BINSETTINGS_LEN` (`lib/http2.c:90`): the buffer
/// `populate_binsettings` packs into.
///
/// 80 bytes, which is generous -- three entries occupy 18 -- and the
/// generosity is the point: `nghttp2_pack_settings_payload` is given this as
/// its capacity and fails rather than overrunning. [`binsettings`] keeps the
/// bound and reports the same failure, because the `h2c` upgrade path treats
/// a failed pack as [`CURLcode::FailedInit`] (`lib/http2.c:1647-1651`).
pub(crate) const H2_BINSETTINGS_LEN: usize = 80;

/// How many bytes one SETTINGS entry occupies -- RFC 9113 section 6.5.1: a
/// 16-bit identifier followed by a 32-bit value.
pub(crate) const SETTINGS_ENTRY_LEN: usize = 6;

/// A SETTINGS parameter identifier -- RFC 9113 section 6.5.2 and the
/// `NGHTTP2_SETTINGS_*` enumerators.
///
/// Only the three curl sends are named plus the two it never sends but may
/// receive, because an identifier this module cannot name is one it must
/// ignore: RFC 9113 section 6.5.2 requires *"an endpoint that receives a
/// SETTINGS frame with any unknown or unsupported identifier MUST ignore that
/// setting"*.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // receive-side identifiers are exercised in tests
pub(crate) enum SettingsId {
    /// `SETTINGS_HEADER_TABLE_SIZE` -- 0x01.
    HeaderTableSize,
    /// `SETTINGS_ENABLE_PUSH` -- 0x02. `iv[2]` in `populate_settings`.
    EnablePush,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` -- 0x03. `iv[0]`.
    MaxConcurrentStreams,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` -- 0x04. `iv[1]`.
    InitialWindowSize,
    /// `SETTINGS_MAX_FRAME_SIZE` -- 0x05.
    MaxFrameSize,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` -- 0x06.
    MaxHeaderListSize,
}

impl SettingsId {
    /// The 16-bit identifier.
    pub(crate) const fn as_u16(self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x0001,
            Self::EnablePush => 0x0002,
            Self::MaxConcurrentStreams => 0x0003,
            Self::InitialWindowSize => 0x0004,
            Self::MaxFrameSize => 0x0005,
            Self::MaxHeaderListSize => 0x0006,
        }
    }

    /// The identifier a 16-bit field names, or [`None`] for one this module
    /// must ignore.
    #[allow(dead_code)] // exercised by SETTINGS parser tests
    pub(crate) const fn from_u16(raw: u16) -> Option<Self> {
        match raw {
            0x0001 => Some(Self::HeaderTableSize),
            0x0002 => Some(Self::EnablePush),
            0x0003 => Some(Self::MaxConcurrentStreams),
            0x0004 => Some(Self::InitialWindowSize),
            0x0005 => Some(Self::MaxFrameSize),
            0x0006 => Some(Self::MaxHeaderListSize),
            _ => None,
        }
    }
}

/// One entry of a SETTINGS payload -- `nghttp2_settings_entry`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SettingsEntry {
    /// `settings_id`.
    pub(crate) id: SettingsId,
    /// `value`.
    pub(crate) value: u32,
}

impl SettingsEntry {
    /// An entry, spelled the way the C's two assignments read.
    pub(crate) const fn new(id: SettingsId, value: u32) -> Self {
        Self { id, value }
    }

    /// The six bytes RFC 9113 section 6.5.1 specifies, big-endian throughout.
    pub(crate) fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.as_u16().to_be_bytes());
        out.extend_from_slice(&self.value.to_be_bytes());
    }
}

/// The three settings curl announces, in curl's order.
///
/// The order IS the contract. `populate_settings` (`lib/http2.c:222-237`)
/// writes `iv[0]` = MAX_CONCURRENT_STREAMS, `iv[1]` = INITIAL_WINDOW_SIZE,
/// `iv[2]` = ENABLE_PUSH, and that sequence reaches the wire twice over: as
/// the payload of the initial SETTINGS frame, and -- base64url-encoded -- as
/// the value of the `HTTP2-Settings` header of an `h2c` upgrade, which
/// 1,476 fixtures compare as part of one joined string.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SettingsTable {
    /// The three entries, in the C's assignment order.
    pub(crate) entries: [SettingsEntry; H2_SETTINGS_IV_LEN],
}

impl SettingsTable {
    /// `populate_settings(iv, data, ctx)` (`lib/http2.c:222-237`).
    ///
    /// * `max_concurrent_streams` is `Curl_multi_max_concurrent_streams(
    ///   data->multi)`, which the multi handle owns and this file is handed.
    /// * `initial_window_size` is [`initial_win_size`]'s answer. The C also
    ///   writes it back into `ctx->initial_win_size` when a context was passed
    ///   (`:231-232`); that write is [`H2ConnCtx::apply_settings`]'s job here,
    ///   so this function stays pure and a test can assert its bytes without
    ///   building a connection.
    /// * `enable_push` is `data->multi->push_cb != NULL` -- ONE exactly when a
    ///   push callback is registered, and zero otherwise.
    ///
    /// The `#[rustfmt::skip]` is on the table literal because the ORDER of
    /// those three lines is the wire contract, and an item a formatter may
    /// rewrite is an item whose order is not guaranteed.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[rustfmt::skip]
    pub(crate) const fn populate(
        max_concurrent_streams: u32,
        initial_window_size: u32,
        push_callback_registered: bool,
    ) -> Self {
        Self {
            entries: [
                SettingsEntry::new(SettingsId::MaxConcurrentStreams, max_concurrent_streams),
                SettingsEntry::new(SettingsId::InitialWindowSize, initial_window_size),
                SettingsEntry::new(SettingsId::EnablePush, push_callback_registered as u32),
            ],
        }
    }

    /// The announced MAX_CONCURRENT_STREAMS -- `iv[0].value`.
    #[allow(dead_code)] // consumer: this module's tests
    pub(crate) const fn max_concurrent_streams(&self) -> u32 {
        self.entries[0].value
    }

    /// The announced INITIAL_WINDOW_SIZE -- `iv[1].value`, which the C copies
    /// into `ctx->initial_win_size`.
    pub(crate) const fn initial_window_size(&self) -> u32 {
        self.entries[1].value
    }

    /// The announced ENABLE_PUSH -- `iv[2].value`.
    #[allow(dead_code)] // consumer: this module's tests
    pub(crate) const fn enable_push(&self) -> u32 {
        self.entries[2].value
    }
}

/// `nghttp2_pack_settings_payload(buf, H2_BINSETTINGS_LEN, iv, ivlen)` as
/// `populate_binsettings` calls it (`lib/http2.c:239-249`).
///
/// Eighteen bytes for three entries, big-endian, in the table's order and
/// with nothing else -- no frame header, because a SETTINGS PAYLOAD is what
/// both consumers want: [`settings_frame`] prepends the header, and
/// [`binsettings`] base64url-encodes the payload alone.
///
/// # Errors
///
/// [`CURLcode::FailedInit`] when the payload would exceed
/// [`H2_BINSETTINGS_LEN`]. That is the code the C's own caller produces for a
/// failed pack (`lib/http2.c:1648-1650`, `failf` *"nghttp2 unexpectedly
/// failed on pack_settings_payload"*), so the bound is enforced here and
/// reported in the C's currency rather than being left to overrun a buffer
/// that no longer exists.
pub(crate) fn pack_settings_payload(
    table: &SettingsTable,
) -> CodeResult<Vec<u8>> {
    let needed = table.entries.len() * SETTINGS_ENTRY_LEN;
    if needed > H2_BINSETTINGS_LEN {
        return Err(CURLcode::FailedInit);
    }
    let mut out = Vec::with_capacity(needed);
    for entry in &table.entries {
        entry.encode(&mut out);
    }
    Ok(out)
}

/// The initial SETTINGS frame: a nine-byte header over
/// [`pack_settings_payload`]'s eighteen.
///
/// `nghttp2_submit_settings(ctx->h2, NGHTTP2_FLAG_NONE, iv, ivlen)`
/// (`lib/http2.c:2457-2458`) -- flags NONE, stream 0.
///
/// # Errors
///
/// As [`pack_settings_payload`], plus [`CURLcode::TooLarge`] from [`frame`],
/// which three entries cannot reach.
pub(crate) fn settings_frame(table: &SettingsTable) -> CodeResult<Vec<u8>> {
    let payload = pack_settings_payload(table)?;
    frame(FrameType::Settings, FRAME_FLAG_NONE, 0, &payload)
}

/// The SETTINGS acknowledgement RFC 9113 section 6.5.3 requires of a
/// receiver: `ACK` set, and an EMPTY payload.
///
/// nghttp2 queues this itself, which is why no `submit` call for it appears in
/// `lib/http2.c`; the obligation is the protocol's rather than curl's, and
/// [`H2ConnCtx::ingest`] discharges it.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`frame`], unreachable for an empty payload.
#[allow(dead_code)] // exercised by SETTINGS parser tests
pub(crate) fn settings_ack_frame() -> CodeResult<Vec<u8>> {
    frame(FrameType::Settings, FRAME_FLAG_ACK, 0, &[])
}

/// `cf_h2_update_settings(ctx, initial_win_size)` (`lib/http2.c:251-261`): a
/// SETTINGS frame carrying INITIAL_WINDOW_SIZE and nothing else.
///
/// One entry, not three. `h2_submit` sends it only when
/// [`initial_win_size`]'s answer has CHANGED since the last announcement
/// (`lib/http2.c:2114-2119`), so an unchanged rate limit puts no frame on the
/// wire at all -- which is the observable half of the behaviour.
///
/// # Errors
///
/// [`CURLcode::SendError`], which is what the C returns when
/// `nghttp2_submit_settings` fails at `:257-258`. Serialising cannot fail for
/// a six-byte payload, so the code is stated for the contract rather than
/// reachable by it.
pub(crate) fn settings_window_update_frame(
    initial_win_size: u32,
) -> CodeResult<Vec<u8>> {
    let mut payload = Vec::with_capacity(SETTINGS_ENTRY_LEN);
    SettingsEntry::new(SettingsId::InitialWindowSize, initial_win_size)
        .encode(&mut payload);
    frame(FrameType::Settings, FRAME_FLAG_NONE, 0, &payload)
        .map_err(|_| CURLcode::SendError)
}

/// The base64url form of the SETTINGS payload -- the value of the
/// `HTTP2-Settings` header of an `h2c` upgrade.
///
/// `curlx_base64url_encode(binsettings, binlen, &base64, &blen)`
/// (`lib/http2.c:1653`), which is UNPADDED and uses the URL-and-filename-safe
/// alphabet. [`crate::util::base64::url_encode`] is that encoder, and it is
/// reached rather than the `base64` crate precisely because it is curl's:
/// specification 0.6.7's byte-exact comparison reaches this string.
///
/// # Errors
///
/// [`CURLcode::FailedInit`] as [`pack_settings_payload`] reports it, and
/// whatever [`crate::util::base64::url_encode`] reports -- which for
/// eighteen bytes is nothing.
pub(crate) fn binsettings(table: &SettingsTable) -> CodeResult<String> {
    let payload = pack_settings_payload(table)?;
    // `lib/http2.c:1647` treats a zero-length pack as the same failure as a
    // negative return: `if(!curlx_sztouz(rc, &binlen) || !binlen)`.
    if payload.is_empty() {
        return Err(CURLcode::FailedInit);
    }
    base64::url_encode(&payload)
}

// ---------------------------------------------------------------------------
// 4a. The synchronous filter / asynchronous `h2` boundary.
//
// `h2` is deliberately driven as a sans-executor state machine. Its
// `Connection` owns this in-memory AsyncRead + AsyncWrite pair; the filter
// pumps bytes between these queues and the next connection filter, then polls
// `h2` with the caller's readiness cycle. No task is spawned, no runtime clock
// is read, and no socket is opened here.

/// Shared queues behind [`H2Io`].
///
/// The outbound queue is soft-limited. `AsyncWrite::poll_write` is not allowed
/// to accept half a frame and then forget the rest, while curl's network queue
/// still needs to report full at one chunk for readiness decisions. A soft
/// limit gives both properties: [`BufQ::is_full`] retains curl's one-chunk
/// signal and writes may extend far enough to keep one h2 codec operation
/// atomic.
#[derive(Debug)]
struct H2IoState {
    inbound: BufQ,
    outbound: BufQ,
    staging: Vec<u8>,
    exact_settings: Vec<u8>,
    preface_written: usize,
    settings_rewritten: bool,
    suppress_upgrade_stream1_headers: bool,
    suppressed_continuation_stream: Option<u32>,
}

impl H2IoState {
    fn new(
        exact_settings: Vec<u8>,
        suppress_upgrade_stream1_headers: bool,
    ) -> Self {
        Self {
            inbound: BufQ::with_opts(
                H2_CHUNK_SIZE,
                H2_NW_RECV_CHUNKS,
                BufqOpts::SOFT_LIMIT,
            ),
            outbound: BufQ::with_opts(
                H2_CHUNK_SIZE,
                H2_NW_SEND_CHUNKS,
                BufqOpts::SOFT_LIMIT,
            ),
            staging: Vec::new(),
            exact_settings,
            preface_written: 0,
            settings_rewritten: false,
            suppress_upgrade_stream1_headers,
            suppressed_continuation_stream: None,
        }
    }

    fn queue_outbound(&mut self, bytes: &[u8]) -> io::Result<()> {
        let written = self.outbound.write(bytes).map_err(bufq_io_error)?;
        if written != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "HTTP/2 codec output queue accepted a partial frame",
            ));
        }
        Ok(())
    }

    fn accept_codec_bytes(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.staging.extend_from_slice(bytes);
        self.process_codec_bytes()?;
        Ok(bytes.len())
    }

    fn process_codec_bytes(&mut self) -> io::Result<()> {
        if self.preface_written < H2_CLIENT_PREFACE.len() {
            let needed = H2_CLIENT_PREFACE.len() - self.preface_written;
            let take = needed.min(self.staging.len());
            if take != 0 {
                let expected = H2_CLIENT_PREFACE
                    .get(self.preface_written..self.preface_written + take)
                    .unwrap_or_default();
                let actual = self.staging.get(..take).unwrap_or_default();
                if actual != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "h2 emitted an invalid client connection preface",
                    ));
                }
                let prefix: Vec<u8> = self.staging.drain(..take).collect();
                self.queue_outbound(&prefix)?;
                self.preface_written += take;
            }
            if self.preface_written < H2_CLIENT_PREFACE.len() {
                return Ok(());
            }
        }

        loop {
            let Some(head) = FrameHead::parse(&self.staging) else {
                return Ok(());
            };
            if self.staging.len() < head.total_len() {
                return Ok(());
            }
            let whole: Vec<u8> =
                self.staging.drain(..head.total_len()).collect();
            let kind = head.frame_type();

            if !self.settings_rewritten
                && kind == Some(FrameType::Settings)
                && !head.is_ack()
                && head.stream_id == 0
            {
                let settings = self.exact_settings.clone();
                self.queue_outbound(&settings)?;
                self.settings_rewritten = true;
                continue;
            }

            // The h2 session is configured with a deliberately permissive
            // receive window so it never rejects bytes that curl's own window
            // decisions admitted. Its automatic WINDOW_UPDATE frames are
            // therefore bookkeeping only and must not reach the wire; the
            // explicit decisions in `apply_window_change` do.
            if kind == Some(FrameType::WindowUpdate) {
                continue;
            }

            if kind == Some(FrameType::Headers)
                && head.stream_id == 1
                && self.suppress_upgrade_stream1_headers
            {
                if (head.flags & FRAME_FLAG_END_HEADERS) != 0 {
                    self.suppress_upgrade_stream1_headers = false;
                } else {
                    self.suppressed_continuation_stream = Some(1);
                }
                continue;
            }

            if kind == Some(FrameType::Continuation)
                && self.suppressed_continuation_stream == Some(head.stream_id)
            {
                if (head.flags & FRAME_FLAG_END_HEADERS) != 0 {
                    self.suppressed_continuation_stream = None;
                    self.suppress_upgrade_stream1_headers = false;
                }
                continue;
            }

            self.queue_outbound(&whole)?;
        }
    }
}

fn bufq_io_error(code: CURLcode) -> io::Error {
    let kind = if code == CURLcode::Again {
        io::ErrorKind::WouldBlock
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, format!("HTTP/2 buffer queue error: {code:?}"))
}

/// The queue handle retained by the filter while [`h2::client::Connection`]
/// owns the [`H2Io`] endpoint.
#[derive(Clone, Debug)]
struct H2IoHandle {
    state: Arc<Mutex<H2IoState>>,
}

impl H2IoHandle {
    fn lock(&self) -> MutexGuard<'_, H2IoState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn push_input(&self, bytes: &[u8]) -> CodeResult<usize> {
        let mut state = self.lock();
        let written = state.inbound.write(bytes)?;
        if written == bytes.len() {
            Ok(written)
        } else {
            Err(CURLcode::RecvError)
        }
    }

    fn read_output(&self, bytes: &mut [u8]) -> CodeResult<usize> {
        self.lock().outbound.read(bytes)
    }

    fn pending_output(&self) -> usize {
        self.lock().outbound.len()
    }

    #[cfg(test)]
    fn settings_rewritten(&self) -> bool {
        self.lock().settings_rewritten
    }
}

/// Async I/O presented to `h2`; all actual network I/O remains in the filter
/// chain.
#[derive(Debug)]
struct H2Io {
    handle: H2IoHandle,
}

impl H2Io {
    fn new(
        exact_settings: Vec<u8>,
        suppress_upgrade_stream1_headers: bool,
    ) -> (Self, H2IoHandle) {
        let handle = H2IoHandle {
            state: Arc::new(Mutex::new(H2IoState::new(
                exact_settings,
                suppress_upgrade_stream1_headers,
            ))),
        };
        (
            Self {
                handle: handle.clone(),
            },
            handle,
        )
    }
}

impl AsyncRead for H2Io {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let target = buf.initialize_unfilled();
        match self.handle.lock().inbound.read(target) {
            Ok(read) => {
                buf.advance(read);
                Poll::Ready(Ok(()))
            }
            Err(CURLcode::Again) => Poll::Pending,
            Err(code) => Poll::Ready(Err(bufq_io_error(code))),
        }
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.handle.lock().accept_codec_bytes(buf))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let result = self.handle.lock().process_codec_bytes();
        Poll::Ready(result)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

// ---------------------------------------------------------------------------
// 5. Window sizing -- `cf_h2_initial_win_size` (`lib/http2.c:209-220`) and
//    `cf_h2_update_local_win` (`:308-354`).

/// The floor the C clamps a rate-limited window to, with its own comment:
/// *"It needs to be at least 8k or servers may be unhappy"* (`lib/http2.c:
/// 213-214`).
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
pub(crate) const H2_MIN_RATE_LIMITED_WINDOW: u32 = 8192;

/// `cf_h2_initial_win_size(data)` (`lib/http2.c:209-220`).
///
/// The C, transcribed:
///
/// ```c
/// curl_off_t rps = Curl_rlimit_per_step(&data->progress.dl.rlimit);
/// if((rps > 0) && (rps < H2_STREAM_WINDOW_SIZE_INITIAL))
///   return CURLMAX((uint32_t)rps, 8192);
/// return H2_STREAM_WINDOW_SIZE_INITIAL;
/// ```
///
/// Both halves of the conjunction are load-bearing and both are easy to lose:
///
/// * `rps > 0` means an INACTIVE limiter -- `Curl_rlimit_per_step` answers 0
///   for one -- takes the default rather than a window of zero, which would
///   stall the stream before it started.
/// * `rps < H2_STREAM_WINDOW_SIZE_INITIAL` means a limit ABOVE 64 KiB is no
///   limit at all as far as the window is concerned, so it also takes the
///   default. A rate limit is a ceiling on throughput, not a request to
///   enlarge a buffer.
///
/// The clamp is then `CURLMAX(rps, 8192)`, so a limit of 100 bytes per step
/// still announces 8192.
///
/// The limiter arrives as a borrowed [`RateLimit`] rather than being reached
/// through a handle, which is specification 0.3.3's pattern P12 applied: the
/// answer is a pure function of the limiter and a test states one without
/// building a transfer.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
#[must_use]
pub(crate) fn initial_win_size(rlimit: &RateLimit) -> u32 {
    let rps = rlimit.per_step();
    // The comparison is performed in `i64`, as the C's is in `curl_off_t`, so
    // that a rate above `u32::MAX` cannot wrap into the window range on the
    // way to the test. `H2_STREAM_WINDOW_SIZE_INITIAL` is 65,536 and fits
    // every integer type involved.
    if rps > 0 && rps < H2_STREAM_WINDOW_SIZE_INITIAL as i64 {
        // The cast cannot truncate: `rps` is inside `0..65_536` here.
        let rps = rps as u32;
        return if rps > H2_MIN_RATE_LIMITED_WINDOW {
            rps
        } else {
            H2_MIN_RATE_LIMITED_WINDOW
        };
    }
    // `H2_STREAM_WINDOW_SIZE_INITIAL` is 65,536, well inside `u32`.
    H2_STREAM_WINDOW_SIZE_INITIAL as u32
}

/// `cf_h2_get_desired_local_win(cf, data)` (`lib/http2.c:292-306`).
///
/// The C, transcribed:
///
/// ```c
/// curl_off_t avail = Curl_rlimit_avail(&data->progress.dl.rlimit,
///                                      Curl_pgrs_now(data));
/// if(avail < CURL_OFF_T_MAX) {   /* limit in place */
///   if(avail <= 0)          return 0;
///   else if(avail < INT32_MAX) return (int32_t)avail;
/// }
/// return H2_STREAM_WINDOW_SIZE_MAX;
/// ```
///
/// `CURL_OFF_T_MAX` is the sentinel [`RateLimit::available`] answers for an
/// UNLIMITED limiter, so the outer test is *"is there a limit at all"* and the
/// three results are: no limit or a limit larger than [`i32::MAX`] gives the
/// unthrottled maximum; an exhausted budget gives zero, which closes the
/// window; anything else gives the remaining budget verbatim.
///
/// `now` is the injected clock's reading rather than
/// `Curl_pgrs_now(data)` reaching for the process clock, which is
/// specification 0.3.3 P12 again -- and the reason this file contains no
/// `Instant::now` at all.
#[must_use]
pub(crate) fn desired_local_win(rlimit: &mut RateLimit, now: CurlTime) -> i32 {
    let avail = rlimit.available(now);
    if avail < i64::MAX {
        if avail <= 0 {
            return 0;
        }
        if avail < i64::from(i32::MAX) {
            // Inside `1..i32::MAX`, so the cast is exact.
            return avail as i32;
        }
    }
    // `H2_STREAM_WINDOW_SIZE_MAX` is 10,485,760, well inside `i32`.
    H2_STREAM_WINDOW_SIZE_MAX as i32
}

/// What `cf_h2_update_local_win` decides to do about one stream's receive
/// window (`lib/http2.c:308-354`).
///
/// The C performs the decision and the two nghttp2 calls in one function; they
/// are split here so the DECISION is a pure function a test can assert
/// exhaustively, and so the `WINDOW_UPDATE` increment -- which is
/// wire-observable, and which specification 0.8.1 freezes -- is a value rather
/// than a side effect.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum LocalWindowChange {
    /// `if(dwsize != stream->local_window_size)` was false: the C does
    /// nothing, sends nothing, and leaves the recorded size alone.
    Unchanged,
    /// `dwsize > wsize`: set the local window size AND submit a
    /// `WINDOW_UPDATE` for the difference (`lib/http2.c:321-339`). The C's
    /// trace line is *"\[%d\] local window update by %d"* with the increment.
    Grow {
        /// The new `stream->local_window_size`.
        size: i32,
        /// The `WINDOW_UPDATE` increment: `dwsize - wsize`.
        increment: i32,
    },
    /// `dwsize <= wsize`: set the local window size and send NOTHING
    /// (`lib/http2.c:340-351`). The C's trace line is *"\[%d\] local window
    /// size now %d"*, with no increment because there is no frame.
    Shrink {
        /// The new `stream->local_window_size`.
        size: i32,
    },
}

impl LocalWindowChange {
    /// The whole of `cf_h2_update_local_win`'s branching.
    ///
    /// * `desired` is [`desired_local_win`]'s answer, ALREADY forced to zero
    ///   for a paused stream or one whose write failed --
    ///   `dwsize = (stream->write_paused || stream->xfer_result) ? 0 : ...`
    ///   (`lib/http2.c:316-317`). Forcing is the caller's because both inputs
    ///   are stream state; see [`H2StreamCtx::local_window_target`].
    /// * `recorded` is `stream->local_window_size`.
    /// * `effective` is
    ///   `nghttp2_session_get_stream_effective_local_window_size()`, the size
    ///   the peer is currently working to, which may lag `recorded` because a
    ///   `WINDOW_UPDATE` has to be acknowledged by consumption rather than by
    ///   a frame.
    #[must_use]
    pub(crate) const fn decide(
        desired: i32,
        recorded: i32,
        effective: i32,
    ) -> Self {
        if desired == recorded {
            Self::Unchanged
        } else if desired > effective {
            Self::Grow {
                size: desired,
                // Both are non-negative and `desired > effective`, so the
                // difference is positive and cannot overflow.
                increment: desired - effective,
            }
        } else {
            Self::Shrink { size: desired }
        }
    }

    /// The `WINDOW_UPDATE` increment this change puts on the wire, or [`None`]
    /// when it puts none there.
    #[must_use]
    pub(crate) const fn increment(self) -> Option<i32> {
        match self {
            Self::Grow { increment, .. } => Some(increment),
            Self::Unchanged | Self::Shrink { .. } => None,
        }
    }

    /// The size to record in `stream->local_window_size`, or [`None`] when the
    /// recorded size does not move.
    #[must_use]
    pub(crate) const fn recorded_size(self) -> Option<i32> {
        match self {
            Self::Grow { size, .. } | Self::Shrink { size } => Some(size),
            Self::Unchanged => None,
        }
    }
}

// ---------------------------------------------------------------------------
// 6. The control frames curl itself submits.

/// `nghttp2_submit_window_update(h2, NGHTTP2_FLAG_NONE, stream_id, increment)`
/// (`lib/http2.c:329-330`) -- RFC 9113 section 6.9.
///
/// `stream_id` of 0 addresses the CONNECTION window, which is what
/// `cf_h2_ctx_open`'s `set_local_window_size(..., 0,
/// HTTP2_HUGE_WINDOW_SIZE)` at `lib/http2.c:2467` amounts to on the wire.
///
/// # Errors
///
/// [`CURLcode::Http2`] for a non-positive increment, which RFC 9113 section
/// 6.9 makes a `PROTOCOL_ERROR` and which is the code the C reports for a
/// failed `nghttp2_submit_window_update` (`lib/http2.c:331-334`).
pub(crate) fn window_update_frame(
    stream_id: u32,
    increment: i32,
) -> CodeResult<Vec<u8>> {
    if increment <= 0 {
        return Err(CURLcode::Http2);
    }
    // Non-negative, so the cast is exact; the reserved high bit is clear
    // because `increment` is bounded by `i32::MAX`.
    let payload = (increment as u32).to_be_bytes();
    frame(
        FrameType::WindowUpdate,
        FRAME_FLAG_NONE,
        stream_id,
        &payload,
    )
    .map_err(|_| CURLcode::Http2)
}

/// `nghttp2_submit_rst_stream(h2, NGHTTP2_FLAG_NONE, stream_id, error)`
/// (`lib/http2.c:440-441`) -- RFC 9113 section 6.4.
///
/// `http2_data_done` sends this with `NGHTTP2_STREAM_CLOSED` when a transfer
/// ends before its stream did, and `on_header` sends it with
/// `NGHTTP2_PROTOCOL_ERROR` for a `PUSH_PROMISE` from a server that is not
/// authoritative for the promised authority (`lib/http2.c:1443-1444`).
///
/// # Errors
///
/// [`CURLcode::Http2`] from [`frame`], unreachable for a four-byte payload.
pub(crate) fn rst_stream_frame(
    stream_id: u32,
    error: H2Error,
) -> CodeResult<Vec<u8>> {
    let payload = error.as_u32().to_be_bytes();
    frame(FrameType::RstStream, FRAME_FLAG_NONE, stream_id, &payload)
        .map_err(|_| CURLcode::Http2)
}

/// `nghttp2_submit_ping(h2, 0, ZERO_NULL)` (`lib/http2.c:579`) -- RFC 9113
/// section 6.7.
///
/// The C passes a null opaque-data pointer, which nghttp2 documents as
/// meaning *"zero-cleared"*, so the eight payload bytes are zero. Flags NONE:
/// this is a ping, not the acknowledgement of one.
///
/// # Errors
///
/// [`CURLcode::Http2`], which is what the C returns when the submit fails
/// (`lib/http2.c:580-584`).
#[allow(dead_code)] // exact control-frame bytes are asserted in this module's tests
pub(crate) fn ping_frame() -> CodeResult<Vec<u8>> {
    frame(FrameType::Ping, FRAME_FLAG_NONE, 0, &[0u8; 8])
        .map_err(|_| CURLcode::Http2)
}

/// The `PING` acknowledgement RFC 9113 section 6.7 requires: `ACK` set and the
/// received opaque data echoed VERBATIM.
///
/// nghttp2 queues this itself, which is why no submit call appears in
/// `lib/http2.c`; [`H2ConnCtx::ingest`] discharges the obligation.
///
/// # Errors
///
/// [`CURLcode::Http2`] when `opaque` is not the eight bytes RFC 9113 fixes,
/// which is a `FRAME_SIZE_ERROR` on the wire and a caller bug here.
#[allow(dead_code)] // exercised by PING parser tests
pub(crate) fn ping_ack_frame(opaque: &[u8]) -> CodeResult<Vec<u8>> {
    if opaque.len() != 8 {
        return Err(CURLcode::Http2);
    }
    frame(FrameType::Ping, FRAME_FLAG_ACK, 0, opaque)
        .map_err(|_| CURLcode::Http2)
}

/// The debug data `cf_h2_shutdown` sends with its GOAWAY
/// (`lib/http2.c:2587-2588`).
///
/// The C passes `sizeof("shutdown")`, which INCLUDES the terminating NUL, so
/// nine bytes reach the wire and the ninth is zero. That is a quirk rather
/// than a mistake -- RFC 9113 section 6.8 makes the debug data opaque and of
/// any length -- and it is preserved byte for byte, because the debug data of
/// a GOAWAY is exactly the kind of thing a peer logs.
#[rustfmt::skip]
pub(crate) const H2_SHUTDOWN_REASON: &[u8] = b"shutdown\0";

/// `nghttp2_submit_goaway(h2, NGHTTP2_FLAG_NONE, last_stream_id, 0,
/// "shutdown", sizeof("shutdown"))` (`lib/http2.c:2585-2588`) -- RFC 9113
/// section 6.8.
///
/// The error code is 0, `NO_ERROR`: this is a graceful shutdown and the C says
/// so. `last_stream_id` is `ctx->local_max_sid`, the highest stream identifier
/// this endpoint has processed.
///
/// # Errors
///
/// [`CURLcode::SendError`], which is what the C returns when the submit fails
/// (`lib/http2.c:2589-2593`).
pub(crate) fn goaway_frame(
    last_stream_id: i32,
    error: H2Error,
    debug: &[u8],
) -> CodeResult<Vec<u8>> {
    let mut payload = Vec::with_capacity(8 + debug.len());
    // A negative identifier cannot reach the wire: RFC 9113 makes the field 31
    // bits and `STREAM_ID_MASK` clears the reserved bit, so a negative value
    // is clamped to zero rather than sign-extended into the reserved bit.
    let last = if last_stream_id < 0 {
        0
    } else {
        last_stream_id as u32 & STREAM_ID_MASK
    };
    payload.extend_from_slice(&last.to_be_bytes());
    payload.extend_from_slice(&error.as_u32().to_be_bytes());
    payload.extend_from_slice(debug);
    frame(FrameType::Goaway, FRAME_FLAG_NONE, 0, &payload)
        .map_err(|_| CURLcode::SendError)
}

// ---------------------------------------------------------------------------
// 7. HTTP/2 error codes -- the one part of `h2`'s public surface whose values
//    are the protocol's own, and therefore byte-compatible with nghttp2's.

/// An HTTP/2 error code -- `nghttp2_error_code`, RFC 9113 section 7.
///
/// A newtype over [`h2::Reason`] rather than a fresh enumeration, because
/// `h2::Reason`'s fourteen constants ARE the registry: `NO_ERROR` is 0 through
/// `HTTP_1_1_REQUIRED` at 13, exactly as `NGHTTP2_NO_ERROR` through
/// `NGHTTP2_HTTP_1_1_REQUIRED`. That is the part of `h2` this module consumes
/// directly, and consuming it means the numbers are stated once in the
/// dependency graph rather than transcribed here.
///
/// The wrapper exists for three reasons the bare `h2::Reason` cannot serve:
///
/// * `stream->error` is a `uint32_t` that may hold a code no registry entry
///   names -- RFC 9113 section 7 reserves the space and requires an unknown
///   code to be treated as `INTERNAL_ERROR` rather than rejected -- and
///   [`Self::as_u32`] round-trips one unchanged;
/// * [`Self::strerror`] must produce `nghttp2_http2_strerror`'s spelling and
///   not `h2::Reason::description`'s, which is a different string; and
/// * it keeps `h2` out of this module's public signatures, so the dependency
///   is an implementation detail rather than part of the contract.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub(crate) struct H2Error(u32);

impl H2Error {
    // The six codes `lib/http2.c` names, as their registry integers.
    //
    // Written as integers rather than as `H2Error(u32::from(h2::Reason::X))`
    // for one mechanical reason: `impl From<Reason> for u32` is not a `const
    // fn` and `Reason`'s field is private, so no `const` expression can reach
    // through it at Rust 1.75. The integers are therefore stated here and
    // `every_error_code_agrees_with_the_h2_registry` asserts each one against
    // `h2::Reason` at test time -- so `h2` remains the authority for the
    // registry and a divergence is a test failure rather than a silent
    // disagreement. [`Self::from_reason`] performs the same conversion at
    // run time, where `From` is available.

    /// `NGHTTP2_NO_ERROR` -- the value `h2_stream_ctx_create` initialises
    /// `stream->error` to (`lib/http2.c:285`).
    pub(crate) const NO_ERROR: Self = Self(0);

    /// `NGHTTP2_PROTOCOL_ERROR` -- the code `on_header` resets a
    /// non-authoritative `PUSH_PROMISE` with (`lib/http2.c:1444`).
    pub(crate) const PROTOCOL_ERROR: Self = Self(1);

    /// `NGHTTP2_INTERNAL_ERROR` -- what RFC 9113 section 7 requires an
    /// unrecognised code to be treated as.
    #[allow(dead_code)] // consumer: this module's tests
    pub(crate) const INTERNAL_ERROR: Self = Self(2);

    /// `NGHTTP2_STREAM_CLOSED` -- the code `http2_data_done` resets a
    /// prematurely finished stream with (`lib/http2.c:441`).
    #[allow(dead_code)] // exact RST_STREAM bytes are asserted in tests
    pub(crate) const STREAM_CLOSED: Self = Self(5);

    /// `NGHTTP2_REFUSED_STREAM` -- the code `http2_handle_stream_close`
    /// singles out for a retry on a fresh connection (`lib/http2.c:1682`).
    pub(crate) const REFUSED_STREAM: Self = Self(7);

    /// `NGHTTP2_HTTP_1_1_REQUIRED` -- the code `Curl_h2_http_1_1_error` tests
    /// for (`lib/http2.c:2964`).
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    pub(crate) const HTTP_1_1_REQUIRED: Self = Self(13);

    /// The code a wire field carried, whether or not the registry names it.
    #[must_use]
    #[allow(dead_code)] // exercised by control-frame parser tests
    pub(crate) const fn from_u32(raw: u32) -> Self {
        Self(raw)
    }

    /// The code a [`h2::Reason`] names.
    ///
    /// The run-time conversion, which is where `h2`'s own `From` is usable.
    /// This is the path an `h2::Error` carrying a reason takes on its way to
    /// `stream->error`.
    #[must_use]
    #[allow(dead_code)] // consumer: the multiplexer that reports h2's errors
    pub(crate) fn from_reason(reason: h2::Reason) -> Self {
        Self(u32::from(reason))
    }

    /// The raw code, for the four-byte field of a `RST_STREAM` or `GOAWAY`.
    #[must_use]
    pub(crate) const fn as_u32(self) -> u32 {
        self.0
    }

    /// Whether this is `NO_ERROR`, which is what `stream->error ?` tests at
    /// `lib/http2.c:1700`.
    #[must_use]
    pub(crate) const fn is_error(self) -> bool {
        self.0 != 0
    }

    /// `nghttp2_http2_strerror(error)`, whose spelling the C splices into the
    /// `failf` of `http2_handle_stream_close` (`lib/http2.c:1697-1699`).
    ///
    /// nghttp2 answers the REGISTRY NAME -- `"PROTOCOL_ERROR"`, not a
    /// sentence -- and `"unknown"` for a code outside the registry. That is a
    /// different string from [`h2::Reason::description`], which renders
    /// `"unspecific protocol error detected"`, so the mapping is written here
    /// rather than delegated. Nothing in `tests/data` compares these strings,
    /// which is why they are diagnostics rather than frozen wire bytes -- but
    /// they reach `CURLOPT_ERRORBUFFER`, so they are still reproduced.
    #[must_use]
    #[rustfmt::skip]
    pub(crate) const fn strerror(self) -> &'static str {
        match self.0 {
            0  => "NO_ERROR",
            1  => "PROTOCOL_ERROR",
            2  => "INTERNAL_ERROR",
            3  => "FLOW_CONTROL_ERROR",
            4  => "SETTINGS_TIMEOUT",
            5  => "STREAM_CLOSED",
            6  => "FRAME_SIZE_ERROR",
            7  => "REFUSED_STREAM",
            8  => "CANCEL",
            9  => "COMPRESSION_ERROR",
            10 => "CONNECT_ERROR",
            11 => "ENHANCE_YOUR_CALM",
            12 => "INADEQUATE_SECURITY",
            13 => "HTTP_1_1_REQUIRED",
            _  => "unknown",
        }
    }
}

/// Renders the registry name rather than the integer, because every consumer
/// of this type -- a trace line, a `failf`, a test failure -- wants the name.
impl fmt::Debug for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H2Error({}, {})", self.0, self.strerror())
    }
}

/// `nghttp2_http2_strerror`'s spelling, for a `failf` that splices it.
impl fmt::Display for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.strerror())
    }
}

/// `Curl_h2_http_1_1_error(data)` (`lib/http2.c:2960-2967`).
///
/// The C's own comment is the whole of the contract: *"Only call this function
/// for a transfer that already got an HTTP/2 CURLE_HTTP2_STREAM error!"* It
/// reads the stream error through `Curl_conn_get_stream_error`, which is the
/// [`CfQuery::StreamError`] query, and compares it against
/// `NGHTTP2_HTTP_1_1_REQUIRED`. The version test the C performs first --
/// `Curl_conn_http_version(data, data->conn) == 20` -- is the caller's, because
/// the caller is the one holding the connection.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
#[must_use]
pub(crate) fn is_http_1_1_required(stream_error: H2Error) -> bool {
    stream_error == H2Error::HTTP_1_1_REQUIRED
}

// ---------------------------------------------------------------------------
// 8. The `h2c` upgrade -- `Curl_http2_request_upgrade`
//    (`lib/http2.c:1635-1671`).

/// `Curl_http2_request_upgrade(req, data)` (`lib/http2.c:1635-1671`): append
/// the two headers that ask an HTTP/1.1 server to switch to HTTP/2.
///
/// The bytes, exactly as `curlx_dyn_addf` writes them at `:1661-1664`:
///
/// ```text
/// Upgrade: h2c\r\nHTTP2-Settings: <base64url of the SETTINGS payload>\r\n
/// ```
///
/// # What this function does NOT write, and why that matters
///
/// It does not write `Connection: Upgrade, HTTP2-Settings`. That line is the
/// `H1_HD_CONNECTION` slot's, built by `http_add_connection_hd` from the two
/// state flags this function sets: `lib/http.c:2795-2801` appends the token
/// `Upgrade` when `data->state.http_hd_upgrade` is set and
/// `HTTP2-Settings` when `data->state.http_hd_h2_settings` is, each with the
/// `", "` separator the slot maintains. `protocols/http1.rs` already
/// implements that slot, so writing the line here as well would emit it twice
/// -- and the ORDER of the two tokens comes from the order of those two
/// `if`s, which is why setting the flags is the whole of this function's
/// contribution to it.
///
/// # The three state writes
///
/// * `state.http_hd_upgrade = true` (`:1659`) -- feeds the `Connection:` slot.
/// * `state.http_hd_h2_settings = true` (`:1660`) -- likewise.
/// * `state.upgr101 = Upgrade101::H2` (`:1667`, `k->upgr101 = UPGR101_H2`) and
///   `state.upgrade_in_progress = true` (`:1668`,
///   `data->conn->bits.upgrade_in_progress = TRUE`) -- what tells the response
///   side to expect a `101 Switching Protocols` and to hand the connection
///   over afterwards.
///
/// The C sets `http_hd_upgrade` and `http_hd_h2_settings` BEFORE the
/// `curlx_dyn_addf` that may fail, and `upgr101` AFTER it -- so a failed
/// append leaves the first two set and the third clear. That ordering is
/// reproduced rather than tidied: `Curl_http` frees the request buffer and
/// abandons the request on a failure here, so the difference is unobservable,
/// and reproducing it costs nothing while diverging would need justifying.
///
/// # Errors
///
/// [`CURLcode::FailedInit`] when the SETTINGS payload cannot be packed, which
/// is the code behind the C's `failf` *"nghttp2 unexpectedly failed on
/// pack_settings_payload"* (`:1648-1650`); and [`CURLcode::TooLarge`] from
/// [`DynBuf`] once the request buffer's 1 MiB ceiling is reached. The C
/// additionally calls `curlx_dyn_free(req)` on both paths; freeing is the
/// caller's here, because ownership of the buffer never leaves
/// `protocols/http1.rs`'s `compose_request` -- which is exactly what
/// [`crate::protocols::http1::UpgradeWriter`]'s own documentation records.
pub(crate) fn request_upgrade(
    req: &mut DynBuf,
    state: &mut RequestState,
    table: &SettingsTable,
) -> CodeResult<()> {
    let base64 = binsettings(table)?;

    // `:1659-1660`, before the append that may fail.
    state.http_hd_upgrade = true;
    state.http_hd_h2_settings = true;

    // `:1661-1664`. Written as three `addn` calls over `#[rustfmt::skip]`
    // literals plus the encoded value, rather than as one format string, so
    // that no formatter and no future edit can reorder or respell the
    // wire-bearing parts. The bytes are identical to the C's
    // "Upgrade: %s\r\nHTTP2-Settings: %s\r\n".
    req.addn(UPGRADE_HEADER_PREFIX)?;
    req.addn(H2C_PROTO_ID)?;
    req.addn(CRLF)?;
    req.addn(H2_SETTINGS_HEADER)?;
    req.addn(COLON_SPACE)?;
    req.addn(base64.as_bytes())?;
    req.addn(CRLF)?;

    // `:1667-1668`, after the append.
    state.upgr101 = Upgrade101::H2;
    state.upgrade_in_progress = true;
    Ok(())
}

/// `"Upgrade: "` -- wire-bearing, hence `#[rustfmt::skip]`.
#[rustfmt::skip]
const UPGRADE_HEADER_PREFIX: &[u8] = b"Upgrade: ";

/// `": "` -- the separator every HTTP/1 header line uses, and the one place
/// this module's emission differs from a push header's (see
/// [`crate::headers::PushHeaders`], whose entries carry a bare colon).
#[rustfmt::skip]
const COLON_SPACE: &[u8] = b": ";

/// `"\r\n"` -- wire-bearing, hence `#[rustfmt::skip]`.
#[rustfmt::skip]
const CRLF: &[u8] = b"\r\n";

/// The [`UpgradeWriter`] `protocols/http1.rs` calls from its
/// `H1_HD_UPGRADE` slot.
///
/// `add_upgrade` (`lib/http.c:2964-2976`) makes two independent contributions
/// in the C's order: `Curl_http2_request_upgrade(req, data)` and then, for a
/// WebSocket scheme, `Curl_ws_request(data, req)`. The two belong to different
/// modules, so this type owns the first and DELEGATES the second to whatever
/// the caller supplies -- which is what makes it composable without either
/// module importing the other.
///
/// The generic parameter defaults to
/// [`crate::protocols::http1::NoUpgrades`], whose `websocket` contributes
/// nothing: that is the C's own behaviour with `CURL_DISABLE_WEBSOCKETS`
/// defined, and it is the right default for a build that has HTTP/2 and not
/// WebSocket.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Http2Upgrade<W = NoUpgrades> {
    /// The three settings to announce, decided by the caller because two of
    /// the three come from the multi handle and the transfer's rate limit.
    table: SettingsTable,
    /// Who writes the WebSocket handshake, when there is one to write.
    websocket: W,
}

impl Http2Upgrade<NoUpgrades> {
    /// An upgrade writer that announces `table` and writes no WebSocket
    /// handshake.
    #[allow(dead_code)] // consumer: the transfer core's request composition
    #[must_use]
    pub(crate) const fn new(table: SettingsTable) -> Self {
        Self {
            table,
            websocket: NoUpgrades,
        }
    }
}

impl<W> Http2Upgrade<W> {
    /// An upgrade writer that announces `table` and delegates the WebSocket
    /// handshake to `websocket`.
    #[allow(dead_code)] // consumer: the transfer core, once ws.rs is wired
    #[must_use]
    pub(crate) const fn with_websocket(
        table: SettingsTable,
        websocket: W,
    ) -> Self {
        Self { table, websocket }
    }

    /// The settings this writer announces.
    #[allow(dead_code)] // consumer: this module's tests
    #[must_use]
    pub(crate) const fn settings(&self) -> &SettingsTable {
        &self.table
    }
}

impl<W: UpgradeWriter + fmt::Debug> UpgradeWriter for Http2Upgrade<W> {
    fn h2c(
        &mut self,
        req: &mut DynBuf,
        state: &mut RequestState,
    ) -> CodeResult<()> {
        request_upgrade(req, state, &self.table)
    }

    fn websocket(
        &mut self,
        req: &mut DynBuf,
        state: &mut RequestState,
        headers: &[String],
    ) -> CodeResult<()> {
        self.websocket.websocket(req, state, headers)
    }
}

// ---------------------------------------------------------------------------
// 9. The ordered field list -- `Curl_http_req_to_h2` (`lib/http.c:4874-4940`)
//    over `Curl_h1_req_parse_read` (`lib/http1.c`), as `h2_submit` chains them
//    at `lib/http2.c:2083-2096`.

/// `H2_NON_FIELD` (`lib/http.c:4822-4830`) -- the connection-specific header
/// fields RFC 9113 section 8.2.2 forbids in an HTTP/2 message.
///
/// The C's own comment above the table is *"keep them sorted by length!"*, and
/// [`permissible_field`] relies on it: the loop returns `TRUE` the moment the
/// candidate is SHORTER than the current entry, which is only a correct early
/// exit while the table ascends. The order is therefore part of the data and
/// the `#[rustfmt::skip]` protects it.
///
/// `TE` is absent, and deliberately: RFC 9113 section 8.2.2 permits it with
/// the single value `trailers`, so it gets its own arm in [`req_to_h2`]
/// rather than being dropped here.
#[rustfmt::skip]
pub(crate) const H2_NON_FIELD: [&[u8]; 6] = [
    b"Host",
    b"Upgrade",
    b"Connection",
    b"Keep-Alive",
    b"Proxy-Connection",
    b"Transfer-Encoding",
];

/// `h2_permissible_field(e)` (`lib/http.c:4832-4844`).
///
/// The C, transcribed:
///
/// ```c
/// for(i = 0; i < CURL_ARRAYSIZE(H2_NON_FIELD); ++i) {
///   if(e->namelen < H2_NON_FIELD[i].namelen)     return TRUE;
///   if(e->namelen == H2_NON_FIELD[i].namelen &&
///      curl_strequal(H2_NON_FIELD[i].name, e->name))  return FALSE;
/// }
/// return TRUE;
/// ```
///
/// The early `TRUE` on a shorter name is what the sorted table buys, and the
/// comparison is CASE-INSENSITIVE (`curl_strequal`), because an application
/// may have supplied `connection:` in any case through
/// `CURLOPT_HTTPHEADER`.
#[must_use]
pub(crate) fn permissible_field(name: &[u8]) -> bool {
    for forbidden in H2_NON_FIELD {
        if name.len() < forbidden.len() {
            return true;
        }
        if name.len() == forbidden.len() && casecompare(forbidden, name) {
            return false;
        }
    }
    true
}

/// `http_TE_has_token(fvalue, token)` (`lib/http.c:4846-4872`).
///
/// Answers whether a `TE:` value carries `token` as one of its
/// comma-separated tokens, so that RFC 9113 section 8.2.2's single permitted
/// value can be recognised. Four properties of the C are reproduced and each
/// changes an answer:
///
/// * leading blanks AND commas are skipped before each token, so `TE: ,
///   trailers` is accepted;
/// * a token ends at the first of space, tab, carriage return, semicolon or
///   comma -- the C's `curlx_str_cspn(&fvalue, &name, " \t\r;,")` -- so
///   `trailers;q=0.5` matches on `trailers`;
/// * the comparison is case-insensitive, `curlx_str_casecompare`;
/// * after a non-matching token the remainder up to the next comma is
///   skipped, and a quoted string inside it is skipped AS A UNIT so that a
///   comma inside quotes does not end the parameter. A quoted string that does
///   not close is a syntax error and the whole value is REJECTED -- the C's
///   comment: *"if we do not cleanly find a quoted word here, the header value
///   does not follow HTTP syntax and we reject"*.
#[must_use]
pub(crate) fn te_has_token(value: &[u8], token: &[u8]) -> bool {
    let mut rest = value;
    while let Some(&first) = rest.first() {
        // Skip blanks and commas to the first token byte.
        if first == b' ' || first == b'\t' || first == b',' {
            rest = &rest[1..];
            continue;
        }

        // The token runs to the first delimiter.
        let end = rest
            .iter()
            .position(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b';' | b','))
            .unwrap_or(rest.len());
        let (name, tail) = rest.split_at(end);
        // `curlx_str_cspn` fails on an empty span, which the C treats as
        // "reject the whole value".
        if name.is_empty() {
            return false;
        }
        if name.len() == token.len() && casecompare(name, token) {
            return true;
        }
        rest = tail;

        // Skip the remainder of this element, honouring quoted strings.
        while let Some(&byte) = rest.first() {
            if byte == b',' {
                break;
            }
            if byte == b'"' {
                match quoted_word_end(rest) {
                    Some(at) => rest = &rest[at..],
                    // An unterminated quoted string rejects the value.
                    None => return false,
                }
                continue;
            }
            rest = &rest[1..];
        }
    }
    false
}

/// Where the quoted string starting at `input[0]` ends, as an index one past
/// its closing quote -- the successor of `curlx_str_quotedword`.
///
/// [`None`] when the quote never closes, which is the syntax error
/// [`te_has_token`] rejects the whole value for. A backslash escapes the byte
/// after it, as RFC 9110 section 5.6.4's `quoted-pair` requires, so
/// `"a\"b"` is one word.
fn quoted_word_end(input: &[u8]) -> Option<usize> {
    // `input[0]` is the opening quote; scanning starts after it.
    let mut at = 1;
    while let Some(&byte) = input.get(at) {
        match byte {
            b'\\' => at += 2,
            b'"' => return Some(at + 1),
            _ => at += 1,
        }
    }
    None
}

/// The literal value RFC 9113 section 8.2.2 permits `TE:` to carry, and the
/// value `Curl_http_req_to_h2` substitutes for whatever the request said
/// (`lib/http.c:4931-4932`).
///
/// Wire-bearing, hence `#[rustfmt::skip]`. The substitution is the point: a
/// request whose `TE:` read `trailers, gzip` emits `te: trailers` and not the
/// original, because only the one token is permitted.
#[rustfmt::skip]
pub(crate) const TE_TRAILERS: &[u8] = b"trailers";

/// `"TE"` -- the name whose value gets that treatment.
#[rustfmt::skip]
const NAME_TE: &[u8] = b"TE";

/// `"Host"` -- the name `Curl_http_req_to_h2` falls back to for `:authority`
/// (`lib/http.c:4906-4908`).
#[rustfmt::skip]
const NAME_HOST: &[u8] = b"Host";

/// `"CONNECT"` -- the method for which no `:scheme` is emitted
/// (`lib/http.c:4888`).
#[rustfmt::skip]
const METHOD_CONNECT: &[u8] = b"CONNECT";

/// `"https"` and `"http"` -- the `:scheme` values the C derives from
/// `Curl_conn_is_ssl` (`lib/http.c:4899`).
#[rustfmt::skip]
const SCHEME_HTTPS: &[u8] = b"https";
#[rustfmt::skip]
const SCHEME_HTTP: &[u8] = b"http";

/// One HTTP/1 request head, split into the three things HTTP/2 needs from it.
///
/// The successor of `struct httpreq` (`lib/http1.h`) restricted to what
/// `Curl_http_req_to_h2` actually reads: `req->method`, `req->path`,
/// `req->scheme`, `req->authority` and `req->headers`. The two optional
/// members are [`None`] for a request composed by
/// `protocols/http1.rs`, which writes an origin-form target, and are carried
/// because `cf-h2-proxy.c` builds a `CONNECT` request that sets `authority`
/// and no `path`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct H1Request {
    /// `req->method` -- `"GET"`, `"HEAD"`, `"CONNECT"` or whatever
    /// `CURLOPT_CUSTOMREQUEST` supplied.
    pub(crate) method: Vec<u8>,
    /// `req->path` -- the request target, origin form.
    pub(crate) path: Vec<u8>,
    /// `req->scheme`, when the caller fixed one. [`None`] makes
    /// [`req_to_h2`] derive it.
    pub(crate) scheme: Option<Vec<u8>>,
    /// `req->authority`, when the caller fixed one. [`None`] makes
    /// [`req_to_h2`] take it from the `Host:` header.
    pub(crate) authority: Option<Vec<u8>>,
    /// `req->headers`, in the order they were written.
    pub(crate) headers: HeaderSet,
}

/// `Curl_h1_req_parse_read(&stream->h1, buf, len, ...)` (`lib/http1.c`),
/// restricted to what `h2_submit` needs from it (`lib/http2.c:2083-2094`).
///
/// The input is a COMPLETE HTTP/1 request head as
/// `protocols/http1.rs`'s `compose_request` emits it: a request line, then
/// header lines, then the empty line that ends the head. The parse is
/// deliberately narrow -- it exists so that the ordered field list can be
/// derived from bytes this workspace itself wrote -- and its narrowness is
/// what makes it total:
///
/// * the request line is `method SP target SP version CRLF`, and only the
///   first two fields survive, because HTTP/2 has no version token;
/// * a header line is `name COLON value CRLF` with leading blanks of the value
///   dropped and trailing blanks trimmed, which is
///   [`HeaderSet::h1_add_line`]'s contract and is therefore not restated here;
/// * an obs-fold continuation line -- one beginning with a space or tab -- is
///   REFUSED, because RFC 9110 section 5.2 deprecates it and
///   `protocols/http1.rs` never writes one.
///
/// # Errors
///
/// [`CURLcode::WeirdServerReply`] for a head that is not shaped as above,
/// which is the code the C's own `Curl_h1_req_parse_read` reports for a
/// malformed line; and whatever [`HeaderSet::h1_add_line`] reports, which is
/// [`CURLcode::OutOfMemory`] at the set's limits.
pub(crate) fn parse_h1_request(head: &[u8]) -> CodeResult<H1Request> {
    let mut lines = head.split(|&byte| byte == b'\n');
    let request_line = lines.next().ok_or(CURLcode::WeirdServerReply)?;
    let request_line = strip_cr(request_line);
    if request_line.is_empty() {
        return Err(CURLcode::WeirdServerReply);
    }

    // `method SP target SP version`. Splitting on the FIRST two spaces rather
    // than on every space keeps a target containing a space -- which is
    // malformed, but which curl passes through rather than rejecting -- from
    // being silently truncated.
    let first = request_line
        .iter()
        .position(|&byte| byte == b' ')
        .ok_or(CURLcode::WeirdServerReply)?;
    let (method, after_method) = request_line.split_at(first);
    let after_method = after_method.get(1..).unwrap_or_default();
    let second = after_method
        .iter()
        .position(|&byte| byte == b' ')
        .ok_or(CURLcode::WeirdServerReply)?;
    let (path, _version) = after_method.split_at(second);
    if method.is_empty() || path.is_empty() {
        return Err(CURLcode::WeirdServerReply);
    }

    let mut headers = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
    for line in lines {
        let line = strip_cr(line);
        // The empty line ends the head; anything after it is a body and not
        // this function's business.
        if line.is_empty() {
            break;
        }
        if matches!(line.first(), Some(b' ') | Some(b'\t')) {
            return Err(CURLcode::WeirdServerReply);
        }
        headers.h1_add_line(line)?;
    }

    Ok(H1Request {
        method: method.to_vec(),
        path: path.to_vec(),
        scheme: None,
        authority: None,
        headers,
    })
}

/// `line` without a single trailing carriage return.
fn strip_cr(line: &[u8]) -> &[u8] {
    match line.strip_suffix(b"\r") {
        Some(rest) => rest,
        None => line,
    }
}

/// `Curl_http_req_to_h2(h2_headers, req, data)` (`lib/http.c:4874-4940`): the
/// ordered field list HPACK encodes.
///
/// **This function is the whole of R-C.** `h2` compresses and frames what it
/// is given; WHICH fields exist and in WHAT ORDER is decided here, and the
/// order is the C's:
///
/// 1. `:method` -- always.
/// 2. `:scheme` -- unless the method is `CONNECT` and the caller fixed none.
/// 3. `:authority` -- from `req->authority`, else from the `Host:` header;
///    omitted when neither exists.
/// 4. `:path` -- when `req->path` is set, which for a `CONNECT` it is not.
/// 5. every regular header, IN THE ORDER THE REQUEST WROTE THEM, minus the six
///    [`H2_NON_FIELD`] names and with `TE` reduced to `trailers`.
///
/// Nothing is sorted, at any point. The authoritative set is a [`HeaderSet`],
/// which never reorders, and `http::HeaderMap` is deliberately never used as
/// STORAGE: it lowercases, it groups by name, and it gives no ordering
/// guarantee across distinct names -- three properties that each change the
/// bytes a fixture compares. [`request_for_h2`] documents the checked,
/// transient conversion required at `h2`'s public boundary.
///
/// # Lower-casing IS applied, and it is not this module's idea
///
/// `Curl_dynhds_set_opts(h2_headers, DYNHDS_OPT_LOWERCASE)` at
/// `lib/http.c:4909` is the C's, and RFC 9113 section 8.2 requires it: *"field
/// names MUST be converted to lowercase"*. So the field list this function
/// returns carries lowercase names while the ORDER is the request's -- which
/// is exactly the pair of properties that makes an HTTP/2 request comparable
/// against its HTTP/1 spelling in a fixture.
///
/// # The pseudo-header names keep their colons
///
/// [`HTTP_PSEUDO_METHOD`] and its four siblings are consumed from
/// [`crate::headers`] and each begins with `':'`. The stored name keeps it, as
/// [`crate::headers::HeaderStore::push`]'s invariant for
/// [`CURLH_PSEUDO`] requires, so a `curl_easy_header` query for `:status`
/// finds it.
///
/// # Errors
///
/// Whatever [`HeaderSet::add`] reports, which is [`CURLcode::OutOfMemory`] at
/// the set's entry-count or total-size limit.
pub(crate) fn req_to_h2(
    request: &H1Request,
    conn_is_ssl: bool,
) -> CodeResult<HeaderSet> {
    // `lib/http.c:4885-4899`. `req->scheme` wins; otherwise a non-`CONNECT`
    // method derives one from the connection, and a `CONNECT` gets none.
    //
    // The C additionally consults `Curl_checkheaders(data, ":scheme")` between
    // those two, so that an application may fix the pseudo-header through
    // `CURLOPT_HTTPHEADER`. That path arrives here as `request.scheme`,
    // because a `:scheme` supplied that way is not a regular header and
    // `protocols/http1.rs` does not write it into the head -- which is why
    // this function reads one field where the C reads two.
    let derived_scheme: Option<&[u8]> = match request.scheme.as_deref() {
        Some(scheme) => Some(scheme),
        None => {
            if request.method == METHOD_CONNECT {
                None
            } else if conn_is_ssl {
                Some(SCHEME_HTTPS)
            } else {
                Some(SCHEME_HTTP)
            }
        }
    };

    // `lib/http.c:4901-4908`. `req->authority` wins; otherwise the `Host:`
    // header's value, which `HeaderSet::get` finds case-insensitively and in
    // insertion order -- the same `Curl_dynhds_get` the C calls.
    let derived_authority: Option<&[u8]> = match request.authority.as_deref() {
        Some(authority) => Some(authority),
        None => request.headers.get(NAME_HOST).map(|entry| entry.value()),
    };

    // `lib/http.c:4909`: DYNHDS_OPT_LOWERCASE, set before the first `add` so
    // that every name -- pseudo-headers included, though they are already
    // lowercase -- is folded on the way in.
    let mut fields = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
    fields.set_opts(true);

    // 1-4: the pseudo-headers, in `lib/http.c:4910-4928`'s order.
    fields.add(HTTP_PSEUDO_METHOD, &request.method)?;
    if let Some(scheme) = derived_scheme {
        fields.add(HTTP_PSEUDO_SCHEME, scheme)?;
    }
    if let Some(authority) = derived_authority {
        fields.add(HTTP_PSEUDO_AUTHORITY, authority)?;
    }
    if !request.path.is_empty() {
        fields.add(HTTP_PSEUDO_PATH, &request.path)?;
    }

    // 5: the regular headers, `lib/http.c:4929-4938`, in arrival order.
    for (name, value) in request.headers.iter() {
        // The C's comment: *"'TE' is special in that it is only permissible
        // when it has only value 'trailers'. RFC 9113 ch. 8.2.2"*. The test is
        // on the LENGTH first, exactly as the C's `e->namelen == 2 &&` is, so
        // a header called `TExx` cannot take this arm.
        if name.len() == NAME_TE.len() && casecompare(NAME_TE, name) {
            if te_has_token(value, TE_TRAILERS) {
                // The emitted value is the LITERAL, not the original: a `TE:
                // trailers, gzip` becomes `te: trailers`.
                fields.add(name, TE_TRAILERS)?;
            }
            // A `TE:` without the token contributes NOTHING -- there is no
            // `else` in the C either.
            continue;
        }
        if permissible_field(name) {
            fields.add(name, value)?;
        }
    }

    Ok(fields)
}

/// Converts curl's ordered field list at the `h2` boundary.
///
/// [`HeaderSet`] remains the authoritative storage. `http::HeaderMap` exists
/// only for the duration of `h2::client::SendRequest::send_request`, because
/// that is the public type `h2 0.4.15` accepts. `http 1.4.2` iterates distinct
/// names in first-insertion order and values of one name in append order, so
/// the conversion is byte-preserving whenever repeated names are contiguous.
/// A repeated name that reappears after another name is rejected rather than
/// silently regrouped: changing the HPACK field order would be a wire defect.
fn request_for_h2(fields: &HeaderSet) -> CodeResult<Request<()>> {
    let method = fields
        .get(HTTP_PSEUDO_METHOD)
        .ok_or(CURLcode::BadFunctionArgument)?;
    let method = Method::from_bytes(method.value())
        .map_err(|_| CURLcode::BadFunctionArgument)?;
    let scheme = fields.get(HTTP_PSEUDO_SCHEME).map(|entry| entry.value());
    let authority =
        fields.get(HTTP_PSEUDO_AUTHORITY).map(|entry| entry.value());
    let path = fields
        .get(HTTP_PSEUDO_PATH)
        .map_or(b"/".as_slice(), |entry| entry.value());

    let uri = if method == Method::CONNECT && scheme.is_none() {
        let authority = authority.ok_or(CURLcode::BadFunctionArgument)?;
        Uri::try_from(authority).map_err(|_| CURLcode::BadFunctionArgument)?
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
        Uri::from_maybe_shared(uri)
            .map_err(|_| CURLcode::BadFunctionArgument)?
    };

    let mut map = HeaderMap::new();
    let mut completed_names: Vec<Vec<u8>> = Vec::new();
    let mut current_name: Option<Vec<u8>> = None;

    for (name, value) in fields.iter() {
        if name.first() == Some(&b':') {
            continue;
        }

        let same_group = current_name
            .as_deref()
            .is_some_and(|current| casecompare(current, name));
        if !same_group {
            if completed_names
                .iter()
                .any(|completed| casecompare(completed, name))
            {
                return Err(CURLcode::Http2);
            }
            if let Some(completed) = current_name.replace(name.to_vec()) {
                completed_names.push(completed);
            }
        }

        let header_name = HeaderName::from_bytes(name)
            .map_err(|_| CURLcode::BadFunctionArgument)?;
        let header_value = HeaderValue::from_bytes(value)
            .map_err(|_| CURLcode::BadFunctionArgument)?;
        map.append(header_name, header_value);
    }

    let mut request = Request::new(());
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_2;
    *request.headers_mut() = map;
    Ok(request)
}

/// The receive window `h2` tracks internally.
///
/// The peer never sees this value: [`H2IoState`] replaces the initial SETTINGS
/// frame with curl's measured table and suppresses h2's automatic
/// WINDOW_UPDATE frames. A permissive internal window lets h2 validate,
/// decompress and frame the connection without rejecting bytes that curl's
/// independently managed window admitted. Curl's visible window remains
/// [`H2_STREAM_WINDOW_SIZE_MAX`] per stream and
/// [`HTTP2_HUGE_WINDOW_SIZE`] for the connection.
const H2_INTERNAL_RECV_WINDOW: u32 = HTTP2_HUGE_WINDOW_SIZE as u32;

/// The h2-owned handles attached to one curl stream.
#[derive(Debug)]
struct H2SubmittedStream {
    id: u32,
    response: h2::client::ResponseFuture,
    sender: h2::SendStream<Bytes>,
}

/// A directly driven `h2 0.4.15` client connection.
///
/// This is the production HPACK / HEADERS / DATA path. The filter remains
/// synchronous, so the connection is polled with a no-op waker whenever curl's
/// pollset says the underlying transport made progress. The queue-backed
/// [`H2Io`] never blocks a write and returns `Pending` for an empty read, which
/// is exactly the sans-executor contract required here.
#[derive(Debug)]
struct H2Driver {
    io: H2IoHandle,
    sender: h2::client::SendRequest<Bytes>,
    connection: h2::client::Connection<H2Io, Bytes>,
    ping: Option<h2::PingPong>,
    closed: bool,
}

impl H2Driver {
    fn new(
        table: &SettingsTable,
        suppress_upgrade_stream1_headers: bool,
    ) -> CurlResult<Self> {
        let exact_settings = settings_frame(table).map_err(Error::new)?;
        let (io, io_handle) =
            H2Io::new(exact_settings, suppress_upgrade_stream1_headers);

        let mut builder = h2::client::Builder::new();
        builder
            .max_concurrent_streams(table.max_concurrent_streams())
            .initial_window_size(H2_INTERNAL_RECV_WINDOW)
            .initial_connection_window_size(
                u32::try_from(HTTP2_HUGE_WINDOW_SIZE)
                    .map_err(|_| Error::new(CURLcode::Http2))?,
            )
            .enable_push(table.enable_push() != 0);

        let mut handshake = Box::pin(builder.handshake::<_, Bytes>(io));
        let waker = futures::task::noop_waker_ref();
        let mut task = TaskContext::from_waker(waker);
        let (sender, mut connection) = match handshake.as_mut().poll(&mut task)
        {
            Poll::Ready(Ok(pair)) => pair,
            Poll::Ready(Err(error)) => {
                return Err(h2_error(error, "HTTP/2 client handshake failed"));
            }
            Poll::Pending => {
                return Err(Error::with_context(
                    CURLcode::FailedInit,
                    "HTTP/2 queue-backed handshake unexpectedly blocked",
                ));
            }
        };

        let mut driver = Self {
            io: io_handle,
            sender,
            ping: connection.ping_pong(),
            connection,
            closed: false,
        };
        driver.drive()?;
        Ok(driver)
    }

    fn drive(&mut self) -> CurlResult<()> {
        if self.closed {
            return Ok(());
        }
        let waker = futures::task::noop_waker_ref();
        let mut task = TaskContext::from_waker(waker);
        match Pin::new(&mut self.connection).poll(&mut task) {
            Poll::Pending => Ok(()),
            Poll::Ready(Ok(())) => {
                self.closed = true;
                Ok(())
            }
            Poll::Ready(Err(error)) => {
                self.closed = true;
                Err(h2_error(error, "HTTP/2 connection failed"))
            }
        }
    }

    fn submit_request(
        &mut self,
        fields: &HeaderSet,
        end_stream: bool,
    ) -> CurlResult<H2SubmittedStream> {
        let request = request_for_h2(fields).map_err(Error::new)?;
        let waker = futures::task::noop_waker_ref();
        let mut task = TaskContext::from_waker(waker);
        match self.sender.poll_ready(&mut task) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                return Err(h2_error(
                    error,
                    "HTTP/2 request stream is unavailable",
                ));
            }
            Poll::Pending => return Err(Error::new(CURLcode::Again)),
        }
        let (response, sender) = self
            .sender
            .send_request(request, end_stream)
            .map_err(|error| {
                h2_error(error, "HTTP/2 request HEADERS could not be submitted")
            })?;
        let id = u32::from(response.stream_id());
        Ok(H2SubmittedStream {
            id,
            response,
            sender,
        })
    }

    fn push_input(&self, bytes: &[u8]) -> CodeResult<usize> {
        self.io.push_input(bytes)
    }

    fn drain_output(&self, target: &mut BufQ) -> CodeResult<usize> {
        let mut moved = 0usize;
        while self.io.pending_output() != 0 {
            let wanted = self.io.pending_output().min(H2_CHUNK_SIZE);
            let mut chunk = vec![0u8; wanted];
            let read = self.io.read_output(&mut chunk)?;
            let bytes = chunk.get(..read).unwrap_or_default();
            let written = target.write(bytes)?;
            if written != read {
                return Err(CURLcode::SendError);
            }
            moved = moved.saturating_add(written);
        }
        Ok(moved)
    }

    fn max_concurrent_streams(&self) -> usize {
        self.sender.current_max_send_streams()
    }

    fn pending_output(&self) -> usize {
        self.io.pending_output()
    }

    fn send_ping(&mut self) -> CurlResult<()> {
        let ping = self.ping.as_mut().ok_or_else(|| {
            Error::with_context(
                CURLcode::Http2,
                "HTTP/2 ping handle is unavailable",
            )
        })?;
        ping.send_ping(h2::Ping::opaque()).map_err(|error| {
            h2_error(error, "HTTP/2 ping could not be submitted")
        })
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    #[cfg(test)]
    fn settings_rewritten(&self) -> bool {
        self.io.settings_rewritten()
    }
}

fn h2_error(error: h2::Error, context: &'static str) -> Error {
    Error::with_source(CURLcode::Http2, context, error)
}

// ---------------------------------------------------------------------------
// 10. Projecting an HTTP/2 response back into the HTTP/1 shape every client
//     writer, header store and `--include` consumer already understands --
//     `on_header` (`lib/http2.c:1392-1565`) and
//     `http2_handle_stream_close` (`:1709-1737`).

/// The status line an HTTP/2 response is projected onto --
/// `lib/http2.c:1518-1522`.
///
/// The C composes it from three pieces: the literal `"HTTP/2 "`, the `:status`
/// value AS RECEIVED (not the parsed integer), and the literal `" \r\n"`. The
/// trailing SPACE before the CRLF is not a typo and must not be tidied: it
/// stands where an HTTP/1 status line would carry a reason phrase, HTTP/2 has
/// none, and the space is what keeps the line parseable by a consumer
/// expecting three fields. `protocols/http1.rs`'s `parse_h2_status` accepts
/// exactly this shape.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`DynBuf`] at its ceiling, which a status line
/// cannot reach.
pub(crate) fn status_line(
    out: &mut DynBuf,
    status_value: &[u8],
) -> CodeResult<()> {
    out.addn(H2_STATUS_PREFIX)?;
    out.addn(status_value)?;
    out.addn(H2_STATUS_SUFFIX)
}

/// `"HTTP/2 "` -- wire-bearing, hence `#[rustfmt::skip]`.
#[rustfmt::skip]
const H2_STATUS_PREFIX: &[u8] = b"HTTP/2 ";

/// `" \r\n"` -- wire-bearing, and the trailing space is load-bearing. See
/// [`status_line`].
#[rustfmt::skip]
const H2_STATUS_SUFFIX: &[u8] = b" \r\n";

/// The `:status` line pushed into the header store --
/// `lib/http2.c:1510-1512`.
///
/// The C builds `":status:%u\r"` from the PARSED code -- three digits, no
/// leading zeros suppressed and none added, because `%u` of a value
/// `Curl_http_decode_status` has already bounded to `100..1000` is always
/// three digits -- and pushes it with origin [`CURLH_PSEUDO`]. The trailing
/// carriage return with NO newline is what
/// [`crate::headers::HeaderStore::push`] expects: it strips one `\n` and then
/// one `\r`, in that order.
///
/// The name stored is therefore `:status`, colon retained, which is the
/// invariant [`CURLH_PSEUDO`] carries.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`DynBuf`] at its ceiling, unreachable here.
pub(crate) fn pseudo_status_line(
    out: &mut DynBuf,
    status_code: u32,
) -> CodeResult<()> {
    out.addn(HTTP_PSEUDO_STATUS)?;
    out.addn(H2_COLON)?;
    out.addf(format_args!("{status_code}"))?;
    out.addn(CR)
}

/// `"\r"` -- the single carriage return `lib/http2.c:1510`'s format string
/// ends with.
#[rustfmt::skip]
const CR: &[u8] = b"\r";

/// One response header projected into an HTTP/1 line --
/// `lib/http2.c:1542-1549`.
///
/// `name`, `": "`, `value`, `"\r\n"`. The separator carries a SPACE, which is
/// the difference from a stored push header's bare colon
/// (`lib/http2.c:1478`); specification 0.6.7 makes both observable and
/// [`crate::headers::PushHeaders`] documents the other half.
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
    out.addn(COLON_SPACE)?;
    out.addn(value)?;
    out.addn(CRLF)
}

/// One trailer projected into an HTTP/1 line --
/// `http2_handle_stream_close` (`lib/http2.c:1721-1723`).
///
/// The C's format string is `"%.*s: %.*s\x0d\x0a"`, which is the same bytes as
/// [`header_line`] writes with the CRLF spelled in hexadecimal. The two are
/// nevertheless separate functions, because the DESTINATION differs and that
/// is what the reader needs to see: a trailer is written with
/// `CLIENTWRITE_HEADER | CLIENTWRITE_TRAILER` (`:1729`), which
/// [`crate::headers::classify_origin`] turns into [`CURLH_TRAILER`], while a
/// header carries [`crate::headers::CURLH_HEADER`].
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`DynBuf`] at its ceiling.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
pub(crate) fn trailer_line(
    out: &mut DynBuf,
    name: &[u8],
    value: &[u8],
) -> CodeResult<()> {
    header_line(out, name, value)
}

/// The client-write flags a projected trailer carries --
/// `lib/http2.c:1728-1730`.
///
/// Consumed as a pair rather than re-derived, so that
/// [`crate::headers::classify_origin`] is the single place the precedence
/// `CONNECT > 1XX > TRAILER > HEADER` is decided.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
pub(crate) const TRAILER_WRITE_FLAGS: u32 =
    crate::headers::CLIENTWRITE_HEADER | crate::headers::CLIENTWRITE_TRAILER;

/// The origin bit a stored trailer carries -- [`CURLH_TRAILER`].
///
/// [`TRAILER_WRITE_FLAGS`] is what the CLIENT WRITER is handed and this is what
/// the HEADER STORE ends up holding; the two are related by
/// [`crate::headers::classify_origin`], and stating both makes the relationship
/// assertable rather than assumed. A caller that pushes a trailer line into the
/// store directly -- bypassing the client writer -- uses this.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
pub(crate) const TRAILER_ORIGIN: u32 = CURLH_TRAILER;

// ---------------------------------------------------------------------------
// 11. One stream's state -- `struct h2_stream_ctx` (`lib/http2.c:125-150`) and
//     `h2_stream_ctx_create` (`:267-289`).

/// `CURL_PUSH_OK` (`include/curl/multi.h`): accept the promised stream.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
pub(crate) const CURL_PUSH_OK: i32 = 0;

/// `CURL_PUSH_DENY`: refuse it.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
pub(crate) const CURL_PUSH_DENY: i32 = 1;

/// `CURL_PUSH_ERROROUT`: refuse it AND fail the parent transfer.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
pub(crate) const CURL_PUSH_ERROROUT: i32 = 2;

/// What a `CURLMOPT_PUSHFUNCTION` callback answered.
///
/// The three integers above are the ABI; this is how the answer travels
/// inside the engine, so that a value outside the three cannot be mistaken for
/// one of them. `lib/http2.c`'s `push_promise` treats anything that is not
/// `CURL_PUSH_OK` as a refusal and singles out `CURL_PUSH_ERROROUT`, so
/// [`Self::from_i32`] maps every other integer onto [`Self::Deny`] --
/// which is the C's behaviour and not a widening of it.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum PushVerdict {
    /// `CURL_PUSH_OK`.
    Ok,
    /// `CURL_PUSH_DENY`, and every unrecognised answer.
    #[default]
    Deny,
    /// `CURL_PUSH_ERROROUT`.
    ErrorOut,
}

impl PushVerdict {
    /// The verdict an integer answer names.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn from_i32(raw: i32) -> Self {
        match raw {
            CURL_PUSH_OK => Self::Ok,
            CURL_PUSH_ERROROUT => Self::ErrorOut,
            // `CURL_PUSH_DENY` and anything else.
            _ => Self::Deny,
        }
    }

    /// The integer the ABI carries.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn as_i32(self) -> i32 {
        match self {
            Self::Ok => CURL_PUSH_OK,
            Self::Deny => CURL_PUSH_DENY,
            Self::ErrorOut => CURL_PUSH_ERROROUT,
        }
    }
}

/// Everything HTTP/2 keeps about one transfer's stream.
///
/// The successor of `struct h2_stream_ctx` (`lib/http2.c:125-150`). Three of
/// the C's members do not survive as members, and each omission is a
/// translation rather than a loss:
///
/// * `char **push_headers` with its `_used` and `_alloc` counters becomes a
///   [`PushHeaders`], which owns the growth, the 1,280-field ceiling and both
///   ABI accessors. The store contract is DEFINED by
///   `lib/http2.c:1452-1480` and IMPLEMENTED in [`crate::headers`]; this
///   module coordinates with it and does not restate it.
/// * `struct h1_req_parser h1` becomes [`Self::req_head`], a plain
///   accumulator, because [`parse_h1_request`] parses a complete head rather
///   than resuming a partial parse.
/// * the eight `BIT(...)` flags become eight `bool` fields, since a bitfield
///   buys nothing once the struct is not shared with C.
#[derive(Debug)]
pub(crate) struct H2StreamCtx {
    /// `sendbuf` -- the request body waiting to be framed.
    sendbuf: BufQ,
    /// The partial request head, accumulated until it is complete. Stands
    /// where `struct h1_req_parser h1` does.
    req_head: Vec<u8>,
    /// `resp_trailers` -- the response TRAILER fields, kept in their OWN store
    /// so that they are never confused with the response headers. That
    /// separation is the C's (`lib/http2.c:128`) and it is what lets
    /// [`Self::flush_trailers`] tag them [`CURLH_TRAILER`].
    resp_trailers: HeaderSet,
    /// `resp_hds_len` -- how many response-header bytes have been written into
    /// the receive buffer.
    resp_hds_len: usize,
    /// `nrcvd_data` -- DATA payload bytes received on this stream.
    nrcvd_data: i64,
    /// The response bytes projected out of this stream and not yet taken by the
    /// transfer.
    ///
    /// Stands where `h2_xfer_write_resp` (`lib/http2.c:903-932`) writes
    /// straight into the client writer. It exists as a buffer rather than a
    /// call because the client writer belongs to [`crate::transfer`] and a
    /// connection filter must not reach into it: the filter accumulates and
    /// [`Self::take_response`] hands over, which is the same bytes in the same
    /// order with the ownership the other way round.
    response: Vec<u8>,
    /// The response head future created by `h2::SendRequest`.
    response_future: Option<h2::client::ResponseFuture>,
    /// The h2 receive half once the response head has arrived.
    recv_stream: Option<h2::RecvStream>,
    /// The h2 send half that frames request DATA.
    send_stream: Option<h2::SendStream<Bytes>>,
    /// The `PUSH_PROMISE` fields, as the push callback will read them.
    push_headers: PushHeaders,
    /// `push_headers_alloc` -- 0, then 10, then doubled on exhaustion.
    push_headers_alloc: usize,
    /// `status_code` -- `-1` until a `:status` arrives.
    status_code: i32,
    /// `error` -- the stream error code, `NO_ERROR` until one does.
    error: H2Error,
    /// `xfer_result` -- the result of writing the response out, once it fails.
    xfer_result: Option<CURLcode>,
    /// `local_window_size` -- the receive window this endpoint has announced.
    local_window_size: i32,
    /// The currently effective receive window after DATA and explicit
    /// WINDOW_UPDATE increments.
    effective_local_window_size: i32,
    /// `id` -- the HTTP/2 stream identifier, `-1` before one is assigned.
    id: i32,
    /// `resp_hds_complete` -- a complete, final response has arrived.
    resp_hds_complete: bool,
    /// `closed`.
    closed: bool,
    /// `reset`.
    reset: bool,
    /// `reset_by_server`.
    reset_by_server: bool,
    /// `close_handled`.
    #[allow(dead_code)]
    // consumer: the transfer core, and this module's tests
    close_handled: bool,
    /// `bodystarted` -- the response body has begun, so a further header field
    /// is a TRAILER.
    bodystarted: bool,
    /// `body_eos` -- the whole request body is in [`Self::sendbuf`].
    body_eos: bool,
    /// Whether END_STREAM has been handed to h2 for the request body.
    local_eos_sent: bool,
    /// `write_paused` -- `CURLOPT_WRITEFUNCTION` asked for a pause.
    write_paused: bool,
}

impl Default for H2StreamCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl H2StreamCtx {
    /// `h2_stream_ctx_create(ctx)` (`lib/http2.c:267-289`), field for field.
    ///
    /// The five values the C assigns explicitly after its `calloc` are the ones
    /// that are not zero, and each is load-bearing:
    ///
    /// * `id = -1`, so an unopened stream is distinguishable from stream 0;
    /// * `status_code = -1`, so "no status yet" is distinguishable from a
    ///   status of 0, which no HTTP response carries but which a zeroed field
    ///   would produce;
    /// * `error = NGHTTP2_NO_ERROR`;
    /// * `local_window_size = H2_STREAM_WINDOW_SIZE_INITIAL`;
    /// * `sendbuf` sized [`H2_STREAM_SEND_CHUNKS`] with `BUFQ_OPT_NONE` --
    ///   a HARD limit, deliberately, so that the upload buffer cannot grow past
    ///   the default window and the progress meter stays *"closer to reality"*
    ///   as `lib/http2.c:77-78` puts it.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_initial_window(H2_STREAM_WINDOW_SIZE_INITIAL as u32)
    }

    fn with_initial_window(initial_window_size: u32) -> Self {
        let initial_window_size =
            i32::try_from(initial_window_size).unwrap_or(i32::MAX);
        Self {
            sendbuf: BufQ::with_opts(
                H2_CHUNK_SIZE,
                H2_STREAM_SEND_CHUNKS,
                BufqOpts::NONE,
            ),
            req_head: Vec::new(),
            resp_trailers: HeaderSet::with_limits(0, DYN_HTTP_REQUEST),
            resp_hds_len: 0,
            nrcvd_data: 0,
            response: Vec::new(),
            response_future: None,
            recv_stream: None,
            send_stream: None,
            push_headers: PushHeaders::new(),
            push_headers_alloc: 0,
            status_code: -1,
            error: H2Error::NO_ERROR,
            xfer_result: None,
            local_window_size: initial_window_size,
            effective_local_window_size: initial_window_size,
            id: -1,
            resp_hds_complete: false,
            closed: false,
            reset: false,
            reset_by_server: false,
            close_handled: false,
            bodystarted: false,
            body_eos: false,
            local_eos_sent: false,
            write_paused: false,
        }
    }

    /// The stream identifier, or `-1` before one is assigned.
    #[must_use]
    pub(crate) const fn id(&self) -> i32 {
        self.id
    }

    /// Assigns the identifier `h2_submit` receives from the request submission
    /// (`lib/http2.c:2166`), or the `1` that an `h2c` upgrade opens implicitly
    /// (`:2431`).
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    pub(crate) fn set_id(&mut self, id: i32) {
        self.id = id;
    }

    fn attach_h2(&mut self, submitted: H2SubmittedStream) -> CodeResult<()> {
        self.id = i32::try_from(submitted.id).map_err(|_| CURLcode::Http2)?;
        self.response_future = Some(submitted.response);
        self.send_stream = Some(submitted.sender);
        Ok(())
    }

    /// The response status, or `-1` before a `:status` arrives.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn status_code(&self) -> i32 {
        self.status_code
    }

    /// Records a decoded `:status` -- `Curl_http_decode_status`'s output.
    ///
    /// The C's decoder bounds the value to `100..1000` before this point, so
    /// the range check belongs to the decoder and not here; what this records
    /// is that a status ARRIVED, which is what `-1` distinguishes.
    pub(crate) fn set_status_code(&mut self, status: i32) {
        self.status_code = status;
    }

    /// `stream->error` -- the code a `RST_STREAM` or a stream close carried.
    #[must_use]
    pub(crate) const fn error(&self) -> H2Error {
        self.error
    }

    /// The receive window this endpoint has announced for the stream.
    #[must_use]
    pub(crate) const fn local_window_size(&self) -> i32 {
        self.local_window_size
    }

    /// The receive window the peer can still consume before another explicit
    /// WINDOW_UPDATE.
    #[must_use]
    pub(crate) const fn effective_local_window_size(&self) -> i32 {
        self.effective_local_window_size
    }

    /// Whether the stream is paused for writing.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn is_write_paused(&self) -> bool {
        self.write_paused
    }

    /// Whether the response body has begun, which makes a further field a
    /// trailer.
    #[must_use]
    pub(crate) const fn body_started(&self) -> bool {
        self.bodystarted
    }

    /// Records that the response body has begun.
    pub(crate) fn set_body_started(&mut self) {
        self.bodystarted = true;
    }

    /// Whether a complete, final response has arrived.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn response_complete(&self) -> bool {
        self.resp_hds_complete
    }

    /// Records that a complete, final response has arrived.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    pub(crate) fn set_response_complete(&mut self) {
        self.resp_hds_complete = true;
    }

    /// Whether the stream has closed.
    #[must_use]
    pub(crate) const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether the stream was reset, and by whom.
    #[must_use]
    pub(crate) const fn was_reset(&self) -> bool {
        self.reset
    }

    /// How many DATA payload bytes have arrived on the stream.
    #[must_use]
    pub(crate) const fn received_data(&self) -> i64 {
        self.nrcvd_data
    }

    /// How many response-header bytes have been projected into the receive
    /// buffer -- `resp_hds_len`.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn response_header_bytes(&self) -> usize {
        self.resp_hds_len
    }

    /// The request head accumulated so far.
    #[must_use]
    pub(crate) fn request_head(&self) -> &[u8] {
        &self.req_head
    }

    /// The trailer store, so the caller can project it.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn trailers(&self) -> &HeaderSet {
        &self.resp_trailers
    }

    /// The `PUSH_PROMISE` field set, as `curl_pushheader_bynum` and
    /// `curl_pushheader_byname` read it through the ABI.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn push_headers(&self) -> &PushHeaders {
        &self.push_headers
    }

    #[cfg(test)]
    fn push_headers_alloc(&self) -> usize {
        self.push_headers_alloc
    }

    /// The unsent request body.
    #[must_use]
    pub(crate) const fn send_buffer(&self) -> &BufQ {
        &self.sendbuf
    }

    /// `stream->write_paused = pause` (`lib/http2.c:2629`).
    pub(crate) fn set_write_paused(&mut self, pause: bool) {
        self.write_paused = pause;
    }

    /// Records a failure writing the response out -- `stream->xfer_result`.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    pub(crate) fn set_transfer_result(&mut self, result: CURLcode) {
        self.xfer_result = Some(result);
    }

    /// The window size `cf_h2_update_local_win` aims for
    /// (`lib/http2.c:316-317`).
    ///
    /// `dwsize = (stream->write_paused || stream->xfer_result) ? 0 : ...`. Both
    /// inputs are stream state, so the forcing lives here and
    /// [`LocalWindowChange::decide`] stays a pure function of three integers.
    /// Zero closes the window, which is precisely what a paused stream wants:
    /// it stops the peer sending data nobody is reading.
    #[must_use]
    pub(crate) fn local_window_target(
        &self,
        rlimit: &mut RateLimit,
        now: CurlTime,
    ) -> i32 {
        if self.write_paused || self.xfer_result.is_some() {
            0
        } else {
            desired_local_win(rlimit, now)
        }
    }

    /// Applies a [`LocalWindowChange`], recording the new size.
    ///
    /// Split from the decision so that the recorded size cannot drift from the
    /// frame that was sent: a caller that emits the `WINDOW_UPDATE` and
    /// forgets to record ends up sending the same increment for ever.
    pub(crate) fn apply_local_window(&mut self, change: LocalWindowChange) {
        if let LocalWindowChange::Grow { increment, .. } = change {
            self.effective_local_window_size =
                self.effective_local_window_size.saturating_add(increment);
        }
        if let Some(size) = change.recorded_size() {
            self.local_window_size = size;
        }
    }

    fn account_inbound_window(&mut self, len: usize) {
        let amount = i32::try_from(len).unwrap_or(i32::MAX);
        self.effective_local_window_size =
            self.effective_local_window_size.saturating_sub(amount);
    }

    /// Accumulates request-head bytes, answering whether the head is now
    /// complete.
    ///
    /// A head ends with the empty line -- `CRLF CRLF` -- which is what
    /// `protocols/http1.rs`'s `H1_HD_LAST` slot writes. `h2_submit` returns
    /// early with `if(!stream->h1.done)` (`lib/http2.c:2090-2093`) until then,
    /// and this is the same test.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] once the accumulated head would exceed
    /// [`DYN_HTTP_REQUEST`], the same 1 MiB ceiling
    /// `protocols/http1.rs` composes under. Without the bound a peer that
    /// never sent the empty line would grow this buffer without limit.
    pub(crate) fn accumulate_request_head(
        &mut self,
        bytes: &[u8],
    ) -> CodeResult<bool> {
        let room = DYN_HTTP_REQUEST.saturating_sub(self.req_head.len());
        if bytes.len() > room {
            return Err(CURLcode::TooLarge);
        }
        self.req_head.extend_from_slice(bytes);
        Ok(head_is_complete(&self.req_head))
    }

    /// Releases the request head once it has been converted, as
    /// `Curl_h1_req_parse_free(&stream->h1)` does at `lib/http2.c:2100` --
    /// with the C's own comment, *"no longer needed"*.
    pub(crate) fn release_request_head(&mut self) {
        self.req_head = Vec::new();
    }

    /// Records one `PUSH_PROMISE` field, in the C's stored form.
    ///
    /// Delegates to [`PushHeaders::push`], which owns the whole contract:
    /// `"name:value"` with NO space after the colon (`lib/http2.c:1478`), the
    /// growth from ten by doubling, and the refusal past 1,280 fields that
    /// `lib/http2.c:1463-1468` reaches by refusing to grow beyond 1,000
    /// ALLOCATED slots.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] at that ceiling, at which point the fields are
    /// discarded -- the C calls `free_push_headers(stream)` before failing the
    /// stream at `:1466`, so a caller that saw this error must not then read
    /// the store. The C's `failf` text is [`TOO_MANY_PUSH_PROMISE_HEADERS`],
    /// reported by the caller because diagnostics belong where the transfer
    /// is.
    pub(crate) fn push_promise_field(
        &mut self,
        name: &[u8],
        value: &[u8],
    ) -> CodeResult<()> {
        if self.push_headers.count() >= self.push_headers_alloc {
            if self.push_headers_alloc > 1000 {
                self.free_push_headers();
                return Err(CURLcode::TooLarge);
            }
            self.push_headers_alloc = if self.push_headers_alloc == 0 {
                10
            } else {
                self.push_headers_alloc.saturating_mul(2)
            };
        }
        self.push_headers.push(name, value)
    }

    /// `free_push_headers(stream)` (`lib/http2.c:152-159`).
    pub(crate) fn free_push_headers(&mut self) {
        self.push_headers.free();
        self.push_headers_alloc = 0;
    }

    /// Records one response TRAILER field -- `Curl_dynhds_add(
    /// &stream->resp_trailers, ...)` (`lib/http2.c:1488-1490`).
    ///
    /// The destination is the SEPARATE store, never the response headers.
    ///
    /// # Errors
    ///
    /// Whatever [`HeaderSet::add`] reports, which the C turns into
    /// `NGHTTP2_ERR_CALLBACK_FAILURE` after `cf_h2_header_error`.
    pub(crate) fn add_trailer(
        &mut self,
        name: &[u8],
        value: &[u8],
    ) -> CodeResult<()> {
        self.resp_trailers.add(name, value)
    }

    /// Projects every trailer into its HTTP/1 line, in arrival order --
    /// `http2_handle_stream_close` (`lib/http2.c:1709-1737`).
    ///
    /// The C writes each line separately, resetting a scratch buffer between
    /// them and calling `Curl_client_write` once per line with
    /// [`TRAILER_WRITE_FLAGS`]. The lines are returned here rather than
    /// written, because the client writer belongs to
    /// [`crate::transfer`]; the ORDER and the BYTES are what this module owes,
    /// and both are the C's.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] from [`DynBuf`] at its ceiling, which
    /// [`DYN_TRAILERS`] sets at 64 KiB per line.
    ///
    /// [`DYN_TRAILERS`]: crate::util::dynbuf::DYN_TRAILERS
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    pub(crate) fn flush_trailers(&self) -> CodeResult<Vec<Vec<u8>>> {
        let mut lines = Vec::with_capacity(self.resp_trailers.count());
        for (name, value) in self.resp_trailers.iter() {
            let mut line = DynBuf::new(crate::util::dynbuf::DYN_TRAILERS);
            trailer_line(&mut line, name, value)?;
            lines.push(line.take());
        }
        Ok(lines)
    }

    /// Records a `RST_STREAM` from the peer -- `on_stream_close`'s
    /// `stream->reset_by_server` path.
    pub(crate) fn reset_by_peer(&mut self, error: H2Error) {
        self.closed = true;
        self.reset = true;
        self.reset_by_server = true;
        self.error = error;
    }

    /// Records the `RST_STREAM` this endpoint sends when a transfer ends before
    /// its stream did -- `http2_data_done` (`lib/http2.c:434-443`).
    ///
    /// The C sets `closed` and `reset` and NOT `reset_by_server`, which is what
    /// makes the `failf` of `http2_handle_stream_close` say *"reset by curl"*
    /// rather than *"reset by server"* (`:1698`).
    pub(crate) fn reset_by_us(&mut self) {
        self.closed = true;
        self.reset = true;
    }

    /// Records a clean stream close.
    pub(crate) fn close(&mut self, error: H2Error) {
        self.closed = true;
        self.error = error;
    }

    /// `http2_handle_stream_close(cf, data, stream, &nlen)`
    /// (`lib/http2.c:1673-1745`): what a closed stream means for the transfer.
    ///
    /// The five outcomes, in the C's order of testing, because the order is the
    /// meaning:
    ///
    /// 1. reset with `REFUSED_STREAM` -- [`StreamClose::RefusedRetry`]. The C
    ///    additionally marks the connection for closure and sets
    ///    `data->state.refused_stream` so that `Curl_retry_request` picks the
    ///    transfer up on a fresh connection, and returns
    ///    [`CURLcode::RecvError`] to trigger it.
    /// 2. reset AFTER a complete response, for a request that wanted no body --
    ///    success. The C's comment: *"error after response headers, but we did
    ///    not want a body anyway, ignore"*.
    /// 3. any other reset -- [`CURLcode::Http2Stream`] when the stream carried
    ///    an error code, else [`CURLcode::PartialFile`] when bytes had already
    ///    been counted, else [`CURLcode::Http2`].
    /// 4. closed cleanly but before the response headers finished --
    ///    [`CURLcode::Http2Stream`], with the C's *"treated as error"*.
    /// 5. otherwise success, and the trailers are flushed first.
    ///
    /// `bytecount` is `data->req.bytecount`, which the transfer owns.
    #[must_use]
    pub(crate) fn handle_close(
        &self,
        no_body: bool,
        bytecount: i64,
    ) -> StreamClose {
        if self.reset {
            if self.error == H2Error::REFUSED_STREAM {
                return StreamClose::RefusedRetry;
            }
            if self.resp_hds_complete && no_body {
                return StreamClose::Ignored;
            }
            let code = if self.error.is_error() {
                CURLcode::Http2Stream
            } else if bytecount != 0 {
                CURLcode::PartialFile
            } else {
                CURLcode::Http2
            };
            return StreamClose::Failed {
                code,
                by_server: self.reset_by_server,
            };
        }
        if !self.bodystarted {
            return StreamClose::Failed {
                code: CURLcode::Http2Stream,
                by_server: false,
            };
        }
        StreamClose::Complete
    }

    /// Marks the close as handled -- `stream->close_handled = TRUE`
    /// (`lib/http2.c:1694`, `:1739`).
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    pub(crate) fn set_close_handled(&mut self) {
        self.close_handled = true;
    }

    /// Whether the close has been handled.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn close_handled(&self) -> bool {
        self.close_handled
    }

    /// Accepts request-body bytes into [`Self::sendbuf`].
    ///
    /// # Errors
    ///
    /// Whatever [`BufQ::write`] reports at its hard chunk limit.
    pub(crate) fn write_body(&mut self, body: &[u8]) -> CodeResult<usize> {
        self.sendbuf.write(body)
    }

    /// Records that the whole request body is now in [`Self::sendbuf`] --
    /// `stream->body_eos`.
    pub(crate) fn set_body_eos(&mut self) {
        self.body_eos = true;
    }

    /// Whether the whole request body has been accepted.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn body_eos(&self) -> bool {
        self.body_eos
    }

    /// Accumulates projected response bytes -- what `h2_xfer_write_resp`
    /// writes out (`lib/http2.c:903-932`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] once the pending response would exceed
    /// [`H2_CONN_WINDOW_SIZE`], which is the same ceiling the connection's own
    /// receive window imposes: a peer that sends more than the announced window
    /// is in error, and a transfer that never drains must not grow this without
    /// limit.
    pub(crate) fn deliver_response(&mut self, bytes: &[u8]) -> CodeResult<()> {
        if self.response.len().saturating_add(bytes.len()) > H2_CONN_WINDOW_SIZE
        {
            return Err(CURLcode::TooLarge);
        }
        self.response.extend_from_slice(bytes);
        Ok(())
    }

    /// Copies up to `buf.len()` projected response bytes out, answering how
    /// many moved.
    ///
    /// The successor of the upper layer consuming what
    /// `Curl_xfer_write_resp` wrote. Draining rather than handing over the
    /// whole buffer keeps [`ConnFilter::recv`]'s contract -- *"read up to
    /// `buf.len()` bytes"* -- exact.
    pub(crate) fn take_response(&mut self, buf: &mut [u8]) -> usize {
        let take = buf.len().min(self.response.len());
        let Some(target) = buf.get_mut(..take) else {
            return 0;
        };
        let Some(source) = self.response.get(..take) else {
            return 0;
        };
        target.copy_from_slice(source);
        self.response.drain(..take);
        take
    }

    /// How many projected response bytes are waiting.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) fn pending_response(&self) -> usize {
        self.response.len()
    }

    /// Accounts DATA payload bytes received -- `stream->nrcvd_data`.
    pub(crate) fn account_data(&mut self, len: usize) {
        // Saturating rather than wrapping: a transfer of more than 8 exbibytes
        // is not reachable, and a wrap would turn a byte count into a negative
        // one that `handle_close`'s `bytecount != 0` test would still pass but
        // that a progress meter would render nonsensically.
        self.nrcvd_data = self
            .nrcvd_data
            .saturating_add(i64::try_from(len).unwrap_or(i64::MAX));
    }

    /// Accounts response-header bytes projected into the receive buffer --
    /// `stream->resp_hds_len`.
    pub(crate) fn account_response_header(&mut self, len: usize) {
        self.resp_hds_len = self.resp_hds_len.saturating_add(len);
    }

    /// `h2_stream_ctx_free(stream)` (`lib/http2.c:161-168`): release every
    /// buffer this stream holds.
    ///
    /// The C frees the struct too; here the struct is owned by the connection's
    /// stream table and is dropped when it is removed, so this is the part that
    /// releases CAPACITY rather than the part that releases the allocation.
    pub(crate) fn free(&mut self) {
        self.sendbuf.free();
        self.req_head = Vec::new();
        self.response = Vec::new();
        self.response_future = None;
        self.recv_stream = None;
        self.send_stream = None;
        self.resp_trailers.free();
        self.free_push_headers();
    }
}

/// The `failf` text `on_header` emits when a `PUSH_PROMISE` carries more
/// fields than the store will hold (`lib/http2.c:1465`).
///
/// Reproduced verbatim: it reaches `CURLOPT_ERRORBUFFER`.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
#[rustfmt::skip]
pub(crate) const TOO_MANY_PUSH_PROMISE_HEADERS: &str =
    "Too many PUSH_PROMISE headers";

/// What a closed stream means for the transfer --
/// [`H2StreamCtx::handle_close`]'s answer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum StreamClose {
    /// The response is complete. The trailers, if any, are flushed first.
    Complete,
    /// The stream was reset after a complete response for a request that
    /// wanted no body, so the reset is ignored and the transfer succeeded.
    Ignored,
    /// `REFUSED_STREAM`: retry on a fresh connection. The caller marks the
    /// connection for closure, sets the transfer's `refused_stream` flag and
    /// reports [`CURLcode::RecvError`].
    RefusedRetry,
    /// The transfer failed.
    Failed {
        /// The code to report.
        code: CURLcode,
        /// Whether the peer reset the stream, which decides whether the C's
        /// `failf` says *"reset by server"* or *"reset by curl"*.
        by_server: bool,
    },
}

impl StreamClose {
    /// The [`CURLcode`] this outcome reports, or [`None`] for the two that
    /// succeed.
    #[must_use]
    pub(crate) const fn code(self) -> Option<CURLcode> {
        match self {
            Self::Complete | Self::Ignored => None,
            Self::RefusedRetry => Some(CURLcode::RecvError),
            Self::Failed { code, .. } => Some(code),
        }
    }
}

/// Whether `head` carries the empty line that ends an HTTP/1 message head.
///
/// `CRLF CRLF` is what `protocols/http1.rs` writes, and a bare `LF LF`
/// is accepted too because [`parse_h1_request`] tolerates it -- the two
/// spellings must agree about where the head ends or a head accepted by one
/// would be rejected by the other.
#[must_use]
fn head_is_complete(head: &[u8]) -> bool {
    head.windows(4).any(|window| window == b"\r\n\r\n")
        || head.windows(2).any(|window| window == b"\n\n")
}

// ---------------------------------------------------------------------------
// 12. The connection's own state -- `struct cf_h2_ctx` (`lib/http2.c:92-116`),
//     `cf_h2_ctx_init` (`:177-187`) and the frame handling of `on_frame_recv`
//     (`:1147-1220`).

/// What one received frame means.
///
/// `on_frame_recv` is a callback nghttp2 invokes with a decoded frame. The
/// production path now receives that same information from `h2`; this value
/// enum belongs to the byte-level conformance parser that independently checks
/// control-frame sizes, acknowledgements and extension-frame handling.
///
/// An event is a VALUE rather than a callback, which is what makes ingestion
/// testable: a test feeds bytes and asserts the sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // retained for byte-level parser conformance tests
pub(crate) enum H2Event {
    /// A SETTINGS frame without `ACK` (`lib/http2.c:1170-1196`). The adopted
    /// values are already in the context; this reports what changed, because
    /// the C signals the multi handle only when MAX_CONCURRENT_STREAMS moved:
    /// *"only signal change if the value actually changed"* (`:1181-1186`).
    Settings {
        /// True when MAX_CONCURRENT_STREAMS took a new value.
        max_concurrent_changed: bool,
    },
    /// A SETTINGS frame WITH `ACK`: the peer accepted ours. Nothing to do, and
    /// the C's `if(!(frame->hd.flags & NGHTTP2_FLAG_ACK))` skips it -- reported
    /// here so that ingestion is total over what arrived.
    SettingsAck,
    /// A GOAWAY (`lib/http2.c:1197-1206`).
    Goaway {
        /// `frame->goaway.last_stream_id`.
        last_stream_id: i32,
        /// `frame->goaway.error_code`.
        error: H2Error,
    },
    /// A PING without `ACK`. The acknowledgement is already queued.
    Ping,
    /// A PING with `ACK`: the peer answered ours, which is what
    /// `cf_h2_keep_alive` sent it for.
    PingAck,
    /// A WINDOW_UPDATE. `stream_id` of 0 addresses the connection.
    WindowUpdate {
        /// Which stream, or 0 for the connection.
        stream_id: u32,
        /// The increment, which RFC 9113 section 6.9 makes positive.
        increment: i32,
    },
    /// A RST_STREAM.
    RstStream {
        /// Which stream.
        stream_id: u32,
        /// The error code it carried.
        error: H2Error,
    },
    /// A PRIORITY frame, which RFC 9113 section 5.3.2 deprecates and which
    /// curl neither sends nor acts on.
    Priority {
        /// Which stream.
        stream_id: u32,
    },
    /// A HEADERS, PUSH_PROMISE or CONTINUATION frame: an HPACK block, which
    /// `h2` decompresses. Handed on WHOLE -- header and payload -- because a
    /// header block may span a CONTINUATION and only the decompressor knows
    /// where it ends.
    HeaderBlock {
        /// The frame header, so the flags and the stream identifier survive.
        head: FrameHead,
        /// The frame payload, unmodified.
        payload: Vec<u8>,
    },
    /// A DATA frame.
    Data {
        /// Which stream.
        stream_id: u32,
        /// Whether `END_STREAM` was set.
        end_stream: bool,
        /// The payload, padding included -- unpadding is `h2`'s, because the
        /// pad length is part of the frame's own framing.
        payload: Vec<u8>,
    },
    /// An extension frame, which RFC 9113 section 5.5 requires a receiver to
    /// DISCARD. Reported so that a trace can say it was seen.
    Ignored {
        /// The `type` byte nobody recognised.
        kind: u8,
    },
}

/// `END_STREAM` on a DATA or HEADERS frame -- RFC 9113 section 6.1.
#[allow(dead_code)] // used by the byte-level parser conformance path
const FRAME_FLAG_END_STREAM: u8 = 0x01;

/// The whole of one HTTP/2 connection's state.
///
/// The successor of `struct cf_h2_ctx` (`lib/http2.c:92-116`). Three members
/// change shape and one disappears:
///
/// * `nghttp2_session *h2` becomes the typed [`H2Driver`] plus [`Self::open`].
///   `h2 0.4.15` owns HPACK, HEADERS/DATA framing and peer stream state; the
///   surrounding context retains curl's explicit SETTINGS and flow-control
///   decisions and the queues that connect the asynchronous codec to the
///   synchronous filter chain.
/// * `struct uint_hash streams` becomes [`Self::streams`], a vector keyed by
///   the transfer identifier the C uses as its hash key (`data->mid`). A
///   `HashMap` is deliberately not used: the C's own hash has 63 buckets and
///   the table is bounded by MAX_CONCURRENT_STREAMS, so a scan is correct and
///   ordered -- and specification 0.1.1 makes performance an explicit
///   non-goal, so the faithful and auditable structure wins.
/// * `struct cf_call_data call_data` disappears entirely. It exists so a
///   C callback can find the easy handle the filter is currently serving;
///   here the handle arrives as a parameter and there is nothing to stash.
/// * `struct bufc_pool stream_bufcp` is not shared. The C pools chunks across
///   every stream of a connection; each [`H2StreamCtx`] owns its own
///   [`BufQ`] here, which trades chunk reuse -- a performance property -- for
///   the absence of a shared mutable pool, and specification 0.1.1 settles that
///   trade in favour of the simpler ownership.
#[derive(Debug)]
pub(crate) struct H2ConnCtx {
    /// `inbufq` -- network input awaiting frame parsing.
    inbufq: BufQ,
    /// `outbufq` -- frames awaiting the network.
    outbufq: BufQ,
    /// The h2-owned HPACK, HEADERS, DATA and peer-state engine.
    driver: Option<H2Driver>,
    /// `scratch` -- where one projected header line is composed.
    scratch: DynBuf,
    /// `streams`, keyed by the transfer identifier.
    streams: Vec<(u32, H2StreamCtx)>,
    /// `drain_total` -- the sum of every stream's pending drain, which
    /// `should_close_session` tests against zero.
    drain_total: usize,
    /// `initial_win_size` -- the INITIAL_WINDOW_SIZE last announced.
    initial_win_size: u32,
    /// `max_concurrent_streams` -- [`DEFAULT_MAX_CONCURRENT_STREAMS`] until the
    /// peer's SETTINGS replaces it.
    max_concurrent_streams: u32,
    /// `goaway_error` -- the code a received GOAWAY carried.
    goaway_error: H2Error,
    /// `remote_max_sid` -- the highest identifier the peer will process,
    /// `INT32_MAX` until a GOAWAY narrows it (`lib/http2.c:184`).
    remote_max_sid: i32,
    /// `local_max_sid` -- the highest identifier this endpoint has processed,
    /// and the value a GOAWAY of ours carries.
    local_max_sid: i32,
    /// The connection-level send window, as WINDOW_UPDATEs from the peer move
    /// it. Stands where `nghttp2_session_get_remote_window_size` is called, in
    /// `cf_h2_adjust_pollset` (`lib/http2.c:2344`).
    remote_window_size: i64,
    /// `initialized` -- the buffers exist. `cf_h2_ctx_init` sets it and
    /// `cf_h2_ctx_free` tests it.
    initialized: bool,
    /// Whether the session is open -- the successor of `ctx->h2 != NULL`.
    open: bool,
    /// `via_h1_upgrade` -- the session came from a `101 Switching Protocols`;
    /// stream 1 is the HTTP/1 request and its duplicate h2 HEADERS are
    /// suppressed while h2 still tracks the stream.
    via_h1_upgrade: bool,
    /// `conn_closed`.
    conn_closed: bool,
    /// `rcvd_goaway`.
    rcvd_goaway: bool,
    /// `sent_goaway`.
    sent_goaway: bool,
    /// `enable_push` -- whether the PEER permits server push, from its
    /// SETTINGS.
    enable_push: bool,
    /// `nw_out_blocked` -- the last flush could not drain [`Self::outbufq`].
    nw_out_blocked: bool,
}

impl H2ConnCtx {
    /// `cf_h2_ctx_init(ctx, via_h1_upgrade)` (`lib/http2.c:177-187`).
    ///
    /// The five values the C assigns are reproduced: the two queues at
    /// [`H2_NW_RECV_CHUNKS`] and [`H2_NW_SEND_CHUNKS`] with `BUFQ_OPT_NONE`,
    /// the scratch buffer at `CURL_MAX_HTTP_HEADER`, `remote_max_sid` at
    /// `2147483647`, and `initialized`.
    ///
    /// [`Self::max_concurrent_streams`] starts at
    /// [`DEFAULT_MAX_CONCURRENT_STREAMS`] rather than at zero, which is where
    /// `cf_h2_ctx_open` puts it (`lib/http2.c:2409`); doing it here rather than
    /// at open means a query arriving before the session opened gets the
    /// documented default instead of zero, and `lib/http2.h:31-32`'s comment
    /// -- *"value for MAX_CONCURRENT_STREAMS we use until we get an updated
    /// setting from the peer"* -- is what that default is for.
    #[must_use]
    pub(crate) fn new(via_h1_upgrade: bool) -> Self {
        Self {
            inbufq: BufQ::with_opts(
                H2_CHUNK_SIZE,
                H2_NW_RECV_CHUNKS,
                BufqOpts::NONE,
            ),
            outbufq: BufQ::with_opts(
                H2_CHUNK_SIZE,
                H2_NW_SEND_CHUNKS,
                BufqOpts::SOFT_LIMIT,
            ),
            driver: None,
            scratch: DynBuf::new(DYN_HTTP_REQUEST),
            streams: Vec::new(),
            drain_total: 0,
            initial_win_size: 0,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            goaway_error: H2Error::NO_ERROR,
            remote_max_sid: i32::MAX,
            local_max_sid: 0,
            // RFC 9113 section 6.9.2: both endpoints start with 65,535.
            remote_window_size: H2_DEFAULT_WINDOW_SIZE as i64,
            initialized: true,
            open: false,
            via_h1_upgrade,
            conn_closed: false,
            rcvd_goaway: false,
            sent_goaway: false,
            enable_push: false,
            nw_out_blocked: false,
        }
    }

    /// Whether the session is open -- `ctx->h2 != NULL`.
    #[must_use]
    pub(crate) const fn is_open(&self) -> bool {
        self.open
    }

    /// Whether the buffers exist -- `ctx->initialized`.
    #[must_use]
    pub(crate) const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Whether this session came from an HTTP/1.1 upgrade.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn via_h1_upgrade(&self) -> bool {
        self.via_h1_upgrade
    }

    /// `ctx->max_concurrent_streams`.
    #[must_use]
    pub(crate) const fn max_concurrent_streams(&self) -> u32 {
        self.max_concurrent_streams
    }

    /// `ctx->initial_win_size` -- the INITIAL_WINDOW_SIZE last announced.
    #[must_use]
    pub(crate) const fn initial_win_size(&self) -> u32 {
        self.initial_win_size
    }

    /// `ctx->enable_push` -- whether the PEER permits server push.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn peer_enables_push(&self) -> bool {
        self.enable_push
    }

    /// `ctx->rcvd_goaway`.
    #[must_use]
    pub(crate) const fn received_goaway(&self) -> bool {
        self.rcvd_goaway
    }

    /// `ctx->sent_goaway`.
    #[must_use]
    pub(crate) const fn sent_goaway(&self) -> bool {
        self.sent_goaway
    }

    /// `ctx->goaway_error`.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn goaway_error(&self) -> H2Error {
        self.goaway_error
    }

    /// `ctx->remote_max_sid`.
    #[must_use]
    pub(crate) const fn remote_max_sid(&self) -> i32 {
        self.remote_max_sid
    }

    /// `ctx->local_max_sid` -- what a GOAWAY of ours carries.
    #[must_use]
    pub(crate) const fn local_max_sid(&self) -> i32 {
        self.local_max_sid
    }

    /// `ctx->conn_closed`.
    #[must_use]
    pub(crate) const fn conn_closed(&self) -> bool {
        self.conn_closed
    }

    /// `ctx->nw_out_blocked`.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn network_out_blocked(&self) -> bool {
        self.nw_out_blocked
    }

    /// `nghttp2_session_get_remote_window_size(ctx->h2)` -- the connection's
    /// send window, which `cf_h2_adjust_pollset` tests for exhaustion.
    #[must_use]
    pub(crate) const fn remote_window_size(&self) -> i64 {
        self.remote_window_size
    }

    /// How many bytes are waiting to go out -- `Curl_bufq_len(&ctx->outbufq)`.
    #[must_use]
    pub(crate) fn pending_output(&self) -> usize {
        self.outbufq.len()
            + self.driver.as_ref().map_or(0, H2Driver::pending_output)
    }

    /// Whether any input is buffered -- what `cf_h2_data_pending` tests
    /// (`lib/http2.c:2691-2692`).
    #[must_use]
    pub(crate) fn has_pending_input(&self) -> bool {
        !self.inbufq.is_empty()
    }

    /// `nghttp2_session_want_write(ctx->h2)` -- is there anything to send?
    #[must_use]
    pub(crate) fn want_write(&self) -> bool {
        self.pending_output() != 0
    }

    /// `nghttp2_session_want_read(ctx->h2)` -- is the session still interested
    /// in input?
    ///
    /// A session that has received a GOAWAY or seen the connection close is
    /// not, which is what makes `cf_h2_shutdown`'s completion test terminate.
    #[must_use]
    pub(crate) const fn want_read(&self) -> bool {
        !self.conn_closed && !self.rcvd_goaway
    }

    /// `should_close_session(ctx)` (`lib/http2.c:478-485`).
    ///
    /// The C's own comment: *"Returns nonzero if current HTTP/2 session should
    /// be closed"*. The conjunction is `drain_total == 0 && !want_read &&
    /// !want_write`.
    #[must_use]
    pub(crate) fn should_close_session(&self) -> bool {
        self.drain_total == 0 && !self.want_read() && !self.want_write()
    }

    /// `nghttp2_session_check_request_allowed(ctx->h2)` -- may another request
    /// be submitted?
    ///
    /// RFC 9113 section 6.8 forbids opening a stream above a received GOAWAY's
    /// `last_stream_id`, and nghttp2 answers `0` once that has happened, which
    /// is what `cf_h2_query`'s MAX_CONCURRENT arm keys off
    /// (`lib/http2.c:2738`).
    #[must_use]
    pub(crate) const fn request_allowed(&self) -> bool {
        !self.rcvd_goaway && !self.conn_closed && self.open
    }

    /// `H2_STREAM_CTX(ctx, data)` (`lib/http2.c:263-265`), shared.
    #[must_use]
    pub(crate) fn stream(&self, mid: u32) -> Option<&H2StreamCtx> {
        self.streams
            .iter()
            .find(|(held, _)| *held == mid)
            .map(|(_, stream)| stream)
    }

    /// `H2_STREAM_CTX(ctx, data)`, mutable.
    #[must_use]
    pub(crate) fn stream_mut(&mut self, mid: u32) -> Option<&mut H2StreamCtx> {
        self.streams
            .iter_mut()
            .find(|(held, _)| *held == mid)
            .map(|(_, stream)| stream)
    }

    /// `http2_data_setup(cf, data, &stream)` (`lib/http2.c:369-395`).
    ///
    /// Idempotent, as the C is: an existing stream is returned rather than
    /// replaced, which is what makes `CF_CTRL_DATA_SETUP` safe to distribute
    /// more than once.
    pub(crate) fn data_setup(&mut self, mid: u32) -> &mut H2StreamCtx {
        // The POSITION is resolved first and the borrow taken afterwards, so
        // that the search and the possible insertion do not overlap. Written
        // this way rather than with `iter_mut().find()` because the insertion
        // branch has to mutate the vector the search borrowed.
        let at = match self.streams.iter().position(|(held, _)| *held == mid) {
            Some(at) => at,
            None => {
                let initial = if self.initial_win_size == 0 {
                    H2_STREAM_WINDOW_SIZE_INITIAL as u32
                } else {
                    self.initial_win_size
                };
                self.streams
                    .push((mid, H2StreamCtx::with_initial_window(initial)));
                self.streams.len().saturating_sub(1)
            }
        };
        // `at` indexes a live element on both paths: the search found one, or
        // the push created one and `at` is its position. There is therefore no
        // fallible access and no fallback to invent.
        &mut self.streams[at].1
    }

    /// `Curl_uint32_hash_remove(&ctx->streams, data->mid)`
    /// (`lib/http2.c:451`), releasing the stream's buffers first as
    /// `h2_stream_ctx_free` does.
    pub(crate) fn data_done(&mut self, mid: u32) {
        if let Some(at) = self.streams.iter().position(|(held, _)| *held == mid)
        {
            if let Some((_, stream)) = self.streams.get_mut(at) {
                stream.free();
            }
            self.streams.remove(at);
        }
    }

    /// How many streams the connection is carrying -- `conn->attached_xfers` as
    /// `cf_h2_query`'s MAX_CONCURRENT arm reads it (`lib/http2.c:2740`).
    #[must_use]
    pub(crate) fn attached_streams(&self) -> usize {
        self.streams.len()
    }

    /// Records the INITIAL_WINDOW_SIZE just announced -- the C's
    /// `if(ctx) ctx->initial_win_size = iv[1].value` (`lib/http2.c:231-232`)
    /// and `cf_h2_update_settings`'s own assignment at `:259`.
    pub(crate) fn apply_settings(&mut self, table: &SettingsTable) {
        self.initial_win_size = table.initial_window_size();
    }

    fn submit_h2_request(
        &mut self,
        fields: &HeaderSet,
        end_stream: bool,
    ) -> CurlResult<H2SubmittedStream> {
        match self.driver.as_mut() {
            Some(driver) => driver.submit_request(fields, end_stream),
            None => Err(Error::with_context(
                CURLcode::Http2,
                "HTTP/2 request submitted before the h2 session opened",
            )),
        }
    }

    fn send_h2_ping(&mut self) -> CurlResult<()> {
        match self.driver.as_mut() {
            Some(driver) => driver.send_ping(),
            None => Err(Error::with_context(
                CURLcode::Http2,
                "HTTP/2 ping sent before the h2 session opened",
            )),
        }
    }

    /// Pumps queued network input through h2 and transfers every frame h2
    /// produced into curl's network output queue.
    fn drive_h2(&mut self) -> CurlResult<()> {
        let Self {
            inbufq,
            outbufq,
            driver,
            max_concurrent_streams,
            conn_closed,
            ..
        } = self;
        let Some(driver) = driver.as_mut() else {
            return Err(Error::with_context(
                CURLcode::Http2,
                "HTTP/2 session is not open",
            ));
        };

        while let Some(bytes) = inbufq.peek().map(<[u8]>::to_vec) {
            let accepted = driver.push_input(&bytes).map_err(Error::new)?;
            if accepted == 0 {
                return Err(Error::new(CURLcode::Again));
            }
            inbufq.skip(accepted);
            if accepted < bytes.len() {
                return Err(Error::new(CURLcode::Again));
            }
        }

        driver.drive()?;
        *max_concurrent_streams =
            u32::try_from(driver.max_concurrent_streams()).unwrap_or(u32::MAX);
        if driver.is_closed() {
            *conn_closed = true;
        }
        driver.drain_output(outbufq).map_err(Error::new)?;
        Ok(())
    }

    /// Queues bytes for the network.
    ///
    /// The successor of nghttp2's `send_callback` writing into `ctx->outbufq`
    /// (`lib/http2.c:624`): a frame this module built goes here and
    /// [`Self::flush_to`] moves it down the chain.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] when the queue will not take the whole frame. A
    /// partially queued frame is not a frame, so a short write is refused
    /// rather than accepted -- which is the one place this module is STRICTER
    /// than the C, whose `Curl_bufq_write` may write less and whose caller then
    /// reports `NGHTTP2_ERR_WOULDBLOCK`. Refusing is correct here because the
    /// caller has no way to resume a half-written frame.
    pub(crate) fn queue_frame(&mut self, frame: &[u8]) -> CodeResult<()> {
        let written = self.outbufq.write(frame)?;
        if written == frame.len() {
            Ok(())
        } else {
            Err(CURLcode::SendError)
        }
    }

    /// Accepts network input -- `Curl_cf_recv_bufq(cf->next, ...,
    /// &ctx->inbufq, ...)`, and the path
    /// `Curl_http2_upgrade` uses for the bytes that arrived after a
    /// `101` (`lib/http2.c:2933-2944`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`] when the queue will not take everything, which
    /// is the code `Curl_http2_upgrade` reports for exactly that at `:2937`;
    /// the C additionally distinguishes a SHORT copy, reporting
    /// [`CURLcode::Http2`] with *"connection buffer size could not take all
    /// data"* (`:2940-2943`), and that distinction is preserved.
    pub(crate) fn accept_input(&mut self, bytes: &[u8]) -> CodeResult<usize> {
        let copied =
            self.inbufq.write(bytes).map_err(|_| CURLcode::RecvError)?;
        if copied < bytes.len() {
            return Err(CURLcode::Http2);
        }
        Ok(copied)
    }

    /// `nw_out_flush(cf, data)` (`lib/http2.c:397-418`): push [`Self::outbufq`]
    /// down the chain.
    ///
    /// The C's three outcomes are reproduced exactly, and the middle one is the
    /// interesting case:
    ///
    /// * an empty queue succeeds immediately, before any call downward;
    /// * [`CURLcode::Again`] from below sets `nw_out_blocked` and propagates;
    /// * a partial drain propagates [`CURLcode::Again`] EVEN THOUGH the write
    ///   succeeded -- `return Curl_bufq_is_empty(&ctx->outbufq) ? CURLE_OK :
    ///   CURLE_AGAIN` (`:417`) -- because the caller's contract is "everything
    ///   went out or come back".
    ///
    /// # Errors
    ///
    /// Whatever the filter below reports, [`CURLcode::Again`] included.
    pub(crate) fn flush_to(
        &mut self,
        below: &mut (dyn ConnFilter + 'static),
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<()> {
        if self.outbufq.is_empty() {
            return Ok(());
        }
        while let Some(chunk) = self.outbufq.peek() {
            // The chunk is copied out before the send because `send` needs
            // `&mut` access to the chain while `peek` holds `&mut self`. A
            // frame is at most 16 KiB here, and specification 0.1.1 makes
            // performance a non-goal.
            let pending = chunk.to_vec();
            match below.send(cx, &pending, false) {
                Ok(0) => {
                    // A zero-length accept is what the C's `if(!nwritten)`
                    // treats as would-block (`lib/http2.c:638-641`).
                    self.nw_out_blocked = true;
                    return Err(Error::new(CURLcode::Again));
                }
                Ok(sent) => {
                    self.outbufq.skip(sent);
                    if sent < pending.len() {
                        // Partial: the chain took what it could and the rest
                        // stays queued. `:417`'s contract is `CURLE_AGAIN`.
                        return Err(Error::new(CURLcode::Again));
                    }
                }
                Err(error) if error.code() == CURLcode::Again => {
                    self.nw_out_blocked = true;
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
        self.nw_out_blocked = false;
        Ok(())
    }

    /// `h2_process_pending_input(cf, data)` (`lib/http2.c:492-533`): decode
    /// every complete frame in [`Self::inbufq`].
    ///
    /// The control frames whose bytes curl chooses are handled HERE -- the
    /// context is updated and any obligatory acknowledgement is queued -- and
    /// the rest are returned as events. An incomplete trailing frame stays in
    /// the queue for the next call, which is what makes this callable on
    /// whatever a single read produced.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`] for a frame that violates RFC 9113's fixed sizes --
    /// a RST_STREAM that is not four bytes, a PING that is not eight, a GOAWAY
    /// shorter than eight, a SETTINGS whose length is not a multiple of six --
    /// each of which is a connection error the C leaves to nghttp2 and which
    /// must be detected somewhere. Also [`CURLcode::Http2`] when an
    /// acknowledgement cannot be queued.
    #[allow(dead_code)] // byte-level parser conformance tests exercise this path
    pub(crate) fn ingest(&mut self) -> CodeResult<Vec<H2Event>> {
        let mut events = Vec::new();
        while let Some(head) = self.peek_frame_head() {
            // A frame is read out of the queue in one piece before it is
            // interpreted, because a chunked queue may split it and every
            // parser below wants a contiguous payload.
            if head.length > FRAME_MAX_PAYLOAD_LEN {
                return Err(CURLcode::Http2);
            }
            if self.inbufq.len() < head.total_len() {
                // Incomplete: wait for more input.
                break;
            }
            let mut whole = vec![0u8; head.total_len()];
            let read = self.inbufq.read(&mut whole)?;
            if read != whole.len() {
                // The length was proved above, so this cannot happen; treating
                // it as a protocol error rather than asserting keeps the
                // function total.
                return Err(CURLcode::Http2);
            }
            let payload = whole.get(FRAME_HEADER_LEN..).unwrap_or_default();
            events.push(self.interpret(head, payload)?);
        }
        Ok(events)
    }

    /// The header of the next queued frame, or [`None`] when fewer than
    /// [`FRAME_HEADER_LEN`] bytes are queued.
    #[allow(dead_code)] // helper for the byte-level parser conformance path
    fn peek_frame_head(&self) -> Option<FrameHead> {
        if self.inbufq.len() < FRAME_HEADER_LEN {
            return None;
        }
        // The header may straddle two chunks, so it is gathered rather than
        // peeked at in place.
        let mut header = [0u8; FRAME_HEADER_LEN];
        let mut filled = 0;
        let mut offset = 0;
        while filled < FRAME_HEADER_LEN {
            let chunk = self.inbufq.peek_at(offset)?;
            if chunk.is_empty() {
                return None;
            }
            let take = chunk.len().min(FRAME_HEADER_LEN - filled);
            let source = chunk.get(..take)?;
            let target = header.get_mut(filled..filled + take)?;
            target.copy_from_slice(source);
            filled += take;
            offset += take;
        }
        FrameHead::parse(&header)
    }

    /// What one complete frame means, and what it obliges us to send.
    #[allow(dead_code)] // helper for the byte-level parser conformance path
    fn interpret(
        &mut self,
        head: FrameHead,
        payload: &[u8],
    ) -> CodeResult<H2Event> {
        let Some(kind) = head.frame_type() else {
            // RFC 9113 section 5.5: an unknown type MUST be discarded.
            return Ok(H2Event::Ignored { kind: head.kind });
        };
        if kind.carries_header_block() {
            return Ok(H2Event::HeaderBlock {
                head,
                payload: payload.to_vec(),
            });
        }
        match kind {
            FrameType::Data => {
                self.local_max_sid = self.local_max_sid.max(
                    i32::try_from(head.stream_id).unwrap_or(self.local_max_sid),
                );
                Ok(H2Event::Data {
                    stream_id: head.stream_id,
                    end_stream: (head.flags & FRAME_FLAG_END_STREAM) != 0,
                    payload: payload.to_vec(),
                })
            }
            FrameType::Priority => Ok(H2Event::Priority {
                stream_id: head.stream_id,
            }),
            FrameType::RstStream => {
                let code = be_u32(payload).ok_or(CURLcode::Http2)?;
                Ok(H2Event::RstStream {
                    stream_id: head.stream_id,
                    error: H2Error::from_u32(code),
                })
            }
            FrameType::Settings => self.interpret_settings(head, payload),
            FrameType::Ping => {
                if payload.len() != 8 {
                    return Err(CURLcode::Http2);
                }
                if head.is_ack() {
                    return Ok(H2Event::PingAck);
                }
                // RFC 9113 section 6.7: the acknowledgement echoes the opaque
                // data verbatim.
                let ack = ping_ack_frame(payload)?;
                self.queue_frame(&ack).map_err(|_| CURLcode::Http2)?;
                Ok(H2Event::Ping)
            }
            FrameType::Goaway => {
                let last = be_u32(payload.get(..4).unwrap_or_default())
                    .ok_or(CURLcode::Http2)?;
                let code = be_u32(payload.get(4..8).unwrap_or_default())
                    .ok_or(CURLcode::Http2)?;
                // `lib/http2.c:1197-1205`.
                self.rcvd_goaway = true;
                self.goaway_error = H2Error::from_u32(code);
                // `frame->goaway.last_stream_id` is 31 bits, so it always fits.
                self.remote_max_sid =
                    i32::try_from(last & STREAM_ID_MASK).unwrap_or(i32::MAX);
                Ok(H2Event::Goaway {
                    last_stream_id: self.remote_max_sid,
                    error: self.goaway_error,
                })
            }
            FrameType::WindowUpdate => {
                let raw = be_u32(payload).ok_or(CURLcode::Http2)?;
                // RFC 9113 section 6.9: the high bit is reserved and the
                // increment is 31 bits, so it always fits an `i32`.
                let increment =
                    i32::try_from(raw & STREAM_ID_MASK).unwrap_or(i32::MAX);
                if increment == 0 {
                    // RFC 9113 section 6.9: a zero increment is a
                    // PROTOCOL_ERROR.
                    return Err(CURLcode::Http2);
                }
                if head.stream_id == 0 {
                    self.remote_window_size = self
                        .remote_window_size
                        .saturating_add(i64::from(increment));
                }
                Ok(H2Event::WindowUpdate {
                    stream_id: head.stream_id,
                    increment,
                })
            }
            // Handled above by `carries_header_block`; named rather than
            // wildcarded so a frame type added to `FrameType` is a compile
            // error here.
            FrameType::Headers
            | FrameType::PushPromise
            | FrameType::Continuation => Ok(H2Event::HeaderBlock {
                head,
                payload: payload.to_vec(),
            }),
        }
    }

    /// The SETTINGS arm of `on_frame_recv` (`lib/http2.c:1170-1196`).
    ///
    /// The C reads the adopted values back out of nghttp2 with
    /// `nghttp2_session_get_remote_settings`, which is the same thing as
    /// reading them out of the frame -- so they are read from the frame here,
    /// and the two settings the C asks for are the two that are adopted:
    /// MAX_CONCURRENT_STREAMS and ENABLE_PUSH. Every other identifier is
    /// ignored, which RFC 9113 section 6.5.2 requires.
    #[allow(dead_code)] // helper for the byte-level parser conformance path
    fn interpret_settings(
        &mut self,
        head: FrameHead,
        payload: &[u8],
    ) -> CodeResult<H2Event> {
        if head.is_ack() {
            // RFC 9113 section 6.5: an ACK carries no payload.
            if !payload.is_empty() {
                return Err(CURLcode::Http2);
            }
            return Ok(H2Event::SettingsAck);
        }
        if payload.len() % SETTINGS_ENTRY_LEN != 0 {
            return Err(CURLcode::Http2);
        }

        let before = self.max_concurrent_streams;
        for entry in payload.chunks_exact(SETTINGS_ENTRY_LEN) {
            let id = u16::from_be_bytes([
                entry.first().copied().unwrap_or(0),
                entry.get(1).copied().unwrap_or(0),
            ]);
            let Some(value) = be_u32(entry.get(2..6).unwrap_or_default())
            else {
                return Err(CURLcode::Http2);
            };
            match SettingsId::from_u16(id) {
                Some(SettingsId::MaxConcurrentStreams) => {
                    self.max_concurrent_streams = value;
                }
                Some(SettingsId::EnablePush) => {
                    self.enable_push = value != 0;
                }
                // Every other identifier, named or not, is ignored -- which is
                // what RFC 9113 section 6.5.2 requires and what the C does by
                // asking nghttp2 for only these two.
                _ => {}
            }
        }

        // RFC 9113 section 6.5: a receiver MUST acknowledge. nghttp2 queues
        // this itself, which is why no submit call appears in the C.
        let ack = settings_ack_frame()?;
        self.queue_frame(&ack).map_err(|_| CURLcode::Http2)?;

        Ok(H2Event::Settings {
            // `lib/http2.c:1181` -- *"only signal change if the value actually
            // changed"*.
            max_concurrent_changed: before != self.max_concurrent_streams,
        })
    }

    /// Records that the peer closed the connection.
    pub(crate) fn set_conn_closed(&mut self) {
        self.conn_closed = true;
    }

    /// Records that a GOAWAY of ours has gone out -- `ctx->sent_goaway = TRUE`
    /// (`lib/http2.c:2584`).
    pub(crate) fn set_sent_goaway(&mut self) {
        self.sent_goaway = true;
    }

    /// `cf_h2_ctx_open`'s session creation, minus the nghttp2 callbacks that
    /// have no successor (`lib/http2.c:2368-2485`).
    ///
    /// What reaches the wire, in the C's order:
    ///
    /// 1. for a session that did NOT come from an upgrade, the client preface
    ///    and then our SETTINGS -- `nghttp2_submit_settings(..., iv, ivlen)` at
    ///    `:2457`;
    /// 2. for one that DID, `nghttp2_session_upgrade2` queues the client
    ///    preface and SETTINGS again (the C comment at `:2431` says exactly
    ///    *"queue SETTINGS frame (again)"*). [`CfH2::seed_upgrade_stream`]
    ///    creates h2's stream-1 state while [`H2IoState`] suppresses only the
    ///    duplicate HEADERS for the HTTP/1 request;
    /// 3. either way, the connection-level window is raised to
    ///    [`HTTP2_HUGE_WINDOW_SIZE`] -- `set_local_window_size(..., 0, ...)` at
    ///    `:2467` -- which on the wire is a `WINDOW_UPDATE` on stream 0 for the
    ///    difference from RFC 9113's 65,535 default.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when the SETTINGS payload cannot be packed,
    /// which is the code the C reports for the upgrade path at `:2423`;
    /// [`CURLcode::Http2`] for a failed submit, as `:2439` and `:2462` and
    /// `:2472` all report.
    pub(crate) fn open(&mut self, table: &SettingsTable) -> CurlResult<()> {
        self.apply_settings(table);

        let driver = H2Driver::new(table, self.via_h1_upgrade)?;
        driver.drain_output(&mut self.outbufq).map_err(Error::new)?;
        self.driver = Some(driver);

        // `:2467`. The increment is the difference from the protocol default,
        // because a `WINDOW_UPDATE` carries an increment and not a target.
        let increment = i32::try_from(
            HTTP2_HUGE_WINDOW_SIZE.saturating_sub(H2_DEFAULT_WINDOW_SIZE),
        )
        .map_err(|_| Error::new(CURLcode::Http2))?;
        let update = window_update_frame(0, increment).map_err(Error::new)?;
        self.queue_frame(&update).map_err(Error::new)?;

        self.open = true;
        Ok(())
    }

    /// `cf_h2_ctx_close(ctx)` (`lib/http2.c:202-207`): delete the session,
    /// keeping the buffers.
    pub(crate) fn close_session(&mut self) {
        self.driver = None;
        self.open = false;
    }

    /// `cf_h2_ctx_free(ctx)` (`lib/http2.c:189-200`): release everything.
    ///
    /// The C's `memset(ctx, 0, sizeof(*ctx))` clears `initialized` too, which
    /// is what makes a second free a no-op; the same property is reproduced.
    pub(crate) fn free(&mut self) {
        if !self.initialized {
            return;
        }
        self.inbufq.free();
        self.outbufq.free();
        self.driver = None;
        self.scratch.free();
        for (_, stream) in &mut self.streams {
            stream.free();
        }
        self.streams = Vec::new();
        self.initialized = false;
        self.open = false;
    }

    /// The scratch buffer one projected header line is composed in --
    /// `ctx->scratch`, reset before each use as `curlx_dyn_reset` does at
    /// `lib/http2.c:1517` and `:1542`.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    pub(crate) fn scratch(&mut self) -> &mut DynBuf {
        self.scratch.reset();
        &mut self.scratch
    }
}

/// A big-endian `u32` from exactly four bytes, or [`None`] for any other
/// length.
///
/// Total, and deliberately strict about the length: every caller is reading a
/// field RFC 9113 fixes at four bytes, and a frame that carries fewer is a
/// `FRAME_SIZE_ERROR` rather than a value to guess at.
#[allow(dead_code)] // helper for the byte-level parser conformance path
fn be_u32(bytes: &[u8]) -> Option<u32> {
    let four = bytes.get(..4)?;
    if bytes.len() != 4 {
        return None;
    }
    Some(u32::from_be_bytes([
        *four.first()?,
        *four.get(1)?,
        *four.get(2)?,
        *four.get(3)?,
    ]))
}

// ---------------------------------------------------------------------------
// 13. The filter -- `struct Curl_cftype Curl_cft_nghttp2`
//     (`lib/http2.c:2773-2789`).

/// One filter-attributed trace line -- `CURL_TRC_CF`.
///
/// The same per-module shim `conn/filters.rs`, `conn/happy_eyeballs.rs` and
/// `proxy/haproxy.rs` each declare over the exported `trc_cf!`: the wrapper is
/// per-module by construction, because `macro_rules!` is not exported from any
/// of them, and it exists so a call site states the filter's identity and
/// socket index without repeating the verbosity test.
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

/// The HTTP/2 connection filter.
///
/// # Which transfer is being served
///
/// C threads `struct Curl_easy *data` through all twelve callbacks and stashes
/// it in `ctx->call_data` with the `CF_DATA_SAVE` / `CF_DATA_RESTORE` pair
/// (`lib/http2.c:118-120`) so that an nghttp2 callback can find it.
/// [`CallCtx`] deliberately carries only the tracer and the clock, and
/// `conn/filters.rs` records why: *"the transfer's own state reaches a filter
/// through [`CfControl::DataSetup`], which is exactly what that event is
/// for."* A multiplexing filter nevertheless has to know WHICH of several
/// streams a `send` or a `recv` concerns, so the identity arrives through
/// [`Self::set_current`] -- the successor of `CF_DATA_SAVE` -- and
/// [`Self::clear_current`], the successor of `CF_DATA_RESTORE`. The identifier
/// is `data->mid`, which is what the C's own stream table is keyed by
/// (`lib/http2.c:263-265`).
///
/// # Which of the twelve callbacks are overridden
///
/// All twelve. `Curl_cft_nghttp2` names a function for every member of
/// `struct Curl_cftype` (`lib/http2.c:2777-2788`), which no other filter in
/// the tree does, and the identity test asserts the count.
#[derive(Debug)]
pub(crate) struct CfH2 {
    /// The chain link, socket index and two state flags.
    base: FilterBase,
    /// `cf->ctx`, typed -- there is no `void *` and nothing to cast back.
    ctx: H2ConnCtx,
    /// The three settings to announce, decided by the caller because two of
    /// them come from the multi handle and the transfer's rate limit.
    settings: SettingsTable,
    /// Which transfer the current call concerns -- the successor of
    /// `ctx->call_data`.
    current: Option<u32>,
    /// `cf->conn->httpversion_seen`, recorded rather than written through:
    /// `CF_CTRL_CONN_INFO_UPDATE` sets it to 20 (`lib/http2.c:2675`) and
    /// `crate::conn` owns the connection it belongs on.
    seen_http_version: Option<i32>,
    /// `Curl_conn_set_multiplex(cf->conn)` (`lib/http2.c:2676`), recorded for
    /// the same reason.
    multiplex: bool,
    /// A diagnostic mirror of requests already submitted to h2, keyed by
    /// transfer identifier.
    ///
    /// The ORDER is decided here and h2 compresses it synchronously in
    /// [`ConnFilter::send`]. The mirror keeps the ordered input inspectable by
    /// diagnostics and tests; taking it never drives the protocol.
    pending_requests: Vec<(u32, HeaderSet)>,
    /// Raw HPACK blocks retained only by the byte-level conformance parser.
    pending_blocks: Vec<(FrameHead, Vec<u8>)>,
}

impl CfH2 {
    /// `http2_cfilter_add` / `http2_cfilter_insert_after`'s construction
    /// (`lib/http2.c:2791-2846`), which is a `calloc` plus
    /// `cf_h2_ctx_init(ctx, via_h1_upgrade)`.
    ///
    /// The context is allocated EAGERLY, as the C's `calloc` is, so
    /// [`ConnFilter::destroy`] and [`ConnFilter::close`] always have something
    /// well defined to act on however early they are called. The C's only
    /// failure was that allocation and has no successor here.
    #[allow(dead_code)] // consumer: the filter factory in `crate::conn`
    #[must_use]
    pub(crate) fn new(
        sockindex: SocketIndex,
        conn: Option<ConnId>,
        settings: SettingsTable,
        via_h1_upgrade: bool,
    ) -> Self {
        let mut base = FilterBase::new(sockindex);
        base.set_conn(conn);
        Self {
            base,
            ctx: H2ConnCtx::new(via_h1_upgrade),
            settings,
            current: None,
            seen_http_version: None,
            multiplex: false,
            pending_requests: Vec::new(),
            pending_blocks: Vec::new(),
        }
    }

    /// `Curl_http2_switch_at(cf, data)` (`lib/http2.c:2885-2903`): build the
    /// filter and install it immediately BELOW the filter at `index`.
    ///
    /// The filter is built UNATTACHED -- `conn` is [`None`] -- because
    /// [`FilterChain::insert_after`] stamps `cf->conn` and `cf->sockindex` onto
    /// every node it splices and asserts the filter arrives unattached, exactly
    /// as `Curl_conn_cf_insert_after` (`lib/cfilters.c:345-363`) does and as
    /// `http2_cfilter_insert_after` leaves them.
    ///
    /// # Errors
    ///
    /// Whatever [`FilterChain::insert_after`] reports, which is
    /// [`CURLcode::BadFunctionArgument`] for a position that does not resolve.
    /// Construction itself cannot fail.
    #[allow(dead_code)] // consumer: the filter factory in `crate::conn`
    pub(crate) fn insert_after(
        cx: &mut CallCtx<'_, '_>,
        chain: &mut FilterChain,
        index: usize,
        settings: SettingsTable,
        via_h1_upgrade: bool,
    ) -> CurlResult<()> {
        let filter =
            Self::new(chain.sockindex(), None, settings, via_h1_upgrade);
        chain.insert_after(cx, index, link(filter))
    }

    /// `CF_DATA_SAVE(save, cf, data)`: the transfer the next call concerns.
    #[allow(dead_code)] // consumer: the transfer core
    pub(crate) fn set_current(&mut self, mid: u32) {
        self.current = Some(mid);
    }

    /// `CF_DATA_RESTORE(cf, save)`.
    #[allow(dead_code)] // consumer: the transfer core
    pub(crate) fn clear_current(&mut self) {
        self.current = None;
    }

    /// Seeds h2's stream 1 after an HTTP/1.1 `101` upgrade.
    ///
    /// The HTTP/1 request already reached the peer, but h2 must still own the
    /// stream state so it can decode the response and keep the connection-wide
    /// HPACK table synchronized. Submitting the same ordered fields creates
    /// that state; [`H2IoState`] suppresses only the duplicate outbound
    /// HEADERS frame. Subsequent streams use h2 normally.
    #[allow(dead_code)] // consumer: the HTTP/1 101 handover
    pub(crate) fn seed_upgrade_stream(
        &mut self,
        mid: u32,
        fields: &HeaderSet,
    ) -> CurlResult<()> {
        if !self.ctx.via_h1_upgrade() {
            return Err(Error::with_context(
                CURLcode::BadFunctionArgument,
                "HTTP/2 upgrade stream requested on a prior-knowledge session",
            ));
        }
        self.ctx.data_setup(mid);
        let submitted = self.ctx.submit_h2_request(fields, true)?;
        if submitted.id != 1 {
            return Err(Error::with_context(
                CURLcode::Http2,
                "HTTP/2 upgrade did not allocate stream 1",
            ));
        }
        if let Some(stream) = self.ctx.stream_mut(mid) {
            stream.attach_h2(submitted).map_err(Error::new)?;
            stream.set_body_eos();
            stream.local_eos_sent = true;
        }
        Ok(())
    }

    /// Which transfer the current call concerns, if any.
    #[allow(dead_code)] // consumer: this module's tests
    #[must_use]
    pub(crate) const fn current(&self) -> Option<u32> {
        self.current
    }

    /// The connection state, shared.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn ctx(&self) -> &H2ConnCtx {
        &self.ctx
    }

    /// The connection state, mutable.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) fn ctx_mut(&mut self) -> &mut H2ConnCtx {
        &mut self.ctx
    }

    /// The three settings this filter announces.
    #[allow(dead_code)] // consumer: this module's tests
    #[must_use]
    pub(crate) const fn settings(&self) -> &SettingsTable {
        &self.settings
    }

    /// `cf->conn->httpversion_seen`, once `CF_CTRL_CONN_INFO_UPDATE` has set
    /// it.
    #[allow(dead_code)] // consumer: `crate::conn`, and this module's tests
    #[must_use]
    pub(crate) const fn seen_http_version(&self) -> Option<i32> {
        self.seen_http_version
    }

    /// Whether `Curl_conn_set_multiplex` has been asked for.
    #[allow(dead_code)] // consumer: `crate::conn`, and this module's tests
    #[must_use]
    pub(crate) const fn multiplex(&self) -> bool {
        self.multiplex
    }

    /// Takes the ordered field list built for `mid`, for HPACK to compress.
    #[allow(dead_code)] // consumer: the transfer core
    #[must_use]
    pub(crate) fn take_pending_request(
        &mut self,
        mid: u32,
    ) -> Option<HeaderSet> {
        let at = self
            .pending_requests
            .iter()
            .position(|(held, _)| *held == mid)?;
        Some(self.pending_requests.remove(at).1)
    }

    /// Takes every received HPACK block, in arrival order, for `h2` to
    /// decompress.
    #[allow(dead_code)] // consumer: the transfer core
    #[must_use]
    pub(crate) fn take_header_blocks(&mut self) -> Vec<(FrameHead, Vec<u8>)> {
        core::mem::take(&mut self.pending_blocks)
    }

    /// `Curl_conn_get_alpn_negotiated` through the chain -- the
    /// [`CfQuery::AlpnNegotiated`] query, id 15.
    ///
    /// This is how the ALPN result reaches HTTP/2, and it is the ONLY way:
    /// specification 0.4.2 turns `#include "vtls/vtls.h"` in a protocol file
    /// into *"no TLS import at all"*, because the filter chain interposes TLS
    /// transparently. There is consequently no `use crate::tls` anywhere in
    /// this module and no TLS session is ever opened from here.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) fn alpn_negotiated(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Option<String> {
        let answer = self.query_below(cx, CfQuery::AlpnNegotiated).ok()?;
        match answer {
            CfQueryValue::AlpnNegotiated(protocol) => protocol,
            _ => None,
        }
    }

    /// `Curl_conn_is_ssl(data->conn, FIRSTSOCKET)` as
    /// `Curl_http_req_to_h2` consults it for `:scheme`
    /// (`lib/http.c:4899`).
    ///
    /// Derived from the ALPN query rather than from a TLS import, for the
    /// reason [`Self::alpn_negotiated`] records: ALPN is negotiated inside the
    /// TLS handshake and exists nowhere else, so an answer at all means the
    /// chain below is TLS-protected. A chain that answers [`None`] -- because
    /// no filter understood the query, or because the handshake selected
    /// nothing -- is cleartext, which is the safe direction: it produces
    /// `:scheme: http`, and a `:scheme` mismatch is a visible protocol error
    /// rather than a silent downgrade of anything.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) fn conn_is_ssl(&mut self, cx: &mut CallCtx<'_, '_>) -> bool {
        self.alpn_negotiated(cx).is_some()
    }

    /// Puts one query to the chain below, or reports
    /// [`CURLcode::UnknownOption`] when there is no chain.
    fn query_below(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        match self.base.next_mut() {
            Some(next) => next.query(cx, query),
            None => Err(Error::new(CURLcode::UnknownOption)),
        }
    }

    /// `Curl_conn_cf_get_socket(cf, data)` -- the [`CfQuery::Socket`] query.
    ///
    /// `CURL_SOCKET_BAD` when nothing below owns a descriptor, which is what
    /// [`ConnFilter::adjust_pollset`] then declines to act on.
    fn socket(&mut self, cx: &mut CallCtx<'_, '_>) -> Socket {
        match self.query_below(cx, CfQuery::Socket) {
            Ok(CfQueryValue::Socket(sock)) => sock,
            _ => CURL_SOCKET_BAD,
        }
    }

    /// Hands buffered request-body bytes to h2, which owns DATA framing.
    fn flush_h2_body(&mut self, mid: u32) -> CurlResult<()> {
        loop {
            let (pending, eos, already_sent) = match self.ctx.stream_mut(mid) {
                Some(stream) => {
                    let pending = stream.sendbuf.peek().map(<[u8]>::to_vec);
                    let final_chunk = match pending.as_ref() {
                        Some(chunk) => chunk.len() == stream.sendbuf.len(),
                        None => true,
                    };
                    let eos = stream.body_eos && final_chunk;
                    (pending, eos, stream.local_eos_sent)
                }
                None => {
                    return Err(Error::with_context(
                        CURLcode::Http2,
                        "HTTP/2 body has no stream",
                    ));
                }
            };

            if pending.is_none() && (!eos || already_sent) {
                return Ok(());
            }

            let mut sender = match self.ctx.stream_mut(mid) {
                Some(stream) => stream.send_stream.take(),
                None => None,
            }
            .ok_or_else(|| {
                Error::with_context(
                    CURLcode::Http2,
                    "HTTP/2 body has no h2 send stream",
                )
            })?;

            let bytes = pending
                .as_deref()
                .map_or_else(Bytes::new, Bytes::copy_from_slice);
            let sent_len = bytes.len();
            if let Err(error) = sender.send_data(bytes, eos) {
                if let Some(stream) = self.ctx.stream_mut(mid) {
                    stream.send_stream = Some(sender);
                }
                return Err(h2_error(
                    error,
                    "HTTP/2 DATA could not be submitted",
                ));
            }

            if let Some(stream) = self.ctx.stream_mut(mid) {
                stream.sendbuf.skip(sent_len);
                stream.local_eos_sent = eos;
                if !eos {
                    stream.send_stream = Some(sender);
                }
            }
            if eos {
                return Ok(());
            }
        }
    }

    /// Polls h2 response futures and receive streams after connection progress.
    fn poll_h2_streams(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        let mids: Vec<u32> =
            self.ctx.streams.iter().map(|(mid, _)| *mid).collect();
        for mid in mids {
            self.poll_h2_response_head(mid)?;
            self.poll_h2_response_body(cx, mid)?;
        }
        self.ctx.drive_h2()
    }

    fn poll_h2_response_head(&mut self, mid: u32) -> CurlResult<()> {
        let mut future = match self.ctx.stream_mut(mid) {
            Some(stream) => stream.response_future.take(),
            None => None,
        };
        let Some(mut future) = future.take() else {
            return Ok(());
        };

        let waker = futures::task::noop_waker_ref();
        let mut task = TaskContext::from_waker(waker);
        match Pin::new(&mut future).poll(&mut task) {
            Poll::Pending => {
                if let Some(stream) = self.ctx.stream_mut(mid) {
                    stream.response_future = Some(future);
                }
                Ok(())
            }
            Poll::Ready(Err(error)) => {
                let reason = error
                    .reason()
                    .map(H2Error::from_reason)
                    .unwrap_or(H2Error::INTERNAL_ERROR);
                if let Some(stream) = self.ctx.stream_mut(mid) {
                    stream.reset_by_peer(reason);
                }
                Ok(())
            }
            Poll::Ready(Ok(response)) => {
                let (parts, body) = response.into_parts();
                let status = parts.status.as_str().as_bytes().to_vec();
                let headers: Vec<(Vec<u8>, Vec<u8>)> = parts
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().as_bytes().to_vec(),
                            value.as_bytes().to_vec(),
                        )
                    })
                    .collect();

                let status_projection = self
                    .on_response_field(
                        mid,
                        FrameType::Headers,
                        HTTP_PSEUDO_STATUS,
                        &status,
                    )
                    .map_err(Error::new)?;
                if let FieldProjection::Status { status_line, .. } =
                    status_projection
                {
                    if let Some(stream) = self.ctx.stream_mut(mid) {
                        stream
                            .deliver_response(&status_line)
                            .map_err(Error::new)?;
                    }
                }

                for (name, value) in headers {
                    let projection = self
                        .on_response_field(
                            mid,
                            FrameType::Headers,
                            &name,
                            &value,
                        )
                        .map_err(Error::new)?;
                    if let FieldProjection::Header { line } = projection {
                        if let Some(stream) = self.ctx.stream_mut(mid) {
                            stream
                                .deliver_response(&line)
                                .map_err(Error::new)?;
                        }
                    }
                }

                if let Some(stream) = self.ctx.stream_mut(mid) {
                    stream.deliver_response(CRLF).map_err(Error::new)?;
                    stream.set_response_complete();
                    stream.set_body_started();
                    stream.recv_stream = Some(body);
                }
                Ok(())
            }
        }
    }

    fn poll_h2_response_body(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        mid: u32,
    ) -> CurlResult<()> {
        let mut receiver = match self.ctx.stream_mut(mid) {
            Some(stream) => stream.recv_stream.take(),
            None => None,
        };
        let Some(mut receiver) = receiver.take() else {
            return Ok(());
        };

        let waker = futures::task::noop_waker_ref();
        let mut task = TaskContext::from_waker(waker);
        loop {
            match receiver.poll_data(&mut task) {
                Poll::Ready(Some(Ok(data))) => {
                    let len = data.len();
                    if let Err(error) =
                        receiver.flow_control().release_capacity(len)
                    {
                        return Err(h2_error(
                            error,
                            "HTTP/2 receive capacity could not be released",
                        ));
                    }
                    let change = if let Some(stream) = self.ctx.stream_mut(mid)
                    {
                        stream.account_data(len);
                        stream.account_inbound_window(len);
                        stream.deliver_response(&data).map_err(Error::new)?;
                        let mut rlimit = RateLimit::default();
                        let desired =
                            stream.local_window_target(&mut rlimit, cx.now());
                        LocalWindowChange::decide(
                            desired,
                            stream.local_window_size(),
                            stream.effective_local_window_size(),
                        )
                    } else {
                        LocalWindowChange::Unchanged
                    };
                    self.apply_window_change(cx, mid, change)?;
                }
                Poll::Ready(Some(Err(error))) => {
                    let reason = error
                        .reason()
                        .map(H2Error::from_reason)
                        .unwrap_or(H2Error::INTERNAL_ERROR);
                    if let Some(stream) = self.ctx.stream_mut(mid) {
                        stream.reset_by_peer(reason);
                    }
                    return Ok(());
                }
                Poll::Ready(None) => {
                    match receiver.poll_trailers(&mut task) {
                        Poll::Ready(Ok(Some(trailers))) => {
                            if let Some(stream) = self.ctx.stream_mut(mid) {
                                for (name, value) in trailers.iter() {
                                    stream
                                        .add_trailer(
                                            name.as_str().as_bytes(),
                                            value.as_bytes(),
                                        )
                                        .map_err(Error::new)?;
                                }
                                stream.close(H2Error::NO_ERROR);
                            }
                        }
                        Poll::Ready(Ok(None)) => {
                            if let Some(stream) = self.ctx.stream_mut(mid) {
                                stream.close(H2Error::NO_ERROR);
                            }
                        }
                        Poll::Ready(Err(error)) => {
                            let reason = error
                                .reason()
                                .map(H2Error::from_reason)
                                .unwrap_or(H2Error::INTERNAL_ERROR);
                            if let Some(stream) = self.ctx.stream_mut(mid) {
                                stream.reset_by_peer(reason);
                            }
                        }
                        Poll::Pending => {
                            if let Some(stream) = self.ctx.stream_mut(mid) {
                                stream.recv_stream = Some(receiver);
                            }
                        }
                    }
                    return Ok(());
                }
                Poll::Pending => {
                    if let Some(stream) = self.ctx.stream_mut(mid) {
                        stream.recv_stream = Some(receiver);
                    }
                    return Ok(());
                }
            }
        }
    }

    /// `h2_progress_egress(cf, data)` (`lib/http2.c:1786-1826`): ask h2 to
    /// serialise pending HEADERS/DATA/control work, then flush the resulting
    /// bytes through the chain.
    ///
    /// [`H2ConnCtx::drive_h2`] is the nghttp2-session-send half and
    /// [`H2ConnCtx::flush_to`] is the network-queue half.
    ///
    /// # Errors
    ///
    /// Whatever the filter below reports, [`CURLcode::Again`] included when the
    /// queue could not be drained.
    fn progress_egress(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        if self.ctx.is_open() {
            self.ctx.drive_h2()?;
        }
        // The chain and the context are disjoint fields, so both are borrowed
        // at once by naming them separately -- which is what makes this
        // expressible without a cell or a clone.
        let Self { base, ctx, .. } = self;
        match base.next_mut() {
            Some(next) => ctx.flush_to(next, cx),
            // `lib/cfilters.c:80`'s bottom-of-chain code for a SEND is
            // `CURLE_RECV_ERROR`, and `conn/filters.rs` preserves that swapped
            // pair verbatim rather than repairing it. A filter with nothing
            // below it cannot flush, and this is the code that says so.
            None => Err(Error::with_context(
                CURLcode::RecvError,
                "HTTP/2 egress: bottom of the filter chain reached",
            )),
        }
    }

    /// `h2_progress_ingress(cf, data, data_max_bytes)`
    /// (`lib/http2.c:1862-1941`): read from the chain and decode frames.
    ///
    /// The C's first act is the one most easily lost: *"if(should_close_session(
    /// ctx)) return CURLE_HTTP2"* (`:1871-1874`), BEFORE any read. A session
    /// with nothing to read, nothing to write and no drain outstanding is over,
    /// and reading again would block for ever.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`] when the session should already be closed or a frame
    /// violates RFC 9113's fixed sizes; whatever the filter below reports
    /// otherwise, [`CURLcode::Again`] included.
    fn progress_ingress(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        max_bytes: usize,
    ) -> CurlResult<Vec<H2Event>> {
        if self.ctx.should_close_session() {
            trc!(
                cx,
                self.trace_filter(),
                self.sockindex().as_i32(),
                "[0] ingress: session is closed"
            );
            return Err(Error::with_context(
                CURLcode::Http2,
                "HTTP/2 ingress: session is closed",
            ));
        }

        // `:1876-1881`: whatever is already buffered is handed to h2 FIRST,
        // before another read, so a frame split across two reads is completed
        // rather than starved.
        self.ctx.drive_h2()?;
        self.poll_h2_streams(cx)?;

        // `:1883-1930`: then read more, bounded by what the caller can take.
        // The C reads into `ctx->inbufq` through `Curl_cf_recv_bufq`; here the
        // read is a plain `recv` into a stack buffer that is then queued, which
        // is the same two steps without the queue owning the read.
        let want = max_bytes.clamp(FRAME_HEADER_LEN, H2_CHUNK_SIZE);
        let mut scratch = vec![0u8; want];
        let read = {
            let Self { base, .. } = self;
            match base.next_mut() {
                Some(next) => next.recv(cx, &mut scratch),
                // `lib/cfilters.c:89`'s bottom-of-chain code for a RECEIVE is
                // `CURLE_SEND_ERROR` -- the other half of the swapped pair.
                None => Err(Error::with_context(
                    CURLcode::SendError,
                    "HTTP/2 ingress: bottom of the filter chain reached",
                )),
            }
        };
        match read {
            Ok(0) => {
                // A zero-length read is end of file: the peer closed.
                self.ctx.set_conn_closed();
            }
            Ok(got) => {
                let fresh = scratch.get(..got).unwrap_or_default();
                self.ctx.accept_input(fresh).map_err(Error::new)?;
                self.ctx.drive_h2()?;
                self.poll_h2_streams(cx)?;
            }
            Err(error) if error.code() == CURLcode::Again => {
                // Nothing more to read right now, which is not a failure: what
                // was already buffered has been decoded.
            }
            Err(error) => return Err(error),
        }
        Ok(Vec::new())
    }

    /// Routes one decoded event into the state it belongs to.
    ///
    /// The successor of `on_frame_recv`'s dispatch (`lib/http2.c:1166-1219`)
    /// for the events whose effects are this module's. The two that are not --
    /// [`H2Event::HeaderBlock`] and [`H2Event::Data`] -- are held for the
    /// caller: a header block is `h2`'s to decompress, and DATA is the
    /// transfer's to write out.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] when a stream's pending response would overflow
    /// the connection window, which a peer that respects the window cannot
    /// cause.
    fn route(&mut self, event: &H2Event) -> CodeResult<()> {
        match event {
            H2Event::HeaderBlock { head, payload } => {
                self.pending_blocks.push((*head, payload.clone()));
            }
            H2Event::Data {
                stream_id,
                end_stream,
                payload,
            } => {
                let mid = self.mid_of_stream(*stream_id);
                if let Some(mid) = mid {
                    if let Some(stream) = self.ctx.stream_mut(mid) {
                        stream.account_data(payload.len());
                        stream.deliver_response(payload)?;
                        stream.set_body_started();
                        if *end_stream {
                            stream.close(H2Error::NO_ERROR);
                        }
                    }
                }
            }
            H2Event::RstStream { stream_id, error } => {
                if let Some(mid) = self.mid_of_stream(*stream_id) {
                    if let Some(stream) = self.ctx.stream_mut(mid) {
                        stream.reset_by_peer(*error);
                    }
                }
            }
            // Every remaining event's effect is already recorded in the
            // context by `H2ConnCtx::interpret`, which is where the
            // acknowledgements are queued too. They are named rather than
            // wildcarded so that an event added to `H2Event` is a compile error
            // here.
            H2Event::Settings { .. }
            | H2Event::SettingsAck
            | H2Event::Goaway { .. }
            | H2Event::Ping
            | H2Event::PingAck
            | H2Event::WindowUpdate { .. }
            | H2Event::Priority { .. }
            | H2Event::Ignored { .. } => {}
        }
        Ok(())
    }

    /// Which transfer owns the stream with this identifier.
    ///
    /// C asks nghttp2, which stores the easy handle as the stream's user data
    /// (`nghttp2_session_get_stream_user_data`); here the association is the
    /// stream table's, so the lookup is a scan of it. [`None`] for a stream
    /// nobody claims, which `on_frame_recv` treats as *"No Curl_easy
    /// associated"* and ignores rather than failing (`lib/http2.c:1214-1217`).
    fn mid_of_stream(&self, stream_id: u32) -> Option<u32> {
        let wanted = i32::try_from(stream_id).ok()?;
        self.ctx
            .streams
            .iter()
            .find(|(_, stream)| stream.id() == wanted)
            .map(|(mid, _)| *mid)
    }

    /// `cf_h2_flush(cf, data)` (`lib/http2.c:2282-2322`).
    ///
    /// The C resumes a suspended stream first -- `nghttp2_session_resume_data`
    /// at `:2293` -- so that a stream whose body was withheld by flow control
    /// starts producing DATA again, and then progresses egress.
    /// [`Self::flush_h2_body`] hands the queued body back to h2's
    /// [`h2::SendStream`], which performs the corresponding flow-control
    /// suspension and resumption.
    ///
    /// # Errors
    ///
    /// As [`Self::progress_egress`].
    #[allow(dead_code)] // consumer: `CfControl::Flush`, and this module's tests
    pub(crate) fn flush(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        if let Some(mid) = self.current {
            if self.ctx.stream(mid).is_some() {
                self.flush_h2_body(mid)?;
            }
        }
        let result = self.progress_egress(cx);
        let pending = self.ctx.pending_output();
        trc!(
            cx,
            self.trace_filter(),
            self.sockindex().as_i32(),
            "flush -> {}, nw_send_buffer({})",
            result.is_ok(),
            pending
        );
        result
    }

    /// `http2_data_pause(cf, data, pause)` (`lib/http2.c:2618-2649`).
    ///
    /// Three effects, in the C's order:
    ///
    /// 1. `stream->write_paused = pause`;
    /// 2. `cf_h2_update_local_win`, which for a pause aims the receive window
    ///    at ZERO -- that is what actually stops the peer sending;
    /// 3. an egress attempt, so the `WINDOW_UPDATE` leaves promptly. The C
    ///    discards its result -- `(void)h2_progress_egress(cf, data)` at
    ///    `:2635` -- because a pause must not fail for want of a flush, and
    ///    that discard is preserved.
    ///
    /// The C additionally marks the transfer dirty when UNpausing, with a
    /// comment explaining that the server may or may not have opened the window
    /// meanwhile; marking is [`crate::multi`]'s and is reported through the
    /// return value rather than performed here.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`] when the window update cannot be built or queued,
    /// which is the code `cf_h2_update_local_win` reports at `:327` and `:334`.
    #[allow(dead_code)] // consumer: `CfControl::DataPause`
    pub(crate) fn data_pause(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        pause: bool,
        rlimit: &mut RateLimit,
    ) -> CurlResult<bool> {
        let Some(mid) = self.current else {
            // `DEBUGASSERT(data)` guards the C here, and with no stream the
            // whole body is skipped: `if(ctx && ctx->h2 && stream)`.
            return Ok(false);
        };
        if !self.ctx.is_open() || self.ctx.stream(mid).is_none() {
            return Ok(false);
        }

        let now = cx.now();
        let change = {
            let Some(stream) = self.ctx.stream_mut(mid) else {
                return Ok(false);
            };
            stream.set_write_paused(pause);
            let desired = stream.local_window_target(rlimit, now);
            let recorded = stream.local_window_size();
            let effective = stream.effective_local_window_size();
            LocalWindowChange::decide(desired, recorded, effective)
        };
        self.apply_window_change(cx, mid, change)?;

        // `:2635`: the egress attempt whose result the C discards.
        let _ = self.progress_egress(cx);

        let id = self.ctx.stream(mid).map_or(-1, H2StreamCtx::id);
        trc!(
            cx,
            self.trace_filter(),
            self.sockindex().as_i32(),
            "[{}] stream now {}paused",
            id,
            if pause { "" } else { "un" }
        );
        // The C marks the transfer dirty when unpausing; reported rather than
        // performed, because the multi handle owns that.
        Ok(!pause)
    }

    /// Emits the `WINDOW_UPDATE` a [`LocalWindowChange`] calls for and records
    /// the new size -- the two nghttp2 calls of `cf_h2_update_local_win`
    /// (`lib/http2.c:318-352`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`], which is what the C reports for either failing.
    fn apply_window_change(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        mid: u32,
        change: LocalWindowChange,
    ) -> CurlResult<()> {
        let id = self.ctx.stream(mid).map_or(-1, H2StreamCtx::id);
        if let Some(increment) = change.increment() {
            // A stream that has not been opened has no window to update, and
            // `nghttp2_submit_window_update` on stream `-1` is a caller error
            // rather than a frame.
            if id >= 0 {
                let stream_id = u32::try_from(id).unwrap_or(0);
                let frame = window_update_frame(stream_id, increment)
                    .map_err(Error::new)?;
                self.ctx.queue_frame(&frame).map_err(Error::new)?;
                trc!(
                    cx,
                    self.trace_filter(),
                    self.sockindex().as_i32(),
                    "[{}] local window update by {}",
                    id,
                    increment
                );
            }
        } else if let Some(size) = change.recorded_size() {
            trc!(
                cx,
                self.trace_filter(),
                self.sockindex().as_i32(),
                "[{}] local window size now {}",
                id,
                size
            );
        }
        if let Some(stream) = self.ctx.stream_mut(mid) {
            stream.apply_local_window(change);
        }
        Ok(())
    }

    /// `http2_data_done(cf, data)` (`lib/http2.c:420-452`).
    ///
    /// The C's order matters and is reproduced: a stream that is still open
    /// gets a `RST_STREAM` with `STREAM_CLOSED` and the queue is flushed,
    /// THEN the stream is removed from the table. Removing first would discard
    /// the identifier the reset needs.
    ///
    /// # Errors
    ///
    /// None: the C discards both results here --
    /// `(void)nghttp2_session_send(ctx->h2)` and `(void)nw_out_flush(cf, data)`
    /// at `:446-447` -- because a finished transfer must not fail for want of a
    /// courtesy frame.
    #[allow(dead_code)] // consumer: `CfControl::DataDone`
    pub(crate) fn data_done(&mut self, cx: &mut CallCtx<'_, '_>) {
        let Some(mid) = self.current else {
            return;
        };
        if !self.ctx.is_initialized() || self.ctx.stream(mid).is_none() {
            return;
        }

        if self.ctx.is_open() {
            let id = self.ctx.stream(mid).map_or(-1, H2StreamCtx::id);
            let closed =
                self.ctx.stream(mid).is_some_and(H2StreamCtx::is_closed);
            if !closed && id > 0 {
                trc!(
                    cx,
                    self.trace_filter(),
                    self.sockindex().as_i32(),
                    "[{}] premature DATA_DONE, RST stream",
                    id
                );
                if let Some(stream) = self.ctx.stream_mut(mid) {
                    stream.reset_by_us();
                    if let Some(mut sender) = stream.send_stream.take() {
                        sender.send_reset(h2::Reason::STREAM_CLOSED);
                    }
                }
                // Both results discarded, as the C discards them.
                let _ = self.progress_egress(cx);
            }
        }

        self.ctx.data_done(mid);
        self.pending_requests.retain(|(held, _)| *held != mid);
    }

    /// `http2_send_ping(cf, data)` (`lib/http2.c:573-593`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`] when the frame cannot be queued, which is what the C
    /// reports for a failed `nghttp2_submit_ping` at `:583`; and
    /// [`CURLcode::SendError`] for a failed flush, as `:590` reports.
    #[allow(dead_code)] // consumer: `ConnFilter::keep_alive`
    pub(crate) fn send_ping(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<()> {
        self.ctx.send_h2_ping()?;
        match self.progress_egress(cx) {
            Ok(()) => Ok(()),
            // A ping that has been queued but not yet drained has still been
            // sent as far as the caller is concerned: h2 buffers it too, and
            // only a hard failure becomes `CURLE_SEND_ERROR`.
            Err(error) if error.code() == CURLcode::Again => Ok(()),
            Err(_) => Err(Error::with_context(
                CURLcode::SendError,
                "HTTP/2 ping could not be sent",
            )),
        }
    }

    /// `http2_connisalive(cf, data, input_pending)`
    /// (`lib/http2.c:534-571`).
    ///
    /// The subtle half is what happens when the chain below reports bytes
    /// waiting. The C's comment: *"This happens before we have sent off a
    /// request and the connection is not in use by any other transfer, there
    /// should not be any data here, only 'protocol frames'"*. So it CLEARS
    /// `input_pending`, reads those bytes, decodes them, and reports the
    /// connection dead if decoding failed or if the session is now over.
    fn conn_is_alive(&mut self, cx: &mut CallCtx<'_, '_>) -> Liveness {
        let below = {
            let Self { base, .. } = self;
            match base.next_mut() {
                Some(next) => next.is_alive(cx),
                None => Liveness::DEAD,
            }
        };
        if !below.alive {
            return Liveness::DEAD;
        }
        if !below.input_pending {
            return Liveness::alive(false);
        }

        // `:544-568`. `input_pending` becomes false whatever happens next.
        match self.progress_ingress(cx, H2_CHUNK_SIZE) {
            Ok(events) => {
                for event in &events {
                    // `:557-559`: *"immediate error, considered dead"*.
                    if self.route(event).is_err() {
                        return Liveness::DEAD;
                    }
                }
                // `:561`: `alive = !should_close_session(ctx)`.
                if self.ctx.should_close_session() {
                    Liveness::DEAD
                } else {
                    Liveness::alive(false)
                }
            }
            Err(error) if error.code() == CURLcode::Again => {
                Liveness::alive(false)
            }
            // `:564-567`: *"the read failed so let's say this is dead
            // anyway"*.
            Err(_) => Liveness::DEAD,
        }
    }

    /// `stream_recv(cf, data, stream, buf, len, pnread)`
    /// (`lib/http2.c:1827-1860`): what the stream's state means for a read.
    ///
    /// The C's ladder, in its order, and its FIRST act is the one worth
    /// noticing: it updates the receive window before deciding anything, so
    /// that a read is also what opens the window back up. The result starts at
    /// [`CURLcode::Again`] and only the four tests below move it.
    ///
    /// **The C returns no bytes through this path.** `stream_recv` opens with
    /// `(void)buf; (void)len; *pnread = 0;` (`:1834-1836`), because the response
    /// was already written out during ingestion by `h2_xfer_write_resp`. Here
    /// the projected bytes are accumulated in the stream instead -- see
    /// [`H2StreamCtx::deliver_response`] for why -- so this function DOES hand
    /// them over, which is the one place the byte path differs from the C's and
    /// it differs by carrying the same bytes through the filter contract rather
    /// than around it.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] when there is nothing yet; whatever
    /// [`H2StreamCtx::handle_close`] decided for a closed stream; and
    /// [`CURLcode::PartialFile`] or [`CURLcode::Http2`] for a stream the
    /// connection has abandoned.
    fn stream_recv(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        mid: u32,
        buf: &mut [u8],
        no_body: bool,
        rlimit: &mut RateLimit,
    ) -> CurlResult<usize> {
        // `:1838-1839`: the window is refreshed before anything is decided.
        let now = cx.now();
        let change = {
            let Some(stream) = self.ctx.stream_mut(mid) else {
                return Err(Error::with_context(
                    CURLcode::Http2,
                    "http/2 recv on a transfer never opened or already cleared",
                ));
            };
            let desired = stream.local_window_target(rlimit, now);
            let recorded = stream.local_window_size();
            let effective = stream.effective_local_window_size();
            LocalWindowChange::decide(desired, recorded, effective)
        };
        self.apply_window_change(cx, mid, change)?;

        // Whatever has been projected is handed over first: a byte in hand is
        // not an error condition, whatever the stream's state.
        let taken = match self.ctx.stream_mut(mid) {
            Some(stream) => stream.take_response(buf),
            None => 0,
        };
        if taken > 0 {
            return Ok(taken);
        }

        let Some(stream) = self.ctx.stream(mid) else {
            return Err(Error::with_context(
                CURLcode::Http2,
                "http/2 recv on a transfer never opened or already cleared",
            ));
        };
        let id = stream.id();

        // `:1841-1844`.
        if let Some(code) = stream.xfer_result {
            trc!(
                cx,
                self.trace_filter(),
                self.sockindex().as_i32(),
                "[{}] xfer write failed",
                id
            );
            return Err(Error::new(code));
        }

        // `:1845-1848`.
        if stream.is_closed() {
            trc!(
                cx,
                self.trace_filter(),
                self.sockindex().as_i32(),
                "[{}] returning CLOSE",
                id
            );
            let outcome = stream.handle_close(no_body, stream.received_data());
            if let Some(code) = outcome.code() {
                return Err(Error::new(code));
            }
            // A complete stream reads as end of file.
            return Ok(0);
        }

        // `:1849-1854`. Three independent conditions, and the third is the one
        // a GOAWAY makes true: a stream above the peer's last processed
        // identifier will never be answered.
        let abandoned = stream.was_reset()
            || (self.ctx.conn_closed() && !self.ctx.has_pending_input())
            || (self.ctx.received_goaway() && self.ctx.remote_max_sid() < id);
        if abandoned {
            trc!(
                cx,
                self.trace_filter(),
                self.sockindex().as_i32(),
                "[{}] returning ERR",
                id
            );
            let code = if stream.received_data() != 0 {
                CURLcode::PartialFile
            } else {
                CURLcode::Http2
            };
            return Err(Error::new(code));
        }

        Err(Error::new(CURLcode::Again))
    }
}

impl ConnFilter for CfH2 {
    // -- the `name` and `flags` members ----------------------------------

    fn trace_name(&self) -> &'static str {
        HTTP2_FILTER_NAME
    }

    fn cf_type(&self) -> CfType {
        HTTP2_FLAGS
    }

    // -- the `Curl_cfilter` instance members -----------------------------

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    // -- 1. destroy ------------------------------------------------------

    /// `cf_h2_destroy(cf, data)` (`lib/http2.c:2557-2566`): free the context
    /// and clear the pointer to it.
    ///
    /// Does NOT chain, and must not: the caller has already severed the link
    /// and owns the rest of the chain.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        let _ = cx;
        self.ctx.free();
        self.pending_requests = Vec::new();
        self.pending_blocks = Vec::new();
    }

    // -- 2. connect ------------------------------------------------------

    /// `cf_h2_connect(cf, data, done)` (`lib/http2.c:2487-2539`).
    ///
    /// The C's five steps, in order:
    ///
    /// 1. an already connected filter reports done immediately;
    /// 2. the filters BELOW are connected first, and a `false` from them
    ///    propagates unchanged -- HTTP/2 has nothing to do over a transport
    ///    that is not up;
    /// 3. the session is opened if it is not open, and that is the `first_time`
    ///    case;
    /// 4. on any subsequent call ingress is progressed FIRST, because the peer's
    ///    SETTINGS may already be waiting;
    /// 5. egress is progressed, and -- the step most easily got wrong --
    ///    [`CURLcode::Again`] from it is NOT a failure: *"Send out our SETTINGS
    ///    and ACKs and such. If that blocks, we have it buffered and can count
    ///    this filter as being connected"* (`:2525-2526`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] or [`CURLcode::Http2`] from opening the
    /// session; whatever the filter below reports while connecting.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        // `:2496-2499`.
        if self.base.is_connected() {
            return Ok(true);
        }

        // `:2501-2506`.
        {
            let Self { base, .. } = self;
            match base.next_mut() {
                Some(next) => {
                    if !next.base().is_connected() {
                        let done = next.connect(cx)?;
                        if !done {
                            return Ok(false);
                        }
                    }
                }
                None => {
                    return Err(Error::with_context(
                        CURLcode::FailedInit,
                        "HTTP/2 filter has no transport below it",
                    ));
                }
            }
        }

        // `:2512-2517`.
        let first_time = if self.ctx.is_open() {
            false
        } else {
            let table = self.settings;
            self.ctx.open(&table)?;
            true
        };

        // `:2519-2523`.
        if !first_time {
            let events = self.progress_ingress(cx, H2_CHUNK_SIZE)?;
            for event in &events {
                self.route(event).map_err(Error::new)?;
            }
        }

        // `:2527-2529`: `CURLE_AGAIN` is tolerated and nothing else is.
        match self.progress_egress(cx) {
            Ok(()) => {}
            Err(error) if error.code() == CURLcode::Again => {}
            Err(error) => return Err(error),
        }

        // `:2531-2533`.
        self.base.set_connected(true);
        trc!(
            cx,
            self.trace_filter(),
            self.sockindex().as_i32(),
            "cf_connect() -> 0, 1"
        );
        Ok(true)
    }

    // -- 3. close --------------------------------------------------------

    /// `cf_h2_close(cf, data)` (`lib/http2.c:2541-2555`): delete the session,
    /// clear `connected`, and CHAIN the close downward.
    ///
    /// The buffers survive, as they do in the C -- `cf_h2_ctx_close` deletes
    /// only the nghttp2 session -- so the filter may be connected again
    /// afterwards, which `lib/cfilters.h:424-425` requires of every
    /// implementation.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.ctx.close_session();
        self.base.set_connected(false);
        if let Some(next) = self.base.next_mut() {
            next.close(cx);
        }
    }

    // -- 4. shutdown -----------------------------------------------------

    /// `cf_h2_shutdown(cf, data, done)` (`lib/http2.c:2568-2616`).
    ///
    /// Four steps, and every one of the C's guards is load-bearing:
    ///
    /// 1. a filter that is not connected, has no session, has already shut down
    ///    or whose connection has closed reports done and does nothing;
    /// 2. a GOAWAY goes out ONCE -- `if(!ctx->sent_goaway)` -- carrying
    ///    `ctx->local_max_sid`, error 0 and the debug data
    ///    [`H2_SHUTDOWN_REASON`];
    /// 3. egress and then ingress are progressed while there is anything to do,
    ///    and [`CURLcode::Again`] from either is flattened to success at
    ///    `:2604-2605`;
    /// 4. done means the connection closed, or nothing is left to write, read
    ///    or flush. `cf->shutdown` is then set when the shutdown FAILED or
    ///    finished -- `cf->shutdown = (result || *done)` at `:2614` -- which is
    ///    why a failure is not retried.
    ///
    /// Does NOT chain: the shutdown driver in `conn/filters.rs` walks the chain
    /// one filter at a time and honours the deadline between steps.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] when the GOAWAY cannot be queued, as `:2592`
    /// reports; whatever the filter below reports otherwise.
    fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        // `:2576-2579`.
        if !self.base.is_connected()
            || !self.ctx.is_open()
            || self.base.has_shut_down()
            || self.ctx.conn_closed()
        {
            return Ok(true);
        }

        // `:2583-2595`.
        if !self.ctx.sent_goaway() {
            self.ctx.set_sent_goaway();
            let last = self.ctx.local_max_sid();
            let frame =
                goaway_frame(last, H2Error::NO_ERROR, H2_SHUTDOWN_REASON)
                    .map_err(Error::new)?;
            if let Err(code) = self.ctx.queue_frame(&frame) {
                self.base.set_shut_down(true);
                return Err(Error::with_context(
                    code,
                    "HTTP/2 GOAWAY could not be queued",
                ));
            }
        }

        // `:2596-2605`.
        let mut result: CurlResult<()> = Ok(());
        if self.ctx.want_write() {
            result = self.progress_egress(cx);
        }
        if result.is_ok() && self.ctx.want_read() {
            result =
                self.progress_ingress(cx, H2_CHUNK_SIZE).and_then(|events| {
                    for event in &events {
                        self.route(event).map_err(Error::new)?;
                    }
                    Ok(())
                });
        }
        let result = match result {
            Err(error) if error.code() == CURLcode::Again => Ok(()),
            other => other,
        };

        // `:2607-2610`.
        let done = self.ctx.conn_closed()
            || (result.is_ok()
                && !self.ctx.want_write()
                && !self.ctx.want_read()
                && self.ctx.pending_output() == 0);

        // `:2614`.
        self.base.set_shut_down(result.is_err() || done);
        result.map(|()| done)
    }

    // -- 5. adjust pollset ----------------------------------------------

    /// `cf_h2_adjust_pollset(cf, data, ps)` (`lib/http2.c:2324-2366`).
    ///
    /// The boolean algebra is transcribed rather than reasoned about, because
    /// getting it wrong stalls a transfer in a way no test names:
    ///
    /// ```c
    /// c_exhaust = want_send && !remote_window_size;
    /// s_exhaust = want_send && stream && stream->id >= 0 &&
    ///             !stream_remote_window_size;
    /// want_recv = (want_recv || c_exhaust || s_exhaust);
    /// want_send = (!s_exhaust && want_send) ||
    ///             (!c_exhaust && want_write) || !outbufq_empty;
    /// ```
    ///
    /// The shape is: a sender whose window is exhausted must WAIT FOR A READ,
    /// because only a `WINDOW_UPDATE` from the peer will unblock it -- so an
    /// exhausted window converts a write interest into a read interest. And
    /// the second branch runs only when the pollset says nothing at all is
    /// wanted AND a GOAWAY of ours is still going out (`:2356-2364`), which is
    /// what keeps a shutdown progressing after the transfer stopped caring.
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset::set`] reports, which is
    /// [`CURLcode::BadFunctionArgument`] for a socket that is not a
    /// descriptor.
    fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        // `:2334-2335`.
        if !self.ctx.is_open() {
            return Ok(());
        }
        let sock = self.socket(cx);
        if !is_valid_sock(sock) {
            // The C calls `Curl_pollset_check` unconditionally, which
            // `DEBUGASSERT`s a valid descriptor; declining here is the same
            // decision made without the assertion.
            return Ok(());
        }

        let (mut want_recv, mut want_send) = ps.check(sock);
        if want_recv || want_send {
            // `:2344-2351`.
            let c_exhaust = want_send && self.ctx.remote_window_size() == 0;
            let s_exhaust = want_send
                && self
                    .current
                    .and_then(|mid| self.ctx.stream(mid))
                    .is_some_and(|stream| {
                        stream.id() >= 0
                            && !stream.send_buffer().is_empty()
                            && stream
                                .send_stream
                                .as_ref()
                                .is_some_and(|sender| sender.capacity() == 0)
                    });
            want_recv = want_recv || c_exhaust || s_exhaust;
            want_send = (!s_exhaust && want_send)
                || (!c_exhaust && self.ctx.want_write())
                || self.ctx.pending_output() != 0;
            let trc = cx.tracer_mut();
            ps.set(sock, want_recv, want_send, trc).map_err(Error::new)
        } else if self.ctx.sent_goaway() && !self.base.has_shut_down() {
            // `:2356-2364`: a shutdown in progress.
            let want_send =
                self.ctx.want_write() || self.ctx.pending_output() != 0;
            let want_recv = self.ctx.want_read();
            let trc = cx.tracer_mut();
            ps.set(sock, want_recv, want_send, trc).map_err(Error::new)
        } else {
            Ok(())
        }
    }

    // -- 6. data pending -------------------------------------------------

    /// `cf_h2_data_pending(cf, data)` (`lib/http2.c:2686-2694`).
    ///
    /// Buffered input answers `true` without consulting the chain; otherwise
    /// the question goes down, and the bottom answers `false`.
    fn data_pending(&mut self, cx: &CallCtx<'_, '_>) -> bool {
        if self.ctx.has_pending_input() {
            return true;
        }
        match self.base.next_mut() {
            Some(next) => next.data_pending(cx),
            None => false,
        }
    }

    // -- 7. send ---------------------------------------------------------

    /// `cf_h2_send(cf, data, buf, len, eos, pnwritten)`
    /// (`lib/http2.c:2192-2281`) over `h2_submit` (`:2058-2190`).
    ///
    /// The bytes arriving here are an HTTP/1 request as
    /// `protocols/http1.rs`'s `compose_request` wrote it, which is exactly what
    /// the C receives: `h2_submit` parses them with `Curl_h1_req_parse_read`
    /// and converts the result with `Curl_http_req_to_h2`. Reproduced in that
    /// order:
    ///
    /// 1. the head is accumulated until it is complete, and an incomplete head
    ///    consumes its bytes and returns -- the C's
    ///    `if(!stream->h1.done) goto out` at `:2090-2093`;
    /// 2. the head is converted into the ORDERED field list and submitted
    ///    directly to h2, which performs HPACK and emits the HEADERS frame;
    /// 3. the announced INITIAL_WINDOW_SIZE is re-checked and a one-entry
    ///    SETTINGS frame goes out if it MOVED -- `if(initial_win_size !=
    ///    ctx->initial_win_size)` at `:2115`, and nothing goes out when it did
    ///    not;
    /// 4. whatever followed the head is body, and goes into the stream's send
    ///    buffer -- `cf_h2_body_send` at `:2173`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`] with no current transfer; [`CURLcode::TooLarge`]
    /// from the head accumulator at its ceiling; [`CURLcode::SendError`] when
    /// the settings frame cannot be queued, as `:2116` reports; whatever
    /// [`req_to_h2`] reports.
    fn send(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &[u8],
        eos: bool,
    ) -> CurlResult<usize> {
        let Some(mid) = self.current else {
            return Err(Error::with_context(
                CURLcode::Http2,
                "http/2 send with no transfer selected",
            ));
        };
        // `http2_data_setup(cf, data, &stream)` at `:2079`.
        self.ctx.data_setup(mid);

        // Once h2 assigned a stream identifier, every subsequent send is body
        // data. The HTTP/1-shaped request head is parsed exactly once.
        if self.ctx.stream(mid).is_some_and(|stream| stream.id() > 0) {
            let took = match self.ctx.stream_mut(mid) {
                Some(stream) => {
                    let took = stream.write_body(buf).map_err(Error::new)?;
                    if eos && took == buf.len() {
                        stream.set_body_eos();
                    }
                    took
                }
                None => 0,
            };
            self.flush_h2_body(mid)?;
            match self.progress_egress(cx) {
                Ok(()) => {}
                Err(error) if error.code() == CURLcode::Again => {}
                Err(error) => return Err(error),
            }
            return Ok(took);
        }

        // 1. `:2083-2093`.
        let already = self
            .ctx
            .stream(mid)
            .map_or(0, |stream| stream.request_head().len());
        let complete = match self.ctx.stream_mut(mid) {
            Some(stream) => {
                stream.accumulate_request_head(buf).map_err(Error::new)?
            }
            None => false,
        };
        if !complete {
            // Every byte was consumed into the head and none of it was a body.
            return Ok(buf.len());
        }

        // 2. `:2096-2106`. The head ends at the empty line; what follows it in
        // this very call is body.
        let head = self
            .ctx
            .stream(mid)
            .map_or_else(Vec::new, |stream| stream.request_head().to_vec());
        let head_len = head_length(&head);
        let consumed_by_head = head_len.saturating_sub(already);
        let body = buf.get(consumed_by_head..).unwrap_or_default();
        let conn_is_ssl = self.conn_is_ssl(cx);
        let parsed = parse_h1_request(&head).map_err(Error::new)?;
        let fields = req_to_h2(&parsed, conn_is_ssl).map_err(Error::new)?;

        // 3. `:2112-2119`.
        let announced = self.settings.initial_window_size();
        if announced != self.ctx.initial_win_size() {
            let frame =
                settings_window_update_frame(announced).map_err(Error::new)?;
            self.ctx.queue_frame(&frame).map_err(Error::new)?;
            let table = self.settings;
            self.ctx.apply_settings(&table);
        }

        // h2 owns HPACK and the HEADERS frame. The ordered HeaderSet remains
        // available through the diagnostic seam, but it is submitted here,
        // not left for an external caller to frame.
        let end_stream = eos && body.is_empty();
        let submitted = self.ctx.submit_h2_request(&fields, end_stream)?;
        if let Some(stream) = self.ctx.stream_mut(mid) {
            stream.attach_h2(submitted).map_err(Error::new)?;
            if end_stream {
                stream.set_body_eos();
                stream.local_eos_sent = true;
            }
            // `:2100`, with the C's comment *"no longer needed"*.
            stream.release_request_head();
        }
        self.pending_requests.retain(|(held, _)| *held != mid);
        self.pending_requests.push((mid, fields));

        // 4. `:2168-2181`.
        let mut written = consumed_by_head.min(buf.len());
        if !body.is_empty() || eos {
            if let Some(stream) = self.ctx.stream_mut(mid) {
                let took = stream.write_body(body).map_err(Error::new)?;
                written = written.saturating_add(took);
                if eos && took == body.len() {
                    stream.set_body_eos();
                }
            }
        }
        self.flush_h2_body(mid)?;

        // The frames just queued are pushed out, and a would-block is not a
        // failure of the send: the bytes are accepted and buffered, which is
        // what `:2249-2262` settles for.
        match self.progress_egress(cx) {
            Ok(()) => {}
            Err(error) if error.code() == CURLcode::Again => {}
            Err(error) => return Err(error),
        }
        Ok(written)
    }

    // -- 8. recv ---------------------------------------------------------

    /// `cf_h2_recv(cf, data, buf, len, pnread)` (`lib/http2.c:1942-2010`).
    ///
    /// The C's shape, and the retry is the point: [`Self::stream_recv`] is
    /// tried first, and only a [`CURLcode::Again`] from it justifies going to
    /// the network -- *"result = h2_progress_ingress(...); result =
    /// stream_recv(...)"* at `:1967-1973`. Egress is then progressed whatever
    /// happened, from the C's `out:` label at `:1986-1997`, so that
    /// acknowledgements queued during ingestion leave promptly.
    ///
    /// A read on a transfer with no stream is the C's `failf` *"http/2 recv on
    /// a transfer never opened or already cleared"* and
    /// [`CURLcode::Http2`] (`:1951-1959`).
    ///
    /// # Errors
    ///
    /// As [`Self::stream_recv`] and [`Self::progress_ingress`].
    fn recv(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        let Some(mid) = self.current else {
            return Err(Error::with_context(
                CURLcode::Http2,
                "http/2 recv with no transfer selected",
            ));
        };
        if self.ctx.stream(mid).is_none() {
            return Err(Error::with_context(
                CURLcode::Http2,
                "http/2 recv on a transfer never opened or already cleared",
            ));
        }

        // The rate limiter and the `no_body` flag belong to the transfer, which
        // a connection filter cannot reach. An unlimited limiter and a
        // body-wanted request are the defaults every transfer starts from, and
        // a caller that needs the other behaviour drives
        // [`Self::stream_recv`] directly with its own.
        let mut rlimit = RateLimit::default();
        let first = self.stream_recv(cx, mid, buf, false, &mut rlimit);
        let outcome = match first {
            Err(ref error) if error.code() == CURLcode::Again => {
                match self.progress_ingress(cx, buf.len()) {
                    Ok(events) => {
                        for event in &events {
                            self.route(event).map_err(Error::new)?;
                        }
                        self.stream_recv(cx, mid, buf, false, &mut rlimit)
                    }
                    Err(error) if error.code() == CURLcode::Again => first,
                    Err(error) => Err(error),
                }
            }
            other => other,
        };

        // `:1986-1997`: egress runs whatever happened, and its own would-block
        // does not override the read's result.
        match self.progress_egress(cx) {
            Ok(()) => {}
            Err(error) if error.code() == CURLcode::Again => {}
            Err(error) => return Err(error),
        }
        outcome
    }

    // -- 9. control ------------------------------------------------------

    /// `cf_h2_cntrl(cf, data, event, arg1, arg2)`
    /// (`lib/http2.c:2651-2684`).
    ///
    /// Five of the seven events do something and two do not, and the two are as
    /// deliberate as the five:
    ///
    /// * `DATA_SETUP` -- the C's `case CF_CTRL_DATA_SETUP: break;` at
    ///   `:2662-2663`. Nothing, because a stream is created lazily by the first
    ///   send. The arm is written out rather than folded into the default so
    ///   that the emptiness is visibly the C's;
    /// * `DATA_PAUSE` -- [`Self::data_pause`];
    /// * `FLUSH` -- [`Self::flush`];
    /// * `DATA_DONE` -- [`Self::data_done`];
    /// * `CONN_INFO_UPDATE` -- records `httpversion_seen = 20` and asks for
    ///   multiplexing, and ONLY on the primary chain and ONLY once connected:
    ///   `if(!cf->sockindex && cf->connected)` at `:2674`;
    /// * `DATA_DONE_SEND` and `FORGET_SOCKET` -- the C's `default: break;`.
    ///
    /// Does NOT chain: `conn/filters.rs`'s control driver distributes an event
    /// to every filter itself and applies the per-event policy.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::data_pause`] or [`Self::flush`] reports. The two are
    /// first-fail events, so an error here stops the distribution.
    fn cntrl(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        event: CfControl,
    ) -> CurlResult<()> {
        match event {
            // `:2662-2663`.
            CfControl::DataSetup => Ok(()),
            // `:2664-2666`.
            CfControl::DataPause { pause } => {
                let mut rlimit = RateLimit::default();
                self.data_pause(cx, pause, &mut rlimit).map(|_| ())
            }
            // `:2667-2669`.
            CfControl::Flush => self.flush(cx),
            // `:2670-2672`.
            CfControl::DataDone { .. } => {
                self.data_done(cx);
                Ok(())
            }
            // `:2673-2678`.
            CfControl::ConnInfoUpdate => {
                if self.base.sockindex() == SocketIndex::First
                    && self.base.is_connected()
                {
                    self.seen_http_version = Some(HTTP2_VERSION);
                    self.multiplex = true;
                }
                Ok(())
            }
            // `:2679-2680`, the C's `default: break;`.
            CfControl::DataDoneSend | CfControl::ForgetSocket => Ok(()),
        }
    }

    // -- 10. is alive ----------------------------------------------------

    /// `cf_h2_is_alive(cf, data, input_pending)`
    /// (`lib/http2.c:2696-2711`).
    ///
    /// `alive = (ctx && ctx->h2 && http2_connisalive(...))`, so a filter with
    /// no open session is dead however healthy the transport below it is.
    fn is_alive(&mut self, cx: &mut CallCtx<'_, '_>) -> Liveness {
        if !self.ctx.is_initialized() || !self.ctx.is_open() {
            return Liveness::DEAD;
        }
        let liveness = self.conn_is_alive(cx);
        trc!(
            cx,
            self.trace_filter(),
            self.sockindex().as_i32(),
            "conn alive -> {}, input_pending={}",
            liveness.alive,
            liveness.input_pending
        );
        liveness
    }

    // -- 11. keep alive --------------------------------------------------

    /// `cf_h2_keep_alive(cf, data)` (`lib/http2.c:2713-2723`): send a PING.
    ///
    /// # Errors
    ///
    /// As [`Self::send_ping`].
    fn keep_alive(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        self.send_ping(cx)
    }

    // -- 12. query -------------------------------------------------------

    /// `cf_h2_query(cf, data, query, pres1, pres2)`
    /// (`lib/http2.c:2725-2771`).
    ///
    /// Four queries are answered and the other eleven fall through, and one of
    /// the four falls through CONDITIONALLY -- which is the detail a
    /// transcription loses:
    ///
    /// * `MAX_CONCURRENT` -- the peer's setting once a request is allowed, and
    ///   otherwise *"the limit is what we have in use right now"*, clamped to
    ///   [`i32::MAX`] (`:2734-2747`);
    /// * `STREAM_ERROR` -- the current stream's error, or 0 (`:2748-2752`);
    /// * `NEED_FLUSH` -- `true` when the connection queue or the current
    ///   stream's send buffer holds anything, and otherwise **falls through**
    ///   rather than answering `false`: the C's `break` inside the `case` at
    ///   `:2760` leaves the switch and reaches the chain call, so a filter
    ///   below gets to answer (`:2753-2761`);
    /// * `HTTP_VERSION` -- [`HTTP2_VERSION`], 20 (`:2762-2764`).
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
                let effective = if self.ctx.request_allowed() {
                    u64::from(self.ctx.max_concurrent_streams())
                } else {
                    self.ctx.attached_streams() as u64
                };
                let clamped = i32::try_from(effective).unwrap_or(i32::MAX);
                return Ok(CfQueryValue::MaxConcurrent(clamped));
            }
            CfQuery::StreamError => {
                let error = self
                    .current
                    .and_then(|mid| self.ctx.stream(mid))
                    .map_or(0, |stream| stream.error().as_u32());
                let clamped = i32::try_from(error).unwrap_or(i32::MAX);
                return Ok(CfQueryValue::StreamError(clamped));
            }
            CfQuery::NeedFlush => {
                let stream_pending = self
                    .current
                    .and_then(|mid| self.ctx.stream(mid))
                    .is_some_and(|stream| !stream.send_buffer().is_empty());
                if self.ctx.pending_output() != 0 || stream_pending {
                    return Ok(CfQueryValue::NeedFlush(true));
                }
                // Deliberately NOT `Ok(NeedFlush(false))`: the C's `break`
                // leaves the switch and reaches the chain call below.
            }
            CfQuery::HttpVersion => {
                return Ok(CfQueryValue::HttpVersion(HTTP2_VERSION));
            }
            // The eleven the C's `default: break;` lets through.
            CfQuery::ConnectReplyMs
            | CfQuery::Socket
            | CfQuery::TimerConnect
            | CfQuery::TimerAppConnect
            | CfQuery::IpInfo
            | CfQuery::RemoteAddr
            | CfQuery::HostPort
            | CfQuery::SslInfo
            | CfQuery::SslCtxInfo
            | CfQuery::Transport
            | CfQuery::AlpnNegotiated => {}
        }
        self.query_below(cx, query)
    }
}

/// The version [`CfQuery::HttpVersion`] answers, and the value
/// `CF_CTRL_CONN_INFO_UPDATE` writes into `conn->httpversion_seen`
/// (`lib/http2.c:2675`, `:2763`).
///
/// curl encodes an HTTP version as two decimal digits -- 10, 11, 20, 30 -- so
/// HTTP/2 is 20 and not 2.
pub(crate) const HTTP2_VERSION: i32 = 20;

/// How many bytes of `head` the message head occupies, terminator included.
///
/// The counterpart of [`head_is_complete`]: that answers whether the empty line
/// is present and this answers where it ends, so a `send` can tell head bytes
/// from body bytes in one buffer. Answers the whole length when no terminator is
/// present, which is the case [`head_is_complete`] has already excluded.
#[must_use]
fn head_length(head: &[u8]) -> usize {
    if let Some(at) = head.windows(4).position(|window| window == b"\r\n\r\n") {
        return at + 4;
    }
    if let Some(at) = head.windows(2).position(|window| window == b"\n\n") {
        return at + 2;
    }
    head.len()
}

// ---------------------------------------------------------------------------
// 14. Response fields, server push, and version selection -- `on_header`
//     (`lib/http2.c:1392-1565`), `push_promise` (`:774-885`) and
//     `Curl_http2_may_switch` (`:2848-2864`).

/// Where one decoded response field belongs, and what it produced.
///
/// `on_header` has four destinations and picks between them by inspecting the
/// frame type and the stream's state, in that order. The four are named here so
/// that a caller handing decoded fields over cannot put one in the wrong place,
/// and so that a test can assert which destination was chosen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FieldProjection {
    /// A `:status` pseudo-header (`lib/http2.c:1499-1536`). Two things come out
    /// of it, and both reach the application.
    Status {
        /// The line pushed into the header store: `":status:NNN\r"`, origin
        /// [`CURLH_PSEUDO`].
        store_line: Vec<u8>,
        /// The status line written out: `"HTTP/2 NNN \r\n"`, trailing space
        /// included.
        status_line: Vec<u8>,
        /// The decoded code, which the stream now records.
        code: i32,
    },
    /// An ordinary response field (`:1539-1552`): one `"name: value\r\n"` line
    /// written out and stored with [`crate::headers::CURLH_HEADER`].
    Header {
        /// The projected line.
        line: Vec<u8>,
    },
    /// A field arriving after the body started, which makes it a TRAILER
    /// (`:1484-1497`). It has gone into the stream's SEPARATE trailer store and
    /// produces nothing now: the lines are emitted together at stream close,
    /// tagged [`CURLH_TRAILER`].
    Trailer,
    /// A field of a `PUSH_PROMISE` (`:1423-1482`). It has gone into the
    /// stream's [`PushHeaders`] as `"name:value"` and produces nothing: the
    /// push callback reads it through `curl_pushheader_bynum` and
    /// `curl_pushheader_byname`.
    PushPromise,
}

impl FieldProjection {
    /// The origin bit a store push carries, or [`None`] for a projection that
    /// stores nothing now.
    ///
    /// The precedence `CONNECT > 1XX > TRAILER > HEADER` lives in
    /// [`crate::headers::classify_origin`] and is not restated; what is stated
    /// here is which of the five bits each destination lands on.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) const fn origin(&self) -> Option<u32> {
        match self {
            Self::Status { .. } => Some(CURLH_PSEUDO),
            Self::Header { .. } => Some(crate::headers::CURLH_HEADER),
            Self::Trailer | Self::PushPromise => None,
        }
    }
}

impl CfH2 {
    /// `on_header(session, frame, name, namelen, value, valuelen, ...)`
    /// (`lib/http2.c:1392-1565`): file one decoded field.
    ///
    /// `h2` decompressed it; this decides where it goes, and the ORDER of the
    /// four tests is the decision:
    ///
    /// 1. a `PUSH_PROMISE` frame's fields go to the push store, whatever they
    ///    are named -- so a promised `:status` is a push field and not a status;
    /// 2. otherwise, once the body has started, the field is a TRAILER;
    /// 3. otherwise, a field named `:status` is the status;
    /// 4. otherwise it is an ordinary header.
    ///
    /// Reversing 2 and 3 would file a trailing `:status` as a second status;
    /// reversing 1 and 2 would file a promise's fields as trailers of the
    /// stream that received the promise.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`] with no current transfer or no stream, which is the
    /// C's *"Internal NULL stream"* `failf` and
    /// `NGHTTP2_ERR_CALLBACK_FAILURE` (`:1416-1419`);
    /// [`CURLcode::BadFunctionArgument`] from
    /// [`crate::protocols::http1::decode_status`] for a `:status` that is not
    /// three digits; [`CURLcode::TooLarge`] from the push store at its 1,280
    /// field ceiling, at which point [`TOO_MANY_PUSH_PROMISE_HEADERS`] is the
    /// text to report; whatever the trailer store reports.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    pub(crate) fn on_response_field(
        &mut self,
        mid: u32,
        frame_type: FrameType,
        name: &[u8],
        value: &[u8],
    ) -> CodeResult<FieldProjection> {
        // 1. `:1423-1482`.
        if frame_type == FrameType::PushPromise {
            let stream = self.ctx.stream_mut(mid).ok_or(CURLcode::Http2)?;
            stream.push_promise_field(name, value)?;
            return Ok(FieldProjection::PushPromise);
        }

        let body_started =
            self.ctx.stream(mid).ok_or(CURLcode::Http2)?.body_started();

        // 2. `:1484-1497`.
        if body_started {
            let stream = self.ctx.stream_mut(mid).ok_or(CURLcode::Http2)?;
            stream.add_trailer(name, value)?;
            return Ok(FieldProjection::Trailer);
        }

        // 3. `:1499-1536`.
        if name == HTTP_PSEUDO_STATUS {
            let code = super::http1::decode_status(value)?;
            let mut store = DynBuf::new(DYN_HTTP_REQUEST);
            // The C formats the PARSED code with `%u`, not the received bytes,
            // so a value of `"200"` and a value of `"200"` with different
            // padding cannot produce two different store lines.
            let unsigned = u32::try_from(code).unwrap_or(0);
            pseudo_status_line(&mut store, unsigned)?;
            let mut line = DynBuf::new(DYN_HTTP_REQUEST);
            // The status LINE carries the received bytes, as `:1520` does.
            status_line(&mut line, value)?;
            let store_line = store.take();
            let status_line = line.take();
            let projected = status_line.len();
            if let Some(stream) = self.ctx.stream_mut(mid) {
                stream.set_status_code(code);
                stream.account_response_header(projected);
            }
            return Ok(FieldProjection::Status {
                store_line,
                status_line,
                code,
            });
        }

        // 4. `:1539-1552`.
        let mut line = DynBuf::new(DYN_HTTP_REQUEST);
        header_line(&mut line, name, value)?;
        let projected = line.take();
        if let Some(stream) = self.ctx.stream_mut(mid) {
            stream.account_response_header(projected.len());
        }
        Ok(FieldProjection::Header { line: projected })
    }

    /// The `:authority` check `on_header` performs on a `PUSH_PROMISE`
    /// (`lib/http2.c:1426-1450`).
    ///
    /// RFC 9113 section 8.4 -- the C cites RFC 7540 section 8.2 -- requires
    /// that *"a client MUST treat a PUSH_PROMISE for which the server is not
    /// authoritative as a stream error of type PROTOCOL_ERROR"*, and the C's
    /// test is a disjunction that is easy to get backwards:
    ///
    /// ```c
    /// if(!curl_strequal(check, value) &&
    ///    ((conn->remote_port != conn->given->defport) ||
    ///     !curl_strequal(conn->host.name, value)))
    /// ```
    ///
    /// where `check` is `"host:port"`. So the promise is authoritative when the
    /// promised authority equals `"host:port"`, OR when the port is the
    /// scheme's default AND the authority equals the bare host. Both
    /// comparisons are CASE-INSENSITIVE, because `curl_strequal` is, which
    /// matters for a hostname.
    ///
    /// Returns `true` when the promise may be accepted.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    #[must_use]
    pub(crate) fn push_authority_is_ours(
        host: &[u8],
        remote_port: u16,
        default_port: u16,
        promised: &[u8],
    ) -> bool {
        let mut check = Vec::with_capacity(host.len() + 6);
        check.extend_from_slice(host);
        check.extend_from_slice(H2_COLON);
        check.extend_from_slice(remote_port.to_string().as_bytes());
        if check.len() == promised.len() && casecompare(&check, promised) {
            return true;
        }
        remote_port == default_port
            && host.len() == promised.len()
            && casecompare(host, promised)
    }

    /// The `RST_STREAM` a non-authoritative `PUSH_PROMISE` earns
    /// (`lib/http2.c:1443-1444`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::Http2`] when the frame cannot be built or queued.
    #[allow(dead_code)] // consumer: the transfer core, and this module's tests
    pub(crate) fn reject_push(&mut self, stream_id: u32) -> CodeResult<()> {
        let frame = rst_stream_frame(stream_id, H2Error::PROTOCOL_ERROR)?;
        self.ctx.queue_frame(&frame)
    }
}

/// `Curl_http2_may_switch(data)` (`lib/http2.c:2848-2864`): may this transfer
/// speak HTTP/2 immediately, without ALPN and without an upgrade?
///
/// Three conditions, all of which must hold:
///
/// * the connection is not already at HTTP/2 -- `Curl_conn_http_version(...) <
///   20`;
/// * HTTP/2 is among the wanted majors -- `neg.wanted & CURL_HTTP_V2x`;
/// * prior knowledge was asked for -- `neg.h2_prior_knowledge`.
///
/// And one refusal that overrides all three: a non-tunnelling HTTP proxy, with
/// the C's own `infof` *"Ignoring HTTP/2 prior knowledge due to proxy"* and its
/// comment *"We do not support HTTP/2 proxies yet"* (`:2854-2858`).
///
/// [`HttpNegotiation`] is declared in `protocols/mod.rs` and consumed here
/// rather than re-declared, which is what keeps the version policy in one
/// place.
#[allow(dead_code)] // consumer: `crate::conn`'s connection setup
#[must_use]
pub(crate) fn may_switch(
    conn_http_version: i32,
    neg: &HttpNegotiation,
    http_proxy: bool,
    tunnel_proxy: bool,
) -> bool {
    if conn_http_version >= HTTP2_VERSION {
        return false;
    }
    if !neg.wanted.intersects(super::CURL_HTTP_V2X) {
        return false;
    }
    if !neg.h2_prior_knowledge {
        return false;
    }
    // `:2853-2860`.
    !(http_proxy && !tunnel_proxy)
}

/// The `infof` a refused prior-knowledge switch emits
/// (`lib/http2.c:2857`).
///
/// Reproduced verbatim: it reaches `--verbose` output.
#[allow(dead_code)] // consumer: the transfer core, and this module's tests
#[rustfmt::skip]
pub(crate) const IGNORING_PRIOR_KNOWLEDGE: &str =
    "Ignoring HTTP/2 prior knowledge due to proxy";

/// Whether the `h2c` upgrade dance applies -- the four conditions
/// `H1_HD_UPGRADE` tests before calling `Curl_http2_request_upgrade`
/// (`lib/http.c:2956-2961`).
///
/// `protocols/http1.rs`'s `add_upgrade` already performs exactly this
/// conjunction before reaching [`UpgradeWriter::h2c`], which is why this
/// function exists for the callers that must decide EARLIER -- the connection
/// setup, which has to know whether to install this filter at all -- rather
/// than being called from the request writer a second time.
#[allow(dead_code)] // consumer: `crate::conn`'s connection setup
#[must_use]
pub(crate) fn wants_h2c_upgrade(
    conn_is_ssl: bool,
    httpversion: u8,
    neg: &HttpNegotiation,
) -> bool {
    !conn_is_ssl
        && httpversion < 20
        && neg.wanted.intersects(super::CURL_HTTP_V2X)
        && neg.h2_upgrade
}

/// `Curl_http2_upgrade(data, conn, sockindex, mem, nread)`
/// (`lib/http2.c:2905-2956`): take the connection over after a `101 Switching
/// Protocols`.
///
/// The `101` itself is handled by `protocols/http1.rs`, which owns the
/// response side; what this performs is the handover, and the C's four steps
/// are reproduced:
///
/// 1. the filter is created with `via_h1_upgrade` true, which is [`CfH2::new`]'s
///    fourth argument;
/// 2. `data->req.httpversion_sent = 20`, `data->req.header = TRUE` -- *"we
///    expect the real response to come in h2"* -- and
///    `data->req.headerline = 0`;
/// 3. any bytes that arrived AFTER the `101` are already HTTP/2 and are queued
///    as connection input (`:2927-2947`). A short copy is the C's
///    [`CURLcode::Http2`] with *"connection buffer size could not take all
///    data"*, which [`H2ConnCtx::accept_input`] reports;
/// 4. the chain is connected and `CF_CTRL_CONN_INFO_UPDATE` is distributed,
///    which is what records `httpversion_seen = 20`.
///
/// Step 2 belongs to the transfer and is reported through
/// [`UpgradeHandover`] rather than performed here, because a connection filter
/// cannot reach `data->req`.
///
/// # Errors
///
/// [`CURLcode::RecvError`] or [`CURLcode::Http2`] from queueing the leftover
/// bytes, exactly as `:2935-2944` reports them.
#[allow(dead_code)] // consumer: `crate::conn`'s connection setup
pub(crate) fn upgrade_handover(
    filter: &mut CfH2,
    leftover: &[u8],
) -> CodeResult<UpgradeHandover> {
    if !leftover.is_empty() {
        filter.ctx_mut().accept_input(leftover)?;
    }
    Ok(UpgradeHandover {
        httpversion_sent: HTTP2_VERSION,
        expect_header: true,
        headerline: 0,
        copied: leftover.len(),
    })
}

/// Complete h2c handover including the implicit stream-1 state h2 needs.
#[allow(dead_code)] // consumer: the HTTP/1 101 handover
pub(crate) fn upgrade_handover_with_request(
    filter: &mut CfH2,
    mid: u32,
    fields: &HeaderSet,
    leftover: &[u8],
) -> CurlResult<UpgradeHandover> {
    filter.seed_upgrade_stream(mid, fields)?;
    upgrade_handover(filter, leftover).map_err(Error::new)
}

/// What [`upgrade_handover`] tells the transfer to record.
///
/// Three `data->req` members and the byte count, returned as a value because
/// `data->req` belongs to [`crate::transfer`] and a filter must not reach into
/// it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct UpgradeHandover {
    /// `data->req.httpversion_sent = 20` (`lib/http2.c:2923`).
    pub(crate) httpversion_sent: i32,
    /// `data->req.header = TRUE` (`:2924`) -- the real response arrives in
    /// HTTP/2.
    pub(crate) expect_header: bool,
    /// `data->req.headerline = 0` (`:2925`) -- the header line counter
    /// restarts.
    pub(crate) headerline: i32,
    /// How many leftover bytes were queued, which the C reports with
    /// `infof` *"Copied HTTP/2 data in stream buffer to connection buffer after
    /// upgrade: len=%zu"* (`:2945-2946`).
    pub(crate) copied: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::tests::{
        events, new_log, EventLog, InMemory, TransportHandle,
    };
    use crate::headers::{
        classify_origin, CLIENTWRITE_1XX, CLIENTWRITE_CONNECT,
        CLIENTWRITE_HEADER, CLIENTWRITE_TRAILER, CURLH_1XX, CURLH_CONNECT,
        CURLH_HEADER, MAX_PUSH_PROMISE_HEADERS,
    };
    use crate::util::timeval::TestClock;

    fn settings(push: bool) -> SettingsTable {
        SettingsTable::populate(100, H2_STREAM_WINDOW_SIZE_INITIAL as u32, push)
    }

    fn filter_with_transport(
        push: bool,
        via_h1_upgrade: bool,
    ) -> (CfH2, TransportHandle, EventLog) {
        let log = new_log();
        let (transport, state) = InMemory::new("MEM", &log);
        let mut filter = CfH2::new(
            SocketIndex::First,
            Some(ConnId::new(7)),
            settings(push),
            via_h1_upgrade,
        );
        filter.base_mut().set_next(Some(link(transport)));
        (filter, state, log)
    }

    fn connect_filter(filter: &mut CfH2, clock: &TestClock) {
        let mut cx = CallCtx::new(clock);
        assert!(filter.connect(&mut cx).expect("HTTP/2 connect"));
    }

    fn output(state: &TransportHandle) -> Vec<u8> {
        state.borrow().output.clone()
    }

    fn one_setting_frame(id: SettingsId, value: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        SettingsEntry::new(id, value).encode(&mut payload);
        frame(FrameType::Settings, FRAME_FLAG_NONE, 0, &payload)
            .expect("one SETTINGS entry")
    }

    #[test]
    fn settings_are_exactly_three_entries_in_curl_order() {
        let table = settings(false);
        assert_eq!(
            table.entries.map(|entry| entry.id),
            [
                SettingsId::MaxConcurrentStreams,
                SettingsId::InitialWindowSize,
                SettingsId::EnablePush,
            ]
        );
        assert_eq!(table.max_concurrent_streams(), 100);
        assert_eq!(table.initial_window_size(), 64 * 1024);
        assert_eq!(table.enable_push(), 0);

        #[rustfmt::skip]
        let payload = [
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
            0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(pack_settings_payload(&table).unwrap(), payload);

        let mut expected =
            vec![0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        expected.extend_from_slice(&payload);
        assert_eq!(settings_frame(&table).unwrap(), expected);

        let with_push = settings(true);
        assert_eq!(with_push.enable_push(), 1);
        let pushed = pack_settings_payload(&with_push).unwrap();
        assert_eq!(pushed.last(), Some(&1));
    }

    #[test]
    fn initial_window_size_matches_every_measured_rate_branch() {
        let unlimited = RateLimit::default();
        assert_eq!(initial_win_size(&unlimited), 64 * 1024);

        let low = RateLimit::new(100, 0, CurlTime::ZERO);
        assert_eq!(initial_win_size(&low), 8192);

        let middle = RateLimit::new(30_000, 0, CurlTime::ZERO);
        assert_eq!(initial_win_size(&middle), 30_000);

        let boundary = RateLimit::new(64 * 1024, 0, CurlTime::ZERO);
        assert_eq!(initial_win_size(&boundary), 64 * 1024);

        let high = RateLimit::new(1_000_000, 0, CurlTime::ZERO);
        assert_eq!(initial_win_size(&high), 64 * 1024);
    }

    #[test]
    fn all_nine_window_constants_keep_their_derivations() {
        assert_eq!(H2_CHUNK_SIZE, 16 * 1024);
        assert_eq!(H2_CONN_WINDOW_SIZE, 10 * 1024 * 1024);
        assert_eq!(H2_NW_RECV_CHUNKS, H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE);
        assert_eq!(H2_NW_SEND_CHUNKS, 1);
        assert_eq!(H2_STREAM_WINDOW_SIZE_MAX, 10 * 1024 * 1024);
        assert_eq!(H2_STREAM_WINDOW_SIZE_INITIAL, 64 * 1024);
        assert_eq!(
            H2_STREAM_SEND_CHUNKS,
            H2_STREAM_WINDOW_SIZE_INITIAL / H2_CHUNK_SIZE
        );
        assert_eq!(H2_STREAM_POOL_SPARES, H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE);
        assert_eq!(HTTP2_HUGE_WINDOW_SIZE, 100 * H2_STREAM_WINDOW_SIZE_MAX);
    }

    #[test]
    fn h2c_upgrade_headers_and_base64_are_byte_exact() {
        let table = settings(false);
        assert_eq!(binsettings(&table).unwrap(), "AAMAAABkAAQAAQAAAAIAAAAA");

        let mut request = DynBuf::new(DYN_HTTP_REQUEST);
        let mut state = RequestState::default();
        request_upgrade(&mut request, &mut state, &table).unwrap();
        assert_eq!(
            request.as_slice(),
            b"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAQAAAAIAAAAA\r\n"
        );
        assert!(state.http_hd_upgrade);
        assert!(state.http_hd_h2_settings);
        assert_eq!(state.upgr101, Upgrade101::H2);
        assert!(state.upgrade_in_progress);

        let mut eventual = request.take();
        eventual.extend_from_slice(b"Connection: Upgrade, HTTP2-Settings\r\n");
        assert_eq!(
            eventual,
            b"Upgrade: h2c\r\n\
              HTTP2-Settings: AAMAAABkAAQAAQAAAAIAAAAA\r\n\
              Connection: Upgrade, HTTP2-Settings\r\n"
        );
    }

    #[test]
    fn pseudo_headers_keep_colons_and_regular_fields_keep_curl_order() {
        let mut headers = HeaderSet::new();
        headers.add(b"Host", b"example.test").unwrap();
        headers.add(b"X-Zeta", b"z").unwrap();
        headers.add(b"Connection", b"keep-alive").unwrap();
        headers.add(b"TE", b"gzip, trailers").unwrap();
        headers.add(b"X-Alpha", b"a").unwrap();
        let request = H1Request {
            method: b"GET".to_vec(),
            path: b"/resource".to_vec(),
            scheme: None,
            authority: None,
            headers,
        };

        let fields = req_to_h2(&request, true).unwrap();
        let actual: Vec<(Vec<u8>, Vec<u8>)> = fields
            .iter()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(
            actual,
            vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"https".to_vec()),
                (b":authority".to_vec(), b"example.test".to_vec()),
                (b":path".to_vec(), b"/resource".to_vec()),
                (b"x-zeta".to_vec(), b"z".to_vec()),
                (b"te".to_vec(), b"trailers".to_vec()),
                (b"x-alpha".to_vec(), b"a".to_vec()),
            ]
        );
        assert!(fields
            .entries()
            .iter()
            .take(4)
            .all(|entry| entry.name().first() == Some(&b':')));
    }

    #[test]
    fn transient_h2_headermap_never_silently_regroups_fields() {
        let mut contiguous = HeaderSet::new();
        contiguous.set_opts(true);
        contiguous.add(HTTP_PSEUDO_METHOD, b"GET").unwrap();
        contiguous.add(HTTP_PSEUDO_SCHEME, b"https").unwrap();
        contiguous
            .add(HTTP_PSEUDO_AUTHORITY, b"example.test")
            .unwrap();
        contiguous.add(HTTP_PSEUDO_PATH, b"/").unwrap();
        contiguous.add(b"x-a", b"one").unwrap();
        contiguous.add(b"x-a", b"two").unwrap();
        contiguous.add(b"x-b", b"three").unwrap();
        let request = request_for_h2(&contiguous).unwrap();
        let ordered: Vec<(&str, &[u8])> = request
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect();
        assert_eq!(
            ordered,
            vec![
                ("x-a", b"one".as_slice()),
                ("x-a", b"two".as_slice()),
                ("x-b", b"three".as_slice()),
            ]
        );

        let mut interleaved = contiguous.clone();
        interleaved.reset();
        interleaved.set_opts(true);
        interleaved.add(HTTP_PSEUDO_METHOD, b"GET").unwrap();
        interleaved.add(HTTP_PSEUDO_SCHEME, b"https").unwrap();
        interleaved
            .add(HTTP_PSEUDO_AUTHORITY, b"example.test")
            .unwrap();
        interleaved.add(HTTP_PSEUDO_PATH, b"/").unwrap();
        interleaved.add(b"x-a", b"one").unwrap();
        interleaved.add(b"x-b", b"two").unwrap();
        interleaved.add(b"x-a", b"three").unwrap();
        assert!(matches!(request_for_h2(&interleaved), Err(CURLcode::Http2)));
    }

    #[test]
    fn trailers_use_a_separate_store_and_trailer_origin() {
        let mut filter =
            CfH2::new(SocketIndex::First, None, settings(false), false);
        filter.ctx.apply_settings(&settings(false));
        let stream = filter.ctx.data_setup(11);
        stream.set_id(1);
        stream.set_body_started();

        assert_eq!(
            filter
                .on_response_field(
                    11,
                    FrameType::Headers,
                    b"x-trailer",
                    b"value",
                )
                .unwrap(),
            FieldProjection::Trailer
        );
        let stream = filter.ctx.stream(11).unwrap();
        assert_eq!(stream.trailers().count(), 1);
        assert_eq!(stream.trailers().getn(0).unwrap().name(), b"x-trailer");
        assert_eq!(stream.trailers().getn(0).unwrap().value(), b"value");
        assert_eq!(TRAILER_ORIGIN, CURLH_TRAILER);
        assert_eq!(
            classify_origin(CLIENTWRITE_HEADER | CLIENTWRITE_TRAILER),
            Some(CURLH_TRAILER)
        );
        assert_eq!(classify_origin(CLIENTWRITE_HEADER), Some(CURLH_HEADER));
        assert_eq!(
            classify_origin(
                CLIENTWRITE_HEADER
                    | CLIENTWRITE_TRAILER
                    | CLIENTWRITE_1XX
                    | CLIENTWRITE_CONNECT,
            ),
            Some(CURLH_CONNECT)
        );
        assert_eq!(
            classify_origin(
                CLIENTWRITE_HEADER | CLIENTWRITE_TRAILER | CLIENTWRITE_1XX,
            ),
            Some(CURLH_1XX)
        );
        assert_eq!(
            stream.flush_trailers().unwrap(),
            vec![b"x-trailer: value\r\n".to_vec()]
        );
    }

    #[test]
    fn push_headers_match_the_c_abi_and_growth_contract() {
        let mut stream = H2StreamCtx::new();
        stream.push_promise_field(b"Name", b"first").unwrap();
        assert_eq!(stream.push_headers_alloc(), 10);
        stream.push_promise_field(b"name", b"second").unwrap();
        stream.push_promise_field(b"x", b" padded ").unwrap();

        assert_eq!(
            stream.push_headers().by_num(0),
            Some(b"Name:first".as_slice())
        );
        assert_eq!(
            stream.push_headers().by_name(b"Name"),
            Some(b"first".as_slice())
        );
        assert_eq!(
            stream.push_headers().by_name(b"name"),
            Some(b"second".as_slice())
        );
        assert_eq!(stream.push_headers().by_name(b"NAME"), None);
        assert_eq!(
            stream.push_headers().by_name(b"x"),
            Some(b" padded ".as_slice())
        );
        assert_eq!(stream.push_headers().by_name(b""), None);
        assert_eq!(stream.push_headers().by_name(b":"), None);
        assert_eq!(stream.push_headers().by_name(b"a:b"), None);
        assert_eq!(stream.push_headers().by_name(b"\0ignored"), None);

        while stream.push_headers().count() < 10 {
            stream.push_promise_field(b"a", b"b").unwrap();
        }
        assert_eq!(stream.push_headers_alloc(), 10);
        stream.push_promise_field(b"a", b"b").unwrap();
        assert_eq!(stream.push_headers_alloc(), 20);

        while stream.push_headers().count() < MAX_PUSH_PROMISE_HEADERS {
            stream.push_promise_field(b"a", b"b").unwrap();
        }
        assert_eq!(stream.push_headers_alloc(), 1280);
        assert_eq!(
            stream.push_promise_field(b"a", b"b"),
            Err(CURLcode::TooLarge)
        );
        assert!(stream.push_headers().is_empty());
        assert_eq!(stream.push_headers_alloc(), 0);
        assert_eq!(
            TOO_MANY_PUSH_PROMISE_HEADERS,
            "Too many PUSH_PROMISE headers"
        );
        assert_eq!(CURL_PUSH_OK, 0);
        assert_eq!(CURL_PUSH_DENY, 1);
        assert_eq!(CURL_PUSH_ERROROUT, 2);
    }

    #[test]
    fn local_window_changes_emit_only_the_measured_updates() {
        let clock = TestClock::new(CurlTime::ZERO);
        let mut cx = CallCtx::new(&clock);
        let mut filter =
            CfH2::new(SocketIndex::First, None, settings(false), false);
        filter.ctx.apply_settings(&settings(false));
        filter.ctx.data_setup(1).set_id(1);

        let desired = H2_STREAM_WINDOW_SIZE_MAX as i32;
        let initial = H2_STREAM_WINDOW_SIZE_INITIAL as i32;
        let grow = LocalWindowChange::decide(desired, initial, initial);
        assert_eq!(
            grow,
            LocalWindowChange::Grow {
                size: desired,
                increment: desired - initial,
            }
        );
        filter.apply_window_change(&mut cx, 1, grow).unwrap();
        let expected = window_update_frame(1, desired - initial).unwrap();
        let mut actual = vec![0; expected.len()];
        assert_eq!(
            filter.ctx.outbufq.read(&mut actual).unwrap(),
            expected.len()
        );
        assert_eq!(actual, expected);
        assert_eq!(filter.ctx.stream(1).unwrap().local_window_size(), desired);

        let shrink = LocalWindowChange::decide(0, desired, desired);
        assert_eq!(shrink, LocalWindowChange::Shrink { size: 0 });
        filter.apply_window_change(&mut cx, 1, shrink).unwrap();
        assert!(filter.ctx.outbufq.is_empty());

        filter
            .ctx
            .stream_mut(1)
            .unwrap()
            .account_inbound_window(4096);
        let effective =
            filter.ctx.stream(1).unwrap().effective_local_window_size();
        let resume = LocalWindowChange::decide(desired, 0, effective);
        assert_eq!(resume.increment(), Some(desired - effective));
        filter.apply_window_change(&mut cx, 1, resume).unwrap();
        let expected = window_update_frame(1, desired - effective).unwrap();
        let mut actual = vec![0; expected.len()];
        filter.ctx.outbufq.read(&mut actual).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn control_frames_keep_their_exact_wire_shapes() {
        assert_eq!(
            ping_frame().unwrap(),
            [0, 0, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
        );
        assert_eq!(
            rst_stream_frame(3, H2Error::STREAM_CLOSED).unwrap(),
            [0, 0, 4, 3, 0, 0, 0, 0, 3, 0, 0, 0, 5]
        );
        let goaway =
            goaway_frame(3, H2Error::NO_ERROR, H2_SHUTDOWN_REASON).unwrap();
        assert_eq!(FrameHead::parse(&goaway).unwrap().length, 17);
        assert_eq!(goaway.last(), Some(&0));
        assert_eq!(H2_SHUTDOWN_REASON, b"shutdown\0");
    }

    #[test]
    fn h2_reason_registry_and_http11_required_match_h2() {
        assert_eq!(H2Error::from_reason(h2::Reason::NO_ERROR).as_u32(), 0);
        assert_eq!(
            H2Error::from_reason(h2::Reason::PROTOCOL_ERROR).as_u32(),
            1
        );
        assert_eq!(H2Error::from_reason(h2::Reason::STREAM_CLOSED).as_u32(), 5);
        assert_eq!(
            H2Error::from_reason(h2::Reason::REFUSED_STREAM).as_u32(),
            7
        );
        assert_eq!(
            H2Error::from_reason(h2::Reason::HTTP_1_1_REQUIRED).as_u32(),
            13
        );
        assert!(is_http_1_1_required(H2Error::HTTP_1_1_REQUIRED));
        assert!(!is_http_1_1_required(H2Error::NO_ERROR));
    }

    #[test]
    fn filter_identity_queries_and_non_chaining_contract_are_exact() {
        let clock = TestClock::new(CurlTime::ZERO);
        let (mut filter, state, log) = filter_with_transport(false, false);
        let mut cx = CallCtx::new(&clock);

        assert_eq!(filter.trace_name(), "HTTP/2");
        assert_eq!(filter.cf_type(), CF_TYPE_MULTIPLEX | CF_TYPE_HTTP);
        assert_eq!(
            filter.query(&mut cx, CfQuery::HttpVersion).unwrap(),
            CfQueryValue::HttpVersion(20)
        );

        state.borrow_mut().socket = 42;
        assert_eq!(
            filter.query(&mut cx, CfQuery::Socket).unwrap(),
            CfQueryValue::Socket(42)
        );
        let unknown = filter.query(&mut cx, CfQuery::RemoteAddr);
        assert_eq!(unknown.unwrap_err().code(), CURLcode::UnknownOption);

        filter.cntrl(&mut cx, CfControl::DataSetup).unwrap();
        assert!(state.borrow().controls.is_empty());
        assert!(filter.shutdown(&mut cx).unwrap());
        assert_eq!(state.borrow().shutdowns, 0);
        filter.destroy(&mut cx);
        assert!(!events(&log).iter().any(|event| event == "MEM:destroy"));
    }

    #[test]
    fn h2_driver_rewrites_settings_and_frames_request_headers() {
        let clock = TestClock::new(CurlTime::ZERO);
        let (mut filter, state, _) = filter_with_transport(false, false);
        connect_filter(&mut filter, &clock);

        let initial = output(&state);
        assert!(initial.starts_with(H2_CLIENT_PREFACE));
        let settings_offset = H2_CLIENT_PREFACE.len();
        let expected_settings = settings_frame(&settings(false)).unwrap();
        assert_eq!(
            initial
                .get(settings_offset..settings_offset + expected_settings.len())
                .unwrap(),
            expected_settings
        );
        let window = window_update_frame(
            0,
            i32::try_from(HTTP2_HUGE_WINDOW_SIZE - H2_DEFAULT_WINDOW_SIZE)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            initial
                .get(settings_offset + expected_settings.len()..)
                .unwrap(),
            window
        );
        assert!(filter.ctx.driver.as_ref().unwrap().settings_rewritten());

        let baseline = initial.len();
        filter.set_current(1);
        let request = b"GET /demo HTTP/1.1\r\n\
                        Host: example.test\r\n\
                        X-Zeta: z\r\n\
                        X-Alpha: a\r\n\r\n";
        let mut cx = CallCtx::new(&clock);
        assert_eq!(filter.send(&mut cx, request, true).unwrap(), request.len());

        let sent = output(&state);
        let frame = sent.get(baseline..).unwrap();
        let head = FrameHead::parse(frame).unwrap();
        assert_eq!(head.frame_type(), Some(FrameType::Headers));
        assert_eq!(head.stream_id, 1);
        assert_ne!(head.length, 0);
        assert_ne!(head.flags & FRAME_FLAG_END_HEADERS, 0);
        assert_eq!(filter.ctx.stream(1).unwrap().id(), 1);
    }

    #[test]
    fn peer_settings_drive_max_concurrent_query_through_h2() {
        let clock = TestClock::new(CurlTime::ZERO);
        let (mut filter, state, _) = filter_with_transport(false, false);
        connect_filter(&mut filter, &clock);
        state.borrow_mut().input =
            one_setting_frame(SettingsId::MaxConcurrentStreams, 7);

        let mut cx = CallCtx::new(&clock);
        filter
            .progress_ingress(&mut cx, H2_CHUNK_SIZE)
            .expect("peer SETTINGS");
        assert_eq!(
            filter.query(&mut cx, CfQuery::MaxConcurrent).unwrap(),
            CfQueryValue::MaxConcurrent(7)
        );
        filter.progress_egress(&mut cx).unwrap();

        let sent = output(&state);
        let ack = settings_ack_frame().unwrap();
        assert!(sent.windows(ack.len()).any(|candidate| candidate == ack));
    }

    #[test]
    fn h2_driver_decodes_response_data_and_keeps_trailers_separate() {
        let clock = TestClock::new(CurlTime::ZERO);
        let (mut filter, state, _) = filter_with_transport(false, false);
        connect_filter(&mut filter, &clock);
        filter.set_current(1);
        let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut cx = CallCtx::new(&clock);
        filter.send(&mut cx, request, true).unwrap();

        let mut peer =
            frame(FrameType::Settings, FRAME_FLAG_NONE, 0, &[]).unwrap();
        peer.extend_from_slice(
            &frame(FrameType::Headers, FRAME_FLAG_END_HEADERS, 1, &[0x88])
                .unwrap(),
        );
        peer.extend_from_slice(
            &frame(FrameType::Data, FRAME_FLAG_NONE, 1, b"ok").unwrap(),
        );
        let mut trailer_block = vec![0x00, 0x09];
        trailer_block.extend_from_slice(b"x-trailer");
        trailer_block.extend_from_slice(&[0x01, b'v']);
        peer.extend_from_slice(
            &frame(
                FrameType::Headers,
                FRAME_FLAG_END_HEADERS | FRAME_FLAG_END_STREAM,
                1,
                &trailer_block,
            )
            .unwrap(),
        );
        state.borrow_mut().input = peer;

        let mut received = [0u8; 128];
        let count = filter.recv(&mut cx, &mut received).unwrap();
        assert_eq!(&received[..count], b"HTTP/2 200 \r\n\r\nok");
        let stream = filter.ctx.stream(1).unwrap();
        assert!(stream.is_closed());
        assert_eq!(stream.received_data(), 2);
        assert_eq!(stream.trailers().count(), 1);
        assert_eq!(
            stream.flush_trailers().unwrap(),
            vec![b"x-trailer: v\r\n".to_vec()]
        );
    }

    #[test]
    fn h2c_handover_seeds_stream_one_without_duplicate_headers() {
        let clock = TestClock::new(CurlTime::ZERO);
        let (mut filter, state, _) = filter_with_transport(false, true);
        connect_filter(&mut filter, &clock);
        let baseline = output(&state).len();

        let mut h1_headers = HeaderSet::new();
        h1_headers.add(b"Host", b"example.test").unwrap();
        let h1 = H1Request {
            method: b"GET".to_vec(),
            path: b"/first".to_vec(),
            scheme: None,
            authority: None,
            headers: h1_headers,
        };
        let fields = req_to_h2(&h1, false).unwrap();
        filter.seed_upgrade_stream(1, &fields).unwrap();
        let mut cx = CallCtx::new(&clock);
        filter.progress_egress(&mut cx).unwrap();
        assert_eq!(output(&state).len(), baseline);
        assert_eq!(filter.ctx.stream(1).unwrap().id(), 1);

        filter.set_current(2);
        let second = b"GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n";
        filter.send(&mut cx, second, true).unwrap();
        let sent = output(&state);
        let head = FrameHead::parse(sent.get(baseline..).unwrap()).unwrap();
        assert_eq!(head.frame_type(), Some(FrameType::Headers));
        assert_eq!(head.stream_id, 3);
    }

    #[test]
    fn need_flush_falls_through_only_when_h2_has_nothing_pending() {
        let clock = TestClock::new(CurlTime::ZERO);
        let (mut filter, state, _) = filter_with_transport(false, false);
        let mut cx = CallCtx::new(&clock);
        state
            .borrow_mut()
            .answers
            .push((CfQuery::NeedFlush, CfQueryValue::NeedFlush(false)));
        assert_eq!(
            filter.query(&mut cx, CfQuery::NeedFlush).unwrap(),
            CfQueryValue::NeedFlush(false)
        );
        assert_eq!(state.borrow().queries, vec![CfQuery::NeedFlush]);

        filter.ctx.queue_frame(&ping_frame().unwrap()).unwrap();
        assert_eq!(
            filter.query(&mut cx, CfQuery::NeedFlush).unwrap(),
            CfQueryValue::NeedFlush(true)
        );
        assert_eq!(state.borrow().queries, vec![CfQuery::NeedFlush]);
    }

    #[test]
    fn alpn_is_consumed_through_query_and_never_opens_tls_here() {
        let clock = TestClock::new(CurlTime::ZERO);
        let (mut filter, state, _) = filter_with_transport(false, false);
        let mut cx = CallCtx::new(&clock);
        state.borrow_mut().answers.push((
            CfQuery::AlpnNegotiated,
            CfQueryValue::AlpnNegotiated(Some("h2".to_string())),
        ));
        assert_eq!(filter.alpn_negotiated(&mut cx).as_deref(), Some("h2"));
        assert!(filter.conn_is_ssl(&mut cx));
        assert_eq!(
            state.borrow().queries,
            vec![CfQuery::AlpnNegotiated, CfQuery::AlpnNegotiated]
        );
    }

    #[test]
    fn negotiation_selects_prior_knowledge_and_h2c_exactly() {
        let mut negotiation = HttpNegotiation {
            wanted: super::super::CURL_HTTP_V2X,
            allowed: super::super::CURL_HTTP_V2X,
            preferred: super::super::CURL_HTTP_V2X,
            h2_upgrade: true,
            h2_prior_knowledge: true,
            ..HttpNegotiation::default()
        };
        assert!(may_switch(11, &negotiation, false, false));
        assert!(!may_switch(20, &negotiation, false, false));
        assert!(!may_switch(11, &negotiation, true, false));
        assert_eq!(
            IGNORING_PRIOR_KNOWLEDGE,
            "Ignoring HTTP/2 prior knowledge due to proxy"
        );

        assert!(wants_h2c_upgrade(false, 11, &negotiation));
        assert!(!wants_h2c_upgrade(true, 11, &negotiation));
        assert!(!wants_h2c_upgrade(false, 20, &negotiation));
        negotiation.h2_upgrade = false;
        assert!(!wants_h2c_upgrade(false, 11, &negotiation));
    }

    #[test]
    fn upgrade_handover_copies_leftover_bytes_and_reports_transfer_state() {
        let clock = TestClock::new(CurlTime::ZERO);
        let (mut filter, _, _) = filter_with_transport(false, true);
        connect_filter(&mut filter, &clock);

        let mut headers = HeaderSet::new();
        headers.set_opts(true);
        headers.add(HTTP_PSEUDO_METHOD, b"GET").unwrap();
        headers.add(HTTP_PSEUDO_SCHEME, b"http").unwrap();
        headers.add(HTTP_PSEUDO_AUTHORITY, b"example.test").unwrap();
        headers.add(HTTP_PSEUDO_PATH, b"/").unwrap();
        let leftover = one_setting_frame(SettingsId::MaxConcurrentStreams, 9);
        let handover =
            upgrade_handover_with_request(&mut filter, 1, &headers, &leftover)
                .unwrap();
        assert_eq!(
            handover,
            UpgradeHandover {
                httpversion_sent: 20,
                expect_header: true,
                headerline: 0,
                copied: leftover.len(),
            }
        );
        assert!(filter.ctx.has_pending_input());
    }
}
