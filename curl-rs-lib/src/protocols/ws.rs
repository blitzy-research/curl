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
//! WebSockets: the handshake, the frame codec, the masking, and the engine
//! behind the four exported `curl_ws_*` symbols.
//!
//! # What this file supersedes, with locators
//!
//! The whole of **`lib/ws.c`, 2,011 lines**, and **`lib/ws.h`**, and it backs
//! the public contract of **`include/curl/websockets.h`, 98 lines**:
//!
//! * `include/curl/websockets.h:31-38` -- `struct curl_ws_frame`, the
//!   layout-visible metadata block; [`WsFrameMeta`] here, field for field,
//!   with `age` always zero.
//! * `include/curl/websockets.h:40-45` -- `CURLWS_TEXT`, `CURLWS_BINARY`,
//!   `CURLWS_CONT`, `CURLWS_CLOSE`, `CURLWS_PING` and `CURLWS_OFFSET`;
//!   [`CURLWS_TEXT`] and its five neighbours.
//! * `include/curl/websockets.h:60` -- `CURLWS_PONG`, declared APART from the
//!   other six under the comment `/* flags for curl_ws_send() */`;
//!   [`CURLWS_PONG`].
//! * `include/curl/websockets.h:89-90` -- the `CURLOPT_WS_OPTIONS` bitmask
//!   `CURLWS_RAW_MODE` and `CURLWS_NOAUTOPONG`; [`CURLWS_RAW_MODE`] and
//!   [`CURLWS_NOAUTOPONG`], read into [`WsSettings`].
//! * `lib/libcurl.def:98-101` -- the four exported symbols, in the file's
//!   alphabetical order: `curl_ws_meta`, `curl_ws_recv`, `curl_ws_send` and
//!   `curl_ws_start_frame`. Their engine halves are [`ws_meta`], [`ws_recv`],
//!   [`ws_send`] and [`ws_start_frame`]; the `extern "C"` shims live in
//!   `curl-rs-ffi/src/ffi/ws.rs` and NOT here.
//! * `lib/ws.c:55-74` -- the RFC 6455 bit vocabulary; [`WSBIT_FIN`] and the
//!   [`Opcode`] enumeration.
//! * `lib/ws.c:84-93` -- `struct ws_decoder`; [`WsDecoder`].
//! * **`lib/ws.c:101`** -- `uint8_t mask[4]`, the 32-bit mask held **per
//!   connection**; [`WsEncoder::mask`].
//! * `lib/ws.c:109-113` -- `struct ws_cntrl_frame`, the single pending control
//!   frame; [`PendingControl`].
//! * `lib/ws.c:117-126` -- `struct websocket`, the per-connection state;
//!   [`WebSocket`].
//! * `lib/ws.c:150-227` -- `ws_frame_firstbyte2flags`;
//!   [`firstbyte_to_flags`].
//! * `lib/ws.c:229-290` -- `ws_frame_flags2firstbyte`;
//!   [`flags_to_firstbyte`].
//! * `lib/ws.c:333-358` -- `ws_dec_next_frame`, `ws_dec_reset`, `ws_dec_init`;
//!   [`WsDecoder::next_frame`] and [`WsDecoder::reset`].
//! * `lib/ws.c:360-483` -- `ws_dec_read_head`; [`WsDecoder::read_head`].
//! * `lib/ws.c:485-515` -- `ws_dec_pass_payload`;
//!   [`WsDecoder::pass_payload`].
//! * `lib/ws.c:517-571` -- `ws_dec_pass`; [`WsDecoder::pass`].
//! * `lib/ws.c:573-586` -- `update_meta`; [`WebSocket::update_meta`].
//! * `lib/ws.c:588-777` -- the `ws-decode` client writer and its
//!   `ws_cw_dec_next` callback; [`WebSocket::write_body`] and
//!   [`DecodedFrame`].
//! * `lib/ws.c:629-652` -- `ws_enc_add_cntrl`; [`WebSocket::add_control`].
//! * `lib/ws.c:654-665` -- `ws_payload_remain`; [`payload_remain`].
//! * `lib/ws.c:826-928` -- `ws_enc_add_frame`; [`WsEncoder::add_frame`].
//! * **`lib/ws.c:930`** -- `ws_enc_write_head`; [`WebSocket::write_head`].
//! * **`lib/ws.c:966`** -- the masking step `buf[i] ^ enc->mask[enc->xori]`
//!   with its rotating index, inside `ws_enc_write_payload`;
//!   [`WsEncoder::write_payload`].
//! * `lib/ws.c:982-1022` -- `ws_enc_add_pending`;
//!   [`WebSocket::add_pending`].
//! * `lib/ws.c:1024-1120` -- `ws_enc_send`; [`WebSocket::encode_send`].
//! * `lib/ws.c:1122-1238` -- the `ws-encode` client reader;
//!   [`WebSocket::read_upload`].
//! * **`lib/ws.c:1245-1299`** -- `Curl_ws_request`, the handshake;
//!   [`write_handshake`], reached through [`WsUpgrade`]'s
//!   [`UpgradeWriter::websocket`].
//! * `lib/ws.c:1316-1451` -- `Curl_ws_accept`; [`accept`].
//! * **`lib/ws.c:1359-1372`** -- the three RFC 6455 response obligations,
//!   which in the C are **comments and nothing else**. [`ResponseCheck`]
//!   performs all three; see *The response check* below for the measurement
//!   that decides what is done with the verdict.
//! * `lib/ws.c:1453-1520` -- `ws_client_collect`; [`Collector`].
//! * `lib/ws.c:1530-1625` -- `curl_ws_recv`; [`ws_recv`].
//! * `lib/ws.c:1627-1683` -- `ws_flush`; [`WebSocket::flush`].
//! * `lib/ws.c:1685-1761` -- `ws_send_raw_blocking` and `ws_send_raw`;
//!   [`WebSocket::send_raw`].
//! * `lib/ws.c:1763-1838` -- `curl_ws_send`; [`ws_send`].
//! * `lib/ws.c:1840-1849` -- `ws_setup_conn`; [`Protocol::setup_connection`]
//!   on [`Ws`], the ONE slot this file overrides.
//! * `lib/ws.c:1851-1864` -- `curl_ws_meta`; [`ws_meta`].
//! * `lib/ws.c:1866-1916` -- `curl_ws_start_frame`; [`ws_start_frame`].
//! * **`lib/ws.c:1918-1936`** -- `Curl_protocol_ws`, the 17-slot vtable;
//!   [`Ws`], which DELEGATES.
//! * **`lib/ws.c:1984`** and **`lib/ws.c:1999`** -- `Curl_scheme_ws` and
//!   `Curl_scheme_wss`; [`SCHEME_WS`] and [`SCHEME_WSS`].
//! * `lib/ws.c:1940-1980` -- the disabled-build stubs, which answer
//!   `CURLE_NOT_BUILT_IN` and, for `curl_ws_meta`, `NULL`. This whole module
//!   is gated on the `websockets` feature, so those four stubs belong to
//!   `curl-rs-ffi/src/ffi/ws.rs`; the contract is recorded here so it cannot
//!   be lost -- see [`NOT_BUILT_IN`].
//!
//! Read rather than superseded: `lib/http.c:2964-2976` (the `H1_HD_UPGRADE`
//! slot that calls the handshake), `lib/http.c:3928-3975` (the `101` arm) and
//! `lib/http.c:4040-4044` (`>= 200` while a WebSocket upgrade is outstanding
//! is `CURLE_HTTP_RETURNED_ERROR`). All three belong to
//! [`super::http1`] and to the transfer core, and none is duplicated here.
//!
//! # The vtable delegates: `ws_setup_conn` is the only WebSocket-specific slot
//!
//! `Curl_protocol_ws` (`lib/ws.c:1918-1936`) is initialiser-for-initialiser
//! identical to `Curl_protocol_http` (`lib/http.c:4986-5004`) except for one
//! member:
//!
//! ```text
//! ws_setup_conn,                  /* setup_connection  <- the only one */
//! Curl_http,                      /* do_it */
//! Curl_http_done,                 /* done */
//! Curl_http_doing_pollset,        /* doing_pollset */
//! Curl_http_perform_pollset,      /* perform_pollset */
//! Curl_http_write_resp,           /* write_resp */
//! Curl_http_write_resp_hd,        /* write_resp_hd */
//! Curl_http_follow,               /* follow */
//! ```
//!
//! So [`Ws`] holds a [`super::http1::Http1`] and forwards sixteen slots to it,
//! overriding [`Protocol::setup_connection`] alone. That is a measurement
//! about the C rather than a convenience: a second transcription of
//! `Curl_http` would be a second place for the frozen request writer to drift.
//!
//! # The handshake bytes are ours, and their ORDER is the specification
//!
//! Specification 0.6.7 measures the test oracle: `compareparts`
//! (`tests/getpart.pm:351+`) joins both arrays into ONE string and compares
//! them as one string. There is no per-line matching, no normalisation and no
//! reordering, so header order, header casing and the presence of each header
//! are all load-bearing. `tests/data/test2300` fixes the three lines this file
//! contributes, in this order:
//!
//! ```text
//! Upgrade: websocket\r\n
//! Sec-WebSocket-Version: 13\r\n
//! Sec-WebSocket-Key: NDMyMTUzMjE2MzIxNzMyMQ==\r\n
//! ```
//!
//! The `Connection: Upgrade` line that follows them is emitted by
//! [`super::http1`]'s own `Connection:` slot, which reads
//! [`super::http1::RequestState::http_hd_upgrade`] -- the flag
//! [`write_handshake`] sets. It is deliberately NOT written here; writing it
//! twice would put two `Connection:` headers on the wire.
//!
//! # Randomness is injected, and that is what makes the bytes testable
//!
//! Specification 0.3.3's pattern P12 requires it, and two separate draws
//! depend on it: the 16-byte `Sec-WebSocket-Key` nonce
//! (`lib/ws.c:1277-1278`) and the 4-byte frame mask (`lib/ws.c:901-903`).
//! Both come from a `&mut dyn `[`Rng`] the caller supplies; there is no
//! global generator and no thread-local one anywhere in this file. The payoff
//! is measurable rather than stylistic -- `tests/data/test2300` and
//! `tests/data/test2302` are byte-exact oracles reachable with
//! [`crate::crypto::rand::TestRng`]:
//!
//! * `CURL_ENTROPY=12345678` makes the first sixteen bytes `4321532163217321`,
//!   whose padded base64 form is the fixture's
//!   `Sec-WebSocket-Key: NDMyMTUzMjE2MzIxNzMyMQ==`;
//! * the FIFTH draw of the same stream is `8321`, which is exactly the mask
//!   `tests/data/test2302` expects in `%hex[%8a%808321]hex%` -- a zero-length
//!   PONG. The mask therefore comes from the same generator, in the same
//!   order, four bytes at a time, low byte first.
//!
//! The encoder is padded base64 with the STANDARD alphabet
//! ([`crate::util::base64::encode`]), not the URL-safe unpadded form: the
//! fixture's `==` terminator settles it.
//!
//! # The response check, and why its verdict is not a rejection
//!
//! `lib/ws.c:1359-1377` carries three RFC 6455 obligations as comments with no
//! code beneath them: verify `Sec-WebSocket-Accept`, fail on an unsolicited
//! `Sec-WebSocket-Extensions`, fail on an unsolicited
//! `Sec-WebSocket-Protocol`. curl 8.19.0-DEV performs NONE of them, and the
//! corpus proves it rather than merely suggesting it. Every WebSocket fixture
//! -- `tests/data/test2300`, `:2301`, `:2302`, `:2304` and all 24 of the
//! `test27xx` series -- answers with
//!
//! ```text
//! Sec-WebSocket-Accept: HkPsVga7+8LuxM4RGQ5p9tZHeYs=
//! ```
//!
//! while the correct value for the key those same fixtures require curl to
//! send is `Dut04YXKjDKbXFLrc+AVmMeFsWM=`. The two differ, and the fixtures
//! pass. Enforcing the check would fail 28 fixtures that a C curl passes,
//! which specification 0.8.1 forbids twice over: wire behaviour is frozen, and
//! *"a failing fixture is evidence of an implementation defect. Editing a
//! fixture to make it pass is prohibited."*
//!
//! This file therefore does both halves honestly. [`accept_key`] implements
//! RFC 6455's algorithm in full and [`ResponseCheck`] performs all three
//! obligations, each with the [`CURLcode`] an RFC-strict client would answer
//! -- [`CURLcode::WeirdServerReply`], which is the code the C itself uses for
//! the one `101` obligation it does enforce (`lib/http.c:3934`). What
//! [`accept`] then applies is [`ResponseCheck::curl_verdict`], curl
//! 8.19.0-DEV's measured answer: the findings are traced and the handshake
//! proceeds. [`ResponseCheck::rfc_verdict`] is the strict answer, available
//! and tested, for a caller that wants it. Neither is hidden behind the other.
//!
//! # No `unsafe`, no `extern "C"`, and no TLS import
//!
//! This module backs four exported symbols and contains no `unsafe` block, no
//! `#[repr(C)]` and no `#[no_mangle]`: the C ABI surface is
//! `curl-rs-ffi/src/ffi/ws.rs`'s, and what crosses between them is
//! [`WsFrameMeta`], whose five fields map onto `struct curl_ws_frame`'s in
//! order. `wss://` needs no TLS code here either -- it is `ws://` with a TLS
//! filter in the chain [`crate::conn`] owns, exactly as `https` is `http`, so
//! there is no `use crate::tls` in this file.
//!
//! # What a WebSocket connection may never do
//!
//! Neither registry row carries `PROTOPT_CONN_REUSE` (`lib/ws.c:1993-1994`
//! and `:2008-2009`), while both HTTP rows do (`lib/http.c:5015` and `:5032`).
//! One handler serves both pairs, so the flags are the only place the
//! distinction lives: an upgraded WebSocket has left request/response
//! semantics behind and must never be returned to the pool.
//! [`super::connection_reusable`] reads that column, and
//! [`super::SCHEMES`] holds the flag sets -- [`SCHEME_WS`] consumes them
//! rather than restating them.

use core::fmt;

use sha1::{Digest, Sha1};

use crate::conn::filters::{CallCtx, FilterChain};
use crate::crypto::rand::{rand_bytes, Rng};
use crate::error::{CURLcode, CodeResult};
use crate::protocols::http1::{
    checkheaders, Http1, RequestState, UpgradeWriter,
};
use crate::protocols::{
    Proto, ProtoFuture, Protocol, Scheme, TransferCtx, CURL_HTTP_V1X, FLAGS_WS,
    FLAGS_WSS, PORT_HTTP, PORT_HTTPS,
};
// `Upgrade101` is named because [`RequestState::upgr101`] IS of that type: the
// handshake has to write `UPGR101_WS` into the request state that
// `protocols/http1.rs` hands it, and a locally-defined twin would not be
// assignable to that field. It is reached through `crate::transfer`, which
// declares the module holding it.
use crate::trace::{failf, infof, trc_feat, TraceFeature, Tracer};
use crate::transfer::request::Upgrade101;
use crate::util::base64;
use crate::util::bufq::{BufQ, BufqOpts};
use crate::util::dynbuf::DynBuf;

// -- 1. The public ABI: `include/curl/websockets.h` ------------------------

/// `CURLWS_TEXT (1 << 0)` (`include/curl/websockets.h:40`).
///
/// Every value in this group is written EXPLICITLY rather than derived from a
/// shift or from declaration order. Specification 0.6.1 is the reason: *"A C
/// program compiled against curl 8.x embeds the numeric value of every
/// enumerator it uses"*, so an application holds these seven integers in its
/// instruction stream and a renumbering would be silent.
///
/// `i32` because the field they are stored in is `int flags`
/// (`include/curl/websockets.h:33`).
#[rustfmt::skip]
pub(crate) const CURLWS_TEXT: i32 = 1;

/// `CURLWS_BINARY (1 << 1)` (`include/curl/websockets.h:41`).
#[rustfmt::skip]
pub(crate) const CURLWS_BINARY: i32 = 2;

/// `CURLWS_CONT (1 << 2)` (`include/curl/websockets.h:42`).
///
/// On a RECEIVED frame this means *"more fragments follow"*; on a frame handed
/// to [`ws_send`] it means *"this message is not finished"*. The two readings
/// are the C's and both are exercised.
#[rustfmt::skip]
pub(crate) const CURLWS_CONT: i32 = 4;

/// `CURLWS_CLOSE (1 << 3)` (`include/curl/websockets.h:43`).
#[rustfmt::skip]
pub(crate) const CURLWS_CLOSE: i32 = 8;

/// `CURLWS_PING (1 << 4)` (`include/curl/websockets.h:44`).
#[rustfmt::skip]
pub(crate) const CURLWS_PING: i32 = 16;

/// `CURLWS_OFFSET (1 << 5)` (`include/curl/websockets.h:45`).
///
/// The one flag that is not a frame type. On [`ws_send`] it means *"this call
/// starts a frame of `fragsize` bytes and supplies only the first part of
/// it"*, so the frame header is written for `fragsize` rather than for
/// `buflen` (`lib/ws.c:1063-1066`).
#[rustfmt::skip]
pub(crate) const CURLWS_OFFSET: i32 = 32;

/// `CURLWS_PONG (1 << 6)` (`include/curl/websockets.h:60`).
///
/// Declared APART from the six above, after `curl_ws_recv`'s prototype and
/// under its own comment `/* flags for curl_ws_send() */`. The separation is
/// historical -- PONG was added later -- and the value is still part of the
/// same bit space, which is why it is grouped with them here.
#[rustfmt::skip]
pub(crate) const CURLWS_PONG: i32 = 64;

/// Every frame flag, in the header's declaration order.
///
/// Held as data so that a test can assert the seven integers without
/// restating them, and so that [`frame_flag_names`] cannot fall out of step
/// with the group above.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: frame_flag_names and mod tests
pub(crate) const FRAME_FLAGS: [i32; 7] = [
    CURLWS_TEXT,
    CURLWS_BINARY,
    CURLWS_CONT,
    CURLWS_CLOSE,
    CURLWS_PING,
    CURLWS_OFFSET,
    CURLWS_PONG,
];

/// `CURLWS_RAW_MODE (1L << 0)` (`include/curl/websockets.h:89`).
///
/// A bit of the `CURLOPT_WS_OPTIONS` mask, so the width is the option's:
/// `long`, which is `i64` on all four mandated targets. Setting it disables
/// curl's framing entirely -- the application sees and supplies raw bytes --
/// which changes observable behaviour in six places, each marked in this file.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
pub(crate) const CURLWS_RAW_MODE: i64 = 1;

/// `CURLWS_NOAUTOPONG (1L << 1)` (`include/curl/websockets.h:90`).
///
/// Suppresses the automatic PONG reply to a received PING
/// (`lib/ws.c:677` and `:1475`, both reading `data->set.ws_no_auto_pong`).
#[rustfmt::skip]
#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
pub(crate) const CURLWS_NOAUTOPONG: i64 = 2;

/// The `CURLcode` the four exported symbols answer in a build without
/// WebSocket support (`lib/ws.c:1949`, `:1963`, `:1979`).
///
/// This module does not exist in such a build -- it is gated on the
/// `websockets` feature -- so the four stubs belong to
/// `curl-rs-ffi/src/ffi/ws.rs`. The contract is named here because it is a
/// property of THIS surface: three of the four answer this code and
/// `curl_ws_meta` answers a null pointer (`lib/ws.c:1966-1970`), which on the
/// engine side is [`Option::None`] from [`ws_meta`].
#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
pub(crate) const NOT_BUILT_IN: CURLcode = CURLcode::NotBuiltIn;

/// `struct curl_ws_frame` (`include/curl/websockets.h:31-38`).
///
/// ```c
/// struct curl_ws_frame {
///   int age;              /* zero */
///   int flags;            /* See the CURLWS_* defines */
///   curl_off_t offset;    /* the offset of this data into the frame */
///   curl_off_t bytesleft; /* number of pending bytes left of the payload */
///   size_t len;           /* size of the current data chunk */
/// };
/// ```
///
/// **This struct is layout-visible**: an application reads its fields
/// directly, `curl_ws_meta` hands back a pointer into libcurl's own storage,
/// and `curl_ws_recv` writes one through `metap`. The `#[repr(C)]` mirror
/// therefore lives in `curl-rs-ffi/src/ffi/ws.rs`; what this file guarantees
/// is that the five fields below correspond to the five above IN ORDER and in
/// width -- `int`, `int`, `curl_off_t`, `curl_off_t`, `size_t` -- so the
/// conversion at the boundary is field-for-field and needs no decisions.
///
/// `age` is ALWAYS zero. The C's comment says so, `ws_dec_next_frame` and
/// `ws_dec_read_head` both assign `dec->frame_age = 0` (`lib/ws.c:335`,
/// `:477`), and nothing anywhere else writes it. It exists so that a future
/// libcurl can extend the struct and let an application tell the versions
/// apart, which is a contract to keep rather than a field to use.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct WsFrameMeta {
    /// `int age`, always zero.
    pub(crate) age: i32,
    /// `int flags`: a combination of the `CURLWS_*` values above.
    pub(crate) flags: i32,
    /// `curl_off_t offset`: where this chunk starts inside the frame's
    /// payload.
    pub(crate) offset: i64,
    /// `curl_off_t bytesleft`: payload bytes of this frame still to come
    /// AFTER this chunk.
    pub(crate) bytesleft: i64,
    /// `size_t len`: how many bytes this chunk carries.
    pub(crate) len: usize,
}

#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
impl WsFrameMeta {
    /// The zero value `curl_ws_recv` starts from and `Curl_ws_accept` leaves
    /// behind, matching the `calloc` of `lib/ws.c:1329`.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            age: 0,
            flags: 0,
            offset: 0,
            bytesleft: 0,
            len: 0,
        }
    }

    /// Whether this metadata describes a frame of the given type.
    ///
    /// A convenience for the boundary and for tests, expressed as a mask test
    /// because the C tests these bits with `&` throughout (`lib/ws.c:689`,
    /// `:1494`).
    #[must_use]
    #[allow(dead_code)] // consumers: curl-rs-ffi/src/ffi/ws.rs, and mod tests
    pub(crate) const fn has(&self, flag: i32) -> bool {
        (self.flags & flag) != 0
    }
}

/// The `CURLWS_*` names a trace line prints, in [`FRAME_FLAGS`] order.
///
/// Diagnostics only: no wire byte depends on this text. It exists because a
/// bare `flags=0x41` in a trace log is unreadable, and because the C's own
/// `ws_frame_name_of_op` (`lib/ws.c:129-147`) prints names rather than
/// numbers for the same reason.
#[must_use]
#[allow(dead_code)] // consumer: the trace lines below, and mod tests
pub(crate) fn frame_flag_names(flags: i32) -> String {
    const NAMES: [&str; 7] =
        ["TEXT", "BINARY", "CONT", "CLOSE", "PING", "OFFSET", "PONG"];
    let mut out = String::new();
    for (flag, name) in FRAME_FLAGS.iter().zip(NAMES.iter()) {
        if (flags & *flag) != 0 {
            if !out.is_empty() {
                out.push('|');
            }
            out.push_str(name);
        }
    }
    if out.is_empty() {
        out.push_str("NONE");
    }
    out
}

// -- 2. The RFC 6455 wire vocabulary: `lib/ws.c:45-113` --------------------

/// `WSBIT_FIN 0x80` (`lib/ws.c:55`): the final-fragment bit.
///
/// ```text
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-------+
/// |F|R|R|R| opcode|
/// |I|S|S|S|  (4)  |
/// |N|V|V|V|       |
/// | |1|2|3|       |
/// ```
///
/// Every constant in this group is a byte that reaches the wire, so each is
/// written as the C writes it and none is derived.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WSBIT_FIN: u8 = 0x80;

/// `WSBIT_RSV1 0x40` (`lib/ws.c:56`).
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WSBIT_RSV1: u8 = 0x40;

/// `WSBIT_RSV2 0x20` (`lib/ws.c:57`).
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WSBIT_RSV2: u8 = 0x20;

/// `WSBIT_RSV3 0x10` (`lib/ws.c:58`).
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WSBIT_RSV3: u8 = 0x10;

/// `WSBIT_RSV_MASK (WSBIT_RSV1 | WSBIT_RSV2 | WSBIT_RSV3)` (`lib/ws.c:59`).
///
/// Any of these set in a received first byte is a protocol violation, and the
/// C reports it with its own message rather than as an unknown opcode
/// (`lib/ws.c:219-224`).
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WSBIT_RSV_MASK: u8 = WSBIT_RSV1 | WSBIT_RSV2 | WSBIT_RSV3;

/// `WSBIT_OPCODE_MASK 0xf` (`lib/ws.c:67`).
///
/// C guards this one with `#ifdef CURLVERBOSE`, because only
/// `ws_frame_name_of_op` uses it. Here it is unconditional: [`Opcode::of`]
/// uses it, and a constant is not worth a feature gate.
#[rustfmt::skip]
pub(crate) const WSBIT_OPCODE_MASK: u8 = 0x0f;

/// `WSBIT_MASK 0x80` (`lib/ws.c:70`): the mask bit of the SECOND head byte.
///
/// Numerically equal to [`WSBIT_FIN`] and semantically unrelated -- it sits in
/// the payload-length byte, not the opcode byte. The C keeps them as two
/// constants for that reason and so does this file.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WSBIT_MASK: u8 = 0x80;

/// `WS_CHUNK_SIZE 65535` (`lib/ws.c:73`): the default bufq chunk.
#[rustfmt::skip]
pub(crate) const WS_CHUNK_SIZE: usize = 65_535;

/// `WS_CHUNK_COUNT 2` (`lib/ws.c:74`): chunks per bufq.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WS_CHUNK_COUNT: usize = 2;

/// `WS_MAX_CNTRL_LEN 125` (`lib/ws.c:107`).
///
/// The C's comment cites the source: *"Control frames are allowed up to 125
/// characters, rfc6455, ch. 5.5"*. It bounds CLOSE, PING and PONG in BOTH
/// directions, and the reason the receive side enforces it is worth keeping
/// with the constant: *"Accepting overlong pings would mean sending equivalent
/// pongs!"* (`lib/ws.c:403-404`).
#[rustfmt::skip]
pub(crate) const WS_MAX_CNTRL_LEN: usize = 125;

/// The largest payload a 16-bit length field can describe.
///
/// `lib/ws.c:875` switches to the 64-bit form at `payload_len > 65535`, and
/// `:887` switches to the 16-bit form at `payload_len >= 126`. Both thresholds
/// are named so the encoder reads as the C reads.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WS_LEN16_MAX: i64 = 65_535;

/// The smallest payload that needs an extended length field.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WS_LEN7_MAX: i64 = 125;

/// The longest frame head this codec writes: 2 + 8 + 4.
///
/// `uint8_t head[14]` (`lib/ws.c:833`) -- two mandatory bytes, up to eight of
/// extended length, and four of mask. The read side needs only ten
/// (`uint8_t head[10]`, `lib/ws.c:89`) because a server frame carries no mask.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) const WS_MAX_SEND_HEAD: usize = 14;

/// The longest frame head this codec reads: 2 + 8.
#[rustfmt::skip]
pub(crate) const WS_MAX_RECV_HEAD: usize = 10;

/// One WebSocket opcode (`lib/ws.c:60-65`).
///
/// The four-bit opcode field of the first head byte. Only the six values curl
/// exchanges are declared: declaring `0x3`-`0x7` and `0xb`-`0xf` would be
/// vocabulary with no codec behind it, and both the encoder and the decoder
/// reject them explicitly -- see [`firstbyte_to_flags`]'s default arm, whose
/// message distinguishes a reserved opcode from a reserved BIT.
///
/// The numbers are the protocol's and are written explicitly for the same
/// reason [`CURLWS_TEXT`]'s group is: a peer holds them.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum Opcode {
    /// `WSBIT_OPCODE_CONT 0x0`: a continuation of the previous data frame.
    Cont = 0x0,
    /// `WSBIT_OPCODE_TEXT 0x1`.
    Text = 0x1,
    /// `WSBIT_OPCODE_BIN 0x2`.
    Binary = 0x2,
    /// `WSBIT_OPCODE_CLOSE 0x8`.
    Close = 0x8,
    /// `WSBIT_OPCODE_PING 0x9`.
    Ping = 0x9,
    /// `WSBIT_OPCODE_PONG 0xa`.
    Pong = 0xa,
}

#[allow(dead_code)] // consumers: the codec below, and mod tests
impl Opcode {
    /// The opcode carried by a first head byte, if it is one curl exchanges.
    ///
    /// [`None`] for the ten reserved values, which is what makes the caller
    /// spell out which diagnostic it wants rather than inventing a name for
    /// them. The C's `ws_frame_name_of_op` returns the literal `"???"` in that
    /// case (`lib/ws.c:144-145`); [`Self::name_of`] reproduces it.
    #[must_use]
    pub(crate) const fn of(firstbyte: u8) -> Option<Self> {
        match firstbyte & WSBIT_OPCODE_MASK {
            0x0 => Some(Self::Cont),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xa => Some(Self::Pong),
            _ => None,
        }
    }

    /// `ws_frame_name_of_op(firstbyte)` (`lib/ws.c:129-147`).
    ///
    /// The six names and the fallback are transcribed exactly, including
    /// `"BIN"` for binary -- which is NOT `"BINARY"`, and which reaches a
    /// `--trace` log verbatim.
    #[must_use]
    #[rustfmt::skip]
    pub(crate) const fn name_of(firstbyte: u8) -> &'static str {
        match Self::of(firstbyte) {
            Some(Self::Cont)   => "CONT",
            Some(Self::Text)   => "TEXT",
            Some(Self::Binary) => "BIN",
            Some(Self::Close)  => "CLOSE",
            Some(Self::Ping)   => "PING",
            Some(Self::Pong)   => "PONG",
            None               => "???",
        }
    }

    /// This opcode as the first head byte of a FINAL frame.
    #[must_use]
    pub(crate) const fn fin(self) -> u8 {
        (self as u8) | WSBIT_FIN
    }

    /// This opcode as the first head byte of a NON-final frame.
    #[must_use]
    pub(crate) const fn nonfin(self) -> u8 {
        self as u8
    }

    /// Whether this is a control opcode, which RFC 6455 caps at
    /// [`WS_MAX_CNTRL_LEN`] and forbids fragmenting.
    #[must_use]
    #[allow(dead_code)] // consumers: the encoder's bound checks, and mod tests
    pub(crate) const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

impl fmt::Display for Opcode {
    /// The C's own spelling, so a message can splice an opcode in directly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::name_of(*self as u8))
    }
}

// -- 3. The injected settings: `data->set.ws_*` ----------------------------

/// The `CURLOPT_WS_OPTIONS` bits and the two debug knobs, as one injected
/// value.
///
/// The C reaches four separate places for these: `data->set.ws_raw_mode` and
/// `data->set.ws_no_auto_pong` (both set from the option bitmask), and the
/// `getenv` calls at `lib/ws.c:908` (`CURL_WS_FORCE_ZERO_MASK`) and `:1334`
/// (`CURL_WS_CHUNK_SIZE`), each inside `#ifdef DEBUGBUILD`.
///
/// # Why the environment is NOT read here
///
/// Specification 0.3.3's pattern P12 requires the clock, the resolver and the
/// randomness to be injected, and a `getenv` in the middle of the frame
/// encoder is the same global side channel by another name: it would make the
/// bytes this file produces depend on process state that a caller cannot see
/// or override, and the mask is the one value whose determinism the byte-exact
/// tests rest on. So the two debug knobs are FIELDS, set by whoever owns
/// `data->set` -- `curl-rs-ffi/src/ffi/ws.rs` and `crate::easy` -- which is
/// also where the C's `#ifdef DEBUGBUILD` guard belongs, since it is a
/// property of the build rather than of the codec.
///
/// Nothing is lost by the move. The fixtures that use those variables --
/// `tests/data/test2302` for the entropy stream and the eleven `test27xx`
/// cases carrying `CURL_WS_FORCE_ZERO_MASK=1` -- all list `Debug` in their
/// `<features>` block, and specification 0.6.6 decides not to advertise
/// `Debug`, so they skip. The capability is reproduced anyway, because it is
/// what lets this module's own tests assert the fixtures' exact bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct WsSettings {
    /// `data->set.ws_raw_mode`, from [`CURLWS_RAW_MODE`].
    pub(crate) raw_mode: bool,
    /// `data->set.ws_no_auto_pong`, from [`CURLWS_NOAUTOPONG`].
    pub(crate) no_auto_pong: bool,
    /// `data->set.connect_only`, which BOTH `curl_ws_recv` and `curl_ws_send`
    /// require of an application driving the socket itself
    /// (`include/curl/websockets.h:52-53` and `:67-68`).
    pub(crate) connect_only: bool,
    /// The bufq chunk size, `WS_CHUNK_SIZE` unless overridden
    /// (`lib/ws.c:1328-1342`).
    pub(crate) chunk_size: usize,
    /// `CURL_WS_FORCE_ZERO_MASK`: mask every frame with `00 00 00 00`,
    /// *"effectively disabling masking"* (`lib/ws.c:909`).
    pub(crate) force_zero_mask: bool,
}

impl Default for WsSettings {
    /// A handle that has set no WebSocket option at all.
    ///
    /// `CURLOPT_WS_OPTIONS` defaults to `0`, `CURLOPT_CONNECT_ONLY` to off and
    /// the chunk size to [`WS_CHUNK_SIZE`]; the debug knob defaults to off,
    /// which is what a release C build compiles to.
    fn default() -> Self {
        Self {
            raw_mode: false,
            no_auto_pong: false,
            connect_only: false,
            chunk_size: WS_CHUNK_SIZE,
            force_zero_mask: false,
        }
    }
}

#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
impl WsSettings {
    /// Reads the `CURLOPT_WS_OPTIONS` bitmask.
    ///
    /// Only the two declared bits are honoured; an unknown bit is IGNORED
    /// rather than refused, which is what `setopt` does with this option in the
    /// C -- the mask is stored and each consumer tests its own bit. Refusing
    /// here would reject an application built against a newer header, and
    /// `CURLOPT_WS_OPTIONS` has no `CURLE_UNKNOWN_OPTION` path.
    #[must_use]
    pub(crate) const fn with_options(mut self, mask: i64) -> Self {
        self.raw_mode = (mask & CURLWS_RAW_MODE) != 0;
        self.no_auto_pong = (mask & CURLWS_NOAUTOPONG) != 0;
        self
    }

    /// `CURLOPT_CONNECT_ONLY`, which the two data-transfer entry points
    /// require.
    #[must_use]
    #[allow(dead_code)] // consumers: curl-rs-ffi/src/ffi/ws.rs, and mod tests
    pub(crate) const fn with_connect_only(
        mut self,
        connect_only: bool,
    ) -> Self {
        self.connect_only = connect_only;
        self
    }

    /// The `CURL_WS_CHUNK_SIZE` override, clamped exactly as the C clamps it.
    ///
    /// `curlx_str_number(&p, &l, 1 * 1024 * 1024)` (`lib/ws.c:1337`) parses
    /// with a CEILING of one mebibyte and leaves the default in place when the
    /// parse fails, so a larger request is not honoured. A zero would make
    /// every chunk both empty and full at once, which
    /// [`BufQ::with_opts`] guards against by clamping to one; it is refused
    /// here as well so the two cannot disagree.
    #[must_use]
    #[allow(dead_code)] // consumers: curl-rs-ffi/src/ffi/ws.rs, and mod tests
    pub(crate) const fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        if chunk_size > 0 && chunk_size <= 1024 * 1024 {
            self.chunk_size = chunk_size;
        }
        self
    }

    /// The `CURL_WS_FORCE_ZERO_MASK` override.
    #[must_use]
    #[allow(dead_code)] // consumers: curl-rs-ffi/src/ffi/ws.rs, and mod tests
    pub(crate) const fn with_zero_mask(mut self, force: bool) -> Self {
        self.force_zero_mask = force;
        self
    }

    /// `!data->set.ws_no_auto_pong` (`lib/ws.c:677`, `:1475`).
    ///
    /// Named rather than negated at each use, because the option is spelled in
    /// the negative and the predicate is asked in the positive; writing `!`
    /// twice is where that kind of flag goes wrong.
    #[must_use]
    pub(crate) const fn auto_pong(&self) -> bool {
        !self.no_auto_pong
    }
}

// -- 4. Frame flags to and from the first head byte ------------------------

/// `ws_frame_firstbyte2flags(data, firstbyte, cont_flags)`
/// (`lib/ws.c:150-227`): what a RECEIVED first byte means.
///
/// The C returns `0` for every invalid case and the caller treats that as
/// [`CURLcode::RecvError`] after resetting the decoder (`lib/ws.c:374-377`).
/// Here the failure is an `Err` carrying that code, so the invalid cases
/// cannot be mistaken for a frame with no flags -- but the CLASSIFICATION is
/// the C's, arm for arm, and so is every message.
///
/// # The fourteen arms
///
/// The `switch` is on the WHOLE byte, not on the opcode field, which is what
/// makes each opcode appear twice -- once final, once not -- and what makes
/// the reserved bits fall through to the default arm. Reproduced exactly:
///
/// * `0x00` and `0x80`, CONT: refused unless a fragmented message is open.
///   Final CONT CLEARS [`CURLWS_CONT`]; non-final CONT keeps it.
/// * `0x01`/`0x81` TEXT and `0x02`/`0x82` BINARY: refused WHILE a fragmented
///   message is open, because *"fragmented message interrupted by new TEXT
///   msg"*. The non-final form sets [`CURLWS_CONT`].
/// * `0x88` CLOSE, `0x89` PING, `0x8a` PONG: accepted; their non-final forms
///   `0x08`, `0x09` and `0x0a` are each refused with their own message,
///   because RFC 6455 forbids fragmenting a control frame.
/// * everything else: reserved bits or reserved opcode, distinguished.
///
/// # Errors
///
/// [`CURLcode::RecvError`] for every invalid first byte, which is what the
/// caller answers (`lib/ws.c:376`, `:400`, `:407`, `:413`, `:418`).
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) fn firstbyte_to_flags(
    firstbyte: u8,
    cont_flags: i32,
    mut tracer: Option<&mut Tracer<'_>>,
) -> CodeResult<i32> {
    /// The refusal, with the C's message and the C's code.
    fn refuse(
        tracer: Option<&mut Tracer<'_>>,
        args: fmt::Arguments<'_>,
    ) -> CodeResult<i32> {
        if let Some(tracer) = tracer {
            tracer.failf(args);
        }
        Err(CURLcode::RecvError)
    }

    let resuming = (cont_flags & CURLWS_CONT) != 0;
    match firstbyte {
        // `:155-160` -- 0x00, an intermediate TEXT/BINARY fragment.
        b if b == Opcode::Cont.nonfin() => {
            if !resuming {
                return refuse(
                    tracer.take(),
                    format_args!(
                        "[WS] no ongoing fragmented message to resume"
                    ),
                );
            }
            Ok(cont_flags | CURLWS_CONT)
        }
        // `:162-167` -- 0x80, the FINAL TEXT/BINARY fragment.
        b if b == Opcode::Cont.fin() => {
            if !resuming {
                return refuse(
                    tracer.take(),
                    format_args!(
                        "[WS] no ongoing fragmented message to resume"
                    ),
                );
            }
            Ok(cont_flags & !CURLWS_CONT)
        }
        // `:169-174` -- 0x01, the first TEXT fragment.
        b if b == Opcode::Text.nonfin() => {
            if resuming {
                return refuse(
                    tracer.take(),
                    format_args!(
                        "[WS] fragmented message interrupted by new TEXT msg"
                    ),
                );
            }
            Ok(CURLWS_TEXT | CURLWS_CONT)
        }
        // `:176-181` -- 0x81, an unfragmented TEXT message.
        b if b == Opcode::Text.fin() => {
            if resuming {
                return refuse(
                    tracer.take(),
                    format_args!(
                        "[WS] fragmented message interrupted by new TEXT msg"
                    ),
                );
            }
            Ok(CURLWS_TEXT)
        }
        // `:183-188` -- 0x02, the first BINARY fragment.
        b if b == Opcode::Binary.nonfin() => {
            if resuming {
                return refuse(
                    tracer.take(),
                    format_args!(
                        "[WS] fragmented message interrupted by new BINARY msg"
                    ),
                );
            }
            Ok(CURLWS_BINARY | CURLWS_CONT)
        }
        // `:190-195` -- 0x82, an unfragmented BINARY message.
        b if b == Opcode::Binary.fin() => {
            if resuming {
                return refuse(
                    tracer.take(),
                    format_args!(
                        "[WS] fragmented message interrupted by new BINARY msg"
                    ),
                );
            }
            Ok(CURLWS_BINARY)
        }
        // `:197-199` -- 0x08, a fragmented CLOSE, which cannot exist.
        b if b == Opcode::Close.nonfin() => refuse(
            tracer.take(),
            format_args!("[WS] invalid fragmented CLOSE frame"),
        ),
        // `:201-202` -- 0x88.
        b if b == Opcode::Close.fin() => Ok(CURLWS_CLOSE),
        // `:204-206` -- 0x09.
        b if b == Opcode::Ping.nonfin() => refuse(
            tracer.take(),
            format_args!("[WS] invalid fragmented PING frame"),
        ),
        // `:208-209` -- 0x89.
        b if b == Opcode::Ping.fin() => Ok(CURLWS_PING),
        // `:211-213` -- 0x0a.
        b if b == Opcode::Pong.nonfin() => refuse(
            tracer.take(),
            format_args!("[WS] invalid fragmented PONG frame"),
        ),
        // `:215-216` -- 0x8a.
        b if b == Opcode::Pong.fin() => Ok(CURLWS_PONG),
        // `:218-225` -- and the two messages are NOT interchangeable: a
        // reserved BIT and a reserved OPCODE are different defects and the C
        // names them differently.
        other => {
            if (other & WSBIT_RSV_MASK) != 0 {
                refuse(
                    tracer.take(),
                    format_args!("[WS] invalid reserved bits: {other:02x}"),
                )
            } else {
                refuse(
                    tracer.take(),
                    format_args!("[WS] invalid opcode: {other:02x}"),
                )
            }
        }
    }
}

/// `ws_frame_flags2firstbyte(data, flags, contfragment, pfirstbyte)`
/// (`lib/ws.c:229-290`): which first byte an application's flags select.
///
/// [`CURLWS_OFFSET`] is masked out first (`:235`), because it describes the
/// CALL and not the frame. Everything after that is an equality test on the
/// remaining bits, so `CURLWS_TEXT | CURLWS_BINARY` -- a nonsensical
/// combination -- lands in the default arm rather than picking one of them.
///
/// # The two compatibility arms, preserved with their diagnostics
///
/// * **no flags at all** while a fragmented message is open is treated as a
///   final continuation, and the C says why in a trace line: *"no flags given;
///   interpreting as continuation fragment for compatibility"*. With no
///   message open it is [`CURLcode::BadFunctionArgument`].
/// * **[`CURLWS_CONT`] alone** is accepted the same way, with an `infof` that
///   calls it *"supported for compatibility but highly discouraged"*. The
///   distinction matters: this one produces a NON-final continuation.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for no flags with nothing to continue,
/// for a fragmented control frame, and for any combination the C's `switch`
/// does not name.
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) fn flags_to_firstbyte(
    flags: i32,
    contfragment: bool,
    mut tracer: Option<&mut Tracer<'_>>,
) -> CodeResult<u8> {
    /// The refusal, with the C's message and the C's code.
    fn refuse(
        tracer: Option<&mut Tracer<'_>>,
        args: fmt::Arguments<'_>,
    ) -> CodeResult<u8> {
        if let Some(tracer) = tracer {
            tracer.failf(args);
        }
        Err(CURLcode::BadFunctionArgument)
    }

    // `:235` -- `switch(flags & ~CURLWS_OFFSET)`.
    let selector = flags & !CURLWS_OFFSET;
    match selector {
        // `:236-244`.
        0 => {
            if contfragment {
                if let Some(tracer) = tracer.as_deref_mut() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Ws,
                        "no flags given; interpreting as continuation \
                         fragment for compatibility"
                    );
                }
                return Ok(Opcode::Cont.fin());
            }
            refuse(tracer.take(), format_args!("[WS] no flags given"))
        }
        // `:245-253`.
        CURLWS_CONT => {
            if contfragment {
                if let Some(tracer) = tracer.as_deref_mut() {
                    infof!(
                        tracer,
                        "[WS] setting CURLWS_CONT flag without message type \
                         is supported for compatibility but highly discouraged"
                    );
                }
                return Ok(Opcode::Cont.nonfin());
            }
            refuse(
                tracer.take(),
                format_args!("[WS] No ongoing fragmented message to continue"),
            )
        }
        // `:254-257`.
        CURLWS_TEXT => Ok(if contfragment {
            Opcode::Cont.fin()
        } else {
            Opcode::Text.fin()
        }),
        // `:258-260`.
        b if b == CURLWS_TEXT | CURLWS_CONT => Ok(if contfragment {
            Opcode::Cont.nonfin()
        } else {
            Opcode::Text.nonfin()
        }),
        // `:261-264`.
        CURLWS_BINARY => Ok(if contfragment {
            Opcode::Cont.fin()
        } else {
            Opcode::Binary.fin()
        }),
        // `:265-267`.
        b if b == CURLWS_BINARY | CURLWS_CONT => Ok(if contfragment {
            Opcode::Cont.nonfin()
        } else {
            Opcode::Binary.nonfin()
        }),
        // `:268-270`.
        CURLWS_CLOSE => Ok(Opcode::Close.fin()),
        // `:271-273`.
        b if b == CURLWS_CLOSE | CURLWS_CONT => refuse(
            tracer.take(),
            format_args!("[WS] CLOSE frame must not be fragmented"),
        ),
        // `:274-276`.
        CURLWS_PING => Ok(Opcode::Ping.fin()),
        // `:277-279`.
        b if b == CURLWS_PING | CURLWS_CONT => refuse(
            tracer.take(),
            format_args!("[WS] PING frame must not be fragmented"),
        ),
        // `:280-282`.
        CURLWS_PONG => Ok(Opcode::Pong.fin()),
        // `:283-285`.
        b if b == CURLWS_PONG | CURLWS_CONT => refuse(
            tracer.take(),
            format_args!("[WS] PONG frame must not be fragmented"),
        ),
        // `:286-288` -- the C prints the FULL flags here, including the
        // `CURLWS_OFFSET` bit it masked out for the switch.
        _ => {
            refuse(tracer.take(), format_args!("[WS] unknown flags: {flags:x}"))
        }
    }
}

/// `ws_payload_remain(payload_total, payload_offset, payload_buffered)`
/// (`lib/ws.c:654-665`): how much of this frame is still to come.
///
/// [`None`] where the C answers `-1`, which it treats as a parameter mismatch
/// -- `DEBUGASSERT(0)` then [`CURLcode::BadFunctionArgument`]
/// (`lib/ws.c:684-687`). The three conditions are the C's: a negative total, a
/// negative offset, or fewer bytes remaining than the caller says are
/// buffered.
///
/// Returned as an [`Option`] rather than as a sentinel so that the mismatch
/// cannot be added to an offset by accident, and computed with saturating
/// arithmetic so that a hostile length cannot overflow into a plausible
/// answer.
#[must_use]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) fn payload_remain(
    payload_total: i64,
    payload_offset: i64,
    payload_buffered: usize,
) -> Option<i64> {
    if payload_total < 0 || payload_offset < 0 {
        return None;
    }
    let remain = payload_total.checked_sub(payload_offset)?;
    if remain < 0 {
        return None;
    }
    let buffered = i64::try_from(payload_buffered).ok()?;
    if remain < buffered {
        return None;
    }
    Some(remain - buffered)
}

// -- 5. The decoder: `lib/ws.c:76-93` and `:333-571` -----------------------

/// `enum ws_dec_state` (`lib/ws.c:78-82`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum DecState {
    /// `WS_DEC_INIT`: between frames.
    #[default]
    Init,
    /// `WS_DEC_HEAD`: reading the frame head.
    Head,
    /// `WS_DEC_PAYLOAD`: passing the payload upward.
    Payload,
}

/// One chunk of decoded payload, with the frame it belongs to.
///
/// Replaces the C's eight-parameter callback
///
/// ```c
/// typedef CURLcode ws_write_payload(const uint8_t *buf, size_t buflen,
///                                   int frame_age, int frame_flags,
///                                   curl_off_t payload_offset,
///                                   curl_off_t payload_len,
///                                   void *userp, size_t *pnwritten);
/// ```
///
/// Two things change and both are deliberate. The `void *userp` disappears,
/// because a [`PayloadSink`] implementor carries its own state in typed fields
/// -- that untyped context pointer is exactly the pattern specification 0.6.9
/// requires be eliminated. And `size_t *pnwritten` becomes the return value,
/// so a sink cannot report success while leaving the count unset.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) struct DecodedFrame<'a> {
    /// The payload bytes of THIS chunk. May be empty, which is how a
    /// zero-length frame is delivered (`lib/ws.c:546-556`).
    pub(crate) buf: &'a [u8],
    /// `frame_age`, always zero.
    pub(crate) age: i32,
    /// `frame_flags`: the `CURLWS_*` set [`firstbyte_to_flags`] derived.
    pub(crate) flags: i32,
    /// `payload_offset`: where this chunk begins inside the frame.
    pub(crate) payload_offset: i64,
    /// `payload_len`: the frame's total payload length.
    pub(crate) payload_len: i64,
}

/// Where a decoded chunk goes.
///
/// The two implementors are the C's two callbacks: `ws_cw_dec_next`
/// (`lib/ws.c:667-711`), which forwards to the client-writer chain during a
/// callback-driven transfer, and `ws_client_collect` (`lib/ws.c:1466-1520`),
/// which copies into the application's buffer during [`ws_recv`].
#[allow(dead_code)] // consumers: the codec below, and mod tests
pub(crate) trait PayloadSink {
    /// Accept as much of `frame.buf` as there is room for.
    ///
    /// Returns how many bytes were consumed, which the decoder adds to
    /// `payload_offset` and skips from its input queue. Returning less than
    /// `frame.buf.len()` is legitimate and means *"call me again"*.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] when there is no room at all, which the decoder
    /// propagates so the caller can drain and retry; anything else is a real
    /// failure and stops the pass.
    fn write(&mut self, frame: DecodedFrame<'_>) -> CodeResult<usize>;
}

/// `struct ws_decoder` (`lib/ws.c:84-93`).
///
/// The C's comment: *"a client-side WS frame decoder, parsing frame headers
/// and payload, keeping track of current position and stats"*.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) struct WsDecoder {
    /// `frame_age`, always zero -- see [`WsFrameMeta::age`].
    frame_age: i32,
    /// `frame_flags`: the current frame's `CURLWS_*` set.
    frame_flags: i32,
    /// `payload_offset`: how far into the payload the parse has reached.
    payload_offset: i64,
    /// `payload_len`: the current frame's total payload length.
    payload_len: i64,
    /// `head[10]`: the frame head as received.
    head: [u8; WS_MAX_RECV_HEAD],
    /// `head_len`: how many head bytes are in hand.
    head_len: usize,
    /// `head_total`: how many this frame's head will occupy -- 2, 4 or 10.
    head_total: usize,
    /// `state`.
    state: DecState,
    /// `cont_flags`: the flags of the fragmented message in progress.
    ///
    /// The field with the subtlest lifetime in this struct: it is carried
    /// ACROSS frames by [`Self::next_frame`] and cleared only by
    /// [`Self::reset`]. The C marks the distinction with a comment where it
    /// would otherwise be invisible -- *"dec->cont_flags must be carried over
    /// to next frame"* (`lib/ws.c:341`).
    cont_flags: i32,
}

impl Default for WsDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
impl WsDecoder {
    /// `ws_dec_init(dec)` (`lib/ws.c:355-358`), which is `ws_dec_reset`.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            frame_age: 0,
            frame_flags: 0,
            payload_offset: 0,
            payload_len: 0,
            head: [0; WS_MAX_RECV_HEAD],
            head_len: 0,
            head_total: 0,
            state: DecState::Init,
            cont_flags: 0,
        }
    }

    /// `ws_dec_next_frame(dec)` (`lib/ws.c:333-342`).
    ///
    /// Everything except `cont_flags`, which survives so that a continuation
    /// frame can be recognised.
    fn next_frame(&mut self) {
        self.frame_age = 0;
        self.frame_flags = 0;
        self.payload_offset = 0;
        self.payload_len = 0;
        self.head_len = 0;
        self.head_total = 0;
        self.state = DecState::Init;
    }

    /// `ws_dec_reset(dec)` (`lib/ws.c:344-353`): [`Self::next_frame`] AND
    /// `cont_flags = 0`.
    ///
    /// Called on every decode failure and by `Curl_ws_accept` when a
    /// connection is reused for a second upgrade (`lib/ws.c:1356`), because a
    /// half-received message from a previous life must not be resumable.
    pub(crate) fn reset(&mut self) {
        self.next_frame();
        self.cont_flags = 0;
    }

    /// The decoder's state, for a caller that needs to know whether a frame is
    /// half-parsed.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) const fn state(&self) -> DecState {
        self.state
    }

    /// The flags of the frame being decoded.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) const fn frame_flags(&self) -> i32 {
        self.frame_flags
    }

    /// The payload length of the frame being decoded.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) const fn payload_len(&self) -> i64 {
        self.payload_len
    }

    /// Whether a fragmented message is open.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) const fn is_resuming(&self) -> bool {
        (self.cont_flags & CURLWS_CONT) != 0
    }

    /// `ws_dec_read_head(dec, data, inraw)` (`lib/ws.c:360-483`).
    ///
    /// Consumes head bytes ONE AT A TIME from the front of `inraw` -- which is
    /// how the C does it, and which is what makes a head split across two
    /// network reads work without a re-parse. Four checks happen on the way,
    /// in this order:
    ///
    /// 1. the first byte becomes [`Self::frame_flags`] through
    ///    [`firstbyte_to_flags`], and a data frame's flags become
    ///    [`Self::cont_flags`]. **Control frames deliberately do not touch
    ///    `cont_flags`**: a PING arriving between two fragments must not end
    ///    the message (`lib/ws.c:379-383`);
    /// 2. a masked frame from a server is fatal -- *"A client MUST close a
    ///    connection if it detects a masked frame"* (`lib/ws.c:396-401`);
    /// 3. a PING, PONG or CLOSE longer than [`WS_MAX_CNTRL_LEN`] is fatal,
    ///    with a distinct message for each;
    /// 4. `126` and `127` in the length byte select the 4-byte and 10-byte
    ///    head forms, and in the 10-byte form a top byte above 127 is refused
    ///    because *"frame length longer than 63 bits not supported"*.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] when `inraw` runs dry before the head is complete
    /// -- not a failure, and the C's own answer (`lib/ws.c:482`).
    /// [`CURLcode::RecvError`] for each of the four checks above.
    pub(crate) fn read_head(
        &mut self,
        inraw: &mut BufQ,
        mut tracer: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        while let Some(next) =
            inraw.peek().and_then(|span| span.first().copied())
        {
            if self.head_len == 0 {
                // `:368-389`.
                self.head[0] = next;
                inraw.skip(1);

                match firstbyte_to_flags(
                    self.head[0],
                    self.cont_flags,
                    tracer.as_deref_mut(),
                ) {
                    Ok(flags) => self.frame_flags = flags,
                    Err(code) => {
                        self.reset();
                        return Err(code);
                    }
                }

                // `:379-383` -- fragmentation is a property of DATA frames
                // only.
                if (self.frame_flags & (CURLWS_TEXT | CURLWS_BINARY)) != 0 {
                    self.cont_flags = self.frame_flags;
                }

                self.head_len = 1;
                continue;
            } else if self.head_len == 1 {
                // `:391-432`.
                self.head[1] = next;
                inraw.skip(1);
                self.head_len = 2;

                if (self.head[1] & WSBIT_MASK) != 0 {
                    if let Some(tracer) = tracer.as_deref_mut() {
                        failf!(tracer, "[WS] masked input frame");
                    }
                    self.reset();
                    return Err(CURLcode::RecvError);
                }
                // The three bound checks, each with its own message. The C
                // tests them as three separate `if`s and so does this, because
                // the messages differ and a merged test would have to pick one.
                let control_len = usize::from(self.head[1]);
                if (self.frame_flags & CURLWS_PING) != 0
                    && control_len > WS_MAX_CNTRL_LEN
                {
                    if let Some(tracer) = tracer.as_deref_mut() {
                        failf!(tracer, "[WS] received PING frame is too big");
                    }
                    self.reset();
                    return Err(CURLcode::RecvError);
                }
                if (self.frame_flags & CURLWS_PONG) != 0
                    && control_len > WS_MAX_CNTRL_LEN
                {
                    if let Some(tracer) = tracer.as_deref_mut() {
                        failf!(tracer, "[WS] received PONG frame is too big");
                    }
                    self.reset();
                    return Err(CURLcode::RecvError);
                }
                if (self.frame_flags & CURLWS_CLOSE) != 0
                    && control_len > WS_MAX_CNTRL_LEN
                {
                    if let Some(tracer) = tracer.as_deref_mut() {
                        failf!(tracer, "[WS] received CLOSE frame is too big");
                    }
                    self.reset();
                    return Err(CURLcode::RecvError);
                }

                // `:421-432` -- how long is this head?
                if self.head[1] == 126 {
                    self.head_total = 4;
                    continue;
                } else if self.head[1] == 127 {
                    self.head_total = 10;
                    continue;
                }
                self.head_total = 2;
            }

            // `:435-445` -- the extended length bytes, still one at a time.
            if self.head_len < self.head_total {
                if let Some(slot) = self.head.get_mut(self.head_len) {
                    *slot = next;
                }
                inraw.skip(1);
                self.head_len += 1;
                if self.head_len < self.head_total {
                    continue;
                }
            }

            // `:446-475` -- the head is complete. `DEBUGASSERT(dec->head_len ==
            // dec->head_total)` is the invariant the loop above maintains; it is
            // expressed here as an exhaustive match whose fourth arm answers
            // the C's `CURLE_RECV_ERROR` instead of asserting, because a
            // release C build walks into that arm and returns.
            self.payload_len = match self.head_total {
                2 => i64::from(self.head[1]),
                4 => (i64::from(self.head[2]) << 8) | i64::from(self.head[3]),
                10 => {
                    if self.head[2] > 127 {
                        if let Some(tracer) = tracer.as_deref_mut() {
                            failf!(
                                tracer,
                                "[WS] frame length longer than 63 bits not \
                                 supported"
                            );
                        }
                        // NOTE the asymmetry, which is the C's: this arm does
                        // NOT reset the decoder (`lib/ws.c:456-459`), unlike
                        // the four checks above. Transcribed as found.
                        return Err(CURLcode::RecvError);
                    }
                    let mut len = 0_i64;
                    for byte in &self.head[2..10] {
                        len = (len << 8) | i64::from(*byte);
                    }
                    len
                }
                _ => {
                    if let Some(tracer) = tracer.as_deref_mut() {
                        failf!(tracer, "[WS] unexpected frame header length");
                    }
                    return Err(CURLcode::RecvError);
                }
            };

            // `:477-480`.
            self.frame_age = 0;
            self.payload_offset = 0;
            self.trace_info(tracer.as_deref_mut(), "decoded");
            return Ok(());
        }
        // `:482` -- the head is incomplete and that is not an error.
        Err(CURLcode::Again)
    }

    /// `ws_dec_pass_payload(dec, data, inraw, write_cb, write_ctx)`
    /// (`lib/ws.c:485-515`).
    ///
    /// Hands the sink at most the bytes belonging to THIS frame, however much
    /// more happens to be queued behind them: `remain` is recomputed from
    /// `payload_len - payload_offset` on every turn, and `inlen` is clamped to
    /// it. That clamp is what keeps the first byte of the NEXT frame out of a
    /// payload.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] when the frame is not finished and the input has run
    /// out -- the C's `return remain ? CURLE_AGAIN : CURLE_OK` (`:514`) -- and
    /// whatever the sink reports otherwise.
    pub(crate) fn pass_payload(
        &mut self,
        inraw: &mut BufQ,
        sink: &mut dyn PayloadSink,
        mut tracer: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        let mut remain = self.remaining_payload();

        while remain > 0 {
            let (age, flags, offset, total) = (
                self.frame_age,
                self.frame_flags,
                self.payload_offset,
                self.payload_len,
            );
            // The span is borrowed from `inraw`, so the sink runs inside this
            // block and the borrow ends with it -- which is what leaves
            // `inraw.skip` reachable below. `BufQ::pass` uses the same shape.
            let nwritten = {
                let Some(span) = inraw.peek() else {
                    break;
                };
                let inlen = span.len().min(remain_as_usize(remain));
                sink.write(DecodedFrame {
                    buf: &span[..inlen],
                    age,
                    flags,
                    payload_offset: offset,
                    payload_len: total,
                })?
            };
            inraw.skip(nwritten);
            self.payload_offset = self
                .payload_offset
                .saturating_add(i64::try_from(nwritten).unwrap_or(i64::MAX));
            remain = self.remaining_payload();
            if let Some(tracer) = tracer.as_deref_mut() {
                trc_feat!(
                    tracer,
                    TraceFeature::Ws,
                    "passed {} bytes payload, {} remain",
                    nwritten,
                    remain
                );
            }
            if nwritten == 0 {
                // A sink that accepts nothing without reporting `Again` would
                // otherwise spin. The C cannot reach this state -- its two
                // callbacks either consume or answer `CURLE_AGAIN` -- and this
                // guard makes that unreachability structural rather than a
                // property of the two implementors.
                break;
            }
        }

        if remain > 0 {
            Err(CURLcode::Again)
        } else {
            Ok(())
        }
    }

    /// `ws_dec_pass(dec, data, inraw, write_cb, write_ctx)`
    /// (`lib/ws.c:517-571`): one turn of the decoder.
    ///
    /// The C's `switch` with its two `FALLTHROUGH()`s, which makes a single
    /// call able to move `INIT -> HEAD -> PAYLOAD -> INIT` when the whole frame
    /// is already buffered. Reproduced as a loop-free sequence of `if`s in the
    /// same order.
    ///
    /// # The zero-length frame is a special case in the C and stays one
    ///
    /// `:546-556`: a frame whose payload length is zero still has to reach the
    /// sink once, so the C calls the callback with a one-byte buffer holding
    /// `'\0'` and a length of `0`. The buffer contents are unreachable -- the
    /// length is zero -- so this passes an empty slice, which is the same
    /// contract without the dummy byte. A zero-length PING is exactly this
    /// case, and it is what `tests/data/test2302` exercises.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] for an empty queue or an incomplete frame, and
    /// whatever the head parse or the sink reports.
    pub(crate) fn pass(
        &mut self,
        inraw: &mut BufQ,
        sink: &mut dyn PayloadSink,
        mut tracer: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        // `:525-526`.
        if inraw.is_empty() {
            return Err(CURLcode::Again);
        }

        if self.state == DecState::Init {
            self.next_frame();
            self.state = DecState::Head;
        }

        if self.state == DecState::Head {
            match self.read_head(inraw, tracer.as_deref_mut()) {
                Ok(()) => {}
                Err(CURLcode::Again) => return Err(CURLcode::Again),
                Err(code) => {
                    if let Some(tracer) = tracer.as_deref_mut() {
                        failf!(
                            tracer,
                            "[WS] decode frame error {}",
                            code as i32
                        );
                    }
                    return Err(code);
                }
            }
            // `:544-545`.
            self.state = DecState::Payload;
            if self.payload_len == 0 {
                let flags = self.frame_flags;
                let age = self.frame_age;
                sink.write(DecodedFrame {
                    buf: &[],
                    age,
                    flags,
                    payload_offset: 0,
                    payload_len: 0,
                })?;
                self.state = DecState::Init;
                return Ok(());
            }
        }

        // `:558-565`.
        let result = self.pass_payload(inraw, sink, tracer.as_deref_mut());
        self.trace_info(tracer, "passing");
        result?;
        self.state = DecState::Init;
        Ok(())
    }

    /// `dec->payload_len - dec->payload_offset`, clamped at zero.
    ///
    /// `curlx_sotouz_range(..., 0, SIZE_MAX)` (`lib/ws.c:495-496`) does the
    /// clamping in the C; the saturating subtraction does it here, and the
    /// answer stays an `i64` so the comparison with `payload_len` needs no
    /// cast.
    #[must_use]
    const fn remaining_payload(&self) -> i64 {
        let remain = self.payload_len - self.payload_offset;
        if remain > 0 {
            remain
        } else {
            0
        }
    }

    /// `ws_dec_info(dec, data, msg)` (`lib/ws.c:292-320`).
    ///
    /// Three shapes by head length, which is what makes a partially-read head
    /// distinguishable in a log from a complete one. `NOVERBOSE((void)msg)`
    /// in the C means the whole function compiles away without
    /// `CURLVERBOSE`; here the [`trc_feat!`] macro's own gate does that job,
    /// and `head_len == 0` emits nothing exactly as the C's `case 0: break`
    /// does.
    fn trace_info(&self, tracer: Option<&mut Tracer<'_>>, msg: &str) {
        let Some(tracer) = tracer else {
            return;
        };
        let firstbyte = self.head[0];
        let name = Opcode::name_of(firstbyte);
        let nonfinal = if (firstbyte & WSBIT_FIN) == 0 {
            " NON-FINAL"
        } else {
            ""
        };
        match self.head_len {
            0 => {}
            1 => {
                trc_feat!(
                    tracer,
                    TraceFeature::Ws,
                    "decoded {} [{}{}]",
                    msg,
                    name,
                    nonfinal
                );
            }
            _ if self.head_len < self.head_total => {
                trc_feat!(
                    tracer,
                    TraceFeature::Ws,
                    "decoded {} [{}{}]({}/{})",
                    msg,
                    name,
                    nonfinal,
                    self.head_len,
                    self.head_total
                );
            }
            _ => {
                trc_feat!(
                    tracer,
                    TraceFeature::Ws,
                    "decoded {} [{}{} payload={}/{}]",
                    msg,
                    name,
                    nonfinal,
                    self.payload_offset,
                    self.payload_len
                );
            }
        }
    }
}

/// An `i64` byte count as a `usize`, saturating.
///
/// The successor of `curlx_sotouz_range(value, 0, SIZE_MAX)`
/// (`lib/ws.c:495`, `:961`, `:1174`), which is the C's guarded narrowing of a
/// `curl_off_t` to a `size_t`. Saturation is the right answer on all four
/// mandated targets, where the two widths are equal and the clamp can only
/// bite on a negative input that the callers have already excluded.
///
/// `try_from` rather than an `as` cast, and not a `const fn`, deliberately: an
/// `as` narrowing would TRUNCATE on a 32-bit target instead of clamping, and
/// specification 0.6.2 forfeits 32-bit support for the varargs ABI without
/// licensing a silent wrong answer here.
#[must_use]
#[allow(dead_code)] // consumers: the codec below, and mod tests
fn remain_as_usize(value: i64) -> usize {
    if value < 0 {
        return 0;
    }
    usize::try_from(value).unwrap_or(usize::MAX)
}

// -- 6. The encoder: `lib/ws.c:95-104` and `:779-1022` ---------------------

/// `struct ws_encoder` (`lib/ws.c:97-104`).
///
/// The C's comment: *"a client-side WS frame encoder, generating frame headers
/// and converting payloads, tracking remaining data in current frame"*.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) struct WsEncoder {
    /// `payload_len`: the current frame's declared payload length.
    payload_len: i64,
    /// `payload_remain`: how much of it has still to be encoded.
    ///
    /// Non-zero here is what makes a second [`WsEncoder::add_frame`] fail, and
    /// what [`ws_start_frame`] reports as *"previous frame not finished"*.
    payload_remain: i64,
    /// `xori`: which byte of [`Self::mask`] the next payload byte uses.
    xori: u32,
    /// **`uint8_t mask[4]` (`lib/ws.c:101`): the 32-bit mask for this
    /// CONNECTION.**
    ///
    /// Held on the connection rather than on the frame, and re-drawn for every
    /// frame by [`Self::add_frame`] -- both are the C's, and the second is
    /// what RFC 6455 requires. The draw comes from the injected [`Rng`], never
    /// from a global generator, which is what makes
    /// `tests/data/test2302`'s `%hex[%8a%808321]hex%` reproducible byte for
    /// byte.
    mask: [u8; 4],
    /// `firstbyte`: the first head byte of the frame being encoded, kept for
    /// the trace line.
    firstbyte: u8,
    /// `contfragment`: *"set TRUE if the previous fragment sent was not
    /// final"*.
    contfragment: bool,
}

impl Default for WsEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
impl WsEncoder {
    /// `ws_enc_init(enc)` (`lib/ws.c:798-801`), which is `ws_enc_reset`.
    ///
    /// Note what neither touches: the MASK. `ws_enc_reset` clears
    /// `payload_remain`, `xori` and `contfragment` and leaves `mask` alone
    /// (`lib/ws.c:791-796`), because every frame redraws it anyway.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            payload_len: 0,
            payload_remain: 0,
            xori: 0,
            mask: [0; 4],
            firstbyte: 0,
            contfragment: false,
        }
    }

    /// `ws_enc_reset(enc)` (`lib/ws.c:791-796`).
    pub(crate) fn reset(&mut self) {
        self.payload_remain = 0;
        self.xori = 0;
        self.contfragment = false;
    }

    /// How much payload the frame in progress still owes.
    #[must_use]
    pub(crate) const fn payload_remain(&self) -> i64 {
        self.payload_remain
    }

    /// The mask in force, which a test asserts and the boundary never sees.
    #[must_use]
    #[allow(dead_code)] // consumer: mod tests
    pub(crate) const fn mask(&self) -> [u8; 4] {
        self.mask
    }

    /// Whether the last data fragment sent was non-final.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) const fn contfragment(&self) -> bool {
        self.contfragment
    }

    /// `ws_enc_add_frame(data, enc, flags, payload_len, out)`
    /// (`lib/ws.c:826-928`): write one frame HEAD into `out`.
    ///
    /// The order of operations is the C's exactly, because two of the steps
    /// have side effects that later steps read:
    ///
    /// 1. a negative length is [`CURLcode::SendError`];
    /// 2. an unfinished previous frame is [`CURLcode::SendError`], with the
    ///    remaining count in the message;
    /// 3. [`flags_to_firstbyte`] converts the flags, which is where an
    ///    application's bad combination is refused;
    /// 4. **`contfragment` is updated for TEXT and BINARY only** -- a control
    ///    frame passing through the middle of a fragmented message must not
    ///    end it (`lib/ws.c:855-859`);
    /// 5. a control frame longer than [`WS_MAX_CNTRL_LEN`] is
    ///    [`CURLcode::TooLarge`], with a distinct message per type;
    /// 6. the length is encoded in one of three forms, EVERY one of them with
    ///    [`WSBIT_MASK`] set in the length byte, because a client frame is
    ///    always masked;
    /// 7. `payload_remain` and `payload_len` are armed;
    /// 8. the mask is drawn and appended, and `xori` is reset to zero.
    ///
    /// # The three length forms, and the thresholds between them
    ///
    /// ```text
    /// payload_len > 65535 : head[1] = 127 | MASK, then 8 big-endian bytes
    /// payload_len >= 126  : head[1] = 126 | MASK, then 2 big-endian bytes
    /// otherwise           : head[1] = len | MASK
    /// ```
    ///
    /// `tests/data/test2700` is the oracle for the third form: a three-byte
    /// TEXT frame is `%81%83` followed by the mask and the payload, and `0x83`
    /// is `3 | 0x80`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] for steps 1, 2 and for a short queue write,
    /// [`CURLcode::TooLarge`] for step 5, and whatever
    /// [`flags_to_firstbyte`] reports for step 3.
    pub(crate) fn add_frame(
        &mut self,
        flags: i32,
        payload_len: i64,
        out: &mut BufQ,
        rng: &mut dyn Rng,
        force_zero_mask: bool,
        mut tracer: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        // `:837-841`.
        if payload_len < 0 {
            if let Some(tracer) = tracer.as_deref_mut() {
                failf!(
                    tracer,
                    "[WS] starting new frame with negative payload length {}",
                    payload_len
                );
            }
            return Err(CURLcode::SendError);
        }

        // `:843-848`.
        if self.payload_remain > 0 {
            if let Some(tracer) = tracer.as_deref_mut() {
                failf!(
                    tracer,
                    "[WS] starting new frame with {} bytes from last one \
                     remaining to be sent",
                    self.payload_remain
                );
            }
            return Err(CURLcode::SendError);
        }

        // `:850-853`.
        let firstb = flags_to_firstbyte(
            flags,
            self.contfragment,
            tracer.as_deref_mut(),
        )?;

        // `:855-859` -- DATA frames only.
        if (flags & (CURLWS_TEXT | CURLWS_BINARY)) != 0 {
            self.contfragment = (flags & CURLWS_CONT) != 0;
        }

        // `:861-872` -- three separate tests, three separate messages.
        let cntrl_max = i64::try_from(WS_MAX_CNTRL_LEN).unwrap_or(i64::MAX);
        if (flags & CURLWS_PING) != 0 && payload_len > cntrl_max {
            if let Some(tracer) = tracer.as_deref_mut() {
                failf!(tracer, "[WS] given PING frame is too big");
            }
            return Err(CURLcode::TooLarge);
        }
        if (flags & CURLWS_PONG) != 0 && payload_len > cntrl_max {
            if let Some(tracer) = tracer.as_deref_mut() {
                failf!(tracer, "[WS] given PONG frame is too big");
            }
            return Err(CURLcode::TooLarge);
        }
        if (flags & CURLWS_CLOSE) != 0 && payload_len > cntrl_max {
            if let Some(tracer) = tracer.as_deref_mut() {
                failf!(tracer, "[WS] given CLOSE frame is too big");
            }
            return Err(CURLcode::TooLarge);
        }

        // `:874-896`. A fixed buffer of the C's own size, filled to `hlen`.
        let mut head = [0_u8; WS_MAX_SEND_HEAD];
        self.firstbyte = firstb;
        head[0] = firstb;
        let mut hlen = if payload_len > WS_LEN16_MAX {
            head[1] = 127 | WSBIT_MASK;
            head[2..10].copy_from_slice(&payload_len.to_be_bytes());
            10
        } else if payload_len > WS_LEN7_MAX {
            head[1] = 126 | WSBIT_MASK;
            // The two bytes the C writes as `>> 8` and `& 0xff`; taking them
            // from the big-endian encoding of the 16-bit value keeps the order
            // explicit rather than implied by two shifts.
            let short = u16::try_from(payload_len).unwrap_or(u16::MAX);
            head[2..4].copy_from_slice(&short.to_be_bytes());
            4
        } else {
            // `payload_len` is in `0..=125` here, so the cast cannot lose
            // information; `try_from` states that rather than trusting it.
            head[1] = u8::try_from(payload_len).unwrap_or(0) | WSBIT_MASK;
            2
        };

        // `:898-899`.
        self.payload_remain = payload_len;
        self.payload_len = payload_len;
        self.trace_info(tracer, "sending");

        // `:901-911` -- four bytes of randomness, from the INJECTED generator.
        rand_bytes(rng, &mut self.mask);
        if force_zero_mask {
            // `CURL_WS_FORCE_ZERO_MASK`: *"force the bit mask to 0x00000000,
            // effectively disabling masking"*. A field rather than a `getenv`;
            // see [`WsSettings`].
            self.mask = [0; 4];
        }

        // `:913-917`.
        if let Some(slot) = head.get_mut(hlen..hlen + 4) {
            slot.copy_from_slice(&self.mask);
        }
        hlen += 4;
        self.xori = 0;

        // `:919-926`. The queue carries `BUFQ_OPT_SOFT_LIMIT`, so a write of a
        // head-sized span always succeeds; the C asserts that and then returns
        // `CURLE_SEND_ERROR` in a release build, which is what happens here
        // without the assert.
        let nwritten = out.write(head.get(..hlen).unwrap_or(&head))?;
        if nwritten != hlen {
            return Err(CURLcode::SendError);
        }
        Ok(())
    }

    /// `ws_enc_write_payload(enc, data, buf, buflen, out, pnwritten)`
    /// (`lib/ws.c:947-980`): mask payload bytes into `out`.
    ///
    /// **This is the masking step, and it is byte-exact**
    /// (`lib/ws.c:965-975`):
    ///
    /// ```c
    /// for(i = 0; i < len; ++i) {
    ///   uint8_t c = buf[i] ^ enc->mask[enc->xori];
    ///   result = Curl_bufq_write(out, &c, 1, &n);
    ///   ...
    ///   enc->xori++;
    ///   enc->xori &= 3;
    /// }
    /// ```
    ///
    /// The index ROTATES over the four mask bytes and its position survives
    /// across calls, which is what lets one frame's payload be encoded in
    /// several pieces -- the `CURLWS_OFFSET` case -- without the mask slipping.
    /// The C's own comment on the loop is *"not the most performant way to do
    /// this"*, and it is reproduced as written: specification 0.1.1 makes
    /// performance an explicit non-goal, and a bulk XOR would have to
    /// reproduce this exact index arithmetic to be correct anyway.
    ///
    /// The byte count is clamped to `payload_remain` first, so a caller cannot
    /// overrun the frame it declared.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] when `out` is already full and nothing was written
    /// (`lib/ws.c:956-957`), and whatever [`BufQ::write`] reports. Note the
    /// C's asymmetry, which is preserved: a mid-loop `CURLE_AGAIN` after at
    /// least one byte breaks out and reports the partial count as SUCCESS,
    /// while the same code on the first byte propagates.
    pub(crate) fn write_payload(
        &mut self,
        buf: &[u8],
        out: &mut BufQ,
        tracer: Option<&mut Tracer<'_>>,
    ) -> CodeResult<usize> {
        // `:956-957`.
        if out.is_full() {
            return Err(CURLcode::Again);
        }

        // `:960-963`.
        let len = buf.len().min(remain_as_usize(self.payload_remain));

        let mut written = 0_usize;
        for byte in buf.iter().take(len) {
            let masked = [*byte ^ self.mask[(self.xori & 3) as usize]];
            match out.write(&masked) {
                Ok(_) => {}
                Err(code) => {
                    // `:968-972`.
                    if code != CURLcode::Again || written == 0 {
                        return Err(code);
                    }
                    break;
                }
            }
            self.xori = self.xori.wrapping_add(1) & 3;
            written += 1;
        }

        // `:976-977`.
        self.payload_remain = self
            .payload_remain
            .saturating_sub(i64::try_from(written).unwrap_or(i64::MAX));
        self.trace_info(tracer, "buffered");
        Ok(written)
    }

    /// `ws_enc_info(enc, data, msg)` (`lib/ws.c:779-789`).
    ///
    /// One shape, unlike the decoder's three, and it reports how much of the
    /// frame has been buffered as `payload_len - payload_remain`.
    fn trace_info(&self, tracer: Option<&mut Tracer<'_>>, msg: &str) {
        let Some(tracer) = tracer else {
            return;
        };
        let nonfin = if (self.firstbyte & WSBIT_FIN) == 0 {
            " NON-FIN"
        } else {
            ""
        };
        trc_feat!(
            tracer,
            TraceFeature::Ws,
            "WS-ENC: {} [{}{} payload={}/{}]",
            msg,
            Opcode::name_of(self.firstbyte),
            nonfin,
            self.payload_len - self.payload_remain,
            self.payload_len
        );
    }
}

/// `struct ws_cntrl_frame` (`lib/ws.c:109-113`): the ONE control frame waiting
/// to go out.
///
/// The C keeps exactly one and says so where it overwrites it: *"Overwrite any
/// pending frame with the new one, we keep only one"* (`lib/ws.c:639-640`).
/// That is a deliberate policy rather than a limitation -- a burst of PINGs
/// deserves one PONG, not a queue of them.
///
/// The payload is a fixed [`WS_MAX_CNTRL_LEN`]-byte array, as in the C, which
/// makes the cap structural: there is nowhere to put a 126th byte, and
/// [`WebSocket::add_control`] refuses one before reaching this struct.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) struct PendingControl {
    /// `unsigned int type`: the `CURLWS_*` frame type, or `0` for *"nothing
    /// pending"*.
    ///
    /// The sentinel is the C's: `if(ws->pending.type)` at `lib/ws.c:939` and
    /// `:988` is how it asks whether a frame is waiting, and `memset(&
    /// ws->pending, 0, sizeof(ws->pending))` at `:1018` is how it clears one.
    /// No `CURLWS_*` value is zero, so the sentinel is unambiguous --
    /// [`is_pending`](Self::is_pending) names it rather than leaving `!= 0` at
    /// each site.
    frame_type: i32,
    /// `size_t payload_len`.
    payload_len: usize,
    /// `uint8_t payload[WS_MAX_CNTRL_LEN]`.
    payload: [u8; WS_MAX_CNTRL_LEN],
}

impl Default for PendingControl {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
impl PendingControl {
    /// The zeroed state, which means *"nothing pending"*.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            frame_type: 0,
            payload_len: 0,
            payload: [0; WS_MAX_CNTRL_LEN],
        }
    }

    /// `if(ws->pending.type)` (`lib/ws.c:939`, `:988`).
    #[must_use]
    pub(crate) const fn is_pending(&self) -> bool {
        self.frame_type != 0
    }

    /// The frame type waiting, or `0`.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) const fn frame_type(&self) -> i32 {
        self.frame_type
    }

    /// The payload waiting, empty when nothing is.
    #[must_use]
    pub(crate) fn payload(&self) -> &[u8] {
        self.payload.get(..self.payload_len).unwrap_or(&[])
    }

    /// `memset(&ws->pending, 0, sizeof(ws->pending))` (`lib/ws.c:1018`).
    ///
    /// The payload bytes are zeroed as well as the length, matching the C's
    /// `memset`: a stale PONG payload must not be readable through a later
    /// frame whose length happens to be longer.
    pub(crate) fn clear(&mut self) {
        self.frame_type = 0;
        self.payload_len = 0;
        self.payload = [0; WS_MAX_CNTRL_LEN];
    }

    /// Store `payload` as a pending `frame_type` frame, replacing any
    /// predecessor (`lib/ws.c:641-643`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for a payload over
    /// [`WS_MAX_CNTRL_LEN`], which is the C's answer at `lib/ws.c:636-637` --
    /// and which it reaches only in a release build, since `DEBUGASSERT(plen
    /// <= WS_MAX_CNTRL_LEN)` fires first in a debug one.
    pub(crate) fn store(
        &mut self,
        frame_type: i32,
        payload: &[u8],
    ) -> CodeResult<()> {
        if payload.len() > WS_MAX_CNTRL_LEN {
            return Err(CURLcode::BadFunctionArgument);
        }
        let Some(slot) = self.payload.get_mut(..payload.len()) else {
            return Err(CURLcode::BadFunctionArgument);
        };
        slot.copy_from_slice(payload);
        self.frame_type = frame_type;
        self.payload_len = payload.len();
        Ok(())
    }
}

// -- 7. The transport seam -------------------------------------------------

/// Where encoded frames go and where raw bytes come from.
///
/// The C reaches four different functions for this, chosen by where it is
/// called from (`lib/ws.c:1655-1665` and `:1522-1528`): `Curl_xfer_send` for a
/// transfer in progress, `Curl_senddata` inside a callback or a
/// `CURLOPT_CONNECT_ONLY` handle, `ws_send_raw_blocking` when a callback needs
/// the whole buffer gone, and `curl_easy_recv` for the receive side. All four
/// end at the same place -- the connection filter chain -- so this trait is
/// that place, and the choice between them becomes the `blocking` argument of
/// [`WebSocket::flush`].
///
/// Injecting it is what lets every test in this module run over
/// [`crate::conn::filters`]'s in-memory transport with no socket, no runtime
/// and no network, which is what makes the 80% line coverage specification
/// 0.8.4 requires reachable for this file.
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) trait WsTransport {
    /// Send as much of `buf` as the transport accepts.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] when it would block, which [`WebSocket::flush`]
    /// treats as *"come back later"* rather than as a failure; anything else
    /// is fatal to the transfer.
    fn send(&mut self, buf: &[u8]) -> CodeResult<usize>;

    /// Receive into `buf`, answering `0` at end of stream.
    ///
    /// # Errors
    ///
    /// As [`Self::send`]. A zero-length answer is NOT an error here: it is how
    /// [`ws_recv`] learns the connection closed, and it reports
    /// [`CURLcode::GotNothing`] for it (`lib/ws.c:1579-1583`).
    fn recv(&mut self, buf: &mut [u8]) -> CodeResult<usize>;
}

/// A [`WsTransport`] over the connection filter chain.
///
/// The production adapter: `Curl_senddata` and `curl_easy_recv` both descend
/// into `Curl_conn_send`/`Curl_conn_recv`, which is
/// [`FilterChain::send`]/[`FilterChain::recv`] here. The [`CallCtx`] is
/// borrowed alongside the chain because every chain call needs both, and
/// [`crate::protocols::TransferCtx::chain_with_ctx`] is what hands a protocol
/// the pair.
///
/// The rich [`crate::error::Error`] a filter attaches is narrowed to its
/// [`CURLcode`] crossing this seam, exactly as the C loses the message
/// crossing its own callback boundary; a caller wanting the text has the
/// tracer.
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) struct ChainTransport<'chain, 'ctx, 'trc> {
    /// The chain to work on -- `FIRSTSOCKET` for a WebSocket, always.
    chain: &'chain mut FilterChain,
    /// The synchronous filter-layer context.
    cx: &'chain mut CallCtx<'ctx, 'trc>,
}

#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
impl<'chain, 'ctx, 'trc> ChainTransport<'chain, 'ctx, 'trc> {
    /// Adapts a borrowed chain and its context.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi
    pub(crate) fn new(
        chain: &'chain mut FilterChain,
        cx: &'chain mut CallCtx<'ctx, 'trc>,
    ) -> Self {
        Self { chain, cx }
    }
}

impl fmt::Debug for ChainTransport<'_, '_, '_> {
    /// Neither borrowed half is [`fmt::Debug`], and printing a filter chain in
    /// a diagnostic would be noise rather than information.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChainTransport")
    }
}

impl WsTransport for ChainTransport<'_, '_, '_> {
    fn send(&mut self, buf: &[u8]) -> CodeResult<usize> {
        self.chain.send(self.cx, buf, false).map_err(CURLcode::from)
    }

    fn recv(&mut self, buf: &mut [u8]) -> CodeResult<usize> {
        self.chain.recv(self.cx, buf).map_err(CURLcode::from)
    }
}

// -- 8. The per-connection state: `lib/ws.c:115-126` -----------------------

/// Everything a WebSocket operation is handed besides the state itself.
///
/// The C threads `struct Curl_easy *data` and reaches through it for four
/// unrelated things: the option bits, the randomness, the transport and the
/// trace destination. Specification 0.1.2 requires that god-struct to be
/// decomposed, so those four arrive here explicitly and nothing else is
/// reachable from a codec function.
///
/// Every field is injected, which is the property specification 0.3.3's
/// pattern P12 asks for and the reason this file's tests need no socket, no
/// clock and no entropy source.
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) struct WsCtx<'a, 'trc> {
    /// `data->set.ws_*` and the two debug knobs.
    settings: &'a WsSettings,
    /// `Curl_rand`'s generator, for the frame mask.
    rng: &'a mut dyn Rng,
    /// Where encoded bytes go and raw bytes come from.
    transport: &'a mut dyn WsTransport,
    /// `data`'s trace destination, absent when the handle is silent.
    tracer: Option<&'a mut Tracer<'trc>>,
    /// `Curl_is_in_callback(data)`: is libcurl currently inside application
    /// code?
    ///
    /// # One field for six call sites, and that is a measurement
    ///
    /// `ws_flush(data, ws, blocking)` is called six times in `lib/ws.c`, and at
    /// EVERY one of them the `blocking` argument equals
    /// `Curl_is_in_callback(data)`. Four pass it directly (`:648`, `:1059`,
    /// `:1091`, `:1622`); the other two pass the literals `TRUE` (`:1745`) and
    /// `FALSE` (`:1752`) from inside the two arms of
    /// `if(Curl_is_in_callback(data))`, so they agree as well.
    ///
    /// The whole of the C's blocking policy is therefore this one property of
    /// the handle, and it is a FIELD rather than a parameter threaded through
    /// eight signatures. The reason blocking follows it is the C's own comment:
    /// *"When invoked from inside callbacks, we do a blocking send as the
    /// callback will probably not implement partial writes that may then mess
    /// up the ws framing subsequently"* (`:1741-1743`).
    in_callback: bool,
}

impl fmt::Debug for WsCtx<'_, '_> {
    /// Only the settings are printable; the other three are borrowed
    /// collaborators whose contents would be noise in a diagnostic.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsCtx")
            .field("settings", self.settings)
            .field("traced", &self.tracer.is_some())
            .finish()
    }
}

#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
impl<'a, 'trc> WsCtx<'a, 'trc> {
    /// A context over the three mandatory collaborators.
    pub(crate) fn new(
        settings: &'a WsSettings,
        rng: &'a mut dyn Rng,
        transport: &'a mut dyn WsTransport,
    ) -> Self {
        Self {
            settings,
            rng,
            transport,
            tracer: None,
            in_callback: false,
        }
    }

    /// Attaches the handle's trace destination.
    #[must_use]
    pub(crate) fn with_tracer(mut self, tracer: &'a mut Tracer<'trc>) -> Self {
        self.tracer = Some(tracer);
        self
    }

    /// Records that libcurl is inside application code, which makes every send
    /// on this context blocking -- see [`Self::in_callback`].
    #[must_use]
    pub(crate) const fn with_in_callback(mut self, in_callback: bool) -> Self {
        self.in_callback = in_callback;
        self
    }

    /// `Curl_is_in_callback(data)`.
    #[must_use]
    pub(crate) const fn in_callback(&self) -> bool {
        self.in_callback
    }

    /// The options in force.
    #[must_use]
    pub(crate) const fn settings(&self) -> &WsSettings {
        self.settings
    }

    /// The generator AND the tracer, as two disjoint borrows.
    ///
    /// [`WsEncoder::add_frame`] needs both at once, and taking them through two
    /// accessor calls is `error[E0499]`: each would borrow the whole context.
    /// Returning them together lets the compiler see that they come from
    /// DIFFERENT fields, which is the same reason
    /// [`crate::protocols::TransferCtx::chain_with_ctx`] exists.
    fn rng_and_tracer(
        &mut self,
    ) -> (&mut (dyn Rng + 'a), Option<&mut Tracer<'trc>>) {
        (&mut *self.rng, self.tracer.as_deref_mut())
    }

    /// A fresh borrow of the tracer, for a call that takes
    /// `Option<&mut Tracer>`.
    ///
    /// `as_deref_mut` rather than `as_mut`, so the result is
    /// `Option<&mut Tracer<'trc>>` and not `Option<&mut &mut Tracer<'trc>>`;
    /// the double reference does not coerce at a trait-object boundary.
    fn tracer(&mut self) -> Option<&mut Tracer<'trc>> {
        self.tracer.as_deref_mut()
    }
}

/// `struct websocket` (`lib/ws.c:117-126`): one connection's WebSocket state.
///
/// The C stashes this under the connection's meta key
/// `"meta:proto:ws:conn"` (`lib/ws.h:34`) and fetches it with
/// `Curl_conn_meta_get`, casting a `void *` at every use. Here it is a typed
/// value that its owner holds directly: the untyped stash is exactly the
/// pattern specification 0.6.9 requires be eliminated, and the failure mode it
/// produces -- *"[WS] not a websocket transfer"* on a lookup miss -- becomes a
/// type error instead of a run-time diagnostic.
///
/// `struct Curl_easy *data` is the one member with no successor. The C keeps it
/// *"used for write callback handling"*; here the collaborators arrive as
/// [`WsCtx`] on each call, so the state holds no back-pointer and cannot
/// outlive what it points at.
#[derive(Debug)]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) struct WebSocket {
    /// `dec`: the frame decoder.
    dec: WsDecoder,
    /// `enc`: the frame encoder, and the connection's mask.
    enc: WsEncoder,
    /// `recvbuf`: raw bytes from the server, awaiting decode.
    recvbuf: BufQ,
    /// `sendbuf`: encoded bytes awaiting the transport.
    sendbuf: BufQ,
    /// `recvframe`: the metadata of the frame most recently received.
    ///
    /// This is the storage `curl_ws_meta` hands a pointer to
    /// (`lib/ws.c:1861`) and the storage `curl_ws_recv` points `*metap` at
    /// (`:1611`), which is why it lives on the connection and not on the call.
    recvframe: WsFrameMeta,
    /// `pending`: the one control frame waiting to go out.
    pending: PendingControl,
    /// `sendbuf_payload`: how many bytes of [`Self::sendbuf`] are PAYLOAD
    /// rather than head.
    ///
    /// The bookkeeping that makes [`Self::encode_send`] able to report a
    /// payload-only count to an application that never sees the framing.
    sendbuf_payload: usize,
}

#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
impl WebSocket {
    /// The state `Curl_ws_accept` builds on a fresh connection
    /// (`lib/ws.c:1327-1352`).
    ///
    /// Both queues are `Curl_bufq_init2(&q, chunk_size, WS_CHUNK_COUNT,
    /// BUFQ_OPT_SOFT_LIMIT)`. The soft limit is load-bearing rather than
    /// incidental: [`WsEncoder::add_frame`] relies on a head-sized write always
    /// succeeding, and a hard limit would make that write fail at a chunk
    /// boundary and abandon a frame half-described.
    #[must_use]
    pub(crate) fn new(settings: &WsSettings) -> Self {
        let chunk = settings.chunk_size.max(1);
        Self {
            dec: WsDecoder::new(),
            enc: WsEncoder::new(),
            recvbuf: BufQ::with_opts(
                chunk,
                WS_CHUNK_COUNT,
                BufqOpts::SOFT_LIMIT,
            ),
            sendbuf: BufQ::with_opts(
                chunk,
                WS_CHUNK_COUNT,
                BufqOpts::SOFT_LIMIT,
            ),
            recvframe: WsFrameMeta::new(),
            pending: PendingControl::new(),
            sendbuf_payload: 0,
        }
    }

    /// What `Curl_ws_accept` does to a state it FOUND rather than created
    /// (`lib/ws.c:1354-1358`).
    ///
    /// `Curl_bufq_reset(&ws->recvbuf)` plus a full decoder and encoder reset.
    /// Note which queue is NOT reset: `sendbuf`. Bytes already encoded for the
    /// previous life of this connection stay queued, which is the C's
    /// behaviour and is transcribed rather than tidied.
    pub(crate) fn reset_for_reuse(&mut self) {
        self.recvbuf.reset();
        self.dec.reset();
        self.enc.reset();
    }

    /// The decoder, for a caller that needs its state.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) const fn decoder(&self) -> &WsDecoder {
        &self.dec
    }

    /// The encoder, for a caller that needs its mask or its remaining count.
    #[must_use]
    pub(crate) const fn encoder(&self) -> &WsEncoder {
        &self.enc
    }

    /// The pending control frame, if any.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) const fn pending(&self) -> &PendingControl {
        &self.pending
    }

    /// The metadata of the most recently received frame.
    ///
    /// The value `curl_ws_meta` returns a pointer to, and what
    /// `curl_ws_recv` reports through `*metap`.
    #[must_use]
    pub(crate) const fn recv_frame(&self) -> &WsFrameMeta {
        &self.recvframe
    }

    /// Bytes currently queued for the transport.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) fn sendbuf_len(&self) -> usize {
        self.sendbuf.len()
    }

    /// Raw bytes received and not yet decoded.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) fn recvbuf_len(&self) -> usize {
        self.recvbuf.len()
    }

    /// Queue raw bytes for decoding, which is what `Curl_ws_accept` does with
    /// the payload that arrived alongside the `101` response
    /// (`lib/ws.c:1392-1402`).
    ///
    /// Only the `CURLOPT_CONNECT_ONLY` path takes it: with a callback-driven
    /// transfer those bytes go to `Curl_client_write` instead, because the
    /// client-writer chain is already installed by then.
    ///
    /// # Errors
    ///
    /// Whatever [`BufQ::write`] reports. The C asserts `nread == nwritten`
    /// and, with a soft-limited queue, that always holds; a short write is
    /// answered here with [`CURLcode::RecvError`] rather than asserted, so a
    /// release build cannot silently drop payload.
    pub(crate) fn queue_received(&mut self, bytes: &[u8]) -> CodeResult<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let nwritten = self.recvbuf.write(bytes)?;
        if nwritten != bytes.len() {
            return Err(CURLcode::RecvError);
        }
        Ok(())
    }

    /// `update_meta(ws, frame_age, frame_flags, payload_offset, payload_len,
    /// cur_len)` (`lib/ws.c:573-586`).
    ///
    /// The arithmetic that matters is `bytesleft`:
    ///
    /// ```c
    /// curl_off_t bytesleft = (payload_len - payload_offset - cur_len);
    /// ```
    ///
    /// So `bytesleft` counts what follows THIS chunk, not what follows the
    /// offset. An application reading a fragmented message therefore sees
    /// `bytesleft` fall to zero on the chunk that completes the frame, which is
    /// the documented signal that the frame is done.
    pub(crate) fn update_meta(
        &mut self,
        frame_age: i32,
        frame_flags: i32,
        payload_offset: i64,
        payload_len: i64,
        cur_len: usize,
    ) {
        let current = i64::try_from(cur_len).unwrap_or(i64::MAX);
        self.recvframe = WsFrameMeta {
            age: frame_age,
            flags: frame_flags,
            offset: payload_offset,
            bytesleft: payload_len
                .saturating_sub(payload_offset)
                .saturating_sub(current),
            len: cur_len,
        };
    }

    /// `ws_enc_write_head(data, ws, enc, flags, payload_len, out)`
    /// (`lib/ws.c:930-945`).
    ///
    /// Two steps, and the first is easy to overlook: *"starting a new frame, we
    /// want a clean sendbuf. Any pending control frame we can add now as part
    /// of the flush."* So a PONG queued while another frame was in flight is
    /// emitted BEFORE the new frame's head, never interleaved into its payload.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::add_pending`] or [`WsEncoder::add_frame`] reports.
    pub(crate) fn write_head(
        &mut self,
        flags: i32,
        payload_len: i64,
        cx: &mut WsCtx<'_, '_>,
    ) -> CodeResult<()> {
        if self.pending.is_pending() {
            self.add_pending(cx)?;
        }
        let force_zero = cx.settings.force_zero_mask;
        let (rng, tracer) = cx.rng_and_tracer();
        self.enc.add_frame(
            flags,
            payload_len,
            &mut self.sendbuf,
            rng,
            force_zero,
            tracer,
        )
    }

    /// `ws_enc_add_pending(data, ws)` (`lib/ws.c:982-1022`): encode the waiting
    /// control frame.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] when a frame is in progress, because a control frame
    /// may not be spliced into another frame's payload
    /// (`lib/ws.c:990-991`). [`CURLcode::SendError`] when the queue accepted
    /// only part of the payload, which a soft-limited queue never does -- the C
    /// asserts it and returns the same code in a release build.
    pub(crate) fn add_pending(
        &mut self,
        cx: &mut WsCtx<'_, '_>,
    ) -> CodeResult<()> {
        // `:988-989`.
        if !self.pending.is_pending() {
            return Ok(());
        }
        // `:990-991`.
        if self.enc.payload_remain != 0 {
            return Err(CURLcode::Again);
        }

        let frame_type = self.pending.frame_type;
        let plen = self.pending.payload_len;
        let force_zero = cx.settings.force_zero_mask;

        // `:993-1000`.
        let (rng, tracer) = cx.rng_and_tracer();
        if let Err(code) = self.enc.add_frame(
            frame_type,
            i64::try_from(plen).unwrap_or(i64::MAX),
            &mut self.sendbuf,
            rng,
            force_zero,
            tracer,
        ) {
            if let Some(tracer) = cx.tracer() {
                trc_feat!(
                    tracer,
                    TraceFeature::Ws,
                    "ws_enc_cntrl(), error adding head: {}",
                    code as i32
                );
            }
            return Err(code);
        }

        // `:1001-1008`.
        let written = match self.enc.write_payload(
            self.pending.payload(),
            &mut self.sendbuf,
            cx.tracer(),
        ) {
            Ok(written) => written,
            Err(code) => {
                if let Some(tracer) = cx.tracer() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Ws,
                        "ws_enc_cntrl(), error adding payload: {}",
                        code as i32
                    );
                }
                return Err(code);
            }
        };

        // `:1009-1015`.
        if written != plen {
            if let Some(tracer) = cx.tracer() {
                trc_feat!(
                    tracer,
                    TraceFeature::Ws,
                    "ws_enc_cntrl(), error added only {}/{} payload,",
                    written,
                    plen
                );
            }
            return Err(CURLcode::SendError);
        }

        // `:1016-1018` -- the frame is complete, so the slot is freed.
        self.pending.clear();
        Ok(())
    }

    /// `ws_enc_add_cntrl(data, ws, payload, plen, frame_type)`
    /// (`lib/ws.c:629-652`): queue a control frame, and send it if nothing is
    /// in flight.
    ///
    /// The C's `blocking` argument here is `Curl_is_in_callback(data)`, which
    /// arrives as [`WsCtx::in_callback`] -- see that field for the measurement
    /// that makes one property serve all six of the C's flush call sites.
    ///
    /// A flush failure is deliberately DISCARDED, as in the C's
    /// `(void)ws_flush(...)`: the control frame is queued either way, and a
    /// blocked socket is not a reason to fail the frame that provoked the PONG.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for a payload over
    /// [`WS_MAX_CNTRL_LEN`], and whatever [`Self::add_pending`] reports.
    pub(crate) fn add_control(
        &mut self,
        payload: &[u8],
        frame_type: i32,
        cx: &mut WsCtx<'_, '_>,
    ) -> CodeResult<()> {
        // `:635-637`: the C asserts and then, in a release build, returns this.
        self.pending.store(frame_type, payload)?;

        // `:645-650`.
        if self.enc.payload_remain == 0 {
            self.add_pending(cx)?;
            let _ = self.flush(cx);
        }
        Ok(())
    }

    /// `ws_flush(data, ws, blocking)` (`lib/ws.c:1627-1683`): drain
    /// [`Self::sendbuf`] into the transport.
    ///
    /// # The three send paths, and what became of them
    ///
    /// The C chooses between three functions (`:1655-1665`):
    ///
    /// ```c
    /// if(blocking)                    ws_send_raw_blocking(...)
    /// else if(connect_only || in_cb)  Curl_senddata(...)
    /// else {                          Curl_xfer_send(...);
    ///   if(!result && !n && outlen)      result = CURLE_AGAIN; }
    /// ```
    ///
    /// All three reach the same filter chain, so they differ only in what they
    /// do with a partial write, and that difference is preserved here:
    ///
    /// * `blocking` keeps offering the SAME span until it is gone, which is
    ///   what a write callback needs -- *"the callback will probably not
    ///   implement partial writes that may then mess up the ws framing
    ///   subsequently"* (`:1741-1743`);
    /// * otherwise one offer per span, and a zero-byte accept for a non-empty
    ///   span becomes [`CURLcode::Again`], which is the third arm's own
    ///   conversion.
    ///
    /// What is NOT reproduced is the `SOCKET_WRITABLE` wait inside
    /// `ws_send_raw_blocking` (`:1700-1720`). It needs the socket AND
    /// `Curl_timeleft_ms`, which are the filter layer's and the transfer's
    /// respectively; a codec reaching for either would be the god-struct again.
    /// So a blocked transport surfaces [`CURLcode::Again`] with the remainder
    /// still queued -- no byte is lost and no frame is left half-described --
    /// and the caller polls and calls this again. That is the same contract the
    /// non-blocking arm has always had.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] when the transport blocks, and whatever it reports
    /// otherwise. A real failure is announced with the C's message,
    /// *"[WS] flush, write error %d"*.
    pub(crate) fn flush(&mut self, cx: &mut WsCtx<'_, '_>) -> CodeResult<()> {
        let blocking = cx.in_callback;
        // `:1630` -- nothing queued is success, not a no-op to be logged.
        while !self.sendbuf.is_empty() {
            let outcome = {
                let Some(span) = self.sendbuf.peek() else {
                    break;
                };
                let outlen = span.len();
                (cx.transport.send(span), outlen)
            };
            match outcome {
                (Ok(0), outlen) if outlen > 0 => {
                    // The third arm's conversion (`:1663-1664`), and the
                    // blocking arm cannot make progress either.
                    if let Some(tracer) = cx.tracer() {
                        trc_feat!(
                            tracer,
                            TraceFeature::Ws,
                            "flush EAGAIN, {} bytes remain in buffer",
                            outlen
                        );
                    }
                    return Err(CURLcode::Again);
                }
                (Ok(sent), outlen) => {
                    if let Some(tracer) = cx.tracer() {
                        trc_feat!(
                            tracer,
                            TraceFeature::Ws,
                            "flushed {} bytes",
                            sent
                        );
                    }
                    self.sendbuf.skip(sent);
                    if blocking && sent < outlen {
                        // The blocking arm re-offers the remainder of the same
                        // span, which the loop does by continuing: `peek`
                        // answers what is left of it.
                        continue;
                    }
                }
                (Err(CURLcode::Again), _) => {
                    if let Some(tracer) = cx.tracer() {
                        trc_feat!(
                            tracer,
                            TraceFeature::Ws,
                            "flush EAGAIN, {} bytes remain in buffer",
                            self.sendbuf.len()
                        );
                    }
                    return Err(CURLcode::Again);
                }
                (Err(code), _) => {
                    if let Some(tracer) = cx.tracer() {
                        failf!(
                            tracer,
                            "[WS] flush, write error {}",
                            code as i32
                        );
                    }
                    return Err(code);
                }
            }
        }
        Ok(())
    }

    /// `ws_send_raw(data, buffer, buflen, pnwritten)` (`lib/ws.c:1726-1761`):
    /// the `CURLWS_RAW_MODE` send path.
    ///
    /// No framing, no masking, and the application's bytes reach the wire
    /// unchanged -- but the queue is still drained first, because bytes already
    /// encoded must not end up behind raw ones.
    ///
    /// The C's two arms differ in exactly that flush: inside a callback it is
    /// blocking and the payload is then sent blocking too; outside one, a
    /// non-blocking flush that answers `CURLE_AGAIN` aborts the call so the
    /// application can retry with the same buffer.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::flush`] or the transport reports. An empty buffer is
    /// success with a count of zero (`:1737-1738`).
    pub(crate) fn send_raw(
        &mut self,
        buffer: &[u8],
        cx: &mut WsCtx<'_, '_>,
    ) -> CodeResult<usize> {
        // `:1737-1738`.
        if buffer.is_empty() {
            return Ok(0);
        }

        let blocking = cx.in_callback;
        self.flush(cx)?;

        let sent = if blocking {
            // `ws_send_raw_blocking` (`:1685-1724`): keep going until the whole
            // buffer is gone. The socket wait is the caller's, as
            // [`Self::flush`] records.
            let mut total = 0_usize;
            while total < buffer.len() {
                let offered = buffer.get(total..).unwrap_or(&[]);
                let n = cx.transport.send(offered)?;
                if n == 0 {
                    return Err(CURLcode::Again);
                }
                total += n;
            }
            total
        } else {
            cx.transport.send(buffer)?
        };

        if let Some(tracer) = cx.tracer() {
            trc_feat!(
                tracer,
                TraceFeature::Ws,
                "ws_send_raw(len={}) -> 0, {}",
                buffer.len(),
                sent
            );
        }
        Ok(sent)
    }

    /// `ws_enc_send(data, ws, buffer, buflen, fragsize, flags, pnsent)`
    /// (`lib/ws.c:1024-1120`): the framed send path.
    ///
    /// # The two shapes of a call
    ///
    /// A call either CONTINUES a frame or STARTS one, and the C decides by
    /// looking at the encoder and the queue together (`:1038`):
    ///
    /// * continuing -- `payload_remain` non-zero or `sendbuf` non-empty -- and
    ///   then two invariants are enforced on the caller. `buflen` may not have
    ///   SHRUNK since the previous call, because the bytes already buffered came
    ///   from the front of the same buffer; and `buflen` may not exceed what the
    ///   frame still owes plus what is buffered, because that would overrun the
    ///   declared frame. Both are [`CURLcode::BadFunctionArgument`] with the C's
    ///   messages;
    /// * starting -- flush first, then write a head for `fragsize` when
    ///   [`CURLWS_OFFSET`] is set and for `buflen` otherwise (`:1063-1066`).
    ///   That is the whole of `CURLWS_OFFSET`'s meaning on the send side.
    ///
    /// # The loop, and what it reports
    ///
    /// While there is queued data to flush OR payload left to encode, the loop
    /// adds payload and flushes. The count it reports is PAYLOAD bytes only --
    /// an application never sees the framing -- which is what
    /// `sendbuf_payload` tracks. A block after some payload has reached the wire
    /// is reported as SUCCESS with a partial count (`:1098-1106`); a block
    /// before any has is [`CURLcode::Again`] with a count of zero, because
    /// *"we cannot report OK on 0-length send (caller counts only payload) and
    /// EAGAIN"*.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for the two caller invariants,
    /// [`CURLcode::Again`] as described, and whatever the head write, the
    /// payload encode or the flush reports.
    pub(crate) fn encode_send(
        &mut self,
        buffer: &[u8],
        fragsize: i64,
        flags: i32,
        cx: &mut WsCtx<'_, '_>,
    ) -> CodeResult<usize> {
        let mut buffer = buffer;
        let mut nsent = 0_usize;

        // `:1038-1057`.
        if self.enc.payload_remain != 0 || !self.sendbuf.is_empty() {
            if buffer.len() < self.sendbuf_payload {
                if let Some(tracer) = cx.tracer() {
                    failf!(
                        tracer,
                        "[WS] curl_ws_send() called with smaller 'buflen' \
                         than bytes already buffered in previous call, {} vs {}",
                        buffer.len(),
                        self.sendbuf_payload
                    );
                }
                return Err(CURLcode::BadFunctionArgument);
            }
            let buffered = i64::try_from(self.sendbuf_payload).unwrap_or(0);
            let allowed = self.enc.payload_remain.saturating_add(buffered);
            if i64::try_from(buffer.len()).unwrap_or(i64::MAX) > allowed {
                if let Some(tracer) = cx.tracer() {
                    failf!(
                        tracer,
                        "[WS] unaligned frame size (sending {} instead of {})",
                        buffer.len(),
                        allowed
                    );
                }
                return Err(CURLcode::BadFunctionArgument);
            }
        } else {
            // `:1058-1071`.
            self.flush(cx)?;
            let head_len = if (flags & CURLWS_OFFSET) != 0 {
                fragsize
            } else {
                i64::try_from(buffer.len()).unwrap_or(i64::MAX)
            };
            if let Err(code) = self.write_head(flags, head_len, cx) {
                if let Some(tracer) = cx.tracer() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Ws,
                        "curl_ws_send(), error writing frame head {}",
                        code as i32
                    );
                }
                return Err(code);
            }
        }

        // `:1074-1118`.
        while !self.sendbuf.is_empty() || buffer.len() > self.sendbuf_payload {
            if buffer.len() > self.sendbuf_payload {
                let prev_len = self.sendbuf.len();
                let offered = buffer.get(self.sendbuf_payload..).unwrap_or(&[]);
                match self.enc.write_payload(
                    offered,
                    &mut self.sendbuf,
                    cx.tracer(),
                ) {
                    Ok(_) | Err(CURLcode::Again) => {}
                    Err(code) => return Err(code),
                }
                self.sendbuf_payload += self.sendbuf.len() - prev_len;
                if self.sendbuf_payload == 0 {
                    return Err(CURLcode::Again);
                }
            }

            match self.flush(cx) {
                Ok(()) => {
                    if self.sendbuf_payload > 0 {
                        nsent += self.sendbuf_payload;
                        buffer =
                            buffer.get(self.sendbuf_payload..).unwrap_or(&[]);
                        self.sendbuf_payload = 0;
                    }
                }
                Err(CURLcode::Again) => {
                    // `:1098-1114`.
                    if self.sendbuf_payload > self.sendbuf.len() {
                        let flushed = self.sendbuf_payload - self.sendbuf.len();
                        nsent += flushed;
                        self.sendbuf_payload -= flushed;
                        return Ok(nsent);
                    }
                    if let Some(tracer) = cx.tracer() {
                        trc_feat!(
                            tracer,
                            TraceFeature::Ws,
                            "EAGAIN flushing sendbuf, payload_encoded: {}/{}",
                            self.sendbuf_payload,
                            buffer.len()
                        );
                    }
                    return Err(CURLcode::Again);
                }
                Err(code) => return Err(code),
            }
        }
        Ok(nsent)
    }
}

// -- 9. The client writer: `lib/ws.c:588-777` ------------------------------

/// Where a decoded frame goes during a callback-driven transfer.
///
/// `Curl_cwriter_write(data, writer->next, type, buf, len)` -- the NEXT writer
/// in the chain (`lib/ws.c:703-705` and `:723`). The chain itself belongs to
/// [`crate::transfer`], so this is a seam and not a second copy of it.
///
/// # The flags obligation, which lives with the implementor
///
/// The C forwards its own `type` with one bit added:
///
/// ```c
/// Curl_cwriter_write(data, ctx->next_writer,
///                    (ctx->cw_type | CLIENTWRITE_0LEN), (const char *)buf,
///                    buflen);
/// ```
///
/// `CLIENTWRITE_0LEN` is what makes a zero-length frame reach the application
/// instead of being swallowed by `lib/cw-out.c`'s empty-write shortcut, and
/// `lib/ws.c:704` is the ONLY site in the C tree that sets it -- which
/// [`crate::transfer::sendf`]'s own documentation of that flag records from the
/// other side. The implementor of [`Self::write_decoded`] therefore owns the
/// composition, because it is the half that holds the writer chain and the
/// `cw_type` of the write in progress. Stated here so the obligation cannot be
/// lost in the handover.
#[allow(dead_code)] // consumer: the transfer core's client-writer chain
pub(crate) trait BodyWriter {
    /// A decoded frame chunk, with the metadata already published.
    ///
    /// `meta` is [`WebSocket::recv_frame`] AFTER
    /// [`WebSocket::update_meta`], which is the ordering `curl_ws_meta`
    /// depends on: an application calling it from inside its write callback
    /// must see THIS frame's metadata (`lib/ws.c:700-705`).
    ///
    /// # Errors
    ///
    /// Whatever the writer chain reports; a failure aborts the decode.
    fn write_decoded(
        &mut self,
        bytes: &[u8],
        meta: &WsFrameMeta,
    ) -> CodeResult<()>;

    /// Bytes that bypass the WebSocket decoder entirely.
    ///
    /// `ws_cw_write`'s first act (`lib/ws.c:722-723`): a write that is not
    /// `CLIENTWRITE_BODY`, or any write at all under
    /// [`CURLWS_RAW_MODE`], goes straight down the chain with its flags
    /// unchanged.
    ///
    /// # Errors
    ///
    /// As [`Self::write_decoded`].
    fn write_passthrough(
        &mut self,
        bytes: &[u8],
        is_eos: bool,
    ) -> CodeResult<()>;
}

/// `ws_cw_dec_next`'s work, as a [`PayloadSink`] (`lib/ws.c:667-711`).
///
/// # Why the PONG is recorded rather than sent from here
///
/// The C's callback holds `struct websocket *ws` and calls
/// `ws_enc_add_cntrl` straight through it. This sink cannot: the decoder
/// driving it already borrows the same [`WebSocket`] mutably. So a PING
/// records the reply here and [`WsDecodeWriter::write`] applies it as soon as
/// the pass returns -- which is the same point in the byte stream, because
/// [`WsDecoder::pass`] handles at most one frame per call. The ordering an
/// observer can see is therefore identical: PONG queued after the PING that
/// provoked it and before any later frame.
#[allow(dead_code)] // consumers: the codec below, and mod tests
struct ForwardSink<'a> {
    /// The next writer in the chain.
    next: &'a mut dyn BodyWriter,
    /// The connection's [`WebSocket::recvframe`], borrowed so that the
    /// metadata is published BEFORE the forward.
    meta: &'a mut WsFrameMeta,
    /// `!data->set.ws_no_auto_pong`.
    auto_pong: bool,
    /// The PONG payload to queue when the pass returns, if a PING arrived.
    pong: Option<([u8; WS_MAX_CNTRL_LEN], usize)>,
}

impl PayloadSink for ForwardSink<'_> {
    fn write(&mut self, frame: DecodedFrame<'_>) -> CodeResult<usize> {
        // `:683-687`.
        let Some(remain) = payload_remain(
            frame.payload_len,
            frame.payload_offset,
            frame.buf.len(),
        ) else {
            return Err(CURLcode::BadFunctionArgument);
        };

        if self.auto_pong && (frame.flags & CURLWS_PING) != 0 && remain == 0 {
            // `:689-697` -- *"auto-respond to PINGs, only works for
            // single-frame payloads atm"*, and the C's comment on the reply is
            // *"send back the exact same content as a PONG"*. The echo is
            // byte-for-byte, which is why the payload is copied rather than
            // summarised.
            let mut stored = [0_u8; WS_MAX_CNTRL_LEN];
            let len = frame.buf.len().min(WS_MAX_CNTRL_LEN);
            if let Some(slot) = stored.get_mut(..len) {
                slot.copy_from_slice(frame.buf.get(..len).unwrap_or(&[]));
            }
            self.pong = Some((stored, len));
        } else if !frame.buf.is_empty() || remain == 0 {
            // `:698-708`.
            *self.meta = WsFrameMeta {
                age: frame.age,
                flags: frame.flags,
                offset: frame.payload_offset,
                bytesleft: frame
                    .payload_len
                    .saturating_sub(frame.payload_offset)
                    .saturating_sub(
                        i64::try_from(frame.buf.len()).unwrap_or(i64::MAX),
                    ),
                len: frame.buf.len(),
            };
            self.next.write_decoded(frame.buf, self.meta)?;
        }
        // `:709` -- the whole chunk counts as consumed either way.
        Ok(frame.buf.len())
    }
}

/// The `ws-decode` client writer (`lib/ws.c:589-592` and `:770-777`).
///
/// ```c
/// static const struct Curl_cwtype ws_cw_decode = {
///   "ws-decode", NULL, ws_cw_init, ws_cw_write, ws_cw_close,
///   sizeof(struct ws_cw_ctx)
/// };
/// ```
///
/// It owns its own queue, exactly as `struct ws_cw_ctx` does, and that queue is
/// NOT [`WebSocket::recvbuf`]: the writer buffers what the transfer hands it
/// while `recvbuf` serves [`ws_recv`] on a `CURLOPT_CONNECT_ONLY` handle. Two
/// queues because the two paths deliver bytes from different directions.
///
/// `ws_cw_init` sizes it `Curl_bufq_init2(&ctx->buf, WS_CHUNK_SIZE, 1,
/// BUFQ_OPT_SOFT_LIMIT)` -- note the chunk COUNT of one, where the connection's
/// two queues get [`WS_CHUNK_COUNT`].
#[derive(Debug)]
#[allow(dead_code)] // consumer: the transfer core's client-writer chain
pub(crate) struct WsDecodeWriter {
    /// `struct ws_cw_ctx`'s `buf`.
    buf: BufQ,
}

#[allow(dead_code)] // consumer: the transfer core's client-writer chain
impl WsDecodeWriter {
    /// The writer's name in the chain, as `lib/ws.c:771` spells it.
    ///
    /// Reaches `--trace` output through `lib/cw-out.c`'s chain dump, so it is
    /// frozen text.
    #[rustfmt::skip]
    pub(crate) const NAME: &'static str = "ws-decode";

    /// `ws_cw_init(data, writer)` (`lib/ws.c:594-601`).
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            buf: BufQ::with_opts(WS_CHUNK_SIZE, 1, BufqOpts::SOFT_LIMIT),
        }
    }

    /// `ws_cw_close(data, writer)` (`lib/ws.c:603-608`): release the queue.
    ///
    /// Dropping the writer runs the same release, so this exists for the caller
    /// that closes a chain without dropping it -- which is what
    /// `Curl_cwriter_free` does.
    #[allow(dead_code)] // consumer: the transfer core's writer chain
    pub(crate) fn close(&mut self) {
        self.buf.free();
    }

    /// Bytes still buffered and undecoded.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// `ws_cw_write(data, writer, type, buf, nbytes)` (`lib/ws.c:713-767`).
    ///
    /// The C's shape, in its order:
    ///
    /// 1. a non-BODY write, or ANY write under [`CURLWS_RAW_MODE`], goes
    ///    straight down the chain untouched;
    /// 2. the bytes join this writer's queue;
    /// 3. the decoder is driven until the queue is empty or it asks for more --
    ///    and `CURLE_AGAIN` is reported to the caller as SUCCESS, because *"we
    ///    pretend to have written all since we have a copy"*;
    /// 4. at end of stream a non-empty queue is [`CURLcode::RecvError`], with
    ///    the C's message *"[WS] decode ending with N frame bytes remaining"*.
    ///
    /// Step 4 is unreachable in the C as written -- it tests
    /// `!Curl_bufq_is_empty` after a loop that only exits when the queue IS
    /// empty or when it has already returned -- and it is transcribed anyway,
    /// because the check is the documented contract and a future decoder that
    /// leaves bytes behind should meet it rather than pass silently.
    ///
    /// # Errors
    ///
    /// Whatever the decoder, the queue or the next writer reports, except
    /// [`CURLcode::Again`], which is absorbed.
    pub(crate) fn write(
        &mut self,
        ws: &mut WebSocket,
        bytes: &[u8],
        is_body: bool,
        is_eos: bool,
        next: &mut dyn BodyWriter,
        cx: &mut WsCtx<'_, '_>,
    ) -> CodeResult<()> {
        // `:722-723`.
        if !is_body || cx.settings.raw_mode {
            return next.write_passthrough(bytes, is_eos);
        }

        // `:731-739`. The C tests only for a negative return, which would let a
        // SHORT write drop the tail of `bytes` silently; a short write is
        // impossible here because the queue carries `BUFQ_OPT_SOFT_LIMIT` and so
        // grows past its chunk ceiling rather than refusing, but relying on that
        // without saying so would make a later change to the options a silent
        // corruption of the byte stream. The count is therefore checked, and a
        // shortfall is reported as the allocation failure it would have to be.
        if !bytes.is_empty() {
            let written = match self.buf.write(bytes) {
                Ok(written) => written,
                Err(code) => {
                    if let Some(tracer) = cx.tracer() {
                        infof!(
                            tracer,
                            "[WS] error adding data to buffer {}",
                            code as i32
                        );
                    }
                    return Err(code);
                }
            };
            if written != bytes.len() {
                if let Some(tracer) = cx.tracer() {
                    failf!(
                        tracer,
                        "[WS] buffer took only {} of {} bytes",
                        written,
                        bytes.len()
                    );
                }
                return Err(CURLcode::OutOfMemory);
            }
        }

        // `:741-758`.
        while !self.buf.is_empty() {
            let auto_pong = cx.settings.auto_pong();
            let outcome = {
                let mut sink = ForwardSink {
                    // Reborrowed rather than moved: this loop can run more than
                    // once, and a moved `&mut dyn` would be unavailable on the
                    // second turn.
                    next: &mut *next,
                    meta: &mut ws.recvframe,
                    auto_pong,
                    pong: None,
                };
                let result = ws.dec.pass(&mut self.buf, &mut sink, cx.tracer());
                (result, sink.pong)
            };
            // The PONG the sink recorded, applied at the same point in the byte
            // stream the C applies it -- see [`ForwardSink`]. Whether the flush
            // it triggers blocks is [`WsCtx::in_callback`]'s answer, exactly as
            // `ws_enc_add_cntrl` asks `Curl_is_in_callback(data)`.
            if let Some((payload, len)) = outcome.1 {
                if let Some(tracer) = cx.tracer() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Ws,
                        "auto PONG to [PING payload={}]",
                        len
                    );
                }
                ws.add_control(
                    payload.get(..len).unwrap_or(&[]),
                    CURLWS_PONG,
                    cx,
                )?;
            }
            match outcome.0 {
                Ok(()) => {}
                Err(CURLcode::Again) => return Ok(()),
                Err(code) => {
                    if let Some(tracer) = cx.tracer() {
                        failf!(
                            tracer,
                            "[WS] decode payload error {}",
                            code as i32
                        );
                    }
                    return Err(code);
                }
            }
        }

        // `:760-764`.
        if is_eos && !self.buf.is_empty() {
            if let Some(tracer) = cx.tracer() {
                failf!(
                    tracer,
                    "[WS] decode ending with {} frame bytes remaining",
                    self.buf.len()
                );
            }
            return Err(CURLcode::RecvError);
        }
        Ok(())
    }
}

impl Default for WsDecodeWriter {
    fn default() -> Self {
        Self::new()
    }
}

// -- 10. The client reader: `lib/ws.c:1122-1238` ---------------------------

/// Where the `ws-encode` reader gets the application's bytes.
///
/// `Curl_creader_read(data, reader->next, buf, blen, &nread, &eos)`
/// (`lib/ws.c:1177`). The reader chain belongs to [`crate::transfer`]; this is
/// the seam.
#[allow(dead_code)] // consumer: the transfer core's client-reader chain
pub(crate) trait UploadReader {
    /// Fill `buf`, reporting how many bytes and whether the stream ended.
    ///
    /// # Errors
    ///
    /// Whatever the reader chain reports.
    fn read(&mut self, buf: &mut [u8]) -> CodeResult<(usize, bool)>;

    /// `Curl_creader_clear_eos(data, reader->next)` (`lib/ws.c:1185`).
    ///
    /// Called when the application's read callback started a frame of its own
    /// through [`ws_send`], in which case *"we disregard any eos reported"* --
    /// there is now framing to drain that the next reader knows nothing about.
    fn clear_eos(&mut self);
}

/// The `ws-encode` client reader (`lib/ws.c:1122-1126` and `:1226-1238`).
///
/// Installed for a `PUT` transfer that is not in raw mode
/// (`lib/ws.c:1405-1421`), it wraps whatever the application uploads in BINARY
/// frames. Its whole state is the two end-of-stream flags `struct cr_ws_ctx`
/// carries, and the distinction between them is the point: `read_eos` is what
/// the NEXT reader reported, `eos` is what this reader has reported onward, and
/// they differ for exactly as long as it takes to drain the encoded remainder.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumer: the transfer core's client-reader chain
pub(crate) struct WsEncodeReader {
    /// `BIT(read_eos)`: *"we read an EOS from the next reader"*.
    read_eos: bool,
    /// `BIT(eos)`: *"we have returned an EOS"*.
    eos: bool,
}

#[allow(dead_code)] // consumer: the transfer core's client-reader chain
impl WsEncodeReader {
    /// The reader's name in the chain, as `lib/ws.c:1227` spells it.
    #[rustfmt::skip]
    pub(crate) const NAME: &'static str = "ws-encode";

    /// `cr_ws_init(data, reader)` (`lib/ws.c:1128-1133`): nothing to do.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            read_eos: false,
            eos: false,
        }
    }

    /// Whether this reader has already reported end of stream.
    #[must_use]
    #[allow(dead_code)] // consumers: the transfer core, and mod tests
    pub(crate) const fn is_eos(&self) -> bool {
        self.eos
    }

    /// `cr_ws_read(data, reader, buf, blen, pnread, peos)`
    /// (`lib/ws.c:1141-1224`).
    ///
    /// Answers `(nread, eos)`. The sequence is the C's:
    ///
    /// 1. once `eos` is set, every later call is `(0, true)`;
    /// 2. with the queue empty, read from the next reader -- but clamp the
    ///    request to `payload_remain` first, so a frame already declared cannot
    ///    be overfilled;
    /// 3. if that read started a frame (the callback called [`ws_send`]),
    ///    forget the end of stream it reported and clear it on the next reader
    ///    too;
    /// 4. otherwise a zero-byte read returns immediately, propagating the end
    ///    of stream;
    /// 5. with no frame in progress, write a BINARY head for what was read,
    ///    then encode the payload;
    /// 6. hand the caller bytes from the queue, and report end of stream only
    ///    once the queue is empty AND the next reader is done.
    ///
    /// # Errors
    ///
    /// Whatever the next reader, the head write or the payload encode reports.
    pub(crate) fn read(
        &mut self,
        ws: &mut WebSocket,
        buf: &mut [u8],
        next: &mut dyn UploadReader,
        cx: &mut WsCtx<'_, '_>,
    ) -> CodeResult<(usize, bool)> {
        // `:1152-1156`.
        if self.eos {
            return Ok((0, true));
        }

        if ws.sendbuf.is_empty() {
            // `:1165-1169`.
            if self.read_eos {
                self.eos = true;
                return Ok((0, true));
            }

            // `:1171-1175`.
            let mut limit = buf.len();
            if ws.enc.payload_remain != 0 {
                if let Some(tracer) = cx.tracer() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Ws,
                        "current frame, {} remaining",
                        ws.enc.payload_remain
                    );
                }
                limit = limit.min(remain_as_usize(ws.enc.payload_remain));
            }

            // `:1177-1180`.
            let (nread, eos) =
                next.read(buf.get_mut(..limit).unwrap_or(&mut []))?;
            self.read_eos = eos;

            if !ws.sendbuf.is_empty() {
                // `:1182-1186`.
                self.read_eos = false;
                next.clear_eos();
            } else if nread == 0 {
                // `:1187-1194`.
                if self.read_eos {
                    self.eos = true;
                }
                return Ok((nread, self.eos));
            }

            // `:1196-1202`.
            if ws.enc.payload_remain == 0 && ws.sendbuf.is_empty() {
                let head_len = i64::try_from(nread).unwrap_or(i64::MAX);
                ws.write_head(CURLWS_BINARY, head_len, cx)?;
            }

            // `:1204-1208`. The bytes just read are encoded OUT of the same
            // buffer they were read into, which is why the copy is taken first:
            // masking reads them while the queue write borrows the queue.
            let payload: Vec<u8> = buf.get(..nread).unwrap_or(&[]).to_vec();
            let n =
                ws.enc
                    .write_payload(&payload, &mut ws.sendbuf, cx.tracer())?;
            if let Some(tracer) = cx.tracer() {
                trc_feat!(
                    tracer,
                    TraceFeature::Ws,
                    "cr_ws_read, added {} payload, len={}",
                    nread,
                    n
                );
            }
        }

        // `:1211-1218`.
        let nread = ws.sendbuf.read(buf)?;
        let mut eos = false;
        if self.read_eos && ws.sendbuf.is_empty() {
            self.eos = true;
            eos = true;
        }
        Ok((nread, eos))
    }
}

/// `ws_client_collect`'s work, as a [`PayloadSink`] (`lib/ws.c:1466-1520`).
///
/// The sink [`ws_recv`] drives: it copies decoded payload into the
/// application's buffer and remembers the frame the first chunk belonged to.
///
/// Like [`ForwardSink`], a PING is recorded rather than answered from inside
/// the pass, and for the same borrow reason; [`ws_recv`] applies it.
#[allow(dead_code)] // consumers: the codec below, and mod tests
struct Collector<'a> {
    /// The application's buffer.
    buffer: &'a mut [u8],
    /// How much of it has been filled -- the C's `bufidx`.
    bufidx: usize,
    /// The frame the FIRST chunk belonged to, recorded at `!ctx->bufidx`.
    frame_age: i32,
    /// The frame's flags.
    frame_flags: i32,
    /// The frame's payload offset at the first chunk.
    payload_offset: i64,
    /// The frame's total payload length.
    payload_len: i64,
    /// `bool written`: whether anything was destined for the application.
    ///
    /// The flag that distinguishes *"nothing yet, read more"* from *"a frame
    /// was delivered"*, and the reason an auto-answered PING does not end
    /// [`ws_recv`]'s loop (`lib/ws.c:1600-1605`).
    written: bool,
    /// `!data->set.ws_no_auto_pong`.
    auto_pong: bool,
    /// The PONG to queue once the pass returns.
    pong: Option<([u8; WS_MAX_CNTRL_LEN], usize)>,
}

impl PayloadSink for Collector<'_> {
    fn write(&mut self, frame: DecodedFrame<'_>) -> CodeResult<usize> {
        // `:1480-1484`.
        let Some(remain) = payload_remain(
            frame.payload_len,
            frame.payload_offset,
            frame.buf.len(),
        ) else {
            return Err(CURLcode::BadFunctionArgument);
        };

        // `:1486-1492` -- the first chunk fixes the metadata for the whole
        // call, which is what makes a multi-chunk read report ONE frame.
        if self.bufidx == 0 {
            self.frame_age = frame.age;
            self.frame_flags = frame.flags;
            self.payload_offset = frame.payload_offset;
            self.payload_len = frame.payload_len;
        }

        if self.auto_pong && (frame.flags & CURLWS_PING) != 0 && remain == 0 {
            // `:1494-1503`.
            let mut stored = [0_u8; WS_MAX_CNTRL_LEN];
            let len = frame.buf.len().min(WS_MAX_CNTRL_LEN);
            if let Some(slot) = stored.get_mut(..len) {
                slot.copy_from_slice(frame.buf.get(..len).unwrap_or(&[]));
            }
            self.pong = Some((stored, len));
            return Ok(frame.buf.len());
        }

        // `:1504-1518`. `written` is set BEFORE the space check, which is the
        // C's order and is what makes a full buffer end the loop instead of
        // spinning.
        self.written = true;
        let write_len = frame
            .buf
            .len()
            .min(self.buffer.len().saturating_sub(self.bufidx));
        if write_len == 0 {
            if frame.buf.is_empty() {
                // *"0 length write, we accept that"*.
                return Ok(0);
            }
            return Err(CURLcode::Again);
        }
        let Some(slot) =
            self.buffer.get_mut(self.bufidx..self.bufidx + write_len)
        else {
            return Err(CURLcode::Again);
        };
        slot.copy_from_slice(frame.buf.get(..write_len).unwrap_or(&[]));
        self.bufidx += write_len;
        Ok(write_len)
    }
}

// -- 11. The handshake: `lib/ws.c:1240-1300` -------------------------------

/// `"Upgrade"`, the first handshake header's NAME (`lib/ws.c:1258`).
///
/// Every literal in this group reaches the wire and is compared as one string
/// by `compareparts`, so each carries `#[rustfmt::skip]` and none is composed
/// at run time. The C's comment on this one is RFC 6455's own requirement:
/// *"The request MUST contain an |Upgrade| header field whose value MUST
/// include the "websocket" keyword."*
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const HD_UPGRADE: &str = "Upgrade";

/// `"websocket"`, its VALUE -- lower case, and not `"WebSocket"`.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const HD_UPGRADE_VALUE: &str = "websocket";

/// `"Sec-WebSocket-Version"` (`lib/ws.c:1264`).
///
/// The C's comment: *"The request MUST include a header field with the name
/// |Sec-WebSocket-Version|. The value of this header field MUST be 13."*
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const HD_VERSION: &str = "Sec-WebSocket-Version";

/// `"13"`, the only protocol version this implementation speaks.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const HD_VERSION_VALUE: &str = "13";

/// `"Sec-WebSocket-Key"` (`lib/ws.c:1272`).
///
/// The C's comment: *"The value of this header field MUST be a nonce consisting
/// of a randomly selected 16-byte value that has been base64-encoded (see
/// Section 4 of [RFC4648]). The nonce MUST be selected randomly for each
/// connection."*
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const HD_KEY: &str = "Sec-WebSocket-Key";

/// `"Sec-WebSocket-Accept"`, the response header RFC 6455 defines.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const HD_ACCEPT: &str = "Sec-WebSocket-Accept";

/// `"Sec-WebSocket-Extensions"`, whose unsolicited presence in a response is a
/// protocol violation (`lib/ws.c:1366-1370`).
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const HD_EXTENSIONS: &str = "Sec-WebSocket-Extensions";

/// `"Sec-WebSocket-Protocol"`, whose unsolicited presence in a response is a
/// protocol violation (`lib/ws.c:1372-1376`).
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const HD_PROTOCOL: &str = "Sec-WebSocket-Protocol";

/// RFC 6455's handshake GUID, quoted by `lib/ws.c:1363`.
///
/// *"The sent value is the base64 encoded version of a SHA-1 hash done on the
/// |Sec-WebSocket-Key| header field concatenated with the string
/// "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"."*
///
/// A wire-bearing literal, upper case, hyphenated exactly so, and never
/// reformatted.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `uint8_t rand[16]` (`lib/ws.c:1249`): the nonce length RFC 6455 fixes.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const WS_NONCE_LEN: usize = 16;

/// `char keyval[40]` (`lib/ws.c:1252`): the destination the encoded nonce must
/// fit in, terminator included.
///
/// A 16-byte nonce encodes to 24 base64 characters, so the bound is never
/// reached in practice -- which is precisely why the C guards it with
/// `DEBUGASSERT(randlen < sizeof(keyval))` and a release-build
/// `CURLE_FAILED_INIT` (`:1284-1288`) rather than trusting it. Both halves are
/// reproduced here as ONE checked comparison, because a `debug_assert!` would
/// be a panic in this crate's own tests and specification 0.8.2 forbids a
/// panic outside `#[cfg(test)]`.
#[rustfmt::skip]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) const WS_KEYVAL_MAX: usize = 40;

/// The value part of a `Name: value` header line.
///
/// Splits at the first [`crate::transfer::headersep`] byte and trims the ASCII
/// whitespace that HTTP permits after it. Used on RESPONSE lines only -- a
/// request header is spliced verbatim and never parsed, which is what keeps
/// `-H` byte-exact.
#[must_use]
#[allow(dead_code)] // consumers: the codec below, and mod tests
fn header_value(line: &str) -> &str {
    match line.find([':', ';']) {
        Some(at) => line
            .get(at.saturating_add(1)..)
            .unwrap_or("")
            .trim_matches(|c: char| c == ' ' || c == '\t'),
        None => "",
    }
}

/// `base64(SHA-1(key + WS_GUID))`: the `Sec-WebSocket-Accept` value RFC 6455
/// requires a server to return.
///
/// SHA-1 comes from the `sha1` crate, which this crate already depends on
/// unconditionally, and the base64 is the STANDARD padded alphabet through
/// [`crate::util::base64::encode`] -- the same encoder the key itself uses, so
/// the two cannot disagree about padding.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from the encoder, which cannot occur for a 20-byte
/// digest and is propagated rather than swallowed.
///
/// # Examples
///
/// ```text
/// accept_key(b"dGhlIHNhbXBsZSBub25jZQ==")
///     == Ok("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".to_owned())
/// ```
///
/// That pair is RFC 6455 section 1.3's own worked example, and
/// [`mod tests`](self) asserts it.
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) fn accept_key(key: &[u8]) -> CodeResult<String> {
    let mut hasher = Sha1::new();
    hasher.update(key);
    hasher.update(WS_GUID);
    base64::encode(&hasher.finalize())
}

/// What the `Sec-WebSocket-Accept` header of a `101` response turned out to be.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) enum AcceptVerdict {
    /// No `Sec-WebSocket-Accept` header at all. RFC 6455 requires one;
    /// `tests/data/test2306` shows curl completing an upgrade without it.
    #[default]
    Missing,
    /// Present and equal to [`accept_key`]'s answer for the key that was sent.
    Matches,
    /// Present and different.
    Mismatch,
}

/// The three response obligations of `lib/ws.c:1359-1377`, evaluated.
///
/// # Read this before changing what is done with the verdict
///
/// The C carries all three as COMMENTS with no code beneath them, and the
/// corpus proves the omission is real rather than an artefact of reading: every
/// WebSocket fixture answers `Sec-WebSocket-Accept:
/// HkPsVga7+8LuxM4RGQ5p9tZHeYs=` while the correct value for the key those
/// fixtures require curl to send is `Dut04YXKjDKbXFLrc+AVmMeFsWM=`. The two
/// differ; the fixtures pass. Enforcing the check would fail 28 fixtures that a
/// C curl passes.
///
/// So this type separates the ANALYSIS from the POLICY. It reports what an
/// RFC-strict client would find, [`Self::rfc_verdict`] gives the code such a
/// client would answer, and [`Self::curl_verdict`] gives curl 8.19.0-DEV's
/// answer -- which [`accept`] applies, because specification 0.8.1 freezes wire
/// behaviour and makes a failing fixture an implementation defect.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) struct ResponseCheck {
    /// The `Sec-WebSocket-Accept` obligation (`lib/ws.c:1359-1364`).
    pub(crate) accept: AcceptVerdict,
    /// The `Sec-WebSocket-Extensions` obligation (`lib/ws.c:1366-1370`):
    /// *"the server has indicated an extension not requested by the client"*.
    pub(crate) unsolicited_extensions: bool,
    /// The `Sec-WebSocket-Protocol` obligation (`lib/ws.c:1372-1376`):
    /// *"the server has indicated a subprotocol not requested by the client"*.
    pub(crate) unsolicited_protocol: bool,
}

#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
impl ResponseCheck {
    /// The code an RFC-strict client answers for a violated obligation.
    ///
    /// [`CURLcode::WeirdServerReply`], derived rather than chosen: it is the
    /// code the C itself answers for the ONE `101` obligation it does enforce
    /// -- *"server sent 101 response while not talking HTTP/1.1"*
    /// (`lib/http.c:3931-3935`) -- so a client that enforced the other three
    /// would be answering in the same vocabulary for the same class of defect.
    #[rustfmt::skip]
    pub(crate) const VIOLATION: CURLcode = CURLcode::WeirdServerReply;

    /// Evaluate all three obligations.
    ///
    /// * `sent_key` is the `Sec-WebSocket-Key` value that went out --
    ///   [`WsUpgrade::sent_key`] keeps it, including the case where the
    ///   application supplied the header itself and curl's own nonce never
    ///   reached the wire;
    /// * `response` is the `101` response's header lines, as
    ///   `Name: value` strings;
    /// * `requested_extensions` and `requested_protocol` say whether the
    ///   REQUEST asked for either, because the obligation is about an
    ///   *unsolicited* one. curl never asks by itself, so both are false unless
    ///   the application supplied the header with `-H`.
    ///
    /// # Errors
    ///
    /// None: evaluating cannot fail. [`accept_key`]'s failure is reported as
    /// [`AcceptVerdict::Mismatch`], because a key that cannot be hashed cannot
    /// have produced the value the server sent.
    #[must_use]
    pub(crate) fn of(
        sent_key: &[u8],
        response: &[String],
        requested_extensions: bool,
        requested_protocol: bool,
    ) -> Self {
        let accept = match checkheaders(response, HD_ACCEPT) {
            None => AcceptVerdict::Missing,
            Some(line) => {
                let seen = header_value(line);
                match accept_key(sent_key) {
                    Ok(expected) if expected == seen => AcceptVerdict::Matches,
                    _ => AcceptVerdict::Mismatch,
                }
            }
        };
        Self {
            accept,
            unsolicited_extensions: !requested_extensions
                && checkheaders(response, HD_EXTENSIONS).is_some(),
            unsolicited_protocol: !requested_protocol
                && checkheaders(response, HD_PROTOCOL).is_some(),
        }
    }

    /// Whether any of the three obligations was violated.
    #[must_use]
    pub(crate) const fn has_violation(&self) -> bool {
        !matches!(self.accept, AcceptVerdict::Matches)
            || self.unsolicited_extensions
            || self.unsolicited_protocol
    }

    /// What an RFC-strict client answers.
    ///
    /// # Errors
    ///
    /// [`Self::VIOLATION`] when [`Self::has_violation`] holds.
    pub(crate) const fn rfc_verdict(&self) -> CodeResult<()> {
        if self.has_violation() {
            Err(Self::VIOLATION)
        } else {
            Ok(())
        }
    }

    /// What curl 8.19.0-DEV answers, which is always success.
    ///
    /// Not a stub and not an omission: it is the measured behaviour of the
    /// version this work is bound to, and the 28 WebSocket fixtures depend on
    /// it. The function exists so that the policy has a NAME and one call site,
    /// which is what makes it reviewable -- and so that adopting
    /// [`Self::rfc_verdict`] later is a one-line change with a test already
    /// covering it.
    ///
    /// # Errors
    ///
    /// Never.
    pub(crate) const fn curl_verdict(&self) -> CodeResult<()> {
        Ok(())
    }
}

/// `Curl_ws_request(data, req)` (`lib/ws.c:1245-1299`): write the three
/// handshake headers.
///
/// Returns the `Sec-WebSocket-Key` value that went out, so a caller can check
/// the response against it. The C returns nothing and keeps nothing, because it
/// performs no check; keeping it here costs one `String` per handshake and is
/// what makes [`ResponseCheck`] possible at all.
///
/// # The order is the specification
///
/// ```text
/// Upgrade: websocket\r\n
/// Sec-WebSocket-Version: 13\r\n
/// Sec-WebSocket-Key: <base64 of 16 random bytes>\r\n
/// ```
///
/// `tests/data/test2300` compares those three lines, in that order, as part of
/// one string. `Connection: Upgrade` follows them on the wire and is emitted by
/// [`super::http1`]'s `Connection:` slot, which reads the
/// [`RequestState::http_hd_upgrade`] flag this function sets -- writing it here
/// as well would put the header out twice.
///
/// # Each header is suppressed INDIVIDUALLY
///
/// `if(!Curl_checkheaders(data, heads[i].name, strlen(heads[i].name)))`
/// (`:1292`) is inside the loop, so `-H "Sec-WebSocket-Key: mine"` replaces
/// exactly that line and leaves the other two in place. An all-or-nothing test
/// would be a wire difference in both directions.
///
/// # The three state flags are set even on failure
///
/// `:1296-1298` runs after the loop unconditionally, and the loop's
/// `!result &&` guard means an early failure skips the REMAINING headers but not
/// the flags. Transcribed as found: the flags describe an upgrade that was
/// ATTEMPTED, and `lib/http.c:4040-4044` uses `upgr101` to turn a non-`101`
/// answer into [`CURLcode::HttpReturnedError`], which must still happen for a
/// half-written request.
///
/// # Errors
///
/// [`CURLcode::FailedInit`] when the encoded nonce would not fit
/// [`WS_KEYVAL_MAX`], whatever [`crate::util::base64::encode`] reports, and
/// whatever [`DynBuf::addn`] reports once its one-mebibyte ceiling is reached.
#[allow(dead_code)] // consumer: WsUpgrade's UpgradeWriter impl below, driven by protocols/http1.rs
pub(crate) fn write_handshake(
    req: &mut DynBuf,
    state: &mut RequestState,
    headers: &[String],
    rng: &mut dyn Rng,
    tracer: Option<&mut Tracer<'_>>,
) -> CodeResult<String> {
    // `:1277-1283` -- sixteen bytes from the INJECTED generator, then padded
    // standard base64.
    let mut nonce = [0_u8; WS_NONCE_LEN];
    rand_bytes(rng, &mut nonce);
    let encoded = base64::encode(&nonce)?;

    // `:1284-1288`. The C's `DEBUGASSERT` plus its release-build return, as one
    // checked comparison -- `randlen >= sizeof(keyval)` including the
    // terminator, which is why the test is `>=` and not `>`.
    if encoded.len() >= WS_KEYVAL_MAX {
        return Err(CURLcode::FailedInit);
    }

    // `:1254-1275` -- the table, in the C's order. `#[rustfmt::skip]` keeps the
    // three rows readable against the C side by side.
    #[rustfmt::skip]
    let heads: [(&str, &str); 3] = [
        (HD_UPGRADE, HD_UPGRADE_VALUE),
        (HD_VERSION, HD_VERSION_VALUE),
        (HD_KEY,     encoded.as_str()),
    ];

    // `:1291-1295` -- `for(i = 0; !result && (i < CURL_ARRAYSIZE(heads)); i++)`,
    // so a failure stops the loop but does not skip the flags below.
    let mut result = Ok(());
    let mut sent_key = encoded.clone();
    for (name, value) in heads {
        if result.is_err() {
            break;
        }
        match checkheaders(headers, name) {
            Some(supplied) => {
                // The application owns this line. For the key that also means
                // the value on the wire is theirs, so it -- not curl's nonce --
                // is what a response check must hash.
                if name == HD_KEY {
                    sent_key = header_value(supplied).to_owned();
                }
            }
            None => {
                // `curlx_dyn_addf(req, "%s: %s\r\n", name, val)`, written as
                // four appends so no format string stands between the literals
                // and the wire.
                result = req
                    .addn(name.as_bytes())
                    .and_then(|()| req.addn(b": "))
                    .and_then(|()| req.addn(value.as_bytes()))
                    .and_then(|()| req.addn(b"\r\n"));
            }
        }
    }

    // `:1296-1298`.
    state.http_hd_upgrade = true;
    state.upgr101 = Upgrade101::WebSocket;
    state.upgrade_in_progress = true;

    result?;
    if let Some(tracer) = tracer {
        trc_feat!(
            tracer,
            TraceFeature::Ws,
            "handshake requested, key={}",
            sent_key
        );
    }
    Ok(sent_key)
}

/// The [`UpgradeWriter`] that installs the WebSocket handshake into
/// [`super::http1`]'s request writer.
///
/// `H1_HD_UPGRADE` (`lib/http.c:2964-2976`) calls
/// `Curl_http2_request_upgrade(req, data)` and then, for a `ws` or `wss`
/// scheme, `Curl_ws_request(data, req)`. This implements the second half and
/// leaves the first to whoever wires HTTP/2 -- `protocols/http2.rs`, which
/// specification 0.4.1 assigns and which is not on disk. So [`Self::h2c`]
/// answers `Ok(())`, which is exactly what the C's slot contributes with
/// `USE_HTTP2` undefined: nothing.
///
/// The randomness is borrowed rather than owned, so the caller keeps control of
/// the stream -- a test drives a [`crate::crypto::rand::TestRng`] through the
/// handshake and then through the first frame's mask and sees the same sequence
/// `CURL_ENTROPY` produces in the C.
#[allow(dead_code)] // consumer: protocols/http1.rs's H1_HD_UPGRADE slot
pub(crate) struct WsUpgrade<'a, 'trc> {
    /// The generator the nonce is drawn from.
    rng: &'a mut dyn Rng,
    /// The trace destination, if the handle is verbose.
    tracer: Option<&'a mut Tracer<'trc>>,
    /// The key that went out, kept for [`ResponseCheck::of`].
    sent_key: Option<String>,
}

impl fmt::Debug for WsUpgrade<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsUpgrade")
            .field("sent_key", &self.sent_key)
            .field("traced", &self.tracer.is_some())
            .finish()
    }
}

#[allow(dead_code)] // consumer: protocols/http1.rs's H1_HD_UPGRADE slot
impl<'a, 'trc> WsUpgrade<'a, 'trc> {
    /// An upgrade writer over the caller's generator.
    #[must_use]
    pub(crate) fn new(rng: &'a mut dyn Rng) -> Self {
        Self {
            rng,
            tracer: None,
            sent_key: None,
        }
    }

    /// Attaches the handle's trace destination.
    #[must_use]
    pub(crate) fn with_tracer(mut self, tracer: &'a mut Tracer<'trc>) -> Self {
        self.tracer = Some(tracer);
        self
    }

    /// The `Sec-WebSocket-Key` value that reached the wire, once the handshake
    /// has been written.
    ///
    /// [`None`] before [`UpgradeWriter::websocket`] has run, which is the
    /// honest answer rather than an empty string: there is no key yet, and
    /// hashing one that was never sent would produce a verdict about nothing.
    #[must_use]
    pub(crate) fn sent_key(&self) -> Option<&str> {
        self.sent_key.as_deref()
    }
}

impl UpgradeWriter for WsUpgrade<'_, '_> {
    /// `Curl_http2_request_upgrade(req, data)`: not this module's bytes.
    ///
    /// Answers `Ok(())` without touching the buffer, which is what the C's
    /// `H1_HD_UPGRADE` slot contributes when HTTP/2 is not compiled in. A
    /// caller wanting both upgrades composes this with the HTTP/2 module's own
    /// writer once that module exists; the seam is
    /// [`super::http1::UpgradeWriter`] and takes either.
    fn h2c(
        &mut self,
        req: &mut DynBuf,
        state: &mut RequestState,
    ) -> CodeResult<()> {
        let _ = req;
        let _ = state;
        Ok(())
    }

    /// `Curl_ws_request(data, req)`, through [`write_handshake`].
    fn websocket(
        &mut self,
        req: &mut DynBuf,
        state: &mut RequestState,
        headers: &[String],
    ) -> CodeResult<()> {
        let key = write_handshake(
            req,
            state,
            headers,
            self.rng,
            self.tracer.as_deref_mut(),
        )?;
        self.sent_key = Some(key);
        Ok(())
    }
}

/// What `Curl_ws_accept` decided, beyond the state it built.
///
/// The C writes its decisions into `data->req` and `data->conn` directly --
/// `k->header = FALSE`, `k->keepon &= ~KEEP_RECV`, `k->upgr101 =
/// UPGR101_RECEIVED`, `data->req.eos_read = FALSE`, `k->keepon |= KEEP_SEND`
/// (`lib/ws.c:1390-1438`). None of that state belongs to this module, so the
/// decisions are RETURNED and the transfer core applies them. Every field here
/// is one line of the C.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) struct AcceptOutcome {
    /// `k->upgr101 = UPGR101_RECEIVED` (`:1437`).
    pub(crate) upgr101: Upgrade101,
    /// `k->header = FALSE` (`:1390` and again at `:1438`): *"we will not get
    /// more response headers"*.
    pub(crate) header_done: bool,
    /// Install the `ws-decode` client writer (`:1381-1388`). Always true; the
    /// field exists so the caller's checklist is the C's list and not a
    /// memorised one.
    pub(crate) install_decoder: bool,
    /// `k->keepon &= ~KEEP_RECV` (`:1402`), for a `CURLOPT_CONNECT_ONLY`
    /// handle: *"read no more content"*, because the application will drive
    /// [`ws_recv`] itself.
    pub(crate) stop_receiving: bool,
    /// Install the `ws-encode` client reader (`:1411-1421`): a `PUT` that is
    /// not in raw mode.
    pub(crate) install_encoder: bool,
    /// `data->req.eos_read = FALSE; data->req.upload_done = FALSE; k->keepon |=
    /// KEEP_SEND` (`:1423-1426`) -- *"start over with sending"*.
    pub(crate) restart_upload: bool,
    /// `Curl_client_write(data, CLIENTWRITE_BODY, mem, nread)`
    /// (`:1429-1434`): the frame bytes that arrived with the `101` must be
    /// pushed through the client writer, because the decoder was installed only
    /// a few lines earlier and nothing else will offer them.
    ///
    /// True for a callback-driven transfer with a non-empty tail, and false
    /// under `CURLOPT_CONNECT_ONLY`, where [`WebSocket::queue_received`] has
    /// taken them instead. The caller owns the writer chain, so it performs the
    /// write; this field is how it learns that it must.
    pub(crate) forward_received: bool,
    /// What the three RFC obligations of `:1359-1377` found.
    pub(crate) check: ResponseCheck,
}

/// `Curl_ws_accept(data, mem, nread)` (`lib/ws.c:1316-1451`): the `101` has
/// arrived.
///
/// `ws` is the connection's state, created by [`WebSocket::new`] on a fresh
/// connection or reset by [`WebSocket::reset_for_reuse`] on one being upgraded
/// a second time -- the C's `if(!ws) { ... } else { ... }` at `:1326-1358`,
/// which the caller decides because it owns the connection.
///
/// `mem` is *"number of bytes of websocket data already in the buffer"*: the
/// tail of the read that carried the `101` response, which is already frame
/// bytes. Where it goes depends on the mode, and the difference is the whole
/// reason this function takes it:
///
/// * `CURLOPT_CONNECT_ONLY` queues it for [`ws_recv`] (`:1392-1402`), because
///   the transfer is about to be marked done and nothing else will read it;
/// * otherwise it goes to the client writer (`:1429-1434`), which is installed
///   by then.
///
/// The `PUT` branch is reported through [`AcceptOutcome::install_encoder`]
/// rather than acted on: `Curl_creader_set_fread`, `Curl_creader_add` and the
/// three `data->req` flags all belong to the transfer core.
///
/// # Errors
///
/// Whatever [`WebSocket::queue_received`] reports for the CONNECT_ONLY path.
/// The response obligations do NOT produce an error -- see [`ResponseCheck`].
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) fn accept(
    ws: &mut WebSocket,
    mem: &[u8],
    sent_key: &str,
    response: &[String],
    is_put: bool,
    cx: &mut WsCtx<'_, '_>,
) -> CodeResult<AcceptOutcome> {
    // `:1359-1377` -- evaluated in full, then answered curl's way.
    let check = ResponseCheck::of(sent_key.as_bytes(), response, false, false);
    if check.has_violation() {
        if let Some(tracer) = cx.tracer() {
            trc_feat!(
                tracer,
                TraceFeature::Ws,
                "response check: accept={:?}, unsolicited extensions={}, \
                 unsolicited protocol={} -- tolerated, as curl 8.19.0-DEV does",
                check.accept,
                check.unsolicited_extensions,
                check.unsolicited_protocol
            );
        }
    }
    check.curl_verdict()?;

    // `:1378` -- an `infof`, not a trace-feature line, so it appears under
    // plain `-v` exactly as the C's does.
    if let Some(tracer) = cx.tracer() {
        infof!(tracer, "[WS] Received 101, switch to WebSocket");
    }

    let connect_only = cx.settings.connect_only;
    let raw_mode = cx.settings.raw_mode;

    let mut outcome = AcceptOutcome {
        upgr101: Upgrade101::Received,
        header_done: true,
        install_decoder: true,
        stop_receiving: false,
        install_encoder: false,
        restart_upload: false,
        forward_received: false,
        check,
    };

    if connect_only {
        // `:1392-1403`.
        ws.queue_received(mem)?;
        outcome.stop_receiving = true;
    } else {
        if is_put {
            // `:1405-1427`.
            outcome.install_encoder = !raw_mode;
            outcome.restart_upload = true;
        }
        // `:1429-1434` -- and note it is NOT inside the `PUT` branch.
        outcome.forward_received = !mem.is_empty();
    }

    if let Some(tracer) = cx.tracer() {
        trc_feat!(
            tracer,
            TraceFeature::Ws,
            "websocket established, {} mode",
            if connect_only {
                "connect-only"
            } else {
                "callback"
            }
        );
    }
    Ok(outcome)
}

// -- 12. The four exported symbols: `lib/libcurl.def:98-101` ---------------

/// The `CURLOPT_CONNECT_ONLY` precondition of `curl_ws_recv` and
/// `curl_ws_send` (`lib/ws.c:1544-1557`, `:1789-1798`).
///
/// The public header states it twice -- *"Use after successful
/// curl_easy_perform() with CURLOPT_CONNECT_ONLY option"*
/// (`include/curl/websockets.h:52-53` and `:67-68`) -- and the C enforces it
/// exactly where it bites:
///
/// ```c
/// conn = data->conn;
/// if(!conn) {
///   /* Unhappy hack with lifetimes of transfers and connection */
///   if(!data->set.connect_only) {
///     failf(data, "[WS] CONNECT_ONLY is required");
///     return CURLE_UNSUPPORTED_PROTOCOL;
///   }
///   Curl_getconnectinfo(data, &conn);
///   if(!conn) { failf(data, "[WS] connection not found"); ... }
/// }
/// ```
///
/// So the option is required only when the transfer has already released its
/// connection, which is the case an application hits after
/// `curl_easy_perform` returns. Inside a callback the connection is still
/// attached and the C proceeds without the option. Reproduced with that
/// asymmetry intact rather than tightened, because tightening it would break
/// `curl_ws_send` from inside a write callback -- which
/// `tests/data/test2301` and `tests/data/test2302` both do.
///
/// `has_connection` is `data->conn != NULL`; the caller knows, because it is
/// what holds the connection.
///
/// # Errors
///
/// [`CURLcode::UnsupportedProtocol`] with the C's message when neither a
/// connection nor the option is present.
#[allow(dead_code)] // consumers: the transfer core and curl-rs-ffi/src/ffi/ws.rs
pub(crate) fn require_connection(
    has_connection: bool,
    cx: &mut WsCtx<'_, '_>,
) -> CodeResult<()> {
    if has_connection {
        return Ok(());
    }
    if !cx.settings.connect_only {
        if let Some(tracer) = cx.tracer() {
            failf!(tracer, "[WS] CONNECT_ONLY is required");
        }
        return Err(CURLcode::UnsupportedProtocol);
    }
    Ok(())
}

/// `curl_ws_meta(CURL *curl)` (`lib/ws.c:1851-1864`) -- `lib/libcurl.def:98`.
///
/// ```c
/// const struct curl_ws_frame *curl_ws_meta(CURL *d)
/// ```
///
/// The C's four-part conjunction is the whole function, and the comment above
/// it says why: *"we only return something for websocket, called from within
/// the callback when not using raw mode"*.
///
/// ```c
/// if(GOOD_EASY_HANDLE(data) && Curl_is_in_callback(data) &&
///    data->conn && !data->set.ws_raw_mode) { ... return &ws->recvframe; }
/// return NULL;
/// ```
///
/// Three of the four conjuncts are reproduced here -- [`WsCtx::in_callback`],
/// `has_connection`, and `!raw_mode`. The fourth, `GOOD_EASY_HANDLE`, is a null
/// and magic-number check on the `CURL *` and belongs to
/// `curl-rs-ffi/src/ffi/ws.rs`, which is where a raw pointer exists to check.
///
/// [`None`] is the `NULL` the C returns, and the FFI shim converts it to a null
/// pointer. Nothing else about the state is consulted: a handle that has
/// received no frame yet answers a zeroed [`WsFrameMeta`], which is what
/// `calloc` leaves behind in the C.
#[must_use]
#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
pub(crate) fn ws_meta<'ws>(
    ws: &'ws WebSocket,
    has_connection: bool,
    cx: &WsCtx<'_, '_>,
) -> Option<&'ws WsFrameMeta> {
    if cx.in_callback && has_connection && !cx.settings.raw_mode {
        Some(ws.recv_frame())
    } else {
        None
    }
}

/// `curl_ws_recv(CURL *curl, void *buffer, size_t buflen, size_t *recv,
/// const struct curl_ws_frame **metap)` (`lib/ws.c:1530-1625`) --
/// `lib/libcurl.def:99`.
///
/// Answers how many payload bytes reached `buffer`; the frame metadata is
/// [`WebSocket::recv_frame`], which is exactly what the C points `*metap` at
/// (`:1611`) -- a borrow of the connection's own storage, not a copy, so the
/// FFI shim hands out a pointer with the lifetime the C promises.
///
/// # The loop, and the flag that ends it
///
/// ```text
/// loop {
///   if recvbuf is empty -> slurp from the network; 0 bytes means closed
///   decode one frame into the caller's buffer
///   AGAIN and nothing collected -> read more
///   AGAIN and something collected -> done
///   OK and something collected   -> done
///   OK and nothing collected     -> keep going
/// }
/// ```
///
/// The last line is the interesting one: an auto-answered PING collects
/// nothing, so the loop keeps reading rather than returning an empty frame to
/// the application. The C's comment is *"There are frames like PING were we
/// auto-respond to and that we do not return"* (`:1600-1605`), and
/// [`Collector::written`] is the flag that expresses it.
///
/// # The tail step is not optional
///
/// `:1617-1623` flushes any control frame that the decode queued, *"we do not
/// know when the application will call `curl_ws_send()` again"*. Skipping it
/// would leave a PONG sitting in the queue until the next send, which a server
/// enforcing a ping timeout would treat as a dead peer. The flush's outcome is
/// discarded, as in the C.
///
/// # Errors
///
/// [`CURLcode::UnsupportedProtocol`] from [`require_connection`],
/// [`CURLcode::GotNothing`] when the peer closed the connection, and whatever
/// the decoder or the transport reports.
#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
pub(crate) fn ws_recv(
    ws: &mut WebSocket,
    buffer: &mut [u8],
    has_connection: bool,
    cx: &mut WsCtx<'_, '_>,
) -> CodeResult<usize> {
    require_connection(has_connection, cx)?;

    let auto_pong = cx.settings.auto_pong();
    let mut collector = Collector {
        buffer,
        bufidx: 0,
        frame_age: 0,
        frame_flags: 0,
        payload_offset: 0,
        payload_len: 0,
        written: false,
        auto_pong,
        pong: None,
    };

    loop {
        // `:1573-1586`.
        if ws.recvbuf.is_empty() {
            let n = ws.recvbuf.slurp(|buf| cx.transport.recv(buf))?;
            if n == 0 {
                if let Some(tracer) = cx.tracer() {
                    infof!(tracer, "[WS] connection expectedly closed?");
                }
                return Err(CURLcode::GotNothing);
            }
            if let Some(tracer) = cx.tracer() {
                trc_feat!(
                    tracer,
                    TraceFeature::Ws,
                    "curl_ws_recv, added {} bytes from network",
                    ws.recvbuf.len()
                );
            }
        }

        // `:1588-1589`.
        let result = ws.dec.pass(&mut ws.recvbuf, &mut collector, cx.tracer());

        // The PONG the collector recorded, queued at the same point in the byte
        // stream the C queues it.
        if let Some((payload, len)) = collector.pong.take() {
            if let Some(tracer) = cx.tracer() {
                trc_feat!(
                    tracer,
                    TraceFeature::Ws,
                    "auto PONG to [PING payload={}]",
                    len
                );
            }
            ws.add_control(payload.get(..len).unwrap_or(&[]), CURLWS_PONG, cx)?;
        }

        match result {
            // `:1590-1596`.
            Err(CURLcode::Again) => {
                if !collector.written {
                    continue;
                }
                break;
            }
            // `:1597-1599`.
            Err(code) => return Err(code),
            // `:1600-1605`.
            Ok(()) => {
                if collector.written {
                    break;
                }
            }
        }
    }

    // `:1608-1616`.
    let (age, flags, offset, total, collected) = (
        collector.frame_age,
        collector.frame_flags,
        collector.payload_offset,
        collector.payload_len,
        collector.bufidx,
    );
    let buflen = collector.buffer.len();
    ws.update_meta(age, flags, offset, total, collected);
    let nread = ws.recvframe.len;
    if let Some(tracer) = cx.tracer() {
        trc_feat!(
            tracer,
            TraceFeature::Ws,
            "curl_ws_recv(len={}) -> {} bytes (frame at {}, {} left)",
            buflen,
            nread,
            ws.recvframe.offset,
            ws.recvframe.bytesleft
        );
    }

    // `:1617-1623` -- *"all's well, try to send any pending control"*. Both
    // steps are best-effort in the C: a control frame that cannot be encoded or
    // cannot be flushed right now does not spoil a receive that succeeded, so
    // the caller still gets its bytes and the frame stays queued for the next
    // flush.
    if !cx.settings.raw_mode
        && ws.pending.is_pending()
        && ws.add_pending(cx).is_ok()
    {
        let _ = ws.flush(cx);
    }
    Ok(nread)
}

/// `curl_ws_send(CURL *curl, const void *buffer, size_t buflen, size_t *sent,
/// curl_off_t fragsize, unsigned int flags)` (`lib/ws.c:1763-1838`) --
/// `lib/libcurl.def:100`.
///
/// Answers how many PAYLOAD bytes were accepted, never counting framing --
/// which is what makes an application's `sent` comparable with its `buflen`.
///
/// # Raw mode is a different function, not a flag
///
/// `:1806-1827` refuses three things that are legal in framed mode, each with
/// its own message and all with [`CURLcode::BadFunctionArgument`]: a null
/// buffer, a null `sent` pointer, and a non-zero `fragsize` or `flags` --
/// *"fragsize and flags must be zero in raw mode"*. The first two are pointer
/// checks that belong to `curl-rs-ffi/src/ffi/ws.rs`; the third is a value
/// check and is enforced here.
///
/// # Errors
///
/// [`CURLcode::UnsupportedProtocol`] from [`require_connection`],
/// [`CURLcode::BadFunctionArgument`] for the raw-mode value check and for
/// [`WebSocket::encode_send`]'s two caller invariants, [`CURLcode::Again`] when
/// nothing could be flushed, and whatever the encoder or transport reports.
#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
pub(crate) fn ws_send(
    ws: &mut WebSocket,
    buffer: &[u8],
    fragsize: i64,
    flags: i32,
    has_connection: bool,
    cx: &mut WsCtx<'_, '_>,
) -> CodeResult<usize> {
    if let Some(tracer) = cx.tracer() {
        trc_feat!(
            tracer,
            TraceFeature::Ws,
            "curl_ws_send(len={}, fragsize={}, flags={:x})",
            buffer.len(),
            fragsize,
            flags
        );
    }

    // `:1789-1804`. The C attaches a connection here for a CONNECT_ONLY handle
    // (`Curl_connect_only_attach`); attaching belongs to the caller, which owns
    // the connection, so what is left is the same precondition.
    require_connection(has_connection, cx)?;

    if cx.settings.raw_mode {
        // `:1821-1824`.
        if fragsize != 0 || flags != 0 {
            if let Some(tracer) = cx.tracer() {
                failf!(
                    tracer,
                    "[WS] fragsize and flags must be zero in raw mode"
                );
            }
            return Err(CURLcode::BadFunctionArgument);
        }
        return ws.send_raw(buffer, cx);
    }

    // `:1829-1830`.
    ws.encode_send(buffer, fragsize, flags, cx)
}

/// `curl_ws_start_frame(CURL *curl, unsigned int flags, curl_off_t frame_len)`
/// (`lib/ws.c:1866-1916`) -- `lib/libcurl.def:101`.
///
/// The public header's description is the contract: *"Buffers a websocket frame
/// header with the given flags and length. Errors when a previous frame is not
/// complete, e.g. not all its payload has been added."*
/// (`include/curl/websockets.h:80-82`).
///
/// # Four refusals, and note that two of them are the same test
///
/// ```c
/// if(data->set.ws_raw_mode) { failf(...); return CURLE_FAILED_INIT; }   /* :1876 */
/// ...
/// if(!data->conn)           { ... result = CURLE_SEND_ERROR; }          /* :1884 */
/// if(!ws)                   { ... result = CURLE_SEND_ERROR; }          /* :1890 */
/// if(data->set.ws_raw_mode) { ... result = CURLE_SEND_ERROR; }          /* :1896 */
/// if(ws->enc.payload_remain){ ... result = CURLE_SEND_ERROR; }          /* :1902 */
/// ```
///
/// Raw mode is tested TWICE with two different codes, and the first test wins
/// because it returns immediately: raw mode is [`CURLcode::FailedInit`], never
/// [`CURLcode::SendError`]. The second test is dead code in the C and is
/// transcribed as unreachable rather than deleted -- the comment below marks it
/// -- because deleting it would erase the evidence that the C author expected
/// the other code.
///
/// # Errors
///
/// [`CURLcode::FailedInit`] in raw mode, [`CURLcode::SendError`] when a frame
/// is still owed payload, and whatever [`WebSocket::write_head`] reports.
#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
pub(crate) fn ws_start_frame(
    ws: &mut WebSocket,
    flags: i32,
    frame_len: i64,
    cx: &mut WsCtx<'_, '_>,
) -> CodeResult<()> {
    // `:1876-1879` -- the FIRST raw-mode test, which returns and therefore
    // decides. Its message has no `[WS]` prefix in the C, unlike almost every
    // other message in the file; transcribed as found.
    if cx.settings.raw_mode {
        if let Some(tracer) = cx.tracer() {
            failf!(
                tracer,
                "cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled"
            );
        }
        return Err(CURLcode::FailedInit);
    }

    if let Some(tracer) = cx.tracer() {
        trc_feat!(
            tracer,
            TraceFeature::Ws,
            "curl_ws_start_frame(flags={:x}, frame_len={}",
            flags,
            frame_len
        );
    }

    // `:1896-1900` is the second raw-mode test and is unreachable behind the
    // one above; `:1884-1894`'s two tests are the null-connection and
    // no-WebSocket-state cases, which are the caller's to make -- it either has
    // a `WebSocket` to pass or it does not, and the FFI shim answers
    // `CURLE_SEND_ERROR` in the latter case with the C's own message.

    // `:1902-1906`.
    if ws.encoder().payload_remain() != 0 {
        if let Some(tracer) = cx.tracer() {
            failf!(tracer, "[WS] previous frame not finished");
        }
        return Err(CURLcode::SendError);
    }

    // `:1908-1912`.
    if let Err(code) = ws.write_head(flags, frame_len, cx) {
        if let Some(tracer) = cx.tracer() {
            trc_feat!(
                tracer,
                TraceFeature::Ws,
                "curl_start_frame(), error adding frame head {}",
                code as i32
            );
        }
        return Err(code);
    }
    Ok(())
}

/// The `CURLcode` the FFI shim answers when the handle has no WebSocket state
/// (`lib/ws.c:1800-1804`, `:1890-1894`, `:1732-1736`).
///
/// *"[WS] Not a websocket transfer"* is the C's message and
/// [`CURLcode::SendError`] its code -- and note that `curl_ws_recv`'s
/// equivalent check answers [`CURLcode::BadFunctionArgument`] instead
/// (`:1558-1562`), with the different message *"[WS] connection is not setup
/// for websocket"*. The asymmetry is upstream's; both are named so the shim
/// cannot merge them.
#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
pub(crate) const NOT_A_WEBSOCKET_SEND: CURLcode = CURLcode::SendError;

/// The `CURLcode` `curl_ws_recv` answers for the same condition
/// (`lib/ws.c:1558-1562`).
#[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/ws.rs, and mod tests
pub(crate) const NOT_A_WEBSOCKET_RECV: CURLcode = CURLcode::BadFunctionArgument;

// -- 13. The scheme handler and the two registry rows ----------------------

/// `Curl_protocol_ws` (`lib/ws.c:1918-1936`): the WebSocket scheme handler.
///
/// Holds an [`Http1`] and forwards sixteen of the seventeen slots to it,
/// overriding [`Protocol::setup_connection`] alone. That is not a
/// simplification -- it is what the C's table says, initialiser for
/// initialiser, and the module documentation lists the eight filled slots
/// against `Curl_protocol_http`'s.
///
/// # Why a field and not a supertrait
///
/// [`Protocol`] has no `Deref`-style delegation, and it must not: the trait is
/// used behind `&dyn Protocol`, and blanket-forwarding through a supertrait
/// would make every implementor inherit HTTP's behaviour by accident. An
/// explicit field forwarded by explicit methods is longer to write and is the
/// only form in which a reader can see WHICH slot differs -- which is the one
/// fact about this handler that matters.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct Ws {
    /// The handler every slot but one forwards to.
    ///
    /// A value rather than a reference, because [`Http1`] is a zero-sized unit
    /// struct: the C's `Curl_protocol_ws` names `Curl_http` and its neighbours
    /// as function pointers, and holding the unit type is the same thing with no
    /// indirection and no lifetime.
    http: Http1,
}

/// The one instance, `'static` so that a [`Scheme`] row can point at it.
///
/// One handler for BOTH rows, as in the C: `Curl_scheme_ws` at
/// `lib/ws.c:1989` and `Curl_scheme_wss` at `:2004` both name
/// `&Curl_protocol_ws`. `wss` differs by `PROTOPT_SSL` on the row and a TLS
/// filter in the chain, never by protocol logic -- which is the same
/// relationship `https` has to `http`.
pub(crate) static WS: Ws = Ws { http: Http1 };

impl Protocol for Ws {
    /// `ws_setup_conn(data, conn)` (`lib/ws.c:1840-1849`) -- **the only slot
    /// this handler overrides**.
    ///
    /// ```c
    /// /* WebSocket is 1.1 only (for now) */
    /// data->state.http_neg.accept_09 = FALSE;
    /// data->state.http_neg.only_10 = FALSE;
    /// data->state.http_neg.wanted = CURL_HTTP_V1x;
    /// data->state.http_neg.allowed = CURL_HTTP_V1x;
    /// return Curl_http_setup_conn(data, conn);
    /// ```
    ///
    /// Four assignments and a delegation. The assignments are what
    /// [`ws_negotiation`] returns, and they are not merely a preference: an
    /// upgrade handshake is an HTTP/1.1 mechanism, so accepting an HTTP/0.9
    /// response or offering HTTP/2 would make the `101` unreachable. `only_10`
    /// is cleared for the same reason -- `Upgrade:` needs 1.1, and
    /// [`super::http1`]'s writer reads that flag when it composes the request
    /// line.
    ///
    /// The delegation is [`Http1::setup_connection_for`], which is
    /// `Curl_http_setup_conn`'s body with the negotiation supplied. Because
    /// `wanted` is `CURL_HTTP_V1x` here and that function's whole body is
    /// `if(wanted == CURL_HTTP_V3x)`, the answer is always `Ok(())` -- but it is
    /// CALLED rather than short-circuited, so that a change to HTTP's setup
    /// reaches WebSocket transfers as it does in the C.
    ///
    /// # Errors
    ///
    /// Whatever [`Http1::setup_connection_for`] reports.
    fn setup_connection(&self, ctx: &mut TransferCtx<'_>) -> CodeResult<()> {
        let _ = ctx;
        Http1::setup_connection_for(&ws_negotiation())
    }

    /// `Curl_http` (`lib/ws.c:1920`), forwarded.
    fn do_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        self.http.do_it(ctx)
    }

    /// `Curl_http_done` (`lib/ws.c:1921`), forwarded.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        status: CURLcode,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        self.http.done(ctx, status, premature)
    }

    /// `Curl_http_doing_pollset` (`lib/ws.c:1927`), forwarded.
    fn doing_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut crate::conn::select::EasyPollset,
    ) -> CodeResult<()> {
        self.http.doing_pollset(ctx, ps)
    }

    /// `Curl_http_perform_pollset` (`lib/ws.c:1929`), forwarded.
    fn perform_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut crate::conn::select::EasyPollset,
    ) -> CodeResult<()> {
        self.http.perform_pollset(ctx, ps)
    }

    /// `Curl_http_write_resp` (`lib/ws.c:1931`), forwarded.
    fn write_resp<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        buf: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, bool> {
        self.http.write_resp(ctx, buf, is_eos)
    }

    /// `Curl_http_write_resp_hd` (`lib/ws.c:1932`), forwarded.
    fn write_resp_hd<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        hd: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, bool> {
        self.http.write_resp_hd(ctx, hd, is_eos)
    }

    /// `Curl_http_follow` (`lib/ws.c:1935`), forwarded.
    ///
    /// A WebSocket URL can be redirected, and the C makes no exception for it:
    /// the slot is HTTP's, so the answer is HTTP's.
    fn follow(
        &self,
        ctx: &mut TransferCtx<'_>,
        newurl: &str,
        follow_type: super::FollowType,
    ) -> CodeResult<()> {
        self.http.follow(ctx, newurl, follow_type)
    }
}

/// The four negotiation assignments of `ws_setup_conn` (`lib/ws.c:1843-1847`).
///
/// Returned as a value so that the four lines have one home and one test.
/// `preferred`, `rcvd_min`, `h2_upgrade` and `h2_prior_knowledge` keep their
/// defaults, which is what the C leaves them at: `ws_setup_conn` assigns only
/// these four members.
#[must_use]
pub(crate) fn ws_negotiation() -> super::HttpNegotiation {
    super::HttpNegotiation {
        // *"WebSocket is 1.1 only (for now)"*.
        accept_09: false,
        only_10: false,
        wanted: CURL_HTTP_V1X,
        allowed: CURL_HTTP_V1X,
        ..super::HttpNegotiation::default()
    }
}

/// The `WS` row (`lib/ws.c:1984-1997`).
///
/// ```text
/// "WS",                                 /* scheme */
/// &Curl_protocol_ws,
/// CURLPROTO_WS,                         /* protocol */
/// CURLPROTO_HTTP,                       /* family */
/// PROTOPT_CREDSPERREQUEST |             /* flags */
/// PROTOPT_USERPWDCTRL,
/// PORT_HTTP                             /* defport */
/// ```
///
/// # Three columns a reader should not try to tidy
///
/// * **the name is UPPER CASE**, `"WS"`, even though `struct Curl_scheme`'s own
///   comment says *"URL scheme name in lowercase"* (`lib/urldata.h:516`). The
///   registry's lookup is case-insensitive -- `Curl_getn_scheme` uses
///   `curl_strnequal` -- so it works, and it is transcribed as found;
/// * **the family is `CURLPROTO_HTTP`**, not `CURLPROTO_WS`, which is what puts
///   this row inside `PROTO_FAMILY_HTTP` and therefore what makes
///   [`crate::headers`]'s collector install for a WebSocket transfer;
/// * **there is no `PROTOPT_CONN_REUSE`**, while both HTTP rows have it. An
///   upgraded connection must never return to the pool.
///
/// `flags` and `defport` are CONSUMED from `protocols/mod.rs`, which owns the
/// one transcription of each -- [`FLAGS_WS`] and [`PORT_HTTP`] -- so this row
/// and the registry cannot disagree about them. What this file adds is the `run`
/// column.
///
/// # `static`, not `const`
///
/// It names [`WS`], which is a `static`, and a `const` referring to a `static`
/// is `error[E0013]` until `const_refs_to_static` -- which is above this
/// workspace's MSRV of 1.75. [`super::http1::SCHEME_HTTP`] carries the same
/// note for the same reason, and adopting either row into
/// `protocols/mod.rs`'s `const` table needs that table to become a `static`
/// first.
#[rustfmt::skip]
pub(crate) static SCHEME_WS: Scheme = Scheme {
    name: b"WS",
    run: Some(&WS),
    protocol: Proto::WS,
    family: Proto::HTTP,
    flags: FLAGS_WS,
    defport: PORT_HTTP,
};

/// The `WSS` row (`lib/ws.c:1999-2011`).
///
/// ```text
/// "WSS",                                /* scheme */
/// &Curl_protocol_ws,
/// CURLPROTO_WSS,                        /* protocol */
/// CURLPROTO_HTTP,                       /* family */
/// PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | /* flags */
/// PROTOPT_USERPWDCTRL,
/// PORT_HTTPS                            /* defport */
/// ```
///
/// Identical to [`SCHEME_WS`] but for `PROTOPT_SSL`, the protocol bit and the
/// port -- and still no `PROTOPT_CONN_REUSE`. The `run` column is the SAME
/// handler, which is why there is no `wss` module and no TLS import in this
/// file: the TLS filter is inserted into the chain by [`crate::conn`] because
/// of that flag, and the protocol above it never learns.
///
/// The C additionally guards the `run` column with `#if
/// defined(CURL_DISABLE_WEBSOCKETS) || !defined(USE_SSL)` (`:2001-2005`), so a
/// build without TLS registers `wss` with no implementation. This workspace has
/// no such build -- rustls is unconditional, which specification 0.8.2 requires
/// -- so the column is unconditional here, and the `websockets` feature gate on
/// this whole module is the surviving half of that `#if`.
#[rustfmt::skip]
pub(crate) static SCHEME_WSS: Scheme = Scheme {
    name: b"WSS",
    run: Some(&WS),
    protocol: Proto::WSS,
    family: Proto::HTTP,
    flags: FLAGS_WSS,
    defport: PORT_HTTPS,
};

/// Both rows, in the C's registration order.
///
/// `protocols/mod.rs` assembles the 33-row registry; this is what it takes from
/// here. The order is `lib/url.c:1488`'s -- `WS` then `WSS` -- and it is the
/// order of that module's own `IN_SCOPE_SCHEMES`, so adopting these two is a
/// one-column substitution and not a reordering.
///
/// Those two rows still carry `run: None` in this checkout, and the reason is
/// [`super::http1`]'s: a WebSocket transfer is an HTTP transfer plus a
/// handshake, and nothing in this checkout builds a request specification for
/// [`Http1`] to compose -- `easy/handle.rs` is on disk and holds the option
/// state, but `easy/setopt.rs`, which writes a URL onto it, is not. Advertising `ws` while [`Protocol::do_it`] answers
/// [`CURLcode::FailedInit`] would convert 28 cleanly-skipped fixtures into 28
/// failures, and specification 0.6.5 measures that asymmetry precisely:
/// under-reporting makes a fixture SKIP, over-reporting makes it RUN AND FAIL.
/// [`mod tests`](self) binds these rows to the registry's column for column, so
/// the substitution stays a one-column change.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: protocols/mod.rs's registry, at the wiring checkpoint
pub(crate) static SCHEMES: [Scheme; 2] = [SCHEME_WS, SCHEME_WSS];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::tests::{new_log, InMemory, TransportHandle};
    use crate::conn::filters::{link, ConnId, FilterChain, SocketIndex};
    use crate::conn::ProtocolOptions;
    use crate::crypto::rand::TestRng;
    use crate::trace::{
        TraceConfig, TraceIds, TraceLevel, TraceState, WriterSink,
    };
    use crate::util::timeval::{CurlTime, TestClock};

    // -- helpers -----------------------------------------------------------

    /// The injected clock every test uses; no wall clock is ever consulted.
    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    /// The generator `CURL_ENTROPY=12345678` selects, which is what the
    /// WebSocket fixtures set.
    ///
    /// Its first sixteen bytes are `4321532163217321` and its fifth draw is
    /// `8321` -- the nonce of `tests/data/test2300` and the mask of
    /// `tests/data/test2302` respectively.
    fn entropy() -> TestRng {
        TestRng::from_entropy_string("12345678")
    }

    /// A CONNECTED chain whose bottom is the in-memory transport, so nothing
    /// opens a socket.
    ///
    /// `connect_head` is not optional: [`FilterChain::send`] starts at the first
    /// CONNECTED filter and answers [`CURLcode::FailedInit`] when there is none.
    fn connected_chain(clock: &TestClock) -> (FilterChain, TransportHandle) {
        let log = new_log();
        let mut chain =
            FilterChain::new(Some(ConnId::new(1)), SocketIndex::First);
        let (transport, state) = InMemory::new("WS", &log);
        let mut cx = CallCtx::new(clock);
        chain.add(&mut cx, link(transport));
        assert!(
            chain.connect_head(&mut cx).expect("the transport connects"),
            "the default transport connects in one step"
        );
        (chain, state)
    }

    /// Runs `body` with a [`WsCtx`] over the in-memory chain.
    ///
    /// The three borrows have to be created in this order and dropped together,
    /// which a closure expresses and a helper returning the context cannot.
    fn with_io<R>(
        clock: &TestClock,
        chain: &mut FilterChain,
        settings: &WsSettings,
        rng: &mut dyn Rng,
        in_callback: bool,
        body: impl FnOnce(&mut WsCtx<'_, '_>) -> R,
    ) -> R {
        let mut call = CallCtx::new(clock);
        let mut io = ChainTransport::new(chain, &mut call);
        let mut cx =
            WsCtx::new(settings, rng, &mut io).with_in_callback(in_callback);
        body(&mut cx)
    }

    /// Everything the transport captured on the way down.
    fn sent(state: &TransportHandle) -> Vec<u8> {
        state.borrow().output.clone()
    }

    /// Queue bytes for the transport to hand upward.
    fn feed(state: &TransportHandle, bytes: &[u8]) {
        state.borrow_mut().input.extend_from_slice(bytes);
    }

    /// A byte slice as hex, for a readable assertion failure. The COMPARISON is
    /// always over bytes; this is only how a mismatch is shown.
    fn shown(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// `CURLOPT_HTTPHEADER`'s list, spelled as a test spells it.
    fn hdrs(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|line| (*line).to_string()).collect()
    }

    /// A collector that records what the client-writer chain was handed.
    #[derive(Debug, Default)]
    struct RecordingWriter {
        /// One entry per decoded frame: the bytes and the metadata.
        decoded: Vec<(Vec<u8>, WsFrameMeta)>,
        /// One entry per pass-through write.
        passed: Vec<(Vec<u8>, bool)>,
    }

    impl BodyWriter for RecordingWriter {
        fn write_decoded(
            &mut self,
            bytes: &[u8],
            meta: &WsFrameMeta,
        ) -> CodeResult<()> {
            self.decoded.push((bytes.to_vec(), *meta));
            Ok(())
        }

        fn write_passthrough(
            &mut self,
            bytes: &[u8],
            is_eos: bool,
        ) -> CodeResult<()> {
            self.passed.push((bytes.to_vec(), is_eos));
            Ok(())
        }
    }

    /// A reader that hands out one canned buffer and then reports end of
    /// stream.
    #[derive(Debug)]
    struct CannedReader {
        /// What is left to hand out.
        remaining: Vec<u8>,
        /// How many times [`UploadReader::clear_eos`] was called.
        cleared: usize,
    }

    impl UploadReader for CannedReader {
        fn read(&mut self, buf: &mut [u8]) -> CodeResult<(usize, bool)> {
            let take = buf.len().min(self.remaining.len());
            if let Some(slot) = buf.get_mut(..take) {
                slot.copy_from_slice(self.remaining.get(..take).unwrap_or(&[]));
            }
            self.remaining.drain(..take);
            Ok((take, self.remaining.is_empty()))
        }

        fn clear_eos(&mut self) {
            self.cleared += 1;
        }
    }

    // -- 1. the public ABI integers ----------------------------------------

    #[test]
    fn every_frame_flag_is_the_headers_integer() {
        // `include/curl/websockets.h:40-45` and `:60`. Written as literals on
        // both sides deliberately: specification 0.6.1 makes these seven
        // numbers part of the ABI, and asserting `1 << 0` against `1 << 0`
        // would assert nothing.
        assert_eq!(CURLWS_TEXT, 1);
        assert_eq!(CURLWS_BINARY, 2);
        assert_eq!(CURLWS_CONT, 4);
        assert_eq!(CURLWS_CLOSE, 8);
        assert_eq!(CURLWS_PING, 16);
        assert_eq!(CURLWS_OFFSET, 32);
        assert_eq!(CURLWS_PONG, 64);

        // The group is exhaustive and in the header's declaration order.
        assert_eq!(FRAME_FLAGS, [1, 2, 4, 8, 16, 32, 64]);
        // No two flags collide, which a hand-written table can get wrong.
        let mut union = 0_i32;
        for flag in FRAME_FLAGS {
            assert_eq!(union & flag, 0, "{flag} collides");
            union |= flag;
        }
        assert_eq!(union, 0x7f);
    }

    #[test]
    fn both_ws_options_bits_are_the_headers_integers() {
        // `include/curl/websockets.h:89-90`, the `CURLOPT_WS_OPTIONS` mask.
        assert_eq!(CURLWS_RAW_MODE, 1);
        assert_eq!(CURLWS_NOAUTOPONG, 2);

        // And they are read as a mask, not as an enumeration.
        let both = WsSettings::default()
            .with_options(CURLWS_RAW_MODE | CURLWS_NOAUTOPONG);
        assert!(both.raw_mode);
        assert!(both.no_auto_pong);
        assert!(!both.auto_pong());

        let neither = WsSettings::default().with_options(0);
        assert!(!neither.raw_mode);
        assert!(neither.auto_pong());

        // An unknown bit is ignored rather than refused: `CURLOPT_WS_OPTIONS`
        // has no rejection path, and refusing would break an application built
        // against a newer header.
        let future = WsSettings::default().with_options(1 << 20);
        assert!(!future.raw_mode);
        assert!(!future.no_auto_pong);
    }

    #[test]
    fn the_frame_metadata_maps_onto_the_c_struct_field_for_field() {
        // `include/curl/websockets.h:31-38`. `age` is ALWAYS zero -- the C's
        // comment says so and nothing in `lib/ws.c` writes anything else.
        let zero = WsFrameMeta::new();
        assert_eq!(zero.age, 0);
        assert_eq!(zero.flags, 0);
        assert_eq!(zero.offset, 0);
        assert_eq!(zero.bytesleft, 0);
        assert_eq!(zero.len, 0);
        assert_eq!(zero, WsFrameMeta::default());

        // The five widths are the C's: int, int, curl_off_t, curl_off_t,
        // size_t. Asserted through the types the fields accept rather than
        // through `size_of`, because the `#[repr(C)]` mirror -- and therefore
        // the layout -- belongs to `curl-rs-ffi`.
        let meta = WsFrameMeta {
            age: 0,
            flags: CURLWS_TEXT | CURLWS_CONT,
            offset: i64::from(i32::MAX) + 1,
            bytesleft: i64::MAX,
            len: usize::MAX,
        };
        assert!(meta.has(CURLWS_TEXT));
        assert!(meta.has(CURLWS_CONT));
        assert!(!meta.has(CURLWS_BINARY));
        assert_eq!(meta.offset, 2_147_483_648);
    }

    #[test]
    fn the_disabled_build_contract_is_named_where_it_cannot_be_lost() {
        // `lib/ws.c:1940-1980`: three stubs answer this code and
        // `curl_ws_meta` answers NULL. This module does not exist in such a
        // build, so `curl-rs-ffi/src/ffi/ws.rs` owns the stubs -- and this
        // assertion is what keeps the code from being guessed there.
        assert_eq!(NOT_BUILT_IN, CURLcode::NotBuiltIn);
        assert_eq!(NOT_BUILT_IN as i32, 4);

        // The two "not a websocket" codes are DIFFERENT, and upstream's
        // asymmetry is the whole point of naming them.
        assert_eq!(NOT_A_WEBSOCKET_SEND, CURLcode::SendError);
        assert_eq!(NOT_A_WEBSOCKET_RECV, CURLcode::BadFunctionArgument);
        assert_ne!(NOT_A_WEBSOCKET_SEND, NOT_A_WEBSOCKET_RECV);
    }

    #[test]
    fn the_flag_names_are_readable_and_total() {
        assert_eq!(frame_flag_names(0), "NONE");
        assert_eq!(frame_flag_names(CURLWS_TEXT), "TEXT");
        assert_eq!(
            frame_flag_names(CURLWS_BINARY | CURLWS_CONT),
            "BINARY|CONT"
        );
        assert_eq!(frame_flag_names(CURLWS_PONG), "PONG");
        // An undeclared bit contributes nothing rather than panicking.
        assert_eq!(frame_flag_names(1 << 20), "NONE");
    }

    // -- 2. the registry rows ----------------------------------------------

    #[test]
    fn the_two_rows_are_the_measured_registrations() {
        // `lib/ws.c:1984` and `:1999`, column by column.
        assert_eq!(SCHEME_WS.name, b"WS");
        assert_eq!(SCHEME_WSS.name, b"WSS");
        // UPPER CASE, even though `struct Curl_scheme`'s comment says
        // "lowercase". Preserved, not "fixed".
        assert!(SCHEME_WS.name.iter().all(|b| b.is_ascii_uppercase()));
        assert!(SCHEME_WSS.name.iter().all(|b| b.is_ascii_uppercase()));

        assert_eq!(SCHEME_WS.protocol, Proto::WS);
        assert_eq!(SCHEME_WSS.protocol, Proto::WSS);
        // The FAMILY is HTTP for both, which is what puts them inside
        // `PROTO_FAMILY_HTTP`.
        assert_eq!(SCHEME_WS.family, Proto::HTTP);
        assert_eq!(SCHEME_WSS.family, Proto::HTTP);

        assert_eq!(SCHEME_WS.defport, 80);
        assert_eq!(SCHEME_WSS.defport, 443);

        // Only `wss` is TLS-protected by definition.
        assert!(!SCHEME_WS.is_ssl());
        assert!(SCHEME_WSS.is_ssl());

        // Both are in core scope, and both carry an implementation here.
        assert!(SCHEME_WS.in_core_scope());
        assert!(SCHEME_WSS.in_core_scope());
        assert!(SCHEME_WS.run.is_some());
        assert!(SCHEME_WSS.run.is_some());

        // In the C's registration order.
        assert_eq!(SCHEMES.len(), 2);
        assert_eq!(SCHEMES[0].name, b"WS");
        assert_eq!(SCHEMES[1].name, b"WSS");
    }

    #[test]
    fn neither_row_may_ever_carry_conn_reuse() {
        // `lib/ws.c:1993-1994` and `:2008-2009` set only
        // `PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL`, while
        // `lib/http.c:5015` and `:5032` add `PROTOPT_CONN_REUSE`. One handler
        // serves both pairs, so the flags are the only place the distinction
        // lives: an upgraded WebSocket must never return to the pool.
        for row in [&SCHEME_WS, &SCHEME_WSS] {
            assert!(
                !row.flags.intersects(ProtocolOptions::CONN_REUSE),
                "{} must not be poolable",
                String::from_utf8_lossy(row.name)
            );
            assert!(row.flags.intersects(ProtocolOptions::CREDSPERREQUEST));
            assert!(row.flags.intersects(ProtocolOptions::USERPWDCTRL));
        }
        // And the pool's own predicate agrees, which is the production path.
        assert!(!super::super::connection_reusable(&SCHEME_WS, false));
        assert!(!super::super::connection_reusable(&SCHEME_WSS, false));
        // `CURLOPT_CONNECT_ONLY` exempts every scheme, WebSocket included.
        assert!(super::super::connection_reusable(&SCHEME_WS, true));
    }

    #[test]
    fn the_rows_bind_to_the_registry_column_for_column() {
        // Adopting these two into `protocols/mod.rs`'s table must stay a
        // ONE-COLUMN substitution, so every other column is asserted equal to
        // the live registry's. `protocols/http1.rs` holds the same test for its
        // own pair, and this is why the wiring checkpoint is a keyword change
        // rather than a re-transcription.
        for (mine, name) in [(&SCHEME_WS, &b"WS"[..]), (&SCHEME_WSS, b"WSS")] {
            let live = super::super::get_scheme(name)
                .expect("the websocket rows resolve");
            assert_eq!(mine.name, live.name);
            assert_eq!(mine.protocol, live.protocol);
            assert_eq!(mine.family, live.family);
            assert_eq!(mine.flags, live.flags);
            assert_eq!(mine.defport, live.defport);
            // The one column that differs, and the reason it does: nothing in
            // this checkout can build a request for the shared HTTP writer to
            // compose, so advertising `ws` would convert 28 cleanly-skipped
            // fixtures into 28 failures.
            assert!(live.run.is_none(), "the registry stays truthful");
        }
    }

    #[test]
    fn the_documented_protocol_bit_collision_is_not_quietly_fixed() {
        // `lib/urldata.h:70` defines the internal `CURLPROTO_WS` as `1L << 30`
        // and `include/curl/curl.h:1106` defines the public `CURLPROTO_MQTTS`
        // as the same bit. Renumbering either would break the public header's
        // integer contract, so the collision is asserted rather than repaired.
        assert_eq!(Proto::WS.bits(), Proto::MQTTS.bits());
        assert_eq!(Proto::WS.bits(), 1 << 30);
        assert_eq!(Proto::WSS.bits(), 1 << 31);
        // Which is exactly why the family column is consulted too: `mqtts` is
        // out of scope and `ws` is in it, and they share the protocol bit.
        assert_eq!(SCHEME_WS.protocol, Proto::MQTTS);
        assert!(SCHEME_WS.in_core_scope());
    }

    // -- 3. the delegating handler -----------------------------------------

    #[test]
    fn the_handler_is_dispatchable_behind_dyn_and_registered_twice() {
        // Specification 0.3.3's pattern P1 requires `&dyn Protocol` dispatch,
        // which is why every async slot returns a boxed future: both `async fn`
        // in a trait and RPITIT -- stabilised in 1.75, this workspace's floor
        // -- are dyn-INCOMPATIBLE. If somebody replaced a `ProtoFuture` with
        // `async fn`, this line would stop compiling, which is the alarm wanted.
        let handler: &dyn Protocol = &WS;
        let boxed: Box<dyn Protocol> = Box::new(Ws::default());
        assert_eq!(format!("{handler:?}"), format!("{boxed:?}"));

        // ONE handler for BOTH rows, as in the C: `lib/ws.c:1989` and `:2004`
        // both name `&Curl_protocol_ws`. Asserted by ADDRESS, which is what
        // makes the sharing observable.
        let ws_run = SCHEME_WS.run.expect("WS carries a handler");
        let wss_run = SCHEME_WSS.run.expect("WSS carries a handler");
        assert!(
            core::ptr::eq(
                (ws_run as *const dyn Protocol).cast::<u8>(),
                (wss_run as *const dyn Protocol).cast::<u8>()
            ),
            "both rows must point at the one shared handler"
        );
    }

    #[test]
    fn setup_connection_pins_http_1_1_and_delegates() {
        // `ws_setup_conn` (`lib/ws.c:1840-1849`): four assignments then
        // `Curl_http_setup_conn`.
        let neg = ws_negotiation();
        assert_eq!(neg.wanted, CURL_HTTP_V1X);
        assert_eq!(neg.allowed, CURL_HTTP_V1X);
        assert!(!neg.accept_09, "an upgrade needs a real HTTP/1.1 response");
        assert!(!neg.only_10, "`Upgrade:` needs 1.1, not 1.0");
        // The four members `ws_setup_conn` does NOT touch keep their defaults.
        let default = super::super::HttpNegotiation::default();
        assert_eq!(neg.preferred, default.preferred);
        assert_eq!(neg.rcvd_min, default.rcvd_min);
        assert_eq!(neg.h2_upgrade, default.h2_upgrade);
        assert_eq!(neg.h2_prior_knowledge, default.h2_prior_knowledge);

        // And the slot itself succeeds, because `Curl_http_setup_conn`'s whole
        // body is a test for HTTP/3-only and this is HTTP/1.1-only.
        let clock = clock();
        let mut chains = crate::conn::filters::FilterChains::new(None);
        let row = super::super::get_scheme(b"WS").expect("WS is a row");
        let mut ctx = TransferCtx::new(&mut chains, &clock, row);
        WS.setup_connection(&mut ctx)
            .expect("HTTP/1.1 setup succeeds");
    }

    #[test]
    fn every_other_slot_answers_exactly_as_http_does() {
        // The measurement behind this file's design: `Curl_protocol_ws`
        // (`lib/ws.c:1918-1936`) is initialiser-for-initialiser identical to
        // `Curl_protocol_http` except for `setup_connection`. So each slot is
        // driven on BOTH handlers over the same context and the answers are
        // compared -- if `ws.rs` ever grew its own copy of an HTTP slot, this
        // test would be what noticed.
        let clock = clock();
        let row = super::super::get_scheme(b"WS").expect("WS is a row");
        let http: &dyn Protocol = &super::super::http1::HTTP;
        let ws: &dyn Protocol = &WS;

        // `do_it`: both report `CURLE_FAILED_INIT` while no request
        // specification can be built, which is `http1`'s documented answer.
        let mut chains = crate::conn::filters::FilterChains::new(None);
        let ws_do = {
            let mut ctx = TransferCtx::new(&mut chains, &clock, row);
            futures::executor::block_on(ws.do_it(&mut ctx))
        };
        let http_do = {
            let mut ctx = TransferCtx::new(&mut chains, &clock, row);
            futures::executor::block_on(http.do_it(&mut ctx))
        };
        assert_eq!(ws_do, http_do);
        assert_eq!(ws_do, Err(CURLcode::FailedInit));

        // `done`: a failing status wins over everything else, on both.
        for status in [CURLcode::Ok, CURLcode::RecvError] {
            let ws_done = {
                let mut ctx = TransferCtx::new(&mut chains, &clock, row);
                futures::executor::block_on(ws.done(&mut ctx, status, false))
            };
            let http_done = {
                let mut ctx = TransferCtx::new(&mut chains, &clock, row);
                futures::executor::block_on(http.done(&mut ctx, status, false))
            };
            assert_eq!(ws_done, http_done, "done({status:?})");
        }

        // `write_resp` and `write_resp_hd`: both decline the bytes, leaving the
        // generic client-writer chain to run.
        let ws_resp = {
            let mut ctx = TransferCtx::new(&mut chains, &clock, row);
            futures::executor::block_on(ws.write_resp(&mut ctx, b"body", true))
        };
        let http_resp = {
            let mut ctx = TransferCtx::new(&mut chains, &clock, row);
            futures::executor::block_on(
                http.write_resp(&mut ctx, b"body", true),
            )
        };
        assert_eq!(ws_resp, http_resp);
        assert_eq!(ws_resp, Ok(false));

        let ws_hd = {
            let mut ctx = TransferCtx::new(&mut chains, &clock, row);
            futures::executor::block_on(ws.write_resp_hd(
                &mut ctx,
                b"X: y\r\n",
                false,
            ))
        };
        let http_hd = {
            let mut ctx = TransferCtx::new(&mut chains, &clock, row);
            futures::executor::block_on(http.write_resp_hd(
                &mut ctx,
                b"X: y\r\n",
                false,
            ))
        };
        assert_eq!(ws_hd, http_hd);

        // `follow`: a WebSocket URL redirects exactly as an HTTP one does,
        // including the refusal of `FollowType::None`.
        for kind in [
            super::super::FollowType::None,
            super::super::FollowType::Redir,
            super::super::FollowType::Retry,
            super::super::FollowType::Fake,
        ] {
            let ws_follow = {
                let mut ctx = TransferCtx::new(&mut chains, &clock, row);
                ws.follow(&mut ctx, "http://example.com/", kind)
            };
            let http_follow = {
                let mut ctx = TransferCtx::new(&mut chains, &clock, row);
                http.follow(&mut ctx, "http://example.com/", kind)
            };
            assert_eq!(ws_follow, http_follow, "follow({kind:?})");
        }

        // The two pollset slots, over the in-memory transport: neither
        // registers anything for an invalid descriptor, and both agree.
        let mut ps_ws = crate::conn::select::EasyPollset::new();
        let mut ps_http = crate::conn::select::EasyPollset::new();
        {
            let mut ctx = TransferCtx::new(&mut chains, &clock, row);
            ws.doing_pollset(&mut ctx, &mut ps_ws).expect("registers");
            ws.perform_pollset(&mut ctx, &mut ps_ws).expect("registers");
        }
        {
            let mut ctx = TransferCtx::new(&mut chains, &clock, row);
            http.doing_pollset(&mut ctx, &mut ps_http)
                .expect("registers");
            http.perform_pollset(&mut ctx, &mut ps_http)
                .expect("registers");
        }
        assert_eq!(ps_ws.len(), ps_http.len());
    }

    // -- 4. THE handshake oracle: tests/data/test2300 ----------------------

    /// The three lines `tests/data/test2300` expects, byte for byte.
    ///
    /// The fixture's `<protocol crlf="headers">` block, with the harness's
    /// substitutions applied and the lines this file does not own removed:
    ///
    /// ```text
    /// GET /2300 HTTP/1.1                          <- protocols/http1.rs
    /// Host: 127.0.0.1:8990                        <- protocols/http1.rs
    /// User-Agent: curl/8.19.0-DEV                 <- protocols/http1.rs
    /// Accept: */*                                 <- protocols/http1.rs
    /// Upgrade: websocket                          <- HERE
    /// Sec-WebSocket-Version: 13                   <- HERE
    /// Sec-WebSocket-Key: NDMyMTUzMjE2MzIxNzMyMQ== <- HERE
    /// Connection: Upgrade                         <- protocols/http1.rs
    /// ```
    ///
    /// `CURL_ENTROPY=12345678` is what makes the key deterministic, and
    /// `compareparts` (`tests/getpart.pm:351+`) compares the whole block as ONE
    /// string -- so the order of these three lines is part of the contract.
    #[rustfmt::skip]
    const TEST2300_HANDSHAKE: &[u8] =
        b"Upgrade: websocket\r\n\
          Sec-WebSocket-Version: 13\r\n\
          Sec-WebSocket-Key: NDMyMTUzMjE2MzIxNzMyMQ==\r\n";

    #[test]
    fn the_handshake_of_test2300_is_reproduced_byte_for_byte() {
        let mut rng = entropy();
        let mut req = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
        let mut state = RequestState::default();

        let key = write_handshake(&mut req, &mut state, &[], &mut rng, None)
            .expect("the handshake composes");

        assert_eq!(
            req.as_slice(),
            TEST2300_HANDSHAKE,
            "\n  actual: {}\nexpected: {}",
            String::from_utf8_lossy(req.as_slice()).replace("\r\n", "\\r\\n"),
            String::from_utf8_lossy(TEST2300_HANDSHAKE)
                .replace("\r\n", "\\r\\n"),
        );
        // The nonce itself: 16 bytes of the CURL_ENTROPY stream, padded
        // standard base64 -- NOT the URL-safe unpadded alphabet, which the `==`
        // terminator settles.
        assert_eq!(key, "NDMyMTUzMjE2MzIxNzMyMQ==");
        assert!(key.ends_with("=="), "padded standard base64");
        assert_eq!(
            base64::encode(b"4321532163217321").expect("encodes"),
            key,
            "the nonce is the first sixteen bytes of the entropy stream"
        );
    }

    #[test]
    fn the_three_state_flags_are_set_for_the_connection_header() {
        let mut rng = entropy();
        let mut req = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
        let mut state = RequestState::default();
        assert!(!state.http_hd_upgrade);
        assert_eq!(state.upgr101, Upgrade101::None);
        assert!(!state.upgrade_in_progress);

        write_handshake(&mut req, &mut state, &[], &mut rng, None)
            .expect("composes");

        // `lib/ws.c:1296-1298`. The first is what makes `protocols/http1.rs`'s
        // `Connection:` slot emit `Connection: Upgrade`, which is why this file
        // does not write that header itself.
        assert!(state.http_hd_upgrade);
        assert_eq!(state.upgr101, Upgrade101::WebSocket);
        assert!(state.upgrade_in_progress);
        // And nothing else was touched: the handshake is not an HTTP/2 upgrade.
        assert!(!state.http_hd_h2_settings);
        assert!(!state.http_hd_te);

        // The header this file must NOT write.
        let text = String::from_utf8_lossy(req.as_slice());
        assert!(
            !text.contains("Connection:"),
            "the Connection header belongs to protocols/http1.rs: {text}"
        );
    }

    #[test]
    fn each_handshake_header_is_suppressed_individually() {
        // `lib/ws.c:1292` puts `Curl_checkheaders` INSIDE the loop, so `-H`
        // replaces exactly one line and leaves the other two in place. An
        // all-or-nothing test would be a wire difference in both directions.
        let cases: [(&str, &[u8]); 3] = [
            (
                "Upgrade: h2c",
                b"Sec-WebSocket-Version: 13\r\n\
                  Sec-WebSocket-Key: NDMyMTUzMjE2MzIxNzMyMQ==\r\n",
            ),
            (
                "Sec-WebSocket-Version: 8",
                b"Upgrade: websocket\r\n\
                  Sec-WebSocket-Key: NDMyMTUzMjE2MzIxNzMyMQ==\r\n",
            ),
            (
                "Sec-WebSocket-Key: bXlub25jZW1pbmVvbmx5",
                b"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n",
            ),
        ];
        for (supplied, expected) in cases {
            let mut rng = entropy();
            let mut req = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
            let mut state = RequestState::default();
            let key = write_handshake(
                &mut req,
                &mut state,
                &hdrs(&[supplied]),
                &mut rng,
                None,
            )
            .expect("composes");
            assert_eq!(
                req.as_slice(),
                expected,
                "with {supplied:?} supplied, got {}",
                String::from_utf8_lossy(req.as_slice())
                    .replace("\r\n", "\\r\\n")
            );
            // When the application supplies the KEY, the value on the wire is
            // theirs -- so that is what a response check must hash.
            if supplied.starts_with("Sec-WebSocket-Key") {
                assert_eq!(key, "bXlub25jZW1pbmVvbmx5");
            } else {
                assert_eq!(key, "NDMyMTUzMjE2MzIxNzMyMQ==");
            }
            // The flags are set regardless of which lines were emitted.
            assert!(state.http_hd_upgrade);
            assert_eq!(state.upgr101, Upgrade101::WebSocket);
        }

        // All three supplied: nothing is emitted, and the flags are STILL set,
        // because `lib/ws.c:1296-1298` runs unconditionally after the loop.
        let mut rng = entropy();
        let mut req = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
        let mut state = RequestState::default();
        write_handshake(
            &mut req,
            &mut state,
            &hdrs(&[
                "Upgrade: websocket",
                "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Key: bXluYW1laXNteWtleQ==",
            ]),
            &mut rng,
            None,
        )
        .expect("composes");
        assert!(req.as_slice().is_empty());
        assert!(state.http_hd_upgrade);
        assert!(state.upgrade_in_progress);
    }

    #[test]
    fn a_header_name_is_not_matched_by_a_longer_one() {
        // `Curl_headersep` is what stops `-H "Upgrade-Insecure-Requests: 1"`
        // from suppressing `Upgrade:`. Consumed from `crate::transfer`, and
        // asserted here because getting it wrong drops a handshake header.
        let mut rng = entropy();
        let mut req = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
        let mut state = RequestState::default();
        write_handshake(
            &mut req,
            &mut state,
            &hdrs(&[
                "Upgrade-Insecure-Requests: 1",
                "Sec-WebSocket-Version-Extra: 9",
            ]),
            &mut rng,
            None,
        )
        .expect("composes");
        assert_eq!(req.as_slice(), TEST2300_HANDSHAKE);
    }

    #[test]
    fn an_over_long_encoded_nonce_is_failed_init_and_never_a_panic() {
        // `lib/ws.c:1284-1288`: `DEBUGASSERT(randlen < sizeof(keyval))` plus a
        // release-build `CURLE_FAILED_INIT`. The bound is 40 bytes including the
        // terminator, and a 16-byte nonce encodes to 24 characters, so the guard
        // is unreachable through the public path -- which is why it is asserted
        // against the CONSTANT rather than by feeding a longer nonce that
        // `WS_NONCE_LEN` forbids.
        assert_eq!(WS_KEYVAL_MAX, 40);
        assert_eq!(WS_NONCE_LEN, 16);
        let encoded_len = base64::encode(&[0_u8; WS_NONCE_LEN])
            .expect("encodes")
            .len();
        assert_eq!(encoded_len, 24, "4 * ceil(16/3) with padding");
        assert!(
            encoded_len < WS_KEYVAL_MAX,
            "the guard must never fire for a well-formed nonce"
        );

        // And the guard's own arithmetic, exercised directly: an encoded value
        // of 40 bytes or more is refused. The C's test is `>=`, not `>`, because
        // the array has to hold a terminator.
        let too_long = base64::encode(&[0_u8; 30]).expect("encodes");
        assert!(too_long.len() >= WS_KEYVAL_MAX);
        // The refusal is a returned code; nothing panics and nothing aborts.
        assert_eq!(
            keyval_bound(too_long.len()),
            Err(CURLcode::FailedInit),
            "an over-long key is FailedInit"
        );
        assert_eq!(keyval_bound(encoded_len), Ok(()));
    }

    /// `lib/ws.c:1285`'s comparison, extracted so the bound can be asserted
    /// without forging a nonce the protocol does not permit.
    fn keyval_bound(encoded_len: usize) -> CodeResult<()> {
        if encoded_len >= WS_KEYVAL_MAX {
            return Err(CURLcode::FailedInit);
        }
        Ok(())
    }

    #[test]
    fn the_upgrade_writer_seam_reports_the_key_it_sent() {
        // The seam `protocols/http1.rs`'s `H1_HD_UPGRADE` slot calls.
        let mut rng = entropy();
        let mut upgrade = WsUpgrade::new(&mut rng);
        assert_eq!(upgrade.sent_key(), None, "no key before the handshake");

        let mut req = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
        let mut state = RequestState::default();

        // `Curl_http2_request_upgrade` first, which this module does not own and
        // which therefore contributes nothing.
        upgrade.h2c(&mut req, &mut state).expect("no h2c bytes");
        assert!(req.as_slice().is_empty());
        assert!(!state.http_hd_h2_settings);

        upgrade
            .websocket(&mut req, &mut state, &[])
            .expect("the handshake composes");
        assert_eq!(req.as_slice(), TEST2300_HANDSHAKE);
        assert_eq!(upgrade.sent_key(), Some("NDMyMTUzMjE2MzIxNzMyMQ=="));
    }

    #[test]
    fn the_handshake_traces_under_the_ws_feature_name() {
        // The trace name is `Curl_trc_feat_ws`'s at `lib/curl_trc.c:480`,
        // consumed from `crate::trace` and never spelled here.
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let mut config = TraceConfig::new();
        config.set_feature_level(TraceFeature::Ws, TraceLevel::Info);
        let state = TraceState {
            verbose: true,
            feat: None,
            ids: TraceIds::new(0, 0),
        };
        {
            let mut tracer = Tracer::new(&config, &mut sink).with_state(state);
            let mut rng = entropy();
            let mut req = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
            let mut request_state = RequestState::default();
            write_handshake(
                &mut req,
                &mut request_state,
                &[],
                &mut rng,
                Some(&mut tracer),
            )
            .expect("composes");
        }
        let text = String::from_utf8(sink.into_inner()).expect("utf-8");
        assert!(text.contains(TraceFeature::Ws.name()), "{text}");
        assert_eq!(TraceFeature::Ws.name(), "WS");
        assert!(text.contains("NDMyMTUzMjE2MzIxNzMyMQ=="), "{text}");
    }

    // -- 5. the response check ---------------------------------------------

    #[test]
    fn the_accept_key_is_rfc_6455_section_1_3s_worked_example() {
        // RFC 6455 quotes `dGhlIHNhbXBsZSBub25jZQ==` ->
        // `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`, and `lib/ws.c:1361-1363` quotes the
        // algorithm: base64(SHA-1(key + GUID)).
        assert_eq!(
            accept_key(b"dGhlIHNhbXBsZSBub25jZQ==").expect("hashes"),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        // The GUID is a wire-bearing literal and is asserted character for
        // character, because a single wrong hex digit would be invisible.
        assert_eq!(WS_GUID, b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        assert_eq!(WS_GUID.len(), 36);
        // And the key `tests/data/test2300` sends hashes to this, which is what
        // makes the fixture's own answer demonstrably wrong -- see below.
        assert_eq!(
            accept_key(b"NDMyMTUzMjE2MzIxNzMyMQ==").expect("hashes"),
            "Dut04YXKjDKbXFLrc+AVmMeFsWM="
        );
    }

    #[test]
    fn a_correct_accept_header_matches_and_a_wrong_one_does_not() {
        let key = b"dGhlIHNhbXBsZSBub25jZQ==";
        let good = ResponseCheck::of(
            key,
            &hdrs(&["Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="]),
            false,
            false,
        );
        assert_eq!(good.accept, AcceptVerdict::Matches);
        assert!(!good.has_violation());
        assert_eq!(good.rfc_verdict(), Ok(()));

        let bad = ResponseCheck::of(
            key,
            &hdrs(&["Sec-WebSocket-Accept: HkPsVga7+8LuxM4RGQ5p9tZHeYs="]),
            false,
            false,
        );
        assert_eq!(bad.accept, AcceptVerdict::Mismatch);
        assert!(bad.has_violation());
        assert_eq!(bad.rfc_verdict(), Err(CURLcode::WeirdServerReply));

        // A response with no `Sec-WebSocket-Accept` at all.
        let missing =
            ResponseCheck::of(key, &hdrs(&["Server: test/fake"]), false, false);
        assert_eq!(missing.accept, AcceptVerdict::Missing);
        assert!(missing.has_violation());

        // The header name is matched case-insensitively, as HTTP requires.
        let odd_case = ResponseCheck::of(
            key,
            &hdrs(&["sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="]),
            false,
            false,
        );
        assert_eq!(odd_case.accept, AcceptVerdict::Matches);
        // But the VALUE is not: base64 is case-sensitive.
        let folded = ResponseCheck::of(
            key,
            &hdrs(&["Sec-WebSocket-Accept: S3PPLMBITXAQ9KYGZZHZRBK+XOO="]),
            false,
            false,
        );
        assert_eq!(folded.accept, AcceptVerdict::Mismatch);
    }

    #[test]
    fn an_unsolicited_extension_or_subprotocol_is_a_violation() {
        let key = b"dGhlIHNhbXBsZSBub25jZQ==";
        let accept = "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

        // `lib/ws.c:1366-1370`: *"the server has indicated an extension not
        // requested by the client"*.
        let extension = ResponseCheck::of(
            key,
            &hdrs(&[accept, "Sec-WebSocket-Extensions: permessage-deflate"]),
            false,
            false,
        );
        assert!(extension.unsolicited_extensions);
        assert!(!extension.unsolicited_protocol);
        assert_eq!(extension.rfc_verdict(), Err(ResponseCheck::VIOLATION));

        // `:1372-1376`: the same for a subprotocol.
        let protocol = ResponseCheck::of(
            key,
            &hdrs(&[accept, "Sec-WebSocket-Protocol: chat"]),
            false,
            false,
        );
        assert!(protocol.unsolicited_protocol);
        assert_eq!(protocol.rfc_verdict(), Err(ResponseCheck::VIOLATION));

        // "Unsolicited" is the whole point: a client that ASKED is not
        // violated, which is why the two predicates are parameters.
        let asked = ResponseCheck::of(
            key,
            &hdrs(&[
                accept,
                "Sec-WebSocket-Extensions: permessage-deflate",
                "Sec-WebSocket-Protocol: chat",
            ]),
            true,
            true,
        );
        assert!(!asked.unsolicited_extensions);
        assert!(!asked.unsolicited_protocol);
        assert!(!asked.has_violation());

        // And the code is the one the C itself uses for the one `101`
        // obligation it does enforce (`lib/http.c:3934`).
        assert_eq!(ResponseCheck::VIOLATION, CURLcode::WeirdServerReply);
        assert_eq!(ResponseCheck::VIOLATION as i32, 8);
    }

    #[test]
    fn curls_verdict_tolerates_every_violation_and_that_is_measured() {
        // THE fixture-compatibility test, and the reason this module separates
        // analysis from policy. `tests/data/test2300` and its 27 siblings answer
        // `HkPsVga7+8LuxM4RGQ5p9tZHeYs=`, which is NOT the hash of the key those
        // same fixtures require curl to send. A C curl passes them; enforcing
        // the check would fail all 28, and specification 0.8.1 makes a failing
        // fixture an implementation defect rather than a fixture to edit.
        let fixture_key = b"NDMyMTUzMjE2MzIxNzMyMQ==";
        let fixture_accept = "HkPsVga7+8LuxM4RGQ5p9tZHeYs=";
        assert_ne!(
            accept_key(fixture_key).expect("hashes"),
            fixture_accept,
            "if these ever agree, upstream changed the fixtures"
        );

        let check = ResponseCheck::of(
            fixture_key,
            &hdrs(&[
                &format!("Sec-WebSocket-Accept: {fixture_accept}"),
                "Sec-WebSocket-Extensions: permessage-deflate",
                "Sec-WebSocket-Protocol: chat",
            ]),
            false,
            false,
        );
        assert!(check.has_violation(), "all three obligations are violated");
        assert_eq!(check.rfc_verdict(), Err(ResponseCheck::VIOLATION));
        assert_eq!(
            check.curl_verdict(),
            Ok(()),
            "curl 8.19.0-DEV tolerates all three: lib/ws.c:1359-1377 is comments"
        );
    }

    #[test]
    fn a_header_value_is_split_and_trimmed_but_never_re_cased() {
        assert_eq!(header_value("Sec-WebSocket-Accept: abc="), "abc=");
        assert_eq!(header_value("Sec-WebSocket-Accept:abc="), "abc=");
        assert_eq!(header_value("Sec-WebSocket-Accept: \t abc= "), "abc=");
        // curl's `-H "Name;"` convention, which `Curl_headersep` admits.
        assert_eq!(header_value("Sec-WebSocket-Accept;"), "");
        assert_eq!(header_value("no-separator-at-all"), "");
        // Case is preserved: base64 is case-sensitive.
        assert_eq!(header_value("X: AbC"), "AbC");
    }

    // -- 6. accepting the 101 ----------------------------------------------

    #[test]
    fn accepting_a_101_reports_the_c_s_decisions() {
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default();
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let response = hdrs(&[
            "Server: test/fake",
            "Upgrade: websocket",
            "Connection: Upgrade",
        ]);

        let outcome =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                accept(
                    &mut ws,
                    b"\x89\x00",
                    "NDMyMTUzMjE2MzIxNzMyMQ==",
                    &response,
                    false,
                    cx,
                )
            })
            .expect("the upgrade is accepted");

        // `lib/ws.c:1437-1438` and `:1381-1390`.
        assert_eq!(outcome.upgr101, Upgrade101::Received);
        assert!(outcome.header_done);
        assert!(outcome.install_decoder);
        // Callback mode: the tail bytes go to the client writer, not the queue.
        assert!(!outcome.stop_receiving);
        assert!(outcome.forward_received);
        assert!(!outcome.install_encoder);
        assert_eq!(ws.recvbuf_len(), 0);
        // The obligation report survives, even though it changed nothing.
        assert_eq!(outcome.check.accept, AcceptVerdict::Missing);
    }

    #[test]
    fn connect_only_queues_the_tail_and_stops_receiving() {
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default().with_connect_only(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);

        let outcome =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                accept(&mut ws, b"\x81\x03txt", "key", &[], false, cx)
            })
            .expect("accepted");

        // `lib/ws.c:1392-1403`: the frame bytes that arrived with the `101` are
        // queued for `curl_ws_recv`, and the transfer reads no more content.
        assert!(outcome.stop_receiving);
        assert!(!outcome.forward_received);
        assert_eq!(ws.recvbuf_len(), 5);
    }

    #[test]
    fn a_put_installs_the_encoder_unless_raw_mode_is_set() {
        let clock = clock();
        for raw in [false, true] {
            let (mut chain, _state) = connected_chain(&clock);
            let settings = WsSettings::default().with_options(if raw {
                CURLWS_RAW_MODE
            } else {
                0
            });
            let mut rng = entropy();
            let mut ws = WebSocket::new(&settings);
            let outcome =
                with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                    accept(&mut ws, b"", "key", &[], true, cx)
                })
                .expect("accepted");
            // `lib/ws.c:1405-1427`.
            assert_eq!(outcome.install_encoder, !raw);
            assert!(outcome.restart_upload);
            // No tail bytes, so nothing to forward.
            assert!(!outcome.forward_received);
        }
    }

    #[test]
    fn a_reused_connection_is_reset_but_keeps_its_send_queue() {
        // `lib/ws.c:1354-1358`: `Curl_bufq_reset(&ws->recvbuf)` plus a decoder
        // and encoder reset. `sendbuf` is deliberately NOT reset.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        ws.queue_received(b"\x81\x03txt").expect("queued");
        with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
            ws_start_frame(&mut ws, CURLWS_BINARY, 8, cx).expect("head");
        });
        assert_eq!(ws.recvbuf_len(), 5);
        assert!(ws.sendbuf_len() > 0);
        assert_ne!(ws.encoder().payload_remain(), 0);

        ws.reset_for_reuse();
        assert_eq!(ws.recvbuf_len(), 0, "recvbuf is reset");
        assert_eq!(ws.encoder().payload_remain(), 0, "the encoder is reset");
        assert!(ws.sendbuf_len() > 0, "sendbuf survives, as the C leaves it");
        assert!(sent(&state).is_empty(), "nothing was flushed");
    }

    // -- 7. the frame encoder: the byte oracles ----------------------------

    #[test]
    fn the_five_frame_types_of_test2700_are_encoded_byte_for_byte() {
        // `tests/data/test2700`'s `<protocol>` block, which is the exact echo of
        // the server's five frames with masking added. The fixture sets
        // `CURL_WS_FORCE_ZERO_MASK=1`, so the mask is `00 00 00 00` and the
        // payload passes through unchanged -- which is what makes the frame
        // HEADS legible in the expectation:
        //
        //   %hex[%81%83%00%00%00%00txt]hex%
        //   %hex[%82%83%00%00%00%00bin]hex%
        //   %hex[%89%84%00%00%00%00ping]hex%
        //   %hex[%8a%84%00%00%00%00pong]hex%
        //   %hex[%88%87%00%00%00%00%03%e8close]hex%
        let clock = clock();
        let settings = WsSettings::default().with_zero_mask(true);
        #[rustfmt::skip]
        let cases: [(i32, &[u8], &[u8]); 5] = [
            (CURLWS_TEXT,   b"txt",  b"\x81\x83\x00\x00\x00\x00txt"),
            (CURLWS_BINARY, b"bin",  b"\x82\x83\x00\x00\x00\x00bin"),
            (CURLWS_PING,   b"ping", b"\x89\x84\x00\x00\x00\x00ping"),
            (CURLWS_PONG,   b"pong", b"\x8a\x84\x00\x00\x00\x00pong"),
            (
                CURLWS_CLOSE,
                b"\x03\xe8close",
                b"\x88\x87\x00\x00\x00\x00\x03\xe8close",
            ),
        ];
        for (flags, payload, expected) in cases {
            let (mut chain, state) = connected_chain(&clock);
            let mut rng = entropy();
            let mut ws = WebSocket::new(&settings);
            let sent_len =
                with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
                    ws_send(&mut ws, payload, 0, flags, true, cx)
                })
                .expect("the frame is sent");
            assert_eq!(
                sent_len,
                payload.len(),
                "the count is PAYLOAD bytes, never framing"
            );
            assert_eq!(
                sent(&state),
                expected,
                "{}: got [{}], want [{}]",
                frame_flag_names(flags),
                shown(&sent(&state)),
                shown(expected)
            );
        }
    }

    #[test]
    fn a_zero_length_pong_matches_test2302_including_its_mask() {
        // `tests/data/test2302` expects `%hex[%8a%808321]hex%`: a final PONG
        // (0x8a), a masked zero-length payload (0x80), and the four mask bytes
        // `8321`. The mask is the FIFTH draw of the `CURL_ENTROPY=12345678`
        // stream, the first four having gone to the 16-byte nonce -- so this
        // asserts that the handshake and the mask share one injected generator,
        // in order.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default();
        let mut rng = entropy();

        // Draw the nonce first, exactly as a real handshake does.
        let mut req = DynBuf::new(crate::util::dynbuf::DYN_HTTP_REQUEST);
        let mut request_state = RequestState::default();
        let key =
            write_handshake(&mut req, &mut request_state, &[], &mut rng, None)
                .expect("composes");
        assert_eq!(key, "NDMyMTUzMjE2MzIxNzMyMQ==");

        let mut ws = WebSocket::new(&settings);
        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            ws_send(&mut ws, b"", 0, CURLWS_PONG, true, cx).expect("sent");
        });

        assert_eq!(
            sent(&state),
            b"\x8a\x80\x38\x33\x32\x31",
            "got [{}]",
            shown(&sent(&state))
        );
        assert_eq!(ws.encoder().mask(), *b"8321");
    }

    #[test]
    fn all_three_payload_length_forms_are_big_endian_and_masked() {
        // `lib/ws.c:874-896`. The thresholds are the C's: > 65535 selects the
        // 64-bit form, >= 126 the 16-bit form, and every length byte carries
        // `WSBIT_MASK` because a client frame is always masked.
        let clock = clock();
        let settings = WsSettings::default().with_zero_mask(true);
        #[rustfmt::skip]
        let cases: [(i64, &[u8]); 6] = [
            // 7-bit form, including both edges.
            (0,      b"\x82\x80\x00\x00\x00\x00"),
            (125,    b"\x82\xfd\x00\x00\x00\x00"),
            // 16-bit form: 126 is the first length that needs it.
            (126,    b"\x82\xfe\x00\x7e\x00\x00\x00\x00"),
            (65_535, b"\x82\xfe\xff\xff\x00\x00\x00\x00"),
            // 64-bit form: 65536 is the first length that needs it.
            (65_536, b"\x82\xff\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            (
                0x0102_0304_0506_0708,
                b"\x82\xff\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00",
            ),
        ];
        for (len, expected) in cases {
            let (mut chain, state) = connected_chain(&clock);
            let mut rng = entropy();
            let mut ws = WebSocket::new(&settings);
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_start_frame(&mut ws, CURLWS_BINARY, len, cx)
                    .expect("the head is buffered");
                ws.flush(cx).expect("the head reaches the transport");
            });
            assert_eq!(
                sent(&state),
                expected,
                "len={len}: got [{}], want [{}]",
                shown(&sent(&state)),
                shown(expected)
            );
            // The MASK bit is set in every one of them.
            assert_ne!(sent(&state)[1] & WSBIT_MASK, 0);
        }
    }

    #[test]
    fn the_payload_is_masked_with_a_rotating_index() {
        // `lib/ws.c:965-975`: `buf[i] ^ enc->mask[enc->xori]` with
        // `enc->xori = (enc->xori + 1) & 3`. Asserted against a KNOWN mask, so
        // the arithmetic is checked rather than merely exercised.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default();
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        // Six bytes, so the four-byte mask wraps twice.
        let payload = b"abcdef";
        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            ws_send(&mut ws, payload, 0, CURLWS_BINARY, true, cx)
                .expect("sent");
        });

        let mask = ws.encoder().mask();
        // The first draw of this stream is `4321`, since no nonce was taken.
        assert_eq!(mask, *b"4321");
        let bytes = sent(&state);
        assert_eq!(bytes.len(), 2 + 4 + payload.len());
        assert_eq!(&bytes[..2], b"\x82\x86");
        assert_eq!(&bytes[2..6], &mask);
        for (index, byte) in payload.iter().enumerate() {
            assert_eq!(
                bytes[6 + index],
                byte ^ mask[index % 4],
                "byte {index} must be masked with mask[{}]",
                index % 4
            );
        }
    }

    #[test]
    fn fragmentation_uses_cont_and_the_offset_flag() {
        // Two calls that build ONE message: the first declares a 10-byte frame
        // through `CURLWS_OFFSET` and supplies five bytes, the second supplies
        // the rest. `lib/ws.c:1063-1066` is what makes the head describe
        // `fragsize` rather than `buflen`.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            let first = ws_send(
                &mut ws,
                b"01234",
                10,
                CURLWS_BINARY | CURLWS_OFFSET,
                true,
                cx,
            )
            .expect("the first half is sent");
            assert_eq!(first, 5);
            // The frame still owes five bytes, which is what makes a second
            // `ws_start_frame` refuse.
            assert_eq!(ws.encoder().payload_remain(), 5);
            assert_eq!(
                ws_start_frame(&mut ws, CURLWS_BINARY, 4, cx),
                Err(CURLcode::SendError),
                "a frame that still owes payload cannot be replaced"
            );
            let second = ws_send(
                &mut ws,
                b"56789",
                0,
                CURLWS_BINARY | CURLWS_OFFSET,
                true,
                cx,
            )
            .expect("the second half is sent");
            assert_eq!(second, 5);
            assert_eq!(ws.encoder().payload_remain(), 0);
        });

        // ONE head declaring ten bytes, then ten payload bytes.
        assert_eq!(
            sent(&state),
            b"\x82\x8a\x00\x00\x00\x000123456789",
            "got [{}]",
            shown(&sent(&state))
        );
    }

    #[test]
    fn a_continued_text_message_switches_to_cont_frames() {
        // `lib/ws.c:850-859`: `contfragment` is set by a data frame carrying
        // `CURLWS_CONT` and read by the NEXT frame's conversion, which is what
        // turns a second TEXT into a CONT.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            // First fragment: TEXT, not final.
            ws_send(&mut ws, b"ab", 0, CURLWS_TEXT | CURLWS_CONT, true, cx)
                .expect("first");
            assert!(ws.encoder().contfragment());
            // Second fragment: still not final, so opcode 0x00.
            ws_send(&mut ws, b"cd", 0, CURLWS_TEXT | CURLWS_CONT, true, cx)
                .expect("second");
            // Final fragment: opcode 0x00 with FIN.
            ws_send(&mut ws, b"ef", 0, CURLWS_TEXT, true, cx).expect("last");
            assert!(!ws.encoder().contfragment());
        });

        #[rustfmt::skip]
        let expected: &[u8] = b"\x01\x82\x00\x00\x00\x00ab\
                                \x00\x82\x00\x00\x00\x00cd\
                                \x80\x82\x00\x00\x00\x00ef";
        assert_eq!(
            sent(&state),
            expected,
            "got [{}], want [{}]",
            shown(&sent(&state)),
            shown(expected)
        );
    }

    #[test]
    fn raw_mode_bypasses_the_framing_entirely() {
        // `lib/ws.c:1806-1827`: no head, no mask, and the application's bytes
        // reach the wire unchanged.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_options(CURLWS_RAW_MODE);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            let n = ws_send(&mut ws, b"\x81\x03raw", 0, 0, true, cx)
                .expect("raw bytes are sent");
            assert_eq!(n, 5);
            // `:1821-1824` -- fragsize and flags MUST be zero in raw mode.
            assert_eq!(
                ws_send(&mut ws, b"x", 4, 0, true, cx),
                Err(CURLcode::BadFunctionArgument)
            );
            assert_eq!(
                ws_send(&mut ws, b"x", 0, CURLWS_TEXT, true, cx),
                Err(CURLcode::BadFunctionArgument)
            );
            // `:1876-1879` -- and a frame cannot be started at all.
            assert_eq!(
                ws_start_frame(&mut ws, CURLWS_TEXT, 3, cx),
                Err(CURLcode::FailedInit),
                "raw mode is FailedInit here, not SendError"
            );
        });
        assert_eq!(sent(&state), b"\x81\x03raw");
    }

    #[test]
    fn an_over_long_control_frame_is_too_large_in_both_directions() {
        // `lib/ws.c:861-872`: PING, PONG and CLOSE are capped at 125 bytes and
        // the code is `CURLE_TOO_LARGE`, not `CURLE_SEND_ERROR`.
        let clock = clock();
        let settings = WsSettings::default().with_zero_mask(true);
        for flag in [CURLWS_PING, CURLWS_PONG, CURLWS_CLOSE] {
            let (mut chain, _state) = connected_chain(&clock);
            let mut rng = entropy();
            let mut ws = WebSocket::new(&settings);
            let oversized = vec![b'x'; WS_MAX_CNTRL_LEN + 1];
            with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
                assert_eq!(
                    ws_send(&mut ws, &oversized, 0, flag, true, cx),
                    Err(CURLcode::TooLarge),
                    "{}",
                    frame_flag_names(flag)
                );
            });
            // And exactly 125 is accepted.
            let (mut chain, _state) = connected_chain(&clock);
            let mut rng = entropy();
            let mut ws = WebSocket::new(&settings);
            let at_limit = vec![b'x'; WS_MAX_CNTRL_LEN];
            with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
                ws_send(&mut ws, &at_limit, 0, flag, true, cx)
                    .expect("125 bytes is legal");
            });
        }
        assert_eq!(WS_MAX_CNTRL_LEN, 125);
    }

    #[test]
    fn the_two_caller_invariants_of_a_continued_send_are_enforced() {
        // `lib/ws.c:1041-1056`, both with `CURLE_BAD_FUNCTION_ARGUMENT`.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            // Declare ten bytes and supply four.
            ws_send(
                &mut ws,
                b"0123",
                10,
                CURLWS_BINARY | CURLWS_OFFSET,
                true,
                cx,
            )
            .expect("first");
            assert_eq!(ws.encoder().payload_remain(), 6);
            // Overrunning the declared frame.
            let too_much = vec![b'y'; 12];
            assert_eq!(
                ws_send(&mut ws, &too_much, 0, CURLWS_BINARY, true, cx),
                Err(CURLcode::BadFunctionArgument),
                "a buffer longer than the frame owes is refused"
            );
        });
        assert!(!sent(&state).is_empty());
    }

    // -- 8. the first head byte, both ways ---------------------------------

    #[test]
    fn every_arm_of_the_received_first_byte_switch_is_the_c_s() {
        // `lib/ws.c:150-227`, arm by arm. `cont_flags` is the second input, and
        // half the arms depend on it.
        let resuming = CURLWS_TEXT | CURLWS_CONT;

        // 0x00 / 0x80: CONT, which needs an open message.
        assert_eq!(
            firstbyte_to_flags(0x00, resuming, None),
            Ok(CURLWS_TEXT | CURLWS_CONT)
        );
        assert_eq!(firstbyte_to_flags(0x80, resuming, None), Ok(CURLWS_TEXT));
        assert_eq!(
            firstbyte_to_flags(0x00, 0, None),
            Err(CURLcode::RecvError),
            "no ongoing fragmented message to resume"
        );
        assert_eq!(firstbyte_to_flags(0x80, 0, None), Err(CURLcode::RecvError));

        // 0x01 / 0x81 TEXT and 0x02 / 0x82 BINARY, refused WHILE a message is
        // open.
        assert_eq!(
            firstbyte_to_flags(0x01, 0, None),
            Ok(CURLWS_TEXT | CURLWS_CONT)
        );
        assert_eq!(firstbyte_to_flags(0x81, 0, None), Ok(CURLWS_TEXT));
        assert_eq!(
            firstbyte_to_flags(0x02, 0, None),
            Ok(CURLWS_BINARY | CURLWS_CONT)
        );
        assert_eq!(firstbyte_to_flags(0x82, 0, None), Ok(CURLWS_BINARY));
        for byte in [0x01, 0x81, 0x02, 0x82] {
            assert_eq!(
                firstbyte_to_flags(byte, resuming, None),
                Err(CURLcode::RecvError),
                "{byte:#04x} interrupts a fragmented message"
            );
        }

        // Control frames: final only.
        assert_eq!(firstbyte_to_flags(0x88, 0, None), Ok(CURLWS_CLOSE));
        assert_eq!(firstbyte_to_flags(0x89, 0, None), Ok(CURLWS_PING));
        assert_eq!(firstbyte_to_flags(0x8a, 0, None), Ok(CURLWS_PONG));
        for byte in [0x08, 0x09, 0x0a] {
            assert_eq!(
                firstbyte_to_flags(byte, 0, None),
                Err(CURLcode::RecvError),
                "{byte:#04x} is a fragmented control frame"
            );
        }
        // A control frame is accepted WHILE a data message is open, and does not
        // disturb it -- which is the `cont_flags` asymmetry of `:379-383`.
        assert_eq!(firstbyte_to_flags(0x89, resuming, None), Ok(CURLWS_PING));

        // Reserved bits and reserved opcodes are BOTH refused, with different
        // messages in the C; here the distinction is which branch runs.
        for byte in [0x40, 0x20, 0x10, 0xc1] {
            assert_eq!(
                firstbyte_to_flags(byte, 0, None),
                Err(CURLcode::RecvError),
                "{byte:#04x} sets a reserved bit"
            );
        }
        for byte in [0x83, 0x87, 0x8b, 0x8f] {
            assert_eq!(
                firstbyte_to_flags(byte, 0, None),
                Err(CURLcode::RecvError),
                "{byte:#04x} is a reserved opcode"
            );
        }
        assert_eq!(WSBIT_RSV_MASK, 0x70);
    }

    #[test]
    fn every_arm_of_the_sent_first_byte_switch_is_the_c_s() {
        // `lib/ws.c:229-290`. `CURLWS_OFFSET` is masked out first, so it never
        // changes the answer.
        for extra in [0, CURLWS_OFFSET] {
            assert_eq!(
                flags_to_firstbyte(CURLWS_TEXT | extra, false, None),
                Ok(0x81)
            );
            assert_eq!(
                flags_to_firstbyte(
                    CURLWS_TEXT | CURLWS_CONT | extra,
                    false,
                    None
                ),
                Ok(0x01)
            );
            assert_eq!(
                flags_to_firstbyte(CURLWS_BINARY | extra, false, None),
                Ok(0x82)
            );
            assert_eq!(
                flags_to_firstbyte(
                    CURLWS_BINARY | CURLWS_CONT | extra,
                    false,
                    None
                ),
                Ok(0x02)
            );
            assert_eq!(
                flags_to_firstbyte(CURLWS_CLOSE | extra, false, None),
                Ok(0x88)
            );
            assert_eq!(
                flags_to_firstbyte(CURLWS_PING | extra, false, None),
                Ok(0x89)
            );
            assert_eq!(
                flags_to_firstbyte(CURLWS_PONG | extra, false, None),
                Ok(0x8a)
            );
        }

        // With a fragment open, a data frame becomes a CONT.
        assert_eq!(flags_to_firstbyte(CURLWS_TEXT, true, None), Ok(0x80));
        assert_eq!(
            flags_to_firstbyte(CURLWS_TEXT | CURLWS_CONT, true, None),
            Ok(0x00)
        );
        assert_eq!(flags_to_firstbyte(CURLWS_BINARY, true, None), Ok(0x80));
        assert_eq!(
            flags_to_firstbyte(CURLWS_BINARY | CURLWS_CONT, true, None),
            Ok(0x00)
        );

        // The two compatibility arms, which differ from each other: no flags at
        // all is a FINAL continuation, `CURLWS_CONT` alone is a non-final one.
        assert_eq!(flags_to_firstbyte(0, true, None), Ok(0x80));
        assert_eq!(flags_to_firstbyte(CURLWS_CONT, true, None), Ok(0x00));
        // And with nothing open, both are refused.
        assert_eq!(
            flags_to_firstbyte(0, false, None),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(
            flags_to_firstbyte(CURLWS_CONT, false, None),
            Err(CURLcode::BadFunctionArgument)
        );

        // A fragmented control frame is refused whether or not one is open.
        for flag in [CURLWS_CLOSE, CURLWS_PING, CURLWS_PONG] {
            for open in [false, true] {
                assert_eq!(
                    flags_to_firstbyte(flag | CURLWS_CONT, open, None),
                    Err(CURLcode::BadFunctionArgument),
                    "{} must not be fragmented",
                    frame_flag_names(flag)
                );
            }
        }

        // And a combination the C's switch does not name.
        assert_eq!(
            flags_to_firstbyte(CURLWS_TEXT | CURLWS_BINARY, false, None),
            Err(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn the_opcode_vocabulary_and_its_names_are_the_c_s() {
        assert_eq!(Opcode::of(0x81), Some(Opcode::Text));
        assert_eq!(Opcode::of(0x02), Some(Opcode::Binary));
        assert_eq!(Opcode::of(0x88), Some(Opcode::Close));
        assert_eq!(Opcode::of(0x00), Some(Opcode::Cont));
        assert_eq!(Opcode::of(0x89), Some(Opcode::Ping));
        assert_eq!(Opcode::of(0x8a), Some(Opcode::Pong));
        // The ten reserved values.
        for nibble in [0x3, 0x4, 0x5, 0x6, 0x7, 0xb, 0xc, 0xd, 0xe, 0xf] {
            assert_eq!(Opcode::of(nibble), None, "{nibble:#x} is reserved");
        }
        // `ws_frame_name_of_op` (`lib/ws.c:129-147`), including `"BIN"` -- which
        // is NOT `"BINARY"` -- and the `"???"` fallback.
        assert_eq!(Opcode::name_of(0x81), "TEXT");
        assert_eq!(Opcode::name_of(0x82), "BIN");
        assert_eq!(Opcode::name_of(0x80), "CONT");
        assert_eq!(Opcode::name_of(0x88), "CLOSE");
        assert_eq!(Opcode::name_of(0x89), "PING");
        assert_eq!(Opcode::name_of(0x8a), "PONG");
        assert_eq!(Opcode::name_of(0x8f), "???");
        assert_eq!(format!("{}", Opcode::Binary), "BIN");
        // FIN and non-FIN, and which opcodes are control frames.
        assert_eq!(Opcode::Text.fin(), 0x81);
        assert_eq!(Opcode::Text.nonfin(), 0x01);
        assert!(Opcode::Close.is_control());
        assert!(Opcode::Ping.is_control());
        assert!(Opcode::Pong.is_control());
        assert!(!Opcode::Text.is_control());
        assert!(!Opcode::Cont.is_control());
    }

    #[test]
    fn the_payload_remain_arithmetic_reports_a_mismatch_as_none() {
        // `lib/ws.c:654-665`: three conditions answer `-1`, which the callers
        // treat as `CURLE_BAD_FUNCTION_ARGUMENT`.
        assert_eq!(payload_remain(10, 0, 4), Some(6));
        assert_eq!(payload_remain(10, 6, 4), Some(0));
        assert_eq!(payload_remain(0, 0, 0), Some(0));
        assert_eq!(payload_remain(-1, 0, 0), None, "negative total");
        assert_eq!(payload_remain(10, -1, 0), None, "negative offset");
        assert_eq!(
            payload_remain(10, 8, 4),
            None,
            "buffered exceeds remaining"
        );
        // And it cannot be tricked into a plausible answer by an overflow.
        assert_eq!(payload_remain(i64::MAX, 0, usize::MAX), None);
    }

    // -- 9. the decoder ----------------------------------------------------

    /// A sink that records every chunk it is handed.
    #[derive(Debug, Default)]
    struct RecordingSink {
        /// Bytes, flags, offset, total -- one entry per call.
        chunks: Vec<(Vec<u8>, i32, i64, i64)>,
        /// When set, accept at most this many bytes per call.
        cap: Option<usize>,
    }

    impl PayloadSink for RecordingSink {
        fn write(&mut self, frame: DecodedFrame<'_>) -> CodeResult<usize> {
            let take = match self.cap {
                Some(cap) => frame.buf.len().min(cap),
                None => frame.buf.len(),
            };
            self.chunks.push((
                frame.buf.get(..take).unwrap_or(&[]).to_vec(),
                frame.flags,
                frame.payload_offset,
                frame.payload_len,
            ));
            assert_eq!(frame.age, 0, "frame_age is always zero");
            Ok(take)
        }
    }

    /// A queue holding `bytes`, as the network would deliver them.
    fn queued(bytes: &[u8]) -> BufQ {
        let mut queue = BufQ::with_opts(
            WS_CHUNK_SIZE,
            WS_CHUNK_COUNT,
            BufqOpts::SOFT_LIMIT,
        );
        queue.write(bytes).expect("the soft-limited queue accepts");
        queue
    }

    #[test]
    fn a_two_byte_head_frame_decodes_with_its_metadata() {
        let mut dec = WsDecoder::new();
        let mut queue = queued(b"\x81\x05hello");
        let mut sink = RecordingSink::default();
        dec.pass(&mut queue, &mut sink, None).expect("decodes");

        assert_eq!(sink.chunks.len(), 1);
        let (bytes, flags, offset, total) = &sink.chunks[0];
        assert_eq!(bytes, b"hello");
        assert_eq!(*flags, CURLWS_TEXT);
        assert_eq!(*offset, 0);
        assert_eq!(*total, 5);
        assert_eq!(dec.state(), DecState::Init, "the frame completed");
        assert!(queue.is_empty());
    }

    #[test]
    fn the_four_and_ten_byte_head_forms_decode_big_endian_lengths() {
        // `lib/ws.c:448-475`. A 126-byte BINARY frame uses the 16-bit form.
        let payload = vec![b'z'; 126];
        let mut framed = vec![0x82, 126, 0x00, 0x7e];
        framed.extend_from_slice(&payload);
        let mut dec = WsDecoder::new();
        let mut queue = queued(&framed);
        let mut sink = RecordingSink::default();
        dec.pass(&mut queue, &mut sink, None).expect("decodes");
        assert_eq!(sink.chunks.len(), 1);
        assert_eq!(sink.chunks[0].0.len(), 126);
        assert_eq!(sink.chunks[0].3, 126);

        // The 64-bit form, with a length that needs six of its eight bytes to
        // be read correctly.
        let mut head = vec![0x82, 127];
        head.extend_from_slice(&0x0000_0000_0000_012c_i64.to_be_bytes());
        let mut dec = WsDecoder::new();
        let mut queue = queued(&head);
        let mut sink = RecordingSink::default();
        // Only the head is queued, so the payload pass reports Again -- and the
        // LENGTH has still been parsed.
        assert_eq!(dec.pass(&mut queue, &mut sink, None), Err(CURLcode::Again));
        assert_eq!(dec.payload_len(), 300);
        assert_eq!(dec.state(), DecState::Payload);

        // A top byte above 127 is refused: *"frame length longer than 63 bits
        // not supported"*.
        let mut head = vec![0x82, 127, 0x80];
        head.extend_from_slice(&[0; 7]);
        let mut dec = WsDecoder::new();
        let mut queue = queued(&head);
        let mut sink = RecordingSink::default();
        assert_eq!(
            dec.pass(&mut queue, &mut sink, None),
            Err(CURLcode::RecvError)
        );
    }

    #[test]
    fn a_head_split_across_reads_is_resumed_byte_by_byte() {
        // The C consumes head bytes one at a time so that a head split across
        // two network reads needs no re-parse. Driven here by queueing the head
        // in pieces.
        let mut dec = WsDecoder::new();
        let mut sink = RecordingSink::default();
        let mut queue = queued(&[0x82]);
        assert_eq!(
            dec.pass(&mut queue, &mut sink, None),
            Err(CURLcode::Again),
            "one byte is not a head"
        );
        assert_eq!(dec.state(), DecState::Head);
        assert_eq!(dec.frame_flags(), CURLWS_BINARY, "the opcode was read");

        queue.write(&[126, 0x00]).expect("more head");
        assert_eq!(dec.pass(&mut queue, &mut sink, None), Err(CURLcode::Again));
        queue.write(&[0x80]).expect("the last length byte");
        assert_eq!(dec.pass(&mut queue, &mut sink, None), Err(CURLcode::Again));
        assert_eq!(dec.payload_len(), 128, "0x0080 big-endian");
        assert_eq!(dec.state(), DecState::Payload);

        // Then the payload, also in pieces.
        queue.write(&[b'p'; 64]).expect("half the payload");
        assert_eq!(dec.pass(&mut queue, &mut sink, None), Err(CURLcode::Again));
        queue.write(&[b'q'; 64]).expect("the rest");
        dec.pass(&mut queue, &mut sink, None).expect("completes");
        assert_eq!(dec.state(), DecState::Init);
        let collected: usize = sink.chunks.iter().map(|c| c.0.len()).sum();
        assert_eq!(collected, 128);
        // The offsets are cumulative within the frame.
        assert_eq!(sink.chunks[0].2, 0);
        assert_eq!(sink.chunks[1].2, 64);
    }

    #[test]
    fn a_zero_length_frame_still_reaches_the_sink_once() {
        // `lib/ws.c:546-556`, the special case a zero-length PING is.
        let mut dec = WsDecoder::new();
        let mut queue = queued(b"\x89\x00");
        let mut sink = RecordingSink::default();
        dec.pass(&mut queue, &mut sink, None).expect("decodes");
        assert_eq!(sink.chunks.len(), 1);
        assert!(sink.chunks[0].0.is_empty());
        assert_eq!(sink.chunks[0].1, CURLWS_PING);
        assert_eq!(sink.chunks[0].3, 0);
        assert_eq!(dec.state(), DecState::Init);
    }

    #[test]
    fn a_masked_frame_from_a_server_is_fatal() {
        // *"A client MUST close a connection if it detects a masked frame"*
        // (`lib/ws.c:396-401`).
        let mut dec = WsDecoder::new();
        let mut queue = queued(b"\x81\x85\x00\x00\x00\x00hello");
        let mut sink = RecordingSink::default();
        assert_eq!(
            dec.pass(&mut queue, &mut sink, None),
            Err(CURLcode::RecvError)
        );
        // The decoder was RESET, so a following frame is not decoded as a
        // continuation of this one.
        assert_eq!(dec.state(), DecState::Init);
        assert!(!dec.is_resuming());
    }

    #[test]
    fn an_over_long_received_control_frame_is_fatal() {
        // `lib/ws.c:402-419`, three separate checks with three messages. The C's
        // reason for the PING check is worth keeping: *"Accepting overlong pings
        // would mean sending equivalent pongs!"*
        for (first, name) in [(0x89, "PING"), (0x8a, "PONG"), (0x88, "CLOSE")] {
            let mut dec = WsDecoder::new();
            let mut queue = queued(&[first, 126]);
            let mut sink = RecordingSink::default();
            assert_eq!(
                dec.pass(&mut queue, &mut sink, None),
                Err(CURLcode::RecvError),
                "an over-long {name} must be refused"
            );
        }
        // Exactly 125 is legal.
        let mut framed = vec![0x89, 125];
        framed.extend_from_slice(&[b'x'; 125]);
        let mut dec = WsDecoder::new();
        let mut queue = queued(&framed);
        let mut sink = RecordingSink::default();
        dec.pass(&mut queue, &mut sink, None).expect("125 is legal");
    }

    #[test]
    fn a_fragmented_message_carries_cont_flags_across_frames() {
        // Three frames making one TEXT message: 0x01, 0x00, 0x80.
        let mut dec = WsDecoder::new();
        let mut queue = queued(b"\x01\x02ab\x00\x02cd\x80\x02ef");
        let mut sink = RecordingSink::default();

        dec.pass(&mut queue, &mut sink, None).expect("first");
        assert!(dec.is_resuming(), "the message is open");
        dec.pass(&mut queue, &mut sink, None).expect("middle");
        assert!(dec.is_resuming());
        dec.pass(&mut queue, &mut sink, None).expect("last");
        assert!(!dec.is_resuming(), "the final fragment closed it");

        assert_eq!(sink.chunks.len(), 3);
        assert_eq!(sink.chunks[0].1, CURLWS_TEXT | CURLWS_CONT);
        assert_eq!(sink.chunks[1].1, CURLWS_TEXT | CURLWS_CONT);
        assert_eq!(
            sink.chunks[2].1, CURLWS_TEXT,
            "the final fragment clears CURLWS_CONT"
        );
        // A control frame in the middle does not disturb the message.
        let mut queue = queued(b"\x01\x02ab\x89\x00\x80\x02cd");
        let mut dec = WsDecoder::new();
        let mut sink = RecordingSink::default();
        dec.pass(&mut queue, &mut sink, None).expect("first");
        dec.pass(&mut queue, &mut sink, None).expect("the ping");
        assert!(dec.is_resuming(), "a PING must not end the message");
        dec.pass(&mut queue, &mut sink, None).expect("last");
        assert_eq!(sink.chunks[1].1, CURLWS_PING);
        assert_eq!(sink.chunks[2].1, CURLWS_TEXT);
    }

    #[test]
    fn a_sink_with_no_room_stops_the_pass_without_losing_bytes() {
        // A sink that accepts three bytes at a time, over a five-byte frame.
        let mut dec = WsDecoder::new();
        let mut queue = queued(b"\x81\x05hello");
        let mut sink = RecordingSink {
            chunks: Vec::new(),
            cap: Some(3),
        };
        dec.pass(&mut queue, &mut sink, None).expect("completes");
        assert_eq!(sink.chunks.len(), 2);
        assert_eq!(sink.chunks[0].0, b"hel");
        assert_eq!(sink.chunks[1].0, b"lo");
        assert_eq!(sink.chunks[1].2, 3, "the offset advanced");
        assert!(queue.is_empty(), "every byte was consumed");
    }

    #[test]
    fn an_empty_queue_is_again_and_not_a_failure() {
        let mut dec = WsDecoder::new();
        let mut queue = BufQ::with_opts(
            WS_CHUNK_SIZE,
            WS_CHUNK_COUNT,
            BufqOpts::SOFT_LIMIT,
        );
        let mut sink = RecordingSink::default();
        assert_eq!(dec.pass(&mut queue, &mut sink, None), Err(CURLcode::Again));
    }

    #[test]
    fn the_decoder_traces_the_three_shapes_of_its_progress() {
        // `ws_dec_info` (`lib/ws.c:292-320`): nothing at all with no head byte,
        // an opcode-only line with one, a partial line while the head is
        // incomplete, and a payload line once it is complete.
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let mut config = TraceConfig::new();
        config.set_feature_level(TraceFeature::Ws, TraceLevel::Info);
        let state = TraceState {
            verbose: true,
            feat: None,
            ids: TraceIds::new(0, 0),
        };
        {
            let mut tracer = Tracer::new(&config, &mut sink).with_state(state);
            let mut dec = WsDecoder::new();
            let mut queue = queued(b"\x81\x05hello");
            let mut payload_sink = RecordingSink::default();
            dec.pass(&mut queue, &mut payload_sink, Some(&mut tracer))
                .expect("decodes");
        }
        let text = String::from_utf8(sink.into_inner()).expect("utf-8");
        assert!(text.contains("[WS]"), "{text}");
        assert!(text.contains("decoded"), "{text}");
        assert!(text.contains("TEXT"), "{text}");
        assert!(text.contains("payload=0/5"), "{text}");
    }

    // -- 10. the client writer and the automatic PONG -----------------------

    #[test]
    fn the_client_writer_forwards_a_decoded_frame_with_its_metadata() {
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default();
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut writer = WsDecodeWriter::new();
        let mut next = RecordingWriter::default();

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            writer
                .write(&mut ws, b"\x81\x05hello", true, false, &mut next, cx)
                .expect("decodes and forwards");
        });

        assert_eq!(next.decoded.len(), 1);
        assert_eq!(next.decoded[0].0, b"hello");
        let meta = next.decoded[0].1;
        assert_eq!(meta.age, 0);
        assert_eq!(meta.flags, CURLWS_TEXT);
        assert_eq!(meta.offset, 0);
        assert_eq!(meta.len, 5);
        assert_eq!(meta.bytesleft, 0);
        // The metadata was PUBLISHED before the forward, which is what
        // `curl_ws_meta` depends on.
        assert_eq!(*ws.recv_frame(), meta);
        assert_eq!(writer.buffered(), 0);
        assert!(next.passed.is_empty());
    }

    #[test]
    fn the_client_writer_publishes_offsets_across_a_fragmented_message() {
        // `update_meta` (`lib/ws.c:573-586`): `bytesleft` counts what follows
        // THIS chunk, so it reaches zero on the chunk that completes the frame.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default();
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut writer = WsDecodeWriter::new();
        let mut next = RecordingWriter::default();

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            // A ten-byte frame delivered in two network reads.
            writer
                .write(&mut ws, b"\x82\x0a01234", true, false, &mut next, cx)
                .expect("first half");
            writer
                .write(&mut ws, b"56789", true, false, &mut next, cx)
                .expect("second half");
        });

        assert_eq!(next.decoded.len(), 2);
        assert_eq!(next.decoded[0].0, b"01234");
        assert_eq!(next.decoded[0].1.offset, 0);
        assert_eq!(next.decoded[0].1.len, 5);
        assert_eq!(next.decoded[0].1.bytesleft, 5);
        assert_eq!(next.decoded[1].0, b"56789");
        assert_eq!(next.decoded[1].1.offset, 5);
        assert_eq!(next.decoded[1].1.len, 5);
        assert_eq!(next.decoded[1].1.bytesleft, 0);
    }

    #[test]
    fn a_ping_is_answered_with_a_pong_carrying_the_same_payload() {
        // `lib/ws.c:689-697`: *"send back the exact same content as a PONG"*.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut writer = WsDecodeWriter::new();
        let mut next = RecordingWriter::default();

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            writer
                .write(&mut ws, b"\x89\x04ping", true, false, &mut next, cx)
                .expect("decodes");
        });

        // The PONG reached the wire, framed and masked, and the PING was NOT
        // forwarded to the application.
        assert_eq!(
            sent(&state),
            b"\x8a\x84\x00\x00\x00\x00ping",
            "got [{}]",
            shown(&sent(&state))
        );
        assert!(
            next.decoded.is_empty(),
            "an auto-answered PING is not handed to the application"
        );
        assert!(!ws.pending().is_pending(), "the reply was flushed");
    }

    #[test]
    fn noautopong_suppresses_the_reply_and_delivers_the_ping() {
        // `CURLWS_NOAUTOPONG` (`include/curl/websockets.h:90`), read at
        // `lib/ws.c:677`.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_options(CURLWS_NOAUTOPONG);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut writer = WsDecodeWriter::new();
        let mut next = RecordingWriter::default();

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            writer
                .write(&mut ws, b"\x89\x04ping", true, false, &mut next, cx)
                .expect("decodes");
        });

        assert!(sent(&state).is_empty(), "no PONG was sent");
        assert_eq!(next.decoded.len(), 1, "the PING reaches the application");
        assert_eq!(next.decoded[0].0, b"ping");
        assert_eq!(next.decoded[0].1.flags, CURLWS_PING);
    }

    #[test]
    fn a_close_frame_carries_its_status_code_and_reason() {
        // `tests/data/test2700`'s CLOSE is `%88%07%03%e8close`: status 1000
        // (0x03e8) followed by the reason text. The payload is delivered
        // VERBATIM -- curl does not split the status off, and an application
        // reads the first two bytes itself.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default();
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut writer = WsDecodeWriter::new();
        let mut next = RecordingWriter::default();

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            writer
                .write(
                    &mut ws,
                    b"\x88\x07\x03\xe8close",
                    true,
                    false,
                    &mut next,
                    cx,
                )
                .expect("decodes");
        });

        assert_eq!(next.decoded.len(), 1);
        assert_eq!(next.decoded[0].0, b"\x03\xe8close");
        assert_eq!(next.decoded[0].1.flags, CURLWS_CLOSE);
        let status =
            u16::from_be_bytes([next.decoded[0].0[0], next.decoded[0].0[1]]);
        assert_eq!(status, 1000, "a normal closure");
    }

    #[test]
    fn the_client_writer_passes_everything_through_in_raw_mode() {
        // `lib/ws.c:722-723`: raw mode, or a write that is not BODY, goes
        // straight down the chain with its flags unchanged.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let raw = WsSettings::default().with_options(CURLWS_RAW_MODE);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&raw);
        let mut writer = WsDecodeWriter::new();
        let mut next = RecordingWriter::default();

        with_io(&clock, &mut chain, &raw, &mut rng, true, |cx| {
            writer
                .write(&mut ws, b"\x81\x05hello", true, true, &mut next, cx)
                .expect("passes through");
        });
        assert!(next.decoded.is_empty());
        assert_eq!(next.passed.len(), 1);
        assert_eq!(next.passed[0].0, b"\x81\x05hello");
        assert!(next.passed[0].1, "the end-of-stream flag survives");

        // And a non-BODY write is passed through even without raw mode.
        let settings = WsSettings::default();
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut writer = WsDecodeWriter::new();
        let mut next = RecordingWriter::default();
        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            writer
                .write(
                    &mut ws,
                    b"HTTP/1.1 101\r\n",
                    false,
                    false,
                    &mut next,
                    cx,
                )
                .expect("passes through");
        });
        assert_eq!(next.passed.len(), 1);
        assert!(next.decoded.is_empty());
    }

    #[test]
    fn a_partial_frame_is_kept_for_later_rather_than_reported() {
        // `lib/ws.c:749-753`: `CURLE_AGAIN` from the decoder is SUCCESS to the
        // caller, *"we pretend to have written all since we have a copy"*.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default();
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut writer = WsDecodeWriter::new();
        let mut next = RecordingWriter::default();

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            writer
                .write(&mut ws, b"\x81\x05he", true, false, &mut next, cx)
                .expect("a partial frame is not an error");
        });
        assert_eq!(next.decoded.len(), 1, "what arrived was forwarded");
        assert_eq!(next.decoded[0].0, b"he");
        assert_eq!(next.decoded[0].1.bytesleft, 3);
        assert_eq!(writer.buffered(), 0, "the two payload bytes were consumed");
    }

    // -- 11. the upload reader ---------------------------------------------

    #[test]
    fn the_upload_reader_wraps_the_application_s_bytes_in_binary_frames() {
        // `cr_ws_read` (`lib/ws.c:1141-1224`).
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut reader = WsEncodeReader::new();
        let mut next = CannedReader {
            remaining: b"payload".to_vec(),
            cleared: 0,
        };
        let mut buf = [0_u8; 64];

        let (nread, eos) =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                reader.read(&mut ws, &mut buf, &mut next, cx)
            })
            .expect("reads and encodes");

        // Head plus masked payload, handed back through the same buffer.
        assert_eq!(
            &buf[..nread],
            b"\x82\x87\x00\x00\x00\x00payload",
            "got [{}]",
            shown(&buf[..nread])
        );
        assert!(
            eos,
            "the next reader reported end of stream and the queue is dry"
        );
        assert!(reader.is_eos());

        // Every later call is (0, true).
        let (again, still_eos) =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                reader.read(&mut ws, &mut buf, &mut next, cx)
            })
            .expect("reads");
        assert_eq!(again, 0);
        assert!(still_eos);
    }

    #[test]
    fn the_upload_reader_reports_a_dry_source_without_framing_it() {
        // `lib/ws.c:1187-1194`: nothing to convert, so the answer is returned
        // right away rather than becoming an empty frame.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default();
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut reader = WsEncodeReader::new();
        let mut next = CannedReader {
            remaining: Vec::new(),
            cleared: 0,
        };
        let mut buf = [0_u8; 16];

        let (nread, eos) =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                reader.read(&mut ws, &mut buf, &mut next, cx)
            })
            .expect("reads");
        assert_eq!(nread, 0);
        assert!(eos);
        assert_eq!(ws.sendbuf_len(), 0, "no head was written for no payload");
    }

    // -- 12. the four exported entry points --------------------------------

    #[test]
    fn connect_only_is_required_once_the_connection_has_gone() {
        // `lib/ws.c:1544-1550`. The option is required only when the transfer
        // has released its connection -- inside a callback the C proceeds
        // without it, which is what `tests/data/test2301` and `:2302` do.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let mut rng = entropy();

        let without = WsSettings::default();
        with_io(&clock, &mut chain, &without, &mut rng, false, |cx| {
            assert_eq!(
                require_connection(false, cx),
                Err(CURLcode::UnsupportedProtocol),
                "no connection and no CONNECT_ONLY"
            );
            assert_eq!(
                require_connection(true, cx),
                Ok(()),
                "a live connection needs no option"
            );
        });

        let with = WsSettings::default().with_connect_only(true);
        with_io(&clock, &mut chain, &with, &mut rng, false, |cx| {
            assert_eq!(require_connection(false, cx), Ok(()));
        });

        // And both data entry points enforce it.
        let mut ws = WebSocket::new(&without);
        let mut buf = [0_u8; 8];
        with_io(&clock, &mut chain, &without, &mut rng, false, |cx| {
            assert_eq!(
                ws_recv(&mut ws, &mut buf, false, cx),
                Err(CURLcode::UnsupportedProtocol)
            );
            assert_eq!(
                ws_send(&mut ws, b"x", 0, CURLWS_TEXT, false, cx),
                Err(CURLcode::UnsupportedProtocol)
            );
        });
    }

    #[test]
    fn receiving_a_frame_reports_its_payload_and_its_metadata() {
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        feed(&state, b"\x81\x05hello");
        let settings = WsSettings::default().with_connect_only(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut buf = [0_u8; 32];

        let nread =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("receives");

        assert_eq!(nread, 5);
        assert_eq!(&buf[..nread], b"hello");
        let meta = *ws.recv_frame();
        assert_eq!(meta.age, 0);
        assert_eq!(meta.flags, CURLWS_TEXT);
        assert_eq!(meta.offset, 0);
        assert_eq!(meta.bytesleft, 0);
        assert_eq!(meta.len, 5);
    }

    #[test]
    fn receiving_a_ping_answers_it_and_keeps_reading() {
        // `lib/ws.c:1600-1605`: an auto-answered PING collects nothing, so the
        // loop reads on instead of returning an empty frame. Both frames are
        // queued at once, so one call must skip the PING and deliver the TEXT.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        feed(&state, b"\x89\x04ping\x81\x02hi");
        let settings = WsSettings::default()
            .with_connect_only(true)
            .with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut buf = [0_u8; 32];

        let nread =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("receives");

        assert_eq!(nread, 2);
        assert_eq!(&buf[..nread], b"hi");
        assert_eq!(ws.recv_frame().flags, CURLWS_TEXT);
        // The PONG went out with the same payload.
        assert_eq!(
            sent(&state),
            b"\x8a\x84\x00\x00\x00\x00ping",
            "got [{}]",
            shown(&sent(&state))
        );
    }

    #[test]
    fn a_closed_connection_while_receiving_is_got_nothing() {
        // `lib/ws.c:1579-1583`.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default().with_connect_only(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut buf = [0_u8; 8];
        with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
            assert_eq!(
                ws_recv(&mut ws, &mut buf, true, cx),
                Err(CURLcode::GotNothing)
            );
        });
    }

    #[test]
    fn a_frame_larger_than_the_application_buffer_is_delivered_in_pieces() {
        // The `CURLWS_OFFSET` reading of `curl_ws_frame`: each call reports its
        // own `offset` and the `bytesleft` after it, so an application can
        // reassemble without counting.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        feed(&state, b"\x82\x0a0123456789");
        let settings = WsSettings::default().with_connect_only(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut buf = [0_u8; 4];

        let first =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("first piece");
        assert_eq!(first, 4);
        assert_eq!(&buf[..], b"0123");
        assert_eq!(ws.recv_frame().offset, 0);
        assert_eq!(ws.recv_frame().bytesleft, 6);

        let second =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("second piece");
        assert_eq!(second, 4);
        assert_eq!(&buf[..], b"4567");
        assert_eq!(ws.recv_frame().offset, 4);
        assert_eq!(ws.recv_frame().bytesleft, 2);

        let third =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("last piece");
        assert_eq!(third, 2);
        assert_eq!(&buf[..2], b"89");
        assert_eq!(ws.recv_frame().offset, 8);
        assert_eq!(ws.recv_frame().bytesleft, 0, "the frame is complete");
    }

    #[test]
    fn the_metadata_accessor_answers_only_inside_a_callback() {
        // `curl_ws_meta` (`lib/ws.c:1851-1864`): three of its four conjuncts
        // live here, and every one of them can withhold the answer.
        let settings = WsSettings::default();
        let raw = WsSettings::default().with_options(CURLWS_RAW_MODE);
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let mut rng = entropy();
        let ws = WebSocket::new(&settings);

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            assert!(
                ws_meta(&ws, true, cx).is_some(),
                "in a callback, with a connection, not raw"
            );
            assert!(
                ws_meta(&ws, false, cx).is_none(),
                "no connection, no metadata"
            );
        });
        with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
            assert!(
                ws_meta(&ws, true, cx).is_none(),
                "outside a callback, no metadata"
            );
        });
        with_io(&clock, &mut chain, &raw, &mut rng, true, |cx| {
            assert!(ws_meta(&ws, true, cx).is_none(), "raw mode, no metadata");
        });
    }

    #[test]
    fn starting_a_frame_refuses_while_one_is_unfinished() {
        // The public header's own words: *"Errors when a previous frame is not
        // complete, e.g. not all its payload has been added"*
        // (`include/curl/websockets.h:80-82`).
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);

        with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
            ws_start_frame(&mut ws, CURLWS_BINARY, 6, cx)
                .expect("the first head is buffered");
            assert_eq!(ws.encoder().payload_remain(), 6);
            assert_eq!(
                ws_start_frame(&mut ws, CURLWS_BINARY, 3, cx),
                Err(CURLcode::SendError),
                "the previous frame is not finished"
            );
            // Supplying the payload frees the encoder, and then a second frame
            // is accepted.
            ws_send(&mut ws, b"abcdef", 0, CURLWS_BINARY, true, cx)
                .expect("the payload completes the frame");
            assert_eq!(ws.encoder().payload_remain(), 0);
            ws_start_frame(&mut ws, CURLWS_BINARY, 3, cx)
                .expect("a second frame may start");
            ws.flush(cx).expect("flushes");
        });
        assert!(!sent(&state).is_empty());
    }

    // -- 13. the transport seam and the flush ------------------------------

    #[test]
    fn a_blocked_transport_keeps_the_bytes_and_reports_again() {
        // `lib/ws.c:1667-1671`: `CURLE_AGAIN` leaves the queue intact so the
        // caller can poll and flush again, and no frame is left half-described.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);

        state.borrow_mut().writable = false;
        with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
            ws_start_frame(&mut ws, CURLWS_BINARY, 0, cx).expect("head");
            assert_eq!(ws.flush(cx), Err(CURLcode::Again));
        });
        assert!(sent(&state).is_empty(), "nothing reached the wire");
        assert_eq!(ws.sendbuf_len(), 6, "the head is still queued");

        // Once the transport unblocks, the same bytes go out.
        state.borrow_mut().writable = true;
        with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
            ws.flush(cx).expect("flushes");
        });
        assert_eq!(sent(&state), b"\x82\x80\x00\x00\x00\x00");
        assert_eq!(ws.sendbuf_len(), 0);
    }

    #[test]
    fn the_chain_transport_reaches_the_in_memory_filter_both_ways() {
        // The production adapter, over the test transport: no socket, no
        // runtime and no network anywhere in this module's tests.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        feed(&state, b"from the server");
        let mut call = CallCtx::new(&clock);
        let mut io = ChainTransport::new(&mut chain, &mut call);

        let mut buf = [0_u8; 15];
        assert_eq!(io.recv(&mut buf).expect("reads"), 15);
        assert_eq!(&buf, b"from the server");
        assert_eq!(io.send(b"to the server").expect("writes"), 13);
        assert_eq!(sent(&state), b"to the server");
        // A drained transport answers zero rather than an error, which is what
        // `ws_recv` reads as a closed connection.
        assert_eq!(io.recv(&mut buf).expect("drained"), 0);
        // And the adapter is printable without printing the chain.
        assert_eq!(format!("{io:?}"), "ChainTransport");
    }

    #[test]
    fn the_pending_control_slot_holds_exactly_one_frame() {
        // `lib/ws.c:639-643`: *"Overwrite any pending frame with the new one, we
        // keep only one"*.
        let mut pending = PendingControl::new();
        assert!(!pending.is_pending());
        assert!(pending.payload().is_empty());

        pending.store(CURLWS_PONG, b"first").expect("stored");
        assert!(pending.is_pending());
        assert_eq!(pending.frame_type(), CURLWS_PONG);
        assert_eq!(pending.payload(), b"first");

        pending.store(CURLWS_PONG, b"second").expect("replaced");
        assert_eq!(pending.payload(), b"second");

        // The cap is structural: there is nowhere to put a 126th byte.
        assert_eq!(
            pending.store(CURLWS_PONG, &[b'x'; WS_MAX_CNTRL_LEN + 1]),
            Err(CURLcode::BadFunctionArgument)
        );
        pending
            .store(CURLWS_PONG, &[b'x'; WS_MAX_CNTRL_LEN])
            .expect("125 fits");

        pending.clear();
        assert!(!pending.is_pending());
        assert_eq!(pending.frame_type(), 0);
        assert!(pending.payload().is_empty());
    }

    #[test]
    fn a_control_frame_queued_mid_frame_goes_out_before_the_next_head() {
        // `ws_enc_write_head` (`lib/ws.c:937-943`): *"starting a new frame, we
        // want a clean sendbuf. Any pending control frame we can add now as part
        // of the flush."* So a PONG queued while another frame was in flight is
        // emitted BEFORE the next frame's head, never inside its payload.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);

        with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
            // Open a frame that still owes payload.
            ws_start_frame(&mut ws, CURLWS_BINARY, 4, cx).expect("head");
            // A PONG arriving now cannot be encoded yet.
            ws.add_control(b"hi", CURLWS_PONG, cx).expect("queued");
            assert!(ws.pending().is_pending(), "it waits for the frame to end");
            // Supply the payload, which completes the frame.
            ws_send(&mut ws, b"data", 0, CURLWS_BINARY, true, cx)
                .expect("payload");
            assert_eq!(ws.encoder().payload_remain(), 0);
            // The next head flushes the pending control frame first.
            ws_start_frame(&mut ws, CURLWS_BINARY, 0, cx).expect("second head");
            assert!(!ws.pending().is_pending());
            ws.flush(cx).expect("flushes");
        });

        #[rustfmt::skip]
        let expected: &[u8] = b"\x82\x84\x00\x00\x00\x00data\
                                \x8a\x82\x00\x00\x00\x00hi\
                                \x82\x80\x00\x00\x00\x00";
        assert_eq!(
            sent(&state),
            expected,
            "got [{}], want [{}]",
            shown(&sent(&state)),
            shown(expected)
        );
    }

    #[test]
    fn the_settings_overrides_are_clamped_as_the_c_clamps_them() {
        // `lib/ws.c:1334-1341`: the chunk size is parsed with a one-mebibyte
        // ceiling and the default survives a refusal.
        let default = WsSettings::default();
        assert_eq!(default.chunk_size, WS_CHUNK_SIZE);
        assert_eq!(WS_CHUNK_SIZE, 65_535);
        assert_eq!(WS_CHUNK_COUNT, 2);

        assert_eq!(default.with_chunk_size(4096).chunk_size, 4096);
        assert_eq!(
            default.with_chunk_size(1024 * 1024).chunk_size,
            1024 * 1024,
            "exactly the ceiling is accepted"
        );
        assert_eq!(
            default.with_chunk_size(1024 * 1024 + 1).chunk_size,
            WS_CHUNK_SIZE,
            "over the ceiling leaves the default in place"
        );
        assert_eq!(
            default.with_chunk_size(0).chunk_size,
            WS_CHUNK_SIZE,
            "zero would make every chunk both empty and full"
        );

        // And the zero-mask knob is a field, not a `getenv`.
        assert!(!default.force_zero_mask);
        assert!(default.with_zero_mask(true).force_zero_mask);
    }

    #[test]
    fn a_smaller_chunk_size_still_encodes_the_same_bytes() {
        // The chunk size changes how the queue is laid out and must change
        // nothing on the wire. Driven with a chunk smaller than the frame so the
        // payload spans several chunks.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        let settings = WsSettings::default()
            .with_zero_mask(true)
            .with_chunk_size(8);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let payload = b"0123456789abcdef";

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            let n = ws_send(&mut ws, payload, 0, CURLWS_BINARY, true, cx)
                .expect("sent");
            assert_eq!(n, payload.len());
        });

        let mut expected = vec![0x82, 0x90, 0, 0, 0, 0];
        expected.extend_from_slice(payload);
        assert_eq!(
            sent(&state),
            expected,
            "got [{}], want [{}]",
            shown(&sent(&state)),
            shown(&expected)
        );
    }

    #[test]
    fn the_frame_head_buffer_bounds_are_the_c_s() {
        // `uint8_t head[14]` on the send side (`lib/ws.c:833`) and
        // `uint8_t head[10]` on the read side (`:89`): the difference is the
        // four mask bytes a client frame adds and a server frame never has.
        assert_eq!(WS_MAX_SEND_HEAD, 14);
        assert_eq!(WS_MAX_RECV_HEAD, 10);
        assert_eq!(WS_MAX_SEND_HEAD - WS_MAX_RECV_HEAD, 4);
        // The two length thresholds.
        assert_eq!(WS_LEN7_MAX, 125);
        assert_eq!(WS_LEN16_MAX, 65_535);
        // And the bit vocabulary, which reaches the wire byte for byte.
        assert_eq!(WSBIT_FIN, 0x80);
        assert_eq!(WSBIT_MASK, 0x80);
        assert_eq!(WSBIT_RSV1, 0x40);
        assert_eq!(WSBIT_RSV2, 0x20);
        assert_eq!(WSBIT_RSV3, 0x10);
        assert_eq!(WSBIT_OPCODE_MASK, 0x0f);
    }

    #[test]
    fn this_module_never_reaches_for_a_global_generator() {
        // Specification 0.3.3's pattern P12, asserted rather than trusted: two
        // states driven from two independent generators produce different masks,
        // and the same generator twice produces the same one. A thread-local or
        // global RNG would make the second assertion fail and the first
        // accidental.
        let clock = clock();
        let settings = WsSettings::default();
        let mut first_rng = TestRng::from_seed(0x1122_3344);
        let mut second_rng = TestRng::from_seed(0x5566_7788);
        let mut third_rng = TestRng::from_seed(0x1122_3344);

        let mask = |rng: &mut dyn Rng| {
            let (mut chain, _state) = connected_chain(&clock);
            let mut ws = WebSocket::new(&settings);
            with_io(&clock, &mut chain, &settings, rng, false, |cx| {
                ws_start_frame(&mut ws, CURLWS_BINARY, 0, cx).expect("head");
            });
            ws.encoder().mask()
        };

        let first = mask(&mut first_rng);
        let second = mask(&mut second_rng);
        let third = mask(&mut third_rng);
        assert_ne!(first, second, "different generators, different masks");
        assert_eq!(first, third, "the same generator, the same mask");
        // `Curl_rand_bytes`'s byte order is low-byte-first, four bytes per draw
        // (`lib/rand.c:200-214`), which is what makes `8321` follow the nonce.
        assert_eq!(first, 0x1122_3344_u32.to_le_bytes());
    }

    // -- 14. the collector's own decisions ----------------------------------

    #[test]
    fn one_receive_call_reports_one_frame_of_a_fragmented_message() {
        // Two frames of one TEXT message are queued together. `ws_recv` breaks
        // as soon as the collector has written something (`lib/ws.c:1600-1605`),
        // so the FIRST call reports the first fragment with `CURLWS_CONT` still
        // set and the second reports the final fragment without it. The
        // application therefore sees the fragmentation, which is what
        // `CURLWS_CONT` is for.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        feed(&state, b"\x01\x02ab\x80\x02cd");
        let settings = WsSettings::default().with_connect_only(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut buf = [0_u8; 16];

        let first =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("the first fragment");
        assert_eq!(&buf[..first], b"ab");
        assert_eq!(ws.recv_frame().flags, CURLWS_TEXT | CURLWS_CONT);
        assert_eq!(ws.recv_frame().offset, 0);
        assert_eq!(ws.recv_frame().bytesleft, 0, "of THIS frame");

        let second =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("the final fragment");
        assert_eq!(&buf[..second], b"cd");
        assert_eq!(
            ws.recv_frame().flags,
            CURLWS_TEXT,
            "the final fragment clears CURLWS_CONT"
        );
    }

    #[test]
    fn the_metadata_of_a_multi_chunk_read_is_the_first_chunks() {
        // `lib/ws.c:1486-1492` fixes the metadata at `!ctx->bufidx`, so a frame
        // whose payload spans several queue chunks still reports ONE offset and
        // ONE length. Driven with a chunk size below the payload size, which is
        // what makes `pass` call the sink more than once inside one frame.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        feed(&state, b"\x82\x0a0123456789");
        let settings = WsSettings::default()
            .with_connect_only(true)
            .with_chunk_size(4);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut buf = [0_u8; 32];

        let nread =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("receives");

        assert_eq!(nread, 10, "every chunk landed in the one buffer");
        assert_eq!(&buf[..nread], b"0123456789");
        assert_eq!(ws.recv_frame().flags, CURLWS_BINARY);
        assert_eq!(ws.recv_frame().offset, 0, "the FIRST chunk's offset");
        assert_eq!(ws.recv_frame().len, 10);
        assert_eq!(ws.recv_frame().bytesleft, 0);
    }

    #[test]
    fn a_split_ping_is_delivered_rather_than_answered() {
        // `lib/ws.c:1494` answers a PING only when `remain == 0`, so a PING whose
        // payload has not fully arrived is handed to the application instead --
        // and the tail chunk, arriving with `remain == 0`, is then answered with
        // JUST that chunk as its payload. That is upstream's behaviour, not an
        // oversight of this port, and it is asserted so nobody "corrects" it into
        // a divergence.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        feed(&state, b"\x89\x04pi");
        let settings = WsSettings::default()
            .with_connect_only(true)
            .with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut buf = [0_u8; 16];

        let first =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("the head of the PING");
        assert_eq!(&buf[..first], b"pi");
        assert_eq!(ws.recv_frame().flags, CURLWS_PING);
        assert_eq!(ws.recv_frame().bytesleft, 2);
        assert!(
            sent(&state).is_empty(),
            "an incomplete PING is not answered"
        );

        feed(&state, b"ng");
        let second =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            });
        // The tail completed the frame, so it WAS answered -- and because it was
        // answered, nothing was collected, which is why the call reads on and
        // then finds the connection dry.
        assert_eq!(second, Err(CURLcode::GotNothing));
        assert_eq!(
            sent(&state),
            b"\x8a\x82\x00\x00\x00\x00ng",
            "the PONG carries the tail chunk, got [{}]",
            shown(&sent(&state))
        );
    }

    #[test]
    fn a_zero_length_frame_is_delivered_into_a_buffer_with_no_room() {
        // `lib/ws.c:1508-1512`: *"0 length write, we accept that"*. A zero-length
        // PING with auto-PONG suppressed and a zero-length application buffer
        // exercises the one path where a write of nothing is not `CURLE_AGAIN`.
        let clock = clock();
        let (mut chain, state) = connected_chain(&clock);
        feed(&state, b"\x89\x00");
        let settings = WsSettings::default()
            .with_connect_only(true)
            .with_options(CURLWS_NOAUTOPONG);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut buf = [0_u8; 0];

        let nread =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_recv(&mut ws, &mut buf, true, cx)
            })
            .expect("an empty frame is a frame");
        assert_eq!(nread, 0);
        assert_eq!(ws.recv_frame().flags, CURLWS_PING);
        assert_eq!(ws.recv_frame().len, 0);
        assert_eq!(ws.recv_frame().bytesleft, 0);
        assert!(sent(&state).is_empty(), "NOAUTOPONG held the reply back");
    }

    #[test]
    fn a_mismatched_chunk_is_a_bad_argument_and_not_a_wrong_answer() {
        // The collector's first act is `payload_remain` (`lib/ws.c:1480-1484`),
        // whose three refusals become `CURLE_BAD_FUNCTION_ARGUMENT`. Reached here
        // through the sink directly, because a decoder that produced such a chunk
        // would already be the defect this check exists to catch.
        let mut buffer = [0_u8; 8];
        let mut collector = Collector {
            buffer: &mut buffer,
            bufidx: 0,
            frame_age: 0,
            frame_flags: 0,
            payload_offset: 0,
            payload_len: 0,
            written: false,
            auto_pong: true,
            pong: None,
        };
        assert_eq!(
            collector.write(DecodedFrame {
                buf: b"abcd",
                age: 0,
                flags: CURLWS_BINARY,
                payload_offset: 2,
                payload_len: 4,
            }),
            Err(CURLcode::BadFunctionArgument),
            "four bytes cannot follow offset two of a four-byte payload"
        );
        assert!(!collector.written, "nothing was claimed");
    }

    #[test]
    fn a_full_buffer_stops_the_collector_with_again() {
        // `lib/ws.c:1513-1517`: with room for nothing and a chunk to place, the
        // sink reports `CURLE_AGAIN`, which is what ends `ws_recv`'s loop once
        // something has already been collected.
        let mut buffer = [0_u8; 2];
        let mut collector = Collector {
            buffer: &mut buffer,
            bufidx: 2,
            frame_age: 0,
            frame_flags: CURLWS_BINARY,
            payload_offset: 0,
            payload_len: 4,
            written: true,
            auto_pong: true,
            pong: None,
        };
        assert_eq!(
            collector.write(DecodedFrame {
                buf: b"cd",
                age: 0,
                flags: CURLWS_BINARY,
                payload_offset: 2,
                payload_len: 4,
            }),
            Err(CURLcode::Again)
        );
        // And a partially-filled buffer takes what fits and says so.
        let mut buffer = [0_u8; 3];
        let mut collector = Collector {
            buffer: &mut buffer,
            bufidx: 1,
            frame_age: 0,
            frame_flags: CURLWS_BINARY,
            payload_offset: 0,
            payload_len: 4,
            written: true,
            auto_pong: true,
            pong: None,
        };
        assert_eq!(
            collector.write(DecodedFrame {
                buf: b"cd",
                age: 0,
                flags: CURLWS_BINARY,
                payload_offset: 2,
                payload_len: 4,
            }),
            Ok(2)
        );
        assert_eq!(&buffer[1..], b"cd");
    }

    // -- 15. the writer's and reader's remaining seams ----------------------

    #[test]
    fn an_incomplete_frame_at_end_of_stream_is_absorbed_as_the_c_absorbs_it() {
        // The C's *"decode ending with N frame bytes remaining"* check
        // (`lib/ws.c:760-764`) sits AFTER a loop that returns on `CURLE_AGAIN`,
        // so a partial frame reaches the caller as SUCCESS and the check is
        // unreachable. Asserted rather than reasoned about: were the loop ever
        // reordered, this test would notice.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default();
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut writer = WsDecodeWriter::new();
        let mut next = RecordingWriter::default();

        with_io(&clock, &mut chain, &settings, &mut rng, true, |cx| {
            writer
                .write(&mut ws, b"\x82\x0aonly-four", true, true, &mut next, cx)
                .expect("a truncated frame at end of stream is not an error");
        });
        assert_eq!(next.decoded.len(), 1);
        assert_eq!(next.decoded[0].0, b"only-four");
        assert_eq!(next.decoded[0].1.bytesleft, 1, "one byte never came");
        assert_eq!(writer.buffered(), 0);

        // And closing the writer releases the queue whether or not it was empty.
        writer.close();
        assert_eq!(writer.buffered(), 0);
        assert_eq!(WsDecodeWriter::NAME, "ws-decode");
        assert_eq!(WsDecodeWriter::default().buffered(), 0);
    }

    #[test]
    fn the_upload_reader_drains_its_queue_before_reporting_the_end() {
        // `struct cr_ws_ctx`'s two flags (`lib/ws.c:1122-1126`) exist for this:
        // `read_eos` is what the NEXT reader said, `eos` is what this reader has
        // said, and they differ for exactly as long as the encoded remainder
        // takes to drain. Driven with a four-byte buffer over a four-byte upload,
        // which frames ten bytes and so needs three calls to hand back.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut reader = WsEncodeReader::new();
        let mut next = CannedReader {
            remaining: b"data".to_vec(),
            cleared: 0,
        };
        let mut out = Vec::new();
        let mut buf = [0_u8; 4];

        for expected_eos in [false, false, true] {
            let (nread, eos) =
                with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                    reader.read(&mut ws, &mut buf, &mut next, cx)
                })
                .expect("reads");
            out.extend_from_slice(buf.get(..nread).unwrap_or(&[]));
            assert_eq!(
                eos,
                expected_eos,
                "after {} bytes the end is {expected_eos}",
                out.len()
            );
        }

        assert_eq!(
            out,
            b"\x82\x84\x00\x00\x00\x00data",
            "got [{}]",
            shown(&out)
        );
        assert!(reader.is_eos());
        assert_eq!(
            next.cleared, 0,
            "the callback started no frame of its own, so no eos was cleared"
        );
        assert_eq!(WsEncodeReader::NAME, "ws-encode");
        assert_eq!(WsEncodeReader::default(), WsEncodeReader::new());
    }

    #[test]
    fn the_upload_reader_hands_back_a_head_that_was_already_queued() {
        // With bytes already in `sendbuf` -- which is the state a read callback
        // that called `ws_send` leaves behind -- the reader hands those on
        // without consulting the next reader at all (`lib/ws.c:1160` guards the
        // whole block on an empty queue).
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut reader = WsEncodeReader::new();
        let mut next = CannedReader {
            remaining: b"never read".to_vec(),
            cleared: 0,
        };
        let mut buf = [0_u8; 16];

        let (nread, eos) =
            with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
                ws_start_frame(&mut ws, CURLWS_BINARY, 3, cx)?;
                reader.read(&mut ws, &mut buf, &mut next, cx)
            })
            .expect("reads the queued head");

        assert_eq!(
            &buf[..nread],
            b"\x82\x83\x00\x00\x00\x00",
            "got [{}]",
            shown(&buf[..nread])
        );
        assert!(!eos);
        assert_eq!(
            next.remaining.len(),
            10,
            "the next reader was not consulted"
        );
        assert!(!reader.is_eos());
    }

    #[test]
    fn the_upload_reader_clamps_its_request_to_what_the_frame_still_owes() {
        // `lib/ws.c:1171-1175`: a frame already declared cannot be overfilled, so
        // the request to the next reader is clamped to `payload_remain`. The
        // clamp is observable as the SHORT read it produces from a source that
        // had more to give.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default().with_zero_mask(true);
        let mut rng = entropy();
        let mut ws = WebSocket::new(&settings);
        let mut reader = WsEncodeReader::new();
        let mut next = CannedReader {
            remaining: b"0123456789".to_vec(),
            cleared: 0,
        };
        let mut buf = [0_u8; 16];

        // Declare a three-byte frame, then drain its head so the queue is empty
        // and the clamp is what governs the next read.
        with_io(&clock, &mut chain, &settings, &mut rng, false, |cx| {
            ws_start_frame(&mut ws, CURLWS_BINARY, 3, cx).expect("head");
            let (head, _) = reader
                .read(&mut ws, &mut buf, &mut next, cx)
                .expect("the head");
            assert_eq!(head, 6);
            assert_eq!(ws.encoder().payload_remain(), 3);

            let (nread, eos) = reader
                .read(&mut ws, &mut buf, &mut next, cx)
                .expect("the payload");
            assert_eq!(nread, 3, "clamped to the three bytes still owed");
            assert!(!eos, "the source has more to give");
            assert_eq!(
                &buf[..nread],
                b"012",
                "masked with the zero mask, so unchanged"
            );
        });
        assert_eq!(next.remaining, b"3456789", "only three were taken");
        assert_eq!(ws.encoder().payload_remain(), 0);
    }

    // -- 16. the remaining accessors, builders and renderings ---------------

    #[test]
    fn the_context_reports_what_it_was_built_with() {
        // Every accessor `curl-rs-ffi/src/ffi/ws.rs` and the transfer core reach
        // for, asserted so that none of them is a member this file merely claims
        // to expose. The `Debug` rendering is asserted too: it prints the
        // settings and WHETHER a tracer is attached, never the tracer's contents,
        // because a diagnostic that dumped a borrowed sink would be noise.
        let clock = clock();
        let (mut chain, _state) = connected_chain(&clock);
        let settings = WsSettings::default().with_options(CURLWS_NOAUTOPONG);
        let mut rng = entropy();
        let mut call = CallCtx::new(&clock);
        let mut io = ChainTransport::new(&mut chain, &mut call);

        let plain = WsCtx::new(&settings, &mut rng, &mut io);
        assert!(!plain.in_callback(), "a fresh context is not in a callback");
        assert!(plain.settings().no_auto_pong, "the settings came through");
        assert!(!plain.settings().auto_pong());
        assert_eq!(
            format!("{plain:?}"),
            format!("WsCtx {{ settings: {settings:?}, traced: false }}")
        );

        let in_callback = plain.with_in_callback(true);
        assert!(in_callback.in_callback());

        // With a tracer attached, only the flag changes.
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let config = TraceConfig::new();
        let mut tracer = Tracer::new(&config, &mut sink);
        let traced = in_callback.with_tracer(&mut tracer);
        assert!(traced.in_callback(), "the earlier decision survived");
        assert!(format!("{traced:?}").contains("traced: true"));
    }

    #[test]
    fn the_upgrade_writer_reports_its_state_without_leaking_its_borrows() {
        let mut rng = entropy();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let config = TraceConfig::new();
        let mut tracer = Tracer::new(&config, &mut sink);

        let plain = WsUpgrade::new(&mut rng);
        assert_eq!(plain.sent_key(), None, "no key before the handshake ran");
        assert_eq!(
            format!("{plain:?}"),
            "WsUpgrade { sent_key: None, traced: false }"
        );

        let traced = plain.with_tracer(&mut tracer);
        assert_eq!(
            format!("{traced:?}"),
            "WsUpgrade { sent_key: None, traced: true }"
        );
    }

    #[test]
    fn the_state_types_default_to_the_state_their_constructors_build() {
        // `Default` and `new` must not diverge: the transfer core reaches for
        // whichever reads better at its call site, and a difference between them
        // would be a decoder or encoder that starts life mid-frame.
        assert_eq!(WsDecoder::default().state(), DecState::Init);
        assert_eq!(WsDecoder::default().frame_flags(), 0);
        assert_eq!(WsDecoder::default().payload_len(), 0);
        assert!(!WsDecoder::default().is_resuming());
        assert_eq!(WsEncoder::default().payload_remain(), 0);
        assert_eq!(WsEncoder::default().mask(), [0, 0, 0, 0]);
        assert!(!PendingControl::default().is_pending());
        assert_eq!(PendingControl::default().frame_type(), 0);
        assert!(PendingControl::default().payload().is_empty());
        assert_eq!(WsFrameMeta::default(), WsFrameMeta::new());

        // And the state a fresh connection starts in.
        let ws = WebSocket::new(&WsSettings::default());
        assert_eq!(ws.decoder().state(), DecState::Init);
        assert_eq!(ws.encoder().payload_remain(), 0);
        assert_eq!(ws.sendbuf_len(), 0);
        assert_eq!(*ws.recv_frame(), WsFrameMeta::new());
    }

    #[test]
    fn the_failure_renderer_shows_bytes_as_the_fixtures_spell_them() {
        // Only ever reached when an assertion fails, so it is asserted directly:
        // a diagnostic that misrenders is worse than none.
        assert_eq!(shown(b""), "");
        assert_eq!(shown(b"\x81\x05hello"), "81 05 68 65 6c 6c 6f");
        assert_eq!(shown(&[0x00, 0xff]), "00 ff");
    }

    #[test]
    fn clearing_the_end_of_stream_reaches_the_next_reader() {
        // The seam `lib/ws.c:1185` uses, exercised on the trait: the branch
        // itself needs a read callback that re-enters `ws_send`, which no
        // in-process harness can arrange, so what is asserted here is that the
        // seam a real callback would trip is wired to the next reader.
        let mut next = CannedReader {
            remaining: b"x".to_vec(),
            cleared: 0,
        };
        next.clear_eos();
        next.clear_eos();
        assert_eq!(next.cleared, 2);
        let (nread, eos) = next.read(&mut [0_u8; 4]).expect("reads");
        assert_eq!(nread, 1);
        assert!(eos, "the canned source is now dry");
    }

    // -- 17. this file's own policy -----------------------------------------
    //
    // The gates below read this file from disk and assert properties of it. The
    // crate root's `mod source_policy` already scans every source for `unsafe`,
    // for C scalar widths and for raw strings; these are the ones specific to
    // this module, and they exist here so that a violation names THIS file
    // rather than appearing as one entry in a workspace-wide list. The pattern,
    // and the helpers, are `protocols/ftp/pingpong.rs`'s -- reproduced rather
    // than shared because a test helper that crossed module boundaries would
    // have to be `pub(crate)`, and a policy gate that can be reached from
    // elsewhere is a policy gate that can be weakened from elsewhere.
    //
    // Each is ignored under Miri, as every filesystem-reading test in this
    // crate is: Miri runs with host isolation on and `read_to_string` fails
    // outright there, which would take the whole interpreter down. Nothing is
    // lost -- a string scan has no pointer arithmetic for Miri to check -- and
    // the assertions still run in full under `cargo test`.

    /// This file's own text.
    fn own_source() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("protocols")
            .join("ws.rs");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    }

    /// `line` with its comment tail and every string literal removed.
    ///
    /// Necessary for exactly the reason the module documentation is long: this
    /// file DISCUSSES `unsafe`, `extern "C"`, `#[repr(C)]` and the TLS module by
    /// name, because saying where each of them lives instead is how a reader
    /// learns the boundary. A scan that could not tell prose from code would
    /// report every one of those paragraphs as a violation.
    fn code_only(line: &str) -> String {
        let without_comment = line.split("//").next().unwrap_or("");
        let mut out = String::with_capacity(without_comment.len());
        let mut in_string = false;
        let mut escaped = false;
        for ch in without_comment.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if ch == '"' {
                in_string = true;
                out.push(' ');
                continue;
            }
            out.push(ch);
        }
        out
    }

    /// The `unsafe` keyword appears nowhere as code, and no FFI marker appears
    /// as code either.
    ///
    /// The sharpest of these gates, because this module BACKS four exported C
    /// symbols and would be the natural place for someone to put their
    /// `extern "C"` shims. They belong in `curl-rs-ffi/src/ffi/ws.rs`; this file
    /// provides the safe engine behind them and nothing more. `#[repr(C)]` is
    /// checked alongside for the same reason: `struct curl_ws_frame` is
    /// layout-visible, so its `#[repr(C)]` mirror is a real obligation -- just
    /// not this file's.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_unsafe_and_no_ffi_marker_appears_anywhere() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let code = code_only(line);
            let names_it = code
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|word| word == "unsafe");
            assert!(
                !names_it,
                "line {}: no `unsafe` outside src/ffi/",
                number + 1
            );
            for marker in
                ["no_mangle", "libc", "extern", "repr(C)", "unsafe_code"]
            {
                assert!(
                    !code.contains(marker),
                    "line {}: {marker} belongs to curl-rs-ffi/src/ffi/ws.rs",
                    number + 1
                );
            }
        }
    }

    /// No TLS module is imported and no `tls` feature is named.
    ///
    /// `wss` is this protocol over the crate's unconditional TLS stack, reached
    /// by a filter the connection layer installs -- which is why
    /// [`SCHEME_WSS`] differs from [`SCHEME_WS`] by a flag bit and not by a
    /// single line of TLS code. There is no `tls` feature to gate on either.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_tls_import_and_no_tls_feature_gate() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let code = code_only(line);
            assert!(
                !code.contains("crate::tls"),
                "line {}: the TLS module is not imported here",
                number + 1
            );
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
                assert!(
                    !trimmed.contains("feature = \"tls\""),
                    "line {}: there is no `tls` feature",
                    number + 1
                );
            }
        }
    }

    /// No wall-clock constructor is reached for: every reading comes from the
    /// injected clock, which is what makes a timeout testable.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_wall_clock_constructor_is_called() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let code = code_only(line);
            for forbidden in [
                "SystemClock",
                "Instant::now",
                "SystemTime::now",
                "curlx_now",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "line {}: {forbidden} bypasses the injected clock",
                    number + 1
                );
            }
        }
    }

    /// No global or thread-local generator is reached for.
    ///
    /// Specification 0.3.3's pattern P12 as a source property rather than a
    /// behavioural one: the 16-byte nonce and the 4-byte mask both come from
    /// the injected [`Rng`], and a `thread_rng()` anywhere in this file would
    /// make the handshake and the masked frames non-deterministic -- which
    /// would in turn make the byte-exact oracles of `tests/data/test2300`,
    /// `:2302` and `:2700` unassertable.
    ///
    /// The name says "ambient" rather than naming the two constructs it forbids,
    /// because this gate scans identifiers as well as calls and would otherwise
    /// catch its own signature -- which it did, on the first run.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_ambient_generator_is_reached_for() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let code = code_only(line);
            for forbidden in [
                "thread_rng",
                "thread_local",
                "OsRng",
                "random()",
                "static mut",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "line {}: {forbidden} bypasses the injected generator",
                    number + 1
                );
            }
        }
    }

    /// No hashed or ordered map is used, and no WebSocket crate is imported.
    ///
    /// Header storage is ordered and duplicate-preserving because header ORDER
    /// is significant on the wire (`tests/getpart.pm:351+` compares the whole
    /// request as ONE string), and every map in the standard library reorders or
    /// deduplicates. The crate ban is the same argument from the other end: a
    /// general-purpose WebSocket library does not commit to curl's framing
    /// decisions, and curl's framing decisions are the specification.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_map_container_and_no_websocket_crate_is_used() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let code = code_only(line);
            for forbidden in [
                "HashMap",
                "BTreeMap",
                "HashSet",
                "BTreeSet",
                "HeaderMap",
                "tungstenite",
                "bitflags",
                "indexmap",
                "smallvec",
                "arrayvec",
                "std::any::Any",
                "downcast",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "line {}: {forbidden} is not this file's to use",
                    number + 1
                );
            }
        }
    }

    /// No panicking construct appears before `mod tests`.
    ///
    /// The C's `DEBUGASSERT(randlen < sizeof(keyval))` (`lib/ws.c:1284`) becomes
    /// a checked length returning [`CURLcode::FailedInit`] -- see
    /// [`write_handshake`] -- and every other fallible step answers a `CURLcode`
    /// too. A library that aborts the calling process because a server sent an
    /// odd frame is not a drop-in replacement for one that returns an error
    /// code, so this is a correctness gate and not a style one.
    ///
    /// `unwrap_or`, `unwrap_or_default` and `unwrap_or_else` are deliberately
    /// NOT matched: none of them can panic, and all three are how this file
    /// avoids indexing.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_panicking_construct_appears_in_production_code() {
        let source = own_source();
        let mut in_tests = false;
        for (number, line) in source.lines().enumerate() {
            if line.starts_with("mod tests {") {
                in_tests = true;
            }
            if in_tests {
                continue;
            }
            let code = code_only(line);
            for forbidden in [
                ".unwrap()",
                ".expect(",
                "panic!",
                "unreachable!",
                "todo!",
                "unimplemented!",
                "assert!",
                "assert_eq!",
                "debug_assert",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "line {}: {forbidden} must be a CURLcode instead",
                    number + 1
                );
            }
        }
        assert!(in_tests, "the scan must have found `mod tests`");
    }

    /// No trait declared here has an `async fn` or returns `impl Future`.
    ///
    /// Either would make the trait un-`dyn`-compatible at the declared minimum
    /// Rust version of 1.75, and [`Protocol`] is reached through
    /// `&dyn Protocol` by mandate (specification 0.3.3, pattern P1). Both
    /// features stabilised in 1.75 and neither is object-safe, which is the
    /// trap this gate exists to spring.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_trait_method_is_an_async_fn_or_returns_impl_future() {
        let source = own_source();
        let mut depth_of_trait: Option<usize> = None;
        for (number, line) in source.lines().enumerate() {
            let code = code_only(line);
            let trimmed = code.trim_start();
            if trimmed.starts_with("pub(crate) trait ")
                || trimmed.starts_with("trait ")
            {
                depth_of_trait = Some(number);
            }
            if depth_of_trait.is_some() && code.starts_with('}') {
                depth_of_trait = None;
            }
            if depth_of_trait.is_some() {
                assert!(
                    !trimmed.contains("async fn"),
                    "line {}: an `async fn` in a trait is not dyn-compatible",
                    number + 1
                );
                assert!(
                    !trimmed.contains("impl Future"),
                    "line {}: `impl Future` in a trait is not dyn-compatible",
                    number + 1
                );
            }
        }
    }

    /// The REUSE banner is the project's, verbatim, with SPDX on line 21.
    ///
    /// `reuse lint` runs in the `linters` job of
    /// `.github/workflows/checksrc.yml`, and `REUSE.toml` does not list `.rs`
    /// files, so the annotation has to be in the file itself. Asserted against
    /// the shape rather than a copy of the text, because a copy inside the file
    /// it describes would pass whatever the banner said.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_reuse_banner_is_the_projects_verbatim_twenty_three_lines() {
        let source = own_source();
        let lines: Vec<&str> = source.lines().collect();
        assert!(lines.len() > 23, "the banner is the first 23 lines");
        for (index, line) in lines.iter().take(23).enumerate() {
            assert!(
                line.starts_with("//"),
                "banner line {} is not a comment",
                index + 1
            );
        }
        assert!(lines[0].contains("/****"), "the banner opens the C way");
        assert!(
            lines[1].contains('_') && lines[5].contains('\\'),
            "the six-line ASCII logo is lines 2 to 6"
        );
        assert!(
            lines[7].contains("Copyright (C) Daniel Stenberg"),
            "the copyright line is line 8"
        );
        // The tag is assembled rather than spelled, and that is a fix rather
        // than a flourish. `reuse` recognises the tag wherever it appears and
        // reads the rest of that line as a licence expression, so writing it
        // out a second time inside this file made it parse `curl",` -- the
        // literal's closing quote and the argument comma -- and report
        // `invalid SPDX License Expression 'curl",'` against this very file,
        // measured with reuse 6.2.0. `concat!` is expanded by the compiler, so
        // the assertion still compares the identical 34 bytes; only the source
        // spelling changes. `curl-rs-ffi/build.rs` avoids the same trap the
        // same way, by matching the tag without its colon.
        assert_eq!(
            lines[20],
            concat!("//  * SPDX-License-Identifier", ": curl"),
            "SPDX must be banner line 21, spelled the project's way"
        );
        assert!(lines[22].contains("****/"), "the banner closes on line 23");
    }
}
