//**************************************************************************
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
//**************************************************************************/
//! Per-request state: supersedes `lib/request.c` and `lib/request.h`.
//!
//! Two deliberate exceptions to that, and both matter:
//!
//! 1. **A redirect or a retry keeps the overall timing.** The follow path
//!    calls [`SingleRequest::soft_reset`] and NOT
//!    [`SingleRequest::hard_reset`], so [`SingleRequest::start`] is not
//!    re-recorded and `%{time_total}` still measures the whole operation.
//!    `lib/request.h:144-146` says so outright: *"Reset members, but keep
//!    start time for overall duration calc."*
//! 2. **The redirect bookkeeping outlives the attempt.** The redirect
//!    counter, the total request count and the would-be-redirected URL live
//!    in [`FollowState`], which the operation owns across every attempt --
//!    they are `data->state` fields in the C (`lib/urldata.h:1078`), not
//!    `struct SingleRequest` fields, and a counter reset per attempt would
//!    make `CURLOPT_MAXREDIRS` unenforceable.
//!
//! # Why this module declares a seam instead of importing the engine
//!
//! `lib/request.c` includes `urldata.h`, `cfilters.h`, `transfer.h`, `url.h`,
//! `sendf.h`, `progress.h` and `doh.h`, and reaches through
//! `struct Curl_easy *data` for whatever it needs. Several of those include
//! `request.h` straight back, so a literal transcription would make
//! `transfer/request.rs` and `transfer/mod.rs` mutually dependent -- a module
//! cycle Rust does permit and this module refuses, because the engine is
//! assembled LAST and everything it assembles must be nameable without it.
//!
//! The two client-chain pointers of `struct SingleRequest` --
//! `writer_stack` (`lib/request.h:86`) and `reader_stack` (`:89`) -- are that
//! seam's [`RequestIo::client_start`], [`RequestIo::client_reset`],
//! [`RequestIo::client_cleanup`], [`RequestIo::client_read`],
//! [`RequestIo::creader_done`] and [`RequestIo::creader_total_length`]. The
//! chains themselves are `crate::transfer::sendf`'s `ClientIo`, which the
//! engine owns: it already carries the write-side and read-side projections
//! of this struct's fields, and two owners of one field is the defect this
//! arrangement exists to avoid.
//!
//! # No `bool *done` out-parameters
//!
//! `Curl_xfer_send_shutdown(data, &done)` reports readiness by writing
//! through a caller-supplied pointer. Here it returns [`SendShutdown`], so a
//! caller cannot read the flag without having handled the error and cannot
//! forget to initialise it. Written bytes are likewise a RETURN value rather
//! than the C's `size_t *pnwritten`.

use core::fmt;

use crate::error::{CURLcode, CodeResult};
use crate::transfer::progress::{Progress, TimerId};
use crate::transfer::sendf::{ReadOutcome, TraceDataKind};
use crate::util::bufq::{BufQ, BufqOpts};
use crate::util::redact::RedactedOpt;
use crate::util::timeval::CurlTime;

// The request-control vocabulary

/// Which halves of a transfer are still live -- supersedes the `KEEP_*` bits
/// of `data->req.keepon` (`lib/urldata.h:413-414`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct KeepFlags(i32);

impl KeepFlags {
    /// Neither direction: the value `Curl_req_hard_reset` stores at
    /// `lib/request.c:135`.
    #[allow(dead_code)]
    pub(crate) const NONE: Self = Self(0);

    /// `KEEP_RECV` (`lib/urldata.h:413`), *"there is or may be data to
    /// read"*.
    #[allow(dead_code)]
    pub(crate) const RECV: Self = Self(1 << 0);

    /// `KEEP_SEND` (`lib/urldata.h:414`), *"there is or may be data to
    /// write"*.
    #[allow(dead_code)]
    pub(crate) const SEND: Self = Self(1 << 1);

    /// True when every bit set in `other` is also set here.
    ///
    /// Stands where the C writes `data->req.keepon & KEEP_SEND` as a truth
    /// test -- `CURL_WANT_SEND` and `CURL_WANT_RECV` at
    /// `lib/urldata.h:417-419` are exactly this.
    #[allow(dead_code)]
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// The same mask with every bit of `other` cleared -- the C's
    /// `keepon &= ~other`.
    #[allow(dead_code)]
    pub(crate) const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// True when neither direction is live.
    #[allow(dead_code)]
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The raw mask, for the accessor that mirrors the C's `int keepon`.
    #[allow(dead_code)]
    pub(crate) const fn bits(self) -> i32 {
        self.0
    }
}

impl core::ops::BitOr for KeepFlags {
    type Output = Self;

    /// Combines two masks, standing where the C writes
    /// `KEEP_RECV | KEEP_SEND`.
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOrAssign for KeepFlags {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// The `Expect: 100-continue` handshake state -- supersedes
/// `enum expect100` (`lib/request.h:34-40`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum Expect100 {
    /// `EXP100_SEND_DATA`: *"enough waiting, just send the body now"*.
    #[default]
    SendData = 0,
    /// `EXP100_AWAITING_CONTINUE`: waiting for the `100 Continue` header.
    AwaitingContinue = 1,
    /// `EXP100_SENDING_REQUEST`: still sending the request, and will wait for
    /// the `100` header once done with it.
    SendingRequest = 2,
    /// `EXP100_FAILED`: used on a `417 Expectation Failed` response.
    Failed = 3,
}

impl Expect100 {
    /// Every state, in the C's declaration order.
    #[allow(dead_code)]
    pub(crate) const VARIANTS: [Self; 4] = [
        Self::SendData,
        Self::AwaitingContinue,
        Self::SendingRequest,
        Self::Failed,
    ];

    /// The C spelling, for a diagnostic that has to match the C's.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::SendData => "EXP100_SEND_DATA",
            Self::AwaitingContinue => "EXP100_AWAITING_CONTINUE",
            Self::SendingRequest => "EXP100_SENDING_REQUEST",
            Self::Failed => "EXP100_FAILED",
        }
    }
}

/// The `101 Switching Protocols` upgrade state -- supersedes
/// `enum upgrade101` (`lib/request.h:42-47`).
///
/// The discriminants are the C's declaration order, and explicit for the same
/// reason [`Expect100`]'s are.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum Upgrade101 {
    /// `UPGR101_NONE`, the default state. This is the value
    /// `Curl_req_hard_reset` restores at `lib/request.c:136`.
    #[default]
    None = 0,
    /// `UPGR101_WS`: an upgrade to WebSocket was requested.
    WebSocket = 1,
    /// `UPGR101_H2`: an upgrade to HTTP/2 was requested.
    H2 = 2,
    /// `UPGR101_RECEIVED`: the `101` response has arrived.
    Received = 3,
}

impl Upgrade101 {
    /// Every state, in the C's declaration order.
    #[allow(dead_code)]
    pub(crate) const VARIANTS: [Self; 4] =
        [Self::None, Self::WebSocket, Self::H2, Self::Received];

    /// The C spelling, for a diagnostic that has to match the C's.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::None => "UPGR101_NONE",
            Self::WebSocket => "UPGR101_WS",
            Self::H2 => "UPGR101_H2",
            Self::Received => "UPGR101_RECEIVED",
        }
    }
}

/// How far a send-direction shutdown got -- the typed successor of
/// `Curl_xfer_send_shutdown`'s `bool *done` (`lib/transfer.h:159`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum SendShutdown {
    /// The shutdown is under way and must be advanced again. The C's
    /// `*done == FALSE`, which `req_flush` answers with `CURLE_AGAIN`
    /// (`lib/request.c:330-331`).
    Pending,
    /// The send direction is shut down. The C's `*done == TRUE`.
    Complete,
}

impl SendShutdown {
    /// True when nothing further is required.
    #[allow(dead_code)]
    pub(crate) const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

// The settings this module reads, and the debug-build environment seam

/// `data->set.upload_buffer_size`'s default -- `UPLOADBUFFER_DEFAULT`
/// (`lib/urldata.h:209`), assigned at `lib/url.c:438`.
pub(crate) const UPLOAD_BUFFER_DEFAULT: usize = 65536;

/// The three settings `lib/request.c` reads out of `data->set`.
///
/// Gathered into one `Copy` value rather than reached for individually, for
/// the reason `crate::transfer::sendf`'s `ClientConfig` gives: nothing in
/// `lib/request.c` writes a setting, so handing over a copy makes that
/// structural instead of conventional.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RequestConfig {
    /// `data->set.upload_buffer_size`, read at `lib/request.c:73`, `:79` and
    /// `:81`.
    ///
    /// The send queue's chunk size. A change between two requests on one
    /// handle rebuilds the queue -- see [`SingleRequest::soft_reset`].
    pub(crate) upload_buffer_size: usize,

    /// `data->set.max_send_speed`, read at `lib/request.c:200-203`.
    ///
    /// `CURLOPT_MAX_SEND_SPEED_LARGE`, which `--limit-rate` sets. Zero means
    /// unlimited, which is why the C tests `if(data->set.max_send_speed)`
    /// rather than comparing against -1. It clamps BODY bytes only.
    pub(crate) max_send_speed: i64,

    /// `data->set.opt_no_body`, read at `lib/request.c:158`.
    ///
    /// `CURLOPT_NOBODY`. The only setting a hard reset copies into the
    /// request, which is why it cannot simply be cleared with the rest.
    pub(crate) opt_no_body: bool,
}

impl Default for RequestConfig {
    /// curl's own defaults: a 64 KiB upload buffer, no send-rate cap, and a
    /// request that does have a body.
    fn default() -> Self {
        Self {
            upload_buffer_size: UPLOAD_BUFFER_DEFAULT,
            max_send_speed: 0,
            opt_no_body: false,
        }
    }
}

/// The one environment variable `lib/request.c` reads, behind a seam.
pub(crate) trait DebugEnv: fmt::Debug {
    /// `getenv("CURL_SMALLREQSEND")`, verbatim and unparsed.
    ///
    /// Unparsed because the C parses it with `curlx_str_number(&p,
    /// &body_small, body_len)`, whose ceiling is the CURRENT body length and
    /// therefore is not known to whoever reads the variable. See
    /// [`SingleRequest::xfer_send`] for the parse.
    fn small_req_send(&self) -> Option<&str>;
}

// `RequestIo` -- everything `lib/request.c` reaches through `data` for

/// The typed seam between the request state machine and the transfer engine.
///
/// # `CodeResult`, and where `CURLE_AGAIN` survives
///
/// [`CURLcode::Again`] is a READINESS condition and is preserved precisely
/// where the C preserves it, which is not everywhere:
///
/// * [`Self::xfer_send`] never reports it. `Curl_xfer_send`
///   (`lib/transfer.c:840-843`) converts the transport's `CURLE_AGAIN` into
///   `CURLE_OK` with zero bytes written, and an implementation must do the
///   same -- a blocked send is `Ok(0)`.
/// * [`Self::client_read`] may report it, and `Curl_req_send_more` treats it
///   as non-fatal for the iteration (`lib/request.c:457-458`).
/// * [`Self::xfer_flush`] may report it, and `req_flush` passes it straight
///   out (`lib/request.c:304`).
pub(crate) trait RequestIo: fmt::Debug {
    // ---- settings -------------------------------------------------------

    /// The three `data->set` values this module reads.
    fn config(&self) -> RequestConfig;

    /// `data && data->conn`: whether a transfer and a connection exist.
    ///
    /// Read by `Curl_req_send` (`lib/request.c:374`) and `req_flush`
    /// (`:289`), both of which answer `CURLE_FAILED_INIT` when it is false.
    fn has_connection(&self) -> bool;

    /// The debug-build environment, when this build exposes one.
    ///
    /// `None` in production. See [`DebugEnv`].
    fn debug_env(&self) -> Option<&dyn DebugEnv> {
        None
    }

    // ---- the transport send path ----------------------------------------

    /// `Curl_xfer_send(data, buf, blen, eos, pnwritten)`
    /// (`lib/transfer.c:829-850`): offer bytes to the connection.
    ///
    /// # Errors
    ///
    /// Any transport failure, unchanged. Never [`CURLcode::Again`].
    fn xfer_send(&mut self, bytes: &[u8], eos: bool) -> CodeResult<usize>;

    /// `Curl_xfer_needs_flush(data)` (`lib/transfer.c:819-822`): whether the
    /// connection is holding output that has not reached the wire.
    fn xfer_needs_flush(&self) -> bool;

    /// `Curl_xfer_flush(data)` (`lib/transfer.c:824-827`): push whatever the
    /// connection is holding.
    ///
    /// # Errors
    ///
    /// Any transport failure, and [`CURLcode::Again`] when the flush could
    /// not complete. `req_flush` returns that code to ITS caller unchanged.
    fn xfer_flush(&mut self) -> CodeResult<()>;

    /// `Curl_xfer_send_close(data)` (`lib/transfer.c:865-869`): the request
    /// body is complete, so tell the connection filters.
    ///
    /// # Errors
    ///
    /// Any failure the filter chain reports. The C's own body cannot fail,
    /// but its signature can, and the request path propagates it.
    fn xfer_send_close(&mut self) -> CodeResult<()>;

    /// `Curl_xfer_send_shutdown(data, &done)` (`lib/transfer.c:160-165`):
    /// begin or advance a graceful shutdown of the send direction.
    ///
    /// # Errors
    ///
    /// Any failure the filter chain reports. Whether that failure is fatal is
    /// the CALLER's decision -- see `shutdown_err_ignore` in
    /// [`SingleRequest::flush`].
    fn xfer_send_shutdown(&mut self) -> CodeResult<SendShutdown>;

    /// `Curl_xfer_send_is_paused(data)` (`lib/transfer.c:883-886`).
    ///
    /// The default body is the C's, transcribed: sending is paused exactly
    /// when the upload rate limiter is blocked. An implementation should not
    /// override it, and the default is provided so that no implementation can
    /// accidentally let the two answers disagree.
    fn xfer_send_is_paused(&self) -> bool {
        self.progress().upload().rlimit().is_blocked()
    }

    // ---- the client reader and writer chains ----------------------------

    /// `Curl_client_read(data, buf, blen, pnread, peos)`
    /// (`lib/sendf.c:1180-1220`): pull upload bytes from the application.
    ///
    /// # Errors
    ///
    /// Whatever a reader stage returns, including [`CURLcode::Again`] when
    /// the application has nothing ready.
    fn client_read(&mut self, into: &mut [u8]) -> CodeResult<ReadOutcome>;

    /// `Curl_creader_done(data, premature)` (`lib/sendf.c:1457-1464`): tell
    /// every reader stage the upload is over.
    ///
    /// `premature` is the C's argument name and carries
    /// `data->req.upload_aborted`.
    fn creader_done(&mut self, premature: bool);

    /// `Curl_creader_total_length(data)` (`lib/sendf.c:1408-1412`): how many
    /// bytes the reader chain will produce in total.
    fn creader_total_length(&self) -> i64;

    /// `Curl_client_start(data)` (`lib/sendf.c:95-115`): a new request
    /// attempt is beginning, so rewind the reader chain if one is pending.
    ///
    /// # Errors
    ///
    /// The first stage's failure, unchanged. [`SingleRequest::soft_reset`]
    /// propagates it exactly.
    fn client_start(&mut self) -> CodeResult<()>;

    /// `Curl_client_reset(data)` (`lib/sendf.c:79-93`): tear the chains down
    /// between attempts, keeping the readers when a rewind is pending.
    fn client_reset(&mut self);

    /// `Curl_client_cleanup(data)` (`lib/sendf.c:70-77`): tear both chains
    /// down for good.
    fn client_cleanup(&mut self);

    // ---- the resolver ----------------------------------------------------

    /// `Curl_doh_close(data)`: release any DNS-over-HTTPS request state this
    /// attempt started.
    fn doh_close(&mut self);

    // ---- progress accounting --------------------------------------------

    /// The transfer's accounting, shared.
    fn progress(&self) -> &Progress;

    /// The transfer's accounting, mutable.
    fn progress_mut(&mut self) -> &mut Progress;

    /// `Curl_pgrs_now(data)` (`lib/progress.c:171-177`): sample the injected
    /// clock, store the reading and return it.
    ///
    /// THE ONLY source of time in this module. An implementation samples its
    /// `Clock` through `Progress::sample` so that the reading lands where the
    /// C stores it.
    fn pgrs_now(&mut self) -> CurlTime;

    /// `Curl_pgrsTime(data, timer)` (`lib/progress.c:323-326`): sample the
    /// clock and record the reading against `timer`.
    fn pgrs_time(&mut self, timer: TimerId);

    // ---- diagnostics -----------------------------------------------------

    /// `Curl_debug(data, kind, buf, len)`: hand a raw payload to the
    /// application's debug callback.
    fn debug(&mut self, kind: TraceDataKind, bytes: &[u8]);

    /// `infof(data, ...)`: a verbose-mode informational line, not an error.
    ///
    /// The lines this module emits are compared against the recorded stderr
    /// of curl 8.19.0-DEV by the fixture corpus, so their wording is frozen.
    fn infof(&mut self, line: fmt::Arguments<'_>);

    /// `failf(data, ...)`: the line that reaches `CURLOPT_ERRORBUFFER`.
    ///
    /// Emitted IN ADDITION to returning an error, never instead of one.
    fn failf(&mut self, line: fmt::Arguments<'_>);

    /// `DEBUGF(infof(data, ...))`: a line the C emits only in a debug build.
    ///
    /// A distinct method rather than a `cfg` on the call site, so that a test
    /// can assert the C's exact debug wording -- which several of the shapes
    /// this module preserves only ever appear in -- while a production build
    /// discards it. The default body does discard it.
    fn trace(&mut self, line: fmt::Arguments<'_>) {
        let _ = line;
    }
}

// `SingleRequest` -- the state of one request attempt

/// The state of one request attempt -- supersedes `struct SingleRequest`
/// (`lib/request.h:56-131`).
///
/// Every behaviourally relevant member of the C struct is here, in the C's
/// declaration order, with four representation changes and no others:
///
/// | C member | here | why |
/// |---|---|---|
/// | `int keepon` | [`KeepFlags`] | a mask, not a number |
/// | `struct bufq sendbuf` plus `BIT(sendbuf_init)` | `Option<BufQ>` | the flag IS whether the queue exists; two encodings of one fact can disagree |
/// | `char *location`, `char *newurl` | `Option<String>` | owned, freed by drop |
/// | `struct Curl_cwriter *writer_stack`, `struct Curl_creader *reader_stack` | [`RequestIo`] | see the module documentation |
pub(crate) struct SingleRequest {
    /// `req.size`: the expected response body length, or -1 when it is not
    /// known at this point (`lib/request.h:57`).
    pub(crate) size: i64,

    /// `req.maxdownload`: the most body data to fetch, or -1 for unlimited
    /// (`lib/request.h:58-59`).
    pub(crate) maxdownload: i64,

    /// `req.bytecount`: the total number of body bytes read
    /// (`lib/request.h:60`).
    pub(crate) bytecount: i64,

    /// `req.writebytecount`: the number of BODY bytes written to the server
    /// (`lib/request.h:61`).
    ///
    /// Header bytes never reach this counter. See [`Self::xfer_send`].
    pub(crate) writebytecount: i64,

    /// `req.start`: when this transfer started (`lib/request.h:63`).
    ///
    /// Recorded by [`Self::start`] from [`RequestIo::pgrs_now`] and
    /// deliberately NOT touched by [`Self::soft_reset`], which is what keeps
    /// the overall duration measurable across a redirect.
    pub(crate) start: CurlTime,

    /// `req.headerbytecount`: received server headers, CONNECT headers
    /// excluded (`lib/request.h:64-65`).
    pub(crate) headerbytecount: u32,

    /// `req.allheadercount`: all received headers, server and CONNECT
    /// (`lib/request.h:66`).
    pub(crate) allheadercount: u32,

    /// `req.deductheadercount`: bytes that do not count when deciding whether
    /// anything was transferred at the end of a connection
    /// (`lib/request.h:67-72`).
    pub(crate) deductheadercount: u32,

    /// `req.headerline`: counts header lines so the first can be recognised
    /// (`lib/request.h:73-74`).
    pub(crate) headerline: i32,

    /// `req.offset`: the resume offset read from a `Content-Range:` header
    /// (`lib/request.h:75-76`).
    pub(crate) offset: i64,

    /// `req.httpcode`: the status from the `HTTP/1.? XXX` or `RTSP/1.? XXX`
    /// line (`lib/request.h:77-78`).
    ///
    /// Read by the follow path to decide whether an inherited explicit port
    /// survives a redirect -- 401 and 407 are the two codes that keep it.
    pub(crate) httpcode: i32,

    /// `req.keepon`: which halves of the transfer are still live
    /// (`lib/request.h:79`). Private; see the type's documentation.
    keepon: KeepFlags,

    /// `req.httpversion_sent`: the version used in the REQUEST -- 09, 10, 11
    /// and so on (`lib/request.h:80`).
    ///
    /// Set by [`Self::send`] from the value the protocol module passes, and
    /// never inferred from the header bytes.
    pub(crate) httpversion_sent: u8,

    /// `req.httpversion`: the version seen in the RESPONSE
    /// (`lib/request.h:81`).
    pub(crate) httpversion: u8,

    /// `req.upgr101`: the `101` upgrade state (`lib/request.h:82`).
    pub(crate) upgr101: Upgrade101,

    /// `req.sendbuf` together with `BIT(sendbuf_init)`
    /// (`lib/request.h:90` and `:127`): the bytes waiting to go to the
    /// server.
    sendbuf: Option<BufQ>,

    /// `req.sendbuf_hds_len`: how many of the queued bytes are HEADER bytes
    /// (`lib/request.h:91`).
    ///
    /// Always a prefix of the queue, which is what lets a partial flush
    /// subtract exactly the header bytes it managed to send.
    pub(crate) sendbuf_hds_len: usize,

    /// `req.timeofdoc`: the document's own timestamp, in Unix seconds
    /// (`lib/request.h:92`).
    ///
    /// Zero means "not known", which is the value a hard reset restores.
    pub(crate) timeofdoc: i64,

    /// `req.location`: the `Location:` header's value, allocated
    /// (`lib/request.h:93-94`).
    ///
    /// Set whatever the follow settings are. When following is off, the multi
    /// handle takes it and performs a FAKE follow with it so that
    /// `CURLINFO_REDIRECT_URL` still answers (`lib/multi.c:2038-2043`).
    pub(crate) location: Option<String>,

    /// `req.newurl`: the URL to use for a redirect or a retry
    /// (`lib/request.h:95-96`).
    ///
    /// Set means "go round again". The multi handle takes it, clears it and
    /// performs a REDIR follow (`lib/multi.c:2013-2028`).
    pub(crate) newurl: Option<String>,

    /// `req.setcookies`: how many `Set-Cookie:` headers this response carried
    /// (`lib/request.h:99`).
    ///
    /// Behind the `cookies` feature exactly as the C puts it behind
    /// `#ifndef CURL_DISABLE_COOKIES`.
    #[cfg(feature = "cookies")]
    pub(crate) setcookies: u8,

    /// `BIT(header)`: incoming data is still HTTP header
    /// (`lib/request.h:101`).
    pub(crate) header: bool,

    /// `BIT(done)`: the request is finished, so no more send or receive
    /// should happen (`lib/request.h:102-104`).
    ///
    /// The C's comment is worth keeping: this can be true BEFORE
    /// [`Self::upload_done`] or [`Self::download_done`] is.
    pub(crate) done: bool,

    /// `BIT(content_range)`: a `Content-Range:` header was found
    /// (`lib/request.h:105`).
    pub(crate) content_range: bool,

    /// `BIT(download_done)`: the download is complete
    /// (`lib/request.h:106`).
    pub(crate) download_done: bool,

    /// `BIT(eos_written)`: end-of-stream has been written to the client
    /// (`lib/request.h:107`).
    pub(crate) eos_written: bool,

    /// `BIT(eos_read)`: end-of-stream has been read FROM the client
    /// (`lib/request.h:108`).
    pub(crate) eos_read: bool,

    /// `BIT(eos_sent)`: end-of-stream has been sent TO the server
    /// (`lib/request.h:109`).
    pub(crate) eos_sent: bool,

    /// `BIT(rewind_read)`: the reader needs a rewind at the next start
    /// (`lib/request.h:110`).
    pub(crate) rewind_read: bool,

    /// `BIT(upload_done)`: all request data has been sent
    /// (`lib/request.h:111`).
    pub(crate) upload_done: bool,

    /// `BIT(upload_aborted)`: the upload was aborted, which also shows
    /// [`Self::upload_done`] as true (`lib/request.h:112-113`).
    pub(crate) upload_aborted: bool,

    /// `BIT(ignorebody)`: a response body is being read and discarded
    /// (`lib/request.h:114`).
    pub(crate) ignorebody: bool,

    /// `BIT(http_bodyless)`: the response status is 100..=199, 204 or 304
    /// (`lib/request.h:115-116`).
    pub(crate) http_bodyless: bool,

    /// `BIT(chunk)`: the response is chunked transfer-encoded
    /// (`lib/request.h:117`).
    pub(crate) chunk: bool,

    /// `BIT(resp_trailer)`: the response carried a `Trailer:` header field
    /// (`lib/request.h:118`).
    #[allow(dead_code)]
    pub(crate) resp_trailer: bool,

    /// `BIT(ignore_cl)`: ignore the response's `Content-Length:`
    /// (`lib/request.h:119`).
    pub(crate) ignore_cl: bool,

    /// `BIT(upload_chunky)`: the UPLOAD is chunked transfer-encoded
    /// (`lib/request.h:120-121`).
    pub(crate) upload_chunky: bool,

    /// `BIT(no_body)`: the response has no body (`lib/request.h:122`).
    ///
    /// The one boolean a hard reset does not clear: it restores it from
    /// [`RequestConfig::opt_no_body`] instead (`lib/request.c:158`).
    pub(crate) no_body: bool,

    /// `BIT(authneg)`: the authentication phase has started, so this request
    /// carries an auth header but is not the final one of the negotiation
    /// (`lib/request.h:123-126`).
    pub(crate) authneg: bool,

    /// `BIT(shutdown)`: the request's end will shut the connection down
    /// (`lib/request.h:128`).
    ///
    /// Set through `Curl_xfer_set_shutdown` (`lib/transfer.h:79-81`) after
    /// the transfer is set up, and read by [`Self::flush`] once the client's
    /// end-of-stream has been both read and sent.
    pub(crate) shutdown: bool,

    /// `BIT(shutdown_err_ignore)`: a shutdown error must not fail the request
    /// (`lib/request.h:129`).
    ///
    /// Neither reset touches this either: it is a property of how the
    /// transfer was SET UP, not of the attempt, and `Curl_xfer_set_shutdown`
    /// is what writes it.
    pub(crate) shutdown_err_ignore: bool,

    /// `BIT(reader_started)`: client reads have begun (`lib/request.h:130`).
    #[allow(dead_code)]
    pub(crate) reader_started: bool,
}

/// Metadata only: the two URLs are redacted and the byte counts are not.
///
/// # Why this is not `#[derive(Debug)]`
///
/// Two fields carry a URL that the peer chose: [`Self::location`], the
/// `Location:` header verbatim, and [`Self::newurl`], the redirect or retry
/// target. A URL routinely carries a credential -- userinfo in the authority,
/// a signed query parameter, a one-time token in a path -- and
/// `crate::url::Url`'s own formatter redacts userinfo for exactly that reason,
/// so rendering these two as plain strings here would have reinstated by the
/// back door what that formatter closed. They render as byte counts.
///
/// # Why the rest is a chosen subset rather than all forty-odd fields
///
/// This struct mirrors `struct SingleRequest` (`lib/request.h:52-140`) field
/// for field, and most of those fields are counters and single-bit flags whose
/// individual values are meaningless without the transfer that set them. A
/// forty-row dump is not a diagnostic; it is noise that hides the four numbers
/// a reader of a transfer-level message wants. So this renders the size and
/// progress accounting, the phase flags that decide what happens next, and the
/// presence of the queued send buffer -- whose contents `crate::util::bufq`
/// already declines to render.
///
/// Nothing about the stored values changes: [`Self::location`] and
/// [`Self::newurl`] are ordinary `pub(crate)` fields and every consumer reads
/// them verbatim, so redirect handling and `CURLINFO_REDIRECT_URL` are
/// unaffected.
impl fmt::Debug for SingleRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleRequest")
            // Size and progress accounting.
            .field("size", &self.size)
            .field("maxdownload", &self.maxdownload)
            .field("bytecount", &self.bytecount)
            .field("writebytecount", &self.writebytecount)
            .field("headerbytecount", &self.headerbytecount)
            .field("offset", &self.offset)
            .field("httpcode", &self.httpcode)
            .field("keepon", &self.keepon())
            // The redirect targets, redacted.
            .field(
                "location",
                &RedactedOpt(self.location.as_deref().map(str::as_bytes)),
            )
            .field(
                "newurl",
                &RedactedOpt(self.newurl.as_deref().map(str::as_bytes)),
            )
            // The phase flags that decide what happens next.
            .field("header", &self.header)
            .field("done", &self.done)
            .field("upload_done", &self.upload_done)
            .field("ignorebody", &self.ignorebody)
            .field("chunk", &self.chunk)
            .field("eos_read", &self.eos_read)
            .field("eos_sent", &self.eos_sent)
            // The queued send buffer reports presence and length only; its
            // bytes are the request body.
            .field("has_sendbuf", &self.sendbuf.is_some())
            .field("sendbuf_hds_len", &self.sendbuf_hds_len)
            .finish_non_exhaustive()
    }
}

impl Default for SingleRequest {
    /// The state `Curl_req_init` leaves behind (`lib/request.c:38-41`).
    ///
    /// The C writes `memset(req, 0, sizeof(*req))` and relies on every
    /// consumer setting the two sentinels before reading them. That is not
    /// reproduced: `size` and `maxdownload` are -1 here, because a zero
    /// `size` means "an empty response" and a zero `maxdownload` would forbid
    /// every byte, and because `Curl_req_hard_reset` -- which restores the
    /// same virgin state -- sets both to -1 explicitly at
    /// `lib/request.c:124-125`. Establishing the invariant once, here, is
    /// what makes the two paths agree.
    fn default() -> Self {
        Self {
            size: -1,
            maxdownload: -1,
            bytecount: 0,
            writebytecount: 0,
            start: CurlTime::ZERO,
            headerbytecount: 0,
            allheadercount: 0,
            deductheadercount: 0,
            headerline: 0,
            offset: 0,
            httpcode: 0,
            keepon: KeepFlags::NONE,
            httpversion_sent: 0,
            httpversion: 0,
            upgr101: Upgrade101::None,
            sendbuf: None,
            sendbuf_hds_len: 0,
            timeofdoc: 0,
            location: None,
            newurl: None,
            #[cfg(feature = "cookies")]
            setcookies: 0,
            header: false,
            done: false,
            content_range: false,
            download_done: false,
            eos_written: false,
            eos_read: false,
            eos_sent: false,
            rewind_read: false,
            upload_done: false,
            upload_aborted: false,
            ignorebody: false,
            http_bodyless: false,
            chunk: false,
            resp_trailer: false,
            ignore_cl: false,
            upload_chunky: false,
            no_body: false,
            authneg: false,
            shutdown: false,
            shutdown_err_ignore: false,
            reader_started: false,
        }
    }
}

// The keep-flag vocabulary

impl SingleRequest {
    /// Which halves of the transfer are still live -- reads `req.keepon`.
    #[allow(dead_code)]
    pub(crate) const fn keepon(&self) -> KeepFlags {
        self.keepon
    }

    /// Marks the given halves live -- the C's `keepon |= flags`.
    #[allow(dead_code)]
    pub(crate) fn keep_on(&mut self, flags: KeepFlags) {
        self.keepon |= flags;
    }

    /// Marks the given halves finished -- the C's `keepon &= ~flags`.
    #[allow(dead_code)]
    pub(crate) fn keep_off(&mut self, flags: KeepFlags) {
        self.keepon = self.keepon.without(flags);
    }

    /// Replaces the whole mask -- the C's `keepon = flags`.
    ///
    /// The transfer setup functions of `lib/transfer.c` assign the mask
    /// outright rather than adjusting it, so the shape exists here too.
    #[allow(dead_code)]
    pub(crate) fn set_keepon(&mut self, flags: KeepFlags) {
        self.keepon = flags;
    }

    /// `CURL_WANT_SEND(data)` (`lib/urldata.h:417`).
    #[allow(dead_code)]
    pub(crate) const fn wants_send(&self) -> bool {
        self.keepon.contains(KeepFlags::SEND)
    }

    /// `CURL_WANT_RECV(data)` (`lib/urldata.h:419`).
    #[allow(dead_code)]
    pub(crate) const fn wants_recv(&self) -> bool {
        self.keepon.contains(KeepFlags::RECV)
    }

    /// `req.sendbuf_init` (`lib/request.h:127`): whether the send queue
    /// exists yet.
    #[allow(dead_code)]
    pub(crate) const fn sendbuf_init(&self) -> bool {
        self.sendbuf.is_some()
    }

    /// How many bytes are queued for the server, zero before the queue
    /// exists -- `Curl_bufq_len(&req.sendbuf)`.
    #[allow(dead_code)]
    pub(crate) fn sendbuf_len(&self) -> usize {
        match &self.sendbuf {
            Some(queue) => queue.len(),
            None => 0,
        }
    }

    /// The send queue's chunk size, zero before the queue exists --
    /// `req.sendbuf.chunk_size`, read at `lib/request.c:79` and `:387`.
    #[allow(dead_code)]
    pub(crate) fn sendbuf_chunk_size(&self) -> usize {
        match &self.sendbuf {
            Some(queue) => queue.chunk_size(),
            None => 0,
        }
    }
}

// Initialisation, reset, start, done, cleanup

impl SingleRequest {
    /// `Curl_req_init(req)` (`lib/request.c:38-41`): the state of the request
    /// for first use.
    ///
    /// The C's `memset` with the two sentinels made explicit; see
    /// [`Default::default`], which this delegates to so that the two entry
    /// points cannot drift.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `Curl_req_soft_reset(req, data)` (`lib/request.c:43-87`): the request
    /// may continue with a follow-up.
    ///
    /// # The send queue
    ///
    /// Three cases, all the C's (`lib/request.c:72-84`):
    ///
    /// 1. No queue yet: build one, one chunk of
    ///    [`RequestConfig::upload_buffer_size`] bytes, soft-limited.
    /// 2. A queue whose chunk size still matches: empty it and keep the
    ///    allocation.
    /// 3. A queue whose chunk size no longer matches, because
    ///    `CURLOPT_UPLOAD_BUFFERSIZE` was set between attempts: release it
    ///    and build a new one at the new size. The C resets it first and then
    ///    frees it, which looks redundant and is preserved -- the reset is
    ///    what returns the chunks to the queue's spare list, and the free then
    ///    releases them from there.
    ///
    /// # Errors
    ///
    /// [`RequestIo::client_start`]'s error, unchanged and unwrapped. The C
    /// returns before touching the send queue in that case
    /// (`lib/request.c:68-70`), and so does this: a rewind that failed leaves
    /// the transfer unable to retry, and the caller is about to fail it.
    #[allow(dead_code)]
    pub(crate) fn soft_reset(
        &mut self,
        io: &mut dyn RequestIo,
    ) -> CodeResult<()> {
        // `lib/request.c:48-66`, in the C's order.
        self.done = false;
        self.upload_done = false;
        self.upload_aborted = false;
        self.download_done = false;
        self.eos_written = false;
        self.eos_read = false;
        self.eos_sent = false;
        self.ignorebody = false;
        self.shutdown = false;
        self.bytecount = 0;
        self.writebytecount = 0;
        self.header = false;
        self.headerline = 0;
        self.headerbytecount = 0;
        self.allheadercount = 0;
        self.deductheadercount = 0;
        self.httpversion_sent = 0;
        self.httpversion = 0;
        self.sendbuf_hds_len = 0;

        // `:68-70`. Before the queue, and returning early on failure.
        io.client_start()?;

        // `:72-84`.
        let chunk_size = io.config().upload_buffer_size;
        match &mut self.sendbuf {
            None => self.sendbuf = Some(new_sendbuf(chunk_size)),
            Some(queue) => {
                queue.reset();
                if chunk_size != queue.chunk_size() {
                    queue.free();
                    self.sendbuf = Some(new_sendbuf(chunk_size));
                }
            }
        }

        Ok(())
    }

    /// `Curl_req_start(req, data)` (`lib/request.c:89-94`): the request is
    /// about to start.
    ///
    /// # Errors
    ///
    /// [`Self::soft_reset`]'s error, unchanged. The start instant is recorded
    /// either way, exactly as the C records it before the call that can fail.
    #[allow(dead_code)]
    pub(crate) fn start(&mut self, io: &mut dyn RequestIo) -> CodeResult<()> {
        self.start = io.pgrs_now();
        self.soft_reset(io)
    }

    /// `Curl_req_done(req, data, aborted)` (`lib/request.c:98-109`): the
    /// request is over.
    ///
    /// # Errors
    ///
    /// None. `Ok(())` unconditionally, which is the C's `return CURLE_OK` at
    /// `:108`. The result type is kept so that the seam's shape matches the C
    /// signature its callers were written against, and so that a future
    /// failure here would be a compile error at every call site rather than a
    /// silently discarded one.
    #[allow(dead_code)]
    pub(crate) fn done(
        &mut self,
        io: &mut dyn RequestIo,
        aborted: bool,
    ) -> CodeResult<()> {
        // `:102-103`.
        if !aborted {
            let _ = self.flush(io);
        }
        // `:104`.
        io.client_reset();
        // `:105-107`.
        io.doh_close();
        // `:108`.
        Ok(())
    }

    /// `Curl_req_hard_reset(req, data)` (`lib/request.c:111-164`): restore the
    /// virgin state without discarding the reusable allocations.
    #[allow(dead_code)]
    pub(crate) fn hard_reset(&mut self, io: &mut dyn RequestIo) {
        // `:113`.
        let t0 = CurlTime::ZERO;

        // `:115-118`. The URL first, then the client chains, then the queue.
        self.newurl = None;
        io.client_reset();
        if let Some(queue) = &mut self.sendbuf {
            queue.reset();
        }

        // `:120-122`.
        io.doh_close();

        // `:124-143`.
        self.size = -1;
        self.maxdownload = -1;
        self.bytecount = 0;
        self.writebytecount = 0;
        self.start = t0;
        self.headerbytecount = 0;
        self.allheadercount = 0;
        self.deductheadercount = 0;
        self.headerline = 0;
        self.offset = 0;
        self.httpcode = 0;
        self.keepon = KeepFlags::NONE;
        self.upgr101 = Upgrade101::None;
        self.sendbuf_hds_len = 0;
        self.timeofdoc = 0;
        self.location = None;
        self.newurl = None;
        #[cfg(feature = "cookies")]
        {
            self.setcookies = 0;
        }

        // `:144-160`.
        self.header = false;
        self.content_range = false;
        self.download_done = false;
        self.eos_written = false;
        self.eos_read = false;
        self.eos_sent = false;
        self.rewind_read = false;
        self.upload_done = false;
        self.upload_aborted = false;
        self.ignorebody = false;
        self.http_bodyless = false;
        self.chunk = false;
        self.ignore_cl = false;
        self.upload_chunky = false;
        self.no_body = io.config().opt_no_body;
        self.authneg = false;
        self.shutdown = false;

        // `:161-163`. Unpause both directions.
        let progress = io.progress_mut();
        progress.download_mut().rlimit_mut().block(false, t0);
        progress.upload_mut().rlimit_mut().block(false, t0);
    }

    /// `Curl_req_free(req, data)` (`lib/request.c:166-172`): release the
    /// request's state, which is not usable afterwards.
    #[allow(dead_code)]
    pub(crate) fn free(&mut self, io: &mut dyn RequestIo) {
        // `:168`.
        self.newurl = None;
        // Not in the C's list because a C `char *` that is about to be
        // forgotten costs nothing; here the string owns its allocation, so it
        // is released with the rest of the request rather than outliving it.
        self.location = None;
        // `:169-170`.
        if let Some(queue) = &mut self.sendbuf {
            queue.free();
        }
        self.sendbuf = None;
        self.sendbuf_hds_len = 0;
        // `:171`.
        io.client_cleanup();
    }
}

/// One soft-limited chunk of `chunk_size` bytes --
/// `Curl_bufq_init2(&req->sendbuf, size, 1, BUFQ_OPT_SOFT_LIMIT)`
/// (`lib/request.c:73-74`, `:81-82`).
///
/// A free function because the C spells the same three arguments out twice and
/// a single definition cannot let the two sites disagree.
fn new_sendbuf(chunk_size: usize) -> BufQ {
    BufQ::with_opts(chunk_size, 1, BufqOpts::SOFT_LIMIT)
}

/// An unsigned decimal number with no sign, no prefix and no leading blanks,
/// rejected when it exceeds `max` -- `curlx_str_number(&p, &num, max)`
/// through `str_num_base` (`lib/curlx/strparse.c:157-191`).
fn parse_capped_number(text: &str, max: u64) -> Option<u64> {
    const BASE: u64 = 10;

    let mut value = 0_u64;
    let mut digits = 0_usize;

    for byte in text.bytes() {
        if !byte.is_ascii_digit() {
            break;
        }
        let digit = u64::from(byte - b'0');
        if max < digit || value > (max - digit) / BASE {
            return None;
        }
        value = value * BASE + digit;
        digits += 1;
    }

    if digits == 0 {
        None
    } else {
        Some(value)
    }
}

// The low-level send

impl SingleRequest {
    /// `xfer_send(data, buf, blen, hds_len, pnwritten)`
    /// (`lib/request.c:174-229`): offer `bytes` to the transport, of which the
    /// first `hds_len` are request HEADER bytes.
    ///
    /// # Errors
    ///
    /// The transport's error, unchanged. Never [`CURLcode::Again`]: see
    /// [`RequestIo::xfer_send`].
    ///
    /// # Panics
    ///
    /// In a debug build only, when `hds_len` exceeds `bytes.len()` -- the C's
    /// `DEBUGASSERT(hds_len <= blen)` at `:182`. A release build clamps it,
    /// so the slicing below cannot fail in either profile.
    #[allow(dead_code)]
    pub(crate) fn xfer_send(
        &mut self,
        io: &mut dyn RequestIo,
        bytes: &[u8],
        hds_len: usize,
    ) -> CodeResult<usize> {
        let queued_len = self.sendbuf_len();
        let queue_is_empty = self.sendbuf_empty();
        self.xfer_send_queued(io, bytes, hds_len, queued_len, queue_is_empty)
    }

    /// [`Self::xfer_send`] with the send queue's state passed in rather than
    /// read from `self`.
    ///
    /// The flush loop owns the queue while it drains it -- see
    /// [`Self::sendbuf_flush`] -- so it cannot let this method read the queue
    /// back out of `self`. Handing the two values over explicitly is also
    /// exact rather than merely convenient: the C reads
    /// `Curl_bufq_len(&data->req.sendbuf)` at `:208`, which is BEFORE any skip
    /// for this iteration, and that is the value the flush loop passes.
    fn xfer_send_queued(
        &mut self,
        io: &mut dyn RequestIo,
        bytes: &[u8],
        hds_len: usize,
        queued_len: usize,
        queue_is_empty: bool,
    ) -> CodeResult<usize> {
        // `:182`.
        debug_assert!(
            hds_len <= bytes.len(),
            "xfer_send: a header prefix of {hds_len} cannot exceed the {} \
             bytes offered",
            bytes.len()
        );
        let hds_len = hds_len.min(bytes.len());

        // `:183-197`. The debug-build override, body bytes only. `blen` is
        // the C's local, which starts at the full length and only ever
        // shrinks.
        let mut blen = bytes.len();
        let body_len = blen - hds_len;
        if body_len != 0 {
            if let Some(raw) = io.debug_env().and_then(DebugEnv::small_req_send)
            {
                if let Some(small) = parse_capped_number(raw, body_len as u64) {
                    // The cap was `body_len`, so this cannot exceed it and the
                    // conversion cannot lose a bit.
                    blen = hds_len + small as usize;
                }
            }
        }

        // `:198-204`. The send-rate clamp, body bytes only.
        let max_send_speed = io.config().max_send_speed;
        if max_send_speed > 0 {
            let body_bytes = blen - hds_len;
            if body_bytes as i64 > max_send_speed {
                blen = hds_len + max_send_speed as usize;
            }
        }

        // `:206-211`. This call is the end of the stream exactly when the
        // client has already reported end-of-stream AND the queue is either
        // empty or entirely covered by this call. Both disjuncts are needed:
        // the direct-send path of `Curl_req_send` has an empty queue, and the
        // flush path has a queue whose whole remaining length is this chunk.
        let mut eos = false;
        if self.eos_read && (queue_is_empty || queued_len == blen) {
            io.trace(format_args!("sending last upload chunk of {blen} bytes"));
            eos = true;
        }

        // `:212`.
        let offered = bytes.get(..blen).unwrap_or(bytes);
        let nwritten = io.xfer_send(offered, eos)?;
        debug_assert!(
            nwritten <= blen,
            "xfer_send: the transport reported {nwritten} bytes accepted of \
             {blen} offered"
        );
        let nwritten = nwritten.min(blen);

        // `:213-227`.
        if eos && blen == nwritten {
            self.eos_sent = true;
        }
        if nwritten != 0 {
            // `:217-219`. The header prefix, up to what was accepted.
            if hds_len != 0 {
                let reported = hds_len.min(nwritten);
                io.debug(TraceDataKind::HeaderOut, &bytes[..reported]);
            }
            // `:220-225`. Then the body, and only the body is accounted for.
            if nwritten > hds_len {
                let body = &bytes[hds_len..nwritten];
                let body_len = body.len();
                io.debug(TraceDataKind::DataOut, body);
                self.writebytecount += body_len as i64;
                // `Curl_pgrs_upload_inc` reads the clock itself in the C; the
                // reading is sampled here so that the byte count and the
                // instant it is charged at provably agree. The limiter is
                // drained inside `upload_inc`, so there is no second charge.
                let now = io.pgrs_now();
                io.progress_mut().upload_inc(body_len, now);
            }
        }

        Ok(nwritten)
    }
}

// The upload queue, the flush, end-of-stream and shutdown

impl SingleRequest {
    /// `req_send_buffer_add(data, buf, blen, hds_len)`
    /// (`lib/request.c:352-365`): queue `bytes`, of which the first `hds_len`
    /// are request HEADER bytes.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`] from the queue, and
    /// [`CURLcode::FailedInit`] when no queue exists. The C cannot reach the
    /// second case -- `Curl_req_start` always precedes `Curl_req_send` -- and
    /// would write into a zeroed queue if it did; a defined refusal replaces
    /// that.
    ///
    /// # Panics
    ///
    /// In a debug build only, when the queue took less than the whole input,
    /// which would mean the soft limit was lost.
    #[allow(dead_code)]
    pub(crate) fn sendbuf_add(
        &mut self,
        bytes: &[u8],
        hds_len: usize,
    ) -> CodeResult<()> {
        let queue = match &mut self.sendbuf {
            Some(queue) => queue,
            None => return Err(CURLcode::FailedInit),
        };
        // `:358-360`.
        let written = queue.write(bytes)?;
        // `:361-362`.
        debug_assert_eq!(
            written,
            bytes.len(),
            "the send queue is soft-limited and must take all of it"
        );
        // `:363`.
        self.sendbuf_hds_len += hds_len;
        Ok(())
    }

    /// `req_send_buffer_flush(data)` (`lib/request.c:231-253`): hand the
    /// queued bytes to the transport, oldest first.
    ///
    /// # Errors
    ///
    /// The transport's error, unchanged.
    fn sendbuf_flush(&mut self, io: &mut dyn RequestIo) -> CodeResult<()> {
        let mut queue = match self.sendbuf.take() {
            Some(queue) => queue,
            None => return Ok(()),
        };
        let mut result = Ok(());

        // `:237`: `while(Curl_bufq_peek(&data->req.sendbuf, &buf, &blen))`.
        loop {
            // Read before peeking. `peek` does not change either value, and
            // the C reads them at `:207-208`, which is before the skip for
            // this turn -- so this is the same reading, taken where the borrow
            // checker can see it is.
            let queued_len = queue.len();
            let queue_is_empty = queue.is_empty();
            let hds_total = self.sendbuf_hds_len;

            let run = match queue.peek() {
                Some(run) => run,
                None => break,
            };
            let blen = run.len();
            // `:238`.
            let hds_len = hds_total.min(blen);

            // `:239-241`.
            let nwritten = match self.xfer_send_queued(
                io,
                run,
                hds_len,
                queued_len,
                queue_is_empty,
            ) {
                Ok(nwritten) => nwritten,
                Err(code) => {
                    result = Err(code);
                    break;
                }
            };

            // `:243-246`.
            queue.skip(nwritten);
            if hds_len != 0 {
                self.sendbuf_hds_len -= hds_len.min(nwritten);
            }

            // `:247-250`.
            if nwritten < blen {
                break;
            }
        }

        self.sendbuf = Some(queue);
        result
    }

    /// `req_set_upload_done(data)` (`lib/request.c:255-283`): all request data
    /// has been sent, or the send has been abandoned.
    ///
    /// Four informational lines are possible and the choice between them is
    /// frozen, because the fixture corpus compares recorded stderr:
    ///
    /// | condition | line |
    /// |---|---|
    /// | aborted, bytes sent | `abort upload after having sent N bytes` |
    /// | aborted, no bytes | `abort upload` |
    /// | not aborted, bytes sent | `upload completely sent off: N bytes` |
    /// | no bytes, download not done, reader length not 0 | `We are completely uploaded and fine` |
    /// | no bytes, download not done, reader length 0 | `Request completely sent off` |
    ///
    /// # Errors
    ///
    /// [`RequestIo::xfer_send_close`]'s error, unchanged.
    ///
    /// # Panics
    ///
    /// In a debug build only, when the upload was already done -- the C's
    /// `DEBUGASSERT(!data->req.upload_done)` at `:257`. Both callers guard on
    /// it, so reaching it twice is a caller bug and not a state this method
    /// should absorb.
    #[allow(dead_code)]
    pub(crate) fn set_upload_done(
        &mut self,
        io: &mut dyn RequestIo,
    ) -> CodeResult<()> {
        // `:257`.
        debug_assert!(
            !self.upload_done,
            "req_set_upload_done runs once per attempt"
        );

        // `:258-259`.
        self.upload_done = true;
        self.keep_off(KeepFlags::SEND);

        // `:261-262`.
        io.pgrs_time(TimerId::PostTransfer);
        io.creader_done(self.upload_aborted);

        // `:264-280`.
        if self.upload_aborted {
            // `:265`. The header count is deliberately left alone, exactly as
            // the C leaves it: the next `Curl_req_soft_reset` zeroes it, and
            // nothing reads it in between now and then.
            if let Some(queue) = &mut self.sendbuf {
                queue.reset();
            }
            if self.writebytecount != 0 {
                io.infof(format_args!(
                    "abort upload after having sent {} bytes",
                    self.writebytecount
                ));
            } else {
                io.infof(format_args!("abort upload"));
            }
        } else if self.writebytecount != 0 {
            io.infof(format_args!(
                "upload completely sent off: {} bytes",
                self.writebytecount
            ));
        } else if !self.download_done {
            // `:276`.
            debug_assert!(
                self.sendbuf_empty(),
                "nothing was sent and nothing is queued, so the queue is empty"
            );
            // `:277-279`.
            if io.creader_total_length() != 0 {
                io.infof(format_args!("We are completely uploaded and fine"));
            } else {
                io.infof(format_args!("Request completely sent off"));
            }
        }

        // `:282`.
        io.xfer_send_close()
    }

    /// `req_flush(data)` (`lib/request.c:285-336`): push everything that is
    /// waiting, and finish the upload when there is nothing left.
    ///
    /// Five steps, in this order, and the order is the behaviour:
    ///
    /// 1. **No transfer or no connection** answers
    ///    [`CURLcode::FailedInit`] (`:289-290`).
    /// 2. **Queued bytes** are flushed. Bytes still queued afterwards answer
    ///    [`CURLcode::Again`] (`:292-301`).
    /// 3. **Otherwise**, a connection holding output has its own flush invoked
    ///    and that result is returned directly, `CURLE_AGAIN` included
    ///    (`:302-305`). This arm is an `else`: a queue with bytes in it never
    ///    reaches it.
    /// 4. **A read but unsent end-of-stream** is sent as a ZERO-LENGTH send
    ///    with the end-of-stream flag set (`:307-314`). This is a required
    ///    event, not an optimisable one: an HTTP/2 or HTTP/3 stream is
    ///    half-closed by that empty frame, and a chunked upload's terminating
    ///    zero-length chunk is written by the filter that observes it. There
    ///    is no `if length != 0` guard anywhere on this path.
    /// 5. **A complete upload** is finished off, through a graceful send
    ///    shutdown first when the transfer asked for one (`:316-334`).
    ///
    /// # `shutdown_err_ignore`
    ///
    /// A shutdown error is normally propagated. With
    /// [`Self::shutdown_err_ignore`] set it is turned into success AND into
    /// completion -- the C sets both `result = CURLE_OK` and `done = TRUE` at
    /// `:324-325`, so the upload finishes in the same call rather than being
    /// retried -- and the C's line is emitted verbatim.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] with no connection, [`CURLcode::Again`] when
    /// bytes remain or a shutdown is still pending, and any transport error
    /// unchanged.
    #[allow(dead_code)]
    pub(crate) fn flush(&mut self, io: &mut dyn RequestIo) -> CodeResult<()> {
        // 1 -- `:289-290`.
        if !io.has_connection() {
            return Err(CURLcode::FailedInit);
        }

        // 2 -- `:292-301`.
        if !self.sendbuf_empty() {
            self.sendbuf_flush(io)?;
            if !self.sendbuf_empty() {
                io.trace(format_args!(
                    "Curl_req_flush(len={}) -> EAGAIN",
                    self.sendbuf_len()
                ));
                return Err(CURLcode::Again);
            }
        }
        // 3 -- `:302-305`.
        else if io.xfer_needs_flush() {
            io.trace(format_args!("Curl_req_flush(), xfer send_pending"));
            return io.xfer_flush();
        }

        // 4 -- `:307-314`. The C passes a one-byte local with a length of
        // zero; an empty slice is the same offer without the unused byte.
        if self.eos_read && !self.eos_sent {
            self.xfer_send(io, &[], 0)?;
            debug_assert!(
                self.eos_sent,
                "a zero-length send with end-of-stream always records it"
            );
        }

        // 5 -- `:316-334`.
        if !self.upload_done && self.eos_read && self.eos_sent {
            debug_assert!(
                self.sendbuf_empty(),
                "end-of-stream was sent, so nothing can still be queued"
            );
            if self.shutdown {
                match io.xfer_send_shutdown() {
                    Ok(SendShutdown::Complete) => {}
                    // `:330-331`.
                    Ok(SendShutdown::Pending) => return Err(CURLcode::Again),
                    Err(code) => {
                        // `:321-326`.
                        if !self.shutdown_err_ignore {
                            return Err(code);
                        }
                        io.infof(format_args!(
                            "Shutdown send direction error: {}. Broken \
                             server? Proceeding as if everything is ok.",
                            code.as_i32()
                        ));
                    }
                }
            }
            // `:333`.
            return self.set_upload_done(io);
        }

        Ok(())
    }
}

// Sending the request headers, and continuing the upload

impl SingleRequest {
    /// `Curl_req_send(data, req, httpversion)` (`lib/request.c:367-412`): send
    /// the request headers, buffering whatever does not go out.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] with no connection, and any error from the
    /// send, the queue or [`Self::send_more`], unchanged. Never
    /// [`CURLcode::Again`]: a blocked send leaves bytes queued, which
    /// [`Self::send_more`] answers `Ok(())` for.
    #[allow(dead_code)]
    pub(crate) fn send(
        &mut self,
        io: &mut dyn RequestIo,
        header_bytes: &[u8],
        httpversion: u8,
    ) -> CodeResult<()> {
        // `:374-375`.
        if !io.has_connection() {
            return Err(CURLcode::FailedInit);
        }

        // `:377`.
        self.httpversion_sent = httpversion;

        // `:378-379`. The C reads the pointer and the length out of the
        // dynbuf; the slice is both.
        let total = header_bytes.len();
        let mut sent = 0_usize;

        // `:385-399`.
        if self.sendbuf_empty()
            && io.creader_total_length() == 0
            && total <= self.sendbuf_chunk_size()
        {
            self.eos_read = true;
            sent = self.xfer_send(io, header_bytes, total)?;
            // `:392-398`: `buf += nwritten; blen -= nwritten;` and, when
            // nothing is left, the upload is complete already.
            if sent == total {
                self.set_upload_done(io)?;
            }
        }

        // `:401-410`.
        let remaining = header_bytes.get(sent..).unwrap_or(&[]);
        if !remaining.is_empty() {
            // Every remaining byte is a header byte, so the header count grows
            // by the whole length -- the C's `req_send_buffer_add(data, buf,
            // blen, blen)` at `:405`.
            self.sendbuf_add(remaining, remaining.len())?;
            return self.send_more(io);
        }

        Ok(())
    }

    /// `Curl_req_send_more(data)` (`lib/request.c:445-466`): read more from
    /// the client and flush everything that is buffered.
    ///
    /// # Errors
    ///
    /// Any error from the client read except [`CURLcode::Again`], and any
    /// error from the flush except [`CURLcode::Again`].
    ///
    /// **Never [`CURLcode::Again`].** `lib/request.h:191-193` promises it:
    /// *"@return CURLE_OK on success or the error on the sending. Never
    /// returns CURLE_AGAIN."* The flush's `CURLE_AGAIN` means "bytes are still
    /// queued", which is a state the caller learns from
    /// [`Self::want_send`] rather than from a return code, so it is converted
    /// to `Ok(())` at `:462-463`.
    #[allow(dead_code)]
    pub(crate) fn send_more(
        &mut self,
        io: &mut dyn RequestIo,
    ) -> CodeResult<()> {
        // `:450-459`.
        if !self.upload_aborted
            && !self.eos_read
            && !io.xfer_send_is_paused()
            && !self.sendbuf_is_full()
        {
            match self.sendbuf_fill_from_client(io) {
                Ok(_) => {}
                // `:457-458`.
                Err(CURLcode::Again) => {}
                Err(code) => return Err(code),
            }
        }

        // `:461-463`.
        match self.flush(io) {
            Err(CURLcode::Again) => Ok(()),
            other => other,
        }
    }

    /// `Curl_bufq_sipn(&data->req.sendbuf, 0, add_from_client, data, &nread)`
    /// (`lib/request.c:455-456`) together with `add_from_client`
    /// (`:338-350`).
    ///
    /// # Errors
    ///
    /// Whatever the client read returns, [`CURLcode::Again`] included, and
    /// [`CURLcode::OutOfMemory`] or [`CURLcode::Again`] from the queue itself.
    /// [`CURLcode::FailedInit`] when no queue exists, which the documented
    /// call order makes unreachable.
    fn sendbuf_fill_from_client(
        &mut self,
        io: &mut dyn RequestIo,
    ) -> CodeResult<usize> {
        let mut queue = match self.sendbuf.take() {
            Some(queue) => queue,
            None => return Err(CURLcode::FailedInit),
        };

        let mut eos_read = false;
        let outcome = queue.sipn(0, |dest| {
            let read = io.client_read(dest)?;
            if read.eos {
                eos_read = true;
            }
            Ok(read.bytes_read)
        });

        self.sendbuf = Some(queue);
        if eos_read {
            self.eos_read = true;
        }
        outcome
    }
}

// Want-send, want-receive, abort and stop

impl SingleRequest {
    /// `Curl_req_sendbuf_empty(data)` (`lib/request.c:414-417`): true when
    /// nothing is waiting to go to the server.
    ///
    /// True before the queue exists, which is the C's `!req->sendbuf_init`
    /// disjunct.
    #[allow(dead_code)]
    pub(crate) fn sendbuf_empty(&self) -> bool {
        match &self.sendbuf {
            None => true,
            Some(queue) => queue.is_empty(),
        }
    }

    /// `Curl_bufq_is_full(&data->req.sendbuf)`, read at `lib/request.c:453`.
    ///
    /// False before the queue exists: a queue that has not been built is not
    /// under pressure, and answering true would stop
    /// [`Self::send_more`] reading from the client for ever.
    #[allow(dead_code)]
    pub(crate) fn sendbuf_is_full(&self) -> bool {
        match &self.sendbuf {
            None => false,
            Some(queue) => queue.is_full(),
        }
    }

    /// `Curl_req_want_send(data)` (`lib/request.c:419-430`): the request has
    /// something to send and is not blocked.
    #[allow(dead_code)]
    pub(crate) fn want_send(&self, io: &dyn RequestIo) -> bool {
        !self.done
            && !io.progress().upload().rlimit().is_blocked()
            && (self.keepon.contains(KeepFlags::SEND)
                || !self.sendbuf_empty()
                || io.xfer_needs_flush())
    }

    /// `Curl_req_want_recv(data)` (`lib/request.c:432-438`): the request wants
    /// to receive and is not blocked.
    ///
    /// The DOWNLOAD limiter, and `KEEP_RECV` alone -- there is no queue or
    /// pending-output disjunct on this side.
    #[allow(dead_code)]
    pub(crate) fn want_recv(&self, io: &dyn RequestIo) -> bool {
        !self.done
            && !io.progress().download().rlimit().is_blocked()
            && self.keepon.contains(KeepFlags::RECV)
    }

    /// `Curl_req_done_sending(data)` (`lib/request.c:440-443`): the request has
    /// sent all its headers and data.
    #[allow(dead_code)]
    pub(crate) fn done_sending(&self, io: &dyn RequestIo) -> bool {
        self.upload_done && !self.want_send(io)
    }

    /// `Curl_req_abort_sending(data)` (`lib/request.c:468-477`): stop sending
    /// request data.
    ///
    /// # Errors
    ///
    /// [`Self::set_upload_done`]'s error, unchanged.
    #[allow(dead_code)]
    pub(crate) fn abort_sending(
        &mut self,
        io: &mut dyn RequestIo,
    ) -> CodeResult<()> {
        // `:470-475`.
        if !self.upload_done {
            if let Some(queue) = &mut self.sendbuf {
                queue.reset();
            }
            self.upload_aborted = true;
            self.keep_off(KeepFlags::SEND);
            return self.set_upload_done(io);
        }
        Ok(())
    }

    /// `Curl_req_stop_send_recv(data)` (`lib/request.c:479-489`): stop sending
    /// AND receiving.
    ///
    /// # Errors
    ///
    /// [`Self::abort_sending`]'s error, unchanged -- and the keep bits are
    /// cleared even then, exactly as the C clears them before returning the
    /// code it saved.
    #[allow(dead_code)]
    pub(crate) fn stop_send_recv(
        &mut self,
        io: &mut dyn RequestIo,
    ) -> CodeResult<()> {
        let mut result = Ok(());
        // `:485-486`.
        if self.keepon.contains(KeepFlags::SEND) {
            result = self.abort_sending(io);
        }
        // `:487`.
        self.keepon = self.keepon.without(KeepFlags::RECV | KeepFlags::SEND);
        result
    }
}

// Redirect and retry bookkeeping

/// Why a new request is being issued -- supersedes `followtype`
/// (`lib/http.h:40-48`).
///
/// The discriminants are the C's declaration order, written out for the same
/// reason [`Expect100`]'s are.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum FollowType {
    /// `FOLLOW_NONE`. The C's own comment: *"not used within the function,
    /// just a placeholder to allow initing to this"* -- so it is the value a
    /// caller starts from and never the value it passes.
    #[default]
    None = 0,
    /// `FOLLOW_FAKE`: *"only records stuff, not actually following"*. The URL
    /// is worked out and stored for `CURLINFO_REDIRECT_URL`, and no request is
    /// issued.
    Fake = 1,
    /// `FOLLOW_RETRY`: *"set if this is a request retry as opposed to a real
    /// redirect following"*. Uses the same new-request path and does NOT count
    /// as a redirect.
    Retry = 2,
    /// `FOLLOW_REDIR`: *"a full true redirect"*.
    Redir = 3,
}

impl FollowType {
    /// Every kind, in the C's declaration order.
    #[allow(dead_code)]
    pub(crate) const VARIANTS: [Self; 4] =
        [Self::None, Self::Fake, Self::Retry, Self::Redir];

    /// The C spelling, for a diagnostic that has to match the C's.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::None => "FOLLOW_NONE",
            Self::Fake => "FOLLOW_FAKE",
            Self::Retry => "FOLLOW_RETRY",
            Self::Redir => "FOLLOW_REDIR",
        }
    }
}

/// What `CURLOPT_FOLLOWLOCATION` was set to -- supersedes the `CURLFOLLOW_*`
/// bits (`include/curl/curl.h:178-187`) and `data->set.http_follow_mode`.
///
/// These four integers are part of the public ABI: a C program compiled
/// against curl 8.19.0-DEV holds them in its instruction stream, so the
/// discriminants are pinned and asserted rather than inferred.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum FollowMode {
    /// `0`: redirects are not followed. `CURLINFO_REDIRECT_URL` still answers,
    /// through a [`FollowType::Fake`] follow.
    #[default]
    Disabled = 0,
    /// `CURLFOLLOW_ALL` = 1: *"generic follow redirects"*. A custom request
    /// method is kept for every request.
    All = 1,
    /// `CURLFOLLOW_OBEYCODE` = 2: *"Do not use the custom method in the
    /// follow-up request if the HTTP code instructs so (301, 302, 303)"*.
    ObeyCode = 2,
    /// `CURLFOLLOW_FIRSTONLY` = 3: *"Only use the custom method in the first
    /// request, always reset in the next"*.
    FirstOnly = 3,
}

impl FollowMode {
    /// Every mode, in ABI order.
    #[allow(dead_code)]
    pub(crate) const VARIANTS: [Self; 4] =
        [Self::Disabled, Self::All, Self::ObeyCode, Self::FirstOnly];

    /// The ABI integer.
    #[allow(dead_code)]
    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }

    /// True when redirects are followed at all.
    #[allow(dead_code)]
    pub(crate) const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// `curl_easy_setopt(CURLOPT_FOLLOWLOCATION, value)`'s validation
    /// (`lib/setopt.c:1072-1077`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for anything above 3 -- and for
    /// anything NEGATIVE too, which is not obvious from the C: it tests
    /// `(unsigned long)arg > 3`, and the cast turns every negative value into
    /// a very large one. Reproducing that as a closed range keeps the outcome
    /// and drops the trap.
    #[allow(dead_code)]
    pub(crate) fn from_option_value(value: i64) -> CodeResult<Self> {
        match value {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::All),
            2 => Ok(Self::ObeyCode),
            3 => Ok(Self::FirstOnly),
            _ => Err(CURLcode::BadFunctionArgument),
        }
    }
}

/// `CURLOPT_MAXREDIRS`'s default -- `set->maxredirs = 30` at
/// `lib/url.c:363`, described there as a *"sensible default"*.
pub(crate) const MAXREDIRS_DEFAULT: i16 = 30;

/// The `CURLOPT_MAXREDIRS` value that means "no limit"
/// (`lib/http.c:1130`).
pub(crate) const MAXREDIRS_UNLIMITED: i16 = -1;

/// The lowest accepted `CURLOPT_MAXREDIRS` value -- `value_range(&arg, -1,
/// -1, 0x7fff)`'s `below_error` at `lib/setopt.c:1079`.
pub(crate) const MAXREDIRS_MIN: i64 = -1;

/// The highest accepted `CURLOPT_MAXREDIRS` value. Above it the setting is
/// CLAMPED, not rejected -- see [`validate_maxredirs`].
pub(crate) const MAXREDIRS_MAX: i64 = 0x7fff;

/// `curl_easy_setopt(CURLOPT_MAXREDIRS, value)`'s validation
/// (`lib/setopt.c:1078-1082` through `value_range` at `:832-841`).
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for a value below
/// [`MAXREDIRS_MIN`].
#[allow(dead_code)]
pub(crate) fn validate_maxredirs(value: i64) -> CodeResult<i16> {
    if value < MAXREDIRS_MIN {
        return Err(CURLcode::BadFunctionArgument);
    }
    // `0x7fff` is `i16::MAX`, so the clamp makes the conversion exact.
    Ok(value.min(MAXREDIRS_MAX) as i16)
}

/// Which POST-preserving overrides `CURLOPT_POSTREDIR` selected --
/// supersedes `data->set.post301`, `post302` and `post303`
/// (`lib/urldata.h:1588-1590`).
///
/// The bit values are the public `CURL_REDIR_*` integers
/// (`include/curl/curl.h:2400-2405`) and are pinned by the constants below.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct PostRedir {
    /// `set.post301`: keep a POST as a POST after a 301.
    pub(crate) post301: bool,
    /// `set.post302`: keep a POST as a POST after a 302.
    pub(crate) post302: bool,
    /// `set.post303`: keep a POST as a POST after a 303.
    pub(crate) post303: bool,
}

/// `CURL_REDIR_GET_ALL` (`include/curl/curl.h:2400`): switch to GET on all
/// three codes. Also the lowest accepted `CURLOPT_POSTREDIR` value.
pub(crate) const CURL_REDIR_GET_ALL: i64 = 0;

/// `CURL_REDIR_POST_301` (`include/curl/curl.h:2401`).
pub(crate) const CURL_REDIR_POST_301: i64 = 1;

/// `CURL_REDIR_POST_302` (`include/curl/curl.h:2402`).
pub(crate) const CURL_REDIR_POST_302: i64 = 2;

/// `CURL_REDIR_POST_303` (`include/curl/curl.h:2403`).
pub(crate) const CURL_REDIR_POST_303: i64 = 4;

impl PostRedir {
    /// `curl_easy_setopt(CURLOPT_POSTREDIR, value)`'s validation
    /// (`lib/setopt.c:1083-1090`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for a value below
    /// [`CURL_REDIR_GET_ALL`].
    #[allow(dead_code)]
    pub(crate) fn from_option_value(value: i64) -> CodeResult<Self> {
        if value < CURL_REDIR_GET_ALL {
            return Err(CURLcode::BadFunctionArgument);
        }
        Ok(Self {
            post301: (value & CURL_REDIR_POST_301) != 0,
            post302: (value & CURL_REDIR_POST_302) != 0,
            post303: (value & CURL_REDIR_POST_303) != 0,
        })
    }

    /// The `CURLOPT_POSTREDIR` value these three flags encode.
    #[allow(dead_code)]
    pub(crate) const fn as_i64(self) -> i64 {
        let mut bits = CURL_REDIR_GET_ALL;
        if self.post301 {
            bits |= CURL_REDIR_POST_301;
        }
        if self.post302 {
            bits |= CURL_REDIR_POST_302;
        }
        if self.post303 {
            bits |= CURL_REDIR_POST_303;
        }
        bits
    }
}

/// The kind of HTTP request in flight -- supersedes `Curl_HttpReq`
/// (`lib/http.h:30-37`) and `data->state.httpreq`.
///
/// Declaration order preserved, and explicit, because
/// `data->state.httpreq` is stored as a `uint8_t`
/// (`lib/urldata.h:1082-1083`) and the numbers therefore cross a field.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum HttpRequestKind {
    /// `HTTPREQ_GET`.
    #[default]
    Get = 0,
    /// `HTTPREQ_POST`.
    Post = 1,
    /// `HTTPREQ_POST_FORM`. The C's comment: *"we make a difference
    /// internally"*.
    PostForm = 2,
    /// `HTTPREQ_POST_MIME`, likewise distinguished internally.
    PostMime = 3,
    /// `HTTPREQ_PUT`.
    Put = 4,
    /// `HTTPREQ_HEAD`.
    Head = 5,
}

impl HttpRequestKind {
    /// Every kind, in the C's declaration order.
    #[allow(dead_code)]
    pub(crate) const VARIANTS: [Self; 6] = [
        Self::Get,
        Self::Post,
        Self::PostForm,
        Self::PostMime,
        Self::Put,
        Self::Head,
    ];

    /// True for the three kinds the C tests together whenever it asks
    /// *"is this a POST"* -- `HTTPREQ_POST`, `HTTPREQ_POST_FORM` and
    /// `HTTPREQ_POST_MIME` (`lib/http.c:1324-1326`, `:1348-1350`,
    /// `:1366-1368`).
    #[allow(dead_code)]
    pub(crate) const fn is_post_like(self) -> bool {
        matches!(self, Self::Post | Self::PostForm | Self::PostMime)
    }

    /// The C spelling, for a diagnostic that has to match the C's.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::Get => "HTTPREQ_GET",
            Self::Post => "HTTPREQ_POST",
            Self::PostForm => "HTTPREQ_POST_FORM",
            Self::PostMime => "HTTPREQ_POST_MIME",
            Self::Put => "HTTPREQ_PUT",
            Self::Head => "HTTPREQ_HEAD",
        }
    }
}

/// The settings the follow path reads out of `data->set`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FollowSettings {
    /// `data->set.http_follow_mode`, from `CURLOPT_FOLLOWLOCATION`.
    pub(crate) mode: FollowMode,

    /// `data->set.maxredirs`, from `CURLOPT_MAXREDIRS`.
    /// [`MAXREDIRS_UNLIMITED`] means no limit.
    pub(crate) maxredirs: i16,

    /// `data->set.post301`, `post302` and `post303`, from
    /// `CURLOPT_POSTREDIR`.
    pub(crate) postredir: PostRedir,

    /// `data->set.http_auto_referer`, from `CURLOPT_AUTOREFERER`
    /// (`lib/http.c:1142`).
    pub(crate) auto_referer: bool,

    /// `data->set.allow_auth_to_other_hosts`, from
    /// `CURLOPT_UNRESTRICTED_AUTH` (`lib/http.c:1210`).
    ///
    /// When false -- the default -- credentials are dropped on a redirect that
    /// changes the port or the scheme.
    pub(crate) allow_auth_to_other_hosts: bool,
}

impl Default for FollowSettings {
    /// curl's own defaults: following off, 30 redirects, no POST overrides, no
    /// automatic referer, and credentials restricted to the original host.
    fn default() -> Self {
        Self {
            mode: FollowMode::Disabled,
            maxredirs: MAXREDIRS_DEFAULT,
            postredir: PostRedir::default(),
            auto_referer: false,
            allow_auth_to_other_hosts: false,
        }
    }
}

/// The follow bookkeeping of one OPERATION, across every attempt it makes --
/// the `data->state` and `data->info` members the follow path touches.
///
/// Deliberately not part of [`SingleRequest`]: a redirect resets the request
/// and must NOT reset these, or `CURLOPT_MAXREDIRS` could never be reached and
/// a redirect loop would run for ever. `Curl_pretransfer` is what clears them,
/// once per operation, and [`Self::pretransfer`] is that.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FollowState {
    /// `data->state.followlocation` (`lib/urldata.h:1078`): the redirect
    /// counter, *"including auth reloads"* (`lib/http.c:1137-1138`).
    ///
    /// A `u16` because the C field is a `uint16_t`, and
    /// [`MAXREDIRS_MAX`] fits it.
    pub(crate) followlocation: u16,

    /// `data->state.requests` (`lib/urldata.h:960`): *"request counter:
    /// redirects + authentication retakes"*.
    ///
    /// Incremented for every non-[`FollowType::Fake`] follow, retries
    /// included.
    pub(crate) requests: i32,

    /// `data->info.httpcode`: the status `CURLINFO_RESPONSE_CODE` reports.
    pub(crate) httpcode: i32,

    /// `data->info.wouldredirect` (`lib/urldata.h:762`): *"URL this would have
    /// been redirected to if asked to"*.
    ///
    /// Written by a [`FollowType::Fake`] follow and read by
    /// `CURLINFO_REDIRECT_URL`. Owned, so it is released with the state.
    pub(crate) wouldredirect: Option<String>,

    /// `data->state.allow_port` (`lib/urldata.h:1096-1097`): whether
    /// `CURLOPT_PORT` is allowed to take effect.
    ///
    /// `Curl_pretransfer` sets it (`lib/transfer.c:533`) and a redirect to an
    /// absolute URL clears it (`lib/http.c:1274`), so an explicit port does
    /// not follow the transfer to a host that never asked for it.
    pub(crate) allow_port: bool,

    /// `data->state.http_ignorecustom`: drop `CURLOPT_CUSTOMREQUEST` for the
    /// next request.
    ///
    /// Set by [`FollowMode::FirstOnly`] after the first request
    /// (`lib/http.c:1279-1284`) and by a status-driven switch to GET under
    /// [`FollowMode::ObeyCode`] (`lib/http.c:1105`).
    pub(crate) ignore_custom_request: bool,

    /// `data->state.this_is_a_follow` (`lib/urldata.h:1091`): *"this is a
    /// followed Location: request"*.
    ///
    /// Read by the URL layer to decide whether the user's `CURLU` handle may
    /// be reused (`lib/url.c:1645`) and to annotate a diagnostic (`:1571`).
    pub(crate) this_is_a_follow: bool,
}

impl FollowState {
    /// The state `Curl_pretransfer` establishes
    /// (`lib/transfer.c:492-494` and `:533`).
    ///
    /// Note which fields are NOT cleared: `httpcode` and `wouldredirect` are
    /// `data->info` members that `Curl_initinfo` owns, and clearing them here
    /// would erase the previous transfer's `CURLINFO_RESPONSE_CODE` before the
    /// application had a chance to read it.
    #[allow(dead_code)]
    pub(crate) fn pretransfer(&mut self) {
        self.requests = 0;
        self.followlocation = 0;
        self.this_is_a_follow = false;
        self.allow_port = true;
    }

    /// True when the redirect counter has reached the configured ceiling.
    ///
    /// `lib/http.c:1130-1131`: `(maxredirs != -1) && (followlocation >=
    /// maxredirs)`. [`MAXREDIRS_UNLIMITED`] therefore never reaches it, and a
    /// ceiling of zero is reached immediately -- which is how
    /// `--max-redirs 0` refuses the very first redirect.
    #[allow(dead_code)]
    pub(crate) fn reached_max_redirects(&self, maxredirs: i16) -> bool {
        maxredirs != MAXREDIRS_UNLIMITED
            && i64::from(self.followlocation) >= i64::from(maxredirs)
    }
}

/// What the protocol made of a redirect target -- the two outcomes of
/// `curl_url_set(data->state.uh, CURLUPART_URL, newurl, flags)` followed by
/// `curl_url_get` (`lib/http.c:1181-1204`).
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum ResolvedTarget {
    /// The target parsed; here is the absolute URL to request.
    Url(String),

    /// The target did not parse.
    ///
    /// `code` is what a follow must return, already mapped from `CURLUcode` by
    /// `Curl_uc_to_curlcode` -- the mapping belongs to the URL API, so the
    /// protocol performs it and this module consumes the result. `reason` is
    /// `curl_url_strerror(uc)`, which appears verbatim in the C's failure
    /// line.
    Unparsable {
        /// The curl code the failure maps to.
        code: CURLcode,
        /// `curl_url_strerror`'s static text.
        reason: &'static str,
    },
}

/// The protocol-specific half of following a redirect.
pub(crate) trait ProtocolFollow: fmt::Debug {
    /// `Curl_is_absolute_url(newurl, NULL, 0, FALSE)`, as called at
    /// `lib/http.c:1176`.
    fn target_is_absolute(&self, target: &str) -> bool;

    /// `curl_url_set(data->state.uh, CURLUPART_URL, newurl, flags)` and the
    /// `curl_url_get` that follows it (`lib/http.c:1181-1204`).
    fn resolve_target(
        &mut self,
        target: &str,
        follow_type: FollowType,
    ) -> ResolvedTarget;

    /// Replace `data->state.referer` with the current URL stripped of its
    /// fragment, its user and its password (`lib/http.c:1142-1168`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`], which is the only failure the C reports
    /// here -- it folds every `CURLUcode` from the five URL calls into it at
    /// `:1166-1167`.
    fn set_auto_referer(&mut self) -> CodeResult<()>;

    /// Drop the credentials when the resolved URL moved to another port or
    /// another scheme (`lib/http.c:1207-1250`).
    ///
    /// # Errors
    ///
    /// Whatever reading the port or the scheme back out of the URL reports.
    fn clear_auth_if_moved(&mut self, allow_port: bool) -> CodeResult<()>;

    /// `Curl_bufref_set(&data->state.url, follow_url, 0, curl_free)`
    /// (`lib/http.c:1275`): the URL the next request will use.
    fn commit_url(&mut self, url: String);

    /// `data->state.httpreq`: the request method in flight.
    fn request_method(&self) -> HttpRequestKind;

    /// `data->state.httpreq = method` (`lib/http.c:1110`).
    fn set_request_method(&mut self, method: HttpRequestKind);

    /// `data->set.str[STRING_CUSTOMREQUEST]`: what `CURLOPT_CUSTOMREQUEST` was
    /// set to, if anything.
    fn custom_request(&self) -> Option<&str>;
}

impl SingleRequest {
    /// `multi_follow(data, handler, newurl, type)`
    /// (`lib/multi.c:1870-1878`): follow a redirect or issue a retry.
    ///
    /// `protocol` is `None` when the scheme's handler has no `follow`
    /// operation, and the answer is then [`CURLcode::TooManyRedirects`] --
    /// which reads oddly and is the C's, deliberately: the multi handle is
    /// about to go back to `CONNECT` with a URL nothing can act on, so
    /// answering "no more redirects" is what stops it. Silently ignoring the
    /// follow would leave the transfer looping.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooManyRedirects`] with no follow operation, and whatever
    /// [`Self::follow_location`] reports.
    #[allow(dead_code)]
    pub(crate) fn follow(
        &mut self,
        io: &mut dyn RequestIo,
        protocol: Option<&mut dyn ProtocolFollow>,
        settings: &FollowSettings,
        state: &mut FollowState,
        target: &str,
        follow_type: FollowType,
    ) -> CodeResult<()> {
        match protocol {
            Some(protocol) => self.follow_location(
                io,
                protocol,
                settings,
                state,
                target,
                follow_type,
            ),
            None => Err(CURLcode::TooManyRedirects),
        }
    }

    /// `Curl_http_follow(data, newurl, type)` (`lib/http.c:1115-1396`), with
    /// its URL, scheme, port and method work delegated to `protocol`.
    ///
    /// Nine steps, in the C's order:
    ///
    /// 1. Every non-fake follow increments [`FollowState::requests`]
    ///    (`:1127-1128`), retries included.
    /// 2. A real redirect either trips the ceiling -- in which case it becomes
    ///    a FAKE follow so the would-be target is still recorded -- or
    ///    increments [`FollowState::followlocation`] and sets the automatic
    ///    referer (`:1129-1170`). A RETRY does neither, which is what keeps a
    ///    retried request from consuming a redirect.
    /// 3. An absolute target on a redirect that is not a retry and not a 401
    ///    or 407 forfeits any inherited explicit port (`:1172-1179`).
    /// 4. The target is resolved. A parse failure is fatal unless the follow is
    ///    fake, in which case the raw target is kept verbatim
    ///    (`:1181-1204`).
    /// 5. Credentials are dropped when the URL moved, unless
    ///    `CURLOPT_UNRESTRICTED_AUTH` permits them to travel
    ///    (`:1207-1250`).
    /// 6. A FAKE follow stores the URL, answers
    ///    [`CURLcode::TooManyRedirects`] if it got here by tripping the
    ///    ceiling, and stops (`:1253-1263`).
    /// 7. The URL is committed, the request is SOFT reset -- not hard, so the
    ///    operation's timing survives -- and the C's line is emitted
    ///    (`:1265-1284`).
    /// 8. The method is switched where the status says so
    ///    (`:1286-1385`).
    /// 9. A failed rewind is fatal unless the method became GET, and then the
    ///    redirect timer is recorded and the transfer sizes are forgotten
    ///    (`:1387-1393`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooManyRedirects`] when the ceiling was reached, the
    /// resolution's error, the referer's or the credential check's error, and
    /// the deferred rewind failure.
    ///
    /// # Panics
    ///
    /// In a debug build only, on [`FollowType::None`] -- the C's
    /// `DEBUGASSERT(type != FOLLOW_NONE)` at `:1124`. It is the initialiser
    /// value, never an argument.
    #[allow(dead_code)]
    pub(crate) fn follow_location(
        &mut self,
        io: &mut dyn RequestIo,
        protocol: &mut dyn ProtocolFollow,
        settings: &FollowSettings,
        state: &mut FollowState,
        target: &str,
        follow_type: FollowType,
    ) -> CodeResult<()> {
        // `:1124`.
        debug_assert!(
            follow_type != FollowType::None,
            "FOLLOW_NONE is an initialiser, not an argument"
        );

        let mut follow_type = follow_type;
        let mut reached_max = false;

        // 1 -- `:1127-1128`.
        if follow_type != FollowType::Fake {
            state.requests = state.requests.saturating_add(1);
        }

        // 2 -- `:1129-1170`.
        if follow_type == FollowType::Redir {
            if state.reached_max_redirects(settings.maxredirs) {
                reached_max = true;
                // `:1132-1133`: switch to fake so that the would-be
                // redirected-to URL is still stored.
                follow_type = FollowType::Fake;
            } else {
                state.followlocation = state.followlocation.saturating_add(1);
                if settings.auto_referer {
                    protocol.set_auto_referer()?;
                }
            }
        }

        // 3 -- `:1172-1179`.
        let disallow_port = follow_type != FollowType::Retry
            && self.httpcode != 401
            && self.httpcode != 407
            && protocol.target_is_absolute(target);

        // 4 and 5 -- `:1181-1250`.
        let follow_url = match protocol.resolve_target(target, follow_type) {
            ResolvedTarget::Url(url) => {
                // `:1207-1250`.
                if !settings.allow_auth_to_other_hosts
                    && follow_type != FollowType::Fake
                {
                    protocol.clear_auth_if_moved(state.allow_port)?;
                }
                url
            }
            ResolvedTarget::Unparsable { code, reason } => {
                // `:1186-1197`.
                if code == CURLcode::OutOfMemory
                    || follow_type != FollowType::Fake
                {
                    io.failf(format_args!(
                        "The redirect target URL could not be parsed: \
                             {reason}"
                    ));
                    return Err(code);
                }
                // The URL did not parse, but this is a fake follow, so the
                // field is duplicated as-is.
                target.to_string()
            }
        };

        // 6 -- `:1253-1263`.
        if follow_type == FollowType::Fake {
            state.wouldredirect = Some(follow_url);
            if reached_max {
                io.failf(format_args!(
                    "Maximum ({}) redirects followed",
                    settings.maxredirs
                ));
                return Err(CURLcode::TooManyRedirects);
            }
            return Ok(());
        }

        // 7 -- `:1265-1284`.
        if disallow_port {
            state.allow_port = false;
        }
        // The C hands the allocation to the bufref and then reads the same
        // pointer for the line below.
        protocol.commit_url(follow_url.clone());
        let rewind_result = self.soft_reset(io);
        io.infof(format_args!(
            "Issue another request to this URL: '{follow_url}'"
        ));
        state.this_is_a_follow = true;
        if settings.mode == FollowMode::FirstOnly
            && protocol.custom_request().is_some()
            && !state.ignore_custom_request
        {
            state.ignore_custom_request = true;
            io.infof(format_args!(
                "Drop custom request method for next request"
            ));
        }

        // 8 -- `:1286-1385`.
        let switch_to_get =
            self.redirect_method_switch(io, protocol, settings, state);

        // 9 -- `:1387-1393`.
        if let Err(code) = rewind_result {
            if !switch_to_get {
                return Err(code);
            }
        }
        io.pgrs_time(TimerId::Redirect);
        io.progress_mut().reset_transfer_sizes();

        Ok(())
    }

    /// The status-driven half of `Curl_http_follow`'s `switch`
    /// (`lib/http.c:1293-1385`), and `http_switch_to_get`
    /// (`:1098-1112`) with it.
    ///
    /// Three codes act; every other code, including 304, 305, 307 and 308,
    /// leaves the method alone:
    ///
    /// * **301 Moved Permanently** and **302 Found** switch a POST to a GET,
    ///   unless `CURLOPT_POSTREDIR` set the matching bit. The C's comment
    ///   explains why a switch that RFC 1945 forbids is the default:
    ///   *"Many webservers expect this ... To be sure that libcurl gets the
    ///   page that most user agents would get, libcurl has to force GET."*
    /// * **303 See Other** switches ANY non-GET method to GET, because the
    ///   `Location:` is *"not the resource but a substitute for the
    ///   resource"* -- so a PUT or a DELETE switches too. A POST switches
    ///   unless `CURL_REDIR_POST_303` is set.
    ///
    /// `http_switch_to_get` also decides what to say about a custom method,
    /// and the three modes differ:
    ///
    /// * [`FollowMode::ObeyCode`] honours the status: the custom method is
    ///   dropped and `Switch to GET because of N response` is logged.
    /// * [`FollowMode::All`] keeps it and logs `Stick to M instead of GET`.
    /// * [`FollowMode::FirstOnly`] keeps it silently, because it has already
    ///   logged `Drop custom request method for next request` at step 7 and
    ///   saying both would contradict itself.
    fn redirect_method_switch(
        &mut self,
        io: &mut dyn RequestIo,
        protocol: &mut dyn ProtocolFollow,
        settings: &FollowSettings,
        state: &mut FollowState,
    ) -> bool {
        let method = protocol.request_method();
        let code = state.httpcode;

        // `:1293-1385`. Only three codes act; `default:` and the two explicit
        // no-op arms (304 at `:1373` and 305 at `:1377`) all fall through.
        let switch_to_get = match code {
            // `:1306-1329`.
            301 => method.is_post_like() && !settings.postredir.post301,
            // `:1331-1354`.
            302 => method.is_post_like() && !settings.postredir.post302,
            // `:1356-1371`.
            303 => {
                method != HttpRequestKind::Get
                    && (!method.is_post_like() || !settings.postredir.post303)
            }
            _ => false,
        };

        if switch_to_get {
            // `http_switch_to_get`, `:1098-1112`.
            let custom = protocol.custom_request().is_some();
            if (custom || method != HttpRequestKind::Get)
                && settings.mode == FollowMode::ObeyCode
            {
                // `:1104-1106`.
                io.infof(format_args!(
                    "Switch to GET because of {code} response"
                ));
                state.ignore_custom_request = true;
            } else if custom && settings.mode != FollowMode::FirstOnly {
                // `:1108-1109`. Read back rather than captured earlier so the
                // borrow ends before the method is written.
                if let Some(name) = protocol.custom_request() {
                    io.infof(format_args!("Stick to {name} instead of GET"));
                }
            }
            // `:1110-1111`.
            protocol.set_request_method(HttpRequestKind::Get);
            self.rewind_read = false;
        }

        switch_to_get
    }
}

// Tests

// `cargo test` builds with `debug_assertions` on, so the contract assertions
// this module transcribes from the C's `DEBUGASSERT`s do fire during a test
// run. No test drives a path into one deliberately: an assertion that fires
// is a caller bug, and the C's own callers respect every one of them.
#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::Duration;

    use super::*;
    use crate::util::timeval::{Clock, TestClock};

    // -- the doubles ------------------------------------------------------

    /// What the scripted transport does with one send.
    #[derive(Clone, Debug)]
    enum SendStep {
        /// Accept this many bytes, clamped to what was offered.
        Accept(usize),
        /// Accept nothing: the transport is blocking. `Curl_xfer_send` reports
        /// that as success with zero written, never as `CURLE_AGAIN`.
        Block,
        /// Fail with this code.
        Fail(CURLcode),
    }

    /// One send the transport observed.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SendRecord {
        offered: Vec<u8>,
        eos: bool,
        accepted: usize,
    }

    /// One payload that reached the debug callback.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct DebugRecord {
        kind: TraceDataKind,
        bytes: Vec<u8>,
    }

    /// What the scripted client reader does with one read.
    #[derive(Clone, Debug)]
    enum ReadStep {
        /// Hand over these bytes, and say whether they are the last.
        Bytes(Vec<u8>, bool),
        /// End of stream with no bytes.
        Eos,
        /// Nothing ready yet.
        Again,
        /// Fail with this code.
        Fail(CURLcode),
    }

    /// A [`DebugEnv`] whose one variable is fixed by the test.
    #[derive(Debug)]
    struct FixedEnv {
        small_req_send: Option<String>,
    }

    impl DebugEnv for FixedEnv {
        fn small_req_send(&self) -> Option<&str> {
            self.small_req_send.as_deref()
        }
    }

    /// The whole seam, in memory.
    #[derive(Debug)]
    struct TestIo {
        clock: TestClock,
        progress: Progress,
        config: RequestConfig,
        connected: bool,
        env: Option<FixedEnv>,
        sends: VecDeque<SendStep>,
        sent: Vec<SendRecord>,
        needs_flush: bool,
        flush_results: VecDeque<CodeResult<()>>,
        flushes: usize,
        shutdowns: VecDeque<CodeResult<SendShutdown>>,
        shutdown_calls: usize,
        send_closes: usize,
        send_close_result: CodeResult<()>,
        reads: VecDeque<ReadStep>,
        read_calls: usize,
        total_length: i64,
        creader_done_calls: Vec<bool>,
        client_start_result: CodeResult<()>,
        client_starts: usize,
        client_resets: usize,
        client_cleanups: usize,
        doh_closes: usize,
        debugged: Vec<DebugRecord>,
        info: Vec<String>,
        fail: Vec<String>,
        traces: Vec<String>,
        timers: Vec<TimerId>,
    }

    impl TestIo {
        /// A connected transport that accepts everything, a client with
        /// nothing to upload, and a clock pinned at 100 seconds.
        fn new() -> Self {
            Self {
                clock: TestClock::new(CurlTime::new(100, 0)),
                progress: Progress::default(),
                config: RequestConfig {
                    // Small enough that a test can overflow one chunk with a
                    // readable literal.
                    upload_buffer_size: 16,
                    max_send_speed: 0,
                    opt_no_body: false,
                },
                connected: true,
                env: None,
                sends: VecDeque::new(),
                sent: Vec::new(),
                needs_flush: false,
                flush_results: VecDeque::new(),
                flushes: 0,
                shutdowns: VecDeque::new(),
                shutdown_calls: 0,
                send_closes: 0,
                send_close_result: Ok(()),
                reads: VecDeque::new(),
                read_calls: 0,
                total_length: 0,
                creader_done_calls: Vec::new(),
                client_start_result: Ok(()),
                client_starts: 0,
                client_resets: 0,
                client_cleanups: 0,
                doh_closes: 0,
                debugged: Vec::new(),
                info: Vec::new(),
                fail: Vec::new(),
                traces: Vec::new(),
                timers: Vec::new(),
            }
        }

        /// Queues one transport outcome per element, in order.
        fn script_sends(&mut self, steps: &[SendStep]) {
            self.sends.extend(steps.iter().cloned());
        }

        /// Queues one client-read outcome per element, in order.
        fn script_reads(&mut self, steps: &[ReadStep]) {
            self.reads.extend(steps.iter().cloned());
        }

        /// Every offer the transport saw, as a flat byte string.
        fn offered_bytes(&self) -> Vec<u8> {
            let mut all = Vec::new();
            for record in &self.sent {
                all.extend_from_slice(&record.offered);
            }
            all
        }

        /// Every byte the transport ACCEPTED, in order.
        fn accepted_bytes(&self) -> Vec<u8> {
            let mut all = Vec::new();
            for record in &self.sent {
                all.extend_from_slice(&record.offered[..record.accepted]);
            }
            all
        }

        /// How many offers carried the end-of-stream flag.
        fn eos_offers(&self) -> usize {
            self.sent.iter().filter(|record| record.eos).count()
        }

        /// The concatenation of every payload traced under `kind`.
        fn debugged_under(&self, kind: TraceDataKind) -> Vec<u8> {
            let mut all = Vec::new();
            for record in &self.debugged {
                if record.kind == kind {
                    all.extend_from_slice(&record.bytes);
                }
            }
            all
        }

        /// Whether any informational line equals `line` exactly.
        fn said(&self, line: &str) -> bool {
            self.info.iter().any(|seen| seen == line)
        }

        /// Whether any debug-build trace line equals `line` exactly.
        fn traced(&self, line: &str) -> bool {
            self.traces.iter().any(|seen| seen == line)
        }

        /// Blocks or unblocks the upload limiter, which is also what
        /// `Curl_xfer_pause_send` does.
        fn block_upload(&mut self, blocked: bool) {
            let now = self.clock.now();
            self.progress.upload_mut().rlimit_mut().block(blocked, now);
        }

        /// Blocks or unblocks the download limiter.
        fn block_download(&mut self, blocked: bool) {
            let now = self.clock.now();
            self.progress
                .download_mut()
                .rlimit_mut()
                .block(blocked, now);
        }
    }

    impl RequestIo for TestIo {
        fn config(&self) -> RequestConfig {
            self.config
        }

        fn has_connection(&self) -> bool {
            self.connected
        }

        fn debug_env(&self) -> Option<&dyn DebugEnv> {
            match &self.env {
                Some(env) => Some(env),
                None => None,
            }
        }

        fn xfer_send(&mut self, bytes: &[u8], eos: bool) -> CodeResult<usize> {
            let step = self
                .sends
                .pop_front()
                .unwrap_or(SendStep::Accept(usize::MAX));
            let accepted = match step {
                SendStep::Fail(code) => return Err(code),
                SendStep::Block => 0,
                SendStep::Accept(count) => count.min(bytes.len()),
            };
            self.sent.push(SendRecord {
                offered: bytes.to_vec(),
                eos,
                accepted,
            });
            Ok(accepted)
        }

        fn xfer_needs_flush(&self) -> bool {
            self.needs_flush
        }

        fn xfer_flush(&mut self) -> CodeResult<()> {
            self.flushes += 1;
            self.flush_results.pop_front().unwrap_or(Ok(()))
        }

        fn xfer_send_close(&mut self) -> CodeResult<()> {
            self.send_closes += 1;
            self.send_close_result
        }

        fn xfer_send_shutdown(&mut self) -> CodeResult<SendShutdown> {
            self.shutdown_calls += 1;
            self.shutdowns
                .pop_front()
                .unwrap_or(Ok(SendShutdown::Complete))
        }

        fn client_read(&mut self, into: &mut [u8]) -> CodeResult<ReadOutcome> {
            self.read_calls += 1;
            match self.reads.pop_front().unwrap_or(ReadStep::Eos) {
                ReadStep::Fail(code) => Err(code),
                ReadStep::Again => Err(CURLcode::Again),
                ReadStep::Eos => Ok(ReadOutcome::EOS),
                ReadStep::Bytes(bytes, eos) => {
                    let count = bytes.len().min(into.len());
                    into[..count].copy_from_slice(&bytes[..count]);
                    if count < bytes.len() {
                        // The destination was too small, so the remainder goes
                        // back on the script and this read is not the last.
                        self.reads.push_front(ReadStep::Bytes(
                            bytes[count..].to_vec(),
                            eos,
                        ));
                        Ok(ReadOutcome::new(count, false))
                    } else {
                        Ok(ReadOutcome::new(count, eos))
                    }
                }
            }
        }

        fn creader_done(&mut self, premature: bool) {
            self.creader_done_calls.push(premature);
        }

        fn creader_total_length(&self) -> i64 {
            self.total_length
        }

        fn client_start(&mut self) -> CodeResult<()> {
            self.client_starts += 1;
            self.client_start_result
        }

        fn client_reset(&mut self) {
            self.client_resets += 1;
        }

        fn client_cleanup(&mut self) {
            self.client_cleanups += 1;
        }

        fn doh_close(&mut self) {
            self.doh_closes += 1;
        }

        fn progress(&self) -> &Progress {
            &self.progress
        }

        fn progress_mut(&mut self) -> &mut Progress {
            &mut self.progress
        }

        fn pgrs_now(&mut self) -> CurlTime {
            self.progress.sample(&self.clock)
        }

        fn pgrs_time(&mut self, timer: TimerId) {
            self.timers.push(timer);
            self.progress.time(timer, &self.clock);
        }

        fn debug(&mut self, kind: TraceDataKind, bytes: &[u8]) {
            self.debugged.push(DebugRecord {
                kind,
                bytes: bytes.to_vec(),
            });
        }

        fn infof(&mut self, line: fmt::Arguments<'_>) {
            self.info.push(line.to_string());
        }

        fn failf(&mut self, line: fmt::Arguments<'_>) {
            self.fail.push(line.to_string());
        }

        fn trace(&mut self, line: fmt::Arguments<'_>) {
            self.traces.push(line.to_string());
        }
    }

    /// The protocol half of a follow, in memory.
    #[derive(Debug)]
    struct TestFollow {
        absolute: bool,
        resolve: VecDeque<ResolvedTarget>,
        resolve_types: Vec<FollowType>,
        referer_result: CodeResult<()>,
        referer_calls: usize,
        clear_auth_result: CodeResult<()>,
        clear_auth_calls: Vec<bool>,
        committed: Vec<String>,
        method: HttpRequestKind,
        method_sets: Vec<HttpRequestKind>,
        custom_request: Option<String>,
    }

    impl TestFollow {
        /// Resolves every target to `url`, is not absolute, and has no custom
        /// method.
        fn new(url: &str) -> Self {
            let mut resolve = VecDeque::new();
            resolve.push_back(ResolvedTarget::Url(url.to_string()));
            Self {
                absolute: false,
                resolve,
                resolve_types: Vec::new(),
                referer_result: Ok(()),
                referer_calls: 0,
                clear_auth_result: Ok(()),
                clear_auth_calls: Vec::new(),
                committed: Vec::new(),
                method: HttpRequestKind::Get,
                method_sets: Vec::new(),
                custom_request: None,
            }
        }
    }

    impl ProtocolFollow for TestFollow {
        fn target_is_absolute(&self, _target: &str) -> bool {
            self.absolute
        }

        fn resolve_target(
            &mut self,
            target: &str,
            follow_type: FollowType,
        ) -> ResolvedTarget {
            self.resolve_types.push(follow_type);
            self.resolve
                .pop_front()
                .unwrap_or_else(|| ResolvedTarget::Url(target.to_string()))
        }

        fn set_auto_referer(&mut self) -> CodeResult<()> {
            self.referer_calls += 1;
            self.referer_result
        }

        fn clear_auth_if_moved(&mut self, allow_port: bool) -> CodeResult<()> {
            self.clear_auth_calls.push(allow_port);
            self.clear_auth_result
        }

        fn commit_url(&mut self, url: String) {
            self.committed.push(url);
        }

        fn request_method(&self) -> HttpRequestKind {
            self.method
        }

        fn set_request_method(&mut self, method: HttpRequestKind) {
            self.method_sets.push(method);
            self.method = method;
        }

        fn custom_request(&self) -> Option<&str> {
            self.custom_request.as_deref()
        }
    }

    /// A started request over a fresh seam: the state every send test needs.
    fn started() -> (SingleRequest, TestIo) {
        let mut io = TestIo::new();
        let mut req = SingleRequest::new();
        req.start(&mut io).expect("a fresh start cannot fail");
        (req, io)
    }

    // -- the vocabulary ---------------------------------------------------

    #[test]
    fn keep_flags_carry_the_c_bit_values() {
        assert_eq!(KeepFlags::NONE.bits(), 0);
        assert_eq!(KeepFlags::RECV.bits(), 1 << 0);
        assert_eq!(KeepFlags::SEND.bits(), 1 << 1);
        assert!(KeepFlags::NONE.is_empty());
        assert!(!KeepFlags::RECV.is_empty());

        let both = KeepFlags::RECV | KeepFlags::SEND;
        assert_eq!(both.bits(), 3);
        assert!(both.contains(KeepFlags::RECV));
        assert!(both.contains(KeepFlags::SEND));
        assert!(both.contains(both));
        assert!(!KeepFlags::RECV.contains(KeepFlags::SEND));
        // The empty set is contained in everything, which is what makes
        // `contains` usable as the C's truth test.
        assert!(KeepFlags::NONE.contains(KeepFlags::NONE));

        assert_eq!(both.without(KeepFlags::SEND), KeepFlags::RECV);
        assert_eq!(both.without(both), KeepFlags::NONE);

        let mut accumulated = KeepFlags::NONE;
        accumulated |= KeepFlags::SEND;
        assert_eq!(accumulated, KeepFlags::SEND);
    }

    #[test]
    fn expect100_and_upgrade101_keep_the_source_order() {
        assert_eq!(Expect100::SendData as i32, 0);
        assert_eq!(Expect100::AwaitingContinue as i32, 1);
        assert_eq!(Expect100::SendingRequest as i32, 2);
        assert_eq!(Expect100::Failed as i32, 3);
        assert_eq!(Expect100::default(), Expect100::SendData);
        assert_eq!(Expect100::VARIANTS.len(), 4);
        for (index, state) in Expect100::VARIANTS.iter().enumerate() {
            assert_eq!(*state as usize, index);
            assert!(state.c_name().starts_with("EXP100_"));
        }

        assert_eq!(Upgrade101::None as i32, 0);
        assert_eq!(Upgrade101::WebSocket as i32, 1);
        assert_eq!(Upgrade101::H2 as i32, 2);
        assert_eq!(Upgrade101::Received as i32, 3);
        assert_eq!(Upgrade101::default(), Upgrade101::None);
        assert_eq!(Upgrade101::VARIANTS.len(), 4);
        for (index, state) in Upgrade101::VARIANTS.iter().enumerate() {
            assert_eq!(*state as usize, index);
            assert!(state.c_name().starts_with("UPGR101_"));
        }
    }

    #[test]
    fn send_shutdown_reports_only_completion() {
        assert!(SendShutdown::Complete.is_complete());
        assert!(!SendShutdown::Pending.is_complete());
        assert_ne!(SendShutdown::Pending, SendShutdown::Complete);
    }

    #[test]
    fn the_request_configuration_defaults_to_curls_own() {
        let config = RequestConfig::default();
        assert_eq!(config.upload_buffer_size, UPLOAD_BUFFER_DEFAULT);
        assert_eq!(UPLOAD_BUFFER_DEFAULT, 65536);
        assert_eq!(config.max_send_speed, 0);
        assert!(!config.opt_no_body);
    }

    // -- initialisation ---------------------------------------------------

    #[test]
    fn the_initial_request_is_zeroed_but_for_two_sentinels() {
        let req = SingleRequest::new();

        // The two the C sets explicitly rather than leaving at zero.
        assert_eq!(req.size, -1);
        assert_eq!(req.maxdownload, -1);

        assert_eq!(req.bytecount, 0);
        assert_eq!(req.writebytecount, 0);
        assert_eq!(req.start, CurlTime::ZERO);
        assert_eq!(req.headerbytecount, 0);
        assert_eq!(req.allheadercount, 0);
        assert_eq!(req.deductheadercount, 0);
        assert_eq!(req.headerline, 0);
        assert_eq!(req.offset, 0);
        assert_eq!(req.httpcode, 0);
        assert_eq!(req.keepon(), KeepFlags::NONE);
        assert_eq!(req.httpversion_sent, 0);
        assert_eq!(req.httpversion, 0);
        assert_eq!(req.upgr101, Upgrade101::None);
        assert_eq!(req.sendbuf_hds_len, 0);
        assert_eq!(req.timeofdoc, 0);
        assert!(req.location.is_none());
        assert!(req.newurl.is_none());
        #[cfg(feature = "cookies")]
        assert_eq!(req.setcookies, 0);

        // No queue, so both queue predicates answer for its absence.
        assert!(!req.sendbuf_init());
        assert!(req.sendbuf_empty());
        assert!(!req.sendbuf_is_full());
        assert_eq!(req.sendbuf_len(), 0);
        assert_eq!(req.sendbuf_chunk_size(), 0);

        // Every one of the C's 23 BIT() members, false.
        assert!(!req.header);
        assert!(!req.done);
        assert!(!req.content_range);
        assert!(!req.download_done);
        assert!(!req.eos_written);
        assert!(!req.eos_read);
        assert!(!req.eos_sent);
        assert!(!req.rewind_read);
        assert!(!req.upload_done);
        assert!(!req.upload_aborted);
        assert!(!req.ignorebody);
        assert!(!req.http_bodyless);
        assert!(!req.chunk);
        assert!(!req.resp_trailer);
        assert!(!req.ignore_cl);
        assert!(!req.upload_chunky);
        assert!(!req.no_body);
        assert!(!req.authneg);
        assert!(!req.shutdown);
        assert!(!req.shutdown_err_ignore);
        assert!(!req.reader_started);
    }

    /// Every field set to something a fresh request would never hold, so that
    /// a reset which misses one is caught rather than accidentally correct.
    fn dirty_request() -> SingleRequest {
        let mut req = SingleRequest::new();
        req.size = 4096;
        req.maxdownload = 2048;
        req.bytecount = 111;
        req.writebytecount = 222;
        req.start = CurlTime::new(7, 500_000);
        req.headerbytecount = 33;
        req.allheadercount = 44;
        req.deductheadercount = 55;
        req.headerline = 6;
        req.offset = 777;
        req.httpcode = 404;
        req.set_keepon(KeepFlags::RECV | KeepFlags::SEND);
        req.httpversion_sent = 11;
        req.httpversion = 20;
        req.upgr101 = Upgrade101::Received;
        req.sendbuf_hds_len = 9;
        req.timeofdoc = 1_700_000_000;
        req.location = Some("https://example.test/moved".to_string());
        req.newurl = Some("https://example.test/next".to_string());
        #[cfg(feature = "cookies")]
        {
            req.setcookies = 3;
        }
        req.header = true;
        req.done = true;
        req.content_range = true;
        req.download_done = true;
        req.eos_written = true;
        req.eos_read = true;
        req.eos_sent = true;
        req.rewind_read = true;
        req.upload_done = true;
        req.upload_aborted = true;
        req.ignorebody = true;
        req.http_bodyless = true;
        req.chunk = true;
        req.resp_trailer = true;
        req.ignore_cl = true;
        req.upload_chunky = true;
        req.no_body = true;
        req.authneg = true;
        req.shutdown = true;
        req.shutdown_err_ignore = true;
        req.reader_started = true;
        req
    }

    // -- soft reset --------------------------------------------------------

    #[test]
    fn soft_reset_clears_exactly_the_source_field_list() {
        let mut io = TestIo::new();
        let mut req = dirty_request();
        req.soft_reset(&mut io).expect("the client start succeeds");

        // Cleared: the nine booleans of `lib/request.c:48-56`.
        assert!(!req.done);
        assert!(!req.upload_done);
        assert!(!req.upload_aborted);
        assert!(!req.download_done);
        assert!(!req.eos_written);
        assert!(!req.eos_read);
        assert!(!req.eos_sent);
        assert!(!req.ignorebody);
        assert!(!req.shutdown);
        // Zeroed: the nine counters of `:57-66`, plus `header`.
        assert_eq!(req.bytecount, 0);
        assert_eq!(req.writebytecount, 0);
        assert!(!req.header);
        assert_eq!(req.headerline, 0);
        assert_eq!(req.headerbytecount, 0);
        assert_eq!(req.allheadercount, 0);
        assert_eq!(req.deductheadercount, 0);
        assert_eq!(req.httpversion_sent, 0);
        assert_eq!(req.httpversion, 0);
        assert_eq!(req.sendbuf_hds_len, 0);

        // Untouched -- and this half of the assertion is the load-bearing
        // one, because a reset that cleared any of these would break the
        // follow-up request that is being set up while it runs.
        assert_eq!(req.size, 4096);
        assert_eq!(req.maxdownload, 2048);
        assert_eq!(req.start, CurlTime::new(7, 500_000));
        assert_eq!(req.offset, 777);
        assert_eq!(req.httpcode, 404);
        assert_eq!(req.keepon(), KeepFlags::RECV | KeepFlags::SEND);
        assert_eq!(req.upgr101, Upgrade101::Received);
        assert_eq!(req.timeofdoc, 1_700_000_000);
        assert_eq!(req.location.as_deref(), Some("https://example.test/moved"));
        assert_eq!(req.newurl.as_deref(), Some("https://example.test/next"));
        #[cfg(feature = "cookies")]
        assert_eq!(req.setcookies, 3);
        assert!(req.content_range);
        assert!(req.rewind_read);
        assert!(req.http_bodyless);
        assert!(req.chunk);
        assert!(req.resp_trailer);
        assert!(req.ignore_cl);
        assert!(req.upload_chunky);
        assert!(req.no_body);
        assert!(req.authneg);
        assert!(req.shutdown_err_ignore);
        assert!(req.reader_started);

        // The client chain was started exactly once.
        assert_eq!(io.client_starts, 1);
    }

    #[test]
    fn soft_reset_propagates_the_client_start_error_before_the_queue() {
        let mut io = TestIo::new();
        io.client_start_result = Err(CURLcode::ReadError);
        let mut req = SingleRequest::new();

        assert_eq!(req.soft_reset(&mut io), Err(CURLcode::ReadError));
        // The C returns at `:69-70`, before touching the send queue.
        assert!(!req.sendbuf_init());
        // The fields before the call were still cleared, exactly as the C
        // clears them before calling.
        assert!(!req.done);
    }

    #[test]
    fn soft_reset_creates_then_reuses_then_resizes_the_send_queue() {
        let mut io = TestIo::new();
        let mut req = SingleRequest::new();

        // First: created at the configured size.
        req.soft_reset(&mut io).expect("created");
        assert!(req.sendbuf_init());
        assert_eq!(req.sendbuf_chunk_size(), 16);

        // Second, same size: emptied and REUSED, so the size is unchanged and
        // the queued bytes are gone.
        req.sendbuf_add(b"0123456789", 4).expect("queued");
        assert_eq!(req.sendbuf_len(), 10);
        assert_eq!(req.sendbuf_hds_len, 4);
        req.soft_reset(&mut io).expect("reused");
        assert!(req.sendbuf_init());
        assert_eq!(req.sendbuf_chunk_size(), 16);
        assert_eq!(req.sendbuf_len(), 0);
        assert_eq!(req.sendbuf_hds_len, 0);

        // Third, after `CURLOPT_UPLOAD_BUFFERSIZE` changed: rebuilt at the new
        // size.
        io.config.upload_buffer_size = 64;
        req.soft_reset(&mut io).expect("resized");
        assert_eq!(req.sendbuf_chunk_size(), 64);
        assert!(req.sendbuf_empty());
    }

    // -- start, done, hard reset, cleanup ---------------------------------

    #[test]
    fn start_records_the_pinned_clock_and_then_soft_resets() {
        let mut io = TestIo::new();
        io.clock.set(CurlTime::new(1_234, 567_000));
        let mut req = dirty_request();

        req.start(&mut io).expect("started");

        assert_eq!(req.start, CurlTime::new(1_234, 567_000));
        // The soft reset ran: its fields are cleared and the queue exists.
        assert!(!req.done);
        assert_eq!(req.bytecount, 0);
        assert!(req.sendbuf_init());
        assert_eq!(io.client_starts, 1);
    }

    #[test]
    fn a_soft_reset_after_a_start_preserves_the_overall_start_time() {
        let mut io = TestIo::new();
        io.clock.set(CurlTime::new(10, 0));
        let mut req = SingleRequest::new();
        req.start(&mut io).expect("started");
        assert_eq!(req.start, CurlTime::new(10, 0));

        // Time passes and the request is followed. `Curl_req_soft_reset` is
        // what a redirect calls, and it must NOT re-record the start.
        io.clock.advance(Duration::from_secs(5));
        req.soft_reset(&mut io).expect("reset");
        assert_eq!(req.start, CurlTime::new(10, 0));

        // Whereas a fresh start does re-record it.
        req.start(&mut io).expect("restarted");
        assert_eq!(req.start, CurlTime::new(15, 0));
    }

    #[test]
    fn start_records_the_instant_even_when_the_reset_fails() {
        let mut io = TestIo::new();
        io.clock.set(CurlTime::new(42, 0));
        io.client_start_result = Err(CURLcode::ReadError);
        let mut req = SingleRequest::new();

        assert_eq!(req.start(&mut io), Err(CURLcode::ReadError));
        // The C assigns `req->start` at `:92` and only then calls the function
        // that can fail.
        assert_eq!(req.start, CurlTime::new(42, 0));
    }

    #[test]
    fn done_flushes_and_discards_the_result() {
        let (mut req, mut io) = started();
        // Bytes that cannot go out: the flush will answer CURLE_AGAIN.
        req.sendbuf_add(b"pending", 0).expect("queued");
        io.script_sends(&[SendStep::Block]);

        assert_eq!(req.done(&mut io, false), Ok(()));

        // The flush was attempted and its CURLE_AGAIN was swallowed.
        assert_eq!(io.sent.len(), 1);
        assert_eq!(io.client_resets, 1);
        assert_eq!(io.doh_closes, 1);
    }

    #[test]
    fn done_propagates_nothing_even_when_the_flush_fails_outright() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"pending", 0).expect("queued");
        io.script_sends(&[SendStep::Fail(CURLcode::SendError)]);

        assert_eq!(req.done(&mut io, false), Ok(()));
        assert_eq!(io.client_resets, 1);
        assert_eq!(io.doh_closes, 1);
    }

    #[test]
    fn done_aborted_skips_the_flush_entirely() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"pending", 0).expect("queued");

        assert_eq!(req.done(&mut io, true), Ok(()));

        assert!(io.sent.is_empty(), "an aborted request sends nothing more");
        assert_eq!(io.client_resets, 1);
        assert_eq!(io.doh_closes, 1);
        // The bytes are still queued: nothing tried to push them.
        assert_eq!(req.sendbuf_len(), 7);
    }

    #[test]
    fn hard_reset_restores_the_virgin_state_and_keeps_the_queue() {
        let mut io = TestIo::new();
        let mut req = dirty_request();
        req.soft_reset(&mut io).expect("queue built");
        req.sendbuf_add(b"queued", 3).expect("queued");
        req.size = 4096;
        req.start = CurlTime::new(7, 500_000);

        req.hard_reset(&mut io);

        assert_eq!(req.size, -1);
        assert_eq!(req.maxdownload, -1);
        assert_eq!(req.bytecount, 0);
        assert_eq!(req.writebytecount, 0);
        assert_eq!(req.start, CurlTime::ZERO);
        assert_eq!(req.headerbytecount, 0);
        assert_eq!(req.allheadercount, 0);
        assert_eq!(req.deductheadercount, 0);
        assert_eq!(req.headerline, 0);
        assert_eq!(req.offset, 0);
        assert_eq!(req.httpcode, 0);
        assert_eq!(req.keepon(), KeepFlags::NONE);
        assert_eq!(req.upgr101, Upgrade101::None);
        assert_eq!(req.sendbuf_hds_len, 0);
        assert_eq!(req.timeofdoc, 0);
        assert!(req.location.is_none());
        assert!(req.newurl.is_none());
        #[cfg(feature = "cookies")]
        assert_eq!(req.setcookies, 0);

        // The easily missed ones: all of these are in the C's list and none is
        // in the soft reset's.
        assert!(!req.content_range);
        assert!(!req.http_bodyless);
        assert!(!req.chunk);
        assert!(!req.ignore_cl);
        assert!(!req.upload_chunky);
        assert!(!req.authneg);
        assert!(!req.rewind_read);
        assert!(!req.shutdown);
        // And the rest of the C's list.
        assert!(!req.header);
        assert!(!req.download_done);
        assert!(!req.eos_written);
        assert!(!req.eos_read);
        assert!(!req.eos_sent);
        assert!(!req.upload_done);
        assert!(!req.upload_aborted);
        assert!(!req.ignorebody);

        // Kept: the reusable allocation, emptied rather than freed.
        assert!(req.sendbuf_init());
        assert!(req.sendbuf_empty());
        assert_eq!(req.sendbuf_chunk_size(), 16);
        // Kept: the three members neither reset touches.
        assert!(req.resp_trailer);
        assert!(req.shutdown_err_ignore);
        assert!(req.reader_started);
        // The chains were reset and the resolver was closed.
        assert_eq!(io.client_resets, 1);
        assert_eq!(io.doh_closes, 1);
    }

    #[test]
    fn hard_reset_takes_no_body_from_the_configuration() {
        let mut io = TestIo::new();
        let mut req = SingleRequest::new();

        io.config.opt_no_body = true;
        req.no_body = false;
        req.hard_reset(&mut io);
        assert!(req.no_body, "CURLOPT_NOBODY survives a hard reset");

        io.config.opt_no_body = false;
        req.no_body = true;
        req.hard_reset(&mut io);
        assert!(!req.no_body);
    }

    #[test]
    fn hard_reset_unblocks_both_rate_limiters_at_the_zero_instant() {
        let mut io = TestIo::new();
        io.clock.set(CurlTime::new(500, 0));
        io.block_upload(true);
        io.block_download(true);
        assert!(io.progress().upload().rlimit().is_blocked());
        assert!(io.progress().download().rlimit().is_blocked());

        let mut req = SingleRequest::new();
        req.hard_reset(&mut io);

        assert!(!io.progress().upload().rlimit().is_blocked());
        assert!(!io.progress().download().rlimit().is_blocked());
    }

    #[test]
    fn hard_reset_without_a_queue_leaves_the_queue_absent() {
        let mut io = TestIo::new();
        let mut req = SingleRequest::new();
        req.hard_reset(&mut io);
        assert!(!req.sendbuf_init());
        assert!(req.sendbuf_empty());
    }

    #[test]
    fn free_releases_the_queue_the_urls_and_the_client_stack() {
        let mut io = TestIo::new();
        let mut req = dirty_request();
        req.soft_reset(&mut io).expect("queue built");
        req.sendbuf_add(b"queued", 2).expect("queued");
        req.location = Some("https://example.test/a".to_string());
        req.newurl = Some("https://example.test/b".to_string());

        req.free(&mut io);

        assert!(req.location.is_none());
        assert!(req.newurl.is_none());
        assert!(!req.sendbuf_init());
        assert_eq!(req.sendbuf_len(), 0);
        assert_eq!(req.sendbuf_hds_len, 0);
        assert_eq!(io.client_cleanups, 1);

        // Idempotent: a second call finds nothing left and does not panic.
        req.free(&mut io);
        assert_eq!(io.client_cleanups, 2);
    }

    // -- the low-level send ------------------------------------------------

    #[test]
    fn xfer_send_reports_headers_and_body_under_their_own_kinds() {
        let (mut req, mut io) = started();

        let written = req
            .xfer_send(&mut io, b"HEADERSbody", 7)
            .expect("the transport accepted everything");

        assert_eq!(written, 11);
        assert_eq!(io.debugged_under(TraceDataKind::HeaderOut), b"HEADERS");
        assert_eq!(io.debugged_under(TraceDataKind::DataOut), b"body");
        // Only the body reaches the counters.
        assert_eq!(req.writebytecount, 4);
        assert_eq!(io.progress().size_upload(), 4);
    }

    #[test]
    fn xfer_send_reports_only_the_accepted_prefix_of_the_headers() {
        let (mut req, mut io) = started();
        io.script_sends(&[SendStep::Accept(3)]);

        let written = req
            .xfer_send(&mut io, b"HEADERSbody", 7)
            .expect("a partial write is not an error");

        assert_eq!(written, 3);
        assert_eq!(io.debugged_under(TraceDataKind::HeaderOut), b"HEA");
        assert!(io.debugged_under(TraceDataKind::DataOut).is_empty());
        // Nothing of the body went out, so nothing was counted.
        assert_eq!(req.writebytecount, 0);
        assert_eq!(io.progress().size_upload(), 0);
    }

    #[test]
    fn xfer_send_with_a_zero_length_header_prefix_reports_no_headers() {
        let (mut req, mut io) = started();

        let written = req.xfer_send(&mut io, b"payload", 0).expect("sent");

        assert_eq!(written, 7);
        assert!(io.debugged_under(TraceDataKind::HeaderOut).is_empty());
        assert_eq!(io.debugged_under(TraceDataKind::DataOut), b"payload");
        assert_eq!(req.writebytecount, 7);
    }

    #[test]
    fn xfer_send_accepting_nothing_reports_nothing_and_is_not_an_error() {
        let (mut req, mut io) = started();
        io.script_sends(&[SendStep::Block]);

        assert_eq!(req.xfer_send(&mut io, b"HEADERSbody", 7), Ok(0));
        assert!(io.debugged.is_empty());
        assert_eq!(req.writebytecount, 0);
    }

    #[test]
    fn xfer_send_propagates_the_transport_error_untouched() {
        let (mut req, mut io) = started();
        io.script_sends(&[SendStep::Fail(CURLcode::SendError)]);

        assert_eq!(
            req.xfer_send(&mut io, b"HEADERSbody", 7),
            Err(CURLcode::SendError)
        );
        assert!(io.debugged.is_empty());
        assert_eq!(req.writebytecount, 0);
        assert!(!req.eos_sent);
    }

    #[test]
    fn max_send_speed_clamps_the_body_and_never_the_headers() {
        let (mut req, mut io) = started();
        io.config.max_send_speed = 2;

        let written = req.xfer_send(&mut io, b"HEADERSbody", 7).expect("sent");

        // The offer is `header_len + min(body_len, max_send_speed)`.
        assert_eq!(io.offered_bytes(), b"HEADERSbo");
        assert_eq!(written, 9);
        assert_eq!(io.debugged_under(TraceDataKind::HeaderOut), b"HEADERS");
        assert_eq!(io.debugged_under(TraceDataKind::DataOut), b"bo");
        assert_eq!(req.writebytecount, 2);
    }

    #[test]
    fn max_send_speed_above_the_body_length_clamps_nothing() {
        let (mut req, mut io) = started();
        io.config.max_send_speed = 1_000;

        req.xfer_send(&mut io, b"HEADERSbody", 7).expect("sent");
        assert_eq!(io.offered_bytes(), b"HEADERSbody");
    }

    #[test]
    fn max_send_speed_does_not_shorten_a_header_only_send() {
        let (mut req, mut io) = started();
        io.config.max_send_speed = 1;

        // Every byte is header, so there is no body for the cap to act on --
        // the C's own comment: "The headers do not count to the max speed."
        req.xfer_send(&mut io, b"HEADERS", 7).expect("sent");
        assert_eq!(io.offered_bytes(), b"HEADERS");
        assert_eq!(req.writebytecount, 0);
    }

    #[test]
    fn small_req_send_shortens_the_body_and_never_the_headers() {
        let (mut req, mut io) = started();
        io.env = Some(FixedEnv {
            small_req_send: Some("1".to_string()),
        });

        req.xfer_send(&mut io, b"HEADERSbody", 7).expect("sent");

        assert_eq!(io.offered_bytes(), b"HEADERSb");
        assert_eq!(io.debugged_under(TraceDataKind::HeaderOut), b"HEADERS");
        assert_eq!(io.debugged_under(TraceDataKind::DataOut), b"b");
    }

    #[test]
    fn small_req_send_is_ignored_where_there_is_no_body() {
        let (mut req, mut io) = started();
        io.env = Some(FixedEnv {
            small_req_send: Some("1".to_string()),
        });

        // The C guards the whole block with `if(body_len)`.
        req.xfer_send(&mut io, b"HEADERS", 7).expect("sent");
        assert_eq!(io.offered_bytes(), b"HEADERS");
    }

    #[test]
    fn small_req_send_is_ignored_when_it_does_not_parse_or_is_too_large() {
        for value in ["", "abc", "-1", " 2", "99"] {
            let (mut req, mut io) = started();
            io.env = Some(FixedEnv {
                small_req_send: Some(value.to_string()),
            });

            req.xfer_send(&mut io, b"HEADERSbody", 7).expect("sent");
            assert_eq!(
                io.offered_bytes(),
                b"HEADERSbody",
                "the override {value:?} must be ignored"
            );
        }
    }

    #[test]
    fn small_req_send_is_inert_without_the_environment_seam() {
        let (mut req, mut io) = started();
        assert!(io.debug_env().is_none(), "production has no seam");

        req.xfer_send(&mut io, b"HEADERSbody", 7).expect("sent");
        assert_eq!(io.offered_bytes(), b"HEADERSbody");
    }

    #[test]
    fn parse_capped_number_matches_the_c_parser() {
        // A plain number within the ceiling.
        assert_eq!(parse_capped_number("7", 10), Some(7));
        assert_eq!(parse_capped_number("10", 10), Some(10));
        // Leading zeroes are accepted, as `str_num_base` accepts them.
        assert_eq!(parse_capped_number("007", 10), Some(7));
        // Trailing non-digits end the parse without failing it.
        assert_eq!(parse_capped_number("7x", 10), Some(7));
        assert_eq!(parse_capped_number("12,34", 100), Some(12));
        // No digit at the very start is a failure, blanks included.
        assert_eq!(parse_capped_number("", 10), None);
        assert_eq!(parse_capped_number("x7", 10), None);
        assert_eq!(parse_capped_number(" 7", 10), None);
        assert_eq!(parse_capped_number("+7", 10), None);
        assert_eq!(parse_capped_number("-7", 10), None);
        // Above the ceiling is a failure, not a clamp.
        assert_eq!(parse_capped_number("11", 10), None);
        assert_eq!(parse_capped_number("100", 10), None);
        // The C's low-ceiling branch: a ceiling below the base.
        assert_eq!(parse_capped_number("5", 5), Some(5));
        assert_eq!(parse_capped_number("6", 5), None);
        assert_eq!(parse_capped_number("0", 0), Some(0));
        assert_eq!(parse_capped_number("1", 0), None);
        // Nothing overflows, whatever the input length.
        assert_eq!(parse_capped_number("99999999999999999999999", 64), None);
        assert_eq!(
            parse_capped_number(&u64::MAX.to_string(), u64::MAX),
            Some(u64::MAX)
        );
    }

    // -- end of stream -----------------------------------------------------

    #[test]
    fn a_final_nonempty_send_carries_end_of_stream_once() {
        let (mut req, mut io) = started();
        req.eos_read = true;

        req.xfer_send(&mut io, b"tail", 0).expect("sent");

        assert_eq!(io.eos_offers(), 1);
        assert!(req.eos_sent);
        assert!(io.traced("sending last upload chunk of 4 bytes"));
    }

    #[test]
    fn end_of_stream_is_not_recorded_on_a_partial_final_send() {
        let (mut req, mut io) = started();
        req.eos_read = true;
        io.script_sends(&[SendStep::Accept(2)]);

        req.xfer_send(&mut io, b"tail", 0).expect("sent");

        // The flag was offered, but not everything was accepted, so the C's
        // `eos && (blen == *pnwritten)` does not hold.
        assert_eq!(io.eos_offers(), 1);
        assert!(!req.eos_sent);
    }

    #[test]
    fn end_of_stream_is_not_offered_before_the_client_reports_it() {
        let (mut req, mut io) = started();
        assert!(!req.eos_read);

        req.xfer_send(&mut io, b"tail", 0).expect("sent");

        assert_eq!(io.eos_offers(), 0);
        assert!(!req.eos_sent);
    }

    #[test]
    fn flush_performs_the_required_zero_length_end_of_stream_send() {
        let (mut req, mut io) = started();
        req.eos_read = true;
        // Already uploaded, so the flush stops after the zero-length send
        // rather than going on to finish the upload.
        req.upload_done = true;

        req.flush(&mut io).expect("flushed");

        assert_eq!(io.sent.len(), 1, "the zero-length event is required");
        assert_eq!(io.sent[0].offered.len(), 0);
        assert!(io.sent[0].eos);
        assert!(req.eos_sent);
        assert_eq!(io.eos_offers(), 1, "and it happens exactly once");

        // A second flush does not repeat it.
        req.flush(&mut io).expect("flushed again");
        assert_eq!(io.sent.len(), 1);
    }

    #[test]
    fn the_zero_length_end_of_stream_send_propagates_its_error() {
        let (mut req, mut io) = started();
        req.eos_read = true;
        io.script_sends(&[SendStep::Fail(CURLcode::SendError)]);

        assert_eq!(req.flush(&mut io), Err(CURLcode::SendError));
        assert!(!req.eos_sent);
        assert_eq!(io.send_closes, 0);
    }

    // -- the queue and the flush -------------------------------------------

    #[test]
    fn queue_insertion_takes_everything_and_counts_only_the_header_prefix() {
        let (mut req, _io) = started();

        // Sixteen is the chunk size, so this exceeds it and the soft limit is
        // what makes the write succeed anyway.
        req.sendbuf_add(b"0123456789abcdefghij", 5).expect("queued");

        assert_eq!(req.sendbuf_len(), 20);
        assert_eq!(req.sendbuf_hds_len, 5);
        assert!(!req.sendbuf_empty());
        assert!(req.sendbuf_is_full());
    }

    #[test]
    fn queue_insertion_without_a_queue_is_failed_init() {
        let mut req = SingleRequest::new();
        assert_eq!(req.sendbuf_add(b"x", 0), Err(CURLcode::FailedInit));
    }

    #[test]
    fn the_flush_drains_the_queue_and_splits_header_from_body() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"HEAD", 4).expect("queued");
        req.sendbuf_add(b"BODY", 0).expect("queued");
        assert_eq!(req.sendbuf_hds_len, 4);

        req.flush(&mut io).expect("flushed");

        assert_eq!(io.accepted_bytes(), b"HEADBODY");
        assert!(req.sendbuf_empty());
        assert_eq!(req.sendbuf_hds_len, 0);
        assert_eq!(io.debugged_under(TraceDataKind::HeaderOut), b"HEAD");
        assert_eq!(io.debugged_under(TraceDataKind::DataOut), b"BODY");
        assert_eq!(req.writebytecount, 4);
    }

    #[test]
    fn a_partial_flush_reports_again_and_keeps_the_remaining_bytes() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"HEADBODY", 4).expect("queued");
        io.script_sends(&[SendStep::Accept(2)]);

        assert_eq!(req.flush(&mut io), Err(CURLcode::Again));

        assert_eq!(req.sendbuf_len(), 6);
        // Exactly the header bytes that went out were deducted.
        assert_eq!(req.sendbuf_hds_len, 2);
        assert!(io.traced("Curl_req_flush(len=6) -> EAGAIN"));

        // The next flush resumes at the same offset and finishes.
        req.flush(&mut io).expect("flushed");
        assert_eq!(io.accepted_bytes(), b"HEADBODY");
        assert_eq!(req.sendbuf_hds_len, 0);
        assert!(req.sendbuf_empty());
    }

    #[test]
    fn a_blocked_flush_reports_again_without_consuming_anything() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"HEADBODY", 4).expect("queued");
        io.script_sends(&[SendStep::Block]);

        assert_eq!(req.flush(&mut io), Err(CURLcode::Again));
        assert_eq!(req.sendbuf_len(), 8);
        assert_eq!(req.sendbuf_hds_len, 4);
        assert!(io.traced("Curl_req_flush(len=8) -> EAGAIN"));
    }

    #[test]
    fn a_failing_flush_propagates_and_retains_the_unsent_bytes() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"HEADBODY", 4).expect("queued");
        io.script_sends(&[SendStep::Fail(CURLcode::SendError)]);

        assert_eq!(req.flush(&mut io), Err(CURLcode::SendError));
        assert_eq!(req.sendbuf_len(), 8, "a failed turn skips nothing");
        assert_eq!(req.sendbuf_hds_len, 4);
    }

    #[test]
    fn the_flush_without_a_connection_is_failed_init() {
        let (mut req, mut io) = started();
        io.connected = false;
        assert_eq!(req.flush(&mut io), Err(CURLcode::FailedInit));
        assert!(io.sent.is_empty());
    }

    #[test]
    fn an_empty_queue_defers_to_the_transports_own_flush() {
        let (mut req, mut io) = started();
        io.needs_flush = true;

        req.flush(&mut io).expect("flushed");

        assert_eq!(io.flushes, 1);
        assert!(io.traced("Curl_req_flush(), xfer send_pending"));
        assert!(io.sent.is_empty());
    }

    #[test]
    fn the_transports_flush_result_is_returned_unchanged() {
        let (mut req, mut io) = started();
        io.needs_flush = true;
        io.flush_results.push_back(Err(CURLcode::Again));

        // The C returns `Curl_xfer_flush(data)` directly, CURLE_AGAIN and all.
        assert_eq!(req.flush(&mut io), Err(CURLcode::Again));

        io.flush_results.push_back(Err(CURLcode::SendError));
        assert_eq!(req.flush(&mut io), Err(CURLcode::SendError));
    }

    #[test]
    fn a_queue_with_bytes_never_reaches_the_transport_flush_arm() {
        let (mut req, mut io) = started();
        io.needs_flush = true;
        req.sendbuf_add(b"queued", 0).expect("queued");

        req.flush(&mut io).expect("flushed");

        // The C's `else if` is what makes this an either-or.
        assert_eq!(io.flushes, 0);
        assert_eq!(io.accepted_bytes(), b"queued");
    }

    // -- upload completion and shutdown ------------------------------------

    #[test]
    fn upload_completion_clears_keep_send_and_records_one_timer() {
        let (mut req, mut io) = started();
        req.set_keepon(KeepFlags::RECV | KeepFlags::SEND);
        req.writebytecount = 12;

        req.set_upload_done(&mut io).expect("completed");

        assert!(req.upload_done);
        assert_eq!(req.keepon(), KeepFlags::RECV);
        assert_eq!(io.timers, vec![TimerId::PostTransfer]);
        assert_eq!(io.creader_done_calls, vec![false]);
        assert_eq!(io.send_closes, 1);
        assert!(io.said("upload completely sent off: 12 bytes"));
    }

    #[test]
    fn the_post_transfer_timer_is_recorded_exactly_once_per_attempt() {
        let (mut req, mut io) = started();
        req.eos_read = true;
        req.eos_sent = true;

        // The flush finishes the upload.
        req.flush(&mut io).expect("flushed");
        assert!(req.upload_done);
        assert_eq!(io.timers, vec![TimerId::PostTransfer]);

        // Flushing again, and aborting afterwards, must not record it again.
        req.flush(&mut io).expect("flushed again");
        req.abort_sending(&mut io).expect("already done");
        assert_eq!(io.timers, vec![TimerId::PostTransfer]);
        assert_eq!(io.creader_done_calls.len(), 1);
        assert_eq!(io.send_closes, 1);
    }

    #[test]
    fn the_four_completion_lines_follow_the_source_conditions() {
        // Aborted with bytes sent.
        let (mut req, mut io) = started();
        req.upload_aborted = true;
        req.writebytecount = 9;
        req.set_upload_done(&mut io).expect("completed");
        assert!(io.said("abort upload after having sent 9 bytes"));
        assert_eq!(io.creader_done_calls, vec![true]);

        // Aborted with nothing sent.
        let (mut req, mut io) = started();
        req.upload_aborted = true;
        req.set_upload_done(&mut io).expect("completed");
        assert!(io.said("abort upload"));

        // Not aborted, nothing sent, download not done, a reader with a
        // length: -1 counts as "has a length", which is the trap.
        let (mut req, mut io) = started();
        io.total_length = -1;
        req.set_upload_done(&mut io).expect("completed");
        assert!(io.said("We are completely uploaded and fine"));

        let (mut req, mut io) = started();
        io.total_length = 5;
        req.set_upload_done(&mut io).expect("completed");
        assert!(io.said("We are completely uploaded and fine"));

        // Not aborted, nothing sent, download not done, reader length zero.
        let (mut req, mut io) = started();
        io.total_length = 0;
        req.set_upload_done(&mut io).expect("completed");
        assert!(io.said("Request completely sent off"));

        // Not aborted, nothing sent, but the download already finished: the C
        // says nothing at all.
        let (mut req, mut io) = started();
        req.download_done = true;
        req.set_upload_done(&mut io).expect("completed");
        assert!(io.info.is_empty());
    }

    #[test]
    fn an_aborted_completion_discards_the_queued_bytes() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"unsent", 0).expect("queued");
        req.upload_aborted = true;

        req.set_upload_done(&mut io).expect("completed");

        assert!(req.sendbuf_empty());
        assert!(io.sent.is_empty());
    }

    #[test]
    fn upload_completion_propagates_the_send_close_error() {
        let (mut req, mut io) = started();
        io.send_close_result = Err(CURLcode::SendError);

        assert_eq!(req.set_upload_done(&mut io), Err(CURLcode::SendError));

        // The state still moved: the C sets the flags, records the timer and
        // tells the reader before it closes the send side, so a failure there
        // does not roll any of that back.
        assert!(req.upload_done);
        assert!(req.keepon().is_empty());
        assert_eq!(io.timers, vec![TimerId::PostTransfer]);
        assert_eq!(io.creader_done_calls, vec![false]);
        assert_eq!(io.send_closes, 1);
    }

    #[test]
    fn a_pending_send_shutdown_reports_again_and_is_retried() {
        let (mut req, mut io) = started();
        req.eos_read = true;
        req.eos_sent = true;
        req.shutdown = true;
        io.shutdowns.push_back(Ok(SendShutdown::Pending));

        assert_eq!(req.flush(&mut io), Err(CURLcode::Again));
        assert!(!req.upload_done);
        assert_eq!(io.shutdown_calls, 1);
        assert_eq!(io.send_closes, 0);

        // The default script answers Complete, so the retry finishes.
        req.flush(&mut io).expect("flushed");
        assert!(req.upload_done);
        assert_eq!(io.shutdown_calls, 2);
        assert_eq!(io.send_closes, 1);
    }

    #[test]
    fn a_failing_send_shutdown_propagates_by_default() {
        let (mut req, mut io) = started();
        req.eos_read = true;
        req.eos_sent = true;
        req.shutdown = true;
        io.shutdowns.push_back(Err(CURLcode::SendError));

        assert_eq!(req.flush(&mut io), Err(CURLcode::SendError));
        assert!(!req.upload_done);
        assert_eq!(io.send_closes, 0);
        assert!(io.info.is_empty());
    }

    #[test]
    fn an_ignored_shutdown_error_completes_the_upload_in_the_same_call() {
        let (mut req, mut io) = started();
        req.eos_read = true;
        req.eos_sent = true;
        req.shutdown = true;
        req.shutdown_err_ignore = true;
        io.shutdowns.push_back(Err(CURLcode::SendError));

        req.flush(&mut io).expect("the error was ignored");

        assert!(
            io.said(
                "Shutdown send direction error: 55. Broken server? \
                 Proceeding as if everything is ok."
            ),
            "lines were {:?}",
            io.info
        );
        // Both `result = CURLE_OK` and `done = TRUE`, so the upload finished
        // here rather than being retried.
        assert!(req.upload_done);
        assert_eq!(io.shutdown_calls, 1);
        assert_eq!(io.send_closes, 1);
    }

    #[test]
    fn no_shutdown_is_attempted_unless_the_transfer_asked_for_one() {
        let (mut req, mut io) = started();
        req.eos_read = true;
        req.eos_sent = true;
        assert!(!req.shutdown);

        req.flush(&mut io).expect("flushed");

        assert_eq!(io.shutdown_calls, 0);
        assert!(req.upload_done);
    }

    // -- sending the request headers ---------------------------------------

    #[test]
    fn a_header_only_request_is_sent_directly_and_completes_at_once() {
        let (mut req, mut io) = started();
        io.total_length = 0;

        req.send(&mut io, b"GET / HTTP/1.1\r\n", 11).expect("sent");

        assert_eq!(req.httpversion_sent, 11);
        // One send, the whole block, marked as the end of the stream.
        assert_eq!(io.sent.len(), 1);
        assert_eq!(io.sent[0].offered, b"GET / HTTP/1.1\r\n");
        assert!(io.sent[0].eos);
        assert!(req.eos_read);
        assert!(req.eos_sent);
        // Every byte was a header byte, so nothing was counted as body.
        assert_eq!(
            io.debugged_under(TraceDataKind::HeaderOut),
            b"GET / HTTP/1.1\r\n"
        );
        assert!(io.debugged_under(TraceDataKind::DataOut).is_empty());
        assert_eq!(req.writebytecount, 0);
        // And the upload is finished without a second call.
        assert!(req.upload_done);
        assert_eq!(io.send_closes, 1);
        assert!(req.sendbuf_empty());
        assert!(io.said("Request completely sent off"));
    }

    #[test]
    fn the_header_bytes_are_offered_verbatim() {
        let (mut req, mut io) = started();
        io.total_length = 0;
        io.config.upload_buffer_size = 512;
        req.soft_reset(&mut io).expect("resized");

        // Deliberately unusual: lower-cased names, an unusual order, an extra
        // space. Nothing here may normalise any of it.
        let headers =
            b"GET /x HTTP/1.1\r\naccept:  */*\r\nhost: a.test\r\n\r\n";
        req.send(&mut io, headers, 11).expect("sent");

        assert_eq!(io.offered_bytes(), headers);
        assert_eq!(io.debugged_under(TraceDataKind::HeaderOut), headers);
    }

    #[test]
    fn an_oversized_header_block_is_queued_and_never_direct_sent() {
        let (mut req, mut io) = started();
        io.total_length = 0;
        // Seventeen bytes against a chunk size of sixteen.
        let headers = b"0123456789abcdefg";
        assert!(headers.len() > req.sendbuf_chunk_size());
        io.script_sends(&[SendStep::Block]);

        req.send(&mut io, headers, 11).expect("queued");

        // The direct send did not happen, so the client has NOT been declared
        // finished and the bytes are on the queue.
        assert!(!req.eos_read);
        assert_eq!(req.sendbuf_len(), 17);
        assert_eq!(req.sendbuf_hds_len, 17);
        assert!(!req.upload_done);
    }

    #[test]
    fn a_declared_request_body_prevents_the_direct_send() {
        let (mut req, mut io) = started();
        io.total_length = 4;
        io.script_sends(&[SendStep::Block]);
        // Nothing ready from the client, so the fill cannot be what records
        // end of stream and the direct send is the only candidate.
        io.script_reads(&[ReadStep::Again]);

        req.send(&mut io, b"HEAD", 11).expect("queued");

        // The direct send declares end of stream READ before sending and
        // therefore offers the flag; the queued path does neither.
        assert!(!req.eos_read);
        assert_eq!(io.eos_offers(), 0);
        assert_eq!(req.sendbuf_len(), 4);
        assert_eq!(req.sendbuf_hds_len, 4);
        assert!(!req.upload_done);
        assert_eq!(io.read_calls, 1, "a body was asked for");
    }

    #[test]
    fn an_unknown_request_body_length_prevents_the_direct_send() {
        let (mut req, mut io) = started();
        // -1 is "unknown", which is not zero, so the C's `!total_length` is
        // false and the direct send is skipped.
        io.total_length = -1;
        io.script_sends(&[SendStep::Block]);
        io.script_reads(&[ReadStep::Again]);

        req.send(&mut io, b"HEAD", 11).expect("queued");

        assert!(!req.eos_read);
        assert_eq!(io.eos_offers(), 0);
        assert_eq!(req.sendbuf_len(), 4);
        assert_eq!(req.sendbuf_hds_len, 4);
    }

    #[test]
    fn the_clients_end_of_stream_is_what_records_it_on_the_queued_path() {
        let (mut req, mut io) = started();
        io.total_length = 4;
        // The client hands over its whole body and says so.
        io.script_reads(&[ReadStep::Bytes(b"BODY".to_vec(), true)]);

        req.send(&mut io, b"HEAD", 11).expect("sent");

        assert!(req.eos_read);
        assert!(req.eos_sent);
        assert_eq!(io.accepted_bytes(), b"HEADBODY");
        assert_eq!(io.debugged_under(TraceDataKind::HeaderOut), b"HEAD");
        assert_eq!(io.debugged_under(TraceDataKind::DataOut), b"BODY");
        assert_eq!(req.writebytecount, 4);
        assert!(req.upload_done);
    }

    #[test]
    fn a_partially_sent_header_block_queues_only_the_remainder() {
        let (mut req, mut io) = started();
        io.total_length = 0;
        // Accept four of eight, then block so nothing else moves.
        io.script_sends(&[SendStep::Accept(4), SendStep::Block]);

        req.send(&mut io, b"HEADBODY", 11).expect("queued");

        assert_eq!(io.sent[0].offered, b"HEADBODY");
        assert_eq!(io.sent[0].accepted, 4);
        // The four that did not go out are queued, all of them header bytes.
        assert_eq!(req.sendbuf_len(), 4);
        assert_eq!(req.sendbuf_hds_len, 4);
        assert!(!req.upload_done);

        // Flushing finishes them, and they are still reported as headers.
        req.flush(&mut io).expect("flushed");
        assert_eq!(io.accepted_bytes(), b"HEADBODY");
        assert_eq!(io.debugged_under(TraceDataKind::HeaderOut), b"HEADBODY");
        assert_eq!(req.writebytecount, 0);
    }

    #[test]
    fn sending_without_a_connection_is_failed_init() {
        let (mut req, mut io) = started();
        io.connected = false;
        assert_eq!(
            req.send(&mut io, b"GET /\r\n", 11),
            Err(CURLcode::FailedInit)
        );
        assert_eq!(req.httpversion_sent, 0, "nothing was recorded either");
    }

    #[test]
    fn a_direct_send_failure_propagates_and_queues_nothing() {
        let (mut req, mut io) = started();
        io.total_length = 0;
        io.script_sends(&[SendStep::Fail(CURLcode::SendError)]);

        assert_eq!(
            req.send(&mut io, b"GET /\r\n", 11),
            Err(CURLcode::SendError)
        );
        assert!(req.sendbuf_empty());
        assert!(!req.upload_done);
        // The version was recorded before the send, as the C records it.
        assert_eq!(req.httpversion_sent, 11);
    }

    #[test]
    fn an_empty_header_block_completes_without_sending_anything() {
        let (mut req, mut io) = started();
        io.total_length = 0;

        req.send(&mut io, b"", 11).expect("sent");

        // A zero-length direct send: the C's `blen <= chunk_size` holds, the
        // send offers nothing, and `!blen` completes the upload.
        assert_eq!(io.sent.len(), 1);
        assert!(io.sent[0].offered.is_empty());
        assert!(req.eos_sent);
        assert!(req.upload_done);
        assert!(req.sendbuf_empty());
    }

    // -- continuing the upload ---------------------------------------------

    #[test]
    fn a_request_with_a_body_reads_the_client_and_sends_both() {
        let (mut req, mut io) = started();
        io.total_length = 5;
        io.script_reads(&[ReadStep::Bytes(b"HELLO".to_vec(), true)]);

        req.send(&mut io, b"PUT /\r\n", 11).expect("sent");

        assert_eq!(io.accepted_bytes(), b"PUT /\r\nHELLO");
        assert_eq!(io.debugged_under(TraceDataKind::HeaderOut), b"PUT /\r\n");
        assert_eq!(io.debugged_under(TraceDataKind::DataOut), b"HELLO");
        assert_eq!(req.writebytecount, 5);
        assert_eq!(io.progress().size_upload(), 5);
        assert!(req.eos_read);
        assert!(req.eos_sent);
        assert!(req.upload_done);
        assert!(io.said("upload completely sent off: 5 bytes"));
    }

    #[test]
    fn send_more_stops_reading_once_the_client_reports_end_of_stream() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"body", 0).expect("queued");
        io.script_reads(&[ReadStep::Eos]);

        req.send_more(&mut io).expect("sent");
        assert!(req.eos_read);
        assert_eq!(io.read_calls, 1);

        // A second call must not ask again.
        req.send_more(&mut io).expect("sent");
        assert_eq!(io.read_calls, 1);
    }

    #[test]
    fn send_more_does_not_read_while_the_transport_send_is_paused() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"body", 0).expect("queued");
        io.block_upload(true);

        req.send_more(&mut io).expect("sent");

        assert_eq!(io.read_calls, 0, "a paused send reads nothing");
        // It still flushed what it already had.
        assert_eq!(io.accepted_bytes(), b"body");
    }

    #[test]
    fn send_more_does_not_read_while_the_queue_is_full() {
        let (mut req, mut io) = started();
        // One chunk of sixteen, filled exactly.
        req.sendbuf_add(b"0123456789abcdef", 0).expect("queued");
        assert!(req.sendbuf_is_full());
        io.script_sends(&[SendStep::Block]);

        req.send_more(&mut io).expect("sent");

        assert_eq!(io.read_calls, 0);
    }

    #[test]
    fn send_more_does_not_read_after_the_upload_was_aborted() {
        let (mut req, mut io) = started();
        req.upload_aborted = true;

        req.send_more(&mut io).expect("sent");

        assert_eq!(io.read_calls, 0);
    }

    #[test]
    fn a_client_read_that_is_not_ready_is_not_fatal_for_the_iteration() {
        let (mut req, mut io) = started();
        io.script_reads(&[ReadStep::Again]);

        req.send_more(&mut io)
            .expect("CURLE_AGAIN from the client is fine");

        assert_eq!(io.read_calls, 1);
        assert!(!req.eos_read);
        assert!(io.sent.is_empty(), "there was nothing to send");
    }

    #[test]
    fn any_other_client_read_error_propagates() {
        let (mut req, mut io) = started();
        io.script_reads(&[ReadStep::Fail(CURLcode::AbortedByCallback)]);

        assert_eq!(req.send_more(&mut io), Err(CURLcode::AbortedByCallback));
        assert!(!req.eos_read, "a failed read never records end of stream");
    }

    #[test]
    fn send_more_converts_the_flushs_again_into_success() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"body", 0).expect("queued");
        req.eos_read = true;
        io.script_sends(&[SendStep::Block]);

        // The flush answers CURLE_AGAIN; the documented contract of
        // `Curl_req_send_more` is that it never does.
        req.send_more(&mut io).expect("converted to OK");
        assert_eq!(req.sendbuf_len(), 4);
    }

    #[test]
    fn send_more_still_propagates_a_real_flush_failure() {
        let (mut req, mut io) = started();
        req.sendbuf_add(b"body", 0).expect("queued");
        req.eos_read = true;
        io.script_sends(&[SendStep::Fail(CURLcode::SendError)]);

        assert_eq!(req.send_more(&mut io), Err(CURLcode::SendError));
    }

    #[test]
    fn send_more_without_a_queue_is_failed_init_from_the_fill() {
        let mut io = TestIo::new();
        let mut req = SingleRequest::new();
        // No start, so no queue: the fill cannot proceed.
        assert_eq!(req.send_more(&mut io), Err(CURLcode::FailedInit));
    }

    #[test]
    fn a_client_read_larger_than_one_chunk_is_taken_over_several_turns() {
        let (mut req, mut io) = started();
        io.total_length = 20;
        io.script_reads(&[ReadStep::Bytes(
            b"0123456789abcdefghij".to_vec(),
            true,
        )]);

        req.send(&mut io, b"PUT\r\n", 11).expect("sent");
        // Sixteen bytes of room per turn, so the first read fills the chunk and
        // reports no end of stream; the loop comes back for the rest.
        while !req.upload_done {
            req.send_more(&mut io).expect("sent");
        }

        assert_eq!(io.accepted_bytes(), b"PUT\r\n0123456789abcdefghij");
        assert_eq!(req.writebytecount, 20);
        assert!(req.eos_read);
        assert!(req.eos_sent);
    }

    // -- the predicates ----------------------------------------------------

    #[test]
    fn want_send_needs_a_live_request_an_unblocked_limiter_and_a_reason() {
        let (mut req, mut io) = started();
        assert!(!req.want_send(&io), "no reason yet");

        // Reason one: KEEP_SEND.
        req.keep_on(KeepFlags::SEND);
        assert!(req.want_send(&io));
        req.keep_off(KeepFlags::SEND);
        assert!(!req.want_send(&io));

        // Reason two: queued bytes.
        req.sendbuf_add(b"x", 0).expect("queued");
        assert!(req.want_send(&io));

        // Done overrides every reason.
        req.done = true;
        assert!(!req.want_send(&io));
        req.done = false;
        assert!(req.want_send(&io));

        // A blocked UPLOAD limiter overrides every reason too.
        io.block_upload(true);
        assert!(!req.want_send(&io));
        io.block_upload(false);
        assert!(req.want_send(&io));
    }

    #[test]
    fn want_send_counts_output_the_connection_is_still_holding() {
        let (req, mut io) = started();
        assert!(req.sendbuf_empty());
        assert!(!req.wants_send());
        assert!(!req.want_send(&io));

        io.needs_flush = true;
        assert!(req.want_send(&io), "reason three");
    }

    #[test]
    fn want_recv_needs_keep_recv_and_an_unblocked_download_limiter() {
        let (mut req, mut io) = started();
        assert!(!req.want_recv(&io));

        req.keep_on(KeepFlags::RECV);
        assert!(req.want_recv(&io));
        assert!(req.wants_recv());

        req.done = true;
        assert!(!req.want_recv(&io));
        req.done = false;

        io.block_download(true);
        assert!(!req.want_recv(&io));
        io.block_download(false);
        assert!(req.want_recv(&io));
    }

    #[test]
    fn the_two_limiters_block_the_two_directions_independently() {
        let (mut req, mut io) = started();
        req.set_keepon(KeepFlags::RECV | KeepFlags::SEND);

        io.block_upload(true);
        assert!(!req.want_send(&io));
        assert!(req.want_recv(&io), "the download side is untouched");

        io.block_upload(false);
        io.block_download(true);
        assert!(req.want_send(&io));
        assert!(!req.want_recv(&io));
    }

    #[test]
    fn done_sending_needs_both_halves() {
        let (mut req, mut io) = started();

        assert!(!req.done_sending(&io), "the upload is not done");

        req.upload_done = true;
        assert!(req.done_sending(&io));

        // Queued bytes make `want_send` true again, so sending is not done.
        req.sendbuf_add(b"x", 0).expect("queued");
        assert!(!req.done_sending(&io));
        req.flush(&mut io).expect("flushed");
        assert!(req.done_sending(&io));

        // Output the connection holds does the same.
        io.needs_flush = true;
        assert!(!req.done_sending(&io));
    }

    #[test]
    fn aborting_the_send_is_idempotent() {
        let (mut req, mut io) = started();
        req.set_keepon(KeepFlags::RECV | KeepFlags::SEND);
        req.sendbuf_add(b"unsent", 0).expect("queued");

        req.abort_sending(&mut io).expect("aborted");

        assert!(req.upload_aborted);
        assert!(req.upload_done);
        assert_eq!(req.keepon(), KeepFlags::RECV);
        assert!(req.sendbuf_empty());
        assert_eq!(io.creader_done_calls, vec![true]);
        assert_eq!(io.send_closes, 1);
        assert!(io.said("abort upload"));

        // A second abort changes nothing and reports success.
        req.abort_sending(&mut io).expect("already aborted");
        assert_eq!(io.creader_done_calls.len(), 1);
        assert_eq!(io.send_closes, 1);
        assert_eq!(io.timers.len(), 1);
    }

    #[test]
    fn aborting_after_bytes_went_out_names_the_count() {
        let (mut req, mut io) = started();
        req.xfer_send(&mut io, b"payload", 0).expect("sent");
        assert_eq!(req.writebytecount, 7);

        req.abort_sending(&mut io).expect("aborted");
        assert!(io.said("abort upload after having sent 7 bytes"));
    }

    #[test]
    fn aborting_an_already_finished_upload_does_nothing() {
        let (mut req, mut io) = started();
        req.upload_done = true;

        req.abort_sending(&mut io).expect("nothing to do");

        assert!(!req.upload_aborted);
        assert!(io.creader_done_calls.is_empty());
        assert_eq!(io.send_closes, 0);
    }

    #[test]
    fn stop_send_recv_aborts_the_send_then_clears_both_bits() {
        let (mut req, mut io) = started();
        req.set_keepon(KeepFlags::RECV | KeepFlags::SEND);

        req.stop_send_recv(&mut io).expect("stopped");

        assert!(req.upload_aborted);
        assert!(req.upload_done);
        assert_eq!(req.keepon(), KeepFlags::NONE);
        assert_eq!(io.creader_done_calls, vec![true]);
    }

    #[test]
    fn stop_send_recv_without_keep_send_does_not_abort() {
        let (mut req, mut io) = started();
        req.set_keepon(KeepFlags::RECV);

        req.stop_send_recv(&mut io).expect("stopped");

        assert!(!req.upload_aborted);
        assert!(io.creader_done_calls.is_empty());
        assert_eq!(req.keepon(), KeepFlags::NONE);
    }

    #[test]
    fn stop_send_recv_clears_the_bits_even_when_the_abort_fails() {
        let (mut req, mut io) = started();
        io.send_close_result = Err(CURLcode::SendError);
        req.set_keepon(KeepFlags::RECV | KeepFlags::SEND);

        assert_eq!(req.stop_send_recv(&mut io), Err(CURLcode::SendError));

        // The C saves the code, clears the bits and only then returns it.
        assert_eq!(req.keepon(), KeepFlags::NONE);
        assert!(req.upload_aborted);
    }

    #[test]
    fn the_keep_flag_helpers_agree_with_the_mask() {
        let mut req = SingleRequest::new();
        assert!(!req.wants_send());
        assert!(!req.wants_recv());

        req.keep_on(KeepFlags::SEND);
        assert!(req.wants_send());
        assert!(!req.wants_recv());

        req.keep_on(KeepFlags::RECV);
        assert!(req.wants_send());
        assert!(req.wants_recv());

        req.keep_off(KeepFlags::SEND);
        assert!(!req.wants_send());
        assert!(req.wants_recv());

        req.set_keepon(KeepFlags::NONE);
        assert!(req.keepon().is_empty());
    }

    // -- follow options ----------------------------------------------------

    #[test]
    fn follow_mode_pins_the_abi_integers() {
        assert_eq!(FollowMode::Disabled.as_i64(), 0);
        assert_eq!(FollowMode::All.as_i64(), 1);
        assert_eq!(FollowMode::ObeyCode.as_i64(), 2);
        assert_eq!(FollowMode::FirstOnly.as_i64(), 3);
        assert_eq!(FollowMode::default(), FollowMode::Disabled);
        assert_eq!(FollowMode::VARIANTS.len(), 4);
        for (index, mode) in FollowMode::VARIANTS.iter().enumerate() {
            assert_eq!(mode.as_i64(), index as i64);
        }
        assert!(!FollowMode::Disabled.is_enabled());
        assert!(FollowMode::All.is_enabled());
        assert!(FollowMode::ObeyCode.is_enabled());
        assert!(FollowMode::FirstOnly.is_enabled());
    }

    #[test]
    fn follow_location_option_validation_matches_the_source() {
        assert_eq!(FollowMode::from_option_value(0), Ok(FollowMode::Disabled));
        assert_eq!(FollowMode::from_option_value(1), Ok(FollowMode::All));
        assert_eq!(FollowMode::from_option_value(2), Ok(FollowMode::ObeyCode));
        assert_eq!(FollowMode::from_option_value(3), Ok(FollowMode::FirstOnly));
        // Above three, and -- through the C's cast to unsigned long -- below
        // zero too.
        for value in [4_i64, 5, 1_000, -1, -2, i64::MIN, i64::MAX] {
            assert_eq!(
                FollowMode::from_option_value(value),
                Err(CURLcode::BadFunctionArgument),
                "{value} must be rejected"
            );
        }
    }

    #[test]
    fn maxredirs_validation_rejects_below_minus_one_and_clamps_above_max() {
        assert_eq!(MAXREDIRS_DEFAULT, 30);
        assert_eq!(MAXREDIRS_UNLIMITED, -1);
        assert_eq!(MAXREDIRS_MIN, -1);
        assert_eq!(MAXREDIRS_MAX, 0x7fff);
        assert_eq!(MAXREDIRS_MAX, i64::from(i16::MAX));

        assert_eq!(validate_maxredirs(-1), Ok(-1));
        assert_eq!(validate_maxredirs(0), Ok(0));
        assert_eq!(validate_maxredirs(30), Ok(30));
        assert_eq!(validate_maxredirs(0x7fff), Ok(0x7fff));
        // Above the ceiling is CLAMPED, not rejected.
        assert_eq!(validate_maxredirs(0x8000), Ok(0x7fff));
        assert_eq!(validate_maxredirs(i64::MAX), Ok(0x7fff));
        // Below it IS rejected.
        assert_eq!(validate_maxredirs(-2), Err(CURLcode::BadFunctionArgument));
        assert_eq!(
            validate_maxredirs(i64::MIN),
            Err(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn postredir_option_validation_reads_the_three_bits() {
        assert_eq!(CURL_REDIR_GET_ALL, 0);
        assert_eq!(CURL_REDIR_POST_301, 1);
        assert_eq!(CURL_REDIR_POST_302, 2);
        assert_eq!(CURL_REDIR_POST_303, 4);

        let none = PostRedir::from_option_value(0).expect("valid");
        assert_eq!(none, PostRedir::default());
        assert_eq!(none.as_i64(), 0);

        let all = PostRedir::from_option_value(7).expect("valid");
        assert!(all.post301 && all.post302 && all.post303);
        assert_eq!(all.as_i64(), 7);

        let only302 = PostRedir::from_option_value(2).expect("valid");
        assert!(!only302.post301 && only302.post302 && !only302.post303);
        assert_eq!(only302.as_i64(), 2);

        // Unknown high bits are ignored, exactly as the C ignores them.
        let extra = PostRedir::from_option_value(0xff).expect("valid");
        assert_eq!(extra.as_i64(), 7);

        assert_eq!(
            PostRedir::from_option_value(-1),
            Err(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn the_follow_vocabulary_keeps_the_source_order() {
        assert_eq!(FollowType::None as i32, 0);
        assert_eq!(FollowType::Fake as i32, 1);
        assert_eq!(FollowType::Retry as i32, 2);
        assert_eq!(FollowType::Redir as i32, 3);
        assert_eq!(FollowType::default(), FollowType::None);
        for (index, kind) in FollowType::VARIANTS.iter().enumerate() {
            assert_eq!(*kind as usize, index);
            assert!(kind.c_name().starts_with("FOLLOW_"));
        }

        assert_eq!(HttpRequestKind::Get as i32, 0);
        assert_eq!(HttpRequestKind::Post as i32, 1);
        assert_eq!(HttpRequestKind::PostForm as i32, 2);
        assert_eq!(HttpRequestKind::PostMime as i32, 3);
        assert_eq!(HttpRequestKind::Put as i32, 4);
        assert_eq!(HttpRequestKind::Head as i32, 5);
        assert_eq!(HttpRequestKind::default(), HttpRequestKind::Get);
        assert_eq!(HttpRequestKind::VARIANTS.len(), 6);
        for (index, kind) in HttpRequestKind::VARIANTS.iter().enumerate() {
            assert_eq!(*kind as usize, index);
            assert!(kind.c_name().starts_with("HTTPREQ_"));
        }

        assert!(HttpRequestKind::Post.is_post_like());
        assert!(HttpRequestKind::PostForm.is_post_like());
        assert!(HttpRequestKind::PostMime.is_post_like());
        assert!(!HttpRequestKind::Get.is_post_like());
        assert!(!HttpRequestKind::Put.is_post_like());
        assert!(!HttpRequestKind::Head.is_post_like());
    }

    #[test]
    fn the_follow_settings_default_to_curls_own() {
        let settings = FollowSettings::default();
        assert_eq!(settings.mode, FollowMode::Disabled);
        assert_eq!(settings.maxredirs, MAXREDIRS_DEFAULT);
        assert_eq!(settings.postredir, PostRedir::default());
        assert!(!settings.auto_referer);
        assert!(!settings.allow_auth_to_other_hosts);
    }

    #[test]
    fn pretransfer_clears_the_counters_but_not_the_reported_info() {
        let mut state = FollowState {
            followlocation: 4,
            requests: 9,
            httpcode: 302,
            wouldredirect: Some("https://example.test/z".to_string()),
            allow_port: false,
            ignore_custom_request: true,
            this_is_a_follow: true,
        };

        state.pretransfer();

        assert_eq!(state.followlocation, 0);
        assert_eq!(state.requests, 0);
        assert!(!state.this_is_a_follow);
        assert!(state.allow_port, "Curl_pretransfer sets this one TRUE");
        // `data->info` members are not this function's business.
        assert_eq!(state.httpcode, 302);
        assert_eq!(
            state.wouldredirect.as_deref(),
            Some("https://example.test/z")
        );
    }

    #[test]
    fn the_redirect_ceiling_is_reached_at_the_configured_count() {
        let mut state = FollowState::default();
        assert!(state.reached_max_redirects(0), "zero refuses the first");
        assert!(!state.reached_max_redirects(1));
        assert!(!state.reached_max_redirects(MAXREDIRS_UNLIMITED));

        state.followlocation = 30;
        assert!(state.reached_max_redirects(30));
        assert!(state.reached_max_redirects(29));
        assert!(!state.reached_max_redirects(31));
        assert!(
            !state.reached_max_redirects(MAXREDIRS_UNLIMITED),
            "-1 is never reached"
        );
    }

    // -- following ---------------------------------------------------------

    /// A follow-ready request, seam, protocol double, settings and state.
    fn follow_fixture(
        url: &str,
    ) -> (
        SingleRequest,
        TestIo,
        TestFollow,
        FollowSettings,
        FollowState,
    ) {
        let (req, io) = started();
        let mut state = FollowState::default();
        state.pretransfer();
        let settings = FollowSettings {
            mode: FollowMode::All,
            ..FollowSettings::default()
        };
        (req, io, TestFollow::new(url), settings, state)
    }

    #[test]
    fn a_protocol_without_a_follow_operation_answers_too_many_redirects() {
        let (mut req, mut io, _protocol, settings, mut state) =
            follow_fixture("https://example.test/next");

        assert_eq!(
            req.follow(
                &mut io,
                None,
                &settings,
                &mut state,
                "https://example.test/next",
                FollowType::Redir,
            ),
            Err(CURLcode::TooManyRedirects)
        );
        // Nothing was counted and nothing was reset.
        assert_eq!(state.requests, 0);
        assert_eq!(state.followlocation, 0);
    }

    #[test]
    fn a_real_redirect_counts_commits_resets_and_logs() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://example.test/next");
        io.clock.set(CurlTime::new(10, 0));
        req.start(&mut io).expect("started");
        io.clock.advance(Duration::from_secs(3));
        req.bytecount = 500;
        req.done = true;

        req.follow(
            &mut io,
            Some(&mut protocol),
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");

        assert_eq!(state.requests, 1);
        assert_eq!(state.followlocation, 1);
        assert!(state.this_is_a_follow);
        assert!(state.wouldredirect.is_none());
        assert_eq!(protocol.committed, vec!["https://example.test/next"]);
        assert_eq!(protocol.resolve_types, vec![FollowType::Redir]);
        assert!(io.said(
            "Issue another request to this URL: 'https://example.test/next'"
        ));
        // The soft reset ran: per-attempt state is clear.
        assert!(!req.done);
        assert_eq!(req.bytecount, 0);
        // But the overall start time survived, which is the whole point.
        assert_eq!(req.start, CurlTime::new(10, 0));
        // And the redirect timer was recorded and the sizes forgotten.
        assert_eq!(io.timers, vec![TimerId::Redirect]);
        assert_eq!(io.progress().size_upload(), 0);
        assert_eq!(io.progress().size_download(), 0);
    }

    #[test]
    fn a_retry_uses_the_same_path_but_counts_no_redirect() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://example.test/same");
        req.done = true;

        req.follow(
            &mut io,
            Some(&mut protocol),
            &settings,
            &mut state,
            "https://example.test/same",
            FollowType::Retry,
        )
        .expect("retried");

        // Counted as a request, NOT as a redirect.
        assert_eq!(state.requests, 1);
        assert_eq!(state.followlocation, 0);
        // The reset still happened, so the next attempt starts clean.
        assert!(!req.done);
        assert_eq!(protocol.committed.len(), 1);
    }

    #[test]
    fn a_fake_follow_records_the_url_and_issues_nothing() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://example.test/would");
        req.done = true;

        req.follow(
            &mut io,
            Some(&mut protocol),
            &settings,
            &mut state,
            "/would",
            FollowType::Fake,
        )
        .expect("recorded");

        assert_eq!(
            state.wouldredirect.as_deref(),
            Some("https://example.test/would")
        );
        // Not counted, nothing committed, nothing reset, nothing logged.
        assert_eq!(state.requests, 0);
        assert_eq!(state.followlocation, 0);
        assert!(protocol.committed.is_empty());
        assert!(req.done, "a fake follow does not soft reset");
        assert!(io.timers.is_empty());
        assert!(!state.this_is_a_follow);
        // And no credential check: the C skips it for a fake follow.
        assert!(protocol.clear_auth_calls.is_empty());
    }

    #[test]
    fn a_redirect_at_the_ceiling_becomes_a_fake_follow_and_then_fails() {
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/over");
        settings.maxredirs = 2;
        state.followlocation = 2;
        req.done = true;

        assert_eq!(
            req.follow(
                &mut io,
                Some(&mut protocol),
                &settings,
                &mut state,
                "/over",
                FollowType::Redir,
            ),
            Err(CURLcode::TooManyRedirects)
        );

        // The would-be target was still recorded, which is why the C switches
        // to a fake follow rather than failing outright.
        assert_eq!(
            state.wouldredirect.as_deref(),
            Some("https://example.test/over")
        );
        assert!(protocol.committed.is_empty());
        assert!(req.done, "no reset happened");
        // The redirect counter did NOT move; the request counter did, because
        // the type was still REDIR when it was counted.
        assert_eq!(state.followlocation, 2);
        assert_eq!(state.requests, 1);
        assert_eq!(
            protocol.resolve_types,
            vec![FollowType::Fake],
            "the resolution ran in fake mode"
        );
        assert!(io
            .fail
            .iter()
            .any(|line| line == "Maximum (2) redirects followed"));
    }

    #[test]
    fn an_unlimited_ceiling_is_never_reached() {
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/next");
        settings.maxredirs = MAXREDIRS_UNLIMITED;
        state.followlocation = u16::MAX - 1;

        req.follow(
            &mut io,
            Some(&mut protocol),
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");

        assert_eq!(state.followlocation, u16::MAX);
        assert!(state.wouldredirect.is_none());
        // And the counter saturates rather than wrapping.
        req.follow(
            &mut io,
            Some(&mut protocol),
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");
        assert_eq!(state.followlocation, u16::MAX);
    }

    #[test]
    fn a_ceiling_of_zero_refuses_the_very_first_redirect() {
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/over");
        settings.maxredirs = 0;

        assert_eq!(
            req.follow(
                &mut io,
                Some(&mut protocol),
                &settings,
                &mut state,
                "/over",
                FollowType::Redir,
            ),
            Err(CURLcode::TooManyRedirects)
        );
        assert!(io
            .fail
            .iter()
            .any(|line| line == "Maximum (0) redirects followed"));
    }

    #[test]
    fn the_automatic_referer_runs_only_for_a_counted_real_redirect() {
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/next");
        settings.auto_referer = true;

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");
        assert_eq!(protocol.referer_calls, 1);

        // A retry does not set it.
        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Retry,
        )
        .expect("retried");
        assert_eq!(protocol.referer_calls, 1);

        // Nor does a redirect that tripped the ceiling.
        settings.maxredirs = 0;
        let _ = req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        );
        assert_eq!(protocol.referer_calls, 1);
    }

    #[test]
    fn a_failing_automatic_referer_stops_the_follow() {
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/next");
        settings.auto_referer = true;
        protocol.referer_result = Err(CURLcode::OutOfMemory);

        assert_eq!(
            req.follow_location(
                &mut io,
                &mut protocol,
                &settings,
                &mut state,
                "/next",
                FollowType::Redir,
            ),
            Err(CURLcode::OutOfMemory)
        );
        assert!(protocol.committed.is_empty());
    }

    #[test]
    fn an_unparsable_target_is_fatal_for_a_real_follow() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("unused");
        protocol.resolve.clear();
        protocol.resolve.push_back(ResolvedTarget::Unparsable {
            code: CURLcode::UrlMalformat,
            reason: "Malformed input to a URL function",
        });

        assert_eq!(
            req.follow_location(
                &mut io,
                &mut protocol,
                &settings,
                &mut state,
                "http://[",
                FollowType::Redir,
            ),
            Err(CURLcode::UrlMalformat)
        );
        assert!(io.fail.iter().any(|line| line
            == "The redirect target URL could not be parsed: Malformed \
                input to a URL function"));
        assert!(protocol.committed.is_empty());
    }

    #[test]
    fn an_unparsable_target_survives_a_fake_follow_as_the_raw_string() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("unused");
        protocol.resolve.clear();
        protocol.resolve.push_back(ResolvedTarget::Unparsable {
            code: CURLcode::UrlMalformat,
            reason: "Malformed input to a URL function",
        });

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "gopher://weird",
            FollowType::Fake,
        )
        .expect("a fake follow keeps the raw target");

        assert_eq!(state.wouldredirect.as_deref(), Some("gopher://weird"));
        assert!(io.fail.is_empty());
    }

    #[test]
    fn an_out_of_memory_resolution_is_fatal_even_for_a_fake_follow() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("unused");
        protocol.resolve.clear();
        protocol.resolve.push_back(ResolvedTarget::Unparsable {
            code: CURLcode::OutOfMemory,
            reason: "Out of memory",
        });

        assert_eq!(
            req.follow_location(
                &mut io,
                &mut protocol,
                &settings,
                &mut state,
                "/anything",
                FollowType::Fake,
            ),
            Err(CURLcode::OutOfMemory)
        );
        assert!(state.wouldredirect.is_none());
    }

    #[test]
    fn an_absolute_redirect_forfeits_an_inherited_explicit_port() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://other.test/next");
        protocol.absolute = true;
        assert!(state.allow_port);

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "https://other.test/next",
            FollowType::Redir,
        )
        .expect("followed");

        assert!(!state.allow_port);
    }

    #[test]
    fn a_401_or_407_keeps_the_explicit_port_and_so_does_a_retry() {
        for code in [401, 407] {
            let (mut req, mut io, mut protocol, settings, mut state) =
                follow_fixture("https://other.test/next");
            protocol.absolute = true;
            req.httpcode = code;

            req.follow_location(
                &mut io,
                &mut protocol,
                &settings,
                &mut state,
                "https://other.test/next",
                FollowType::Redir,
            )
            .expect("followed");

            assert!(state.allow_port, "{code} must keep the port");
        }

        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://other.test/next");
        protocol.absolute = true;
        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "https://other.test/next",
            FollowType::Retry,
        )
        .expect("retried");
        assert!(state.allow_port, "a retry must keep the port");
    }

    #[test]
    fn a_relative_redirect_keeps_the_explicit_port() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://example.test/next");
        assert!(!protocol.absolute);

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");

        assert!(state.allow_port);
    }

    #[test]
    fn credentials_are_checked_unless_unrestricted_auth_is_permitted() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://other.test/next");
        assert!(!settings.allow_auth_to_other_hosts);

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");
        // The check ran, and it saw the current allow-port state.
        assert_eq!(protocol.clear_auth_calls, vec![true]);

        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://other.test/next");
        settings.allow_auth_to_other_hosts = true;
        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");
        assert!(protocol.clear_auth_calls.is_empty());
    }

    #[test]
    fn a_failing_credential_check_stops_the_follow() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://other.test/next");
        protocol.clear_auth_result = Err(CURLcode::UrlMalformat);

        assert_eq!(
            req.follow_location(
                &mut io,
                &mut protocol,
                &settings,
                &mut state,
                "/next",
                FollowType::Redir,
            ),
            Err(CURLcode::UrlMalformat)
        );
        assert!(protocol.committed.is_empty());
    }

    #[test]
    fn first_only_drops_the_custom_method_once_and_says_so_once() {
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/next");
        settings.mode = FollowMode::FirstOnly;
        protocol.custom_request = Some("PATCH".to_string());

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");

        assert!(state.ignore_custom_request);
        assert!(io.said("Drop custom request method for next request"));

        // A second redirect does not say it again.
        io.info.clear();
        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");
        assert!(!io.said("Drop custom request method for next request"));
    }

    #[test]
    fn the_other_modes_keep_the_custom_method_at_step_seven() {
        for mode in [FollowMode::All, FollowMode::ObeyCode] {
            let (mut req, mut io, mut protocol, mut settings, mut state) =
                follow_fixture("https://example.test/next");
            settings.mode = mode;
            protocol.custom_request = Some("PATCH".to_string());

            req.follow_location(
                &mut io,
                &mut protocol,
                &settings,
                &mut state,
                "/next",
                FollowType::Redir,
            )
            .expect("followed");

            assert!(!state.ignore_custom_request, "{mode:?}");
            assert!(!io.said("Drop custom request method for next request"));
        }
    }

    #[test]
    fn without_a_custom_method_first_only_says_nothing() {
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/next");
        settings.mode = FollowMode::FirstOnly;
        assert!(protocol.custom_request.is_none());

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");

        assert!(!state.ignore_custom_request);
        assert!(!io.said("Drop custom request method for next request"));
    }

    // -- the method transitions -------------------------------------------

    /// Runs one redirect and reports whether the method became GET.
    fn method_after(
        code: i32,
        method: HttpRequestKind,
        postredir: PostRedir,
        mode: FollowMode,
    ) -> (HttpRequestKind, Vec<String>) {
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/next");
        settings.postredir = postredir;
        settings.mode = mode;
        protocol.method = method;
        state.httpcode = code;

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");

        (protocol.method, io.info.clone())
    }

    #[test]
    fn a_301_or_302_turns_a_post_into_a_get_unless_postredir_says_otherwise() {
        let keep_all = PostRedir::from_option_value(7).expect("valid");
        let none = PostRedir::default();

        for code in [301, 302] {
            for method in [
                HttpRequestKind::Post,
                HttpRequestKind::PostForm,
                HttpRequestKind::PostMime,
            ] {
                let (after, _) =
                    method_after(code, method, none, FollowMode::All);
                assert_eq!(
                    after,
                    HttpRequestKind::Get,
                    "{code} with {method:?} switches by default"
                );

                let (after, _) =
                    method_after(code, method, keep_all, FollowMode::All);
                assert_eq!(
                    after, method,
                    "{code} with {method:?} is kept under POSTREDIR"
                );
            }

            // A non-POST method is untouched by 301 and 302.
            for method in [
                HttpRequestKind::Get,
                HttpRequestKind::Put,
                HttpRequestKind::Head,
            ] {
                let (after, _) =
                    method_after(code, method, none, FollowMode::All);
                assert_eq!(after, method, "{code} leaves {method:?} alone");
            }
        }

        // And the two bits are independent.
        let only301 =
            PostRedir::from_option_value(CURL_REDIR_POST_301).expect("valid");
        let (after, _) =
            method_after(301, HttpRequestKind::Post, only301, FollowMode::All);
        assert_eq!(after, HttpRequestKind::Post);
        let (after, _) =
            method_after(302, HttpRequestKind::Post, only301, FollowMode::All);
        assert_eq!(after, HttpRequestKind::Get);
    }

    #[test]
    fn a_303_turns_any_non_get_method_into_a_get() {
        let none = PostRedir::default();

        for method in [
            HttpRequestKind::Post,
            HttpRequestKind::PostForm,
            HttpRequestKind::PostMime,
            HttpRequestKind::Put,
            HttpRequestKind::Head,
        ] {
            let (after, _) = method_after(303, method, none, FollowMode::All);
            assert_eq!(after, HttpRequestKind::Get, "303 switches {method:?}");
        }

        // A GET stays a GET, and the C skips the switch entirely.
        let (after, _) =
            method_after(303, HttpRequestKind::Get, none, FollowMode::All);
        assert_eq!(after, HttpRequestKind::Get);
    }

    #[test]
    fn curl_redir_post_303_keeps_a_post_but_not_a_put() {
        let keep303 =
            PostRedir::from_option_value(CURL_REDIR_POST_303).expect("valid");

        for method in [
            HttpRequestKind::Post,
            HttpRequestKind::PostForm,
            HttpRequestKind::PostMime,
        ] {
            let (after, _) =
                method_after(303, method, keep303, FollowMode::All);
            assert_eq!(after, method, "303 keeps {method:?} under POSTREDIR");
        }

        // The override is scoped to POST: a PUT still becomes a GET, because
        // the C's condition only exempts the three POST kinds.
        let (after, _) =
            method_after(303, HttpRequestKind::Put, keep303, FollowMode::All);
        assert_eq!(after, HttpRequestKind::Get);
    }

    #[test]
    fn every_other_status_leaves_the_method_alone() {
        let none = PostRedir::default();
        for code in [0, 200, 300, 304, 305, 306, 307, 308, 401, 407] {
            let (after, lines) = method_after(
                code,
                HttpRequestKind::Post,
                none,
                FollowMode::All,
            );
            assert_eq!(
                after,
                HttpRequestKind::Post,
                "{code} must not switch the method"
            );
            assert!(
                !lines.iter().any(|line| line.starts_with("Switch to GET")),
                "{code} must not log a switch"
            );
        }
    }

    #[test]
    fn obey_code_drops_the_custom_method_and_all_sticks_to_it() {
        // OBEYCODE: the status wins, the custom method is dropped, and the C's
        // line names the code.
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/next");
        settings.mode = FollowMode::ObeyCode;
        protocol.custom_request = Some("PATCH".to_string());
        protocol.method = HttpRequestKind::Post;
        state.httpcode = 301;
        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");
        assert!(io.said("Switch to GET because of 301 response"));
        assert!(state.ignore_custom_request);
        assert_eq!(protocol.method, HttpRequestKind::Get);

        // ALL: the custom method is kept and the C says so.
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/next");
        settings.mode = FollowMode::All;
        protocol.custom_request = Some("PATCH".to_string());
        protocol.method = HttpRequestKind::Post;
        state.httpcode = 302;
        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");
        assert!(io.said("Stick to PATCH instead of GET"));
        assert!(!state.ignore_custom_request);
        assert_eq!(protocol.method, HttpRequestKind::Get);

        // FIRSTONLY: silent here, because step seven already said its line.
        let (mut req, mut io, mut protocol, mut settings, mut state) =
            follow_fixture("https://example.test/next");
        settings.mode = FollowMode::FirstOnly;
        protocol.custom_request = Some("PATCH".to_string());
        protocol.method = HttpRequestKind::Post;
        state.httpcode = 303;
        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");
        assert!(!io.said("Stick to PATCH instead of GET"));
        assert!(io.said("Drop custom request method for next request"));
        assert_eq!(protocol.method, HttpRequestKind::Get);
    }

    #[test]
    fn obey_code_says_nothing_when_the_method_is_already_a_plain_get() {
        // Neither a custom method nor a non-GET method, so the C's first
        // condition is false and its `else if` needs a custom method it does
        // not have. Reached through a 303, whose switch does not require a
        // POST -- but a GET does not switch either, so this asserts silence on
        // the path that runs.
        let (after, lines) = method_after(
            303,
            HttpRequestKind::Get,
            PostRedir::default(),
            FollowMode::ObeyCode,
        );
        assert_eq!(after, HttpRequestKind::Get);
        assert!(!lines.iter().any(|line| line.starts_with("Switch to GET")));
        assert!(!lines.iter().any(|line| line.starts_with("Stick to")));
    }

    #[test]
    fn the_switch_to_get_cancels_a_pending_rewind() {
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://example.test/next");
        protocol.method = HttpRequestKind::Post;
        state.httpcode = 302;
        req.rewind_read = true;

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("followed");

        assert!(!req.rewind_read, "a GET has no body left to rewind");
    }

    #[test]
    fn a_failed_rewind_is_fatal_only_when_the_method_did_not_become_a_get() {
        // The method does NOT become GET, so the rewind failure is returned.
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://example.test/next");
        io.client_start_result = Err(CURLcode::ReadError);
        protocol.method = HttpRequestKind::Put;
        state.httpcode = 307;

        assert_eq!(
            req.follow_location(
                &mut io,
                &mut protocol,
                &settings,
                &mut state,
                "/next",
                FollowType::Redir,
            ),
            Err(CURLcode::ReadError)
        );
        // The URL was still committed and the line still emitted: the C does
        // not return early, it defers.
        assert_eq!(protocol.committed.len(), 1);
        assert!(io.said(
            "Issue another request to this URL: 'https://example.test/next'"
        ));
        assert!(io.timers.is_empty(), "the redirect timer is not reached");

        // The method DOES become GET, so the same failure is forgiven.
        let (mut req, mut io, mut protocol, settings, mut state) =
            follow_fixture("https://example.test/next");
        io.client_start_result = Err(CURLcode::ReadError);
        protocol.method = HttpRequestKind::Post;
        state.httpcode = 302;

        req.follow_location(
            &mut io,
            &mut protocol,
            &settings,
            &mut state,
            "/next",
            FollowType::Redir,
        )
        .expect("a POST turned into a GET has no body to replay");
        assert_eq!(protocol.method, HttpRequestKind::Get);
        assert_eq!(io.timers, vec![TimerId::Redirect]);
    }

    // -- the seam's own defaults -------------------------------------------

    /// The seam with ONLY its required methods implemented -- which is what a
    /// production engine looks like, because the three defaulted methods are
    /// defaulted precisely so that no engine has to write them.
    #[derive(Debug)]
    struct PlainIo(TestIo);

    impl RequestIo for PlainIo {
        fn config(&self) -> RequestConfig {
            self.0.config()
        }
        fn has_connection(&self) -> bool {
            self.0.has_connection()
        }
        fn xfer_send(&mut self, bytes: &[u8], eos: bool) -> CodeResult<usize> {
            self.0.xfer_send(bytes, eos)
        }
        fn xfer_needs_flush(&self) -> bool {
            self.0.xfer_needs_flush()
        }
        fn xfer_flush(&mut self) -> CodeResult<()> {
            self.0.xfer_flush()
        }
        fn xfer_send_close(&mut self) -> CodeResult<()> {
            self.0.xfer_send_close()
        }
        fn xfer_send_shutdown(&mut self) -> CodeResult<SendShutdown> {
            self.0.xfer_send_shutdown()
        }
        fn client_read(&mut self, into: &mut [u8]) -> CodeResult<ReadOutcome> {
            self.0.client_read(into)
        }
        fn creader_done(&mut self, premature: bool) {
            self.0.creader_done(premature);
        }
        fn creader_total_length(&self) -> i64 {
            self.0.creader_total_length()
        }
        fn client_start(&mut self) -> CodeResult<()> {
            self.0.client_start()
        }
        fn client_reset(&mut self) {
            self.0.client_reset();
        }
        fn client_cleanup(&mut self) {
            self.0.client_cleanup();
        }
        fn doh_close(&mut self) {
            self.0.doh_close();
        }
        fn progress(&self) -> &Progress {
            self.0.progress()
        }
        fn progress_mut(&mut self) -> &mut Progress {
            self.0.progress_mut()
        }
        fn pgrs_now(&mut self) -> CurlTime {
            self.0.pgrs_now()
        }
        fn pgrs_time(&mut self, timer: TimerId) {
            self.0.pgrs_time(timer);
        }
        fn debug(&mut self, kind: TraceDataKind, bytes: &[u8]) {
            self.0.debug(kind, bytes);
        }
        fn infof(&mut self, line: fmt::Arguments<'_>) {
            self.0.infof(line);
        }
        fn failf(&mut self, line: fmt::Arguments<'_>) {
            self.0.failf(line);
        }
    }

    #[test]
    fn a_seam_that_overrides_nothing_reads_no_environment_and_traces_nothing() {
        let mut io = PlainIo(TestIo::new());
        io.0.env = Some(FixedEnv {
            small_req_send: Some("1".to_string()),
        });

        // The default answer is None even though the inner double HAS an
        // environment, so the C's `#ifdef DEBUGBUILD`-disabled state is what a
        // production engine gets and the override cannot fire.
        assert!(io.debug_env().is_none());
        // And the default trace discards its line rather than storing one.
        io.trace(format_args!("discarded"));
        assert!(io.0.traces.is_empty());

        // Now drive a whole request through it, so the default bodies are
        // exercised on the real paths rather than in isolation.
        let mut req = SingleRequest::new();
        req.start(&mut io).expect("started");
        io.0.total_length = 4;
        io.0.script_reads(&[ReadStep::Bytes(b"BODY".to_vec(), true)]);
        req.send(&mut io, b"PUT\r\n", 11).expect("sent");

        // The body was NOT shortened, which is what proves the environment was
        // never consulted.
        assert_eq!(io.0.accepted_bytes(), b"PUT\r\nBODY");
        assert_eq!(req.writebytecount, 4);
        assert!(req.upload_done);
        assert!(io.0.traces.is_empty(), "no trace line was kept");

        // The remaining seam methods, on their own paths. First the
        // transport's own flush, which an empty queue defers to.
        io.0.needs_flush = true;
        assert!(io.xfer_needs_flush());
        req.flush(&mut io).expect("flushed");
        assert_eq!(io.0.flushes, 1);
        assert!(io.0.traces.is_empty(), "the default trace still keeps none");
        io.0.needs_flush = false;

        // Then the send shutdown, which needs the upload reopened.
        req.upload_done = false;
        req.eos_read = true;
        req.eos_sent = false;
        req.shutdown = true;
        io.0.shutdowns.push_back(Ok(SendShutdown::Complete));
        req.flush(&mut io).expect("flushed");
        assert_eq!(io.0.shutdown_calls, 1);
        assert!(req.upload_done);

        let mut protocol = TestFollow::new("https://example.test/next");
        let settings = FollowSettings::default();
        let mut state = FollowState::default();
        protocol.resolve.clear();
        protocol.resolve.push_back(ResolvedTarget::Unparsable {
            code: CURLcode::UrlMalformat,
            reason: "Malformed input to a URL function",
        });
        assert_eq!(
            req.follow(
                &mut io,
                Some(&mut protocol),
                &settings,
                &mut state,
                "http://[",
                FollowType::Redir,
            ),
            Err(CURLcode::UrlMalformat)
        );
        assert_eq!(io.0.fail.len(), 1);

        req.done(&mut io, true).expect("done");
        req.free(&mut io);
        assert_eq!(io.0.client_resets, 1);
        assert_eq!(io.0.client_cleanups, 1);
        assert_eq!(io.0.doh_closes, 1);
    }

    #[test]
    fn flushing_the_queue_before_it_exists_is_a_silent_no_operation() {
        let mut io = TestIo::new();
        let mut req = SingleRequest::new();

        // `flush` cannot reach this -- `sendbuf_empty` answers true without a
        // queue and the drain arm is skipped -- so the defensive answer is
        // asserted directly rather than left unexercised.
        assert!(!req.sendbuf_init());
        req.sendbuf_flush(&mut io).expect("nothing to drain");
        assert!(io.sent.is_empty());
        assert!(!req.sendbuf_init(), "and no queue was conjured up");
    }

    // -- the module's own invariants ---------------------------------------

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_module_never_reads_a_host_clock_or_names_the_platform() {
        // Assembled rather than written out, so that the needles cannot match
        // this test's own source and leave the gate vacuous.
        let monotonic = concat!("Instant", "::", "now");
        let wall = concat!("SystemTime", "::", "now");
        let platform = concat!("libc", "::");
        let allocate = concat!("alloc", "::", "alloc");

        let source = include_str!("request.rs");
        let mut offenders: Vec<String> = Vec::new();
        for (index, line) in source.lines().enumerate() {
            // Comments are stripped: this module DISCUSSES all four spellings
            // in its documentation, and a scan that kept prose would flag the
            // prose rather than the code.
            let code = line.split("//").next().unwrap_or("");
            for needle in [monotonic, wall, platform, allocate] {
                if code.contains(needle) {
                    offenders.push(format!("{}: {needle}", index + 1));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "every instant reaches this module through RequestIo::pgrs_now, \
             and no platform type belongs here. Offenders: {offenders:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_module_does_not_depend_on_the_transfer_module_root() {
        let source = include_str!("request.rs");
        for (index, line) in source.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            let trimmed = code.trim_start();
            if !trimmed.starts_with("use ") {
                continue;
            }
            // `crate::transfer::<child>` is fine -- progress, ratelimit and
            // sendf are all below this module's parent. An import of the
            // parent ITSELF, which is where the engine lives, would be the
            // cycle the module documentation refuses.
            assert!(
                !trimmed.contains("use crate::transfer;"),
                "line {}: the engine is reached through RequestIo, never by \
                 importing its module",
                index + 1
            );
            assert!(
                !trimmed.contains("crate::protocols"),
                "line {}: protocol work is reached through ProtocolFollow",
                index + 1
            );
            assert!(
                !trimmed.contains("crate::tls"),
                "line {}: no TLS import belongs in the request layer",
                index + 1
            );
        }
    }

    /// A redirect target cannot appear in a formatted request.
    ///
    /// `Location:` and the derived redirect URL both arrive from the peer and
    /// both can carry a credential, which is why `crate::url::Url` redacts
    /// userinfo; this asserts the same for the two places a transfer keeps one.
    #[test]
    fn a_redirect_url_cannot_reach_a_formatted_request() {
        const LOCATION: &str = "https://alice:hunter2@example.com/next?tok=s3";

        let mut req = SingleRequest::new();
        req.location = Some(String::from(LOCATION));
        req.newurl = Some(String::from(LOCATION));

        let text = format!("{req:?}");
        assert!(!text.contains("hunter2"), "the password leaked: {text}");
        assert!(!text.contains("alice"), "the username leaked: {text}");
        assert!(!text.contains("example.com"), "the target leaked: {text}");
        assert!(
            text.contains(&format!("<redacted, {} bytes>", LOCATION.len())),
            "{text}"
        );

        // The accounting a reader of a transfer message wants still renders,
        // and the dump says it is a summary rather than the whole struct.
        assert!(text.contains("bytecount"), "{text}");
        assert!(text.contains(".."), "{text}");

        // The stored values are unchanged, so redirect handling is unaffected.
        assert_eq!(req.newurl.as_deref(), Some(LOCATION));
    }
}
