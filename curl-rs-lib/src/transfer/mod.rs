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
//! The transfer core: the loop, its buffers and its accounting.
//!
//! Supersedes `lib/transfer.c` with `lib/transfer.h` (the transfer loop, which
//! becomes async, and the whole `Curl_xfer_*` surface), together with the
//! per-state transfer work `lib/multi.c` drives -- `multi_runsingle`'s
//! `switch(data->mstate)` and its helpers `state_connect`, `state_resolving`,
//! `state_do`, `state_performing`, `state_ratelimiting`, `mspeed_check`,
//! `multi_do`, `multi_do_more`, `multi_follow`, `protocol_connect`,
//! `protocol_connecting`, `protocol_doing`, `multi_handle_timeout`,
//! `is_finished` and `multi_done`. It also supersedes `lib/request.c`
//! (per-request state), `lib/sendf.c` (manual buffers become `BytesMut`),
//! `lib/cw-out.c` with `lib/cw-pause.c` (the client-writer chain and pause
//! handling), `lib/progress.c` (accounting, with the output format frozen),
//! `lib/ratelimit.c` (`--limit-rate` pacing), `lib/content_encoding.c` (zlib,
//! brotli and zstd calls become `flate2`, `brotli` and `zstd`) and
//! `lib/http_chunks.c` (chunked framing, byte-exact in both directions).
//!
//! The division of labour with `crate::multi` is the C's own, made explicit:
//! the WORK of a state belongs here and the multi handle's COLLECTION
//! mechanics -- the transfer table, the three membership sets, the message
//! queue and `CURLMSG_DONE` -- stay there. [`Transfer::run_single`] therefore
//! returns a typed [`RunSingle`] rather than touching a set or a message.
//!
//! `pub(crate)`: a transfer is driven through an easy or a multi handle, and
//! no exported symbol names a transfer directly.
//!
//! This is one of the two directories the line-coverage gate of
//! specification 0.8.4 measures, at 80 percent of lines or better. Almost
//! everything here is time-driven, so the clock reaches this directory by
//! injection -- as a [`CurlTime`] parameter or a [`Clock`] reference from
//! `crate::util::timeval` -- and never by reading the host clock. A module
//! that read the clock itself could not be tested deterministically, and the
//! gate would be out of reach.
//!
//! [`CurlTime`]: crate::util::timeval::CurlTime
//! [`Clock`]: crate::util::timeval::Clock
//!
//! # The seven children, and why this file is last
//!
//! The order in which they compose is dependency order rather than
//! preference. [`ratelimit`] came first because it depends on nothing but the
//! utility layer: it is a self-contained arithmetic primitive that progress
//! accounting EMBEDS, following `lib/urldata.h:786-791`, where
//! `struct pgrs_dir` carries a `struct Curl_rlimit` as a member. [`progress`]
//! is second, and it is the only module in this directory that may name
//! [`ratelimit`]; nothing may invert that direction. [`sendf`] is the shared
//! substrate the remaining four compose out of, and this module root is the
//! dependency-LAST aggregator: it may name all seven, and none of them may
//! name it.
//!
//! That last sentence is the whole reason the C's include cycle does not
//! become a module cycle. `lib/sendf.c` includes `transfer.h`,
//! `lib/request.c` includes `transfer.h` and `lib/cw-out.c` includes both --
//! and all three are included BY `lib/transfer.c` in turn. What those files
//! reach through the cycle for arrives instead as narrow seams the engine
//! implements: [`sendf::TransferControl`] for the three operations
//! `lib/sendf.c` asks of the transfer loop, and [`request::RequestIo`] for
//! everything `lib/request.c` reaches through `data` for. This file
//! implements neither trait itself; the OWNER of a transfer does, and hands
//! the result in through [`TransferIo::request_io`].
//!
//! # No runtime, no clock, no socket, no TLS
//!
//! Nothing here constructs a `tokio` runtime. `curl-rs/src/main.rs` owns a
//! current-thread runtime and `crate::multi` owns a multi-thread one, so the
//! futures below are runtime-agnostic: they await, and whoever polls them
//! decides on which thread. Nothing here reads a host clock either -- every
//! instant arrives from the injected [`Clock`] through
//! [`request::RequestIo::pgrs_now`], which is what makes a timeout diagnostic
//! and a rate-limit decision assertable against a pinned
//! [`TestClock`](crate::util::timeval::TestClock). Nothing here touches a
//! socket, a descriptor set or a pollset: readiness arrives from the tokio
//! reactor by way of `crate::conn`, so the four C pollset callbacks
//! (`connecting_pollset`, `doing_pollset`, `domore_pollset` and
//! `perform_pollset`) are never called from this file. And nothing here names
//! a TLS type: `crate::conn`'s filter chain interposes TLS transparently, so
//! the transfer core sees typed filter I/O and cannot tell an encrypted
//! connection from a plain one.

use core::fmt;

use crate::conn::filters::SocketIndex;
use crate::conn::ProtocolOptions;
use crate::error::{CURLMcode, CURLcode, CodeResult, CurlResult, Error};
use crate::multi::state::CurlMstate;
use crate::protocols::{Proto, Protocol, Scheme, TransferCtx};
use crate::trace::TimerId as ExpireId;
use crate::transfer::progress::{
    Check, Done as PgrsDone, Meter, TimerId as PgrsTimer,
};
use crate::transfer::request::{
    FollowSettings, FollowState, FollowType, HttpRequestKind, KeepFlags,
    ProtocolFollow, RequestIo, SendShutdown, SingleRequest,
};
use crate::transfer::sendf::ClientWriteFlags;
use crate::util::timediff::{mstotv, TimeDiff};
use crate::util::timeval::timediff_ms;

/// Transfer accounting and timing: supersedes `lib/progress.c` and
/// `lib/progress.h`.
///
/// Owns the state `CURLINFO_*_T`, the progress callbacks, the low-speed abort
/// and `--write-out`'s `%{time_*}`, `%{size_*}` and `%{speed_*}` variables all
/// read -- the measured `struct Progress` and `struct pgrs_dir` of
/// `lib/urldata.h:786-831`.
///
/// It renders nothing. The built-in meter's layout, `time2str` and `max6out`
/// belong to `curl-rs/src/output/progress.rs` and
/// `curl-rs/src/callbacks/progress.rs`, where the emitted bytes are frozen;
/// this module preserves every value they read and hands it over in one
/// snapshot. It reads no clock and arms no timer either: an instant arrives as
/// a parameter or a `Clock` to sample, and the low-speed check RETURNS the
/// `EXPIRE_SPEEDCHECK` request rather than making it.
pub(crate) mod progress;

/// The client reader and writer chains: supersedes `lib/sendf.c` and
/// `lib/sendf.h`.
///
/// The shared substrate of this directory. Every response byte in the crate
/// reaches the application through `ClientIo::client_write` and every request
/// byte leaves it through `ClientIo::client_read`, so `writeout`, `chunked`,
/// `content_encoding` and `request` all compose out of the two traits declared
/// here -- `ClientWriter` and `ClientReader` -- rather than out of a
/// per-protocol arrangement of their own.
///
/// It names neither this module root nor `writeout`: `lib/sendf.c` includes
/// `transfer.h`, `cw-out.h` and `cw-pause.h`, and all three include `sendf.h`
/// straight back, so the C's include cycle would become a module cycle. What
/// the C reaches through those includes for arrives instead as three narrow
/// seams the dependency-last engine implements -- `TransferControl` for the
/// three operations that belong to the transfer loop, `ClientIoFactory` for the
/// two writer stages `lib/cw-out.c` and `lib/cw-pause.c` own, and `TraceSink`
/// for the five diagnostic emitters. The base writer stack is still assembled
/// HERE, in the exact order of `lib/sendf.c:325-368`, because that order is the
/// contract: the pause stage is installed FIRST and therefore ends up BEHIND
/// the download stage, so a length check happens before any byte is buffered
/// for a paused transfer.
///
/// It reads no clock either. The one instant it needs arrives as an injected
/// [`Clock`], which is what lets the upload rate-limit clamp and the
/// `TIMER_STARTTRANSFER` record be asserted deterministically.
///
/// [`Clock`]: crate::util::timeval::Clock
pub(crate) mod sendf;

/// Per-request state: supersedes `lib/request.c` and `lib/request.h`.
///
/// One `SingleRequest` covers one request attempt -- its counters, its upload
/// send queue, its send and flush path, its pause and blocking predicates, its
/// completion, and the redirect and retry bookkeeping that carries an
/// operation from one attempt to the next.
///
/// It names neither this module root nor a protocol module, and both omissions
/// are structural. `lib/request.c` includes `transfer.h` and `url.h`, which
/// include `request.h` straight back, so the C's include cycle would become a
/// module cycle; and `Curl_http_follow` lives in `lib/http.c`, so a literal
/// transcription would put HTTP inside the request layer. What the C reaches
/// through those includes for arrives instead as two narrow seams the
/// dependency-last engine and the protocol modules implement -- `RequestIo` for
/// the transport, client-chain, resolver, progress and diagnostic operations,
/// and `ProtocolFollow` for the URL, scheme, port and request-method work a
/// redirect needs. The bookkeeping around that work -- the counters, the
/// ceiling, the fake-follow storage, the soft reset and the frozen log lines --
/// stays here, so no protocol module reimplements it.
///
/// It reads no clock. Every instant arrives through `RequestIo::pgrs_now`,
/// which is `Curl_pgrs_now` (`lib/progress.c:171-177`), so the request start
/// time and the `TIMER_POSTRANSFER` record are both assertable against a
/// pinned [`TestClock`].
///
/// [`TestClock`]: crate::util::timeval::TestClock
pub(crate) mod request;

/// The token bucket behind `--limit-rate`: supersedes `lib/ratelimit.c` and
/// `lib/ratelimit.h`.
///
/// Serves `CURLOPT_MAX_RECV_SPEED_LARGE` and `CURLOPT_MAX_SEND_SPEED_LARGE`,
/// which is what the command-line tool sets for `--limit-rate`, and the
/// pause mechanism, which is expressed as a blocked limiter rather than as a
/// separate flag.
///
/// It computes durations and nothing else: no timer is armed here, and no
/// transfer state is touched, so the `PERFORMING` and `RATELIMITING`
/// transitions and the `TOOFAST` expiry identifier belong to the transfer
/// loop that consumes it. The contract between the two is transcribed from
/// `lib/multi.c:1880-1921` into the documentation of the module's `wait_ms`
/// and `next_step_ms`.
pub(crate) mod ratelimit;

/// The client-output and pause-handling writer stages: supersedes
/// `lib/cw-out.c` with `lib/cw-out.h` and `lib/cw-pause.c` with
/// `lib/cw-pause.h`.
///
/// The bottom of the writer chain, and the only module in the crate that
/// invokes `CURLOPT_WRITEFUNCTION` and `CURLOPT_HEADERFUNCTION`. It owns the
/// two stages [`sendf`] deliberately does not name -- `cw-out` at
/// `CURL_CW_CLIENT` and `cw-pause` at `CURL_CW_PROTOCOL`, both reached there
/// through `ClientIoFactory` -- together with the ordered buffering that makes
/// `curl_easy_pause` replay a paused transfer's bytes in their original order,
/// and the `hds-collect` stage that fills the store `curl_easy_header` reads.
///
/// It depends on [`sendf`] and never the other way round, which is what keeps
/// the C's `sendf.h` / `cw-out.h` / `cw-pause.h` include cycle from becoming a
/// module cycle. It does not name this module root either: the one operation it
/// needs from the transfer loop, `Curl_xfer_pause_recv`, arrives through
/// `sendf`'s `TransferControl` seam.
pub(crate) mod writeout;

/// HTTP/1.1 chunked transfer coding, in both directions: supersedes
/// `lib/http_chunks.c` and `lib/http_chunks.h`.
///
/// The receive state machine that de-frames a chunked response body and its
/// trailers, and the encoder that frames a chunked request body -- both
/// byte-exact, because 1,476 of the fixtures under `tests/data/` compare the
/// bytes on the wire as one string and would fail on a size line spelled with
/// a different case or a leading zero. Chunk framing is therefore NOT
/// delegated to hyper, which manages the connection and nothing about these
/// bytes.
///
/// It depends on [`sendf`] for the two chain contracts and on nothing else in
/// this directory, and it names neither [`writeout`] nor a protocol module.
/// The C reaches through `struct Curl_easy` for a downstream writer, a source
/// reader and `CURLOPT_TRAILERFUNCTION`; all three arrive here as narrow seams
/// the consumer implements, which is also what lets the parser be driven from
/// memory, one byte at a time, without a network.
pub(crate) mod chunked;

/// Content and transfer decoding: supersedes `lib/content_encoding.c` and
/// `lib/content_encoding.h`.
///
/// The registry of decoders this build compiled, the `Accept-Encoding` token
/// list that registry produces, and the construction of the unencoding writer
/// stack from a `Content-Encoding` or `Transfer-Encoding` header value. The
/// C's zlib, brotli and zstd calls become `flate2` on its pure-Rust backend,
/// `brotli` and `zstd`; every registry order, separator byte, state machine
/// and refusal point is transcribed rather than reinterpreted.
///
/// It depends on [`sendf`] for the writer contract and on [`chunked`] for the
/// one transfer coding it installs without owning -- `"chunked"`, whose stage
/// arrives through `chunked::transfer_unencoder` -- and it names no protocol
/// module: HTTP/1 assembly CONSUMES this module, both to install the stack
/// from a response header and to emit `Accept-Encoding` with the exact bytes
/// and order `content_encodings` produces.
///
/// Decoding is streamed. Each stage decompresses into a fixed 16 KiB window
/// and forwards what it produced immediately, so a highly compressible body
/// costs a bounded amount of resident memory rather than its expanded size,
/// and a downstream refusal returns that stage's own code unchanged.
pub(crate) mod content_encoding;

// ---------------------------------------------------------------------------
// Constants the C spells with `#define`
// ---------------------------------------------------------------------------

/// `CONN_MAX_RETRIES` (`lib/transfer.c:655`): how many times a connection may
/// die and be retried before the transfer gives up.
///
/// The C defines it INSIDE `Curl_retry_request`, immediately before the only
/// two lines that read it, and the count is reset in exactly one other place:
/// [`Transfer::pretransfer`], once per top-level operation. The comment there
/// explains why -- without the reset a reused handle reaches
/// `CONN_MAX_RETRIES + 1` and refuses to retry at all.
#[allow(dead_code)] // consumers: retry_request here, and crate::multi's traces
pub(crate) const CONN_MAX_RETRIES: i32 = 5;

/// `int maxloops = 10` (`lib/transfer.c:227`): the download loop's budget.
///
/// # This permits ELEVEN passes, not ten
///
/// The C loop is `do { ... } while(maxloops--)`, and a post-decrement in the
/// condition yields the OLD value: the tenth evaluation sees `1` (true, and
/// leaves 0), the eleventh sees `0` (false). So the body runs once before the
/// first test and then ten more times. [`Transfer::sendrecv_dl`] preserves
/// that count exactly -- turning it into ten iterations would change how much
/// of a ready response one call drains, which is observable in the order
/// `sendrecv_dl() no EAGAIN/pending data, mark as dirty` appears in a trace.
#[allow(dead_code)] // consumer: sendrecv_dl here
pub(crate) const MAX_DL_LOOPS: u32 = 10;

/// `CURL_PREREQFUNC_OK` (`include/curl/curl.h:506`): the pre-request callback
/// accepted the transfer.
// consumers: state_do here, and curl-rs-ffi's option surface
#[allow(dead_code)]
pub(crate) const CURL_PREREQFUNC_OK: i32 = 0;

/// `CURL_PREREQFUNC_ABORT` (`include/curl/curl.h:509`): the pre-request
/// callback refused the transfer.
///
/// Read for completeness rather than compared against: `state_do` tests
/// `prereq_rc != CURL_PREREQFUNC_OK` (`lib/multi.c:2080`), so ANY other value
/// aborts, and this constant names the one the header documents.
#[allow(dead_code)] // consumer: curl-rs-ffi's option surface
pub(crate) const CURL_PREREQFUNC_ABORT: i32 = 1;

/// `CURL_HTTP_V1x` (`lib/http.h:50`): the HTTP/1 major version bit.
#[allow(dead_code)] // consumers: HttpNegotiation here, and crate::protocols
pub(crate) const CURL_HTTP_V1X: u8 = 1 << 0;

/// `CURL_HTTP_V2x` (`lib/http.h:51`): the HTTP/2 major version bit.
#[allow(dead_code)] // consumers: HttpNegotiation here, and crate::protocols
pub(crate) const CURL_HTTP_V2X: u8 = 1 << 1;

/// `CURL_HTTP_V3x` (`lib/http.h:52`): the HTTP/3 major version bit.
#[allow(dead_code)] // consumers: HttpNegotiation here, and crate::protocols
pub(crate) const CURL_HTTP_V3X: u8 = 1 << 2;

// ---------------------------------------------------------------------------
// Typed control values: where C's out-parameters and magic integers went
// ---------------------------------------------------------------------------

/// Whether an asynchronous phase finished -- the successor of C's
/// `bool *done`.
///
/// Four `Curl_protocol` members carry a `bool *done` out-parameter
/// (`do_it`, `connect_it`, `connecting` and `doing`, `lib/urldata.h:436-455`),
/// and three multi-handle helpers thread one through as well
/// (`protocol_connect`, `protocol_connecting` and `protocol_doing`,
/// `lib/multi.c:1778-1843`). AAP section 0.1.2 requires every one of them to
/// disappear, so readiness is a RETURNED value here and nothing writes through
/// a caller-supplied pointer.
///
/// [`crate::protocols::Protocol`] expresses the same readiness as a plain
/// `bool` inside its [`crate::protocols::ProtoFuture`]; this type is what the
/// transfer core converts that `bool` into the moment it crosses into the
/// driver, so no state transition is ever decided by an unnamed boolean.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)] // consumers: the driver here, and crate::protocols
pub(crate) enum AsyncStep {
    /// The phase made progress but is not finished: come back to it. The C's
    /// `*done == FALSE`.
    Pending,
    /// The phase is finished. The C's `*done == TRUE`.
    Complete,
}

impl AsyncStep {
    /// Reads a C readiness boolean as a step.
    ///
    /// The one place a `bool` is admitted, and deliberately narrow: it is the
    /// boundary with [`crate::protocols::Protocol`], whose futures resolve to
    /// the `bool` the C wrote through its pointer.
    #[allow(dead_code)] // consumer: the driver here
    pub(crate) const fn from_done(done: bool) -> Self {
        if done {
            Self::Complete
        } else {
            Self::Pending
        }
    }

    /// Whether the phase is finished.
    #[allow(dead_code)] // consumer: the driver here
    pub(crate) const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

impl From<SendShutdown> for AsyncStep {
    /// [`crate::transfer::request`] speaks [`SendShutdown`] for the send
    /// direction's graceful close; the two vocabularies are the same two
    /// outcomes and convert without a decision.
    fn from(shutdown: SendShutdown) -> Self {
        if shutdown.is_complete() {
            Self::Complete
        } else {
            Self::Pending
        }
    }
}

/// What the second half of a two-part DO decided -- the successor of
/// `multi_do_more`'s `int *complete`.
///
/// The C documents the integer above the function: *"'complete' can return 0
/// for incomplete, 1 for done and -1 for go back to DOING state there is more
/// work to do!"* (`lib/multi.c:1699-1700`). Three magic integers, two of which
/// select a state, and `state_do`'s reader spells the selection
/// `control == 1 ? MSTATE_DID : MSTATE_DOING` after testing `if(control)`
/// (`lib/multi.c:2627-2632`) -- so `0` is "stay" and every non-zero value is a
/// transition. The three become three variants, and the mapping is stated on
/// each so a reader of the C can follow it back.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)] // consumers: the driver here, and crate::protocols's ftp
pub(crate) enum DoMoreStep {
    /// The C's `0`: not finished, stay in `DOING_MORE`.
    Pending,
    /// The C's `1`: finished, advance to `DID`.
    Advance,
    /// The C's `-1`: go back to `DOING`, there is more to do first.
    Retry,
}

impl DoMoreStep {
    /// Reads the C's `int *complete` as a step.
    ///
    /// Present because FTP's `ftp_do_more` writes the integer directly
    /// (`lib/ftp.c`), and because a test asserting the C's three values needs
    /// somewhere to state them once.
    #[allow(dead_code)] // consumer: crate::protocols's ftp
    pub(crate) const fn from_complete(complete: i32) -> Self {
        if complete == 0 {
            Self::Pending
        } else if complete > 0 {
            Self::Advance
        } else {
            Self::Retry
        }
    }

    /// The C integer this step corresponds to: `0`, `1` or `-1`.
    #[allow(dead_code)] // consumer: crate::protocols's ftp
    pub(crate) const fn as_complete(self) -> i32 {
        match self {
            Self::Pending => 0,
            Self::Advance => 1,
            Self::Retry => -1,
        }
    }
}

/// Whether the driver should run the state machine again at once -- the
/// successor of `CURLM_CALL_MULTI_PERFORM`.
///
/// `multi_runsingle` loops `while((mresult == CURLM_CALL_MULTI_PERFORM) ||
/// multi_ischanged(multi, FALSE))` (`lib/multi.c:2740-2741`), and every
/// transitional state sets that code so the next state runs without waiting
/// for the caller to come back. Keeping it as a [`CURLMcode`] would mean
/// mixing a control signal into an error channel, which is exactly how the C's
/// callers came to have to remember that one negative code is not a failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)] // consumers: the driver here, and crate::multi
pub(crate) enum DriverStep {
    /// Run the state machine again immediately: the transition was in-memory
    /// and the next state can make progress now.
    RunAgain,
    /// Nothing more can be done until I/O, a timer or the multi handle wakes
    /// this transfer. The C's `CURLM_OK`.
    Pending,
}

impl DriverStep {
    /// Whether the driver loop should iterate again.
    #[allow(dead_code)] // consumers: the driver here, and crate::multi
    pub(crate) const fn runs_again(self) -> bool {
        matches!(self, Self::RunAgain)
    }

    /// The [`CURLMcode`] the C returns for this step.
    ///
    /// For the ABI shim and for a test that wants to compare against the C's
    /// own value; the driver itself never converts.
    #[allow(dead_code)] // consumer: crate::multi
    pub(crate) const fn as_multi_code(self) -> CURLMcode {
        match self {
            Self::RunAgain => CURLMcode::CallMultiPerform,
            Self::Pending => CURLMcode::Ok,
        }
    }
}

/// What one turn of the driver leaves for the multi handle to do.
///
/// `multi_runsingle` communicates three different things through two channels:
/// its [`CURLMcode`] return, the `data->result` field it writes, and the
/// `handle_completed` call it makes internally (`lib/multi.c:2736-2739`). The
/// third is the multi handle's OWN bookkeeping -- build a `CURLMsg`, move the
/// transfer between the four membership sets, decrement `xfers_alive` -- and
/// AAP section 0.4.1 puts that in `crate::multi`. So the driver reports
/// completion instead of performing it, and [`Self::Completed`] carries exactly
/// what `handle_completed` needs: the transfer's final [`CURLcode`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)] // consumer: crate::multi
pub(crate) enum RunSingle {
    /// The state machine has more in-memory work: call again at once. The C's
    /// `CURLM_CALL_MULTI_PERFORM`.
    RunAgain,
    /// The transfer is parked -- on I/O readiness, on a timer, or in
    /// `PENDING` waiting for a connection. The C's `CURLM_OK`.
    Pending,
    /// `MSTATE_COMPLETED` was reached. The multi handle queues `CURLMSG_DONE`
    /// with this code, moves the transfer to its `msgsent` set and decrements
    /// the alive count.
    Completed(CURLcode),
}

impl RunSingle {
    /// The driver step this outcome implies.
    ///
    /// [`Self::Completed`] is [`DriverStep::Pending`]: the C returns
    /// `CURLM_OK` from `handle_completed`'s branch (`lib/multi.c:2738`) and
    /// does not loop again, because a completed transfer has nothing left to
    /// run.
    #[allow(dead_code)] // consumer: crate::multi
    pub(crate) const fn step(self) -> DriverStep {
        match self {
            Self::RunAgain => DriverStep::RunAgain,
            Self::Pending | Self::Completed(_) => DriverStep::Pending,
        }
    }

    /// The final code, when this outcome is a completion.
    #[allow(dead_code)] // consumer: crate::multi
    pub(crate) const fn completion(self) -> Option<CURLcode> {
        match self {
            Self::Completed(code) => Some(code),
            Self::RunAgain | Self::Pending => None,
        }
    }
}

/// Which of a connection's two channels a direction of the transfer uses --
/// the successor of `conn->send_idx` and `conn->recv_idx`.
///
/// The C stores raw `int` socket indexes and admits exactly three values:
/// `-1` for "this direction is not in use", `0` for `FIRSTSOCKET` and `1` for
/// `SECONDARYSOCKET`. `xfer_setup` asserts the range twice
/// (`lib/transfer.c:691-692`) and `CONN_SOCK_IDX_VALID(i)` -- `((i) >= 0) &&
/// ((i) < 2)` (`lib/urldata.h:648`) -- is what `MSTATE_DID` tests before
/// deciding whether there is anything to transfer at all
/// (`lib/multi.c:2652-2653`).
///
/// Three admissible values in an `int` is a type, so this is one: the
/// assertions become unrepresentable states, and [`Self::channel`] hands back
/// the [`SocketIndex`] `crate::conn` speaks rather than an integer a caller
/// must remember the meaning of. The C's integers survive as
/// [`Self::as_i32`] and [`Self::from_i32`], because they cross the ABI in
/// `CURLINFO_ACTIVESOCKET` and appear in the `xfer_setup` trace line.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
// consumers: the driver here, crate::protocols, crate::multi
#[allow(dead_code)]
pub(crate) enum ChannelIndex {
    /// The C's `-1`: this direction of the transfer is not in use.
    #[default]
    None,
    /// The C's `FIRSTSOCKET`, 0 (`lib/urldata.h:646`).
    First,
    /// The C's `SECONDARYSOCKET`, 1 (`lib/urldata.h:647`) -- an FTP data
    /// connection, and nothing else among the in-scope schemes.
    Secondary,
}

impl ChannelIndex {
    /// The C integer: `-1`, `0` or `1`.
    #[allow(dead_code)] // consumers: the trace lines here, and crate::multi
    pub(crate) const fn as_i32(self) -> i32 {
        match self {
            Self::None => -1,
            Self::First => 0,
            Self::Secondary => 1,
        }
    }

    /// Reads a C socket index, rejecting anything outside `-1..=1`.
    ///
    /// The two `DEBUGASSERT`s of `xfer_setup` (`lib/transfer.c:691-692`) as a
    /// total function: a debug assertion aborts a debug build and is compiled
    /// out of a release one, whereas this reports the refusal in both.
    #[allow(dead_code)] // consumer: crate::protocols and the ABI shim
    pub(crate) const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            -1 => Some(Self::None),
            0 => Some(Self::First),
            1 => Some(Self::Secondary),
            _ => None,
        }
    }

    /// The connection channel this index names, or [`None`] when the direction
    /// is unused.
    #[allow(dead_code)] // consumer: the driver here
    pub(crate) const fn channel(self) -> Option<SocketIndex> {
        match self {
            Self::None => None,
            Self::First => Some(SocketIndex::First),
            Self::Secondary => Some(SocketIndex::Secondary),
        }
    }

    /// The index of `channel`.
    #[allow(dead_code)] // consumer: crate::protocols
    pub(crate) const fn of(channel: SocketIndex) -> Self {
        match channel {
            SocketIndex::First => Self::First,
            SocketIndex::Secondary => Self::Secondary,
        }
    }

    /// `CONN_SOCK_IDX_VALID(i)` (`lib/urldata.h:648`): whether this index
    /// names a channel.
    #[allow(dead_code)] // consumer: state_did here
    pub(crate) const fn is_valid(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// What `Curl_connect` decided -- the successor of its two out-parameters and
/// its one sentinel error.
///
/// `Curl_connect(data, &async, &connected)` reports FOUR outcomes through
/// three channels, and `state_connect` reads all three
/// (`lib/multi.c:2275-2324`): the return code, which may be the sentinel
/// `CURLE_NO_CONNECTION_AVAILABLE`; `async`, which says a name lookup is now
/// in flight; and `connected`, which says the transport is already up. The
/// four become four variants, so no caller can forget to test one of them --
/// and the sentinel stops being an error, because a transfer parked for want
/// of a connection has not failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)] // consumers: the driver here, and crate::conn
pub(crate) enum ConnectOutcome {
    /// `CURLE_NO_CONNECTION_AVAILABLE`: the pool is at its limit. The transfer
    /// goes to `PENDING` and waits.
    NoConnectionAvailable,
    /// `async == TRUE`: a name lookup is in flight. The transfer goes to
    /// `RESOLVING`.
    Resolving,
    /// `connected == TRUE`: the transport is up. The transfer goes to
    /// `PROTOCONNECT`.
    Connected,
    /// Neither: a connect is in flight. The transfer goes to `CONNECTING`.
    Connecting,
}

/// What the injected resolver reported -- the successor of `Curl_resolv_check`'s
/// `struct Curl_dns_entry **dns` out-parameter.
///
/// `state_resolving` tests the pointer rather than the code
/// (`lib/multi.c:2246`), and traces which of the two it got:
/// `Curl_resolv_check() -> %d, %s` with `dns ? "found" : "missing"`
/// (`:2235-2236`). The entry itself belongs to `crate::dns` and never reaches
/// this file: the transfer core needs to know only whether the name is
/// resolved, because everything it would do with the entry --
/// `Curl_once_resolved` -- is [`TransferIo::once_resolved`]'s to do.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)] // consumers: the driver here, and crate::dns
pub(crate) enum ResolveStep {
    /// The C's `dns == NULL`: still resolving.
    Pending,
    /// The C's `dns != NULL`: the name is resolved.
    Resolved,
}

// ---------------------------------------------------------------------------
// The vocabulary `data->set` and `data->state` keep in plain integers
// ---------------------------------------------------------------------------

/// `CURLOPT_TIMECONDITION`'s value -- the four `CURL_TIMECOND_*` integers
/// (`include/curl/curl.h:2407-2416`).
///
/// The discriminants are pinned because they are public ABI: a C program
/// compiled against curl 8.19.0-DEV holds them in its instruction stream.
/// `CURL_TIMECOND_LAST = 4` is a bound rather than a condition and has no
/// variant, exactly as `crate::error`'s sentinels have none.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: meets_timecondition here, and the ABI shim
pub(crate) enum TimeCondition {
    /// `CURL_TIMECOND_NONE` = 0: no condition. The default.
    #[default]
    None = 0,
    /// `CURL_TIMECOND_IFMODSINCE` = 1: fetch only if newer than the value.
    ///
    /// Also the behaviour of every unrecognised value, because the C's
    /// `switch` writes `case CURL_TIMECOND_IFMODSINCE: default:`
    /// (`lib/transfer.c:126-127`) -- the two labels share one arm.
    IfModSince = 1,
    /// `CURL_TIMECOND_IFUNMODSINCE` = 2: fetch only if older than the value.
    IfUnmodSince = 2,
    /// `CURL_TIMECOND_LASTMOD` = 3: `--time-cond` with a file, which the tool
    /// turns into one of the two above before it reaches the library.
    LastMod = 3,
}

impl TimeCondition {
    /// The ABI integer.
    #[allow(dead_code)] // consumer: the ABI shim
    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }

    /// Reads a `CURLOPT_TIMECONDITION` value.
    ///
    /// Anything outside `0..=3` is [`Self::IfModSince`], which is what the C's
    /// shared `default:` label makes of it (`lib/transfer.c:126-127`) -- so a
    /// caller cannot obtain a condition the comparison below does not handle.
    #[allow(dead_code)] // consumer: the ABI shim
    pub(crate) const fn from_i64(raw: i64) -> Self {
        match raw {
            0 => Self::None,
            2 => Self::IfUnmodSince,
            3 => Self::LastMod,
            _ => Self::IfModSince,
        }
    }
}

/// Which HTTP major versions this transfer wants and will accept --
/// the two `http_majors` masks of `struct http_negotiation`
/// (`lib/http.h:63-72`).
///
/// Only the two fields the transfer core writes are here. The other six --
/// `rcvd_min`, `preferred`, `h2_upgrade`, `h2_prior_knowledge`, `accept_09`
/// and `only_10` -- belong to the HTTP module, which decides them; this file
/// touches `wanted` and `allowed` in exactly one place, the HTTP/2 downgrade
/// of `state_performing` (`lib/multi.c:1966-1967`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: state_performing here, and crate::protocols
pub(crate) struct HttpNegotiation {
    /// `neg->wanted`: the major versions to offer the server.
    pub(crate) wanted: u8,
    /// `neg->allowed`: the major versions to accept from it.
    pub(crate) allowed: u8,
}

impl Default for HttpNegotiation {
    /// `Curl_http_neg_init`'s `CURL_HTTP_VERSION_NONE` arm
    /// (`lib/http.c:118-122`): offer 1 and 2, accept 1, 2 and 3.
    fn default() -> Self {
        Self {
            wanted: CURL_HTTP_V1X | CURL_HTTP_V2X,
            allowed: CURL_HTTP_V1X | CURL_HTTP_V2X | CURL_HTTP_V3X,
        }
    }
}

impl HttpNegotiation {
    /// Both masks forced to HTTP/1 -- the downgrade `state_performing` performs
    /// after an `HTTP_1_1_REQUIRED` stream error (`lib/multi.c:1966-1967`).
    #[allow(dead_code)] // consumer: state_performing here
    pub(crate) fn force_http1(&mut self) {
        self.wanted = CURL_HTTP_V1X;
        self.allowed = CURL_HTTP_V1X;
    }
}

/// One authentication target's method masks -- the `want` and `picked` members
/// of `struct auth` (`lib/urldata.h:849-853`).
///
/// `avail`, `done`, `multipass` and `iestyle` are the authentication module's
/// and are not here: `Curl_pretransfer` touches only these two
/// (`lib/transfer.c:500-501` and `:550-551`), and this file exists to preserve
/// what it touches.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: pretransfer here, and crate::auth
pub(crate) struct AuthPick {
    /// `auth.want`: the methods the application asked for, through
    /// `CURLOPT_HTTPAUTH` or `CURLOPT_PROXYAUTH`.
    pub(crate) want: u32,
    /// `auth.picked`: the method actually in use.
    pub(crate) picked: u32,
}

impl AuthPick {
    /// `data->state.authhost.picked &= data->state.authhost.want`
    /// (`lib/transfer.c:550`).
    ///
    /// The C's comment states the reason: *"In case the handle is reused and an
    /// authentication method was picked in the session we need to make sure we
    /// only use the one(s) we now consider to be fine"*. A handle that
    /// negotiated NTLM and is then restricted to Basic must not keep NTLM.
    #[allow(dead_code)] // consumer: pretransfer here
    pub(crate) fn intersect_picked_with_want(&mut self) {
        self.picked &= self.want;
    }
}

/// How far an FTP wildcard operation has got -- `CURLWC_*`
/// (`lib/ftplistparser.h:43-54`).
///
/// The C's declaration order, with `CURLWC_CLEAR` at 0 and `CURLWC_INIT` at 1
/// written out because `Curl_pretransfer` compares against the second with
/// `if(wc->state < CURLWC_INIT)` (`lib/transfer.c:563`) -- an ordering test,
/// which is why the type derives [`Ord`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumers: the driver here, and crate::protocols's ftp
pub(crate) enum WildcardStage {
    /// `CURLWC_CLEAR` = 0: nothing allocated yet.
    #[default]
    Clear = 0,
    /// `CURLWC_INIT` = 1: the pattern and path are set up.
    Init = 1,
    /// `CURLWC_MATCHING`: the library is fetching the directory listing.
    Matching = 2,
    /// `CURLWC_DOWNLOADING`: one matched file is being transferred.
    Downloading = 3,
    /// `CURLWC_CLEAN`: release resources and reset settings.
    Clean = 4,
    /// `CURLWC_SKIP`: skip over this concrete file.
    Skip = 5,
    /// `CURLWC_ERROR`: the operation failed.
    Error = 6,
    /// `CURLWC_DONE`: the wildcard loop is over.
    Done = 7,
}

/// Where this transfer's credentials came from -- the four `CREDS_*` integers
/// (`lib/urldata.h:934-937`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: pretransfer here, crate::auth, crate::url
pub(crate) enum CredsSource {
    /// `CREDS_NONE` = 0.
    #[default]
    None = 0,
    /// `CREDS_URL` = 1: parsed out of the URL's userinfo.
    Url = 1,
    /// `CREDS_OPTION` = 2: set with `CURLOPT_USERNAME` or `CURLOPT_PASSWORD`.
    Option = 2,
    /// `CREDS_NETRC` = 3: found in `.netrc`.
    Netrc = 3,
}

// ---------------------------------------------------------------------------
// `data->set`, `data->info` and `data->state`, narrowed to what this file uses
// ---------------------------------------------------------------------------

/// The `data->set` members the transfer core reads.
///
/// `struct UserDefined` (`lib/urldata.h:1330-1620`) carries more than 200
/// fields and every C function in `lib/transfer.c` reaches into it through
/// `data`. This is that reach made explicit and narrowed to the members
/// `Curl_pretransfer`, `Curl_xfer_recv`, `Curl_retry_request`,
/// `Curl_meets_timecondition`, `Curl_checkheaders` and the state machine
/// actually read -- enumerable by a reader, and settable by a test without a
/// two-hundred-field initialiser.
///
/// Nothing here is written by this file: the transfer core reads settings and
/// writes [`TransferState`], which is the C's own division between `data->set`
/// and `data->state`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumers: the driver here, crate::easy, crate::multi
pub(crate) struct TransferSettings {
    /// `data->set.str[STRING_SET_URL]`, from `CURLOPT_URL`.
    pub(crate) url: Option<String>,

    /// Whether `data->set.uh` is set, from `CURLOPT_CURLU`.
    ///
    /// The HANDLE is not here -- it belongs to `crate::url` -- because
    /// `Curl_pretransfer` does exactly two things with it: test it for
    /// presence, and ask it for a URL. The second is
    /// [`TransferIo::url_from_handle`].
    pub(crate) has_url_handle: bool,

    /// `data->set.postfields`, from `CURLOPT_POSTFIELDS`: the in-memory
    /// request body.
    ///
    /// Owned bytes rather than a pointer, and bytes rather than a `String`,
    /// because `CURLOPT_POSTFIELDS` admits arbitrary binary content whenever
    /// `CURLOPT_POSTFIELDSIZE` is set.
    pub(crate) postfields: Option<Vec<u8>>,

    /// `data->set.postfieldsize`, from `CURLOPT_POSTFIELDSIZE`. -1 means
    /// "measure the bytes", which is what the derivation in
    /// [`Transfer::pretransfer`] does.
    pub(crate) postfieldsize: i64,

    /// `data->set.set_resume_from`, from `CURLOPT_RESUME_FROM`: whether a
    /// resume offset was given at all.
    pub(crate) set_resume_from: bool,

    /// `data->set.filesize`, from `CURLOPT_INFILESIZE`.
    pub(crate) filesize: i64,

    /// `data->set.method`, from `CURLOPT_HTTPGET`, `CURLOPT_UPLOAD`,
    /// `CURLOPT_POST` and their relations.
    pub(crate) method: HttpRequestKind,

    /// `data->set.prefer_ascii`, from `CURLOPT_TRANSFERTEXT`.
    pub(crate) prefer_ascii: bool,

    /// `data->set.list_only`, from `CURLOPT_DIRLISTONLY`.
    ///
    /// The C guards the copy with `#ifdef CURL_LIST_ONLY_PROTOCOL`
    /// (`lib/transfer.c:487-489`), which is defined when FTP, POP3 or another
    /// list-capable scheme is compiled in. Here the field is unconditional and
    /// the COPY is feature-gated, so a build without `ftp` still round-trips
    /// the option through `curl_easy_setopt` unchanged.
    pub(crate) list_only: bool,

    /// `data->set.httpauth`, from `CURLOPT_HTTPAUTH`.
    pub(crate) httpauth: u32,

    /// `data->set.proxyauth`, from `CURLOPT_PROXYAUTH`.
    pub(crate) proxyauth: u32,

    /// `data->set.str[STRING_USERAGENT]`, from `CURLOPT_USERAGENT`.
    pub(crate) useragent: Option<String>,

    /// `data->set.str[STRING_USERNAME]`, from `CURLOPT_USERNAME`.
    pub(crate) username: Option<String>,

    /// `data->set.str[STRING_PASSWORD]`, from `CURLOPT_PASSWORD`.
    pub(crate) password: Option<String>,

    /// `data->set.str[STRING_PROXYUSERNAME]`, from `CURLOPT_PROXYUSERNAME`.
    pub(crate) proxyusername: Option<String>,

    /// `data->set.str[STRING_PROXYPASSWORD]`, from `CURLOPT_PROXYPASSWORD`.
    pub(crate) proxypassword: Option<String>,

    /// `data->set.timeout`, from `CURLOPT_TIMEOUT`, in milliseconds. Zero
    /// means no overall deadline, which is why `MSTATE_SETUP` arms the timer
    /// only when it is non-zero (`lib/multi.c:2505-2506`).
    pub(crate) timeout_ms: TimeDiff,

    /// `data->set.connecttimeout`, from `CURLOPT_CONNECTTIMEOUT`, in
    /// milliseconds. Zero means no connect deadline.
    pub(crate) connecttimeout_ms: TimeDiff,

    /// `data->set.buffer_size`, from `CURLOPT_BUFFERSIZE`: the ceiling
    /// [`Transfer::xfer_recv`] clamps every receive to
    /// (`lib/transfer.c:860-861`).
    pub(crate) buffer_size: usize,

    /// `data->set.timecondition`, from `CURLOPT_TIMECONDITION`.
    pub(crate) timecondition: TimeCondition,

    /// `data->set.timevalue`, from `CURLOPT_TIMEVALUE`, in Unix seconds. Zero
    /// disables the condition.
    pub(crate) timevalue: i64,

    /// `data->set.wildcard_enabled`, from `CURLOPT_WILDCARDMATCH`.
    pub(crate) wildcard_enabled: bool,

    /// `data->set.connect_only`, from `CURLOPT_CONNECT_ONLY`.
    pub(crate) connect_only: bool,

    /// `data->set.connect_only_ws`: `CURLOPT_CONNECT_ONLY` set to 2, which a
    /// WebSocket transfer uses to keep running after the handshake.
    pub(crate) connect_only_ws: bool,

    /// `data->set.headers`, from `CURLOPT_HTTPHEADER`: the application's
    /// custom request headers, in insertion order.
    ///
    /// A `Vec<String>` rather than a `curl_slist`: the list keeps its C shape
    /// only at the ABI boundary, per AAP section 0.6.9, and [`checkheaders`]
    /// needs nothing but ordered iteration.
    pub(crate) headers: Vec<String>,

    /// `data->set.rtspreq == RTSPREQ_RECEIVE`, from `CURLOPT_RTSP_REQUEST`.
    ///
    /// Read in exactly one place -- the retry decision
    /// (`lib/transfer.c:632`), where an RTSP RECEIVE must not be retried
    /// because it is a server-driven interleaved stream rather than a request.
    /// A bare `bool` because that comparison is all the transfer core does
    /// with the option; RTSP is out of implementation scope per AAP section
    /// 0.2.2, and the field keeps the retry rule intact for the day it is not.
    pub(crate) rtsp_receive: bool,

    /// `data->set.no_signal`, from `CURLOPT_NOSIGNAL`.
    ///
    /// Carried and NOT acted on. The C uses it to decide whether to install a
    /// `SIGPIPE` handler around a transfer (`lib/transfer.c:535-541` and
    /// `lib/multi.c:1855-1861`), and AAP section 0.4.1 removes that mechanism:
    /// `crate::conn`'s transport writes with `MSG_NOSIGNAL` semantics on every
    /// platform in the four-target matrix, so nothing here has a signal
    /// disposition to save or restore. The option still round-trips, which is
    /// what preserving the `no_signal` semantics externally requires.
    pub(crate) no_signal: bool,
}

/// The `data->info` members the transfer core WRITES.
///
/// `struct PureInfo` (`lib/urldata.h:735-790`) is `curl_easy_getinfo`'s
/// backing store and belongs to `curl-rs-lib/src/easy/getinfo.rs`. Two of its
/// members are written from the files this module supersedes and nowhere else,
/// so they live here and that file reads them:
///
/// | member | written by | read by |
/// |---|---|---|
/// | `info.timecond` | `Curl_meets_timecondition` (`lib/transfer.c:130`, `:137`) | `CURLINFO_CONDITION_UNMET` |
/// | `info.request_size` | `Curl_xfer_send` (`lib/transfer.c:845`) | `CURLINFO_REQUEST_SIZE` |
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: the driver here, and easy/getinfo.rs
pub(crate) struct TransferInfo {
    /// `data->info.timecond`: the time condition was not met, so no transfer
    /// happened. `CURLINFO_CONDITION_UNMET` reports it.
    pub(crate) timecond: bool,

    /// `data->info.request_size`: how many request bytes reached the
    /// connection, headers included. `CURLINFO_REQUEST_SIZE` reports it.
    ///
    /// Accumulated ONLY by bytes actually written -- see
    /// [`Transfer::xfer_send`], which adds nothing when the transport blocks.
    pub(crate) request_size: i64,
}

/// The `data->state` members the transfer core owns for one OPERATION.
///
/// `struct UrlState` (`lib/urldata.h:939-1110`) is the mutable half of the
/// god-struct: state that outlives a single request attempt but not the
/// operation. The division matters and is the C's:
///
/// * [`SingleRequest`] is reset between attempts -- a redirect clears it;
/// * this is reset by [`Transfer::pretransfer`], ONCE per operation, so a
///   redirect keeps the retry count, the redirect count and the request count.
///
/// Getting that boundary wrong is not cosmetic. `state.retrycount` reset per
/// attempt would make [`CONN_MAX_RETRIES`] unreachable, and
/// [`FollowState::followlocation`] reset per attempt would make
/// `CURLOPT_MAXREDIRS` unreachable and a redirect loop endless.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumers: the driver here, crate::multi, crate::easy
pub(crate) struct TransferState {
    /// `data->state.retrycount` (`lib/urldata.h:1000`): how many times this
    /// operation has retried a dead connection.
    ///
    /// Reset in exactly two places, both transcribed:
    /// [`Transfer::pretransfer`] (`lib/transfer.c:457`) and the exhaustion
    /// branch of [`Transfer::retry_request`] (`:659`).
    pub(crate) retrycount: i32,

    /// `data->state.url` (`lib/urldata.h:951`), a `bufref` in the C: the URL
    /// this attempt is using.
    ///
    /// [`Transfer::retry_request`] duplicates it for the retry, and the HTTP/2
    /// downgrade duplicates it when the retry check produced no target
    /// (`lib/multi.c:1972`).
    pub(crate) url: Option<String>,

    /// `data->state.infilesize` (`lib/urldata.h:958`): how many bytes the
    /// upload will send, or -1 when that is not known.
    ///
    /// Derived once per operation by [`Transfer::pretransfer`]; the derivation
    /// is three cases and is transcribed there.
    pub(crate) infilesize: i64,

    /// `data->state.httpreq` (`lib/urldata.h:1082`): the request method in
    /// flight, which a redirect may change.
    pub(crate) httpreq: HttpRequestKind,

    /// `data->state.upload` (`lib/urldata.h:1094`): this transfer is an
    /// upload.
    ///
    /// `Curl_init_CONNECT` derives it from the method
    /// (`lib/transfer.c:439`), which is why it is set on every entry to
    /// `CONNECT` rather than once in pretransfer -- a redirect that turns a
    /// PUT into a GET must clear it.
    pub(crate) upload: bool,

    /// `data->state.prefer_ascii` (`lib/urldata.h:1089`): FTP ASCII mode.
    pub(crate) prefer_ascii: bool,

    /// `data->state.list_only` (`lib/urldata.h:1090`): FTP directory listing
    /// only.
    pub(crate) list_only: bool,

    /// `data->state.errorbuf` (`lib/urldata.h:1092`): a message has already
    /// been written to `CURLOPT_ERRORBUFFER`, so a later, vaguer one must not
    /// overwrite it.
    ///
    /// Cleared by pretransfer (`lib/transfer.c:495`) and, deliberately, by the
    /// HTTP/2 downgrade, whose comment is *"clear the error message bit too as
    /// we ignore the one we got"* (`lib/multi.c:1968-1969`).
    pub(crate) errorbuf: bool,

    /// `data->state.authproblem` (`lib/urldata.h:1093`): authentication could
    /// not be completed.
    pub(crate) authproblem: bool,

    /// `data->state.authhost` (`lib/urldata.h:1010`): the origin server's
    /// authentication masks.
    pub(crate) authhost: AuthPick,

    /// `data->state.authproxy` (`lib/urldata.h:1011`): the proxy's.
    pub(crate) authproxy: AuthPick,

    /// `data->state.refused_stream` (`lib/urldata.h:1103`): an HTTP/2
    /// `REFUSED_STREAM` arrived, so the request may safely be reissued.
    ///
    /// Cleared by [`Transfer::retry_request`] the moment it acts on it
    /// (`lib/transfer.c:651`).
    pub(crate) refused_stream: bool,

    /// `data->state.http_neg` (`lib/urldata.h:1069`): the HTTP version masks.
    pub(crate) http_neg: HttpNegotiation,

    /// `data->state.done` (`lib/urldata.h:1098`): [`Transfer::complete`] has
    /// already run for this attempt.
    ///
    /// The whole of `multi_done`'s idempotence (`lib/multi.c:679-681`).
    pub(crate) done: bool,

    /// `data->state.wildcardmatch` (`lib/urldata.h:1088`): this operation is
    /// an FTP wildcard match.
    pub(crate) wildcardmatch: bool,

    /// `data->wildcard->state` (`lib/urldata.h:1146`): how far that match has
    /// got.
    pub(crate) wildcard: WildcardStage,

    /// `data->state.aptr.uagent` (`lib/urldata.h:924`): the prepared
    /// `User-Agent:` header LINE, terminator included.
    ///
    /// Stored assembled rather than as the bare value, because that is what
    /// the C stores and what the HTTP layer splices into the request without
    /// re-formatting: `curl_maprintf("User-Agent: %s\r\n", ...)`
    /// (`lib/transfer.c:583`). Reassembling it downstream would put the bytes
    /// of a frozen wire header in two places.
    pub(crate) uagent: Option<String>,

    /// `data->state.aptr.user` (`lib/urldata.h:915`).
    pub(crate) aptr_user: Option<String>,

    /// `data->state.aptr.passwd` (`lib/urldata.h:916`).
    pub(crate) aptr_passwd: Option<String>,

    /// `data->state.aptr.proxyuser` (`lib/urldata.h:917`).
    pub(crate) aptr_proxyuser: Option<String>,

    /// `data->state.aptr.proxypasswd` (`lib/urldata.h:918`).
    pub(crate) aptr_proxypasswd: Option<String>,

    /// `data->state.creds_from` (`lib/urldata.h:1085`): where the credentials
    /// in use came from.
    pub(crate) creds_from: CredsSource,

    /// The redirect and retry bookkeeping, owned by
    /// [`crate::transfer::request`].
    ///
    /// Held here rather than in [`SingleRequest`] for the reason this struct's
    /// documentation gives: it must survive an attempt.
    pub(crate) follow: FollowState,

    /// `data->state.recent_conn_id` (`lib/urldata.h:944-945`): the most recent
    /// connection used, which *"might no longer exist"*.
    ///
    /// Written from [`ConnectionOutcome`] when a transfer completes, and read
    /// by `CURLINFO_CONN_ID`.
    pub(crate) recent_conn_id: Option<i64>,

    /// `data->state.lastconnect_id` (`lib/urldata.h:943`): the last
    /// connection, the C's `-1` spelled [`None`].
    ///
    /// [`None`] when the connection was destroyed rather than kept, which is
    /// what `CURLINFO_LASTSOCKET` reports as unusable.
    pub(crate) lastconnect_id: Option<i64>,
}

impl TransferState {
    /// The state a fresh transfer starts in.
    ///
    /// Not [`Default`], because two fields have non-zero virgin values:
    /// `infilesize` is -1 (unknown, not empty) and
    /// [`FollowState::allow_port`] is true. `Default` is derived as well, so
    /// that a test can start from all-zeroes deliberately, but production
    /// paths use this.
    #[allow(dead_code)] // consumer: Transfer::new here
    pub(crate) fn new() -> Self {
        Self {
            infilesize: -1,
            follow: FollowState {
                allow_port: true,
                ..FollowState::default()
            },
            ..Self::default()
        }
    }

    /// `Curl_init_CONNECT` (`lib/transfer.c:435-440`): the per-`CONNECT`
    /// initialiser the C wires into `mstate`'s `finit[]` table
    /// (`lib/multi.c:141`).
    ///
    /// Two of the C's three assignments bind the application's read callback
    /// and its opaque pointer into `data->state`, which
    /// [`crate::transfer::sendf`]'s reader chain owns here; they arrive
    /// through [`TransferIo::bind_upload_source`]. The third is this, and it
    /// runs on EVERY entry to `CONNECT` -- once per redirect, not once per
    /// operation -- because a redirect that rewrites a PUT as a GET must stop
    /// the transfer being an upload.
    #[allow(dead_code)] // consumer: Transfer::set_mstate here
    pub(crate) fn init_connect(&mut self) {
        self.upload = matches!(self.httpreq, HttpRequestKind::Put);
    }
}

// ---------------------------------------------------------------------------
// The two seams: what the transfer core asks of its owner
// ---------------------------------------------------------------------------

/// A boxed future the transfer core awaits, resolving to a [`CodeResult`].
///
/// The same shape as [`crate::protocols::ProtoFuture`] and for the same
/// reason: the seams below are reached as `&mut dyn` trait objects, and a trait
/// with an `async fn` is not object-safe on any Rust version -- `async fn` in
/// traits became available in 1.75, the declared minimum, but only for
/// statically dispatched calls. Boxing is what buys dynamic dispatch, which is
/// what keeps the engine independent of who owns the connection.
///
/// `Send` is required for the reason AAP section 0.8.3 gives: the multi handle
/// drives transfers on a multi-thread runtime, so a future held across an await
/// on a task must be `Send`.
pub(crate) type XferFuture<'a, T> = core::pin::Pin<
    Box<dyn core::future::Future<Output = CodeResult<T>> + Send + 'a>,
>;

/// The multi handle's own machinery, as the transfer core needs it.
///
/// Everything here is a decision the multi handle OWNS and the transfer core
/// only triggers: the expiry tree, the three membership sets, the shared
/// transfer buffer and the completion notification. AAP section 0.4.1 puts
/// `lib/multi.c`'s collection mechanics in `crate::multi`, so this is the seam
/// across that line, and it is narrow on purpose -- ten operations, each one a
/// named C function.
///
/// It is a SEPARATE trait from [`TransferIo`] rather than more methods on it
/// because the two have different owners: a transfer driven through the easy
/// interface has a connection but only a degenerate multi handle, and the split
/// lets that case implement the scheduler as the C's `easy.c` does -- with a
/// private multi handle of one transfer -- without the connection seam knowing.
pub(crate) trait TransferScheduler: fmt::Debug {
    /// `Curl_expire(data, timeout_ms, id)`: arm `id` to fire in `timeout_ms`
    /// milliseconds.
    ///
    /// The timer identifiers are [`crate::trace::TimerId`], imported here as
    /// `ExpireId` because [`crate::transfer::progress`] has a `TimerId` of its
    /// own for the `TIMER_*` accounting labels and the two are different
    /// vocabularies. This file arms five: `TIMEOUT` and `CONNECTTIMEOUT` in
    /// `SETUP`, `TOOFAST` from the rate-limit check, `SPEEDCHECK` from the
    /// progress check, and `SHUTDOWN` while a graceful close is in flight.
    ///
    /// A sixth, `100_TIMEOUT`, reaches the same seam from the same transfer but
    /// not from this file. The C arms it in the `Expect: 100-continue` client
    /// READER -- `Curl_expire(data, data->set.expect_100_timeout,
    /// EXPIRE_100_TIMEOUT)` (`lib/http.c:1487`) -- and disarms it there too
    /// (`lib/http.c:1459` and `:1519`); `lib/transfer.c` and `lib/request.c`
    /// contain no `Curl_expire` call at all. That reader is
    /// `crate::protocols`', it runs inside this transfer's reader stack, and it
    /// arms the timer through this method. The seam is deliberately generic over
    /// [`crate::trace::TimerId`] so that all fifteen names travel one path and
    /// no owner grows a table of its own.
    fn expire(&mut self, timeout_ms: TimeDiff, timer: ExpireId);

    /// `Curl_expire_clear(data)`: disarm every timer this transfer has armed.
    ///
    /// The second half of `init_completed` (`lib/multi.c:127`), which runs on
    /// entry to `COMPLETED`.
    fn expire_clear(&mut self);

    /// `Curl_multi_mark_dirty(data)`: run this transfer again as soon as
    /// possible, without waiting for readiness.
    ///
    /// The successor of the C's *"simulated SELECT results"*
    /// (`lib/transfer.c:317-318`): buffered data that no descriptor will ever
    /// report as readable.
    fn mark_dirty(&mut self);

    /// `Curl_multi_clear_dirty(data)`: this transfer is parked on a timer, so
    /// take it out of the run-now set (`lib/multi.c:1896`).
    fn clear_dirty(&mut self);

    /// The `PENDING` transition's set movement (`lib/multi.c:2290-2292`):
    /// remove this transfer from `process` and `dirty`, add it to `pending`.
    ///
    /// One operation rather than three, because the three are not
    /// independently meaningful: a transfer in two of the sets at once
    /// violates the invariant `struct Curl_multi` documents, *"Each transfer's
    /// mid may be present in at most one of these"* (`lib/multihandle.h:93`).
    fn park_pending(&mut self);

    /// `process_pending_handles(multi)`: move transfers waiting for a
    /// connection back into the run set.
    ///
    /// Called at every point the C calls it, which is more places than is
    /// obvious: a connection became available, a new multiplexed connection
    /// came up, a transfer finished, or the multi handle changed. Each site
    /// below cites its line.
    fn process_pending_handles(&mut self);

    /// `multi_ischanged(multi, clear)` (`lib/multi.c:1630-1648`): whether a
    /// transfer was added or removed since the last check.
    ///
    /// `clear` is the C's own second argument: `TRUE` consumes the flag and
    /// `FALSE` peeks. Both forms are used, and which one a call site uses is
    /// load-bearing -- see [`Transfer::run_single`].
    fn multi_changed(&mut self, clear: bool) -> bool;

    /// `CURLM_NTFY(data, CURLMNOTIFY_EASY_DONE)`: the application's
    /// notification callback, fired when a transfer reaches `DONE` -- or
    /// `COMPLETED` directly from before `DONE` (`lib/multi.c:170-180`).
    fn notify_easy_done(&mut self);

    /// `Curl_multi_ev_assess_xfer(multi, data)` (`lib/multi.c:2242`):
    /// re-examine which descriptors this transfer waits on.
    ///
    /// Called from `RESOLVING` only, and the C's comment says why: a resolver
    /// attempt may have closed and reopened sockets, *"the application thus
    /// needs to be told, even if it is likely that the same socket(s) will
    /// again be used further down"*.
    ///
    /// # Errors
    ///
    /// A [`CURLMcode`], which `state_resolving` returns to its caller
    /// unchanged before touching the resolver's answer.
    fn assess_registrations(&mut self) -> Result<(), CURLMcode>;

    /// `multi->dead` (`lib/multi.c:2441`): a multi-level callback failed, so
    /// every transfer in this handle has failed with it.
    fn is_dead(&self) -> bool;

    /// `Curl_multi_xfer_buf_borrow(data, &buf, &blen)`: take the multi
    /// handle's shared download buffer.
    ///
    /// Ownership MOVES to the caller and comes back through
    /// [`Self::xfer_buf_release`], which is what makes the C's borrow
    /// discipline -- one borrower at a time, asserted with
    /// `DEBUGASSERT(!data->multi->xfer_buf_borrowed)` -- an invariant the
    /// type system keeps rather than a rule a reviewer checks.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`], which the C answers when the allocation
    /// fails.
    fn xfer_buf_borrow(&mut self) -> CodeResult<Vec<u8>>;

    /// `Curl_multi_xfer_buf_release(data, buf)`: give the buffer back.
    ///
    /// Called on EVERY path out of the download loop, error paths included --
    /// the C's `out:` label does it once for the same reason
    /// (`lib/transfer.c:332`).
    fn xfer_buf_release(&mut self, buf: Vec<u8>);
}

/// Everything the transfer core reaches out of this file for.
///
/// The successor of `struct Curl_easy *data` and `struct connectdata *conn`,
/// which between them are what every function in `lib/transfer.c` and every
/// state helper in `lib/multi.c` reaches through. Passing a successor to the
/// god-struct would defeat the decomposition AAP section 0.1.2 requires, so
/// this enumerates the operations instead, in sections, each method naming the
/// C function it supersedes.
///
/// # One value implements three traits
///
/// [`Self::request_io`] and [`Self::scheduler`] hand back the OTHER two seams
/// rather than duplicating them. In practice one type -- the engine that owns
/// the easy handle -- implements all three and both accessors return `self`;
/// they are methods rather than supertraits because trait-object upcasting is
/// not available on Rust 1.75, the declared minimum, so `&mut dyn TransferIo`
/// cannot be narrowed to `&mut dyn RequestIo` by coercion.
///
/// # The defaults are a disabled build, not a convenience
///
/// The defaulted methods each reproduce what the C does when the corresponding
/// feature is compiled out: `#ifndef CURL_DISABLE_COOKIES` around the cookie
/// load, `#ifndef CURL_DISABLE_HSTS` around the HSTS load, `#ifndef
/// CURL_DISABLE_FTP` around the wildcard initialiser, and so on. A build
/// without those features answers exactly as these defaults do, so an
/// implementing owner overrides a method when the feature is present and
/// leaves it
/// alone when it is not.
///
/// # What is deliberately NOT here
///
/// No descriptor, no pollset, no `select` mask and no socket. The four C
/// pollset callbacks that would need them -- `connecting_pollset`,
/// `doing_pollset`, `domore_pollset` and `perform_pollset` -- are subsumed by
/// the tokio reactor, exactly as [`crate::protocols::Protocol`]'s four
/// defaults record. No TLS type either: [`Self::conn_send`] and
/// [`Self::conn_recv`] go through `crate::conn`'s filter chain, which
/// interposes TLS transparently.
pub(crate) trait TransferIo: fmt::Debug {
    // -- the other two seams ----------------------------------------------

    /// The per-request seam [`crate::transfer::request`] declares, mutably.
    fn request_io(&mut self) -> &mut dyn RequestIo;

    /// The per-request seam, shared -- for the predicates
    /// [`SingleRequest::want_send`], [`SingleRequest::want_recv`] and
    /// [`SingleRequest::done_sending`] take by reference.
    fn request_io_ref(&self) -> &dyn RequestIo;

    /// The multi handle's machinery.
    fn scheduler(&mut self) -> &mut dyn TransferScheduler;

    // -- progress accounting ----------------------------------------------

    /// `Curl_pgrsCheck(data)` (`lib/progress.c:668-676`): update the counters
    /// and run the low-speed check.
    ///
    /// A composite rather than three separate reads, because
    /// [`crate::transfer::progress::Progress::check`] needs the accounting, the
    /// configured low-speed limit, both pause flags and the application's
    /// callback at the same instant, and the implementing owner holds all four.
    /// Handing
    /// them out one at a time would mean four simultaneous borrows of one
    /// value.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OperationTimedout`] with the low-speed text when the
    /// transfer has been under the limit for too long, and
    /// [`CURLcode::AbortedByCallback`] when the progress callback refused.
    fn pgrs_check(&mut self, req_done: bool) -> CurlResult<Check>;

    /// `Curl_pgrsUpdate(data)` (`lib/progress.c:663-666`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::AbortedByCallback`] when the progress callback refused.
    fn pgrs_update(&mut self, req_done: bool) -> CurlResult<Meter>;

    /// `Curl_pgrsUpdate_nometer(data)` (`lib/progress.c:681-684`): recalculate
    /// without calling back and without drawing.
    ///
    /// Used on exactly one path -- a connect that failed before there was a
    /// connection (`lib/multi.c:2361`) -- where calling the application back
    /// would report a transfer that never started.
    fn pgrs_update_nometer(&mut self, req_done: bool);

    /// `Curl_pgrsDone(data)` (`lib/progress.c:191-205`): the final update.
    ///
    /// # Errors
    ///
    /// [`CURLcode::AbortedByCallback`] when the progress callback refused.
    fn pgrs_done(&mut self, req_done: bool) -> CurlResult<PgrsDone>;

    /// `Curl_timeleft_ms(data)` (`lib/connect.c:139-142`): milliseconds left
    /// before this transfer's deadline, zero for "no limit", negative when it
    /// has passed.
    ///
    /// The implementing owner computes it with [`crate::conn::timeleft_ms`],
    /// which
    /// takes the connection's deadline state and the injected clock. The sign
    /// convention is the C's and is load-bearing: `< 0` means expired and `0`
    /// means unlimited, so a test for expiry must not be `<= 0`.
    fn timeleft_ms(&mut self) -> TimeDiff;

    // -- connection ownership ---------------------------------------------

    /// `data->conn != NULL`: whether this transfer owns a connection.
    ///
    /// Read at four decision points in `multi_runsingle`, one of which
    /// (`lib/multi.c:2473-2479`) turns its absence into
    /// [`CURLMcode::InternalError`] rather than a dereference.
    fn has_connection(&self) -> bool;

    /// `data->conn->scheme` (`lib/urldata.h:514-523`): the registry row for the
    /// scheme in use, or [`None`] when there is no connection.
    fn scheme(&self) -> Option<&'static Scheme>;

    /// `data->conn->bits.reuse`: this connection came from the pool.
    fn conn_is_reused(&self) -> bool;

    /// `data->conn->bits.close`: this connection must not be reused.
    fn conn_wants_close(&self) -> bool;

    /// `data->conn->bits.multiplex`: this connection carries several streams.
    ///
    /// Distinct from [`Self::conn_is_multiplex`], which asks the FILTER CHAIN
    /// whether the negotiated protocol multiplexes. The C reads the bit in
    /// `MSTATE_DID` (`lib/multi.c:2646`) and the chain everywhere else, and the
    /// two answers can differ before ALPN has settled.
    fn conn_multiplex_bit(&self) -> bool;

    /// `Curl_conn_is_multiplex(conn, sockindex)`: whether the negotiated
    /// protocol on `channel` multiplexes streams.
    fn conn_is_multiplex(&mut self, channel: SocketIndex) -> bool;

    /// `data->conn->bits.do_more`: the DO phase has a second half, so `DID`
    /// must be reached through `DOING_MORE`.
    fn conn_wants_do_more(&self) -> bool;

    /// `data->conn->bits.protoconnstart` (`lib/multi.c:1828-1836`): the
    /// protocol-specific connect has already been started, so it must not be
    /// started again.
    fn protoconn_started(&self) -> bool;

    /// Sets `data->conn->bits.protoconnstart` (`lib/multi.c:1835`).
    fn set_protoconn_started(&mut self);

    /// `Curl_conn_data_pending(data, sockindex)`: whether a filter is holding
    /// received bytes that no descriptor will report.
    fn conn_data_pending(&mut self, channel: SocketIndex) -> bool;

    /// `Curl_conn_send(data, sockindex, buf, blen, eos, &n)`.
    ///
    /// # Errors
    ///
    /// Any transport failure, and [`CURLcode::Again`] when the send would block
    /// -- which [`Transfer::xfer_send`] converts, exactly as `Curl_xfer_send`
    /// does (`lib/transfer.c:840-843`).
    fn conn_send(
        &mut self,
        channel: SocketIndex,
        buf: &[u8],
        eos: bool,
    ) -> CodeResult<usize>;

    /// `Curl_conn_recv(data, sockindex, buf, blen, &n)`.
    ///
    /// # Errors
    ///
    /// Any transport failure, and [`CURLcode::Again`] when nothing is ready. A
    /// zero-length `Ok` is END OF STREAM and never "not ready" -- the C's
    /// comment at `lib/transfer.c:287` states the invariant: *"We only get a
    /// 0-length receive at the end of the response"*.
    fn conn_recv(
        &mut self,
        channel: SocketIndex,
        buf: &mut [u8],
    ) -> CodeResult<usize>;

    /// `Curl_conn_needs_flush(data, sockindex)`: a filter is holding output
    /// that has not reached the wire.
    fn conn_needs_flush(&mut self, channel: SocketIndex) -> bool;

    /// `Curl_conn_flush(data, sockindex)`: push it.
    ///
    /// # Errors
    ///
    /// Any transport failure, and [`CURLcode::Again`] when the flush could not
    /// complete.
    fn conn_flush(&mut self, channel: SocketIndex) -> CodeResult<()>;

    /// `Curl_conn_shutdown(data, sockindex, &done)`: begin or advance a
    /// graceful close of `channel`.
    ///
    /// The `bool *done` becomes an [`AsyncStep`], per AAP section 0.1.2. An
    /// implementing owner arms `ExpireId::Shutdown` while the answer is
    /// [`AsyncStep::Pending`], which is what `Curl_shutdown_start` does
    /// (`lib/connect.c:156`).
    ///
    /// # Errors
    ///
    /// Any transport failure. Whether it is fatal is the CALLER's decision --
    /// see [`SingleRequest::shutdown_err_ignore`].
    fn conn_shutdown(&mut self, channel: SocketIndex) -> CodeResult<AsyncStep>;

    /// `Curl_shutdown_started(data, sockindex)` (`lib/transfer.c:153-158`):
    /// whether a graceful close of `channel` is already under way.
    fn conn_shutdown_started(&mut self, channel: SocketIndex) -> bool;

    /// `streamclose(conn, reason)`: end this STREAM at the end of the transfer.
    /// On a multiplexed connection the connection itself survives.
    ///
    /// The reason is `&'static str` because every C call site passes a literal
    /// and the reason is echoed into a trace line rather than parsed.
    fn stream_close(&mut self, reason: &'static str);

    /// `connclose(conn, reason)`: end the whole CONNECTION at the end of the
    /// transfer.
    fn conn_close(&mut self, reason: &'static str);

    /// `conn->bits.retry = TRUE` (`lib/transfer.c:669-673`): this connection is
    /// being abandoned for a retry.
    ///
    /// The C's comment explains why the bit is separate from `bits.close`:
    /// *"Marking it this way should prevent i.e HTTP transfers to return error
    /// just because nothing has been transferred!"*
    fn conn_mark_retry(&mut self);

    /// `Curl_detach_connection(data)`: this transfer no longer uses its
    /// connection.
    fn detach_connection(&mut self);

    /// `Curl_conn_terminate(data, conn, dead_connection)`: shut the connection
    /// down and destroy it.
    ///
    /// `dead` forbids sending anything during the teardown, which is what stops
    /// an FTP `QUIT` from blocking on a socket that timed out
    /// (`lib/multi.c:2348`).
    fn terminate_connection(&mut self, dead: bool);

    /// `Curl_cpool_do_locked(data, conn, multi_done_locked, &ctx)`
    /// (`lib/multi.c:596-663` and `:732`): decide, under the pool's lock, what
    /// becomes of this transfer's connection.
    ///
    /// The whole of `multi_done_locked` is behind this one call and stays in
    /// `crate::conn::pool`, which owns the pool: whether the connection is
    /// terminated or kept, the `Connection #%ld to host %s:%d left intact`
    /// line, and the two connection identifiers the C stores back into
    /// `data->state`. The transfer core supplies `premature` and takes the
    /// identifiers back.
    fn complete_connection(&mut self, premature: bool) -> ConnectionOutcome;

    /// `Curl_conn_ev_data_pause(data, pause)` (`lib/transfer.c:909`): the
    /// application paused or resumed the receive direction.
    fn ev_data_pause(&mut self, pause: bool);

    /// `Curl_conn_ev_data_done(data, premature)` (`lib/multi.c:722`): this
    /// transfer is finished with the connection.
    fn ev_data_done(&mut self, premature: bool);

    /// `Curl_conn_ev_data_done_send(data)` (`lib/transfer.c:867`): the request
    /// body is complete.
    fn ev_data_done_send(&mut self);

    // -- the asynchronous connection lifecycle -----------------------------

    /// `Curl_connect(data, &async, &connected)` (`lib/multi.c:2284`): find or
    /// establish a connection for this transfer.
    ///
    /// The three out-channels become one [`ConnectOutcome`]; see that type for
    /// why the C's sentinel error is not an error here.
    ///
    /// # Errors
    ///
    /// Any real failure. When it fails the connection may ALREADY be gone --
    /// the C's comment at `lib/multi.c:2253-2255` says so of the resolver path
    /// -- so a caller must not assume [`Self::has_connection`] still answers
    /// true.
    fn connect(&mut self) -> XferFuture<'_, ConnectOutcome>;

    /// `Curl_conn_connect(data, FIRSTSOCKET, FALSE, &connected)`
    /// (`lib/multi.c:2529`): drive the filter chain's connect.
    ///
    /// [`AsyncStep::Complete`] is the C's `connected == TRUE`.
    ///
    /// # Errors
    ///
    /// Any failure the chain reports, a TLS handshake failure included -- which
    /// reaches this file as an ordinary code, because the chain interposes TLS
    /// transparently.
    fn conn_connect(&mut self) -> XferFuture<'_, AsyncStep>;

    /// `Curl_resolv_check(data, &dns)` (`lib/multi.c:2234`): advance the
    /// injected resolver.
    ///
    /// # Errors
    ///
    /// A resolution failure, which `RESOLVING` treats as a stream error.
    fn resolver_check(&mut self) -> XferFuture<'_, ResolveStep>;

    /// `Curl_once_resolved(data, dns, &connected)` (`lib/multi.c:2250`):
    /// continue connection setup now that the name is known.
    ///
    /// [`AsyncStep::Complete`] is the C's `connected == TRUE`.
    ///
    /// # Errors
    ///
    /// Any failure. The C's comment is the contract, and the reason
    /// `state_resolving` drops its connection on this path: *"if
    /// Curl_once_resolved() returns failure, the connection struct is already
    /// freed and gone"* (`lib/multi.c:2253-2255`).
    fn once_resolved(&mut self) -> XferFuture<'_, AsyncStep>;

    /// `Curl_async_shutdown(data)` (`lib/multi.c:684`): abandon any resolver
    /// work still in flight.
    fn resolver_shutdown(&mut self);

    // -- the protocol -------------------------------------------------------

    /// `data->conn->scheme->run` (`lib/urldata.h:517`): this scheme's transfer
    /// implementation, or [`None`] when the build carries none.
    ///
    /// The C tests the pointer for `NULL` and so does every caller here:
    /// `Curl_getn_scheme`'s contract is *"Check the ->run struct field for
    /// non-NULL to figure out if an implementation is present"*
    /// (`lib/url.c:1474-1476`).
    fn protocol(&self) -> Option<&'static dyn Protocol>;

    /// The context a [`Protocol`] operation is called with.
    ///
    /// Assembled by the implementing owner from the filter chains, the injected
    /// clock
    /// and the scheme, because those three are the connection's and not the
    /// transfer core's. The core builds no context of its own and stores none:
    /// a [`TransferCtx`] borrows the chains mutably, so it is created for one
    /// call and dropped.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when there is no connection to build a context
    /// over -- the code the C answers wherever it tests `data && data->conn`
    /// (`lib/transfer.c:148-149`).
    fn xfer_ctx(&mut self) -> CodeResult<TransferCtx<'_>>;

    /// `conn->scheme->run->write_resp_hd != NULL` (`lib/transfer.c:702`):
    /// whether this scheme writes response HEADERS through the protocol hook.
    ///
    /// A predicate rather than a pointer test, because Rust cannot ask a trait
    /// object whether a defaulted method was overridden. It decides two things
    /// in [`Transfer::xfer_setup`]: the initial value of
    /// [`SingleRequest::header`], and whether the transfer wants to receive at
    /// all when the response has no body (`lib/transfer.c:714`).
    fn writes_response_headers(&self) -> bool;

    /// `conn->scheme->run->connecting != NULL` (`lib/multi.c:1840-1841`):
    /// whether this scheme has a protocol-connect continuation.
    ///
    /// The same kind of predicate, deciding the same kind of thing: when it is
    /// false, `protocol_connect` reports completion however `connect_it`
    /// answered, so the transfer never enters `PROTOCONNECTING`.
    fn protocol_has_connecting(&self) -> bool;

    /// Both seams a redirect needs, borrowed at once.
    ///
    /// [`SingleRequest::follow`] takes the request seam AND the protocol's
    /// follow half, because `Curl_http_follow` reaches through `data` for both
    /// (`lib/http.c:1115-1396`). A single `&mut dyn TransferIo` cannot hand out
    /// two independent mutable borrows of itself, so it hands them out together,
    /// and the implementing owner keeps the two halves in separate fields.
    ///
    /// The protocol half is [`None`] when the scheme has no `follow` operation,
    /// which [`SingleRequest::follow`] turns into
    /// [`CURLcode::TooManyRedirects`] -- the C's `multi_follow` answer for a
    /// `NULL` slot (`lib/multi.c:1875-1877`).
    fn follow_seams(
        &mut self,
    ) -> (&mut dyn RequestIo, Option<&mut dyn ProtocolFollow>);

    /// The redirect settings [`SingleRequest::follow`] reads.
    fn follow_settings(&self) -> FollowSettings;

    /// `Curl_h2_http_1_1_error(data)`: whether the HTTP/2 stream error was
    /// `HTTP_1_1_REQUIRED`.
    ///
    /// The default is false, which is what a build without HTTP/2 answers --
    /// the C guards the whole downgrade branch with `#ifndef CURL_DISABLE_HTTP`
    /// and reaches an HTTP/2-only helper inside it (`lib/multi.c:1958-1987`).
    fn h2_http_1_1_error(&self) -> bool {
        false
    }

    // -- the client writer and reader chains -------------------------------

    /// `Curl_client_write(data, type, buf, blen)` (`lib/sendf.c:375-401`): send
    /// response bytes down the writer chain to the application.
    ///
    /// # Errors
    ///
    /// Whatever a stage returns, [`CURLcode::WriteError`] from the
    /// application's own callback included.
    fn client_write(
        &mut self,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CodeResult<()>;

    /// `Curl_cw_out_done(data)` (`lib/cw-out.c:504-517`), reached through
    /// [`writeout::done`]: the download has ended, so deliver everything the
    /// client stage is still holding.
    ///
    /// `premature` is `Curl_xfer_write_done`'s parameter, which the C ignores
    /// with `(void)premature` (`lib/transfer.c:815`). It is carried rather than
    /// dropped because the caller HAS the fact and a future stage may want it;
    /// the implementing owner must not let it change what is delivered.
    ///
    /// # Errors
    ///
    /// Whatever the first failing stage returned.
    fn client_write_done(&mut self, premature: bool) -> CodeResult<()>;

    /// `Curl_cwriter_is_paused(data)` (`lib/cw-out.c:453-464`), reached through
    /// [`writeout::is_paused`].
    fn client_writer_is_paused(&self) -> bool;

    /// `Curl_cwriter_unpause(data)` (`lib/cw-out.c:487-502`), reached through
    /// [`writeout::unpause`]: replay what the client stage held back.
    ///
    /// # Errors
    ///
    /// Whatever the replay reports, propagated EXACTLY -- see
    /// [`Transfer::xfer_pause_recv`].
    fn client_writer_unpause(&mut self) -> CodeResult<()>;

    /// `Curl_creader_is_paused(data)`: the reader chain is holding the upload.
    fn client_reader_is_paused(&self) -> bool;

    /// `Curl_creader_unpause(data)`: resume it.
    ///
    /// # Errors
    ///
    /// Whatever the first stage reports.
    fn client_reader_unpause(&mut self) -> CodeResult<()>;

    /// `Curl_creader_set_rewind(data, TRUE)` (`lib/transfer.c:674`): the next
    /// attempt must re-read the upload from the beginning.
    fn client_reader_set_rewind(&mut self, rewind: bool);

    /// The two assignments of `Curl_init_CONNECT` that bind the application's
    /// read callback and its opaque pointer (`lib/transfer.c:437-438`).
    ///
    /// The callback and pointer live in [`crate::transfer::sendf`]'s reader
    /// chain here, so the binding is the owner's; the third assignment,
    /// the upload flag, is [`TransferState::init_connect`]'s.
    fn bind_upload_source(&mut self) {}

    // -- pretransfer services ----------------------------------------------

    /// `curl_url_get(data->set.uh, CURLUPART_URL, &url, 0)`
    /// (`lib/transfer.c:470-471`): the URL held by the application's `CURLU`
    /// handle.
    ///
    /// [`None`] when no handle is set. `Some(Err(_))` when the handle holds no
    /// usable URL, which [`Transfer::pretransfer`] reports as
    /// [`CURLcode::UrlMalformat`] with the C's `No URL set` line.
    ///
    /// The default is [`None`], which is a transfer where no handle was set.
    fn url_from_handle(&mut self) -> Option<CodeResult<String>> {
        None
    }

    /// `Curl_cookie_loadfiles(data)` (`lib/transfer.c:517`).
    ///
    /// The default is `Ok(())`: the C compiles the call out under
    /// `CURL_DISABLE_COOKIES`.
    ///
    /// # Errors
    ///
    /// Whatever reading a jar reports.
    fn cookie_loadfiles(&mut self) -> CodeResult<()> {
        Ok(())
    }

    /// `Curl_cookie_run(data)` (`lib/transfer.c:519`): activate the jar. The
    /// C's own comment on the call is `/* activate */`.
    fn cookie_run(&mut self) {}

    /// `data->state.resolve != NULL` (`lib/transfer.c:522`): whether
    /// `CURLOPT_RESOLVE` supplied any host-port pairs.
    fn has_resolve_list(&self) -> bool {
        false
    }

    /// `Curl_loadhostpairs(data)` (`lib/transfer.c:523`): apply
    /// `CURLOPT_RESOLVE`.
    ///
    /// # Errors
    ///
    /// Whatever parsing a pair reports.
    fn load_host_pairs(&mut self) -> CodeResult<()> {
        Ok(())
    }

    /// `Curl_hsts_loadfiles(data)` (`lib/transfer.c:527`).
    ///
    /// # Errors
    ///
    /// Whatever reading the file reports.
    fn hsts_loadfiles(&mut self) -> CodeResult<()> {
        Ok(())
    }

    /// `Curl_hsts_loadcb(data, data->hsts)` (`lib/transfer.c:572`): the
    /// application's HSTS read callback.
    ///
    /// # Errors
    ///
    /// Whatever the callback reports.
    fn hsts_loadcb(&mut self) -> CodeResult<()> {
        Ok(())
    }

    /// `Curl_wildcard_init(wc)` and the reset around it
    /// (`lib/transfer.c:555-570`): prepare the FTP wildcard state.
    ///
    /// Called only when `CURLOPT_WILDCARDMATCH` is on and the stage is below
    /// [`WildcardStage::Init`], which is the C's `if(wc->state < CURLWC_INIT)`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`], the only failure the C reports here.
    fn wildcard_init(&mut self) -> CodeResult<()> {
        Ok(())
    }

    /// `Curl_initinfo(data)` (`lib/transfer.c:543`): reset the
    /// session-specific `curl_easy_getinfo` values.
    fn init_info(&mut self);

    /// `Curl_data_priority_clear_state(data)` (`lib/transfer.c:503`): forget
    /// the HTTP/2 priority tree this handle was part of.
    ///
    /// The default does nothing, which is a build without HTTP/2 -- the C
    /// defines the function as a no-op macro under that configuration.
    fn priority_clear_state(&mut self) {}

    /// `Curl_http_neg_init(data, &data->state.http_neg)`
    /// (`lib/transfer.c:497`): the HTTP version masks `CURLOPT_HTTP_VERSION`
    /// implies.
    ///
    /// Returns the masks rather than writing them, so that
    /// [`Transfer::pretransfer`] stores them where every other piece of state
    /// is stored. The default is [`HttpNegotiation::default`], which is the C's
    /// `CURL_HTTP_VERSION_NONE` arm (`lib/http.c:118-122`).
    fn http_neg_init(&mut self) -> HttpNegotiation {
        HttpNegotiation::default()
    }

    /// `Curl_headers_cleanup(data)` (`lib/transfer.c:607`): drop the collected
    /// response headers of the previous transfer.
    fn headers_cleanup(&mut self);

    /// `Curl_netrc_cleanup(&data->state.netrc)` (`lib/multi.c:735`): flush the
    /// `.netrc` cache at the end of a transfer.
    fn netrc_cleanup(&mut self) {}

    /// `data->set.fprereq(...)` (`lib/multi.c:2069-2088`): the application's
    /// pre-request callback, already called with the two addresses and two
    /// ports the C passes it.
    ///
    /// [`None`] when no callback is set. The value is compared against
    /// [`CURL_PREREQFUNC_OK`], and ANY other integer aborts the transfer,
    /// exactly as the C's `!=` does.
    ///
    /// The implementing owner is responsible for raising the in-callback flag
    /// around
    /// the call, which is what `Curl_set_in_callback` does at
    /// `lib/multi.c:2073` and `:2079`.
    fn prereq(&mut self) -> Option<i32> {
        None
    }

    // -- diagnostics --------------------------------------------------------

    /// `CURL_TRC_M(data, ...)`: a trace line about the multi-handle layer.
    ///
    /// The bracketed identifier of such a line is the transfer's STATE name,
    /// which is why [`CurlMstate::name`] exists and why nothing here spells a
    /// state name as a literal. The default discards, because
    /// `CURLOPT_VERBOSE` is off by default.
    fn trace_multi(&mut self, line: fmt::Arguments<'_>) {
        let _ = line;
    }

    /// `CURL_TRC_WRITE(data, ...)`: a trace line about the writer chain.
    fn trace_write(&mut self, line: fmt::Arguments<'_>) {
        let _ = line;
    }
}

/// What became of a transfer's connection when the transfer finished.
///
/// The two identifiers `multi_done_locked` writes back into `data->state`
/// (`lib/multi.c:629`, `:654` and `:660`), returned rather than written because
/// the decision is `crate::conn::pool`'s and the storage is the transfer's.
///
/// `recent` is `state.recent_conn_id`, *"The most recent connection used, might
/// no longer exist"* (`lib/urldata.h:944-945`), and survives whatever the pool
/// then decides -- unlike `last`, a terminated connection's identifier still
/// lands there. It is written only once this transfer was the connection's last
/// user, because the C writes it at `:629`, after the in-use early return at
/// `:625`. `last` is `state.lastconnect_id`, *"The last connection, -1 if
/// undefined"* (`:943`), and is [`None`] -- the C's `-1` -- when the connection
/// was destroyed rather than kept, which is what makes `CURLINFO_LASTSOCKET`
/// report it as unusable.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: complete here, crate::conn::pool, crate::easy
pub(crate) struct ConnectionOutcome {
    /// `data->state.recent_conn_id`, or [`None`] when no connection was in use.
    pub(crate) recent: Option<i64>,

    /// `data->state.lastconnect_id`: `Some(id)` when the connection was kept
    /// for reuse, [`None`] for the C's `-1`.
    pub(crate) last: Option<i64>,

    /// `CONN_INUSE(conn)` after this transfer detached
    /// (`lib/multi.c:621-626`): another transfer is still using the connection,
    /// so nothing was decided about it.
    ///
    /// This is the flag that makes `data->state.done` conditional, which is easy
    /// to miss in the C: `multi_done_locked` sets it at `:628`, AFTER the
    /// in-use check returns early at `:625`. A transfer sharing a multiplexed
    /// connection therefore leaves `state.done` false, and `multi_done` may run
    /// again for it -- which is what lets the LAST stream on a connection make
    /// the pool decision. Reproduced rather than tidied.
    pub(crate) still_in_use: bool,
}

// ---------------------------------------------------------------------------
// Custom request headers: `Curl_headersep` and `Curl_checkheaders`
// ---------------------------------------------------------------------------

/// `Curl_headersep(x)` (`lib/transfer.h:26`): whether `byte` terminates a
/// custom header's NAME.
///
/// ```text
/// #define Curl_headersep(x) ((((x) == ':') || ((x) == ';')))
/// ```
///
/// Two separators, and the second is the one that matters. A colon is the
/// ordinary field separator, and a semicolon is curl's own convention for
/// *"send this header even though it has no value"* -- `-H "Accept;"` emits a
/// bare `Accept:` where `-H "Accept:"` REMOVES the default. A prefix match that
/// accepted anything else would make `-H "Accept-Encoding: gzip"` answer a
/// lookup for `Accept`, and the request would then be missing its own default
/// `Accept` header. That is a wire difference, so the predicate is exact.
#[allow(dead_code)] // consumers: checkheaders here, and crate::protocols's http
pub(crate) const fn headersep(byte: u8) -> bool {
    byte == b':' || byte == b';'
}

/// `Curl_checkheaders(data, thisheader, thislen)`
/// (`lib/transfer.c:84-99`): the first custom header whose name is `prefix`, or
/// [`None`].
///
/// Three properties, all observable:
///
/// * the comparison is CASE-INSENSITIVE, over ASCII only -- the C uses
///   `curl_strnequal`, whose fold is the identity above `0x7f`, so
///   `crate::util::strcase`'s equivalent is what this uses through
///   [`str::eq_ignore_ascii_case`] on the prefix slice;
/// * the byte AFTER the prefix must satisfy [`headersep`], so `Accept` does not
///   match `Accept-Encoding:`;
/// * the FIRST match in insertion order wins, and it is returned VERBATIM --
///   not normalised, not trimmed, not re-cased -- because the caller splices
///   those exact bytes into the request.
///
/// # Panics
///
/// Never. The C asserts two preconditions in a debug build --
/// `DEBUGASSERT(thislen)` and `DEBUGASSERT(thisheader[thislen - 1] != ':')`
/// (`lib/transfer.c:89-90`) -- and this answers [`None`] for both instead: an
/// empty prefix cannot have a separator after it, and a prefix ending in a
/// colon can never be followed by one. Refusing is the same OUTCOME as the C's
/// release build reaches, without the debug build's abort.
#[allow(dead_code)] // consumers: crate::protocols's http, smtp and imap paths
pub(crate) fn checkheaders<'headers>(
    headers: &'headers [String],
    prefix: &str,
) -> Option<&'headers str> {
    // `DEBUGASSERT(thislen)`: an empty prefix would match every header at
    // position zero and then test `header[0]` as the separator.
    if prefix.is_empty() {
        return None;
    }
    // `DEBUGASSERT(thisheader[thislen - 1] != ':')`: with the colon inside the
    // prefix, the separator test would look at the byte AFTER it and reject
    // every well-formed header.
    if prefix.as_bytes().last() == Some(&b':') {
        return None;
    }

    let len = prefix.len();
    headers.iter().find_map(|header| {
        let bytes = header.as_bytes();
        // `curl_strnequal(head->data, thisheader, thislen)` followed by
        // `Curl_headersep(head->data[thislen])`. The length test comes first
        // because C reads `head->data[thislen]` and relies on the string's
        // terminator to make an exact-length header fail the separator test;
        // a Rust slice has no terminator, so the bound is explicit.
        if bytes.len() <= len {
            return None;
        }
        let matches =
            header[..len].eq_ignore_ascii_case(prefix) && headersep(bytes[len]);
        if matches {
            Some(header.as_str())
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// The transfer engine
// ---------------------------------------------------------------------------

/// One transfer, and the state machine that drives it.
///
/// The successor of the transfer-shaped half of `struct Curl_easy`: the request
/// attempt ([`Self::req`]), the operation's state ([`Self::state`]), the two
/// `curl_easy_getinfo` values this layer writes ([`Self::info`]), the settings
/// it reads ([`Self::settings`]) and the position in the state machine
/// ([`Self::mstate`]).
///
/// Everything ELSE a transfer needs -- the connection, the filter chains, the
/// client reader and writer chains, the progress accounting, the resolver, the
/// multi handle's sets and timers -- arrives through [`TransferIo`], so this
/// struct is the part of a transfer that has no dependencies of its own and can
/// be driven from memory in a test.
///
/// # Not a god-struct successor
///
/// `struct Curl_easy` has more than 200 fields and every file in `lib/` reaches
/// into it. This has five, and the ownership is explicit: [`Self::req`] is reset
/// between attempts, [`Self::state`] is reset once per operation, and
/// [`Self::settings`] is never written here at all. That split is exactly the
/// C's `data->req` / `data->state` / `data->set` division, which the C observes
/// by convention and this observes by construction.
#[derive(Debug)]
#[allow(dead_code)] // consumers: crate::multi and crate::easy
pub(crate) struct Transfer {
    /// `data->mstate` (`lib/multihandle.h:51-70`): where in the state machine
    /// this transfer is.
    ///
    /// Private, and written only by [`Self::set_mstate`], so that the trace
    /// line, the notification and the per-state initialiser the C attaches to a
    /// transition cannot be skipped by an assignment. The C achieves the same
    /// with a comment -- *"always use this function to change state, to make
    /// debugging easier"* (`lib/multi.c:130`) -- and the comment is
    /// unenforceable.
    mstate: CurlMstate,

    /// `data->req`: the current request attempt.
    pub(crate) req: SingleRequest,

    /// `data->state`, narrowed: the operation's state.
    pub(crate) state: TransferState,

    /// `data->info`, narrowed to the two members this layer writes.
    pub(crate) info: TransferInfo,

    /// `data->set`, narrowed to what this layer reads.
    settings: TransferSettings,

    /// `data->result` (`lib/multi.c:2743`): the code the multi handle will
    /// report for this transfer.
    result: CURLcode,

    /// Whether [`Self::pretransfer`] has run for this operation.
    ///
    /// The C needs no such flag because `MSTATE_INIT` is unreachable a second
    /// time -- its comment is *"A handle never comes back to this state"*
    /// (`lib/multi.c:2490-2491`) -- except through the FTP wildcard restart at
    /// `:2695`, which deliberately DOES come back and deliberately does run
    /// pretransfer again.
    ///
    /// `MSTATE_INIT` here runs [`Self::pretransfer`] unconditionally, exactly as
    /// the C does; this flag is not a gate on that. It is READ through
    /// [`Self::pretransfer_done`] by a caller that drives one transfer without a
    /// multi handle's run set -- `crate::easy` -- and therefore has no other way
    /// to tell whether `INIT` has been through. The wildcard restart clears it
    /// exactly where the C returns to `INIT`, so the next iteration reports the
    /// new attempt as uninitialised rather than as a continuation.
    pretransfer_done: bool,

    /// `data->conn->send_idx` (`lib/urldata.h:660`): which connection channel
    /// this transfer sends on.
    ///
    /// # Why this is on the transfer and not on the connection
    ///
    /// The C stores both indexes on `struct connectdata` because `data` and
    /// `conn` are separate structures, each reachable from everywhere, and
    /// whichever one holds them is readable from both. Here they belong to the
    /// transfer, for two reasons: [`Self::xfer_setup`] is the only writer and
    /// is a transfer operation, and the C's own assertions are conditions
    /// relating an index to the REQUEST's `want_send` -- which is transfer
    /// state. A connection carries at most one transfer's channel assignment at
    /// a time in either arrangement, because `xfer_setup` runs per attempt.
    send_channel: ChannelIndex,

    /// `data->conn->recv_idx` (`lib/urldata.h:661`): which connection channel
    /// this transfer receives on. See [`Self::send_channel`].
    recv_channel: ChannelIndex,
}

// Construction, accessors and the one place a state changes

#[allow(dead_code)] // consumers: crate::multi and crate::easy
impl Transfer {
    /// A transfer in [`CurlMstate::Init`] with `settings`.
    ///
    /// `MSTATE_INIT` is the C's own starting point -- its comment is *"0 - start
    /// in this state"* (`lib/multihandle.h:52`) -- and no trace line is emitted
    /// for it, because `mstate` returns early when the state does not change
    /// (`lib/multi.c:158-160`) and a fresh transfer is already there.
    pub(crate) fn new(settings: TransferSettings) -> Self {
        Self {
            mstate: CurlMstate::Init,
            req: SingleRequest::default(),
            state: TransferState::new(),
            info: TransferInfo::default(),
            settings,
            result: CURLcode::Ok,
            pretransfer_done: false,
            send_channel: ChannelIndex::None,
            recv_channel: ChannelIndex::None,
        }
    }

    /// `data->mstate`.
    pub(crate) const fn mstate(&self) -> CurlMstate {
        self.mstate
    }

    /// `data->result`.
    pub(crate) const fn result(&self) -> CURLcode {
        self.result
    }

    /// `data->set`, shared.
    pub(crate) const fn settings(&self) -> &TransferSettings {
        &self.settings
    }

    /// `data->set`, mutable -- for the OWNER of the handle, which is where
    /// `curl_easy_setopt` lands.
    ///
    /// Nothing in this file calls it: the transfer core reads settings and
    /// writes state, which is the division [`TransferSettings`] documents.
    pub(crate) fn settings_mut(&mut self) -> &mut TransferSettings {
        &mut self.settings
    }

    /// `multistate(data, state)` -- `mstate` (`lib/multi.c:131-197`).
    ///
    /// Four things happen here and all four are the C's, in the C's order:
    ///
    /// 1. a transition to the SAME state returns at once and traces nothing
    ///    (`:158-160`);
    /// 2. the trace line `-> [STATE]` is emitted with the state's own name
    ///    (`:166`), which is why [`CurlMstate::name`] exists;
    /// 3. `DONE` notifies the application, and so does a jump to `COMPLETED`
    ///    from before `DONE` -- the C's comment is *"we sometimes directly jump
    ///    to COMPLETED"* (`:172-179`);
    /// 4. the state's initialiser runs, from the C's `finit[]` table
    ///    (`:138-155` and `:195-196`): `Curl_init_CONNECT` on `CONNECT`,
    ///    `before_perform` on `DID`, `init_completed` on `COMPLETED`.
    ///
    /// The set movement the C performs for `COMPLETED` (`:181-190`) is the multi
    /// handle's and is not here; the driver reports the completion through
    /// [`RunSingle::Completed`] and `crate::multi` moves the membership.
    pub(crate) fn set_mstate(
        &mut self,
        io: &mut dyn TransferIo,
        state: CurlMstate,
    ) {
        let old = self.mstate;
        // `:158-160`: "do not bother when the new state is the same as the old
        // state".
        if old == state {
            return;
        }

        self.mstate = state;
        io.trace_multi(format_args!("-> [{}]", state.name()));

        match state {
            // `:169-171`.
            CurlMstate::Done => io.scheduler().notify_easy_done(),
            // `:172-180`: a direct jump from before DONE notifies too.
            CurlMstate::Completed => {
                if old < CurlMstate::Done {
                    io.scheduler().notify_easy_done();
                }
            }
            CurlMstate::Init
            | CurlMstate::Pending
            | CurlMstate::Setup
            | CurlMstate::Connect
            | CurlMstate::Resolving
            | CurlMstate::Connecting
            | CurlMstate::ProtoConnect
            | CurlMstate::ProtoConnecting
            | CurlMstate::Do
            | CurlMstate::Doing
            | CurlMstate::DoingMore
            | CurlMstate::Did
            | CurlMstate::Performing
            | CurlMstate::RateLimiting
            | CurlMstate::MsgSent => {}
        }

        // The `finit[]` table (`:138-155`), whose three non-null entries are
        // spelled out here. An exhaustive match rather than a table, so that
        // adding a state without deciding its initialiser does not compile.
        match state {
            // `Curl_init_CONNECT` (`lib/transfer.c:435-440`).
            CurlMstate::Connect => {
                self.state.init_connect();
                io.bind_upload_source();
            }
            // `before_perform` (`lib/multi.c:114-118`).
            CurlMstate::Did => {
                self.req.chunk = false;
                io.request_io().pgrs_time(PgrsTimer::PreTransfer);
            }
            // `init_completed` (`lib/multi.c:120-128`).
            CurlMstate::Completed => {
                io.detach_connection();
                io.scheduler().expire_clear();
            }
            CurlMstate::Init
            | CurlMstate::Pending
            | CurlMstate::Setup
            | CurlMstate::Resolving
            | CurlMstate::Connecting
            | CurlMstate::ProtoConnect
            | CurlMstate::ProtoConnecting
            | CurlMstate::Do
            | CurlMstate::Doing
            | CurlMstate::DoingMore
            | CurlMstate::Performing
            | CurlMstate::RateLimiting
            | CurlMstate::Done
            | CurlMstate::MsgSent => {}
        }
    }

    /// `Curl_meets_timecondition(data, timeofdoc)`
    /// (`lib/transfer.c:120-144`): whether `CURLOPT_TIMECONDITION` admits a
    /// document with this timestamp.
    ///
    /// Four rules, transcribed:
    ///
    /// * either side being zero succeeds, because an unknown document time and
    ///   an unset `CURLOPT_TIMEVALUE` are both "no condition" (`:122-123`);
    /// * `IFMODSINCE` -- and every unrecognised value, which shares its `case`
    ///   label -- fails when the document is NOT NEWER, `timeofdoc <=
    ///   timevalue`, so equality fails (`:128`);
    /// * `IFUNMODSINCE` fails when the document is NOT OLDER, `timeofdoc >=
    ///   timevalue`, so equality fails on this side too (`:135`);
    /// * a failure sets `info.timecond`, which `CURLINFO_CONDITION_UNMET`
    ///   reports, and emits one of two frozen lines.
    ///
    /// The two lines are compared against recorded stderr by the fixture corpus
    /// and are reproduced exactly: `The requested document is not new enough`
    /// and `The requested document is not old enough`.
    pub(crate) fn meets_timecondition(
        &mut self,
        io: &mut dyn TransferIo,
        timeofdoc: i64,
    ) -> bool {
        // `:122-123`.
        if timeofdoc == 0 || self.settings.timevalue == 0 {
            return true;
        }

        match self.settings.timecondition {
            // `:134-140`.
            TimeCondition::IfUnmodSince => {
                if timeofdoc >= self.settings.timevalue {
                    io.request_io().infof(format_args!(
                        "The requested document is not old enough"
                    ));
                    self.info.timecond = true;
                    return false;
                }
            }
            // `:126-133`. `IFMODSINCE` shares its arm with the C's `default:`,
            // so `None` and `LastMod` land here as well -- which is why
            // [`TimeCondition::from_i64`] cannot produce a value this match
            // treats differently.
            TimeCondition::IfModSince
            | TimeCondition::None
            | TimeCondition::LastMod => {
                if timeofdoc <= self.settings.timevalue {
                    io.request_io().infof(format_args!(
                        "The requested document is not new enough"
                    ));
                    self.info.timecond = true;
                    return false;
                }
            }
        }

        true
    }

    /// The first custom request header named `prefix`, or [`None`].
    ///
    /// [`checkheaders`] over `data->set.headers`; the free function is what a
    /// protocol module calls when it has the list but no [`Transfer`].
    pub(crate) fn checkheaders(&self, prefix: &str) -> Option<&str> {
        checkheaders(&self.settings.headers, prefix)
    }
}

// `Curl_pretransfer`: once per operation, before anything else

#[allow(dead_code)] // consumers: the driver here, crate::easy
impl Transfer {
    /// `Curl_pretransfer(data)` (`lib/transfer.c:447-609`): initialise the
    /// operation.
    ///
    /// Called ONCE for one transfer *"no matter if it has redirects or do multi
    /// pass authentication etc"* -- the C's own comment (`:443-445`) -- which is
    /// what makes it the right place to reset the retry count, the redirect
    /// count and the request count, and the wrong place for anything a redirect
    /// must repeat.
    ///
    /// The C's order is preserved exactly, including where a failure stops the
    /// sequence: the five service calls are chained through `if(!result)`, so
    /// the FIRST error wins and the rest do not run.
    ///
    /// # Two C mechanisms are deliberately absent
    ///
    /// `signal(SIGPIPE, SIG_IGN)` (`:535-541`) is not ported. AAP section 0.4.1
    /// removes it: `crate::conn`'s transport writes with `MSG_NOSIGNAL`
    /// semantics on every target in the matrix, so there is no disposition to
    /// save -- and `multi_posttransfer`, whose whole body is the restore
    /// (`lib/multi.c:1853-1862`), therefore has nothing to do either. The
    /// option still round-trips through [`TransferSettings::no_signal`].
    ///
    /// `Curl_bufref_set(&data->state.url, ...)` (`:478`) becomes an owned
    /// [`String`]: the C's `bufref` borrows `data->set.str[STRING_SET_URL]`
    /// without copying and relies on the setting outliving the transfer, which
    /// is exactly the aliasing an owned string removes.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::UrlMalformat`] with `No URL set` when neither
    ///   `CURLOPT_URL` nor `CURLOPT_CURLU` supplies a URL, and when the handle
    ///   supplies one that cannot be read back;
    /// * [`CURLcode::BadFunctionArgument`] with `cannot mix POSTFIELDS with
    ///   RESUME_FROM`;
    /// * whatever the cookie, resolve, HSTS or wildcard service reports.
    pub(crate) fn pretransfer(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<()> {
        // `:451-457`. The C's comment is worth keeping whole: without this
        // reset, "when the connection drops, it will not enter the retry
        // mechanism on CONN_MAX_RETRIES + 1 attempts and will immediately throw
        // 'Connection died, tried CONN_MAX_RETRIES times before giving up'".
        self.state.retrycount = 0;

        // `:459-463`.
        if self.settings.url.is_none() && !self.settings.has_url_handle {
            io.request_io().failf(format_args!("No URL set"));
            return Err(CURLcode::UrlMalformat);
        }

        // `:465-476`: "CURLOPT_CURLU overrides CURLOPT_URL and the contents of
        // the CURLU handle is allowed to be changed by the user between
        // transfers". The C frees the string setting first and then overwrites
        // it, so the handle wins even when both are set.
        if self.settings.has_url_handle {
            match io.url_from_handle() {
                Some(Ok(url)) => self.settings.url = Some(url),
                // `:472-475`: any `CURLUcode` becomes the same refusal, which
                // is why the seam's error type carries no detail here.
                Some(Err(_)) | None => {
                    io.request_io().failf(format_args!("No URL set"));
                    return Err(CURLcode::UrlMalformat);
                }
            }
        }

        // `:478`.
        self.state.url = self.settings.url.clone();

        // `:480-484`.
        if self.settings.postfields.is_some() && self.settings.set_resume_from {
            io.request_io()
                .failf(format_args!("cannot mix POSTFIELDS with RESUME_FROM"));
            return Err(CURLcode::BadFunctionArgument);
        }

        // `:486-490`.
        self.state.prefer_ascii = self.settings.prefer_ascii;
        // `:487-489` is `#ifdef CURL_LIST_ONLY_PROTOCOL`, which is defined when
        // a list-capable scheme is compiled in. Of those, only FTP is in scope.
        #[cfg(feature = "ftp")]
        {
            self.state.list_only = self.settings.list_only;
        }
        self.state.httpreq = self.settings.method;

        // `:492-495`. `FollowState::pretransfer` covers all four of the C's
        // assignments here plus `allow_port`, which the C sets later at `:533`.
        // Moving it earlier is unobservable: nothing between the two points
        // reads it, and every path between them either continues to `:533` or
        // abandons the transfer.
        self.state.follow.pretransfer();
        self.state.errorbuf = false;

        // `:496-498`, the C's `#ifndef CURL_DISABLE_HTTP`.
        self.state.http_neg = io.http_neg_init();

        // `:499-503`.
        self.state.authproblem = false;
        self.state.authhost.want = self.settings.httpauth;
        self.state.authproxy.want = self.settings.proxyauth;
        self.state.follow.wouldredirect = None;
        io.priority_clear_state();

        // `:505-514`: the upload size, in the C's three cases.
        self.state.infilesize = self.derive_infilesize();

        // `:516-519`. From here the C chains every step through `if(!result)`,
        // so the first failure is the one reported and the rest do not run.
        let mut result = io.cookie_loadfiles();
        if result.is_ok() {
            io.cookie_run();
        }

        // `:521-523`.
        if result.is_ok() && io.has_resolve_list() {
            result = io.load_host_pairs();
        }

        // `:525-527`.
        if result.is_ok() {
            result = io.hsts_loadfiles();
        }

        // `:529-573`.
        if result.is_ok() {
            // `:530-533`: "Allow data->set.use_port to set which port to use.
            // This needs to be disabled for example when we follow Location:
            // headers to URLs using different ports!"
            self.state.follow.allow_port = true;

            // `:543-545`.
            io.init_info();
            let now = io.request_io().pgrs_now();
            let progress = io.request_io().progress_mut();
            progress.reset_transfer_sizes();
            progress.start_now(now);

            // `:547-551`.
            self.state.authhost.intersect_picked_with_want();
            self.state.authproxy.intersect_picked_with_want();

            // `:553-571`, the C's `#ifndef CURL_DISABLE_FTP`.
            result = self.pretransfer_wildcard(io);

            // `:572`.
            if result.is_ok() {
                result = io.hsts_loadcb();
            }
        }

        // `:575-586`. The bytes are frozen: `curl_maprintf("User-Agent:
        // %s\r\n", ...)`, terminator included, spliced into the request as-is
        // by the HTTP layer. The C's comment says why it is not protocol-gated:
        // "since we can attempt to tunnel basically anything through an HTTP
        // proxy we cannot limit this based on protocol".
        if result.is_ok() {
            if let Some(agent) = self.settings.useragent.as_deref() {
                self.state.uagent = Some(format!("User-Agent: {agent}\r\n"));
            }
        }

        // `:588-604`.
        if self.settings.username.is_some() || self.settings.password.is_some()
        {
            self.state.creds_from = CredsSource::Option;
        }
        if result.is_ok() {
            self.state.aptr_user = self.settings.username.clone();
            self.state.aptr_passwd = self.settings.password.clone();
            self.state.aptr_proxyuser = self.settings.proxyusername.clone();
            self.state.aptr_proxypasswd = self.settings.proxypassword.clone();
        }

        // `:606-608`.
        self.req.headerbytecount = 0;
        io.headers_cleanup();
        self.pretransfer_done = true;
        result
    }

    /// `data->state.infilesize`'s derivation (`lib/transfer.c:505-514`).
    ///
    /// Three cases, and the middle one has a sub-case:
    ///
    /// * `PUT` takes `CURLOPT_INFILESIZE` verbatim, whatever it is -- including
    ///   -1, which means "unknown" and makes the upload chunked;
    /// * anything that is neither `GET` nor `HEAD` takes
    ///   `CURLOPT_POSTFIELDSIZE`, and when that is -1 AND in-memory post fields
    ///   are set, the LENGTH of those bytes;
    /// * `GET` and `HEAD` send nothing, so zero.
    ///
    /// The C measures with `strlen(data->set.postfields)`, which stops at the
    /// first NUL byte; this measures the stored slice, which does not. The
    /// difference is unreachable: `CURLOPT_POSTFIELDS` with embedded NULs
    /// REQUIRES `CURLOPT_POSTFIELDSIZE` -- its manual says so -- and with the
    /// size set this branch is not taken.
    fn derive_infilesize(&self) -> i64 {
        match self.settings.method {
            HttpRequestKind::Put => self.settings.filesize,
            HttpRequestKind::Get | HttpRequestKind::Head => 0,
            HttpRequestKind::Post
            | HttpRequestKind::PostForm
            | HttpRequestKind::PostMime => {
                let size = self.settings.postfieldsize;
                match self.settings.postfields.as_deref() {
                    Some(bytes) if size == -1 => bytes.len() as i64,
                    _ => size,
                }
            }
        }
    }

    /// The FTP wildcard half of pretransfer (`lib/transfer.c:553-571`).
    ///
    /// The C allocates `data->wildcard` on demand and then, `if(wc->state <
    /// CURLWC_INIT)`, releases the previous match's pattern and path and
    /// re-initialises. Here the stage lives in [`TransferState::wildcard`] and
    /// the release plus initialise is [`TransferIo::wildcard_init`], because
    /// what it frees -- the FTP list parser's own state -- belongs to the
    /// protocol module.
    ///
    /// # Errors
    ///
    /// Whatever the initialiser reports; the C's own failure here is
    /// [`CURLcode::OutOfMemory`].
    fn pretransfer_wildcard(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<()> {
        #[cfg(feature = "ftp")]
        {
            self.state.wildcardmatch = self.settings.wildcard_enabled;
            if self.state.wildcardmatch
                && self.state.wildcard < WildcardStage::Init
            {
                io.wildcard_init()?;
                self.state.wildcard = WildcardStage::Init;
            }
            Ok(())
        }
        #[cfg(not(feature = "ftp"))]
        {
            // Without FTP the C compiles the block out entirely, so the stage
            // stays where it was and no initialiser runs.
            let _ = io;
            Ok(())
        }
    }
}

// `Curl_retry_request`: was that a dead reused connection?

#[allow(dead_code)] // consumers: the driver here
impl Transfer {
    /// `Curl_retry_request(data, &url)` (`lib/transfer.c:614-677`): decide
    /// whether this request should be reissued on a fresh connection, and on
    /// which URL.
    ///
    /// `Ok(Some(url))` means retry with `url`; `Ok(None)` means do not. The C
    /// signals the same two outcomes through an out-parameter it documents with
    /// *"Returns CURLE_OK **and** sets '\*url' if a request retry is
    /// wanted"* (`:611`), which is a shape an [`Option`] states instead.
    ///
    /// # The three conditions, and why each is narrow
    ///
    /// 1. An UPLOAD on a scheme that is neither HTTP nor RTSP is never retried
    ///    (`:623-625`). The C's reason: over HTTP an upload still gets a
    ///    response, so a silent connection death is detectable; over FTP it is
    ///    not, and reissuing would send the body twice.
    /// 2. A REUSED connection that delivered nothing -- `bytecount +
    ///    headerbytecount == 0` -- is retried when a body was expected and the
    ///    request is unfinished, or unconditionally for the HTTP family
    ///    (`:627-642`). The C's reason: the server may have closed an idle
    ///    connection between the pool handing it out and the request reaching
    ///    it. `RTSPREQ_RECEIVE` is excluded because it is a server-driven
    ///    stream rather than a request.
    /// 3. A `REFUSED_STREAM` is retried, and ONLY when nothing arrived
    ///    (`:643-653`). The C's reason is worth keeping: the code *"can
    ///    typically only happen on HTTP/2 level if the stream is safe to issue
    ///    again, but the nghttp2 API can deliver the message to other streams
    ///    as well, which is why this adds the check the data counters too"*.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] when the retry allowance is exhausted, with the
    /// C's `Connection died, tried %d times before giving up` -- and note that
    /// the count is reset to zero on that path, so the NEXT operation on the
    /// handle starts fresh.
    pub(crate) fn retry_request(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<Option<String>> {
        let Some(scheme) = io.scheme() else {
            // No connection means nothing to retry. The C dereferences
            // `data->conn` unconditionally here, and reaches this function only
            // from states that guarantee one.
            return Ok(None);
        };

        // `:620-625`.
        let http_or_rtsp = scheme
            .protocol
            .intersects(Proto::FAMILY_HTTP.union(Proto::RTSP));
        if self.state.upload && !http_or_rtsp {
            return Ok(None);
        }

        let nothing_received =
            self.req.bytecount + i64::from(self.req.headerbytecount) == 0;
        let http_family = scheme.protocol.intersects(Proto::FAMILY_HTTP);

        // `:627-634`.
        let mut retry = io.conn_is_reused()
            && nothing_received
            && ((!self.req.no_body && !self.req.done) || http_family)
            && !self.settings.rtsp_receive;

        // `:643-653`. `else if`, so a connection that already qualifies does
        // not consume the refused-stream flag.
        if !retry && self.state.refused_stream && nothing_received {
            io.request_io().infof(format_args!(
                "REFUSED_STREAM, retrying a fresh connect"
            ));
            self.state.refused_stream = false;
            retry = true;
        }

        if !retry {
            return Ok(None);
        }

        // `:655-661`. The post-increment is the C's: the FIRST call sees zero,
        // compares it against five, and leaves one behind -- so five retries
        // happen and the sixth attempt gives up.
        let attempted = self.state.retrycount;
        self.state.retrycount += 1;
        if attempted >= CONN_MAX_RETRIES {
            io.request_io().failf(format_args!(
                "Connection died, tried {CONN_MAX_RETRIES} times before giving up"
            ));
            self.state.retrycount = 0;
            return Err(CURLcode::SendError);
        }

        // `:662-663`. The count reported is the INCREMENTED one, so the first
        // retry logs 1.
        io.request_io().infof(format_args!(
            "Connection died, retrying a fresh connect (retry count: {})",
            self.state.retrycount
        ));

        // `:664-666`. The C duplicates `data->state.url` and answers
        // `CURLE_OUT_OF_MEMORY` when the duplication fails; a `clone` of an
        // owned string aborts instead, which is Rust's allocation contract and
        // not a behaviour this file can choose.
        let url = self.state.url.clone().ok_or(CURLcode::OutOfMemory)?;

        // `:668-674`.
        io.conn_close("retry");
        io.conn_mark_retry();
        io.client_reader_set_rewind(true);
        Ok(Some(url))
    }
}

// `xfer_setup` and the shutdown flags: which channels this transfer uses

#[allow(dead_code)] // consumers: crate::protocols, which sets a transfer up
impl Transfer {
    /// `xfer_setup(data, send_idx, recv_idx, recv_size)`
    /// (`lib/transfer.c:679-725`): tell the transfer which channels to use.
    ///
    /// The four wrappers below are the C's four entry points and are what a
    /// protocol module calls; this is the shared body. Everything it does is
    /// the C's, in order:
    ///
    /// 1. the two channel indexes are stored on the connection;
    /// 2. `req.size` takes `recv_size`, so -1 stays "unknown";
    /// 3. `req.header` becomes [`TransferIo::writes_response_headers`], which
    ///    is the C's `!!conn->scheme->run->write_resp_hd`;
    /// 4. both shutdown flags are cleared, because *"by default, we do not
    ///    shutdown at the end of the transfer"* (`:703`);
    /// 5. the download size is published ONLY when no response headers are
    ///    expected and the size is positive (`:710-711`) -- with headers the
    ///    real body length is not known yet, and publishing `recv_size` would
    ///    make the progress meter count header bytes towards the body;
    /// 6. `KEEP_RECV` and `KEEP_SEND` are set only when the transfer wants
    ///    headers or a body at all, and only for a channel that exists
    ///    (`:713-721`).
    ///
    /// # The C's three assertions
    ///
    /// `DEBUGASSERT((send_idx <= 1) && (send_idx >= -1))` and its twin for
    /// `recv_idx` (`:691-692`) are unrepresentable here: [`ChannelIndex`] has
    /// three values. The third, *"if request wants to send, switching off the
    /// send direction is wrong"* (`:693-694`), and the fourth, *"without
    /// receiving, there should be not recv_size"* (`:699-700`), are conditions
    /// on the ARGUMENTS rather than on their types, and they are checked with
    /// [`debug_assert!`] -- which is the C's `DEBUGASSERT` exactly: active in a
    /// debug build, compiled out of a release one.
    pub(crate) fn xfer_setup(
        &mut self,
        io: &mut dyn TransferIo,
        send: ChannelIndex,
        recv: ChannelIndex,
        recv_size: i64,
    ) {
        // `:693-694`.
        debug_assert!(
            send.is_valid() || !self.req.want_send(io.request_io_ref()),
            "xfer_setup: the request wants to send, so the send direction must \
             not be switched off (lib/transfer.c:693-694)"
        );
        // `:699-700`.
        debug_assert!(
            recv.is_valid() || recv_size == -1,
            "xfer_setup: without receiving there should be no recv_size \
             (lib/transfer.c:699-700)"
        );

        // `:696-697`.
        self.send_channel = send;
        self.recv_channel = recv;

        // `:701-705`.
        self.req.size = recv_size;
        self.req.header = io.writes_response_headers();
        self.req.shutdown = false;
        self.req.shutdown_err_ignore = false;

        // `:707-711`. The C's comment explains the placement: "The code
        // sequence below is placed in this function just because all necessary
        // input is not always known in do_complete() as this function may be
        // called after that".
        if !self.req.header && recv_size > 0 {
            io.request_io().progress_mut().set_download_size(recv_size);
        }

        // `:713-721`: "we want header and/or body, if neither then do not do
        // this!"
        if io.writes_response_headers() || !self.req.no_body {
            if recv.is_valid() {
                self.req.keep_on(KeepFlags::RECV);
            }
            if send.is_valid() {
                self.req.keep_on(KeepFlags::SEND);
            }
        }

        io.trace_multi(format_args!(
            "xfer_setup: recv_idx={}, send_idx={}",
            recv.as_i32(),
            send.as_i32()
        ));
    }

    /// `Curl_xfer_setup_nop(data)` (`lib/transfer.c:727-730`): the transfer
    /// neither sends nor receives.
    pub(crate) fn xfer_setup_nop(&mut self, io: &mut dyn TransferIo) {
        self.xfer_setup(io, ChannelIndex::None, ChannelIndex::None, -1);
    }

    /// `Curl_xfer_setup_send(data, sockindex)` (`lib/transfer.c:739-743`): the
    /// transfer sends on `channel` and receives nothing.
    pub(crate) fn xfer_setup_send(
        &mut self,
        io: &mut dyn TransferIo,
        channel: SocketIndex,
    ) {
        self.xfer_setup(io, ChannelIndex::of(channel), ChannelIndex::None, -1);
    }

    /// `Curl_xfer_setup_recv(data, sockindex, recv_size)`
    /// (`lib/transfer.c:745-750`): the transfer receives `recv_size` bytes on
    /// `channel`, or an unknown number when it is -1, and sends nothing.
    pub(crate) fn xfer_setup_recv(
        &mut self,
        io: &mut dyn TransferIo,
        channel: SocketIndex,
        recv_size: i64,
    ) {
        self.xfer_setup(
            io,
            ChannelIndex::None,
            ChannelIndex::of(channel),
            recv_size,
        );
    }

    /// `Curl_xfer_setup_sendrecv(data, sockindex, recv_size)`
    /// (`lib/transfer.c:732-737`): the transfer uses ONE channel for both
    /// directions.
    pub(crate) fn xfer_setup_sendrecv(
        &mut self,
        io: &mut dyn TransferIo,
        channel: SocketIndex,
        recv_size: i64,
    ) {
        let index = ChannelIndex::of(channel);
        self.xfer_setup(io, index, index, recv_size);
    }

    /// `Curl_xfer_set_shutdown(data, shutdown, ignore_errors)`
    /// (`lib/transfer.c:752-761`): shut the connection down when this transfer
    /// ends.
    ///
    /// Must be called AFTER an `xfer_setup`, which clears both flags. The C
    /// asserts the one-direction rule -- *"Shutdown should only be set when the
    /// transfer only sends or receives"* (`:756-758`) -- and so does this: a
    /// transfer using both directions has no unambiguous moment at which the
    /// connection is finished with.
    ///
    /// `ignore_errors` is carried separately because it is read at a different
    /// time and by different code: [`SingleRequest::flush`] consults it when a
    /// shutdown fails, and a failure there must not fail a transfer whose data
    /// has already been delivered.
    pub(crate) fn xfer_set_shutdown(
        &mut self,
        shutdown: bool,
        ignore_errors: bool,
    ) {
        debug_assert!(
            !shutdown
                || !self.send_channel.is_valid()
                || !self.recv_channel.is_valid(),
            "xfer_set_shutdown: shutdown is only for a transfer that sends or \
             receives, not both (lib/transfer.c:756-758)"
        );
        self.req.shutdown = shutdown;
        self.req.shutdown_err_ignore = ignore_errors;
    }

    /// `data->conn->send_idx`: the channel this transfer sends on.
    pub(crate) const fn send_channel(&self) -> ChannelIndex {
        self.send_channel
    }

    /// `data->conn->recv_idx`: the channel this transfer receives on.
    pub(crate) const fn recv_channel(&self) -> ChannelIndex {
        self.recv_channel
    }
}

// The raw transport: `Curl_xfer_send`, `Curl_xfer_recv` and their neighbours

#[allow(dead_code)] // consumers: the loop here, crate::protocols, request.rs
impl Transfer {
    /// `Curl_xfer_send(data, buf, blen, eos, &n)`
    /// (`lib/transfer.c:829-850`): offer request bytes to the connection.
    ///
    /// Two behaviours, both load-bearing:
    ///
    /// * a transport `CURLE_AGAIN` becomes `Ok(0)` (`:840-843`). A blocked send
    ///   is not a failure, and the caller distinguishes it by the count rather
    ///   than by a code -- which is why [`request::RequestIo::xfer_send`]
    ///   documents that it never reports [`CURLcode::Again`];
    /// * `info.request_size` grows by what was ACTUALLY written (`:844-845`),
    ///   never by what was offered. A partial send must not inflate
    ///   `CURLINFO_REQUEST_SIZE`.
    ///
    /// The debug line's shape is the C's exactly --
    /// `Curl_xfer_send(len=%zu, eos=%d) -> %d, %zu` (`:847-848`) -- with `eos`
    /// and the code rendered as the integers `%d` produces for a C `bool` and a
    /// `CURLcode`.
    ///
    /// # Errors
    ///
    /// Any transport failure other than [`CURLcode::Again`], and
    /// [`CURLcode::FailedInit`] when the transfer has no send channel, which is
    /// the code the C answers wherever it tests `data && data->conn`.
    pub(crate) fn xfer_send(
        &mut self,
        io: &mut dyn TransferIo,
        buf: &[u8],
        eos: bool,
    ) -> CodeResult<usize> {
        // `Curl_conn_send` validates the index and answers
        // `CURLE_BAD_FUNCTION_ARGUMENT` for `-1` (`lib/cfilters.c:1084-1085`).
        // Reaching that answer WITHOUT calling the filter chain keeps the trace
        // line below on every path, which is where the C emits it.
        let outcome = match self.send_channel.channel() {
            Some(channel) => io.conn_send(channel, buf, eos),
            None => Err(CURLcode::BadFunctionArgument),
        };
        let (result, written) = match outcome {
            // `:840-843`.
            Err(CURLcode::Again) => (CURLcode::Ok, 0),
            Err(code) => (code, 0),
            // `:844-845`.
            Ok(written) => {
                if written > 0 {
                    self.info.request_size += written as i64;
                }
                (CURLcode::Ok, written)
            }
        };

        io.request_io().trace(format_args!(
            "Curl_xfer_send(len={}, eos={}) -> {}, {}",
            buf.len(),
            i32::from(eos),
            result.as_i32(),
            written
        ));

        if result == CURLcode::Ok {
            Ok(written)
        } else {
            Err(result)
        }
    }

    /// `Curl_xfer_recv(data, buf, blen, &n)` (`lib/transfer.c:852-863`):
    /// receive response bytes from the connection.
    ///
    /// The one thing it adds to the filter chain's own receive is the clamp to
    /// `CURLOPT_BUFFERSIZE` (`:860-861`), which is what makes that option
    /// govern the size of every read rather than only the buffer's allocation.
    /// The C asserts the setting is positive (`:858`); a zero here would clamp
    /// every read to nothing and stall the transfer, so it is treated as the
    /// programming error it is and reported rather than asserted.
    ///
    /// A zero-length `Ok` is END OF STREAM, never "not ready" -- see
    /// [`TransferIo::conn_recv`].
    ///
    /// # Errors
    ///
    /// Any transport failure, [`CURLcode::Again`] when nothing is ready, and
    /// [`CURLcode::BadFunctionArgument`] when there is no receive channel --
    /// which is what `Curl_conn_recv` answers for an index of `-1`
    /// (`lib/cfilters.c:1067-1068`).
    ///
    /// # Panics
    ///
    /// In a debug build, when `CURLOPT_BUFFERSIZE` is zero. That is the C's
    /// `DEBUGASSERT(data->set.buffer_size > 0)` (`:858`) exactly: a release
    /// build proceeds, and the clamp below then reads nothing -- which the loop
    /// would read as an end of stream. The assertion is where that is caught.
    pub(crate) fn xfer_recv(
        &mut self,
        io: &mut dyn TransferIo,
        buf: &mut [u8],
    ) -> CodeResult<usize> {
        let Some(channel) = self.recv_channel.channel() else {
            return Err(CURLcode::BadFunctionArgument);
        };
        debug_assert!(
            self.settings.buffer_size > 0,
            "Curl_xfer_recv: CURLOPT_BUFFERSIZE must be positive \
             (lib/transfer.c:858)"
        );

        // `:860-861`.
        let want = buf.len().min(self.settings.buffer_size);
        io.conn_recv(channel, &mut buf[..want])
    }

    /// `Curl_xfer_needs_flush(data)` (`lib/transfer.c:819-822`): the connection
    /// is holding request bytes that have not reached the wire.
    pub(crate) fn xfer_needs_flush(&self, io: &mut dyn TransferIo) -> bool {
        match self.send_channel.channel() {
            Some(channel) => io.conn_needs_flush(channel),
            None => false,
        }
    }

    /// `Curl_xfer_flush(data)` (`lib/transfer.c:824-827`): push them.
    ///
    /// # Errors
    ///
    /// Any transport failure, [`CURLcode::Again`] when the flush could not
    /// complete, and [`CURLcode::BadFunctionArgument`] with no send channel --
    /// `Curl_conn_flush`'s own answer for an invalid index
    /// (`lib/cfilters.c:967-968`).
    pub(crate) fn xfer_flush(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<()> {
        let Some(channel) = self.send_channel.channel() else {
            return Err(CURLcode::BadFunctionArgument);
        };
        io.conn_flush(channel)
    }

    /// `Curl_xfer_send_close(data)` (`lib/transfer.c:865-869`): the request body
    /// is complete.
    ///
    /// The C's body is one event and an unconditional `CURLE_OK`; the signature
    /// returns a code because [`request::RequestIo::xfer_send_close`] does, and
    /// a filter that fails while flushing its last bytes has somewhere to say
    /// so.
    ///
    /// # Errors
    ///
    /// Whatever the filter chain reports for the event.
    pub(crate) fn xfer_send_close(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<()> {
        io.ev_data_done_send();
        Ok(())
    }

    /// `Curl_xfer_send_shutdown(data, &done)` (`lib/transfer.c:160-165`): begin
    /// or advance a graceful close of the SEND direction.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] with no CONNECTION -- the C's `if(!data ||
    /// !data->conn) return CURLE_FAILED_INIT` (`:162-163`) --
    /// [`CURLcode::BadFunctionArgument`] with a connection but no send channel,
    /// which is `Curl_conn_shutdown`'s answer for an invalid index
    /// (`lib/cfilters.c:165-166`), and whatever the filter chain reports.
    pub(crate) fn xfer_send_shutdown(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<AsyncStep> {
        if !io.has_connection() {
            return Err(CURLcode::FailedInit);
        }
        let Some(channel) = self.send_channel.channel() else {
            return Err(CURLcode::BadFunctionArgument);
        };
        io.conn_shutdown(channel)
    }

    /// `xfer_recv_shutdown(data, &done)` (`lib/transfer.c:146-151`): the same
    /// for the RECEIVE direction.
    ///
    /// # Errors
    ///
    /// As [`Self::xfer_send_shutdown`].
    fn xfer_recv_shutdown(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<AsyncStep> {
        if !io.has_connection() {
            return Err(CURLcode::FailedInit);
        }
        let Some(channel) = self.recv_channel.channel() else {
            return Err(CURLcode::BadFunctionArgument);
        };
        io.conn_shutdown(channel)
    }

    /// `xfer_recv_shutdown_started(data)` (`lib/transfer.c:153-158`): whether a
    /// graceful close of the receive direction is already under way.
    fn xfer_recv_shutdown_started(&self, io: &mut dyn TransferIo) -> bool {
        match self.recv_channel.channel() {
            Some(channel) => io.conn_shutdown_started(channel),
            None => false,
        }
    }
}

// Response bytes on their way to the application

#[allow(dead_code)] // consumers: the loop here and crate::protocols
impl Transfer {
    /// `Curl_xfer_write_resp(data, buf, blen, is_eos)`
    /// (`lib/transfer.c:763-793`): hand raw response bytes to the writer chain,
    /// giving the protocol first refusal.
    ///
    /// The C tests `if(data->conn->scheme->run->write_resp)` and, when the slot
    /// is filled, lets the protocol take *"full responsibility for writing all
    /// received download data to the client"*. Rust cannot test a defaulted
    /// method for a `NULL`, so [`crate::protocols::Protocol::write_resp`]
    /// returns whether it CONSUMED the bytes, and its default answers `false` --
    /// which is the same decision, made by the callee instead of the caller.
    ///
    /// Two rules survive verbatim:
    ///
    /// * the generic path writes nothing when there is nothing to write and no
    ///   end of stream to announce -- `if(blen || is_eos)` (`:777`) -- so a
    ///   zero-length write never reaches the application's callback by
    ///   accident;
    /// * a SUCCESSFUL end of stream marks both `eos_written` and
    ///   `download_done` (`:785-789`), whichever path wrote it. The C's comment
    ///   is *"If we wrote the EOS, we are definitely done"*.
    ///
    /// The trace line is the C's -- `xfer_write_resp(len=%zu, eos=%d) -> %d`
    /// (`:790-791`) -- and is emitted on every path, failures included.
    ///
    /// # Errors
    ///
    /// Whatever the protocol hook or the writer chain reports.
    pub(crate) async fn xfer_write_resp(
        &mut self,
        io: &mut dyn TransferIo,
        buf: &[u8],
        is_eos: bool,
    ) -> CodeResult<()> {
        let result = self.write_resp_inner(io, buf, is_eos).await;

        // `:785-789`.
        if result.is_ok() && is_eos {
            self.req.eos_written = true;
            self.req.download_done = true;
        }

        // `:790-791`. `%d` on a `CURLcode` is its integer, and 0 on success.
        let code = match result {
            Ok(()) => CURLcode::Ok,
            Err(code) => code,
        };
        io.trace_write(format_args!(
            "xfer_write_resp(len={}, eos={}) -> {}",
            buf.len(),
            i32::from(is_eos),
            code.as_i32()
        ));
        result
    }

    /// The protocol-first-refusal half of [`Self::xfer_write_resp`]
    /// (`lib/transfer.c:769-783`).
    ///
    /// Separated so that the two post-conditions -- the end-of-stream marks and
    /// the trace line -- are written once and cannot be skipped by an early
    /// return.
    async fn write_resp_inner(
        &mut self,
        io: &mut dyn TransferIo,
        buf: &[u8],
        is_eos: bool,
    ) -> CodeResult<()> {
        // `:769-773`.
        if let Some(protocol) = io.protocol() {
            let mut ctx = io.xfer_ctx()?;
            if protocol.write_resp(&mut ctx, buf, is_eos).await? {
                return Ok(());
            }
        }

        // `:774-783`.
        if !buf.is_empty() || is_eos {
            let mut flags = ClientWriteFlags::BODY;
            if is_eos {
                flags = flags.union(ClientWriteFlags::EOS);
            }
            io.client_write(flags, buf)?;
        }
        Ok(())
    }

    /// `Curl_xfer_write_resp_hd(data, hd, hdlen, is_eos)`
    /// (`lib/transfer.c:800-811`): hand ONE response header line to the writer
    /// chain.
    ///
    /// The protocol hook is offered the line first, exactly as for a body write,
    /// and the fallback is the ordinary response path -- the C's
    /// `Curl_xfer_write_resp(data, hd0, hdlen, is_eos)` (`:810`). The bytes are
    /// passed through untouched, terminator and all: the C asserts the caller
    /// supplied a NUL-terminated line (`:804`) and this file takes the slice
    /// the caller gave it, which is the same contract without the terminator.
    ///
    /// # Errors
    ///
    /// Whatever the hook or the writer chain reports.
    pub(crate) async fn xfer_write_resp_hd(
        &mut self,
        io: &mut dyn TransferIo,
        hd: &[u8],
        is_eos: bool,
    ) -> CodeResult<()> {
        // `:803-808`.
        if io.writes_response_headers() {
            if let Some(protocol) = io.protocol() {
                let mut ctx = io.xfer_ctx()?;
                if protocol.write_resp_hd(&mut ctx, hd, is_eos).await? {
                    return Ok(());
                }
            }
        }
        // `:809-810`.
        self.xfer_write_resp(io, hd, is_eos).await
    }

    /// `Curl_xfer_write_done(data, premature)` (`lib/transfer.c:813-817`): the
    /// multi handle has set the transfer to DONE, so flush the client stage.
    ///
    /// The C's comment on the call is the reason it exists at all: *"Last chance
    /// to trigger missing response things like writing an EOS to the client"*
    /// (`lib/transfer.h:96-97`).
    ///
    /// # Errors
    ///
    /// Whatever the first failing writer stage returned.
    pub(crate) fn xfer_write_done(
        &mut self,
        io: &mut dyn TransferIo,
        premature: bool,
    ) -> CodeResult<()> {
        io.client_write_done(premature)
    }

    /// `Curl_xfer_write_is_paused(data)` (`lib/transfer.c:795-798`): the writer
    /// chain is holding response bytes back.
    pub(crate) fn xfer_write_is_paused(&self, io: &dyn TransferIo) -> bool {
        io.client_writer_is_paused()
    }
}

// Pausing: a paused direction IS a blocked rate limiter

#[allow(dead_code)] // consumers: the loop here, crate::easy's curl_easy_pause
impl Transfer {
    /// `Curl_xfer_send_is_paused(data)` (`lib/transfer.c:883-886`): the upload
    /// is paused.
    ///
    /// # Pause is not a flag of its own
    ///
    /// The C answers `Curl_rlimit_is_blocked(&data->progress.ul.rlimit)` -- the
    /// UPLOAD rate limiter's blocked bit -- and that is the whole
    /// representation: `curl_easy_pause(CURLPAUSE_SEND)` blocks the limiter and
    /// resuming unblocks it. One encoding for "not sending right now" means a
    /// paused transfer and a rate-limited transfer cannot disagree about whether
    /// the transfer may proceed, which is why [`crate::transfer::ratelimit`]
    /// carries the bit rather than this file carrying a second one.
    pub(crate) fn xfer_send_is_paused(&self, io: &dyn TransferIo) -> bool {
        io.request_io_ref()
            .progress()
            .upload()
            .rlimit()
            .is_blocked()
    }

    /// `Curl_xfer_recv_is_paused(data)` (`lib/transfer.c:888-891`): the download
    /// is paused -- the DOWNLOAD limiter's blocked bit.
    pub(crate) fn xfer_recv_is_paused(&self, io: &dyn TransferIo) -> bool {
        io.request_io_ref()
            .progress()
            .download()
            .rlimit()
            .is_blocked()
    }

    /// `Curl_xfer_is_blocked(data)` (`lib/transfer.c:871-881`): the transfer is
    /// not done but cannot proceed.
    ///
    /// The C's truth table, which is not symmetric and is transcribed rather
    /// than simplified:
    ///
    /// | wants send | wants receive | blocked when |
    /// |---|---|---|
    /// | no | no | never |
    /// | no | yes | receive is paused |
    /// | yes | no | send is paused |
    /// | yes | yes | BOTH are paused |
    ///
    /// The last row is the interesting one: a bidirectional transfer with only
    /// its download paused is NOT blocked, because the upload can still make
    /// progress -- and [`Self::sendrecv`] relies on that to keep draining an
    /// upload while the application holds the response.
    pub(crate) fn xfer_is_blocked(&self, io: &dyn TransferIo) -> bool {
        let want_send = self.req.keepon().contains(KeepFlags::SEND);
        let want_recv = self.req.keepon().contains(KeepFlags::RECV);

        if !want_send {
            // `:875-876`.
            want_recv && self.xfer_recv_is_paused(io)
        } else if !want_recv {
            // `:877-878`.
            self.xfer_send_is_paused(io)
        } else {
            // `:879-880`.
            self.xfer_recv_is_paused(io) && self.xfer_send_is_paused(io)
        }
    }

    /// `Curl_xfer_pause_send(data, enable)` (`lib/transfer.c:893-901`): pause or
    /// resume the upload.
    ///
    /// Three steps, in the C's order: block or unblock the upload limiter at the
    /// injected instant; when RESUMING, unpause the reader chain if it is
    /// paused; and tell the accounting either way, because a resumed transfer's
    /// speed samples must not include the time it spent paused.
    ///
    /// # Errors
    ///
    /// Whatever the reader chain's resume reports, propagated exactly -- the C
    /// assigns it to `result` and returns it after the accounting call, so the
    /// notification happens even when the resume failed.
    pub(crate) fn xfer_pause_send(
        &mut self,
        io: &mut dyn TransferIo,
        enable: bool,
    ) -> CodeResult<()> {
        // `:896`.
        let now = io.request_io().pgrs_now();
        io.request_io()
            .progress_mut()
            .upload_mut()
            .rlimit_mut()
            .block(enable, now);

        // `:897-898`.
        let mut result = Ok(());
        if !enable && io.client_reader_is_paused() {
            result = io.client_reader_unpause();
        }

        // `:899`.
        io.request_io().progress_mut().send_pause(enable);
        result
    }

    /// `Curl_xfer_pause_recv(data, enable)` (`lib/transfer.c:903-911`): pause or
    /// resume the download.
    ///
    /// The upload form's three steps with one addition, and the addition is
    /// ordered: the connection filters are told AFTER the writer chain has
    /// replayed what it held (`:909`), so a filter that resumes reading cannot
    /// deliver new bytes ahead of the buffered ones. That order is what makes
    /// `curl_easy_pause` deliver a paused transfer's bytes in their original
    /// sequence.
    ///
    /// # Errors
    ///
    /// Whatever the writer chain's replay reports, propagated exactly -- and
    /// note that both remaining steps still run, exactly as in the C.
    pub(crate) fn xfer_pause_recv(
        &mut self,
        io: &mut dyn TransferIo,
        enable: bool,
    ) -> CodeResult<()> {
        // `:906`.
        let now = io.request_io().pgrs_now();
        io.request_io()
            .progress_mut()
            .download_mut()
            .rlimit_mut()
            .block(enable, now);

        // `:907-908`.
        let mut result = Ok(());
        if !enable && io.client_writer_is_paused() {
            result = io.client_writer_unpause();
        }

        // `:909-910`.
        io.ev_data_pause(enable);
        io.request_io().progress_mut().recv_pause(enable);
        result
    }
}

// `Curl_sendrecv`: one pass of the transfer loop

/// Why [`Transfer::sendrecv_dl`] stopped reading.
///
/// The C tracks the same three facts in three local booleans -- `is_eos`,
/// `rate_limited` and `rcvd_eagain` (`lib/transfer.c:229-230`) -- and reads all
/// three in one condition after the loop (`:314-315`). Naming the reason makes
/// that condition a `match` on a value rather than a conjunction of three
/// negations, and it is the one place where getting it wrong is invisible: a
/// transfer that forgot to mark itself dirty simply stalls until an unrelated
/// wakeup.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
enum DownloadStop {
    /// The response ended: a zero-length receive, or the synthetic end of stream
    /// the no-trailer case produces.
    EndOfStream,
    /// The download rate limiter has no tokens left.
    RateLimited,
    /// The transport reported [`CURLcode::Again`] and the loop believed it.
    WouldBlock,
    /// The loop stopped for any other reason: the budget ran out, the request
    /// finished, or the receive direction was switched off.
    Other,
}

#[allow(dead_code)] // consumers: the driver here
impl Transfer {
    /// `Curl_sendrecv(data)` (`lib/transfer.c:357-431`): one pass of the
    /// transfer loop -- receive what is ready, send what can go, then account.
    ///
    /// The order is the C's and matters: download first, upload second,
    /// accounting third, and the two completeness checks last. A pass that
    /// uploaded before draining a ready response would let a server's window
    /// fill while curl was still writing.
    ///
    /// # Errors
    ///
    /// * whatever the download or upload half reports;
    /// * [`CURLcode::OperationTimedout`] when the deadline passed with work
    ///   still outstanding, with the C's exact known-size or unknown-size line;
    /// * [`CURLcode::PartialFile`] when a known-length response ended short;
    /// * [`CURLcode::AbortedByCallback`] from either progress call.
    pub(crate) async fn sendrecv(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<()> {
        let result = self.sendrecv_inner(io).await;
        // `:428-429`.
        if let Err(code) = result {
            io.request_io()
                .trace(format_args!("Curl_sendrecv() -> {}", code.as_i32()));
            return Err(code);
        }
        Ok(())
    }

    /// The body of [`Self::sendrecv`], separated so that the C's `out:` label --
    /// which only logs -- is written once.
    async fn sendrecv_inner(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<()> {
        // `:362-365`. A fully blocked transfer does NO I/O and reports success:
        // there is nothing wrong with it, it is waiting for the application.
        if self.xfer_is_blocked(io) {
            return Ok(());
        }

        // `:367-373`. The C's comment: "We go ahead and do a read if we have a
        // readable socket or if the stream was rewound (in which case we have
        // data in a buffer)".
        if self.req.keepon().contains(KeepFlags::RECV) {
            self.sendrecv_dl(io).await?;
            if self.req.done {
                return Ok(());
            }
        }

        // `:375-380`.
        if self.req.want_send(io.request_io_ref()) {
            self.sendrecv_ul(io)?;
        }

        // `:382-384`.
        self.pgrs_check(io)?;

        if !self.req.keepon().is_empty() {
            // `:386-406`.
            if io.timeleft_ms() < 0 {
                return Err(self.report_transfer_timeout(io));
            }
        } else {
            // `:407-419`. The C's comment: "The transfer has been performed.
            // Just make some general checks before returning."
            if !self.req.no_body
                && self.req.size != -1
                && self.req.bytecount != self.req.size
                && self.req.newurl.is_none()
            {
                io.request_io().failf(format_args!(
                    "transfer closed with {} bytes remaining to read",
                    self.req.size - self.req.bytecount
                ));
                return Err(CURLcode::PartialFile);
            }
        }

        // `:421-423`.
        if self.req.keepon().is_empty() {
            self.req.done = true;
        }

        // `:425`. Only the code matters here; whether the meter would draw is
        // the caller's business, and on this path there is no caller waiting
        // for it.
        let req_done = self.req.done;
        let _ = io.pgrs_update(req_done).map_err(Error::into_code)?;
        Ok(())
    }

    /// `Curl_pgrsCheck(data)` plus the `EXPIRE_SPEEDCHECK` the C arms inside it
    /// (`lib/progress.c:166`).
    ///
    /// [`crate::transfer::progress`] cannot arm a timer -- it holds no multi
    /// handle -- so it RETURNS the request as a
    /// [`crate::transfer::progress::SpeedCheck`] and this is where the timer is
    /// armed. The meter's answer is discarded here on purpose: drawing the
    /// built-in progress bar is `curl-rs/src/output/progress.rs`'s, and the
    /// implementing owner of [`TransferIo::pgrs_check`] is what reaches it.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OperationTimedout`] with the low-speed text, or
    /// [`CURLcode::AbortedByCallback`].
    fn pgrs_check(&mut self, io: &mut dyn TransferIo) -> CodeResult<()> {
        let req_done = self.req.done;
        let check = io.pgrs_check(req_done).map_err(Error::into_code)?;
        if let Some(in_ms) = check.speedcheck.arm_ms() {
            io.scheduler().expire(in_ms, ExpireId::SpeedCheck);
        }
        Ok(())
    }

    /// The two timeout diagnostics of `Curl_sendrecv`
    /// (`lib/transfer.c:388-403`), and the code they accompany.
    ///
    /// Two lines, distinguished by whether the response length is known, and
    /// both frozen:
    ///
    /// ```text
    /// Operation timed out after %ld milliseconds with %ld out of %ld bytes received
    /// Operation timed out after %ld milliseconds with %ld bytes received
    /// ```
    ///
    /// The elapsed time is measured from `t_startsingle` -- THIS request, not the
    /// operation -- which is what makes a redirect's timeout report the time the
    /// final request took. [`Self::handle_timeout`] measures from a different
    /// origin, and the difference is the C's.
    fn report_transfer_timeout(&mut self, io: &mut dyn TransferIo) -> CURLcode {
        let now = io.request_io().pgrs_now();
        let started = io.request_io().progress().start_single();
        let elapsed = timediff_ms(now, started);

        if self.req.size != -1 {
            io.request_io().failf(format_args!(
                "Operation timed out after {elapsed} milliseconds with {} out \
                 of {} bytes received",
                self.req.bytecount, self.req.size
            ));
        } else {
            io.request_io().failf(format_args!(
                "Operation timed out after {elapsed} milliseconds with {} \
                 bytes received",
                self.req.bytecount
            ));
        }
        CURLcode::OperationTimedout
    }

    /// `sendrecv_ul(data)` (`lib/transfer.c:341-351`): send request data.
    ///
    /// The C asserts that it is never reached with the send side already
    /// finished -- and then tests the same condition anyway, with the comment
    /// *"We should not get here when the sending is already done. It probably
    /// means that someone set `data-req.keepon |= KEEP_SEND` when it should
    /// not"*. Both are preserved: the assertion documents the invariant in a
    /// debug build, and the test keeps a release build correct if it is
    /// violated.
    ///
    /// # Errors
    ///
    /// Whatever [`SingleRequest::send_more`] reports.
    fn sendrecv_ul(&mut self, io: &mut dyn TransferIo) -> CodeResult<()> {
        let done_sending = self.req.done_sending(io.request_io_ref());
        debug_assert!(
            !done_sending,
            "sendrecv_ul: reached with the send side already done \
             (lib/transfer.c:346)"
        );
        if !done_sending {
            return self.req.send_more(io.request_io());
        }
        Ok(())
    }
}

#[allow(dead_code)] // consumers: sendrecv here
impl Transfer {
    /// `sendrecv_dl(data, k)` (`lib/transfer.c:220-336`): drain whatever the
    /// connection has ready.
    ///
    /// Borrows the multi handle's shared buffer, runs the bounded loop, and
    /// gives the buffer back on EVERY path -- which is what the C's single
    /// `out:` label achieves and what makes the borrow discipline safe to
    /// express as ownership here.
    ///
    /// # Errors
    ///
    /// Whatever the receive, the writer chain or the request's stop reports.
    /// [`CURLcode::Again`] never escapes: the loop either believes it and stops,
    /// or treats it as a synthetic end of stream.
    async fn sendrecv_dl(&mut self, io: &mut dyn TransferIo) -> CodeResult<()> {
        // `:232-234`.
        let mut buffer = io.scheduler().xfer_buf_borrow()?;

        let outcome = self.download_loop(io, &mut buffer).await;

        // `:314-329`, which the C reaches only by FALLING OUT of the loop.
        // `Ok(None)` is the C's `goto out`, and it skips both blocks.
        let result = match outcome {
            Ok(Some(stop)) => {
                self.after_download_loop(io, stop);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(code) => Err(code),
        };

        // `:332`.
        io.scheduler().xfer_buf_release(buffer);

        // `:333-334`.
        if let Err(code) = result {
            io.request_io()
                .trace(format_args!("sendrecv_dl() -> {}", code.as_i32()));
            return Err(code);
        }
        Ok(())
    }

    /// The `do { ... } while(maxloops--)` of `sendrecv_dl`
    /// (`lib/transfer.c:238-312`).
    ///
    /// `Ok(Some(stop))` means the loop ended and the caller must run the two
    /// post-loop blocks; `Ok(None)` is the C's `goto out`, which skips them.
    ///
    /// # The budget is eleven passes
    ///
    /// See [`MAX_DL_LOOPS`]: the C's post-decrement in the condition gives one
    /// unconditional pass plus ten more. The loop below counts down a `u32` from
    /// [`MAX_DL_LOOPS`] and tests BEFORE decrementing, which reproduces the
    /// count exactly.
    ///
    /// # Errors
    ///
    /// Any real failure from the receive, the writer chain or
    /// [`SingleRequest::stop_send_recv`].
    async fn download_loop(
        &mut self,
        io: &mut dyn TransferIo,
        buffer: &mut [u8],
    ) -> CodeResult<Option<DownloadStop>> {
        let mut budget = MAX_DL_LOOPS;
        let mut is_multiplex = false;

        loop {
            // `:241-246`. The C's comment: "Multiplexed connection have
            // inherent handling of EOF and we do not have to carefully restrict
            // the amount we try to read. Multiplexed changes only in one
            // direction." So once true it is never re-tested.
            if !is_multiplex {
                is_multiplex = io.conn_is_multiplex(SocketIndex::First);
            }

            // `:248-249`.
            let mut want = buffer.len();

            // `:251-267`: the rate-limit clamp.
            if want > 0
                && io
                    .request_io_ref()
                    .progress()
                    .download()
                    .rlimit()
                    .is_active()
            {
                let now = io.request_io().pgrs_now();
                let available = io
                    .request_io()
                    .progress_mut()
                    .download_mut()
                    .rlimit_mut()
                    .available(now);
                // `:261-264`. The C's comment: "In case of rate limited
                // downloads: if this loop already got data and less than 16k is
                // left in the limit, break out. We want to stutter a bit to
                // keep in the limit, but too small receives will just cost cpu
                // unnecessarily."
                if available <= 0 {
                    return Ok(Some(DownloadStop::RateLimited));
                }
                if available < want as i64 {
                    // The cast is exact: `available` is positive and below
                    // `want`, which is a `usize`.
                    want = available as usize;
                }
            }

            // `:269-285`. The C's `rcvd_eagain` is cleared here on every pass
            // and read once, after the loop; that reading is
            // [`DownloadStop::WouldBlock`], so the flag itself is not needed --
            // the only path that would set it returns that variant at once.
            let received = match self.xfer_recv_resp(
                io,
                &mut buffer[..want],
                is_multiplex,
            ) {
                Ok(received) => received,
                // `:272-273`: a real error leaves at once.
                Err(code) if code != CURLcode::Again => return Err(code),
                Err(_) => {
                    // `:276-284`. A download that is already complete, on a
                    // response with no body and no announced trailer, does
                    // not wait for an end of stream that will never arrive.
                    if self.req.download_done
                        && self.req.no_body
                        && !self.req.resp_trailer
                    {
                        io.request_io().trace(format_args!(
                            "EAGAIN, download done, no trailer announced, \
                                 not waiting for EOS"
                        ));
                        0
                    } else {
                        return Ok(Some(DownloadStop::WouldBlock));
                    }
                }
            };

            // `:287-288`. The C's comment states the invariant this rests on:
            // "We only get a 0-length receive at the end of the response".
            let is_eos = received == 0;

            if is_eos {
                // `:290-296`.
                self.req.stop_send_recv(io.request_io())?;
                // `:294-295`: "already did write this to client, leave".
                if self.req.eos_written {
                    return Ok(Some(DownloadStop::EndOfStream));
                }
            }

            // `:298-300`.
            let write =
                self.xfer_write_resp(io, &buffer[..received], is_eos).await;
            match write {
                Err(code) => return Err(code),
                Ok(()) if self.req.done => return Ok(None),
                Ok(()) => {}
            }

            // `:302-307`. The C's comment: "if we are done, we stop receiving.
            // On multiplexed connections, we should read the EOS. Which may
            // arrive as meta data after the bytes. Not taking it in might lead
            // to RST of streams."
            if (!is_multiplex && self.req.download_done) || is_eos {
                self.req.keep_off(KeepFlags::RECV);
            }

            // `:309-310`.
            if !self.req.keepon().contains(KeepFlags::RECV) {
                return Ok(Some(if is_eos {
                    DownloadStop::EndOfStream
                } else {
                    DownloadStop::Other
                }));
            }

            // `:312`: `while(maxloops--)`. The old value decides, so a budget of
            // zero ends the loop after the pass that has just run.
            if budget == 0 {
                return Ok(Some(if is_eos {
                    DownloadStop::EndOfStream
                } else {
                    DownloadStop::Other
                }));
            }
            budget -= 1;
        }
    }

    /// The two blocks after `sendrecv_dl`'s loop
    /// (`lib/transfer.c:314-329`).
    ///
    /// The first marks the transfer dirty when the loop stopped for a reason
    /// that does NOT mean "nothing more to read": the response has not ended, no
    /// rate limit is in force, the transfer still wants to receive, and either
    /// the transport never said it would block or a filter is still holding
    /// bytes. Without it a transfer with buffered data waits for a readability
    /// event that will never come, because the bytes are already in memory --
    /// which is why the C calls the mechanism *"simulated SELECT results"*.
    ///
    /// The second stops an upload that can no longer be answered: the download
    /// is finished, the send side is not, and the connection is closing or
    /// multiplexed. The C's line is `we are done reading and this is set to
    /// close, stop send`.
    fn after_download_loop(
        &mut self,
        io: &mut dyn TransferIo,
        stop: DownloadStop,
    ) {
        // `:314-320`.
        let wants_recv = self.req.keepon().contains(KeepFlags::RECV);
        let ended = matches!(
            stop,
            DownloadStop::EndOfStream | DownloadStop::RateLimited
        );
        let rcvd_eagain = matches!(stop, DownloadStop::WouldBlock);
        if !ended
            && wants_recv
            && (!rcvd_eagain || self.data_pending(io, rcvd_eagain))
        {
            io.scheduler().mark_dirty();
            io.trace_multi(format_args!(
                "sendrecv_dl() no EAGAIN/pending data, mark as dirty"
            ));
        }

        // `:322-329`. The C's comment: "When we have read the entire thing and
        // the close bit is set, the server may now close the connection. If
        // there is now any kind of sending going on from our side, we need to
        // stop that immediately."
        let send_only = self.req.keepon() == KeepFlags::SEND;
        let is_multiplex = io.conn_is_multiplex(SocketIndex::First);
        if send_only && (io.conn_wants_close() || is_multiplex) {
            io.request_io().infof(format_args!(
                "we are done reading and this is set to close, stop send"
            ));
            // `:328`. The C DISCARDS this code, and so does this: the download
            // has already succeeded, and failing it because the abandoned
            // upload could not be tidied would change the transfer's result.
            let _ = self.req.abort_sending(io.request_io());
        }
    }

    /// `data_pending(data, rcvd_eagain)` (`lib/transfer.c:102-114`): whether a
    /// filter is still holding received bytes.
    ///
    /// Three answers, by scheme family:
    ///
    /// * FTP asks the SECONDARY channel, because that is where its data
    ///   connection is and the control channel's readiness says nothing about
    ///   the body;
    /// * SCP and SFTP answer true until the transport has actually reported
    ///   [`CURLcode::Again`]. The C's comment is the reason: *"in the case of
    ///   libssh2, we can never be really sure that we have emptied its internal
    ///   buffers so we MUST always try until we get EAGAIN back"*. AAP section
    ///   0.5.2 replaces libssh2 with `russh`, and the rule is kept: a library
    ///   with its own internal buffering cannot be trusted to have none left
    ///   until it says so;
    /// * everything else asks the first channel's filters.
    fn data_pending(&self, io: &mut dyn TransferIo, rcvd_eagain: bool) -> bool {
        let Some(scheme) = io.scheme() else {
            return false;
        };

        // `:106-107`.
        if scheme.protocol.intersects(Proto::FAMILY_FTP) {
            return io.conn_data_pending(SocketIndex::Secondary);
        }

        // `:109-113`.
        let ssh = scheme.protocol.intersects(Proto::SCP.union(Proto::SFTP));
        (!rcvd_eagain && ssh) || io.conn_data_pending(SocketIndex::First)
    }

    /// `xfer_recv_resp(data, buf, blen, eos_reliable, &pnread)`
    /// (`lib/transfer.c:175-213`): one receive, with the two clamps the C
    /// applies before it.
    ///
    /// The clamps are exclusive and ordered:
    ///
    /// 1. when the transport's end-of-stream detection is NOT reliable, the
    ///    response headers are done, and the body length is known, read no more
    ///    than the body has left (`:186-188`). Reading past it would consume the
    ///    next response's bytes on a reused connection;
    /// 2. otherwise, when a graceful close of the receive direction has already
    ///    begun, read NOTHING (`:189-192`) -- the C's comment is *"we already
    ///    received everything. Do not try more."*
    ///
    /// A zero-length receive with `req.shutdown` set advances the shutdown and
    /// reports [`CURLcode::Again`] while it is pending (`:200-209`), so the
    /// caller waits rather than treating an unfinished close as the end of the
    /// response.
    ///
    /// # Errors
    ///
    /// Whatever the transport reports, and [`CURLcode::Again`] while a shutdown
    /// is still in progress.
    fn xfer_recv_resp(
        &mut self,
        io: &mut dyn TransferIo,
        buf: &mut [u8],
        eos_reliable: bool,
    ) -> CodeResult<usize> {
        // `DEBUGASSERT(blen > 0)` (`:182`).
        debug_assert!(
            !buf.is_empty(),
            "xfer_recv_resp: called with an empty buffer \
             (lib/transfer.c:182)"
        );

        // `:186-192`.
        let mut want = buf.len();
        if !eos_reliable && !self.req.header && self.req.size != -1 {
            // `curlx_sotouz_range(data->req.size - data->req.bytecount, 0,
            // blen)`: clamp the remainder into `0..=blen`.
            let remaining = self.req.size - self.req.bytecount;
            want = remaining.clamp(0, want as i64) as usize;
        } else if self.xfer_recv_shutdown_started(io) {
            want = 0;
        }

        // `:194-198`.
        let mut received = 0_usize;
        if want > 0 {
            received = self.xfer_recv(io, &mut buf[..want])?;
        }

        // `:200-211`.
        if received == 0 {
            // The C nests these; short-circuiting `&&` keeps the shutdown call
            // behind the flag exactly as the nesting did.
            if self.req.shutdown
                && self.xfer_recv_shutdown(io)? == AsyncStep::Pending
            {
                return Err(CURLcode::Again);
            }
            io.request_io()
                .trace(format_args!("sendrecv_dl: we are done"));
        }
        Ok(received)
    }
}

// The rate-limit gate: `mspeed_check`

/// Whether the rate limiters admit I/O now.
///
/// `mspeed_check` reports the same two outcomes as a [`CURLcode`] --
/// `CURLE_AGAIN` for "wait" and `CURLE_OK` for "go" (`lib/multi.c:1899` and
/// `:1921`) -- and both call sites test it as a control signal rather than as an
/// error: `state_performing` compares against `CURLE_AGAIN`
/// (`lib/multi.c:1934`) and `state_ratelimiting` writes `if(!mspeed_check(data))`
/// (`:2218`). Naming the two outcomes keeps a readiness decision out of the
/// error channel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
enum RateGate {
    /// The C's `CURLE_AGAIN`: a limiter needs an idle wait, `TOOFAST` is armed
    /// and the transfer is in `RATELIMITING`.
    Waiting,
    /// The C's `CURLE_OK`: proceed, and the transfer is in `PERFORMING`.
    Proceed,
}

#[allow(dead_code)] // consumers: the driver here
impl Transfer {
    /// `mspeed_check(data)` (`lib/multi.c:1880-1922`): consult both rate
    /// limiters and park the transfer if either needs an idle wait.
    ///
    /// Three behaviours, in the C's order:
    ///
    /// 1. when either limiter reports a wait, the transfer moves to
    ///    `RATELIMITING`, `TOOFAST` is armed for the LONGER of the two waits,
    ///    the dirty bit is cleared -- so the transfer is not run again
    ///    immediately, which would defeat the wait -- and the C's line
    ///    `[RLIMIT] waiting %ldms` is traced;
    /// 2. when neither does, the next token refill is scheduled instead, at the
    ///    SMALLER of the two non-zero times -- `CURLMIN` unless one is zero, in
    ///    which case `CURLMAX`, which is the C's idiom for "the other one"
    ///    (`:1907-1909`) -- and `[RLIMIT] next token update in %ldms` is traced.
    ///    The C's comment says why the timer is needed at all: *"when will the
    ///    rate limits increase next? The transfer needs to run again at that
    ///    time or it may stall"*;
    /// 3. either way, a transfer not already in `PERFORMING` is put there, with
    ///    `[RLIMIT] wait over, continue` traced FIRST -- so the line carries the
    ///    state it is leaving, which is how the C's trace prefix works.
    ///
    /// No wall-clock sleep and no spin: the wait is a timer the multi handle
    /// owns, and the transfer is not runnable until it fires.
    fn speed_check(&mut self, io: &mut dyn TransferIo) -> RateGate {
        // `:1882-1883`.
        let dl_active = io
            .request_io_ref()
            .progress()
            .download()
            .rlimit()
            .is_active();
        let ul_active =
            io.request_io_ref().progress().upload().rlimit().is_active();

        if dl_active || ul_active {
            // `:1885`. One reading for both limiters, which is what makes the
            // pair of waits comparable.
            let now = io.request_io().pgrs_now();
            let send_ms = io
                .request_io()
                .progress_mut()
                .upload_mut()
                .rlimit_mut()
                .wait_ms(now);
            let recv_ms = io
                .request_io()
                .progress_mut()
                .download_mut()
                .rlimit_mut()
                .wait_ms(now);

            // `:1891-1900`.
            if send_ms != 0 || recv_ms != 0 {
                let wait = send_ms.max(recv_ms);
                if self.mstate != CurlMstate::RateLimiting {
                    self.set_mstate(io, CurlMstate::RateLimiting);
                }
                io.scheduler().expire(wait, ExpireId::TooFast);
                io.scheduler().clear_dirty();
                io.trace_multi(format_args!("[RLIMIT] waiting {wait}ms"));
                return RateGate::Waiting;
            }

            // `:1901-1914`.
            let send_next = io
                .request_io_ref()
                .progress()
                .upload()
                .rlimit()
                .next_step_ms(now);
            let recv_next = io
                .request_io_ref()
                .progress()
                .download()
                .rlimit()
                .next_step_ms(now);
            if send_next != 0 || recv_next != 0 {
                let mut next_ms = send_next.min(recv_next);
                if next_ms == 0 {
                    next_ms = send_next.max(recv_next);
                }
                io.scheduler().expire(next_ms, ExpireId::TooFast);
                io.trace_multi(format_args!(
                    "[RLIMIT] next token update in {next_ms}ms"
                ));
            }
        }

        // `:1917-1920`.
        if self.mstate != CurlMstate::Performing {
            io.trace_multi(format_args!("[RLIMIT] wait over, continue"));
            self.set_mstate(io, CurlMstate::Performing);
        }
        RateGate::Proceed
    }
}

// The state machine

/// What one state's work decided.
///
/// `multi_runsingle` threads three facts out of every `case`: the [`CURLMcode`]
/// it will return, the `CURLcode` it writes to `data->result`, and a local
/// `stream_error` that the error handler reads (`lib/multi.c:2431-2436`). The
/// helpers do it through two out-parameters and a return value; this carries the
/// three together, so a state cannot set one and forget another.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
struct StateOutcome {
    /// The C's `mresult`.
    step: DriverStep,
    /// The C's `result`, which becomes `data->result`.
    result: CURLcode,
    /// The C's `stream_error`: this transfer's connection must be detached and
    /// terminated rather than returned to the pool.
    stream_error: bool,
}

impl StateOutcome {
    /// Nothing more to do now: the C's `mresult = CURLM_OK` with no error.
    const fn pending() -> Self {
        Self {
            step: DriverStep::Pending,
            result: CURLcode::Ok,
            stream_error: false,
        }
    }

    /// The C's `mresult = CURLM_CALL_MULTI_PERFORM`: the next state can run at
    /// once.
    const fn run_again() -> Self {
        Self {
            step: DriverStep::RunAgain,
            result: CURLcode::Ok,
            stream_error: false,
        }
    }

    /// A failure whose connection may still be reusable.
    const fn failed(result: CURLcode) -> Self {
        Self {
            step: DriverStep::Pending,
            result,
            stream_error: false,
        }
    }

    /// A failure that must take the connection with it -- the C's
    /// `stream_error = TRUE`.
    const fn stream_failed(result: CURLcode) -> Self {
        Self {
            step: DriverStep::Pending,
            result,
            stream_error: true,
        }
    }

    /// This outcome with `result` instead.
    const fn with_result(mut self, result: CURLcode) -> Self {
        self.result = result;
        self
    }
}

/// Bounds one pending async step by the time this transfer has left.
///
/// # What this replaces, and why it is not an addition
///
/// The C never blocks inside `multi_runsingle`. Every step it takes is
/// non-blocking: `Curl_conn_connect` writes `FALSE` through `*connected` and
/// returns, the state machine reports `CURLM_OK`, the application polls, and
/// `multi_handle_timeout` catches the deadline on the NEXT entry. The deadline
/// is therefore enforced by the poll loop's timeout, computed from
/// `Curl_timeleft_ms` and armed as `EXPIRE_TIMEOUT` in `SETUP`.
///
/// The typed steps here keep that shape exactly -- [`AsyncStep::Pending`] IS
/// `*connected == FALSE` -- so the driver's own
/// [`Transfer::handle_timeout`] remains the thing that produces the C's four
/// diagnostics, and this wrapper never gets to fire on a well-behaved
/// implementation. What it covers is the one hazard the translation
/// introduces:
/// an `.await` genuinely CAN block, and a seam whose future waits on a
/// socket that goes silent would wait past a deadline the C would have
/// enforced. `tokio::time::timeout` restores the bound, which is the same
/// substitution AAP section 0.6.9 makes for `lib/hostip.c`'s
/// `alarm()`/`sigsetjmp` pair -- there, on a blocking resolver; here, on a
/// blocking step.
///
/// # The sign convention decides whether anything is armed at all
///
/// `Curl_timeleft_ms`'s three cases (`lib/connect.c:98-101`) each mean
/// something different here:
///
/// * `0` -- *"no timeout (ie there is infinite time left)"*. Nothing is armed,
///   and no Tokio timer is touched, so a transfer without `CURLOPT_TIMEOUT` and
///   without `CURLOPT_CONNECTTIMEOUT` costs exactly what it did before.
/// * `< 0` -- already expired. Also unarmed: the driver checked this before it
///   reached any state work (`lib/multi.c:2481-2486`) and has the diagnostic,
///   so arming a zero-length timer here would only race it into a worse
///   message.
/// * `> 0` -- the bound, in milliseconds.
///
/// Note that `Curl_timeleft_ms` is already phase-aware: it returns the shutdown
/// deadline while a graceful close is in flight, the CONNECT deadline while
/// `Curl_is_connecting`, and the operation deadline afterwards
/// (`lib/connect.c:104-136`). No phase argument is needed, and none is
/// invented.
///
/// # Cancellation is safe here, and only here
///
/// Elapsing DROPS the inner future, which abandons whatever it had half-done.
/// That is sound because of what the caller does next: every state helper
/// treats a timeout as a stream error, so `posttransfer` runs, the completion
/// runs premature, the stream is closed with `Disconnect due to timeout` and
/// the connection is TERMINATED rather than pooled. There is no state left for
/// a later transfer to inherit -- which is precisely the C's own answer to a
/// timed-out connection.
///
/// Generic over the future rather than over one alias, because the eight steps
/// this bounds arrive as two: [`XferFuture`] from [`TransferIo`] and
/// [`crate::protocols::ProtoFuture`] from [`Protocol`].
///
/// # Errors
///
/// [`CURLcode::OperationTimedout`] when the bound elapses, and whatever the
/// operation itself reports otherwise.
async fn bounded<F, T>(left_ms: TimeDiff, op: F) -> CodeResult<T>
where
    F: core::future::Future<Output = CodeResult<T>>,
{
    // `0` and `< 0` both mean "do not arm"; see above.
    if left_ms <= 0 {
        return op.await;
    }
    // `mstotv` refuses only a NEGATIVE count, so this branch cannot be taken
    // for a positive one. Falling back to the unbounded await rather than
    // unwrapping keeps a future change to that function from becoming a panic.
    let Some(span) = mstotv(left_ms) else {
        return op.await;
    };

    match tokio::time::timeout(span, op).await {
        Ok(result) => result,
        // The diagnostic is NOT written here. `handle_timeout` owns the four
        // phase-specific lines, and it runs on the driver's next entry with the
        // same expired deadline, so writing one here would duplicate it.
        Err(_elapsed) => Err(CURLcode::OperationTimedout),
    }
}

#[allow(dead_code)] // consumers: run_single here
impl Transfer {
    /// `case MSTATE_SETUP` (`lib/multi.c:2501-2514`): start a new transfer.
    ///
    /// Transitional: it records the per-request timing origin, arms the two
    /// configured deadlines and falls through to `CONNECT`. The C's comment on
    /// the connect timer is the reason it is armed HERE rather than in
    /// `CONNECT`: *"Since a connection might go to pending and back to CONNECT
    /// several times before it actually takes off, we need to set the timeout
    /// once in SETUP before we enter CONNECT the first time"*.
    ///
    /// Both timers are armed only when configured, because zero means "no
    /// limit" and arming a zero-millisecond timer would expire the transfer
    /// immediately.
    fn state_setup(&mut self, io: &mut dyn TransferIo) {
        // `:2504`.
        io.request_io().pgrs_time(PgrsTimer::StartSingle);

        // `:2505-2506`.
        if self.settings.timeout_ms != 0 {
            io.scheduler()
                .expire(self.settings.timeout_ms, ExpireId::Timeout);
        }
        // `:2507-2511`.
        if self.settings.connecttimeout_ms != 0 {
            io.scheduler().expire(
                self.settings.connecttimeout_ms,
                ExpireId::ConnectTimeout,
            );
        }

        // `:2513`.
        self.set_mstate(io, CurlMstate::Connect);
    }

    /// `state_connect(multi, data, &result)` (`lib/multi.c:2275-2324`): acquire
    /// a connection.
    ///
    /// Four outcomes, and the first is not a failure: with no connection
    /// available the transfer moves to `PENDING` and its membership moves from
    /// the process set to the pending set, which is what makes
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS` a queue rather than an error. On every
    /// other outcome, including a failure, the pending queue is given a chance
    /// to run -- the C's `else process_pending_handles(data->multi)`.
    ///
    /// A new connection that can multiplex wakes the pending queue a SECOND
    /// time (`:2310-2314`), because other transfers waiting for a connection can
    /// now share this one.
    async fn state_connect(&mut self, io: &mut dyn TransferIo) -> StateOutcome {
        // `:2284`.
        let left = io.timeleft_ms();
        let outcome = match bounded(left, io.connect()).await {
            Ok(outcome) => outcome,
            Err(code) => {
                // `:2296-2297`: the pending queue runs even on failure.
                io.scheduler().process_pending_handles();
                return StateOutcome::failed(code);
            }
        };

        // `:2285-2295`.
        if outcome == ConnectOutcome::NoConnectionAvailable {
            self.set_mstate(io, CurlMstate::Pending);
            io.scheduler().park_pending();
            return StateOutcome::pending();
        }
        io.scheduler().process_pending_handles();

        match outcome {
            // `:2300-2302`.
            ConnectOutcome::Resolving => {
                self.set_mstate(io, CurlMstate::Resolving);
                StateOutcome::pending()
            }
            // `:2309-2316`.
            ConnectOutcome::Connected => {
                if !io.conn_is_reused()
                    && io.conn_is_multiplex(SocketIndex::First)
                {
                    io.scheduler().process_pending_handles();
                }
                self.set_mstate(io, CurlMstate::ProtoConnect);
                StateOutcome::run_again()
            }
            // `:2317-2319`.
            ConnectOutcome::Connecting => {
                self.set_mstate(io, CurlMstate::Connecting);
                StateOutcome::run_again()
            }
            // Handled above; repeated here because the match is exhaustive over
            // the type rather than over the cases the C happens to write.
            ConnectOutcome::NoConnectionAvailable => StateOutcome::pending(),
        }
    }

    /// `state_resolving(multi, data, &stream_error, &result)`
    /// (`lib/multi.c:2225-2273`): wait for the injected resolver.
    ///
    /// The registration reassessment happens BEFORE the resolver's answer is
    /// acted on and its failure is returned immediately, which is the C's order
    /// (`:2242-2244`). Its comment explains why it happens at all: a resolver
    /// attempt may have closed and opened sockets, and the application must be
    /// told even when the same ones are about to be used again.
    ///
    /// A resolution failure is a stream error, and the connection may already be
    /// gone -- see [`TransferIo::once_resolved`].
    ///
    /// # Errors
    ///
    /// A [`CURLMcode`] from [`TransferScheduler::assess_registrations`], which
    /// the C returns before touching the answer.
    async fn state_resolving(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> Result<StateOutcome, CURLMcode> {
        // `:2234-2236`.
        let left = io.timeleft_ms();
        let checked = bounded(left, io.resolver_check()).await;

        // `:2242-2244`.
        io.scheduler().assess_registrations()?;

        let step = match checked {
            Err(code) => return Ok(StateOutcome::stream_failed(code)),
            // `:2246`: the C tests the entry pointer, so "still resolving" is
            // success with nothing to do.
            Ok(ResolveStep::Pending) => return Ok(StateOutcome::pending()),
            Ok(ResolveStep::Resolved) => {
                let left = io.timeleft_ms();
                bounded(left, io.once_resolved()).await
            }
        };

        match step {
            // `:2252-2255`.
            Err(code) => Ok(StateOutcome::stream_failed(code)),
            // `:2256-2264`: "call again please so that we get the next socket
            // setup".
            Ok(connected) => {
                self.set_mstate(
                    io,
                    if connected.is_complete() {
                        CurlMstate::ProtoConnect
                    } else {
                        CurlMstate::Connecting
                    },
                );
                Ok(StateOutcome::run_again())
            }
        }
    }

    /// `case MSTATE_CONNECTING` (`lib/multi.c:2525-2547`): wait for the
    /// transport.
    ///
    /// Gated on the receive direction not being paused, which is easy to
    /// overlook and is deliberate: an application that paused the download
    /// before the connection came up must not have the handshake driven
    /// underneath it, because the first response bytes would arrive with nowhere
    /// to go.
    ///
    /// A successful connect wakes the pending queue when the connection is NEW
    /// and multiplexes, exactly as `CONNECT` does.
    async fn state_connecting(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> StateOutcome {
        // `:2528`.
        if self.xfer_recv_is_paused(io) {
            return StateOutcome::pending();
        }

        // `:2529`.
        let left = io.timeleft_ms();
        match bounded(left, io.conn_connect()).await {
            // `:2530-2538`.
            Ok(AsyncStep::Complete) => {
                if !io.conn_is_reused()
                    && io.conn_is_multiplex(SocketIndex::First)
                {
                    io.scheduler().process_pending_handles();
                }
                self.set_mstate(io, CurlMstate::ProtoConnect);
                StateOutcome::run_again()
            }
            // `:2546`: still connecting, nothing to report.
            Ok(AsyncStep::Pending) => StateOutcome::pending(),
            // `:2539-2545`.
            Err(code) => {
                self.posttransfer();
                let _ = self.complete(io, code, true).await;
                StateOutcome::stream_failed(code)
            }
        }
    }

    /// `case MSTATE_PROTOCONNECT` (`lib/multi.c:2549-2577`) together with
    /// `protocol_connect` (`:1818-1843`).
    ///
    /// A REUSED connection skips the protocol connect entirely and goes straight
    /// to `DO`. The C's comment explains: *"ftp seems to hang when protoconnect
    /// on reused connection since we handle PROTOCONNECT in general inside the
    /// filers, it seems wrong to restart this on a reused connection"*.
    ///
    /// Otherwise the scheme's `connect_it` runs at most ONCE per connection --
    /// `conn->bits.protoconnstart` is the guard -- and a scheme with no
    /// continuation is done however `connect_it` answered.
    async fn state_protoconnect(
        &mut self,
        io: &mut dyn TransferIo,
        carried: CURLcode,
    ) -> StateOutcome {
        // `:2550-2558`. The C tests `!result` first, where `result` is carried
        // over from a previous iteration of the driver loop; that carry is
        // preserved by taking it as an argument.
        if carried == CURLcode::Ok && io.conn_is_reused() {
            self.set_mstate(io, CurlMstate::Do);
            return StateOutcome::run_again();
        }

        // `:2559-2560`: the C attempts the connect only when nothing has failed
        // yet -- `if(!result) result = protocol_connect(...)`. A carried failure
        // therefore skips the attempt and lands in the same error arm, which is
        // why the C's last branch is a bare `else` rather than an `else if`.
        let outcome = if carried == CURLcode::Ok {
            self.protocol_connect(io).await
        } else {
            Err(carried)
        };

        match outcome {
            // `:2561-2570`.
            Ok(connected) => {
                self.set_mstate(
                    io,
                    if connected.is_complete() {
                        CurlMstate::Do
                    } else {
                        CurlMstate::ProtoConnecting
                    },
                );
                StateOutcome::run_again()
            }
            // `:2571-2576`.
            Err(code) => {
                self.posttransfer();
                let _ = self.complete(io, code, true).await;
                StateOutcome::stream_failed(code)
            }
        }
    }

    /// `protocol_connect(data, &protocol_done)` (`lib/multi.c:1818-1843`).
    ///
    /// # Errors
    ///
    /// Whatever the scheme's `connect_it` reports. Note where the C returns:
    /// `if(result) return result;` INSIDE the guard, so a failing `connect_it`
    /// leaves `protoconnstart` clear and would be attempted again if the
    /// transfer somehow returned to this state.
    async fn protocol_connect(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> CodeResult<AsyncStep> {
        let mut connected = AsyncStep::Pending;

        // `:1828-1836`.
        if !io.protoconn_started() {
            if let Some(protocol) = io.protocol() {
                let left = io.timeleft_ms();
                let mut ctx = io.xfer_ctx()?;
                connected = AsyncStep::from_done(
                    bounded(left, protocol.connect_it(&mut ctx)).await?,
                );
            }
            io.set_protoconn_started();
        }

        // `:1838-1841`: "Unless this protocol does not have any
        // protocol-connect callback, as then we know we are done."
        if !io.protocol_has_connecting() {
            connected = AsyncStep::Complete;
        }
        Ok(connected)
    }

    /// `case MSTATE_PROTOCONNECTING` (`lib/multi.c:2579-2593`) together with
    /// `protocol_connecting` (`:1778-1791`).
    ///
    /// The C resets its `done` flag to false before every call
    /// (`:1784`), so a scheme that leaves the out-parameter untouched is treated
    /// as unfinished rather than as finished -- which a returned value makes
    /// impossible to get wrong.
    async fn state_protoconnecting(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> StateOutcome {
        let connected = match io.protocol() {
            // `:1783-1786`.
            Some(protocol) => {
                let left = io.timeleft_ms();
                let ctx = io.xfer_ctx();
                match ctx {
                    Ok(mut ctx) => bounded(left, protocol.connecting(&mut ctx))
                        .await
                        .map(AsyncStep::from_done),
                    Err(code) => Err(code),
                }
            }
            // `:1787-1788`: no scheme implementation means nothing to wait for.
            None => Ok(AsyncStep::Complete),
        };

        match connected {
            // `:2582-2586`.
            Ok(AsyncStep::Complete) => {
                self.set_mstate(io, CurlMstate::Do);
                StateOutcome::run_again()
            }
            Ok(AsyncStep::Pending) => StateOutcome::pending(),
            // `:2587-2592`.
            Err(code) => {
                self.posttransfer();
                let _ = self.complete(io, code, true).await;
                StateOutcome::stream_failed(code)
            }
        }
    }

    /// `multi_posttransfer(data)` (`lib/multi.c:1853-1862`): restore what
    /// pretransfer changed.
    ///
    /// The C's whole body is the `SIGPIPE` restore, which AAP section 0.4.1
    /// removes -- see [`Self::pretransfer`]. The call SITES are kept, all
    /// fourteen of them, because they mark the exact points at which a transfer
    /// stops being able to write to its connection, and a future obligation that
    /// belongs at those points has somewhere to go. Keeping an empty function
    /// with fourteen faithful call sites is honest; deleting the calls would
    /// silently move that boundary.
    #[inline]
    fn posttransfer(&mut self) {}
}

#[allow(dead_code)] // consumers: run_single here
impl Transfer {
    /// `state_do(data, &stream_error, &result)` (`lib/multi.c:2063-2198`): issue
    /// the request.
    ///
    /// Four paths, in the C's order:
    ///
    /// 1. the pre-request callback runs first and any answer other than
    ///    [`CURL_PREREQFUNC_OK`] aborts with the C's line `operation aborted by
    ///    pre-request callback` and [`CURLcode::AbortedByCallback`];
    /// 2. a connect-only transfer that is not a WebSocket goes straight to
    ///    `DONE` -- there is no request to issue;
    /// 3. otherwise the scheme's `do_it` runs. Its readiness decides between
    ///    `DOING` (unfinished), `DOING_MORE` (finished, second half wanted) and
    ///    `DID` (finished);
    /// 4. a [`CURLcode::SendError`] on a REUSED connection is the race the retry
    ///    machinery exists for, and is retried through `SETUP` rather than
    ///    reported.
    ///
    /// The wildcard short-circuit inside path 3 is the C's: a match that has
    /// finished or is skipping this file does not enter `DOING` at all, and skips
    /// `DONE` too when the connection is already gone.
    async fn state_do(&mut self, io: &mut dyn TransferIo) -> StateOutcome {
        // `:2069-2089`.
        if let Some(answer) = io.prereq() {
            if answer != CURL_PREREQFUNC_OK {
                io.request_io().failf(format_args!(
                    "operation aborted by pre-request callback"
                ));
                let result = CURLcode::AbortedByCallback;
                self.posttransfer();
                let _ = self.complete(io, result, false).await;
                return StateOutcome::stream_failed(result);
            }
        }

        // `:2091-2094`.
        if self.settings.connect_only && !self.settings.connect_only_ws {
            self.set_mstate(io, CurlMstate::Done);
            return StateOutcome::run_again();
        }

        // `:2096-2098`.
        let left = io.timeleft_ms();
        let done = match io.protocol() {
            Some(protocol) => match io.xfer_ctx() {
                Ok(mut ctx) => bounded(left, protocol.do_it(&mut ctx))
                    .await
                    .map(AsyncStep::from_done),
                Err(code) => Err(code),
            },
            // `multi_do` leaves `*done` false and answers `CURLE_OK` when the
            // slot is empty (`:1688-1691`), which no in-scope scheme does: the
            // C's own comment on the member is "MUST be set".
            None => Ok(AsyncStep::Pending),
        };

        match done {
            // `:2102-2137`.
            Ok(AsyncStep::Pending) => {
                // `:2104-2118`, the C's `#ifndef CURL_DISABLE_FTP`.
                if self.state.wildcardmatch
                    && matches!(
                        self.state.wildcard,
                        WildcardStage::Done | WildcardStage::Skip
                    )
                {
                    let _ = self.complete(io, CURLcode::Ok, false).await;
                    // `:2112-2113`: "if there is no connection left, skip the
                    // DONE state".
                    let next = if io.has_connection() {
                        CurlMstate::Done
                    } else {
                        CurlMstate::Completed
                    };
                    self.set_mstate(io, next);
                    return StateOutcome::run_again();
                }
                // `:2119-2122`.
                self.set_mstate(io, CurlMstate::Doing);
                StateOutcome::run_again()
            }
            // `:2125-2136`.
            Ok(AsyncStep::Complete) => {
                let next = if io.conn_wants_do_more() {
                    CurlMstate::DoingMore
                } else {
                    CurlMstate::Did
                };
                self.set_mstate(io, next);
                StateOutcome::run_again()
            }
            // `:2138-2186`.
            Err(CURLcode::SendError) if io.conn_is_reused() => {
                self.state_do_retry(io).await
            }
            // `:2187-2193`.
            Err(code) => {
                self.posttransfer();
                if io.has_connection() {
                    let _ = self.complete(io, code, false).await;
                }
                StateOutcome::stream_failed(code)
            }
        }
    }

    /// The `CURLE_SEND_ERROR`-on-a-reused-connection path of `state_do`
    /// (`lib/multi.c:2138-2186`).
    ///
    /// The C's comment states the case: *"In this situation, a connection that we
    /// were trying to use may have unexpectedly died. If possible, send the
    /// connection back to the CONNECT phase so we can try again."*
    ///
    /// Two details are easy to lose and are preserved:
    ///
    /// * the retry proceeds when the completion returned `CURLE_OK` OR
    ///   [`CURLcode::SendError`] (`:2163`), because a send error while tidying
    ///   up the dead connection is the very failure being retried;
    /// * with no retry URL the connection is left to the error handler --
    ///   `*stream_errorp = TRUE` (`:2183`) -- rather than reported as a new
    ///   failure.
    async fn state_do_retry(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> StateOutcome {
        let mut result = CURLcode::SendError;

        // `:2150-2155`.
        let retry_url = match self.retry_request(io) {
            Ok(url) => url,
            Err(code) => {
                // "a failure here pretty much implies an out of memory".
                self.posttransfer();
                let _ = self.complete(io, code, false).await;
                return StateOutcome::stream_failed(code);
            }
        };

        // `:2157-2158`.
        self.posttransfer();
        let done_result = self.complete(io, result, false).await;

        // `:2160-2185`.
        let Some(url) = retry_url else {
            return StateOutcome::stream_failed(result);
        };

        if done_result != CURLcode::Ok && done_result != CURLcode::SendError {
            // `:2176-2179`: "done did not return OK or SEND_ERROR".
            return StateOutcome::failed(done_result);
        }

        match self.follow(io, &url, FollowType::Retry) {
            Ok(()) => {
                self.set_mstate(io, CurlMstate::Setup);
                StateOutcome::run_again().with_result(CURLcode::Ok)
            }
            Err(code) => {
                // `:2171-2174`: "Follow failed".
                result = code;
                StateOutcome::failed(result)
            }
        }
    }

    /// `case MSTATE_DOING` (`lib/multi.c:2599-2617`) together with
    /// `protocol_doing` (`:1798-1811`).
    ///
    /// An unfinished DO phase reports nothing and stays put; a finished one
    /// chooses between `DOING_MORE` and `DID` on the same connection bit
    /// `state_do` reads, so the two paths into `DID` cannot disagree.
    async fn state_doing(&mut self, io: &mut dyn TransferIo) -> StateOutcome {
        let left = io.timeleft_ms();
        let done = match io.protocol() {
            // `:1803-1806`.
            Some(protocol) => match io.xfer_ctx() {
                Ok(mut ctx) => bounded(left, protocol.doing(&mut ctx))
                    .await
                    .map(AsyncStep::from_done),
                Err(code) => Err(code),
            },
            // `:1807-1808`.
            None => Ok(AsyncStep::Complete),
        };

        match done {
            // `:2603-2610`.
            Ok(AsyncStep::Complete) => {
                let next = if io.conn_wants_do_more() {
                    CurlMstate::DoingMore
                } else {
                    CurlMstate::Did
                };
                self.set_mstate(io, next);
                StateOutcome::run_again()
            }
            Ok(AsyncStep::Pending) => StateOutcome::pending(),
            // `:2611-2616`.
            Err(code) => {
                self.posttransfer();
                let _ = self.complete(io, code, false).await;
                StateOutcome::stream_failed(code)
            }
        }
    }

    /// `case MSTATE_DOING_MORE` (`lib/multi.c:2619-2642`) together with
    /// `multi_do_more` (`:1703-1714`).
    ///
    /// The three outcomes of [`DoMoreStep`], and the C's `else` for the first is
    /// a comment rather than code: *"else stay in DO_MORE"*.
    async fn state_doing_more(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> StateOutcome {
        let left = io.timeleft_ms();
        let control = match io.protocol() {
            // `:1710-1711`.
            Some(protocol) => match io.xfer_ctx() {
                Ok(mut ctx) => bounded(left, protocol.do_more(&mut ctx))
                    .await
                    .map(|done| {
                        // The Rust trait reports readiness as a `bool`, and its
                        // default answers `true` -- so a scheme with no second half
                        // ADVANCES, which is `1`. The C's `-1` is reachable only
                        // from a scheme that writes the integer itself; FTP is the
                        // one that does, and it does so through this mapping's
                        // [`DoMoreStep::from_complete`].
                        if done {
                            DoMoreStep::Advance
                        } else {
                            DoMoreStep::Pending
                        }
                    }),
                Err(code) => Err(code),
            },
            // `:1708`: `*complete = 0` with no handler.
            None => Ok(DoMoreStep::Pending),
        };

        match control {
            Ok(step) => self.apply_do_more(io, step),
            // `:2636-2641`.
            Err(code) => {
                self.posttransfer();
                let _ = self.complete(io, code, false).await;
                StateOutcome::stream_failed(code)
            }
        }
    }

    /// The three outcomes of `multi_do_more`'s `int *completed`
    /// (`lib/multi.c:2626-2635`), applied.
    ///
    /// Separate from [`Self::state_doing_more`] because
    /// [`DoMoreStep::Retry`] -- the C's `-1` -- is not reachable through the
    /// `bool`-reporting trait member: a scheme that wants to go back to `DOING`
    /// says so by writing the integer, which is what
    /// [`DoMoreStep::from_complete`] maps. Keeping the application of a step
    /// separate from its production means all three can be exercised, and means
    /// a scheme that gains the ability to ask for `-1` needs no change here.
    fn apply_do_more(
        &mut self,
        io: &mut dyn TransferIo,
        control: DoMoreStep,
    ) -> StateOutcome {
        match control {
            // `:2626-2630`: "if positive, advance to DO_DONE".
            DoMoreStep::Advance => {
                self.set_mstate(io, CurlMstate::Did);
                StateOutcome::run_again()
            }
            // `:2631-2635`: "if negative, go back to DOING".
            DoMoreStep::Retry => {
                self.set_mstate(io, CurlMstate::Doing);
                StateOutcome::run_again()
            }
            // The C's `else` is a comment: "else stay in DO_MORE".
            DoMoreStep::Pending => StateOutcome::pending(),
        }
    }

    /// `case MSTATE_DID` (`lib/multi.c:2644-2665`): the request is away.
    ///
    /// Transitional, and it decides one thing: whether there is anything to
    /// transfer. The C's comment is the rule -- *"Only perform the transfer if
    /// there is a good socket to work with. Having both BAD is a signal to skip
    /// immediately to DONE"* -- and `CONN_SOCK_IDX_VALID` is
    /// [`ChannelIndex::is_valid`].
    ///
    /// A multiplexing connection wakes the pending queue first, because the
    /// request is now on the wire and another stream can start.
    ///
    /// The wildcard assignment is the C's, guarded by `PROTOPT_WILDCARD`: a
    /// scheme that does not implement wildcards must not leave the operation
    /// looping, so the match is marked finished before `DONE`.
    fn state_did(&mut self, io: &mut dyn TransferIo) -> StateOutcome {
        // `:2646-2648`.
        if io.conn_multiplex_bit() {
            io.scheduler().process_pending_handles();
        }

        // `:2650-2663`.
        if self.send_channel.is_valid() || self.recv_channel.is_valid() {
            self.set_mstate(io, CurlMstate::Performing);
        } else {
            #[cfg(feature = "ftp")]
            {
                let wildcard_capable = io.scheme().is_some_and(|scheme| {
                    scheme.flags.intersects(ProtocolOptions::WILDCARD)
                });
                if self.state.wildcardmatch && !wildcard_capable {
                    self.state.wildcard = WildcardStage::Done;
                }
            }
            self.set_mstate(io, CurlMstate::Done);
        }
        StateOutcome::run_again()
    }

    /// `state_ratelimiting(data, &result)` (`lib/multi.c:2200-2223`).
    ///
    /// The progress check runs FIRST, before the rate gate, because a transfer
    /// that has been too slow for too long must fail even while it is waiting
    /// for tokens -- otherwise `--speed-limit` and `--limit-rate` together would
    /// never abort.
    ///
    /// Its failure closes the connection under the same two exceptions as
    /// `state_performing`: not for a `PROTOPT_DUAL` scheme, where the error was
    /// on the data connection, and not for [`CURLcode::Http2Stream`], where only
    /// one stream failed.
    async fn state_ratelimiting(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> StateOutcome {
        // `:2207`.
        if let Err(code) = self.pgrs_check(io) {
            // `:2209-2216`.
            self.close_stream_on_transfer_error(io, code);
            self.posttransfer();
            let _ = self.complete(io, code, true).await;
            return StateOutcome::failed(code);
        }

        // `:2217-2220`.
        match self.speed_check(io) {
            RateGate::Proceed => StateOutcome::run_again(),
            RateGate::Waiting => StateOutcome::pending(),
        }
    }

    /// `streamclose(data->conn, "Transfer returned error")` with the C's two
    /// exceptions (`lib/multi.c:1998-2000` and `:2210-2212`).
    ///
    /// The C's comment is the reasoning: *"The transfer phase returned error, we
    /// mark the connection to get closed to prevent being reused. This is
    /// because we cannot possibly know if the connection is in a good shape or
    /// not now. Unless it is a protocol which uses two 'channels' like FTP, as
    /// then the error happened in the data connection."* The second exception,
    /// [`CURLcode::Http2Stream`], is a single stream failing on a connection
    /// that is otherwise healthy.
    fn close_stream_on_transfer_error(
        &mut self,
        io: &mut dyn TransferIo,
        result: CURLcode,
    ) {
        let dual = io.scheme().is_some_and(|scheme| {
            scheme.flags.intersects(ProtocolOptions::DUAL)
        });
        if !dual && result != CURLcode::Http2Stream {
            io.stream_close("Transfer returned error");
        }
    }
}

#[allow(dead_code)] // consumers: run_single here
impl Transfer {
    /// `state_performing(data, &stream_error, &result)`
    /// (`lib/multi.c:1924-2061`): move the data, then decide what the transfer
    /// does next.
    ///
    /// The longest state in the machine, and every branch is observable:
    ///
    /// 1. the rate gate runs first, and a wait returns with no I/O at all;
    /// 2. [`Self::sendrecv`] does the work;
    /// 3. a finished request, or an early [`CURLcode::RecvError`], asks
    ///    [`Self::retry_request`] whether this was a dead reused connection --
    ///    and a retry CLEARS the error and marks the request done, so the code
    ///    below treats it as a completed attempt rather than a failure;
    /// 4. an HTTP/2 `HTTP_1_1_REQUIRED` stream error downgrades to HTTP/1.1 and
    ///    retries;
    /// 5. any other error closes the stream, completes prematurely and keeps its
    ///    code;
    /// 6. a finished request whose WRITER IS NOT PAUSED either follows a
    ///    redirect or a retry back to `SETUP`, or goes to `DONE` -- recording a
    ///    `Location:` on the way out when following is off;
    /// 7. a finished request whose writer IS paused does neither, and the
    ///    transfer stays in `PERFORMING` until the application resumes it.
    async fn state_performing(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> StateOutcome {
        // `:1934-1935`.
        if self.speed_check(io) == RateGate::Waiting {
            return StateOutcome::pending();
        }

        // `:1938`.
        let mut result = match self.sendrecv(io).await {
            Ok(()) => CURLcode::Ok,
            Err(code) => code,
        };
        let mut retry_url = None;
        let mut retry = false;

        // `:1940-1957`. The C's comment: "If CURLE_RECV_ERROR happens early
        // enough, we assume it was a race condition and the server closed the
        // reused connection exactly when we wanted to use it, so figure out if
        // that is indeed the case."
        if self.req.done || result == CURLcode::RecvError {
            match self.retry_request(io) {
                Ok(url) => {
                    retry = url.is_some();
                    retry_url = url;
                }
                Err(code) => {
                    if result == CURLcode::Ok {
                        result = code;
                    }
                }
            }
            if retry {
                // `:1951-1956`: "if we are to retry, set the result to OK and
                // consider the request as done".
                result = CURLcode::Ok;
                self.req.done = true;
            }
        }
        // `:1958-1987`, the C's `#ifndef CURL_DISABLE_HTTP`. An `else if`, so a
        // request that already chose a retry does not downgrade as well.
        else if result == CURLcode::Http2Stream && io.h2_http_1_1_error() {
            match self.retry_request(io) {
                Ok(url) => {
                    io.request_io()
                        .infof(format_args!("Downgrades to HTTP/1.1"));
                    io.stream_close("Disconnect HTTP/2 for HTTP/1");
                    self.state.http_neg.force_http1();
                    // `:1968-1969`: "clear the error message bit too as we
                    // ignore the one we got".
                    self.state.errorbuf = false;
                    // `:1970-1972`: "typically for HTTP_1_1_REQUIRED error on
                    // first flight".
                    retry_url = url.or_else(|| self.state.url.clone());
                    match retry_url {
                        None => result = CURLcode::OutOfMemory,
                        Some(_) => {
                            retry = true;
                            result = CURLcode::Ok;
                            self.req.done = true;
                        }
                    }
                }
                Err(code) => result = code,
            }
        }

        if result != CURLcode::Ok {
            // `:1989-2004`.
            self.close_stream_on_transfer_error(io, result);
            self.posttransfer();
            let _ = self.complete(io, result, true).await;
            return StateOutcome::failed(result);
        }

        // `:2005`. A paused writer defers the whole decision: the response is
        // not delivered yet, so neither a redirect nor `DONE` may run.
        if !(self.req.done && !io.client_writer_is_paused()) {
            // `:2055-2057`: "not errored, not done". The C discards the answer
            // -- `mspeed_check(data);` -- because the call is made for its
            // effect: it either parks the transfer in `RATELIMITING` with a
            // `TOOFAST` timer or arms the next token update. Either way this
            // iteration is over.
            let _ = self.speed_check(io);
            return StateOutcome::pending();
        }

        // `:2009`.
        self.posttransfer();

        // `:2011-2053`.
        let follow_target = if retry {
            // `:2023-2024`.
            retry_url.map(|url| (url, FollowType::Retry))
        } else {
            // `:2015-2022`: "if the URL is a follow-location and not just a
            // retried request then figure out the URL here".
            self.req.newurl.take().map(|url| (url, FollowType::Redir))
        };

        match follow_target {
            Some((url, follow_type)) => {
                // `:2025-2031`. The C ignores this code with a comment --
                // "multi_done() might return CURLE_GOT_NOTHING" -- because a
                // redirect is not the moment to report a tidy-up failure.
                let _ = self.complete(io, CURLcode::Ok, false).await;
                match self.follow(io, &url, follow_type) {
                    Ok(()) => {
                        self.set_mstate(io, CurlMstate::Setup);
                        StateOutcome::run_again()
                    }
                    Err(code) => StateOutcome::failed(code),
                }
            }
            None => {
                // `:2036-2047`: "but first check to see if we got a location
                // info even though we are not following redirects".
                let mut result = CURLcode::Ok;
                let mut stream_error = false;
                if let Some(location) = self.req.location.take() {
                    if let Err(code) =
                        self.follow(io, &location, FollowType::Fake)
                    {
                        stream_error = true;
                        // `:2043-2045`. The completion's answer REPLACES the
                        // follow's, which is easy to read past: a tidy
                        // completion leaves `result` at success, so the transfer
                        // still goes to `DONE` below -- carrying
                        // `stream_error`, which `is_finished` then ignores
                        // because it only acts on a failure. Reproduced rather
                        // than tidied.
                        result = self.complete(io, code, true).await;
                    }
                }

                // `:2049-2052`.
                if result == CURLcode::Ok {
                    self.set_mstate(io, CurlMstate::Done);
                    return StateOutcome {
                        step: DriverStep::RunAgain,
                        result,
                        stream_error,
                    };
                }
                StateOutcome {
                    step: DriverStep::Pending,
                    result,
                    stream_error,
                }
            }
        }
    }

    /// `multi_follow(data, handler, newurl, type)`
    /// (`lib/multi.c:1870-1878`): follow a redirect or reissue a request.
    ///
    /// The decision and the bookkeeping both belong to
    /// [`crate::transfer::request`] -- the redirect counter, the ceiling, the
    /// method rewrite and the frozen log lines are all
    /// [`SingleRequest::follow`]'s -- and the protocol half arrives through
    /// [`TransferIo::protocol_follow`]. A scheme with no `follow` operation
    /// answers [`CURLcode::TooManyRedirects`], which reads oddly and is the C's:
    /// the transfer is about to go back to `SETUP` with a URL nothing can act
    /// on, so answering "no more redirects" is what stops it looping.
    ///
    /// # Errors
    ///
    /// Whatever the follow reports, [`CURLcode::TooManyRedirects`] included.
    fn follow(
        &mut self,
        io: &mut dyn TransferIo,
        url: &str,
        follow_type: FollowType,
    ) -> CodeResult<()> {
        let settings = io.follow_settings();
        // `self.req` and `self.state.follow` are disjoint fields, so both may be
        // borrowed for one call; the two SEAMS come out together for the reason
        // [`TransferIo::follow_seams`] gives.
        let (req_io, protocol) = io.follow_seams();
        self.req.follow(
            req_io,
            protocol,
            &settings,
            &mut self.state.follow,
            url,
            follow_type,
        )
    }
}

// Completion: `multi_done`

/// `Curl_1st_err(r1, r2)` (`lib/url.h:95-99`): the first code that is not
/// success.
///
/// The C's own documentation is the contract, and the second sentence is the
/// point: *"Always eval all arguments, return the first result != CURLE_OK. A
/// non-short-circuit evaluation."* Both operations must RUN -- a client-write
/// flush must happen even when the protocol's own completion failed -- and only
/// the reported code is chosen. Rust's `?` and `&&` both short-circuit, so this
/// is written as a function over two already-evaluated codes.
const fn first_err(first: CURLcode, second: CURLcode) -> CURLcode {
    match first {
        CURLcode::Ok => second,
        _ => first,
    }
}

#[allow(dead_code)] // consumers: the driver here, crate::multi
impl Transfer {
    /// `multi_done(data, status, premature)` (`lib/multi.c:665-737`): the
    /// transfer is over; release what it holds and decide about its connection.
    ///
    /// # Idempotent, and that is the first thing it does
    ///
    /// `data->state.done` guards the whole body (`:679-681`). The state machine
    /// reaches this from fourteen places -- five error paths, the retry path, the
    /// redirect path and `DONE` itself -- and several of them can run in
    /// sequence, so a second call must be a no-op rather than a second protocol
    /// completion.
    ///
    /// # Three callback failures are promoted to "premature"
    ///
    /// [`CURLcode::AbortedByCallback`], [`CURLcode::ReadError`] and
    /// [`CURLcode::WriteError`] force `premature` (`:690-702`). The C's comment
    /// is the reasoning: *"When we are aborted due to a callback return code it
    /// basically have to be counted as premature as there is trouble ahead if we
    /// do not."* A premature completion is what stops the connection being
    /// returned to the pool in an unknown state.
    ///
    /// # The order, which is fixed
    ///
    /// 1. abandon any resolver work still in flight (`:684`);
    /// 2. drop the redirect junk -- `req.newurl` and `req.location` (`:687-688`),
    ///    which the C frees so that a later `CURLINFO` read cannot see a URL
    ///    from a transfer that is over;
    /// 3. the scheme's `done`, ONLY when the transfer got as far as
    ///    `PROTOCONNECT` (`:705`), because a scheme that never connected has
    ///    nothing to release;
    /// 4. the final progress update, SKIPPED when the status is already a
    ///    callback abort (`:710-712`) -- the C's comment: *"avoid this if we
    ///    already aborted by callback to avoid this calling another callback"*;
    /// 5. the client writer's flush, combined with [`first_err`] so that it runs
    ///    whatever step 3 reported (`:719`);
    /// 6. the connection filters' `DATA_DONE` event (`:722`);
    /// 7. the pending queue, because a connection may just have been freed
    ///    (`:724`);
    /// 8. the request's own completion, only when nothing has failed yet
    ///    (`:726-727`);
    /// 9. the pool's decision, under its lock (`:732`);
    /// 10. the `.netrc` cache flush (`:735`).
    pub(crate) async fn complete(
        &mut self,
        io: &mut dyn TransferIo,
        status: CURLcode,
        premature: bool,
    ) -> CURLcode {
        // `:676-677`.
        io.trace_multi(format_args!(
            "multi_done: status: {} prem: {} done: {}",
            status.as_i32(),
            i32::from(premature),
            i32::from(self.state.done)
        ));

        // `:679-681`.
        if self.state.done {
            return CURLcode::Ok;
        }

        // `:683-688`.
        io.resolver_shutdown();
        self.req.newurl = None;
        self.req.location = None;

        // `:690-702`.
        let premature = premature
            || matches!(
                status,
                CURLcode::AbortedByCallback
                    | CURLcode::ReadError
                    | CURLcode::WriteError
            );

        // `:704-708`.
        let mut result = self.protocol_done(io, status, premature).await;

        // `:710-716`.
        if result != CURLcode::AbortedByCallback {
            let req_done = self.req.done;
            if io.pgrs_done(req_done).is_err() && result == CURLcode::Ok {
                result = CURLcode::AbortedByCallback;
            }
        }

        // `:718-719`.
        let flushed = match self.xfer_write_done(io, premature) {
            Ok(()) => CURLcode::Ok,
            Err(code) => code,
        };
        result = first_err(result, flushed);

        // `:721-724`.
        io.ev_data_done(premature);
        io.scheduler().process_pending_handles();

        // `:726-727`.
        if result == CURLcode::Ok {
            if let Err(code) = self.req.done(io.request_io(), premature) {
                result = code;
            }
        }

        // `:729-732`.
        let outcome = io.complete_connection(premature);
        if !outcome.still_in_use {
            // `:628-629`, inside `multi_done_locked` and AFTER its in-use
            // check: a transfer that was not the last user leaves `state.done`
            // false, so the last one still gets to make the pool decision.
            self.state.done = true;
            self.state.recent_conn_id = outcome.recent;
            self.state.lastconnect_id = outcome.last;
        }

        // `:734-735`.
        io.netrc_cleanup();
        result
    }

    /// The scheme's `done` operation, gated as the C gates it
    /// (`lib/multi.c:704-708`).
    ///
    /// Two conditions, and both matter: the scheme must HAVE the operation --
    /// which every in-scope scheme does, the C's own comment calling it one of
    /// the two members that *"MUST be set"* -- and the transfer must have reached
    /// `PROTOCONNECT`, so that a scheme's completion never runs for a connection
    /// its own connect never touched. With either unmet the status passes
    /// through unchanged.
    async fn protocol_done(
        &mut self,
        io: &mut dyn TransferIo,
        status: CURLcode,
        premature: bool,
    ) -> CURLcode {
        if self.mstate < CurlMstate::ProtoConnect {
            return status;
        }
        let Some(protocol) = io.protocol() else {
            return status;
        };
        let ctx = io.xfer_ctx();
        match ctx {
            Ok(mut ctx) => {
                match protocol.done(&mut ctx, status, premature).await {
                    Ok(()) => status,
                    Err(code) => code,
                }
            }
            Err(code) => code,
        }
    }
}

// Timeouts and the final error handling

#[allow(dead_code)] // consumers: run_single here
impl Transfer {
    /// `multi_handle_timeout(data, &stream_error, &result)`
    /// (`lib/multi.c:1719-1770`): has this transfer run out of time, and if so,
    /// say so exactly.
    ///
    /// `None` means there is time left. `Some(outcome)` means the deadline has
    /// passed, the diagnostic has been written, and the state machine must be
    /// skipped -- the C's `goto statemachine_end`.
    ///
    /// The C's `(void)multi_done(data, *result, TRUE)` (`:1764`) is NOT done
    /// here. It is the one asynchronous thing `multi_handle_timeout` does, and
    /// hoisting it to the caller is what keeps this function synchronous -- it
    /// runs twice per iteration in the C, and a future for something that
    /// answers `None` almost every time is a cost with nothing behind it. Both
    /// call sites reproduce the C's `if(data->conn)` guard.
    ///
    /// # Four diagnostics, chosen by phase
    ///
    /// | phase | line |
    /// |---|---|
    /// | `RESOLVING` | `Resolving timed out after %ld milliseconds` |
    /// | `CONNECTING` | `Connection timed out after %ld milliseconds` |
    /// | later, known size | `Operation timed out after %ld milliseconds with %ld out of %ld bytes received` |
    /// | later, unknown size | `Operation timed out after %ld milliseconds with %ld bytes received` |
    ///
    /// The elapsed time is measured from `t_startsingle` while the transfer is
    /// still connecting and from `t_startop` afterwards (`:1729-1732`), which is
    /// what makes a redirect's connect timeout report the time THAT connect took
    /// while a transfer timeout reports the whole operation.
    ///
    /// # The connection is closed only if it was used
    ///
    /// `if(data->mstate > MSTATE_DO)` (`:1760`) guards the stream close: a
    /// transfer that timed out before the request went out has nothing on the
    /// wire, so its connection may still be reusable. Past `DO` it may hold half
    /// a request, and the C's reason is in the reason string it passes --
    /// `Disconnect due to timeout`.
    fn handle_timeout(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> Option<TimeoutHit> {
        // `:1725-1726`.
        if io.timeleft_ms() >= 0 {
            return None;
        }

        // `:1728-1732`.
        let now = io.request_io().pgrs_now();
        let since = if self.mstate.is_connecting() {
            io.request_io().progress().start_single()
        } else {
            io.request_io().progress().start_op()
        };
        let elapsed = timediff_ms(now, since);

        match self.mstate {
            // `:1733-1736`.
            CurlMstate::Resolving => io.request_io().failf(format_args!(
                "Resolving timed out after {elapsed} milliseconds"
            )),
            // `:1737-1740`.
            CurlMstate::Connecting => io.request_io().failf(format_args!(
                "Connection timed out after {elapsed} milliseconds"
            )),
            // `:1741-1756`.
            _ => {
                if self.req.size != -1 {
                    io.request_io().failf(format_args!(
                        "Operation timed out after {elapsed} milliseconds \
                         with {} out of {} bytes received",
                        self.req.bytecount, self.req.size
                    ));
                } else {
                    io.request_io().failf(format_args!(
                        "Operation timed out after {elapsed} milliseconds \
                         with {} bytes received",
                        self.req.bytecount
                    ));
                }
            }
        }

        // `:1757-1765`. The C nests the two tests; `&&` is the same thing.
        let mut stream_error = false;
        if io.has_connection() && self.mstate > CurlMstate::Do {
            io.stream_close("Disconnect due to timeout");
            stream_error = true;
        }
        Some(TimeoutHit { stream_error })
    }

    /// `is_finished(multi, data, stream_error, result)`
    /// (`lib/multi.c:2327-2383`): the state machine's single error exit.
    ///
    /// Everything about a failing transfer happens HERE and nowhere else, which
    /// is what the C's comment guarantees: *"No attempt to disconnect
    /// connections must be made before this - connection detach and termination
    /// happens only here"*.
    ///
    /// Three paths:
    ///
    /// * a FAILURE runs the pending queue, then either detaches and terminates
    ///   the connection when this was a stream error -- marking it DEAD when the
    ///   code is [`CURLcode::OperationTimedout`], so nothing is sent over it --
    ///   or, when `CONNECT` failed before there was a connection at all, reports
    ///   progress without the meter. Either way the transfer goes to
    ///   `COMPLETED`;
    /// * a SUCCESS with a connection still calls the progress callback, and an
    ///   abort there closes the stream with `Aborted by callback` and moves to
    ///   `DONE` -- or to `COMPLETED` when `DONE` has already passed;
    /// * a transfer already at `COMPLETED` or beyond is left alone.
    ///
    /// # Not `async`
    ///
    /// `is_finished` awaits nothing: every operation it performs -- running the
    /// pending queue, detaching and terminating a connection, closing a stream,
    /// one progress callback -- is synchronous in the C and synchronous on the
    /// seams here.
    fn finish(
        &mut self,
        io: &mut dyn TransferIo,
        stream_error: bool,
        result: CURLcode,
    ) -> CURLcode {
        // `:2332`.
        if self.mstate >= CurlMstate::Completed {
            return result;
        }

        if result != CURLcode::Ok {
            // `:2342-2343`: "Check if we can move pending requests to send
            // pipe".
            io.scheduler().process_pending_handles();

            if io.has_connection() {
                // `:2346-2356`.
                if stream_error {
                    // `:2348`: "Do not attempt to send data over a connection
                    // that timed out".
                    let dead = result == CURLcode::OperationTimedout;
                    io.detach_connection();
                    io.terminate_connection(dead);
                }
            } else if self.mstate == CurlMstate::Connect {
                // `:2358-2362`: `Curl_connect()` failed.
                self.posttransfer();
                let req_done = self.req.done;
                io.pgrs_update_nometer(req_done);
            }

            // `:2364-2365`.
            self.set_mstate(io, CurlMstate::Completed);
            return result;
        }

        // `:2367-2380`: "if there is still a connection to use, call the
        // progress function".
        if io.has_connection() {
            let req_done = self.req.done;
            if let Err(error) = io.pgrs_update(req_done) {
                // `:2371-2378`: "aborted due to progress callback return code
                // must close the connection".
                io.stream_close("Aborted by callback");
                let next = if self.mstate < CurlMstate::Done {
                    CurlMstate::Done
                } else {
                    CurlMstate::Completed
                };
                self.set_mstate(io, next);
                return error.into_code();
            }
        }
        result
    }
}

/// What a timeout decided, for the state machine's error exit.
///
/// The C threads it through the same `stream_error` local every state helper
/// writes (`lib/multi.c:2465`); naming it keeps `multi_handle_timeout`'s two
/// out-parameters from becoming two more arguments.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TimeoutHit {
    /// The C's `*stream_error`: the connection had been used, so it must be
    /// terminated rather than pooled.
    stream_error: bool,
}

// The driver: `multi_runsingle`

/// Validates a raw state integer -- the C's `default:` arm
/// (`lib/multi.c:2713-2714`).
///
/// [`CurlMstate`] has 17 variants and no `Last`, so the state machine's `match`
/// is exhaustive over the TYPE and the C's `default: return
/// CURLM_INTERNAL_ERROR` is unreachable from inside the driver. It is reachable
/// from OUTSIDE, where a state arrives as an integer across the C ABI, and this
/// is that boundary: [`CurlMstate::LAST`] -- the C's `MSTATE_LAST`, commented
/// *"not a true state, never use this"* (`lib/multihandle.h:69`) -- and every
/// other out-of-range integer answer [`CURLMcode::InternalError`], exactly as
/// the C's `switch` does.
///
/// # Errors
///
/// [`CURLMcode::InternalError`] for `MSTATE_LAST` and for any integer outside
/// `0..17`.
#[allow(dead_code)] // consumers: crate::multi and the ABI shim
pub(crate) fn validate_state(raw: i32) -> Result<CurlMstate, CURLMcode> {
    CurlMstate::from_i32(raw).ok_or(CURLMcode::InternalError)
}

#[allow(dead_code)] // consumers: crate::multi and crate::easy
impl Transfer {
    /// `multi_runsingle(multi, data, sigpipe_ctx)`
    /// (`lib/multi.c:2427-2745`): run this transfer's state machine until it
    /// cannot make progress.
    ///
    /// # The loop, and why it is a loop
    ///
    /// Several states are TRANSITIONAL: they change nothing but the state and
    /// must not cost a round trip through the caller's poll loop. The C expresses
    /// that with `CURLM_CALL_MULTI_PERFORM` and a `do { } while` (`:2462` and
    /// `:2740-2741`); this expresses it with [`DriverStep::RunAgain`] and the
    /// same loop, so a transfer moving `INIT` -> `SETUP` -> `CONNECT` ->
    /// `PROTOCONNECT` -> `DO` reaches `DO` in one call. Genuinely pending I/O
    /// answers [`DriverStep::Pending`] and the loop ends.
    ///
    /// The second condition, `multi_ischanged(multi, FALSE)`, keeps the loop
    /// going when a transfer was added or removed while this one ran: a freed
    /// connection may be exactly what this transfer was waiting for.
    ///
    /// # `result` survives an iteration
    ///
    /// The C declares `result` OUTSIDE the loop (`:2435`), and `PROTOCONNECT`
    /// reads it -- `if(!result && data->conn->bits.reuse)` (`:2550`). That carry
    /// is preserved here and passed explicitly to
    /// [`Self::state_protoconnect`], because a carried value read implicitly is
    /// exactly the kind of thing a decomposition loses.
    ///
    /// # Errors
    ///
    /// [`CURLMcode::InternalError`] when a state past `CONNECT` and before
    /// `COMPLETED` has no connection (`:2473-2479`), and whatever
    /// [`TransferScheduler::assess_registrations`] reports.
    pub(crate) async fn run_single(
        &mut self,
        io: &mut dyn TransferIo,
    ) -> Result<RunSingle, CURLMcode> {
        // `:2435`. Declared OUTSIDE the loop; see the note above on the carry.
        let mut result = CURLcode::Ok;

        // `:2441-2448`: a multi-level callback already failed, so every transfer
        // in the handle has failed with it.
        //
        // The C does NOT return here, and neither does this. It completes the
        // transfer, parks it at `COMPLETED` and falls into the loop, where
        // `case MSTATE_COMPLETED` does nothing and `is_finished` -- which
        // returns immediately at `COMPLETED` -- leaves the code alone. Keeping
        // that path costs one iteration and buys the loop's first act,
        // `process_pending_handles`: a transfer that has just given up its
        // connection is exactly when the queue wants running.
        if io.scheduler().is_dead() {
            result = CURLcode::AbortedByCallback;
            self.posttransfer();
            let _ = self.complete(io, result, false).await;
            self.set_mstate(io, CurlMstate::Completed);
        }

        // `:2452-2454`: "transfer runs now, clear the dirty bit. This may be set
        // again during processing, triggering a re-run later."
        io.scheduler().clear_dirty();

        let mut step;

        loop {
            // `:2465`.
            let mut stream_error = false;
            step = DriverStep::Pending;

            // `:2468-2471`.
            if io.scheduler().multi_changed(true) {
                io.trace_multi(format_args!(
                    "multi changed, check CONNECT_PEND queue"
                ));
                io.scheduler().process_pending_handles();
            }

            // `:2473-2479`. The C asserts and then tests anyway; the test is
            // what a release build relies on, so it is the part reproduced.
            if self.mstate > CurlMstate::Connect
                && self.mstate < CurlMstate::Completed
                && !io.has_connection()
            {
                return Err(CURLMcode::InternalError);
            }

            // `:2481-2486`: "Wait for the connect state as only then is the
            // start time stored, but we must not check already completed
            // handles."
            let timed_out = if self.mstate >= CurlMstate::Connect
                && self.mstate < CurlMstate::Completed
            {
                match self.handle_timeout(io) {
                    Some(hit) => {
                        // The C completes the transfer inside
                        // `multi_handle_timeout` (`:1764`); it is done here so
                        // that the completion is asynchronous like every other,
                        // and under the SAME guard -- `if(data->conn)` at
                        // `:1758` brackets both the stream close and the
                        // completion, so a transfer that timed out before it had
                        // a connection is not completed at all.
                        if io.has_connection() {
                            let _ = self
                                .complete(io, CURLcode::OperationTimedout, true)
                                .await;
                        }
                        result = CURLcode::OperationTimedout;
                        stream_error = hit.stream_error;
                        true
                    }
                    None => false,
                }
            } else {
                false
            };

            if !timed_out {
                let outcome = self.run_state(io, result).await?;
                step = outcome.step;
                result = outcome.result;
                stream_error = outcome.stream_error;

                // `:2717-2728`. The C's comment is the rule: "We now handle
                // stream timeouts if and only if this will be the last loop
                // iteration. We only check this on the last iteration to ensure
                // that if we know we have additional work to do immediately
                // (i.e. CURLM_CALL_MULTI_PERFORM == TRUE) then we should do that
                // before declaring the connection timed out as we may almost
                // have a completed connection."
                if self.mstate >= CurlMstate::Connect
                    && self.mstate < CurlMstate::Do
                    && !step.runs_again()
                    && !io.scheduler().multi_changed(false)
                {
                    if let Some(hit) = self.handle_timeout(io) {
                        // Same `if(data->conn)` guard as the first check.
                        if io.has_connection() {
                            let _ = self
                                .complete(io, CURLcode::OperationTimedout, true)
                                .await;
                        }
                        result = CURLcode::OperationTimedout;
                        stream_error = hit.stream_error;
                    }
                }
            }

            // `:2730-2734`, the C's `statemachine_end:` label.
            result = self.finish(io, stream_error, result);
            if result != CURLcode::Ok {
                step = DriverStep::RunAgain;
            }

            // `:2736-2739`. Note what is NOT done: the C reaches
            // `handle_completed` and returns WITHOUT assigning `data->result`,
            // which is written at `:2743` alone. The code travels to the
            // application inside the `CURLMSG_DONE` message instead -- built by
            // `handle_completed` from this very value -- so assigning it here
            // would put a code in a field the C leaves untouched, and
            // `curl_multi_remove_handle` reads that field (`:804`).
            if self.mstate == CurlMstate::Completed {
                return Ok(RunSingle::Completed(result));
            }

            // `:2740-2741`.
            if !step.runs_again() && !io.scheduler().multi_changed(false) {
                break;
            }
        }

        // `:2743-2744`.
        self.result = result;
        Ok(match step {
            DriverStep::RunAgain => RunSingle::RunAgain,
            DriverStep::Pending => RunSingle::Pending,
        })
    }

    /// The `switch(data->mstate)` of `multi_runsingle`
    /// (`lib/multi.c:2488-2715`), exhaustive over [`CurlMstate`].
    ///
    /// Two of the C's cases FALL THROUGH -- `INIT` into `SETUP` and `SETUP` into
    /// `CONNECT` (`:2499` and `:2514`) -- and both are reproduced by calling the
    /// next state's work directly, which is what a fall-through is. Everything
    /// else is one arm per state.
    ///
    /// `carried` is the C's `result` from a previous iteration; see
    /// [`Self::run_single`].
    ///
    /// # Errors
    ///
    /// Whatever [`Self::state_resolving`] reports.
    async fn run_state(
        &mut self,
        io: &mut dyn TransferIo,
        carried: CURLcode,
    ) -> Result<StateOutcome, CURLMcode> {
        Ok(match self.mstate {
            // `:2489-2499`. Transitional: "init this transfer. A handle never
            // comes back to this state" -- except through the wildcard restart
            // in `DONE`, which clears the flag this checks.
            CurlMstate::Init => {
                if let Err(code) = self.pretransfer(io) {
                    return Ok(StateOutcome::failed(code));
                }
                self.set_mstate(io, CurlMstate::Setup);
                io.request_io().pgrs_time(PgrsTimer::StartOp);
                // FALLTHROUGH to SETUP (`:2499`).
                self.state_setup(io);
                // FALLTHROUGH to CONNECT (`:2514`).
                self.state_connect(io).await
            }

            // `:2501-2514`.
            CurlMstate::Setup => {
                self.state_setup(io);
                // FALLTHROUGH to CONNECT.
                self.state_connect(io).await
            }

            // `:2516-2518`.
            CurlMstate::Connect => self.state_connect(io).await,

            // `:2520-2523`.
            CurlMstate::Resolving => self.state_resolving(io).await?,

            // `:2525-2547`.
            CurlMstate::Connecting => self.state_connecting(io).await,

            // `:2549-2577`.
            CurlMstate::ProtoConnect => {
                self.state_protoconnect(io, carried).await
            }

            // `:2579-2593`.
            CurlMstate::ProtoConnecting => self.state_protoconnecting(io).await,

            // `:2595-2597`.
            CurlMstate::Do => self.state_do(io).await,

            // `:2599-2617`.
            CurlMstate::Doing => self.state_doing(io).await,

            // `:2619-2642`.
            CurlMstate::DoingMore => self.state_doing_more(io).await,

            // `:2644-2665`. `DID` never writes `result`, so the carry survives
            // it -- see the note on the three do-nothing states below.
            CurlMstate::Did => self.state_did(io).with_result(carried),

            // `:2667-2669`.
            CurlMstate::RateLimiting => self.state_ratelimiting(io).await,

            // `:2671-2673`.
            CurlMstate::Performing => self.state_performing(io).await,

            // `:2675-2703`.
            CurlMstate::Done => self.state_done(io, carried).await,

            // `:2705-2711`. `COMPLETED` is finished; `PENDING` and `MSGSENT`
            // are not in the run set at all -- the C's comment is "handles in
            // these states should NOT be in this list" -- so all three do
            // nothing. A `PENDING` transfer resumes when its owner moves it back
            // to `CONNECT`, which is `crate::multi`'s
            // `process_pending_handles`.
            //
            // Three bare `break`s in the C, which leave `result` ALONE. That
            // matters for exactly one entry: a dead multi handle arrives here
            // already at `COMPLETED` carrying `CURLE_ABORTED_BY_CALLBACK`, and
            // returning a fresh `CURLE_OK` would erase the reason the transfer
            // failed on its way to the application's `CURLMSG_DONE`.
            CurlMstate::Completed
            | CurlMstate::Pending
            | CurlMstate::MsgSent => {
                StateOutcome::pending().with_result(carried)
            }
        })
    }

    /// `case MSTATE_DONE` (`lib/multi.c:2675-2703`): the post-transfer state.
    ///
    /// The C's comment: *"this state is highly transient, so run another loop
    /// after this"* -- so it always answers [`DriverStep::RunAgain`], even when
    /// the completion failed.
    ///
    /// Three things happen. The completion runs once, when there is still a
    /// connection. An EARLIER error takes precedence over the completion's --
    /// `if(!result) result = res` (`:2686-2687`) -- because the earlier one is
    /// the reason the transfer is here. And an FTP wildcard match that has not
    /// finished goes back to `INIT` to start the next file, which is the ONE way
    /// a transfer re-enters `INIT`; the pretransfer flag is cleared there so the
    /// next iteration initialises the new attempt.
    async fn state_done(
        &mut self,
        io: &mut dyn TransferIo,
        carried: CURLcode,
    ) -> StateOutcome {
        let mut result = carried;

        // `:2679-2688`.
        if io.has_connection() {
            let completion = self.complete(io, result, false).await;
            // `:2685-2687`: "allow a previously set error code take precedence".
            if result == CURLcode::Ok {
                result = completion;
            }
        }

        // `:2690-2699`, the C's `#ifndef CURL_DISABLE_FTP`.
        #[cfg(feature = "ftp")]
        if self.state.wildcardmatch
            && self.state.wildcard != WildcardStage::Done
        {
            // `:2693-2696`: "if a wildcard is set and we are not ending -> lets
            // start again with MSTATE_INIT".
            self.pretransfer_done = false;
            self.set_mstate(io, CurlMstate::Init);
            return StateOutcome::run_again().with_result(result);
        }

        // `:2700-2702`: "after we have DONE what we are supposed to do, go
        // COMPLETED, and it does not matter what the multi_done() returned!"
        self.set_mstate(io, CurlMstate::Completed);
        StateOutcome::run_again().with_result(result)
    }

    /// Whether [`Self::pretransfer`] has run for this operation.
    ///
    /// Read by `crate::easy`, which drives one transfer without a multi handle's
    /// run set and therefore has to know whether `INIT` has been through.
    pub(crate) const fn pretransfer_done(&self) -> bool {
        self.pretransfer_done
    }
}

// TESTS

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::Duration;

    use super::*;
    use crate::conn::filters::FilterChains;
    use crate::conn::select::EasyPollset;
    use crate::protocols::ProtoFuture;
    use crate::transfer::progress::{
        CallbackFlavour, LowSpeedLimit, Paused, Progress, ProgressCallback,
        ProgressSnapshot,
    };
    use crate::transfer::ratelimit::RateLimit;
    use crate::transfer::request::{
        DebugEnv, FollowMode, PostRedir, RequestConfig, ResolvedTarget,
        MAXREDIRS_DEFAULT,
    };
    use crate::transfer::sendf::{ReadOutcome, TraceDataKind};
    use crate::util::timeval::{Clock, CurlTime, TestClock};

    // ---- the protocol double ---------------------------------------------

    /// One scripted answer from a [`Protocol`] operation that reports readiness.
    ///
    /// Three shapes, because the typed steps admit exactly three. There is no
    /// fourth, and no out-parameter that a scheme could leave untouched.
    #[derive(Clone, Debug)]
    enum Step {
        /// `Ok(true)`: finished -- [`AsyncStep::Complete`].
        Done,
        /// `Ok(false)`: not yet -- [`AsyncStep::Pending`].
        Pending,
        /// A failure.
        Fail(CURLcode),
        /// Suspends for `Duration`, then finishes. The only step whose future
        /// really awaits, and the one the deadline tests use.
        Hang(Duration),
    }

    /// Everything the scripted protocol will answer, per operation.
    ///
    /// Held in a thread-local rather than in the protocol value, because
    /// [`Scheme`] carries `&'static dyn Protocol` and a `static` must be
    /// [`Sync`]. Each `#[test]` runs on its own thread and `#[tokio::test]`
    /// blocks on that thread, so a thread-local IS per-test state -- and,
    /// unlike a leaked `Box`, it leaves nothing for Miri to report.
    #[derive(Debug, Default)]
    struct ProtoScript {
        do_it: VecDeque<Step>,
        done: VecDeque<CURLcode>,
        do_more: VecDeque<Step>,
        connect_it: VecDeque<Step>,
        connecting: VecDeque<Step>,
        doing: VecDeque<Step>,
        write_resp: VecDeque<CodeResult<bool>>,
        write_resp_hd: VecDeque<CodeResult<bool>>,
        /// Every call, in order, by operation name.
        calls: Vec<&'static str>,
        /// The four pollset callbacks. MUST stay zero: readiness comes from the
        /// reactor, never from arithmetic over descriptor masks.
        pollsets: usize,
        /// `(status, premature)` for every `done`.
        done_args: Vec<(CURLcode, bool)>,
    }

    thread_local! {
        /// The scripted protocol's state for THIS test.
        static PROTO: RefCell<ProtoScript> =
            RefCell::new(ProtoScript::default());
    }

    /// Runs `body` over the script.
    fn proto<R>(body: impl FnOnce(&mut ProtoScript) -> R) -> R {
        PROTO.with(|cell| body(&mut cell.borrow_mut()))
    }

    /// Empties the script and every recording. Called by every test that uses
    /// the protocol double, because threads are reused across tests.
    fn proto_reset() {
        proto(|script| *script = ProtoScript::default());
    }

    /// How many times `which` was called.
    fn proto_calls(which: &str) -> usize {
        proto(|script| script.calls.iter().filter(|c| **c == which).count())
    }

    /// Pops the next step for `which`, defaulting to [`Step::Done`] -- the
    /// answer every optional [`Protocol`] member's own default gives.
    fn next_step(which: &'static str) -> Step {
        proto(|script| {
            script.calls.push(which);
            let queue = match which {
                "do_it" => &mut script.do_it,
                "do_more" => &mut script.do_more,
                "connect_it" => &mut script.connect_it,
                "connecting" => &mut script.connecting,
                _ => &mut script.doing,
            };
            queue.pop_front().unwrap_or(Step::Done)
        })
    }

    /// Turns one step into the future a `bool`-reporting member returns.
    fn step_future(step: Step) -> ProtoFuture<'static, bool> {
        match step {
            Step::Done => Box::pin(core::future::ready(Ok(true))),
            Step::Pending => Box::pin(core::future::ready(Ok(false))),
            Step::Fail(code) => Box::pin(core::future::ready(Err(code))),
            Step::Hang(span) => Box::pin(async move {
                tokio::time::sleep(span).await;
                Ok(true)
            }),
        }
    }

    /// The scripted scheme implementation.
    ///
    /// A unit struct, so that it can live in a `static`; all of its state is the
    /// thread-local above.
    #[derive(Debug)]
    struct FakeProtocol;

    impl Protocol for FakeProtocol {
        fn do_it<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> ProtoFuture<'a, bool> {
            let _ = ctx;
            step_future(next_step("do_it"))
        }

        fn done<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
            status: CURLcode,
            premature: bool,
        ) -> ProtoFuture<'a, ()> {
            let _ = ctx;
            let code = proto(|script| {
                script.calls.push("done");
                script.done_args.push((status, premature));
                script.done.pop_front().unwrap_or(CURLcode::Ok)
            });
            Box::pin(core::future::ready(match code {
                CURLcode::Ok => Ok(()),
                other => Err(other),
            }))
        }

        fn do_more<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> ProtoFuture<'a, bool> {
            let _ = ctx;
            step_future(next_step("do_more"))
        }

        fn connect_it<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> ProtoFuture<'a, bool> {
            let _ = ctx;
            step_future(next_step("connect_it"))
        }

        fn connecting<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> ProtoFuture<'a, bool> {
            let _ = ctx;
            step_future(next_step("connecting"))
        }

        fn doing<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> ProtoFuture<'a, bool> {
            let _ = ctx;
            step_future(next_step("doing"))
        }

        fn write_resp<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
            buf: &'a [u8],
            is_eos: bool,
        ) -> ProtoFuture<'a, bool> {
            let _ = (ctx, buf, is_eos);
            let answer = proto(|script| {
                script.calls.push("write_resp");
                script.write_resp.pop_front().unwrap_or(Ok(false))
            });
            Box::pin(core::future::ready(answer))
        }

        fn write_resp_hd<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
            hd: &'a [u8],
            is_eos: bool,
        ) -> ProtoFuture<'a, bool> {
            let _ = (ctx, hd, is_eos);
            let answer = proto(|script| {
                script.calls.push("write_resp_hd");
                script.write_resp_hd.pop_front().unwrap_or(Ok(false))
            });
            Box::pin(core::future::ready(answer))
        }

        // The four pollsets exist ONLY so that a call can be detected. Nothing
        // in `crate::transfer` may reach them.
        fn proto_pollset(
            &self,
            ctx: &mut TransferCtx<'_>,
            ps: &mut EasyPollset,
        ) -> CodeResult<()> {
            let _ = (ctx, ps);
            proto(|script| script.pollsets += 1);
            Ok(())
        }

        fn doing_pollset(
            &self,
            ctx: &mut TransferCtx<'_>,
            ps: &mut EasyPollset,
        ) -> CodeResult<()> {
            let _ = (ctx, ps);
            proto(|script| script.pollsets += 1);
            Ok(())
        }

        fn domore_pollset(
            &self,
            ctx: &mut TransferCtx<'_>,
            ps: &mut EasyPollset,
        ) -> CodeResult<()> {
            let _ = (ctx, ps);
            proto(|script| script.pollsets += 1);
            Ok(())
        }

        fn perform_pollset(
            &self,
            ctx: &mut TransferCtx<'_>,
            ps: &mut EasyPollset,
        ) -> CodeResult<()> {
            let _ = (ctx, ps);
            proto(|script| script.pollsets += 1);
            Ok(())
        }
    }

    /// The one scripted implementation every scheme below points at.
    static FAKE: FakeProtocol = FakeProtocol;

    /// A plain HTTP scheme with an implementation.
    static SCHEME_HTTP: Scheme = Scheme {
        name: b"http",
        run: Some(&FAKE),
        protocol: Proto::HTTP,
        family: Proto::HTTP,
        flags: ProtocolOptions::CREDSPERREQUEST,
        defport: 80,
    };

    /// FTP: two channels, so `PROTOPT_DUAL` -- which changes where pending data
    /// is looked for and whether a transfer error closes the connection.
    static SCHEME_FTP: Scheme = Scheme {
        name: b"ftp",
        run: Some(&FAKE),
        protocol: Proto::FTP,
        family: Proto::FTP,
        flags: ProtocolOptions::DUAL.union(ProtocolOptions::WILDCARD),
        defport: 21,
    };

    /// SFTP: the family the download loop keeps trying until a real `EAGAIN`
    /// before it believes the transport is empty.
    static SCHEME_SFTP: Scheme = Scheme {
        name: b"SFTP",
        run: Some(&FAKE),
        protocol: Proto::SFTP,
        family: Proto::SFTP,
        flags: ProtocolOptions::DIRLOCK,
        defport: 22,
    };

    /// A registered scheme with NO implementation -- the C's `ZERO_NULL` `run`
    /// column.
    static SCHEME_STUB: Scheme = Scheme {
        name: b"gopher",
        run: None,
        protocol: Proto::GOPHER,
        family: Proto::GOPHER,
        flags: ProtocolOptions::NONE,
        defport: 70,
    };

    // ---- recordings ------------------------------------------------------

    /// One scripted transport receive.
    #[derive(Clone, Debug)]
    enum RecvStep {
        /// Hand over these bytes. Fewer than asked for is fine; a remainder
        /// goes back on the script.
        Bytes(Vec<u8>),
        /// Zero bytes: end of stream.
        Eos,
        /// `CURLE_AGAIN`: nothing ready.
        Again,
        /// A real failure.
        Fail(CURLcode),
    }

    /// One scripted transport send.
    #[derive(Clone, Debug)]
    enum SendStep {
        /// Accept up to this many bytes.
        Accept(usize),
        /// `CURLE_AGAIN`, which `Curl_xfer_send` converts to zero written.
        Again,
        /// A real failure.
        Fail(CURLcode),
    }

    /// One observed receive.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RecvRecord {
        channel: SocketIndex,
        wanted: usize,
        got: usize,
    }

    /// One observed client write.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct WriteRecord {
        flags: ClientWriteFlags,
        bytes: Vec<u8>,
    }

    /// One observed `Curl_expire`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TimerRecord {
        in_ms: TimeDiff,
        timer: ExpireId,
    }

    /// A progress callback that never refuses.
    #[derive(Debug, Default)]
    struct QuietCallback {
        /// Whether the handle is currently inside a callback.
        in_callback: bool,
        /// `Some(code)` makes both callbacks refuse with that code.
        refuse: Option<i32>,
    }

    impl ProgressCallback for QuietCallback {
        fn flavour(&self) -> Option<CallbackFlavour> {
            self.refuse.map(|_| CallbackFlavour::XferInfo)
        }

        fn set_in_callback(&mut self, active: bool) {
            self.in_callback = active;
        }

        fn xferinfo(&mut self, snapshot: &ProgressSnapshot) -> i32 {
            let _ = snapshot;
            self.refuse.unwrap_or(0)
        }

        fn progress(&mut self, snapshot: &ProgressSnapshot) -> i32 {
            let _ = snapshot;
            self.refuse.unwrap_or(0)
        }
    }

    /// No `CURL_SMALLREQSEND` in the environment.
    #[derive(Debug)]
    struct NoEnv;

    impl DebugEnv for NoEnv {
        fn small_req_send(&self) -> Option<&str> {
            None
        }
    }

    // ---- the request half ------------------------------------------------

    /// [`RequestIo`], in memory.
    ///
    /// A field of [`FakeIo`] rather than the same value, because
    /// [`TransferIo::follow_seams`] must hand out the request half and the
    /// protocol half AT ONCE. Two disjoint fields make that a split borrow the
    /// compiler accepts; one value would need `unsafe`, which this crate forbids
    /// outside `src/ffi/`.
    #[derive(Debug)]
    struct FakeReq {
        clock: TestClock,
        progress: Progress,
        callback: QuietCallback,
        env: NoEnv,
        connected: bool,
        sends: VecDeque<SendStep>,
        /// `(offered, eos, accepted)` per send.
        send_log: Vec<(usize, bool, usize)>,
        needs_flush: bool,
        flushes: usize,
        send_closes: usize,
        /// The request body the client reader will hand over, in order.
        client_body: VecDeque<Vec<u8>>,
        client_reads: usize,
        send_shutdowns: VecDeque<CodeResult<SendShutdown>>,
        info: Vec<String>,
        fail: Vec<String>,
        trace: Vec<String>,
        pgrs_timers: Vec<PgrsTimer>,
    }

    impl Default for FakeReq {
        fn default() -> Self {
            Self {
                clock: TestClock::new(CurlTime::new(1_000, 0)),
                progress: Progress::default(),
                callback: QuietCallback::default(),
                env: NoEnv,
                connected: true,
                sends: VecDeque::new(),
                send_log: Vec::new(),
                needs_flush: false,
                flushes: 0,
                send_closes: 0,
                client_body: VecDeque::new(),
                client_reads: 0,
                send_shutdowns: VecDeque::new(),
                info: Vec::new(),
                fail: Vec::new(),
                trace: Vec::new(),
                pgrs_timers: Vec::new(),
            }
        }
    }

    impl RequestIo for FakeReq {
        fn config(&self) -> RequestConfig {
            RequestConfig::default()
        }

        fn has_connection(&self) -> bool {
            self.connected
        }

        fn debug_env(&self) -> Option<&dyn DebugEnv> {
            Some(&self.env)
        }

        fn xfer_send(&mut self, bytes: &[u8], eos: bool) -> CodeResult<usize> {
            let step = self
                .sends
                .pop_front()
                .unwrap_or(SendStep::Accept(usize::MAX));
            let accepted = match step {
                SendStep::Fail(code) => return Err(code),
                SendStep::Again => return Err(CURLcode::Again),
                SendStep::Accept(count) => count.min(bytes.len()),
            };
            self.send_log.push((bytes.len(), eos, accepted));
            Ok(accepted)
        }

        fn xfer_needs_flush(&self) -> bool {
            self.needs_flush
        }

        fn xfer_flush(&mut self) -> CodeResult<()> {
            self.flushes += 1;
            Ok(())
        }

        fn xfer_send_close(&mut self) -> CodeResult<()> {
            self.send_closes += 1;
            Ok(())
        }

        fn xfer_send_shutdown(&mut self) -> CodeResult<SendShutdown> {
            self.send_shutdowns
                .pop_front()
                .unwrap_or(Ok(SendShutdown::Complete))
        }

        fn client_read(&mut self, into: &mut [u8]) -> CodeResult<ReadOutcome> {
            self.client_reads += 1;
            let Some(chunk) = self.client_body.pop_front() else {
                return Ok(ReadOutcome::EOS);
            };
            let taken = chunk.len().min(into.len());
            into[..taken].copy_from_slice(&chunk[..taken]);
            if taken < chunk.len() {
                self.client_body.push_front(chunk[taken..].to_vec());
            }
            Ok(ReadOutcome::new(taken, self.client_body.is_empty()))
        }

        fn creader_done(&mut self, premature: bool) {
            let _ = premature;
        }

        fn creader_total_length(&self) -> i64 {
            0
        }

        fn client_start(&mut self) -> CodeResult<()> {
            Ok(())
        }

        fn client_reset(&mut self) {}

        fn client_cleanup(&mut self) {}

        fn doh_close(&mut self) {}

        fn progress(&self) -> &Progress {
            &self.progress
        }

        fn progress_mut(&mut self) -> &mut Progress {
            &mut self.progress
        }

        fn pgrs_now(&mut self) -> CurlTime {
            self.progress.sample(&self.clock)
        }

        fn pgrs_time(&mut self, timer: PgrsTimer) {
            self.pgrs_timers.push(timer);
            self.progress.time(timer, &self.clock);
        }

        fn debug(&mut self, kind: TraceDataKind, bytes: &[u8]) {
            let _ = (kind, bytes);
        }

        fn infof(&mut self, line: fmt::Arguments<'_>) {
            self.info.push(line.to_string());
        }

        fn failf(&mut self, line: fmt::Arguments<'_>) {
            self.fail.push(line.to_string());
        }

        fn trace(&mut self, line: fmt::Arguments<'_>) {
            self.trace.push(line.to_string());
        }
    }

    // ---- the scheduler half ----------------------------------------------

    /// [`TransferScheduler`], in memory.
    #[derive(Debug)]
    struct FakeSched {
        timers: Vec<TimerRecord>,
        expire_clears: usize,
        dirty: bool,
        dirty_marks: usize,
        dirty_clears: usize,
        parks: usize,
        pending_runs: usize,
        /// Answers for `multi_changed`, consumed only by a clearing call.
        changed: VecDeque<bool>,
        notify_done: usize,
        assess: Result<(), CURLMcode>,
        assessments: usize,
        dead: bool,
        buf_borrows: usize,
        buf_size: usize,
        buf_borrow_result: Option<CURLcode>,
    }

    impl Default for FakeSched {
        fn default() -> Self {
            Self {
                timers: Vec::new(),
                expire_clears: 0,
                dirty: false,
                dirty_marks: 0,
                dirty_clears: 0,
                parks: 0,
                pending_runs: 0,
                changed: VecDeque::new(),
                notify_done: 0,
                assess: Ok(()),
                assessments: 0,
                dead: false,
                buf_borrows: 0,
                buf_size: 16_384,
                buf_borrow_result: None,
            }
        }
    }

    impl TransferScheduler for FakeSched {
        fn expire(&mut self, timeout_ms: TimeDiff, timer: ExpireId) {
            self.timers.push(TimerRecord {
                in_ms: timeout_ms,
                timer,
            });
        }

        fn expire_clear(&mut self) {
            self.expire_clears += 1;
        }

        fn mark_dirty(&mut self) {
            self.dirty = true;
            self.dirty_marks += 1;
        }

        fn clear_dirty(&mut self) {
            self.dirty = false;
            self.dirty_clears += 1;
        }

        fn park_pending(&mut self) {
            self.parks += 1;
        }

        fn process_pending_handles(&mut self) {
            self.pending_runs += 1;
        }

        fn multi_changed(&mut self, clear: bool) -> bool {
            match self.changed.front().copied() {
                // A peek does not consume; only the C's
                // `multi_ischanged(multi, TRUE)` does.
                Some(answer) => {
                    if clear {
                        self.changed.pop_front();
                    }
                    answer
                }
                None => false,
            }
        }

        fn notify_easy_done(&mut self) {
            self.notify_done += 1;
        }

        fn assess_registrations(&mut self) -> Result<(), CURLMcode> {
            self.assessments += 1;
            self.assess
        }

        fn is_dead(&self) -> bool {
            self.dead
        }

        fn xfer_buf_borrow(&mut self) -> CodeResult<Vec<u8>> {
            self.buf_borrows += 1;
            match self.buf_borrow_result {
                Some(code) => Err(code),
                None => Ok(vec![0_u8; self.buf_size.max(1)]),
            }
        }

        fn xfer_buf_release(&mut self, buf: Vec<u8>) {
            // The real owner keeps the allocation; the length is all a test
            // needs to see come back.
            self.buf_size = buf.len();
        }
    }

    // ---- the follow half -------------------------------------------------

    /// [`ProtocolFollow`], scripted.
    #[derive(Debug, Default)]
    struct FakeFollow {
        /// What `resolve_target` answers, in order.
        resolve: VecDeque<ResolvedTarget>,
        /// The URL `commit_url` last received.
        committed: Option<String>,
        /// The method in flight.
        method: HttpRequestKind,
        /// Every `resolve_target` argument pair, in order.
        resolved: Vec<(String, FollowType)>,
    }

    impl ProtocolFollow for FakeFollow {
        fn target_is_absolute(&self, target: &str) -> bool {
            target.contains("://")
        }

        fn resolve_target(
            &mut self,
            target: &str,
            follow_type: FollowType,
        ) -> ResolvedTarget {
            self.resolved.push((target.to_string(), follow_type));
            self.resolve
                .pop_front()
                .unwrap_or_else(|| ResolvedTarget::Url(target.to_string()))
        }

        fn set_auto_referer(&mut self) -> CodeResult<()> {
            Ok(())
        }

        fn clear_auth_if_moved(&mut self, allow_port: bool) -> CodeResult<()> {
            let _ = allow_port;
            Ok(())
        }

        fn commit_url(&mut self, url: String) {
            self.committed = Some(url);
        }

        fn request_method(&self) -> HttpRequestKind {
            self.method
        }

        fn set_request_method(&mut self, method: HttpRequestKind) {
            self.method = method;
        }

        fn custom_request(&self) -> Option<&str> {
            None
        }
    }

    // ---- the whole seam --------------------------------------------------

    /// [`TransferIo`], in memory, over the three halves above.
    #[derive(Debug)]
    struct FakeIo {
        req: FakeReq,
        sched: FakeSched,
        follow: FakeFollow,

        /// Both filter chains, for [`TransferIo::xfer_ctx`].
        chains: FilterChains,
        limits: LowSpeedLimit,
        /// What `Curl_timeleft_ms` answers. `0` is "no limit".
        timeleft: TimeDiff,
        /// Answers for `Curl_timeleft_ms` BEFORE `timeleft`, in order. The real
        /// one is clock-derived and so changes within one driver iteration,
        /// which is exactly what the second timeout check depends on.
        timeleft_steps: VecDeque<TimeDiff>,
        /// Makes `xfer_ctx` fail even though a scheme is registered.
        xfer_ctx_fails: Option<CURLcode>,

        // -- the connection
        scheme: Option<&'static Scheme>,
        connected: bool,
        reused: bool,
        wants_close: bool,
        multiplex_bit: bool,
        multiplex: bool,
        wants_do_more: bool,
        protoconn_started: bool,
        pending_data: bool,
        shutdown_started: bool,

        // -- scripted transport
        recvs: VecDeque<RecvStep>,
        recv_log: Vec<RecvRecord>,
        conn_sends: VecDeque<SendStep>,
        conn_send_log: Vec<(usize, bool, usize)>,
        shutdowns: VecDeque<CodeResult<AsyncStep>>,
        flushes: usize,

        // -- scripted lifecycle
        connects: VecDeque<CodeResult<ConnectOutcome>>,
        conn_connects: VecDeque<CodeResult<AsyncStep>>,
        resolver_checks: VecDeque<CodeResult<ResolveStep>>,
        once_resolveds: VecDeque<CodeResult<AsyncStep>>,
        resolver_shutdowns: usize,
        hang_connect: Option<Duration>,
        hang_conn_connect: Option<Duration>,

        // -- scripted client chains
        writes: VecDeque<CodeResult<()>>,
        write_log: Vec<WriteRecord>,
        write_done: Vec<bool>,
        write_done_result: CodeResult<()>,
        writer_paused: bool,
        writer_unpause: CodeResult<()>,
        writer_unpauses: usize,
        reader_paused: bool,
        reader_unpause: CodeResult<()>,
        reader_unpauses: usize,
        rewinds: Vec<bool>,
        upload_bindings: usize,

        // -- connection lifecycle recordings
        stream_closes: Vec<&'static str>,
        conn_closes: Vec<&'static str>,
        retries: usize,
        detaches: usize,
        terminates: Vec<bool>,
        completions: Vec<bool>,
        completion_outcome: ConnectionOutcome,
        pauses: Vec<bool>,
        data_dones: Vec<bool>,
        done_sends: usize,
        nometer_updates: usize,

        // -- pretransfer services
        url_handle: Option<CodeResult<String>>,
        cookie_load: CodeResult<()>,
        cookie_runs: usize,
        resolve_list: bool,
        host_pairs: CodeResult<()>,
        host_pair_calls: usize,
        hsts_files: CodeResult<()>,
        hsts_cb: CodeResult<()>,
        wildcard: CodeResult<()>,
        wildcard_calls: usize,
        info_inits: usize,
        priority_clears: usize,
        header_cleanups: usize,
        netrc_cleanups: usize,
        prereq: Option<i32>,
        negotiation: HttpNegotiation,

        // -- protocol seams
        writes_response_headers: bool,
        has_connecting: bool,
        follow_settings: FollowSettings,
        h2_downgrade: bool,

        // -- diagnostics
        multi_trace: Vec<String>,
        write_trace: Vec<String>,
    }

    impl Default for FakeIo {
        fn default() -> Self {
            Self {
                req: FakeReq::default(),
                sched: FakeSched::default(),
                follow: FakeFollow::default(),
                chains: FilterChains::new(None),
                limits: LowSpeedLimit::new(0, 0),
                timeleft: 0,
                timeleft_steps: VecDeque::new(),
                xfer_ctx_fails: None,
                scheme: Some(&SCHEME_HTTP),
                connected: true,
                reused: false,
                wants_close: false,
                multiplex_bit: false,
                multiplex: false,
                wants_do_more: false,
                protoconn_started: false,
                pending_data: false,
                shutdown_started: false,
                recvs: VecDeque::new(),
                recv_log: Vec::new(),
                conn_sends: VecDeque::new(),
                conn_send_log: Vec::new(),
                shutdowns: VecDeque::new(),
                flushes: 0,
                connects: VecDeque::new(),
                conn_connects: VecDeque::new(),
                resolver_checks: VecDeque::new(),
                once_resolveds: VecDeque::new(),
                resolver_shutdowns: 0,
                hang_connect: None,
                hang_conn_connect: None,
                writes: VecDeque::new(),
                write_log: Vec::new(),
                write_done: Vec::new(),
                write_done_result: Ok(()),
                writer_paused: false,
                writer_unpause: Ok(()),
                writer_unpauses: 0,
                reader_paused: false,
                reader_unpause: Ok(()),
                reader_unpauses: 0,
                rewinds: Vec::new(),
                upload_bindings: 0,
                stream_closes: Vec::new(),
                conn_closes: Vec::new(),
                retries: 0,
                detaches: 0,
                terminates: Vec::new(),
                completions: Vec::new(),
                completion_outcome: ConnectionOutcome {
                    recent: Some(7),
                    last: Some(7),
                    still_in_use: false,
                },
                pauses: Vec::new(),
                data_dones: Vec::new(),
                done_sends: 0,
                nometer_updates: 0,
                url_handle: None,
                cookie_load: Ok(()),
                cookie_runs: 0,
                resolve_list: false,
                host_pairs: Ok(()),
                host_pair_calls: 0,
                hsts_files: Ok(()),
                hsts_cb: Ok(()),
                wildcard: Ok(()),
                wildcard_calls: 0,
                info_inits: 0,
                priority_clears: 0,
                header_cleanups: 0,
                netrc_cleanups: 0,
                prereq: None,
                negotiation: HttpNegotiation::default(),
                writes_response_headers: false,
                has_connecting: false,
                follow_settings: FollowSettings {
                    mode: FollowMode::All,
                    maxredirs: MAXREDIRS_DEFAULT,
                    postredir: PostRedir {
                        post301: false,
                        post302: false,
                        post303: false,
                    },
                    auto_referer: false,
                    allow_auth_to_other_hosts: false,
                },
                h2_downgrade: false,
                multi_trace: Vec::new(),
                write_trace: Vec::new(),
            }
        }
    }

    impl FakeIo {
        /// Whether any recorded line contains `needle`.
        fn traced(&self, needle: &str) -> bool {
            self.multi_trace.iter().any(|line| line.contains(needle))
                || self.write_trace.iter().any(|line| line.contains(needle))
                || self.req.trace.iter().any(|line| line.contains(needle))
                || self.req.info.iter().any(|line| line.contains(needle))
        }

        /// Whether any `failf` line contains `needle`.
        fn failed_with(&self, needle: &str) -> bool {
            self.req.fail.iter().any(|line| line.contains(needle))
        }

        /// Every deadline armed under `timer`, in order.
        fn armed(&self, timer: ExpireId) -> Vec<TimeDiff> {
            self.sched
                .timers
                .iter()
                .filter(|record| record.timer == timer)
                .map(|record| record.in_ms)
                .collect()
        }

        /// Every state name traced, in transition order.
        fn states(&self) -> Vec<String> {
            self.multi_trace
                .iter()
                .filter(|line| line.starts_with("-> ["))
                .cloned()
                .collect()
        }
    }

    impl TransferIo for FakeIo {
        fn request_io(&mut self) -> &mut dyn RequestIo {
            &mut self.req
        }

        fn request_io_ref(&self) -> &dyn RequestIo {
            &self.req
        }

        fn scheduler(&mut self) -> &mut dyn TransferScheduler {
            &mut self.sched
        }

        fn pgrs_check(&mut self, req_done: bool) -> CurlResult<Check> {
            let now = self.req.progress.sample(&self.req.clock);
            let paused = Paused {
                recv: self.req.progress.download().rlimit().is_blocked(),
                send: self.req.progress.upload().rlimit().is_blocked(),
            };
            self.req.progress.check(
                now,
                req_done,
                self.limits,
                paused,
                &mut self.req.callback,
            )
        }

        fn pgrs_update(&mut self, req_done: bool) -> CurlResult<Meter> {
            let now = self.req.progress.sample(&self.req.clock);
            self.req
                .progress
                .update(now, req_done, &mut self.req.callback)
        }

        fn pgrs_update_nometer(&mut self, req_done: bool) {
            self.nometer_updates += 1;
            let now = self.req.progress.sample(&self.req.clock);
            self.req.progress.update_nometer(now, req_done);
        }

        fn pgrs_done(&mut self, req_done: bool) -> CurlResult<PgrsDone> {
            let now = self.req.progress.sample(&self.req.clock);
            self.req
                .progress
                .done(now, req_done, &mut self.req.callback)
        }

        fn timeleft_ms(&mut self) -> TimeDiff {
            self.timeleft_steps.pop_front().unwrap_or(self.timeleft)
        }

        fn has_connection(&self) -> bool {
            self.connected
        }

        fn scheme(&self) -> Option<&'static Scheme> {
            self.scheme
        }

        fn conn_is_reused(&self) -> bool {
            self.reused
        }

        fn conn_wants_close(&self) -> bool {
            self.wants_close
        }

        fn conn_multiplex_bit(&self) -> bool {
            self.multiplex_bit
        }

        fn conn_is_multiplex(&mut self, channel: SocketIndex) -> bool {
            let _ = channel;
            self.multiplex
        }

        fn conn_wants_do_more(&self) -> bool {
            self.wants_do_more
        }

        fn protoconn_started(&self) -> bool {
            self.protoconn_started
        }

        fn set_protoconn_started(&mut self) {
            self.protoconn_started = true;
        }

        fn conn_data_pending(&mut self, channel: SocketIndex) -> bool {
            let _ = channel;
            self.pending_data
        }

        fn conn_send(
            &mut self,
            channel: SocketIndex,
            buf: &[u8],
            eos: bool,
        ) -> CodeResult<usize> {
            let _ = channel;
            let step = self
                .conn_sends
                .pop_front()
                .unwrap_or(SendStep::Accept(usize::MAX));
            let accepted = match step {
                SendStep::Fail(code) => return Err(code),
                SendStep::Again => return Err(CURLcode::Again),
                SendStep::Accept(count) => count.min(buf.len()),
            };
            self.conn_send_log.push((buf.len(), eos, accepted));
            Ok(accepted)
        }

        fn conn_recv(
            &mut self,
            channel: SocketIndex,
            buf: &mut [u8],
        ) -> CodeResult<usize> {
            let step = self.recvs.pop_front().unwrap_or(RecvStep::Eos);
            let wanted = buf.len();
            let got = match step {
                RecvStep::Fail(code) => {
                    self.recv_log.push(RecvRecord {
                        channel,
                        wanted,
                        got: 0,
                    });
                    return Err(code);
                }
                RecvStep::Again => {
                    self.recv_log.push(RecvRecord {
                        channel,
                        wanted,
                        got: 0,
                    });
                    return Err(CURLcode::Again);
                }
                RecvStep::Eos => 0,
                RecvStep::Bytes(bytes) => {
                    let count = bytes.len().min(wanted);
                    buf[..count].copy_from_slice(&bytes[..count]);
                    if count < bytes.len() {
                        self.recvs.push_front(RecvStep::Bytes(
                            bytes[count..].to_vec(),
                        ));
                    }
                    count
                }
            };
            self.recv_log.push(RecvRecord {
                channel,
                wanted,
                got,
            });
            Ok(got)
        }

        fn conn_needs_flush(&mut self, channel: SocketIndex) -> bool {
            let _ = channel;
            self.req.needs_flush
        }

        fn conn_flush(&mut self, channel: SocketIndex) -> CodeResult<()> {
            let _ = channel;
            self.flushes += 1;
            Ok(())
        }

        fn conn_shutdown(
            &mut self,
            channel: SocketIndex,
        ) -> CodeResult<AsyncStep> {
            let _ = channel;
            self.shutdowns
                .pop_front()
                .unwrap_or(Ok(AsyncStep::Complete))
        }

        fn conn_shutdown_started(&mut self, channel: SocketIndex) -> bool {
            let _ = channel;
            self.shutdown_started
        }

        fn stream_close(&mut self, reason: &'static str) {
            self.stream_closes.push(reason);
        }

        fn conn_close(&mut self, reason: &'static str) {
            self.conn_closes.push(reason);
        }

        fn conn_mark_retry(&mut self) {
            self.retries += 1;
        }

        fn detach_connection(&mut self) {
            self.detaches += 1;
            self.connected = false;
            self.req.connected = false;
        }

        fn terminate_connection(&mut self, dead: bool) {
            self.terminates.push(dead);
        }

        fn complete_connection(
            &mut self,
            premature: bool,
        ) -> ConnectionOutcome {
            self.completions.push(premature);
            self.completion_outcome
        }

        fn ev_data_pause(&mut self, pause: bool) {
            self.pauses.push(pause);
        }

        fn ev_data_done(&mut self, premature: bool) {
            self.data_dones.push(premature);
        }

        fn ev_data_done_send(&mut self) {
            self.done_sends += 1;
        }

        fn connect(&mut self) -> XferFuture<'_, ConnectOutcome> {
            if let Some(span) = self.hang_connect {
                return Box::pin(async move {
                    tokio::time::sleep(span).await;
                    Ok(ConnectOutcome::Connected)
                });
            }
            let answer = self
                .connects
                .pop_front()
                .unwrap_or(Ok(ConnectOutcome::Connected));
            Box::pin(core::future::ready(answer))
        }

        fn conn_connect(&mut self) -> XferFuture<'_, AsyncStep> {
            if let Some(span) = self.hang_conn_connect {
                return Box::pin(async move {
                    tokio::time::sleep(span).await;
                    Ok(AsyncStep::Complete)
                });
            }
            let answer = self
                .conn_connects
                .pop_front()
                .unwrap_or(Ok(AsyncStep::Complete));
            Box::pin(core::future::ready(answer))
        }

        fn resolver_check(&mut self) -> XferFuture<'_, ResolveStep> {
            let answer = self
                .resolver_checks
                .pop_front()
                .unwrap_or(Ok(ResolveStep::Resolved));
            Box::pin(core::future::ready(answer))
        }

        fn once_resolved(&mut self) -> XferFuture<'_, AsyncStep> {
            let answer = self
                .once_resolveds
                .pop_front()
                .unwrap_or(Ok(AsyncStep::Complete));
            Box::pin(core::future::ready(answer))
        }

        fn resolver_shutdown(&mut self) {
            self.resolver_shutdowns += 1;
        }

        fn protocol(&self) -> Option<&'static dyn Protocol> {
            self.scheme.and_then(|scheme| scheme.run)
        }

        fn xfer_ctx(&mut self) -> CodeResult<TransferCtx<'_>> {
            if let Some(code) = self.xfer_ctx_fails {
                return Err(code);
            }
            let scheme = self.scheme.ok_or(CURLcode::FailedInit)?;
            // Disjoint fields, so one `&mut self` yields both borrows.
            Ok(TransferCtx::new(&mut self.chains, &self.req.clock, scheme))
        }

        fn writes_response_headers(&self) -> bool {
            self.writes_response_headers
        }

        fn protocol_has_connecting(&self) -> bool {
            self.has_connecting
        }

        fn follow_seams(
            &mut self,
        ) -> (&mut dyn RequestIo, Option<&mut dyn ProtocolFollow>) {
            // The split borrow this double exists to demonstrate: `req` and
            // `follow` are disjoint fields, so both come out of one `&mut self`
            // with no `unsafe` anywhere.
            let has_follow =
                self.scheme.and_then(|scheme| scheme.run).is_some();
            let protocol: Option<&mut dyn ProtocolFollow> = if has_follow {
                Some(&mut self.follow)
            } else {
                None
            };
            (&mut self.req, protocol)
        }

        fn follow_settings(&self) -> FollowSettings {
            self.follow_settings
        }

        fn h2_http_1_1_error(&self) -> bool {
            self.h2_downgrade
        }

        fn client_write(
            &mut self,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CodeResult<()> {
            self.write_log.push(WriteRecord {
                flags,
                bytes: buf.to_vec(),
            });
            self.writes.pop_front().unwrap_or(Ok(()))
        }

        fn client_write_done(&mut self, premature: bool) -> CodeResult<()> {
            self.write_done.push(premature);
            self.write_done_result
        }

        fn client_writer_is_paused(&self) -> bool {
            self.writer_paused
        }

        fn client_writer_unpause(&mut self) -> CodeResult<()> {
            self.writer_unpauses += 1;
            self.writer_unpause
        }

        fn client_reader_is_paused(&self) -> bool {
            self.reader_paused
        }

        fn client_reader_unpause(&mut self) -> CodeResult<()> {
            self.reader_unpauses += 1;
            self.reader_unpause
        }

        fn client_reader_set_rewind(&mut self, rewind: bool) {
            self.rewinds.push(rewind);
        }

        fn bind_upload_source(&mut self) {
            self.upload_bindings += 1;
        }

        fn url_from_handle(&mut self) -> Option<CodeResult<String>> {
            self.url_handle.clone()
        }

        fn cookie_loadfiles(&mut self) -> CodeResult<()> {
            self.cookie_load
        }

        fn cookie_run(&mut self) {
            self.cookie_runs += 1;
        }

        fn has_resolve_list(&self) -> bool {
            self.resolve_list
        }

        fn load_host_pairs(&mut self) -> CodeResult<()> {
            self.host_pair_calls += 1;
            self.host_pairs
        }

        fn hsts_loadfiles(&mut self) -> CodeResult<()> {
            self.hsts_files
        }

        fn hsts_loadcb(&mut self) -> CodeResult<()> {
            self.hsts_cb
        }

        fn wildcard_init(&mut self) -> CodeResult<()> {
            self.wildcard_calls += 1;
            self.wildcard
        }

        fn init_info(&mut self) {
            self.info_inits += 1;
        }

        fn priority_clear_state(&mut self) {
            self.priority_clears += 1;
        }

        fn http_neg_init(&mut self) -> HttpNegotiation {
            self.negotiation
        }

        fn headers_cleanup(&mut self) {
            self.header_cleanups += 1;
        }

        fn netrc_cleanup(&mut self) {
            self.netrc_cleanups += 1;
        }

        fn prereq(&mut self) -> Option<i32> {
            self.prereq
        }

        fn trace_multi(&mut self, line: fmt::Arguments<'_>) {
            self.multi_trace.push(line.to_string());
        }

        fn trace_write(&mut self, line: fmt::Arguments<'_>) {
            self.write_trace.push(line.to_string());
        }
    }

    // ---- the seam with NOTHING configured ---------------------------------

    /// [`TransferIo`] with every DEFAULTED member left at its default.
    ///
    /// The trait's twelve-odd optional members carry defaults that spell out
    /// what a transfer whose owner configured nothing gets: no `CURLU` handle,
    /// no cookie jar, no `CURLOPT_RESOLVE` pairs, no HSTS cache, no wildcard
    /// match, no pre-request callback, no HTTP/2 downgrade and no trace sink.
    /// [`FakeIo`] overrides all of them so that tests can script them, which
    /// leaves the defaults themselves unexercised -- so this wrapper delegates
    /// only the REQUIRED members and inherits the rest.
    #[derive(Debug, Default)]
    struct BareIo(FakeIo);

    impl TransferIo for BareIo {
        fn request_io(&mut self) -> &mut dyn RequestIo {
            self.0.request_io()
        }

        fn request_io_ref(&self) -> &dyn RequestIo {
            self.0.request_io_ref()
        }

        fn scheduler(&mut self) -> &mut dyn TransferScheduler {
            self.0.scheduler()
        }

        fn pgrs_check(&mut self, req_done: bool) -> CurlResult<Check> {
            self.0.pgrs_check(req_done)
        }

        fn pgrs_update(&mut self, req_done: bool) -> CurlResult<Meter> {
            self.0.pgrs_update(req_done)
        }

        fn pgrs_update_nometer(&mut self, req_done: bool) {
            self.0.pgrs_update_nometer(req_done)
        }

        fn pgrs_done(&mut self, req_done: bool) -> CurlResult<PgrsDone> {
            self.0.pgrs_done(req_done)
        }

        fn timeleft_ms(&mut self) -> TimeDiff {
            self.0.timeleft_ms()
        }

        fn has_connection(&self) -> bool {
            self.0.has_connection()
        }

        fn scheme(&self) -> Option<&'static Scheme> {
            self.0.scheme()
        }

        fn conn_is_reused(&self) -> bool {
            self.0.conn_is_reused()
        }

        fn conn_wants_close(&self) -> bool {
            self.0.conn_wants_close()
        }

        fn conn_multiplex_bit(&self) -> bool {
            self.0.conn_multiplex_bit()
        }

        fn conn_is_multiplex(&mut self, channel: SocketIndex) -> bool {
            self.0.conn_is_multiplex(channel)
        }

        fn conn_wants_do_more(&self) -> bool {
            self.0.conn_wants_do_more()
        }

        fn protoconn_started(&self) -> bool {
            self.0.protoconn_started()
        }

        fn set_protoconn_started(&mut self) {
            self.0.set_protoconn_started()
        }

        fn conn_data_pending(&mut self, channel: SocketIndex) -> bool {
            self.0.conn_data_pending(channel)
        }

        fn conn_send(
            &mut self,
            channel: SocketIndex,
            buf: &[u8],
            eos: bool,
        ) -> CodeResult<usize> {
            self.0.conn_send(channel, buf, eos)
        }

        fn conn_recv(
            &mut self,
            channel: SocketIndex,
            buf: &mut [u8],
        ) -> CodeResult<usize> {
            self.0.conn_recv(channel, buf)
        }

        fn conn_needs_flush(&mut self, channel: SocketIndex) -> bool {
            self.0.conn_needs_flush(channel)
        }

        fn conn_flush(&mut self, channel: SocketIndex) -> CodeResult<()> {
            self.0.conn_flush(channel)
        }

        fn conn_shutdown(
            &mut self,
            channel: SocketIndex,
        ) -> CodeResult<AsyncStep> {
            self.0.conn_shutdown(channel)
        }

        fn conn_shutdown_started(&mut self, channel: SocketIndex) -> bool {
            self.0.conn_shutdown_started(channel)
        }

        fn stream_close(&mut self, reason: &'static str) {
            self.0.stream_close(reason)
        }

        fn conn_close(&mut self, reason: &'static str) {
            self.0.conn_close(reason)
        }

        fn conn_mark_retry(&mut self) {
            self.0.conn_mark_retry()
        }

        fn detach_connection(&mut self) {
            self.0.detach_connection()
        }

        fn terminate_connection(&mut self, dead: bool) {
            self.0.terminate_connection(dead)
        }

        fn complete_connection(
            &mut self,
            premature: bool,
        ) -> ConnectionOutcome {
            self.0.complete_connection(premature)
        }

        fn ev_data_pause(&mut self, pause: bool) {
            self.0.ev_data_pause(pause)
        }

        fn ev_data_done(&mut self, premature: bool) {
            self.0.ev_data_done(premature)
        }

        fn ev_data_done_send(&mut self) {
            self.0.ev_data_done_send()
        }

        fn connect(&mut self) -> XferFuture<'_, ConnectOutcome> {
            self.0.connect()
        }

        fn conn_connect(&mut self) -> XferFuture<'_, AsyncStep> {
            self.0.conn_connect()
        }

        fn resolver_check(&mut self) -> XferFuture<'_, ResolveStep> {
            self.0.resolver_check()
        }

        fn once_resolved(&mut self) -> XferFuture<'_, AsyncStep> {
            self.0.once_resolved()
        }

        fn resolver_shutdown(&mut self) {
            self.0.resolver_shutdown()
        }

        fn protocol(&self) -> Option<&'static dyn Protocol> {
            self.0.protocol()
        }

        fn xfer_ctx(&mut self) -> CodeResult<TransferCtx<'_>> {
            self.0.xfer_ctx()
        }

        fn writes_response_headers(&self) -> bool {
            self.0.writes_response_headers()
        }

        fn protocol_has_connecting(&self) -> bool {
            self.0.protocol_has_connecting()
        }

        fn follow_seams(
            &mut self,
        ) -> (&mut dyn RequestIo, Option<&mut dyn ProtocolFollow>) {
            self.0.follow_seams()
        }

        fn follow_settings(&self) -> FollowSettings {
            self.0.follow_settings()
        }

        fn client_write(
            &mut self,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CodeResult<()> {
            self.0.client_write(flags, buf)
        }

        fn client_write_done(&mut self, premature: bool) -> CodeResult<()> {
            self.0.client_write_done(premature)
        }

        fn client_writer_is_paused(&self) -> bool {
            self.0.client_writer_is_paused()
        }

        fn client_writer_unpause(&mut self) -> CodeResult<()> {
            self.0.client_writer_unpause()
        }

        fn client_reader_is_paused(&self) -> bool {
            self.0.client_reader_is_paused()
        }

        fn client_reader_unpause(&mut self) -> CodeResult<()> {
            self.0.client_reader_unpause()
        }

        fn client_reader_set_rewind(&mut self, rewind: bool) {
            self.0.client_reader_set_rewind(rewind)
        }

        fn init_info(&mut self) {
            self.0.init_info()
        }

        fn headers_cleanup(&mut self) {
            self.0.headers_cleanup()
        }
    }

    // ---- fixtures --------------------------------------------------------

    /// A transfer with a URL set, so [`Transfer::pretransfer`] succeeds.
    fn transfer() -> Transfer {
        let settings = TransferSettings {
            url: Some(String::from("http://example.com/")),
            // `Curl_xfer_recv` asserts a positive buffer size
            // (`lib/transfer.c:858`); curl's own default is 16 KiB.
            buffer_size: 16_384,
            ..TransferSettings::default()
        };
        Transfer::new(settings)
    }

    /// A transfer and its seam, with the protocol script cleared.
    ///
    /// The request is STARTED, because `Curl_req_start` is what builds the send
    /// queue and the driver always reaches it before any I/O: without it
    /// `Curl_req_send_more` answers `CURLE_FAILED_INIT` from
    /// `sendbuf_fill_from_client`, which is a fixture artefact rather than a
    /// behaviour worth asserting.
    fn fixture() -> (Transfer, FakeIo) {
        proto_reset();
        let mut xfer = transfer();
        let mut io = FakeIo::default();
        xfer.req.start(io.request_io()).expect("the request starts");
        (xfer, io)
    }

    /// Places `xfer` in `state` without asserting anything about the journey.
    fn park(xfer: &mut Transfer, io: &mut FakeIo, state: CurlMstate) {
        xfer.set_mstate(io, state);
        io.multi_trace.clear();
        io.sched.timers.clear();
        io.sched.notify_done = 0;
        io.sched.pending_runs = 0;
    }
    // ---- 1. the state matrix ---------------------------------------------

    /// `mstate()` (`lib/curl_trc.c`): all seventeen names, exactly.
    ///
    /// The names are consumed from [`CurlMstate`] rather than redeclared, and
    /// this asserts the consumption: a rename there would change the trace line
    /// `-> [%s]` that `--trace` emits, which is byte-sensitive output.
    #[test]
    fn every_state_traces_its_c_name() {
        let expected = [
            (CurlMstate::Init, "INIT"),
            (CurlMstate::Pending, "PENDING"),
            (CurlMstate::Setup, "SETUP"),
            (CurlMstate::Connect, "CONNECT"),
            (CurlMstate::Resolving, "RESOLVING"),
            (CurlMstate::Connecting, "CONNECTING"),
            (CurlMstate::ProtoConnect, "PROTOCONNECT"),
            (CurlMstate::ProtoConnecting, "PROTOCONNECTING"),
            (CurlMstate::Do, "DO"),
            (CurlMstate::Doing, "DOING"),
            (CurlMstate::DoingMore, "DOING_MORE"),
            (CurlMstate::Did, "DID"),
            (CurlMstate::Performing, "PERFORMING"),
            (CurlMstate::RateLimiting, "RATELIMITING"),
            (CurlMstate::Done, "DONE"),
            (CurlMstate::Completed, "COMPLETED"),
            (CurlMstate::MsgSent, "MSGSENT"),
        ];
        assert_eq!(expected.len(), CurlMstate::COUNT);
        for (state, name) in expected {
            assert_eq!(state.name(), name, "{state:?}");
        }
        // The out-of-range fallback, which the C spells `"?"`.
        assert_eq!(CurlMstate::name_from_i32(i32::from(CurlMstate::LAST)), "?");
        assert_eq!(CurlMstate::name_from_i32(-1), "?");
    }

    /// `default: return CURLM_INTERNAL_ERROR` (`lib/multi.c:2713-2714`).
    ///
    /// `MSTATE_LAST` is *"not a true state, never use this"*
    /// (`lib/multihandle.h:69`), and every integer outside the enumeration
    /// answers the same way.
    #[test]
    fn an_invalid_state_integer_is_an_internal_error() {
        for raw in 0..i32::from(CurlMstate::LAST) {
            assert!(validate_state(raw).is_ok(), "{raw}");
        }
        assert_eq!(
            validate_state(i32::from(CurlMstate::LAST)),
            Err(CURLMcode::InternalError)
        );
        assert_eq!(validate_state(-1), Err(CURLMcode::InternalError));
        assert_eq!(validate_state(9_999), Err(CURLMcode::InternalError));
    }

    /// Every transition traces once, and a transition to the SAME state traces
    /// nothing (`lib/multi.c:158-160`).
    #[test]
    fn a_transition_to_the_same_state_is_silent() {
        let (mut xfer, mut io) = fixture();
        xfer.set_mstate(&mut io, CurlMstate::Setup);
        assert_eq!(io.states(), vec![String::from("-> [SETUP]")]);
        xfer.set_mstate(&mut io, CurlMstate::Setup);
        assert_eq!(io.states().len(), 1);
    }

    /// `DONE` notifies, and so does a direct jump to `COMPLETED` from before
    /// `DONE` (`lib/multi.c:169-180`).
    #[test]
    fn done_and_an_early_completion_both_notify() {
        let (mut xfer, mut io) = fixture();
        xfer.set_mstate(&mut io, CurlMstate::Done);
        assert_eq!(io.sched.notify_done, 1);

        // From DONE to COMPLETED is not a jump, so it does not notify again.
        xfer.set_mstate(&mut io, CurlMstate::Completed);
        assert_eq!(io.sched.notify_done, 1);

        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        xfer.set_mstate(&mut io, CurlMstate::Completed);
        assert_eq!(io.sched.notify_done, 1);
    }

    /// `init_completed` (`lib/multi.c:120-129`): entering `COMPLETED` detaches
    /// the connection and disarms every timer.
    #[test]
    fn completed_detaches_and_disarms() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        xfer.set_mstate(&mut io, CurlMstate::Completed);
        assert_eq!(io.detaches, 1);
        assert_eq!(io.sched.expire_clears, 1);
    }

    /// `Curl_init_CONNECT` (`lib/transfer.c:434-439`) runs on entry to
    /// `CONNECT`, and `before_perform` on entry to `DID`.
    #[test]
    fn the_c_finit_table_runs_on_the_right_states() {
        let (mut xfer, mut io) = fixture();
        xfer.state.upload = true;
        xfer.req.chunk = true;

        xfer.set_mstate(&mut io, CurlMstate::Connect);
        // `data->state.upload = (data->state.httpreq == HTTPREQ_PUT)` -- the
        // fixture's method is GET, so the flag is cleared.
        assert!(!xfer.state.upload);
        assert_eq!(io.upload_bindings, 1);

        xfer.set_mstate(&mut io, CurlMstate::Did);
        assert!(!xfer.req.chunk);
        assert!(io.req.pgrs_timers.contains(&PgrsTimer::PreTransfer));
    }

    // ---- 2. the driver's control values ----------------------------------

    /// [`DriverStep`] and [`RunSingle`] carry the C's two `CURLMcode` answers
    /// and nothing else.
    #[test]
    fn the_driver_control_maps_onto_the_c_codes() {
        assert!(DriverStep::RunAgain.runs_again());
        assert!(!DriverStep::Pending.runs_again());
        assert_eq!(
            DriverStep::RunAgain.as_multi_code(),
            CURLMcode::CallMultiPerform
        );
        assert_eq!(DriverStep::Pending.as_multi_code(), CURLMcode::Ok);

        assert_eq!(RunSingle::RunAgain.step(), DriverStep::RunAgain);
        assert_eq!(RunSingle::Pending.step(), DriverStep::Pending);
        // A completion does NOT loop again: the C returns `CURLM_OK` from
        // `handle_completed`'s branch.
        assert_eq!(
            RunSingle::Completed(CURLcode::Ok).step(),
            DriverStep::Pending
        );
        assert_eq!(RunSingle::Pending.completion(), None);
        assert_eq!(
            RunSingle::Completed(CURLcode::PartialFile).completion(),
            Some(CURLcode::PartialFile)
        );
    }

    /// [`AsyncStep`] and [`DoMoreStep`] replace the C's out-parameters, and
    /// their mappings are the C's integers.
    #[test]
    fn the_typed_steps_replace_the_c_out_parameters() {
        assert_eq!(AsyncStep::from_done(true), AsyncStep::Complete);
        assert_eq!(AsyncStep::from_done(false), AsyncStep::Pending);
        assert!(AsyncStep::Complete.is_complete());
        assert!(!AsyncStep::Pending.is_complete());
        assert_eq!(
            AsyncStep::from(SendShutdown::Complete),
            AsyncStep::Complete
        );
        assert_eq!(AsyncStep::from(SendShutdown::Pending), AsyncStep::Pending);

        // `multi_do_more`'s `int *completed`: 0 stays, 1 advances, -1 goes back.
        assert_eq!(DoMoreStep::from_complete(0), DoMoreStep::Pending);
        assert_eq!(DoMoreStep::from_complete(1), DoMoreStep::Advance);
        assert_eq!(DoMoreStep::from_complete(-1), DoMoreStep::Retry);
        assert_eq!(DoMoreStep::Pending.as_complete(), 0);
        assert_eq!(DoMoreStep::Advance.as_complete(), 1);
        assert_eq!(DoMoreStep::Retry.as_complete(), -1);
    }

    /// [`ChannelIndex`] admits exactly the C's three values.
    #[test]
    fn the_channel_index_admits_only_minus_one_zero_and_one() {
        assert_eq!(ChannelIndex::None.as_i32(), -1);
        assert_eq!(ChannelIndex::First.as_i32(), 0);
        assert_eq!(ChannelIndex::Secondary.as_i32(), 1);
        assert_eq!(ChannelIndex::from_i32(-1), Some(ChannelIndex::None));
        assert_eq!(ChannelIndex::from_i32(0), Some(ChannelIndex::First));
        assert_eq!(ChannelIndex::from_i32(1), Some(ChannelIndex::Secondary));
        assert_eq!(ChannelIndex::from_i32(2), None);
        assert_eq!(ChannelIndex::from_i32(-2), None);

        assert!(!ChannelIndex::None.is_valid());
        assert!(ChannelIndex::First.is_valid());
        assert!(ChannelIndex::Secondary.is_valid());
        assert_eq!(ChannelIndex::None.channel(), None);
        assert_eq!(ChannelIndex::First.channel(), Some(SocketIndex::First));
        assert_eq!(
            ChannelIndex::Secondary.channel(),
            Some(SocketIndex::Secondary)
        );
        assert_eq!(
            ChannelIndex::of(SocketIndex::Secondary),
            ChannelIndex::Secondary
        );
    }

    /// The fifteen timer names, consumed from [`crate::trace`] with the C's
    /// fallback.
    #[test]
    fn the_timer_names_this_layer_arms_are_the_c_names() {
        assert_eq!(ExpireId::Expect100Timeout.name(), "100_TIMEOUT");
        assert_eq!(ExpireId::ConnectTimeout.name(), "CONNECTTIMEOUT");
        assert_eq!(ExpireId::SpeedCheck.name(), "SPEEDCHECK");
        assert_eq!(ExpireId::Timeout.name(), "TIMEOUT");
        assert_eq!(ExpireId::TooFast.name(), "TOOFAST");
        assert_eq!(ExpireId::Shutdown.name(), "SHUTDOWN");
        assert_eq!(ExpireId::COUNT, 15);
        assert_eq!(
            ExpireId::name_from_i32(i32::from(ExpireId::LAST)),
            "UNKNOWN?"
        );
    }

    // ---- 3. the header helpers -------------------------------------------

    /// `Curl_headersep(x)` (`lib/transfer.h:26`): a prefix match is valid only
    /// when the next byte terminates the name.
    #[test]
    fn only_a_colon_or_a_semicolon_separates_a_header_name() {
        assert!(headersep(b':'));
        assert!(headersep(b';'));
        for byte in [b' ', b'=', b'\t', b'\r', b'\n', b'a', b'Z', 0, 0xFF] {
            assert!(!headersep(byte), "{byte:#x}");
        }
    }

    /// `Curl_checkheaders` (`lib/transfer.c:68-84`): case-insensitive, first
    /// match in INSERTION order, returned unnormalised.
    #[test]
    fn a_custom_header_lookup_is_case_insensitive_and_first_wins() {
        let headers = vec![
            String::from("X-First: one"),
            String::from("Content-Type: text/plain"),
            String::from("content-type: application/json"),
            String::from("Cookie; empty"),
        ];

        // The stored spelling comes back, not the queried one.
        assert_eq!(
            checkheaders(&headers, "content-type"),
            Some("Content-Type: text/plain")
        );
        assert_eq!(
            checkheaders(&headers, "CONTENT-TYPE"),
            Some("Content-Type: text/plain")
        );
        // A semicolon terminates a name too -- that is how curl spells "send
        // this header with no value".
        assert_eq!(checkheaders(&headers, "cookie"), Some("Cookie; empty"));
        // A prefix that is not followed by a separator does NOT match.
        assert_eq!(checkheaders(&headers, "Content"), None);
        assert_eq!(checkheaders(&headers, "X"), None);
        // An empty prefix, and a prefix supplied WITH a colon, are both refused:
        // the C asserts `thislen` and asserts the caller stripped the colon.
        assert_eq!(checkheaders(&headers, ""), None);
        assert_eq!(checkheaders(&headers, "Content-Type:"), None);
        // Nothing matches an empty list.
        assert_eq!(checkheaders(&[], "Host"), None);
    }

    /// The same lookup through the transfer, over `data->set.headers`.
    #[test]
    fn the_transfer_looks_its_own_headers_up() {
        let mut xfer = transfer();
        xfer.settings_mut().headers = vec![String::from("Accept: */*")];
        assert_eq!(xfer.checkheaders("accept"), Some("Accept: */*"));
        assert_eq!(xfer.checkheaders("host"), None);
    }

    // ---- 4. the time conditions ------------------------------------------

    /// `Curl_meets_timecondition` (`lib/transfer.c:118-145`): a zero on either
    /// side succeeds unconditionally.
    #[test]
    fn a_zero_document_time_or_condition_always_meets_the_condition() {
        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().timecondition = TimeCondition::IfModSince;
        xfer.settings_mut().timevalue = 1_000;
        assert!(xfer.meets_timecondition(&mut io, 0));
        assert!(!xfer.info.timecond);

        xfer.settings_mut().timevalue = 0;
        assert!(xfer.meets_timecondition(&mut io, 5_000));
        assert!(!xfer.info.timecond);
        assert!(io.req.info.is_empty());
    }

    /// `CURL_TIMECOND_IFMODSINCE`: fails when `timeofdoc <= timevalue`, with the
    /// frozen line.
    #[test]
    fn if_modified_since_fails_on_a_document_that_is_not_newer() {
        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().timecondition = TimeCondition::IfModSince;
        xfer.settings_mut().timevalue = 1_000;

        // Strictly older: refused.
        assert!(!xfer.meets_timecondition(&mut io, 999));
        assert!(xfer.info.timecond);
        assert!(io.traced("The requested document is not new enough"));

        // EQUAL is refused too -- the C compares with `<=`.
        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().timecondition = TimeCondition::IfModSince;
        xfer.settings_mut().timevalue = 1_000;
        assert!(!xfer.meets_timecondition(&mut io, 1_000));
        assert!(xfer.info.timecond);

        // One second newer: accepted, and nothing is said.
        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().timecondition = TimeCondition::IfModSince;
        xfer.settings_mut().timevalue = 1_000;
        assert!(xfer.meets_timecondition(&mut io, 1_001));
        assert!(!xfer.info.timecond);
        assert!(io.req.info.is_empty());
    }

    /// `CURL_TIMECOND_IFUNMODSINCE`: fails when `timeofdoc >= timevalue`.
    #[test]
    fn if_unmodified_since_fails_on_a_document_that_is_not_older() {
        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().timecondition = TimeCondition::IfUnmodSince;
        xfer.settings_mut().timevalue = 1_000;

        assert!(!xfer.meets_timecondition(&mut io, 1_001));
        assert!(xfer.info.timecond);
        assert!(io.traced("The requested document is not old enough"));

        // EQUAL is refused -- `>=`.
        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().timecondition = TimeCondition::IfUnmodSince;
        xfer.settings_mut().timevalue = 1_000;
        assert!(!xfer.meets_timecondition(&mut io, 1_000));

        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().timecondition = TimeCondition::IfUnmodSince;
        xfer.settings_mut().timevalue = 1_000;
        assert!(xfer.meets_timecondition(&mut io, 999));
        assert!(!xfer.info.timecond);
    }

    /// The C's `default:` label is shared with `IFMODSINCE`, so `NONE` and
    /// `LASTMOD` behave as `IFMODSINCE` -- and an unrecognised ABI value folds
    /// onto the same arm rather than becoming a fourth behaviour.
    #[test]
    fn the_unnamed_conditions_share_the_if_modified_since_arm() {
        for condition in [TimeCondition::None, TimeCondition::LastMod] {
            let (mut xfer, mut io) = fixture();
            xfer.settings_mut().timecondition = condition;
            xfer.settings_mut().timevalue = 1_000;
            assert!(!xfer.meets_timecondition(&mut io, 500), "{condition:?}");
            assert!(io.traced("not new enough"));
        }

        assert_eq!(TimeCondition::from_i64(0), TimeCondition::None);
        assert_eq!(TimeCondition::from_i64(1), TimeCondition::IfModSince);
        assert_eq!(TimeCondition::from_i64(2), TimeCondition::IfUnmodSince);
        assert_eq!(TimeCondition::from_i64(3), TimeCondition::LastMod);
        // Junk folds onto IFMODSINCE, which is the C's `default:`.
        assert_eq!(TimeCondition::from_i64(4), TimeCondition::IfModSince);
        assert_eq!(TimeCondition::from_i64(-9), TimeCondition::IfModSince);
        assert_eq!(TimeCondition::None.as_i64(), 0);
        assert_eq!(TimeCondition::LastMod.as_i64(), 3);
    }

    // ---- 5. pretransfer ---------------------------------------------------

    /// `:459-463`: no URL at all is `CURLE_URL_MALFORMAT` with `No URL set`.
    #[test]
    fn pretransfer_requires_a_url() {
        proto_reset();
        let mut xfer = Transfer::new(TransferSettings::default());
        let mut io = FakeIo::default();
        assert_eq!(
            xfer.pretransfer(&mut io),
            Err(CURLcode::UrlMalformat),
            "a transfer with no URL must not start"
        );
        assert!(io.failed_with("No URL set"));
    }

    /// `:465-476`: `CURLOPT_CURLU` overrides `CURLOPT_URL`, and a handle that
    /// cannot produce a URL is the same refusal.
    #[test]
    fn a_url_handle_overrides_the_url_string() {
        proto_reset();
        let settings = TransferSettings {
            url: Some(String::from("http://from-the-string/")),
            has_url_handle: true,
            buffer_size: 16_384,
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo {
            url_handle: Some(Ok(String::from("http://from-the-handle/"))),
            ..FakeIo::default()
        };
        assert_eq!(xfer.pretransfer(&mut io), Ok(()));
        assert_eq!(
            xfer.state.url.as_deref(),
            Some("http://from-the-handle/"),
            "the handle wins even when both are set"
        );

        // A handle that refuses is `No URL set`, whatever the string said.
        let settings = TransferSettings {
            url: Some(String::from("http://from-the-string/")),
            has_url_handle: true,
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo {
            url_handle: Some(Err(CURLcode::UrlMalformat)),
            ..FakeIo::default()
        };
        assert_eq!(xfer.pretransfer(&mut io), Err(CURLcode::UrlMalformat));
        assert!(io.failed_with("No URL set"));

        // So is a handle that produces nothing.
        let settings = TransferSettings {
            has_url_handle: true,
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo {
            url_handle: None,
            ..FakeIo::default()
        };
        assert_eq!(xfer.pretransfer(&mut io), Err(CURLcode::UrlMalformat));
    }

    /// `:480-484`: POSTFIELDS with RESUME_FROM is refused, with the frozen line.
    #[test]
    fn postfields_may_not_be_combined_with_resume_from() {
        proto_reset();
        let settings = TransferSettings {
            url: Some(String::from("http://example.com/")),
            postfields: Some(b"a=1".to_vec()),
            set_resume_from: true,
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo::default();
        assert_eq!(
            xfer.pretransfer(&mut io),
            Err(CURLcode::BadFunctionArgument)
        );
        assert!(io.failed_with("cannot mix POSTFIELDS with RESUME_FROM"));
    }

    /// `:505-514`: the upload size, in all four cases.
    #[test]
    fn the_upload_input_size_follows_the_method() {
        // PUT takes CURLOPT_INFILESIZE verbatim, -1 included.
        for filesize in [0_i64, 17, -1] {
            proto_reset();
            let settings = TransferSettings {
                url: Some(String::from("http://example.com/")),
                method: HttpRequestKind::Put,
                filesize,
                ..TransferSettings::default()
            };
            let mut xfer = Transfer::new(settings);
            let mut io = FakeIo::default();
            assert_eq!(xfer.pretransfer(&mut io), Ok(()));
            assert_eq!(xfer.state.infilesize, filesize);
        }

        // POST takes CURLOPT_POSTFIELDSIZE.
        proto_reset();
        let settings = TransferSettings {
            url: Some(String::from("http://example.com/")),
            method: HttpRequestKind::Post,
            postfieldsize: 42,
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo::default();
        assert_eq!(xfer.pretransfer(&mut io), Ok(()));
        assert_eq!(xfer.state.infilesize, 42);

        // -1 with in-memory post fields measures the bytes.
        proto_reset();
        let settings = TransferSettings {
            url: Some(String::from("http://example.com/")),
            method: HttpRequestKind::Post,
            postfieldsize: -1,
            postfields: Some(b"name=value".to_vec()),
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo::default();
        assert_eq!(xfer.pretransfer(&mut io), Ok(()));
        assert_eq!(xfer.state.infilesize, 10);

        // GET and HEAD send nothing.
        for method in [HttpRequestKind::Get, HttpRequestKind::Head] {
            proto_reset();
            let settings = TransferSettings {
                url: Some(String::from("http://example.com/")),
                method,
                postfieldsize: 99,
                ..TransferSettings::default()
            };
            let mut xfer = Transfer::new(settings);
            let mut io = FakeIo::default();
            assert_eq!(xfer.pretransfer(&mut io), Ok(()));
            assert_eq!(xfer.state.infilesize, 0, "{method:?}");
        }
    }

    /// `:451-457` and `:492-503`: every per-operation counter and mask resets,
    /// the progress origin is taken from the INJECTED clock, and the two auth
    /// masks are intersected.
    #[test]
    fn pretransfer_resets_the_operation_and_starts_the_clock() {
        proto_reset();
        let settings = TransferSettings {
            url: Some(String::from("http://example.com/")),
            httpauth: 0b1010,
            proxyauth: 0b0110,
            prefer_ascii: true,
            method: HttpRequestKind::Post,
            useragent: Some(String::from("curl/8.19.0-DEV")),
            username: Some(String::from("alice")),
            password: Some(String::from("secret-placeholder")),
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo::default();
        io.req.clock.set(CurlTime::new(4_242, 500_000));

        // Dirty everything the reset must clean.
        xfer.state.retrycount = 3;
        xfer.state.follow.followlocation = 9;
        xfer.state.follow.requests = 7;
        xfer.state.follow.wouldredirect = Some(String::from("junk"));
        xfer.state.errorbuf = true;
        xfer.state.authproblem = true;
        xfer.state.authhost.picked = 0b1111;
        xfer.state.authproxy.picked = 0b1111;
        xfer.req.headerbytecount = 99;

        assert_eq!(xfer.pretransfer(&mut io), Ok(()));

        assert_eq!(xfer.state.retrycount, 0, "the retry allowance is restored");
        assert_eq!(xfer.state.follow.followlocation, 0);
        assert_eq!(xfer.state.follow.requests, 0);
        assert_eq!(xfer.state.follow.wouldredirect, None);
        assert!(!xfer.state.errorbuf);
        assert!(!xfer.state.authproblem);
        assert!(xfer.state.follow.allow_port);
        assert!(xfer.state.prefer_ascii);
        assert_eq!(xfer.state.httpreq, HttpRequestKind::Post);
        assert_eq!(xfer.req.headerbytecount, 0);

        // `picked &= want`, both directions.
        assert_eq!(xfer.state.authhost.want, 0b1010);
        assert_eq!(xfer.state.authhost.picked, 0b1010);
        assert_eq!(xfer.state.authproxy.want, 0b0110);
        assert_eq!(xfer.state.authproxy.picked, 0b0110);

        // The exact wire bytes, terminator included.
        assert_eq!(
            xfer.state.uagent.as_deref(),
            Some("User-Agent: curl/8.19.0-DEV\r\n")
        );

        // The credentials came from the options, and were copied.
        assert_eq!(xfer.state.creds_from, CredsSource::Option);
        assert_eq!(xfer.state.aptr_user.as_deref(), Some("alice"));

        // Every service ran, once, in the C's order.
        assert_eq!(io.cookie_runs, 1);
        assert_eq!(io.info_inits, 1);
        assert_eq!(io.priority_clears, 1);
        assert_eq!(io.header_cleanups, 1);

        // `Curl_pgrsStartNow`'s origin is the INJECTED reading, not a system
        // clock. (`t_startop` is the driver's, armed at `INIT`.)
        assert_eq!(
            io.req.progress.start(),
            CurlTime::new(4_242, 500_000),
            "the transfer origin must come from the injected clock"
        );
        assert!(xfer.pretransfer_done());
    }

    /// `:516-573`: the five services are chained through `if(!result)`, so the
    /// FIRST error is reported and the rest do not run.
    #[test]
    fn the_first_pretransfer_service_error_wins() {
        // The cookie load fails, so the host pairs are never loaded.
        proto_reset();
        let mut xfer = transfer();
        let mut io = FakeIo {
            cookie_load: Err(CURLcode::OutOfMemory),
            ..FakeIo::default()
        };
        io.resolve_list = true;
        assert_eq!(xfer.pretransfer(&mut io), Err(CURLcode::OutOfMemory));
        assert_eq!(io.cookie_runs, 0, "the run follows the load");
        assert_eq!(io.host_pair_calls, 0);
        assert_eq!(io.info_inits, 0);

        // The resolve list is consulted only when there IS one.
        proto_reset();
        let mut xfer = transfer();
        let mut io = FakeIo {
            resolve_list: false,
            ..FakeIo::default()
        };
        io.host_pairs = Err(CURLcode::BadFunctionArgument);
        assert_eq!(xfer.pretransfer(&mut io), Ok(()));
        assert_eq!(io.host_pair_calls, 0);

        proto_reset();
        let mut xfer = transfer();
        let mut io = FakeIo {
            resolve_list: true,
            ..FakeIo::default()
        };
        io.host_pairs = Err(CURLcode::BadFunctionArgument);
        assert_eq!(
            xfer.pretransfer(&mut io),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(io.host_pair_calls, 1);
        assert_eq!(io.info_inits, 0);

        // An HSTS file failure stops before the progress reset.
        proto_reset();
        let mut xfer = transfer();
        let mut io = FakeIo {
            hsts_files: Err(CURLcode::ReadError),
            ..FakeIo::default()
        };
        assert_eq!(xfer.pretransfer(&mut io), Err(CURLcode::ReadError));
        assert_eq!(io.info_inits, 0);

        // The HSTS callback runs LAST of the five, so everything before it did.
        proto_reset();
        let mut xfer = transfer();
        let mut io = FakeIo {
            hsts_cb: Err(CURLcode::WriteError),
            ..FakeIo::default()
        };
        assert_eq!(xfer.pretransfer(&mut io), Err(CURLcode::WriteError));
        assert_eq!(io.info_inits, 1);
        assert_eq!(
            xfer.state.uagent, None,
            "the User-Agent is only prepared on success"
        );
    }

    /// The wildcard initialiser runs only for a wildcard-capable scheme with the
    /// option set (`:553-571`).
    #[cfg(feature = "ftp")]
    #[test]
    fn the_wildcard_is_initialised_only_where_it_applies() {
        // FTP carries `PROTOPT_WILDCARD`, and the option is on.
        proto_reset();
        let settings = TransferSettings {
            url: Some(String::from("ftp://example.com/*.txt")),
            wildcard_enabled: true,
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo {
            scheme: Some(&SCHEME_FTP),
            ..FakeIo::default()
        };
        assert_eq!(xfer.pretransfer(&mut io), Ok(()));
        assert_eq!(io.wildcard_calls, 1);
        assert!(xfer.state.wildcardmatch);

        // The C's condition is the OPTION alone -- `data->state.wildcardmatch =
        // data->set.wildcard_enabled` at `:554` -- and it does not consult
        // `PROTOPT_WILDCARD`. So an HTTP transfer with the option set does
        // initialise, and the scheme flag decides later, in `DID`.
        proto_reset();
        let settings = TransferSettings {
            url: Some(String::from("http://example.com/")),
            wildcard_enabled: true,
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo::default();
        assert_eq!(xfer.pretransfer(&mut io), Ok(()));
        assert_eq!(io.wildcard_calls, 1);
        assert!(xfer.state.wildcardmatch);

        // With the option off, nothing happens at all.
        proto_reset();
        let mut xfer = transfer();
        let mut io = FakeIo::default();
        assert_eq!(xfer.pretransfer(&mut io), Ok(()));
        assert_eq!(io.wildcard_calls, 0);
        assert!(!xfer.state.wildcardmatch);

        // The initialiser runs ONCE: a stage at or past `INIT` is left alone.
        proto_reset();
        let settings = TransferSettings {
            url: Some(String::from("ftp://example.com/*.txt")),
            wildcard_enabled: true,
            ..TransferSettings::default()
        };
        let mut xfer = Transfer::new(settings);
        let mut io = FakeIo {
            scheme: Some(&SCHEME_FTP),
            ..FakeIo::default()
        };
        xfer.state.wildcard = WildcardStage::Matching;
        assert_eq!(xfer.pretransfer(&mut io), Ok(()));
        assert_eq!(io.wildcard_calls, 0);
        assert_eq!(xfer.state.wildcard, WildcardStage::Matching);
    }

    // ---- 6. the retry contract -------------------------------------------

    /// A transfer that received nothing on a REUSED connection is retried, with
    /// the frozen line, a duplicated URL, a closed connection and a rewound
    /// reader (`lib/transfer.c:627-674`).
    #[test]
    fn a_reused_connection_that_delivered_nothing_is_retried() {
        let (mut xfer, mut io) = fixture();
        io.reused = true;
        xfer.state.url = Some(String::from("http://example.com/one"));

        let retry = xfer.retry_request(&mut io);
        assert_eq!(retry, Ok(Some(String::from("http://example.com/one"))));
        assert_eq!(xfer.state.retrycount, 1);
        assert!(io.traced(
            "Connection died, retrying a fresh connect (retry count: 1)"
        ));
        assert_eq!(io.conn_closes, vec!["retry"]);
        assert_eq!(io.retries, 1);
        assert_eq!(io.rewinds, vec![true]);
    }

    /// A FRESH connection is never retried, and neither is one that delivered
    /// bytes.
    #[test]
    fn a_fresh_or_productive_connection_is_not_retried() {
        let (mut xfer, mut io) = fixture();
        io.reused = false;
        assert_eq!(xfer.retry_request(&mut io), Ok(None));
        assert_eq!(xfer.state.retrycount, 0);
        assert_eq!(io.conn_closes.len(), 0);

        let (mut xfer, mut io) = fixture();
        io.reused = true;
        xfer.req.bytecount = 1;
        assert_eq!(xfer.retry_request(&mut io), Ok(None));

        let (mut xfer, mut io) = fixture();
        io.reused = true;
        xfer.req.bytecount = 0;
        xfer.req.headerbytecount = 1;
        assert_eq!(
            xfer.retry_request(&mut io),
            Ok(None),
            "header bytes count as received data too"
        );
    }

    /// `:620-625`: an upload on a scheme that is neither HTTP nor RTSP is never
    /// retried, because reissuing would send the body twice.
    #[test]
    fn a_non_http_upload_is_never_retried() {
        let (mut xfer, mut io) = fixture();
        io.scheme = Some(&SCHEME_FTP);
        io.reused = true;
        xfer.state.upload = true;
        xfer.state.url = Some(String::from("ftp://example.com/f"));
        assert_eq!(xfer.retry_request(&mut io), Ok(None));

        // Over HTTP the same upload IS retried: the response makes a silent
        // connection death detectable.
        let (mut xfer, mut io) = fixture();
        io.reused = true;
        xfer.state.upload = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        assert!(xfer.retry_request(&mut io).unwrap().is_some());
    }

    /// `:643-653`: `REFUSED_STREAM` retries once, logs its line and clears the
    /// flag; and it is an `else if`, so a connection that already qualifies does
    /// not consume it.
    #[test]
    fn a_refused_stream_retries_once_and_clears_the_flag() {
        let (mut xfer, mut io) = fixture();
        io.reused = false;
        xfer.state.refused_stream = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        assert!(xfer.retry_request(&mut io).unwrap().is_some());
        assert!(io.traced("REFUSED_STREAM, retrying a fresh connect"));
        assert!(!xfer.state.refused_stream, "the flag is consumed");

        // Only with ZERO bytes received.
        let (mut xfer, mut io) = fixture();
        io.reused = false;
        xfer.state.refused_stream = true;
        xfer.req.bytecount = 5;
        assert_eq!(xfer.retry_request(&mut io), Ok(None));
        assert!(
            xfer.state.refused_stream,
            "the flag survives a productive try"
        );

        // An already-qualifying retry leaves the flag alone.
        let (mut xfer, mut io) = fixture();
        io.reused = true;
        xfer.state.refused_stream = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        assert!(xfer.retry_request(&mut io).unwrap().is_some());
        assert!(xfer.state.refused_stream);
        assert!(!io.traced("REFUSED_STREAM"));
    }

    /// `:655-661`: `CONN_MAX_RETRIES` is five, the count is post-incremented, and
    /// the sixth attempt gives up with the frozen line and a reset count.
    #[test]
    fn the_retry_allowance_is_five_and_then_it_gives_up() {
        assert_eq!(CONN_MAX_RETRIES, 5);

        let (mut xfer, mut io) = fixture();
        io.reused = true;
        xfer.state.url = Some(String::from("http://example.com/"));

        for expected in 1..=CONN_MAX_RETRIES {
            assert!(
                xfer.retry_request(&mut io).unwrap().is_some(),
                "retry {expected} must be granted"
            );
            assert_eq!(xfer.state.retrycount, expected);
        }

        // The sixth is refused.
        assert_eq!(xfer.retry_request(&mut io), Err(CURLcode::SendError));
        assert!(
            io.failed_with("Connection died, tried 5 times before giving up")
        );
        assert_eq!(
            xfer.state.retrycount, 0,
            "the count resets so a later operation gets its own allowance"
        );
    }

    /// `Curl_pretransfer` resets the allowance, which is what makes it
    /// per-operation rather than per-connection (`lib/transfer.c:451-457`).
    #[test]
    fn the_retry_allowance_is_restored_by_pretransfer() {
        let (mut xfer, mut io) = fixture();
        xfer.state.retrycount = CONN_MAX_RETRIES;
        assert_eq!(xfer.pretransfer(&mut io), Ok(()));
        assert_eq!(xfer.state.retrycount, 0);

        io.reused = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        assert!(xfer.retry_request(&mut io).unwrap().is_some());
    }

    /// `:664-666`: without a URL to reissue there is nothing to retry, and the C
    /// answers `CURLE_OUT_OF_MEMORY` when the duplication fails.
    #[test]
    fn a_retry_without_a_url_is_out_of_memory() {
        let (mut xfer, mut io) = fixture();
        io.reused = true;
        xfer.state.url = None;
        assert_eq!(xfer.retry_request(&mut io), Err(CURLcode::OutOfMemory));
    }

    /// Without a scheme there is no connection, so nothing is retried.
    #[test]
    fn a_retry_without_a_scheme_declines() {
        let (mut xfer, mut io) = fixture();
        io.scheme = None;
        io.reused = true;
        assert_eq!(xfer.retry_request(&mut io), Ok(None));
    }

    // ---- 7. the channel setup --------------------------------------------

    /// `xfer_setup` (`lib/transfer.c:679-725`) through its four wrappers.
    #[test]
    fn the_four_setup_wrappers_store_the_c_channels() {
        // No-op: neither direction, no size, no keep flags.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_nop(&mut io);
        assert_eq!(xfer.send_channel(), ChannelIndex::None);
        assert_eq!(xfer.recv_channel(), ChannelIndex::None);
        assert_eq!(xfer.req.size, -1);
        assert!(xfer.req.keepon().is_empty());
        assert!(io.traced("xfer_setup: recv_idx=-1, send_idx=-1"));

        // The keep flags are OR-ed, never cleared -- `k->keepon |= KEEP_RECV`
        // at `:717` and `:720` are the only writes. A flag already set therefore
        // survives a no-op setup, which is the C's behaviour and not an
        // oversight here.
        let (mut xfer, mut io) = fixture();
        xfer.req.keep_on(KeepFlags::RECV);
        xfer.xfer_setup_nop(&mut io);
        assert_eq!(xfer.req.keepon(), KeepFlags::RECV);

        // Send only.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_send(&mut io, SocketIndex::First);
        assert_eq!(xfer.send_channel(), ChannelIndex::First);
        assert_eq!(xfer.recv_channel(), ChannelIndex::None);
        assert_eq!(xfer.req.keepon(), KeepFlags::SEND);
        assert!(io.traced("xfer_setup: recv_idx=-1, send_idx=0"));

        // Receive only, with a known size.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::Secondary, 512);
        assert_eq!(xfer.send_channel(), ChannelIndex::None);
        assert_eq!(xfer.recv_channel(), ChannelIndex::Secondary);
        assert_eq!(xfer.req.size, 512);
        assert_eq!(xfer.req.keepon(), KeepFlags::RECV);
        assert_eq!(
            io.req.progress.download().total_size(),
            512,
            "a known body length with no headers reaches the meter"
        );

        // Both directions on ONE channel.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        assert_eq!(xfer.send_channel(), ChannelIndex::First);
        assert_eq!(xfer.recv_channel(), ChannelIndex::First);
        assert_eq!(xfer.req.keepon(), KeepFlags::RECV | KeepFlags::SEND);
    }

    /// `:710-711`: with response headers expected, the size is NOT published to
    /// the meter -- header bytes would otherwise count towards the body.
    #[test]
    fn a_size_is_published_only_when_no_headers_are_expected() {
        let (mut xfer, mut io) = fixture();
        io.writes_response_headers = true;
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, 900);
        assert!(xfer.req.header, "the scheme writes response headers");
        assert_eq!(xfer.req.size, 900);
        assert_eq!(io.req.progress.download().total_size(), 0);

        // Nor is a non-positive one.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, 0);
        assert_eq!(io.req.progress.download().total_size(), 0);
    }

    /// `:713-721`: a transfer that wants neither headers nor a body sets no keep
    /// flags at all, however many channels it was given.
    #[test]
    fn a_bodyless_transfer_without_headers_keeps_nothing() {
        let (mut xfer, mut io) = fixture();
        xfer.req.no_body = true;
        io.writes_response_headers = false;
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        assert!(xfer.req.keepon().is_empty());

        // With headers wanted, both flags come back.
        let (mut xfer, mut io) = fixture();
        xfer.req.no_body = true;
        io.writes_response_headers = true;
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        assert_eq!(xfer.req.keepon(), KeepFlags::RECV | KeepFlags::SEND);
    }

    /// `Curl_xfer_set_shutdown` (`lib/transfer.c:752-761`): a setup clears both
    /// flags, and the shutdown is only for a one-direction transfer.
    #[test]
    fn an_end_of_transfer_shutdown_is_for_one_direction_only() {
        let (mut xfer, mut io) = fixture();
        xfer.req.shutdown = true;
        xfer.req.shutdown_err_ignore = true;
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        assert!(!xfer.req.shutdown, "a setup clears the flag");
        assert!(!xfer.req.shutdown_err_ignore);

        xfer.xfer_set_shutdown(true, true);
        assert!(xfer.req.shutdown);
        assert!(xfer.req.shutdown_err_ignore);

        // `ignore_errors` is carried separately, and is read at a different time.
        xfer.xfer_set_shutdown(true, false);
        assert!(xfer.req.shutdown);
        assert!(!xfer.req.shutdown_err_ignore);

        // Clearing it is always allowed, whatever the channels are.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        xfer.xfer_set_shutdown(false, false);
        assert!(!xfer.req.shutdown);
    }

    /// The C's `DEBUGASSERT` at `:756-758`, reproduced as a `debug_assert!`.
    #[test]
    #[should_panic(expected = "not both")]
    fn a_two_direction_transfer_may_not_arm_a_shutdown() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        xfer.xfer_set_shutdown(true, false);
    }

    /// The C's `DEBUGASSERT` at `:699-700`: no receive channel means no size.
    #[test]
    #[should_panic(expected = "no recv_size")]
    fn a_size_without_a_receive_channel_is_a_caller_bug() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup(&mut io, ChannelIndex::None, ChannelIndex::None, 10);
    }

    // ---- 8. the raw transport --------------------------------------------

    /// `Curl_xfer_send` (`lib/transfer.c:829-850`): `CURLE_AGAIN` becomes
    /// success with zero written, only real bytes are counted, and the debug
    /// shape is frozen.
    #[test]
    fn a_blocked_send_is_success_with_nothing_written() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_send(&mut io, SocketIndex::First);

        io.conn_sends.push_back(SendStep::Again);
        assert_eq!(xfer.xfer_send(&mut io, b"abcdef", false), Ok(0));
        assert_eq!(
            xfer.info.request_size, 0,
            "nothing reached the wire, so nothing is counted"
        );
        assert!(io.traced("Curl_xfer_send(len=6, eos=0) -> 0, 0"));

        // A partial accept counts only what was accepted.
        io.conn_sends.push_back(SendStep::Accept(4));
        assert_eq!(xfer.xfer_send(&mut io, b"abcdef", true), Ok(4));
        assert_eq!(xfer.info.request_size, 4);
        assert!(io.traced("Curl_xfer_send(len=6, eos=1) -> 0, 4"));

        // A real failure is reported, and counts nothing.
        io.conn_sends.push_back(SendStep::Fail(CURLcode::SendError));
        assert_eq!(
            xfer.xfer_send(&mut io, b"xy", false),
            Err(CURLcode::SendError)
        );
        assert_eq!(xfer.info.request_size, 4);
        assert!(io.traced("Curl_xfer_send(len=2, eos=0) -> 55, 0"));
    }

    /// Without a channel the filter layer's own answer comes back:
    /// `CURLE_BAD_FUNCTION_ARGUMENT` for an index of `-1`
    /// (`lib/cfilters.c:1067` and `:1084`). The send still traces, because the C
    /// emits its `DEBUGF` after the call returns.
    #[test]
    fn an_operation_without_a_channel_is_a_bad_argument() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_nop(&mut io);
        assert_eq!(
            xfer.xfer_send(&mut io, b"x", false),
            Err(CURLcode::BadFunctionArgument)
        );
        assert!(io.traced("Curl_xfer_send(len=1, eos=0) -> 43, 0"));
        assert_eq!(
            xfer.xfer_recv(&mut io, &mut [0_u8; 4]),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(
            xfer.xfer_flush(&mut io),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(
            xfer.xfer_send_shutdown(&mut io),
            Err(CURLcode::BadFunctionArgument)
        );

        // No CONNECTION at all is the shutdown's own `CURLE_FAILED_INIT`.
        io.connected = false;
        assert_eq!(xfer.xfer_send_shutdown(&mut io), Err(CURLcode::FailedInit));
    }

    /// `Curl_xfer_recv` (`lib/transfer.c:852-863`): every read is clamped to
    /// `CURLOPT_BUFFERSIZE`, and a zero setting is refused rather than stalling.
    #[test]
    fn a_receive_is_clamped_to_the_configured_buffer_size() {
        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().buffer_size = 5;
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);

        io.recvs.push_back(RecvStep::Bytes(b"0123456789".to_vec()));
        let mut buf = [0_u8; 10];
        assert_eq!(xfer.xfer_recv(&mut io, &mut buf), Ok(5));
        assert_eq!(&buf[..5], b"01234");
        assert_eq!(
            io.recv_log,
            vec![RecvRecord {
                channel: SocketIndex::First,
                wanted: 5,
                got: 5,
            }]
        );

        // `CURLE_AGAIN` reaches the caller from here -- the conversion to
        // success belongs to the SEND direction only.
        io.recvs.clear();
        io.recvs.push_back(RecvStep::Again);
        assert_eq!(xfer.xfer_recv(&mut io, &mut buf), Err(CURLcode::Again));
    }

    /// The C's `DEBUGASSERT(data->set.buffer_size > 0)` (`lib/transfer.c:858`):
    /// a zero setting would clamp every read to nothing.
    #[test]
    #[should_panic(expected = "CURLOPT_BUFFERSIZE must be positive")]
    fn a_zero_buffer_size_is_a_caller_bug() {
        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().buffer_size = 0;
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        let _ = xfer.xfer_recv(&mut io, &mut [0_u8; 8]);
    }

    /// `xfer_recv_resp` (`lib/transfer.c:174-212`): the read is limited to the
    /// known remaining body when the transport's end-of-stream is unreliable.
    #[tokio::test]
    async fn a_known_body_remainder_clamps_the_read() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.header = false;
        xfer.req.size = 10;
        xfer.req.bytecount = 7;

        io.recvs.push_back(RecvStep::Bytes(vec![b'z'; 64]));
        let mut buf = [0_u8; 32];
        // eos_reliable = false, so the clamp applies: 10 - 7 = 3.
        assert_eq!(xfer.xfer_recv_resp(&mut io, &mut buf, false), Ok(3));
        assert_eq!(io.recv_log[0].wanted, 3);

        // With a RELIABLE end of stream the clamp does not apply.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.header = false;
        xfer.req.size = 10;
        xfer.req.bytecount = 7;
        io.recvs.push_back(RecvStep::Bytes(vec![b'z'; 64]));
        let mut buf = [0_u8; 32];
        assert_eq!(xfer.xfer_recv_resp(&mut io, &mut buf, true), Ok(32));

        // Nor while response headers are still being read.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.header = true;
        xfer.req.size = 10;
        xfer.req.bytecount = 7;
        io.recvs.push_back(RecvStep::Bytes(vec![b'z'; 64]));
        let mut buf = [0_u8; 32];
        assert_eq!(xfer.xfer_recv_resp(&mut io, &mut buf, false), Ok(32));
    }

    /// `:186-192`: with a receive shutdown already under way, nothing more is
    /// read at all.
    #[test]
    fn a_started_receive_shutdown_stops_reading() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.header = true;
        io.shutdown_started = true;

        let mut buf = [0_u8; 8];
        assert_eq!(xfer.xfer_recv_resp(&mut io, &mut buf, true), Ok(0));
        assert!(io.recv_log.is_empty(), "no read was attempted");
    }

    /// `:200-211`: a zero-byte receive advances the typed shutdown, and reports
    /// `CURLE_AGAIN` while it is still pending.
    #[test]
    fn a_pending_shutdown_answers_again_and_a_complete_one_ends_the_stream() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.shutdown = true;
        io.recvs.push_back(RecvStep::Eos);
        io.shutdowns.push_back(Ok(AsyncStep::Pending));

        let mut buf = [0_u8; 8];
        assert_eq!(
            xfer.xfer_recv_resp(&mut io, &mut buf, true),
            Err(CURLcode::Again)
        );
        assert!(!io.traced("sendrecv_dl: we are done"));

        // Completed: the stream really has ended.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.shutdown = true;
        io.recvs.push_back(RecvStep::Eos);
        io.shutdowns.push_back(Ok(AsyncStep::Complete));
        assert_eq!(xfer.xfer_recv_resp(&mut io, &mut buf, true), Ok(0));
        assert!(io.traced("sendrecv_dl: we are done"));

        // A shutdown failure is reported.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.shutdown = true;
        io.recvs.push_back(RecvStep::Eos);
        io.shutdowns.push_back(Err(CURLcode::RecvError));
        assert_eq!(
            xfer.xfer_recv_resp(&mut io, &mut buf, true),
            Err(CURLcode::RecvError)
        );
    }

    /// The send and receive shutdowns are typed, not `bool *done`.
    #[test]
    fn the_shutdowns_report_a_typed_step() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        io.shutdowns.push_back(Ok(AsyncStep::Pending));
        assert_eq!(xfer.xfer_send_shutdown(&mut io), Ok(AsyncStep::Pending));
        io.shutdowns.push_back(Ok(AsyncStep::Complete));
        assert_eq!(xfer.xfer_send_shutdown(&mut io), Ok(AsyncStep::Complete));
    }

    /// `Curl_xfer_needs_flush`, `Curl_xfer_flush` and `Curl_xfer_send_close`
    /// (`lib/transfer.c:819-827` and the `DATA_DONE_SEND` event) all go through
    /// `conn`, never through a socket.
    #[test]
    fn the_flush_and_close_events_go_through_the_filters() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_send(&mut io, SocketIndex::First);

        assert!(!xfer.xfer_needs_flush(&mut io));
        io.req.needs_flush = true;
        assert!(xfer.xfer_needs_flush(&mut io));
        assert_eq!(xfer.xfer_flush(&mut io), Ok(()));
        assert_eq!(io.flushes, 1);

        assert_eq!(xfer.xfer_send_close(&mut io), Ok(()));
        assert_eq!(io.done_sends, 1);

        // Without a send channel there is nothing to flush and nothing to close.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_nop(&mut io);
        assert!(!xfer.xfer_needs_flush(&mut io));
        assert_eq!(
            xfer.xfer_flush(&mut io),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(io.flushes, 0);
    }

    // ---- 9. the response writer ------------------------------------------

    /// `Curl_xfer_write_resp` (`lib/transfer.c:765-798`): the protocol gets first
    /// refusal, the fallback writes `CLIENTWRITE_BODY`, and the end of stream
    /// adds `CLIENTWRITE_EOS` and marks the download done.
    #[tokio::test]
    async fn a_response_write_falls_back_to_a_body_write() {
        let (mut xfer, mut io) = fixture();
        assert_eq!(
            xfer.xfer_write_resp(&mut io, b"hello", false).await,
            Ok(())
        );
        assert_eq!(
            io.write_log,
            vec![WriteRecord {
                flags: ClientWriteFlags::BODY,
                bytes: b"hello".to_vec(),
            }]
        );
        assert!(!xfer.req.eos_written);
        assert!(!xfer.req.download_done);
        assert!(io.traced("xfer_write_resp(len=5, eos=0) -> 0"));

        // The end of stream adds the flag and both marks.
        assert_eq!(xfer.xfer_write_resp(&mut io, b"", true).await, Ok(()));
        assert_eq!(
            io.write_log[1].flags,
            ClientWriteFlags::BODY.union(ClientWriteFlags::EOS)
        );
        assert!(xfer.req.eos_written);
        assert!(xfer.req.download_done);
        assert!(io.traced("xfer_write_resp(len=0, eos=1) -> 0"));
    }

    /// `:774`: an empty write that is NOT the end of stream reaches nobody.
    #[tokio::test]
    async fn an_empty_write_that_is_not_the_end_reaches_nobody() {
        let (mut xfer, mut io) = fixture();
        assert_eq!(xfer.xfer_write_resp(&mut io, b"", false).await, Ok(()));
        assert!(io.write_log.is_empty());
    }

    /// `:769-773`: a protocol that handles the write itself stops the fallback.
    #[tokio::test]
    async fn a_protocol_that_handles_the_write_suppresses_the_fallback() {
        let (mut xfer, mut io) = fixture();
        proto(|script| script.write_resp.push_back(Ok(true)));
        assert_eq!(xfer.xfer_write_resp(&mut io, b"body", true).await, Ok(()));
        assert!(io.write_log.is_empty(), "the protocol took it");
        assert_eq!(proto_calls("write_resp"), 1);
        // The end-of-stream marks are still made: they are the C's
        // post-condition on the WHOLE function, not on the fallback.
        assert!(xfer.req.eos_written);
        assert!(xfer.req.download_done);
    }

    /// A failing write leaves the marks alone and reports the code.
    #[tokio::test]
    async fn a_failed_write_does_not_mark_the_download_done() {
        let (mut xfer, mut io) = fixture();
        io.writes.push_back(Err(CURLcode::WriteError));
        assert_eq!(
            xfer.xfer_write_resp(&mut io, b"x", true).await,
            Err(CURLcode::WriteError)
        );
        assert!(!xfer.req.eos_written);
        assert!(!xfer.req.download_done);
        assert!(io.traced("xfer_write_resp(len=1, eos=1) -> 23"));
    }

    /// `Curl_xfer_write_resp_hd` (`lib/transfer.c:800-811`): the header hook is
    /// offered the line only when the scheme HAS one, and the bytes pass through
    /// with the caller's own termination.
    #[tokio::test]
    async fn a_header_line_is_offered_to_the_header_hook_first() {
        let (mut xfer, mut io) = fixture();
        io.writes_response_headers = true;
        proto(|script| script.write_resp_hd.push_back(Ok(true)));
        assert_eq!(
            xfer.xfer_write_resp_hd(&mut io, b"Host: x\r\n", false)
                .await,
            Ok(())
        );
        assert_eq!(proto_calls("write_resp_hd"), 1);
        assert!(io.write_log.is_empty());

        // Declined: the ordinary response path takes it, bytes unchanged.
        let (mut xfer, mut io) = fixture();
        io.writes_response_headers = true;
        proto(|script| script.write_resp_hd.push_back(Ok(false)));
        assert_eq!(
            xfer.xfer_write_resp_hd(&mut io, b"Host: x\r\n", false)
                .await,
            Ok(())
        );
        assert_eq!(io.write_log[0].bytes, b"Host: x\r\n".to_vec());

        // A scheme without a header hook never reaches it.
        let (mut xfer, mut io) = fixture();
        io.writes_response_headers = false;
        assert_eq!(
            xfer.xfer_write_resp_hd(&mut io, b"Host: x\r\n", false)
                .await,
            Ok(())
        );
        assert_eq!(proto_calls("write_resp_hd"), 0);
        assert_eq!(io.write_log[0].bytes, b"Host: x\r\n".to_vec());
    }

    /// `Curl_xfer_write_done` and `Curl_xfer_write_is_paused` delegate to the
    /// ordered writer chain.
    #[test]
    fn the_write_completion_and_pause_query_delegate_to_writeout() {
        let (mut xfer, mut io) = fixture();
        assert!(!xfer.xfer_write_is_paused(&io));
        io.writer_paused = true;
        assert!(xfer.xfer_write_is_paused(&io));

        assert_eq!(xfer.xfer_write_done(&mut io, true), Ok(()));
        assert_eq!(io.write_done, vec![true]);

        io.write_done_result = Err(CURLcode::WriteError);
        assert_eq!(
            xfer.xfer_write_done(&mut io, false),
            Err(CURLcode::WriteError)
        );
        assert_eq!(io.write_done, vec![true, false]);
    }

    // ---- 10. pause and block ---------------------------------------------

    /// Send-paused IS the upload limiter blocked, and receive-paused IS the
    /// download limiter blocked (`lib/transfer.c:883-891`).
    #[test]
    fn a_paused_direction_is_a_blocked_rate_limiter() {
        let (mut xfer, mut io) = fixture();
        assert!(!xfer.xfer_send_is_paused(&io));
        assert!(!xfer.xfer_recv_is_paused(&io));

        assert_eq!(xfer.xfer_pause_send(&mut io, true), Ok(()));
        assert!(xfer.xfer_send_is_paused(&io));
        assert!(
            !xfer.xfer_recv_is_paused(&io),
            "the directions are separate"
        );

        assert_eq!(xfer.xfer_pause_recv(&mut io, true), Ok(()));
        assert!(xfer.xfer_recv_is_paused(&io));

        assert_eq!(xfer.xfer_pause_send(&mut io, false), Ok(()));
        assert!(!xfer.xfer_send_is_paused(&io));
        assert!(xfer.xfer_recv_is_paused(&io));
    }

    /// `Curl_xfer_is_blocked` (`lib/transfer.c:871-881`): the whole truth table,
    /// all eight rows.
    #[test]
    fn the_blocked_truth_table_is_the_c_truth_table() {
        for (keep, pause_send, pause_recv, blocked) in [
            // No wanted direction is never blocked, however paused it is.
            (KeepFlags::NONE, false, false, false),
            (KeepFlags::NONE, true, true, false),
            // Receive only: blocked iff the receive side is paused.
            (KeepFlags::RECV, false, false, false),
            (KeepFlags::RECV, true, false, false),
            (KeepFlags::RECV, false, true, true),
            (KeepFlags::RECV, true, true, true),
            // Send only: blocked iff the send side is paused.
            (KeepFlags::SEND, false, false, false),
            (KeepFlags::SEND, true, false, true),
            (KeepFlags::SEND, false, true, false),
            (KeepFlags::SEND, true, true, true),
            // Both: blocked only when BOTH are paused.
            (KeepFlags::RECV | KeepFlags::SEND, false, false, false),
            (KeepFlags::RECV | KeepFlags::SEND, true, false, false),
            (KeepFlags::RECV | KeepFlags::SEND, false, true, false),
            (KeepFlags::RECV | KeepFlags::SEND, true, true, true),
        ] {
            let (mut xfer, mut io) = fixture();
            xfer.req.set_keepon(keep);
            assert_eq!(xfer.xfer_pause_send(&mut io, pause_send), Ok(()));
            assert_eq!(xfer.xfer_pause_recv(&mut io, pause_recv), Ok(()));
            assert_eq!(
                xfer.xfer_is_blocked(&io),
                blocked,
                "keepon={:?} send_paused={pause_send} recv_paused={pause_recv}",
                keep.bits()
            );
        }
    }

    /// `:897-899`: resuming the upload replays the reader chain when it is
    /// paused, tells the accounting either way, and propagates the replay's code
    /// EXACTLY.
    #[test]
    fn resuming_the_upload_replays_the_reader_and_reports_its_error() {
        // Not paused: no replay.
        let (mut xfer, mut io) = fixture();
        io.reader_paused = false;
        assert_eq!(xfer.xfer_pause_send(&mut io, false), Ok(()));
        assert_eq!(io.reader_unpauses, 0);

        // Paused: replayed once.
        let (mut xfer, mut io) = fixture();
        io.reader_paused = true;
        assert_eq!(xfer.xfer_pause_send(&mut io, false), Ok(()));
        assert_eq!(io.reader_unpauses, 1);

        // PAUSING never replays, however paused the chain is.
        let (mut xfer, mut io) = fixture();
        io.reader_paused = true;
        assert_eq!(xfer.xfer_pause_send(&mut io, true), Ok(()));
        assert_eq!(io.reader_unpauses, 0);

        // A failing replay is reported, and the accounting still ran.
        let (mut xfer, mut io) = fixture();
        io.reader_paused = true;
        io.reader_unpause = Err(CURLcode::ReadError);
        assert_eq!(
            xfer.xfer_pause_send(&mut io, false),
            Err(CURLcode::ReadError)
        );
        assert!(
            !xfer.xfer_send_is_paused(&io),
            "the limiter still unblocked"
        );
    }

    /// `:907-910`: resuming the download replays the WRITER chain, then tells the
    /// filters -- in that order, so buffered bytes reach the application ahead of
    /// new ones.
    #[test]
    fn resuming_the_download_replays_the_writer_then_tells_the_filters() {
        let (mut xfer, mut io) = fixture();
        io.writer_paused = true;
        assert_eq!(xfer.xfer_pause_recv(&mut io, false), Ok(()));
        assert_eq!(io.writer_unpauses, 1);
        assert_eq!(io.pauses, vec![false]);

        // Pausing reaches the filters too, with `true`.
        let (mut xfer, mut io) = fixture();
        assert_eq!(xfer.xfer_pause_recv(&mut io, true), Ok(()));
        assert_eq!(io.pauses, vec![true]);
        assert_eq!(io.writer_unpauses, 0);

        // A failing replay is reported, and BOTH remaining steps still ran.
        let (mut xfer, mut io) = fixture();
        io.writer_paused = true;
        io.writer_unpause = Err(CURLcode::WriteError);
        assert_eq!(
            xfer.xfer_pause_recv(&mut io, false),
            Err(CURLcode::WriteError)
        );
        assert_eq!(io.pauses, vec![false]);
        assert!(!xfer.xfer_recv_is_paused(&io));
    }

    // ---- 11. the download loop -------------------------------------------

    /// `Curl_sendrecv` (`lib/transfer.c:357-431`): a fully blocked transfer does
    /// NO I/O and reports success.
    #[tokio::test]
    async fn a_fully_blocked_transfer_does_no_io() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        assert_eq!(xfer.xfer_pause_recv(&mut io, true), Ok(()));
        assert!(xfer.xfer_is_blocked(&io));

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(io.recv_log.is_empty());
        assert!(io.conn_send_log.is_empty());
        assert_eq!(io.sched.buf_borrows, 0);
    }

    /// The loop's budget is ELEVEN passes: `maxloops = 10` with a
    /// post-decrement in the condition (`lib/transfer.c:236` and `:312`).
    #[tokio::test]
    async fn the_download_loop_takes_at_most_eleven_passes() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        io.multiplex = true;
        // Endlessly ready, one byte at a time, and never an end of stream.
        for _ in 0..40 {
            io.recvs.push_back(RecvStep::Bytes(b"a".to_vec()));
        }

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert_eq!(
            io.recv_log.len(),
            11,
            "one unconditional pass plus ten more"
        );
        // Data may still be buffered, so the transfer marks itself dirty.
        assert!(io.sched.dirty);
        assert!(
            io.traced("sendrecv_dl() no EAGAIN/pending data, mark as dirty")
        );
    }

    /// A zero-length receive is the end of stream: the request stops, ONE
    /// end-of-stream write is forwarded, and `KEEP_RECV` goes away.
    #[tokio::test]
    async fn a_zero_byte_receive_ends_the_stream_exactly_once() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        io.recvs.push_back(RecvStep::Bytes(b"body".to_vec()));
        io.recvs.push_back(RecvStep::Eos);

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert_eq!(io.write_log.len(), 2);
        assert_eq!(io.write_log[0].bytes, b"body".to_vec());
        assert_eq!(io.write_log[0].flags, ClientWriteFlags::BODY);
        assert!(io.write_log[1].bytes.is_empty());
        assert_eq!(
            io.write_log[1].flags,
            ClientWriteFlags::BODY.union(ClientWriteFlags::EOS)
        );
        assert!(xfer.req.eos_written);
        assert!(xfer.req.download_done);
        assert!(!xfer.req.keepon().contains(KeepFlags::RECV));
        // The end of stream is not a reason to mark the transfer dirty.
        assert!(!io.sched.dirty);
    }

    /// `:294-295`: an end of stream that has ALREADY been written to the client
    /// is not written a second time.
    #[tokio::test]
    async fn an_already_written_end_of_stream_is_not_repeated() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.eos_written = true;
        io.recvs.push_back(RecvStep::Eos);

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(io.write_log.is_empty(), "already did write this to client");
    }

    /// `:269-274`: a real receive error is an error, and it is traced.
    #[tokio::test]
    async fn a_real_receive_error_stops_the_loop() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        io.recvs.push_back(RecvStep::Fail(CURLcode::RecvError));

        assert_eq!(xfer.sendrecv(&mut io).await, Err(CURLcode::RecvError));
        assert!(io.traced("sendrecv_dl() -> 56"));
        assert!(io.traced("Curl_sendrecv() -> 56"));
    }

    /// `:275-284`: `CURLE_AGAIN` normally stops the loop -- and does NOT become
    /// an error.
    #[tokio::test]
    async fn a_would_block_receive_stops_without_failing() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        io.recvs.push_back(RecvStep::Again);

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(io.write_log.is_empty());
        // `rcvd_eagain` with no pending data: NOT dirty.
        assert!(!io.sched.dirty);
    }

    /// `:276-284`: a completed download on a bodyless response with no announced
    /// trailer treats `CURLE_AGAIN` as a synthetic end of stream, with the
    /// source's own debug line.
    #[tokio::test]
    async fn a_no_body_no_trailer_would_block_completes_the_transfer() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.download_done = true;
        xfer.req.no_body = true;
        xfer.req.resp_trailer = false;
        io.recvs.push_back(RecvStep::Again);

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(io.traced(
            "EAGAIN, download done, no trailer announced, not waiting for EOS"
        ));
        assert!(
            xfer.req.eos_written,
            "the synthetic end of stream was written"
        );

        // An ANNOUNCED trailer means the end of stream is still coming.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.download_done = true;
        xfer.req.no_body = true;
        xfer.req.resp_trailer = true;
        io.recvs.push_back(RecvStep::Again);
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(!xfer.req.eos_written);
    }

    /// `:314-320`: buffered data that no descriptor will report marks the
    /// transfer dirty -- the C's *"simulated SELECT results"*.
    #[tokio::test]
    async fn pending_filter_data_marks_the_transfer_dirty() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        io.recvs.push_back(RecvStep::Again);
        io.pending_data = true;

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(io.sched.dirty);
        assert_eq!(io.sched.dirty_marks, 1);
    }

    /// `data_pending` (`lib/transfer.c:102-114`): FTP asks the SECONDARY channel,
    /// SCP and SFTP answer true until a real `CURLE_AGAIN`, everything else asks
    /// the first channel.
    #[test]
    fn pending_data_is_looked_for_where_the_scheme_keeps_it() {
        // FTP: the secondary channel, which is where its data connection is.
        let (xfer, mut io) = fixture();
        io.scheme = Some(&SCHEME_FTP);
        io.pending_data = true;
        assert!(xfer.data_pending(&mut io, true));
        io.pending_data = false;
        assert!(!xfer.data_pending(&mut io, true));

        // SFTP: true until the transport actually said it would block.
        let (xfer, mut io) = fixture();
        io.scheme = Some(&SCHEME_SFTP);
        io.pending_data = false;
        assert!(
            xfer.data_pending(&mut io, false),
            "a library with internal buffers is not trusted until it says EAGAIN"
        );
        assert!(!xfer.data_pending(&mut io, true));

        // HTTP: the first channel's filters.
        let (xfer, mut io) = fixture();
        io.pending_data = true;
        assert!(xfer.data_pending(&mut io, true));
        io.pending_data = false;
        assert!(!xfer.data_pending(&mut io, true));

        // No scheme, no answer.
        let (xfer, mut io) = fixture();
        io.scheme = None;
        io.pending_data = true;
        assert!(!xfer.data_pending(&mut io, true));
    }

    /// `:251-267`: the rate limiter clamps each read, and a limiter with nothing
    /// left stops the loop rather than issuing a tiny read.
    #[tokio::test]
    async fn the_download_rate_clamps_and_then_stops_the_loop() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        let now = io.req.clock.now();
        // 8 bytes per second, so 8 tokens are available at the start.
        *io.req.progress.download_mut().rlimit_mut() =
            RateLimit::new(8, 0, now);
        io.recvs.push_back(RecvStep::Bytes(vec![b'x'; 64]));
        io.recvs.push_back(RecvStep::Eos);

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert_eq!(
            io.recv_log[0].wanted, 8,
            "the read is clamped to the tokens available"
        );

        // With nothing available the loop stops WITHOUT a read.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        let now = io.req.clock.now();
        let mut limit = RateLimit::new(8, 0, now);
        limit.drain(8, now);
        *io.req.progress.download_mut().rlimit_mut() = limit;
        io.recvs.push_back(RecvStep::Bytes(vec![b'x'; 64]));

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(io.recv_log.is_empty(), "no tiny read was issued");
        assert!(!io.sched.dirty, "rate-limited is not dirty");
    }

    /// `:322-329`: a finished download on a closing connection abandons the
    /// upload, with the frozen line.
    ///
    /// The state it needs is precise: an END OF STREAM clears BOTH keep flags
    /// through `Curl_req_stop_send_recv`, so it can never reach this branch. The
    /// only route is a COMPLETED download on a non-multiplexed connection, which
    /// clears `KEEP_RECV` alone (`:302-306`) and leaves `KEEP_SEND` behind.
    #[tokio::test]
    async fn a_closing_connection_stops_an_unfinished_upload() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        xfer.req.download_done = true;
        io.multiplex = false;
        io.recvs.push_back(RecvStep::Bytes(b"tail".to_vec()));
        io.wants_close = true;

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(io
            .traced("we are done reading and this is set to close, stop send"));
        // `Curl_req_abort_sending` then takes `KEEP_SEND` away as well, which is
        // the whole point of the branch.
        assert!(xfer.req.keepon().is_empty());

        // A MULTIPLEXED connection reaches the same branch, because another
        // stream may still want the connection.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        xfer.req.download_done = true;
        io.multiplex = true;
        io.recvs.push_back(RecvStep::Bytes(b"tail".to_vec()));
        io.recvs.push_back(RecvStep::Eos);
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        // The end of stream cleared both flags, so the branch is NOT taken.
        assert!(xfer.req.keepon().is_empty());
        assert!(!io.traced("stop send"));

        // Neither closing nor multiplexed: the upload continues.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        xfer.req.download_done = true;
        io.multiplex = false;
        io.wants_close = false;
        io.recvs.push_back(RecvStep::Bytes(b"tail".to_vec()));
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(!io.traced("stop send"));
        // The upload then finishes on its own terms -- the client reader reported
        // its end of stream -- rather than being abandoned.
        assert!(xfer.req.upload_done);
    }

    /// An end of stream clears BOTH keep flags -- `Curl_req_stop_send_recv`
    /// (`lib/request.c`) -- which is why the "stop send" branch above cannot be
    /// reached through it.
    #[tokio::test]
    async fn an_end_of_stream_stops_both_directions() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        io.recvs.push_back(RecvStep::Eos);
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(xfer.req.keepon().is_empty());
    }

    /// `:302-307`: a non-multiplexed completed download clears `KEEP_RECV`, and a
    /// multiplexed one keeps reading so that the transport's end-of-stream
    /// metadata still arrives.
    #[tokio::test]
    async fn a_multiplexed_stream_keeps_reading_for_the_end_of_stream() {
        // Non-multiplexed: the flag goes as soon as the download is done.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.download_done = true;
        io.multiplex = false;
        io.recvs.push_back(RecvStep::Bytes(b"tail".to_vec()));
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(!xfer.req.keepon().contains(KeepFlags::RECV));
        assert_eq!(io.recv_log.len(), 1);

        // Multiplexed: it keeps going until the real end of stream.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.download_done = true;
        io.multiplex = true;
        io.recvs.push_back(RecvStep::Bytes(b"tail".to_vec()));
        io.recvs.push_back(RecvStep::Eos);
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert_eq!(io.recv_log.len(), 2);
        assert!(!xfer.req.keepon().contains(KeepFlags::RECV));
    }

    /// `:298-300`: a failing client write stops the loop and is reported.
    #[tokio::test]
    async fn a_failing_client_write_stops_the_loop() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        io.recvs.push_back(RecvStep::Bytes(b"body".to_vec()));
        io.writes.push_back(Err(CURLcode::WriteError));

        assert_eq!(xfer.sendrecv(&mut io).await, Err(CURLcode::WriteError));
        assert_eq!(io.recv_log.len(), 1);
    }

    /// The shared buffer is borrowed once and given back on EVERY path -- which
    /// is what the C's single `out:` label achieves.
    #[tokio::test]
    async fn the_transfer_buffer_is_always_returned() {
        for step in [
            RecvStep::Eos,
            RecvStep::Again,
            RecvStep::Fail(CURLcode::RecvError),
            RecvStep::Bytes(b"x".to_vec()),
        ] {
            let (mut xfer, mut io) = fixture();
            xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
            io.sched.buf_size = 4_096;
            io.recvs.push_back(step.clone());
            let _ = xfer.sendrecv(&mut io).await;
            assert_eq!(io.sched.buf_borrows, 1, "{step:?}");
            assert_eq!(io.sched.buf_size, 4_096, "{step:?}");
        }
    }

    /// A borrow that fails is the transfer's error.
    #[tokio::test]
    async fn a_failed_buffer_borrow_fails_the_transfer() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        io.sched.buf_borrow_result = Some(CURLcode::OutOfMemory);
        assert_eq!(xfer.sendrecv(&mut io).await, Err(CURLcode::OutOfMemory));
    }

    // ---- 12. content length and the timeout diagnostics ------------------

    /// `:386-406`: with keep flags still set and the deadline passed, the
    /// known-size and unknown-size diagnostics are exactly the C's.
    #[tokio::test]
    async fn an_expired_transfer_reports_the_bytes_it_received() {
        // Known size. The elapsed time is measured from `t_startsingle`, so the
        // request origin is pinned before the clock moves.
        let (mut xfer, mut io) = fixture();
        io.req.progress.time(PgrsTimer::StartSingle, &io.req.clock);
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.size = 1_000;
        xfer.req.bytecount = 400;
        io.recvs.push_back(RecvStep::Again);
        io.timeleft = -1;
        io.req.clock.advance(Duration::from_millis(2_500));

        assert_eq!(
            xfer.sendrecv(&mut io).await,
            Err(CURLcode::OperationTimedout)
        );
        assert!(
            io.failed_with(
                "Operation timed out after 2500 milliseconds with 400 out of \
                 1000 bytes received"
            ),
            "{:?}",
            io.req.fail
        );

        // Unknown size.
        let (mut xfer, mut io) = fixture();
        io.req.progress.time(PgrsTimer::StartSingle, &io.req.clock);
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.size = -1;
        xfer.req.bytecount = 77;
        io.recvs.push_back(RecvStep::Again);
        io.timeleft = -1;
        io.req.clock.advance(Duration::from_millis(1_250));

        assert_eq!(
            xfer.sendrecv(&mut io).await,
            Err(CURLcode::OperationTimedout)
        );
        assert!(io.failed_with(
            "Operation timed out after 1250 milliseconds with 77 bytes received"
        ));
    }

    /// `:407-419`: a finished transfer whose known length was not delivered is
    /// `CURLE_PARTIAL_FILE`, with the frozen line.
    #[tokio::test]
    async fn a_short_known_length_response_is_a_partial_file() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.size = 100;
        xfer.req.bytecount = 60;
        // The end of stream clears the keep flags, so the check applies.
        io.recvs.push_back(RecvStep::Eos);

        assert_eq!(xfer.sendrecv(&mut io).await, Err(CURLcode::PartialFile));
        assert!(
            io.failed_with("transfer closed with 40 bytes remaining to read")
        );
    }

    /// The same check passes when the length was met exactly, and is skipped for
    /// a bodyless response or one that is about to be followed.
    #[tokio::test]
    async fn an_exact_length_a_no_body_and_a_redirect_all_pass_the_check() {
        // Exactly the announced length.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.size = 100;
        xfer.req.bytecount = 100;
        io.recvs.push_back(RecvStep::Eos);
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(xfer.req.done, "no keep flags left, so the request is done");

        // A bodyless response is not measured.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.size = 100;
        xfer.req.bytecount = 0;
        xfer.req.no_body = true;
        io.recvs.push_back(RecvStep::Eos);
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));

        // Nor is one that carries a new URL: the body belongs to the redirect.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.size = 100;
        xfer.req.bytecount = 10;
        xfer.req.newurl = Some(String::from("http://example.com/next"));
        io.recvs.push_back(RecvStep::Eos);
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));

        // An unknown length cannot be short.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        xfer.req.size = -1;
        xfer.req.bytecount = 3;
        io.recvs.push_back(RecvStep::Eos);
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
    }

    /// `:382-384` and `:425`: the progress check runs after the I/O and its abort
    /// is the transfer's error, and the final update's abort is too.
    #[tokio::test]
    async fn a_refusing_progress_callback_aborts_the_transfer() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        io.recvs.push_back(RecvStep::Eos);
        io.req.callback.refuse = Some(1);

        assert_eq!(
            xfer.sendrecv(&mut io).await,
            Err(CURLcode::AbortedByCallback)
        );
        assert!(io.traced("Curl_sendrecv() -> 42"));
    }

    /// `Curl_pgrsCheck`'s `EXPIRE_SPEEDCHECK` is armed HERE, because
    /// `crate::transfer::progress` holds no multi handle (`lib/progress.c:166`).
    #[test]
    fn the_speed_check_timer_is_armed_from_the_progress_answer() {
        let (mut xfer, mut io) = fixture();
        // A low-speed limit arms the check; the transfer is under it.
        io.limits = LowSpeedLimit::new(1_000, 30);
        assert_eq!(xfer.pgrs_check(&mut io), Ok(()));
        assert_eq!(
            io.armed(ExpireId::SpeedCheck),
            vec![1_000],
            "SPEEDCHECK is armed for the C's one-second window"
        );

        // With no limit configured nothing is armed.
        let (mut xfer, mut io) = fixture();
        io.limits = LowSpeedLimit::new(0, 0);
        assert_eq!(xfer.pgrs_check(&mut io), Ok(()));
        assert!(io.armed(ExpireId::SpeedCheck).is_empty());
    }

    // ---- 13. the rate-limit gate -----------------------------------------

    /// `mspeed_check` (`lib/multi.c:1880-1922`): an idle wait parks the transfer
    /// in `RATELIMITING`, arms `TOOFAST` for the LONGER wait, clears the dirty
    /// bit and traces the C's line.
    #[test]
    fn a_rate_limited_transfer_parks_itself_with_a_toofast_timer() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        let now = io.req.clock.now();
        // One byte per second, and the bucket is empty: a wait is required.
        let mut limit = RateLimit::new(1, 0, now);
        limit.drain(1, now);
        *io.req.progress.download_mut().rlimit_mut() = limit;
        io.sched.mark_dirty();

        assert_eq!(xfer.speed_check(&mut io), RateGate::Waiting);
        assert_eq!(xfer.mstate(), CurlMstate::RateLimiting);
        let armed = io.armed(ExpireId::TooFast);
        assert_eq!(armed.len(), 1);
        assert!(armed[0] > 0, "a positive wait was armed: {armed:?}");
        assert!(io.traced(&format!("[RLIMIT] waiting {}ms", armed[0])));
        assert!(
            !io.sched.dirty,
            "the dirty bit is cleared, or the wait would be defeated"
        );
    }

    /// `:1901-1914`: with no wait required, the NEXT token refill is scheduled
    /// instead, and the transfer returns to `PERFORMING`.
    #[test]
    fn a_running_rate_limit_schedules_its_next_refill() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::RateLimiting);
        let now = io.req.clock.now();
        // Full bucket: no wait, but the refill still has to be scheduled.
        *io.req.progress.download_mut().rlimit_mut() =
            RateLimit::new(1_000, 0, now);

        assert_eq!(xfer.speed_check(&mut io), RateGate::Proceed);
        assert_eq!(xfer.mstate(), CurlMstate::Performing);
        let armed = io.armed(ExpireId::TooFast);
        assert_eq!(armed.len(), 1);
        assert!(io.traced("[RLIMIT] next token update in"));
        assert!(io.traced("[RLIMIT] wait over, continue"));
    }

    /// With no limiter active at all, nothing is armed and nothing is traced --
    /// but a transfer parked in `RATELIMITING` still comes back.
    #[test]
    fn an_unlimited_transfer_is_never_parked() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        assert_eq!(xfer.speed_check(&mut io), RateGate::Proceed);
        assert_eq!(xfer.mstate(), CurlMstate::Performing);
        assert!(io.armed(ExpireId::TooFast).is_empty());
        assert!(!io.traced("[RLIMIT]"));

        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::RateLimiting);
        assert_eq!(xfer.speed_check(&mut io), RateGate::Proceed);
        assert_eq!(xfer.mstate(), CurlMstate::Performing);
        assert!(io.traced("[RLIMIT] wait over, continue"));
    }

    /// `case MSTATE_RATELIMITING` (`lib/multi.c:1926-1954`): the progress check
    /// runs FIRST, and only a permitted rate check reruns immediately.
    #[tokio::test]
    async fn the_rate_limiting_state_checks_progress_before_the_rate() {
        // Still waiting: nothing to rerun.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::RateLimiting);
        let now = io.req.clock.now();
        let mut limit = RateLimit::new(1, 0, now);
        limit.drain(1, now);
        *io.req.progress.download_mut().rlimit_mut() = limit;

        let outcome = xfer.state_ratelimiting(&mut io).await;
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(outcome.result, CURLcode::Ok);
        assert_eq!(xfer.mstate(), CurlMstate::RateLimiting);

        // The wait is over: back to PERFORMING, and run again at once.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::RateLimiting);
        let now = io.req.clock.now();
        *io.req.progress.download_mut().rlimit_mut() =
            RateLimit::new(1_000, 0, now);
        let outcome = xfer.state_ratelimiting(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Performing);
    }

    /// `:1929-1948`: a progress abort in `RATELIMITING` closes a non-dual stream
    /// and completes prematurely.
    #[tokio::test]
    async fn a_progress_abort_while_rate_limited_closes_the_stream() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::RateLimiting);
        io.req.callback.refuse = Some(1);

        let outcome = xfer.state_ratelimiting(&mut io).await;
        assert_eq!(outcome.result, CURLcode::AbortedByCallback);
        assert_eq!(io.stream_closes, vec!["Transfer returned error"]);
        assert_eq!(io.completions, vec![true], "completed prematurely");

        // FTP is `PROTOPT_DUAL`, so its control connection is left alone: the
        // error happened on the data connection.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::RateLimiting);
        io.scheme = Some(&SCHEME_FTP);
        io.req.callback.refuse = Some(1);
        let outcome = xfer.state_ratelimiting(&mut io).await;
        assert_eq!(outcome.result, CURLcode::AbortedByCallback);
        assert!(io.stream_closes.is_empty());
    }

    // ---- 14. the timeout diagnostics -------------------------------------

    /// `multi_handle_timeout` (`lib/multi.c:1719-1770`): time left means no
    /// timeout at all.
    #[test]
    fn a_transfer_with_time_left_does_not_time_out() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.timeleft = 1;
        assert_eq!(xfer.handle_timeout(&mut io), None);
        io.timeleft = 0;
        assert_eq!(
            xfer.handle_timeout(&mut io),
            None,
            "zero is the C's no-limit, not an expiry"
        );
        assert!(io.req.fail.is_empty());
    }

    /// The four phase-specific diagnostics, and the stream close that only
    /// happens past `DO`.
    #[test]
    fn each_phase_reports_its_own_timeout_line() {
        // RESOLVING, measured from the request origin.
        let (mut xfer, mut io) = fixture();
        io.req.progress.time(PgrsTimer::StartSingle, &io.req.clock);
        park(&mut xfer, &mut io, CurlMstate::Resolving);
        io.timeleft = -1;
        io.req.clock.advance(Duration::from_millis(750));
        let hit = xfer.handle_timeout(&mut io).expect("expired");
        assert!(io.failed_with("Resolving timed out after 750 milliseconds"));
        assert!(!hit.stream_error, "nothing was on the wire yet");
        assert!(io.stream_closes.is_empty());

        // CONNECTING.
        let (mut xfer, mut io) = fixture();
        io.req.progress.time(PgrsTimer::StartSingle, &io.req.clock);
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        io.timeleft = -1;
        io.req.clock.advance(Duration::from_millis(1_500));
        let hit = xfer.handle_timeout(&mut io).expect("expired");
        assert!(io.failed_with("Connection timed out after 1500 milliseconds"));
        assert!(!hit.stream_error);

        // Past DO with a known size: the connection is closed and terminated.
        let (mut xfer, mut io) = fixture();
        io.req.progress.time(PgrsTimer::StartOp, &io.req.clock);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        xfer.req.size = 500;
        xfer.req.bytecount = 120;
        io.timeleft = -1;
        io.req.clock.advance(Duration::from_millis(3_000));
        let hit = xfer.handle_timeout(&mut io).expect("expired");
        assert!(io.failed_with(
            "Operation timed out after 3000 milliseconds with 120 out of 500 \
             bytes received"
        ));
        assert!(hit.stream_error, "the request was on the wire");
        assert_eq!(io.stream_closes, vec!["Disconnect due to timeout"]);

        // Past DO with an unknown size.
        let (mut xfer, mut io) = fixture();
        io.req.progress.time(PgrsTimer::StartOp, &io.req.clock);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        xfer.req.size = -1;
        xfer.req.bytecount = 9;
        io.timeleft = -1;
        io.req.clock.advance(Duration::from_millis(400));
        assert!(xfer.handle_timeout(&mut io).is_some());
        assert!(io.failed_with(
            "Operation timed out after 400 milliseconds with 9 bytes received"
        ));
    }

    /// `:1758-1760`: without a connection nothing is closed, however late it is.
    #[test]
    fn a_timeout_without_a_connection_closes_nothing() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.connected = false;
        io.timeleft = -1;
        let hit = xfer.handle_timeout(&mut io).expect("expired");
        assert!(!hit.stream_error);
        assert!(io.stream_closes.is_empty());
    }

    /// `SETUP` arms `TIMEOUT` and `CONNECTTIMEOUT`, and only when configured
    /// (`lib/multi.c:2504-2512`).
    #[test]
    fn setup_arms_the_two_configured_deadlines() {
        let (mut xfer, mut io) = fixture();
        xfer.settings_mut().timeout_ms = 30_000;
        xfer.settings_mut().connecttimeout_ms = 5_000;
        park(&mut xfer, &mut io, CurlMstate::Setup);

        xfer.state_setup(&mut io);
        assert_eq!(io.armed(ExpireId::Timeout), vec![30_000]);
        assert_eq!(io.armed(ExpireId::ConnectTimeout), vec![5_000]);
        assert!(io.req.pgrs_timers.contains(&PgrsTimer::StartSingle));
        assert_eq!(xfer.mstate(), CurlMstate::Connect);

        // Zero means "no limit", so nothing is armed -- arming a zero-millisecond
        // timer would expire the transfer at once.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Setup);
        xfer.state_setup(&mut io);
        assert!(io.armed(ExpireId::Timeout).is_empty());
        assert!(io.armed(ExpireId::ConnectTimeout).is_empty());
    }

    /// The Tokio timer seam: [`bounded`] arms nothing for the two non-positive
    /// cases of `Curl_timeleft_ms`.
    #[tokio::test]
    async fn an_unbounded_step_touches_no_timer() {
        for left in [0_i64, -1, -10_000] {
            let answer = bounded(
                left,
                Box::pin(core::future::ready(Ok::<u8, CURLcode>(7)))
                    as XferFuture<'_, u8>,
            )
            .await;
            assert_eq!(answer, Ok(7), "left={left}");
        }
    }

    /// A step that outlives the transfer's remaining time is cut off with
    /// `CURLE_OPERATION_TIMEDOUT`, and the diagnostic is NOT written here -- the
    /// driver's own `multi_handle_timeout` owns the four phase lines.
    #[tokio::test(start_paused = true)]
    async fn a_step_that_outlives_the_deadline_is_cut_off() {
        let slow = Box::pin(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok::<u8, CURLcode>(7)
        }) as XferFuture<'_, u8>;
        assert_eq!(
            bounded(1_000, slow).await,
            Err(CURLcode::OperationTimedout)
        );

        // A step that finishes inside the bound is untouched.
        let quick = Box::pin(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok::<u8, CURLcode>(7)
        }) as XferFuture<'_, u8>;
        assert_eq!(bounded(1_000, quick).await, Ok(7));
    }

    /// The bound applies to the state machine's pending steps, with both logical
    /// and Tokio time pinned.
    #[tokio::test(start_paused = true)]
    async fn a_connect_that_hangs_past_the_deadline_times_out() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        io.timeleft = 200;
        io.hang_conn_connect = Some(Duration::from_secs(60));

        let outcome = xfer.state_connecting(&mut io).await;
        assert_eq!(outcome.result, CURLcode::OperationTimedout);
        assert!(outcome.stream_error);
        assert_eq!(io.completions, vec![true]);
    }

    /// The same bound covers the PROTOCOL's own steps, so a scheme that never
    /// answers cannot hold a transfer past its deadline either.
    #[tokio::test(start_paused = true)]
    async fn a_protocol_connect_that_hangs_past_the_deadline_times_out() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnect);
        io.timeleft = 200;
        proto(|script| {
            script
                .connect_it
                .push_back(Step::Hang(Duration::from_secs(60)));
        });

        let outcome = xfer.state_protoconnect(&mut io, CURLcode::Ok).await;
        assert_eq!(outcome.result, CURLcode::OperationTimedout);
        assert!(outcome.stream_error);
        assert_eq!(proto_calls("connect_it"), 1);
    }

    // ---- 15. the connection states ---------------------------------------

    /// `state_connect` (`lib/multi.c:2275-2324`): all four outcomes.
    #[tokio::test]
    async fn the_connect_state_has_four_outcomes() {
        // No connection available: PENDING, parked, and the queue is NOT run.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connects
            .push_back(Ok(ConnectOutcome::NoConnectionAvailable));
        let outcome = xfer.state_connect(&mut io).await;
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(outcome.result, CURLcode::Ok);
        assert_eq!(xfer.mstate(), CurlMstate::Pending);
        assert_eq!(io.sched.parks, 1);
        assert_eq!(io.sched.pending_runs, 0);

        // An asynchronous name lookup: RESOLVING, and the queue runs.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connects.push_back(Ok(ConnectOutcome::Resolving));
        let outcome = xfer.state_connect(&mut io).await;
        // The C arms `CURLM_CALL_MULTI_PERFORM` in the `else` branch ONLY
        // (`:2299-2320`), so an asynchronous lookup waits for the resolver
        // rather than being run again at once.
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(xfer.mstate(), CurlMstate::Resolving);
        assert_eq!(io.sched.pending_runs, 1);

        // Already connected: PROTOCONNECT.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connects.push_back(Ok(ConnectOutcome::Connected));
        let outcome = xfer.state_connect(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::ProtoConnect);

        // Still connecting: CONNECTING.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connects.push_back(Ok(ConnectOutcome::Connecting));
        let outcome = xfer.state_connect(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Connecting);
        assert_eq!(io.sched.pending_runs, 1);

        // A failure still runs the pending queue (`:2296-2297`).
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connects.push_back(Err(CURLcode::CouldntConnect));
        let outcome = xfer.state_connect(&mut io).await;
        assert_eq!(outcome.result, CURLcode::CouldntConnect);
        assert!(!outcome.stream_error);
        assert_eq!(io.sched.pending_runs, 1);
    }

    /// `:2310-2314`: a NEW connection that can multiplex wakes the pending queue
    /// a second time, because other transfers can now share it.
    #[tokio::test]
    async fn a_new_multiplex_connection_wakes_the_pending_queue_twice() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connects.push_back(Ok(ConnectOutcome::Connected));
        io.reused = false;
        io.multiplex = true;
        let _ = xfer.state_connect(&mut io).await;
        assert_eq!(io.sched.pending_runs, 2);

        // A REUSED connection is already shared, so once is enough.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connects.push_back(Ok(ConnectOutcome::Connected));
        io.reused = true;
        io.multiplex = true;
        let _ = xfer.state_connect(&mut io).await;
        assert_eq!(io.sched.pending_runs, 1);
    }

    /// `PENDING` performs no transfer work at all: it is the multi handle's
    /// waiting room (`lib/multi.c:2707-2710`).
    #[tokio::test]
    async fn the_pending_state_does_nothing() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Pending);
        let outcome = xfer.run_state(&mut io, CURLcode::Ok).await.unwrap();
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(xfer.mstate(), CurlMstate::Pending);
        assert!(io.recv_log.is_empty());
        assert!(io.connects.is_empty());
        assert_eq!(io.sched.pending_runs, 0);

        // Its owner resumes it by moving it back to CONNECT.
        xfer.set_mstate(&mut io, CurlMstate::Connect);
        io.connects.push_back(Ok(ConnectOutcome::Connected));
        let outcome = xfer.run_state(&mut io, CURLcode::Ok).await.unwrap();
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::ProtoConnect);
    }

    /// `state_resolving` (`lib/multi.c:2225-2273`): the registrations are
    /// reassessed BEFORE the answer is acted on, and its failure wins.
    #[tokio::test]
    async fn the_resolving_state_reassesses_registrations_first() {
        // Still resolving.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Resolving);
        io.resolver_checks.push_back(Ok(ResolveStep::Pending));
        let outcome = xfer.state_resolving(&mut io).await.unwrap();
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(xfer.mstate(), CurlMstate::Resolving);
        assert_eq!(io.sched.assessments, 1);

        // Resolved and connected: PROTOCONNECT, run again.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Resolving);
        io.resolver_checks.push_back(Ok(ResolveStep::Resolved));
        io.once_resolveds.push_back(Ok(AsyncStep::Complete));
        let outcome = xfer.state_resolving(&mut io).await.unwrap();
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::ProtoConnect);

        // Resolved but still connecting.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Resolving);
        io.resolver_checks.push_back(Ok(ResolveStep::Resolved));
        io.once_resolveds.push_back(Ok(AsyncStep::Pending));
        let outcome = xfer.state_resolving(&mut io).await.unwrap();
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Connecting);

        // A resolution failure is a stream error.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Resolving);
        io.resolver_checks
            .push_back(Err(CURLcode::CouldntResolveHost));
        let outcome = xfer.state_resolving(&mut io).await.unwrap();
        assert_eq!(outcome.result, CURLcode::CouldntResolveHost);
        assert!(outcome.stream_error);

        // So is a failure once resolved.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Resolving);
        io.resolver_checks.push_back(Ok(ResolveStep::Resolved));
        io.once_resolveds.push_back(Err(CURLcode::CouldntConnect));
        let outcome = xfer.state_resolving(&mut io).await.unwrap();
        assert_eq!(outcome.result, CURLcode::CouldntConnect);
        assert!(outcome.stream_error);

        // The reassessment's own failure is a `CURLMcode`, reported before the
        // resolver's answer is looked at.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Resolving);
        io.sched.assess = Err(CURLMcode::InternalError);
        io.resolver_checks.push_back(Ok(ResolveStep::Resolved));
        assert_eq!(
            xfer.state_resolving(&mut io).await,
            Err(CURLMcode::InternalError)
        );
        assert_eq!(xfer.mstate(), CurlMstate::Resolving);
    }

    /// `case MSTATE_CONNECTING` (`lib/multi.c:2525-2547`): a PAUSED receive side
    /// does not even attempt the connect.
    #[tokio::test]
    async fn a_paused_receive_defers_the_connect() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        assert_eq!(xfer.xfer_pause_recv(&mut io, true), Ok(()));

        let outcome = xfer.state_connecting(&mut io).await;
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(xfer.mstate(), CurlMstate::Connecting);
        assert!(io.conn_connects.is_empty(), "nothing was attempted");
    }

    /// The connect's three outcomes, and the wake for a new multiplex
    /// connection.
    #[tokio::test]
    async fn the_connecting_state_has_three_outcomes() {
        // Connected: PROTOCONNECT, and a new multiplex connection wakes the
        // queue.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        io.conn_connects.push_back(Ok(AsyncStep::Complete));
        io.reused = false;
        io.multiplex = true;
        let outcome = xfer.state_connecting(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::ProtoConnect);
        assert_eq!(io.sched.pending_runs, 1);

        // Still connecting.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        io.conn_connects.push_back(Ok(AsyncStep::Pending));
        let outcome = xfer.state_connecting(&mut io).await;
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(xfer.mstate(), CurlMstate::Connecting);

        // Failed: posttransfer, a premature completion, and a stream error.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        io.conn_connects.push_back(Err(CURLcode::CouldntConnect));
        let outcome = xfer.state_connecting(&mut io).await;
        assert_eq!(outcome.result, CURLcode::CouldntConnect);
        assert!(outcome.stream_error);
        assert_eq!(io.completions, vec![true]);
    }

    /// `case MSTATE_PROTOCONNECT` (`lib/multi.c:2549-2577`): a REUSED connection
    /// skips the scheme's connect entirely.
    #[tokio::test]
    async fn a_reused_connection_skips_the_protocol_connect() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnect);
        io.reused = true;

        let outcome = xfer.state_protoconnect(&mut io, CURLcode::Ok).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Do);
        assert_eq!(proto_calls("connect_it"), 0);
    }

    /// A fresh connection runs the scheme's connect exactly once, and its
    /// readiness chooses between `DO` and `PROTOCONNECTING`.
    #[tokio::test]
    async fn the_protocol_connect_runs_once_and_chooses_the_next_state() {
        // Completed, and the scheme has no `connecting` member.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnect);
        io.has_connecting = false;
        proto(|script| script.connect_it.push_back(Step::Done));
        let outcome = xfer.state_protoconnect(&mut io, CURLcode::Ok).await;
        assert_eq!(xfer.mstate(), CurlMstate::Do);
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert!(io.protoconn_started);

        // Unfinished, and the scheme HAS a `connecting` member.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnect);
        io.has_connecting = true;
        proto(|script| script.connect_it.push_back(Step::Pending));
        let outcome = xfer.state_protoconnect(&mut io, CURLcode::Ok).await;
        assert_eq!(xfer.mstate(), CurlMstate::ProtoConnecting);
        assert_eq!(outcome.step, DriverStep::RunAgain);

        // Already started: the connect is not repeated, and a scheme with no
        // `connecting` member is therefore done.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnect);
        io.protoconn_started = true;
        io.has_connecting = false;
        let outcome = xfer.state_protoconnect(&mut io, CURLcode::Ok).await;
        assert_eq!(proto_calls("connect_it"), 0);
        assert_eq!(xfer.mstate(), CurlMstate::Do);
        assert_eq!(outcome.step, DriverStep::RunAgain);

        // A failure completes prematurely and is a stream error.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnect);
        proto(|script| {
            script
                .connect_it
                .push_back(Step::Fail(CURLcode::SslConnectError));
        });
        let outcome = xfer.state_protoconnect(&mut io, CURLcode::Ok).await;
        assert_eq!(outcome.result, CURLcode::SslConnectError);
        assert!(outcome.stream_error);
        assert_eq!(io.completions, vec![true]);
    }

    /// `:2550`: the C's `if(!result && ...)` guards read a `result` CARRIED from
    /// a previous loop iteration, so a carried failure suppresses both branches.
    #[tokio::test]
    async fn a_carried_failure_suppresses_the_protocol_connect() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnect);
        io.reused = true;
        let outcome = xfer
            .state_protoconnect(&mut io, CURLcode::CouldntConnect)
            .await;
        assert_eq!(outcome.result, CURLcode::CouldntConnect);
        assert!(outcome.stream_error);
        assert_eq!(proto_calls("connect_it"), 0);
        assert_eq!(
            xfer.mstate(),
            CurlMstate::ProtoConnect,
            "a carried failure does not advance the state"
        );
    }

    /// `case MSTATE_PROTOCONNECTING` (`lib/multi.c:2579-2593`).
    #[tokio::test]
    async fn the_protocol_connecting_state_waits_then_advances() {
        // Unfinished.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnecting);
        proto(|script| script.connecting.push_back(Step::Pending));
        let outcome = xfer.state_protoconnecting(&mut io).await;
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(xfer.mstate(), CurlMstate::ProtoConnecting);

        // Finished.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnecting);
        proto(|script| script.connecting.push_back(Step::Done));
        let outcome = xfer.state_protoconnecting(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Do);

        // Failed.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnecting);
        proto(|script| {
            script
                .connecting
                .push_back(Step::Fail(CURLcode::FtpWeirdPassReply));
        });
        let outcome = xfer.state_protoconnecting(&mut io).await;
        assert_eq!(outcome.result, CURLcode::FtpWeirdPassReply);
        assert!(outcome.stream_error);
        assert_eq!(io.completions, vec![true]);

        // A scheme with no implementation has nothing to wait for.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::ProtoConnecting);
        io.scheme = Some(&SCHEME_STUB);
        let outcome = xfer.state_protoconnecting(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Do);
    }

    // ---- 16. the request states ------------------------------------------

    /// `state_do` (`lib/multi.c:2063-2198`): the pre-request callback runs first,
    /// and a refusal is the C's frozen line.
    #[tokio::test]
    async fn a_refusing_pre_request_callback_aborts_the_transfer() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.prereq = Some(CURL_PREREQFUNC_ABORT);

        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.result, CURLcode::AbortedByCallback);
        assert!(outcome.stream_error);
        assert!(io.failed_with("operation aborted by pre-request callback"));
        assert_eq!(proto_calls("do_it"), 0);
        // The C's call is `multi_done(data, result, FALSE)`, and `multi_done`
        // then RAISES it: `CURLE_ABORTED_BY_CALLBACK` is one of the three codes
        // its own switch treats as premature (`lib/multi.c:690-702`).
        assert_eq!(io.completions, vec![true]);

        // An accepting callback lets the request through.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.prereq = Some(CURL_PREREQFUNC_OK);
        let _ = xfer.state_do(&mut io).await;
        assert_eq!(proto_calls("do_it"), 1);
    }

    /// `:2091-2094`: a connect-only transfer that is not a WebSocket has no
    /// request to issue, so it goes straight to `DONE`.
    #[tokio::test]
    async fn a_connect_only_transfer_goes_straight_to_done() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        xfer.settings_mut().connect_only = true;
        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Done);
        assert_eq!(proto_calls("do_it"), 0);

        // A WebSocket connect-only transfer DOES issue its request.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        xfer.settings_mut().connect_only = true;
        xfer.settings_mut().connect_only_ws = true;
        let _ = xfer.state_do(&mut io).await;
        assert_eq!(proto_calls("do_it"), 1);
    }

    /// `:2100-2166`: the scheme's `do_it` chooses between `DOING`, `DOING_MORE`
    /// and `DID`.
    #[tokio::test]
    async fn the_do_state_chooses_between_doing_doing_more_and_did() {
        // Unfinished: DOING.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        proto(|script| script.do_it.push_back(Step::Pending));
        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Doing);

        // Finished with a second half wanted: DOING_MORE.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.wants_do_more = true;
        proto(|script| script.do_it.push_back(Step::Done));
        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::DoingMore);

        // Finished: DID.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        proto(|script| script.do_it.push_back(Step::Done));
        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Did);
    }

    /// `:2168-2196`: a `CURLE_SEND_ERROR` on a REUSED connection is the race the
    /// retry machinery exists for, and restarts at `SETUP`.
    #[tokio::test]
    async fn a_send_error_on_a_reused_connection_is_retried() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.reused = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        proto(|script| script.do_it.push_back(Step::Fail(CURLcode::SendError)));

        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(outcome.result, CURLcode::Ok, "the retry cleared the error");
        assert_eq!(xfer.mstate(), CurlMstate::Setup);
        assert_eq!(io.follow.resolved.len(), 1);
        assert_eq!(io.follow.resolved[0].1, FollowType::Retry);
        assert_eq!(
            xfer.state.follow.followlocation, 0,
            "a retry is not a redirect and does not count as one"
        );

        // On a FRESH connection the same error is just an error.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.reused = false;
        proto(|script| script.do_it.push_back(Step::Fail(CURLcode::SendError)));
        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.result, CURLcode::SendError);
        assert!(outcome.stream_error);
    }

    /// `case MSTATE_DOING` (`lib/multi.c:2599-2617`).
    #[tokio::test]
    async fn the_doing_state_waits_then_chooses() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Doing);
        proto(|script| script.doing.push_back(Step::Pending));
        let outcome = xfer.state_doing(&mut io).await;
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(xfer.mstate(), CurlMstate::Doing);

        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Doing);
        proto(|script| script.doing.push_back(Step::Done));
        let outcome = xfer.state_doing(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Did);

        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Doing);
        io.wants_do_more = true;
        proto(|script| script.doing.push_back(Step::Done));
        let _ = xfer.state_doing(&mut io).await;
        assert_eq!(xfer.mstate(), CurlMstate::DoingMore);

        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Doing);
        proto(|script| script.doing.push_back(Step::Fail(CURLcode::RecvError)));
        let outcome = xfer.state_doing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::RecvError);
        assert!(outcome.stream_error);
        assert_eq!(io.completions, vec![false]);
    }

    /// `case MSTATE_DOING_MORE` (`lib/multi.c:2619-2642`): all three outcomes of
    /// the C's `int *completed`.
    #[tokio::test]
    async fn the_doing_more_state_covers_all_three_outcomes() {
        // 0: stay put. The C's `else` here is a comment -- "else stay in
        // DO_MORE".
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::DoingMore);
        proto(|script| script.do_more.push_back(Step::Pending));
        let outcome = xfer.state_doing_more(&mut io).await;
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(xfer.mstate(), CurlMstate::DoingMore);

        // 1: advance to DID.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::DoingMore);
        proto(|script| script.do_more.push_back(Step::Done));
        let outcome = xfer.state_doing_more(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Did);

        // -1: back to DOING. The Rust trait reports a `bool`, so this outcome is
        // reached through the typed mapping rather than through a raw integer.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::DoingMore);
        let outcome = xfer.apply_do_more(&mut io, DoMoreStep::Retry);
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Doing);

        // A failure cleans up.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::DoingMore);
        proto(|script| {
            script
                .do_more
                .push_back(Step::Fail(CURLcode::FtpCantGetHost));
        });
        let outcome = xfer.state_doing_more(&mut io).await;
        assert_eq!(outcome.result, CURLcode::FtpCantGetHost);
        assert!(outcome.stream_error);
        assert_eq!(io.completions, vec![false]);
    }

    /// `case MSTATE_DID` (`lib/multi.c:2644-2665`): a usable channel means
    /// `PERFORMING`; neither means `DONE`.
    #[tokio::test]
    async fn the_did_state_needs_a_channel_to_perform() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Did);
        let outcome = xfer.state_did(&mut io);
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Performing);

        // Neither channel: straight to DONE.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_nop(&mut io);
        park(&mut xfer, &mut io, CurlMstate::Did);
        let outcome = xfer.state_did(&mut io);
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Done);

        // A multiplexed connection wakes the pending queue here too.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Did);
        io.multiplex_bit = true;
        let _ = xfer.state_did(&mut io);
        assert_eq!(io.sched.pending_runs, 1);
    }

    /// `:2654-2661`: a wildcard match on a scheme that cannot glob is finished
    /// here rather than iterating for ever.
    #[cfg(feature = "ftp")]
    #[tokio::test]
    async fn a_wildcard_on_a_non_globbing_scheme_is_finished_at_did() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_nop(&mut io);
        park(&mut xfer, &mut io, CurlMstate::Did);
        xfer.state.wildcardmatch = true;
        xfer.state.wildcard = WildcardStage::Matching;
        // HTTP does not carry `PROTOPT_WILDCARD`.
        let _ = xfer.state_did(&mut io);
        assert_eq!(xfer.state.wildcard, WildcardStage::Done);

        // FTP does, so its iteration continues.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_nop(&mut io);
        park(&mut xfer, &mut io, CurlMstate::Did);
        io.scheme = Some(&SCHEME_FTP);
        xfer.state.wildcardmatch = true;
        xfer.state.wildcard = WildcardStage::Matching;
        let _ = xfer.state_did(&mut io);
        assert_eq!(xfer.state.wildcard, WildcardStage::Matching);
    }

    // ---- 17. PERFORMING: redirects, retries and errors -------------------

    /// `state_performing` (`lib/multi.c:1924-2061`): a completed transfer with an
    /// unpaused writer goes to `DONE`.
    #[tokio::test]
    async fn a_finished_transfer_goes_to_done() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.recvs.push_back(RecvStep::Eos);

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(outcome.result, CURLcode::Ok);
        assert_eq!(xfer.mstate(), CurlMstate::Done);
    }

    /// `:2005`: a PAUSED writer defers the whole decision -- the response has not
    /// reached the application, so neither a redirect nor `DONE` may run.
    #[tokio::test]
    async fn a_paused_writer_defers_the_completion() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.recvs.push_back(RecvStep::Eos);
        io.writer_paused = true;

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.step, DriverStep::Pending);
        assert!(xfer.req.done, "the request IS done");
        assert_eq!(
            xfer.mstate(),
            CurlMstate::Performing,
            "but the transfer stays put until the writer drains"
        );
    }

    /// `:1989-2004`: a transfer error closes a non-dual connection, completes
    /// prematurely and keeps the original code.
    #[tokio::test]
    async fn a_transfer_error_closes_the_stream_and_completes_prematurely() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.recvs.push_back(RecvStep::Fail(CURLcode::PartialFile));

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::PartialFile);
        assert_eq!(io.stream_closes, vec!["Transfer returned error"]);
        assert_eq!(io.completions, vec![true]);

        // `PROTOPT_DUAL`: the error was on the data connection, so the control
        // connection is left alone.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.scheme = Some(&SCHEME_FTP);
        io.recvs.push_back(RecvStep::Fail(CURLcode::PartialFile));
        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::PartialFile);
        assert!(io.stream_closes.is_empty());

        // `CURLE_HTTP2_STREAM`: only one stream failed, so the connection stays.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.recvs.push_back(RecvStep::Fail(CURLcode::Http2Stream));
        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::Http2Stream);
        assert!(io.stream_closes.is_empty());
    }

    /// `:1940-1957`: a `CURLE_RECV_ERROR` on a reused connection is retried, the
    /// error is cleared and the request is considered done.
    #[tokio::test]
    async fn an_early_receive_error_on_a_reused_connection_becomes_a_retry() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.reused = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        io.recvs.push_back(RecvStep::Fail(CURLcode::RecvError));

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::Ok, "the retry cleared the error");
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Setup);
        assert_eq!(io.follow.resolved[0].1, FollowType::Retry);
        assert_eq!(
            xfer.state.follow.followlocation, 0,
            "a retry never counts as a redirect"
        );
    }

    /// `:1958-1987`: an `HTTP_1_1_REQUIRED` stream error downgrades to HTTP/1.1
    /// with the frozen lines, forcing both version masks.
    #[tokio::test]
    async fn an_http2_stream_error_downgrades_to_http_1_1() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.h2_downgrade = true;
        io.reused = true;
        xfer.state.errorbuf = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        io.recvs.push_back(RecvStep::Fail(CURLcode::Http2Stream));

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::Ok);
        assert_eq!(xfer.mstate(), CurlMstate::Setup);
        assert!(io.traced("Downgrades to HTTP/1.1"));
        assert_eq!(io.stream_closes, vec!["Disconnect HTTP/2 for HTTP/1"]);
        assert_eq!(xfer.state.http_neg.wanted, CURL_HTTP_V1X);
        assert_eq!(xfer.state.http_neg.allowed, CURL_HTTP_V1X);
        assert!(!xfer.state.errorbuf, "the ignored message bit is cleared");
        assert_eq!(io.follow.resolved[0].1, FollowType::Retry);

        // `:1970-1972`: with no URL from the retry the CURRENT one is duplicated
        // -- the "HTTP_1_1_REQUIRED error on first flight" case.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.h2_downgrade = true;
        io.reused = false;
        xfer.state.url = Some(String::from("http://example.com/first"));
        io.recvs.push_back(RecvStep::Fail(CURLcode::Http2Stream));
        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::Ok);
        assert_eq!(
            io.follow.resolved[0].0, "http://example.com/first",
            "the current URL was duplicated"
        );

        // With neither a retry URL nor a current one, the C answers
        // `CURLE_OUT_OF_MEMORY`.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.h2_downgrade = true;
        io.reused = false;
        xfer.state.url = None;
        io.recvs.push_back(RecvStep::Fail(CURLcode::Http2Stream));
        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::OutOfMemory);
    }

    /// `:2011-2033`: a real redirect completes NON-prematurely and follows with
    /// `FOLLOW_REDIR`, returning to `SETUP`.
    #[tokio::test]
    async fn a_true_redirect_follows_and_restarts_at_setup() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.recvs.push_back(RecvStep::Eos);
        xfer.req.newurl = Some(String::from("http://example.com/next"));

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Setup);
        assert_eq!(io.completions, vec![false], "NOT premature");
        assert_eq!(io.follow.resolved.len(), 1);
        assert_eq!(io.follow.resolved[0].1, FollowType::Redir);
        assert_eq!(
            io.follow.committed.as_deref(),
            Some("http://example.com/next")
        );
        assert_eq!(xfer.state.follow.followlocation, 1);
        assert!(xfer.req.newurl.is_none(), "the URL was detached");
    }

    /// `:2036-2047`: NOT following, but a `Location:` was seen -- the fake follow
    /// records it for `CURLINFO_REDIRECT_URL` without requesting it.
    #[tokio::test]
    async fn a_location_without_following_is_recorded_as_a_fake_redirect() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.follow_settings.mode = FollowMode::Disabled;
        io.recvs.push_back(RecvStep::Eos);
        xfer.req.location = Some(String::from("http://example.com/elsewhere"));

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Done);
        assert_eq!(io.follow.resolved[0].1, FollowType::Fake);
        assert_eq!(
            xfer.state.follow.wouldredirect.as_deref(),
            Some("http://example.com/elsewhere")
        );
        assert!(xfer.req.location.is_none());
    }

    /// A failing fake follow is a stream error (`:2043-2046`) -- but the
    /// completion's answer REPLACES the follow's, so a tidy completion still
    /// lands the transfer in `DONE`.
    #[tokio::test]
    async fn a_failing_fake_follow_is_a_stream_error() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.follow_settings.mode = FollowMode::Disabled;
        io.recvs.push_back(RecvStep::Eos);
        xfer.req.location = Some(String::from("http://example.com/x"));
        io.follow.resolve.push_back(ResolvedTarget::Unparsable {
            code: CURLcode::OutOfMemory,
            reason: "Out of memory",
        });

        let outcome = xfer.state_performing(&mut io).await;
        assert!(outcome.stream_error);
        assert_eq!(
            outcome.result,
            CURLcode::OutOfMemory,
            "the scheme's `done` propagated the status, as `Curl_http_done` \
             does at `lib/http.c:1120`"
        );
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(
            xfer.mstate(),
            CurlMstate::Performing,
            "`is_finished` is the one that terminates the connection"
        );
        assert_eq!(io.completions, vec![true]);

        // The completion's own code is the one reported: `Curl_http_done`'s
        // "Empty reply from server" answers `CURLE_GOT_NOTHING` whatever the
        // status it was handed.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.follow_settings.mode = FollowMode::Disabled;
        io.recvs.push_back(RecvStep::Eos);
        xfer.req.location = Some(String::from("http://example.com/x"));
        io.follow.resolve.push_back(ResolvedTarget::Unparsable {
            code: CURLcode::OutOfMemory,
            reason: "Out of memory",
        });
        proto(|script| script.done.push_back(CURLcode::GotNothing));

        let outcome = xfer.state_performing(&mut io).await;
        assert!(outcome.stream_error);
        assert_eq!(outcome.result, CURLcode::GotNothing);
        assert_eq!(outcome.step, DriverStep::Pending);

        // And the reading that is easy to miss: a completion that answers
        // SUCCESS -- which `:679-681` does for a transfer already completed --
        // leaves `result` clear, so the transfer goes to `DONE` still carrying
        // `stream_error`, which `is_finished` then ignores because it only acts
        // on a failure.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.follow_settings.mode = FollowMode::Disabled;
        io.recvs.push_back(RecvStep::Eos);
        xfer.req.location = Some(String::from("http://example.com/x"));
        io.follow.resolve.push_back(ResolvedTarget::Unparsable {
            code: CURLcode::OutOfMemory,
            reason: "Out of memory",
        });
        xfer.state.done = true;

        let outcome = xfer.state_performing(&mut io).await;
        assert!(outcome.stream_error);
        assert_eq!(outcome.result, CURLcode::Ok);
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Done);
    }

    /// `lib/multi.c:1186-1197`: a fake follow tolerates an unparsable target --
    /// only `CURLE_OUT_OF_MEMORY` stops it -- because the point is to record
    /// what the server said, not to request it.
    #[tokio::test]
    async fn a_fake_follow_records_an_unparsable_target_verbatim() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.follow_settings.mode = FollowMode::Disabled;
        io.recvs.push_back(RecvStep::Eos);
        xfer.req.location = Some(String::from("://not-a-url"));
        io.follow.resolve.push_back(ResolvedTarget::Unparsable {
            code: CURLcode::UrlMalformat,
            reason: "Malformed input to a URL function",
        });

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::Ok);
        assert!(!outcome.stream_error);
        assert_eq!(xfer.mstate(), CurlMstate::Done);
        assert_eq!(
            xfer.state.follow.wouldredirect.as_deref(),
            Some("://not-a-url")
        );
    }

    /// A scheme with no `follow` operation answers `CURLE_TOO_MANY_REDIRECTS`,
    /// which is the C's own answer for a `NULL` slot (`lib/multi.c:1875-1877`).
    #[tokio::test]
    async fn a_scheme_without_a_follow_operation_refuses_to_redirect() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        // A registered scheme with no implementation has no follow either.
        io.scheme = Some(&SCHEME_STUB);
        io.recvs.push_back(RecvStep::Eos);
        xfer.req.newurl = Some(String::from("http://example.com/next"));

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::TooManyRedirects);
        assert_eq!(xfer.mstate(), CurlMstate::Performing);
    }

    /// `:1934-1935`: a rate-limited transfer does no I/O at all in `PERFORMING`.
    #[tokio::test]
    async fn a_rate_limited_performing_transfer_does_no_io() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        let now = io.req.clock.now();
        let mut limit = RateLimit::new(1, 0, now);
        limit.drain(1, now);
        *io.req.progress.download_mut().rlimit_mut() = limit;

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.step, DriverStep::Pending);
        assert_eq!(xfer.mstate(), CurlMstate::RateLimiting);
        assert!(io.recv_log.is_empty());
    }

    // ---- 18. completion --------------------------------------------------

    /// `multi_done` (`lib/multi.c:665-737`): idempotent, and the first thing it
    /// does is say so.
    #[tokio::test]
    async fn the_completion_runs_once() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);

        assert_eq!(
            xfer.complete(&mut io, CURLcode::Ok, false).await,
            CURLcode::Ok
        );
        assert_eq!(io.completions.len(), 1);
        assert_eq!(io.data_dones, vec![false]);
        assert_eq!(io.resolver_shutdowns, 1);
        assert!(xfer.state.done);
        assert!(io.traced("multi_done: status: 0 prem: 0 done: 0"));

        // A second call does nothing at all.
        assert_eq!(
            xfer.complete(&mut io, CURLcode::Ok, false).await,
            CURLcode::Ok
        );
        assert_eq!(io.completions.len(), 1);
        assert_eq!(io.resolver_shutdowns, 1);
        assert!(io.traced("multi_done: status: 0 prem: 0 done: 1"));
    }

    /// `:686-688`: redirect junk is cleared, so a completed transfer cannot leave
    /// a URL behind for the next one.
    #[tokio::test]
    async fn the_completion_clears_the_redirect_junk() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);
        xfer.req.newurl = Some(String::from("http://example.com/a"));
        xfer.req.location = Some(String::from("http://example.com/b"));

        let _ = xfer.complete(&mut io, CURLcode::Ok, false).await;
        assert!(xfer.req.newurl.is_none());
        assert!(xfer.req.location.is_none());
    }

    /// `:690-702`: three codes force premature treatment, whatever the caller
    /// asked for.
    #[tokio::test]
    async fn three_codes_force_a_premature_completion() {
        for status in [
            CURLcode::AbortedByCallback,
            CURLcode::ReadError,
            CURLcode::WriteError,
        ] {
            let (mut xfer, mut io) = fixture();
            park(&mut xfer, &mut io, CurlMstate::Done);
            let _ = xfer.complete(&mut io, status, false).await;
            assert_eq!(io.completions, vec![true], "{status:?}");
            assert_eq!(io.data_dones, vec![true], "{status:?}");
        }

        // Anything else is left as the caller asked.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);
        let _ = xfer.complete(&mut io, CURLcode::PartialFile, false).await;
        assert_eq!(io.completions, vec![false]);
    }

    /// `:704-708`: the scheme's `done` runs only once the transfer reached
    /// `PROTOCONNECT`, and only when the scheme has one.
    #[tokio::test]
    async fn the_protocol_completion_is_gated_on_the_protocol_connect_state() {
        // Before PROTOCONNECT: not called, and the status passes through.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        assert_eq!(
            xfer.complete(&mut io, CURLcode::CouldntConnect, true).await,
            CURLcode::CouldntConnect
        );
        assert_eq!(proto_calls("done"), 0);

        // At or past PROTOCONNECT: called, with the status and the premature
        // flag.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        let _ = xfer.complete(&mut io, CURLcode::Ok, true).await;
        assert_eq!(proto_calls("done"), 1);
        assert_eq!(proto(|s| s.done_args.clone()), vec![(CURLcode::Ok, true)]);

        // Its failure becomes the completion's code.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        proto(|script| script.done.push_back(CURLcode::FtpCantGetHost));
        assert_eq!(
            xfer.complete(&mut io, CURLcode::Ok, false).await,
            CURLcode::FtpCantGetHost
        );

        // A scheme with no implementation contributes nothing.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.scheme = Some(&SCHEME_STUB);
        assert_eq!(
            xfer.complete(&mut io, CURLcode::PartialFile, false).await,
            CURLcode::PartialFile
        );
    }

    /// `:710-716`: the final progress callback is skipped when the status is
    /// ALREADY a callback abort, so the application is not called back into a
    /// failure it caused.
    #[tokio::test]
    async fn an_existing_callback_abort_suppresses_the_final_callback() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.req.callback.refuse = Some(1);
        assert_eq!(
            xfer.complete(&mut io, CURLcode::AbortedByCallback, false)
                .await,
            CURLcode::AbortedByCallback
        );

        // Otherwise the abort is picked up.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.req.callback.refuse = Some(1);
        assert_eq!(
            xfer.complete(&mut io, CURLcode::Ok, false).await,
            CURLcode::AbortedByCallback
        );
    }

    /// `:718-719`: the client flush RUNS even when the protocol's completion
    /// failed, and `Curl_1st_err` keeps the FIRST code.
    #[tokio::test]
    async fn the_client_flush_always_runs_and_the_first_error_wins() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        proto(|script| script.done.push_back(CURLcode::FtpCantGetHost));
        io.write_done_result = Err(CURLcode::WriteError);

        assert_eq!(
            xfer.complete(&mut io, CURLcode::Ok, false).await,
            CURLcode::FtpCantGetHost,
            "the protocol's code came first"
        );
        assert_eq!(io.write_done.len(), 1, "and the flush still ran");

        // With nothing before it, the flush's own code is reported.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.write_done_result = Err(CURLcode::WriteError);
        assert_eq!(
            xfer.complete(&mut io, CURLcode::Ok, false).await,
            CURLcode::WriteError
        );
    }

    /// `first_err` is the C's `Curl_1st_err` (`lib/url.h:95-99`).
    #[test]
    fn the_first_error_is_the_first_non_success() {
        assert_eq!(first_err(CURLcode::Ok, CURLcode::Ok), CURLcode::Ok);
        assert_eq!(
            first_err(CURLcode::Ok, CURLcode::WriteError),
            CURLcode::WriteError
        );
        assert_eq!(
            first_err(CURLcode::ReadError, CURLcode::WriteError),
            CURLcode::ReadError
        );
        assert_eq!(
            first_err(CURLcode::ReadError, CURLcode::Ok),
            CURLcode::ReadError
        );
    }

    /// `:729-732`: the pool decides about the connection, and a transfer that was
    /// NOT the last user leaves `state.done` clear so the last one still gets to
    /// decide.
    #[tokio::test]
    async fn the_pool_decides_and_a_shared_connection_stays_undone() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);
        io.completion_outcome = ConnectionOutcome {
            recent: Some(11),
            last: Some(11),
            still_in_use: false,
        };
        let _ = xfer.complete(&mut io, CURLcode::Ok, false).await;
        assert!(xfer.state.done);
        assert_eq!(xfer.state.recent_conn_id, Some(11));
        assert_eq!(xfer.state.lastconnect_id, Some(11));

        // Another stream is still using it.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);
        io.completion_outcome = ConnectionOutcome {
            recent: Some(4),
            last: None,
            still_in_use: true,
        };
        let _ = xfer.complete(&mut io, CURLcode::Ok, false).await;
        assert!(
            !xfer.state.done,
            "the last user of a multiplexed connection makes the decision"
        );
        assert_eq!(
            xfer.state.recent_conn_id, None,
            "`:629` runs AFTER the in-use return at `:625`"
        );
        assert_eq!(xfer.state.lastconnect_id, None);
    }

    // ---- 19. the error exit ----------------------------------------------

    /// `is_finished` (`lib/multi.c:2327-2383`): a transfer already at
    /// `COMPLETED` is left entirely alone -- the C's `if(data->mstate <
    /// MSTATE_COMPLETED)` brackets the whole body.
    #[test]
    fn a_completed_transfer_is_left_alone() {
        for state in [CurlMstate::Completed, CurlMstate::MsgSent] {
            let (mut xfer, mut io) = fixture();
            park(&mut xfer, &mut io, state);
            // `init_completed` detaches on the way in, so the baseline is what
            // this asserts against.
            let detaches = io.detaches;
            assert_eq!(
                xfer.finish(&mut io, true, CURLcode::CouldntConnect),
                CURLcode::CouldntConnect
            );
            assert_eq!(io.sched.pending_runs, 0, "{state:?}");
            assert_eq!(io.detaches, detaches, "{state:?}");
            assert!(io.terminates.is_empty(), "{state:?}");
            assert_eq!(xfer.mstate(), state);
        }
    }

    /// `:2342-2365`: a failure runs the pending queue, terminates a stream
    /// error's connection and goes to `COMPLETED`.
    #[test]
    fn a_failure_terminates_the_stream_and_completes() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);

        assert_eq!(
            xfer.finish(&mut io, true, CURLcode::RecvError),
            CURLcode::RecvError
        );
        assert_eq!(io.sched.pending_runs, 1);
        assert_eq!(
            io.detaches, 2,
            "once for the stream error, once for `init_completed`"
        );
        assert_eq!(
            io.terminates,
            vec![false],
            "only a timeout marks the connection dead"
        );
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
    }

    /// `:2348-2349`: "Do not attempt to send data over a connection that timed
    /// out" -- `CURLE_OPERATION_TIMEDOUT` is the ONE code that marks it dead.
    #[test]
    fn only_a_timeout_marks_the_connection_dead() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        let _ = xfer.finish(&mut io, true, CURLcode::OperationTimedout);
        assert_eq!(io.terminates, vec![true]);
    }

    /// `:2346-2356`: without a stream error the connection is neither detached
    /// nor terminated -- it may still be reusable.
    #[test]
    fn a_failure_without_a_stream_error_keeps_the_connection() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        assert_eq!(
            xfer.finish(&mut io, false, CURLcode::PartialFile),
            CURLcode::PartialFile
        );
        assert_eq!(io.sched.pending_runs, 1);
        assert_eq!(io.detaches, 1, "`init_completed`'s detach alone");
        assert!(
            io.terminates.is_empty(),
            "the connection may still be reusable"
        );
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
    }

    /// `:2358-2362`: `Curl_connect()` failed, so there is no connection to
    /// terminate; the transfer reports progress WITHOUT the meter instead.
    #[test]
    fn a_connect_failure_without_a_connection_reports_progress_only() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connected = false;

        assert_eq!(
            xfer.finish(&mut io, true, CURLcode::CouldntResolveHost),
            CURLcode::CouldntResolveHost
        );
        assert_eq!(io.detaches, 1, "`init_completed`'s detach alone");
        assert!(io.terminates.is_empty());
        assert_eq!(io.nometer_updates, 1);
        assert_eq!(xfer.mstate(), CurlMstate::Completed);

        // Any OTHER state without a connection does neither: the C's `else if`
        // names `MSTATE_CONNECT` alone.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Resolving);
        io.connected = false;
        let _ = xfer.finish(&mut io, true, CURLcode::CouldntResolveHost);
        assert_eq!(
            io.nometer_updates, 0,
            "the meterless update belongs to CONNECT alone"
        );
    }

    /// `:2367-2369`: a SUCCESS with a connection still calls the progress
    /// function, and a tidy callback changes nothing.
    #[test]
    fn a_success_calls_the_progress_function() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        assert_eq!(xfer.finish(&mut io, false, CURLcode::Ok), CURLcode::Ok);
        assert_eq!(xfer.mstate(), CurlMstate::Performing);
        assert_eq!(io.sched.pending_runs, 0);

        // No connection: no callback, and nothing else either.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.connected = false;
        io.req.callback.refuse = Some(1);
        assert_eq!(
            xfer.finish(&mut io, false, CURLcode::Ok),
            CURLcode::Ok,
            "the callback is not reached without a connection"
        );
    }

    /// `:2371-2378`: an abort in that callback closes the stream and goes to
    /// `DONE` -- or straight to `COMPLETED` once `DONE` has passed.
    #[test]
    fn a_progress_abort_closes_the_stream_and_moves_on() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.req.callback.refuse = Some(1);

        assert_eq!(
            xfer.finish(&mut io, false, CURLcode::Ok),
            CURLcode::AbortedByCallback
        );
        assert_eq!(io.stream_closes, vec!["Aborted by callback"]);
        assert_eq!(xfer.mstate(), CurlMstate::Done);

        // At or past DONE the transfer cannot go back, so it completes.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);
        io.req.callback.refuse = Some(1);
        assert_eq!(
            xfer.finish(&mut io, false, CURLcode::Ok),
            CURLcode::AbortedByCallback
        );
        assert_eq!(io.stream_closes, vec!["Aborted by callback"]);
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
    }

    // ---- 20. the driver --------------------------------------------------

    /// `multi_runsingle` (`lib/multi.c:2429-2745`): a transfer at `COMPLETED`
    /// answers its owner at once, and the code travels in the answer rather than
    /// in `data->result`.
    #[tokio::test]
    async fn a_completed_transfer_reports_completion_to_its_owner() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Completed);

        let answer = xfer.run_single(&mut io).await;
        assert_eq!(answer, Ok(RunSingle::Completed(CURLcode::Ok)));
        assert_eq!(
            xfer.result(),
            CURLcode::Ok,
            "`:2743` is not reached on the completion path"
        );
        assert_eq!(io.sched.dirty_clears, 1, "`:2454`, once before the loop");
    }

    /// `:2441-2448`: a dead multi handle fails every transfer in it -- and the C
    /// does NOT return early, so the pending queue still runs.
    #[tokio::test]
    async fn a_dead_multi_handle_fails_the_transfer_but_still_runs_the_queue() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.sched.dead = true;

        let answer = xfer.run_single(&mut io).await;
        assert_eq!(
            answer,
            Ok(RunSingle::Completed(CURLcode::AbortedByCallback)),
            "the reason survives to the owner's CURLMSG_DONE"
        );
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
        assert_eq!(
            io.completions,
            vec![true],
            "`CURLE_ABORTED_BY_CALLBACK` forces premature (`:690-702`)"
        );
        assert_eq!(
            io.sched.pending_runs, 1,
            "one iteration ran, and its first act was the queue"
        );
    }

    /// `:2468-2471`: a changed multi handle runs the pending queue with the
    /// frozen line, and the peek at `:2740` does not consume the flag a second
    /// time.
    #[tokio::test]
    async fn a_changed_multi_handle_runs_the_pending_queue() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Completed);
        io.sched.changed.push_back(true);

        let _ = xfer.run_single(&mut io).await;
        assert!(io.traced("multi changed, check CONNECT_PEND queue"));
        assert_eq!(io.sched.pending_runs, 1);
        assert!(
            io.sched.changed.is_empty(),
            "`multi_ischanged(multi, TRUE)` consumed it"
        );
    }

    /// `:2473-2479`: past `CONNECT` and before `COMPLETED` a transfer MUST have
    /// a connection; the C answers `CURLM_INTERNAL_ERROR` and so does this.
    #[tokio::test]
    async fn a_transfer_past_connect_must_have_a_connection() {
        for state in [
            CurlMstate::Resolving,
            CurlMstate::Connecting,
            CurlMstate::ProtoConnect,
            CurlMstate::Do,
            CurlMstate::Performing,
            CurlMstate::Done,
        ] {
            let (mut xfer, mut io) = fixture();
            park(&mut xfer, &mut io, state);
            io.connected = false;
            assert_eq!(
                xfer.run_single(&mut io).await,
                Err(CURLMcode::InternalError),
                "{state:?}"
            );
        }

        // `CONNECT` itself and the states before it are exempt, because the
        // connection is what `CONNECT` goes to acquire.
        for state in [
            CurlMstate::Init,
            CurlMstate::Pending,
            CurlMstate::Setup,
            CurlMstate::Connect,
        ] {
            let (mut xfer, mut io) = fixture();
            park(&mut xfer, &mut io, state);
            io.connected = false;
            io.connects
                .push_back(Ok(ConnectOutcome::NoConnectionAvailable));
            assert!(xfer.run_single(&mut io).await.is_ok(), "{state:?}");
        }
    }

    /// `:2489-2514`: `INIT` falls through `SETUP` into `CONNECT`, recording
    /// `TIMER_STARTOP` between the first two.
    #[tokio::test]
    async fn the_init_state_falls_through_setup_into_connect() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Init);
        io.connects.push_back(Ok(ConnectOutcome::Connected));

        let answer = xfer.run_single(&mut io).await;
        assert!(answer.is_ok());
        assert!(xfer.pretransfer_done());
        assert_ne!(
            io.req.progress.start_op(),
            CurlTime::ZERO,
            "`TIMER_STARTOP`, between INIT and SETUP"
        );
        assert_ne!(
            io.req.progress.start_single(),
            CurlTime::ZERO,
            "`TIMER_STARTSINGLE`, in SETUP"
        );
        // The three states in ONE entry, which is what a fall-through means.
        assert_eq!(
            io.states()[..3],
            [
                String::from("-> [SETUP]"),
                String::from("-> [CONNECT]"),
                String::from("-> [PROTOCONNECT]"),
            ]
        );
    }

    /// A failing `pretransfer` never reaches `SETUP`.
    #[tokio::test]
    async fn a_failing_pretransfer_completes_the_transfer() {
        let mut xfer = Transfer::new(TransferSettings::default());
        let mut io = FakeIo::default();
        proto_reset();
        park(&mut xfer, &mut io, CurlMstate::Init);

        let answer = xfer.run_single(&mut io).await;
        assert_eq!(
            answer,
            Ok(RunSingle::Completed(CURLcode::UrlMalformat)),
            "`No URL set`"
        );
        assert!(io.failed_with("No URL set"));
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
    }

    /// `case MSTATE_DONE` (`:2675-2703`): transient, so it always runs again,
    /// and an EARLIER error takes precedence over the completion's.
    #[tokio::test]
    async fn the_done_state_completes_and_keeps_the_earlier_error() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);
        let outcome = xfer.state_done(&mut io, CURLcode::Ok).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(outcome.result, CURLcode::Ok);
        assert_eq!(io.completions, vec![false]);
        assert_eq!(xfer.mstate(), CurlMstate::Completed);

        // The completion's own failure is reported when nothing failed before.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);
        proto(|script| script.done.push_back(CURLcode::GotNothing));
        let outcome = xfer.state_done(&mut io, CURLcode::Ok).await;
        assert_eq!(outcome.result, CURLcode::GotNothing);

        // But an earlier one wins: `if(!result) result = res` (`:2686-2687`).
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);
        proto(|script| script.done.push_back(CURLcode::GotNothing));
        let outcome = xfer.state_done(&mut io, CURLcode::PartialFile).await;
        assert_eq!(outcome.result, CURLcode::PartialFile);
        assert_eq!(xfer.mstate(), CurlMstate::Completed);

        // Without a connection there is nothing to complete.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Done);
        io.connected = false;
        let outcome = xfer.state_done(&mut io, CURLcode::Ok).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert!(io.completions.is_empty());
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
    }

    /// `:2690-2699`: an unfinished FTP wildcard match is the ONE way back to
    /// `INIT`, and the pretransfer flag is cleared so the next file initialises.
    #[cfg(feature = "ftp")]
    #[tokio::test]
    async fn an_unfinished_wildcard_match_restarts_at_init() {
        let (mut xfer, mut io) = fixture();
        io.scheme = Some(&SCHEME_FTP);
        assert!(xfer.pretransfer(&mut io).is_ok());
        xfer.state.wildcardmatch = true;
        xfer.state.wildcard = WildcardStage::Matching;
        park(&mut xfer, &mut io, CurlMstate::Done);

        let outcome = xfer.state_done(&mut io, CURLcode::Ok).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Init);
        assert!(
            !xfer.pretransfer_done(),
            "the next file runs its own pretransfer"
        );

        // A finished match completes as usual.
        let (mut xfer, mut io) = fixture();
        io.scheme = Some(&SCHEME_FTP);
        xfer.state.wildcardmatch = true;
        xfer.state.wildcard = WildcardStage::Done;
        park(&mut xfer, &mut io, CurlMstate::Done);
        let _ = xfer.state_done(&mut io, CURLcode::Ok).await;
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
    }

    /// `:2717-2728`: the second stream-timeout check runs ONLY on what will be
    /// the last iteration -- "we should do that before declaring the connection
    /// timed out as we may almost have a completed connection".
    #[tokio::test]
    async fn the_second_timeout_check_waits_for_the_last_iteration() {
        // `CONNECTING` answering `CURLM_OK` with nothing changed IS the last
        // iteration, so the deadline is declared.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        io.conn_connects.push_back(Ok(AsyncStep::Pending));
        io.timeleft = 0;
        io.req.progress.time(PgrsTimer::StartSingle, &io.req.clock);
        io.req.clock.advance(Duration::from_millis(1_500));
        io.timeleft = -1;

        let answer = xfer.run_single(&mut io).await;
        assert_eq!(
            answer,
            Ok(RunSingle::Completed(CURLcode::OperationTimedout))
        );
        assert!(io.failed_with("Connection timed out after"));

        // The same transfer with work to do immediately does NOT declare it:
        // `CONNECT` answering `CURLM_CALL_MULTI_PERFORM` finishes its work
        // first, and by then the state is past `DO` so the window has closed.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connects.push_back(Ok(ConnectOutcome::Connected));
        io.timeleft = -1;
        let answer = xfer.run_single(&mut io).await;
        assert!(answer.is_ok());
        assert!(
            !io.failed_with("Connection timed out after"),
            "the first check owns the deadline once the state has moved on"
        );
    }

    /// `:2740-2741`: the loop runs again while a state asks for it, and stops
    /// when nothing does.
    #[tokio::test]
    async fn the_driver_loops_while_a_state_asks_to_run_again() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Setup);
        // SETUP -> CONNECT -> RESOLVING, which is pending.
        io.connects.push_back(Ok(ConnectOutcome::Resolving));

        let answer = xfer.run_single(&mut io).await;
        assert_eq!(answer, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::Resolving);

        // A changed multi handle re-runs the loop even when the state did not
        // ask: `multi_ischanged(multi, FALSE)` is the second half of the C's
        // condition.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Resolving);
        io.resolver_checks.push_back(Ok(ResolveStep::Pending));
        io.resolver_checks.push_back(Ok(ResolveStep::Pending));
        io.sched.changed.push_back(false);
        io.sched.changed.push_back(true);
        let answer = xfer.run_single(&mut io).await;
        assert_eq!(answer, Ok(RunSingle::Pending));
        assert_eq!(
            io.sched.assessments, 2,
            "two iterations, because the handle changed"
        );
    }

    /// The whole journey, with every phase answering at once: `INIT` through
    /// `COMPLETED` in one call.
    #[tokio::test]
    async fn a_transfer_runs_from_init_to_completed() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Init);
        io.connects.push_back(Ok(ConnectOutcome::Connected));
        io.recvs.push_back(RecvStep::Eos);
        // The C's scheme does this from inside its own `do_it`; the double has
        // no route to the transfer, so the channel is armed here instead.
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);

        let answer = xfer.run_single(&mut io).await;
        assert_eq!(answer, Ok(RunSingle::Completed(CURLcode::Ok)));
        assert_eq!(
            io.states(),
            vec![
                String::from("-> [SETUP]"),
                String::from("-> [CONNECT]"),
                String::from("-> [PROTOCONNECT]"),
                String::from("-> [DO]"),
                String::from("-> [DID]"),
                String::from("-> [PERFORMING]"),
                String::from("-> [DONE]"),
                String::from("-> [COMPLETED]"),
            ]
        );
        assert_eq!(io.completions, vec![false]);
        assert_eq!(io.data_dones, vec![false]);
        assert!(xfer.req.done);
        assert_eq!(
            proto(|script| script.pollsets),
            0,
            "readiness comes from the reactor, never from descriptor \
             arithmetic"
        );
    }

    /// The same journey with every phase DELAYED: each one answers pending
    /// first, so the transfer needs several entries -- and each entry stops
    /// exactly where the C's `mresult` stops it, which is what the scripts
    /// below encode.
    #[tokio::test]
    async fn a_transfer_runs_from_init_to_completed_one_phase_at_a_time() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Init);

        // INIT -> SETUP -> CONNECT, which hands the name to the resolver.
        // `state_connect` answers `CURLM_OK` for an asynchronous lookup, so this
        // entry stops at RESOLVING without consulting the resolver at all.
        io.connects.push_back(Ok(ConnectOutcome::Resolving));
        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::Resolving);

        // The name is not resolved yet.
        io.resolver_checks.push_back(Ok(ResolveStep::Pending));
        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::Resolving);

        // It resolves, and RESOLVING answers `CURLM_CALL_MULTI_PERFORM`
        // (`lib/multi.c:2262`), so CONNECTING runs in the SAME entry.
        io.resolver_checks.push_back(Ok(ResolveStep::Resolved));
        io.once_resolveds.push_back(Ok(AsyncStep::Pending));
        io.conn_connects.push_back(Ok(AsyncStep::Pending));
        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::Connecting);

        // The socket connects. CONNECTING runs PROTOCONNECT, whose pending
        // answer runs PROTOCONNECTING (`:2568-2570`), which is where this entry
        // stops -- three states in one call.
        io.conn_connects.push_back(Ok(AsyncStep::Complete));
        io.has_connecting = true;
        proto(|script| {
            script.connect_it.push_back(Step::Pending);
            script.connecting.push_back(Step::Pending);
        });
        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::ProtoConnecting);

        // The scheme connects, so DO runs, and its pending answer runs DOING
        // (`:2153-2154`).
        proto(|script| {
            script.connecting.push_back(Step::Done);
            script.do_it.push_back(Step::Pending);
            script.doing.push_back(Step::Pending);
        });
        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::Doing);

        // DOING completes and the connection wants a DO_MORE phase, which is
        // not ready either.
        io.wants_do_more = true;
        proto(|script| {
            script.doing.push_back(Step::Done);
            script.do_more.push_back(Step::Pending);
        });
        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::DoingMore);

        // DO_MORE finishes, so DID hands over to PERFORMING, which has nothing
        // to read yet. The C's scheme arms the channel from inside its own DO
        // phase; the double has no route to the transfer, so it is armed here.
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        proto(|script| script.do_more.push_back(Step::Done));
        io.recvs.push_back(RecvStep::Again);
        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::Performing);

        // The body arrives, and the stream has not ended.
        io.recvs.push_back(RecvStep::Bytes(b"hello".to_vec()));
        io.recvs.push_back(RecvStep::Again);
        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::Performing);

        // The stream ends: PERFORMING -> DONE -> COMPLETED in one entry.
        io.recvs.push_back(RecvStep::Eos);
        assert_eq!(
            xfer.run_single(&mut io).await,
            Ok(RunSingle::Completed(CURLcode::Ok))
        );
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
        assert_eq!(
            io.write_log
                .iter()
                .map(|record| record.bytes.clone())
                .collect::<Vec<_>>(),
            vec![b"hello".to_vec(), Vec::new()],
            "the body, then one EOS"
        );
        assert_eq!(
            proto(|script| script.pollsets),
            0,
            "not one descriptor mask was assembled"
        );
    }

    /// A rate-limited transfer parks in `RATELIMITING` and comes back to
    /// `PERFORMING` when its tokens refill -- through the driver, so the
    /// transition is the one the owner sees.
    #[tokio::test]
    async fn a_rate_limited_transfer_parks_and_resumes_through_the_driver() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        let now = io.req.clock.now();
        let mut limit = RateLimit::new(1_000, 0, now);
        limit.drain(1_000, now);
        *io.req.progress.download_mut().rlimit_mut() = limit;

        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::RateLimiting);
        assert!(io.traced("[RLIMIT] waiting"));
        assert!(io.recv_log.is_empty(), "no I/O while rate limited");

        // Time passes, the bucket refills, and the transfer resumes.
        io.req.clock.advance(Duration::from_secs(2));
        io.recvs.push_back(RecvStep::Eos);
        assert_eq!(
            xfer.run_single(&mut io).await,
            Ok(RunSingle::Completed(CURLcode::Ok))
        );
        assert!(io.traced("[RLIMIT] wait over, continue"));
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
    }

    /// A transfer with no connection capacity parks in `PENDING` and does no
    /// work at all until its owner moves it back to `CONNECT`.
    #[tokio::test]
    async fn a_pending_transfer_waits_for_its_owner() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connect);
        io.connects
            .push_back(Ok(ConnectOutcome::NoConnectionAvailable));

        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::Pending);
        assert_eq!(io.sched.parks, 1);

        // Entered again while still PENDING: nothing happens.
        let before = io.connects.len();
        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::Pending);
        assert_eq!(io.connects.len(), before, "no connection was attempted");

        // The owner grants capacity by moving it back to CONNECT.
        xfer.set_mstate(&mut io, CurlMstate::Connect);
        io.connects.push_back(Ok(ConnectOutcome::Connected));
        assert!(xfer.run_single(&mut io).await.is_ok());
        assert_ne!(xfer.mstate(), CurlMstate::Pending);
    }

    /// `MSGSENT` is terminal: the owner has queued the done message, so the
    /// transfer is not run again.
    #[tokio::test]
    async fn a_message_sent_transfer_does_nothing() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::MsgSent);

        assert_eq!(xfer.run_single(&mut io).await, Ok(RunSingle::Pending));
        assert_eq!(xfer.mstate(), CurlMstate::MsgSent);
        assert!(io.completions.is_empty());
        assert!(io.states().is_empty());
    }

    /// `EXPIRE_100_TIMEOUT` is armed through this very seam, by the `Expect:
    /// 100-continue` client reader in `crate::protocols` -- so the name it
    /// traces is asserted here, where the table lives.
    #[test]
    fn the_expect_100_timer_is_armed_through_the_same_seam() {
        let (_xfer, mut io) = fixture();
        io.scheduler().expire(1_000, ExpireId::Expect100Timeout);
        assert_eq!(io.armed(ExpireId::Expect100Timeout), vec![1_000]);
        assert_eq!(ExpireId::Expect100Timeout.name(), "100_TIMEOUT");
    }

    // ---- 21. the upload half ---------------------------------------------

    /// `sendrecv_ul` (`lib/transfer.c:341-351`): the request body reaches the
    /// wire, and once it is sent the dispatch stops calling the sender.
    #[tokio::test]
    async fn the_upload_dispatch_sends_until_the_body_is_gone() {
        let (mut xfer, mut io) = fixture();
        io.req.client_body.push_back(b"the request body".to_vec());
        xfer.req
            .start(io.request_io())
            .expect("the request restarts");
        xfer.xfer_setup_sendrecv(&mut io, SocketIndex::First, -1);
        io.recvs.push_back(RecvStep::Again);

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert_eq!(
            io.req
                .send_log
                .iter()
                .map(|(offered, _, accepted)| (*offered, *accepted))
                .collect::<Vec<_>>(),
            vec![(16, 16)],
            "the whole body was offered once and accepted"
        );
        assert!(
            xfer.req.done_sending(io.request_io_ref()),
            "the client reader reported the end of the body"
        );

        // A second pass does NOT call the sender again: the C asserts on it and
        // then tests it anyway.
        let before = io.req.send_log.len();
        io.recvs.push_back(RecvStep::Again);
        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert_eq!(io.req.send_log.len(), before);
    }

    /// A body offered in pieces is sent in pieces, and a blocked transport is
    /// simply retried on the next entry.
    #[tokio::test]
    async fn a_blocked_upload_resumes_on_the_next_entry() {
        let (mut xfer, mut io) = fixture();
        io.req.client_body.push_back(b"first".to_vec());
        io.req.client_body.push_back(b"second".to_vec());
        xfer.req
            .start(io.request_io())
            .expect("the request restarts");
        xfer.xfer_setup_send(&mut io, SocketIndex::First);
        io.req.sends.push_back(SendStep::Again);

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert_eq!(
            io.req.send_log.iter().map(|entry| entry.2).sum::<usize>(),
            0,
            "the transport took nothing"
        );
        assert!(!xfer.req.done_sending(io.request_io_ref()));

        assert_eq!(xfer.sendrecv(&mut io).await, Ok(()));
        assert!(
            io.req.send_log.iter().map(|entry| entry.2).sum::<usize>() > 0,
            "the same bytes went out once the transport accepted them"
        );
    }

    // ---- 22. the defaulted seam members ----------------------------------

    /// Every DEFAULTED [`TransferIo`] member answers "not configured", so a
    /// transfer whose owner wires up nothing optional still runs.
    ///
    /// This is a contract, not a formality: `crate::multi` and `crate::easy`
    /// implement the required members and inherit these, and a default that did
    /// anything would silently give every transfer a behaviour its options never
    /// asked for.
    #[test]
    fn the_optional_seam_members_default_to_not_configured() {
        let mut io = BareIo::default();

        // The pretransfer services: none of them is configured, and none of
        // them fails.
        assert!(io.url_from_handle().is_none());
        assert_eq!(io.cookie_loadfiles(), Ok(()));
        io.cookie_run();
        assert!(!io.has_resolve_list());
        assert_eq!(io.load_host_pairs(), Ok(()));
        assert_eq!(io.hsts_loadfiles(), Ok(()));
        assert_eq!(io.hsts_loadcb(), Ok(()));
        assert_eq!(io.wildcard_init(), Ok(()));
        assert_eq!(io.http_neg_init(), HttpNegotiation::default());
        io.priority_clear_state();
        io.netrc_cleanup();

        // The per-transfer hooks.
        assert!(!io.h2_http_1_1_error(), "no HTTP/1.1 downgrade is pending");
        io.bind_upload_source();
        assert!(io.prereq().is_none(), "no pre-request callback is set");

        // The two trace sinks discard, which is what a transfer without
        // `--trace` does.
        io.trace_multi(format_args!("dropped"));
        io.trace_write(format_args!("dropped"));
    }

    /// And a whole transfer runs over that seam: `pretransfer` succeeds and the
    /// journey reaches `COMPLETED` with nothing optional configured.
    #[tokio::test]
    async fn a_transfer_runs_over_the_bare_seam() {
        proto_reset();
        let mut xfer = transfer();
        let mut io = BareIo::default();
        xfer.req.start(io.request_io()).expect("the request starts");
        xfer.set_mstate(&mut io, CurlMstate::Init);
        io.0.connects.push_back(Ok(ConnectOutcome::Connected));
        io.0.recvs.push_back(RecvStep::Eos);
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);

        assert_eq!(
            xfer.run_single(&mut io).await,
            Ok(RunSingle::Completed(CURLcode::Ok))
        );
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
        assert_eq!(
            xfer.state.url.as_deref(),
            Some("http://example.com/"),
            "the URL came from the option, there being no handle"
        );
        assert_eq!(proto(|script| script.pollsets), 0);
    }

    /// `settings()` (`lib/urldata.h`'s `data->set`): the option block, borrowed
    /// for the modules that read a transfer's configuration rather than its
    /// state.
    #[test]
    fn the_settings_are_borrowable() {
        let xfer = transfer();
        assert_eq!(xfer.settings().url.as_deref(), Some("http://example.com/"));
        assert_eq!(xfer.settings().buffer_size, 16_384);
    }

    // ---- 23. the remaining error branches --------------------------------

    /// `:2104-2118`: an FTP wildcard match that is already finished or being
    /// skipped does NOT go on to `DOING` -- it completes and jumps ahead.
    #[cfg(feature = "ftp")]
    #[tokio::test]
    async fn a_finished_wildcard_skips_the_doing_phase() {
        for stage in [WildcardStage::Done, WildcardStage::Skip] {
            let (mut xfer, mut io) = fixture();
            io.scheme = Some(&SCHEME_FTP);
            park(&mut xfer, &mut io, CurlMstate::Do);
            xfer.state.wildcardmatch = true;
            xfer.state.wildcard = stage;
            proto(|script| script.do_it.push_back(Step::Pending));

            let outcome = xfer.state_do(&mut io).await;
            assert_eq!(outcome.step, DriverStep::RunAgain, "{stage:?}");
            assert_eq!(
                xfer.mstate(),
                CurlMstate::Done,
                "with a connection left, DONE still runs"
            );
            assert_eq!(io.completions, vec![false], "{stage:?}");
        }

        // `:2112-2113`: "if there is no connection left, skip the DONE state".
        let (mut xfer, mut io) = fixture();
        io.scheme = Some(&SCHEME_FTP);
        park(&mut xfer, &mut io, CurlMstate::Do);
        xfer.state.wildcardmatch = true;
        xfer.state.wildcard = WildcardStage::Done;
        io.connected = false;
        proto(|script| script.do_it.push_back(Step::Pending));
        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
    }

    /// `multi_do` with an empty `do_it` slot leaves `*done` false and answers
    /// `CURLE_OK` (`:1688-1691`), so the transfer goes to `DOING`.
    #[tokio::test]
    async fn a_scheme_without_an_implementation_never_finishes_its_do_phase() {
        let (mut xfer, mut io) = fixture();
        io.scheme = Some(&SCHEME_STUB);
        park(&mut xfer, &mut io, CurlMstate::Do);

        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.step, DriverStep::RunAgain);
        assert_eq!(outcome.result, CURLcode::Ok);
        assert_eq!(xfer.mstate(), CurlMstate::Doing);
        assert_eq!(proto_calls("do_it"), 0, "there was nothing to call");
    }

    /// A seam that cannot produce a protocol context fails the DO phase with the
    /// context's own code, before the scheme is invoked.
    #[tokio::test]
    async fn a_failing_protocol_context_fails_the_do_phase() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.xfer_ctx_fails = Some(CURLcode::FailedInit);

        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.result, CURLcode::FailedInit);
        assert!(outcome.stream_error);
        assert_eq!(proto_calls("do_it"), 0);
        assert_eq!(io.completions, vec![false]);

        // The same seam failure in the completion is reported by the completion.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.xfer_ctx_fails = Some(CURLcode::FailedInit);
        assert_eq!(
            xfer.complete(&mut io, CURLcode::Ok, false).await,
            CURLcode::FailedInit
        );
        assert_eq!(proto_calls("done"), 0);
    }

    /// `:2150-2155`: a retry decision that fails outright -- "a failure here
    /// pretty much implies an out of memory" -- ends the transfer.
    #[tokio::test]
    async fn a_failing_retry_decision_ends_the_do_phase() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.reused = true;
        // No URL to duplicate, which is the C's out-of-memory case.
        xfer.state.url = None;
        proto(|script| {
            script.do_it.push_back(Step::Fail(CURLcode::SendError));
        });

        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.result, CURLcode::OutOfMemory);
        assert!(outcome.stream_error);
        assert_eq!(io.completions, vec![false]);
        assert!(
            io.follow.resolved.is_empty(),
            "no follow was attempted without a URL"
        );
    }

    /// `:2160-2185`: the two remaining retry outcomes -- no URL to retry, and a
    /// completion whose code is neither success nor the send error being
    /// retried.
    #[tokio::test]
    async fn the_retry_path_reports_what_it_cannot_retry() {
        // A connection that had already delivered a response is not retried, so
        // there is no URL and the error handler takes the connection.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.reused = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        xfer.req.bytecount = 40;
        proto(|script| {
            script.do_it.push_back(Step::Fail(CURLcode::SendError));
        });

        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.result, CURLcode::SendError);
        assert!(outcome.stream_error);
        assert!(io.follow.resolved.is_empty());

        // `:2176-2179`: "done did not return OK or SEND_ERROR".
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.reused = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        proto(|script| {
            script.do_it.push_back(Step::Fail(CURLcode::SendError));
            script.done.push_back(CURLcode::GotNothing);
        });

        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.result, CURLcode::GotNothing);
        assert!(!outcome.stream_error);
        assert!(io.follow.resolved.is_empty());

        // `:2163`: a completion answering the very send error being retried
        // does NOT stop the retry.
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.reused = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        proto(|script| {
            script.do_it.push_back(Step::Fail(CURLcode::SendError));
        });

        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.result, CURLcode::Ok);
        assert_eq!(xfer.mstate(), CurlMstate::Setup);
        assert_eq!(io.follow.resolved[0].1, FollowType::Retry);

        // `:2171-2174`: "Follow failed".
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Do);
        io.reused = true;
        xfer.state.url = Some(String::from("http://example.com/"));
        io.follow.resolve.push_back(ResolvedTarget::Unparsable {
            code: CURLcode::UrlMalformat,
            reason: "Malformed input to a URL function",
        });
        proto(|script| {
            script.do_it.push_back(Step::Fail(CURLcode::SendError));
        });

        let outcome = xfer.state_do(&mut io).await;
        assert_eq!(outcome.result, CURLcode::UrlMalformat);
        assert!(!outcome.stream_error);
        assert_eq!(xfer.mstate(), CurlMstate::Do);
    }

    /// `:1946-1949`: a retry decision that fails while the transfer had NOT
    /// failed reports the decision's own code.
    #[tokio::test]
    async fn a_failing_retry_decision_becomes_the_performing_result() {
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.reused = true;
        xfer.state.url = None;
        io.recvs.push_back(RecvStep::Eos);

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::OutOfMemory);

        // In the HTTP/2 downgrade arm the decision's code is reported too.
        let (mut xfer, mut io) = fixture();
        xfer.xfer_setup_recv(&mut io, SocketIndex::First, -1);
        park(&mut xfer, &mut io, CurlMstate::Performing);
        io.h2_downgrade = true;
        io.reused = true;
        xfer.state.url = None;
        io.recvs.push_back(RecvStep::Fail(CURLcode::Http2Stream));

        let outcome = xfer.state_performing(&mut io).await;
        assert_eq!(outcome.result, CURLcode::OutOfMemory);
        assert!(
            !io.traced("Downgrades to HTTP/1.1"),
            "the downgrade never began"
        );
    }

    /// `:2717-2728`: the second timeout check FIRES when the deadline passes
    /// during the state's own work and this will be the last iteration.
    ///
    /// `Curl_timeleft_ms` is clock-derived, so it can answer "time left" to the
    /// first check and "expired" to the second within one iteration; the scripted
    /// answers reproduce exactly that.
    #[tokio::test]
    async fn the_second_timeout_check_fires_on_the_last_iteration() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        // The first check sees 500 ms left; the connect attempt consumes it; the
        // second check sees the deadline passed.
        io.timeleft_steps.push_back(500);
        io.timeleft_steps.push_back(500);
        io.timeleft = -1;
        io.conn_connects.push_back(Ok(AsyncStep::Pending));

        let answer = xfer.run_single(&mut io).await;
        assert_eq!(
            answer,
            Ok(RunSingle::Completed(CURLcode::OperationTimedout))
        );
        assert!(io.failed_with("Connection timed out after"));
        assert_eq!(
            io.completions,
            vec![true],
            "`multi_handle_timeout`'s completion runs under `if(data->conn)`"
        );
        assert!(
            io.stream_closes.is_empty(),
            "`:1759` closes the stream only past DO, and this is CONNECTING"
        );
        assert_eq!(xfer.mstate(), CurlMstate::Completed);
    }

    /// The same window, but the multi handle changed, so the C defers the
    /// declaration to the next iteration.
    #[tokio::test]
    async fn a_changed_handle_defers_the_second_timeout_check() {
        let (mut xfer, mut io) = fixture();
        park(&mut xfer, &mut io, CurlMstate::Connecting);
        io.timeleft_steps.push_back(500);
        io.timeleft = -1;
        io.conn_connects.push_back(Ok(AsyncStep::Pending));
        io.conn_connects.push_back(Ok(AsyncStep::Pending));
        // A peek at `:2727` sees the change, so the check is skipped; the
        // clearing peek at `:2740` then consumes it and re-runs the loop, where
        // the FIRST check declares the deadline.
        io.sched.changed.push_back(true);

        let answer = xfer.run_single(&mut io).await;
        assert_eq!(
            answer,
            Ok(RunSingle::Completed(CURLcode::OperationTimedout))
        );
        assert_eq!(
            io.req
                .fail
                .iter()
                .filter(|line| line.contains("Connection timed out after"))
                .count(),
            1,
            "declared exactly once"
        );
        assert_eq!(io.completions, vec![true]);
    }
}
