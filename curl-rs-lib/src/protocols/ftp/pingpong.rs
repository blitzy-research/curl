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
//! The FTP request/response cadence -- supersedes `lib/pingpong.c:42-410` with
//! `lib/pingpong.h:36-77`.
//!
//! One command goes out, one multi-line reply comes back, and the reply's last
//! line is recognised by its numeric code. That is the whole of the "ping-pong"
//! conversation, and this file is the engine that runs it: the non-blocking
//! command writer, the line framer that turns a stream of bytes into reply
//! lines, the per-response timeout, and the readiness cadence that drives an
//! FTP state machine forward one reply at a time.
//!
//! Two numeric contracts come from outside this pair of C files and are cited
//! where they are used: the default per-response timeout `RESP_TIMEOUT`
//! (`lib/urldata.h:126-127`) and the buffer ceiling `DYN_PINGPPONG_CMD`
//! (`lib/curlx/dynbuf.h:76`), which is consumed from
//! [`crate::util::dynbuf`] rather than restated here.
//!
//! # Why this is FTP-specific, deliberately
//!
//! The C's own header calls the mechanism *"generic back-and-forth support
//! functions used by FTP, IMAP, POP3, SMTP and whatever more that likes
//! them"*, and `lib/pingpong.h:28-31` compiles it in when any one of those four
//! schemes is enabled. **Three of the four are out of scope.** Specification
//! 0.2.2 excludes SMTP, IMAP and POP3 from implementation -- they are
//! registered for ABI completeness by `crate::protocols::stub` and answer
//! `CURLE_UNSUPPORTED_PROTOCOL` -- so FTP is the only consumer this engine can
//! have, and it lives in the FTP directory rather than in a `lib/`-shaped
//! module of its own.
//!
//! That is a placement decision, not a behavioural one. Nothing here is
//! narrowed to FTP: no reply code is interpreted, no command is composed, and
//! no FTP state is held. Deciding which line ends a reply is exactly the
//! callback [`PingPongOps::end_of_response`] exists for, and it is the FTP
//! module that implements it -- as `ftp_endofresp` does in the C.
//!
//! # The bytes are the specification
//!
//! 257 fixtures name the `ftp` server and 9 name `ftps`, and their
//! `<protocol>` blocks are compared as ONE joined string: every command, every
//! space and every CRLF is part of the expectation. Two consequences shape this
//! file:
//!
//! * **The terminator is owned here and nowhere else.** [`PingPong::sendf`] and
//!   [`PingPong::sendn`] append exactly the two bytes `b"\r\n"`; a caller never
//!   writes them, and a caller that did would put `CRLFCRLF` on the wire.
//! * **A reply line keeps its bytes.** The framer splits on a raw `\n` and the
//!   line it hands on INCLUDES that byte; the `\r` before it is an ordinary
//!   byte of the line, not a terminator to be stripped. Reply lines are byte
//!   slices throughout -- never `str`, never normalised -- because a server may
//!   put anything in a reply and the `CURLINFO_HEADER_IN` trace and the
//!   `CLIENTWRITE_INFO` write both have to see what actually arrived.
//!
//! # Two C function pointers become one small trait
//!
//! `struct pingpong` carries `statemachine` and `endofresp`
//! (`lib/pingpong.h:64-66`), installed through the `PINGPONG_SETUP` macro
//! (`:73-77`). [`PingPongOps`] is the pair, and `ftp/mod.rs` implements it. The
//! state-machine step is asynchronous and returns
//! [`crate::protocols::ProtoFuture`], which is boxed for the reason recorded
//! there: `async fn` in a trait is not dyn-compatible at the declared minimum
//! Rust version, and the callback has to be reachable through `&mut dyn`.
//!
//! The state machine needs the whole world, as `pp->statemachine(data, conn)`
//! does. It receives `&mut PingPong` and the environment seam as separate
//! arguments so that it can drive this engine -- read a reply, send the next
//! command -- without the engine and the FTP state aliasing each other. That is
//! the Rust shape of the C's arrangement, where the state machine reaches `pp`
//! back through `conn->proto.ftpc`, and it is why nothing here holds a pointer
//! to its caller.
//!
//! # The environment is injected, all of it
//!
//! [`PingPongIo`] stands where the C threads `struct Curl_easy *data` and
//! `struct connectdata *conn`. It is a seam and not a successor to the
//! god-struct: it carries the eleven things the ten `Curl_pp_*` functions
//! actually reach for and nothing else. The precedent is
//! [`crate::transfer::TransferIo`], which does the same job for the transfer
//! loop and for the same reason -- specification 0.3.3's pattern P12 requires
//! the clock and the transport to be injected, and without that the coverage
//! this directory is measured at would need a live FTP server.
//!
//! Every reading of the clock in this file goes through
//! [`PingPongIo::clock`], so a test drives the whole cadence with
//! [`crate::util::timeval::TestClock`] and no wall clock is consulted anywhere.
//! The transport methods and the readiness wait have DEFAULT bodies that route
//! through the real [`crate::conn::filters::FilterChain`] and the real
//! [`crate::conn::select`] reactor, so the production wiring lives here rather
//! than being restated by each implementing type, and a test overrides them
//! with a script.
//!
//! # Feature gating
//!
//! None in this file, and that is not an omission. The `ftp` feature gates the
//! declaration of the whole directory -- `#[cfg(feature = "ftp")] pub(crate)
//! mod ftp;` in `crate::protocols` -- so a build with FTP switched off never
//! compiles this module. A second gate here would be redundant and would
//! invite the two spellings to drift.

use core::fmt;

use crate::conn::filters::{CallCtx, FilterChains, SocketIndex};
use crate::conn::select::{
    socket_readable, socket_writable, EasyPollset, PollAction, Socket,
    CURL_SOCKET_BAD,
};
use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::protocols::ProtoFuture;
use crate::trace::{InfoType, Tracer};
use crate::transfer::sendf::ClientWriteFlags;
use crate::util::dynbuf::{DynBuf, DYN_PINGPPONG_CMD};
use crate::util::timediff::TimeDiff;
use crate::util::timeval::{timediff_ms, Clock, CurlTime};

// Pinned numeric contracts

/// The default per-response timeout, in milliseconds --
/// `RESP_TIMEOUT (60 * 1000)` (`lib/urldata.h:126-127`).
///
/// The C comment is *"Default FTP/IMAP etc response timeout in
/// milliseconds"*, and the number is behaviour: it is how long
/// [`PingPong::state_timeout`] waits for one server response when
/// `CURLOPT_SERVER_RESPONSE_TIMEOUT` is unset.
pub(crate) const RESP_TIMEOUT: TimeDiff = 60 * 1000;

/// The size of the stack buffer one transport read fills --
/// `char buffer[900]` (`lib/pingpong.c:255`).
///
/// **This number is control flow, not a tuning parameter.** The outer loop of
/// [`PingPong::readresp`] repeats *"while `gotbytes == sizeof(buffer)`"*
/// (`lib/pingpong.c:343`): a read that filled the buffer exactly is taken as
/// evidence that more is waiting, and any other count ends the loop. Changing
/// 900 changes how many reads a given reply takes, which is observable in the
/// allocation and read-call counts a fixture can measure, so it is reproduced
/// exactly.
const RESP_BUFFER: usize = 900;

/// The two bytes every ping-pong command ends with --
/// `curlx_dyn_addn(&pp->sendbuf, "\r\n", 2)` (`lib/pingpong.c:175`).
///
/// A wire literal, and the reason for the formatting exemption: rustfmt must
/// not be given the chance to wrap or re-spell it, because a reviewer has to be
/// able to read the two escapes and count them. Exactly two bytes, no
/// terminating zero, and appended exactly once per command.
#[rustfmt::skip]
const CRLF: &[u8] = b"\r\n";

/// The wait granularity of a BLOCKING cadence step, in milliseconds --
/// `interval_ms = 1000` with the C's comment *"use 1 second timeout
/// intervals"* (`lib/pingpong.c:87`).
///
/// Clamped down to whatever the response deadline still allows, never up.
const BLOCK_INTERVAL_MS: TimeDiff = 1000;

/// What a short-circuit reports in place of a wait -- the C's `rc = 1`
/// (`lib/pingpong.c:95`, `:98`, `:101`).
///
/// The value is only ever compared against zero, exactly as the C compares
/// `rc`, so it stands for "ready" rather than naming any particular
/// `CURL_CSELECT_*` bit.
const READY_CACHED: u32 = 1;

/// `failf(data, "server response timeout")` (`lib/pingpong.c:82`).
///
/// One constant for both destinations -- the error buffer and the returned
/// error's context -- so the two can never disagree, and so a test can pin the
/// wording against a single source.
const RESPONSE_TIMEOUT_MESSAGE: &str = "server response timeout";

/// `failf(data, "select/poll error")` (`lib/pingpong.c:117`).
const SELECT_ERROR_MESSAGE: &str = "select/poll error";

// The transfer disposition

/// What is to be transferred once the command sequence reaches its data
/// connection -- `curl_pp_transfer` (`lib/pingpong.h:36-40`).
///
/// The discriminants are written out because the C takes them from declaration
/// order and `ftp/mod.rs` compares them; a reordering here would silently
/// change which of the three a comparison matched.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: ftp/mod.rs, and mod tests directly
pub(crate) enum PpTransfer {
    /// `PPTRANSFER_BODY` -- *"yes do transfer a body"*. The default, as the
    /// C's zero-initialised `ftpc->transfer` is.
    #[default]
    Body = 0,
    /// `PPTRANSFER_INFO` -- *"do still go through to get info/headers"*, which
    /// is what `--head` on an FTP URL asks for.
    Info = 1,
    /// `PPTRANSFER_NONE` -- *"do not get anything and do not get info"*.
    None = 2,
}

// What a completed read reports

/// The two out-parameters of `Curl_pp_readresp` (`lib/pingpong.c:249-250`).
///
/// C writes them through `int *code` and `size_t *size` and initialises both to
/// zero on entry (`:257-258`); this is the same pair as a value, initialised the
/// same way by [`Self::PENDING`]. Returning it rather than writing through two
/// pointers is what removes the C's ambiguity about whether the caller may read
/// them after a failure: on [`Err`] there is nothing to read.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PpResponse {
    /// The server's reply code once the final line has been recognised, and
    /// `0` until then -- C's *"0 for errors or not done"*.
    pub(crate) code: i32,
    /// The number of response bytes the completed reply occupied -- C's
    /// `*size = pp->nread_resp`, and `0` while the reply is incomplete.
    pub(crate) size: usize,
}

impl PpResponse {
    /// The entry value: no code and no size, exactly what `Curl_pp_readresp`
    /// writes through its two pointers before it does anything else.
    pub(crate) const PENDING: Self = Self { code: 0, size: 0 };

    /// Whether a complete reply was recognised, which is the C's test of the
    /// returned `code` against zero.
    #[allow(dead_code)] // consumer: ftp/mod.rs, and mod tests directly
    pub(crate) const fn is_complete(self) -> bool {
        self.code != 0
    }
}

// The connection, as this engine reaches it

/// `data->conn` and the clock, borrowed together.
///
/// # Why the pair travels as one value
///
/// Every transport call in the C is `Curl_conn_send`/`Curl_conn_recv` on
/// `data->conn`, and every one of them needs a
/// [`CallCtx`](crate::conn::filters::CallCtx) built over the injected clock.
/// Handing the chains out through one accessor and the clock through another
/// would mean borrowing the implementing type twice at once -- once mutably,
/// once shared -- which the borrow checker refuses. The same composite trick
/// [`crate::transfer::TransferIo::pgrs_check`] uses, and for the same reason.
///
/// The clock is `dyn Clock + Send + Sync` rather than plain `dyn Clock`,
/// matching [`crate::protocols::TransferCtx`]: a protocol's future is `Send` by
/// contract, so anything it can hold across an await must be too.
#[allow(dead_code)] // consumer: ftp/mod.rs, and the default bodies below
pub(crate) struct ConnAccess<'a> {
    /// `conn->cfilter[]` -- both chains, because FTP works on the secondary
    /// one as well.
    chains: &'a mut FilterChains,
    /// `curlx_now()`, injected.
    clock: &'a (dyn Clock + Send + Sync),
}

#[allow(dead_code)] // consumer: ftp/mod.rs, and the default bodies below
impl<'a> ConnAccess<'a> {
    /// Borrows the chains and the clock as one value.
    pub(crate) fn new(
        chains: &'a mut FilterChains,
        clock: &'a (dyn Clock + Send + Sync),
    ) -> Self {
        Self { chains, clock }
    }

    /// A synchronous filter-layer context over the injected clock.
    ///
    /// Deliberately short-lived and untraced: a `CallCtx` is not `Send`, so it
    /// is built inside one call and dropped before the next await, exactly as
    /// [`crate::protocols::TransferCtx::call_ctx`] documents.
    ///
    /// The returned context borrows the CLOCK for `'a` rather than borrowing
    /// `self`, which is what lets the four methods below hold it while they
    /// take the chains mutably. `&'a (dyn Clock + Send + Sync)` is [`Copy`], so
    /// reading the field leaves no borrow of `self` behind, and dropping the
    /// two auto traits on the way to `&dyn Clock` is a widening-free coercion.
    fn call_ctx(&self) -> CallCtx<'a, 'static> {
        CallCtx::new(self.clock)
    }

    /// `Curl_conn_send(data, sockindex, buf, len, FALSE, &written)`
    /// (`lib/cfilters.c:1075-1104`), reached through the first CONNECTED
    /// filter as `Curl_cf_send` does.
    ///
    /// `eos` is always `false` here: the ping-pong layer sends one command and
    /// keeps the connection, and no `Curl_pp_*` caller passes anything else.
    ///
    /// # Errors
    ///
    /// Whatever the chain reports, including [`CURLcode::Again`] when the
    /// write would block and [`CURLcode::FailedInit`] when no filter is
    /// connected -- which is the code the C returns for the same condition.
    fn send(
        &mut self,
        sockindex: SocketIndex,
        buf: &[u8],
    ) -> CurlResult<usize> {
        let mut cx = self.call_ctx();
        self.chains.chain_mut(sockindex).send(&mut cx, buf, false)
    }

    /// `Curl_conn_recv(data, sockindex, buf, len, &nread)`
    /// (`lib/cfilters.c:1106-1131`), reached the same way.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn recv(
        &mut self,
        sockindex: SocketIndex,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        let mut cx = self.call_ctx();
        self.chains.chain_mut(sockindex).recv(&mut cx, buf)
    }

    /// `Curl_conn_data_pending(data, sockindex)` (`lib/cfilters.c:731-749`).
    fn data_pending(&mut self, sockindex: SocketIndex) -> bool {
        let mut cx = self.call_ctx();
        self.chains.chain_mut(sockindex).data_pending(&mut cx)
    }

    /// `conn->sock[sockindex]`, answered by the chain --
    /// `Curl_conn_cf_get_socket` (`lib/cfilters.c:883-890`).
    ///
    /// [`CURL_SOCKET_BAD`] when no filter answers, which is what the C's own
    /// query returns and what [`crate::conn::select::socket_check`] treats as
    /// "no descriptor, just wait".
    fn socket(&mut self, sockindex: SocketIndex) -> Socket {
        let mut cx = self.call_ctx();
        self.chains.chain_mut(sockindex).socket(&mut cx)
    }
}

impl fmt::Debug for ConnAccess<'_> {
    /// Opaque on purpose: this is a bundle of borrows, and printing the chains
    /// would print every filter's state at every trace point.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnAccess").finish()
    }
}

// The environment seam

/// What `struct Curl_easy *data` and `struct connectdata *conn` carried into
/// the ten `Curl_pp_*` functions.
///
/// # Eleven reads, not a god-struct
///
/// The C threads two pointers through every function in `lib/pingpong.c` and
/// between them they carry everything there is. Reproducing that would defeat
/// the decomposition specification 0.1.2 requires, so this trait is exactly the
/// set of things those 413 lines actually touch:
///
/// | This trait | The C it stands for |
/// |------------|---------------------|
/// | [`has_connection`](Self::has_connection) | `if(!conn)` (`:165`) |
/// | [`conn`](Self::conn) | `data->conn`, for the transport |
/// | [`clock`](Self::clock) | `Curl_pgrs_now(data)` (`:59`, `:202`, `:393`) |
/// | [`socket`](Self::socket) | `conn->sock[FIRSTSOCKET]` (`:75`, `:355`) |
/// | [`data_pending`](Self::data_pending) | `Curl_conn_data_pending` (`:94`) |
/// | [`buffered_data_pending`](Self::buffered_data_pending) | the same call at `:99` |
/// | [`send`](Self::send) | `Curl_conn_send` (`:183`, `:376`) |
/// | [`recv`](Self::recv) | `Curl_conn_recv` (`:238`) |
/// | [`wait_ready`](Self::wait_ready) | `Curl_socket_check` (`:103`) |
/// | [`debug`](Self::debug) | `Curl_debug` (`:191`, `:304`) |
/// | [`client_write`](Self::client_write) | `Curl_client_write` (`:310`) |
/// | [`failf`](Self::failf) | `failf` (`:82`, `:117`, `:282`) |
/// | [`add_header_bytes`](Self::add_header_bytes) | `data->req.headerbytecount +=` (`:290`) |
/// | [`server_response_timeout_ms`](Self::server_response_timeout_ms) | `data->set.server_response_timeout` (`:48`) |
/// | [`timeleft_ms`](Self::timeleft_ms) | `Curl_timeleft_ms(data)` (`:61`) |
/// | [`pgrs_check`](Self::pgrs_check) | `Curl_pgrsCheck(data)` (`:111`) |
/// | [`sock_errno`](Self::sock_errno) | `SOCKERRNO` (`:282`) |
///
/// # Five methods have production bodies here
///
/// [`send`](Self::send), [`recv`](Self::recv),
/// [`data_pending`](Self::data_pending),
/// [`socket`](Self::socket) and [`wait_ready`](Self::wait_ready) are DEFAULTED
/// on top of [`conn`](Self::conn), so a type that has a connection gets
/// the real transport and the real reactor without restating either. That is
/// where `Curl_socket_check` is actually replaced: the default
/// [`wait_ready`](Self::wait_ready) awaits
/// [`crate::conn::select::socket_readable`] or
/// [`crate::conn::select::socket_writable`], which are the tokio-reactor
/// successors of the C's `poll` loop and carry their own bound through
/// `tokio::time::timeout`.
///
/// A test overrides those five with a script and never opens a descriptor. That
/// is not a convenience: the readiness path cannot be exercised at all against
/// a real socket without a real server, so the seam is what makes the
/// cadence's branches reachable by a unit test.
///
/// # Why `sock_errno` is asked of the implementing type
///
/// Because reading `errno` is an operating-system call, and this crate names
/// `libc` in exactly one directory (`src/ffi/`). The engine needs the NUMBER
/// only to render it into the C's *"response reading failed (errno: %d)"*
/// message, so it takes it as data.
#[allow(dead_code)] // consumer: ftp/mod.rs, and mod tests directly
pub(crate) trait PingPongIo: fmt::Debug {
    // -- the connection ---------------------------------------------------

    /// `data->conn != NULL` -- whether there is a connection to send on.
    ///
    /// Separate from [`Self::conn`] because [`PingPong::sendf`] needs the
    /// answer without borrowing the chains, and because a test transport has a
    /// connection without having a filter chain.
    fn has_connection(&self) -> bool;

    /// `data->conn` and the injected clock, for the transport defaults.
    ///
    /// [`None`] when there is no connection, or when the owner drives the
    /// transport itself and has overridden all four of
    /// [`send`](Self::send), [`recv`](Self::recv),
    /// [`data_pending`](Self::data_pending) and [`socket`](Self::socket).
    fn conn(&mut self) -> Option<ConnAccess<'_>>;

    /// The injected clock -- the successor of `Curl_pgrs_now(data)`.
    ///
    /// Every timestamp this engine stores comes from here. No wall-clock
    /// constructor is called anywhere in this file.
    fn clock(&self) -> &dyn Clock;

    // -- the transport ----------------------------------------------------

    /// `conn->sock[sockindex]`.
    ///
    /// [`CURL_SOCKET_BAD`] when there is no descriptor, which
    /// [`crate::conn::select::socket_check`] reads as "no sockets, just wait".
    fn socket(&mut self, sockindex: SocketIndex) -> Socket {
        match self.conn() {
            Some(mut access) => access.socket(sockindex),
            None => CURL_SOCKET_BAD,
        }
    }

    /// `Curl_conn_data_pending(data, sockindex)`: are there bytes already
    /// buffered below that a read would return?
    fn data_pending(&mut self, sockindex: SocketIndex) -> bool {
        match self.conn() {
            Some(mut access) => access.data_pending(sockindex),
            None => false,
        }
    }

    /// The same question, asked on the path the C reaches only once a send has
    /// drained -- *"We are receiving and there is data ready in the SSL
    /// library"* (`lib/pingpong.c:99-101`).
    ///
    /// **The C calls the identical function twice**, so this defaults to
    /// [`Self::data_pending`] and a plain implementation behaves as the C
    /// does. It is a method of its own because the two call sites are
    /// semantically distinct -- one asks the connection, the other asks what a
    /// buffering filter is holding -- and specification 0.6.9 makes the
    /// buffered-filter hook part of the destination's connection API. Keeping
    /// them apart means an implementation that CAN distinguish them has
    /// somewhere to say so, without any implementation being obliged to.
    fn buffered_data_pending(&mut self, sockindex: SocketIndex) -> bool {
        self.data_pending(sockindex)
    }

    /// `Curl_conn_send(data, sockindex, buf, buf.len(), FALSE, &written)`,
    /// non-blocking.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] when the write would block -- which the callers
    /// here turn into a successful write of zero bytes, as the C does -- and
    /// whatever else the transport reports.
    fn send(
        &mut self,
        sockindex: SocketIndex,
        buf: &[u8],
    ) -> CurlResult<usize> {
        match self.conn() {
            Some(mut access) => access.send(sockindex, buf),
            None => Err(Error::with_context(
                CURLcode::SendError,
                "send: no connection",
            )),
        }
    }

    /// `Curl_conn_recv(data, sockindex, buf, buf.len(), &nread)`,
    /// non-blocking.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn recv(
        &mut self,
        sockindex: SocketIndex,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        match self.conn() {
            Some(mut access) => access.recv(sockindex, buf),
            None => Err(Error::with_context(
                CURLcode::RecvError,
                "recv: no connection",
            )),
        }
    }

    /// `Curl_socket_check` on one descriptor (`lib/pingpong.c:103-106`): wait
    /// up to `timeout_ms` for `sock` to become ready for `want`.
    ///
    /// `want` is [`PollAction::OUT`] while a command remains half-sent and
    /// [`PollAction::IN`] otherwise, which is exactly the C's
    /// `pp->sendleft ? ... : ...` pair of conditional arguments. The answer is
    /// the C's `CURL_CSELECT_*` bitmask: zero means the wait timed out, any
    /// non-zero value means ready, and an [`Err`] is the C's `rc == -1`.
    ///
    /// # Errors
    ///
    /// Whatever [`crate::conn::select::socket_check`] reports for a failed
    /// wait. [`PingPong::statemach`] turns that into the C's historical
    /// [`CURLcode::OutOfMemory`].
    ///
    /// # Panics
    ///
    /// The default body requires a `tokio` runtime with the time driver
    /// enabled, as everything in [`crate::conn::select`] does.
    fn wait_ready<'a>(
        &'a mut self,
        sock: Socket,
        want: PollAction,
        timeout_ms: TimeDiff,
    ) -> ProtoFuture<'a, u32> {
        // Only the three `Copy` arguments are captured, deliberately: the
        // future must be `Send`, and `&mut Self` would make that a bound on
        // every implementing type rather than only the ones that need it.
        Box::pin(async move {
            if want.contains_out() {
                socket_writable(sock, timeout_ms).await
            } else {
                socket_readable(sock, timeout_ms).await
            }
        })
    }

    // -- diagnostics and the client ----------------------------------------

    /// `Curl_debug(data, kind, ptr, len)`: hand protocol bytes to the trace
    /// destination.
    ///
    /// Called with [`InfoType::HeaderOut`] for the bytes a command actually
    /// put on the wire and [`InfoType::HeaderIn`] for every reply line, both
    /// including their CRLF.
    fn debug(&mut self, kind: InfoType, payload: &[u8]);

    /// `Curl_client_write(data, flags, ptr, len)`: hand reply lines to the
    /// application.
    ///
    /// Always called with [`ClientWriteFlags::INFO`] from here -- reply lines
    /// are *"a kind of headers"*, as `lib/pingpong.c:306-309` puts it.
    ///
    /// # Errors
    ///
    /// Whatever the writer chain reports; [`PingPong::readresp`] propagates it
    /// unchanged and immediately, exactly as the C does.
    fn client_write(
        &mut self,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()>;

    /// `failf(data, ...)`: state why the transfer failed.
    ///
    /// The message reaches `CURLOPT_ERRORBUFFER` and the verbose log. The
    /// callers here also attach the same text to the returned [`Error`], so a
    /// caller that reads neither still sees it.
    fn failf(&mut self, args: fmt::Arguments<'_>);

    /// `data->req.headerbytecount += (unsigned int)gotbytes`
    /// (`lib/pingpong.c:290`).
    ///
    /// The count is what a reply's bytes contribute to
    /// `CURLINFO_HEADER_SIZE`. It is narrowed to `u32` before it arrives
    /// because that is the width the C field has; one read is at most
    /// [`RESP_BUFFER`] bytes, so nothing can be lost.
    fn add_header_bytes(&mut self, count: u32);

    // -- deadlines and cancellation ----------------------------------------

    /// `data->set.server_response_timeout` -- `CURLOPT_SERVER_RESPONSE_TIMEOUT`
    /// in milliseconds, `0` when unset.
    fn server_response_timeout_ms(&self) -> TimeDiff;

    /// `Curl_timeleft_ms(data)`: milliseconds left before the whole transfer's
    /// deadline.
    ///
    /// The C's sign convention is load-bearing and is preserved by the caller:
    /// `0` means *"no timeout applies"* (`lib/pingpong.c:60`) and a negative
    /// value means the deadline has passed.
    fn timeleft_ms(&self) -> TimeDiff;

    /// `Curl_pgrsCheck(data)`: update the progress counters and run the
    /// low-speed and callback-cancellation checks.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OperationTimedout`] for the low-speed limit and
    /// [`CURLcode::AbortedByCallback`] when the progress callback refused,
    /// which [`PingPong::statemach`] propagates ahead of everything else.
    fn pgrs_check(&mut self) -> CurlResult<()>;

    /// `SOCKERRNO` at the moment a read returned zero bytes, for the C's
    /// *"response reading failed (errno: %d)"* message.
    fn sock_errno(&self) -> i32;
}

// The two protocol callbacks

/// The pair of function pointers `PINGPONG_SETUP` installs
/// (`lib/pingpong.h:64-77`).
///
/// `ftp/mod.rs` implements this, as `ftp_statemachine` and `ftp_endofresp` fill
/// the two slots in the C. Nothing else may: the engine has no other consumer
/// in scope, and a second implementation would be a protocol this workspace
/// not build.
///
/// # Why the io type is a parameter
///
/// So that neither side has to choose the other's dispatch. An implementation
/// may name a concrete [`PingPongIo`] and get static dispatch, or name
/// `dyn PingPongIo + Send` and get a trait object; either way
/// `dyn PingPongOps<I>` remains a trait object, which is what
/// [`PingPong::statemach`] and [`PingPong::readresp`] take.
///
/// It also keeps `Send` out of this file entirely.
/// [`crate::protocols::ProtoFuture`] is `Send`, so such a future can
/// only be built over an `I` that is itself `Send`; making that a bound HERE
/// would impose it on the synchronous paths too, where it is not needed and
/// where a `!Send` context -- one carrying a
/// [`Tracer`](crate::trace::Tracer), for instance -- is perfectly usable.
#[allow(dead_code)] // consumer: ftp/mod.rs, and mod tests directly
pub(crate) trait PingPongOps<I>
where
    I: PingPongIo + ?Sized,
{
    /// `pp->statemachine(data, conn)` (`lib/pingpong.h:64`): make one step of
    /// the protocol's own state machine, now that the socket is ready.
    ///
    /// `pp` is the engine the step drives -- it reads the next reply with
    /// [`PingPong::readresp`] and sends the next command with
    /// [`PingPong::sendf`]. It arrives as an argument rather than being
    /// reachable from `self` because the C reaches it through
    /// `conn->proto.ftpc.pp`, and a Rust type that owned it could not
    /// hand it back without aliasing.
    ///
    /// # Errors
    ///
    /// Whatever the protocol reports. [`PingPong::statemach`] returns it
    /// unchanged, as the C's `result = pp->statemachine(...)` does.
    fn statemachine<'a>(
        &'a mut self,
        pp: &'a mut PingPong,
        io: &'a mut I,
    ) -> ProtoFuture<'a, ()>;

    /// `pp->endofresp(data, conn, ptr, len, &code)`
    /// (`lib/pingpong.h:65-66`): is `line` the last line of a reply, and what
    /// is its code?
    ///
    /// `line` is one complete reply line INCLUDING its trailing `\n`, and the
    /// `\r` before it if the server sent one. It is bytes, not text: FTP
    /// replies may carry anything, and `ftp_endofresp` reads only the leading
    /// digits and the fourth byte.
    ///
    /// `code` is the C's `int *code` out-parameter. An implementation writes
    /// reply code through it when it answers `true`, and the engine returns
    /// whatever it holds in [`PpResponse::code`]. Synchronous, because
    /// `ftp_endofresp` performs no I/O.
    fn end_of_response(&mut self, line: &[u8], code: &mut i32) -> bool;
}

// The cadence engine

/// The response cache and the half-sent command -- `struct pingpong`
/// (`lib/pingpong.h:48-71`).
///
/// # The one pointer that could not survive
///
/// C's `char *sendthis` points INTO `sendbuf`, which makes the struct
/// self-referential: moving it invalidates the pointer, and the C gets away
/// with it only because `struct pingpong` lives inside a connection that is
/// never moved. [`Self::sendthis`] is the offset of the same byte instead --
/// `Some(0)` while a command is half-sent, [`None`] when none is -- so the
/// value is movable, the arithmetic is checked, and the flush offset is
/// still exactly the C's `sendthis + sendsize - sendleft`.
///
/// # Two dynbufs, one ceiling
///
/// Both are created with [`DYN_PINGPPONG_CMD`], and the double `P` is the
/// header's own spelling (`lib/curlx/dynbuf.h:76`) rather than a typo here. The
/// ceiling is behaviour: an append that would carry a buffer past it empties
/// the buffer and reports [`CURLcode::TooLarge`], and both the command writer
/// and the reply framer let that code travel out unchanged.
///
/// # Uninitialised is a real state
///
/// The C zero-initialises the struct with its connection and only
/// `Curl_pp_init` makes it usable; `Curl_pp_disconnect` frees the buffers and
/// `memset`s the whole thing back. [`Self::new`] is that zero state,
/// [`Self::init`] is `Curl_pp_init`, and [`Self::disconnect`] is the reset --
/// which is idempotent, because the C's own `if(pp->initialised)` guard makes
/// its second call a no-op too.
///
/// No [`Drop`] implementation, deliberately: the buffers release themselves
/// when this value goes out of scope, which is the entire reason
/// `curlx_dyn_free` had to be called by hand in the C.
#[derive(Debug)]
#[allow(dead_code)] // consumer: ftp/mod.rs, and mod tests directly
pub(crate) struct PingPong {
    /// `nread_resp`: *"number of bytes currently read of a server response"*.
    /// Accumulates across reads and is reported as [`PpResponse::size`] when
    /// the reply completes, then restarts at zero.
    nread_resp: usize,
    /// `sendthis`, as an offset into [`Self::sendbuf`]. See the type's
    /// documentation.
    sendthis: Option<usize>,
    /// `sendleft`: *"number of bytes left to send from the sendthis buffer"*.
    sendleft: usize,
    /// `sendsize`: *"total size of the sendthis buffer"*.
    sendsize: usize,
    /// `response`: set from the injected clock *"when a command has been sent
    /// off, used to time-out response reading"*.
    response: CurlTime,
    /// `sendbuf`: the command being sent, terminator included.
    sendbuf: DynBuf,
    /// `recvbuf`: everything received of the current reply that has not been
    /// consumed, with the most recent final line kept at the front for the
    /// protocol's own parser.
    recvbuf: DynBuf,
    /// `overflow`: *"number of bytes left after a final response line"*.
    overflow: usize,
    /// `nfinal`: *"number of bytes in the final response line, which after a
    /// match is first in the receive buffer"*.
    nfinal: usize,
    /// `BIT(initialised)`.
    initialised: bool,
    /// `BIT(pending_resp)`: *"set TRUE when a server response is pending or in
    /// progress, and is cleared once the last response is read"*.
    pending_resp: bool,
}

impl Default for PingPong {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // consumer: ftp/mod.rs, and mod tests directly
impl PingPong {
    /// The zero state, before [`Self::init`] -- C's zero-initialised
    /// `struct pingpong`.
    ///
    /// The two buffers already carry their ceiling, because a [`DynBuf`] holds
    /// no allocation until something is appended: constructing them here costs
    /// nothing and removes the [`Option`] that a "not yet created" buffer would
    /// otherwise need at every access.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            nread_resp: 0,
            sendthis: None,
            sendleft: 0,
            sendsize: 0,
            response: CurlTime::ZERO,
            sendbuf: DynBuf::new(DYN_PINGPPONG_CMD),
            recvbuf: DynBuf::new(DYN_PINGPPONG_CMD),
            overflow: 0,
            nfinal: 0,
            initialised: false,
            pending_resp: false,
        }
    }

    // -- state the protocol reads ------------------------------------------

    /// `curlx_dyn_ptr(&pp->recvbuf)` with `curlx_dyn_len(&pp->recvbuf)`.
    ///
    /// The FTP parser reads the reply out of here directly -- `lib/ftp.c:1927`
    /// and `:2419` both index past the three-digit code -- so the bytes are
    /// exposed rather than copied out. While [`Self::nfinal`] is non-zero the
    /// final line is the FIRST `nfinal` bytes of this slice, and anything after
    /// it is the [`Self::overflow`].
    pub(crate) fn recvbuf(&self) -> &[u8] {
        self.recvbuf.as_slice()
    }

    /// `pp->overflow`.
    pub(crate) const fn overflow(&self) -> usize {
        self.overflow
    }

    /// `pp->nfinal`.
    pub(crate) const fn nfinal(&self) -> usize {
        self.nfinal
    }

    /// `pp->sendleft`.
    pub(crate) const fn sendleft(&self) -> usize {
        self.sendleft
    }

    /// `pp->sendsize`.
    pub(crate) const fn sendsize(&self) -> usize {
        self.sendsize
    }

    /// `pp->sendthis`, as the offset described on the type.
    pub(crate) const fn sendthis(&self) -> Option<usize> {
        self.sendthis
    }

    /// `pp->nread_resp`.
    pub(crate) const fn nread_resp(&self) -> usize {
        self.nread_resp
    }

    /// `pp->pending_resp`.
    pub(crate) const fn pending_resp(&self) -> bool {
        self.pending_resp
    }

    /// Writes `pp->pending_resp`.
    ///
    /// The protocol layer clears it directly in one place -- `lib/ftp.c:732`,
    /// where `getftpresponse` has finished reading a complete reply -- so the
    /// field is writable rather than private to this engine.
    pub(crate) fn set_pending_resp(&mut self, pending: bool) {
        self.pending_resp = pending;
    }

    /// `pp->response`, the instant the last command was fully sent.
    pub(crate) const fn response(&self) -> CurlTime {
        self.response
    }

    /// `pp->initialised`.
    pub(crate) const fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Forces the retained-send trio into a state the public surface cannot
    /// produce, for the tests that cover [`Self::flushsend`]'s defensive arms.
    ///
    /// `#[cfg(test)]` and therefore absent from the shipped artifact. It exists
    /// because those arms are otherwise unreachable BY CONSTRUCTION -- every
    /// mutation of the three fields goes through this file, and each one leaves
    /// them consistent -- and a guard nobody can reach is a guard nobody can
    /// test either. The C has no counterpart because it has no guard: it
    /// dereferences `pp->sendthis` and subtracts, whatever the three fields
    /// hold.
    #[cfg(test)]
    fn force_retained_send(
        &mut self,
        sendthis: Option<usize>,
        sendsize: usize,
        sendleft: usize,
    ) {
        self.sendthis = sendthis;
        self.sendsize = sendsize;
        self.sendleft = sendleft;
    }

    // -- initialisation ----------------------------------------------------

    /// `Curl_pp_init(pp, pnow)` (`lib/pingpong.c:129-138`): prepare to read a
    /// fresh response.
    ///
    /// `pnow` is the C's `const struct curltime *pnow`, and it is an ARGUMENT
    /// rather than a clock reading taken here: the caller has just read the
    /// clock for its own purposes and the C hands that same instant on, so
    /// taking a second reading would make the response deadline start a
    /// hair later than the C's does.
    ///
    /// # Panics
    ///
    /// In a debug build only, on a second initialisation -- the C's
    /// `DEBUGASSERT(!pp->initialised)` (`:131`). A release build re-initialises,
    /// which is what the C's compiled-out assertion leaves behind and is
    /// harmless: both buffers are replaced by empty ones.
    pub(crate) fn init(&mut self, pnow: CurlTime) {
        debug_assert!(
            !self.initialised,
            "Curl_pp_init on an already initialised pingpong"
        );
        self.nread_resp = 0;
        // `pp->response = *pnow` -- *"start response time-out"*.
        self.response = pnow;
        self.pending_resp = true;
        self.sendbuf = DynBuf::new(DYN_PINGPPONG_CMD);
        self.recvbuf = DynBuf::new(DYN_PINGPPONG_CMD);
        self.initialised = true;
    }

    /// `Curl_pp_disconnect(pp)` (`lib/pingpong.c:398-406`): release the buffers
    /// and return to the zero state.
    ///
    /// Guarded by `initialised` exactly as the C is, which makes a second call
    /// a no-op rather than a double free. The C's `memset(pp, 0, sizeof(*pp))`
    /// becomes a field-by-field reset: the two buffers are released with
    /// [`DynBuf::free`], leaving them reusable, and every scalar returns to its
    /// [`Self::new`] value. Nothing simulates clearing memory that Rust owns.
    ///
    /// # Errors
    ///
    /// Never. The signature returns a result because the C's does, and because
    /// the protocol's own disconnect step returns one and forwards this.
    pub(crate) fn disconnect(&mut self) -> CurlResult<()> {
        if self.initialised {
            self.sendbuf.free();
            self.recvbuf.free();
            self.nread_resp = 0;
            self.sendthis = None;
            self.sendleft = 0;
            self.sendsize = 0;
            self.response = CurlTime::ZERO;
            self.overflow = 0;
            self.nfinal = 0;
            self.initialised = false;
            self.pending_resp = false;
        }
        Ok(())
    }

    // -- deadlines ---------------------------------------------------------

    /// `Curl_pp_state_timeout(data, pp)` (`lib/pingpong.c:44-65`): how many
    /// milliseconds are left for the response being waited on.
    ///
    /// Zero or negative means the deadline has already passed, which is the
    /// C's own contract: *"Returns timeout in ms. 0 or negative number means
    /// the timeout has already triggered"*.
    ///
    /// # Which deadline governs
    ///
    /// `CURLOPT_SERVER_RESPONSE_TIMEOUT` governs ONE server response, not the
    /// time since the connection was made -- that is what makes
    /// [`Self::response`] the origin here rather than the transfer's start.
    /// The C's comment says so explicitly (`:51-54`), and the distinction is
    /// observable: a long download whose control connection answers promptly
    /// must not trip a response timeout.
    ///
    /// The transfer's own deadline still wins when it is nearer, and a
    /// [`PingPongIo::timeleft_ms`] of zero means *"no timeout applies"* rather
    /// than "no time left" (`:60`) -- which is why the comparison tests it
    /// against zero first.
    pub(crate) fn state_timeout<I>(&self, io: &I) -> TimeDiff
    where
        I: PingPongIo + ?Sized,
    {
        // `data->set.server_response_timeout ? ... : RESP_TIMEOUT` (`:48-49`).
        let configured = io.server_response_timeout_ms();
        let response_time = if configured == 0 {
            RESP_TIMEOUT
        } else {
            configured
        };

        // `response_time - curlx_ptimediff_ms(Curl_pgrs_now(data),
        // &pp->response)` (`:58-59`). Saturating rather than wrapping: the
        // difference is a `timediff_t` that saturates at its own extremes, and
        // a wrapped subtraction here would turn a very stale timestamp into a
        // very large positive budget -- the one arithmetic mistake that would
        // hang a transfer instead of failing it.
        let elapsed = timediff_ms(io.clock().now(), self.response);
        let timeout_ms = response_time.saturating_sub(elapsed);

        // `xfer_timeout_ms = Curl_timeleft_ms(data); if(xfer_timeout_ms &&
        // (xfer_timeout_ms < timeout_ms)) return xfer_timeout_ms;` (`:61-63`).
        let xfer_timeout_ms = io.timeleft_ms();
        if xfer_timeout_ms != 0 && xfer_timeout_ms < timeout_ms {
            return xfer_timeout_ms;
        }
        timeout_ms
    }

    /// `Curl_pp_needs_flush(data, pp)` (`lib/pingpong.c:359-364`): is part of a
    /// command still unsent?
    pub(crate) const fn needs_flush(&self) -> bool {
        self.sendleft > 0
    }

    /// `Curl_pp_moredata(pp)` (`lib/pingpong.c:408-411`): is there cached data
    /// that a read would return without blocking?
    ///
    /// The `>` is exact: with `nfinal` bytes cached and nothing after them, the
    /// buffer holds only the final line the protocol has already been shown, so
    /// there is nothing MORE.
    pub(crate) fn moredata(&self) -> bool {
        self.sendleft == 0 && self.recvbuf.len() > self.nfinal
    }

    // -- readiness ---------------------------------------------------------

    /// `Curl_pp_pollset(data, pp, ps)` (`lib/pingpong.c:350-357`): register
    /// what the control connection is waiting for.
    ///
    /// One socket and one direction: writing while a command is half-sent,
    /// reading otherwise. Nothing is ever REMOVED, matching the C's `0` for its
    /// remove mask, and [`EasyPollset::change`] keeps insertion order -- a
    /// pollset entry never moves because another was dropped.
    ///
    /// `trc` is the tracer, when the caller has one. The protocol's four
    /// pollset hooks are handed no tracer by
    /// [`crate::protocols::TransferCtx`], so they pass [`None`]; the parameter
    /// exists because the C's `Curl_pollset_change` takes `data` and emits its
    /// capacity-growth line through it, and losing that line silently would be
    /// worse than accepting an argument that is usually `None`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for a socket that is not a descriptor
    /// and [`CURLcode::OutOfMemory`] if the pollset cannot grow -- both exactly
    /// what the C's `Curl_pollset_change` returns.
    pub(crate) fn pollset<I>(
        &self,
        io: &mut I,
        ps: &mut EasyPollset,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()>
    where
        I: PingPongIo + ?Sized,
    {
        // `int flags = pp->sendleft ? CURL_POLL_OUT : CURL_POLL_IN;` (`:354`).
        let flags = if self.sendleft == 0 {
            PollAction::IN
        } else {
            PollAction::OUT
        };
        let sock = io.socket(SocketIndex::First);
        ps.change(sock, flags, PollAction::NONE, trc)
    }

    /// `Curl_pp_statemach(data, pp, block, disconnecting)`
    /// (`lib/pingpong.c:70-126`): wait for the control connection, then let the
    /// protocol take one step.
    ///
    /// # The five outcomes, all preserved
    ///
    /// | Condition | Result |
    /// |-----------|--------|
    /// | the response deadline has passed | *"server response timeout"* and [`CURLcode::OperationTimedout`] |
    /// | blocking, and progress reports a failure | that failure, ahead of everything else |
    /// | the wait itself failed | *"select/poll error"* and [`CURLcode::OutOfMemory`] |
    /// | ready | whatever [`PingPongOps::statemachine`] reports |
    /// | not ready | [`CURLcode::OperationTimedout`] while disconnecting, otherwise success |
    ///
    /// **The third row is not a mistake being copied.** A failed `poll` reports
    /// `CURLE_OUT_OF_MEMORY` in curl 8.x (`:117-118`), and an application
    /// comparing the code against that constant cannot be told the library has
    /// since decided it meant something else. It is transcribed as found.
    ///
    /// The last row is why `disconnecting` exists: during a `QUIT` exchange a
    /// silent server has to end the wait, whereas during a transfer it merely
    /// means "come back later", which is a success with nothing done.
    ///
    /// # Three short-circuits before any waiting
    ///
    /// Cached bytes make a wait pointless, and the C tests three things before
    /// reaching `Curl_socket_check` (`:94-101`): the connection has data
    /// pending; [`Self::overflow`] is non-zero, so a complete line is already
    /// in the receive buffer; or nothing remains to send and a buffering filter
    /// below is holding bytes. The third is
    /// [`PingPongIo::buffered_data_pending`], which defaults to the second's
    /// question because the C asks the identical one twice; see that method for
    /// why the two are nevertheless separate.
    ///
    /// # Errors
    ///
    /// As the table above.
    ///
    /// # Panics
    ///
    /// Only through the default [`PingPongIo::wait_ready`], which needs a
    /// `tokio` runtime with the time driver enabled. A test that scripts
    /// readiness needs no runtime at all.
    pub(crate) async fn statemach<I, O>(
        &mut self,
        io: &mut I,
        ops: &mut O,
        block: bool,
        disconnecting: bool,
    ) -> CurlResult<()>
    where
        I: PingPongIo + ?Sized,
        O: PingPongOps<I> + ?Sized,
    {
        // `timediff_t timeout_ms = Curl_pp_state_timeout(data, pp);` (`:78`).
        let timeout_ms = self.state_timeout(io);
        if timeout_ms <= 0 {
            // `failf(data, "server response timeout");` (`:82`).
            io.failf(format_args!("{RESPONSE_TIMEOUT_MESSAGE}"));
            return Err(Error::with_context(
                CURLcode::OperationTimedout,
                RESPONSE_TIMEOUT_MESSAGE,
            ));
        }

        // `if(block) { interval_ms = 1000; if(timeout_ms < interval_ms)
        // interval_ms = timeout_ms; } else interval_ms = 0;` (`:86-92`).
        let interval_ms = if block {
            timeout_ms.min(BLOCK_INTERVAL_MS)
        } else {
            0
        };

        let ready = if io.data_pending(SocketIndex::First)
            || self.overflow != 0
            || (self.sendleft == 0
                && io.buffered_data_pending(SocketIndex::First))
        {
            // All three of the C's short-circuits set `rc = 1` (`:94-101`).
            Ok(READY_CACHED)
        } else {
            // The socket is fetched HERE rather than at the top of the
            // function, where the C reads it. The C's read is an array access
            // with no observable effect; this one is a filter-chain query that
            // a tracing build would record, so it is issued only where its
            // value is actually used.
            let sock = io.socket(SocketIndex::First);
            let want = if self.sendleft == 0 {
                PollAction::IN
            } else {
                PollAction::OUT
            };
            io.wait_ready(sock, want, interval_ms).await
        };

        // `if(block) { result = Curl_pgrsCheck(data); if(result) return
        // result; }` (`:109-114`). Ahead of the readiness verdict, so a
        // cancelled transfer reports the cancellation rather than a stale
        // wait error.
        if block {
            io.pgrs_check()?;
        }

        match ready {
            // `if(rc == -1) { failf(data, "select/poll error"); result =
            // CURLE_OUT_OF_MEMORY; }` (`:116-119`).
            Err(_) => {
                io.failf(format_args!("{SELECT_ERROR_MESSAGE}"));
                Err(Error::with_context(
                    CURLcode::OutOfMemory,
                    SELECT_ERROR_MESSAGE,
                ))
            }
            // `else if(rc) result = pp->statemachine(data, data->conn);`
            // (`:120-121`).
            Ok(bits) if bits != 0 => {
                ops.statemachine(self, io).await.map_err(Error::from)
            }
            // `else if(disconnecting) return CURLE_OPERATION_TIMEDOUT;`
            // (`:122-123`) -- with no message, exactly as the C emits none.
            Ok(_) if disconnecting => {
                Err(Error::new(CURLcode::OperationTimedout))
            }
            // Nothing happened and nothing was waiting on it: `result` is
            // still `CURLE_OK` when the C falls out of the chain (`:79`,
            // `:125`).
            Ok(_) => Ok(()),
        }
    }

    // -- sending -----------------------------------------------------------

    /// `Curl_pp_sendf(data, pp, fmt, ...)` and `Curl_pp_vsendf(data, pp, fmt,
    /// args)` in one (`lib/pingpong.c:140-230`): format a command and start
    /// sending it.
    ///
    /// The C pair exists only because C has no way to forward varargs without
    /// a second entry point; [`core::fmt::Arguments`] needs no such split, so
    /// the two collapse into this. `curlx_dyn_vaddf` becomes
    /// [`DynBuf::addf`], which is the same ceiling-checked sink.
    ///
    /// **The caller supplies the command and NOT its terminator.** The C says
    /// so twice -- *"the string should not have any CRLF appended, as this
    /// function will append the necessary things itself"* -- and the two bytes
    /// are appended here, exactly once.
    ///
    /// ```text
    /// pp.sendf(io, format_args!("USER {}", user))?;   // -> b"USER anon\r\n"
    /// ```
    ///
    /// Formatting goes through [`core::fmt`], which produces UTF-8. Where a
    /// command carries bytes that are not text -- an FTP path is whatever the
    /// URL held -- use [`Self::sendn`], which is byte-transparent as the C's
    /// `%s` on a `char *` is.
    ///
    /// # Errors
    ///
    /// As [`Self::sendn`].
    pub(crate) fn sendf<I>(
        &mut self,
        io: &mut I,
        args: fmt::Arguments<'_>,
    ) -> CurlResult<()>
    where
        I: PingPongIo + ?Sized,
    {
        self.send_command(io, |buf| buf.addf(args))
    }

    /// The byte-exact form of [`Self::sendf`]: send `command` followed by the
    /// terminator, with no formatting and no interpretation.
    ///
    /// This is what `Curl_pp_sendf(data, pp, "%s", cmd)` is in the C -- a
    /// spelling `lib/ftp.c` uses at eleven call sites, including
    /// `Curl_pp_sendf(data, &ftpc->pp, "%s", "PASV")` and the `--quote`
    /// commands, whose bytes come from the application. The C's `%s` copies
    /// bytes; Rust's [`core::fmt::Display`] would require them to be UTF-8, so
    /// the byte path is a method rather than a formatting argument.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::SendError`] when there is no connection -- the C's
    ///   `if(!conn) return CURLE_SEND_ERROR` -- and when a command is already
    ///   half-sent, which the C catches with three `DEBUGASSERT`s that a
    ///   release build compiles out.
    /// * [`CURLcode::TooLarge`] or [`CURLcode::OutOfMemory`] from the command
    ///   buffer, whose ceiling is [`DYN_PINGPPONG_CMD`].
    /// * Whatever the transport reports, except [`CURLcode::Again`], which is
    ///   a successful send of nothing.
    pub(crate) fn sendn<I>(
        &mut self,
        io: &mut I,
        command: &[u8],
    ) -> CurlResult<()>
    where
        I: PingPongIo + ?Sized,
    {
        self.send_command(io, |buf| buf.addn(command))
    }

    /// The body of [`Self::sendf`] and [`Self::sendn`], which differ only in
    /// how the command reaches the buffer.
    ///
    /// `compose` is `curlx_dyn_vaddf(&pp->sendbuf, fmt, args)`
    /// (`lib/pingpong.c:170`) and nothing more: it appends the command WITHOUT
    /// its terminator to an already-reset buffer, and reports the dynbuf's own
    /// code if it cannot.
    fn send_command<I, F>(&mut self, io: &mut I, compose: F) -> CurlResult<()>
    where
        I: PingPongIo + ?Sized,
        F: FnOnce(&mut DynBuf) -> CodeResult<()>,
    {
        // `DEBUGASSERT(pp->sendleft == 0); DEBUGASSERT(pp->sendsize == 0);
        // DEBUGASSERT(pp->sendthis == NULL);` (`:161-163`). Debug-asserted as
        // the C does AND checked in every build, because overwriting the buffer
        // while a command is half-sent would put a spliced command on the wire
        // -- a wire-visible defect, not merely a caller mistake.
        debug_assert!(
            self.sendleft == 0 && self.sendsize == 0 && self.sendthis.is_none(),
            "a ping-pong command is already half sent"
        );
        // Unreachable in a build that HAS the assertion above, which is why
        // coverage reports these four lines as unrun: the two guards test the
        // same condition and the debug one stops first. It is the release
        // build's only protection, and
        // `a_second_command_while_one_is_half_sent_is_refused` asserts both
        // shapes so that neither build loses the check.
        if self.sendleft != 0 || self.sendsize != 0 || self.sendthis.is_some() {
            return Err(Error::with_context(
                CURLcode::SendError,
                "a ping-pong command is already half sent",
            ));
        }

        // `if(!conn) return CURLE_SEND_ERROR;` (`:165-167`).
        if !io.has_connection() {
            return Err(Error::with_context(
                CURLcode::SendError,
                "cannot send a command without a connection",
            ));
        }

        // `curlx_dyn_reset(&pp->sendbuf);` (`:169`), then the command, then the
        // terminator (`:174-177`). Every failure travels out as the dynbuf's
        // own code, which is what the C's two `if(result) return result` pairs
        // do.
        self.sendbuf.reset();
        compose(&mut self.sendbuf).map_err(Error::from)?;
        self.sendbuf.addn(CRLF).map_err(Error::from)?;

        // `pp->pending_resp = TRUE;` (`:179`) -- BEFORE the write, so a write
        // that blocks still leaves a response expected.
        self.pending_resp = true;

        let write_len = self.sendbuf.len();
        // `Curl_conn_send(data, FIRSTSOCKET, s, write_len, FALSE,
        // &bytes_written)` (`:183-184`).
        let written = match io.send(SocketIndex::First, self.sendbuf.as_slice())
        {
            Ok(written) => written,
            // `if(result == CURLE_AGAIN) bytes_written = 0;` (`:185-187`).
            Err(error) if error.code() == CURLcode::Again => 0,
            // `else if(result) return result;` (`:188-189`).
            Err(error) => return Err(error),
        };
        // A transport cannot have written more than it was offered. The C would
        // carry the impossible number into its bookkeeping and underflow
        // `sendleft`; this reports it instead of slicing out of bounds.
        let sent =
            match self.sendbuf.as_slice().get(..written) {
                Some(sent) => sent,
                None => return Err(Error::with_context(
                    CURLcode::SendError,
                    "the transport reported writing more than it was offered",
                )),
            };

        // `Curl_debug(data, CURLINFO_HEADER_OUT, s, bytes_written);` (`:191`):
        // the bytes that ACTUALLY went out, which on a short write is a prefix
        // of the command and not the whole of it.
        io.debug(InfoType::HeaderOut, sent);

        if written == write_len {
            // `pp->sendthis = NULL; pp->sendleft = pp->sendsize = 0;
            // pp->response = *Curl_pgrs_now(data);` (`:200-202`). The restamp
            // happens ONLY here: a command that is still going out has not
            // started its response deadline.
            self.sendthis = None;
            self.sendleft = 0;
            self.sendsize = 0;
            self.response = io.clock().now();
        } else {
            // `pp->sendthis = s; pp->sendsize = write_len; pp->sendleft =
            // write_len - bytes_written;` (`:195-197`). The buffer is retained
            // as it stands, so the offset of the first unsent byte is `0 +
            // sendsize - sendleft`.
            self.sendthis = Some(0);
            self.sendsize = write_len;
            self.sendleft = write_len.saturating_sub(written);
        }

        Ok(())
    }

    /// `Curl_pp_flushsend(data, pp)` (`lib/pingpong.c:366-396`): push out
    /// whatever is left of a half-sent command.
    ///
    /// The offset is the C's `pp->sendthis + pp->sendsize - pp->sendleft`
    /// (`:377`) with the pointer replaced by an index, and every step of that
    /// arithmetic is checked: an offset that could not be formed, or a range
    /// the buffer does not cover, is reported rather than sliced.
    ///
    /// **No `CURLINFO_HEADER_OUT` is emitted here**, and that is the C's
    /// behaviour rather than an omission: `Curl_pp_flushsend` makes no
    /// `Curl_debug` call, so the tail of a short-written command never appears
    /// in a trace. Adding it would change `--verbose` output that fixtures
    /// compare.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendError`] if the retained state is inconsistent -- no
    /// command held while bytes remain, or a transport claiming to have written
    /// more than it was given -- and whatever the transport reports.
    /// [`CURLcode::Again`] is a successful write of nothing, as the C makes it.
    pub(crate) fn flushsend<I>(&mut self, io: &mut I) -> CurlResult<()>
    where
        I: PingPongIo + ?Sized,
    {
        // `if(!Curl_pp_needs_flush(data, pp)) return CURLE_OK;` (`:373-374`).
        if !self.needs_flush() {
            return Ok(());
        }

        let Some(start) = self.sendthis else {
            return Err(Error::with_context(
                CURLcode::SendError,
                "bytes remain to be sent but no command is held",
            ));
        };
        let range = start
            .checked_add(self.sendsize)
            .and_then(|end| end.checked_sub(self.sendleft))
            .and_then(|offset| {
                offset.checked_add(self.sendleft).map(|end| offset..end)
            });
        let Some(range) = range else {
            return Err(Error::with_context(
                CURLcode::SendError,
                "the retained command offset does not fit an index",
            ));
        };
        let Some(unsent) = self.sendbuf.as_slice().get(range) else {
            return Err(Error::with_context(
                CURLcode::SendError,
                "the retained command offset is outside the command buffer",
            ));
        };

        // `Curl_conn_send(data, FIRSTSOCKET, pp->sendthis + pp->sendsize -
        // pp->sendleft, pp->sendleft, FALSE, &written)` (`:376-378`).
        let written = match io.send(SocketIndex::First, unsent) {
            Ok(written) => written,
            // `if(result == CURLE_AGAIN) { result = CURLE_OK; written = 0; }`
            // (`:379-382`).
            Err(error) if error.code() == CURLcode::Again => 0,
            Err(error) => return Err(error),
        };
        if written > self.sendleft {
            return Err(Error::with_context(
                CURLcode::SendError,
                "the transport reported writing more than it was offered",
            ));
        }

        if written == self.sendleft {
            // `pp->sendthis = NULL; pp->sendleft = pp->sendsize = 0;
            // pp->response = *Curl_pgrs_now(data);` (`:391-393`).
            self.sendthis = None;
            self.sendleft = 0;
            self.sendsize = 0;
            self.response = io.clock().now();
        } else {
            // `pp->sendleft -= written;` (`:388`) -- and ONLY that: the offset
            // moves because `sendleft` shrank, so `sendthis` and `sendsize`
            // are deliberately left alone.
            self.sendleft = self.sendleft.saturating_sub(written);
        }
        Ok(())
    }

    // -- receiving ---------------------------------------------------------

    /// `Curl_pp_readresp(data, sockindex, pp, &code, &size)`
    /// (`lib/pingpong.c:241-348`): read a piece of a server response.
    ///
    /// Returns [`PpResponse::PENDING`] until a final line is recognised, then
    /// the reply's code and the number of bytes it took. It never blocks: a
    /// transport that would block is a successful read of nothing, and the
    /// caller comes back when [`Self::statemach`] says the socket is ready.
    ///
    /// # The two loops
    ///
    /// The outer loop reads, and repeats only *"while `gotbytes ==
    /// sizeof(buffer)`"* (`:343`) -- a read that exactly filled
    /// [`RESP_BUFFER`] is the C's evidence that more may be waiting, and any
    /// shorter read ends it. The inner loop frames whatever the receive buffer
    /// now holds into lines. Recognising a final line leaves BOTH, which is
    /// what the C's `gotbytes = 0; break;` pair achieves.
    ///
    /// # Framing is on the LF alone
    ///
    /// *"a newline is CRLF in pp-talk, so the CR is ignored as the line is not
    /// really terminated until the LF comes"* (`:299-300`). The line handed on
    /// is `nl - line + 1` bytes long, so it INCLUDES the LF, and a CR before it
    /// is an ordinary byte of the line. Nothing is trimmed, nothing is split on
    /// a `str` boundary, and nothing assumes the bytes are text.
    ///
    /// # What the final line leaves behind
    ///
    /// The final line is deliberately NOT consumed. It stays at the front of
    /// the receive buffer for the protocol's own parser -- `lib/ftp.c` reads
    /// the code and the text straight out of `pp->recvbuf` -- with
    /// [`Self::nfinal`] holding its length and [`Self::overflow`] counting
    /// whatever arrived after it. The NEXT call is what discards it, at the top
    /// of its first iteration.
    ///
    /// # `pending_resp` survives an early return
    ///
    /// It is cleared at the normal exit only (`:345`). A would-block and every
    /// error leave it exactly as it was, because a response IS still pending in
    /// both cases -- the C's early `return`s bypass the assignment, and so do
    /// these.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::RecvError`] with *"response reading failed (errno: %d)"*
    ///   when the transport reports zero bytes, which is a closed connection.
    /// * [`CURLcode::TooLarge`] or [`CURLcode::OutOfMemory`] from the receive
    ///   buffer, whose ceiling is [`DYN_PINGPPONG_CMD`].
    /// * Whatever [`PingPongIo::client_write`] reports, immediately and
    ///   unchanged: a paused or refusing application stops the framing where it
    ///   stands.
    /// * Whatever the transport reports, except [`CURLcode::Again`].
    pub(crate) fn readresp<I, O>(
        &mut self,
        io: &mut I,
        ops: &mut O,
        sockindex: SocketIndex,
    ) -> CurlResult<PpResponse>
    where
        I: PingPongIo + ?Sized,
        O: PingPongOps<I> + ?Sized,
    {
        // `*code = 0; *size = 0;` (`:257-258`) -- *"0 for errors or not done"*.
        let mut outcome = PpResponse::PENDING;
        // `char buffer[900];` (`:255`), on the stack as the C's is.
        let mut buffer = [0_u8; RESP_BUFFER];

        'reads: loop {
            // `gotbytes = 0;` (`:261`), re-zeroed every iteration so that the
            // loop condition below reads the CURRENT read and not the previous
            // one.
            let mut gotbytes = 0_usize;

            // `if(pp->nfinal) { ... curlx_dyn_tail(&pp->recvbuf, full -
            // pp->nfinal); pp->nfinal = 0; }` (`:262-271`): the previous call
            // left its final line at the front for the parser, and this is
            // where it is finally ditched.
            if self.nfinal > 0 {
                let full = self.recvbuf.len();
                let keep = full.saturating_sub(self.nfinal);
                self.recvbuf.tail(keep).map_err(Error::from)?;
                self.nfinal = 0;
            }

            // `if(!pp->overflow) { ... }` (`:272-293`): bytes are already
            // cached, so reading again would block for no reason.
            if self.overflow == 0 {
                gotbytes = match io.recv(sockindex, &mut buffer) {
                    Ok(received) => received,
                    // `if(result == CURLE_AGAIN) return CURLE_OK;` (`:275-276`)
                    // -- and `pending_resp` is deliberately left set.
                    Err(error) if error.code() == CURLcode::Again => {
                        return Ok(outcome)
                    }
                    // `if(result) return result;` (`:278-279`).
                    Err(error) => return Err(error),
                };

                // `if(!gotbytes) { failf(data, "response reading failed
                // (errno: %d)", SOCKERRNO); return CURLE_RECV_ERROR; }`
                // (`:281-284`).
                if gotbytes == 0 {
                    let errno = io.sock_errno();
                    io.failf(format_args!(
                        "response reading failed (errno: {errno})"
                    ));
                    return Err(Error::with_context(
                        CURLcode::RecvError,
                        format!("response reading failed (errno: {errno})"),
                    ));
                }

                // A transport cannot have filled more than the buffer it was
                // given. The C would read past the array; this reports it.
                let Some(received) = buffer.get(..gotbytes) else {
                    return Err(Error::with_context(
                        CURLcode::RecvError,
                        "the transport reported reading more than it was \
                         offered",
                    ));
                };

                // `curlx_dyn_addn(&pp->recvbuf, buffer, gotbytes);` (`:286`).
                self.recvbuf.addn(received).map_err(Error::from)?;

                // `data->req.headerbytecount += (unsigned int)gotbytes;`
                // (`:290`). One read is at most `RESP_BUFFER` bytes, so the
                // narrowing cannot lose anything; it is written as a checked
                // conversion because this crate admits no narrowing cast.
                io.add_header_bytes(
                    u32::try_from(gotbytes).unwrap_or(u32::MAX),
                );

                // `pp->nread_resp += gotbytes;` (`:292`).
                self.nread_resp = self.nread_resp.saturating_add(gotbytes);
            }

            // The framing loop -- `do { ... } while(1);` (`:295-341`), which
            // runs *"while there is buffer left to scan"*.
            loop {
                let len = self.recvbuf.len();
                // `memchr(line, '\n', curlx_dyn_len(&pp->recvbuf))` (`:297`).
                let newline =
                    self.recvbuf.as_slice().iter().position(|&b| b == b'\n');
                let Some(nl) = newline else {
                    // `else { pp->overflow = 0; break; }` (`:335-339`):
                    // *"without a newline, there is no overflow"*. The partial
                    // line stays in the buffer for the next read to complete.
                    self.overflow = 0;
                    break;
                };
                // `size_t length = nl - line + 1;` (`:301`) -- the LF is part
                // of the line.
                let length = nl.saturating_add(1);

                // One borrow of the buffer serves all three consumers below,
                // because each of them mutates something else: the trace sink,
                // the writer chain, and the protocol's own parser state.
                //
                // The `else` arm is unreachable and is written anyway: `length`
                // is one past a position FOUND in this same slice, so the
                // lookup cannot fail. Coverage reports it as unrun for that
                // reason. The alternative spelling is an index, which would
                // trade an unreachable arm for a reachable panic.
                let Some(line) = self.recvbuf.as_slice().get(..length) else {
                    return Err(Error::with_context(
                        CURLcode::RecvError,
                        "the framed reply line is outside the receive buffer",
                    ));
                };

                // `Curl_debug(data, CURLINFO_HEADER_IN, line, length);`
                // (`:304`) -- FIRST, so a trace shows the line even when the
                // write below refuses it.
                io.debug(InfoType::HeaderIn, line);

                // `Curl_client_write(data, CLIENTWRITE_INFO, line, length);`
                // with `if(result) return result;` (`:310-312`). Reply lines
                // are *"a kind of headers"*, which is what `CLIENTWRITE_INFO`
                // says.
                io.client_write(ClientWriteFlags::INFO, line)?;

                // `pp->endofresp(data, conn, line, length, code)` (`:314`),
                // after both deliveries, so the last line of a reply is traced
                // and written like every other line.
                let is_final = ops.end_of_response(line, &mut outcome.code);

                if is_final {
                    // `pp->nfinal = length;` (`:319`) -- keep the final line
                    // first in the buffer for the protocol's parser.
                    self.nfinal = length;
                    // `if(curlx_dyn_len(&pp->recvbuf) > length) pp->overflow =
                    // curlx_dyn_len(&pp->recvbuf) - length; else pp->overflow =
                    // 0;` (`:320-323`).
                    self.overflow = if len > length {
                        len.saturating_sub(length)
                    } else {
                        0
                    };
                    // `*size = pp->nread_resp; pp->nread_resp = 0;`
                    // (`:324-325`) -- *"restart"*.
                    outcome.size = self.nread_resp;
                    self.nread_resp = 0;
                    // `gotbytes = 0; break;` (`:326-327`), whose only purpose
                    // is to fail the outer loop's condition. Breaking the outer
                    // loop directly says that, and still reaches the
                    // `pending_resp` assignment below -- which the C's path
                    // does too.
                    break 'reads;
                }

                // `if(curlx_dyn_len(&pp->recvbuf) > length)
                // curlx_dyn_tail(&pp->recvbuf, curlx_dyn_len(&pp->recvbuf) -
                // length); else curlx_dyn_reset(&pp->recvbuf);` (`:329-333`).
                // The C re-reads the length here; nothing has changed it since
                // `len` was taken.
                if len > length {
                    self.recvbuf
                        .tail(len.saturating_sub(length))
                        .map_err(Error::from)?;
                } else {
                    self.recvbuf.reset();
                }
            }

            // `} while(gotbytes == sizeof(buffer));` (`:343`).
            if gotbytes != RESP_BUFFER {
                break;
            }
        }

        // `pp->pending_resp = FALSE;` (`:345`) -- the normal exit only.
        self.pending_resp = false;
        Ok(outcome)
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use crate::conn::filters::{
        link, CfQuery, CfQueryValue, ConnFilter, FilterBase,
    };
    use crate::util::timeval::TestClock;

    // -- the harness -------------------------------------------------------
    //
    // Everything below is `#[cfg(test)]` and none of it reaches the shipped
    // artifact. Two doubles and no third: a scripted [`PingPongIo`] and a
    // scripted [`PingPongOps`], which between them are the whole environment
    // the C threads through `data` and `conn`.
    //
    // No socket is opened, no server is started, no thread sleeps and no wall
    // clock is read. Readiness is a script, time is a `TestClock` the test
    // advances by hand, and the transport is a queue -- which is what makes the
    // timeout, would-block and short-write branches reachable at all: none of
    // them can be provoked reliably against a real descriptor.
    //
    // `Arc<Mutex<_>>` appears in exactly one place, `MemTransport`, because a
    // filter installed in a chain cannot be read back out of it. Everywhere
    // else the double is owned by the test and inspected directly, so no
    // interior mutability is needed. The crate's own `util::sync_cell` would
    // serve for the one case; std is used instead to keep this file's imports
    // to the modules it genuinely depends on.

    /// What one scripted `recv` does.
    #[derive(Clone, Debug)]
    enum ReadStep {
        /// Hand up these bytes, capped by the caller's buffer. A remainder is
        /// pushed back to the front of the queue, exactly as a socket holding
        /// more than one read's worth behaves.
        Bytes(Vec<u8>),
        /// `CURLE_AGAIN` -- would block.
        Again,
        /// A successful read of zero bytes, which the C treats as a closed
        /// connection.
        Closed,
        /// A transport failure.
        Fail(CURLcode),
        /// Claim to have filled more of the buffer than it holds. Impossible
        /// for a real transport; the engine has to refuse it rather than slice
        /// out of bounds.
        Overreport,
    }

    /// What one scripted `send` does.
    #[derive(Clone, Copy, Debug)]
    enum WriteStep {
        /// Accept at most this many bytes of whatever is offered.
        Limit(usize),
        /// `CURLE_AGAIN` -- would block, so nothing was written.
        Again,
        /// A transport failure.
        Fail(CURLcode),
        /// Claim to have written more than was offered.
        Overreport,
    }

    /// The scripted environment.
    #[derive(Debug)]
    struct TestIo {
        /// The injected clock, shared with the test so it can be advanced.
        clock: Arc<TestClock>,
        /// `data->conn != NULL`.
        connected: bool,
        /// What `recv` does, in order. An exhausted script reports
        /// `CURLE_AGAIN`, which is what a socket with nothing on it does.
        reads: VecDeque<ReadStep>,
        /// How many times `recv` was called -- the outer-loop boundary is
        /// measured with this.
        read_calls: usize,
        /// What `send` does, in order. An exhausted script accepts everything.
        writes: VecDeque<WriteStep>,
        /// Every buffer `send` was offered, in order.
        offered: Vec<Vec<u8>>,
        /// Every byte `send` accepted, concatenated: this is the wire.
        wire: Vec<u8>,
        /// What `wait_ready` reports, in order. An exhausted script reports
        /// zero, which is the C's "timed out, nothing ready".
        readiness: VecDeque<CodeResult<u32>>,
        /// Every wait, with the socket, direction and interval it was given.
        waits: Vec<(Socket, PollAction, TimeDiff)>,
        /// `Curl_conn_data_pending`.
        data_pending: bool,
        /// The answer to the buffered-filter question alone.
        buffered_pending: bool,
        /// `conn->sock[FIRSTSOCKET]`.
        socket: Socket,
        /// Every `Curl_debug` call, in order.
        debug_log: Vec<(InfoType, Vec<u8>)>,
        /// Every `Curl_client_write` call, in order.
        client_writes: Vec<(ClientWriteFlags, Vec<u8>)>,
        /// What the writer chain reports, if it refuses.
        client_write_fails: Option<CURLcode>,
        /// Every `failf` message, in order.
        failures: Vec<String>,
        /// `data->req.headerbytecount`.
        header_bytes: u32,
        /// `data->set.server_response_timeout`.
        server_response_timeout_ms: TimeDiff,
        /// `Curl_timeleft_ms(data)`.
        timeleft_ms: TimeDiff,
        /// What `Curl_pgrsCheck` reports, if it refuses.
        pgrs_fails: Option<CURLcode>,
        /// How many times the progress check ran.
        pgrs_calls: usize,
        /// `SOCKERRNO`.
        errno: i32,
        /// Every operation, in order, so that a test can prove SEQUENCE and
        /// not merely occurrence.
        events: Vec<String>,
    }

    impl TestIo {
        /// A connected environment with an empty script and a clock at ten
        /// seconds -- far enough from zero that a test can move backwards.
        fn new() -> Self {
            Self {
                clock: Arc::new(TestClock::new(CurlTime::new(10, 0))),
                connected: true,
                reads: VecDeque::new(),
                read_calls: 0,
                writes: VecDeque::new(),
                offered: Vec::new(),
                wire: Vec::new(),
                readiness: VecDeque::new(),
                waits: Vec::new(),
                data_pending: false,
                buffered_pending: false,
                socket: 7,
                debug_log: Vec::new(),
                client_writes: Vec::new(),
                client_write_fails: None,
                failures: Vec::new(),
                header_bytes: 0,
                server_response_timeout_ms: 0,
                timeleft_ms: 0,
                pgrs_fails: None,
                pgrs_calls: 0,
                errno: 0,
                events: Vec::new(),
            }
        }

        /// A handle on the clock, for advancing it.
        fn clock_handle(&self) -> Arc<TestClock> {
            Arc::clone(&self.clock)
        }

        fn note(&mut self, what: &str) {
            self.events.push(what.to_string());
        }

        fn script_reads(&mut self, steps: impl IntoIterator<Item = ReadStep>) {
            self.reads.extend(steps);
        }

        fn script_writes(
            &mut self,
            steps: impl IntoIterator<Item = WriteStep>,
        ) {
            self.writes.extend(steps);
        }

        fn script_readiness(
            &mut self,
            steps: impl IntoIterator<Item = CodeResult<u32>>,
        ) {
            self.readiness.extend(steps);
        }

        /// The index of the first event whose text is exactly `what`.
        fn event_index(&self, what: &str) -> Option<usize> {
            self.events.iter().position(|event| event == what)
        }
    }

    impl PingPongIo for TestIo {
        fn has_connection(&self) -> bool {
            self.connected
        }

        /// Always [`None`]: this double drives the transport itself and
        /// overrides all four of the methods that would use a chain. The
        /// default bodies are exercised separately, over a real
        /// [`crate::conn::filters::FilterChain`], by
        /// [`the_default_transport_bodies_reach_a_real_filter_chain`].
        fn conn(&mut self) -> Option<ConnAccess<'_>> {
            None
        }

        fn clock(&self) -> &dyn Clock {
            self.clock.as_ref()
        }

        fn socket(&mut self, _sockindex: SocketIndex) -> Socket {
            self.socket
        }

        fn data_pending(&mut self, _sockindex: SocketIndex) -> bool {
            self.note("data_pending");
            self.data_pending
        }

        fn buffered_data_pending(&mut self, _sockindex: SocketIndex) -> bool {
            self.note("buffered_data_pending");
            self.buffered_pending
        }

        fn send(
            &mut self,
            _sockindex: SocketIndex,
            buf: &[u8],
        ) -> CurlResult<usize> {
            self.note("send");
            self.offered.push(buf.to_vec());
            match self.writes.pop_front() {
                None | Some(WriteStep::Limit(usize::MAX)) => {
                    self.wire.extend_from_slice(buf);
                    Ok(buf.len())
                }
                Some(WriteStep::Limit(limit)) => {
                    let taken = limit.min(buf.len());
                    self.wire.extend_from_slice(&buf[..taken]);
                    Ok(taken)
                }
                Some(WriteStep::Again) => Err(Error::new(CURLcode::Again)),
                Some(WriteStep::Fail(code)) => Err(Error::new(code)),
                Some(WriteStep::Overreport) => Ok(buf.len() + 1),
            }
        }

        fn recv(
            &mut self,
            _sockindex: SocketIndex,
            buf: &mut [u8],
        ) -> CurlResult<usize> {
            self.note("recv");
            self.read_calls += 1;
            match self.reads.pop_front() {
                None | Some(ReadStep::Again) => {
                    Err(Error::new(CURLcode::Again))
                }
                Some(ReadStep::Closed) => Ok(0),
                Some(ReadStep::Fail(code)) => Err(Error::new(code)),
                Some(ReadStep::Overreport) => Ok(buf.len() + 1),
                Some(ReadStep::Bytes(bytes)) => {
                    let taken = bytes.len().min(buf.len());
                    buf[..taken].copy_from_slice(&bytes[..taken]);
                    if taken < bytes.len() {
                        self.reads.push_front(ReadStep::Bytes(
                            bytes[taken..].to_vec(),
                        ));
                    }
                    Ok(taken)
                }
            }
        }

        fn wait_ready<'a>(
            &'a mut self,
            sock: Socket,
            want: PollAction,
            timeout_ms: TimeDiff,
        ) -> ProtoFuture<'a, u32> {
            Box::pin(async move {
                self.note("wait_ready");
                self.waits.push((sock, want, timeout_ms));
                self.readiness.pop_front().unwrap_or(Ok(0))
            })
        }

        fn debug(&mut self, kind: InfoType, payload: &[u8]) {
            self.note(match kind {
                InfoType::HeaderIn => "debug:header_in",
                InfoType::HeaderOut => "debug:header_out",
                _ => "debug:other",
            });
            self.debug_log.push((kind, payload.to_vec()));
        }

        fn client_write(
            &mut self,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CurlResult<()> {
            self.note("client_write");
            self.client_writes.push((flags, buf.to_vec()));
            match self.client_write_fails {
                Some(code) => Err(Error::new(code)),
                None => Ok(()),
            }
        }

        fn failf(&mut self, args: fmt::Arguments<'_>) {
            self.note("failf");
            self.failures.push(args.to_string());
        }

        fn add_header_bytes(&mut self, count: u32) {
            self.header_bytes = self.header_bytes.saturating_add(count);
        }

        fn server_response_timeout_ms(&self) -> TimeDiff {
            self.server_response_timeout_ms
        }

        fn timeleft_ms(&self) -> TimeDiff {
            self.timeleft_ms
        }

        fn pgrs_check(&mut self) -> CurlResult<()> {
            self.note("pgrs_check");
            self.pgrs_calls += 1;
            match self.pgrs_fails {
                Some(code) => Err(Error::new(code)),
                None => Ok(()),
            }
        }

        fn sock_errno(&self) -> i32 {
            self.errno
        }
    }

    /// The scripted protocol callbacks -- what `ftp/mod.rs` will implement.
    #[derive(Debug)]
    struct TestOps {
        /// Every line [`PingPongOps::end_of_response`] was shown, in order and
        /// byte for byte.
        lines: Vec<Vec<u8>>,
        /// How many times the state machine ran.
        steps: usize,
        /// What the state machine reports.
        outcome: CodeResult<()>,
        /// What [`PingPong::moredata`] answered inside the state machine, which
        /// proves the callback really can drive the engine it is handed.
        saw_moredata: Option<bool>,
        /// When set, the final-line verdict is forced instead of being decided
        /// by the FTP rule below.
        force_final: Option<bool>,
    }

    impl Default for TestOps {
        fn default() -> Self {
            Self {
                lines: Vec::new(),
                steps: 0,
                outcome: Ok(()),
                saw_moredata: None,
                force_final: None,
            }
        }
    }

    impl PingPongOps<TestIo> for TestOps {
        fn statemachine<'a>(
            &'a mut self,
            pp: &'a mut PingPong,
            io: &'a mut TestIo,
        ) -> ProtoFuture<'a, ()> {
            Box::pin(async move {
                io.note("statemachine");
                self.steps += 1;
                self.saw_moredata = Some(pp.moredata());
                self.outcome
            })
        }

        /// `ftp_endofresp` (`lib/ftp.c`): the last line of a reply is
        /// `NNN<space>`, and a continuation is `NNN-`.
        fn end_of_response(&mut self, line: &[u8], code: &mut i32) -> bool {
            self.lines.push(line.to_vec());
            let digits = line
                .get(..3)
                .is_some_and(|head| head.iter().all(u8::is_ascii_digit));
            let last = digits && line.get(3) == Some(&b' ');
            let verdict = self.force_final.unwrap_or(last);
            if verdict && digits {
                let text = String::from_utf8_lossy(&line[..3]).into_owned();
                *code = text.parse().unwrap_or(0);
            }
            verdict
        }
    }

    /// An initialised engine and its environment, the pair every test starts
    /// from.
    fn engine() -> (PingPong, TestIo, TestOps) {
        let io = TestIo::new();
        let mut pp = PingPong::new();
        pp.init(io.clock().now());
        (pp, io, TestOps::default())
    }

    /// Runs a future to completion without a `tokio` runtime.
    ///
    /// The crate's own idiom for this -- `conn/pool.rs`, `conn/shutdown.rs` and
    /// `protocols/mod.rs` all drive their futures the same way. No timer is
    /// involved, because every wait in these tests is scripted.
    fn drive<F: core::future::Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }

    /// The whole of one reply, as a scripted read.
    fn reply(bytes: &[u8]) -> ReadStep {
        ReadStep::Bytes(bytes.to_vec())
    }

    // -- the pinned numeric contracts --------------------------------------

    /// `curl_pp_transfer`'s three values are 0, 1 and 2, in declaration order.
    #[test]
    fn the_transfer_enum_holds_its_declaration_order() {
        assert_eq!(PpTransfer::Body as i32, 0);
        assert_eq!(PpTransfer::Info as i32, 1);
        assert_eq!(PpTransfer::None as i32, 2);
        // Zero-initialised in the C, so `Default` has to agree with it.
        assert_eq!(PpTransfer::default(), PpTransfer::Body);
    }

    /// The terminator is two bytes, and they are carriage return and line feed
    /// in that order.
    #[test]
    fn the_terminator_is_exactly_two_bytes() {
        assert_eq!(CRLF.len(), 2);
        assert_eq!(CRLF, b"\r\n");
        assert_eq!(CRLF[0], 13);
        assert_eq!(CRLF[1], 10);
    }

    /// `RESP_TIMEOUT` is a minute and the read buffer is 900 bytes.
    #[test]
    fn the_two_numeric_contracts_are_the_measured_ones() {
        assert_eq!(RESP_TIMEOUT, 60_000);
        assert_eq!(RESP_BUFFER, 900);
        assert_eq!(BLOCK_INTERVAL_MS, 1000);
        // The dynbuf ceiling is consumed, not restated -- but the value the
        // header gives is asserted here so that a change in either place is
        // caught in the module that depends on it.
        assert_eq!(DYN_PINGPPONG_CMD, 64 * 1024);
    }

    /// The two failure texts are exactly the C's.
    #[test]
    fn the_two_failure_texts_are_the_measured_ones() {
        assert_eq!(RESPONSE_TIMEOUT_MESSAGE, "server response timeout");
        assert_eq!(SELECT_ERROR_MESSAGE, "select/poll error");
    }

    /// A pending response carries no code and no size, and knows it.
    #[test]
    fn a_pending_response_is_zero_and_incomplete() {
        assert_eq!(PpResponse::PENDING.code, 0);
        assert_eq!(PpResponse::PENDING.size, 0);
        assert!(!PpResponse::PENDING.is_complete());
        assert_eq!(PpResponse::default(), PpResponse::PENDING);
        assert!(PpResponse {
            code: 220,
            size: 11
        }
        .is_complete());
    }

    // -- initialisation ----------------------------------------------------

    /// The zero state before `Curl_pp_init`.
    #[test]
    fn a_new_engine_is_the_zero_state() {
        let pp = PingPong::new();
        assert!(!pp.is_initialised());
        assert!(!pp.pending_resp());
        assert_eq!(pp.nread_resp(), 0);
        assert_eq!(pp.sendthis(), None);
        assert_eq!(pp.sendleft(), 0);
        assert_eq!(pp.sendsize(), 0);
        assert_eq!(pp.overflow(), 0);
        assert_eq!(pp.nfinal(), 0);
        assert_eq!(pp.response(), CurlTime::ZERO);
        assert!(pp.recvbuf().is_empty());
        assert!(!pp.needs_flush());
        assert!(!pp.moredata());
        // `Default` is `new`, so a struct-update start cannot diverge from it.
        assert!(!PingPong::default().is_initialised());
    }

    /// `Curl_pp_init` sets every field the C sets, and the timestamp it stores
    /// is the caller's rather than a fresh reading.
    #[test]
    fn init_copies_the_callers_timestamp_and_arms_the_response() {
        let clock = TestClock::new(CurlTime::new(42, 500_000));
        let stamp = clock.now();
        // The clock moves AFTER the reading the caller took. A reading taken
        // inside `init` would land here instead, and the assertion below would
        // see 43.5 rather than 42.5.
        clock.advance(Duration::from_secs(1));

        let mut pp = PingPong::new();
        pp.init(stamp);

        assert!(pp.is_initialised());
        assert!(pp.pending_resp());
        assert_eq!(pp.response(), CurlTime::new(42, 500_000));
        assert_ne!(pp.response(), clock.now());
        assert_eq!(pp.nread_resp(), 0);
        assert_eq!(pp.sendthis(), None);
        assert_eq!(pp.sendleft(), 0);
        assert_eq!(pp.sendsize(), 0);
        assert_eq!(pp.overflow(), 0);
        assert_eq!(pp.nfinal(), 0);
        assert!(pp.recvbuf().is_empty());
    }

    /// Both buffers are created with the ping-pong ceiling.
    ///
    /// `DynBuf` reports its ceiling in its `Debug` rendering, which is the only
    /// way to observe it without adding an accessor to a module this file does
    /// not own. The behavioural half of the same claim -- an append past the
    /// ceiling is refused -- is [`a_command_past_the_buffer_ceiling_is_refused`].
    #[test]
    fn init_gives_both_buffers_the_pingpong_ceiling() {
        let (pp, _io, _ops) = engine();
        let rendered = format!("{pp:?}");
        let ceilings = rendered.matches("toobig: 65536").count();
        assert_eq!(
            ceilings, 2,
            "both dynbufs carry DYN_PINGPPONG_CMD: {rendered}"
        );
    }

    /// `Curl_pp_disconnect` releases the buffers, restores the zero state, and
    /// a second call does nothing at all.
    #[test]
    fn disconnect_clears_every_field_and_is_idempotent() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 ready\r\nextra")]);
        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the scripted reply is read");
        assert!(outcome.is_complete());
        io.script_writes([WriteStep::Limit(2)]);
        pp.sendf(&mut io, format_args!("NOOP"))
            .expect("the short write succeeds");

        // Everything that could be left set, is.
        assert!(pp.nfinal() > 0);
        assert!(pp.overflow() > 0);
        assert!(pp.sendleft() > 0);
        assert!(!pp.recvbuf().is_empty());

        assert!(pp.disconnect().is_ok());
        assert!(!pp.is_initialised());
        assert!(!pp.pending_resp());
        assert_eq!(pp.nread_resp(), 0);
        assert_eq!(pp.sendthis(), None);
        assert_eq!(pp.sendleft(), 0);
        assert_eq!(pp.sendsize(), 0);
        assert_eq!(pp.overflow(), 0);
        assert_eq!(pp.nfinal(), 0);
        assert_eq!(pp.response(), CurlTime::ZERO);
        assert!(pp.recvbuf().is_empty());

        // The C's `if(pp->initialised)` guard makes the second call a no-op,
        // and so does this one.
        assert!(pp.disconnect().is_ok());
        assert!(!pp.is_initialised());
    }

    /// A `PingPong` that was never initialised can still be reset.
    #[test]
    fn disconnect_on_an_uninitialised_engine_is_harmless() {
        let mut pp = PingPong::new();
        assert!(pp.disconnect().is_ok());
        assert!(!pp.is_initialised());
    }

    // -- sending -----------------------------------------------------------

    /// The caller writes the command, this file writes the terminator, and it
    /// appears exactly once.
    #[test]
    fn a_command_is_terminated_with_one_crlf() {
        let (mut pp, mut io, _ops) = engine();
        pp.sendf(&mut io, format_args!("USER {}", "name"))
            .expect("the command is sent");

        assert_eq!(io.wire, b"USER name\r\n");
        assert_eq!(io.offered.len(), 1);
        assert_eq!(io.offered[0], b"USER name\r\n");
        // Neither missing nor doubled.
        assert_eq!(
            io.wire.windows(2).filter(|pair| *pair == b"\r\n").count(),
            1
        );
        assert!(io.wire.ends_with(b"\r\n"));
        assert!(!io.wire.ends_with(b"\r\n\r\n"));
        // And no terminating zero: the C's dynbuf keeps one internally and
        // never sends it.
        assert!(!io.wire.contains(&0));
    }

    /// The byte-exact entry point behaves identically, and carries bytes that
    /// are not text.
    #[test]
    fn sendn_is_byte_transparent_and_adds_the_same_terminator() {
        let (mut pp, mut io, _ops) = engine();
        // A path with a byte that is not valid UTF-8, which is why the byte
        // entry point exists at all.
        pp.sendn(&mut io, b"RETR \xffodd")
            .expect("the command is sent");
        assert_eq!(io.wire, b"RETR \xffodd\r\n");
    }

    /// A fully written command clears the retained-send trio, traces the whole
    /// command, and restamps the response deadline.
    #[test]
    fn a_full_send_clears_the_trio_and_restamps_the_response() {
        let (mut pp, mut io, _ops) = engine();
        let clock = io.clock_handle();
        let before = pp.response();
        clock.advance(Duration::from_millis(250));

        pp.sendf(&mut io, format_args!("PWD"))
            .expect("the command is sent");

        assert_eq!(pp.sendthis(), None);
        assert_eq!(pp.sendleft(), 0);
        assert_eq!(pp.sendsize(), 0);
        assert!(!pp.needs_flush());
        assert!(pp.pending_resp());
        // Restamped from the INJECTED clock, so the new stamp is exactly the
        // advanced reading rather than anything the host clock says.
        assert_eq!(pp.response(), CurlTime::new(10, 250_000));
        assert_ne!(pp.response(), before);
        // `CURLINFO_HEADER_OUT` for the whole command, terminator included.
        assert_eq!(
            io.debug_log,
            vec![(InfoType::HeaderOut, b"PWD\r\n".to_vec())]
        );
    }

    /// A short write retains the buffer, records the offset arithmetic, and
    /// traces only the bytes that actually went out.
    #[test]
    fn a_short_write_retains_the_command_and_traces_only_what_went_out() {
        let (mut pp, mut io, _ops) = engine();
        let clock = io.clock_handle();
        let before = pp.response();
        io.script_writes([WriteStep::Limit(4)]);
        clock.advance(Duration::from_millis(500));

        pp.sendf(&mut io, format_args!("PASS mockpw"))
            .expect("a short write is not a failure");

        // `b"PASS mockpw\r\n"` is 13 bytes and four went out.
        assert_eq!(pp.sendsize(), 13);
        assert_eq!(pp.sendleft(), 9);
        assert_eq!(pp.sendthis(), Some(0));
        assert!(pp.needs_flush());
        // The response deadline has NOT been restamped: the command is still
        // going out.
        assert_eq!(pp.response(), before);
        assert_eq!(io.wire, b"PASS");
        assert_eq!(io.debug_log, vec![(InfoType::HeaderOut, b"PASS".to_vec())]);
    }

    /// `CURLE_AGAIN` is a successful send of nothing: everything is retained
    /// and nothing is traced.
    #[test]
    fn a_would_block_send_retains_the_whole_command() {
        let (mut pp, mut io, _ops) = engine();
        let before = pp.response();
        io.script_writes([WriteStep::Again]);

        pp.sendf(&mut io, format_args!("QUIT"))
            .expect("a would-block send is not a failure");

        assert_eq!(pp.sendsize(), 6);
        assert_eq!(pp.sendleft(), 6);
        assert_eq!(pp.sendthis(), Some(0));
        assert_eq!(pp.response(), before);
        assert!(io.wire.is_empty());
        assert_eq!(
            io.debug_log,
            vec![(InfoType::HeaderOut, Vec::new())],
            "the C traces zero bytes rather than skipping the call"
        );
    }

    /// `flushsend` starts at the exact byte the short write stopped on,
    /// finishes the command, and restamps only then.
    #[test]
    fn flushsend_resumes_at_the_first_unsent_byte() {
        let (mut pp, mut io, _ops) = engine();
        let clock = io.clock_handle();
        io.script_writes([WriteStep::Limit(4)]);
        pp.sendf(&mut io, format_args!("PASS mockpw"))
            .expect("the short write succeeds");
        let after_send = pp.response();

        clock.advance(Duration::from_secs(2));
        pp.flushsend(&mut io).expect("the remainder is sent");

        assert_eq!(io.wire, b"PASS mockpw\r\n");
        assert_eq!(io.offered.len(), 2);
        assert_eq!(io.offered[1], b" mockpw\r\n");
        assert_eq!(pp.sendthis(), None);
        assert_eq!(pp.sendleft(), 0);
        assert_eq!(pp.sendsize(), 0);
        assert!(!pp.needs_flush());
        assert_eq!(pp.response(), CurlTime::new(12, 0));
        assert_ne!(pp.response(), after_send);
        // The C emits no `CURLINFO_HEADER_OUT` from the flush path, so the
        // trace still holds only the first four bytes.
        assert_eq!(io.debug_log.len(), 1);
        assert_eq!(io.debug_log[0].1, b"PASS".to_vec());
    }

    /// A partial flush moves only `sendleft`, leaving the offset to follow from
    /// it, and does not restamp.
    #[test]
    fn a_partial_flush_moves_only_sendleft() {
        let (mut pp, mut io, _ops) = engine();
        io.script_writes([WriteStep::Limit(4), WriteStep::Limit(3)]);
        pp.sendf(&mut io, format_args!("PASS mockpw"))
            .expect("the short write succeeds");
        let after_send = pp.response();

        pp.flushsend(&mut io).expect("a partial flush succeeds");

        assert_eq!(pp.sendsize(), 13);
        assert_eq!(pp.sendleft(), 6);
        assert_eq!(pp.sendthis(), Some(0));
        assert_eq!(pp.response(), after_send);
        assert_eq!(io.wire, b"PASS mo");
        assert_eq!(io.offered[1], b" mockpw\r\n");

        // And the next flush starts where this one stopped.
        pp.flushsend(&mut io).expect("the rest is sent");
        assert_eq!(io.offered[2], b"ckpw\r\n");
        assert_eq!(io.wire, b"PASS mockpw\r\n");
        assert!(!pp.needs_flush());
    }

    /// A would-block flush changes nothing at all.
    #[test]
    fn a_would_block_flush_changes_nothing() {
        let (mut pp, mut io, _ops) = engine();
        io.script_writes([WriteStep::Limit(4), WriteStep::Again]);
        pp.sendf(&mut io, format_args!("PASS mockpw"))
            .expect("the short write succeeds");
        let after_send = pp.response();

        pp.flushsend(&mut io)
            .expect("a would-block flush is not a failure");

        assert_eq!(pp.sendsize(), 13);
        assert_eq!(pp.sendleft(), 9);
        assert_eq!(pp.response(), after_send);
        assert_eq!(io.wire, b"PASS");
    }

    /// With nothing half-sent, a flush is a no-op that does not touch the
    /// transport.
    #[test]
    fn flushsend_without_a_pending_command_does_nothing() {
        let (mut pp, mut io, _ops) = engine();
        assert!(!pp.needs_flush());
        pp.flushsend(&mut io).expect("nothing to flush");
        assert!(io.offered.is_empty());
        assert!(io.wire.is_empty());
    }

    /// A transport failure during a flush travels out unchanged.
    #[test]
    fn a_failing_flush_propagates_the_transport_error() {
        let (mut pp, mut io, _ops) = engine();
        io.script_writes([
            WriteStep::Limit(4),
            WriteStep::Fail(CURLcode::SendError),
        ]);
        pp.sendf(&mut io, format_args!("PASS mockpw"))
            .expect("the short write succeeds");

        let error = pp.flushsend(&mut io).expect_err("the flush fails");
        assert_eq!(error.code(), CURLcode::SendError);
        // The retained state is untouched, so a retry is still possible.
        assert_eq!(pp.sendleft(), 9);
    }

    /// The three defensive arms of `flushsend`, over states the public surface
    /// cannot produce.
    ///
    /// The C has no equivalent of any of them: it forms
    /// `pp->sendthis + pp->sendsize - pp->sendleft` from whatever the fields
    /// hold and reads through it. Each arm here reports instead, and each is
    /// reached through the `#[cfg(test)]` mutator that exists for exactly this
    /// -- otherwise they would be unreachable, and an unreachable guard is an
    /// untested one.
    #[test]
    fn the_defensive_flush_arms_report_rather_than_slice_out_of_bounds() {
        // Bytes remain, but no command is held.
        let (mut pp, mut io, _ops) = engine();
        pp.force_retained_send(None, 6, 6);
        let error = pp.flushsend(&mut io).expect_err("no command is held");
        assert_eq!(error.code(), CURLcode::SendError);
        assert!(io.offered.is_empty(), "nothing was offered");

        // The offset arithmetic cannot be formed at all.
        let (mut pp, mut io, _ops) = engine();
        pp.force_retained_send(Some(usize::MAX), usize::MAX, 1);
        let error = pp.flushsend(&mut io).expect_err("the offset overflows");
        assert_eq!(error.code(), CURLcode::SendError);
        assert!(io.offered.is_empty());

        // The range is formable and outside the command buffer.
        let (mut pp, mut io, _ops) = engine();
        pp.force_retained_send(Some(0), 100, 1);
        let error = pp
            .flushsend(&mut io)
            .expect_err("the range is outside the buffer");
        assert_eq!(error.code(), CURLcode::SendError);
        assert!(io.offered.is_empty());
    }

    /// The seam's DEFAULT readiness wait is the tokio reactor, and it answers
    /// without a descriptor.
    ///
    /// `Curl_socket_check` with no valid socket is *"no sockets, just wait"*
    /// (`lib/select.c:131-132`), so a zero interval over [`CURL_SOCKET_BAD`]
    /// returns "nothing ready" immediately -- which exercises the default body,
    /// both of its directions and the timer seam beneath it without opening
    /// anything. A runtime is built here because that body needs one, and the
    /// time driver is enabled because [`crate::conn::select::wait_ms`] sleeps
    /// for zero.
    #[test]
    fn the_default_readiness_wait_reaches_the_tokio_reactor() {
        let state = Arc::new(Mutex::new(TransportState::default()));
        let mut io = ChainIo::new(state, CURL_SOCKET_BAD);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a current-thread runtime builds");

        let readable =
            runtime.block_on(io.wait_ready(CURL_SOCKET_BAD, PollAction::IN, 0));
        assert_eq!(readable, Ok(0));

        let writable = runtime.block_on(io.wait_ready(
            CURL_SOCKET_BAD,
            PollAction::OUT,
            0,
        ));
        assert_eq!(writable, Ok(0));
    }

    /// The connection accessor prints its shape and not its contents.
    #[test]
    fn the_connection_accessor_is_opaque_when_printed() {
        let state = Arc::new(Mutex::new(TransportState::default()));
        let mut io = ChainIo::new(state, 3);
        let access = io.conn().expect("there is a connection");
        assert_eq!(format!("{access:?}"), "ConnAccess");
    }

    /// A transport that claims to have written more than it was offered is
    /// refused rather than allowed to corrupt the bookkeeping.
    #[test]
    fn an_overreporting_transport_is_refused_on_both_paths() {
        let (mut pp, mut io, _ops) = engine();
        io.script_writes([WriteStep::Overreport]);
        let error = pp
            .sendf(&mut io, format_args!("NOOP"))
            .expect_err("an impossible count is refused");
        assert_eq!(error.code(), CURLcode::SendError);

        let (mut pp, mut io, _ops) = engine();
        io.script_writes([WriteStep::Limit(2), WriteStep::Overreport]);
        pp.sendf(&mut io, format_args!("NOOP"))
            .expect("the short write succeeds");
        let error = pp.flushsend(&mut io).expect_err("the flush is refused");
        assert_eq!(error.code(), CURLcode::SendError);
        assert_eq!(pp.sendleft(), 4, "nothing was believed");
    }

    /// Without a connection there is nothing to send on, and the C's code for
    /// that is `CURLE_SEND_ERROR`.
    #[test]
    fn a_command_without_a_connection_is_a_send_error() {
        let (mut pp, mut io, _ops) = engine();
        io.connected = false;
        let error = pp
            .sendf(&mut io, format_args!("NOOP"))
            .expect_err("there is no connection");
        assert_eq!(error.code(), CURLcode::SendError);
        // The buffer was not touched and nothing was offered to the transport.
        assert!(io.offered.is_empty());
        assert_eq!(pp.sendsize(), 0);
    }

    /// A command longer than the buffer ceiling is refused with the dynbuf's
    /// own code, and the buffer is emptied.
    #[test]
    fn a_command_past_the_buffer_ceiling_is_refused() {
        let (mut pp, mut io, _ops) = engine();
        let huge = vec![b'x'; DYN_PINGPPONG_CMD];
        let error = pp
            .sendn(&mut io, &huge)
            .expect_err("the ceiling refuses the command");
        assert_eq!(error.code(), CURLcode::TooLarge);
        assert!(io.offered.is_empty());
        // One byte short of the ceiling still has to leave room for the two
        // terminator bytes and the C's zero byte, so it is refused too; three
        // bytes short is the largest command that fits.
        let (mut pp, mut io, _ops) = engine();
        let fits = vec![b'x'; DYN_PINGPPONG_CMD - 3];
        pp.sendn(&mut io, &fits).expect("the largest command fits");
        assert_eq!(io.wire.len(), DYN_PINGPPONG_CMD - 1);
    }

    /// A transport failure other than a would-block travels out unchanged, and
    /// nothing is traced.
    #[test]
    fn a_failing_send_propagates_the_transport_error() {
        let (mut pp, mut io, _ops) = engine();
        io.script_writes([WriteStep::Fail(CURLcode::SendError)]);
        let error = pp
            .sendf(&mut io, format_args!("NOOP"))
            .expect_err("the send fails");
        assert_eq!(error.code(), CURLcode::SendError);
        assert!(io.debug_log.is_empty());
        // `pending_resp` was set before the attempt, as the C sets it.
        assert!(pp.pending_resp());
    }

    /// A second command while one is half-sent is refused, because it would
    /// splice two commands on the wire.
    #[test]
    fn a_second_command_while_one_is_half_sent_is_refused() {
        let (mut pp, mut io, _ops) = engine();
        io.script_writes([WriteStep::Limit(2)]);
        pp.sendf(&mut io, format_args!("NOOP"))
            .expect("the short write succeeds");
        assert!(pp.needs_flush());

        // The debug assertion fires in a debug build, so the checked path is
        // reached through the release-shaped state instead: clear the assert's
        // trigger but leave the one this test is about.
        let error =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pp.sendf(&mut io, format_args!("QUIT"))
            }));
        match error {
            // A debug build stops at the assertion, which is the C's
            // `DEBUGASSERT`.
            Err(_) => {
                // Read through a binding: `assert!(cfg!(..))` is a constant
                // assertion, which clippy rejects and rightly so.
                let debug_build = cfg!(debug_assertions);
                assert!(debug_build, "only a debug build has the assertion");
            }
            // A release build reports it, which the C does not do at all.
            Ok(result) => {
                let error = result.expect_err("the state is refused");
                assert_eq!(error.code(), CURLcode::SendError);
            }
        }
        // Either way the wire holds one truncated command and no splice.
        assert_eq!(io.wire, b"NO");
    }

    // -- the response deadline ---------------------------------------------

    /// With no option set and no time elapsed, a response has the full minute.
    #[test]
    fn state_timeout_defaults_to_a_minute() {
        let (pp, io, _ops) = engine();
        assert_eq!(pp.state_timeout(&io), 60_000);
    }

    /// `CURLOPT_SERVER_RESPONSE_TIMEOUT` replaces the default outright.
    #[test]
    fn state_timeout_honours_the_configured_response_timeout() {
        let (pp, mut io, _ops) = engine();
        io.server_response_timeout_ms = 4_000;
        assert_eq!(pp.state_timeout(&io), 4_000);
    }

    /// Elapsed time comes off the budget, and it is the INJECTED clock that
    /// measures it.
    #[test]
    fn state_timeout_subtracts_the_elapsed_time() {
        let (pp, io, _ops) = engine();
        let clock = io.clock_handle();

        clock.advance(Duration::from_millis(1_500));
        assert_eq!(pp.state_timeout(&io), 58_500);

        clock.advance(Duration::from_millis(58_499));
        assert_eq!(pp.state_timeout(&io), 1);

        // Exactly expired is zero, and the C's own contract says zero has
        // already triggered.
        clock.advance(Duration::from_millis(1));
        assert_eq!(pp.state_timeout(&io), 0);

        // And past it, negative rather than wrapped.
        clock.advance(Duration::from_secs(5));
        assert_eq!(pp.state_timeout(&io), -5_000);
    }

    /// A transfer timeout of zero means "no timeout applies", not "no time
    /// left".
    #[test]
    fn a_zero_transfer_timeout_does_not_apply() {
        let (pp, mut io, _ops) = engine();
        io.timeleft_ms = 0;
        assert_eq!(pp.state_timeout(&io), 60_000);
    }

    /// The nearer of the two deadlines wins, in both directions.
    #[test]
    fn the_shorter_nonzero_transfer_timeout_wins() {
        let (pp, mut io, _ops) = engine();

        io.timeleft_ms = 2_500;
        assert_eq!(pp.state_timeout(&io), 2_500);

        // Further away than the response budget, so the response budget wins.
        io.timeleft_ms = 90_000;
        assert_eq!(pp.state_timeout(&io), 60_000);

        // Equal is NOT shorter: the C's test is `<`, so the response budget
        // stands.
        io.timeleft_ms = 60_000;
        assert_eq!(pp.state_timeout(&io), 60_000);

        // A transfer whose deadline has passed reports negative, and negative
        // is smaller than anything the response budget can be.
        io.timeleft_ms = -10;
        assert_eq!(pp.state_timeout(&io), -10);
    }

    /// The response deadline is measured from the last command, not from the
    /// connection: a restamp gives the next response its own full budget.
    #[test]
    fn each_response_gets_its_own_budget() {
        let (mut pp, mut io, _ops) = engine();
        let clock = io.clock_handle();

        clock.advance(Duration::from_secs(50));
        assert_eq!(pp.state_timeout(&io), 10_000);

        // A command goes out and is fully written, which restamps.
        pp.sendf(&mut io, format_args!("NOOP"))
            .expect("the command is sent");
        assert_eq!(pp.state_timeout(&io), 60_000);
    }

    // -- the readiness cadence ---------------------------------------------

    /// An expired response deadline reports the C's text and code, and never
    /// reaches the state machine.
    #[test]
    fn statemach_reports_an_expired_response_deadline() {
        let (mut pp, mut io, mut ops) = engine();
        let clock = io.clock_handle();
        clock.advance(Duration::from_secs(60));

        let error = drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect_err("the deadline has passed");

        assert_eq!(error.code(), CURLcode::OperationTimedout);
        assert_eq!(error.message(), "server response timeout");
        assert_eq!(io.failures, vec!["server response timeout".to_string()]);
        assert_eq!(ops.steps, 0);
        assert!(io.waits.is_empty(), "nothing was waited on");
    }

    /// A blocking step waits in one-second intervals, clamped down to whatever
    /// the deadline still allows.
    #[test]
    fn a_blocking_wait_uses_one_second_intervals_clamped_to_the_deadline() {
        let (mut pp, mut io, mut ops) = engine();
        drive(pp.statemach(&mut io, &mut ops, true, false))
            .expect("nothing ready is not a failure");
        assert_eq!(io.waits, vec![(7, PollAction::IN, 1000)]);

        // With less than a second left, the interval is the remainder.
        let (mut pp, mut io, mut ops) = engine();
        let clock = io.clock_handle();
        clock.advance(Duration::from_millis(59_750));
        drive(pp.statemach(&mut io, &mut ops, true, false))
            .expect("nothing ready is not a failure");
        assert_eq!(io.waits, vec![(7, PollAction::IN, 250)]);
    }

    /// A non-blocking step asks whether the socket is ready right now.
    #[test]
    fn a_nonblocking_wait_is_immediate_and_skips_the_progress_check() {
        let (mut pp, mut io, mut ops) = engine();
        drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect("nothing ready is not a failure");
        assert_eq!(io.waits, vec![(7, PollAction::IN, 0)]);
        assert_eq!(
            io.pgrs_calls, 0,
            "the C checks progress only when blocking"
        );
    }

    /// A half-sent command turns the wait around: writability, not
    /// readability.
    #[test]
    fn a_half_sent_command_waits_to_write() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_writes([WriteStep::Limit(1)]);
        pp.sendf(&mut io, format_args!("NOOP"))
            .expect("the short write succeeds");

        drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect("nothing ready is not a failure");
        assert_eq!(io.waits, vec![(7, PollAction::OUT, 0)]);
    }

    /// Data pending on the control connection short-circuits the wait
    /// entirely.
    #[test]
    fn pending_connection_data_short_circuits_the_wait() {
        let (mut pp, mut io, mut ops) = engine();
        io.data_pending = true;

        drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect("the state machine ran");

        assert!(io.waits.is_empty(), "no wait was needed");
        assert_eq!(ops.steps, 1);
    }

    /// A non-zero overflow means a complete line is already cached, which is
    /// the second short-circuit -- and it is reached without asking the
    /// buffered-filter question, because the C tests overflow first.
    #[test]
    fn a_cached_overflow_short_circuits_the_wait() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 ready\r\n331 more\r\n")]);
        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the first reply is read");
        assert!(pp.overflow() > 0);
        io.events.clear();
        io.waits.clear();

        drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect("the state machine ran");

        assert!(io.waits.is_empty());
        assert_eq!(io.event_index("buffered_data_pending"), None);
        assert_eq!(ops.steps, 1);
        assert_eq!(
            ops.saw_moredata,
            Some(true),
            "the callback can see the cached reply through the engine it was \
             handed"
        );
    }

    /// The third short-circuit is the buffered-filter question, and it is asked
    /// only once nothing remains to send.
    #[test]
    fn a_buffering_filter_short_circuits_the_wait_once_the_send_has_drained() {
        let (mut pp, mut io, mut ops) = engine();
        io.buffered_pending = true;

        drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect("the state machine ran");

        assert!(io.waits.is_empty());
        assert!(io.event_index("buffered_data_pending").is_some());
        assert_eq!(ops.steps, 1);

        // With a command half-sent the question is not asked at all, because
        // the C guards it with `!pp->sendleft`.
        let (mut pp, mut io, mut ops) = engine();
        io.buffered_pending = true;
        io.script_writes([WriteStep::Limit(1)]);
        pp.sendf(&mut io, format_args!("NOOP"))
            .expect("the short write succeeds");
        io.events.clear();

        drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect("nothing ready is not a failure");
        assert_eq!(io.event_index("buffered_data_pending"), None);
        assert_eq!(io.waits.len(), 1);
        assert_eq!(ops.steps, 0);
    }

    /// A ready socket runs the state machine, and its result is returned
    /// unchanged -- including a failure.
    #[test]
    fn readiness_runs_the_state_machine_and_returns_its_result() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_readiness([Ok(1)]);
        drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect("the state machine ran");
        assert_eq!(ops.steps, 1);

        let (mut pp, mut io, mut ops) = engine();
        io.script_readiness([Ok(4)]);
        ops.outcome = Err(CURLcode::FtpWeirdPassReply);
        let error = drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect_err("the state machine failed");
        assert_eq!(error.code(), CURLcode::FtpWeirdPassReply);
        assert_eq!(ops.steps, 1);
    }

    /// A failed wait reports the C's text and its historical
    /// `CURLE_OUT_OF_MEMORY`.
    #[test]
    fn a_failed_wait_reports_out_of_memory() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_readiness([Err(CURLcode::BadFunctionArgument)]);

        let error = drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect_err("the wait failed");

        // Transcribed as found: a failed poll is CURLE_OUT_OF_MEMORY in curl
        // 8.x, and an application comparing against that constant must keep
        // matching.
        assert_eq!(error.code(), CURLcode::OutOfMemory);
        assert_eq!(error.message(), "select/poll error");
        assert_eq!(io.failures, vec!["select/poll error".to_string()]);
        assert_eq!(ops.steps, 0);
    }

    /// Nothing ready while disconnecting ends the wait; nothing ready
    /// otherwise is a success with nothing done.
    #[test]
    fn nothing_ready_depends_on_whether_the_connection_is_going_away() {
        let (mut pp, mut io, mut ops) = engine();
        let error = drive(pp.statemach(&mut io, &mut ops, false, true))
            .expect_err("a silent server ends a disconnect");
        assert_eq!(error.code(), CURLcode::OperationTimedout);
        // The C emits no message on this path, and neither does this.
        assert!(io.failures.is_empty());
        assert_eq!(error.message(), CURLcode::OperationTimedout.message());
        assert_eq!(ops.steps, 0);

        let (mut pp, mut io, mut ops) = engine();
        drive(pp.statemach(&mut io, &mut ops, false, false))
            .expect("come back later");
        assert_eq!(ops.steps, 0);
    }

    /// A cancelled transfer reports the cancellation, ahead of both the wait
    /// verdict and the state machine.
    #[test]
    fn a_blocking_step_propagates_progress_cancellation_first() {
        let (mut pp, mut io, mut ops) = engine();
        io.pgrs_fails = Some(CURLcode::AbortedByCallback);
        io.script_readiness([Ok(1)]);

        let error = drive(pp.statemach(&mut io, &mut ops, true, false))
            .expect_err("the callback refused");

        assert_eq!(error.code(), CURLcode::AbortedByCallback);
        assert_eq!(io.pgrs_calls, 1);
        assert_eq!(ops.steps, 0, "the state machine never ran");

        // Even when the wait itself failed, the progress error is the one
        // reported -- the C checks progress first.
        let (mut pp, mut io, mut ops) = engine();
        io.pgrs_fails = Some(CURLcode::AbortedByCallback);
        io.script_readiness([Err(CURLcode::BadFunctionArgument)]);
        let error = drive(pp.statemach(&mut io, &mut ops, true, false))
            .expect_err("the callback refused");
        assert_eq!(error.code(), CURLcode::AbortedByCallback);
    }

    /// The progress check runs AFTER the wait, so a blocking step that waited
    /// still gets checked.
    #[test]
    fn the_progress_check_follows_the_wait() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_readiness([Ok(1)]);
        drive(pp.statemach(&mut io, &mut ops, true, false))
            .expect("the state machine ran");

        let wait = io.event_index("wait_ready").expect("a wait happened");
        let check = io.event_index("pgrs_check").expect("progress was checked");
        let step = io.event_index("statemachine").expect("the machine ran");
        assert!(wait < check, "the C waits first");
        assert!(check < step, "and checks before it steps");
    }

    // -- reading a response ------------------------------------------------

    /// One complete reply: the line reaches both consumers with its LF, the
    /// code and size come back, and the line is left in the buffer for the
    /// protocol's parser.
    #[test]
    fn a_single_line_reply_is_framed_traced_written_and_retained() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 hello\r\n")]);

        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the reply is read");

        assert_eq!(outcome.code, 220);
        assert_eq!(outcome.size, 11);
        assert!(outcome.is_complete());

        // The LF is part of the line and the CR is an ordinary byte before it.
        assert_eq!(
            io.debug_log,
            vec![(InfoType::HeaderIn, b"220 hello\r\n".to_vec())]
        );
        assert_eq!(
            io.client_writes,
            vec![(ClientWriteFlags::INFO, b"220 hello\r\n".to_vec())]
        );
        assert_eq!(ops.lines, vec![b"220 hello\r\n".to_vec()]);

        // The final line stays at the FRONT of the receive buffer, which is
        // where `lib/ftp.c` reads the code out of.
        assert_eq!(pp.recvbuf(), b"220 hello\r\n");
        assert_eq!(pp.nfinal(), 11);
        assert_eq!(pp.overflow(), 0);
        // The size was reported and the counter restarted.
        assert_eq!(pp.nread_resp(), 0);
        assert!(!pp.pending_resp());
        assert_eq!(io.header_bytes, 11);
        assert!(!pp.moredata(), "only the final line is cached");
    }

    /// The trace comes before the client write, and the end-of-response
    /// question comes after both.
    #[test]
    fn a_line_is_traced_then_written_then_judged() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 hello\r\n")]);
        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the reply is read");

        let debug = io.event_index("debug:header_in").expect("traced");
        let write = io.event_index("client_write").expect("written");
        assert!(
            debug < write,
            "CURLINFO_HEADER_IN precedes CLIENTWRITE_INFO"
        );
        // `end_of_response` saw the line, so it ran after the two deliveries:
        // the write is recorded before the judgement in the same iteration.
        assert_eq!(ops.lines.len(), 1);
    }

    /// A multi-line reply: every line is delivered, only the last ends it, and
    /// the reported size counts them all.
    #[test]
    fn a_continuation_reply_delivers_every_line_and_ends_on_the_last() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220-first\r\n220-second\r\n220 last\r\n")]);

        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the reply is read");

        assert_eq!(outcome.code, 220);
        assert_eq!(outcome.size, 33);
        assert_eq!(
            ops.lines,
            vec![
                b"220-first\r\n".to_vec(),
                b"220-second\r\n".to_vec(),
                b"220 last\r\n".to_vec(),
            ]
        );
        assert_eq!(io.client_writes.len(), 3);
        assert_eq!(io.debug_log.len(), 3);
        // Only the final line is left, and the consumed continuations are gone.
        assert_eq!(pp.recvbuf(), b"220 last\r\n");
        assert_eq!(pp.nfinal(), 10);
        assert_eq!(pp.overflow(), 0);
        assert_eq!(io.header_bytes, 33);
    }

    /// A line with no CR is still a line: framing is on the LF alone.
    #[test]
    fn framing_is_on_the_line_feed_alone() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 bare\n")]);

        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the reply is read");

        assert_eq!(outcome.code, 220);
        assert_eq!(ops.lines, vec![b"220 bare\n".to_vec()]);
        assert_eq!(pp.nfinal(), 9);
    }

    /// A stray CR inside a line is delivered as part of it, because only the LF
    /// terminates.
    #[test]
    fn an_interior_carriage_return_is_an_ordinary_byte() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 od\rd\r\n")]);

        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the reply is read");

        assert_eq!(ops.lines, vec![b"220 od\rd\r\n".to_vec()]);
        assert_eq!(io.client_writes[0].1, b"220 od\rd\r\n".to_vec());
    }

    /// Two replies in one read: the first ends the framing and the second is
    /// counted as overflow, then consumed by the next call without another
    /// read.
    #[test]
    fn a_second_reply_in_one_read_becomes_the_overflow() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 first\r\n331 second\r\n")]);

        let first = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the first reply is read");

        assert_eq!(first.code, 220);
        assert_eq!(first.size, 23, "every byte read counts towards the reply");
        assert_eq!(pp.nfinal(), 11);
        assert_eq!(pp.overflow(), 12);
        assert_eq!(pp.recvbuf(), b"220 first\r\n331 second\r\n");
        assert!(pp.moredata(), "there is more than the final line cached");
        assert_eq!(io.read_calls, 1);

        // The next call ditches the retained final line, skips the transport
        // because the overflow is non-zero, and frames the second reply.
        let second = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the second reply is read");

        assert_eq!(second.code, 331);
        assert_eq!(second.size, 0, "no new bytes were read for it");
        assert_eq!(io.read_calls, 1, "the cached bytes needed no read");
        assert_eq!(pp.recvbuf(), b"331 second\r\n");
        assert_eq!(pp.nfinal(), 12);
        assert_eq!(pp.overflow(), 0);
        assert!(!pp.moredata());
    }

    /// A reply split across two reads is assembled, and the incomplete line is
    /// retained with no overflow.
    #[test]
    fn a_partial_line_is_retained_with_no_overflow() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 hel")]);

        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("a partial line is not a failure");

        assert!(!outcome.is_complete());
        assert_eq!(outcome.size, 0);
        assert_eq!(pp.overflow(), 0, "without a newline there is no overflow");
        assert_eq!(pp.nfinal(), 0);
        assert_eq!(pp.recvbuf(), b"220 hel", "the partial line is kept");
        assert_eq!(pp.nread_resp(), 7);
        assert!(ops.lines.is_empty(), "no line was complete");
        assert!(io.client_writes.is_empty());
        // The response is finished being waited for only when a final line
        // arrives, but the C clears `pending_resp` at every normal exit.
        assert!(!pp.pending_resp());

        // The rest arrives and completes it.
        io.script_reads([reply(b"lo\r\n")]);
        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the reply completes");
        assert_eq!(outcome.code, 220);
        assert_eq!(outcome.size, 11, "both reads counted");
        assert_eq!(ops.lines, vec![b"220 hello\r\n".to_vec()]);
        assert_eq!(io.header_bytes, 11);
    }

    /// A read of exactly 900 bytes makes the C try again, and a read of one
    /// more does not -- the boundary is the buffer size, exactly.
    #[test]
    fn the_outer_loop_repeats_only_on_a_full_buffer() {
        // 900 bytes with no newline: one full read, then a second that finds
        // nothing and would block.
        let filler = vec![b'x'; RESP_BUFFER];
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([ReadStep::Bytes(filler.clone())]);
        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("a full read is not a failure");
        assert_eq!(io.read_calls, 2, "900 bytes is evidence of more");
        assert_eq!(pp.nread_resp(), RESP_BUFFER);
        assert_eq!(io.header_bytes, 900);

        // 899 bytes: the loop stops after one read.
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([ReadStep::Bytes(vec![b'x'; RESP_BUFFER - 1])]);
        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("a short read is not a failure");
        assert_eq!(io.read_calls, 1, "899 bytes ends the loop");
        assert_eq!(pp.nread_resp(), RESP_BUFFER - 1);

        // 901 bytes offered: the first read takes 900 and the second takes the
        // remaining one, which ends the loop.
        let (mut pp, mut io, mut ops) = engine();
        let mut oversized = filler.clone();
        oversized.push(b'y');
        io.script_reads([ReadStep::Bytes(oversized)]);
        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the split read is not a failure");
        assert_eq!(io.read_calls, 2);
        assert_eq!(pp.nread_resp(), RESP_BUFFER + 1);
        assert_eq!(io.header_bytes, 901);
        assert_eq!(pp.recvbuf().len(), RESP_BUFFER + 1);

        // 1800 bytes: two full reads, then a third that would block.
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([
            ReadStep::Bytes(filler.clone()),
            ReadStep::Bytes(filler.clone()),
        ]);
        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("two full reads are not a failure");
        assert_eq!(io.read_calls, 3);
        assert_eq!(pp.nread_resp(), 2 * RESP_BUFFER);
        assert_eq!(io.header_bytes, 1800);
    }

    /// A reply that arrives at the end of a full buffer is framed in the second
    /// pass, which is what the outer loop exists for.
    #[test]
    fn a_reply_completed_by_a_second_read_ends_the_loop_at_the_final_line() {
        let head = vec![b'x'; RESP_BUFFER - 2];
        let mut first = head.clone();
        first.extend_from_slice(b"\r\n");
        assert_eq!(first.len(), RESP_BUFFER);

        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([ReadStep::Bytes(first), reply(b"226 done\r\n")]);

        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the reply is read");

        assert_eq!(outcome.code, 226);
        assert_eq!(outcome.size, RESP_BUFFER + 10);
        assert_eq!(io.read_calls, 2);
        assert_eq!(ops.lines.len(), 2, "the filler line, then the final one");
        assert_eq!(pp.recvbuf(), b"226 done\r\n");
    }

    /// A would-block read reports success with nothing done, and leaves the
    /// response pending -- which is what tells the caller to come back.
    #[test]
    fn a_would_block_read_leaves_the_response_pending() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([ReadStep::Again]);
        assert!(pp.pending_resp());

        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("a would-block read is not a failure");

        assert_eq!(outcome, PpResponse::PENDING);
        assert!(
            pp.pending_resp(),
            "the C's early return bypasses the assignment"
        );
        assert!(pp.recvbuf().is_empty());
        assert_eq!(io.read_calls, 1);
    }

    /// A read of zero bytes is a closed connection, reported with the C's exact
    /// message and the errno the environment supplies.
    #[test]
    fn a_zero_byte_read_is_a_receive_error_naming_the_errno() {
        let (mut pp, mut io, mut ops) = engine();
        io.errno = 104;
        io.script_reads([ReadStep::Closed]);

        let error = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect_err("a closed connection is a failure");

        assert_eq!(error.code(), CURLcode::RecvError);
        assert_eq!(error.message(), "response reading failed (errno: 104)");
        assert_eq!(
            io.failures,
            vec!["response reading failed (errno: 104)".to_string()]
        );
        assert!(pp.pending_resp(), "the early return leaves it set");
    }

    /// Any other transport failure travels out unchanged and immediately.
    #[test]
    fn a_failing_read_propagates_the_transport_error() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([ReadStep::Fail(CURLcode::RecvError)]);

        let error = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect_err("the read fails");

        assert_eq!(error.code(), CURLcode::RecvError);
        assert!(io.failures.is_empty(), "the C writes no message here");
        assert!(pp.pending_resp());
    }

    /// A transport that claims to have filled more than the buffer holds is
    /// refused rather than read out of bounds.
    #[test]
    fn an_overreporting_read_is_refused() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([ReadStep::Overreport]);

        let error = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect_err("an impossible count is refused");

        assert_eq!(error.code(), CURLcode::RecvError);
        assert!(pp.recvbuf().is_empty());
    }

    /// A writer chain that refuses stops the framing where it stands, and the
    /// code is the chain's.
    #[test]
    fn a_refusing_client_writer_stops_the_framing() {
        let (mut pp, mut io, mut ops) = engine();
        io.client_write_fails = Some(CURLcode::WriteError);
        io.script_reads([reply(b"220-first\r\n220 last\r\n")]);

        let error = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect_err("the writer refused");

        assert_eq!(error.code(), CURLcode::WriteError);
        // The first line was traced and offered, and nothing was judged.
        assert_eq!(io.debug_log.len(), 1);
        assert_eq!(io.client_writes.len(), 1);
        assert!(ops.lines.is_empty());
        // Nothing was consumed, so a retry sees the same bytes.
        assert_eq!(pp.recvbuf(), b"220-first\r\n220 last\r\n");
        assert!(pp.pending_resp());
    }

    /// A protocol that never recognises a final line keeps consuming lines
    /// until the buffer is empty, and reports nothing.
    #[test]
    fn a_reply_with_no_final_line_consumes_everything_and_reports_nothing() {
        let (mut pp, mut io, mut ops) = engine();
        ops.force_final = Some(false);
        io.script_reads([reply(b"220-one\r\n220-two\r\n")]);

        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("nothing final is not a failure");

        assert_eq!(outcome, PpResponse::PENDING);
        assert_eq!(ops.lines.len(), 2);
        assert!(pp.recvbuf().is_empty(), "both lines were consumed");
        assert_eq!(pp.nfinal(), 0);
        assert_eq!(pp.overflow(), 0);
        assert_eq!(pp.nread_resp(), 18, "the bytes still count");
    }

    /// The receive buffer's ceiling is the ping-pong one, and crossing it
    /// reports the dynbuf's own code.
    #[test]
    fn a_reply_past_the_buffer_ceiling_is_refused() {
        let (mut pp, mut io, mut ops) = engine();
        ops.force_final = Some(false);
        // Enough 900-byte reads with no newline to cross 64 KiB. Each one is
        // exactly the buffer size, so the outer loop keeps going.
        let filler = vec![b'x'; RESP_BUFFER];
        let steps: Vec<ReadStep> =
            (0..80).map(|_| ReadStep::Bytes(filler.clone())).collect();
        io.script_reads(steps);

        let error = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect_err("the ceiling refuses the reply");

        assert_eq!(error.code(), CURLcode::TooLarge);
    }

    /// The retained final line is discarded by the NEXT call, at the top of its
    /// first iteration, and only then.
    #[test]
    fn the_next_call_trims_the_retained_final_line() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 first\r\n"), reply(b"250 second\r\n")]);

        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the first reply is read");
        assert_eq!(pp.recvbuf(), b"220 first\r\n");
        assert_eq!(pp.nfinal(), 11);

        let second = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the second reply is read");

        assert_eq!(second.code, 250);
        assert_eq!(second.size, 12, "only the second reply's bytes");
        assert_eq!(pp.recvbuf(), b"250 second\r\n");
        assert_eq!(pp.nfinal(), 12);
    }

    // -- readiness registration and cached-data queries --------------------

    /// The pollset asks to read normally and to write while a command is
    /// half-sent, on the control socket and nothing else.
    #[test]
    fn the_pollset_direction_follows_the_pending_send() {
        let (mut pp, mut io, _ops) = engine();
        let mut ps = EasyPollset::new();

        assert_eq!(pp.pollset(&mut io, &mut ps, None), Ok(()));
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.action_of(7), PollAction::IN);

        io.script_writes([WriteStep::Limit(1)]);
        pp.sendf(&mut io, format_args!("NOOP"))
            .expect("the short write succeeds");
        let mut ps = EasyPollset::new();
        assert_eq!(pp.pollset(&mut io, &mut ps, None), Ok(()));
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.action_of(7), PollAction::OUT);
    }

    /// A socket that is not a descriptor is refused by the pollset, and the
    /// code is the one the C returns.
    #[test]
    fn the_pollset_refuses_a_socket_that_is_not_a_descriptor() {
        let (pp, mut io, _ops) = engine();
        io.socket = CURL_SOCKET_BAD;
        let mut ps = EasyPollset::new();

        // The socket is handed on unchanged, so what happens next is the
        // pollset's own behaviour and the C's: a debug build stops at the
        // `DEBUGASSERT(VALID_SOCK(sock))` of `lib/select.c:571`, and a release
        // build returns the `CURLE_BAD_FUNCTION_ARGUMENT` of `:573`. Both are
        // asserted so that neither build silently loses the check.
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pp.pollset(&mut io, &mut ps, None)
            }));
        match outcome {
            Err(_) => {
                // Read through a binding: `assert!(cfg!(..))` is a constant
                // assertion, which clippy rejects and rightly so.
                let debug_build = cfg!(debug_assertions);
                assert!(debug_build, "only a debug build has the assertion");
            }
            Ok(result) => {
                assert_eq!(result, Err(CURLcode::BadFunctionArgument));
            }
        }
        assert!(ps.is_empty(), "nothing was registered either way");
    }

    /// `Curl_pp_moredata` in all three of its states.
    #[test]
    fn moredata_needs_a_drained_send_and_more_than_the_final_line() {
        let (mut pp, mut io, mut ops) = engine();
        io.script_reads([reply(b"220 first\r\n331 second\r\n")]);
        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the first reply is read");

        // Cached beyond the final line, nothing to send: there is more.
        assert!(pp.moredata());

        // With a command half-sent there is not, whatever is cached.
        io.script_writes([WriteStep::Limit(1)]);
        pp.sendf(&mut io, format_args!("NOOP"))
            .expect("the short write succeeds");
        assert!(pp.sendleft() > 0);
        assert!(!pp.moredata());
        pp.flushsend(&mut io).expect("the rest is sent");
        assert!(pp.moredata());

        // And with only the final line cached, there is not.
        pp.readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the second reply is read");
        assert_eq!(pp.recvbuf().len(), pp.nfinal());
        assert!(!pp.moredata());
    }

    /// `Curl_pp_needs_flush` is exactly `sendleft > 0`.
    #[test]
    fn needs_flush_is_exactly_a_nonzero_sendleft() {
        let (mut pp, mut io, _ops) = engine();
        assert!(!pp.needs_flush());
        io.script_writes([WriteStep::Limit(1)]);
        pp.sendf(&mut io, format_args!("NOOP"))
            .expect("the short write succeeds");
        assert!(pp.needs_flush());
        assert_eq!(pp.sendleft(), 5);
        pp.flushsend(&mut io).expect("the rest is sent");
        assert!(!pp.needs_flush());
        assert_eq!(pp.sendleft(), 0);
    }

    /// `pending_resp` is writable, because `lib/ftp.c:732` writes it.
    #[test]
    fn pending_resp_can_be_cleared_by_the_protocol() {
        let (mut pp, _io, _ops) = engine();
        assert!(pp.pending_resp());
        pp.set_pending_resp(false);
        assert!(!pp.pending_resp());
        pp.set_pending_resp(true);
        assert!(pp.pending_resp());
    }

    // -- object safety -----------------------------------------------------

    /// The callback trait is usable behind `&mut dyn`, which is what the C's
    /// function pointers were and what pattern P1 requires.
    #[test]
    fn the_callbacks_are_reachable_through_a_trait_object() {
        let (mut pp, mut io, mut concrete) = engine();
        io.script_reads([reply(b"220 hello\r\n")]);
        io.script_readiness([Ok(1)]);

        // Erased. If either method were an `async fn` or returned
        // `impl Future`, this line would not compile at all -- which is the
        // point of it.
        let ops: &mut dyn PingPongOps<TestIo> = &mut concrete;

        let outcome = pp
            .readresp(&mut io, ops, SocketIndex::First)
            .expect("the reply is read through the trait object");
        assert_eq!(outcome.code, 220);

        drive(pp.statemach(&mut io, ops, false, false))
            .expect("the state machine ran through the trait object");
        assert_eq!(concrete.steps, 1);
    }

    /// The environment seam is usable behind `&mut dyn` too, which is what lets
    /// a caller choose dynamic dispatch for it.
    #[test]
    fn the_environment_is_reachable_through_a_trait_object() {
        let mut concrete = TestIo::new();
        concrete.script_reads([reply(b"220 hello\r\n")]);
        let mut pp = PingPong::new();
        pp.init(concrete.clock().now());
        let mut ops = TestOpsDyn::default();

        let io: &mut dyn PingPongIo = &mut concrete;
        let outcome = pp
            .readresp(io, &mut ops, SocketIndex::First)
            .expect("the reply is read through the trait object");
        assert_eq!(outcome.code, 220);
        assert_eq!(pp.state_timeout(io), 60_000);
        pp.sendf(io, format_args!("NOOP"))
            .expect("a command is sent through the trait object");
        assert_eq!(concrete.wire, b"NOOP\r\n");
    }

    /// The callbacks over an ERASED environment, for
    /// [`the_environment_is_reachable_through_a_trait_object`].
    ///
    /// A separate type rather than a second `impl` on [`TestOps`],
    /// because the only method that mentions the environment is the state
    /// machine and this one does not need it: what is being proved is that
    /// `readresp` and `sendf` accept `&mut dyn PingPongIo`.
    #[derive(Debug, Default)]
    struct TestOpsDyn {
        steps: usize,
    }

    impl PingPongOps<dyn PingPongIo + '_> for TestOpsDyn {
        fn statemachine<'a>(
            &'a mut self,
            _pp: &'a mut PingPong,
            _io: &'a mut (dyn PingPongIo + '_),
        ) -> ProtoFuture<'a, ()> {
            self.steps += 1;
            Box::pin(core::future::ready(Ok(())))
        }

        fn end_of_response(&mut self, line: &[u8], code: &mut i32) -> bool {
            if line.get(3) == Some(&b' ') {
                *code = 220;
                return true;
            }
            false
        }
    }

    // -- the default seam bodies, over a real filter chain ------------------

    /// What the in-memory transport below has seen and what it will do next.
    #[derive(Debug, Default)]
    struct TransportState {
        /// Every byte a send accepted, in order. This is the wire.
        wire: Vec<u8>,
        /// The most bytes one send will accept. [`None`] accepts everything.
        write_limit: Option<usize>,
        /// What a receive hands up, in order.
        reads: VecDeque<Vec<u8>>,
        /// What `data_pending` answers.
        pending: bool,
    }

    /// A bottom-of-chain filter with no descriptor, following the crate's own
    /// precedent -- `MemFilter` in `conn/happy_eyeballs.rs`, `Below` in
    /// `tls/mod.rs`, `TestFilter` in `conn/shutdown.rs`.
    #[derive(Debug)]
    struct MemTransport {
        base: FilterBase,
        state: Arc<Mutex<TransportState>>,
        socket: Socket,
    }

    impl MemTransport {
        fn new(state: Arc<Mutex<TransportState>>, socket: Socket) -> Self {
            let mut base = FilterBase::new(SocketIndex::First);
            // Connected from the start: `FilterChain::send` and `recv` reach
            // the first CONNECTED filter, as `Curl_cf_send` does.
            base.set_connected(true);
            Self {
                base,
                state,
                socket,
            }
        }

        fn locked(&self) -> std::sync::MutexGuard<'_, TransportState> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl ConnFilter for MemTransport {
        fn trace_name(&self) -> &'static str {
            "MEM"
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn connect(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            Ok(true)
        }

        fn close(&mut self, _cx: &mut CallCtx<'_, '_>) {}

        fn send(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            buf: &[u8],
            _eos: bool,
        ) -> CurlResult<usize> {
            let mut state = self.locked();
            let taken = state.write_limit.unwrap_or(buf.len()).min(buf.len());
            state.wire.extend_from_slice(&buf[..taken]);
            Ok(taken)
        }

        fn recv(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            buf: &mut [u8],
        ) -> CurlResult<usize> {
            let mut state = self.locked();
            match state.reads.pop_front() {
                None => Err(Error::new(CURLcode::Again)),
                Some(bytes) => {
                    let taken = bytes.len().min(buf.len());
                    buf[..taken].copy_from_slice(&bytes[..taken]);
                    if taken < bytes.len() {
                        state.reads.push_front(bytes[taken..].to_vec());
                    }
                    Ok(taken)
                }
            }
        }

        fn data_pending(&mut self, _cx: &CallCtx<'_, '_>) -> bool {
            self.locked().pending
        }

        fn query(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            query: CfQuery,
        ) -> CurlResult<CfQueryValue> {
            match query {
                CfQuery::Socket => Ok(CfQueryValue::Socket(self.socket)),
                _ => Err(Error::new(CURLcode::UnknownOption)),
            }
        }
    }

    /// An environment with a REAL filter chain and none of the transport
    /// methods overridden, so the seam's default bodies are what run.
    #[derive(Debug)]
    struct ChainIo {
        chains: FilterChains,
        clock: Arc<TestClock>,
        debug_log: Vec<(InfoType, Vec<u8>)>,
        client_writes: Vec<Vec<u8>>,
        failures: Vec<String>,
        header_bytes: u32,
        connected: bool,
    }

    impl ChainIo {
        fn new(state: Arc<Mutex<TransportState>>, socket: Socket) -> Self {
            let clock = Arc::new(TestClock::new(CurlTime::new(5, 0)));
            let mut chains = FilterChains::new(None);
            let mut cx = CallCtx::new(clock.as_ref());
            chains
                .chain_mut(SocketIndex::First)
                .add(&mut cx, link(MemTransport::new(state, socket)));
            Self {
                chains,
                clock,
                debug_log: Vec::new(),
                client_writes: Vec::new(),
                failures: Vec::new(),
                header_bytes: 0,
                connected: true,
            }
        }
    }

    impl PingPongIo for ChainIo {
        fn has_connection(&self) -> bool {
            self.connected
        }

        fn conn(&mut self) -> Option<ConnAccess<'_>> {
            if !self.connected {
                return None;
            }
            Some(ConnAccess::new(&mut self.chains, self.clock.as_ref()))
        }

        fn clock(&self) -> &dyn Clock {
            self.clock.as_ref()
        }

        fn debug(&mut self, kind: InfoType, payload: &[u8]) {
            self.debug_log.push((kind, payload.to_vec()));
        }

        fn client_write(
            &mut self,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CurlResult<()> {
            assert_eq!(flags, ClientWriteFlags::INFO);
            self.client_writes.push(buf.to_vec());
            Ok(())
        }

        fn failf(&mut self, args: fmt::Arguments<'_>) {
            self.failures.push(args.to_string());
        }

        fn add_header_bytes(&mut self, count: u32) {
            self.header_bytes = self.header_bytes.saturating_add(count);
        }

        fn server_response_timeout_ms(&self) -> TimeDiff {
            0
        }

        fn timeleft_ms(&self) -> TimeDiff {
            0
        }

        fn pgrs_check(&mut self) -> CurlResult<()> {
            Ok(())
        }

        fn sock_errno(&self) -> i32 {
            0
        }
    }

    /// The five defaulted seam methods do reach a real chain: a command lands
    /// on the transport, a reply comes back through it, and the socket and the
    /// pending flag are answered by the filter.
    #[test]
    fn the_default_transport_bodies_reach_a_real_filter_chain() {
        let state = Arc::new(Mutex::new(TransportState {
            reads: VecDeque::from(vec![b"220 chain\r\n".to_vec()]),
            pending: true,
            ..TransportState::default()
        }));
        let mut io = ChainIo::new(Arc::clone(&state), 11);
        let mut ops = TestOpsChain::default();
        let mut pp = PingPong::new();
        pp.init(io.clock().now());

        // The default `socket` goes through the chain's `Socket` query.
        assert_eq!(io.socket(SocketIndex::First), 11);
        // The default `data_pending` goes through the chain.
        assert!(io.data_pending(SocketIndex::First));
        assert!(io.buffered_data_pending(SocketIndex::First));

        // The default `send` reaches the transport, terminator included.
        pp.sendf(&mut io, format_args!("USER anon"))
            .expect("the command is sent through the chain");
        assert_eq!(
            state.lock().expect("the transport state").wire,
            b"USER anon\r\n"
        );
        assert_eq!(pp.sendleft(), 0);

        // The default `recv` reads back through it.
        let outcome = pp
            .readresp(&mut io, &mut ops, SocketIndex::First)
            .expect("the reply is read through the chain");
        assert_eq!(outcome.code, 220);
        assert_eq!(io.client_writes, vec![b"220 chain\r\n".to_vec()]);
        assert_eq!(io.header_bytes, 11);

        // A short write through the chain leaves the same bookkeeping, and the
        // flush resumes at the right byte.
        state.lock().expect("the transport state").write_limit = Some(3);
        pp.sendf(&mut io, format_args!("PWD"))
            .expect("the short write succeeds");
        assert_eq!(pp.sendleft(), 2);
        state.lock().expect("the transport state").write_limit = None;
        pp.flushsend(&mut io).expect("the remainder is sent");
        assert_eq!(
            state.lock().expect("the transport state").wire,
            b"USER anon\r\nPWD\r\n"
        );
    }

    /// Without a connection the default bodies answer the way the C's absent
    /// `conn` does: no descriptor, nothing pending, and a send error.
    #[test]
    fn the_default_transport_bodies_answer_safely_without_a_connection() {
        let state = Arc::new(Mutex::new(TransportState::default()));
        let mut io = ChainIo::new(state, 11);
        io.connected = false;

        assert_eq!(io.socket(SocketIndex::First), CURL_SOCKET_BAD);
        assert!(!io.data_pending(SocketIndex::First));
        assert!(!io.buffered_data_pending(SocketIndex::First));
        assert_eq!(
            io.send(SocketIndex::First, b"x").map_err(|e| e.code()),
            Err(CURLcode::SendError)
        );
        let mut buffer = [0_u8; 4];
        assert_eq!(
            io.recv(SocketIndex::First, &mut buffer)
                .map_err(|error| error.code()),
            Err(CURLcode::RecvError)
        );
    }

    /// The callbacks over [`ChainIo`], for the chain test above.
    #[derive(Debug, Default)]
    struct TestOpsChain {
        steps: usize,
    }

    impl PingPongOps<ChainIo> for TestOpsChain {
        fn statemachine<'a>(
            &'a mut self,
            _pp: &'a mut PingPong,
            _io: &'a mut ChainIo,
        ) -> ProtoFuture<'a, ()> {
            self.steps += 1;
            Box::pin(core::future::ready(Ok(())))
        }

        fn end_of_response(&mut self, line: &[u8], code: &mut i32) -> bool {
            if line.get(3) == Some(&b' ') {
                *code = 220;
                return true;
            }
            false
        }
    }

    // -- this file's own policy --------------------------------------------
    //
    // The gates below read this file from disk and assert properties of it. The
    // crate root's `mod source_policy` already scans every source for `unsafe`,
    // for C scalar widths and for raw strings; these are the ones specific to
    // this module, and they exist here so that a violation names THIS file
    // rather than appearing as one entry in a workspace-wide list.
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
            .join("ftp")
            .join("pingpong.rs");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    }

    /// `line` with its comment tail and every string literal removed.
    ///
    /// The same simplification the crate root's gates make, and necessary for
    /// the same reason: this file DISCUSSES `unsafe`, TLS and wall clocks in
    /// prose, and a scan that could not tell prose from code would report every
    /// paragraph as a violation.
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
    /// at all -- not even in a comment.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_unsafe_and_no_ffi_marker_appears_anywhere() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let names_it = code_only(line)
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|word| word == "unsafe");
            assert!(
                !names_it,
                "line {}: no `unsafe` outside src/ffi/",
                number + 1
            );
            // An `extern "C"` block, a `#[no_mangle]` export or a `libc` path
            // would mean the FFI island had spread into a protocol module.
            // Measured against CODE, because the documentation above discusses
            // all three by name -- which is exactly why `code_only` exists.
            let code = code_only(line);
            for marker in ["no_mangle", "libc", "extern"] {
                assert!(
                    !code.contains(marker),
                    "line {}: {marker} belongs to the FFI island",
                    number + 1
                );
            }
        }
    }

    /// No TLS module is imported and no `tls` feature is named.
    ///
    /// FTPS is this protocol over the crate's unconditional TLS stack, reached
    /// by a filter the connection layer installs -- so the cadence engine has
    /// no business naming the TLS module, and there is no `tls` feature to gate
    /// on in the first place.
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
    /// injected [`Clock`].
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

    /// No trait declares an `async fn` or returns `impl Future`.
    ///
    /// Either would make the trait un-`dyn`-compatible at the declared minimum
    /// Rust version, and both callbacks have to be reachable through
    /// `&mut dyn`.
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
            // A trait body ends at a closing brace in the first column.
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

    /// The production half of this file panics nowhere and unwraps nothing.
    ///
    /// `debug_assert!` is exempt and is the only exemption: it is the C's own
    /// `DEBUGASSERT`, it compiles out of a release build, and every site that
    /// carries one also carries the checked path beside it. The test module is
    /// exempt too, because an assertion that cannot fail the test is not a
    /// test.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_production_half_cannot_panic() {
        let source = own_source();
        let tests_begin = source
            .find("#[cfg(test)]")
            .expect("this file has a test module");
        let production = &source[..tests_begin];

        for (number, line) in production.lines().enumerate() {
            let code = code_only(line);
            for forbidden in [
                "unwrap()",
                "expect(",
                "panic!",
                "unreachable!",
                "todo!",
                "unimplemented!",
                "assert!",
                "assert_eq!",
            ] {
                let hit = code.contains(forbidden)
                    && !code.contains("debug_assert!")
                    && !code.contains("unwrap_or");
                assert!(
                    !hit,
                    "line {}: {forbidden} is panic-based control flow",
                    number + 1
                );
            }
        }
    }

    /// Nothing in this file is gated on the `ftp` feature, because the parent
    /// gates the whole directory.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_file_adds_no_feature_gate_of_its_own() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg") || trimmed.starts_with("#![cfg") {
                assert!(
                    !trimmed.contains("feature ="),
                    "line {}: the parent's `mod ftp` gate is the only one",
                    number + 1
                );
            }
        }
    }

    /// The licence banner is the generic 23-line one, with SPDX on line 21 and
    /// the closer on line 23.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_banner_is_the_measured_twenty_three_lines() {
        let source = own_source();
        let lines: Vec<&str> = source.lines().collect();
        assert!(lines.len() > 23, "the banner is 23 lines and then some");
        assert!(lines[0].starts_with("// /****"), "line 1: {}", lines[0]);
        assert_eq!(
            lines[7].trim(),
            "//  * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al."
        );
        // The tag is assembled from two pieces rather than written whole:
        // `reuse lint` scans a file for every occurrence of the identifier and
        // would read this assertion's trailing punctuation as a second,
        // malformed licence expression. Splitting it keeps the file's single
        // real tag -- line 21 -- the only one there is.
        assert_eq!(
            lines[20].trim(),
            concat!("//  * SPDX-License", "-Identifier: curl")
        );
        assert!(lines[22].trim_end().ends_with("***/"), "line 23 closes it");
    }
}
