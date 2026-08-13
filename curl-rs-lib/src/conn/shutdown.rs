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

// THE LICENCE BANNER ABOVE -- 23 lines, byte-identical to `conn/mod.rs:1-23`,
// `conn/filters.rs:1-23` and `conn/select.rs:1-23`, with its
// `SPDX-License-Identifier` tag on line 21 as every other file in this
// directory has.
//
// `lib/cshutdn.c:8-9` carries TWO copyright holders where `lib/connect.c` and
// `lib/cfilters.c` carry one, and the second is recorded here as a REUSE tag
// rather than as a 24th banner line, so that the banner stays identical to its
// three siblings and its licence tag stays on line 21:
//
// SPDX-FileCopyrightText: Linus Nielsen Feltzing, <linus@haxx.se>

//! The graceful-shutdown queue: connections that are finished but not closed.
//!
//! # What a shutting-down connection is
//!
//! When a transfer finishes with a connection that cannot be reused, curl does
//! not simply close the socket. TLS wants a `close_notify` written and
//! acknowledged, FTP wants a `QUIT` and its reply, and an HTTP/2 session wants
//! a `GOAWAY`. All of that is protocol traffic that must happen AFTER the
//! transfer the application was watching has already completed, so it cannot
//! be driven by that transfer. `lib/conncache.c:220-228` is where the decision
//! is made: try one non-blocking shutdown step, and if that does not finish
//! the job, hand the connection to this queue and let the multi handle drive
//! it to completion in the background.
//!
//! Nothing here is reachable from the C ABI. The queue is `pub(crate)` and so
//! is everything it declares; `crate::multi` owns one and drives it, exactly
//! as `struct Curl_multi` owns `struct cshutdn` (`lib/multihandle.h:147`).
//!
//! # Ownership: a FIFO that owns its connections by value
//!
//! C's queue is `struct Curl_llist list` (`lib/cshutdn.h:55`) initialised with
//! a NULL destructor (`lib/cshutdn.c:324`), which is a deliberate statement
//! that the list does not own what it links: the node lives INSIDE the
//! connection as `conn->cshutdn_node`, and freeing a connection while it is
//! still linked corrupts the list. Ownership is therefore a convention
//! maintained by hand at five call sites.
//!
//! Here the queue is a [`VecDeque`] that owns each [`ShuttingDownConnection`]
//! **by value**, and termination -- [`terminate`] -- **consumes** that value.
//! Double-freeing a connection or re-queueing a terminated one is not a bug
//! this module has to avoid; it is a program that does not compile. There is
//! no `Curl_llist_node`, no intrusive link, and no manual destructor
//! discipline.
//!
//! ## The ordering is FIFO, and that is NOT the pool's policy
//!
//! Additions go to the **tail** (`Curl_llist_append`, `lib/cshutdn.c:420`) and
//! "the oldest" is the **first match scanned from the head**
//! (`cshutdn_destroy_oldest`, `:174-180`). Insertion order is the whole of the
//! ordering: no timestamp is consulted and none is stored.
//!
//! `crate::conn::pool`'s eviction is a different policy and the two must not
//! be unified: the connection pool picks its victim with an order-independent
//! full scan for the greatest idle age. Both are called "oldest" in the C and
//! they mean different things. Changing either to the other's rule would
//! change which connection dies under a connection limit.

use core::fmt;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;

use crate::conn::filters::{
    CallCtx, ConnId, FilterChains, ShutdownTimer, SocketIndex,
};
use crate::conn::select::{EasyPollset, PollAction, PollFds, Socket, WaitFds};
use crate::error::{CURLMcode, CURLcode, CurlResult, Error};
use crate::trace::{infof, trc_feat, TimerId, TraceFeature};
use crate::util::timediff::{mstotv, TimeDiff};
use crate::util::timeval::timediff_ms;

// Constants, borrowed rather than restated

/// `DEFAULT_SHUTDOWN_TIMEOUT_MS` (`lib/connect.h:45`): two seconds.
pub(crate) use crate::conn::filters::DEFAULT_SHUTDOWN_TIMEOUT_MS;

/// `FIRSTSOCKET` = 0 (`lib/urldata.h:493`), re-exported for the callers that
/// speak in raw indices.
#[allow(unused_imports)]
pub(crate) use crate::conn::filters::FIRSTSOCKET;

/// `SECONDARYSOCKET` = 1 (`lib/urldata.h:494`).
#[allow(unused_imports)]
pub(crate) use crate::conn::filters::SECONDARYSOCKET;

/// `EXPIRE_SHUTDOWN` = **14** (`lib/urldata.h:901`).
#[allow(dead_code)] // consumers: `crate::multi` and this module's tests
pub(crate) const EXPIRE_SHUTDOWN: i32 = TimerId::Shutdown.as_i32();

/// The longest a single graceful-drain wait may last: **1000 ms**.
const WAIT_SLICE_MAX_MS: TimeDiff = 1000;

// Which handle the work runs against

/// Whose handle a piece of shutdown work is charged to.
///
/// `Curl_cshutdn_terminate` opens with a substitution
/// (`lib/cshutdn.c:135-140`):
///
/// ```c
/// struct Curl_easy *admin = data;
/// if(data->multi && data->multi->admin)
///   admin = data->multi->admin;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: `crate::multi`, once it owns a queue
pub(crate) enum ShutdownHandle {
    /// C's `data`: the handle that asked for the shutdown.
    Caller,
    /// C's `data->multi->admin`: the multi handle's internal handle, which no
    /// application holds a pointer to.
    Admin,
}

impl ShutdownHandle {
    /// The handle `Curl_cshutdn_terminate` picks -- [`Self::Admin`] when the
    /// caller's multi handle has an internal handle, otherwise the caller's.
    ///
    /// [`ShutdownHost::has_admin`] answers the whole of C's `data->multi &&
    /// data->multi->admin`, so the conjunction is not repeated here.
    fn of<H>(host: &H) -> Self
    where
        H: ShutdownHost + ?Sized,
    {
        if host.has_admin() {
            Self::Admin
        } else {
            Self::Caller
        }
    }
}

// The injected protocol disconnect handler

/// What [`ProtocolDisconnect::disconnect`] returns.
pub(crate) type DisconnectFuture<'a> =
    Pin<Box<dyn Future<Output = CurlResult<()>> + 'a>>;

/// A scheme's disconnect handler -- `conn->scheme->run->disconnect`.
///
/// The eighteenth member of `struct Curl_protocol` (`lib/urldata.h:427-512`),
/// reached here as a trait object rather than as a function pointer stored on
/// the connection. The difference matters for more than tidiness: C's handler
/// receives `struct connectdata *` and reaches the whole world through it,
/// whereas this one is handed exactly the two things a disconnect legitimately
/// touches -- the call context and the filter chains -- so a handler cannot
/// reach into the queue that is driving it.
///
/// # `dead`, and the result that is thrown away
///
/// `dead` is `conn->bits.aborted` (`lib/cshutdn.c:62`), and
/// `lib/conncache.c:207-217` is where it is set: a connection used in
/// `CONNECT_ONLY` mode is treated as aborted because *"we do not know what the
/// APP did with it"*, and an errored transfer marks its connection aborted so
/// that no polite protocol farewell is sent -- *"If we do a shutdown for an
/// aborted transfer, the server might think it was successful otherwise (for
/// example an ftps: upload)."*
///
/// The `CURLcode` C's handler returns is **discarded** at the call site
/// (`lib/cshutdn.c:62` evaluates it as a statement). The signature keeps the
/// result so that an implementation can report a failure honestly and so that
/// the trace records it, and this module then discards it exactly as C does.
/// A shutdown has no caller left to fail.
///
/// # The `Send` supertrait
///
/// `struct Curl_share` holds the connection pool by value
/// (`lib/curl_share.h:52`) and the pool holds these as boxed trait objects, so
/// [`crate::share::Share`] can only be `Send + Sync` -- which it statically
/// asserts, because one `CURLSH` is usable from two threads
/// (`tests/libtest/lib506.c`, `lib3207.c`) -- if this is `Send`. `Sync` is
/// deliberately NOT required: the pool exposes mutation through `&mut self`
/// alone and is never aliased, so `Mutex<T>: Sync` needs only `T: Send`.
#[allow(dead_code)] // consumer: `crate::protocols`, once its schemes land
pub(crate) trait ProtocolDisconnect: core::fmt::Debug + Send {
    /// Tear the protocol down. `dead` suppresses any farewell exchange.
    fn disconnect<'a>(
        &'a mut self,
        cx: &'a mut CallCtx<'_, '_>,
        chains: &'a mut FilterChains,
        dead: bool,
    ) -> DisconnectFuture<'a>;
}

// The injected multi handle

/// Everything the owning multi handle supplies to the shutdown queue.
///
/// C reaches all of this through `cshutdn->multi` (`lib/cshutdn.h:56`), a back
/// pointer from the queue to its owner. A back pointer is what this trait
/// replaces, and replacing it is deliberate rather than idiomatic tidying: an
/// owned queue holding `&mut Multi` would alias the multi handle that owns the
/// queue, which is a cycle Rust will not express. Naming the eleven operations
/// the queue actually performs on its owner turns the cycle into a parameter.
#[allow(dead_code)] // consumer: `crate::multi`, once it owns a queue
pub(crate) trait ShutdownHost {
    // -- the handle substitution ------------------------------------------

    /// C's `data->multi && data->multi->admin` (`lib/cshutdn.c:139`).
    ///
    /// The whole conjunction, not just the second half: a caller with no multi
    /// handle has no admin handle to substitute either.
    fn has_admin(&self) -> bool;

    /// C's `data->multi` (`lib/cshutdn.c:157`, `:161`).
    ///
    /// Gates the two notifications at the end of a termination. It is asked
    /// separately from [`Self::has_admin`] because the C asks it separately: a
    /// multi handle without an admin handle still gets its notifications.
    fn has_multi(&self) -> bool;

    // -- the handle's own state -------------------------------------------

    /// C's `data->state.internal` (`lib/cshutdn.c:51`).
    fn is_internal(&self, handle: ShutdownHandle) -> bool;

    /// C's `data->set.timeout = DEFAULT_SHUTDOWN_TIMEOUT_MS`
    /// (`lib/cshutdn.c:52`).
    fn set_operation_timeout_ms(
        &mut self,
        handle: ShutdownHandle,
        timeout_ms: TimeDiff,
    );

    /// C's `Curl_pgrsTime(data, TIMER_STARTOP)` (`lib/cshutdn.c:53`).
    fn restart_operation_timing(&mut self, handle: ShutdownHandle);

    // -- the socket-event layer -------------------------------------------

    /// C's `cshutdn->multi->socket_cb` (`lib/cshutdn.c:411`).
    ///
    /// When no socket callback is installed there is no event state to
    /// maintain, and `Curl_cshutdn_add` skips the assessment entirely -- which
    /// also means the failure path that discards the new connection is
    /// unreachable for a plain `curl_multi_perform` user.
    fn socket_cb_installed(&self) -> bool;

    /// C's `Curl_multi_ev_assess_conn` (`lib/multi_ev.h:59`), reached through
    /// `cshutdn_update_ev` (`lib/cshutdn.c:380-393`).
    fn assess_conn(
        &mut self,
        handle: ShutdownHandle,
        id: ConnId,
        cx: &mut CallCtx<'_, '_>,
        chains: &mut FilterChains,
    ) -> CURLMcode;

    /// C's `Curl_multi_ev_conn_done` (`lib/multi_ev.h:76`,
    /// `lib/cshutdn.c:158`).
    fn conn_done(
        &mut self,
        handle: ShutdownHandle,
        id: ConnId,
        cx: &mut CallCtx<'_, '_>,
        chains: &mut FilterChains,
    );

    /// C's `Curl_multi_connchanged` (`lib/multiif.h:45`,
    /// `lib/cshutdn.c:163`).
    ///
    /// *"There is a connection in the connection pool that is now available"*
    /// -- it wakes transfers parked for want of a connection. It takes only
    /// the multi handle in the C, so it takes no handle here.
    fn connchanged(&mut self);

    /// C's `Curl_expire_ex(data, milli, id)` (`lib/multiif.h:31-32`,
    /// `lib/cshutdn.c:263`).
    ///
    /// Arms one of the handle's timers. This module arms exactly one,
    /// [`EXPIRE_SHUTDOWN`], and it arms it in exactly one place -- see
    /// [`ShutdownQueue::perform_once`] and the arithmetic note beside it.
    fn expire(
        &mut self,
        handle: ShutdownHandle,
        timeout_ms: TimeDiff,
        timer: TimerId,
    );

    // -- the connection limit ---------------------------------------------

    /// C's `multi->max_total_connections` (`lib/multihandle.h:152`).
    ///
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS`; zero means unlimited. Read fresh on
    /// every [`ShutdownQueue::add`] rather than cached, because the
    /// application may set it at any time.
    fn max_total_connections(&self) -> usize;
}

// THE SHUTDOWN-TIMER CONTRACT WITH `conn/mod.rs`
//
// `Curl_shutdown_start(data, sockindex, timeout_ms)` (`:144-160`)
//     Records "now" for `sockindex` and resolves the budget ONCE for the
//     connection, by this rule and in this order:
//
//         explicit > 0            ? explicit
//         : configured > 0        ? configured   (`CURLOPT_SHUTDOWN_TIMEOUT`)
//         : DEFAULT_SHUTDOWN_TIMEOUT_MS          (2000)

/// `Curl_conn_shutdown_timeleft` (`lib/connect.c:178-192`): the deadline
/// across BOTH socket chains.
#[allow(dead_code)] // consumer: `Self::conn_time_left_ms`'s own callers
pub(crate) trait ConnShutdownTimer: ShutdownTimer {
    /// The smallest NON-ZERO remaining time over both socket indices, or zero
    /// when neither index has a deadline.
    ///
    /// # Reading the three answers
    ///
    /// * **Zero** -- no limit, or the shutdown has not started. Not "no time
    ///   left"; the opposite.
    /// * **Negative** -- the deadline has already passed.
    ///   `Curl_shutdown_timeleft` returns `left_ms ? left_ms : -1`
    ///   (`lib/connect.c:175`) precisely so that landing exactly ON the
    ///   deadline reports expiry rather than "unlimited".
    /// * **Positive** -- that many milliseconds remain.
    ///
    /// # Why this is not a `min` over the two values
    ///
    /// ```c
    /// for(i = 0; conn->shutdown.timeout_ms && (i < 2); ++i) {
    ///   if(!conn->shutdown.start[i].tv_sec)
    ///     continue;
    ///   ms = Curl_shutdown_timeleft(data, conn, i);
    ///   if(ms && (!left_ms || ms < left_ms))
    ///     left_ms = ms;
    /// }
    /// ```
    fn conn_time_left_ms(&self) -> TimeDiff {
        let mut left_ms: TimeDiff = 0;
        for sockindex in SocketIndex::ALL {
            let ms = self.time_left_ms(sockindex);
            if ms != 0 && (left_ms == 0 || ms < left_ms) {
                left_ms = ms;
            }
        }
        left_ms
    }
}

impl<T> ConnShutdownTimer for T where T: ShutdownTimer + ?Sized {}

// One connection on its way out

/// A connection being shut down, owned by value.
///
/// # The two latches
///
/// * `shutdown_handler` -- C's `conn->bits.shutdown_handler`. Set
///   UNCONDITIONALLY once the protocol disconnect handler has had its chance,
///   even when the scheme has no handler at all (`lib/cshutdn.c:65`, outside
///   the `if`). That placement is load-bearing and it is easy to get wrong:
///   `Curl_conn_free` (`lib/url.c`) opens by running the disconnect handler
///   AGAIN, with `dead = TRUE`, whenever `!conn->bits.shutdown_handler`. A
///   handler-less scheme that left the latch clear would therefore reach the
///   release path with the latch clear and the guard would be tested against a
///   handler that does not exist; setting the latch unconditionally is what
///   makes that second entry provably unreachable for every connection that
///   passed through this module.
/// * `shutdown_filters` -- C's `conn->bits.shutdown_filters`. Set when a
///   shutdown step reports itself finished (`lib/cshutdn.c:106-107`), read as
///   an immediate "already done" short circuit on the next step (`:85-88`),
///   and read a third time to decide whether the final close is announced as
///   graceful or as forced (`:150-152`).
#[allow(dead_code)] // consumers: `crate::conn::pool` and `crate::multi`
pub(crate) struct ShuttingDownConnection {
    /// C's `conn->connection_id`, the number every trace line carries.
    id: ConnId,
    /// C's `conn->destination`: the pool's reuse key, and what
    /// [`ShutdownQueue::close_oldest`] and
    /// [`ShutdownQueue::destination_count`] match on.
    destination: String,
    /// C's `conn->cfilter[2]`, both chains.
    chains: FilterChains,
    /// The injected deadline. Storage belongs to `conn/mod.rs`; see
    /// [`ConnShutdownTimer`].
    timer: Box<dyn ShutdownTimer>,
    /// The scheme's disconnect handler, when it has one --
    /// `conn->scheme->run->disconnect` (`lib/cshutdn.c:46`).
    handler: Option<Box<dyn ProtocolDisconnect>>,
    /// Latch: the protocol handler has had its one chance.
    shutdown_handler: bool,
    /// Latch: the filter chains have finished shutting down.
    shutdown_filters: bool,
    /// C's `conn->bits.aborted`: passed to the handler as `dead`, and the
    /// reason a failed transfer sends no protocol farewell
    /// (`lib/conncache.c:212-217`).
    aborted: bool,
    /// C's `conn->connect_only`: the application took the socket over through
    /// `CURLOPT_CONNECT_ONLY`, so the filter chains must not be driven.
    connect_only: bool,
    /// C's `conn->bits.in_cpool`. A connection reaching [`terminate`] must
    /// have left the pool already, which is why this exists at all: it is a
    /// precondition to assert, not a state to manage.
    in_pool: bool,
    /// C's `conn->scheme->flags & PROTOPT_NONETWORK`, the `else` branch of
    /// `Curl_conn_is_connected` (`lib/cfilters.c:611-612`).
    no_network: bool,
}

impl fmt::Debug for ShuttingDownConnection {
    /// Deliberately partial: the two injected objects are reported by
    /// PRESENCE.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShuttingDownConnection")
            .field("id", &self.id)
            .field("destination", &self.destination)
            .field("chains", &self.chains)
            .field("has_handler", &self.handler.is_some())
            .field("shutdown_handler", &self.shutdown_handler)
            .field("shutdown_filters", &self.shutdown_filters)
            .field("aborted", &self.aborted)
            .field("connect_only", &self.connect_only)
            .field("in_pool", &self.in_pool)
            .field("no_network", &self.no_network)
            .finish()
    }
}

#[allow(dead_code)] // consumers: `crate::conn::pool` and `crate::multi`
impl ShuttingDownConnection {
    /// A connection with both latches clear and every flag false.
    ///
    /// The chains are re-stamped with `id` so that the identity a trace line
    /// reports through a filter and the identity this module reports cannot
    /// disagree -- C keeps them in step by hand, since `cf->conn` and
    /// `conn->connection_id` are set in different places.
    pub(crate) fn new(
        id: ConnId,
        destination: impl Into<String>,
        mut chains: FilterChains,
        timer: Box<dyn ShutdownTimer>,
    ) -> Self {
        chains.set_conn(Some(id));
        Self {
            id,
            destination: destination.into(),
            chains,
            timer,
            handler: None,
            shutdown_handler: false,
            shutdown_filters: false,
            aborted: false,
            connect_only: false,
            in_pool: false,
            no_network: false,
        }
    }

    /// Installs the scheme's disconnect handler.
    ///
    /// Absent by default, because most of what reaches this queue has no
    /// handler: of the nine schemes in core scope only FTP, SFTP and SCP
    /// register one.
    #[must_use]
    pub(crate) fn with_handler(
        mut self,
        handler: Box<dyn ProtocolDisconnect>,
    ) -> Self {
        self.handler = Some(handler);
        self
    }

    /// Sets `conn->bits.aborted`, which becomes the handler's `dead`.
    #[must_use]
    pub(crate) fn with_aborted(mut self, aborted: bool) -> Self {
        self.aborted = aborted;
        self
    }

    /// Sets `conn->connect_only`.
    #[must_use]
    pub(crate) fn with_connect_only(mut self, connect_only: bool) -> Self {
        self.connect_only = connect_only;
        self
    }

    /// Sets `conn->scheme->flags & PROTOPT_NONETWORK`.
    #[must_use]
    pub(crate) fn with_no_network(mut self, no_network: bool) -> Self {
        self.no_network = no_network;
        self
    }

    /// Sets `conn->bits.in_cpool`.
    ///
    /// Exists so that the precondition [`terminate`] asserts can be exercised,
    /// and so that a pool handing a connection over can state positively that
    /// it has already unlinked it.
    #[must_use]
    pub(crate) fn with_in_pool(mut self, in_pool: bool) -> Self {
        self.in_pool = in_pool;
        self
    }

    /// C's `conn->connection_id`.
    pub(crate) fn id(&self) -> ConnId {
        self.id
    }

    /// C's `conn->destination`.
    pub(crate) fn destination(&self) -> &str {
        &self.destination
    }

    /// C's `conn->bits.aborted`.
    pub(crate) fn aborted(&self) -> bool {
        self.aborted
    }

    /// C's `conn->connect_only`.
    pub(crate) fn connect_only(&self) -> bool {
        self.connect_only
    }

    /// C's `conn->scheme->flags & PROTOPT_NONETWORK`.
    pub(crate) fn no_network(&self) -> bool {
        self.no_network
    }

    /// C's `conn->bits.in_cpool`.
    pub(crate) fn is_in_pool(&self) -> bool {
        self.in_pool
    }

    /// Has the protocol disconnect handler had its chance?
    ///
    /// C's `conn->bits.shutdown_handler`.
    pub(crate) fn handler_has_run(&self) -> bool {
        self.shutdown_handler
    }

    /// Have the filter chains finished shutting down?
    ///
    /// C's `conn->bits.shutdown_filters`. This is also the flag that decides
    /// whether the closing trace line says `force ` (`lib/cshutdn.c:151`).
    pub(crate) fn filters_have_shut_down(&self) -> bool {
        self.shutdown_filters
    }

    /// Does the scheme have a disconnect handler at all?
    pub(crate) fn has_handler(&self) -> bool {
        self.handler.is_some()
    }

    /// Both filter chains, shared.
    pub(crate) fn chains(&self) -> &FilterChains {
        &self.chains
    }

    /// Both filter chains, mutable.
    pub(crate) fn chains_mut(&mut self) -> &mut FilterChains {
        &mut self.chains
    }

    /// The injected deadline, shared.
    pub(crate) fn timer(&self) -> &dyn ShutdownTimer {
        self.timer.as_ref()
    }

    /// The injected deadline, mutable.
    pub(crate) fn timer_mut(&mut self) -> &mut dyn ShutdownTimer {
        self.timer.as_mut()
    }

    /// `Curl_conn_shutdown_timeleft(data, conn)` (`lib/connect.c:178-192`).
    ///
    /// Delegates to [`ConnShutdownTimer::conn_time_left_ms`], which documents
    /// the three meanings of the answer. No deadline is stored here.
    pub(crate) fn shutdown_time_left_ms(&self) -> TimeDiff {
        self.timer.conn_time_left_ms()
    }

    /// `Curl_conn_is_connected(conn, sockindex)` (`lib/cfilters.c:601-613`).
    pub(crate) fn is_connected(&self, sockindex: SocketIndex) -> bool {
        self.chains.chain(sockindex).is_connected(self.no_network)
    }

    // -- the protocol handler, exactly once -------------------------------

    /// `cshutdn_run_conn_handler` (`lib/cshutdn.c:41-66`): give the scheme its
    /// one chance to say goodbye.
    ///
    /// # The cap on a blocking handler
    ///
    /// Cancelling a future is not identical to a handler returning
    /// `CURLE_OPERATION_TIMEDOUT`: work in flight is abandoned at its last
    /// `await` rather than unwound. For a connection whose next act is to be
    /// destroyed that difference is not observable, and abandoning is the only
    /// answer available to a caller who must not block -- which is the same
    /// bargain C strikes, one layer further in.
    ///
    /// # Panics
    ///
    /// Requires a `tokio` runtime with the time driver when the handle is
    /// internal AND the scheme has a handler, as `tokio::time::timeout` does.
    /// Neither a handler-less scheme nor a non-internal handle reaches the
    /// timer.
    pub(crate) async fn run_conn_handler<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        handle: ShutdownHandle,
    ) where
        H: ShutdownHost + ?Sized,
    {
        if self.shutdown_handler {
            return;
        }

        if self.handler.is_some() {
            // `:51-54`: the two statements that give a blocking handler a
            // budget. Read the handle's kind ONCE -- it decides both the
            // statements below and the cap further down, and C tests it once
            // too.
            let internal = host.is_internal(handle);
            if internal {
                host.set_operation_timeout_ms(
                    handle,
                    DEFAULT_SHUTDOWN_TIMEOUT_MS,
                );
                host.restart_operation_timing(handle);
            }

            let dead = self.aborted;
            let id = self.id;
            if let Some(tracer) = cx.tracer_mut() {
                infof!(
                    tracer,
                    "connection #{}, shutdown protocol handler (aborted={})",
                    id,
                    u8::from(dead),
                );
            }

            // `:62`. The borrow is scoped so that the latch below can be
            // written after the future is dropped: `handler` and `chains` are
            // disjoint fields, which is what lets a handler mutate the chains
            // while this function still owns the connection.
            let outcome = {
                let Self {
                    handler, chains, ..
                } = self;
                let handler = handler
                    .as_mut()
                    .expect("handler presence was tested above");
                let running = handler.disconnect(cx, chains, dead);
                match internal
                    .then(|| mstotv(DEFAULT_SHUTDOWN_TIMEOUT_MS))
                    .flatten()
                {
                    Some(cap) => {
                        match tokio::time::timeout(cap, running).await {
                            Ok(result) => result,
                            // The budget elapsed. C's handler would have
                            // reported `CURLE_OPERATION_TIMEDOUT` out of its
                            // own deadline check, exactly as
                            // `Curl_conn_shutdown` does at
                            // `lib/cfilters.c:184-188`; naming the same code
                            // here keeps two descriptions of one event
                            // identical, and it is then discarded just as the
                            // handler's own would have been.
                            Err(_elapsed) => Err(Error::with_context(
                                CURLcode::OperationTimedout,
                                "shutdown protocol handler timed out",
                            )),
                        }
                    }
                    None => running.await,
                }
            };

            // C evaluates the handler's `CURLcode` as a statement (`:62`) and
            // discards it. A shutdown has no caller left to fail, and reporting
            // it would invent an error path the C does not have.
            drop(outcome);
        }

        // `:65` -- unconditional, and outside the `if` above.
        self.shutdown_handler = true;
    }

    // -- one non-blocking step --------------------------------------------

    /// `cshutdn_run_once` (`lib/cshutdn.c:69-108`): one non-blocking shutdown
    /// step over both socket chains. Returns whether the shutdown is FINISHED.
    ///
    /// Private and **silent**, exactly as the C's `static` is. The trace line
    /// belongs to the public [`Self::run_once`] wrapper (`:110-119`), and a
    /// termination's final attempt calls this one (`:148`) -- so a forced close
    /// emits no `shutdown, done=` line. That asymmetry is easy to lose and it
    /// changes what a `--verbose` log contains.
    async fn run_once_inner<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        handle: ShutdownHandle,
    ) -> bool
    where
        H: ShutdownHost + ?Sized,
    {
        // `:79-81`. ONLY the primary index starts the clock, and the deadline
        // it sets then covers BOTH chains -- see
        // [`ConnShutdownTimer::conn_time_left_ms`], which reads every index.
        // Zero asks the timer for its own default, which resolves to
        // `CURLOPT_SHUTDOWN_TIMEOUT` when the application set one and to
        // [`DEFAULT_SHUTDOWN_TIMEOUT_MS`] otherwise (`lib/connect.c:151-154`).
        if !self.timer.started(SocketIndex::First) {
            self.timer.start(SocketIndex::First, 0);
        }

        // `:83`. Before any filter work: a protocol that wants to send a
        // farewell must be able to send it through filters that are still up.
        self.run_conn_handler(cx, host, handle).await;

        // `:85-88`. Already finished on an earlier pass; nothing to retry.
        if self.shutdown_filters {
            return true;
        }

        // `:90-102`, once per chain. Two conditions make a chain's work
        // unnecessary rather than merely finished:
        //
        // * `connect_only` -- the application took the socket over through
        //   `CURLOPT_CONNECT_ONLY` and libcurl must not write to it.
        // * not connected -- there is nothing established to shut down.
        let mut failed = false;
        let mut all_done = true;
        for sockindex in SocketIndex::ALL {
            let (chain_failed, chain_done) = if !self.connect_only
                && self.is_connected(sockindex)
            {
                let Self { chains, timer, .. } = self;
                match chains.chain_mut(sockindex).shutdown(cx, timer.as_mut()) {
                    Ok(done) => (false, done),
                    // C's `Curl_conn_shutdown` writes `*done = FALSE`
                    // (`lib/cfilters.c:178`) before it can return an
                    // error, so an error leaves `doneN` false. The
                    // completion expression below does not care, because
                    // the error term short-circuits it -- but recording
                    // the pair honestly is what makes that provable
                    // rather than assumed.
                    Err(_error) => (true, false),
                }
            } else {
                (false, true)
            };
            failed |= chain_failed;
            all_done &= chain_done;
        }

        // `:104-107`, with the C's own comment:
        //
        //   /* we are done when any failed or both report success */
        //   *done = (r1 || r2 || (done1 && done2));
        let done = failed || all_done;
        if done {
            self.shutdown_filters = true;
        }
        done
    }

    /// `Curl_cshutdn_run_once` (`lib/cshutdn.c:110-119`): one step, traced.
    ///
    /// The public entry point, and the only difference from the private one is
    /// the `[SHUTDOWN] shutdown, done=%d` line it emits afterwards. The C's
    /// `Curl_attach_connection`/`Curl_detach_connection` pair around the call
    /// (`:115`, `:118`) has no successor: the connection is a parameter, so
    /// there is no window in which `data->conn` names something else and no
    /// bookkeeping to undo on the way out.
    ///
    /// # Panics
    ///
    /// As [`Self::run_conn_handler`].
    pub(crate) async fn run_once<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        handle: ShutdownHandle,
    ) -> bool
    where
        H: ShutdownHost + ?Sized,
    {
        let done = self.run_once_inner(cx, host, handle).await;
        // `:117`. C prints a `bool` with `%d`; `u8::from` gives the same 0 or
        // 1.
        if let Some(tracer) = cx.tracer_mut() {
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "[SHUTDOWN] shutdown, done={}",
                u8::from(done),
            );
        }
        done
    }

    // -- release --------------------------------------------------------

    /// The part of `Curl_conn_free` (`lib/url.c`) that this value owns.
    ///
    /// * The **re-run** is unreachable from here, and provably so:
    ///   [`terminate`] always calls [`Self::run_conn_handler`] first, which
    ///   latches unconditionally. The guard exists in the C for callers that
    ///   free a connection which never entered a shutdown at all.
    /// * The **chain discard** is reproduced, and in the C's index order --
    ///   `for(i = 0; i < CURL_ARRAYSIZE(conn->cfilter); ++i)`, so primary then
    ///   secondary. Note that this is the REVERSE of the order in which the two
    ///   chains were just closed; both orders are the C's and both are kept.
    /// * The **string frees** have no successor. Every one of them is a field
    ///   of this value, so dropping the value frees them, in declaration order,
    ///   with no possibility of missing one.
    fn release(mut self, cx: &mut CallCtx<'_, '_>) {
        self.chains.discard_everything(cx);
        drop(self);
    }
}

// Termination: the end of a connection's life

/// `Curl_cshutdn_terminate` (`lib/cshutdn.c:121-165`): close and destroy a
/// connection, optionally trying one last graceful step first.
///
/// # Preconditions
///
/// C asserts three things (`:129-133`):
///
/// * `conn` is non-null -- unrepresentable for an owned value.
/// * `!conn->bits.in_cpool`, the connection has left the pool. This one is a
///   FLAG rather than a borrow, so it is still assertable and is still
///   asserted. A release build proceeds regardless, exactly as C's
///   `DEBUGASSERT` compiles away.
/// * `data && !data->conn`, no transfer is attached to the connection. Also
///   unrepresentable: a `ShuttingDownConnection` moved into this function
///   cannot simultaneously be borrowed by a transfer, so the type system
///   enforces what the C can only check.
///
/// # Panics
///
/// As [`ShuttingDownConnection::run_conn_handler`].
#[allow(dead_code)] // consumers: `crate::conn::pool` and `crate::multi`
pub(crate) async fn terminate<H>(
    cx: &mut CallCtx<'_, '_>,
    host: &mut H,
    mut conn: ShuttingDownConnection,
    do_shutdown: bool,
) where
    H: ShutdownHost + ?Sized,
{
    // `:131`. The remaining assertable precondition; see the doc above.
    debug_assert!(
        !conn.in_pool,
        "a connection must leave the pool before it is terminated"
    );

    // `:135-140`.
    let admin = ShutdownHandle::of(host);

    // `:144`. Unconditional, so that a connection terminated without ever
    // having been stepped still gets its farewell -- and so that the latch is
    // set before `release` below.
    conn.run_conn_handler(cx, host, admin).await;

    // `:145-149`: "Make a last attempt to shutdown handlers and filters, if
    // not done so already." The INNER, silent step -- a forced close emits no
    // `shutdown, done=` line.
    if do_shutdown {
        // C stores the answer in a local it never reads (`:126`, `:148`). Its
        // only effect is on `conn->bits.shutdown_filters`, which the trace
        // below reads instead. Bound to an underscore-prefixed name rather than
        // dropped, because `drop` on a `Copy` type does nothing and the
        // compiler says so.
        let _done = conn.run_once_inner(cx, host, admin).await;
    }

    let id = conn.id;
    // `:150-152`. The prefix is decided by the latch, not by `do_shutdown`: a
    // connection that finished shutting down on an earlier pass closes
    // gracefully even when this call did not try again, and one that never
    // finished is announced as forced even when it did.
    let force = if conn.shutdown_filters { "" } else { "force " };
    if let Some(tracer) = cx.tracer_mut() {
        trc_feat!(
            tracer,
            TraceFeature::Multi,
            "[SHUTDOWN] {}closing connection #{}",
            force,
            id,
        );
    }

    // `:153-154`. SECONDARY FIRST, then primary.
    //
    // `close_and_clear` is `Curl_conn_close` in full
    // (`lib/cfilters.c:144-155`):
    // the head filter's close, then `Curl_shutdown_clear` for that index. The
    // timer is the connection's own, borrowed disjointly from the chains.
    for sockindex in [SocketIndex::Secondary, SocketIndex::First] {
        let ShuttingDownConnection { chains, timer, .. } = &mut conn;
        chains
            .chain_mut(sockindex)
            .close_and_clear(cx, timer.as_mut());
    }

    // `:157-158`. Charged to the CALLER's handle, not the admin's, and skipped
    // entirely when the caller has no multi handle -- there is then no event
    // layer holding descriptor state to correct.
    if host.has_multi() {
        let ShuttingDownConnection { chains, .. } = &mut conn;
        host.conn_done(ShutdownHandle::Caller, id, cx, chains);
    }

    // `:159`. Everything the connection owns goes here.
    conn.release(cx);

    // `:161-164`. Both the trace and the notification are the caller's, and
    // both are gated on the same condition. The order matters for a log: the
    // line is emitted BEFORE the notification, so a reader sees the cause
    // ahead of whatever the woken transfers then do.
    if host.has_multi() {
        if let Some(tracer) = cx.tracer_mut() {
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "[SHUTDOWN] trigger multi connchanged",
            );
        }
        host.connchanged();
    }
}

// ========================================================================= The
// queue

/// The multi handle's FIFO of connections being shut down -- C's
/// `struct cshutdn` (`lib/cshutdn.h:51-58`).
///
/// # Ordering
///
/// Strict FIFO. See the module documentation for why this must not be confused
/// with the connection pool's maximum-age eviction.
#[derive(Debug, Default)]
#[allow(dead_code)] // consumer: `crate::multi`, once it owns a queue
pub(crate) struct ShutdownQueue {
    /// Connections being shut down, oldest at the front.
    queue: VecDeque<ShuttingDownConnection>,
}

#[allow(dead_code)] // consumers: `crate::conn::pool` and `crate::multi`
impl ShutdownQueue {
    /// An empty queue -- `Curl_cshutdn_init` (`lib/cshutdn.c:319-327`) with
    /// nothing left to initialise.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// How many connections are being shut down -- `Curl_cshutdn_count`
    /// (`lib/cshutdn.c:353-360`).
    pub(crate) fn count(&self) -> usize {
        self.queue.len()
    }

    /// Is the queue empty? C spells this `Curl_llist_head(&cshutdn->list)` and
    /// tests the pointer (`lib/cshutdn.c:238`, `:280`, `:286`, `:439`).
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// How many connections to `destination` are being shut down --
    /// `Curl_cshutdn_dest_count` (`lib/cshutdn.c:362-378`).
    pub(crate) fn destination_count(&self, destination: &str) -> usize {
        self.queue
            .iter()
            .filter(|conn| conn.destination == destination)
            .count()
    }

    /// `cshutdn_destroy_oldest` / `Curl_cshutdn_close_oldest`
    /// (`lib/cshutdn.c:167-203`): force one connection closed, returning
    /// whether there was one to close.
    ///
    /// # Panics
    ///
    /// As [`terminate`].
    pub(crate) async fn close_oldest<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        destination: Option<&str>,
    ) -> bool
    where
        H: ShutdownHost + ?Sized,
    {
        // `:174-180`: from the head, stopping at the first match. `None` makes
        // the predicate true immediately, which is the C's `!destination`.
        let found = self.queue.iter().position(|conn| {
            destination.map_or(true, |wanted| conn.destination == wanted)
        });

        match found {
            Some(index) => {
                // `:185`. Removed BEFORE the termination, exactly as the C
                // unlinks before it frees -- and here removal is what produces
                // the owned value `terminate` needs, so the two cannot be done
                // in the wrong order.
                let conn = self
                    .queue
                    .remove(index)
                    .expect("position() returned an index that is in range");
                terminate(cx, host, conn, false).await;
                true
            }
            None => false,
        }
    }

    /// `Curl_cshutdn_add` (`lib/cshutdn.c:395-424`): take ownership of a
    /// connection and start shutting it down in the background.
    ///
    /// # The combined connection limit
    ///
    /// This is the most important invariant shared between this queue and
    /// `crate::conn::pool`, and it is why the pool's count arrives as a
    /// parameter:
    ///
    /// ```text
    /// if max_total > 0 && max_total <= conns_in_pool + shutdown_queue.len()
    ///     force-close the oldest shutdown connection
    /// ```
    ///
    /// # Panics
    ///
    /// As [`terminate`].
    pub(crate) async fn add<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        mut conn: ShuttingDownConnection,
        conns_in_pool: usize,
    ) where
        H: ShutdownHost + ?Sized,
    {
        // `:399`. C reads `cshutdn->multi->admin` into `data` and charges every
        // trace and every termination in this function to it.
        let admin = ShutdownHandle::of(host);

        // `:400`, re-read rather than cached: the application may change
        // `CURLMOPT_MAX_TOTAL_CONNECTIONS` at any time.
        let max_total = host.max_total_connections();

        // `:404-409`.
        if max_total > 0 && max_total <= conns_in_pool + self.count() {
            if let Some(tracer) = cx.tracer_mut() {
                trc_feat!(
                    tracer,
                    TraceFeature::Multi,
                    "[SHUTDOWN] discarding oldest shutdown connection \
                     due to connection limit of {}",
                    max_total,
                );
            }
            // `:408`: any destination, so the head. C ignores the answer; an
            // empty queue means the pool alone reached the limit, and there is
            // nothing here to give up.
            let _closed = self.close_oldest(cx, host, None).await;
        }

        let id = conn.id;

        // `:411-418`. C additionally asserts `cshutdn->multi->socket_cb` inside
        // `cshutdn_update_ev` (`:387`), which is the same condition tested
        // here; the assertion has nothing left to catch once the test is the
        // only way in.
        if host.socket_cb_installed() {
            let assessed = {
                let ShuttingDownConnection { chains, .. } = &mut conn;
                host.assess_conn(admin, id, cx, chains)
            };
            if assessed != CURLMcode::Ok {
                if let Some(tracer) = cx.tracer_mut() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Multi,
                        "[SHUTDOWN] update events failed, discarding #{}",
                        id,
                    );
                }
                // `:415-416`: terminated, not enqueued. `conn` is moved, so
                // the `return` the C needs in order to skip the append is
                // enforced rather than remembered.
                terminate(cx, host, conn, false).await;
                return;
            }
        }

        // `:420`. The TAIL: insertion order is the whole of the ordering.
        self.queue.push_back(conn);

        // `:421-423`.
        if let Some(tracer) = cx.tracer_mut() {
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "[SHUTDOWN] added #{} to shutdowns, now {} conns in shutdown",
                id,
                self.queue.len(),
            );
        }
    }

    // -- the multi-driven pass --------------------------------------------

    /// `cshutdn_perform` / `Curl_cshutdn_perform` (`lib/cshutdn.c:228-264`,
    /// `:426-431`): one non-blocking step over every queued connection.
    ///
    /// # Removal safety
    ///
    /// C captures `enext = Curl_node_next(e)` BEFORE running the step
    /// (`:245`), so that removing the current node cannot lose the walk's
    /// place. The index walk here is equivalent, and the equivalence is
    /// PROVABLE rather than inspected: neither
    /// [`ShuttingDownConnection::run_once`] nor [`terminate`] is handed a
    /// borrow of this queue, so neither can insert into it, remove from it or
    /// reorder it. The only mutation during the walk is this function's own
    /// removal, and not advancing the index after a removal lands on the
    /// element that shifted down -- exactly where C's `e = enext` lands.
    ///
    /// # Panics
    ///
    /// As [`terminate`].
    pub(crate) async fn perform_once<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        handle: ShutdownHandle,
    ) where
        H: ShutdownHost + ?Sized,
    {
        // `:238-239`. Nothing queued means no trace and no timer.
        if self.queue.is_empty() {
            return;
        }

        // `:241-242`.
        if let Some(tracer) = cx.tracer_mut() {
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "[SHUTDOWN] perform on {} connections",
                self.queue.len(),
            );
        }

        // `:235`. The accumulator starts at ZERO, and that is the whole of the
        // quirk documented at the comparison below.
        let mut next_expire_ms: TimeDiff = 0;

        let mut index = 0_usize;
        while index < self.queue.len() {
            // `:247`. The TRACED step: a background pass is exactly where a
            // `shutdown, done=` line belongs.
            let done = self.queue[index].run_once(cx, host, handle).await;
            if done {
                // `:249-250`.
                let conn = self
                    .queue
                    .remove(index)
                    .expect("index was just bounds-checked by the loop");
                terminate(cx, host, conn, false).await;
                // No increment: the next element has shifted into `index`.
            } else {
                // `:255`. Both socket indices, combined -- see
                // [`ConnShutdownTimer::conn_time_left_ms`].
                let ms = self.queue[index].shutdown_time_left_ms();

                // NOTE: This intentionally mirrors lib/cshutdn.c:253-259.
                // Starting at zero means positive future deadlines do not lower
                // the value; only already-expired negative values schedule this
                // path. Do not "fix" without changing curl parity.
                if ms != 0 && ms < next_expire_ms {
                    next_expire_ms = ms;
                }
                index += 1;
            }
        }

        // `:262-263`.
        if next_expire_ms != 0 {
            host.expire(handle, next_expire_ms, TimerId::Shutdown);
        }
    }

    // -- readiness -------------------------------------------------------

    /// Walks every queued connection's pollset -- the shared body of all three
    /// readiness exports (`lib/cshutdn.c:434-533`).
    fn for_each_pollset<F>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        on_error: OnAdjustError,
        mut body: F,
    ) -> CurlResult<()>
    where
        F: FnMut(&EasyPollset),
    {
        // `:439`, `:481`, `:509`: the whole of each function is inside an
        // emptiness test.
        if self.queue.is_empty() {
            return Ok(());
        }

        let mut ps = EasyPollset::new();
        for conn in &mut self.queue {
            ps.reset();
            match conn.chains.adjust_pollset(cx, &mut ps) {
                Ok(()) => body(&ps),
                Err(error) => match on_error {
                    OnAdjustError::Skip => continue,
                    OnAdjustError::Abort => return Err(error),
                },
            }
        }
        Ok(())
    }

    /// The descriptor half of `Curl_cshutdn_setfds` (`lib/cshutdn.c:434-472`):
    /// every queued connection's watched socket with what it is waiting for.
    ///
    /// # This is where the descriptor set stops
    ///
    /// C's function exists to serve `curl_multi_fdset`, so it writes straight
    /// into a libc descriptor set through the libc macro that sets a bit in
    /// one, and tracks `*maxfd` alongside (`:459-468`). All three of those are
    /// libc, and `curl_multi_fdset` is an EXPORTED C API -- so the marshalling
    /// belongs to `curl-rs-ffi`, which is the crate whose job is the C ABI, and
    /// this function hands out typed pairs instead. No libc type, no libc
    /// macro and no `maxfd` appears anywhere in this file.
    pub(crate) fn sockets(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> Vec<(Socket, PollAction)> {
        let mut pairs: Vec<(Socket, PollAction)> = Vec::new();
        let outcome = self.for_each_pollset(cx, OnAdjustError::Skip, |ps| {
            pairs.extend(ps.iter());
        });
        // `Skip` cannot produce an error; the walk always completes.
        debug_assert!(outcome.is_ok(), "a skipping walk cannot fail");
        drop(outcome);
        pairs
    }

    /// `Curl_cshutdn_add_waitfds` (`lib/cshutdn.c:475-501`): record every
    /// queued connection's descriptors in the APPLICATION's array and return
    /// how many entries were NEEDED.
    pub(crate) fn add_waitfds(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        wfds: &mut WaitFds<'_>,
    ) -> u32 {
        let mut need = 0_u32;
        let outcome = self.for_each_pollset(cx, OnAdjustError::Skip, |ps| {
            need = need.saturating_add(wfds.add_ps(ps));
        });
        debug_assert!(outcome.is_ok(), "a skipping walk cannot fail");
        drop(outcome);
        need
    }

    /// `Curl_cshutdn_add_pollfds` (`lib/cshutdn.c:503-534`): buffer every
    /// queued connection's descriptors for an internal wait.
    ///
    /// # Errors
    ///
    /// This is the export that ABORTS on an `adjust_pollset` failure rather
    /// than skipping the connection (`:524-528`), and it empties the caller's
    /// buffer on the way out -- C's `Curl_pollfds_cleanup(cpfds)` at `:526`.
    /// Waiting on a partially filled buffer would wait on the wrong set, so
    /// there is nothing safe to do with what was collected so far.
    pub(crate) fn add_pollfds(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        pfds: &mut PollFds,
    ) -> CurlResult<()> {
        let outcome = self.for_each_pollset(cx, OnAdjustError::Abort, |ps| {
            pfds.add_ps(ps);
        });
        if outcome.is_err() {
            pfds.reset();
        }
        outcome
    }

    // -- the graceful drain ----------------------------------------------

    /// `cshutdn_wait` (`lib/cshutdn.c:207-226`): wait for activity on the
    /// queue, or for `timeout_ms`, whichever comes first.
    ///
    /// The wait is capped at [`WAIT_SLICE_MAX_MS`] -- `CURLMIN(timeout_ms,
    /// 1000)` at `:221` -- so that the drain loop re-examines the queue at
    /// least once a second.
    ///
    /// # Both the count AND a failure are discarded -- exactly as in C
    ///
    /// `Curl_poll(cpfds.pfds, cpfds.n, CURLMIN(timeout_ms, 1000));` at `:221`
    /// is a bare STATEMENT: neither the number of ready descriptors nor a `-1`
    /// is read. The count changes nothing, because the next thing that happens
    /// is a shutdown step on every connection regardless; and a failed wait
    /// returns instantly, so the drain loop keeps passing over the queue until
    /// its own deadline expires and reports `timeout`.
    ///
    /// An earlier revision propagated [`CURLcode::UnrecoverablePoll`] here, on
    /// the argument that the final state is identical and only one trace word
    /// differs. AAP 0.8.2 does not allow that trade: the trace text is
    /// observable output, `--trace`/`--trace-ascii` put it where a fixture can
    /// compare it, and `aborted` where curl says `timeout` is a behaviour
    /// change justified by improvement.
    ///
    /// # What is still propagated
    ///
    /// [`Self::add_pollfds`] failing. That is NOT symmetric with the poll, and
    /// the asymmetry is the C's: `:217-219` is
    /// `result = Curl_cshutdn_add_pollfds(...); if(result) goto out;`, so an
    /// `adjust_pollset` failure ends the wait with a code while the poll's own
    /// failure does not. A blanket "discard everything here" would have been
    /// wrong in the other direction.
    ///
    /// # Panics
    ///
    /// Requires a `tokio` runtime, as [`PollFds::poll`] does.
    async fn wait(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        timeout_ms: TimeDiff,
    ) -> CurlResult<()> {
        // `:211-215`. `NUM_POLLS_ON_STACK` has nothing left to size.
        let mut pfds = PollFds::new();
        // `:217-219` -- this one propagates.
        self.add_pollfds(cx, &mut pfds)?;
        // `:221` -- evaluated as a statement, so both the count and any failure
        // are dropped here as the C drops them.
        let _ = pfds.poll(timeout_ms.min(WAIT_SLICE_MAX_MS)).await;
        Ok(())
    }

    /// `cshutdn_terminate_all` (`lib/cshutdn.c:266-317`): drain the queue,
    /// gracefully for as long as `timeout_ms` allows and forcibly thereafter.
    ///
    /// # Panics
    ///
    /// As [`terminate`] and [`Self::wait`].
    pub(crate) async fn terminate_all<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        handle: ShutdownHandle,
        timeout_ms: TimeDiff,
    ) where
        H: ShutdownHost + ?Sized,
    {
        // `:270`. The INJECTED clock, so that a test can place this at a chosen
        // instant and step it forward without waiting.
        let started = cx.now();

        // `:277`.
        if let Some(tracer) = cx.tracer_mut() {
            trc_feat!(tracer, TraceFeature::Multi, "[SHUTDOWN] shutdown all");
        }

        // `:280-304`.
        while !self.queue.is_empty() {
            self.perform_once(cx, host, handle).await;

            // `:286-289`.
            if self.queue.is_empty() {
                if let Some(tracer) = cx.tracer_mut() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Multi,
                        "[SHUTDOWN] shutdown finished cleanly",
                    );
                }
                break;
            }

            // `:292-297`. C's `>=` is what makes a zero budget one pass.
            let spent_ms = timediff_ms(cx.now(), started);
            if spent_ms >= timeout_ms {
                let why = if timeout_ms > 0 {
                    "timeout"
                } else {
                    "best effort done"
                };
                if let Some(tracer) = cx.tracer_mut() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Multi,
                        "[SHUTDOWN] shutdown finished, {}",
                        why,
                    );
                }
                break;
            }

            // `:299-303`. Positive by construction: the test above proved
            // `spent_ms < timeout_ms`.
            let remain_ms = timeout_ms - spent_ms;
            if self.wait(cx, remain_ms).await.is_err() {
                if let Some(tracer) = cx.tracer_mut() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Multi,
                        "[SHUTDOWN] shutdown finished, aborted",
                    );
                }
                break;
            }
        }

        // `:306-313`. From the FRONT each time, which is what C's repeated
        // `Curl_llist_head` does.
        while let Some(conn) = self.queue.pop_front() {
            terminate(cx, host, conn, false).await;
        }

        // `:314`.
        debug_assert!(
            self.queue.is_empty(),
            "the drain must leave the queue empty"
        );
    }

    /// `Curl_cshutdn_destroy` (`lib/cshutdn.c:329-351`): the owner's
    /// end-of-life call, with C's default budget of zero.
    ///
    /// # Panics
    ///
    /// As [`Self::destroy_with_timeout`].
    pub(crate) async fn destroy<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        handle: ShutdownHandle,
    ) where
        H: ShutdownHost + ?Sized,
    {
        self.destroy_with_timeout(cx, host, handle, 0).await;
    }

    /// [`Self::destroy`] with an explicit budget.
    ///
    /// # This parameter replaces an environment variable, deliberately
    ///
    /// # Panics
    ///
    /// As [`Self::terminate_all`].
    pub(crate) async fn destroy_with_timeout<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        handle: ShutdownHandle,
        timeout_ms: TimeDiff,
    ) where
        H: ShutdownHost + ?Sized,
    {
        // `:346-347`.
        if let Some(tracer) = cx.tracer_mut() {
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "[SHUTDOWN] destroy, {} connections, timeout={}ms",
                self.queue.len(),
                timeout_ms,
            );
        }
        self.terminate_all(cx, host, handle, timeout_ms).await;
    }
}

/// What an `adjust_pollset` failure does to a readiness walk.
///
/// The three C exports do not agree, and the disagreement is deliberate rather
/// than accidental, so it is named rather than smoothed over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OnAdjustError {
    /// The connection contributes nothing and the walk continues --
    /// `Curl_cshutdn_setfds` (`lib/cshutdn.c:454-455`) and
    /// `Curl_cshutdn_add_waitfds` (`:495`).
    Skip,
    /// The buffer is emptied and the error is returned --
    /// `Curl_cshutdn_add_pollfds` (`:524-528`).
    ///
    /// This one is about to be WAITED on. A partial set would wait on the wrong
    /// descriptors, and libcurl would then conclude that a connection had
    /// nothing to do when nobody had asked it.
    Abort,
}

impl Drop for ShutdownQueue {
    /// A non-blocking safety net. It cannot leak and it cannot double-free, and
    /// it deliberately does not attempt what [`ShutdownQueue::destroy`] does.
    fn drop(&mut self) {
        self.queue.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::sync_cell::SyncCell;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::conn::filters::{link, ConnFilter, FilterBase};
    use crate::conn::select::{is_valid_sock, WaitFd, CURL_SOCKET_BAD};
    use crate::error::CURLcode;
    use crate::trace::{TraceConfig, TraceState, Tracer, WriterSink};
    use crate::util::timeval::{Clock, CurlTime, TestClock};

    // Scaffolding

    /// A shared, ordered log of everything the injected seams were asked to do.
    ///
    /// The only way to observe a trait object's behaviour once it has been
    /// boxed into a connection, which is the same reason `conn/filters.rs`'s
    /// own tests keep one.
    type EventLog = Arc<SyncCell<Vec<String>>>;

    fn new_log() -> EventLog {
        Arc::new(SyncCell::new(Vec::new()))
    }

    fn events(log: &EventLog) -> Vec<String> {
        log.borrow().clone()
    }

    fn note(log: &EventLog, what: impl Into<String>) {
        log.borrow_mut().push(what.into());
    }

    /// Runs `body` against a tracer whose `MULTI` feature is verbose and
    /// returns everything it wrote.
    ///
    /// `MULTI` is the feature every `[SHUTDOWN]` line is emitted under, because
    /// `CURL_TRC_M` is a multi-handle line.
    fn multi_trace(body: impl FnOnce(&mut Tracer<'_>)) -> String {
        let mut config = TraceConfig::new();
        config
            .apply(Some(b"multi"))
            .expect("applying \"multi\" cannot fail");
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            body(&mut tracer);
        }
        String::from_utf8(sink.into_inner()).expect("trace output is text")
    }

    /// A clock fixed at a known instant, so that no test waits in real time.
    fn clock_at(secs: i64) -> TestClock {
        TestClock::new(CurlTime::new(secs, 0))
    }

    /// An injected clock a TEST FILTER can advance.
    #[derive(Clone, Debug)]
    struct SharedClock {
        at: Arc<SyncCell<CurlTime>>,
    }

    impl SharedClock {
        fn new(secs: i64) -> Self {
            Self {
                at: Arc::new(SyncCell::new(CurlTime::new(secs, 0))),
            }
        }

        fn advance_ms(&self, ms: u64) {
            let now = *self.at.borrow();
            *self.at.borrow_mut() = now.add(Duration::from_millis(ms));
        }
    }

    impl Clock for SharedClock {
        fn now(&self) -> CurlTime {
            *self.at.borrow_mut()
        }

        /// Wall-clock seconds are only used for formatting a trace timestamp,
        /// which nothing here asserts on, so a constant is honest and enough.
        fn epoch_secs(&self) -> i64 {
            0
        }
    }

    /// A readable trace destination for an `async` test.
    struct TraceCapture {
        config: TraceConfig,
        sink: WriterSink<Vec<u8>>,
    }

    impl TraceCapture {
        fn new() -> Self {
            let mut config = TraceConfig::new();
            config
                .apply(Some(b"multi"))
                .expect("applying \"multi\" cannot fail");
            Self {
                config,
                sink: WriterSink::new(Vec::new()),
            }
        }

        /// A verbose tracer over this capture. Disjoint field borrows, so the
        /// configuration is shared while the sink is written.
        fn tracer(&mut self) -> Tracer<'_> {
            Tracer::new(&self.config, &mut self.sink)
                .with_state(TraceState::verbose())
        }

        fn text(self) -> String {
            String::from_utf8(self.sink.into_inner())
                .expect("trace output is text")
        }
    }

    /// Drives a future to completion with no `tokio` runtime at all.
    fn drive<F: Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }

    // -- the injected timer ------------------------------------------------

    /// What a [`ShutdownTimer`] was asked, and what it answers.
    #[derive(Debug, Default)]
    struct TimerState {
        /// Whether each index has been started.
        started: [bool; SocketIndex::COUNT],
        /// The `timeout_ms` each `start` was passed, in order.
        starts: Vec<(SocketIndex, TimeDiff)>,
        /// What `time_left_ms` answers per index.
        left: [TimeDiff; SocketIndex::COUNT],
        /// Every index `clear` was called for, in order.
        cleared: Vec<SocketIndex>,
    }

    /// A recording [`ShutdownTimer`], standing in for `conn/mod.rs`'s.
    #[derive(Debug)]
    struct TestTimer {
        state: Arc<SyncCell<TimerState>>,
    }

    type TimerHandle = Arc<SyncCell<TimerState>>;

    impl TestTimer {
        /// Not `new`: it hands back a trait object and a handle on its state,
        /// so naming it `new` would misdescribe the return type.
        fn boxed() -> (Box<dyn ShutdownTimer>, TimerHandle) {
            let state: TimerHandle =
                Arc::new(SyncCell::new(TimerState::default()));
            (
                Box::new(Self {
                    state: Arc::clone(&state),
                }),
                state,
            )
        }
    }

    impl ShutdownTimer for TestTimer {
        fn started(&self, sockindex: SocketIndex) -> bool {
            self.state.borrow().started[sockindex.as_usize()]
        }

        fn start(&mut self, sockindex: SocketIndex, timeout_ms: TimeDiff) {
            let mut state = self.state.borrow_mut();
            state.started[sockindex.as_usize()] = true;
            state.starts.push((sockindex, timeout_ms));
        }

        fn time_left_ms(&self, sockindex: SocketIndex) -> TimeDiff {
            self.state.borrow().left[sockindex.as_usize()]
        }

        fn clear(&mut self, sockindex: SocketIndex) {
            self.state.borrow_mut().cleared.push(sockindex);
        }
    }

    // -- the injected protocol disconnect handler --------------------------

    /// A recording [`ProtocolDisconnect`].
    #[derive(Debug)]
    struct TestHandler {
        log: EventLog,
        /// How long the handler pretends to take. `None` returns at once.
        blocks_for: Option<Duration>,
    }

    impl TestHandler {
        /// Not `new`, for the reason [`TestTimer::boxed`] gives.
        fn boxed(log: &EventLog) -> Box<dyn ProtocolDisconnect> {
            Box::new(Self {
                log: Arc::clone(log),
                blocks_for: None,
            })
        }

        /// A handler that outlives its budget, to prove the cap is enforced.
        fn blocking(
            log: &EventLog,
            span: Duration,
        ) -> Box<dyn ProtocolDisconnect> {
            Box::new(Self {
                log: Arc::clone(log),
                blocks_for: Some(span),
            })
        }
    }

    impl ProtocolDisconnect for TestHandler {
        fn disconnect<'a>(
            &'a mut self,
            _cx: &'a mut CallCtx<'_, '_>,
            _chains: &'a mut FilterChains,
            dead: bool,
        ) -> DisconnectFuture<'a> {
            Box::pin(async move {
                note(&self.log, format!("disconnect(dead={dead})"));
                if let Some(span) = self.blocks_for {
                    tokio::time::sleep(span).await;
                    note(&self.log, "disconnect:finished");
                }
                Ok(())
            })
        }
    }

    // -- the injected multi handle -----------------------------------------

    /// A recording [`ShutdownHost`].
    #[derive(Debug)]
    struct TestHost {
        log: EventLog,
        has_admin: bool,
        has_multi: bool,
        internal: bool,
        socket_cb: bool,
        max_total: usize,
        /// What `assess_conn` answers.
        assess: CURLMcode,
    }

    impl TestHost {
        /// The ordinary case: a multi handle with an admin handle, no socket
        /// callback and no connection limit.
        fn new(log: &EventLog) -> Self {
            Self {
                log: Arc::clone(log),
                has_admin: true,
                has_multi: true,
                internal: true,
                socket_cb: false,
                max_total: 0,
                assess: CURLMcode::Ok,
            }
        }
    }

    impl ShutdownHost for TestHost {
        fn has_admin(&self) -> bool {
            self.has_admin
        }

        fn has_multi(&self) -> bool {
            self.has_multi
        }

        fn is_internal(&self, handle: ShutdownHandle) -> bool {
            self.internal && handle == ShutdownHandle::Admin
        }

        fn set_operation_timeout_ms(
            &mut self,
            handle: ShutdownHandle,
            timeout_ms: TimeDiff,
        ) {
            note(&self.log, format!("timeout({handle:?},{timeout_ms})"));
        }

        fn restart_operation_timing(&mut self, handle: ShutdownHandle) {
            note(&self.log, format!("startop({handle:?})"));
        }

        fn socket_cb_installed(&self) -> bool {
            self.socket_cb
        }

        fn assess_conn(
            &mut self,
            handle: ShutdownHandle,
            id: ConnId,
            _cx: &mut CallCtx<'_, '_>,
            _chains: &mut FilterChains,
        ) -> CURLMcode {
            note(&self.log, format!("assess({handle:?},#{id})"));
            self.assess
        }

        fn conn_done(
            &mut self,
            handle: ShutdownHandle,
            id: ConnId,
            _cx: &mut CallCtx<'_, '_>,
            _chains: &mut FilterChains,
        ) {
            note(&self.log, format!("conn_done({handle:?},#{id})"));
        }

        fn connchanged(&mut self) {
            note(&self.log, "connchanged");
        }

        fn expire(
            &mut self,
            handle: ShutdownHandle,
            timeout_ms: TimeDiff,
            timer: TimerId,
        ) {
            note(
                &self.log,
                format!(
                    "expire({handle:?},{timeout_ms},{},{})",
                    timer,
                    timer.as_i32()
                ),
            );
        }

        fn max_total_connections(&self) -> usize {
            self.max_total
        }
    }

    // -- a filter to put in the chains -------------------------------------

    /// What a [`TestFilter`] was asked, and how it answers.
    #[derive(Debug, Default)]
    struct FilterState {
        /// Remaining `shutdown` calls before it reports done.
        shutdown_steps: usize,
        /// When set, `shutdown` fails with this code.
        fail_shutdown: Option<CURLcode>,
        /// The descriptor `adjust_pollset` registers, if valid.
        socket: Socket,
        /// When set, `adjust_pollset` fails with this code.
        fail_pollset: Option<CURLcode>,
        /// When set, every `shutdown` advances this clock by that many
        /// milliseconds -- how a pass is made to "cost" engine time.
        advance_ms: Option<(SharedClock, u64)>,
        shutdowns: usize,
        closes: usize,
    }

    type FilterHandle = Arc<SyncCell<FilterState>>;

    /// A minimal bottom-of-chain filter: no transport, only bookkeeping.
    #[derive(Debug)]
    struct TestFilter {
        base: FilterBase,
        state: FilterHandle,
        name: &'static str,
        log: EventLog,
    }

    impl TestFilter {
        /// A CONNECTED filter, which is the state a shutdown finds one in.
        fn connected(
            name: &'static str,
            sockindex: SocketIndex,
            log: &EventLog,
        ) -> (Self, FilterHandle) {
            let state: FilterHandle = Arc::new(SyncCell::new(FilterState {
                socket: CURL_SOCKET_BAD,
                ..FilterState::default()
            }));
            let mut base = FilterBase::new(sockindex);
            base.set_connected(true);
            let filter = Self {
                base,
                state: Arc::clone(&state),
                name,
                log: Arc::clone(log),
            };
            (filter, state)
        }
    }

    /// Logging the destructor is how a test proves a connection was CONSUMED: a
    /// filter cannot be dropped while anything still owns the chain holding it.
    impl Drop for TestFilter {
        fn drop(&mut self) {
            note(&self.log, format!("{}:drop", self.name));
        }
    }

    impl ConnFilter for TestFilter {
        fn trace_name(&self) -> &'static str {
            self.name
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

        fn close(&mut self, _cx: &mut CallCtx<'_, '_>) {
            self.state.borrow_mut().closes += 1;
            self.base.set_connected(false);
            note(&self.log, format!("{}:close", self.name));
        }

        fn shutdown(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            let mut state = self.state.borrow_mut();
            state.shutdowns += 1;
            if let Some((clock, ms)) = state.advance_ms.clone() {
                clock.advance_ms(ms);
            }
            if let Some(code) = state.fail_shutdown {
                drop(state);
                note(&self.log, format!("{}:shutdown_err", self.name));
                return Err(Error::new(code));
            }
            if state.shutdown_steps > 0 {
                state.shutdown_steps -= 1;
            }
            let done = state.shutdown_steps == 0;
            drop(state);
            note(&self.log, format!("{}:shutdown({done})", self.name));
            Ok(done)
        }

        fn adjust_pollset(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            ps: &mut EasyPollset,
        ) -> CurlResult<()> {
            let (sock, failure) = {
                let state = self.state.borrow();
                (state.socket, state.fail_pollset)
            };
            if let Some(code) = failure {
                return Err(Error::new(code));
            }
            if !is_valid_sock(sock) {
                return Ok(());
            }
            ps.set(sock, true, false, cx.tracer_mut())
                .map_err(Error::from)
        }
    }

    // -- connection builders -----------------------------------------------

    /// A connection with EMPTY chains, so no filter work is possible.
    fn bare_conn(
        id: u64,
        destination: &str,
    ) -> (ShuttingDownConnection, TimerHandle) {
        let (timer, handle) = TestTimer::boxed();
        let conn = ShuttingDownConnection::new(
            ConnId::new(id),
            destination,
            FilterChains::new(Some(ConnId::new(id))),
            timer,
        );
        (conn, handle)
    }

    /// A connection with one connected filter on each chain.
    fn wired_conn(
        cx: &mut CallCtx<'_, '_>,
        id: u64,
        destination: &str,
        log: &EventLog,
    ) -> (
        ShuttingDownConnection,
        TimerHandle,
        FilterHandle,
        FilterHandle,
    ) {
        let (mut conn, timer) = bare_conn(id, destination);
        let (first, first_state) =
            TestFilter::connected("first", SocketIndex::First, log);
        let (second, second_state) =
            TestFilter::connected("second", SocketIndex::Secondary, log);
        conn.chains_mut()
            .chain_mut(SocketIndex::First)
            .add(cx, link(first));
        conn.chains_mut()
            .chain_mut(SocketIndex::Secondary)
            .add(cx, link(second));
        (conn, timer, first_state, second_state)
    }

    // 19. The timer identity

    /// `EXPIRE_SHUTDOWN` is **14**, and it is the same 14 the trace table uses.
    ///
    /// Positional in the C -- `expire_id` declares no discriminants -- so the
    /// only way it can be wrong is by a reordering, which this catches.
    #[test]
    fn the_shutdown_timer_id_is_fourteen_and_is_named_shutdown() {
        assert_eq!(EXPIRE_SHUTDOWN, 14);
        assert_eq!(TimerId::Shutdown.as_i32(), EXPIRE_SHUTDOWN);
        assert_eq!(TimerId::Shutdown.name(), "SHUTDOWN");
    }

    /// The two socket indices are C's 0 and 1, and nothing else is an index.
    #[test]
    fn the_socket_indices_are_the_c_integers() {
        assert_eq!(FIRSTSOCKET, 0);
        assert_eq!(SECONDARYSOCKET, 1);
        assert_eq!(SocketIndex::First.as_i32(), FIRSTSOCKET);
        assert_eq!(SocketIndex::Secondary.as_i32(), SECONDARYSOCKET);
        assert_eq!(
            SocketIndex::from_i32(2).unwrap_err(),
            CURLcode::BadFunctionArgument
        );
        assert_eq!(
            SocketIndex::from_i32(-1).unwrap_err(),
            CURLcode::BadFunctionArgument
        );
    }

    /// The budget is two seconds, and it is the one `filters.rs` holds.
    #[test]
    fn the_default_shutdown_budget_is_two_seconds() {
        assert_eq!(DEFAULT_SHUTDOWN_TIMEOUT_MS, 2000);
        assert_eq!(WAIT_SLICE_MAX_MS, 1000);
    }

    // 1-3. The protocol disconnect handler

    /// A handler-less scheme still latches, and the latch is what stops
    /// `Curl_conn_free` running a handler that does not exist.
    ///
    /// `lib/cshutdn.c:65` sits outside the `if` at `:46`; this is that
    /// placement.
    #[tokio::test]
    async fn a_scheme_without_a_handler_still_latches() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let (mut conn, _timer) = bare_conn(1, "example.com:443");

        assert!(!conn.handler_has_run());
        assert!(!conn.has_handler());
        conn.run_conn_handler(&mut cx, &mut host, ShutdownHandle::Admin)
            .await;
        assert!(conn.handler_has_run());
        assert!(events(&log).is_empty(), "no handler, so nothing was called");
    }

    /// The handler runs EXACTLY once however often the step is repeated.
    #[tokio::test]
    async fn a_handler_runs_exactly_once_and_receives_dead() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let (conn, _timer) = bare_conn(2, "example.com:443");
        let mut conn = conn
            .with_handler(TestHandler::boxed(&log))
            .with_aborted(true);

        for _ in 0..3 {
            conn.run_conn_handler(&mut cx, &mut host, ShutdownHandle::Admin)
                .await;
        }

        let seen = events(&log);
        assert_eq!(
            seen.iter().filter(|e| e.starts_with("disconnect(")).count(),
            1,
            "the latch admits exactly one call: {seen:?}"
        );
        assert!(
            seen.contains(&"disconnect(dead=true)".to_string()),
            "`dead` is `conn->bits.aborted`: {seen:?}"
        );
        // The two handle statements of `:52-53`, once, in the C's order.
        assert_eq!(
            seen.iter()
                .filter(
                    |e| e.starts_with("timeout(") || e.starts_with("startop(")
                )
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "timeout(Admin,2000)".to_string(),
                "startop(Admin)".to_string()
            ],
        );
    }

    /// A blocking handler on the INTERNAL handle is cut off at exactly 2000 ms.
    #[tokio::test(start_paused = true)]
    async fn the_internal_handler_budget_is_two_thousand_milliseconds() {
        // Just under: the outer bound wins, so the cap is not shorter.
        {
            let log = new_log();
            let clock = clock_at(1);
            let mut host = TestHost::new(&log);
            let mut cx = CallCtx::new(&clock);
            let (conn, _timer) = bare_conn(3, "example.com:443");
            let mut conn = conn.with_handler(TestHandler::blocking(
                &log,
                Duration::from_secs(5),
            ));
            let raced = tokio::time::timeout(
                Duration::from_millis(1_999),
                conn.run_conn_handler(
                    &mut cx,
                    &mut host,
                    ShutdownHandle::Admin,
                ),
            )
            .await;
            assert!(raced.is_err(), "the cap is not shorter than 2000 ms");
        }

        // Just over: the cap wins, the handler is cancelled, and the latch is
        // set even though the handler never finished.
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let (conn, _timer) = bare_conn(3, "example.com:443");
        let mut conn = conn
            .with_handler(TestHandler::blocking(&log, Duration::from_secs(5)));
        let raced = tokio::time::timeout(
            Duration::from_millis(2_001),
            conn.run_conn_handler(&mut cx, &mut host, ShutdownHandle::Admin),
        )
        .await;
        assert!(raced.is_ok(), "the cap is not longer than 2000 ms");

        let seen = events(&log);
        assert!(seen.contains(&"disconnect(dead=false)".to_string()));
        assert!(
            !seen.contains(&"disconnect:finished".to_string()),
            "the handler was cancelled, not awaited to completion: {seen:?}"
        );
        assert!(conn.handler_has_run(), "the latch is set even so");
    }

    /// An application handle gets no budget: C leaves `data->set.timeout` alone
    /// unless `data->state.internal` (`lib/cshutdn.c:51`).
    #[tokio::test(start_paused = true)]
    async fn an_application_handle_is_not_capped() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        host.has_admin = false;
        let mut cx = CallCtx::new(&clock);
        let (conn, _timer) = bare_conn(4, "example.com:443");
        let mut conn = conn
            .with_handler(TestHandler::blocking(&log, Duration::from_secs(5)));

        conn.run_conn_handler(&mut cx, &mut host, ShutdownHandle::Caller)
            .await;

        let seen = events(&log);
        assert!(
            seen.contains(&"disconnect:finished".to_string()),
            "uncapped, so it ran to completion: {seen:?}"
        );
        assert!(
            !seen.iter().any(|e| e.starts_with("timeout(")),
            "no budget was imposed: {seen:?}"
        );
    }

    // 4-8. One shutdown step

    /// Only the PRIMARY index starts the queue's timer, and it asks for the
    /// timer's own default by passing zero.
    ///
    /// Measured on empty chains so that the chain-level start of
    /// `lib/cfilters.c:180` cannot contribute a second entry -- that one is
    /// `filters.rs`'s and is exercised there.
    #[tokio::test]
    async fn only_the_primary_index_starts_the_shared_timer() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let (mut conn, timer) = bare_conn(5, "example.com:443");

        assert!(
            conn.run_once(&mut cx, &mut host, ShutdownHandle::Admin)
                .await
        );
        assert_eq!(
            timer.borrow().starts,
            vec![(SocketIndex::First, 0)],
            "one start, primary index, timeout argument zero"
        );
        assert!(!timer.borrow().started[SocketIndex::Secondary.as_usize()]);
    }

    /// A connect-only connection touches no filter: the application owns the
    /// socket now.
    #[tokio::test]
    async fn connect_only_skips_the_filter_chains() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let (conn, _timer, first, second) =
            wired_conn(&mut cx, 6, "example.com:443", &log);
        let mut conn = conn.with_connect_only(true);

        assert!(
            conn.run_once(&mut cx, &mut host, ShutdownHandle::Admin)
                .await,
            "a skipped chain counts as done"
        );
        assert_eq!(first.borrow().shutdowns, 0);
        assert_eq!(second.borrow().shutdowns, 0);
        assert!(conn.filters_have_shut_down());
    }

    /// An error on EITHER chain finishes the shutdown, and both chains are
    /// still attempted.
    ///
    /// `*done = (r1 || r2 || (done1 && done2))` -- the error terms come first
    /// and there is no short circuit between the two chain calls.
    #[tokio::test]
    async fn an_error_on_either_chain_ends_the_shutdown() {
        for failing in [SocketIndex::First, SocketIndex::Secondary] {
            let log = new_log();
            let clock = clock_at(1);
            let mut host = TestHost::new(&log);
            let mut cx = CallCtx::new(&clock);
            let (mut conn, _timer, first, second) =
                wired_conn(&mut cx, 7, "example.com:443", &log);
            // Neither chain would finish on its own.
            first.borrow_mut().shutdown_steps = 9;
            second.borrow_mut().shutdown_steps = 9;
            let target = if failing == SocketIndex::First {
                &first
            } else {
                &second
            };
            target.borrow_mut().fail_shutdown = Some(CURLcode::SendError);

            assert!(
                conn.run_once(&mut cx, &mut host, ShutdownHandle::Admin)
                    .await,
                "{failing:?} failed, so the shutdown is over"
            );
            assert_eq!(first.borrow().shutdowns, 1, "primary was attempted");
            assert_eq!(
                second.borrow().shutdowns,
                1,
                "secondary was attempted too"
            );
            assert!(conn.filters_have_shut_down());
        }
    }

    /// Absent an error, BOTH chains must report themselves done.
    #[tokio::test]
    async fn both_chains_must_finish_when_neither_fails() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let (mut conn, _timer, first, second) =
            wired_conn(&mut cx, 8, "example.com:443", &log);
        // The primary finishes at once; the secondary needs two passes.
        second.borrow_mut().shutdown_steps = 2;

        assert!(
            !conn
                .run_once(&mut cx, &mut host, ShutdownHandle::Admin)
                .await,
            "one chain outstanding is not done"
        );
        assert!(!conn.filters_have_shut_down());
        assert_eq!(second.borrow().shutdowns, 1);

        assert!(
            conn.run_once(&mut cx, &mut host, ShutdownHandle::Admin)
                .await,
            "now both report done"
        );
        assert!(conn.filters_have_shut_down());
        // NOT two. A filter that reported done had its `shutdown` flag set, and
        // `Curl_conn_shutdown` skips connected-and-already-shut-down filters on
        // the way in (`lib/cfilters.c:169-176`); with none left it answers done
        // without calling anything. So the primary is asked exactly once even
        // though the connection was stepped twice.
        assert_eq!(first.borrow().shutdowns, 1);
    }

    /// Once the filter latch is set, a further step returns done at once and
    /// touches nothing.
    #[tokio::test]
    async fn the_filter_latch_short_circuits_a_later_step() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let (mut conn, _timer, first, second) =
            wired_conn(&mut cx, 9, "example.com:443", &log);

        assert!(
            conn.run_once(&mut cx, &mut host, ShutdownHandle::Admin)
                .await
        );
        let (before_first, before_second) =
            (first.borrow().shutdowns, second.borrow().shutdowns);

        // Make the chains unfinishable; the latch must not consult them.
        first.borrow_mut().shutdown_steps = 99;
        second.borrow_mut().shutdown_steps = 99;

        assert!(
            conn.run_once(&mut cx, &mut host, ShutdownHandle::Admin)
                .await
        );
        assert_eq!(first.borrow().shutdowns, before_first);
        assert_eq!(second.borrow().shutdowns, before_second);
    }

    /// The step's trace is `[SHUTDOWN] shutdown, done=%d`, with `done` printed
    /// as C's `%d` prints a bit.
    #[test]
    fn the_step_trace_reports_done_as_a_bit() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let (mut conn, _timer, _first, second) = {
            let mut cx = CallCtx::new(&clock);
            wired_conn(&mut cx, 10, "example.com:443", &log)
        };
        second.borrow_mut().shutdown_steps = 2;

        let unfinished = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            let done =
                drive(conn.run_once(&mut cx, &mut host, ShutdownHandle::Admin));
            assert!(!done);
        });
        assert!(
            unfinished.contains("[SHUTDOWN] shutdown, done=0"),
            "got {unfinished:?}"
        );

        let finished = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            let done =
                drive(conn.run_once(&mut cx, &mut host, ShutdownHandle::Admin));
            assert!(done);
        });
        assert!(
            finished.contains("[SHUTDOWN] shutdown, done=1"),
            "got {finished:?}"
        );
    }

    /// A TERMINATION's final step is silent: `Curl_cshutdn_terminate` calls the
    /// `static` `cshutdn_run_once` (`lib/cshutdn.c:148`), not the traced
    /// wrapper, so a close emits no `shutdown, done=` line.
    #[test]
    fn a_terminations_final_step_emits_no_step_line() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let (conn, _timer, _first, _second) = {
            let mut cx = CallCtx::new(&clock);
            wired_conn(&mut cx, 11, "example.com:443", &log)
        };

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            drive(terminate(&mut cx, &mut host, conn, true));
        });
        assert!(
            !text.contains("shutdown, done="),
            "the final step must be silent: {text:?}"
        );
        assert!(text.contains("[SHUTDOWN] closing connection #11"));
    }

    // 9-11. Termination

    /// Termination CONSUMES the connection, and the proof is that everything it
    /// owned is dropped.
    #[test]
    fn termination_consumes_the_connection_and_releases_everything() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let (conn, _timer, first, second) =
            wired_conn(&mut cx, 12, "example.com:443", &log);
        // Two outstanding handles on the filter state, one of them ours.
        assert_eq!(Arc::strong_count(&first), 2);

        drive(terminate(&mut cx, &mut host, conn, false));

        assert_eq!(
            Arc::strong_count(&first),
            1,
            "the primary filter was dropped, so the connection was consumed"
        );
        assert_eq!(Arc::strong_count(&second), 1);
        let seen = events(&log);
        assert!(seen.contains(&"first:drop".to_string()), "{seen:?}");
        assert!(seen.contains(&"second:drop".to_string()), "{seen:?}");
    }

    /// The close order is SECONDARY then PRIMARY, and the chains are then
    /// discarded in the opposite order.
    #[test]
    fn the_close_order_is_secondary_then_primary() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let (conn, timer, _first, _second) =
            wired_conn(&mut cx, 13, "example.com:443", &log);

        drive(terminate(&mut cx, &mut host, conn, false));

        let closes: Vec<String> = events(&log)
            .into_iter()
            .filter(|e| e.ends_with(":close"))
            .collect();
        assert_eq!(closes, vec!["second:close", "first:close"]);

        // `Curl_conn_close` is close-then-clear, so the timer sees the same
        // order (`lib/cfilters.c:154`).
        assert_eq!(
            timer.borrow().cleared,
            vec![SocketIndex::Secondary, SocketIndex::First]
        );

        let drops: Vec<String> = events(&log)
            .into_iter()
            .filter(|e| e.ends_with(":drop"))
            .collect();
        assert_eq!(
            drops,
            vec!["first:drop", "second:drop"],
            "the discard walks the array by index, the reverse of the close"
        );
    }

    /// The `force ` prefix is decided by the FILTER LATCH, not by whether this
    /// call tried to shut down.
    #[test]
    fn the_force_prefix_follows_the_filter_latch() {
        // Unfinished filters, and no final attempt: forced.
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let (conn, _timer, first, _second) = {
            let mut cx = CallCtx::new(&clock);
            wired_conn(&mut cx, 14, "example.com:443", &log)
        };
        first.borrow_mut().shutdown_steps = 9;
        let forced = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            drive(terminate(&mut cx, &mut host, conn, false));
        });
        assert!(
            forced.contains("[SHUTDOWN] force closing connection #14"),
            "got {forced:?}"
        );

        // Filters that finish during the final attempt: graceful, even though
        // the same call asked for the shutdown.
        let log = new_log();
        let (conn, _timer, _first, _second) = {
            let mut cx = CallCtx::new(&clock);
            wired_conn(&mut cx, 15, "example.com:443", &log)
        };
        let graceful = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            drive(terminate(&mut cx, &mut host, conn, true));
        });
        assert!(
            graceful.contains("[SHUTDOWN] closing connection #15"),
            "got {graceful:?}"
        );
        assert!(!graceful.contains("force closing"), "got {graceful:?}");
    }

    /// The admin handle does the close and the free; the CALLER's multi handle
    /// decides whether anyone is notified.
    ///
    /// `lib/cshutdn.c:135-164`: the substitution covers the handler, the final
    /// attempt, the closes and the release, while `conn_done` and `connchanged`
    /// are charged to `data` and gated on `data->multi`.
    #[tokio::test]
    async fn the_admin_handle_closes_while_the_caller_governs_notifications() {
        // With an admin handle and a multi handle: substituted, and notified.
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let (conn, _timer, _first, _second) = {
            let mut cx = CallCtx::new(&clock);
            wired_conn(&mut cx, 16, "example.com:443", &log)
        };
        let conn = conn.with_handler(TestHandler::boxed(&log));
        let mut capture = TraceCapture::new();
        {
            let mut tracer = capture.tracer();
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            terminate(&mut cx, &mut host, conn, false).await;
        }
        let text = capture.text();
        let seen = events(&log);
        assert!(
            seen.contains(&"timeout(Admin,2000)".to_string()),
            "{seen:?}"
        );
        assert!(
            seen.contains(&"conn_done(Caller,#16)".to_string()),
            "{seen:?}"
        );
        assert!(seen.contains(&"connchanged".to_string()), "{seen:?}");
        assert!(text.contains("[SHUTDOWN] trigger multi connchanged"));

        // No multi handle: no admin substitution, and NO notifications.
        let log = new_log();
        let mut host = TestHost::new(&log);
        host.has_admin = false;
        host.has_multi = false;
        let (conn, _timer, _first, _second) = {
            let mut cx = CallCtx::new(&clock);
            wired_conn(&mut cx, 17, "example.com:443", &log)
        };
        let conn = conn.with_handler(TestHandler::boxed(&log));
        let mut capture = TraceCapture::new();
        {
            let mut tracer = capture.tracer();
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            terminate(&mut cx, &mut host, conn, false).await;
        }
        let text = capture.text();
        let seen = events(&log);
        assert!(
            !seen.iter().any(|e| e.starts_with("conn_done(")),
            "no multi handle, no event layer to correct: {seen:?}"
        );
        assert!(!seen.contains(&"connchanged".to_string()), "{seen:?}");
        assert!(!text.contains("trigger multi connchanged"), "got {text:?}");
        // The close still happened, against the caller's own handle.
        assert!(seen.contains(&"first:close".to_string()), "{seen:?}");
        assert!(
            seen.contains(&"disconnect(dead=false)".to_string()),
            "{seen:?}"
        );
    }

    // 12-16. The FIFO, the counts and the combined limit

    /// A helper: enqueue `n` bare connections numbered from `first_id`.
    fn fill(
        queue: &mut ShutdownQueue,
        cx: &mut CallCtx<'_, '_>,
        host: &mut TestHost,
        ids: &[(u64, &str)],
    ) {
        for (id, destination) in ids {
            let (conn, _timer) = bare_conn(*id, destination);
            drive(queue.add(cx, host, conn, 0));
        }
    }

    /// The queue appends at the tail and takes the head as "oldest": insertion
    /// order is the whole of the ordering.
    #[test]
    fn the_queue_is_a_fifo_and_the_oldest_is_the_head() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let mut queue = ShutdownQueue::new();

        fill(
            &mut queue,
            &mut cx,
            &mut host,
            &[(1, "a:80"), (2, "b:80"), (3, "c:80")],
        );
        assert_eq!(queue.count(), 3);

        let mut closed = Vec::new();
        for _ in 0..3 {
            let text = multi_trace(|tracer| {
                let mut cx = CallCtx::new(&clock).with_tracer(tracer);
                assert!(drive(queue.close_oldest(&mut cx, &mut host, None)));
            });
            let id = text
                .split("closing connection #")
                .nth(1)
                .and_then(|rest| rest.split('\n').next())
                .expect("a closing line")
                .to_string();
            closed.push(id);
        }
        assert_eq!(closed, vec!["1", "2", "3"], "strictly insertion order");
        assert!(queue.is_empty());
        assert!(
            !drive(queue.close_oldest(&mut cx, &mut host, None)),
            "nothing left to close"
        );
    }

    /// With a destination, "oldest" is the FIRST MATCH from the head -- still
    /// FIFO, just filtered.
    #[test]
    fn a_destination_selects_the_first_match_from_the_head() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let mut queue = ShutdownQueue::new();

        fill(
            &mut queue,
            &mut cx,
            &mut host,
            &[(1, "a:80"), (2, "b:80"), (3, "b:80"), (4, "a:80")],
        );

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            assert!(drive(queue.close_oldest(
                &mut cx,
                &mut host,
                Some("b:80")
            )));
        });
        assert!(text.contains("closing connection #2"), "got {text:?}");
        assert_eq!(queue.count(), 3);
        assert_eq!(queue.destination_count("b:80"), 1);
        assert_eq!(queue.destination_count("a:80"), 2);

        assert!(
            !drive(queue.close_oldest(&mut cx, &mut host, Some("z:80"))),
            "an unmatched destination closes nothing"
        );
        assert_eq!(queue.count(), 3);
    }

    /// The counts are what `crate::conn::pool` reads on every eviction turn.
    #[test]
    fn the_counts_are_a_total_and_a_per_destination_tally() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let mut queue = ShutdownQueue::new();

        assert_eq!(queue.count(), 0);
        assert!(queue.is_empty());
        assert_eq!(queue.destination_count("a:80"), 0);

        fill(
            &mut queue,
            &mut cx,
            &mut host,
            &[(1, "a:80"), (2, "a:80"), (3, "b:443")],
        );
        assert_eq!(queue.count(), 3);
        assert!(!queue.is_empty());
        assert_eq!(queue.destination_count("a:80"), 2);
        assert_eq!(queue.destination_count("b:443"), 1);
        // Exact byte equality, so nothing near-misses into a match.
        assert_eq!(queue.destination_count("a:8"), 0);
        assert_eq!(queue.destination_count("A:80"), 0);
    }

    /// Pooled and shutting-down connections count TOGETHER against
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS`, and the pooled figure arrives as a
    /// parameter.
    #[test]
    fn the_connection_limit_counts_the_pool_and_the_queue_together() {
        let clock = clock_at(1);

        // One queued, two pooled, limit three: 3 <= 2 + 1, so the head goes.
        let log = new_log();
        let mut host = TestHost::new(&log);
        host.max_total = 3;
        let mut queue = ShutdownQueue::new();
        {
            let mut cx = CallCtx::new(&clock);
            fill(&mut queue, &mut cx, &mut host, &[(1, "a:80")]);
        }
        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            let (conn, _timer) = bare_conn(2, "b:80");
            drive(queue.add(&mut cx, &mut host, conn, 2));
        });
        assert!(
            text.contains(
                "[SHUTDOWN] discarding oldest shutdown connection due to \
                 connection limit of 3"
            ),
            "got {text:?}"
        );
        assert!(text.contains("closing connection #1"), "got {text:?}");
        assert!(
            text.contains(
                "[SHUTDOWN] added #2 to shutdowns, now 1 conns in shutdown"
            ),
            "got {text:?}"
        );
        assert_eq!(
            queue.count(),
            1,
            "one out, one in -- an `if`, not a `while`"
        );

        // The SAME queue state with one fewer pooled connection: 3 <= 1 + 1 is
        // false, so nothing is discarded. Only the parameter changed, which is
        // what proves the queue reads the pool through it and nowhere else.
        let log = new_log();
        let mut host = TestHost::new(&log);
        host.max_total = 3;
        let mut queue = ShutdownQueue::new();
        {
            let mut cx = CallCtx::new(&clock);
            fill(&mut queue, &mut cx, &mut host, &[(1, "a:80")]);
        }
        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            let (conn, _timer) = bare_conn(2, "b:80");
            drive(queue.add(&mut cx, &mut host, conn, 1));
        });
        assert!(!text.contains("discarding oldest"), "got {text:?}");
        assert_eq!(queue.count(), 2);

        // A limit of zero is unlimited, however many are already queued.
        let log = new_log();
        let mut host = TestHost::new(&log);
        host.max_total = 0;
        let mut queue = ShutdownQueue::new();
        let mut cx = CallCtx::new(&clock);
        fill(&mut queue, &mut cx, &mut host, &[(1, "a:80"), (2, "b:80")]);
        let (conn, _timer) = bare_conn(3, "c:80");
        drive(queue.add(&mut cx, &mut host, conn, 1_000));
        assert_eq!(queue.count(), 3);
    }

    /// A failed event assessment discards the connection instead of enqueueing
    /// it, and the assessment is skipped entirely without a socket callback.
    #[test]
    fn a_failed_event_assessment_discards_the_connection() {
        let clock = clock_at(1);

        let log = new_log();
        let mut host = TestHost::new(&log);
        host.socket_cb = true;
        host.assess = CURLMcode::InternalError;
        let mut queue = ShutdownQueue::new();
        let (conn, _timer, first, _second) = {
            let mut cx = CallCtx::new(&clock);
            wired_conn(&mut cx, 18, "a:80", &log)
        };
        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            drive(queue.add(&mut cx, &mut host, conn, 0));
        });
        assert!(
            text.contains("[SHUTDOWN] update events failed, discarding #18"),
            "got {text:?}"
        );
        assert!(
            text.contains("force closing connection #18"),
            "got {text:?}"
        );
        assert!(
            !text.contains("added #18"),
            "it was never enqueued: {text:?}"
        );
        assert!(queue.is_empty());
        assert_eq!(
            Arc::strong_count(&first),
            1,
            "discarded means terminated, not leaked"
        );

        // No socket callback: no assessment at all, so the failure path is
        // unreachable for a plain `curl_multi_perform` user.
        let log = new_log();
        let mut host = TestHost::new(&log);
        host.socket_cb = false;
        host.assess = CURLMcode::InternalError;
        let mut queue = ShutdownQueue::new();
        let mut cx = CallCtx::new(&clock);
        let (conn, _timer) = bare_conn(19, "a:80");
        drive(queue.add(&mut cx, &mut host, conn, 0));
        assert_eq!(queue.count(), 1);
        assert!(
            !events(&log).iter().any(|e| e.starts_with("assess(")),
            "{:?}",
            events(&log)
        );
    }

    /// A successful assessment is charged to the admin handle and lets the
    /// connection through.
    #[test]
    fn a_successful_event_assessment_admits_the_connection() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        host.socket_cb = true;
        let mut cx = CallCtx::new(&clock);
        let mut queue = ShutdownQueue::new();

        let (conn, _timer) = bare_conn(20, "a:80");
        drive(queue.add(&mut cx, &mut host, conn, 0));

        assert_eq!(queue.count(), 1);
        assert!(events(&log).contains(&"assess(Admin,#20)".to_string()));
    }

    // 17-18. The multi-driven pass

    /// A connection with one connected filter on the PRIMARY chain only.
    ///
    /// One chain is enough for every queue-level test, and it keeps the log
    /// short enough to assert on.
    fn queued_conn(
        cx: &mut CallCtx<'_, '_>,
        id: u64,
        destination: &str,
        name: &'static str,
        log: &EventLog,
    ) -> (ShuttingDownConnection, TimerHandle, FilterHandle) {
        let (mut conn, timer) = bare_conn(id, destination);
        let (filter, state) =
            TestFilter::connected(name, SocketIndex::First, log);
        conn.chains_mut()
            .chain_mut(SocketIndex::First)
            .add(cx, link(filter));
        (conn, timer, state)
    }

    /// A connection whose only filter is on the SECONDARY chain.
    fn secondary_queued_conn(
        cx: &mut CallCtx<'_, '_>,
        id: u64,
        destination: &str,
        log: &EventLog,
    ) -> (ShuttingDownConnection, TimerHandle, FilterHandle) {
        let (mut conn, timer) = bare_conn(id, destination);
        let (filter, state) =
            TestFilter::connected("second", SocketIndex::Secondary, log);
        state.borrow_mut().shutdown_steps = 9;
        conn.chains_mut()
            .chain_mut(SocketIndex::Secondary)
            .add(cx, link(filter));
        (conn, timer, state)
    }

    /// A pass removes and terminates only what finished, keeps the rest IN
    /// ORDER, and does not lose its place.
    ///
    /// C captures the successor before stepping (`lib/cshutdn.c:245`); the
    /// index walk here lands in the same place, which is what this measures.
    #[test]
    fn a_pass_is_removal_safe_and_preserves_the_order_of_the_rest() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let mut queue = ShutdownQueue::new();

        let mut states = Vec::new();
        for (id, name) in
            [(1_u64, "one"), (2, "two"), (3, "three"), (4, "four")]
        {
            let (conn, _timer, state) =
                queued_conn(&mut cx, id, "a:80", name, &log);
            // Only the middle two finish on this pass.
            if id == 1 || id == 4 {
                state.borrow_mut().shutdown_steps = 9;
            }
            states.push((id, state));
            drive(queue.add(&mut cx, &mut host, conn, 0));
        }
        assert_eq!(queue.count(), 4);

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            drive(queue.perform_once(
                &mut cx,
                &mut host,
                ShutdownHandle::Admin,
            ));
        });

        assert!(
            text.contains("[SHUTDOWN] perform on 4 connections"),
            "got {text:?}"
        );
        assert_eq!(queue.count(), 2, "the two that finished were removed");
        // Every one of the four was stepped: the walk did not skip the element
        // that shifted down after a removal.
        for (id, state) in &states {
            assert_eq!(
                state.borrow().shutdowns,
                1,
                "connection #{id} was stepped exactly once"
            );
        }
        // The two that finished were the two that were closed, and neither
        // survivor was.
        assert!(
            text.contains("[SHUTDOWN] closing connection #2"),
            "got {text:?}"
        );
        assert!(
            text.contains("[SHUTDOWN] closing connection #3"),
            "got {text:?}"
        );
        assert!(!text.contains("connection #1"), "got {text:?}");
        assert!(!text.contains("connection #4"), "got {text:?}");

        // The survivors kept their RELATIVE ORDER: draining the FIFO yields
        // them oldest first, which is 1 before 4.
        assert_eq!(queue.destination_count("a:80"), 2);
        let mut drained = Vec::new();
        for _ in 0..2 {
            let closing = multi_trace(|tracer| {
                let mut cx = CallCtx::new(&clock).with_tracer(tracer);
                assert!(drive(queue.close_oldest(&mut cx, &mut host, None)));
            });
            let id = closing
                .split("closing connection #")
                .nth(1)
                .and_then(|rest| rest.split('\n').next())
                .expect("a closing line")
                .to_string();
            drained.push(id);
        }
        assert_eq!(drained, vec!["1", "4"], "insertion order survived removal");
        assert!(queue.is_empty());
    }

    /// An empty queue is a no-op: no trace, no timer.
    #[test]
    fn a_pass_over_an_empty_queue_does_nothing() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut queue = ShutdownQueue::new();

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            drive(queue.perform_once(
                &mut cx,
                &mut host,
                ShutdownHandle::Admin,
            ));
        });
        assert_eq!(text, "");
        assert!(events(&log).is_empty());
    }

    /// **The frozen expiry arithmetic.** A POSITIVE remaining time never arms
    /// the timer; only a NEGATIVE one does; zero never does.
    #[test]
    fn the_expiry_arithmetic_ignores_positive_deadlines() {
        // (primary remaining, secondary remaining) -> expected armed value
        let cases: [([TimeDiff; 2], Option<TimeDiff>); 6] = [
            // Positive: never armed, however small.
            ([500, 0], None),
            ([1, 0], None),
            // Zero everywhere: no limit, so nothing to arm.
            ([0, 0], None),
            // Negative: armed with the negative value.
            ([-5, 0], Some(-5)),
            // Two negatives: the smaller (more expired) wins.
            ([-5, -50], Some(-50)),
            // A negative beside a positive: the combination rule takes the
            // negative, and the quirk then arms it.
            ([-5, 500], Some(-5)),
        ];

        for (left, expected) in cases {
            let log = new_log();
            let clock = clock_at(1);
            let mut host = TestHost::new(&log);
            let mut cx = CallCtx::new(&clock);
            let mut queue = ShutdownQueue::new();

            // Unfinished work on the SECONDARY chain, so the connection is
            // RETAINED and its combined deadline is consulted -- see
            // [`secondary_queued_conn`] for why the primary chain cannot be
            // used here.
            let (conn, timer, _state) =
                secondary_queued_conn(&mut cx, 1, "a:80", &log);
            timer.borrow_mut().left = left;
            drive(queue.add(&mut cx, &mut host, conn, 0));

            drive(queue.perform_once(
                &mut cx,
                &mut host,
                ShutdownHandle::Admin,
            ));

            let armed: Vec<String> = events(&log)
                .into_iter()
                .filter(|e| e.starts_with("expire("))
                .collect();
            match expected {
                None => assert!(
                    armed.is_empty(),
                    "left={left:?} must arm nothing, got {armed:?}"
                ),
                Some(ms) => assert_eq!(
                    armed,
                    vec![format!("expire(Admin,{ms},SHUTDOWN,14)")],
                    "left={left:?}"
                ),
            }
        }
    }

    /// A connection that FINISHED contributes no deadline: it is terminated
    /// instead, so the timer is never consulted for it.
    #[test]
    fn a_finished_connection_arms_no_timer() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let mut queue = ShutdownQueue::new();

        let (conn, timer, _state) =
            queued_conn(&mut cx, 1, "a:80", "one", &log);
        // A deadline that would be armed if it were ever read.
        timer.borrow_mut().left = [0, 0];
        drive(queue.add(&mut cx, &mut host, conn, 0));

        drive(queue.perform_once(&mut cx, &mut host, ShutdownHandle::Admin));

        assert!(queue.is_empty(), "it finished, so it was terminated");
        assert!(
            !events(&log).iter().any(|e| e.starts_with("expire(")),
            "{:?}",
            events(&log)
        );
    }

    /// An expired PRIMARY deadline is caught inside the filter chain, not here.
    #[test]
    fn an_expired_primary_deadline_ends_the_shutdown_inside_the_chain() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut queue = ShutdownQueue::new();

        let state = {
            let mut cx = CallCtx::new(&clock);
            let (conn, timer, state) =
                queued_conn(&mut cx, 1, "a:80", "one", &log);
            state.borrow_mut().shutdown_steps = 99;
            timer.borrow_mut().started = [true, false];
            timer.borrow_mut().left = [-100, 0];
            drive(queue.add(&mut cx, &mut host, conn, 0));
            state
        };

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            drive(queue.perform_once(
                &mut cx,
                &mut host,
                ShutdownHandle::Admin,
            ));
        });

        assert!(queue.is_empty(), "the timeout is terminal: {text:?}");
        assert!(
            text.contains("* shutdown timeout"),
            "the chain reported the expiry: {text:?}"
        );
        assert_eq!(
            state.borrow().shutdowns,
            0,
            "the deadline check runs before any filter is asked"
        );
        assert!(!events(&log).iter().any(|e| e.starts_with("expire(")));

        // And the close is announced as GRACEFUL, not forced -- which is
        // surprising enough to pin. `*done = (r1 || r2 || (done1 && done2));
        // if(*done) conn->bits.shutdown_filters = TRUE;`
        // (`lib/cshutdn.c:105-107`) sets the latch on ANY completion, an error
        // included, and the `force ` prefix is chosen from that same latch
        // (`:151`). So a shutdown that timed out reads in the log exactly like
        // one that succeeded. Frozen as measured.
        assert!(
            text.contains("[SHUTDOWN] closing connection #1"),
            "got {text:?}"
        );
        assert!(!text.contains("force closing"), "got {text:?}");
    }

    // 20-22. The drain

    /// The default budget of zero performs EXACTLY ONE pass and then forces
    /// everything closed.
    ///
    /// `spent_ms >= timeout_ms` with `timeout_ms == 0` is satisfied on the
    /// first check, because elapsed time is never negative
    /// (`lib/cshutdn.c:293`).
    #[tokio::test]
    async fn the_default_destroy_performs_one_pass_then_forces() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut queue = ShutdownQueue::new();

        let mut states = Vec::new();
        {
            let mut cx = CallCtx::new(&clock);
            for (id, name) in [(1_u64, "one"), (2, "two")] {
                let (conn, _timer, state) =
                    queued_conn(&mut cx, id, "a:80", name, &log);
                state.borrow_mut().shutdown_steps = 99;
                states.push(state);
                queue.add(&mut cx, &mut host, conn, 0).await;
            }
        }

        let mut capture = TraceCapture::new();
        {
            let mut tracer = capture.tracer();
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            queue
                .destroy(&mut cx, &mut host, ShutdownHandle::Admin)
                .await;
        }
        let text = capture.text();

        assert!(
            text.contains("[SHUTDOWN] destroy, 2 connections, timeout=0ms"),
            "got {text:?}"
        );
        assert!(text.contains("[SHUTDOWN] shutdown all"), "got {text:?}");
        assert_eq!(
            text.matches("[SHUTDOWN] perform on").count(),
            1,
            "exactly one pass: {text:?}"
        );
        assert!(
            text.contains("[SHUTDOWN] shutdown finished, best effort done"),
            "got {text:?}"
        );
        assert!(!text.contains("shutdown finished cleanly"), "got {text:?}");
        assert!(!text.contains("shutdown finished, timeout"), "got {text:?}");
        assert!(text.contains("[SHUTDOWN] force closing connection #1"));
        assert!(text.contains("[SHUTDOWN] force closing connection #2"));
        assert!(queue.is_empty());
        for state in &states {
            assert_eq!(state.borrow().shutdowns, 1, "one pass, one attempt");
            assert_eq!(state.borrow().closes, 1);
        }
    }

    /// A drain that empties the queue says so, and stops.
    #[tokio::test]
    async fn a_drain_that_finishes_reports_cleanly() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut queue = ShutdownQueue::new();
        {
            let mut cx = CallCtx::new(&clock);
            let (conn, _timer, _state) =
                queued_conn(&mut cx, 1, "a:80", "one", &log);
            queue.add(&mut cx, &mut host, conn, 0).await;
        }

        let mut capture = TraceCapture::new();
        {
            let mut tracer = capture.tracer();
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            queue
                .terminate_all(&mut cx, &mut host, ShutdownHandle::Admin, 5_000)
                .await;
        }
        let text = capture.text();

        assert!(
            text.contains("[SHUTDOWN] shutdown finished cleanly"),
            "got {text:?}"
        );
        assert!(!text.contains("best effort"), "got {text:?}");
        assert!(
            text.contains("[SHUTDOWN] closing connection #1"),
            "got {text:?}"
        );
        assert!(!text.contains("force closing"), "got {text:?}");
        assert!(queue.is_empty());
    }

    /// A positive budget that runs out reports `timeout`, and the wait between
    /// passes is capped at [`WAIT_SLICE_MAX_MS`].
    ///
    /// The engine's clock is injected and advanced by the filter, so the budget
    /// is spent deterministically; `tokio`'s clock is paused, so the capped
    /// wait costs no real time and its length can be measured exactly.
    #[tokio::test(start_paused = true)]
    async fn a_positive_budget_that_runs_out_reports_timeout() {
        let log = new_log();
        let clock = SharedClock::new(1);
        let mut host = TestHost::new(&log);
        let mut queue = ShutdownQueue::new();
        {
            let mut cx = CallCtx::new(&clock);
            let (mut conn, _timer) = bare_conn(1, "a:80");
            let (filter, state) =
                TestFilter::connected("one", SocketIndex::First, &log);
            // Never finishes, and each attempt costs 60 ms of engine time.
            state.borrow_mut().shutdown_steps = 99;
            state.borrow_mut().advance_ms = Some((clock.clone(), 60));
            conn.chains_mut()
                .chain_mut(SocketIndex::First)
                .add(&mut cx, link(filter));
            queue.add(&mut cx, &mut host, conn, 0).await;
        }

        let mut capture = TraceCapture::new();
        {
            let mut tracer = capture.tracer();
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            queue
                .terminate_all(&mut cx, &mut host, ShutdownHandle::Admin, 5_000)
                .await;
        }
        let text = capture.text();

        assert!(
            text.contains("[SHUTDOWN] shutdown finished, timeout"),
            "got {text:?}"
        );
        assert!(!text.contains("best effort"), "got {text:?}");
        assert!(text.contains("force closing connection #1"), "got {text:?}");
        assert!(queue.is_empty());

        // The engine budget is spent 60 ms at a time and the loop stops on
        // `spent_ms >= timeout_ms`, so 5000 ms buys ceil(5000 / 60) = 84
        // passes. That arithmetic is the whole of what the budget does, and
        // pinning the count pins it.
        assert_eq!(
            text.matches("[SHUTDOWN] perform on").count(),
            84,
            "got {text:?}"
        );
    }

    /// The wait between passes is exactly [`WAIT_SLICE_MAX_MS`], even when far
    /// more budget remains.
    #[tokio::test(start_paused = true)]
    async fn the_wait_between_passes_is_capped_at_one_second() {
        /// One connection that never finishes and spends 30 s of engine time
        /// per pass.
        async fn queued(
            clock: &SharedClock,
            host: &mut TestHost,
            log: &EventLog,
        ) -> ShutdownQueue {
            let mut queue = ShutdownQueue::new();
            let mut cx = CallCtx::new(clock);
            let (mut conn, _timer) = bare_conn(1, "a:80");
            let (filter, state) =
                TestFilter::connected("one", SocketIndex::First, log);
            state.borrow_mut().shutdown_steps = 99;
            state.borrow_mut().advance_ms = Some((clock.clone(), 30_000));
            conn.chains_mut()
                .chain_mut(SocketIndex::First)
                .add(&mut cx, link(filter));
            queue.add(&mut cx, host, conn, 0).await;
            queue
        }

        // Just under one slice: the drain has not returned.
        {
            let log = new_log();
            let clock = SharedClock::new(1);
            let mut host = TestHost::new(&log);
            let mut queue = queued(&clock, &mut host, &log).await;
            let mut cx = CallCtx::new(&clock);
            let raced = tokio::time::timeout(
                Duration::from_millis(999),
                queue.terminate_all(
                    &mut cx,
                    &mut host,
                    ShutdownHandle::Admin,
                    60_000,
                ),
            )
            .await;
            assert!(
                raced.is_err(),
                "the wait lasts a full slice, so 999 ms is not enough"
            );
        }

        // Just over: the second pass has run and the drain is finished.
        let log = new_log();
        let clock = SharedClock::new(1);
        let mut host = TestHost::new(&log);
        let mut queue = queued(&clock, &mut host, &log).await;
        let mut cx = CallCtx::new(&clock);
        let raced = tokio::time::timeout(
            Duration::from_millis(1_001),
            queue.terminate_all(
                &mut cx,
                &mut host,
                ShutdownHandle::Admin,
                60_000,
            ),
        )
        .await;
        assert!(
            raced.is_ok(),
            "one capped slice, not the 30 seconds still in the budget"
        );
        assert!(queue.is_empty());
    }

    /// A wait that cannot be set up aborts the graceful loop.
    ///
    /// The connection's pollset cannot be taken, so `add_pollfds` fails; the
    /// drain reports `aborted` and force-closes whatever is left.
    #[tokio::test]
    async fn a_wait_that_fails_reports_aborted() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut queue = ShutdownQueue::new();
        {
            let mut cx = CallCtx::new(&clock);
            let (conn, _timer, state) =
                queued_conn(&mut cx, 1, "a:80", "one", &log);
            state.borrow_mut().shutdown_steps = 99;
            state.borrow_mut().fail_pollset = Some(CURLcode::OutOfMemory);
            queue.add(&mut cx, &mut host, conn, 0).await;
        }

        let mut capture = TraceCapture::new();
        {
            let mut tracer = capture.tracer();
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            queue
                .terminate_all(&mut cx, &mut host, ShutdownHandle::Admin, 5_000)
                .await;
        }
        let text = capture.text();

        assert!(
            text.contains("[SHUTDOWN] shutdown finished, aborted"),
            "got {text:?}"
        );
        assert!(text.contains("force closing connection #1"), "got {text:?}");
        assert!(queue.is_empty());
    }

    /// An explicit budget replaces the environment variable, and it is visible
    /// in the trace.
    #[tokio::test]
    async fn an_explicit_budget_replaces_the_environment_hook() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut queue = ShutdownQueue::new();

        let mut capture = TraceCapture::new();
        {
            let mut tracer = capture.tracer();
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            queue
                .destroy_with_timeout(
                    &mut cx,
                    &mut host,
                    ShutdownHandle::Admin,
                    250,
                )
                .await;
        }
        let text = capture.text();
        assert!(
            text.contains("[SHUTDOWN] destroy, 0 connections, timeout=250ms"),
            "got {text:?}"
        );
        // An empty queue never enters the loop, so nothing else is emitted.
        assert!(!text.contains("perform on"), "got {text:?}");
    }

    // 23-24. Readiness

    /// A connection watching `socket` on its primary chain.
    fn watching_conn(
        cx: &mut CallCtx<'_, '_>,
        id: u64,
        socket: Socket,
        log: &EventLog,
    ) -> (ShuttingDownConnection, FilterHandle) {
        let (mut conn, _timer) = bare_conn(id, "a:80");
        let (filter, state) =
            TestFilter::connected("w", SocketIndex::First, log);
        state.borrow_mut().socket = socket;
        state.borrow_mut().shutdown_steps = 9;
        conn.chains_mut()
            .chain_mut(SocketIndex::First)
            .add(cx, link(filter));
        (conn, state)
    }

    /// The readiness pairs cover EVERY queued connection, in queue order, and a
    /// connection that cannot report contributes nothing without stopping the
    /// walk.
    #[test]
    fn the_readiness_pairs_span_the_whole_queue() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let mut queue = ShutdownQueue::new();

        assert!(
            queue.sockets(&mut cx).is_empty(),
            "an empty queue watches nothing"
        );

        for (id, sock) in [(1_u64, 7_i32), (2, 8), (3, 9)] {
            let (conn, state) = watching_conn(&mut cx, id, sock, &log);
            if id == 2 {
                // This one cannot report; the walk must carry on past it.
                state.borrow_mut().fail_pollset = Some(CURLcode::OutOfMemory);
            }
            drive(queue.add(&mut cx, &mut host, conn, 0));
        }

        let pairs = queue.sockets(&mut cx);
        assert_eq!(
            pairs,
            vec![(7, PollAction::IN), (9, PollAction::IN)],
            "queue order, with the failing connection skipped"
        );
    }

    /// A descriptor named by TWO connections is folded once into the
    /// application's array and counted once, and counting mode needs no
    /// storage.
    #[test]
    fn the_application_array_folds_and_counts_through_select() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let mut queue = ShutdownQueue::new();

        // Two connections on the SAME descriptor, one on its own.
        for (id, sock) in [(1_u64, 7_i32), (2, 7), (3, 8)] {
            let (conn, _state) = watching_conn(&mut cx, id, sock, &log);
            drive(queue.add(&mut cx, &mut host, conn, 0));
        }

        let mut store = [WaitFd::default(); 4];
        let need = {
            let mut wfds = WaitFds::new(&mut store);
            let need = queue.add_waitfds(&mut cx, &mut wfds);
            assert_eq!(wfds.len(), 2, "descriptor 7 was folded into one entry");
            assert_eq!(wfds.filled()[0].fd, 7);
            assert_eq!(wfds.filled()[1].fd, 8);
            need
        };
        assert_eq!(need, 2, "the fold is not double-counted");

        // Counting mode: no storage, and no fold, exactly as
        // `cwfds_add_sock` answers when there is no array
        // (`lib/select.c:446-449`).
        let mut counting = WaitFds::counting();
        assert_eq!(queue.add_waitfds(&mut cx, &mut counting), 3);
        assert!(counting.is_empty());
    }

    /// The internal buffer folds too, and a connection that cannot report its
    /// pollset EMPTIES the buffer and reports the failure.
    ///
    /// The difference from the application array is deliberate: this buffer is
    /// about to be waited on, so a partial set is worse than none
    /// (`lib/cshutdn.c:524-528`).
    #[test]
    fn the_internal_buffer_aborts_and_empties_on_a_failure() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);
        let mut queue = ShutdownQueue::new();

        for (id, sock) in [(1_u64, 7_i32), (2, 7), (3, 8)] {
            let (conn, _state) = watching_conn(&mut cx, id, sock, &log);
            drive(queue.add(&mut cx, &mut host, conn, 0));
        }

        let mut pfds = PollFds::new();
        queue
            .add_pollfds(&mut cx, &mut pfds)
            .expect("every connection can report");
        assert_eq!(pfds.len(), 2, "descriptor 7 folded");

        // Now make the LAST connection fail, so the buffer is partly filled
        // before the failure is reached.
        let (conn, state) = watching_conn(&mut cx, 4, 10, &log);
        state.borrow_mut().fail_pollset = Some(CURLcode::OutOfMemory);
        drive(queue.add(&mut cx, &mut host, conn, 0));

        let mut pfds = PollFds::new();
        let outcome = queue.add_pollfds(&mut cx, &mut pfds);
        assert_eq!(
            outcome.expect_err("the walk aborts").code(),
            CURLcode::OutOfMemory
        );
        assert!(
            pfds.is_empty(),
            "a partial set would wait on the wrong descriptors"
        );
    }

    // 25-28. Structural properties

    /// This module's own source, for the two structural assertions below.
    ///
    /// Reading the file is the only way to assert the ABSENCE of a construct,
    /// and the absences in question are requirements rather than preferences.
    const OWN_SOURCE: &str = include_str!("shutdown.rs");

    /// No descriptor-set type and no libc anywhere in this file.
    #[test]
    fn this_module_names_no_descriptor_set_and_no_libc() {
        for forbidden in [
            concat!("fd_", "set"),
            concat!("FD_", "SET"),
            concat!("libc", "::"),
            concat!("un", "safe"),
            concat!("no_", "mangle"),
            concat!("extern \"", "C\""),
        ] {
            assert!(
                !OWN_SOURCE.contains(forbidden),
                "{forbidden:?} must not appear in this file"
            );
        }
    }

    /// No process-signal apparatus of any kind.
    ///
    /// C brackets every shutdown in a saved-then-restored broken-pipe
    /// disposition because an OpenSSL write to a closed socket would kill the
    /// process. No C TLS library is linked and `rustls` over `tokio` returns a
    /// broken pipe as an error, so there is nothing to save.
    #[test]
    fn this_module_masks_no_signal() {
        for forbidden in [
            concat!("sig", "pipe"),
            concat!("SIG", "PIPE"),
            concat!("Sig", "pipeContext"),
            concat!("sig", "action"),
        ] {
            assert!(
                !OWN_SOURCE.contains(forbidden),
                "{forbidden:?} must not appear in this file"
            );
        }
    }

    /// The queue's eviction is INSERTION ORDER, and it holds nothing that could
    /// support the connection pool's maximum-age rule.
    #[test]
    fn the_queues_policy_is_insertion_order_and_holds_no_age() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut queue = ShutdownQueue::new();

        // Added at ADVANCING instants, youngest last -- so a maximum-age rule
        // would have a different answer available if any age were recorded.
        let stepping = SharedClock::new(100);
        {
            let mut cx = CallCtx::new(&stepping);
            for id in [1_u64, 2, 3] {
                let (conn, _timer) = bare_conn(id, "a:80");
                drive(queue.add(&mut cx, &mut host, conn, 0));
                stepping.advance_ms(10_000);
            }
        }

        // The head goes first, which is the OLDEST BY ARRIVAL.
        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            assert!(drive(queue.close_oldest(&mut cx, &mut host, None)));
        });
        assert!(text.contains("closing connection #1"), "got {text:?}");

        // And nothing in the type could answer any other question: the
        // connection exposes an identity, a destination, five flags and two
        // chains, and no instant of any kind. The names are assembled from
        // fragments so that this assertion is not itself the occurrence it
        // forbids -- the same discipline
        // [`this_module_names_no_descriptor_set_and_no_libc`] uses.
        for forbidden in [
            concat!("added_", "at"),
            concat!("idle_", "since"),
            concat!("last_", "used"),
            concat!("created_", "at"),
        ] {
            assert!(
                !OWN_SOURCE.contains(forbidden),
                "no age state or accessor may exist, found {forbidden:?}"
            );
        }
    }

    /// The pooled-connection count is a PARAMETER: the queue holds no handle
    /// back into the pool.
    #[test]
    fn the_pool_is_reached_only_through_the_parameter() {
        // IMPORTS, not mentions: the documentation names `crate::conn::pool`
        // deliberately and often, because the shared invariant is the point.
        // What must not exist is a path INTO it, or into any other layer this
        // module would otherwise have to reach through. Assembled from
        // fragments for the reason
        // [`this_module_names_no_descriptor_set_and_no_libc`] gives.
        for forbidden in [
            concat!("use crate", "::conn::pool"),
            concat!("use crate", "::multi"),
            concat!("use crate", "::protocols"),
            concat!("use crate", "::tls"),
            concat!("use crate", "::ffi"),
            concat!("use crate", "::transfer"),
            concat!("use crate", "::easy"),
            concat!("use crate", "::proxy"),
        ] {
            assert!(
                !OWN_SOURCE.contains(forbidden),
                "{forbidden:?} must not be imported"
            );
        }

        // The pooled figure is a `usize` argument and nothing else: the queue
        // has no field, no accessor and no trait method that could reach a
        // pool.
        assert!(
            OWN_SOURCE.contains("conns_in_pool: usize"),
            "the pooled count must arrive as a plain parameter"
        );
    }

    /// Dropping a non-empty queue releases everything without blocking.
    ///
    /// The safety net: C's list is built with a NULL destructor
    /// (`lib/cshutdn.c:324`) and leaks every queued connection if
    /// `Curl_cshutdn_destroy` is skipped. This owns them, so it does not.
    #[test]
    fn dropping_a_queue_releases_its_connections() {
        let log = new_log();
        let clock = clock_at(1);
        let mut host = TestHost::new(&log);
        let mut cx = CallCtx::new(&clock);

        let first = {
            let mut queue = ShutdownQueue::new();
            let (conn, state) = watching_conn(&mut cx, 1, 7, &log);
            drive(queue.add(&mut cx, &mut host, conn, 0));
            assert_eq!(Arc::strong_count(&state), 2);
            state
        };

        assert_eq!(
            Arc::strong_count(&first),
            1,
            "the queue went out of scope and took the connection with it"
        );
        let seen = events(&log);
        assert!(seen.contains(&"w:drop".to_string()), "{seen:?}");
        // And no graceful work was attempted, which is the whole point of
        // having a separate `destroy`.
        assert!(!seen.contains(&"w:close".to_string()), "{seen:?}");
    }
}
