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
//! Socket-callback plumbing, the poll surface and the two-level timer.
//!
//! Supersedes `lib/multi_ev.c` and `lib/multi_ev.h` together with the poll,
//! wait and timer spans of `lib/multi.c`. Eleven of the twenty-two exported
//! `curl_multi_*` symbols rest on this module: `curl_multi_socket_action`,
//! `curl_multi_socket` and `curl_multi_socket_all` (both deprecated at
//! `include/curl/multi.h:317` and `:325`, both still exported and both still
//! in the hundred-symbol parity set of `lib/libcurl.def`), `curl_multi_fdset`,
//! `curl_multi_waitfds`, `curl_multi_wait`, `curl_multi_poll`,
//! `curl_multi_wakeup`, `curl_multi_timeout` and `curl_multi_assign` -- plus
//! the timer-callback machinery behind `CURLMOPT_TIMERFUNCTION`.
//!
//! # What this module owns, and what it borrows
//!
//! It owns [`MultiEvents`]: the per-socket book-keeping that was
//! `struct curl_multi_ev` (`lib/multi_ev.h:36-38`), the multi-side half of
//! the timer machinery, and the wakeup handle. It owns no transfer, no
//! connection, no scheduler and no transfer table -- those belong to
//! [`super`] -- and it reaches all of them through [`EventHost`] and
//! [`SchedulerHost`], which is the same dependency inversion
//! [`super::notify`] uses for the notification callback and for the same
//! reason: the loops that must preserve C's exact ordering stay in the
//! module that owns them.
//!
//! The poll vocabulary is likewise borrowed rather than restated.
//! [`crate::conn::select`] supersedes `lib/select.c` and already declares
//! `CURL_POLL_*` as [`PollAction`], `CURL_WAIT_*`, `CURL_CSELECT_*`,
//! [`EasyPollset`], [`PollFds`] and [`WaitFds`]; its `PollAction::REMOVE`
//! records that it is defined there so that "`crate::multi` consumes it from
//! one place". This module re-exports what its own dependents need and
//! declares only the one constant that module has no reason to hold:
//! [`CURL_SOCKET_TIMEOUT`], which belongs to `multi.h`.
//!
//! # Safety, and the absence of `unsafe`
//!
//! Nothing here is `unsafe`, no raw pointer appears, and `libc` is not
//! named: the crate root sets `#![deny(unsafe_code)]` and the sole
//! `#[allow(unsafe_code)]` is on `crate::ffi`. The two `void *` values the C
//! carries -- `CURLMOPT_SOCKETDATA`'s user pointer and the per-socket value
//! `curl_multi_assign` stores -- travel as [`CallbackData`], an opaque
//! integer token that only `curl-rs-ffi` converts to and from a pointer,
//! inside a documented `// SAFETY:` block on its side of the boundary.
//!
//! # `long` is 64-bit here
//!
//! `curl_multi_timeout` and `curl_multi_timer_callback` traffic in C `long`
//! (`include/curl/multi.h:312-315`, `:344`).

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::Notify;

use crate::conn::select::{
    is_valid_sock, wait_ms, EasyPollset, PollEvents, PollFds, WaitFds,
};
use crate::error::{CURLMcode, CURLcode, CodeResult};
use crate::multi::notify::ADMIN_MID;
use crate::multi::state::CurlMstate;
use crate::trace::{failf, infof, trc_feat, trc_timer, TraceFeature, Tracer};
use crate::util::splay::{TimerKey, TimerTree};
use crate::util::timediff::{mstotv, TimeDiff};
use crate::util::timeval::{
    timediff_ceil_ms, timediff_ms, timediff_us, Clock, CurlTime,
};
use crate::util::uint_bset::Uint32SpBset;

// THE BORROWED VOCABULARY

/// A socket, as C's `curl_socket_t` (`include/curl/curl.h:144`).
pub(crate) use crate::conn::select::Socket;

/// `CURL_SOCKET_BAD` = `-1` (`include/curl/curl.h:145`).
///
/// The Winsock spelling at `:142` is `INVALID_SOCKET`; see [`Socket`].
pub(crate) use crate::conn::select::CURL_SOCKET_BAD;

/// The `CURL_POLL_*` family: what the socket callback is told to watch.
pub(crate) use crate::conn::select::PollAction;

/// `CURL_WAIT_POLLIN` = 0x0001 (`include/curl/multi.h:110`).
///
/// The `CURL_WAIT_*` family is the public poll bitmap of
/// [`CurlWaitFd::events`] and `revents`. It travels **both ways** across
/// `curl_multi_wait` and `curl_multi_poll`: in as what the caller wants, out
/// as what happened.
pub(crate) use crate::conn::select::CURL_WAIT_POLLIN;

/// `CURL_WAIT_POLLPRI` = 0x0002 (`include/curl/multi.h:111`).
pub(crate) use crate::conn::select::CURL_WAIT_POLLPRI;

/// `CURL_WAIT_POLLOUT` = 0x0004 (`include/curl/multi.h:112`).
pub(crate) use crate::conn::select::CURL_WAIT_POLLOUT;

/// `CURL_CSELECT_IN` = 0x01 (`include/curl/multi.h:291`).
#[allow(unused_imports)]
pub(crate) use crate::conn::select::CURL_CSELECT_IN;

/// `CURL_CSELECT_OUT` = 0x02 (`include/curl/multi.h:292`). See
/// [`CURL_CSELECT_IN`] for why nothing in this crate reads it.
#[allow(unused_imports)]
pub(crate) use crate::conn::select::CURL_CSELECT_OUT;

/// `CURL_CSELECT_ERR` = 0x04 (`include/curl/multi.h:293`). See
/// [`CURL_CSELECT_IN`] for why nothing in this crate reads it.
#[allow(unused_imports)]
pub(crate) use crate::conn::select::CURL_CSELECT_ERR;

/// One entry of the array `curl_multi_wait` fills -- C's
/// `struct curl_waitfd` (`include/curl/multi.h:114-118`).
pub(crate) use crate::conn::select::WaitFd as CurlWaitFd;

/// One expiry timer -- C's `expire_id` (`lib/urldata.h:886-904`).
///
/// An alias of [`TimerId`](crate::trace::TimerId), which declares the
/// fifteen real timers, their fifteen frozen trace names and the
/// `"UNKNOWN?"` fallback that `trc_timer_name()` answers out of range
/// (`lib/curl_trc.c:303`). Departure 1 in the module documentation records
/// why the enumeration is not declared a second time here.
pub(crate) use crate::trace::TimerId as ExpireId;

/// `CURL_SOCKET_TIMEOUT` (`include/curl/multi.h:289`).
#[allow(dead_code)] // consumer: `super`'s `curl_multi_socket_action`
pub(crate) const CURL_SOCKET_TIMEOUT: Socket = CURL_SOCKET_BAD;

/// A connection's identity -- C's `conn->connection_id`.
///
/// `curl_off_t` in the C, printed with `FMT_OFF_T` in the frozen trace line
/// at `lib/multi_ev.c:344-349`. A number rather than a borrow, because the
/// socket book-keeping must REMEMBER which connection is using a descriptor
/// across many calls without owning it -- the same reasoning
/// [`crate::conn::select`] gives for storing a bare [`Socket`].
pub(crate) type ConnId = i64;

/// The value a callback returns to abort the multi handle.
pub(crate) const CALLBACK_ABORT: i32 = -1;

/// The application's socket callback, as a safe Rust value.
///
/// `curl-rs-ffi` builds one of these around the C function pointer inside a
/// documented `// SAFETY:` block; nothing on this side of the boundary needs
/// `unsafe` to call it. The `Send` bound is what lets a multi handle that
/// runs on a multi-thread runtime hold one.
#[allow(dead_code)] // consumer: `super`'s multi handle, via `curl_multi_setopt`
pub(crate) type SocketCallback =
    Box<dyn FnMut(u32, Socket, PollAction, CallbackData) -> i32 + Send>;

/// The application's timer callback, as a safe Rust value.
///
/// The header's own note is *"The callback should return zero"*
/// (`include/curl/multi.h:311`). [`MultiEvents::update_timer`] is the only
/// caller, and it calls it through [`SchedulerHost::call_timer_cb`], whose
/// signature is this type's.
#[allow(dead_code)] // consumer: `super`'s multi handle, via `curl_multi_setopt`
pub(crate) type TimerCallback = Box<dyn FnMut(TimeDiff) -> i32 + Send>;

/// An opaque application pointer, as an integer token.
///
/// A token rather than a pointer because this crate forbids `unsafe`: only
/// `curl-rs-ffi` may convert between the two, and it does so inside a
/// documented `// SAFETY:` block. Zero is the null pointer, which is what a
/// socket entry holds until [`MultiEvents::assign`] is called for it.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct CallbackData(usize);

impl CallbackData {
    /// The null pointer -- the value a fresh socket entry carries.
    ///
    /// `mev_sh_entry_add` allocates with `curlx_calloc`
    /// (`lib/multi_ev.c:105`), so `user_data` starts null and the callback
    /// receives null until an application assigns something.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s socket callback bridge
    pub(crate) const NONE: Self = Self(0);

    /// Wraps the bit pattern of an application pointer.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_assign`
    pub(crate) const fn from_bits(bits: usize) -> Self {
        Self(bits)
    }

    /// The bit pattern, for the shim that turns it back into a pointer.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s socket callback bridge
    pub(crate) const fn bits(self) -> usize {
        self.0
    }

    /// Whether this is the null pointer.
    #[allow(dead_code)] // consumer: `super`'s diagnostics
    pub(crate) const fn is_none(self) -> bool {
        self.0 == 0
    }
}

/// Which book-keeping subject an assessment is about.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum EvTarget {
    /// A transfer, by its `mid` -- C's `data` with `conn == NULL`.
    Xfer(u32),
    /// A connection, with the transfer whose identity the trace lines carry
    /// -- C's `data` with a non-null `conn`.
    Conn {
        /// The transfer the C passes as `data`, used for tracing only.
        mid: u32,
        /// The connection being assessed.
        conn: ConnId,
    },
}

impl EvTarget {
    /// The transfer this assessment is attributed to.
    pub(crate) const fn mid(self) -> u32 {
        match self {
            Self::Xfer(mid) | Self::Conn { mid, .. } => mid,
        }
    }

    /// The connection, or [`None`] for a transfer -- C's `conn` argument.
    pub(crate) const fn conn(self) -> Option<ConnId> {
        match self {
            Self::Xfer(_) => None,
            Self::Conn { conn, .. } => Some(conn),
        }
    }
}

// THE SEAMS

/// What the event book-keeping needs from the multi handle.
///
/// The C reaches all of this through `struct Curl_multi *` and
/// `struct Curl_easy *`: the installed `CURLMOPT_SOCKETFUNCTION` and its user
/// pointer, the `dead` and `in_callback` flags, the transfer table behind
/// `Curl_multi_get_easy`, the per-state pollset producers, and the previous
/// pollset stashed in the meta hash. None of it belongs to this module --
/// [`super`] owns the handle and the slab, [`crate::conn`] owns the
/// connection, [`crate::dns`](crate) and [`crate::protocols`] own the
/// per-state producers -- so the dependency is inverted, exactly as
/// [`super::notify`]'s `NotifySink` inverts the notification callback. What
/// stays here is every loop whose ORDER is a public contract.
pub(crate) trait EventHost {
    /// Whether `CURLMOPT_SOCKETFUNCTION` is installed -- `multi->socket_cb`.
    ///
    /// **The entire event machinery is inert when this is false**
    /// (`lib/multi_ev.c:484-485`, `:539`), which is what makes a
    /// `curl_multi_perform` application pay nothing for the socket API.
    fn socket_cb_installed(&self) -> bool;

    /// Invokes the application's socket callback.
    fn call_socket_cb(
        &mut self,
        mid: u32,
        s: Socket,
        what: PollAction,
        socketp: CallbackData,
    ) -> i32;

    /// Sets or clears `multi->in_callback`.
    fn set_in_callback(&mut self, value: bool);

    /// Whether a libcurl callback is running -- `multi->in_callback`.
    fn in_callback(&self) -> bool;

    /// Marks the multi handle dead -- `multi->dead = TRUE`.
    ///
    /// Set when a socket or timer callback returns [`CALLBACK_ABORT`]
    /// (`lib/multi_ev.c:209`, `:277`, `lib/multi.c:3459`).
    fn set_dead(&mut self);

    /// Whether the multi handle is dead -- `multi->dead`.
    fn is_dead(&self) -> bool;

    /// Whether `mid` names a live transfer -- `Curl_multi_get_easy(multi,
    /// mid) != NULL` (`lib/multi.c:3953-3963`).
    fn resolves(&self, mid: u32) -> bool;

    /// Queues `mid` to run -- `Curl_multi_mark_dirty(data)`.
    fn mark_dirty(&mut self, mid: u32);

    /// A snapshot of `multi->process`, in ascending `mid` order.
    fn process_mids(&self) -> Vec<u32>;

    /// Removes `mid` from BOTH `multi->process` and `multi->dirty`.
    ///
    /// The self-heal C performs when a `mid` in the process set no longer
    /// resolves (`lib/multi.c:1291-1295`). Both sets, not one: a stale
    /// `mid` left in `dirty` would be rediscovered on the next cycle.
    fn forget_mid(&mut self, mid: u32);

    /// The transfer's state, or [`None`] if it does not resolve --
    /// `data->mstate`.
    fn mstate_of(&self, mid: u32) -> Option<CurlMstate>;

    /// Whether the transfer has a connection -- `data->conn != NULL`.
    ///
    /// `Curl_multi_pollset` returns an empty pollset when it does not, and
    /// the C explains why that is normal rather than exceptional
    /// (`lib/multi.c:1105-1107`).
    fn has_conn(&self, mid: u32) -> bool;

    /// `MSTATE_RESOLVING`: `Curl_resolv_pollset` (`lib/multi.c:1120`).
    ///
    /// Will be `crate::dns`'s.
    fn resolv_pollset(
        &mut self,
        mid: u32,
        ps: &mut EasyPollset,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()>;

    /// `MSTATE_CONNECTING`: `mstate_connecting_pollset`
    /// (`lib/multi.c:1124`).
    ///
    /// Will be `crate::conn`'s.
    fn connecting_pollset(
        &mut self,
        mid: u32,
        ps: &mut EasyPollset,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()>;

    /// `MSTATE_PROTOCONNECT` and `MSTATE_PROTOCONNECTING`:
    /// `mstate_protocol_pollset` (`lib/multi.c:1129`).
    ///
    /// Will be [`crate::protocols`]'s.
    fn protocol_pollset(
        &mut self,
        mid: u32,
        ps: &mut EasyPollset,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()>;

    /// `MSTATE_DO` and `MSTATE_DOING`: `mstate_do_pollset`
    /// (`lib/multi.c:1134`).
    fn do_pollset(
        &mut self,
        mid: u32,
        ps: &mut EasyPollset,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()>;

    /// `MSTATE_DOING_MORE`: `mstate_domore_pollset` (`lib/multi.c:1138`).
    fn domore_pollset(
        &mut self,
        mid: u32,
        ps: &mut EasyPollset,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()>;

    /// `MSTATE_DID` and `MSTATE_PERFORMING`: `mstate_perform_pollset`
    /// (`lib/multi.c:1143`).
    fn perform_pollset(
        &mut self,
        mid: u32,
        ps: &mut EasyPollset,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()>;

    /// A connection's own interest -- `Curl_conn_adjust_pollset(data, conn,
    /// ps)` (`lib/multi_ev.c:489`).
    ///
    /// The connection branch of an assessment, which does NOT go through the
    /// state machine: a connection in the shutdown pool has no transfer
    /// driving it.
    fn conn_adjust_pollset(
        &mut self,
        mid: u32,
        conn: ConnId,
        ps: &mut EasyPollset,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()>;

    /// Takes the previous pollset out of the transfer or connection record.
    ///
    /// C stashes it in the meta hash under `CURL_META_MEV_POLLSET`
    /// (`lib/multi_ev.h:34`), created lazily by `mev_add_new_xfer_pollset`
    /// or `mev_add_new_conn_pollset` and freed by `mev_pollset_dtor`. **In
    /// Rust it is an owned field on the record, and the keyed stash, the
    /// lazy creation and the destructor all disappear**: typed ownership
    /// replaces an untyped keyed stash, and a field that always exists is
    /// indistinguishable from a lazily created empty one -- `mev_assess`
    /// itself only creates the stash when `ps.n` is non-zero and asserts
    /// that the alternative is an empty pollset (`lib/multi_ev.c:500-514`).
    fn take_prev_pollset(&mut self, target: EvTarget) -> Option<EasyPollset>;

    /// Stores the pollset that the next assessment will diff against.
    fn put_prev_pollset(&mut self, target: EvTarget, prev: EasyPollset);

    /// Discards the stash -- `Curl_meta_remove(data,
    /// CURL_META_MEV_POLLSET)` (`lib/multi_ev.c:608`) and
    /// `Curl_conn_meta_remove` (`:617`).
    fn drop_prev_pollset(&mut self, target: EvTarget);

    /// The transfer's level-one timers -- `data->state.expires[]` together
    /// with `data->state.timeoutlist`, `expiretime` and `timenode`
    /// (`lib/urldata.h:988-991`).
    ///
    /// [`ExpireTimers`] is the whole of that group, so a handle holds one
    /// field where C holds four. [`None`] means the `mid` does not resolve.
    fn expire_timers(&self, mid: u32) -> Option<&ExpireTimers>;

    /// [`Self::expire_timers`], mutably.
    fn expire_timers_mut(&mut self, mid: u32) -> Option<&mut ExpireTimers>;

    /// Whether the transfer has been assigned an identifier --
    /// `data->id >= 0`.
    ///
    /// `data->id` is the pool-scoped `curl_off_t` whose sentinel is `-1`, and
    /// it is **not** `data->mid`. One frozen trace line is gated on it
    /// (`lib/multi.c:3643`), which is why the predicate is asked for
    /// separately rather than inferred.
    #[allow(dead_code)]
    fn has_xfer_id(&self, mid: u32) -> bool;
}

/// What the wait and socket entry points additionally need.
pub(crate) trait SchedulerHost: EventHost {
    /// Whether a notification dispatch is in progress --
    /// `multi->in_ntfy_callback` (`super::notify`'s `in_callback`).
    ///
    /// The three socket entry points test [`EventHost::in_callback`] and
    /// then this, both answering [`CURLMcode::RecursiveApiCall`]
    /// (`lib/multi.c:3284-3288`, `:3295-3299`, `:3305-3309`).
    fn in_ntfy_callback(&self) -> bool;

    /// Whether any transfer is queued to run -- `multi_has_dirties`
    /// (`lib/multi.c:3312-3332`).
    ///
    /// `&mut` because the C's version SELF-HEALS while it looks: a `mid` in
    /// `dirty` that is no longer in `process`, or no longer resolves at all,
    /// is removed as it is passed over.
    fn has_dirties(&mut self) -> bool;

    /// How many transfers are running -- `Curl_multi_xfers_running`.
    fn xfers_running(&self) -> u32;

    /// `multi_perform` -- the `checkall` path of `multi_socket`
    /// (`lib/multi.c:3140`).
    fn perform(&mut self) -> CURLMcode;

    /// `multi_run_dirty` (`lib/multi.c:3070-3111`), answering its result and
    /// its `*pnum` -- how many transfers actually ran.
    fn run_dirty(&mut self) -> (CURLMcode, u32);

    /// `multi_ischanged(multi, clear)` (`lib/multi.c:1624-1630`).
    fn ischanged(&mut self, clear: bool) -> bool;

    /// `process_pending_handles(multi)` (`lib/multi.c:3665`).
    fn process_pending_handles(&mut self);

    /// `CURL_MNTFY_HAS_ENTRIES(multi)` -- [`super::notify`]'s
    /// `MultiNotify::has_entries`.
    fn notify_has_entries(&self) -> bool;

    /// `Curl_mntfy_dispatch_all(multi)` -- [`super::notify`]'s
    /// `MultiNotify::dispatch_all`.
    fn dispatch_notifications(&mut self) -> CURLMcode;

    /// `Curl_cshutdn_add_pollfds(&multi->cshutdn, multi->admin, &cpfds)`
    /// (`lib/multi.c:1391`).
    ///
    /// Connections draining in the shutdown pool are polled alongside the
    /// transfers. Will be `crate::conn::shutdown`'s.
    fn cshutdn_add_pollfds(&mut self, pfds: &mut PollFds);

    /// `Curl_cshutdn_add_waitfds(&multi->cshutdn, multi->admin, &cwfds)`
    /// (`lib/multi.c:1303`), answering the count it added.
    fn cshutdn_add_waitfds(&mut self, wfds: &mut WaitFds<'_>) -> u32;

    /// The descriptor half of `Curl_cshutdn_setfds` (`lib/multi.c:1256`).
    ///
    /// C writes straight into the caller's `fd_set`s and updates `max_fd`;
    /// the pairs are returned here instead, because a `fd_set` is a C type
    /// and belongs to `curl-rs-ffi` -- see [`MultiEvents::fdset`].
    fn cshutdn_sockets(&mut self) -> Vec<(Socket, PollAction)>;

    /// Whether `CURLMOPT_TIMERFUNCTION` is installed -- `multi->timer_cb`.
    ///
    /// [`MultiEvents::update_timer`] does nothing at all without it
    /// (`lib/multi.c:3422-3423`).
    fn timer_cb_installed(&self) -> bool;

    /// Invokes the application's timer callback.
    fn call_timer_cb(&mut self, timeout_ms: TimeDiff) -> i32;
}

/// Holds `multi->in_callback` for the duration of one application callback.
struct CallbackGuard<'host, H: EventHost + ?Sized> {
    /// The handle whose flag is held.
    host: &'host mut H,
}

impl<'host, H: EventHost + ?Sized> CallbackGuard<'host, H> {
    /// Sets the flag and takes charge of clearing it.
    fn enter(host: &'host mut H) -> Self {
        host.set_in_callback(true);
        Self { host }
    }

    /// The handle, for making the call the guard exists to wrap.
    fn host(&mut self) -> &mut H {
        self.host
    }
}

impl<H: EventHost + ?Sized> Drop for CallbackGuard<'_, H> {
    fn drop(&mut self) {
        self.host.set_in_callback(false);
    }
}

/// Renders one action as the C's two-fragment `"%s%s"` pair.
///
/// `(x & CURL_POLL_IN) ? "IN" : ""` followed by
/// `(x & CURL_POLL_OUT) ? "OUT" : ""` (`lib/multi_ev.c:257-260`). The
/// consequence is that [`PollAction::INOUT`] renders as the CONCATENATION
/// `"INOUT"` and [`PollAction::NONE`] renders as the EMPTY STRING -- not as
/// a friendlier name from a lookup table. Both are frozen trace output.
const fn action_fragments(action: PollAction) -> (&'static str, &'static str) {
    (
        if action.contains_in() { "IN" } else { "" },
        if action.contains_out() { "OUT" } else { "" },
    )
}

// THE PER-SOCKET RECORD

/// What is known about one socket the application has been told to watch.
///
/// `struct mev_sh_entry` (`lib/multi_ev.c:46-56`) field for field:
///
/// ```text
/// struct uint32_spbset xfers; /* bitset of transfers `mid`s on this socket */
/// struct connectdata *conn;   /* connection using this socket or NULL */
/// void *user_data;            /* libcurl app data via curl_multi_assign() */
/// unsigned int action;        /* CURL_POLL_IN/CURL_POLL_OUT we last told the
///                              * libcurl application to watch out for */
/// unsigned int readers;       /* this many transfers want to read */
/// unsigned int writers;       /* this many transfers want to write */
/// BIT(announced);             /* this socket has been passed to the socket
///                                callback at least once */
/// ```
#[derive(Debug, Default)]
struct ShEntry {
    /// The `mid`s of the transfers using this socket.
    xfers: Uint32SpBset,
    /// The connection using this socket, if any -- C's `struct connectdata
    /// *conn`. At most one, which C asserts (`lib/multi_ev.c:156`).
    conn: Option<ConnId>,
    /// The value `curl_multi_assign` stored, handed back to every callback.
    user_data: CallbackData,
    /// The action the application was last told to watch for.
    ///
    /// The deduplication contract compares against this, so it is written
    /// ONLY after a successful callback (`lib/multi_ev.c:280`).
    action: PollAction,
    /// How many users want to read.
    readers: u32,
    /// How many users want to write.
    writers: u32,
    /// Whether the application has ever been told about this socket.
    ///
    /// Gates the `CURL_POLL_REMOVE` callback: a socket the application never
    /// heard of must not be un-announced (`lib/multi_ev.c:197`).
    announced: bool,
}

impl ShEntry {
    /// How many users this socket has -- `mev_sh_entry_user_count`
    /// (`lib/multi_ev.c:126-129`).
    ///
    /// `Curl_uint32_spbset_count(&e->xfers) + (e->conn ? 1 : 0)`: a
    /// connection counts as one user alongside the transfers.
    fn user_count(&self) -> u32 {
        self.xfers.count() + u32::from(self.conn.is_some())
    }

    /// `mev_sh_entry_xfer_known` (`lib/multi_ev.c:131-135`).
    fn xfer_known(&self, mid: u32) -> bool {
        self.xfers.contains(mid)
    }

    /// `mev_sh_entry_conn_known` (`lib/multi_ev.c:137-141`).
    fn conn_known(&self, conn: ConnId) -> bool {
        self.conn == Some(conn)
    }

    /// `mev_sh_entry_xfer_add` (`lib/multi_ev.c:143-149`).
    ///
    /// The C's `DEBUGASSERT(mev_sh_entry_user_count(e) < 100000)` -- "detect
    /// weird values" -- is kept, since a socket with a hundred thousand
    /// users is a book-keeping failure rather than a workload.
    fn xfer_add(&mut self, mid: u32) {
        debug_assert!(
            self.user_count() < 100_000,
            "a socket with {} users is a book-keeping failure",
            self.user_count()
        );
        self.xfers.add(mid);
    }

    /// `mev_sh_entry_conn_add` (`lib/multi_ev.c:151-161`).
    ///
    /// Answers `false` when a connection is already registered, which C
    /// asserts against and then handles anyway.
    fn conn_add(&mut self, conn: ConnId) -> bool {
        debug_assert!(
            self.user_count() < 100_000,
            "a socket with {} users is a book-keeping failure",
            self.user_count()
        );
        debug_assert!(
            self.conn.is_none(),
            "socket already registered to connection {:?}",
            self.conn
        );
        if self.conn.is_some() {
            return false;
        }
        self.conn = Some(conn);
        true
    }

    /// `mev_sh_entry_xfer_remove` (`lib/multi_ev.c:163-170`), answering
    /// whether the transfer was there.
    fn xfer_remove(&mut self, mid: u32) -> bool {
        let present = self.xfers.contains(mid);
        if present {
            self.xfers.remove(mid);
        }
        present
    }

    /// `mev_sh_entry_conn_remove` (`lib/multi_ev.c:172-181`), answering
    /// whether that connection was the registered one.
    fn conn_remove(&mut self, conn: ConnId) -> bool {
        debug_assert_eq!(
            self.conn,
            Some(conn),
            "removing a connection that is not the registered one"
        );
        if self.conn == Some(conn) {
            self.conn = None;
            return true;
        }
        false
    }
}

/// The socket book-keeping -- C's `struct curl_multi_ev`
/// (`lib/multi_ev.h:36-38`), whose single field is `struct Curl_hash
/// sh_entries`.
#[derive(Debug, Default)]
pub(crate) struct MultiEv {
    /// The per-socket records, keyed on the descriptor.
    entries: BTreeMap<Socket, ShEntry>,
}

impl MultiEv {
    /// An empty store -- `Curl_multi_ev_init` (`lib/multi_ev.c:620-624`).
    ///
    /// C's `hashsize` argument selects the bucket count and has no
    /// counterpart: a [`BTreeMap`] has no buckets, so the parameter is
    /// dropped rather than accepted and ignored.
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Looks a socket up, skipping the invalid one -- `mev_sh_entry_get`
    /// (`lib/multi_ev.c:82-90`).
    ///
    /// `if(s != CURL_SOCKET_BAD)` first: "only look for proper sockets". A
    /// lookup of [`CURL_SOCKET_BAD`] -- and so of [`CURL_SOCKET_TIMEOUT`],
    /// the same integer -- always misses.
    fn get(&self, s: Socket) -> Option<&ShEntry> {
        if s == CURL_SOCKET_BAD {
            return None;
        }
        self.entries.get(&s)
    }

    /// [`Self::get`], mutably.
    fn get_mut(&mut self, s: Socket) -> Option<&mut ShEntry> {
        if s == CURL_SOCKET_BAD {
            return None;
        }
        self.entries.get_mut(&s)
    }

    /// Ensures a record exists -- `mev_sh_entry_add`
    /// (`lib/multi_ev.c:93-118`), answering whether it had to create one.
    fn add(&mut self, s: Socket) -> bool {
        debug_assert!(
            s != CURL_SOCKET_BAD,
            "the invalid socket has no book-keeping entry"
        );
        if self.entries.contains_key(&s) {
            return false;
        }
        self.entries.insert(s, ShEntry::default());
        true
    }

    /// Forgets a socket entirely -- `mev_sh_entry_kill`
    /// (`lib/multi_ev.c:121-124`).
    fn kill(&mut self, s: Socket) {
        self.entries.remove(&s);
    }

    /// How many sockets are known.
    #[allow(dead_code)] // consumer: `super`'s diagnostics
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no socket is known.
    #[allow(dead_code)] // consumer: `super`'s diagnostics
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forgets every socket -- `Curl_multi_ev_cleanup`
    /// (`lib/multi_ev.c:626-629`).
    fn clear(&mut self) {
        self.entries.clear();
    }
}

// LEVEL ONE: ONE TRANSFER'S TIMERS

/// One transfer's pending expiries -- the level-one half of the two-level
/// timer.
///
/// # What C keeps, and why it is four things
///
/// ```text
/// struct curltime expiretime;              /* lib/urldata.h:988 */
/// struct Curl_tree timenode;               /* :989 */
/// struct Curl_llist timeoutlist;           /* :990 */
/// struct time_node expires[EXPIRE_LAST];   /* :991 */
/// ```
///
/// # What this keeps, and why it is fewer
///
/// The array remains, as [`Self::slots`], indexed by [`ExpireId`] so an
/// out-of-range index cannot be written. **The intrusive list is gone**: the
/// nearest timer is a fifteen-element minimum scan over `(instant, arrival)`,
/// which is trivial at this size and which performance is explicitly not a
/// reason to avoid (AAP 0.1.1). The array and its sorted view could
/// previously fall out of step; now there is no second structure to fall out
/// of step with. `expiretime`'s sentinel becomes [`Option`], which is a
/// strict improvement: `{0, 0}` is otherwise indistinguishable from a
/// legitimate reading at the epoch.
///
/// # Fifteen slots, not sixteen
///
/// `expires[EXPIRE_LAST]` is fifteen elements. The sixteenth `expire_id`
/// token is the marker the header calls "not an actual timer" and it has no
/// slot; see departure 3 in the module documentation.
///
/// # Ordering: millisecond instant, then arrival
///
/// Two timers due at the same instant fire in the order they were set, which
/// is what C's insertion scan produces: it breaks only when
/// `curlx_ptimediff_ms(&check->time, &node->time) > 0`, so a new timer is
/// placed AFTER every entry at or before its own instant
/// (`lib/multi.c:3506-3524`). The arrival number reproduces that.
///
/// **The comparison is at MILLISECOND granularity, as the C's is.** That is
/// the whole of the subtlety: `curlx_ptimediff_ms` truncates, so two instants
/// less than a millisecond apart compare EQUAL and the tie-break decides. The
/// consequence is visible: set timer A for now+1500us and then timer B for
/// now+900us, and C's list keeps A at the head, because inserting B found
/// `ptimediff_ms(A, B) == 0` and walked past it. `add_next_timeout` then drains
/// at MICROSECOND granularity (`lib/multi.c:3007`), stops at the head, and
/// defers B to the next cycle even though B is due first.
///
/// An earlier revision compared `(instant, arrival)` at microsecond
/// granularity, which removes that asymmetry, and argued that nothing observes
/// the difference. AAP 0.8.2 forbids exactly that trade -- a refactor that
/// produces different-but-arguably-better output has failed -- and the
/// difference IS observable: which of two timers is reported as next decides
/// which handle `curl_multi_timeout` describes, and therefore the order in
/// which two transfers with near-equal deadlines are serviced. The C's
/// comparison is reproduced instead, asymmetry included.
///
/// Because a truncating difference is not a transitive relation, this is a
/// linear "keep the best so far" scan rather than a sort key -- which is also
/// exactly the shape of the C's insertion walk.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExpireTimers {
    /// One optional `(instant, arrival)` per [`ExpireId`] -- C's `expires[]`.
    ///
    /// The arrival number is the position information C's list encodes; see the
    /// type's note on ordering for why it is consulted at millisecond
    /// granularity.
    slots: [Option<(CurlTime, u64)>; ExpireId::COUNT],
    /// The instant this handle is registered under in the level-two tree, or
    /// [`None`] when it is not registered -- C's `expiretime` and its
    /// `{0, 0}` sentinel.
    expiretime: Option<CurlTime>,
    /// The level-two entry's identity -- C's `timenode`.
    ///
    /// Removal from the tree is by node identity and NOT by instant, because
    /// two handles can be registered at the same instant. This is where the
    /// [`TimerKey`] that [`TimerTree::insert`] returned is kept, exactly
    /// where C keeps `&data->state.timenode`.
    timenode: Option<TimerKey>,
    /// The arrival number the next [`Self::set`] takes.
    ///
    /// Per handle, which is all the tie-break needs: the comparison is only
    /// ever between two of this handle's own timers.
    next_seq: u64,
}

impl Default for ExpireTimers {
    fn default() -> Self {
        Self::new()
    }
}

impl ExpireTimers {
    /// A handle with no pending timer and no level-two entry.
    ///
    /// C reaches the same state with `Curl_llist_init(&data->state.timeoutlist,
    /// NULL)` over a zeroed `Curl_easy`.
    #[allow(dead_code)] // consumer: `crate::easy::handle`
    pub(crate) const fn new() -> Self {
        Self {
            slots: [None; ExpireId::COUNT],
            expiretime: None,
            timenode: None,
            next_seq: 0,
        }
    }

    /// The slot index for an identifier.
    ///
    /// Total: [`ExpireId`] has exactly [`ExpireId::COUNT`] variants with
    /// discriminants `0..COUNT`, which the tests pin, so the index is always
    /// in range and the array access cannot panic.
    const fn index(id: ExpireId) -> usize {
        id as usize
    }

    /// Records `at` for `id`, replacing any previous timer with that id.
    ///
    /// The write half of `multi_addtimeout` (`lib/multi.c:3502-3506`):
    /// `memcpy(&node->time, stamp, ...)` then `node->eid = eid`. Returns the
    /// arrival number, which is the tie-break the C's list position encodes.
    fn set(&mut self, id: ExpireId, at: CurlTime) -> u64 {
        let seq = self.next_seq;
        // As `TimerTree::insert` does, and for the same reason: identical
        // arithmetic in every build profile, where `+= 1` would panic in
        // debug and wrap in release. Exhausting `u64` needs 2^64 timers.
        self.next_seq = self.next_seq.wrapping_add(1);
        self.slots[Self::index(id)] = Some((at, seq));
        seq
    }

    /// Forgets the timer for `id` -- `multi_deltimeout`
    /// (`lib/multi.c:3475-3488`).
    ///
    /// C scans the list for the node whose `eid` matches and unlinks it. The
    /// array index is that scan's result, known without scanning. **The
    /// level-two tree is not touched**, exactly as C does not touch it here.
    fn clear_one(&mut self, id: ExpireId) {
        self.slots[Self::index(id)] = None;
    }

    /// Forgets every timer -- `Curl_llist_destroy(list, NULL)`
    /// (`lib/multi.c:3639`).
    fn clear_all(&mut self) {
        self.slots = [None; ExpireId::COUNT];
    }

    /// The nearest pending timer -- the head of C's sorted `timeoutlist`.
    ///
    /// Ordered by millisecond instant and then by arrival; see the type's note
    /// on ordering for why the granularity is load-bearing.
    ///
    /// The scan visits the slots in [`ExpireId`] order, which is irrelevant to
    /// the answer: the comparison never consults the slot index, so the result
    /// depends only on the recorded instants and arrival numbers, exactly as
    /// C's list position does.
    fn nearest(&self) -> Option<(ExpireId, CurlTime)> {
        let mut best: Option<(usize, CurlTime, u64)> = None;
        for (index, slot) in self.slots.iter().enumerate() {
            let Some((at, seq)) = *slot else { continue };
            let better = match best {
                None => true,
                // `curlx_ptimediff_ms(&best, &at) > 0` is C's break condition
                // at `lib/multi.c:3516-3517`: this entry goes BEFORE `best`
                // only when `best` is more than a whole millisecond later.
                // Equal to the millisecond falls through to arrival order, so
                // the earlier-set timer keeps the head -- FIFO, as C's walk
                // past every `diff <= 0` entry produces.
                Some((_, best_at, best_seq)) => {
                    match timediff_ms(best_at, at) {
                        0 => seq < best_seq,
                        diff => diff > 0,
                    }
                }
            };
            if better {
                best = Some((index, at, seq));
            }
        }
        best.and_then(|(index, at, _)| {
            // `index` came from iterating `slots`, whose length is
            // `ExpireId::COUNT`, so the conversion always succeeds. The
            // fallible form is used because this crate admits no narrowing
            // cast that could silently misname a timer.
            let id = i32::try_from(index).ok()?;
            ExpireId::from_i32(id).map(|id| (id, at))
        })
    }

    /// Whether no timer is pending -- C's `!Curl_llist_head(list)`.
    #[allow(dead_code)] // consumer: `super`'s diagnostics
    pub(crate) fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    /// How many timers are pending -- `Curl_llist_count(&timeoutlist)`.
    ///
    /// Reported in the verbose pollset trace of `lib/multi.c:1176`.
    #[allow(dead_code)] // consumer: `super`'s verbose pollset trace
    pub(crate) fn count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    /// Whether this handle is registered in the level-two tree.
    ///
    /// C's `if(curr_expire->tv_sec || curr_expire->tv_usec)`
    /// (`lib/multi.c:3557`, `:3628`).
    #[allow(dead_code)] // consumer: `super`'s diagnostics
    pub(crate) fn is_registered(&self) -> bool {
        self.expiretime.is_some()
    }
}

// LEVEL TWO: THE MULTI HANDLE'S TREE

/// The multi handle's expiry state -- the level-two half of the timer.
///
/// One tree entry per HANDLE, keyed on that handle's nearest timer -- not one
/// entry per timer. `lib/multi.c` keeps it as `multi->timetree` plus the two
/// fields that remember what the application was last told
/// (`lib/multihandle.h:158-159`).
#[derive(Debug)]
pub(crate) struct MultiTimers {
    /// The registered handles, keyed on their nearest expiry --
    /// `multi->timetree`.
    ///
    /// The payload is the transfer's `mid`, where C carries the
    /// `struct Curl_easy *` it reaches with `Curl_splayget`. A number,
    /// because the tree must not own or outlive a transfer.
    timetree: TimerTree<u32>,
    /// The expiry instant last reported to `CURLMOPT_TIMERFUNCTION` --
    /// `multi->last_expire_ts`.
    last_expire_ts: CurlTime,
    /// The relative timeout last reported -- `multi->last_timeout_ms`,
    /// initialised to `-1` at `lib/multi.c:256`.
    last_timeout_ms: TimeDiff,
}

impl Default for MultiTimers {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiTimers {
    /// An empty tree with nothing yet reported.
    fn new() -> Self {
        Self {
            timetree: TimerTree::new(),
            last_expire_ts: CurlTime::ZERO,
            // `multi->last_timeout_ms = -1` (`lib/multi.c:256`): "no timeout
            // has been reported", which is what branch three of
            // `Curl_update_timer` tests for.
            last_timeout_ms: -1,
        }
    }
}

// THE WAKEUP HANDLE

/// Interrupts a blocked [`MultiEvents::poll`] -- C's `multi->wakeup_pair`.
///
/// # The one cross-thread entry point
///
/// `curl_multi_wakeup` is documented as callable from another thread: *"this
/// function is usually called from another thread, it has to be careful only
/// to access parts of the `Curl_multi` struct that are constant"*, and *"the
/// `wakeup_pair` variable is only written during init and cleanup, making it
/// safe to access from another thread after the init part and before
/// cleanup"* (`lib/multi.c:1594-1596`, `:1608-1610`). Nothing else in the
/// multi interface may be called concurrently with a wait.
///
/// # A notification, not a socket pair
///
/// Consequences that are preserved deliberately:
///
/// * **[`MultiEvents::wakeup`] keeps its failure path.**
///   [`CURLMcode::WakeupFailure`] is unreachable here, because construction
///   cannot fail, but the code is part of the ABI and a C consumer may still
///   receive it from a build without the mechanism. Removing the arm would
///   change the enumeration; see [`MultiEvents::wakeup`].
/// * **C's compile-time gate has no counterpart.** There the wakeup exists
///   only when a `#define` is set, which happens unless
///   `CURL_DISABLE_SOCKETPAIR` is (`lib/multihandle.h:73-76`); the fifteen
///   Cargo features of this workspace contain nothing that disables it, so
///   the capability is unconditional here and no feature is invented for it.
/// * **A signal delivered while nothing is waiting is remembered.**
///   [`Notify::notify_one`] stores one permit, so the next wait returns
///   immediately -- which is what a byte sitting in the self-pipe does.
#[derive(Clone, Debug, Default)]
pub(crate) struct Wakeup {
    /// The shared notification. `Arc` so that a clone handed to another
    /// thread names the same one.
    notify: Arc<Notify>,
}

impl Wakeup {
    /// A fresh handle with no pending signal.
    fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
        }
    }

    /// Wakes a waiter, or arms the next wait -- `Curl_wakeup_signal`.
    ///
    /// Never blocks and never fails, which is why
    /// [`CURLMcode::WakeupFailure`] cannot arise from it.
    pub(crate) fn signal(&self) {
        self.notify.notify_one();
    }

    /// Waits for a signal, consuming it -- the `POLLIN` on
    /// `wakeup_pair[0]` followed by `Curl_wakeup_consume`
    /// (`lib/multi.c:1534-1539`).
    async fn notified(&self) {
        self.notify.notified().await;
    }
}

// THE INTEREST OF A SINGLE TRANSFER

/// Fills `ps` with what transfer `mid` currently wants to watch --
/// `Curl_multi_pollset` (`lib/multi.c:1097-1210`).
///
/// # Errors reaching the caller
///
/// Reported as [`CURLMcode`], mapping as C does (`lib/multi.c:1198-1206`):
/// [`CURLcode::OutOfMemory`] becomes [`CURLMcode::OutOfMemory`], and anything
/// else is announced with the frozen `failf` text
/// `"error determining pollset: %d"` and becomes
/// [`CURLMcode::InternalError`].
pub(crate) fn pollset<H: EventHost + ?Sized>(
    host: &mut H,
    mid: u32,
    ps: &mut EasyPollset,
    mut trc: Option<&mut Tracer<'_>>,
) -> CURLMcode {
    // Reset FIRST, then the early return, in that order
    // (`lib/multi.c:1108-1110`). The C's own rationale for why a transfer
    // with no connection is normal: "If the transfer has no connection, this
    // is fine. Happens when called via curl_multi_remove_handle() =>
    // Curl_multi_ev_assess() => Curl_multi_pollset()."
    ps.reset();
    if !host.has_conn(mid) {
        return CURLMcode::Ok;
    }

    // C reads `data->mstate` from a handle it already holds. A `mid` that
    // does not resolve has no state and also no connection, so the guard
    // above has already returned; this arm exists to keep the function total
    // rather than to describe a reachable case.
    let Some(state) = host.mstate_of(mid) else {
        return CURLMcode::Ok;
    };

    let result = match state {
        // "nothing to poll for yet"
        CurlMstate::Init
        | CurlMstate::Pending
        | CurlMstate::Setup
        | CurlMstate::Connect => Ok(()),

        CurlMstate::Resolving => {
            host.resolv_pollset(mid, ps, trc.as_deref_mut())
        }

        CurlMstate::Connecting => {
            host.connecting_pollset(mid, ps, trc.as_deref_mut())
        }

        CurlMstate::ProtoConnect | CurlMstate::ProtoConnecting => {
            host.protocol_pollset(mid, ps, trc.as_deref_mut())
        }

        CurlMstate::Do | CurlMstate::Doing => {
            host.do_pollset(mid, ps, trc.as_deref_mut())
        }

        CurlMstate::DoingMore => {
            host.domore_pollset(mid, ps, trc.as_deref_mut())
        }

        // `MSTATE_DID` is "same as PERFORMING in regard to polling".
        CurlMstate::Did | CurlMstate::Performing => {
            host.perform_pollset(mid, ps, trc.as_deref_mut())
        }

        // "we need to let time pass, ignore socket(s)"
        CurlMstate::RateLimiting => Ok(()),

        // "nothing more to poll for"
        CurlMstate::Done | CurlMstate::Completed | CurlMstate::MsgSent => {
            Ok(())
        }
    };

    match result {
        Ok(()) => CURLMcode::Ok,
        Err(CURLcode::OutOfMemory) => CURLMcode::OutOfMemory,
        Err(other) => {
            if let Some(tracer) = trc {
                failf!(tracer, "error determining pollset: {}", other.as_i32());
            }
            CURLMcode::InternalError
        }
    }
}

// THE MULTI HANDLE'S EVENT STATE

/// The multi handle's socket book-keeping, timers and wakeup handle.
///
/// Everything this module owns, in one value that [`super`]'s handle holds as
/// a field -- as C holds `struct curl_multi_ev ev` (`lib/multihandle.h`)
/// beside `timetree`, `last_expire_ts`, `last_timeout_ms` and `wakeup_pair`.
/// Grouping them is what lets the handle be split-borrowed: the algorithms
/// take `&mut self` for this state and `&mut H` for everything else, so no
/// call needs two mutable borrows of the same object. See [`EventHost`].
#[derive(Debug)]
pub(crate) struct MultiEvents {
    /// The per-socket records -- C's `multi->ev`.
    ev: MultiEv,
    /// The level-two timer tree and what the application was last told.
    timers: MultiTimers,
    /// The wakeup handle -- C's `multi->wakeup_pair`.
    wakeup: Wakeup,
    /// The injected clock. Every reading in this module comes from here.
    ///
    /// `Arc` rather than `Box` so that [`Self::wakeup_handle`]'s sibling
    /// pattern is available to a caller that wants to share one clock between
    /// the multi handle and the transfers it drives, which is what makes a
    /// whole-engine test advance time once and have every deadline agree.
    clock: Arc<dyn Clock + Send + Sync>,
    /// The most recent reading -- C's `multi->now`.
    ///
    /// `multi_now(multi)` (`lib/multi.c:104-108`) refreshes this and returns
    /// it; [`Self::refresh_now`] is that function and [`Self::now`] is a read
    /// of what it left behind, which is what `&multi->now` denotes at
    /// `lib/multi.c:3161`.
    now: CurlTime,
}

impl MultiEvents {
    /// Fresh event state over `clock` -- `Curl_multi_ev_init` together with
    /// the timer and wakeup initialisation of `Curl_multi_handle`.
    #[allow(dead_code)] // consumer: `super`'s `curl_multi_init`
    pub(crate) fn new(clock: Arc<dyn Clock + Send + Sync>) -> Self {
        let now = clock.now();
        Self {
            ev: MultiEv::new(),
            timers: MultiTimers::new(),
            wakeup: Wakeup::new(),
            clock,
            now,
        }
    }

    /// Forgets every socket -- `Curl_multi_ev_cleanup`
    /// (`lib/multi_ev.c:626-629`).
    #[allow(dead_code)] // consumer: `super`'s `curl_multi_cleanup`
    pub(crate) fn cleanup(&mut self) {
        self.ev.clear();
    }

    /// The socket book-keeping, for diagnostics.
    #[allow(dead_code)] // consumer: `super`'s diagnostics
    pub(crate) fn sockets(&self) -> &MultiEv {
        &self.ev
    }

    /// A handle that another thread may keep -- see [`Wakeup`].
    ///
    /// The only value in this module that may leave the reactor's `&mut`
    /// borrow, which is what makes `curl_multi_wakeup` callable while a wait
    /// is in progress.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_wakeup`
    pub(crate) fn wakeup_handle(&self) -> Wakeup {
        self.wakeup.clone()
    }

    /// The most recent reading -- `&multi->now`.
    #[allow(dead_code)] // consumer: `super`'s scheduler
    pub(crate) fn now(&self) -> CurlTime {
        self.now
    }

    /// Takes a new reading and answers it -- `multi_now(multi)`
    /// (`lib/multi.c:104-108`), whose body is `curlx_pnow(&multi->now);
    /// return &multi->now;`.
    #[allow(dead_code)] // consumer: `super`'s scheduler
    pub(crate) fn refresh_now(&mut self) -> CurlTime {
        self.now = self.clock.now();
        self.now
    }

    /// Attaches an application pointer to a socket -- `Curl_multi_ev_assign`
    /// (`lib/multi_ev.c:550-559`).
    ///
    /// # Errors
    ///
    /// [`CURLMcode::BadSocket`] when the socket is not one this handle has
    /// announced. That is the whole of the failure, and it is why an
    /// application must assign only from inside a socket callback or after
    /// one.
    #[allow(dead_code)] // consumer: `super`'s `curl_multi_assign`
    pub(crate) fn assign(
        &mut self,
        s: Socket,
        user_data: CallbackData,
    ) -> CURLMcode {
        match self.ev.get_mut(s) {
            Some(entry) => {
                entry.user_data = user_data;
                CURLMcode::Ok
            }
            None => CURLMcode::BadSocket,
        }
    }

    /// Reassesses one transfer -- `Curl_multi_ev_assess_xfer`
    /// (`lib/multi_ev.c:520-524`).
    ///
    /// `lib/multi_ev.h:50-52`: *"Assess the transfer by getting its current
    /// pollset, compute any changes to the last one and inform the
    /// application's socket callback if things have changed."*
    #[allow(dead_code)] // consumer: `super`'s scheduler
    pub(crate) fn assess_xfer<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        mid: u32,
        trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        self.assess(host, EvTarget::Xfer(mid), trc)
    }

    /// Reassesses one connection -- `Curl_multi_ev_assess_conn`
    /// (`lib/multi_ev.c:526-531`).
    #[allow(dead_code)] // consumer: `crate::conn::shutdown`
    pub(crate) fn assess_conn<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        mid: u32,
        conn: ConnId,
        trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        self.assess(host, EvTarget::Conn { mid, conn }, trc)
    }

    /// Reassesses a set of transfers -- `Curl_multi_ev_assess_xfer_bset`
    /// (`lib/multi_ev.c:533-548`), whose comment is *"Assess all easy handles
    /// on the list"*.
    #[allow(dead_code)] // consumer: `super`'s scheduler
    pub(crate) fn assess_xfer_set<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        mids: &[u32],
        mut trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        if !host.socket_cb_installed() {
            return CURLMcode::Ok;
        }
        for mid in mids {
            if !host.resolves(*mid) {
                continue;
            }
            let result = self.assess_xfer(host, *mid, trc.as_deref_mut());
            if !result.is_ok() {
                return result;
            }
        }
        CURLMcode::Ok
    }

    /// Queues every transfer using `s` to run -- `Curl_multi_ev_dirty_xfers`
    /// (`lib/multi_ev.c:561-594`), *"Mark all transfers tied to the given
    /// socket as dirty"*.
    #[allow(dead_code)] // consumer: `super`'s socket entry points
    pub(crate) fn dirty_xfers<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        s: Socket,
        mut trc: Option<&mut Tracer<'_>>,
    ) {
        debug_assert!(
            s != CURL_SOCKET_TIMEOUT,
            "the timeout sentinel is not a socket to mark dirty"
        );
        let Some(entry) = self.ev.get(s) else {
            return;
        };

        // The walk is over a snapshot because a `mid` that no longer resolves
        // is removed from the very bitset being walked.
        let mut mids = Vec::new();
        let mut next = entry.xfers.first();
        while let Some(mid) = next {
            mids.push(mid);
            next = entry.xfers.next(mid);
        }
        let has_conn = entry.conn.is_some();

        for mid in mids {
            if host.resolves(mid) {
                host.mark_dirty(mid);
            } else {
                if let Some(tracer) = trc.as_deref_mut() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Multi,
                        "socket transfer {} no longer found",
                        mid
                    );
                }
                if let Some(entry) = self.ev.get_mut(s) {
                    entry.xfer_remove(mid);
                }
            }
        }

        if has_conn {
            // `Curl_multi_mark_dirty(multi->admin)`: the connection is not a
            // transfer, so the admin handle is what runs its filters.
            host.mark_dirty(ADMIN_MID);
        }
    }

    /// Forgets a socket that is about to be closed --
    /// `Curl_multi_ev_socket_done` (`lib/multi_ev.c:596-600`), *"Socket will
    /// be closed, forget anything we know about it."*
    #[allow(dead_code)] // consumer: `crate::conn`'s close path
    pub(crate) fn socket_done<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        mid: u32,
        s: Socket,
        trc: Option<&mut Tracer<'_>>,
    ) {
        let _ = self.forget_socket(host, mid, s, "socket done", trc);
    }

    /// A transfer has left the multi handle -- `Curl_multi_ev_xfer_done`
    /// (`lib/multi_ev.c:602-610`), *"Transfer is removed from the multi"*.
    #[allow(dead_code)] // consumer: `super`'s `curl_multi_remove_handle`
    pub(crate) fn xfer_done<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        mid: u32,
        trc: Option<&mut Tracer<'_>>,
    ) {
        debug_assert!(
            !host.has_conn(mid),
            "a transfer leaving the multi handle must be detached first"
        );
        if mid == ADMIN_MID {
            return;
        }
        let target = EvTarget::Xfer(mid);
        let _ = self.assess(host, target, trc);
        host.drop_prev_pollset(target);
    }

    /// A connection is being destroyed -- `Curl_multi_ev_conn_done`
    /// (`lib/multi_ev.c:612-618`), *"Connection is being destroyed"*.
    #[allow(dead_code)] // consumer: `crate::conn`'s teardown
    pub(crate) fn conn_done<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        mid: u32,
        conn: ConnId,
        trc: Option<&mut Tracer<'_>>,
    ) {
        let target = EvTarget::Conn { mid, conn };
        let _ = self.assess(host, target, trc);
        host.drop_prev_pollset(target);
    }

    /// A socket is about to be closed -- `Curl_multi_will_close`
    /// (`lib/multi.c:2971-2980`).
    #[allow(dead_code)] // consumer: `crate::conn`'s close path
    pub(crate) fn will_close<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        mid: u32,
        s: Socket,
        mut trc: Option<&mut Tracer<'_>>,
    ) {
        if !host.resolves(mid) {
            return;
        }
        if let Some(tracer) = trc.as_deref_mut() {
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "Curl_multi_will_close fd={}",
                s
            );
        }
        self.socket_done(host, mid, s, trc);
    }

    /// `mev_assess` (`lib/multi_ev.c:477-518`): produce the current interest,
    /// diff it against the previous one, and report the difference.
    ///
    /// The first line is the guard that makes the whole subsystem free for an
    /// application that does not use it: `if(!multi || !multi->socket_cb)
    /// return CURLM_OK;`.
    fn assess<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        target: EvTarget,
        mut trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        if !host.socket_cb_installed() {
            return CURLMcode::Ok;
        }

        let mut ps = EasyPollset::new();
        match target.conn() {
            Some(conn) => {
                // The connection branch reports its failure, mapping exactly
                // as `lib/multi_ev.c:490-494` does.
                if let Err(code) = host.conn_adjust_pollset(
                    target.mid(),
                    conn,
                    &mut ps,
                    trc.as_deref_mut(),
                ) {
                    return if code == CURLcode::OutOfMemory {
                        CURLMcode::OutOfMemory
                    } else {
                        CURLMcode::InternalError
                    };
                }
            }
            None => {
                // `Curl_multi_pollset(data, &ps);` -- the result is DISCARDED
                // at `lib/multi_ev.c:497`, unlike the connection branch above.
                // Reproduced rather than tidied: an assessment that cannot
                // determine a transfer's interest still has to reconcile the
                // sockets that transfer used to hold, and returning early
                // would leak them.
                let _ =
                    pollset(host, target.mid(), &mut ps, trc.as_deref_mut());
            }
        }

        // The previous pollset is TAKEN, not borrowed: the diff runs the
        // application's callback. `None` means the target has gone, which
        // leaves nothing to reconcile against.
        let Some(mut prev) = host.take_prev_pollset(target) else {
            return CURLMcode::Ok;
        };
        let result = self.pollset_diff(host, target, &mut ps, &mut prev, trc);
        // `Curl_pollset_move(prev_ps, ps)` happens inside the diff; this is
        // the stash going back where it came from, on the failure path too --
        // C's stash is reached by key and is never in limbo.
        host.put_prev_pollset(target, prev);
        result
    }

    /// `mev_pollset_diff` (`lib/multi_ev.c:284-429`): reconcile one target's
    /// new interest against its previous interest.
    ///
    /// The C's own description, verbatim: *"The transfer `data` reports in
    /// `ps` the sockets it is interested in and which combination of
    /// `CURL_POLL_IN`/`CURL_POLL_OUT` it wants to have monitored for events.
    /// There can be more than 1 transfer interested in the same socket and 1
    /// transfer might be interested in more than 1 socket. `prev_ps` is the
    /// pollset copy from the previous call here. On the 1st call it will be
    /// empty."*
    fn pollset_diff<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        target: EvTarget,
        ps: &mut EasyPollset,
        prev: &mut EasyPollset,
        mut trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        let mid = target.mid();

        // SOCKETS THE TARGET IS INTERESTED IN NOW.
        for (s, cur_action) in ps.iter() {
            // "Have we handled this socket before?"
            let mut first_time = false;
            if self.ev.get(s).is_none() {
                first_time = true;
                self.ev.add(s);
                if let Some(tracer) = trc.as_deref_mut() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Multi,
                        "ev new entry fd={}",
                        s
                    );
                }
            } else if let Some(entry) = self.ev.get(s) {
                first_time = match target.conn() {
                    Some(conn) => !entry.conn_known(conn),
                    None => !entry.xfer_known(mid),
                };
            }

            // "What was the previous action the transfer had regarding this
            // socket? If the transfer is new to the socket, disregard the
            // information in `last_poll`, because the socket might have been
            // destroyed and reopened. We would have cleared the sh_entry for
            // that, but the socket might still be mentioned in the hashed
            // pollsets."
            let mut last_action = PollAction::NONE;
            if first_time {
                let Some(entry) = self.ev.get_mut(s) else {
                    debug_assert!(false, "the entry was just ensured to exist");
                    continue;
                };
                match target.conn() {
                    Some(conn) => {
                        // C answers CURLM_OUT_OF_MEMORY for a second
                        // connection on one socket (`:337-338`), which is not
                        // what went wrong but is what it reports.
                        if !entry.conn_add(conn) {
                            return CURLMcode::OutOfMemory;
                        }
                    }
                    None => entry.xfer_add(mid),
                }
                let xfers = entry.xfers.count();
                let conns = i32::from(entry.conn.is_some());
                if let Some(tracer) = trc.as_deref_mut() {
                    let (kind, id) = match target.conn() {
                        Some(conn) => ("connection", conn),
                        None => ("transfer", i64::from(mid)),
                    };
                    trc_feat!(
                        tracer,
                        TraceFeature::Multi,
                        "ev entry fd={}, added {} #{}, total={}/{} (xfer/conn)",
                        s,
                        kind,
                        id,
                        xfers,
                        conns
                    );
                }
            } else {
                // The scan of `prev_ps` for this socket (`:352-357`). A
                // pollset holds each socket at most once, so the first match
                // is the only match and `action_of` is that search.
                last_action = prev.action_of(s);
            }

            // "track readers/writers changes and report to socket callback"
            let result = self.entry_update(
                host,
                mid,
                s,
                last_action,
                cur_action,
                trc.as_deref_mut(),
            );
            if !result.is_ok() {
                return result;
            }
        }

        // SOCKETS THE TARGET IS NO LONGER INTERESTED IN.
        //
        // Snapshotted because the body may forget the socket it is standing
        // on, and because `prev` is handed back to the stash below.
        let previous: Vec<(Socket, PollAction)> = prev.iter().collect();
        for (s, prev_action) in previous {
            if ps.iter().any(|(other, _)| other == s) {
                // "socket is still supervised"
                continue;
            }

            // "if entry does not exist, we were either never told about it or
            // have already cleaned up this socket via
            // Curl_multi_ev_socket_done(). In other words: this is perfectly
            // normal"
            let Some(entry) = self.ev.get_mut(s) else {
                continue;
            };

            match target.conn() {
                Some(conn) => {
                    if !entry.conn_remove(conn) {
                        // "`conn` says in `prev_ps` that it had been using a
                        // socket, but `conn` has not been registered for it.
                        // This should not happen if our book-keeping is
                        // correct?"
                        if let Some(tracer) = trc.as_deref_mut() {
                            trc_feat!(
                                tracer,
                                TraceFeature::Multi,
                                "ev entry fd={}, conn lost interest but is not registered",
                                s
                            );
                        }
                        continue;
                    }
                }
                None => {
                    if !entry.xfer_remove(mid) {
                        // The same, for a transfer (`:398-406`).
                        if let Some(tracer) = trc.as_deref_mut() {
                            trc_feat!(
                                tracer,
                                TraceFeature::Multi,
                                "ev entry fd={}, transfer lost interest but is not registered",
                                s
                            );
                        }
                        continue;
                    }
                }
            }

            if entry.user_count() != 0 {
                // "track readers/writers changes and report to socket
                // callback" -- the same call as above, with no interest now.
                let result = self.entry_update(
                    host,
                    mid,
                    s,
                    prev_action,
                    PollAction::NONE,
                    trc.as_deref_mut(),
                );
                if !result.is_ok() {
                    return result;
                }
                let (xfers, conns) = match self.ev.get(s) {
                    Some(entry) => {
                        (entry.xfers.count(), i32::from(entry.conn.is_some()))
                    }
                    None => (0, 0),
                };
                if let Some(tracer) = trc.as_deref_mut() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Multi,
                        "ev entry fd={}, removed transfer, total={}/{} (xfer/conn)",
                        s,
                        xfers,
                        conns
                    );
                }
            } else {
                let result = self.forget_socket(
                    host,
                    mid,
                    s,
                    "last user gone",
                    trc.as_deref_mut(),
                );
                if !result.is_ok() {
                    return result;
                }
            }
        }

        // "Remember for next time" -- `Curl_pollset_move(prev_ps, ps)`
        // (`:427`), which replaces everything in `prev` and leaves `ps` empty.
        prev.take_from(ps);
        CURLMcode::Ok
    }

    /// `mev_sh_entry_update` (`lib/multi_ev.c:215-282`): one target's interest
    /// in one socket changed, so update the refcounts and tell the
    /// application if -- and only if -- the socket's aggregate changed.
    ///
    /// **This is the most behaviourally sensitive function in the module.**
    /// Every step below is in C's order, and two of them are early returns
    /// that a reimplementation is likely to drop:
    ///
    /// 1. The callback must be installed. C asserts it and then returns
    ///    [`CURLMcode::Ok`] anyway.
    /// 2. `if(last_action == cur_action) return CURLM_OK;` -- "nothing from
    ///    `data` changed".
    /// 3. The refcounts move, in the exact shape C wrote them. Note the
    ///    `else if`: a user that wanted to read and still wants to read
    ///    neither increments nor decrements. An unconditional recount would
    ///    be a different algorithm with a different callback stream.
    /// 4. Three invariants, kept as debug assertions.
    /// 5. The frozen `"ev update"` trace, whose `'%s%s'` pairs render an
    ///    `INOUT` as the concatenation `"INOUT"` and a `NONE` as the empty
    ///    string -- see [`action_fragments`].
    /// 6. `comboaction` is the union: OUT if anyone writes, IN if anyone
    ///    reads.
    /// 7. **The deduplication contract**: `if((int)entry->action ==
    ///    comboaction) return CURLM_OK;` -- "nothing for socket changed". The
    ///    application is not called when the aggregate is unchanged even
    ///    though an individual user changed.
    /// 8. The callback runs inside the recursion guard, `announced` is set
    ///    BEFORE the result is examined, and `action` is updated only on
    ///    success -- so an aborted callback leaves the socket's recorded
    ///    action as whatever the application was last successfully told.
    fn entry_update<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        mid: u32,
        s: Socket,
        last_action: PollAction,
        cur_action: PollAction,
        mut trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        // 1. "we should only be called when the callback exists"
        debug_assert!(
            host.socket_cb_installed(),
            "the event machinery must be inert without a socket callback"
        );
        if !host.socket_cb_installed() {
            return CURLMcode::Ok;
        }

        // 2. Nothing from this target changed.
        if last_action == cur_action {
            return CURLMcode::Ok;
        }

        let Some(entry) = self.ev.get_mut(s) else {
            debug_assert!(false, "an update needs an existing entry");
            return CURLMcode::Ok;
        };

        // 3. The refcounts, in C's shape.
        if last_action.contains_in() {
            debug_assert!(
                entry.readers > 0,
                "a reader is leaving a socket that has none"
            );
            if !cur_action.contains_in() {
                // Saturating rather than wrapping: the assertion above states
                // the invariant, and a release build that reached here anyway
                // should clamp rather than wrap to four thousand million
                // readers.
                entry.readers = entry.readers.saturating_sub(1);
            }
        } else if cur_action.contains_in() {
            entry.readers = entry.readers.saturating_add(1);
        }

        if last_action.contains_out() {
            debug_assert!(
                entry.writers > 0,
                "a writer is leaving a socket that has none"
            );
            if !cur_action.contains_out() {
                entry.writers = entry.writers.saturating_sub(1);
            }
        } else if cur_action.contains_out() {
            entry.writers = entry.writers.saturating_add(1);
        }

        // 4. The three DEBUGASSERTs of `:251-253`.
        let users = entry.user_count();
        debug_assert!(entry.readers <= users, "more readers than users");
        debug_assert!(entry.writers <= users, "more writers than users");
        debug_assert!(
            entry.writers + entry.readers != 0,
            "an entry with no reader and no writer"
        );

        let readers = entry.readers;
        let writers = entry.writers;
        let announced_action = entry.action;
        let user_data = entry.user_data;

        // 5. FROZEN: `"ev update fd=%" FMT_SOCKET_T ", action '%s%s' -> "
        //    "'%s%s' (%d/%d r/w)"`.
        if let Some(tracer) = trc.as_deref_mut() {
            let (last_in, last_out) = action_fragments(last_action);
            let (cur_in, cur_out) = action_fragments(cur_action);
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "ev update fd={}, action '{}{}' -> '{}{}' ({}/{} r/w)",
                s,
                last_in,
                last_out,
                cur_in,
                cur_out,
                readers,
                writers
            );
        }

        // 6. The union the application is told about.
        let mut combo = PollAction::NONE;
        if writers != 0 {
            combo = combo | PollAction::OUT;
        }
        if readers != 0 {
            combo = combo | PollAction::IN;
        }

        // 7. THE DEDUPLICATION CONTRACT.
        if announced_action == combo {
            return CURLMcode::Ok;
        }

        // FROZEN: `"ev update call(fd=%" FMT_SOCKET_T ", ev=%s%s)"`.
        if let Some(tracer) = trc {
            let (combo_in, combo_out) = action_fragments(combo);
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "ev update call(fd={}, ev={}{})",
                s,
                combo_in,
                combo_out
            );
        }

        // 8. The callback, guarded.
        let rc = {
            let mut guard = CallbackGuard::enter(host);
            guard.host().call_socket_cb(mid, s, combo, user_data)
        };

        // Set BEFORE the result is examined (`:275-276`), so a socket the
        // application has seen once stays announced even when the callback
        // then fails -- which is what makes the eventual `CURL_POLL_REMOVE`
        // reach it.
        if let Some(entry) = self.ev.get_mut(s) {
            entry.announced = true;
        }

        if rc == CALLBACK_ABORT {
            host.set_dead();
            // `entry->action` is deliberately NOT updated on this path.
            return CURLMcode::AbortedByCallback;
        }

        if let Some(entry) = self.ev.get_mut(s) {
            entry.action = combo;
        }
        CURLMcode::Ok
    }

    /// `mev_forget_socket` (`lib/multi_ev.c:185-213`): purge a socket and,
    /// when the application knows about it, emit `CURL_POLL_REMOVE`.
    ///
    /// Two details are load-bearing:
    ///
    /// * A socket with no entry answers [`CURLMcode::Ok`] -- "we never knew or
    ///   already forgot about this socket".
    /// * **The entry is killed unconditionally**, after the callback, whether
    ///   or not the callback failed (`:207`). Only then is the failure
    ///   reported.
    fn forget_socket<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        mid: u32,
        s: Socket,
        cause: &str,
        trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        let Some(entry) = self.ev.get(s) else {
            return CURLMcode::Ok;
        };
        let announced = entry.announced;
        let user_data = entry.user_data;
        let mut rc = 0;

        // "We managed this socket before, tell the socket callback to forget
        // it."
        if announced && host.socket_cb_installed() {
            // FROZEN: `"ev %s, call(fd=%" FMT_SOCKET_T ", ev=REMOVE)"`.
            if let Some(tracer) = trc {
                trc_feat!(
                    tracer,
                    TraceFeature::Multi,
                    "ev {}, call(fd={}, ev=REMOVE)",
                    cause,
                    s
                );
            }
            rc = {
                let mut guard = CallbackGuard::enter(host);
                guard.host().call_socket_cb(
                    mid,
                    s,
                    PollAction::REMOVE,
                    user_data,
                )
            };
            // C clears the flag here (`:204`) although the entry is destroyed
            // immediately below, so nothing can observe it. Kept for exactness.
            if let Some(entry) = self.ev.get_mut(s) {
                entry.announced = false;
            }
        }

        self.ev.kill(s);
        if rc == CALLBACK_ABORT {
            host.set_dead();
            return CURLMcode::AbortedByCallback;
        }
        CURLMcode::Ok
    }
}

// THE DESCRIPTOR-SET AND WAIT SURFACES

/// What [`MultiEvents::fdset`] answers -- the engine half of
/// `curl_multi_fdset`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FdSet {
    /// Every descriptor to watch, with what it is wanted for.
    pub(crate) sockets: Vec<(Socket, PollAction)>,
    /// The largest descriptor seen, or `-1` when there is none -- C's
    /// `this_max_fd`, which starts at `-1` and is what `*max_fd` receives
    /// even when nothing was found.
    pub(crate) max_fd: i32,
}

impl MultiEvents {
    /// The descriptors to watch -- `curl_multi_fdset`
    /// (`lib/multi.c:1213-1263`).
    ///
    /// A `mid` in the process set that does not resolve is SKIPPED and, unlike
    /// [`Self::waitfds`] and the wait, is **not** removed. The asymmetry is
    /// C's (`lib/multi.c:1238-1241` against `:1291-1295`) and it is preserved
    /// deliberately: `curl_multi_fdset` is a pure query.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_fdset`
    pub(crate) fn fdset<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        fd_setsize: Socket,
        mut trc: Option<&mut Tracer<'_>>,
    ) -> FdSet {
        // C's `int this_max_fd = -1;` (`lib/multi.c:1220`).
        let mut result = FdSet {
            sockets: Vec::new(),
            max_fd: -1,
        };
        // One pollset, reset between transfers, as C does with its single
        // stack local.
        let mut ps = EasyPollset::new();

        for mid in host.process_mids() {
            if !host.resolves(mid) {
                // C additionally asserts here in a debug build. Reproducing
                // that would make the recovery untestable in the profile
                // `cargo test` uses, and the recovery is what every shipped C
                // build does; see the note on `DEBUGASSERT(0)` in
                // [`Self::waitfds`].
                continue;
            }
            let _ = pollset(host, mid, &mut ps, trc.as_deref_mut());
            Self::collect_fdset(&mut result, ps.iter(), fd_setsize);
        }

        // "Curl_cshutdn_setfds": connections draining in the shutdown pool
        // participate too.
        let shutdown = host.cshutdn_sockets();
        Self::collect_fdset(&mut result, shutdown.into_iter(), fd_setsize);

        result
    }

    /// Folds `(socket, action)` pairs into an [`FdSet`], applying the
    /// descriptor-set bound.
    ///
    /// The maximum is raised for every descriptor that passes the bound,
    /// whatever it is wanted for: C's `if((int)ps.sockets[i] > this_max_fd)`
    /// sits outside both `FD_SET` tests (`lib/multi.c:1250-1251`).
    fn collect_fdset(
        into: &mut FdSet,
        pairs: impl Iterator<Item = (Socket, PollAction)>,
        fd_setsize: Socket,
    ) {
        for (sock, action) in pairs {
            if !is_valid_sock(sock) || sock >= fd_setsize {
                // "pretend it does not exist"
                continue;
            }
            into.sockets.push((sock, action));
            if sock > into.max_fd {
                into.max_fd = sock;
            }
        }
    }

    /// Whether `curl_multi_waitfds`' arguments are acceptable --
    /// `if(!ufds && (size || !fd_count)) return
    /// CURLM_BAD_FUNCTION_ARGUMENT;` (`lib/multi.c:1276-1277`).
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_waitfds`
    pub(crate) const fn waitfds_args_ok(
        has_ufds: bool,
        size: u32,
        has_fd_count: bool,
    ) -> bool {
        !(!has_ufds && (size != 0 || !has_fd_count))
    }

    /// Fills the caller's array with the descriptors to watch --
    /// `curl_multi_waitfds` (`lib/multi.c:1266-1310`).
    ///
    /// Measured signature (`include/curl/multi.h:522-525`):
    ///
    /// ```c
    /// CURLMcode curl_multi_waitfds(CURLM *multi, struct curl_waitfd *ufds,
    ///                              unsigned int size, unsigned int *fd_count);
    /// ```
    ///
    /// # Errors
    ///
    /// * [`CURLMcode::BadFunctionArgument`] per [`Self::waitfds_args_ok`],
    ///   checked first.
    /// * **[`CURLMcode::OutOfMemory`] when the caller's array is too small**
    ///   -- `if(need != cwfds.n && ufds)`. Nothing ran out of memory; that is
    ///   simply the code C reports, and only when an array was supplied at
    ///   all. In counting mode the mismatch is the whole point and is not an
    ///   error.
    ///
    /// `*fd_count` receives the number of descriptors NEEDED whenever the
    /// caller supplied somewhere to put it -- **including on the
    /// out-of-memory path**, which is what makes "call once to size, once to
    /// fill" work.
    ///
    /// A `mid` that does not resolve is removed from BOTH the process and the
    /// dirty sets. C asserts first -- `DEBUGASSERT(0)` at `lib/multi.c:1290`
    /// -- and then heals; the assertion is not reproduced, because it fires
    /// only in a C `DEBUGBUILD` (which this build does not advertise, AAP
    /// 0.6.6) and reproducing it as a `debug_assert!` would make the healing
    /// untestable in the profile `cargo test` uses.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_waitfds`
    pub(crate) fn waitfds<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        ufds: Option<&mut [CurlWaitFd]>,
        size: u32,
        fd_count: Option<&mut u32>,
        mut trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        let has_ufds = ufds.is_some();
        if !Self::waitfds_args_ok(has_ufds, size, fd_count.is_some()) {
            return CURLMcode::BadFunctionArgument;
        }
        debug_assert!(
            ufds.as_ref()
                .map_or(true, |store| store.len() as u64 == u64::from(size)),
            "the slice and the caller's size must describe the same array"
        );

        let mut need: u32 = 0;
        let mut cwfds = match ufds {
            Some(store) => WaitFds::new(store),
            None => WaitFds::counting(),
        };
        let mut ps = EasyPollset::new();

        for mid in host.process_mids() {
            if !host.resolves(mid) {
                host.forget_mid(mid);
                continue;
            }
            let _ = pollset(host, mid, &mut ps, trc.as_deref_mut());
            need = need.saturating_add(cwfds.add_ps(&ps));
        }

        need = need.saturating_add(host.cshutdn_add_waitfds(&mut cwfds));

        // `if(need != cwfds.n && ufds) mresult = CURLM_OUT_OF_MEMORY;`
        let recorded = u32::try_from(cwfds.len()).unwrap_or(u32::MAX);
        let mresult = if need != recorded && has_ufds {
            CURLMcode::OutOfMemory
        } else {
            CURLMcode::Ok
        };

        // Written on every path, out-of-memory included.
        if let Some(count) = fd_count {
            *count = need;
        }
        mresult
    }

    /// `curl_multi_wait` -- `multi_wait(..., extrawait = FALSE, use_wakeup =
    /// FALSE)` (`lib/multi.c:1574-1582`).
    ///
    /// `ret` receives the number of descriptors with activity.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_wait`
    pub(crate) async fn wait<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        extra_fds: &mut [CurlWaitFd],
        timeout_ms: i32,
        ret: Option<&mut i32>,
        trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        self.multi_wait(host, extra_fds, timeout_ms, ret, false, false, trc)
            .await
    }

    /// `curl_multi_poll` -- `multi_wait(..., extrawait = TRUE, use_wakeup =
    /// TRUE)` (`lib/multi.c:1584-1591`).
    ///
    /// **Those two booleans are the only difference from [`Self::wait`]**, so
    /// there is one implementation and two wrappers rather than two
    /// implementations that could drift.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_poll`
    pub(crate) async fn poll<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        extra_fds: &mut [CurlWaitFd],
        timeout_ms: i32,
        ret: Option<&mut i32>,
        trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        self.multi_wait(host, extra_fds, timeout_ms, ret, true, true, trc)
            .await
    }

    /// `multi_wait` (`lib/multi.c:1332-1572`).
    ///
    /// # The assembly order is load-bearing
    ///
    /// 1. every transfer's pollset, healing dead `mid`s out of the process
    ///    and dirty sets as it goes;
    /// 2. the shutdown pool;
    /// 3. **the count of curl's own descriptors is recorded** -- the caller's
    ///    readiness is read back at `curl_nfds + i`, so the boundary has to be
    ///    known before the caller's descriptors are appended;
    /// 4. the caller's descriptors, translated from `CURL_WAIT_*` into the
    ///    internal `POLL*` bitmap;
    /// 5. the wakeup, last.
    ///
    /// # Errors
    ///
    /// * [`CURLMcode::RecursiveApiCall`] from inside a callback.
    /// * [`CURLMcode::BadFunctionArgument`] for a negative timeout.
    /// * [`CURLMcode::UnrecoverablePoll`] when the polling primitive itself
    ///   fails -- C's `if(pollrc < 0)`. In this design that is a reactor
    ///   error from [`PollFds::poll`], which is the same class of failure:
    ///   not a transfer that went wrong, but the mechanism for waiting.
    async fn multi_wait<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        extra_fds: &mut [CurlWaitFd],
        timeout_ms: i32,
        ret: Option<&mut i32>,
        extrawait: bool,
        use_wakeup: bool,
        mut trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        // The handle check is the shim's; these two are C's own, in order.
        if host.in_callback() {
            return CURLMcode::RecursiveApiCall;
        }
        if timeout_ms < 0 {
            return CURLMcode::BadFunctionArgument;
        }
        let mut timeout_ms = TimeDiff::from(timeout_ms);
        let mut retcode: i32 = 0;
        let mut ps = EasyPollset::new();
        let mut cpfds = PollFds::new();
        // C's `struct Curl_easy *data = NULL;` is a "did we see a transfer?"
        // flag by the time the trace below reads it.
        let mut saw_transfer = false;

        // 1. The transfers.
        for mid in host.process_mids() {
            if !host.resolves(mid) {
                host.forget_mid(mid);
                continue;
            }
            saw_transfer = true;
            let _ = pollset(host, mid, &mut ps, trc.as_deref_mut());
            cpfds.add_ps(&ps);
        }

        // 2. The shutdown pool.
        host.cshutdn_add_pollfds(&mut cpfds);

        // 3. The boundary between curl's descriptors and the caller's.
        let curl_nfds = cpfds.len();

        // 4. The caller's descriptors. The two vocabularies differ, and the C
        // maps them one bit at a time (`:1398-1404`).
        for fd in extra_fds.iter() {
            let mut events = PollEvents::NONE;
            if fd.events & CURL_WAIT_POLLIN != 0 {
                events |= PollEvents::IN;
            }
            if fd.events & CURL_WAIT_POLLPRI != 0 {
                events |= PollEvents::PRI;
            }
            if fd.events & CURL_WAIT_POLLOUT != 0 {
                events |= PollEvents::OUT;
            }
            cpfds.add_sock(fd.fd, events);
        }

        // 5. The wakeup joins the wait itself; see the note above.

        // The internal timeout, AFTER the collection.
        let (_expire_time, timeout_internal) =
            self.timeout(host, trc.as_deref_mut());
        if timeout_internal >= 0 && timeout_internal < timeout_ms {
            timeout_ms = timeout_internal;
        }

        // FROZEN, and emitted only when a transfer was seen -- C's `if(data)`.
        if saw_transfer {
            if let Some(tracer) = trc.as_deref_mut() {
                trc_feat!(
                    tracer,
                    TraceFeature::Multi,
                    "multi_wait(fds={}, timeout={}) tinternal={}",
                    cpfds.len(),
                    timeout_ms,
                    timeout_internal
                );
            }
        }

        if !cpfds.is_empty() || use_wakeup {
            let wakeup = self.wakeup.clone();
            let pollrc = {
                // `biased` so the outcome does not depend on a random choice:
                // readiness is examined first and the wakeup only if the wait
                // would otherwise block, which is the order the C's single
                // `poll()` produces.
                tokio::select! {
                    biased;
                    outcome = cpfds.poll(timeout_ms) => outcome,
                    () = wakeup.notified() => {
                        // The wakeup fired. C consumes the byte and then
                        // decrements `retcode` so that "do not count the
                        // wakeup socket into the returned value" (`:1536-1538`);
                        // an event object was never counted, so nothing is
                        // subtracted here and the count stays as it was.
                        Ok(0)
                    }
                }
            };
            let ready = match pollrc {
                Ok(ready) => ready,
                // C: `if(pollrc < 0) { mresult = CURLM_UNRECOVERABLE_POLL;
                // goto out; }`. Everything the `out:` label does is a cleanup
                // that ownership performs on the way out of this scope.
                Err(_) => return CURLMcode::UnrecoverablePoll,
            };
            if ready > 0 {
                retcode = i32::try_from(ready).unwrap_or(i32::MAX);
            }

            // "copy revents results from the poll to the curl_multi_wait poll
            // struct, the bit values of the actual underlying poll()
            // implementation may not be the same as the ones in the public
            // libcurl API!"
            let polled = cpfds.as_slice();
            for (index, fd) in extra_fds.iter_mut().enumerate() {
                let mut mask: i16 = 0;
                if let Some(entry) = polled.get(curl_nfds + index) {
                    if entry.revents.intersects(PollEvents::IN) {
                        mask |= CURL_WAIT_POLLIN;
                    }
                    if entry.revents.intersects(PollEvents::OUT) {
                        mask |= CURL_WAIT_POLLOUT;
                    }
                    if entry.revents.intersects(PollEvents::PRI) {
                        mask |= CURL_WAIT_POLLPRI;
                    }
                }
                fd.revents = mask;
            }
        }

        if let Some(out) = ret {
            *out = retcode;
        }

        // "Avoid busy-looping when there is nothing particular to wait for."
        if extrawait && cpfds.is_empty() && !use_wakeup {
            let (_expire_time, mut sleep_ms) = self.timeout(host, trc);
            // C writes the clamp as two branches with the same body:
            //
            // ```c
            // if(sleep_ms > timeout_ms) sleep_ms = timeout_ms;
            // /* when there are no easy handles in the multi, this holds a
            //    -1 timeout */
            // else if(sleep_ms < 0) sleep_ms = timeout_ms;
            // ```
            if sleep_ms != 0 {
                if sleep_ms > timeout_ms || sleep_ms < 0 {
                    sleep_ms = timeout_ms;
                }
                // `curlx_wait_ms(sleep_ms)`, which is
                // [`crate::conn::select::wait_ms`] and which converts through
                // `mstotv`: a negative span blocks for ever, zero polls, and
                // the two must not be collapsed. Zero never reaches it, since
                // `sleep_ms == 0` skips the sleep entirely rather than asking
                // for one of length zero.
                let _ = wait_ms(sleep_ms).await;
            }
        }

        CURLMcode::Ok
    }

    /// Interrupts a blocked [`Self::poll`] -- `curl_multi_wakeup`
    /// (`lib/multi.c:1593-1620`).
    ///
    /// # Callable from another thread
    ///
    /// Take a [`Wakeup`] from [`Self::wakeup_handle`] and call
    /// [`Wakeup::signal`] on it; that is the cross-thread form, and it is what
    /// `curl-rs-ffi` uses, because a `&self` here would still be a borrow of
    /// the multi handle. This method is the same signal for a caller that
    /// happens to hold the handle.
    ///
    /// # Errors
    ///
    /// [`CURLMcode::WakeupFailure`] -- *"wakeup is unavailable or failed"* --
    /// which C answers both when `Curl_wakeup_signal` fails and, by falling
    /// off the end of the function, when the mechanism was not compiled in at
    /// all. **The arm is unreachable here and is kept deliberately**: a
    /// [`Notify`] cannot fail to be constructed or signalled, but the code is
    /// part of the ABI, a C consumer may receive it from a differently
    /// configured build, and removing the variant would change the
    /// enumeration. It is [`CURLMcode`]'s to keep, and this is the function
    /// that documents why.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_wakeup`
    pub(crate) fn wakeup(&self) -> CURLMcode {
        self.wakeup.signal();
        CURLMcode::Ok
    }
}

// THE TIMERS

/// Forgets one timer -- `Curl_expire_done` (`lib/multi.c:3606-3612`).
#[allow(dead_code)] // consumer: every module that arms a timer
pub(crate) fn expire_done(
    timers: &mut ExpireTimers,
    id: ExpireId,
    trc: Option<&mut Tracer<'_>>,
) {
    timers.clear_one(id);
    // FROZEN: `CURL_TRC_TIMER(data, id, "cleared")`.
    if let Some(tracer) = trc {
        trc_timer!(tracer, id, "cleared");
    }
}

/// `now + milli`, computed exactly as `Curl_expire_ex` computes it.
///
/// ```c
/// set = *Curl_pgrs_now(data);
/// set.tv_sec += (time_t)(milli / 1000);
/// set.tv_usec += (int)(milli % 1000) * 1000;
/// if(set.tv_usec >= 1000000) { set.tv_sec++; set.tv_usec -= 1000000; }
/// ```
///
/// The carry is euclidean, so it normalises in both directions. C's carry only
/// handles the positive overflow, which is sound for it because every caller
/// passes a non-negative `milli`; the euclidean form agrees with C on all of
/// those and additionally keeps the microsecond invariant of [`CurlTime`] if
/// one ever passes a negative.
fn expire_instant(now: CurlTime, milli: TimeDiff) -> CurlTime {
    let secs = now.secs.saturating_add(milli / 1000);
    let usec = i64::from(now.usec).saturating_add((milli % 1000) * 1000);
    let carry = usec.div_euclid(1_000_000);
    // A remainder from a positive divisor lies in `0..1_000_000`, so it always
    // fits; the fallible form is used because this crate admits no narrowing
    // cast that could silently displace a timer.
    let fraction = i32::try_from(usec.rem_euclid(1_000_000)).unwrap_or(0);
    CurlTime::new(secs.saturating_add(carry), fraction)
}

impl MultiEvents {
    /// The nearest expiry across every registered handle --
    /// `multi_timeout` (`lib/multi.c:3334-3391`).
    ///
    /// Answers the instant and the relative milliseconds, which C returns
    /// through two out-parameters. The four cases, in C's order:
    ///
    /// 1. **A dead handle answers `0`.** C returns before writing
    ///    `*expire_time` at all (`:3348-3351`), leaving the caller's variable
    ///    untouched; [`CurlTime::ZERO`] is answered instead, and no caller
    ///    reads it on that path -- `Curl_update_timer` has already returned and
    ///    the two wait paths only feed it back here.
    /// 2. **Anything queued to run answers `0`**, with the instant set to a
    ///    fresh reading. This is why a dirty transfer makes
    ///    `curl_multi_timeout` report zero rather than the nearest timer.
    /// 3. **Otherwise the tree minimum**, converted with
    ///    `curlx_timediff_ceil_ms` -- which ROUNDS UP, adding 999 microseconds
    ///    before dividing, so a timer 1 microsecond away reports 1 millisecond
    ///    rather than 0 and the caller does not spin. An entry already due
    ///    answers `0`; the comparison for "already due" is at MICROSECOND
    ///    resolution.
    /// 4. **An empty tree answers `-1`** -- "no timeout at all", which is what
    ///    branch one and branch three of [`Self::update_timer`] test for.
    fn timeout<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        trc: Option<&mut Tracer<'_>>,
    ) -> (CurlTime, TimeDiff) {
        if host.is_dead() {
            return (CurlTime::ZERO, 0);
        }

        if host.has_dirties() {
            return (self.refresh_now(), 0);
        }

        // `Curl_splay(&tv_zero, multi->timetree)` surfaces the minimum without
        // removing it, which is [`TimerTree::peek`].
        let Some((key, mid)) =
            self.timers.timetree.peek().map(|(k, v)| (*k, *v))
        else {
            // `*expire_time = tv_zero; *timeout_ms = -1;`
            return (CurlTime::ZERO, -1);
        };

        let pnow = self.refresh_now();
        let expire_time = key.at;
        let timeout_ms = if timediff_us(expire_time, pnow) > 0 {
            // "some time left before expiration"
            timediff_ceil_ms(expire_time, pnow)
        } else {
            // "0 means immediately"
            0
        };

        if let Some(tracer) = trc {
            if let Some((id, _)) =
                host.expire_timers(mid).and_then(ExpireTimers::nearest)
            {
                trc_timer!(
                    tracer,
                    id,
                    "gives multi timeout in {}ms",
                    timeout_ms
                );
            }
        }

        (expire_time, timeout_ms)
    }

    /// `curl_multi_timeout` (`lib/multi.c:3393-3408`).
    ///
    /// # Errors
    ///
    /// [`CURLMcode::RecursiveApiCall`] when called from inside a callback.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_timeout`
    pub(crate) fn app_timeout<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        milliseconds: &mut TimeDiff,
        trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        if host.in_callback() {
            return CURLMcode::RecursiveApiCall;
        }
        let (_expire_time, timeout_ms) = self.timeout(host, trc);
        *milliseconds = timeout_ms;
        CURLMcode::Ok
    }

    /// The nearest expiry as a span, or [`None`] for "no timeout at all".
    #[allow(dead_code)] // consumer: `super`'s scheduler
    pub(crate) fn timeout_duration<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        trc: Option<&mut Tracer<'_>>,
    ) -> Option<std::time::Duration> {
        let (_expire_time, timeout_ms) = self.timeout(host, trc);
        mstotv(timeout_ms)
    }

    /// Tells the application to restart its timer -- `Curl_update_timer`
    /// (`lib/multi.c:3411-3464`).
    ///
    /// # The five branches, and the two that stay silent
    ///
    /// 1. No timeout now and none before -- **no callback**.
    /// 2. No timeout now but one before -- `"[TIMER] clear"`, the value
    ///    normalised to `-1`, callback.
    /// 3. A timeout now and none before -- `"[TIMER] set %ldms, none
    ///    before"`, callback.
    /// 4. A timeout now and one before, at a DIFFERENT instant --
    ///    `"[TIMER] set %ldms, replace previous"`, callback. C's rationale:
    ///    *"We had a timeout before and have one now, the absolute timestamp
    ///    differs. The relative `timeout_ms` may be the same, but the starting
    ///    point differs. Let the application restart its timer."* The
    ///    comparison is at MICROSECOND resolution.
    /// 5. The same instant as before -- **no callback**: *"We have same expire
    ///    time as previously. Our relative 'timeout_ms' may be different now,
    ///    but the application has the timer running and we do not to tell it to
    ///    start this again."*
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s perform and socket paths
    pub(crate) fn update_timer<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        mut trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        if !host.timer_cb_installed() || host.is_dead() {
            return CURLMcode::Ok;
        }
        let (expire_ts, mut timeout_ms) =
            self.timeout(host, trc.as_deref_mut());
        let last_timeout_ms = self.timers.last_timeout_ms;
        let mut set_value = false;

        if timeout_ms < 0 && last_timeout_ms < 0 {
            // 1. "nothing to do"
        } else if timeout_ms < 0 {
            // 2. "there is no timeout now but there was one previously"
            if let Some(tracer) = trc.as_deref_mut() {
                trc_feat!(tracer, TraceFeature::Multi, "[TIMER] clear");
            }
            timeout_ms = -1; // "normalize"
            set_value = true;
        } else if last_timeout_ms < 0 {
            // 3.
            if let Some(tracer) = trc.as_deref_mut() {
                trc_feat!(
                    tracer,
                    TraceFeature::Multi,
                    "[TIMER] set {}ms, none before",
                    timeout_ms
                );
            }
            set_value = true;
        } else if timediff_us(self.timers.last_expire_ts, expire_ts) != 0 {
            // 4.
            if let Some(tracer) = trc {
                trc_feat!(
                    tracer,
                    TraceFeature::Multi,
                    "[TIMER] set {}ms, replace previous",
                    timeout_ms
                );
            }
            set_value = true;
        } else {
            // 5. Same expire time; the application's timer is already running.
        }

        if set_value {
            self.timers.last_expire_ts = expire_ts;
            self.timers.last_timeout_ms = timeout_ms;
            let rc = {
                let mut guard = CallbackGuard::enter(host);
                guard.host().call_timer_cb(timeout_ms)
            };
            if rc == CALLBACK_ABORT {
                host.set_dead();
                return CURLMcode::AbortedByCallback;
            }
        }
        CURLMcode::Ok
    }

    /// Arms a timer -- `Curl_expire_ex` (`lib/multi.c:3526-3586`).
    ///
    /// # The three steps, in C's order
    ///
    /// 1. `multi_deltimeout(data, id)` FIRST -- *"Remove any timer with the
    ///    same id just in case."*
    /// 2. `multi_addtimeout(data, &set, id)` -- *"Add it to the timer list. It
    ///    must stay in the list until it has expired in case we need to
    ///    recompute the minimum timer later."*
    /// 3. The level-two book-keeping, whose early return is the subtle part:
    ///    if the handle is already registered and the new instant is LATER,
    ///    **nothing is done to the tree** -- *"The current splay tree entry is
    ///    sooner than this new expiry time. We do not need to update our splay
    ///    tree entry."* The test is `diff > 0`, so an EQUAL instant falls
    ///    through and re-inserts.
    #[allow(dead_code)] // consumer: every module that arms a timer
    pub(crate) fn expire_ex(
        &mut self,
        timers: &mut ExpireTimers,
        mid: u32,
        milli: TimeDiff,
        id: ExpireId,
        mut trc: Option<&mut Tracer<'_>>,
    ) {
        // `DEBUGASSERT(id < EXPIRE_LAST)`. Unreachable from safe Rust, where
        // an `ExpireId` is valid by construction; kept because the C states it
        // and because the sentinel must never name a slot.
        debug_assert!(
            (id as u8) < ExpireId::LAST,
            "the EXPIRE_LAST marker is not a timer"
        );

        let set = expire_instant(self.clock.now(), milli);

        // 1.
        timers.clear_one(id);
        // 2.
        self.add_timeout(timers, set, id, trc.as_deref_mut());

        // 3.
        if let Some(curr_expire) = timers.expiretime {
            let diff = timediff_ms(set, curr_expire);
            if diff > 0 {
                return;
            }
            // "Since this is an updated time, we must remove the previous
            // entry from the splay tree first and then re-add the new value"
            let removed = timers
                .timenode
                .and_then(|node| self.timers.timetree.remove(node));
            if removed.is_none() {
                let code = if self.timers.timetree.is_empty() {
                    1
                } else {
                    2
                };
                if let Some(tracer) = trc {
                    infof!(
                        tracer,
                        "Internal error removing splay node = {}",
                        code
                    );
                }
            }
        }

        // "Indicate that we are in the splay tree and insert the new timer
        // expiry value since it is our local minimum."
        timers.expiretime = Some(set);
        timers.timenode = Some(self.timers.timetree.insert(set, mid));
    }

    /// `Curl_expire` (`lib/multi.c:3599-3602`), which is **literally** a call
    /// to [`Self::expire_ex`] and nothing else.
    #[allow(dead_code)] // consumer: every module that arms a timer
    pub(crate) fn expire(
        &mut self,
        timers: &mut ExpireTimers,
        mid: u32,
        milli: TimeDiff,
        id: ExpireId,
        trc: Option<&mut Tracer<'_>>,
    ) {
        self.expire_ex(timers, mid, milli, id, trc);
    }

    /// Clears every timer for one handle -- `Curl_expire_clear`
    /// (`lib/multi.c:3618-3647`).
    ///
    /// `has_xfer_id` is `data->id >= 0`, which gates the frozen trace line and
    /// **is not `data->mid`**: `data->id` is the pool-scoped identifier whose
    /// sentinel is `-1`. It is passed in rather than read from the host so that
    /// a caller holding `&mut ExpireTimers` out of the host -- which every
    /// caller does -- need not borrow the host again; compute it first, then
    /// take the borrow.
    #[allow(dead_code)] // consumer: `super`'s `curl_multi_remove_handle`
    pub(crate) fn expire_clear(
        &mut self,
        timers: &mut ExpireTimers,
        has_xfer_id: bool,
        mut trc: Option<&mut Tracer<'_>>,
    ) {
        if timers.expiretime.is_none() {
            return;
        }

        let removed = timers
            .timenode
            .and_then(|node| self.timers.timetree.remove(node));
        if removed.is_none() {
            let code = if self.timers.timetree.is_empty() {
                1
            } else {
                2
            };
            if let Some(tracer) = trc.as_deref_mut() {
                infof!(tracer, "Internal error clearing splay node = {}", code);
            }
        }

        // "clear the timeout list too"
        timers.clear_all();

        // FROZEN, and gated on `data->id >= 0`.
        if has_xfer_id {
            if let Some(tracer) = trc {
                trc_feat!(tracer, TraceFeature::Multi, "[TIMEOUT] all cleared");
            }
        }

        timers.expiretime = None;
        timers.timenode = None;
    }

    /// `multi_addtimeout` (`lib/multi.c:3487-3524`): record a timer and place
    /// it in the handle's order.
    ///
    /// # The trace label is wrong in the C, and is reproduced wrong
    ///
    /// ```c
    /// CURL_TRC_TIMER(data, eid, "set for %" FMT_TIMEDIFF_T "ns",
    ///                curlx_ptimediff_us(&node->time, Curl_pgrs_now(data)));
    /// ```
    fn add_timeout(
        &mut self,
        timers: &mut ExpireTimers,
        at: CurlTime,
        id: ExpireId,
        trc: Option<&mut Tracer<'_>>,
    ) {
        timers.set(id, at);
        if let Some(tracer) = trc {
            let span = timediff_us(at, self.clock.now());
            trc_timer!(tracer, id, "set for {}ns", span);
        }
    }

    /// `add_next_timeout` (`lib/multi.c:2982-3033`): after a handle's entry has
    /// been taken out of the tree, pick its next timer and put it back.
    ///
    /// C's own description, verbatim: *"Each `Curl_easy` has a list of
    /// timeouts. The `add_next_timeout()` is called when it has just been
    /// removed from the splay tree because the timeout has expired. This
    /// function is then to advance in the list to pick the next timeout to use
    /// (skip the already expired ones) and add this node back to the splay tree
    /// again. The splay tree only has each sessionhandle as a single node and
    /// the nearest timeout is used to sort it on."*
    ///
    /// Two details:
    ///
    /// * The drain is at MICROSECOND resolution and its test is `diff <= 0`, so
    ///   **a timer due at exactly this instant is removed**. C stops at the
    ///   first future entry -- *"the list is sorted so get out on the first
    ///   mismatch"* -- which is what taking the nearest each time reproduces.
    /// * When something remains it is re-inserted and **also left in the
    ///   handle's own list**: *"Keep the timer in the list in case we need to
    ///   recompute future timers."*
    fn add_next_timeout(
        &mut self,
        timers: &mut ExpireTimers,
        mid: u32,
        pnow: CurlTime,
    ) {
        // "move over the timeout list for this specific handle and remove all
        // timeouts that are now passed tense"
        while let Some((id, at)) = timers.nearest() {
            if timediff_us(at, pnow) <= 0 {
                timers.clear_one(id);
            } else {
                break;
            }
        }

        match timers.nearest() {
            None => {
                // "clear the expire times within the handles that we remove
                // from the splay tree"
                timers.expiretime = None;
                // The tree entry is already gone -- `get_best` took it -- so
                // the recorded identity is stale and must not be reused. C has
                // no equivalent field to clear.
                timers.timenode = None;
            }
            Some((_id, at)) => {
                timers.expiretime = Some(at);
                timers.timenode = Some(self.timers.timetree.insert(at, mid));
            }
        }
    }

    /// `multi_mark_expired_as_dirty` (`lib/multi.c:3035-3068`): queue every
    /// handle whose timer is due.
    fn mark_expired_as_dirty<H: EventHost + ?Sized>(
        &mut self,
        host: &mut H,
        ts: CurlTime,
        mut trc: Option<&mut Tracer<'_>>,
    ) {
        while let Some((_key, mid)) = self.timers.timetree.get_best(ts) {
            if !host.resolves(mid) {
                continue;
            }

            if let Some(tracer) = trc.as_deref_mut() {
                if let Some((id, _)) =
                    host.expire_timers(mid).and_then(ExpireTimers::nearest)
                {
                    trc_timer!(tracer, id, "has expired");
                }
            }

            if let Some(timers) = host.expire_timers_mut(mid) {
                self.add_next_timeout(timers, mid, ts);
            }
            host.mark_dirty(mid);
        }
    }
}

// THE SOCKET ENTRY POINTS

impl MultiEvents {
    /// `multi_socket` (`lib/multi.c:3113-3181`): run whatever the reported
    /// event makes runnable, then re-arm the application's timer.
    ///
    /// # The order is the behaviour
    ///
    /// * **`checkall`** runs [`SchedulerHost::perform`] and then reassesses
    ///   EVERY active transfer's sockets -- but only when the result is not
    ///   [`CURLMcode::BadHandle`], since there would be nothing to assess.
    /// * **A real socket** marks that socket's transfers dirty.
    /// * **[`CURL_SOCKET_TIMEOUT`]** instead ZEROES `last_expire_ts`, and the C
    ///   explains why at length: *"Asked to run due to time-out. Clear the
    ///   'last_expire_ts' variable to force Curl_update_timer() to trigger a
    ///   callback to the app again even if the same timeout is still the one to
    ///   run after this call. That handles the case when the application asks
    ///   libcurl to run the timeout prematurely."* It is the mechanism by which
    ///   a timeout-driven call re-arms the application's timer, and optimising
    ///   it away would leave an application with a timer that never fires
    ///   again.
    /// * Then the due timers are queued and the dirty transfers run. **If
    ///   anything ran, the clock is read again and the dirty set is run once
    ///   more -- exactly once, not in a loop**: *"Running transfers takes time.
    ///   With a new timestamp, we might catch other expires which are due now.
    ///   Instead of telling the application to set a 0 timeout and call us
    ///   again, we run them here. Do that only once or it might be unfair to
    ///   transfers on other sockets."*
    /// * The tail runs on every path, error included: pending handles are
    ///   promoted, notifications are dispatched, `running_handles` is written,
    ///   and the timer is updated last.
    fn multi_socket<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        checkall: bool,
        s: Socket,
        ev_bitmask: i32,
        running_handles: Option<&mut i32>,
        mut trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        let _ = ev_bitmask;
        // Assigned by both arms below, as C's is: `CURLMcode mresult =
        // CURLM_OK;` is C's way of saying the same thing without definite
        // initialisation to lean on.
        let mut mresult;

        if checkall {
            // "*perform() deals with running_handles on its own"
            mresult = host.perform();
            if mresult != CURLMcode::BadHandle {
                // "Reassess event status of all active transfers"
                let mids = host.process_mids();
                mresult = self.assess_xfer_set(host, &mids, trc.as_deref_mut());
            }
        } else {
            if s != CURL_SOCKET_TIMEOUT {
                // "Mark all transfers of that socket as dirty"
                self.dirty_xfers(host, s, trc.as_deref_mut());
            } else {
                // Force the next `update_timer` to call the application.
                self.timers.last_expire_ts = CurlTime::ZERO;
            }

            let ts = self.refresh_now();
            self.mark_expired_as_dirty(host, ts, trc.as_deref_mut());
            let (result, run_xfers) = host.run_dirty();
            mresult = result;

            // C's `if(mresult) goto out;` skips the second pass on failure.
            if mresult.is_ok() && run_xfers != 0 {
                let ts = self.refresh_now();
                self.mark_expired_as_dirty(host, ts, trc.as_deref_mut());
                let (result, _ran) = host.run_dirty();
                mresult = result;
            }
        }

        // `out:`
        if host.ischanged(true) {
            host.process_pending_handles();
        }

        if mresult.is_ok() && host.notify_has_entries() {
            mresult = host.dispatch_notifications();
        }

        if let Some(out) = running_handles {
            // `(running < INT_MAX) ? (int)running : INT_MAX`
            *out = i32::try_from(host.xfers_running()).unwrap_or(i32::MAX);
        }

        // `if(CURLM_OK >= mresult)` -- also true for
        // `CURLM_CALL_MULTI_PERFORM`, which is negative.
        if mresult <= CURLMcode::Ok {
            mresult = self.update_timer(host, trc);
        }
        mresult
    }

    /// `curl_multi_socket_action` (`lib/multi.c:3292-3302`).
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_socket_action`
    pub(crate) fn socket_action<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        s: Socket,
        ev_bitmask: i32,
        running_handles: Option<&mut i32>,
        trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        if host.in_callback() || host.in_ntfy_callback() {
            return CURLMcode::RecursiveApiCall;
        }
        self.multi_socket(host, false, s, ev_bitmask, running_handles, trc)
    }

    /// `curl_multi_socket` (`lib/multi.c:3281-3290`) -- **deprecated since
    /// 7.19.5 and still exported**.
    ///
    /// ```c
    /// CURL_EXTERN CURLMcode CURL_DEPRECATED(7.19.5, "Use curl_multi_socket_action()")
    /// curl_multi_socket(CURLM *multi_handle, curl_socket_t s, int *running_handles);
    /// ```
    ///
    /// # Why the symbol cannot be dropped
    ///
    /// The header additionally hides it behind a macro:
    ///
    /// ```c
    /// #ifndef CURL_ALLOW_OLD_MULTI_SOCKET
    /// #define curl_multi_socket(x,y,z) curl_multi_socket_action(x,y,0,z)
    /// #endif
    /// ```
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_socket`
    pub(crate) fn socket<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        s: Socket,
        running_handles: Option<&mut i32>,
        trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        if host.in_callback() || host.in_ntfy_callback() {
            return CURLMcode::RecursiveApiCall;
        }
        self.multi_socket(host, false, s, 0, running_handles, trc)
    }

    /// `curl_multi_socket_all` (`lib/multi.c:3304-3313`) -- **deprecated since
    /// 7.19.5 and still exported**, for the reasons [`Self::socket`] records.
    ///
    /// ```c
    /// CURL_EXTERN CURLMcode CURL_DEPRECATED(7.19.5, "Use curl_multi_socket_action()")
    /// curl_multi_socket_all(CURLM *multi_handle, int *running_handles);
    /// ```
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_socket_all`
    pub(crate) fn socket_all<H: SchedulerHost + ?Sized>(
        &mut self,
        host: &mut H,
        running_handles: Option<&mut i32>,
        trc: Option<&mut Tracer<'_>>,
    ) -> CURLMcode {
        if host.in_callback() || host.in_ntfy_callback() {
            return CURLMcode::RecursiveApiCall;
        }
        self.multi_socket(host, true, CURL_SOCKET_BAD, 0, running_handles, trc)
    }
}

// TESTS

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{TraceConfig, TraceState, WriterSink};
    use crate::util::timeval::TestClock;
    use std::time::Duration;

    // THE ABI LAYOUT WITNESS

    /// The C declaration, for a layout assertion and nothing else.
    ///
    /// ```c
    /// struct curl_waitfd {
    ///   curl_socket_t fd;
    ///   short events;
    ///   short revents;
    /// };
    /// ```
    #[repr(C)]
    struct WaitFdWitness {
        fd: Socket,
        events: i16,
        revents: i16,
    }

    /// The `#[repr(C)]` field offsets of a three-field struct.
    const fn repr_c_offsets(
        sizes: [usize; 3],
        aligns: [usize; 3],
    ) -> ([usize; 3], usize) {
        let mut offsets = [0_usize; 3];
        let mut cursor = 0_usize;
        let mut struct_align = 1_usize;
        let mut index = 0;
        while index < 3 {
            let align = aligns[index];
            if align > struct_align {
                struct_align = align;
            }
            // Round the cursor up to this field's alignment.
            cursor = cursor.div_ceil(align) * align;
            offsets[index] = cursor;
            cursor += sizes[index];
            index += 1;
        }
        // And the whole struct up to its own alignment.
        let size = cursor.div_ceil(struct_align) * struct_align;
        (offsets, size)
    }

    #[test]
    fn curl_waitfd_has_the_c_layout() {
        assert_eq!(
            std::mem::size_of::<WaitFdWitness>(),
            8,
            "struct curl_waitfd is 8 bytes on every target of AAP 0.8.3"
        );
        assert_eq!(std::mem::align_of::<WaitFdWitness>(), 4);

        // `fd` at 0, `events` at 4, `revents` at 6.
        let sizes = [
            std::mem::size_of::<Socket>(),
            std::mem::size_of::<i16>(),
            std::mem::size_of::<i16>(),
        ];
        let aligns = [
            std::mem::align_of::<Socket>(),
            std::mem::align_of::<i16>(),
            std::mem::align_of::<i16>(),
        ];
        let (offsets, size) = repr_c_offsets(sizes, aligns);
        assert_eq!(offsets, [0, 4, 6]);
        assert_eq!(size, std::mem::size_of::<WaitFdWitness>());

        // `curl_socket_t` is `int` on all four targets, which is what makes
        // the offsets above what they are. On Windows it would be a
        // pointer-sized unsigned and the struct would be twelve bytes; Windows
        // is out of scope and no branch for it exists here.
        assert_eq!(std::mem::size_of::<Socket>(), 4);
        assert_eq!(std::mem::size_of::<i16>(), 2);
    }

    #[test]
    fn the_engine_side_waitfd_carries_the_same_three_fields() {
        let fd = CurlWaitFd {
            fd: 7,
            events: CURL_WAIT_POLLIN,
            revents: 0,
        };
        assert_eq!(fd.fd, 7);
        assert_eq!(fd.events, CURL_WAIT_POLLIN);
        assert_eq!(fd.revents, 0);
    }

    // THE THREE BIT FAMILIES

    #[test]
    fn the_public_wait_bits_are_pinned() {
        assert_eq!(CURL_WAIT_POLLIN, 0x0001);
        assert_eq!(CURL_WAIT_POLLPRI, 0x0002);
        assert_eq!(CURL_WAIT_POLLOUT, 0x0004);
    }

    #[test]
    fn the_socket_callback_bits_are_pinned() {
        assert_eq!(PollAction::NONE.bits(), 0);
        assert_eq!(PollAction::IN.bits(), 1);
        assert_eq!(PollAction::OUT.bits(), 2);
        assert_eq!(PollAction::INOUT.bits(), 3);
        assert_eq!(PollAction::REMOVE.bits(), 4);
        // `INOUT` is exactly the union, which the C spells as a separate
        // `#define` and which would otherwise look like a coincidence.
        assert_eq!(PollAction::INOUT, PollAction::IN | PollAction::OUT);
        // `REMOVE` is NOT a bit combination: it is 4, a distinct command, and
        // in particular it is not `IN | OUT | something`.
        assert_ne!(PollAction::REMOVE, PollAction::IN | PollAction::OUT);
    }

    #[test]
    fn the_inbound_cselect_bits_are_pinned() {
        assert_eq!(CURL_CSELECT_IN, 0x01);
        assert_eq!(CURL_CSELECT_OUT, 0x02);
        assert_eq!(CURL_CSELECT_ERR, 0x04);
    }

    #[test]
    fn the_three_families_overlap_numerically_and_must_not_be_unified() {
        // The trap this test exists to pin: urgent data and writability share
        // the integer 2 across two different vocabularies.
        assert_eq!(
            i64::from(CURL_CSELECT_OUT),
            i64::from(CURL_WAIT_POLLPRI),
            "the same integer, two unrelated meanings"
        );
        assert_ne!(i64::from(CURL_WAIT_POLLPRI), i64::from(CURL_CSELECT_ERR));
        // And the callback family disagrees with the wait family about 2 and 4.
        assert_eq!(PollAction::OUT.bits(), 2);
        assert_eq!(CURL_WAIT_POLLOUT, 4);
    }

    #[test]
    fn the_timeout_socket_is_the_bad_socket() {
        // `#define CURL_SOCKET_TIMEOUT CURL_SOCKET_BAD`
        // (`include/curl/multi.h:289`): the same integer, told apart only by
        // intent.
        assert_eq!(CURL_SOCKET_TIMEOUT, CURL_SOCKET_BAD);
        assert_eq!(CURL_SOCKET_BAD, -1);
    }

    // THE EXPIRE IDENTIFIERS

    #[test]
    fn every_expire_discriminant_is_pinned() {
        #[rustfmt::skip]
        let expected: [(ExpireId, i32); ExpireId::COUNT] = [
            (ExpireId::Expect100Timeout,   0),
            (ExpireId::AsyncName,          1),
            (ExpireId::ConnectTimeout,     2),
            (ExpireId::DnsPerName,         3),
            (ExpireId::DnsPerName2,        4),
            (ExpireId::HappyEyeballsDns,   5),
            (ExpireId::HappyEyeballs,      6),
            (ExpireId::MultiPending,       7),
            (ExpireId::SpeedCheck,         8),
            (ExpireId::Timeout,            9),
            (ExpireId::TooFast,           10),
            (ExpireId::Quic,              11),
            (ExpireId::FtpAccept,         12),
            (ExpireId::AlpnEyeballs,      13),
            (ExpireId::Shutdown,          14),
        ];
        for (id, value) in expected {
            assert_eq!(id as i32, value);
            assert_eq!(ExpireId::from_i32(value), Some(id));
        }
        // `EXPIRE_LAST` is 15 and is published as a number, never as a value.
        assert_eq!(ExpireId::LAST, 15);
        assert_eq!(ExpireId::COUNT, 15);
        assert_eq!(ExpireId::from_i32(15), None);
    }

    #[test]
    fn the_fifteen_timer_names_are_frozen() {
        #[rustfmt::skip]
        let expected = [
            "100_TIMEOUT", "ASYNC_NAME", "CONNECTTIMEOUT", "DNS_PER_NAME",
            "DNS_PER_NAME2", "HAPPY_EYEBALLS_DNS", "HAPPY_EYEBALLS",
            "MULTI_PENDING", "SPEEDCHECK", "TIMEOUT", "TOOFAST", "QUIC",
            "FTP_ACCEPT", "ALPN_EYEBALLS", "SHUTDOWN",
        ];
        assert_eq!(expected.len(), ExpireId::COUNT);
        for (index, name) in expected.iter().enumerate() {
            let id = ExpireId::from_i32(index as i32).expect("in range");
            assert_eq!(id.name(), *name);
        }
    }

    #[test]
    fn the_timer_fallback_is_unknown_question_mark_and_not_the_state_one() {
        // `trc_timer_name()`'s bounds check (`lib/curl_trc.c:301-303`).
        assert_eq!(ExpireId::name_from_i32(15), "UNKNOWN?");
        assert_eq!(ExpireId::name_from_i32(-1), "UNKNOWN?");
        assert_eq!(ExpireId::name_from_i32(9999), "UNKNOWN?");
        // The multi-state fallback is a DIFFERENT string for a DIFFERENT
        // array (`lib/curl_trc.c:358`). Unifying them would change trace output.
        assert_eq!(CurlMstate::name_from_i32(17), "?");
        assert_ne!(ExpireId::name_from_i32(15), CurlMstate::name_from_i32(17));
    }

    // TRACE CAPTURE HELPERS

    /// Runs `body` against a tracer whose `MULTI` feature is verbose.
    fn multi_trace(body: impl FnOnce(&mut Tracer<'_>)) -> String {
        trace_with(b"multi", body)
    }

    /// Runs `body` against a tracer whose `TIMER` feature is verbose.
    fn timer_trace(body: impl FnOnce(&mut Tracer<'_>)) -> String {
        trace_with(b"timer", body)
    }

    fn trace_with(
        config_text: &[u8],
        body: impl FnOnce(&mut Tracer<'_>),
    ) -> String {
        let mut config = TraceConfig::new();
        config
            .apply(Some(config_text))
            .expect("a known feature name");
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            body(&mut tracer);
        }
        String::from_utf8(sink.into_inner()).expect("trace output is text")
    }

    // THE TEST HOST

    /// One socket-callback invocation, as the application would see it.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SocketCall {
        mid: u32,
        sock: Socket,
        what: PollAction,
        socketp: CallbackData,
    }

    /// As much of a transfer as this module reads.
    #[derive(Debug, Default)]
    struct TestXfer {
        state: Option<CurlMstate>,
        has_conn: bool,
        /// What this transfer's per-state pollset producer yields.
        want: Vec<(Socket, PollAction)>,
        /// The owned previous pollset that replaces C's meta-hash stash.
        prev: EasyPollset,
        /// The level-one timers.
        timers: ExpireTimers,
        has_id: bool,
    }

    impl TestXfer {
        fn wanting(want: &[(Socket, PollAction)]) -> Self {
            Self {
                state: Some(CurlMstate::Performing),
                has_conn: true,
                want: want.to_vec(),
                has_id: true,
                ..Self::default()
            }
        }
    }

    /// A multi handle, reduced to the seams this module reaches through.
    #[derive(Debug)]
    struct TestHost {
        xfers: BTreeMap<u32, TestXfer>,
        conn_want: BTreeMap<ConnId, Vec<(Socket, PollAction)>>,
        conn_prev: BTreeMap<ConnId, EasyPollset>,
        process: Vec<u32>,
        socket_cb: bool,
        socket_calls: Vec<SocketCall>,
        socket_cb_result: i32,
        /// Whether `in_callback` was set while each callback ran.
        guard_seen: Vec<bool>,
        timer_cb: bool,
        timer_calls: Vec<TimeDiff>,
        timer_cb_result: i32,
        in_callback: bool,
        in_ntfy_callback: bool,
        dead: bool,
        dirty_marks: Vec<u32>,
        forgotten: Vec<u32>,
        has_dirties: bool,
        running: u32,
        perform_result: CURLMcode,
        perform_calls: u32,
        run_dirty_results: Vec<(CURLMcode, u32)>,
        run_dirty_calls: usize,
        changed: bool,
        pending_promotions: u32,
        notify_entries: bool,
        notify_result: CURLMcode,
        notify_dispatches: u32,
        cshutdn: Vec<(Socket, PollAction)>,
        pollset_error: Option<CURLcode>,
    }

    impl Default for TestHost {
        fn default() -> Self {
            Self {
                xfers: BTreeMap::new(),
                conn_want: BTreeMap::new(),
                conn_prev: BTreeMap::new(),
                process: Vec::new(),
                socket_cb: true,
                socket_calls: Vec::new(),
                socket_cb_result: 0,
                guard_seen: Vec::new(),
                timer_cb: true,
                timer_calls: Vec::new(),
                timer_cb_result: 0,
                in_callback: false,
                in_ntfy_callback: false,
                dead: false,
                dirty_marks: Vec::new(),
                forgotten: Vec::new(),
                has_dirties: false,
                running: 0,
                perform_result: CURLMcode::Ok,
                perform_calls: 0,
                run_dirty_results: Vec::new(),
                run_dirty_calls: 0,
                changed: false,
                pending_promotions: 0,
                notify_entries: false,
                notify_result: CURLMcode::Ok,
                notify_dispatches: 0,
                cshutdn: Vec::new(),
                pollset_error: None,
            }
        }
    }

    impl TestHost {
        /// A handle with `mids` in its process set, each wanting nothing.
        fn with_xfers(mids: &[u32]) -> Self {
            let mut host = Self::default();
            for mid in mids {
                host.xfers.insert(*mid, TestXfer::wanting(&[]));
                host.process.push(*mid);
            }
            host
        }

        fn set_want(&mut self, mid: u32, want: &[(Socket, PollAction)]) {
            let xfer = self.xfers.entry(mid).or_default();
            xfer.state = Some(CurlMstate::Performing);
            xfer.has_conn = true;
            xfer.has_id = true;
            xfer.want = want.to_vec();
            if !self.process.contains(&mid) {
                self.process.push(mid);
            }
        }

        /// The single pollset producer every state arm delegates to.
        fn produce(
            &mut self,
            mid: u32,
            ps: &mut EasyPollset,
            mut trc: Option<&mut Tracer<'_>>,
        ) -> CodeResult<()> {
            if let Some(code) = self.pollset_error {
                return Err(code);
            }
            let want = self.xfers.get(&mid).map(|x| x.want.clone());
            for (sock, action) in want.unwrap_or_default() {
                ps.set(
                    sock,
                    action.contains_in(),
                    action.contains_out(),
                    trc.as_deref_mut(),
                )?;
            }
            Ok(())
        }

        fn calls(&self) -> &[SocketCall] {
            &self.socket_calls
        }
    }

    impl EventHost for TestHost {
        fn socket_cb_installed(&self) -> bool {
            self.socket_cb
        }

        fn call_socket_cb(
            &mut self,
            mid: u32,
            s: Socket,
            what: PollAction,
            socketp: CallbackData,
        ) -> i32 {
            self.guard_seen.push(self.in_callback);
            self.socket_calls.push(SocketCall {
                mid,
                sock: s,
                what,
                socketp,
            });
            self.socket_cb_result
        }

        fn set_in_callback(&mut self, value: bool) {
            self.in_callback = value;
        }

        fn in_callback(&self) -> bool {
            self.in_callback
        }

        fn set_dead(&mut self) {
            self.dead = true;
        }

        fn is_dead(&self) -> bool {
            self.dead
        }

        fn resolves(&self, mid: u32) -> bool {
            self.xfers.contains_key(&mid)
        }

        fn mark_dirty(&mut self, mid: u32) {
            self.dirty_marks.push(mid);
        }

        fn process_mids(&self) -> Vec<u32> {
            self.process.clone()
        }

        fn forget_mid(&mut self, mid: u32) {
            self.forgotten.push(mid);
            self.process.retain(|held| *held != mid);
        }

        fn mstate_of(&self, mid: u32) -> Option<CurlMstate> {
            self.xfers.get(&mid).and_then(|xfer| xfer.state)
        }

        fn has_conn(&self, mid: u32) -> bool {
            self.xfers.get(&mid).is_some_and(|xfer| xfer.has_conn)
        }

        fn resolv_pollset(
            &mut self,
            mid: u32,
            ps: &mut EasyPollset,
            trc: Option<&mut Tracer<'_>>,
        ) -> CodeResult<()> {
            self.produce(mid, ps, trc)
        }

        fn connecting_pollset(
            &mut self,
            mid: u32,
            ps: &mut EasyPollset,
            trc: Option<&mut Tracer<'_>>,
        ) -> CodeResult<()> {
            self.produce(mid, ps, trc)
        }

        fn protocol_pollset(
            &mut self,
            mid: u32,
            ps: &mut EasyPollset,
            trc: Option<&mut Tracer<'_>>,
        ) -> CodeResult<()> {
            self.produce(mid, ps, trc)
        }

        fn do_pollset(
            &mut self,
            mid: u32,
            ps: &mut EasyPollset,
            trc: Option<&mut Tracer<'_>>,
        ) -> CodeResult<()> {
            self.produce(mid, ps, trc)
        }

        fn domore_pollset(
            &mut self,
            mid: u32,
            ps: &mut EasyPollset,
            trc: Option<&mut Tracer<'_>>,
        ) -> CodeResult<()> {
            self.produce(mid, ps, trc)
        }

        fn perform_pollset(
            &mut self,
            mid: u32,
            ps: &mut EasyPollset,
            trc: Option<&mut Tracer<'_>>,
        ) -> CodeResult<()> {
            self.produce(mid, ps, trc)
        }

        fn conn_adjust_pollset(
            &mut self,
            _mid: u32,
            conn: ConnId,
            ps: &mut EasyPollset,
            mut trc: Option<&mut Tracer<'_>>,
        ) -> CodeResult<()> {
            if let Some(code) = self.pollset_error {
                return Err(code);
            }
            let want = self.conn_want.get(&conn).cloned().unwrap_or_default();
            for (sock, action) in want {
                ps.set(
                    sock,
                    action.contains_in(),
                    action.contains_out(),
                    trc.as_deref_mut(),
                )?;
            }
            Ok(())
        }

        fn take_prev_pollset(
            &mut self,
            target: EvTarget,
        ) -> Option<EasyPollset> {
            match target {
                EvTarget::Xfer(mid) => self
                    .xfers
                    .get_mut(&mid)
                    .map(|xfer| std::mem::take(&mut xfer.prev)),
                EvTarget::Conn { conn, .. } => {
                    Some(self.conn_prev.remove(&conn).unwrap_or_default())
                }
            }
        }

        fn put_prev_pollset(&mut self, target: EvTarget, prev: EasyPollset) {
            match target {
                EvTarget::Xfer(mid) => {
                    if let Some(xfer) = self.xfers.get_mut(&mid) {
                        xfer.prev = prev;
                    }
                }
                EvTarget::Conn { conn, .. } => {
                    self.conn_prev.insert(conn, prev);
                }
            }
        }

        fn drop_prev_pollset(&mut self, target: EvTarget) {
            match target {
                EvTarget::Xfer(mid) => {
                    if let Some(xfer) = self.xfers.get_mut(&mid) {
                        xfer.prev = EasyPollset::new();
                    }
                }
                EvTarget::Conn { conn, .. } => {
                    self.conn_prev.remove(&conn);
                }
            }
        }

        fn expire_timers(&self, mid: u32) -> Option<&ExpireTimers> {
            self.xfers.get(&mid).map(|xfer| &xfer.timers)
        }

        fn expire_timers_mut(&mut self, mid: u32) -> Option<&mut ExpireTimers> {
            self.xfers.get_mut(&mid).map(|xfer| &mut xfer.timers)
        }

        fn has_xfer_id(&self, mid: u32) -> bool {
            self.xfers.get(&mid).is_some_and(|xfer| xfer.has_id)
        }
    }

    impl SchedulerHost for TestHost {
        fn in_ntfy_callback(&self) -> bool {
            self.in_ntfy_callback
        }

        fn has_dirties(&mut self) -> bool {
            self.has_dirties
        }

        fn xfers_running(&self) -> u32 {
            self.running
        }

        fn perform(&mut self) -> CURLMcode {
            self.perform_calls += 1;
            self.perform_result
        }

        fn run_dirty(&mut self) -> (CURLMcode, u32) {
            let outcome = self
                .run_dirty_results
                .get(self.run_dirty_calls)
                .copied()
                .unwrap_or((CURLMcode::Ok, 0));
            self.run_dirty_calls += 1;
            outcome
        }

        fn ischanged(&mut self, clear: bool) -> bool {
            let was = self.changed;
            if clear {
                self.changed = false;
            }
            was
        }

        fn process_pending_handles(&mut self) {
            self.pending_promotions += 1;
        }

        fn notify_has_entries(&self) -> bool {
            self.notify_entries
        }

        fn dispatch_notifications(&mut self) -> CURLMcode {
            self.notify_dispatches += 1;
            self.notify_result
        }

        fn cshutdn_add_pollfds(&mut self, pfds: &mut PollFds) {
            for (sock, action) in &self.cshutdn {
                let mut events = PollEvents::NONE;
                if action.contains_in() {
                    events |= PollEvents::IN;
                }
                if action.contains_out() {
                    events |= PollEvents::OUT;
                }
                pfds.add_sock(*sock, events);
            }
        }

        fn cshutdn_add_waitfds(&mut self, wfds: &mut WaitFds<'_>) -> u32 {
            let mut ps = EasyPollset::new();
            for (sock, action) in &self.cshutdn {
                ps.set(
                    *sock,
                    action.contains_in(),
                    action.contains_out(),
                    None,
                )
                .expect("a valid descriptor");
            }
            wfds.add_ps(&ps)
        }

        fn cshutdn_sockets(&mut self) -> Vec<(Socket, PollAction)> {
            self.cshutdn.clone()
        }

        fn timer_cb_installed(&self) -> bool {
            self.timer_cb
        }

        fn call_timer_cb(&mut self, timeout_ms: TimeDiff) -> i32 {
            self.guard_seen.push(self.in_callback);
            self.timer_calls.push(timeout_ms);
            self.timer_cb_result
        }
    }

    /// Event state over a controllable clock, and the clock itself.
    fn events_at(secs: i64) -> (MultiEvents, Arc<TestClock>) {
        let clock = Arc::new(TestClock::new(CurlTime::new(secs, 0)));
        let events = MultiEvents::new(clock.clone());
        (events, clock)
    }

    // THE SOCKET-CALLBACK CONTRACT

    /// The highest-value test in the module: the exact callback stream two
    /// transfers sharing one descriptor produce.
    ///
    /// Every step's expectation comes from `mev_sh_entry_update`
    /// (`lib/multi_ev.c:215-282`), and the two steps that expect SILENCE are
    /// the deduplication contract.
    #[test]
    fn two_transfers_on_one_socket_produce_the_c_callback_stream() {
        const FD: Socket = 7;
        let (mut events, _clock) = events_at(100);
        let mut host = TestHost::with_xfers(&[1, 2]);

        // Transfer A wants to read: the application is told once.
        host.set_want(1, &[(FD, PollAction::IN)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        assert_eq!(host.calls().len(), 1);
        assert_eq!(host.calls()[0].what, PollAction::IN);
        assert_eq!(host.calls()[0].sock, FD);
        assert_eq!(host.calls()[0].mid, 1);

        // Transfer B wants to read the same descriptor. The aggregate is
        // unchanged, so the application is NOT called.
        host.set_want(2, &[(FD, PollAction::IN)]);
        assert!(events.assess_xfer(&mut host, 2, None).is_ok());
        assert_eq!(host.calls().len(), 1, "the deduplication contract");
        {
            let entry = events.ev.get(FD).expect("the socket is known");
            assert_eq!(entry.readers, 2);
            assert_eq!(entry.writers, 0);
            assert_eq!(entry.user_count(), 2);
        }

        // B also wants to write: the union changes and the application is told.
        host.set_want(2, &[(FD, PollAction::INOUT)]);
        assert!(events.assess_xfer(&mut host, 2, None).is_ok());
        assert_eq!(host.calls().len(), 2);
        assert_eq!(host.calls()[1].what, PollAction::INOUT);
        assert_eq!(events.ev.get(FD).expect("known").writers, 1);

        // B stops writing: the union changes back.
        host.set_want(2, &[(FD, PollAction::IN)]);
        assert!(events.assess_xfer(&mut host, 2, None).is_ok());
        assert_eq!(host.calls().len(), 3);
        assert_eq!(host.calls()[2].what, PollAction::IN);
        assert_eq!(events.ev.get(FD).expect("known").writers, 0);

        // A loses interest. B still reads, so the union is unchanged and the
        // application is NOT called.
        host.set_want(1, &[]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        assert_eq!(host.calls().len(), 3, "the deduplication contract again");
        {
            let entry = events.ev.get(FD).expect("still known");
            assert_eq!(entry.readers, 1);
            assert_eq!(entry.user_count(), 1);
            assert!(entry.readers + entry.writers != 0);
        }

        // B loses interest too: the last user is gone, so the socket is
        // removed and forgotten.
        host.set_want(2, &[]);
        assert!(events.assess_xfer(&mut host, 2, None).is_ok());
        assert_eq!(host.calls().len(), 4);
        assert_eq!(host.calls()[3].what, PollAction::REMOVE);
        assert!(events.ev.get(FD).is_none(), "the entry is killed");
    }

    #[test]
    fn a_socket_the_application_never_saw_is_not_un_announced() {
        // With no socket callback the machinery is inert, so nothing is ever
        // announced and `mev_forget_socket` must stay silent.
        const FD: Socket = 9;
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);
        host.socket_cb = false;
        host.set_want(1, &[(FD, PollAction::IN)]);

        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        assert!(host.calls().is_empty(), "no callback, no work");
        assert!(events.ev.is_empty(), "and no book-keeping either");
    }

    #[test]
    fn the_callback_runs_inside_the_recursion_guard() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(3, PollAction::IN)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        assert_eq!(host.guard_seen, vec![true], "in_callback while calling");
        assert!(!host.in_callback, "and cleared afterwards");
    }

    #[test]
    fn a_refusing_socket_callback_kills_the_multi_handle() {
        const FD: Socket = 11;
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);
        host.socket_cb_result = CALLBACK_ABORT;
        host.set_want(1, &[(FD, PollAction::IN)]);

        assert_eq!(
            events.assess_xfer(&mut host, 1, None),
            CURLMcode::AbortedByCallback
        );
        assert!(host.dead, "multi->dead = TRUE");
        let entry = events.ev.get(FD).expect("the entry survives");
        assert!(entry.announced, "announced is set BEFORE rc is examined");
        assert_eq!(
            entry.action,
            PollAction::NONE,
            "action is NOT updated on the abort path"
        );
        assert!(!host.in_callback, "the guard still cleared the flag");
    }

    #[test]
    fn the_update_trace_concatenates_the_two_action_fragments() {
        const FD: Socket = 4;
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);

        // NONE -> INOUT: the previous action renders as the EMPTY STRING.
        host.set_want(1, &[(FD, PollAction::INOUT)]);
        let first = multi_trace(|tracer| {
            assert!(events.assess_xfer(&mut host, 1, Some(tracer)).is_ok());
        });
        assert!(
            first.contains("action '' -> 'INOUT' (1/1 r/w)"),
            "an empty previous action and a concatenated INOUT: {first}"
        );
        assert!(first.contains("ev update call(fd=4, ev=INOUT)"), "{first}");

        // INOUT -> IN renders exactly as the C's two `%s%s` pairs do.
        host.set_want(1, &[(FD, PollAction::IN)]);
        let second = multi_trace(|tracer| {
            assert!(events.assess_xfer(&mut host, 1, Some(tracer)).is_ok());
        });
        assert!(
            second.contains("action 'INOUT' -> 'IN' (1/0 r/w)"),
            "{second}"
        );
        assert!(second.contains("ev update call(fd=4, ev=IN)"), "{second}");
    }

    #[test]
    fn the_remove_trace_carries_the_callers_cause() {
        const FD: Socket = 5;
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(FD, PollAction::IN)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());

        host.set_want(1, &[]);
        let output = multi_trace(|tracer| {
            assert!(events.assess_xfer(&mut host, 1, Some(tracer)).is_ok());
        });
        assert!(
            output.contains("ev last user gone, call(fd=5, ev=REMOVE)"),
            "{output}"
        );

        // The other caller's cause, through `Curl_multi_will_close`.
        host.set_want(1, &[(FD, PollAction::IN)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        let closing = multi_trace(|tracer| {
            events.will_close(&mut host, 1, FD, Some(tracer));
        });
        assert!(closing.contains("Curl_multi_will_close fd=5"), "{closing}");
        assert!(
            closing.contains("ev socket done, call(fd=5, ev=REMOVE)"),
            "{closing}"
        );
        assert!(events.ev.get(FD).is_none());
    }

    #[test]
    fn a_connection_counts_as_one_user_beside_the_transfers() {
        const FD: Socket = 12;
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(FD, PollAction::IN)]);
        host.conn_want.insert(70, vec![(FD, PollAction::OUT)]);

        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        assert!(events.assess_conn(&mut host, 1, 70, None).is_ok());

        let entry = events.ev.get(FD).expect("known");
        assert_eq!(entry.readers, 1);
        assert_eq!(entry.writers, 1);
        assert_eq!(entry.user_count(), 2, "one transfer plus one connection");
        assert_eq!(entry.conn, Some(70));
        // The application was told IN and then INOUT.
        assert_eq!(host.calls().len(), 2);
        assert_eq!(host.calls()[1].what, PollAction::INOUT);

        // The connection goes away: the transfer still reads, so the socket
        // survives with only the write interest withdrawn.
        host.conn_want.insert(70, vec![]);
        assert!(events.assess_conn(&mut host, 1, 70, None).is_ok());
        let entry = events.ev.get(FD).expect("still known");
        assert_eq!(entry.conn, None);
        assert_eq!(entry.writers, 0);
        assert_eq!(host.calls().len(), 3);
        assert_eq!(host.calls()[2].what, PollAction::IN);
    }

    #[test]
    fn assign_needs_an_announced_socket_and_then_reaches_the_callback() {
        const FD: Socket = 21;
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);

        // "This will fail if this socket is not active."
        assert_eq!(
            events.assign(FD, CallbackData::from_bits(0xdead)),
            CURLMcode::BadSocket
        );

        host.set_want(1, &[(FD, PollAction::IN)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        assert_eq!(
            events.assign(FD, CallbackData::from_bits(0xdead)),
            CURLMcode::Ok
        );
        assert_eq!(host.calls()[0].socketp, CallbackData::NONE);

        // The next callback for that socket carries the assigned value.
        host.set_want(1, &[(FD, PollAction::INOUT)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        assert_eq!(
            host.calls()[1].socketp,
            CallbackData::from_bits(0xdead),
            "curl_multi_assign's value reaches the socket callback"
        );
        // The invalid socket is never a book-keeping key.
        assert_eq!(
            events.assign(CURL_SOCKET_BAD, CallbackData::NONE),
            CURLMcode::BadSocket
        );
    }

    #[test]
    fn dirty_xfers_queues_every_user_and_heals_stale_ones() {
        const FD: Socket = 31;
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1, 2]);
        host.set_want(1, &[(FD, PollAction::IN)]);
        host.set_want(2, &[(FD, PollAction::OUT)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        assert!(events.assess_xfer(&mut host, 2, None).is_ok());

        events.dirty_xfers(&mut host, FD, None);
        assert_eq!(host.dirty_marks, vec![1, 2]);

        // A transfer that has gone away is removed from the entry, with the
        // frozen trace, and does not stop the walk.
        host.dirty_marks.clear();
        host.xfers.remove(&2);
        let output = multi_trace(|tracer| {
            events.dirty_xfers(&mut host, FD, Some(tracer));
        });
        assert!(
            output.contains("socket transfer 2 no longer found"),
            "{output}"
        );
        assert_eq!(host.dirty_marks, vec![1]);
        assert!(!events.ev.get(FD).expect("known").xfer_known(2));

        // An unknown socket is ignored rather than reported.
        host.dirty_marks.clear();
        events.dirty_xfers(&mut host, 999, None);
        assert!(host.dirty_marks.is_empty());
    }

    #[test]
    fn a_registered_connection_makes_the_admin_handle_dirty() {
        const FD: Socket = 32;
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[ADMIN_MID, 1]);
        host.conn_want.insert(5, vec![(FD, PollAction::IN)]);
        assert!(events.assess_conn(&mut host, ADMIN_MID, 5, None).is_ok());

        events.dirty_xfers(&mut host, FD, None);
        assert_eq!(host.dirty_marks, vec![ADMIN_MID]);
    }

    #[test]
    fn a_transfer_leaving_the_multi_handle_releases_its_sockets() {
        const FD: Socket = 41;
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(FD, PollAction::IN)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());

        // A detached transfer reports no interest, which is exactly what makes
        // `xfer_done` release the socket.
        host.xfers.get_mut(&1).expect("present").has_conn = false;
        host.set_want(1, &[]);
        host.xfers.get_mut(&1).expect("present").has_conn = false;
        events.xfer_done(&mut host, 1, None);
        assert_eq!(
            host.calls().last().expect("a call").what,
            PollAction::REMOVE
        );
        assert!(events.ev.is_empty());
    }

    #[test]
    fn the_admin_handle_is_exempt_from_xfer_done() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[ADMIN_MID]);
        host.xfers.get_mut(&ADMIN_MID).expect("present").has_conn = false;
        events.xfer_done(&mut host, ADMIN_MID, None);
        assert!(host.calls().is_empty(), "if(data != multi->admin)");
    }

    #[test]
    fn assessing_a_set_stops_at_the_first_failure_but_skips_stale_mids() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1, 2, 3]);
        host.set_want(1, &[(51, PollAction::IN)]);
        host.set_want(2, &[(52, PollAction::IN)]);
        host.set_want(3, &[(53, PollAction::IN)]);
        host.xfers.remove(&2);

        assert!(events.assess_xfer_set(&mut host, &[1, 2, 3], None).is_ok());
        assert_eq!(host.calls().len(), 2, "the missing transfer is skipped");

        // Now make the callback refuse: the walk stops at the first failure.
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1, 2]);
        host.socket_cb_result = CALLBACK_ABORT;
        host.set_want(1, &[(54, PollAction::IN)]);
        host.set_want(2, &[(55, PollAction::IN)]);
        assert_eq!(
            events.assess_xfer_set(&mut host, &[1, 2], None),
            CURLMcode::AbortedByCallback
        );
        assert_eq!(host.calls().len(), 1);
    }

    // THE POLLSET STATE MACHINE

    #[test]
    fn every_state_decides_what_it_polls_for() {
        // The eight states that produce nothing, whatever the transfer wants.
        #[rustfmt::skip]
        let silent = [
            CurlMstate::Init, CurlMstate::Pending, CurlMstate::Setup,
            CurlMstate::Connect, CurlMstate::RateLimiting, CurlMstate::Done,
            CurlMstate::Completed, CurlMstate::MsgSent,
        ];
        #[rustfmt::skip]
        let polling = [
            CurlMstate::Resolving, CurlMstate::Connecting,
            CurlMstate::ProtoConnect, CurlMstate::ProtoConnecting,
            CurlMstate::Do, CurlMstate::Doing, CurlMstate::DoingMore,
            CurlMstate::Did, CurlMstate::Performing,
        ];
        assert_eq!(
            silent.len() + polling.len(),
            CurlMstate::COUNT,
            "every state is accounted for"
        );

        for state in silent {
            let mut host = TestHost::with_xfers(&[1]);
            host.set_want(1, &[(61, PollAction::IN)]);
            host.xfers.get_mut(&1).expect("present").state = Some(state);
            let mut ps = EasyPollset::new();
            assert_eq!(pollset(&mut host, 1, &mut ps, None), CURLMcode::Ok);
            assert!(ps.is_empty(), "{state:?} polls for nothing");
        }

        for state in polling {
            let mut host = TestHost::with_xfers(&[1]);
            host.set_want(1, &[(61, PollAction::IN)]);
            host.xfers.get_mut(&1).expect("present").state = Some(state);
            let mut ps = EasyPollset::new();
            assert_eq!(pollset(&mut host, 1, &mut ps, None), CURLMcode::Ok);
            assert_eq!(ps.len(), 1, "{state:?} asks its layer what to poll");
            assert_eq!(ps.action_of(61), PollAction::IN);
        }
    }

    #[test]
    fn a_transfer_with_no_connection_polls_for_nothing_in_every_state() {
        for raw in 0..CurlMstate::COUNT {
            let state = CurlMstate::from_i32(raw as i32).expect("a real state");
            let mut host = TestHost::with_xfers(&[1]);
            host.set_want(1, &[(62, PollAction::INOUT)]);
            let xfer = host.xfers.get_mut(&1).expect("present");
            xfer.state = Some(state);
            xfer.has_conn = false;
            let mut ps = EasyPollset::new();
            // Something stale in the pollset must be cleared even so: the
            // reset comes BEFORE the early return.
            ps.add_in(63, None).expect("a valid descriptor");
            assert_eq!(pollset(&mut host, 1, &mut ps, None), CURLMcode::Ok);
            assert!(ps.is_empty(), "reset runs before the early return");
        }
    }

    #[test]
    fn a_pollset_failure_maps_as_the_c_maps_it() {
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(64, PollAction::IN)]);
        host.pollset_error = Some(CURLcode::OutOfMemory);
        let mut ps = EasyPollset::new();
        assert_eq!(
            pollset(&mut host, 1, &mut ps, None),
            CURLMcode::OutOfMemory
        );

        host.pollset_error = Some(CURLcode::BadFunctionArgument);
        let output = multi_trace(|tracer| {
            assert_eq!(
                pollset(&mut host, 1, &mut ps, Some(tracer)),
                CURLMcode::InternalError
            );
        });
        assert!(
            output.contains("error determining pollset: 43"),
            "the frozen failf text with CURLE_BAD_FUNCTION_ARGUMENT: {output}"
        );
    }

    // THE DESCRIPTOR-SET SURFACES

    #[test]
    fn fdset_reports_the_pairs_and_the_maximum() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1, 2]);
        host.set_want(1, &[(3, PollAction::IN)]);
        host.set_want(2, &[(9, PollAction::OUT)]);
        host.cshutdn = vec![(11, PollAction::IN)];

        let fdset = events.fdset(&mut host, 1024, None);
        assert_eq!(
            fdset.sockets,
            vec![
                (3, PollAction::IN),
                (9, PollAction::OUT),
                (11, PollAction::IN)
            ],
            "the shutdown pool's descriptors participate too"
        );
        assert_eq!(fdset.max_fd, 11);
    }

    #[test]
    fn fdset_reports_minus_one_when_there_is_nothing_to_watch() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::default();
        let fdset = events.fdset(&mut host, 1024, None);
        assert!(fdset.sockets.is_empty());
        assert_eq!(fdset.max_fd, -1, "this_max_fd starts at -1");
    }

    #[test]
    fn fdset_pretends_a_descriptor_outside_the_set_does_not_exist() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1, 2]);
        host.set_want(1, &[(1024, PollAction::IN)]);
        host.set_want(2, &[(5, PollAction::IN)]);

        let fdset = events.fdset(&mut host, 1024, None);
        assert_eq!(fdset.sockets, vec![(5, PollAction::IN)]);
        assert_eq!(
            fdset.max_fd, 5,
            "the skipped descriptor does not raise the maximum either"
        );
    }

    #[test]
    fn fdset_skips_a_stale_mid_without_removing_it() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1, 2]);
        host.set_want(1, &[(6, PollAction::IN)]);
        host.set_want(2, &[(7, PollAction::IN)]);
        host.xfers.remove(&1);

        let fdset = events.fdset(&mut host, 1024, None);
        assert_eq!(fdset.sockets, vec![(7, PollAction::IN)]);
        assert!(
            host.forgotten.is_empty(),
            "curl_multi_fdset is a query: it heals nothing"
        );
        assert_eq!(host.process.len(), 2);
    }

    #[test]
    fn waitfds_validates_its_arguments_before_anything_else() {
        // `if(!ufds && (size || !fd_count))`: the predicate the shim must
        // consult BEFORE its own handle check.
        assert!(!MultiEvents::waitfds_args_ok(false, 1, true));
        assert!(!MultiEvents::waitfds_args_ok(false, 0, false));
        assert!(MultiEvents::waitfds_args_ok(false, 0, true));
        assert!(MultiEvents::waitfds_args_ok(true, 0, true));
        assert!(MultiEvents::waitfds_args_ok(true, 4, false));

        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::default();
        let mut count = 0;
        assert_eq!(
            events.waitfds(&mut host, None, 1, Some(&mut count), None),
            CURLMcode::BadFunctionArgument,
            "a null array with a non-zero size"
        );
        assert_eq!(
            events.waitfds(&mut host, None, 0, None, None),
            CURLMcode::BadFunctionArgument,
            "nowhere at all to report"
        );
    }

    #[test]
    fn waitfds_counts_without_a_store_and_fills_with_one() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1, 2]);
        host.set_want(1, &[(3, PollAction::IN)]);
        host.set_want(2, &[(4, PollAction::OUT)]);
        host.cshutdn = vec![(5, PollAction::IN)];

        // "Passing zero size allows to get just a number of fds."
        let mut count = 0;
        assert_eq!(
            events.waitfds(&mut host, None, 0, Some(&mut count), None),
            CURLMcode::Ok
        );
        assert_eq!(count, 3);

        let mut store = vec![CurlWaitFd::default(); 3];
        let mut count = 0;
        assert_eq!(
            events.waitfds(
                &mut host,
                Some(&mut store),
                3,
                Some(&mut count),
                None
            ),
            CURLMcode::Ok
        );
        assert_eq!(count, 3);
        assert_eq!(store[0].fd, 3);
        assert_eq!(store[0].events, CURL_WAIT_POLLIN);
        assert_eq!(store[1].fd, 4);
        assert_eq!(store[1].events, CURL_WAIT_POLLOUT);
        assert_eq!(store[2].fd, 5);
    }

    #[test]
    fn a_too_small_waitfds_array_reports_out_of_memory_and_still_counts() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1, 2]);
        host.set_want(1, &[(3, PollAction::IN)]);
        host.set_want(2, &[(4, PollAction::IN)]);

        let mut store = vec![CurlWaitFd::default(); 1];
        let mut count = 0;
        assert_eq!(
            events.waitfds(
                &mut host,
                Some(&mut store),
                1,
                Some(&mut count),
                None
            ),
            CURLMcode::OutOfMemory,
            "the code C reports for an undersized array"
        );
        assert_eq!(count, 2, "*fd_count is written on the failure path too");
    }

    #[test]
    fn waitfds_heals_a_stale_mid_out_of_both_sets() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1, 2]);
        host.set_want(1, &[(3, PollAction::IN)]);
        host.set_want(2, &[(4, PollAction::IN)]);
        host.xfers.remove(&1);

        let mut count = 0;
        assert_eq!(
            events.waitfds(&mut host, None, 0, Some(&mut count), None),
            CURLMcode::Ok
        );
        assert_eq!(count, 1);
        assert_eq!(
            host.forgotten,
            vec![1],
            "removed from process AND dirty, unlike curl_multi_fdset"
        );
    }

    // THE WAIT

    #[tokio::test(start_paused = true)]
    async fn a_negative_timeout_is_a_bad_argument() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::default();
        assert_eq!(
            events.wait(&mut host, &mut [], -1, None, None).await,
            CURLMcode::BadFunctionArgument
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_refuses_to_run_inside_a_callback() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost {
            in_callback: true,
            ..TestHost::default()
        };
        assert_eq!(
            events.wait(&mut host, &mut [], 0, None, None).await,
            CURLMcode::RecursiveApiCall
        );
    }

    /// Captures what a wait writes to the trace log.
    ///
    /// Written out rather than routed through [`multi_trace`] because the body
    /// has to `await`, which a synchronous closure cannot; reaching for a
    /// blocking executor inside the single-threaded runtime `#[tokio::test]`
    /// provides would deadlock instead.
    async fn traced_wait(
        events: &mut MultiEvents,
        host: &mut TestHost,
        timeout_ms: i32,
        ret: Option<&mut i32>,
    ) -> (CURLMcode, String) {
        let mut config = TraceConfig::new();
        config.apply(Some(b"multi")).expect("a known feature name");
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let outcome = {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            events
                .wait(host, &mut [], timeout_ms, ret, Some(&mut tracer))
                .await
        };
        let text =
            String::from_utf8(sink.into_inner()).expect("trace output is text");
        (outcome, text)
    }

    /// Ignored under Miri because it is the one test here that hands a VALID
    /// descriptor to the wait, and registering one reaches the runtime's
    /// readiness machinery -- "unsupported operation: I/O readiness watching
    /// not supported for epoll", raised inside `mio` rather than by anything
    /// this crate wrote. Every other wait test above passes either no
    /// descriptor or `CURL_SOCKET_BAD`, which
    /// [`poll_sockets`](crate::conn::select::poll_sockets) short-circuits into
    /// a pure timer wait, so they interpret cleanly; this one cannot, because
    /// the frozen `fds=1` in the trace line it asserts on is precisely the
    /// count of registered descriptors.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(
        miri,
        ignore = "registering a descriptor needs epoll, which Miri does not implement"
    )]
    async fn the_internal_timeout_wins_only_when_it_is_shorter() {
        let (mut events, _clock) = events_at(1_000);
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(3, PollAction::IN)]);

        // A timer 20 ms away against a caller asking for 500 ms.
        let mut level_one = ExpireTimers::new();
        events.expire(&mut level_one, 1, 20, ExpireId::Timeout, None);
        *host.expire_timers_mut(1).expect("present") = level_one;

        let mut ready = -1;
        let (outcome, output) =
            traced_wait(&mut events, &mut host, 500, Some(&mut ready)).await;
        assert_eq!(outcome, CURLMcode::Ok);
        assert!(
            output.contains("tinternal=20"),
            "the internal timeout is reported: {output}"
        );
        assert!(
            output.contains("multi_wait(fds=1, timeout=20)"),
            "and it is the shorter one that is used: {output}"
        );

        // The caller's own timeout survives when it is the shorter of the two.
        let (outcome, output) =
            traced_wait(&mut events, &mut host, 5, None).await;
        assert_eq!(outcome, CURLMcode::Ok);
        assert!(
            output.contains("multi_wait(fds=1, timeout=5) tinternal=20"),
            "{output}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_trace_is_silent_when_no_transfer_was_seen() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::default();
        let (outcome, output) =
            traced_wait(&mut events, &mut host, 0, None).await;
        assert_eq!(outcome, CURLMcode::Ok);
        assert!(
            output.is_empty(),
            "C emits the line only `if(data)`: {output}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_reports_the_callers_descriptors_back() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::default();
        let mut extra = vec![CurlWaitFd {
            fd: -1,
            events: CURL_WAIT_POLLIN | CURL_WAIT_POLLPRI,
            revents: 0x7f,
        }];
        let mut ready = -1;
        assert_eq!(
            events
                .wait(&mut host, &mut extra, 5, Some(&mut ready), None)
                .await,
            CURLMcode::Ok
        );
        assert_eq!(ready, 0, "an invalid descriptor is never ready");
        assert_eq!(
            extra[0].revents, 0,
            "revents is always written, in the public vocabulary"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn poll_returns_at_once_when_the_wakeup_has_been_signalled() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::default();
        let wakeup = events.wakeup_handle();

        // The signal arrives before the wait, exactly as a byte already in
        // C's self-pipe would.
        wakeup.signal();
        let mut ready = -1;
        // A long timeout: reaching the assertion at all proves the wait did
        // not sit it out. The runtime is paused, so a real sleep would be
        // auto-advanced rather than waited out, which is why the count is what
        // this asserts on.
        assert_eq!(
            events
                .poll(&mut host, &mut [], 60_000, Some(&mut ready), None)
                .await,
            CURLMcode::Ok
        );
        assert_eq!(
            ready, 0,
            "the wakeup is not counted into the returned value"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_wakeup_handle_travels_between_threads() {
        let (events, _clock) = events_at(1);
        let wakeup = events.wakeup_handle();
        // `Send + Sync + 'static` is the whole point: this is the one entry
        // point another thread may reach while the reactor holds `&mut`.
        let handle = std::thread::spawn(move || {
            wakeup.signal();
        });
        handle.join().expect("the signalling thread");
        assert_eq!(events.wakeup(), CURLMcode::Ok);
    }

    #[tokio::test(start_paused = true)]
    async fn extrawait_sleeps_the_callers_timeout_when_there_is_no_timer() {
        // No descriptors and no wakeup: `extrawait` over an empty tree, whose
        // internal timeout is -1, sleeps for the caller's own timeout instead.
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::default();
        let slept_at_least = tokio::time::timeout(
            Duration::from_millis(249),
            events.multi_wait(&mut host, &mut [], 250, None, true, false, None),
        )
        .await;
        assert!(
            slept_at_least.is_err(),
            "a -1 internal timeout is replaced by the caller's 250 ms"
        );

        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::default();
        let finished = tokio::time::timeout(
            Duration::from_millis(251),
            events.multi_wait(&mut host, &mut [], 250, None, true, false, None),
        )
        .await;
        assert_eq!(
            finished.expect("the wait finishes within 251 ms"),
            CURLMcode::Ok,
            "and not for any longer than that"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn extrawait_does_not_sleep_at_all_when_something_is_already_due() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);
        // A dirty transfer makes the internal timeout zero, and `if(sleep_ms)`
        // then skips the sleep entirely -- zero does NOT mean "sleep zero".
        host.has_dirties = true;
        let finished = tokio::time::timeout(
            Duration::ZERO,
            events.multi_wait(&mut host, &mut [], 250, None, true, false, None),
        )
        .await;
        assert_eq!(
            finished.expect("no timer is ever armed"),
            CURLMcode::Ok,
            "sleep_ms == 0 sleeps not at all"
        );
    }

    // THE TWO-LEVEL TIMER

    #[test]
    fn one_timer_per_handle_and_identifier() {
        let (mut events, _clock) = events_at(10);
        let mut timers = ExpireTimers::new();

        events.expire(&mut timers, 1, 100, ExpireId::Timeout, None);
        assert_eq!(timers.count(), 1);
        assert_eq!(events.timers.timetree.len(), 1);

        // The same identifier again REPLACES rather than duplicates.
        events.expire(&mut timers, 1, 50, ExpireId::Timeout, None);
        assert_eq!(timers.count(), 1, "at most one timer per (handle, id)");
        assert_eq!(
            timers.nearest(),
            Some((ExpireId::Timeout, CurlTime::new(10, 50_000)))
        );

        // A second identifier is a second timer, and the nearest wins.
        events.expire(&mut timers, 1, 10, ExpireId::ConnectTimeout, None);
        assert_eq!(timers.count(), 2);
        assert_eq!(
            timers.nearest(),
            Some((ExpireId::ConnectTimeout, CurlTime::new(10, 10_000)))
        );
        assert_eq!(
            events.timers.timetree.len(),
            1,
            "the tree holds one node per HANDLE, not per timer"
        );
    }

    #[test]
    fn timers_due_at_the_same_instant_fire_in_the_order_they_were_set() {
        let (mut events, _clock) = events_at(10);
        let mut timers = ExpireTimers::new();

        // Two identifiers, one instant. The tie-break is arrival order, which
        // is what C's insertion scan produces.
        events.expire(&mut timers, 1, 100, ExpireId::TooFast, None);
        events.expire(&mut timers, 1, 100, ExpireId::SpeedCheck, None);
        assert_eq!(
            timers.nearest().expect("a pending timer").0,
            ExpireId::TooFast,
            "FIFO among equal instants"
        );

        // Draining takes them in that order.
        let due = CurlTime::new(10, 100_000);
        timers.clear_one(ExpireId::TooFast);
        assert_eq!(
            timers.nearest(),
            Some((ExpireId::SpeedCheck, due)),
            "and the later arrival is next"
        );
    }

    /// The millisecond granularity of the insertion comparison, asymmetry and
    /// all -- `lib/multi.c:3506-3524` against `:3007`.
    #[test]
    fn two_timers_inside_one_millisecond_keep_the_order_they_were_set() {
        let (mut events, _clock) = events_at(10);
        let mut timers = ExpireTimers::new();

        // `expire` takes whole milliseconds, so the sub-millisecond case is
        // built by writing the slots directly -- which is what
        // `multi_addtimeout` does to `data->state.expires[eid]`.
        let later = CurlTime::new(10, 1_500);
        let sooner = CurlTime::new(10, 900);
        timers.set(ExpireId::TooFast, later);
        timers.set(ExpireId::SpeedCheck, sooner);

        // `curlx_ptimediff_ms(later, sooner)` is 0, so the insertion scan walks
        // PAST the entry already there and the first-set timer keeps the head,
        // even though the second is due 600us earlier. C behaves this way and
        // the asymmetry is deliberate here: comparing at microsecond
        // granularity would report `SpeedCheck`, which is a different answer
        // to `curl_multi_timeout` than curl 8.19.0-DEV gives.
        assert_eq!(
            timers.nearest(),
            Some((ExpireId::TooFast, later)),
            "equal to the millisecond means FIFO, not nearest microsecond"
        );

        // A whole millisecond apart is a different matter: the comparison then
        // has something to see and the earlier instant wins regardless of
        // arrival order.
        let mut timers = ExpireTimers::new();
        timers.set(ExpireId::TooFast, CurlTime::new(10, 3_000));
        timers.set(ExpireId::SpeedCheck, CurlTime::new(10, 1_000));
        assert_eq!(
            timers.nearest(),
            Some((ExpireId::SpeedCheck, CurlTime::new(10, 1_000))),
            "2ms earlier, so the scan breaks before the first entry"
        );

        // And the drain still measures in MICROSECONDS (`:3007`), so a timer
        // 900us into the future is not yet due even though it rounds to 0ms.
        let mut timers = ExpireTimers::new();
        timers.set(ExpireId::Timeout, CurlTime::new(10, 900));
        events.add_next_timeout(&mut timers, 1, CurlTime::new(10, 0));
        assert_eq!(
            timers.count(),
            1,
            "timediff_us(900us, 0) > 0, so nothing is drained"
        );
        events.add_next_timeout(&mut timers, 1, CurlTime::new(10, 900));
        assert_eq!(timers.count(), 0, "at the instant itself it is due");
    }

    #[test]
    fn a_later_expiry_does_not_move_the_tree_entry() {
        let (mut events, _clock) = events_at(10);
        let mut timers = ExpireTimers::new();

        events.expire(&mut timers, 1, 50, ExpireId::Timeout, None);
        let registered = timers.expiretime.expect("registered");
        let node = timers.timenode.expect("a tree node");

        // A LATER instant: `if(diff > 0) return;` -- the tree is untouched.
        events.expire(&mut timers, 1, 500, ExpireId::ConnectTimeout, None);
        assert_eq!(timers.expiretime, Some(registered));
        assert_eq!(timers.timenode, Some(node), "the same node, not a new one");
        assert_eq!(events.timers.timetree.len(), 1);

        // An EQUAL instant falls through and re-inserts: `diff == 0` is not
        // `> 0`.
        events.expire(&mut timers, 1, 50, ExpireId::Quic, None);
        assert_eq!(timers.expiretime, Some(registered));
        assert_ne!(
            timers.timenode,
            Some(node),
            "an equal instant re-inserts, so the node identity changes"
        );
        assert_eq!(events.timers.timetree.len(), 1, "and does not accumulate");

        // An EARLIER instant also re-inserts, at the new instant.
        events.expire(&mut timers, 1, 10, ExpireId::TooFast, None);
        assert_eq!(timers.expiretime, Some(CurlTime::new(10, 10_000)));
        assert_eq!(events.timers.timetree.len(), 1);
    }

    #[test]
    fn expire_done_forgets_the_timer_and_leaves_the_tree_alone() {
        let (mut events, _clock) = events_at(10);
        let mut timers = ExpireTimers::new();
        events.expire(&mut timers, 1, 50, ExpireId::Timeout, None);
        let node = timers.timenode;

        let output = timer_trace(|tracer| {
            expire_done(&mut timers, ExpireId::Timeout, Some(tracer));
        });
        assert_eq!(output, "* [TIMER] [TIMEOUT] cleared\n");
        assert!(timers.is_empty(), "the level-one entry is gone");
        assert_eq!(timers.timenode, node, "the tree entry is untouched");
        assert_eq!(events.timers.timetree.len(), 1);
        assert!(timers.is_registered(), "and so is `expiretime`");
    }

    #[test]
    fn expire_clear_removes_everything() {
        let (mut events, _clock) = events_at(10);
        let mut timers = ExpireTimers::new();
        events.expire(&mut timers, 1, 50, ExpireId::Timeout, None);
        events.expire(&mut timers, 1, 60, ExpireId::Quic, None);

        let output = multi_trace(|tracer| {
            events.expire_clear(&mut timers, true, Some(tracer));
        });
        assert_eq!(output, "* [MULTI] [TIMEOUT] all cleared\n");
        assert!(timers.is_empty());
        assert!(!timers.is_registered());
        assert_eq!(timers.timenode, None);
        assert!(events.timers.timetree.is_empty());

        // A second clear is a no-op: `if(nowp->tv_sec || nowp->tv_usec)`.
        let output = multi_trace(|tracer| {
            events.expire_clear(&mut timers, true, Some(tracer));
        });
        assert!(output.is_empty());
    }

    #[test]
    fn expire_clear_is_silent_for_a_transfer_without_an_identifier() {
        let (mut events, _clock) = events_at(10);
        let mut timers = ExpireTimers::new();
        events.expire(&mut timers, 1, 50, ExpireId::Timeout, None);
        // `if(data->id >= 0)` -- and `data->id` is NOT `data->mid`.
        let output = multi_trace(|tracer| {
            events.expire_clear(&mut timers, false, Some(tracer));
        });
        assert!(output.is_empty(), "the line is gated on data->id: {output}");
        assert!(timers.is_empty(), "but the clearing still happened");
    }

    #[test]
    fn the_set_trace_reports_microseconds_under_a_nanosecond_label() {
        let (mut events, _clock) = events_at(10);
        let mut timers = ExpireTimers::new();
        // 250 ms is 250,000 microseconds. The label says `ns`; that is an
        // upstream defect in a frozen string and it is reproduced verbatim.
        let output = timer_trace(|tracer| {
            events.expire(&mut timers, 1, 250, ExpireId::Timeout, Some(tracer));
        });
        assert_eq!(output, "* [TIMER] [TIMEOUT] set for 250000ns\n");
    }

    #[test]
    fn the_expiry_instant_is_computed_field_wise() {
        let (mut events, _clock) = events_at(10);
        let mut timers = ExpireTimers::new();
        // 1,500 ms from 10.000000 is 11.500000: the seconds and the
        // microseconds move separately and the carry is explicit.
        events.expire(&mut timers, 1, 1_500, ExpireId::Timeout, None);
        assert_eq!(timers.expiretime, Some(CurlTime::new(11, 500_000)));

        // And a sub-second delay that carries.
        let clock = Arc::new(TestClock::new(CurlTime::new(10, 900_000)));
        let mut events = MultiEvents::new(clock);
        let mut timers = ExpireTimers::new();
        events.expire(&mut timers, 1, 200, ExpireId::Timeout, None);
        assert_eq!(timers.expiretime, Some(CurlTime::new(11, 100_000)));
    }

    #[test]
    fn an_expired_handle_is_queued_and_its_next_timer_re_registered() {
        let (mut events, clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        let mut timers = ExpireTimers::new();
        events.expire(&mut timers, 1, 10, ExpireId::ConnectTimeout, None);
        events.expire(&mut timers, 1, 40, ExpireId::Timeout, None);
        *host.expire_timers_mut(1).expect("present") = timers;

        // Nothing is due yet.
        clock.advance(Duration::from_millis(5));
        events.mark_expired_as_dirty(&mut host, clock.now(), None);
        assert!(host.dirty_marks.is_empty());
        assert_eq!(events.timers.timetree.len(), 1);

        // The first timer comes due EXACTLY, which `diff <= 0` includes.
        clock.advance(Duration::from_millis(5));
        let output = timer_trace(|tracer| {
            events.mark_expired_as_dirty(&mut host, clock.now(), Some(tracer));
        });
        assert!(
            output.contains("[CONNECTTIMEOUT] has expired"),
            "the head timer is named: {output}"
        );
        assert_eq!(host.dirty_marks, vec![1]);
        let level_one = host.expire_timers(1).expect("present");
        assert_eq!(
            level_one.nearest(),
            Some((ExpireId::Timeout, CurlTime::new(10, 40_000))),
            "the drained entry is gone and the next one remains"
        );
        assert_eq!(
            level_one.expiretime,
            Some(CurlTime::new(10, 40_000)),
            "and the handle is re-registered under it"
        );
        assert_eq!(events.timers.timetree.len(), 1);

        // The second timer, and then the tree empties.
        clock.advance(Duration::from_millis(30));
        events.mark_expired_as_dirty(&mut host, clock.now(), None);
        assert_eq!(host.dirty_marks, vec![1, 1]);
        let level_one = host.expire_timers(1).expect("present");
        assert!(level_one.is_empty());
        assert!(!level_one.is_registered());
        assert!(events.timers.timetree.is_empty());
    }

    #[test]
    fn a_handle_that_has_gone_away_is_skipped_rather_than_ending_the_loop() {
        let (mut events, clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1, 2]);
        for mid in [1_u32, 2_u32] {
            let mut timers = ExpireTimers::new();
            events.expire(&mut timers, mid, 10, ExpireId::Timeout, None);
            *host.expire_timers_mut(mid).expect("present") = timers;
        }
        assert_eq!(events.timers.timetree.len(), 2);
        host.xfers.remove(&1);

        clock.advance(Duration::from_millis(10));
        events.mark_expired_as_dirty(&mut host, clock.now(), None);
        assert_eq!(
            host.dirty_marks,
            vec![2],
            "the survivor is still queued, so the loop continued"
        );
        assert!(events.timers.timetree.is_empty());
    }

    // MULTI_TIMEOUT

    #[test]
    fn multi_timeout_answers_minus_one_for_an_empty_tree() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::default();
        let (expire_time, timeout_ms) = events.timeout(&mut host, None);
        assert_eq!(timeout_ms, -1, "no timeout at all");
        assert_eq!(expire_time, CurlTime::ZERO);
    }

    #[test]
    fn multi_timeout_answers_zero_for_a_dead_handle_or_a_dirty_transfer() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        let mut timers = ExpireTimers::new();
        events.expire(&mut timers, 1, 5_000, ExpireId::Timeout, None);
        *host.expire_timers_mut(1).expect("present") = timers;

        host.dead = true;
        assert_eq!(events.timeout(&mut host, None).1, 0, "a dead handle");

        host.dead = false;
        host.has_dirties = true;
        assert_eq!(
            events.timeout(&mut host, None).1,
            0,
            "anything queued to run"
        );
    }

    #[test]
    fn multi_timeout_rounds_the_remaining_span_up() {
        let (mut events, clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        let mut timers = ExpireTimers::new();
        events.expire(&mut timers, 1, 100, ExpireId::Timeout, None);
        *host.expire_timers_mut(1).expect("present") = timers;

        assert_eq!(events.timeout(&mut host, None).1, 100);

        // 999 microseconds left rounds UP to 1 millisecond, which is what
        // `curlx_timediff_ceil_ms` is for: a caller told 0 would spin.
        clock.advance(Duration::from_micros(99_001));
        let (expire_time, timeout_ms) = events.timeout(&mut host, None);
        assert_eq!(timeout_ms, 1);
        assert_eq!(expire_time, CurlTime::new(10, 100_000));

        // Exactly due answers 0, and the comparison is at microsecond
        // resolution.
        clock.advance(Duration::from_micros(999));
        assert_eq!(events.timeout(&mut host, None).1, 0);
    }

    #[test]
    fn multi_timeout_names_the_timer_that_produced_the_answer() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        let mut timers = ExpireTimers::new();
        events.expire(&mut timers, 1, 70, ExpireId::HappyEyeballs, None);
        *host.expire_timers_mut(1).expect("present") = timers;

        let output = timer_trace(|tracer| {
            assert_eq!(events.timeout(&mut host, Some(tracer)).1, 70);
        });
        assert_eq!(
            output,
            "* [TIMER] [HAPPY_EYEBALLS] gives multi timeout in 70ms\n"
        );
    }

    #[test]
    fn the_application_facing_timeout_refuses_a_callback_context() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::default();
        let mut milliseconds = 12_345;
        host.in_callback = true;
        assert_eq!(
            events.app_timeout(&mut host, &mut milliseconds, None),
            CURLMcode::RecursiveApiCall
        );
        assert_eq!(milliseconds, 12_345, "and writes nothing");

        host.in_callback = false;
        assert_eq!(
            events.app_timeout(&mut host, &mut milliseconds, None),
            CURLMcode::Ok
        );
        assert_eq!(milliseconds, -1);
    }

    #[test]
    fn the_timeout_as_a_duration_distinguishes_never_from_immediately() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);

        // An empty tree is "no timeout", which must NOT become zero.
        assert_eq!(events.timeout_duration(&mut host, None), None);

        host.has_dirties = true;
        assert_eq!(
            events.timeout_duration(&mut host, None),
            Some(Duration::ZERO),
            "and something already due must not become `None`"
        );
    }

    // THE TIMER CALLBACK

    /// Arms one handle so that [`MultiEvents::timeout`] answers `milli`.
    fn arm(
        events: &mut MultiEvents,
        host: &mut TestHost,
        mid: u32,
        milli: TimeDiff,
    ) {
        let mut timers = *host.expire_timers(mid).expect("present");
        events.expire(&mut timers, mid, milli, ExpireId::Timeout, None);
        *host.expire_timers_mut(mid).expect("present") = timers;
    }

    #[test]
    fn update_timer_says_nothing_when_there_was_and_is_no_timeout() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::default();
        let output = multi_trace(|tracer| {
            assert!(events.update_timer(&mut host, Some(tracer)).is_ok());
        });
        assert!(output.is_empty(), "branch 1 is silent: {output}");
        assert!(host.timer_calls.is_empty(), "and calls nothing");
    }

    #[test]
    fn update_timer_reports_a_first_timeout_then_a_replacement_then_a_clear() {
        let (mut events, clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);

        // Branch 3: a timeout now, none before.
        arm(&mut events, &mut host, 1, 200);
        let output = multi_trace(|tracer| {
            assert!(events.update_timer(&mut host, Some(tracer)).is_ok());
        });
        assert_eq!(output, "* [MULTI] [TIMER] set 200ms, none before\n");
        assert_eq!(host.timer_calls, vec![200]);
        assert_eq!(host.guard_seen, vec![true], "inside the recursion guard");

        // Branch 5: the same instant. The relative value has changed, because
        // time moved, and the application is still NOT called.
        clock.advance(Duration::from_millis(50));
        let output = multi_trace(|tracer| {
            assert!(events.update_timer(&mut host, Some(tracer)).is_ok());
        });
        assert!(output.is_empty(), "branch 5 is silent: {output}");
        assert_eq!(host.timer_calls, vec![200], "and calls nothing");

        // Branch 4: a different instant.
        arm(&mut events, &mut host, 1, 10);
        let output = multi_trace(|tracer| {
            assert!(events.update_timer(&mut host, Some(tracer)).is_ok());
        });
        assert_eq!(output, "* [MULTI] [TIMER] set 10ms, replace previous\n");
        assert_eq!(host.timer_calls, vec![200, 10]);

        // Branch 2: the timeout goes away.
        let mut timers = *host.expire_timers(1).expect("present");
        events.expire_clear(&mut timers, true, None);
        *host.expire_timers_mut(1).expect("present") = timers;
        let output = multi_trace(|tracer| {
            assert!(events.update_timer(&mut host, Some(tracer)).is_ok());
        });
        assert_eq!(output, "* [MULTI] [TIMER] clear\n");
        assert_eq!(host.timer_calls, vec![200, 10, -1], "normalised to -1");

        // Branch 1 again: nothing now and nothing before.
        let output = multi_trace(|tracer| {
            assert!(events.update_timer(&mut host, Some(tracer)).is_ok());
        });
        assert!(output.is_empty());
        assert_eq!(host.timer_calls.len(), 3);
    }

    #[test]
    fn update_timer_does_nothing_without_a_callback_or_for_a_dead_handle() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        arm(&mut events, &mut host, 1, 200);

        host.timer_cb = false;
        assert!(events.update_timer(&mut host, None).is_ok());
        assert!(host.timer_calls.is_empty());

        host.timer_cb = true;
        host.dead = true;
        assert!(events.update_timer(&mut host, None).is_ok());
        assert!(host.timer_calls.is_empty());
    }

    #[test]
    fn a_refusing_timer_callback_kills_the_multi_handle() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.timer_cb_result = CALLBACK_ABORT;
        arm(&mut events, &mut host, 1, 30);

        assert_eq!(
            events.update_timer(&mut host, None),
            CURLMcode::AbortedByCallback
        );
        assert!(host.dead);
        assert!(!host.in_callback, "the guard cleared the flag anyway");
    }

    // THE SOCKET ENTRY POINTS

    #[test]
    fn the_socket_entry_points_refuse_a_callback_context() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost {
            in_callback: true,
            ..TestHost::default()
        };

        assert_eq!(
            events.socket_action(&mut host, 3, 0, None, None),
            CURLMcode::RecursiveApiCall
        );
        assert_eq!(
            events.socket(&mut host, 3, None, None),
            CURLMcode::RecursiveApiCall
        );
        assert_eq!(
            events.socket_all(&mut host, None, None),
            CURLMcode::RecursiveApiCall
        );

        // And a notification dispatch counts too.
        host.in_callback = false;
        host.in_ntfy_callback = true;
        assert_eq!(
            events.socket_action(&mut host, 3, 0, None, None),
            CURLMcode::RecursiveApiCall
        );
    }

    #[test]
    fn a_timeout_driven_call_forces_the_application_timer_to_be_re_armed() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        arm(&mut events, &mut host, 1, 5_000);

        // The first call reports the timeout.
        assert!(events.socket_action(&mut host, 3, 0, None, None).is_ok());
        assert_eq!(host.timer_calls, vec![5_000]);

        // A second call for a real socket sees the same instant and stays
        // silent -- branch 5.
        assert!(events.socket_action(&mut host, 3, 0, None, None).is_ok());
        assert_eq!(host.timer_calls, vec![5_000]);

        // A call for CURL_SOCKET_TIMEOUT zeroes `last_expire_ts`, which forces
        // branch 4 even though the timeout has not changed.
        assert!(events
            .socket_action(&mut host, CURL_SOCKET_TIMEOUT, 0, None, None)
            .is_ok());
        assert_eq!(
            host.timer_calls,
            vec![5_000, 5_000],
            "the application is told again"
        );
    }

    #[test]
    fn a_socket_action_runs_the_dirty_set_once_more_when_something_ran() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.run_dirty_results = vec![(CURLMcode::Ok, 2), (CURLMcode::Ok, 1)];

        assert!(events.socket_action(&mut host, 3, 0, None, None).is_ok());
        assert_eq!(
            host.run_dirty_calls, 2,
            "exactly twice -- once more, not in a loop"
        );

        // Nothing ran: one pass only.
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.run_dirty_results = vec![(CURLMcode::Ok, 0)];
        assert!(events.socket_action(&mut host, 3, 0, None, None).is_ok());
        assert_eq!(host.run_dirty_calls, 1);

        // A failure stops the second pass.
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.run_dirty_results = vec![(CURLMcode::InternalError, 3)];
        assert_eq!(
            events.socket_action(&mut host, 3, 0, None, None),
            CURLMcode::InternalError
        );
        assert_eq!(host.run_dirty_calls, 1);
    }

    #[test]
    fn a_socket_action_finishes_with_the_tail_every_time() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.changed = true;
        host.notify_entries = true;
        host.running = 4;
        let mut running = -1;

        assert!(events
            .socket_action(&mut host, 3, 0, Some(&mut running), None)
            .is_ok());
        assert_eq!(host.pending_promotions, 1, "recheckstate was consumed");
        assert!(!host.changed, "and cleared");
        assert_eq!(host.notify_dispatches, 1);
        assert_eq!(running, 4);
    }

    #[test]
    fn a_notification_failure_is_reported_and_stops_the_timer_update() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.notify_entries = true;
        host.notify_result = CURLMcode::OutOfMemory;
        arm(&mut events, &mut host, 1, 100);

        assert_eq!(
            events.socket_action(&mut host, 3, 0, None, None),
            CURLMcode::OutOfMemory
        );
        assert!(
            host.timer_calls.is_empty(),
            "`if(CURLM_OK >= mresult)` gates the timer update"
        );
    }

    #[test]
    fn socket_all_takes_the_checkall_path() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(3, PollAction::IN)]);
        let mut running = -1;
        host.running = 1;

        assert!(events
            .socket_all(&mut host, Some(&mut running), None)
            .is_ok());
        assert_eq!(host.perform_calls, 1);
        assert_eq!(
            host.run_dirty_calls, 0,
            "the checkall path does not run the dirty set itself"
        );
        assert_eq!(
            host.calls().len(),
            1,
            "every active transfer is reassessed"
        );
        assert_eq!(running, 1);
    }

    #[test]
    fn a_bad_handle_from_perform_skips_the_reassessment() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(3, PollAction::IN)]);
        host.perform_result = CURLMcode::BadHandle;

        assert_eq!(
            events.socket_all(&mut host, None, None),
            CURLMcode::BadHandle
        );
        assert!(host.calls().is_empty(), "there would be nothing to assess");
    }

    #[test]
    fn the_deprecated_socket_entry_point_is_socket_action_with_no_bitmask() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(3, PollAction::IN)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        host.dirty_marks.clear();

        // Both deprecated symbols stay, and this one behaves as
        // `curl_multi_socket_action(m, s, 0, n)`.
        assert!(events.socket(&mut host, 3, None, None).is_ok());
        assert_eq!(host.dirty_marks, vec![1]);
    }

    #[test]
    fn running_handles_is_clamped_to_the_c_int_range() {
        let (mut events, _clock) = events_at(10);
        let mut host = TestHost::with_xfers(&[1]);
        host.running = u32::MAX;
        let mut running = 0;
        assert!(events
            .socket_action(&mut host, 3, 0, Some(&mut running), None)
            .is_ok());
        assert_eq!(running, i32::MAX);
    }

    // THE OWNED STATE ITSELF

    #[test]
    fn cleanup_forgets_every_socket_without_telling_the_application() {
        let (mut events, _clock) = events_at(1);
        let mut host = TestHost::with_xfers(&[1]);
        host.set_want(1, &[(3, PollAction::IN), (4, PollAction::OUT)]);
        assert!(events.assess_xfer(&mut host, 1, None).is_ok());
        assert_eq!(events.sockets().len(), 2);
        let calls = host.calls().len();

        events.cleanup();
        assert!(events.sockets().is_empty());
        assert_eq!(
            host.calls().len(),
            calls,
            "cleanup runs while the handle is being destroyed"
        );
    }

    #[test]
    fn the_clock_is_injected_and_nothing_reads_the_host_clock() {
        let (mut events, clock) = events_at(1_234);
        assert_eq!(events.now(), CurlTime::new(1_234, 0));
        clock.advance(Duration::from_millis(1_500));
        assert_eq!(
            events.refresh_now(),
            CurlTime::new(1_235, 500_000),
            "the reading comes from the injected clock alone"
        );
        assert_eq!(events.now(), CurlTime::new(1_235, 500_000));
    }

    #[test]
    fn callback_data_is_an_opaque_token() {
        assert!(CallbackData::NONE.is_none());
        assert_eq!(CallbackData::NONE.bits(), 0);
        let token = CallbackData::from_bits(0x1234_5678);
        assert!(!token.is_none());
        assert_eq!(token.bits(), 0x1234_5678);
    }

    #[test]
    fn an_event_target_names_its_transfer_and_its_connection() {
        assert_eq!(EvTarget::Xfer(7).mid(), 7);
        assert_eq!(EvTarget::Xfer(7).conn(), None);
        let target = EvTarget::Conn { mid: 7, conn: 99 };
        assert_eq!(target.mid(), 7);
        assert_eq!(target.conn(), Some(99));
    }

    #[test]
    fn the_action_fragments_are_the_cs_two_conversions() {
        assert_eq!(action_fragments(PollAction::NONE), ("", ""));
        assert_eq!(action_fragments(PollAction::IN), ("IN", ""));
        assert_eq!(action_fragments(PollAction::OUT), ("", "OUT"));
        assert_eq!(action_fragments(PollAction::INOUT), ("IN", "OUT"));
    }
}
