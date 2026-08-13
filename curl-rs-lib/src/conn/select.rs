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

//! Socket-readiness accounting -- supersedes `lib/select.c:1-727`,
//! `lib/select.h:1-237`, `lib/curlx/wait.c:1-94` and `lib/curlx/wait.h:1-30`.
//!
//! This module owns the readiness vocabulary for the whole crate: the
//! `CURL_POLL_*` action bitmap, the `CURL_CSELECT_*` result bitmap, the
//! `CURL_WAIT_POLL*` application bitmap, and the three containers that carry
//! them -- [`EasyPollset`] (one transfer's sockets), [`PollFds`] (many
//! pollsets folded into one internal array) and [`WaitFds`] (the
//! application-facing array behind `curl_multi_wait`).
//!
//! # Where the descriptor-set marshalling went
//!
//! `FDSET_SOCK` and `VERIFY_SOCK` (`select.h:103-111`) exist only for the
//! descriptor-set flavour of waiting, which reaches the public ABI through
//! `curl_multi_fdset` and `Curl_cshutdn_setfds` (`lib/cshutdn.c:434-471`).
//! That marshalling belongs to `curl-rs-ffi`, which is the crate that owns
//! the C types and the size limit they carry; the constants are named here as
//! provenance and NOTHING in this module builds such a set. This module
//! supplies `(socket, action)` pairs and readiness, and no more -- see
//! [`EasyPollset::iter`], which is deliberately general enough to build any of
//! the three representations `lib/cshutdn.c:434-533` needs.
//!
//! # The codes this module reports, and the one it does not
//!
//! Every failure is a [`CURLcode`]; no local error type is defined, and no
//! integer literal for a code appears anywhere. Four are reachable, each with
//! the C site it comes from:
//!
//! | Code | From | Meaning here |
//! |---|---|---|
//! | [`CURLcode::BadFunctionArgument`] | `select.c:573`, `wait.c:65` | not a descriptor, or a negative pure delay |
//! | [`CURLcode::OutOfMemory`] | `select.c:605` | the pollset capacity cannot grow |
//! | [`CURLcode::OperationTimedout`] | `socks.c:130-132` and its siblings | a deadline that had already passed |
//! | [`CURLcode::UnrecoverablePoll`] | `easy.c:564`, `multi.c:1470` | the wait itself failed, the C's `-1` |
//!
//! A caller that wants "not ready yet" reads `Ok(0)`, which is the answer the
//! C's own `int` return gives it.

use core::fmt;
use core::ops::{BitAnd, BitOr, BitOrAssign, Not};
use core::time::Duration;
use std::io;
use std::mem;
use std::os::fd::RawFd;

use core::future::Future;

use futures::future::{select_all, SelectAll};
use tokio::io::unix::AsyncFd;
use tokio::io::{Interest, Ready};

use crate::error::{CURLcode, CodeResult};
use crate::trace::{trc_feat, TraceFeature, Tracer};
use crate::util::timediff::{mstotv, TimeDiff};

// THE DESCRIPTOR TYPE

/// A socket, as the pollset stores it -- C's `curl_socket_t`.
pub(crate) type Socket = RawFd;

/// The absent socket -- C's `CURL_SOCKET_BAD`.
#[allow(dead_code)]
pub(crate) const CURL_SOCKET_BAD: Socket = -1;

/// `VALID_SOCK()`: is this a descriptor at all?
#[allow(dead_code)]
pub(crate) fn is_valid_sock(sock: Socket) -> bool {
    sock >= 0
}

// CURL_POLL_*: WHAT A TRANSFER WANTS TO DO WITH A SOCKET

/// The `CURL_POLL_*` bitmap -- what a transfer wants a socket for.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct PollAction(u8);

impl PollAction {
    /// `CURL_POLL_NONE` = 0: not interested.
    pub(crate) const NONE: Self = Self(0);

    /// `CURL_POLL_IN` = 1: wants to read, or to accept.
    pub(crate) const IN: Self = Self(1);

    /// `CURL_POLL_OUT` = 2: wants to write, or to complete a connection.
    pub(crate) const OUT: Self = Self(2);

    /// `CURL_POLL_INOUT` = 3: both, and exactly `IN | OUT`.
    ///
    /// The C spells 3 as a separate `#define` rather than as the union, which
    /// makes the identity look like a coincidence. It is not one, and
    /// `inout_is_exactly_in_or_out` fixes it so that renumbering either half
    /// fails a test.
    pub(crate) const INOUT: Self = Self(3);

    /// `CURL_POLL_REMOVE` = 4: stop watching this socket entirely.
    #[allow(dead_code)]
    pub(crate) const REMOVE: Self = Self(4);

    /// The raw integer, for the one caller that needs it: the socket callback.
    #[allow(dead_code)]
    pub(crate) const fn bits(self) -> u8 {
        self.0
    }

    /// Reconstructs an action from the raw integer.
    #[allow(dead_code)]
    pub(crate) const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Wants to read -- `actions[i] & CURL_POLL_IN` (`select.c:419`).
    pub(crate) const fn contains_in(self) -> bool {
        self.0 & Self::IN.0 != 0
    }

    /// Wants to write -- `actions[i] & CURL_POLL_OUT` (`select.c:421`).
    pub(crate) const fn contains_out(self) -> bool {
        self.0 & Self::OUT.0 != 0
    }

    /// No interest at all -- the `!ps->actions[i]` of `select.c:583`.
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for PollAction {
    type Output = Self;

    /// `actions[i] |= add_flags` (`select.c:581`).
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl BitAnd for PollAction {
    type Output = Self;

    /// The mask half of `actions[i] &= ~remove_flags` (`select.c:580`).
    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl Not for PollAction {
    type Output = Self;

    /// `~remove_flags` (`select.c:580`), narrowed to the byte the C narrows it
    /// to by its `(unsigned char)` cast.
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl fmt::Debug for PollAction {
    /// Symbolic, so a failing assertion names the flags instead of an integer.
    ///
    /// `REMOVE` is rendered whole rather than as bits, because it is a verb
    /// and not a union; anything else unrecognised prints as its number.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NONE => formatter.write_str("CURL_POLL_NONE"),
            Self::IN => formatter.write_str("CURL_POLL_IN"),
            Self::OUT => formatter.write_str("CURL_POLL_OUT"),
            Self::INOUT => formatter.write_str("CURL_POLL_INOUT"),
            Self::REMOVE => formatter.write_str("CURL_POLL_REMOVE"),
            Self(bits) => write!(formatter, "PollAction({bits})"),
        }
    }
}

// CURL_CSELECT_*: WHAT A WAIT FOUND

/// `CURL_CSELECT_IN` = 0x01: the first socket is readable.
///
/// `include/curl/multi.h:291`. ABI-visible: the three public `CURL_CSELECT_*`
/// bits are the `ev_bitmask` argument of `curl_multi_socket_action`, so an
/// application composes them itself.
#[allow(dead_code)]
pub(crate) const CURL_CSELECT_IN: u32 = 0x01;

/// `CURL_CSELECT_OUT` = 0x02: the write socket is writable.
///
/// `include/curl/multi.h:292`. ABI-visible; see [`CURL_CSELECT_IN`].
#[allow(dead_code)]
pub(crate) const CURL_CSELECT_OUT: u32 = 0x02;

/// `CURL_CSELECT_ERR` = 0x04: an error condition occurred.
///
/// `include/curl/multi.h:293`. ABI-visible; see [`CURL_CSELECT_IN`].
#[allow(dead_code)]
pub(crate) const CURL_CSELECT_ERR: u32 = 0x04;

/// `CURL_CSELECT_IN2` = 0x08: the SECOND socket is readable.
#[allow(dead_code)]
pub(crate) const CURL_CSELECT_IN2: u32 = CURL_CSELECT_ERR << 1;

// CURL_WAIT_POLL*: WHAT THE APPLICATION SEES

/// `CURL_WAIT_POLLIN` = 0x0001 (`include/curl/multi.h:110`).
#[allow(dead_code)]
pub(crate) const CURL_WAIT_POLLIN: i16 = 0x0001;

/// `CURL_WAIT_POLLPRI` = 0x0002 (`include/curl/multi.h:111`).
///
/// Defined by the public header and NEVER SET by libcurl -- measured:
/// `Curl_waitfds_add_ps` maps only `CURL_POLL_IN` and `CURL_POLL_OUT`
/// (`select.c:477-480`), and no other writer of a `struct curl_waitfd` exists.
/// It is reproduced because the constant is part of the ABI an application
/// compiles against, and it is deliberately not produced, because producing it
/// would be a behaviour change.
#[allow(dead_code)]
pub(crate) const CURL_WAIT_POLLPRI: i16 = 0x0002;

/// `CURL_WAIT_POLLOUT` = 0x0004 (`include/curl/multi.h:112`).
#[allow(dead_code)]
pub(crate) const CURL_WAIT_POLLOUT: i16 = 0x0004;

/// One entry of the array `curl_multi_wait` fills -- C's `struct curl_waitfd`
/// (`include/curl/multi.h:114-118`).
///
/// The C struct is layout-visible: an application allocates the array and
/// reads `revents` out of it. Its `#[repr(C)]` mirror therefore belongs to
/// `curl-rs-ffi`, which owns the ABI, and this is the plain engine-side form
/// that the shim converts to and from. Deliberately NOT `#[repr(C)]`: two
/// definitions claiming to be the C layout would be one too many, and only the
/// crate that generates the header can hold that claim.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WaitFd {
    /// The socket -- C's `curl_socket_t fd`.
    pub(crate) fd: Socket,
    /// What is wanted, in `CURL_WAIT_POLL*` bits -- C's `short events`.
    pub(crate) events: i16,
    /// What happened, in `CURL_WAIT_POLL*` bits -- C's `short revents`.
    ///
    /// Written by the wait, not by [`WaitFds::add_ps`], which is why every
    /// entry this module appends leaves it zero. `curl_multi_wait` is what
    /// fills it in, from the readiness [`poll_sockets`] reports.
    #[allow(dead_code)]
    pub(crate) revents: i16,
}

/// Translates one transfer's interest into the application's vocabulary.
fn wait_events_of(action: PollAction) -> i16 {
    let mut events = 0;
    if action.contains_in() {
        events |= CURL_WAIT_POLLIN;
    }
    if action.contains_out() {
        events |= CURL_WAIT_POLLOUT;
    }
    events
}

// POLL*: THE INTERNAL EVENT BITMAP

/// A `poll(2)`-style event bitmap -- C's `POLLIN`..`POLLNVAL`.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct PollEvents(i16);

impl PollEvents {
    /// No event -- the zero the C initialises `revents` to (`select.c:144`).
    pub(crate) const NONE: Self = Self(0);

    /// `POLLIN` = 0x01: readable, which for a listening socket means
    /// acceptable.
    pub(crate) const IN: Self = Self(0x01);

    /// `POLLPRI` = 0x02: out-of-band data, and `POLLRDBAND` with it.
    ///
    /// [`socket_check`] treats it as an ERROR rather than as readability
    /// (`select.c:169-170`), which is curl's judgement and is preserved.
    pub(crate) const PRI: Self = Self(0x02);

    /// `POLLOUT` = 0x04: writable, which for a connecting socket means
    /// connected.
    pub(crate) const OUT: Self = Self(0x04);

    /// `POLLERR` = 0x08: an error is pending on the socket.
    pub(crate) const ERR: Self = Self(0x08);

    /// `POLLHUP` = 0x10: the peer hung up.
    pub(crate) const HUP: Self = Self(0x10);

    /// `POLLNVAL` = 0x20: the descriptor is not one that can be watched.
    pub(crate) const NVAL: Self = Self(0x20);

    /// The three bits a wait reports whether or not they were asked for.
    ///
    /// `poll(2)` returns `POLLERR`, `POLLHUP` and `POLLNVAL` in `revents`
    /// regardless of `events`, and the masking in [`revents_of`] has to let
    /// them through for the normalisation at `select.c:259-262` to have
    /// anything to act on.
    const UNSOLICITED: Self = Self(Self::ERR.0 | Self::HUP.0 | Self::NVAL.0);

    /// The raw integer, as the C's `short` holds it.
    pub(crate) const fn bits(self) -> i16 {
        self.0
    }

    /// Reconstructs a bitmap from the raw integer.
    ///
    /// Total, for the reason [`PollAction::from_bits`] gives: an unknown bit is
    /// a bit this build does not act on, not an error.
    #[allow(dead_code)]
    pub(crate) const fn from_bits(bits: i16) -> Self {
        Self(bits)
    }

    /// Is any bit set? The `if(ufds[i].revents)` of `select.c:327`.
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Does this bitmap carry any of `other`'s bits?
    ///
    /// The C writes `revents & (A | B)`, whose truth is exactly this.
    pub(crate) const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// `Curl_poll`'s readiness normalisation -- `lib/select.c:256-263`.
    ///
    /// ```text
    /// if(ufds[i].revents & POLLHUP)
    ///   ufds[i].revents |= POLLIN;
    /// if(ufds[i].revents & POLLERR)
    ///   ufds[i].revents |= POLLIN | POLLOUT;
    /// ```
    pub(crate) fn normalise(self) -> Self {
        let mut events = self;
        if events.intersects(Self::HUP) {
            events |= Self::IN;
        }
        if events.intersects(Self::ERR) {
            events |= Self::IN | Self::OUT;
        }
        events
    }
}

impl BitOr for PollEvents {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl BitOrAssign for PollEvents {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl BitAnd for PollEvents {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl Not for PollEvents {
    type Output = Self;

    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl fmt::Debug for PollEvents {
    /// Symbolic and additive, so a failing assertion reads
    /// `POLLIN|POLLHUP` rather than `Self(17)`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return formatter.write_str("0");
        }
        let names = [
            (Self::IN, "POLLIN"),
            (Self::PRI, "POLLPRI"),
            (Self::OUT, "POLLOUT"),
            (Self::ERR, "POLLERR"),
            (Self::HUP, "POLLHUP"),
            (Self::NVAL, "POLLNVAL"),
        ];
        let mut known = Self::NONE;
        let mut first = true;
        for (bit, name) in names {
            if self.intersects(bit) {
                if !first {
                    formatter.write_str("|")?;
                }
                formatter.write_str(name)?;
                first = false;
                known |= bit;
            }
        }
        let rest = *self & !known;
        if !rest.is_empty() {
            if !first {
                formatter.write_str("|")?;
            }
            write!(formatter, "{:#x}", rest.bits())?;
        }
        Ok(())
    }
}

/// Translates one transfer's interest into `poll(2)` events.
///
/// `Curl_pollfds_add_ps` (`select.c:418-422`) and `Curl_pollset_poll`
/// (`select.c:666-672`) perform the same two tests, and both skip the entry
/// entirely when the result is zero.
fn poll_events_of(action: PollAction) -> PollEvents {
    let mut events = PollEvents::NONE;
    if action.contains_in() {
        events |= PollEvents::IN;
    }
    if action.contains_out() {
        events |= PollEvents::OUT;
    }
    events
}

/// One descriptor being waited on -- C's `struct pollfd`
/// (`lib/select.h:49-53`).
///
/// `revents` is retained rather than collapsed away, and that is a deliberate
/// departure from a simpler `(socket, action)` pair: the C's callers READ it
/// after the wait. `lib/multi.c:1465-1470` tests
/// `cpfds.pfds[curl_nfds].revents & POLLIN` to discover whether it was the
/// wakeup descriptor that fired rather than a transfer's socket, and
/// discovering that from a count alone is impossible. Dropping the field would
/// make the whole aggregation write-only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PollFd {
    /// The descriptor, or [`CURL_SOCKET_BAD`] for a slot to be skipped.
    pub(crate) sock: Socket,
    /// What is wanted, in [`PollEvents`] bits.
    pub(crate) events: PollEvents,
    /// What happened, in [`PollEvents`] bits, after a wait.
    pub(crate) revents: PollEvents,
}

impl PollFd {
    /// A slot wanting `events` on `sock`, with nothing yet reported.
    ///
    /// The C assigns the three fields one at a time at each of its four
    /// construction sites (`select.c:142-144`, `:148-150`, `:154-156`,
    /// `:398-399`, `:674-675`) and zeroes `revents` at every one of them.
    pub(crate) fn new(sock: Socket, events: PollEvents) -> Self {
        Self {
            sock,
            events,
            revents: PollEvents::NONE,
        }
    }
}

// THE POLLSET: ONE TRANSFER'S SOCKETS

/// `EZ_POLLSET_DEF_COUNT` = 2 (`lib/select.h:118`).
pub(crate) const EZ_POLLSET_DEF_COUNT: u32 = 2;

/// The floor of the growth rule: `CURLMAX(ps->count * 2, 8)`
/// (`lib/select.c:598`).
const EZ_POLLSET_MIN_GROWTH: u32 = 8;

/// The capacity a pollset grows to from `capacity`.
///
/// `CURLMAX(ps->count * 2, 8)` (`select.c:598`), reproduced including the
/// wrap-around the C's unsigned multiplication performs on overflow -- which
/// is precisely what its own guard at `:604-605` is there to catch, turning
/// the wrapped value into `CURLE_OUT_OF_MEMORY`. Writing `wrapping_mul` states
/// that intent; a checked multiplication would be a different function whose
/// overflow arm no test could reach through the C's own path.
fn grown_capacity(capacity: u32) -> u32 {
    capacity.wrapping_mul(2).max(EZ_POLLSET_MIN_GROWTH)
}

/// The sockets one transfer wants watched -- C's `struct easy_pollset`
/// (`lib/select.h:120-130`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EasyPollset {
    /// The live entries, in insertion order -- C's `sockets`, `actions` and
    /// `n` in one.
    entries: Vec<(Socket, PollAction)>,
    /// The capacity, purely so the growth rule and its trace line behave as
    /// the C's do -- C's `count`.
    ///
    /// This is NOT `entries.capacity()`. [`Vec`] may over-allocate for its own
    /// reasons, and reading a growth decision out of an allocator's choice
    /// would make the trace output depend on the allocator.
    capacity: u32,
}

impl Default for EasyPollset {
    /// An empty pollset at the default capacity.
    ///
    /// `Curl_pollset_init` (`select.c:500-510`) is what this is: point the
    /// pointers at the inline arrays, set `count` to their size, and clear.
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            capacity: EZ_POLLSET_DEF_COUNT,
        }
    }
}

impl EasyPollset {
    /// An empty pollset -- `Curl_pollset_create` and `Curl_pollset_init` in
    /// one.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// How many sockets are watched -- C's `ps->n`.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is nothing watched? The `if(!ps->n)` of `select.c:657`.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The current capacity -- C's `ps->count`.
    ///
    /// Exposed for the tests that pin the growth rule and its trace line. No
    /// production caller needs it, exactly as no C caller reads `count`.
    #[allow(dead_code)]
    pub(crate) fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Every watched socket with its actions, in insertion order.
    #[allow(dead_code)]
    pub(crate) fn iter(
        &self,
    ) -> impl Iterator<Item = (Socket, PollAction)> + '_ {
        self.entries.iter().copied()
    }

    /// Empties the pollset, keeping the capacity -- `Curl_pollset_reset`
    /// (`select.c:487-498`).
    #[allow(dead_code)]
    pub(crate) fn reset(&mut self) {
        self.entries.clear();
    }

    /// Takes `other`'s contents, leaving `other` empty --
    /// `Curl_pollset_move(to, from)` (`select.c:537-556`).
    #[allow(dead_code)]
    pub(crate) fn take_from(&mut self, other: &mut Self) {
        *self = mem::take(other);
    }

    /// Is the live count at the capacity? -- the `i >= ps->count` of
    /// `select.c:597`.
    fn at_capacity(&self) -> bool {
        match u32::try_from(self.entries.len()) {
            Ok(live) => live >= self.capacity,
            Err(_) => true,
        }
    }

    /// The actions held for `sock`, or [`PollAction::NONE`] if it is absent.
    #[allow(dead_code)]
    pub(crate) fn action_of(&self, sock: Socket) -> PollAction {
        self.entries
            .iter()
            .find(|(held, _)| *held == sock)
            .map_or(PollAction::NONE, |(_, action)| *action)
    }

    /// Adds and removes poll flags for `sock` -- `Curl_pollset_change`
    /// (`lib/select.c:561-632`).
    ///
    /// Three cases, in the C's own order:
    ///
    /// 1. **Present.** `actions &= ~remove; actions |= add;` and, if nothing
    ///    is left, the entry goes -- order-preservingly. An entry is never
    ///    left holding [`PollAction::NONE`]; a pollset with such an entry
    ///    would report a socket to every consumer and then ask for no events
    ///    on it.
    /// 2. **Absent, with something to add.** Append, growing first when the
    ///    capacity is reached.
    /// 3. **Absent, with nothing to add.** Nothing happens, and that is not an
    ///    error -- removing a flag from a socket that is not watched is how
    ///    every filter in a chain expresses "not mine".
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for a socket that is not a
    /// descriptor, which is what the C returns at `select.c:573`.
    /// [`CURLcode::OutOfMemory`] if the capacity cannot grow, matching
    /// `:605`; the allocation itself cannot fail recoverably in Rust, so this
    /// is reachable only through the overflow guard.
    #[allow(dead_code)]
    pub(crate) fn change(
        &mut self,
        sock: Socket,
        add: PollAction,
        remove: PollAction,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        // `DEBUGASSERT(VALID_SOCK(sock))` followed by a real return
        // (`select.c:571-573`): a debug build stops at the mistake, a release
        // build reports it.
        debug_assert!(
            is_valid_sock(sock),
            "a pollset change needs a descriptor, not {sock}"
        );
        if !is_valid_sock(sock) {
            return Err(CURLcode::BadFunctionArgument);
        }

        // `select.c:575-577`. All three are debug assertions in the C and stay
        // debug assertions here: they describe a caller error that the release
        // build absorbs harmlessly, since an unknown bit merely fails to match
        // any test below.
        debug_assert!(
            add.bits() <= PollAction::INOUT.bits(),
            "a pollset holds only IN and OUT, not {add:?}"
        );
        debug_assert!(
            remove.bits() <= PollAction::INOUT.bits(),
            "a pollset holds only IN and OUT, not {remove:?}"
        );
        debug_assert!(
            (add & remove).is_empty(),
            "adding and removing {add:?} and {remove:?} overlap"
        );

        if let Some(index) =
            self.entries.iter().position(|(held, _)| *held == sock)
        {
            let action = (self.entries[index].1 & !remove) | add;
            if action.is_empty() {
                // `memmove` compaction (`select.c:584-590`): the tail slides
                // down, so insertion order survives. NOT `swap_remove`.
                self.entries.remove(index);
            } else {
                self.entries[index].1 = action;
            }
            return Ok(());
        }

        // Not present. `if(add_flags)` (`select.c:596`).
        if add.is_empty() {
            return Ok(());
        }

        if self.at_capacity() {
            let grown = grown_capacity(self.capacity);
            // Emitted BEFORE the overflow guard, as `select.c:602-605` emits
            // it: the line reports the capacity that was ASKED for, even when
            // the request is the one that fails.
            if let Some(tracer) = trc {
                trc_feat!(
                    tracer,
                    TraceFeature::Multi,
                    "growing pollset capacity from {} to {}",
                    self.capacity,
                    grown
                );
            }
            if grown <= self.capacity {
                return Err(CURLcode::OutOfMemory);
            }
            // The C reallocates two arrays here and copies into them
            // (`select.c:606-621`). The vector owns that decision, and no
            // reservation is added to imitate it: an allocation hint would be a
            // change made for speed, and performance is an explicit non-goal.
            // What IS tracked is the capacity, because the growth decision and
            // the trace line above are observable where the allocation is not.
            self.capacity = grown;
        }

        self.entries.push((sock, add));
        Ok(())
    }

    /// Sets exactly what is wanted for `sock` -- `Curl_pollset_set`
    /// (`lib/select.c:634-643`).
    ///
    /// The C composes it out of [`Self::change`] and nothing else:
    ///
    /// ```text
    /// Curl_pollset_change(data, ps, sock,
    ///                     (do_in  ? CURL_POLL_IN  : 0) |
    ///                     (do_out ? CURL_POLL_OUT : 0),
    ///                     (!do_in  ? CURL_POLL_IN  : 0) |
    ///                     (!do_out ? CURL_POLL_OUT : 0));
    /// ```
    ///
    /// # Errors
    ///
    /// As [`Self::change`].
    #[allow(dead_code)]
    pub(crate) fn set(
        &mut self,
        sock: Socket,
        do_in: bool,
        do_out: bool,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        let mut add = PollAction::NONE;
        let mut remove = PollAction::NONE;
        if do_in {
            add = add | PollAction::IN;
        } else {
            remove = remove | PollAction::IN;
        }
        if do_out {
            add = add | PollAction::OUT;
        } else {
            remove = remove | PollAction::OUT;
        }
        self.change(sock, add, remove, trc)
    }

    /// `Curl_pollset_add_in` (`select.h:163-164`): also watch for readability.
    ///
    /// # Errors
    ///
    /// As [`Self::change`].
    #[allow(dead_code)]
    pub(crate) fn add_in(
        &mut self,
        sock: Socket,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        self.change(sock, PollAction::IN, PollAction::NONE, trc)
    }

    /// `Curl_pollset_remove_in` (`select.h:165-166`): stop watching for
    /// readability.
    ///
    /// # Errors
    ///
    /// As [`Self::change`].
    #[allow(dead_code)]
    pub(crate) fn remove_in(
        &mut self,
        sock: Socket,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        self.change(sock, PollAction::NONE, PollAction::IN, trc)
    }

    /// `Curl_pollset_add_out` (`select.h:167-168`): also watch for writability.
    ///
    /// # Errors
    ///
    /// As [`Self::change`].
    #[allow(dead_code)]
    pub(crate) fn add_out(
        &mut self,
        sock: Socket,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        self.change(sock, PollAction::OUT, PollAction::NONE, trc)
    }

    /// `Curl_pollset_remove_out` (`select.h:169-170`): stop watching for
    /// writability.
    ///
    /// # Errors
    ///
    /// As [`Self::change`].
    #[allow(dead_code)]
    pub(crate) fn remove_out(
        &mut self,
        sock: Socket,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        self.change(sock, PollAction::NONE, PollAction::OUT, trc)
    }

    /// `Curl_pollset_add_inout` (`select.h:171-173`): watch for both, removing
    /// neither.
    ///
    /// # Errors
    ///
    /// As [`Self::change`].
    #[allow(dead_code)]
    pub(crate) fn add_inout(
        &mut self,
        sock: Socket,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        self.change(sock, PollAction::INOUT, PollAction::NONE, trc)
    }

    /// `Curl_pollset_set_in_only` (`select.h:174-176`): readability, and
    /// explicitly not writability.
    ///
    /// # Errors
    ///
    /// As [`Self::change`].
    #[allow(dead_code)]
    pub(crate) fn set_in_only(
        &mut self,
        sock: Socket,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        self.change(sock, PollAction::IN, PollAction::OUT, trc)
    }

    /// `Curl_pollset_set_out_only` (`select.h:177-179`): writability, and
    /// explicitly not readability.
    ///
    /// # Errors
    ///
    /// As [`Self::change`].
    #[allow(dead_code)]
    pub(crate) fn set_out_only(
        &mut self,
        sock: Socket,
        trc: Option<&mut Tracer<'_>>,
    ) -> CodeResult<()> {
        self.change(sock, PollAction::OUT, PollAction::IN, trc)
    }

    /// What this pollset wants for `sock` -- `Curl_pollset_check`
    /// (`lib/select.c:685-701`).
    #[allow(dead_code)]
    pub(crate) fn check(&self, sock: Socket) -> (bool, bool) {
        debug_assert!(
            is_valid_sock(sock),
            "a pollset check needs a descriptor, not {sock}"
        );
        let action = self.action_of(sock);
        (action.contains_in(), action.contains_out())
    }

    /// Is `sock` watched for readability? -- `Curl_pollset_want_recv`
    /// (`lib/select.c:703-714`).
    #[allow(dead_code)]
    pub(crate) fn want_recv(&self, sock: Socket) -> bool {
        self.entries
            .iter()
            .any(|(held, action)| *held == sock && action.contains_in())
    }

    /// Is `sock` watched for writability? -- `Curl_pollset_want_send`
    /// (`lib/select.c:716-727`).
    #[allow(dead_code)]
    pub(crate) fn want_send(&self, sock: Socket) -> bool {
        self.entries
            .iter()
            .any(|(held, action)| *held == sock && action.contains_out())
    }

    /// Waits for any of these sockets -- `Curl_pollset_poll`
    /// (`lib/select.c:645-683`).
    ///
    /// # Errors
    ///
    /// As [`poll_sockets`], plus [`CURLcode::BadFunctionArgument`] from
    /// [`wait_ms`] when an empty pollset is given a negative timeout.
    #[allow(dead_code)]
    pub(crate) async fn poll(&self, timeout_ms: TimeDiff) -> CodeResult<usize> {
        if self.entries.is_empty() {
            wait_ms(timeout_ms).await?;
            return Ok(0);
        }

        // Built in POLLSET ORDER, skipping any entry that asks for nothing
        // (`select.c:664-678`). Such an entry cannot exist -- `change` removes
        // it -- but the C tests for it and so does this, because the cost is a
        // branch and the alternative is a wait on a descriptor with no
        // interest.
        let mut fds: Vec<PollFd> = self
            .entries
            .iter()
            .filter_map(|(sock, action)| {
                let events = poll_events_of(*action);
                if events.is_empty() {
                    None
                } else {
                    Some(PollFd::new(*sock, events))
                }
            })
            .collect();

        poll_sockets(&mut fds, timeout_ms).await
    }
}

// THE INTERNAL AGGREGATION BUFFER

/// Many pollsets folded into one array for a single wait -- C's
/// `struct curl_pollfds` (`lib/select.h:203-208`).
///
/// This is the INTERNAL shape. `curl_multi_wait` builds one of these over every
/// running transfer plus the multi handle's own wakeup descriptor, waits once,
/// and reads the results back out of it (`lib/multi.c:1400-1480`). The
/// application never sees it; what the application sees is [`WaitFds`], and the
/// asymmetry between the two is deliberate -- see [`Self::add_sock`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PollFds {
    entries: Vec<PollFd>,
}

impl PollFds {
    /// An empty buffer -- `Curl_pollfds_init` (`select.c:336-346`) without its
    /// static-array arguments, which have nothing left to configure.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// How many descriptors are buffered -- C's `cpfds->n`.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the buffer empty? The `if(cpfds.n)` of `lib/multi.c:1455`.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Empties the buffer -- `Curl_pollfds_reset` (`select.c:348-351`), whose
    /// whole body is `cpfds->n = 0`.
    ///
    /// `Curl_conn_connect` resets both its pollset and its buffer on every turn
    /// of its connect loop (`lib/cfilters.c:560-561`), which is the pattern
    /// this exists for.
    #[allow(dead_code)]
    pub(crate) fn reset(&mut self) {
        self.entries.clear();
    }

    /// The buffered descriptors, for a caller that wants to read `revents`.
    ///
    /// `lib/multi.c:1465-1470` indexes the array directly to find out whether
    /// the wakeup descriptor fired. This is how.
    #[allow(dead_code)]
    pub(crate) fn as_slice(&self) -> &[PollFd] {
        &self.entries
    }

    /// Folds a transfer's pollset into the buffer -- `Curl_pollfds_add_ps`
    /// (`lib/select.c:410-429`).
    ///
    /// # Infallible, where the C returns `CURLcode`
    ///
    /// The C's only failure is `curlx_calloc` returning null (`:367-369`,
    /// `:395-396`), sizing an array from the number of descriptors the caller
    /// already holds -- the same order of magnitude as data that is already
    /// resident, with no amplification, which is why it is not among the
    /// externally sized allocations `crate::util::fallible` covers. There is
    /// therefore no error left to return, and saying so in the signature is
    /// more honest than a result that can only ever be `Ok`.
    /// [`EasyPollset::change`] keeps its result because its failures are real:
    /// a bad descriptor and the capacity overflow guard.
    #[allow(dead_code)]
    pub(crate) fn add_ps(&mut self, ps: &EasyPollset) {
        for (sock, action) in ps.iter() {
            let events = poll_events_of(action);
            if !events.is_empty() {
                self.add_sock_folding(sock, events);
            }
        }
    }

    /// Appends one descriptor WITHOUT folding -- `Curl_pollfds_add_sock`
    /// (`lib/select.c:404-408`).
    #[allow(dead_code)]
    pub(crate) fn add_sock(&mut self, sock: Socket, events: PollEvents) {
        self.entries.push(PollFd::new(sock, events));
    }

    /// The folding half of `cpfds_add_sock` (`lib/select.c:380-402`).
    fn add_sock_folding(&mut self, sock: Socket, events: PollEvents) {
        for entry in self.entries.iter_mut().rev() {
            if entry.sock == sock {
                entry.events |= events;
                return;
            }
        }
        self.entries.push(PollFd::new(sock, events));
    }

    /// Waits on everything buffered, recording what happened in `revents`.
    ///
    /// The `Curl_poll(cpfds.pfds, cpfds.n, timeout_ms)` of `lib/multi.c:1462`
    /// and `lib/cshutdn.c:223`, over the buffer that owns the array.
    ///
    /// # Errors
    ///
    /// As [`poll_sockets`].
    #[allow(dead_code)]
    pub(crate) async fn poll(
        &mut self,
        timeout_ms: TimeDiff,
    ) -> CodeResult<usize> {
        poll_sockets(&mut self.entries, timeout_ms).await
    }
}

// THE APPLICATION-FACING ARRAY

/// The array `curl_multi_wait` fills -- C's `struct Curl_waitfds`
/// (`lib/select.h:224-228`).
///
/// The caller owns the storage: `curl_multi_wait` is handed
/// `struct curl_waitfd extra_fds[]` and a count, and libcurl writes into it
/// without ever allocating. That is modelled here as a borrowed mutable slice
/// rather than an owned vector, because the borrow IS the contract -- and
/// because the counting mode below is meaningless without a bounded store.
#[derive(Debug, Default)]
pub(crate) struct WaitFds<'a> {
    /// The caller's array, or [`None`] in counting mode -- C's `wfds`.
    store: Option<&'a mut [WaitFd]>,
    /// How many slots are filled -- C's `n`. Never exceeds the store's length.
    n: usize,
}

impl<'a> WaitFds<'a> {
    /// A writer over the caller's array -- `Curl_waitfds_init`
    /// (`lib/select.c:431-440`).
    ///
    /// The C's `static_count` is the slice's own length here, which removes the
    /// possibility its assertion at `:436` guards against: a null array with a
    /// non-zero count.
    #[allow(dead_code)]
    pub(crate) fn new(store: &'a mut [WaitFd]) -> Self {
        Self {
            store: Some(store),
            n: 0,
        }
    }

    /// A counter with no storage -- `Curl_waitfds_init(cwfds, NULL, 0)`.
    ///
    /// `curl_multi_wait` uses this shape to answer "how many descriptors would
    /// I need?" without writing anywhere, and `Curl_cshutdn_add_waitfds`
    /// (`lib/cshutdn.c:474-500`) accumulates into whichever shape it is given.
    #[allow(dead_code)]
    pub(crate) fn counting() -> Self {
        Self { store: None, n: 0 }
    }

    /// How many slots have been filled -- C's `cwfds->n`.
    ///
    /// Always zero in counting mode, where nothing is written. This is NOT the
    /// `need` that [`Self::add_ps`] returns: `need` counts what the caller
    /// would have needed, this counts what was actually recorded.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.n
    }

    /// Is nothing recorded?
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The slots that were filled, for a caller reading them back.
    #[allow(dead_code)]
    pub(crate) fn filled(&self) -> &[WaitFd] {
        match self.store.as_ref() {
            Some(store) => &store[..self.n],
            None => &[],
        }
    }

    /// Records a transfer's pollset and returns how many entries it NEEDED --
    /// `Curl_waitfds_add_ps` (`lib/select.c:467-485`).
    #[allow(dead_code)]
    pub(crate) fn add_ps(&mut self, ps: &EasyPollset) -> u32 {
        let mut need = 0_u32;
        for (sock, action) in ps.iter() {
            let events = wait_events_of(action);
            if events != 0 {
                need = need.saturating_add(self.add_sock(sock, events));
            }
        }
        need
    }

    /// One descriptor, folded or appended or merely counted -- `cwfds_add_sock`
    /// (`lib/select.c:442-465`).
    ///
    /// Private, exactly as the C's is `static`: the only way into this array is
    /// through a pollset, which is what keeps an internal descriptor such as
    /// the multi handle's wakeup pipe out of it.
    fn add_sock(&mut self, sock: Socket, events: i16) -> u32 {
        let Some(store) = self.store.as_mut() else {
            // `DEBUGASSERT(!cwfds->count && !cwfds->n)` (`select.c:447`).
            debug_assert_eq!(
                self.n, 0,
                "counting mode cannot have filled a slot"
            );
            return 1;
        };

        // Backwards from the most recent entry (`select.c:451-456`). The
        // direction is the C's; with at most one entry per descriptor the
        // result cannot differ from a forward scan, and the C's choice is kept
        // so that a future entry duplicated by some other path folds into the
        // newest rather than the oldest.
        for index in (0..self.n).rev() {
            if store[index].fd == sock {
                store[index].events |= events;
                return 0;
            }
        }

        if self.n < store.len() {
            store[self.n] = WaitFd {
                fd: sock,
                events,
                revents: 0,
            };
            self.n += 1;
        }
        // ONE, whether or not it was recorded: a caller whose array was too
        // small still has to be told how many entries it needed.
        1
    }
}

// THE THREE TIMEOUT CONVENTIONS

/// How long a RAW POLL TIMEOUT asks a wait to last.
fn wait_span(timeout_ms: TimeDiff) -> Option<Duration> {
    mstotv(timeout_ms.min(TimeDiff::from(i32::MAX)))
}

/// Turns a COMPUTED TIME REMAINING into a wait, rejecting one that has run out.
///
/// # Errors
///
/// [`CURLcode::OperationTimedout`] when `time_left_ms` is negative.
#[allow(dead_code)]
pub(crate) fn timeleft_to_wait(time_left_ms: TimeDiff) -> CodeResult<TimeDiff> {
    if time_left_ms < 0 {
        return Err(CURLcode::OperationTimedout);
    }
    Ok(time_left_ms)
}

/// Delays for `timeout_ms` with no socket involved -- `curlx_wait_ms`
/// (`lib/curlx/wait.c:58-94`).
///
/// # The mechanism changed and the behaviour did not
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for a negative delay, which is the
/// `SOCKEINVAL` of `wait.c:65`.
///
/// # Panics
///
/// Requires a `tokio` runtime with the time driver enabled, as every timer in
/// this crate does. A positive delay outside one panics inside `tokio`; zero
/// and negative values return before a timer is created.
#[allow(dead_code)]
pub(crate) async fn wait_ms(timeout_ms: TimeDiff) -> CodeResult<()> {
    if timeout_ms == 0 {
        return Ok(());
    }
    if timeout_ms < 0 {
        return Err(CURLcode::BadFunctionArgument);
    }
    // Strictly positive here, so the "block indefinitely" arm of the mapping
    // cannot arise. Naming zero for it keeps the function total without an
    // unreachable panic: a zero-length sleep is what a zero delay asks for.
    tokio::time::sleep(mstotv(timeout_ms).unwrap_or(Duration::ZERO)).await;
    Ok(())
}

// THE REACTOR SIDE

/// What a wait failure means -- `Curl_poll`'s `EINTR` rule
/// (`lib/select.c:249-253`).
///
/// ```text
/// if((r == -1) && (SOCKERRNO == SOCKEINTR))
///   /* make EINTR from select or poll not a "lethal" error */
///   r = 0;
/// ```
fn wait_failure(error: &io::Error) -> CodeResult<usize> {
    if error.kind() == io::ErrorKind::Interrupted {
        Ok(0)
    } else {
        Err(CURLcode::UnrecoverablePoll)
    }
}

/// The reactor registration that `events` calls for.
fn interest_of(events: PollEvents) -> Interest {
    let mut interest = Interest::ERROR;
    if events.intersects(PollEvents::IN) {
        interest = interest.add(Interest::READABLE);
    }
    if events.intersects(PollEvents::OUT) {
        interest = interest.add(Interest::WRITABLE);
    }
    if events.intersects(PollEvents::PRI) {
        interest = add_priority_interest(interest);
    }
    interest
}

/// Adds out-of-band interest, where the reactor has it.
///
/// `tokio` exposes priority interest on Linux and Android only, mirroring
/// `EPOLLPRI`. Requesting it there is what makes the `POLLPRI` half of
/// [`cselect_of_read`] reachable, rather than a mapping no readiness can ever
/// satisfy.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn add_priority_interest(interest: Interest) -> Interest {
    interest.add(Interest::PRIORITY)
}

/// Leaves the interest alone on a platform without out-of-band interest.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn add_priority_interest(interest: Interest) -> Interest {
    interest
}

/// `POLLPRI` from a reactor readiness, where the platform reports it.
///
/// Platform divergence uses `#[cfg(target_os =...)]` rather than a Cargo
/// feature, so that a target cannot be misconfigured into the wrong half.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn priority_events(ready: Ready) -> PollEvents {
    if ready.is_priority() {
        PollEvents::PRI
    } else {
        PollEvents::NONE
    }
}

/// `POLLPRI` on a platform whose reactor does not report it.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn priority_events(_ready: Ready) -> PollEvents {
    PollEvents::NONE
}

/// Translates a reactor readiness into `poll(2)` events.
///
/// | `tokio` readiness | `poll(2)` bit | Why |
/// |---|---|---|
/// | readable | `POLLIN` | the same idea |
/// | writable | `POLLOUT` | the same idea |
/// | read closed | `POLLHUP` | the peer hung up on us |
/// | write closed | `POLLHUP` | `poll(2)` calls this a hang-up too |
/// | error | `POLLERR` | the same idea |
/// | priority | `POLLPRI` | Linux and Android only -- see [`priority_events`] |
fn events_of_ready(ready: Ready) -> PollEvents {
    let mut events = PollEvents::NONE;
    if ready.is_readable() {
        events |= PollEvents::IN;
    }
    if ready.is_writable() {
        events |= PollEvents::OUT;
    }
    if ready.is_read_closed() || ready.is_write_closed() {
        events |= PollEvents::HUP;
    }
    if ready.is_error() {
        events |= PollEvents::ERR;
    }
    events |= priority_events(ready);
    events
}

/// What a wait reports for one descriptor, given what was asked of it.
///
/// Two steps, in the order `poll(2)` and then `Curl_poll` perform them:
///
/// 1. **Mask.** `poll(2)` reports only the events the caller requested, plus
///    `POLLERR`, `POLLHUP` and `POLLNVAL`, which it reports regardless. That is
///    [`PollEvents::UNSOLICITED`].
/// 2. **Normalise.** `select.c:256-263` then ADDS readability to a hang-up and
///    both directions to an error, and does so WITHOUT re-applying the mask.
///
/// The order matters and the asymmetry is the C's: a descriptor watched only
/// for writing reports `POLLOUT` when writable, nothing when readable, and
/// `POLLIN | POLLOUT | POLLHUP` when the peer hangs up.
fn revents_of(requested: PollEvents, ready: Ready) -> PollEvents {
    (events_of_ready(ready) & (requested | PollEvents::UNSOLICITED)).normalise()
}

/// One descriptor registered with the reactor for the duration of one wait.
struct Watch {
    /// The reactor registration. Dropping it deregisters interest and does
    /// NOT close the descriptor, because the wrapped value is a number and
    /// owns nothing.
    guard: AsyncFd<Socket>,
    /// The interest it was registered with, needed again to await readiness.
    interest: Interest,
    /// Indices into the caller's array that named this descriptor.
    slots: Vec<usize>,
}

/// How many scheduler turns a non-blocking probe is given.
///
/// One is the number that matters, and the rest are insurance; see [`probe`]
/// for what a turn buys and why more than one is offered.
const PROBE_TURNS: usize = 3;

/// Reports readiness that is ALREADY present, without blocking.
///
/// # What it does instead
///
/// It polls, and between polls hands the runtime a turn with
/// `tokio::task::yield_now`. A scheduler with nothing else to run polls its
/// driver with a zero timeout of its own, which collects every pending event,
/// so one turn is what a genuinely ready descriptor needs. Up to
/// [`PROBE_TURNS`] are offered because on a multi-threaded runtime the driver
/// may be held by another worker, and a spurious "not ready" is the one answer
/// this must not give cheaply.
async fn probe<F>(all: &mut SelectAll<F>) -> Option<(F::Output, usize, Vec<F>)>
where
    F: Future + Unpin,
{
    for turn in 0..=PROBE_TURNS {
        if turn > 0 {
            tokio::task::yield_now().await;
        }
        // A zero-length timeout polls its inner future exactly once, which is
        // the probe. The real waker travels with it, unlike a bare one-shot
        // poll, so the driver's wake actually reschedules this task.
        if let Ok(done) = tokio::time::timeout(Duration::ZERO, &mut *all).await
        {
            return Some(done);
        }
    }
    None
}

/// Writes one readiness back to every slot that named the descriptor.
fn record_ready(fds: &mut [PollFd], watch: &Watch, ready: Ready) {
    for slot in &watch.slots {
        let fd = &mut fds[*slot];
        // Accumulating rather than assigning: a descriptor may be reported by
        // the first completion and again by the sweep that follows it.
        fd.revents |= revents_of(fd.events, ready);
    }
}

/// Waits for readiness on a set of descriptors -- `Curl_poll`
/// (`lib/select.c:203-334`).
///
/// # The five behaviours that are load-bearing
///
/// 1. **All descriptors absent means delay.** `select.c:217-228` scans for a
///    single valid descriptor and, finding none, delegates to [`wait_ms`] --
///    which is where the negative timeout stops meaning "for ever" and starts
///    meaning "invalid", exactly as the C's own comment above describes.
/// 2. **The timeout has three meanings**, taken from [`wait_span`].
/// 3. **Interruption is a timeout**, not an error -- see [`wait_failure`].
/// 4. **The readiness is normalised**, so a hang-up reads as readable and an
///    error as both -- see [`PollEvents::normalise`].
/// 5. **The count is of SLOTS, not descriptors.** A descriptor named twice
///    contributes two, because the C counts `struct pollfd` entries whose
///    `revents` is non-zero (`select.c:327-328`).
///
/// # Errors
///
/// [`CURLcode::UnrecoverablePoll`] if the wait itself fails, which is the C's
/// `-1`; [`CURLcode::BadFunctionArgument`] from [`wait_ms`] if a negative
/// timeout reaches the no-descriptor path.
///
/// # Panics
///
/// Requires a `tokio` runtime, as [`wait_ms`] does.
#[allow(dead_code)]
pub(crate) async fn poll_sockets(
    fds: &mut [PollFd],
    timeout_ms: TimeDiff,
) -> CodeResult<usize> {
    // "no sockets, just wait" (`select.c:225-228`). An empty slice takes this
    // path too, which is what `Curl_poll(NULL, 0, ms)` does.
    if !fds.iter().any(|fd| is_valid_sock(fd.sock)) {
        wait_ms(timeout_ms).await?;
        return Ok(0);
    }

    for fd in fds.iter_mut() {
        fd.revents = PollEvents::NONE;
    }

    // Group the slots by descriptor, keeping the caller's order. Duplicate
    // names are merged into one registration whose interest is the union.
    let mut wanted: Vec<(Socket, Interest, Vec<usize>)> = Vec::new();
    for (slot, fd) in fds.iter().enumerate() {
        if !is_valid_sock(fd.sock) {
            continue;
        }
        let interest = interest_of(fd.events);
        match wanted.iter_mut().find(|(sock, _, _)| *sock == fd.sock) {
            Some((_, held, slots)) => {
                *held = held.add(interest);
                slots.push(slot);
            }
            None => wanted.push((fd.sock, interest, vec![slot])),
        }
    }

    let mut watches: Vec<Watch> = Vec::with_capacity(wanted.len());
    let mut unwatchable = 0_usize;
    for (sock, interest, slots) in wanted {
        match AsyncFd::with_interest(sock, interest) {
            Ok(guard) => watches.push(Watch {
                guard,
                interest,
                slots,
            }),
            Err(_refused) => {
                for slot in &slots {
                    fds[*slot].revents = PollEvents::NVAL;
                    unwatchable += 1;
                }
            }
        }
    }
    if unwatchable > 0 {
        // An immediate answer, as `poll(2)` gives for an invalid descriptor.
        return Ok(unwatchable);
    }
    if watches.is_empty() {
        // Unreachable: the scan above found a valid descriptor, and every
        // valid descriptor either registered or was counted as unwatchable.
        // Delegating rather than asserting keeps the function total.
        debug_assert!(false, "a valid descriptor produced no registration");
        wait_ms(timeout_ms).await?;
        return Ok(0);
    }

    // One future per registration, each reporting which registration it was.
    // The index travels in the output because the leftovers are renumbered
    // once the first of them completes.
    let waits: Vec<_> = watches
        .iter()
        .enumerate()
        .map(|(index, watch)| {
            Box::pin(async move {
                let ready = watch
                    .guard
                    .ready(watch.interest)
                    .await
                    .map(|guard| guard.ready());
                (index, ready)
            })
        })
        .collect();

    let mut all = select_all(waits);
    let first = match wait_span(timeout_ms) {
        // Block indefinitely: no timer at all, rather than a very long one.
        None => Some((&mut all).await),
        // Poll, do not block -- and see the note below on why this is not
        // simply a zero-length timeout.
        Some(span) if span.is_zero() => probe(&mut all).await,
        // Bounded. `tokio::time::timeout` polls its inner future before it
        // examines its deadline, so a descriptor that becomes ready in the same
        // instant is still reported.
        Some(span) => tokio::time::timeout(span, &mut all).await.ok(),
    };

    let Some(((index, outcome), _finished, pending)) = first else {
        // The span elapsed with nothing ready: the C's `0`.
        return Ok(0);
    };

    match outcome {
        Ok(ready) => record_ready(fds, &watches[index], ready),
        Err(error) => return wait_failure(&error),
    }

    // `poll(2)` reports EVERY ready descriptor, not just the first, so the
    // remaining registrations are swept without blocking. Each gets exactly
    // one more poll, which is enough to collect the readiness the reactor
    // delivered in the same batch as the completion above.
    for wait in pending {
        if let Ok((index, Ok(ready))) =
            tokio::time::timeout(Duration::ZERO, wait).await
        {
            record_ready(fds, &watches[index], ready);
        }
    }

    Ok(fds.iter().filter(|fd| !fd.revents.is_empty()).count())
}

// THE SINGLE-SOCKET CONVENIENCES

/// The read events [`socket_check`] requests.
///
/// `POLLRDNORM | POLLIN | POLLRDBAND | POLLPRI` (`select.c:143`, `:149`),
/// which with the aliases of `select.h:57-67` -- `POLLRDNORM` is `POLLIN`,
/// `POLLRDBAND` is `POLLPRI` -- is `POLLIN | POLLPRI`.
const CHECK_READ_EVENTS: PollEvents =
    PollEvents::from_bits(PollEvents::IN.bits() | PollEvents::PRI.bits());

/// The write events [`socket_check`] requests.
///
/// `POLLWRNORM | POLLOUT | POLLPRI` (`select.c:155`), which with
/// `POLLWRNORM` being `POLLOUT` is `POLLOUT | POLLPRI`.
const CHECK_WRITE_EVENTS: PollEvents =
    PollEvents::from_bits(PollEvents::OUT.bits() | PollEvents::PRI.bits());

/// The `CURL_CSELECT_*` bits a read descriptor's readiness produces.
fn cselect_of_read(revents: PollEvents, second: bool) -> u32 {
    let mut result = 0;
    if revents.intersects(PollEvents::IN | PollEvents::ERR | PollEvents::HUP) {
        result |= if second {
            CURL_CSELECT_IN2
        } else {
            CURL_CSELECT_IN
        };
    }
    if revents.intersects(PollEvents::PRI | PollEvents::NVAL) {
        result |= CURL_CSELECT_ERR;
    }
    result
}

/// The `CURL_CSELECT_*` bits a write descriptor's readiness produces.
///
/// `select.c:180-185`. Writability alone sets [`CURL_CSELECT_OUT`]; a hang-up
/// counts as an ERROR here where it counted as readability for a read
/// descriptor, because there is nothing useful left to write.
fn cselect_of_write(revents: PollEvents) -> u32 {
    let mut result = 0;
    if revents.intersects(PollEvents::OUT) {
        result |= CURL_CSELECT_OUT;
    }
    if revents.intersects(
        PollEvents::ERR | PollEvents::HUP | PollEvents::PRI | PollEvents::NVAL,
    ) {
        result |= CURL_CSELECT_ERR;
    }
    result
}

/// Waits on up to two read descriptors and one write descriptor --
/// `Curl_socket_check` (`lib/select.c:120-188`).
///
/// # Errors
///
/// As [`poll_sockets`].
///
/// # Panics
///
/// Requires a `tokio` runtime, as [`wait_ms`] does.
#[allow(dead_code)]
pub(crate) async fn socket_check(
    readfd0: Socket,
    readfd1: Socket,
    writefd: Socket,
    timeout_ms: TimeDiff,
) -> CodeResult<u32> {
    if !is_valid_sock(readfd0)
        && !is_valid_sock(readfd1)
        && !is_valid_sock(writefd)
    {
        // "no sockets, just wait" (`select.c:131-132`).
        wait_ms(timeout_ms).await?;
        return Ok(0);
    }

    // Built in the C's order -- first read, second read, write -- because the
    // result mapping walks the same order back (`select.c:140-158`).
    let mut probes: Vec<PollFd> = Vec::with_capacity(3);
    if is_valid_sock(readfd0) {
        probes.push(PollFd::new(readfd0, CHECK_READ_EVENTS));
    }
    if is_valid_sock(readfd1) {
        probes.push(PollFd::new(readfd1, CHECK_READ_EVENTS));
    }
    if is_valid_sock(writefd) {
        probes.push(PollFd::new(writefd, CHECK_WRITE_EVENTS));
    }

    // `r = Curl_poll(...); if(r <= 0) return r;` (`select.c:160-162`): the
    // error arm is the `?` and the timeout arm is the zero.
    if poll_sockets(&mut probes, timeout_ms).await? == 0 {
        return Ok(0);
    }

    let mut result = 0;
    let mut next = 0;
    if is_valid_sock(readfd0) {
        result |= cselect_of_read(probes[next].revents, false);
        next += 1;
    }
    if is_valid_sock(readfd1) {
        result |= cselect_of_read(probes[next].revents, true);
        next += 1;
    }
    if is_valid_sock(writefd) {
        result |= cselect_of_write(probes[next].revents);
    }
    Ok(result)
}

/// `SOCKET_READABLE(x, z)` (`lib/select.h:78-79`).
///
/// `Curl_socket_check(x, CURL_SOCKET_BAD, CURL_SOCKET_BAD, z)`, verbatim. Used
/// wherever curl waits for one socket to become readable -- for example
/// `lib/ftp.c:483` and `lib/cf-socket.c:2049`, both of which pass a zero
/// timeout to ask "is it readable right now?".
///
/// # Errors
///
/// As [`socket_check`].
#[allow(dead_code)]
pub(crate) async fn socket_readable(
    sock: Socket,
    timeout_ms: TimeDiff,
) -> CodeResult<u32> {
    socket_check(sock, CURL_SOCKET_BAD, CURL_SOCKET_BAD, timeout_ms).await
}

/// `SOCKET_WRITABLE(x, z)` (`lib/select.h:80-81`).
///
/// `Curl_socket_check(CURL_SOCKET_BAD, CURL_SOCKET_BAD, x, z)`, verbatim.
/// `lib/cf-socket.c:1285` uses it with a zero timeout to discover whether a
/// connection has completed, since a connecting socket becomes writable exactly
/// when it finishes.
///
/// # Errors
///
/// As [`socket_check`].
#[allow(dead_code)]
pub(crate) async fn socket_writable(
    sock: Socket,
    timeout_ms: TimeDiff,
) -> CodeResult<u32> {
    socket_check(CURL_SOCKET_BAD, CURL_SOCKET_BAD, sock, timeout_ms).await
}

// TESTS

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    use crate::trace::{TraceConfig, TraceState, WriterSink};

    /// A socket pair with both ends non-blocking, as a reactor expects.
    ///
    /// Returned whole so the caller keeps both ends alive: the descriptors are
    /// borrowed by number, so a dropped end is a closed descriptor.
    fn socket_pair() -> (UnixStream, UnixStream) {
        let (left, right) = UnixStream::pair().expect("a socket pair");
        left.set_nonblocking(true).expect("non-blocking left");
        right.set_nonblocking(true).expect("non-blocking right");
        (left, right)
    }

    /// Runs `body` against a tracer whose `MULTI` feature is verbose, and
    /// returns everything it wrote.
    ///
    /// The shape is `crate::trace`'s own test helper, narrowed to the one
    /// feature this module emits under.
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

    /// A pollset holding `sockets`, all watched for readability.
    fn pollset_of(sockets: &[Socket]) -> EasyPollset {
        let mut ps = EasyPollset::new();
        for sock in sockets {
            ps.add_in(*sock, None).expect("a valid descriptor");
        }
        ps
    }

    /// The descriptors a pollset holds, in order.
    fn sockets_of(ps: &EasyPollset) -> Vec<Socket> {
        ps.iter().map(|(sock, _)| sock).collect()
    }

    // --- the three public bitmaps -----------------------------------------

    /// `CURL_POLL_*` are the integers `include/curl/multi.h:283-287` defines.
    ///
    /// ABI-visible: they are the `what` argument of every
    /// `CURLMOPT_SOCKETFUNCTION` callback, so an application holds these
    /// numbers in its own code.
    #[test]
    fn poll_action_constants_are_the_public_integers() {
        assert_eq!(PollAction::NONE.bits(), 0);
        assert_eq!(PollAction::IN.bits(), 1);
        assert_eq!(PollAction::OUT.bits(), 2);
        assert_eq!(PollAction::INOUT.bits(), 3);
        assert_eq!(PollAction::REMOVE.bits(), 4);
    }

    /// `CURL_POLL_INOUT` is not merely 3, it is `IN | OUT`.
    #[test]
    fn inout_is_exactly_in_or_out() {
        assert_eq!(PollAction::INOUT, PollAction::IN | PollAction::OUT);
        assert!(PollAction::INOUT.contains_in());
        assert!(PollAction::INOUT.contains_out());
    }

    /// The bit operations are the ones `select.c:580-581` performs.
    #[test]
    fn poll_action_bit_operations_follow_the_c() {
        // `actions &= ~remove` then `actions |= add`.
        let held = PollAction::INOUT;
        let cleared = held & !PollAction::OUT;
        assert_eq!(cleared, PollAction::IN);
        assert_eq!(cleared | PollAction::OUT, PollAction::INOUT);

        assert!(PollAction::NONE.is_empty());
        assert!(!PollAction::IN.is_empty());
        assert!(!PollAction::IN.contains_out());
        assert!(!PollAction::OUT.contains_in());
        assert_eq!(PollAction::from_bits(3), PollAction::INOUT);
    }

    /// A failing assertion should name the flags, not print an integer.
    #[test]
    fn poll_action_renders_symbolically() {
        assert_eq!(format!("{:?}", PollAction::NONE), "CURL_POLL_NONE");
        assert_eq!(format!("{:?}", PollAction::INOUT), "CURL_POLL_INOUT");
        assert_eq!(format!("{:?}", PollAction::REMOVE), "CURL_POLL_REMOVE");
        assert_eq!(format!("{:?}", PollAction::from_bits(9)), "PollAction(9)");
    }

    /// `CURL_CSELECT_*` are the integers of `multi.h:291-293` plus the
    /// internal fourth of `select.h:72`.
    #[test]
    fn cselect_constants_are_the_public_integers() {
        assert_eq!(CURL_CSELECT_IN, 0x01);
        assert_eq!(CURL_CSELECT_OUT, 0x02);
        assert_eq!(CURL_CSELECT_ERR, 0x04);
        // Derived as `CURL_CSELECT_ERR << 1`, which evaluates to this.
        assert_eq!(CURL_CSELECT_IN2, 0x08);
    }

    /// `CURL_WAIT_POLL*` are the integers of `multi.h:110-112`.
    ///
    /// They deliberately do NOT coincide with the `POLL*` values, which is
    /// what the header's own comment at `:107-109` explains.
    #[test]
    fn wait_poll_constants_are_the_public_integers() {
        assert_eq!(CURL_WAIT_POLLIN, 0x0001);
        assert_eq!(CURL_WAIT_POLLPRI, 0x0002);
        assert_eq!(CURL_WAIT_POLLOUT, 0x0004);
        // The divergence, stated rather than implied: the internal write bit
        // is 0x04 and the application's is 0x04 too, but the internal
        // out-of-band bit is 0x02 where the application's write bit is 0x04.
        assert_ne!(CURL_WAIT_POLLPRI, PollEvents::OUT.bits());
    }

    /// `POLL*` are curl's own fallback numbers (`select.h:42-47`).
    #[test]
    fn poll_events_constants_are_curls_fallback_numbers() {
        assert_eq!(PollEvents::IN.bits(), 0x01);
        assert_eq!(PollEvents::PRI.bits(), 0x02);
        assert_eq!(PollEvents::OUT.bits(), 0x04);
        assert_eq!(PollEvents::ERR.bits(), 0x08);
        assert_eq!(PollEvents::HUP.bits(), 0x10);
        assert_eq!(PollEvents::NVAL.bits(), 0x20);
        assert!(PollEvents::NONE.is_empty());
        assert_eq!(
            format!("{:?}", PollEvents::IN | PollEvents::HUP),
            "POLLIN|POLLHUP"
        );
        assert_eq!(format!("{:?}", PollEvents::NONE), "0");
    }

    /// The events `Curl_socket_check` asks for, after the aliases collapse.
    #[test]
    fn the_check_event_masks_are_the_c_masks() {
        // `POLLRDNORM | POLLIN | POLLRDBAND | POLLPRI` (`select.c:143`).
        assert_eq!(CHECK_READ_EVENTS, PollEvents::IN | PollEvents::PRI);
        // `POLLWRNORM | POLLOUT | POLLPRI` (`select.c:155`).
        assert_eq!(CHECK_WRITE_EVENTS, PollEvents::OUT | PollEvents::PRI);
    }

    // --- the normalisation ------------------------------------------------

    /// `if(revents & POLLHUP) revents |= POLLIN` (`select.c:259-260`).
    ///
    /// A hang-up MUST present as readable, so the caller performs the
    /// zero-length read that tells it the stream ended.
    #[test]
    fn a_hangup_is_also_readable() {
        let normalised = PollEvents::HUP.normalise();
        assert!(normalised.intersects(PollEvents::IN));
        assert!(normalised.intersects(PollEvents::HUP));
        assert!(!normalised.intersects(PollEvents::OUT));
    }

    /// `if(revents & POLLERR) revents |= POLLIN | POLLOUT`
    /// (`select.c:261-262`).
    ///
    /// An error MUST present as both, so that whichever operation the caller
    /// attempts next returns the real failure.
    #[test]
    fn an_error_is_also_readable_and_writable() {
        let normalised = PollEvents::ERR.normalise();
        assert!(normalised.intersects(PollEvents::IN));
        assert!(normalised.intersects(PollEvents::OUT));
        assert!(normalised.intersects(PollEvents::ERR));
    }

    /// Ordinary readiness passes through untouched.
    #[test]
    fn normalisation_leaves_ordinary_readiness_alone() {
        assert_eq!(PollEvents::IN.normalise(), PollEvents::IN);
        assert_eq!(PollEvents::OUT.normalise(), PollEvents::OUT);
        assert_eq!(PollEvents::NONE.normalise(), PollEvents::NONE);
        assert_eq!(
            (PollEvents::IN | PollEvents::OUT).normalise(),
            PollEvents::IN | PollEvents::OUT
        );
    }

    /// A reactor readiness becomes the `poll(2)` bits it corresponds to.
    #[test]
    fn readiness_maps_onto_poll_events() {
        assert_eq!(events_of_ready(Ready::EMPTY), PollEvents::NONE);
        assert_eq!(events_of_ready(Ready::READABLE), PollEvents::IN);
        assert_eq!(events_of_ready(Ready::WRITABLE), PollEvents::OUT);
        assert_eq!(
            events_of_ready(Ready::READ_CLOSED),
            PollEvents::IN | PollEvents::HUP
        );
        assert_eq!(
            events_of_ready(Ready::WRITE_CLOSED),
            PollEvents::OUT | PollEvents::HUP
        );
        assert_eq!(events_of_ready(Ready::ERROR), PollEvents::ERR);
        assert_eq!(
            events_of_ready(Ready::READABLE | Ready::WRITABLE),
            PollEvents::IN | PollEvents::OUT
        );
        // And the error readiness carries no direction of its own, which is
        // exactly why the normalisation has to add both.
        assert!(!events_of_ready(Ready::ERROR).intersects(PollEvents::IN));
        assert!(!events_of_ready(Ready::ERROR).intersects(PollEvents::OUT));
        assert_eq!(
            revents_of(PollEvents::IN | PollEvents::OUT, Ready::ERROR),
            PollEvents::IN | PollEvents::OUT | PollEvents::ERR
        );
    }

    /// `poll(2)` reports only what was asked for -- plus three bits.
    #[test]
    fn revents_are_masked_by_what_was_requested() {
        // Watched for reading, and the descriptor is also writable: the write
        // readiness is not reported, because it was not requested.
        let reported =
            revents_of(PollEvents::IN, Ready::READABLE | Ready::WRITABLE);
        assert_eq!(reported, PollEvents::IN);

        // Watched for writing, and only readable: nothing is reported.
        assert_eq!(
            revents_of(PollEvents::OUT, Ready::READABLE),
            PollEvents::NONE
        );
    }

    /// The unsolicited bits survive the mask, and the normalisation then adds
    /// to them WITHOUT re-applying it.
    ///
    /// This is the composition `select.c` performs in that order, and it is
    /// why a write-only watch still comes back readable on a hang-up.
    #[test]
    fn unsolicited_bits_survive_the_mask() {
        let reported = revents_of(PollEvents::OUT, Ready::READ_CLOSED);
        assert!(reported.intersects(PollEvents::HUP));
        assert!(
            reported.intersects(PollEvents::IN),
            "the normalisation is applied after the mask, not before it"
        );

        let failed = revents_of(PollEvents::IN, Ready::ERROR);
        assert!(failed.intersects(PollEvents::ERR));
        assert!(failed.intersects(PollEvents::IN));
        assert!(
            failed.intersects(PollEvents::OUT),
            "an error reports both directions even when one was not requested"
        );
    }

    /// Every registration asks for errors, whatever else it asks for.
    #[test]
    fn interest_always_includes_errors() {
        assert!(interest_of(PollEvents::NONE).is_error());
        assert!(interest_of(PollEvents::IN).is_readable());
        assert!(interest_of(PollEvents::IN).is_error());
        assert!(!interest_of(PollEvents::IN).is_writable());
        assert!(interest_of(PollEvents::OUT).is_writable());
        let both = interest_of(PollEvents::IN | PollEvents::OUT);
        assert!(both.is_readable() && both.is_writable() && both.is_error());
    }

    // --- the pollset ------------------------------------------------------

    /// `VALID_SOCK(s)` is `s >= 0` (`select.h:100`).
    #[test]
    fn is_valid_sock_is_the_c_predicate() {
        assert!(is_valid_sock(0));
        assert!(is_valid_sock(3));
        assert!(!is_valid_sock(CURL_SOCKET_BAD));
        assert!(!is_valid_sock(-2));
        assert_eq!(CURL_SOCKET_BAD, -1);
    }

    /// A fresh pollset is empty and starts at `EZ_POLLSET_DEF_COUNT`.
    #[test]
    fn a_fresh_pollset_is_empty_at_the_default_capacity() {
        let ps = EasyPollset::new();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
        assert_eq!(ps.capacity(), EZ_POLLSET_DEF_COUNT);
        assert_eq!(EZ_POLLSET_DEF_COUNT, 2);
        assert_eq!(ps, EasyPollset::default());
    }

    /// Adding both flags separately accumulates, and neither loses the other.
    #[test]
    fn add_in_then_add_out_is_inout() {
        let mut ps = EasyPollset::new();
        ps.add_in(7, None).expect("valid");
        assert_eq!(ps.action_of(7), PollAction::IN);
        ps.add_out(7, None).expect("valid");
        assert_eq!(ps.action_of(7), PollAction::INOUT);
        assert_eq!(ps.len(), 1, "the same descriptor is one entry");

        ps.add_inout(8, None).expect("valid");
        assert_eq!(ps.action_of(8), PollAction::INOUT);

        ps.remove_in(7, None).expect("valid");
        assert_eq!(ps.action_of(7), PollAction::OUT);
        ps.remove_out(7, None).expect("valid");
        assert_eq!(ps.action_of(7), PollAction::NONE);
        assert_eq!(sockets_of(&ps), vec![8]);
    }

    /// Removal compacts the tail down, exactly as `memmove` does
    /// (`select.c:584-590`).
    ///
    /// This is the test that forbids [`Vec::swap_remove`]: with it the
    /// surviving order would be `[A, C]` reversed into `[C, A]`, silently.
    #[test]
    fn removal_preserves_insertion_order() {
        let mut ps = pollset_of(&[11, 12, 13]);
        assert_eq!(sockets_of(&ps), vec![11, 12, 13]);

        // Drop the MIDDLE one, which is the only position where the two
        // removal strategies differ.
        ps.remove_in(12, None).expect("valid");
        assert_eq!(sockets_of(&ps), vec![11, 13]);

        // And again with a longer tail, so a single-element tail cannot hide a
        // reordering.
        let mut longer = pollset_of(&[21, 22, 23, 24, 25]);
        longer.remove_in(22, None).expect("valid");
        assert_eq!(sockets_of(&longer), vec![21, 23, 24, 25]);
    }

    /// An entry whose actions reach zero is REMOVED, not left holding
    /// `CURL_POLL_NONE` (`select.c:582-591`).
    #[test]
    fn an_entry_whose_actions_reach_zero_is_removed() {
        let mut ps = EasyPollset::new();
        ps.add_inout(31, None).expect("valid");
        assert_eq!(ps.len(), 1);

        ps.remove_in(31, None).expect("valid");
        assert_eq!(ps.len(), 1, "one flag left, so the entry stays");

        ps.remove_out(31, None).expect("valid");
        assert_eq!(ps.len(), 0, "no flags left, so the entry goes");
        assert!(ps.is_empty());
        assert_eq!(ps.action_of(31), PollAction::NONE);
    }

    /// `set_in_only` clears a previously set write interest
    /// (`select.h:174-176`).
    ///
    /// `cf_socket_adjust_pollset` relies on it for a listening socket
    /// (`lib/cf-socket.c:1341`).
    #[test]
    fn set_in_only_clears_a_previous_out() {
        let mut ps = EasyPollset::new();
        ps.add_out(41, None).expect("valid");
        ps.set_in_only(41, None).expect("valid");
        assert_eq!(ps.action_of(41), PollAction::IN);
        assert_eq!(ps.check(41), (true, false));
    }

    /// `set_out_only` clears a previously set read interest
    /// (`select.h:177-179`).
    ///
    /// The socket filter uses it while a connection is still completing
    /// (`lib/cf-socket.c:1346`).
    #[test]
    fn set_out_only_clears_a_previous_in() {
        let mut ps = EasyPollset::new();
        ps.add_in(42, None).expect("valid");
        ps.set_out_only(42, None).expect("valid");
        assert_eq!(ps.action_of(42), PollAction::OUT);
        assert_eq!(ps.check(42), (false, true));
    }

    /// `Curl_pollset_set` is absolute, so both booleans false removes the
    /// socket (`select.c:634-643`).
    #[test]
    fn set_with_both_false_removes_the_socket() {
        let mut ps = EasyPollset::new();
        ps.set(51, true, true, None).expect("valid");
        assert_eq!(ps.action_of(51), PollAction::INOUT);

        ps.set(51, true, false, None).expect("valid");
        assert_eq!(ps.action_of(51), PollAction::IN);

        ps.set(51, false, false, None).expect("valid");
        assert!(ps.is_empty(), "wanting neither removes the entry");

        // And on a socket that was never there, it is a no-op rather than an
        // error: every filter in a chain says "not mine" this way.
        ps.set(52, false, false, None).expect("valid");
        assert!(ps.is_empty());
    }

    /// `Curl_pollset_check` reports FALSE for both on an absent socket
    /// (`select.c:700`).
    #[test]
    fn check_on_an_absent_socket_wants_neither() {
        let ps = pollset_of(&[61]);
        assert_eq!(ps.check(61), (true, false));
        assert_eq!(ps.check(62), (false, false));
        assert_eq!(ps.action_of(62), PollAction::NONE);
    }

    /// `want_recv` and `want_send` read the two flags (`select.c:703-727`).
    #[test]
    fn want_recv_and_want_send_read_the_flags() {
        let mut ps = EasyPollset::new();
        ps.add_in(71, None).expect("valid");
        ps.add_out(72, None).expect("valid");

        assert!(ps.want_recv(71));
        assert!(!ps.want_send(71));
        assert!(!ps.want_recv(72));
        assert!(ps.want_send(72));
        // Absent: neither.
        assert!(!ps.want_recv(73));
        assert!(!ps.want_send(73));
    }

    /// The growth rule is `CURLMAX(count * 2, 8)` (`select.c:598`).
    #[test]
    fn the_growth_rule_is_double_or_eight() {
        // The floor bites first, twice: 2 * 2 is 4, and 4 * 2 is 8.
        assert_eq!(grown_capacity(2), 8);
        assert_eq!(grown_capacity(4), 8);
        // Then doubling takes over.
        assert_eq!(grown_capacity(8), 16);
        assert_eq!(grown_capacity(16), 32);
        // The C's unsigned multiplication wraps, which is what its own guard
        // at `:604-605` catches and turns into `CURLE_OUT_OF_MEMORY`.
        assert!(grown_capacity(0x8000_0000) <= 0x8000_0000);
    }

    /// Growing past the default capacity keeps every entry in order.
    #[test]
    fn growth_preserves_order() {
        let wanted: Vec<Socket> = (100..112).collect();
        let ps = pollset_of(&wanted);

        assert_eq!(ps.len(), wanted.len());
        assert_eq!(sockets_of(&ps), wanted);
        assert!(
            ps.capacity() >= 16,
            "twelve entries need two growths from two, not one"
        );
        // 2 -> 8 -> 16, which is what a reader of `--trace` output sees.
        assert_eq!(ps.capacity(), 16);
    }

    /// The growth trace names both capacities -- `select.c:602-603`.
    ///
    /// The text is the C's, verbatim. The C's macro additionally prints the
    /// transfer's multi state, which is read out of the easy handle and is
    /// therefore unavailable to this leaf module; the feature label and the
    /// message are the same.
    #[test]
    fn the_growth_trace_names_both_capacities() {
        let output = multi_trace(|tracer| {
            let mut ps = EasyPollset::new();
            for sock in 200..203 {
                ps.add_in(sock, Some(tracer)).expect("valid");
            }
            assert_eq!(ps.capacity(), 8);
        });

        assert_eq!(output, "* [MULTI] growing pollset capacity from 2 to 8\n");
    }

    /// Tracing is optional, and its absence changes nothing.
    #[test]
    fn the_pollset_grows_without_a_tracer() {
        let mut ps = EasyPollset::new();
        for sock in 300..309 {
            ps.add_in(sock, None).expect("valid");
        }
        assert_eq!(ps.len(), 9);
        assert_eq!(ps.capacity(), 16);
    }

    /// `Curl_pollset_reset` empties the set and keeps the capacity
    /// (`select.c:487-498`).
    #[test]
    fn reset_keeps_the_capacity_and_drops_the_entries() {
        let mut ps = pollset_of(&[401, 402, 403]);
        let grown = ps.capacity();
        assert_eq!(grown, 8);

        ps.reset();
        assert!(ps.is_empty());
        assert_eq!(ps.capacity(), grown, "the C keeps `count` across a reset");
    }

    /// The shutdown loop's pattern: ONE pollset, reset between connections.
    ///
    /// `Curl_cshutdn_add_pollfds` and `Curl_cshutdn_add_waitfds`
    /// (`lib/cshutdn.c:474-533`) both initialise a single pollset and reset it
    /// per connection while accumulating into a shared buffer. Nothing may
    /// survive the reset into the next round.
    #[test]
    fn a_pollset_reused_across_connections_accumulates_nothing() {
        let mut ps = EasyPollset::new();
        let mut cpfds = PollFds::new();
        let mut storage = [WaitFd::default(); 8];
        let mut needed = 0;

        {
            let mut cwfds = WaitFds::new(&mut storage);
            for connection in 0..3 {
                ps.reset();
                assert!(ps.is_empty(), "the reset must leave nothing behind");
                ps.add_in(500 + connection, None).expect("valid");
                assert_eq!(ps.len(), 1, "one connection contributes one");
                cpfds.add_ps(&ps);
                needed += cwfds.add_ps(&ps);
            }
            assert_eq!(cwfds.len(), 3);
        }

        assert_eq!(needed, 3);
        assert_eq!(cpfds.len(), 3);
        assert_eq!(
            cpfds
                .as_slice()
                .iter()
                .map(|fd| fd.sock)
                .collect::<Vec<_>>(),
            vec![500, 501, 502]
        );
        assert_eq!(
            storage[..3].iter().map(|fd| fd.fd).collect::<Vec<_>>(),
            vec![500, 501, 502]
        );
    }

    /// `Curl_pollset_move` empties the source and replaces the destination
    /// (`select.c:537-556`).
    #[test]
    fn take_from_moves_the_contents_and_empties_the_source() {
        let mut from = pollset_of(&[601, 602, 603]);
        let moved_capacity = from.capacity();
        let mut to = pollset_of(&[999]);

        to.take_from(&mut from);

        assert_eq!(sockets_of(&to), vec![601, 602, 603]);
        assert_eq!(to.capacity(), moved_capacity, "the capacity travels");
        assert!(from.is_empty(), "the source is left empty");
        assert_eq!(
            from.capacity(),
            EZ_POLLSET_DEF_COUNT,
            "the source is re-initialised, as `Curl_pollset_init(from)` does"
        );
        assert_eq!(to.action_of(999), PollAction::NONE, "`to` was replaced");
    }

    /// A descriptor that is not a descriptor trips the debug assertion.
    ///
    /// `DEBUGASSERT(VALID_SOCK(sock))` (`select.c:571`) is what a debug build
    /// does with it; the release build's answer is the companion test below.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "a pollset change needs a descriptor")]
    fn a_bad_socket_trips_the_debug_assertion() {
        let mut ps = EasyPollset::new();
        let _ = ps.add_in(CURL_SOCKET_BAD, None);
    }

    /// Without debug assertions, a bad descriptor is REPORTED, not ignored.
    ///
    /// `return CURLE_BAD_FUNCTION_ARGUMENT` (`select.c:572-573`).
    #[test]
    #[cfg(not(debug_assertions))]
    fn a_bad_socket_is_rejected_in_a_release_build() {
        let mut ps = EasyPollset::new();
        assert_eq!(
            ps.add_in(CURL_SOCKET_BAD, None),
            Err(CURLcode::BadFunctionArgument)
        );
        assert!(ps.is_empty());
    }

    // --- the two aggregation buffers ---------------------------------------

    /// `Curl_pollfds_add_ps` folds a descriptor two transfers share
    /// (`select.c:424`, with `fold = TRUE`).
    #[test]
    fn pollfds_add_ps_folds_a_shared_descriptor() {
        let mut reading = EasyPollset::new();
        reading.add_in(701, None).expect("valid");
        let mut writing = EasyPollset::new();
        writing.add_out(701, None).expect("valid");
        writing.add_in(702, None).expect("valid");

        let mut cpfds = PollFds::new();
        cpfds.add_ps(&reading);
        cpfds.add_ps(&writing);

        assert_eq!(cpfds.len(), 2, "the shared descriptor folded");
        let entries = cpfds.as_slice();
        assert_eq!(entries[0].sock, 701);
        assert_eq!(
            entries[0].events,
            PollEvents::IN | PollEvents::OUT,
            "the folded entry carries the union of both interests"
        );
        assert_eq!(entries[1].sock, 702);
        assert_eq!(entries[1].events, PollEvents::IN);
    }

    /// An empty pollset contributes nothing, and a reset buffer starts over.
    #[test]
    fn pollfds_reset_starts_over() {
        let mut cpfds = PollFds::new();
        cpfds.add_ps(&EasyPollset::new());
        assert!(cpfds.is_empty());

        cpfds.add_ps(&pollset_of(&[801, 802]));
        assert_eq!(cpfds.len(), 2);
        cpfds.reset();
        assert!(cpfds.is_empty());
        assert_eq!(cpfds.as_slice(), &[]);
    }

    /// `Curl_pollfds_add_sock` does not fold, and the wakeup descriptor it
    /// carries never reaches the application.
    ///
    /// `lib/multi.c:1436` adds `wakeup_pair[0]` to the INTERNAL buffer only.
    /// `curl_multi_wait` fills a separate array for its caller, and this test
    /// is the asymmetry: the same round of accounting puts three descriptors in
    /// the internal buffer and two in the application's.
    #[test]
    fn the_wakeup_descriptor_never_reaches_the_waitfds() {
        let ps = pollset_of(&[901, 902]);

        let mut cpfds = PollFds::new();
        cpfds.add_ps(&ps);
        // The wakeup channel, with the events `lib/multi.c:1436` requests.
        cpfds.add_sock(903, PollEvents::IN);

        let mut storage = [WaitFd::default(); 8];
        let mut cwfds = WaitFds::new(&mut storage);
        let needed = cwfds.add_ps(&ps);

        assert_eq!(cpfds.len(), 3, "the internal buffer watches the wakeup");
        assert_eq!(needed, 2);
        assert_eq!(cwfds.len(), 2, "the application's array does not");
        assert!(
            cwfds.filled().iter().all(|fd| fd.fd != 903),
            "an internal descriptor must never appear in a public array"
        );

        // And it really does not fold: the same descriptor twice is two
        // entries, because `Curl_pollfds_add_sock` passes `fold = FALSE`.
        cpfds.add_sock(903, PollEvents::IN);
        assert_eq!(cpfds.len(), 4);
    }

    /// `cwfds_add_sock` folds a repeated descriptor and counts it ONCE
    /// (`select.c:450-456`).
    ///
    /// The count is what `curl_multi_wait` reports through `numfds`, so
    /// double-counting is an ABI-visible defect.
    #[test]
    fn waitfds_folds_a_repeated_descriptor_and_counts_it_once() {
        let mut reading = EasyPollset::new();
        reading.add_in(1001, None).expect("valid");
        let mut writing = EasyPollset::new();
        writing.add_out(1001, None).expect("valid");

        let mut storage = [WaitFd::default(); 4];
        let mut cwfds = WaitFds::new(&mut storage);
        let first = cwfds.add_ps(&reading);
        let second = cwfds.add_ps(&writing);

        assert_eq!(first, 1);
        assert_eq!(second, 0, "a folded descriptor needs no further slot");
        assert_eq!(cwfds.len(), 1);
        assert_eq!(
            storage[0].events,
            CURL_WAIT_POLLIN | CURL_WAIT_POLLOUT,
            "the events are OR-ed into the entry that already existed"
        );
        assert_eq!(storage[0].fd, 1001);
    }

    /// Counting mode reports what would have been needed and writes nothing
    /// (`select.c:446-449`).
    #[test]
    fn waitfds_counting_mode_needs_no_storage() {
        let ps = pollset_of(&[1101, 1102, 1103]);
        let mut counter = WaitFds::counting();

        assert_eq!(counter.add_ps(&ps), 3);
        assert_eq!(counter.len(), 0, "counting mode fills no slot");
        assert!(counter.is_empty());
        assert_eq!(counter.filled(), &[]);

        // Counting is cumulative across pollsets, exactly as
        // `Curl_cshutdn_add_waitfds` accumulates it.
        assert_eq!(counter.add_ps(&pollset_of(&[1104])), 1);
    }

    /// A full array still reports what was needed (`select.c:459-464`).
    ///
    /// This is how an application discovers that the array it passed was too
    /// small: `numfds` exceeds the size it supplied.
    #[test]
    fn waitfds_overflow_still_reports_what_was_needed() {
        let ps = pollset_of(&[1201, 1202, 1203, 1204]);
        let mut storage = [WaitFd::default(); 2];
        let mut cwfds = WaitFds::new(&mut storage);

        let needed = cwfds.add_ps(&ps);

        assert_eq!(needed, 4, "all four were needed");
        assert_eq!(cwfds.len(), 2, "only two were recorded");
        assert_eq!(
            cwfds.filled().iter().map(|fd| fd.fd).collect::<Vec<_>>(),
            vec![1201, 1202],
            "the first two, in order"
        );
    }

    /// The application's out-of-band bit is defined and never set
    /// (`select.c:477-480`).
    #[test]
    fn waitfds_never_set_the_priority_bit() {
        let mut ps = EasyPollset::new();
        ps.add_inout(1301, None).expect("valid");

        let mut storage = [WaitFd::default(); 2];
        let mut cwfds = WaitFds::new(&mut storage);
        cwfds.add_ps(&ps);

        assert_eq!(storage[0].events, CURL_WAIT_POLLIN | CURL_WAIT_POLLOUT);
        assert_eq!(storage[0].events & CURL_WAIT_POLLPRI, 0);
        assert_eq!(storage[0].revents, 0, "a wait writes that, not the adding");
        assert_eq!(wait_events_of(PollAction::NONE), 0);
        assert_eq!(wait_events_of(PollAction::IN), CURL_WAIT_POLLIN);
        assert_eq!(wait_events_of(PollAction::OUT), CURL_WAIT_POLLOUT);
    }

    // --- the timeout conventions ------------------------------------------

    /// The three meanings of a raw poll timeout are three distinct outcomes.
    ///
    /// Collapsing any two of them "turns a poll into a hang or a wait into a
    /// busy spin", as `crate::util::timediff` puts it.
    #[test]
    fn the_three_timeout_meanings_are_distinct() {
        // Negative: block indefinitely, so there is no span at all.
        assert_eq!(wait_span(-1), None);
        assert_eq!(wait_span(TimeDiff::MIN), None);
        // Zero: poll without blocking.
        assert_eq!(wait_span(0), Some(Duration::ZERO));
        // Positive: wait that long.
        assert_eq!(wait_span(250), Some(Duration::from_millis(250)));
        // And the three really are different from each other.
        assert_ne!(wait_span(-1), wait_span(0));
        assert_ne!(wait_span(0), wait_span(250));
    }

    /// A very long timeout is clamped, as `select.c:238-241` clamps it.
    #[test]
    fn an_enormous_timeout_is_clamped_to_the_c_bound() {
        let clamped = Duration::from_millis(u64::from(i32::MAX.unsigned_abs()));
        assert_eq!(wait_span(TimeDiff::MAX), Some(clamped));
        assert_eq!(wait_span(TimeDiff::from(i32::MAX) + 1), Some(clamped));
        // Anything within the bound is untouched.
        assert_eq!(
            wait_span(TimeDiff::from(i32::MAX)),
            Some(Duration::from_millis(u64::from(i32::MAX.unsigned_abs())))
        );
    }

    /// A computed deadline that has already passed is a TIMEOUT, never an
    /// indefinite wait.
    ///
    /// `Curl_timeleft_ms` reports expiry as a negative value because zero
    /// already means "no limit is configured" (`lib/connect.c:128-129`), and
    /// every C call site tests for it before waiting.
    #[test]
    fn a_computed_deadline_that_has_passed_is_a_timeout() {
        assert_eq!(timeleft_to_wait(-1), Err(CURLcode::OperationTimedout));
        assert_eq!(
            timeleft_to_wait(TimeDiff::MIN),
            Err(CURLcode::OperationTimedout)
        );
        // Zero is "no limit", and the policy for it belongs to the caller, so
        // it comes back unchanged rather than turned into one of the three
        // different things the C's call sites turn it into.
        assert_eq!(timeleft_to_wait(0), Ok(0));
        assert_eq!(timeleft_to_wait(1_000), Ok(1_000));
    }

    /// An interrupted wait is a timeout, not a failure (`select.c:249-253`).
    #[test]
    fn an_interrupted_wait_is_a_timeout() {
        let interrupted = io::Error::from(io::ErrorKind::Interrupted);
        assert_eq!(wait_failure(&interrupted), Ok(0));

        // Anything else is the C's `-1`, which its callers turn into exactly
        // this code (`lib/easy.c:564`).
        let refused = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(wait_failure(&refused), Err(CURLcode::UnrecoverablePoll));
        let bad = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(wait_failure(&bad), Err(CURLcode::UnrecoverablePoll));
    }

    /// The `CURL_CSELECT_*` mapping of `select.c:166-185`.
    #[test]
    fn readiness_maps_onto_the_cselect_bitmap() {
        // Readability, on the first and then the second read descriptor.
        assert_eq!(cselect_of_read(PollEvents::IN, false), CURL_CSELECT_IN);
        assert_eq!(cselect_of_read(PollEvents::IN, true), CURL_CSELECT_IN2);

        // An error or a hang-up counts as readability, because the read that
        // follows is what surfaces it.
        assert_eq!(cselect_of_read(PollEvents::HUP, false), CURL_CSELECT_IN);
        assert_eq!(
            cselect_of_read(PollEvents::ERR, false),
            CURL_CSELECT_IN,
            "the error bit alone sets readability, not the error result"
        );

        // Out-of-band data and an invalid descriptor are errors.
        assert_eq!(cselect_of_read(PollEvents::PRI, false), CURL_CSELECT_ERR);
        assert_eq!(cselect_of_read(PollEvents::NVAL, false), CURL_CSELECT_ERR);
        assert_eq!(cselect_of_read(PollEvents::NONE, false), 0);

        // The write descriptor: writability, and everything else an error.
        assert_eq!(cselect_of_write(PollEvents::OUT), CURL_CSELECT_OUT);
        assert_eq!(cselect_of_write(PollEvents::ERR), CURL_CSELECT_ERR);
        assert_eq!(
            cselect_of_write(PollEvents::HUP),
            CURL_CSELECT_ERR,
            "a hang-up is readability for a reader and an error for a writer"
        );
        assert_eq!(cselect_of_write(PollEvents::NVAL), CURL_CSELECT_ERR);
        assert_eq!(cselect_of_write(PollEvents::NONE), 0);
        assert_eq!(
            cselect_of_write(PollEvents::OUT | PollEvents::ERR),
            CURL_CSELECT_OUT | CURL_CSELECT_ERR
        );
    }

    // --- the waits themselves ---------------------------------------------

    /// A zero delay returns at once, without a timer and without a runtime.
    ///
    /// `if(!timeout_ms) return 0;` (`wait.c:62-63`). Driven by a bare executor
    /// rather than a `tokio` runtime precisely to prove that the early return
    /// happens before any timer is created.
    #[test]
    fn wait_ms_zero_returns_at_once() {
        assert_eq!(futures::executor::block_on(wait_ms(0)), Ok(()));
    }

    /// A negative delay is REJECTED (`wait.c:64-67`).
    ///
    /// "Waiting indefinitely with this function is not allowed" -- the exact
    /// opposite of what the same value means to [`poll_sockets`], and the
    /// asymmetry the module documentation tabulates.
    #[test]
    fn wait_ms_rejects_a_negative_delay() {
        assert_eq!(
            futures::executor::block_on(wait_ms(-1)),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(
            futures::executor::block_on(wait_ms(TimeDiff::MIN)),
            Err(CURLcode::BadFunctionArgument)
        );
    }

    /// A positive delay sleeps and then succeeds.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(miri, ignore = "a tokio timer needs the runtime's driver")]
    async fn wait_ms_sleeps_for_a_positive_delay() {
        assert_eq!(wait_ms(250).await, Ok(()));
    }

    /// An empty pollset delays rather than failing (`select.c:657-658`), and
    /// inherits [`wait_ms`]'s rejection of a negative timeout.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(miri, ignore = "a tokio timer needs the runtime's driver")]
    async fn an_empty_pollset_delays_instead_of_failing() {
        let ps = EasyPollset::new();
        assert_eq!(ps.poll(0).await, Ok(0));
        assert_eq!(ps.poll(10).await, Ok(0));
        assert_eq!(ps.poll(-1).await, Err(CURLcode::BadFunctionArgument));
    }

    /// No valid descriptor means "just wait" (`select.c:217-228`).
    #[tokio::test(start_paused = true)]
    #[cfg_attr(miri, ignore = "a tokio timer needs the runtime's driver")]
    async fn a_set_of_absent_descriptors_just_waits() {
        let mut none = [
            PollFd::new(CURL_SOCKET_BAD, PollEvents::IN),
            PollFd::new(CURL_SOCKET_BAD, PollEvents::OUT),
        ];
        assert_eq!(poll_sockets(&mut none, 5).await, Ok(0));
        assert_eq!(poll_sockets(&mut [], 5).await, Ok(0));
        // The negative timeout now means "invalid", because the delegate is
        // `wait_ms` and not the reactor.
        assert_eq!(
            poll_sockets(&mut none, -1).await,
            Err(CURLcode::BadFunctionArgument)
        );
        // All three sockets absent takes the same path in `socket_check`.
        assert_eq!(
            socket_check(CURL_SOCKET_BAD, CURL_SOCKET_BAD, CURL_SOCKET_BAD, 5)
                .await,
            Ok(0)
        );
    }

    /// A fresh socket pair is writable and not readable.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn a_socket_pair_starts_writable() {
        let (left, _right) = socket_pair();
        let mut fds = [PollFd::new(
            left.as_raw_fd(),
            PollEvents::IN | PollEvents::OUT,
        )];

        assert_eq!(poll_sockets(&mut fds, 50).await, Ok(1));
        assert!(fds[0].revents.intersects(PollEvents::OUT));
        assert!(!fds[0].revents.intersects(PollEvents::IN));

        // The convenience wrappers agree.
        assert_eq!(
            socket_writable(left.as_raw_fd(), 50).await,
            Ok(CURL_CSELECT_OUT)
        );
        assert_eq!(socket_readable(left.as_raw_fd(), 0).await, Ok(0));
    }

    /// Bytes written by the peer make a descriptor readable.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn written_bytes_make_a_descriptor_readable() {
        use std::io::Write;

        let (left, mut right) = socket_pair();
        right
            .write_all(b"curl")
            .expect("the pair accepts four bytes");

        let mut fds = [PollFd::new(left.as_raw_fd(), PollEvents::IN)];
        assert_eq!(poll_sockets(&mut fds, 200).await, Ok(1));
        assert!(fds[0].revents.intersects(PollEvents::IN));

        assert_eq!(
            socket_readable(left.as_raw_fd(), 200).await,
            Ok(CURL_CSELECT_IN)
        );
        // As the SECOND read descriptor, the same readiness is reported in the
        // internal bit instead -- which is why that bit exists.
        assert_eq!(
            socket_check(
                CURL_SOCKET_BAD,
                left.as_raw_fd(),
                CURL_SOCKET_BAD,
                200
            )
            .await,
            Ok(CURL_CSELECT_IN2)
        );
    }

    /// A ZERO timeout reports readiness that is already present.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn a_zero_timeout_still_sees_what_is_already_ready() {
        use std::io::Write;

        let (left, mut right) = socket_pair();

        // A fresh pair is writable, and the connect check must see it NOW.
        assert_eq!(
            socket_writable(left.as_raw_fd(), 0).await,
            Ok(CURL_CSELECT_OUT),
            "a zero timeout must report writability that is already present"
        );

        // Nothing has been sent, so the same descriptor is not yet readable.
        assert_eq!(socket_readable(left.as_raw_fd(), 0).await, Ok(0));

        // Once the peer writes, the zero-timeout read check must see that too.
        right
            .write_all(b"curl")
            .expect("the pair accepts four bytes");
        assert_eq!(
            socket_readable(left.as_raw_fd(), 0).await,
            Ok(CURL_CSELECT_IN),
            "a zero timeout must report readability that is already present"
        );

        // And through the array form, with both directions at once.
        let mut fds = [PollFd::new(
            left.as_raw_fd(),
            PollEvents::IN | PollEvents::OUT,
        )];
        assert_eq!(poll_sockets(&mut fds, 0).await, Ok(1));
        assert_eq!(fds[0].revents, PollEvents::IN | PollEvents::OUT);
    }

    /// The same probe on a MULTI-THREADED runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn a_zero_timeout_probe_works_on_a_multi_thread_runtime() {
        let (left, _right) = socket_pair();

        assert_eq!(
            socket_writable(left.as_raw_fd(), 0).await,
            Ok(CURL_CSELECT_OUT)
        );
        assert_eq!(socket_readable(left.as_raw_fd(), 0).await, Ok(0));
    }

    /// A pollset probed with a zero timeout answers the same way.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn a_pollset_probed_without_blocking_reports_readiness() {
        let (left, _right) = socket_pair();
        let mut ps = EasyPollset::new();
        ps.add_out(left.as_raw_fd(), None).expect("valid");

        assert_eq!(ps.poll(0).await, Ok(1));

        ps.set_in_only(left.as_raw_fd(), None).expect("valid");
        assert_eq!(ps.poll(0).await, Ok(0), "and idle means idle");
    }

    /// A hang-up reads as readable, on a real descriptor.
    ///
    /// The pure normalisation test above pins the arithmetic; this pins that
    /// the reactor's own vocabulary reaches it. Dropping the peer closes its
    /// end, which is what a server closing a connection looks like.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn a_hangup_on_a_real_pair_reads_as_readable() {
        let (left, right) = socket_pair();
        drop(right);

        // Watched for WRITING only, so the readability can only have come
        // from the normalisation.
        let mut fds = [PollFd::new(left.as_raw_fd(), PollEvents::OUT)];
        assert_eq!(poll_sockets(&mut fds, 200).await, Ok(1));
        assert!(
            fds[0].revents.intersects(PollEvents::IN),
            "a hang-up must present as readable: {:?}",
            fds[0].revents
        );
    }

    /// Nothing happening is a timeout, which is `Ok(0)` and not an error.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn an_idle_descriptor_times_out() {
        let (left, _right) = socket_pair();
        let mut fds = [PollFd::new(left.as_raw_fd(), PollEvents::IN)];

        assert_eq!(poll_sockets(&mut fds, 20).await, Ok(0));
        assert!(fds[0].revents.is_empty());
    }

    /// Every ready descriptor is reported, not merely the first.
    ///
    /// `Curl_poll` returns "the number of structures with non zero revent
    /// fields" (`select.c:201`), which `curl_multi_wait` passes to its caller.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn every_ready_descriptor_is_counted() {
        let (first, _first_peer) = socket_pair();
        let (second, _second_peer) = socket_pair();

        let mut fds = [
            PollFd::new(first.as_raw_fd(), PollEvents::OUT),
            PollFd::new(second.as_raw_fd(), PollEvents::OUT),
        ];
        assert_eq!(poll_sockets(&mut fds, 200).await, Ok(2));
        assert!(fds[0].revents.intersects(PollEvents::OUT));
        assert!(fds[1].revents.intersects(PollEvents::OUT));
    }

    /// One descriptor named twice is registered once and reported twice.
    ///
    /// `Curl_socket_check` does exactly this when a caller hands it the same
    /// socket to read and to write, and registering a descriptor twice with one
    /// reactor is refused by the operating system -- so the grouping in
    /// [`poll_sockets`] is what makes the C's own call shape work.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn a_descriptor_named_twice_is_registered_once() {
        use std::io::Write;

        let (left, mut right) = socket_pair();
        right
            .write_all(b"curl")
            .expect("the pair accepts four bytes");
        let sock = left.as_raw_fd();

        let mut fds = [
            PollFd::new(sock, PollEvents::IN),
            PollFd::new(sock, PollEvents::OUT),
        ];
        assert_eq!(poll_sockets(&mut fds, 200).await, Ok(2));
        assert!(fds[0].revents.intersects(PollEvents::IN));
        assert!(fds[1].revents.intersects(PollEvents::OUT));

        // And through the C's own entry point, where it is both read and write
        // descriptor at once.
        assert_eq!(
            socket_check(sock, CURL_SOCKET_BAD, sock, 200).await,
            Ok(CURL_CSELECT_IN | CURL_CSELECT_OUT)
        );
    }

    /// A pollset waits on the descriptors it holds, in its own order.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn a_pollset_waits_on_what_it_holds() {
        let (left, _right) = socket_pair();
        let mut ps = EasyPollset::new();
        ps.add_out(left.as_raw_fd(), None).expect("valid");

        assert_eq!(ps.poll(200).await, Ok(1));

        // Watching for readability alone, the same descriptor is idle.
        ps.set_in_only(left.as_raw_fd(), None).expect("valid");
        assert_eq!(ps.poll(20).await, Ok(0));
    }

    /// An aggregation buffer waits on everything it collected.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn an_aggregation_buffer_waits_on_everything() {
        let (left, _left_peer) = socket_pair();
        let (right, _right_peer) = socket_pair();

        let mut ps = EasyPollset::new();
        ps.add_out(left.as_raw_fd(), None).expect("valid");
        let mut cpfds = PollFds::new();
        cpfds.add_ps(&ps);
        cpfds.add_sock(right.as_raw_fd(), PollEvents::OUT);

        assert_eq!(cpfds.poll(200).await, Ok(2));
        assert!(cpfds.as_slice()[0].revents.intersects(PollEvents::OUT));
        assert!(cpfds.as_slice()[1].revents.intersects(PollEvents::OUT));
    }

    /// Out-of-band data is an ERROR condition, and it reaches a caller.
    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn out_of_band_data_is_reported_as_an_error() {
        use std::net::{TcpListener, TcpStream};

        let listener =
            TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let address = listener.local_addr().expect("its own address");
        let sender =
            TcpStream::connect(address).expect("a loopback connection");
        let (receiver, _peer) = listener.accept().expect("the connection");
        receiver
            .set_nonblocking(true)
            .expect("non-blocking receiver");

        // `send_out_of_band` is `send()` with `MSG_OOB`, which is the only way
        // to produce the condition. `socket2` owns that call, so no descriptor
        // arithmetic appears here.
        let urgent = socket2::Socket::from(sender);
        urgent.send_out_of_band(b"!").expect("one urgent byte");

        let mut fds = [PollFd::new(receiver.as_raw_fd(), CHECK_READ_EVENTS)];
        assert_eq!(poll_sockets(&mut fds, 500).await, Ok(1));
        assert!(
            fds[0].revents.intersects(PollEvents::PRI),
            "urgent data must be reported: {:?}",
            fds[0].revents
        );

        let checked = socket_readable(receiver.as_raw_fd(), 500)
            .await
            .expect("the check itself succeeds");
        assert_ne!(
            checked & CURL_CSELECT_ERR,
            0,
            "out-of-band data is an error condition, not readability"
        );
    }

    /// A descriptor the reactor will not watch is reported as invalid, at once.
    ///
    /// `poll(2)` answers `POLLNVAL` for such a descriptor and does not block,
    /// and [`socket_check`] turns that bit into [`CURL_CSELECT_ERR`]
    /// (`select.c:169-170`). Blocking instead would hide a closed socket for
    /// the whole timeout.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "the reactor needs epoll, which Miri lacks")]
    async fn an_unwatchable_descriptor_is_reported_as_invalid() {
        // A descriptor number that is not open. It passes `VALID_SOCK`, which
        // is the point: only the attempt to watch it can discover the truth.
        let closed = {
            let (left, _right) = socket_pair();
            left.as_raw_fd()
        };

        let mut fds = [PollFd::new(closed, PollEvents::IN)];
        // A long timeout, to prove the answer does not wait for it.
        assert_eq!(poll_sockets(&mut fds, 60_000).await, Ok(1));
        assert_eq!(fds[0].revents, PollEvents::NVAL);

        assert_eq!(socket_readable(closed, 60_000).await, Ok(CURL_CSELECT_ERR));
    }
}
