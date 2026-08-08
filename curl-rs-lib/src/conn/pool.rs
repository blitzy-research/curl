//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Linus Nielsen Feltzing, <linus@haxx.se>
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
// SPDX-License-Identifier: curl
//
//***************************************************************************

//! The connection pool -- supersedes `lib/conncache.c` (910 lines) and
//! `lib/conncache.h` (167 lines).
//!
//! AAP section 0.4.1 states the transformation in one line: *"Intrusive-list
//! cache becomes an owned pool."* That is AAP pattern P5, Repository plus
//! object pool, with explicit ownership and the eviction policy written down
//! rather than inferred; and AAP pattern P12, dependency injection, for the
//! clock, the dead/reuse predicate and the upkeep action.
//!
//! # What is reproduced, and from where
//!
//! * `lib/conncache.h:36-165` -- the pool structure, the three
//!   `CPOOL_LIMIT_*` results, and all four callback contracts including
//!   *"All callbacks are invoked while the pool's lock is held."*
//! * `lib/conncache.c:39-228` -- the lock macros, the destination bundle, pool
//!   initialisation, bundle lookup and removal, and `cpool_discard_conn`.
//! * `lib/conncache.c:231-498` -- pool destruction, transfer initialisation,
//!   both oldest-idle scans, the connection-limit check, and the add path.
//! * `lib/conncache.c:500-758` -- the pool-wide traversal, the
//!   became-idle path, `find`, connection termination, pruning and upkeep.
//! * `lib/conncache.c:761-873` -- lookup by identity, the act-on-one-identity
//!   entry point, and network-change handling.
//! * `lib/url.c:622-700` -- `conn_maxage` and `Curl_conn_seems_dead`, the
//!   dead/reuse policy this module INJECTS rather than implements. See
//!   [`ConnectionHealth`].
//!
//! # THE EVICTION POLICY
//!
//! AAP pattern P5 requires the policy to be documented explicitly, so it is
//! stated here in full and the five points are load-bearing:
//!
//! 1. **Per-destination limit eviction performs a full scan of that
//!    destination bundle** for the maximum idle age among connections that
//!    are **not in use** (`lib/conncache.c:308-334`).
//! 2. **Pool-wide limit eviction performs a full scan of every bundle** for
//!    maximum idle age, excluding **in-use, close-marked, and connect-only**
//!    connections (`:336-368`).
//! 3. **These exclusion sets intentionally differ.** The bundle scan will
//!    evict a close-marked or connect-only connection and the pool-wide scan
//!    will not. The asymmetry is the C's and it is preserved: a destination
//!    that is over its own limit must be able to give up any idle connection
//!    it holds, while the pool-wide sweep leaves alone connections another
//!    layer has already claimed or already decided to discard.
//! 4. **Selection is age-based and order-independent; this is NOT an LRU
//!    list.** Nothing is moved to a front or a back when a connection is
//!    used or becomes idle, and map iteration order is never read as a
//!    recency signal. Replacing the scan with recency-order movement, an
//!    intrusive list or queue-front eviction would change WHICH connection
//!    dies under a limit.
//! 5. **Shutdown queue eviction is a separate FIFO policy and must not be
//!    unified with pool eviction.** [`ShutdownQueue`] answers "which arrived
//!    first"; this module answers "which has been idle longest". The two are
//!    both spelled "oldest" in the C and they are different questions.
//!
//! # No interior lock: the share layer owns serialisation
//!
//! `lib/conncache.c:41-60` shows that the pool's lock is not the pool's:
//! `CPOOL_LOCK` takes `CURL_LOCK_DATA_CONNECT` through `Curl_share_lock` and
//! only when `CURL_SHARE_KEEP_CONNECT(share)` says the pool is shared. The
//! `locked` bit that surrounds it is a `DEBUGASSERT` against re-entrancy and
//! nothing else -- it guards no data.
//!
//! So there is no lock here, of any kind. Every mutation takes `&mut self`,
//! which makes illegal re-entrancy unrepresentable rather than merely
//! asserted: a second caller cannot hold a second mutable borrow, and a
//! callback cannot reach back into the pool because it is never handed one.
//! `CURL_LOCK_DATA_CONNECT` remains an external lock-data identifier that the
//! owner acquires before entering when sharing is configured; share locking is
//! `crate::share`'s and is not reimplemented here.
//!
//! Preserving *"callbacks are invoked while the pool's lock is held"* is
//! therefore automatic: [`ConnectionPool::find`] holds `&mut self` for the
//! whole traversal, so no other caller can observe the pool mid-scan.
//!
//! # Generational keys, and two kinds of identity
//!
//! The C reaches a connection through a `struct connectdata *` and reaches its
//! bundle through an intrusive `Curl_llist_node` embedded in it. Both are
//! replaced, and the replacement is not cosmetic: a raw pointer to a freed
//! connection is indistinguishable from a valid one, whereas a
//! [`PoolKey`] carries a slot AND a generation and every lookup checks both.
//! A key held across a removal is DETECTED -- it answers [`None`], or a
//! [`StaleKey`] where the caller needs to know why -- and it can never alias
//! whichever connection later occupies that slot.
//!
//! That internal key is deliberately NOT the identity the ABI exposes.
//! [`ConnectionId`] is a monotonic `curl_off_t`-compatible number that backs
//! `CURLINFO_CONN_ID`, and [`TransferId`] is its counterpart for
//! `CURLINFO_XFER_ID`. Neither ever carries packed slot or generation bits,
//! because an application that reads a connection identity out of `getinfo`
//! and prints it must see a stable small number, not this module's storage
//! layout.
//!
//! # What has no successor
//!
//! * **The SIGPIPE wrapper.** `Curl_cpool_destroy` brackets its loop with
//!   `sigpipe_init`/`sigpipe_apply`/`sigpipe_restore`
//!   (`lib/conncache.c:235-251`) so that a write to a closing socket cannot
//!   kill the process. Nothing here writes to a socket through a raw
//!   descriptor, so there is no disposition to save.
//! * **`Curl_cpool_do_locked`** (`:828-840`) is "invoke this callback under
//!   the pool's lock". With no interior lock and `&mut self` on every entry
//!   point, the caller already has exactly that, so the wrapper would wrap
//!   nothing.
//! * **The `locked` bit** (`:39`, `:47`, `:55`) and the `initialised` bit
//!   (`:59`, `:125`). The first is the re-entrancy assertion the borrow
//!   checker replaces; the second exists so that `Curl_cpool_destroy` can
//!   tell a zeroed structure from a live one, and a Rust value cannot be
//!   observed before it is constructed.
//! * **`CURLE_OUT_OF_MEMORY` from the add path** (`:483`). The C's only
//!   failure mode is a failed `calloc`; here a failed allocation aborts the
//!   process before any caller could see a code, so [`ConnectionPool::add`]
//!   is infallible and says so in its signature.
//!
//! # One note on the licence banner above
//!
//! It carries both copyright holders of `lib/conncache.c:1-23`, in the C's
//! order. The single blank comment line the C has between "KIND, either
//! express or implied." and its SPDX line is absorbed, which is what places
//! `// SPDX-License-Identifier: curl` on line 21 as this tree's other 81
//! sources have it.

use core::fmt;
use std::collections::BTreeMap;

use crate::conn::filters::{
    CallCtx, ConnId, FilterChains, ShutdownTimer, SocketIndex,
};
use crate::conn::shutdown::{
    terminate as shutdown_terminate, ProtocolDisconnect, ShutdownHandle,
    ShutdownHost, ShutdownQueue, ShuttingDownConnection,
};
use crate::error::{CURLcode, CurlResult};
use crate::trace::{infof, trc_feat, TraceFeature};
use crate::util::timediff::TimeDiff;
use crate::util::timeval::{timediff_ms, CurlTime};
use crate::util::CurlOffT;

// =========================================================================
// Constants the C spells as preprocessor macros
// =========================================================================

/// How often pruning may run, in milliseconds -- the `1000L` of
/// `lib/conncache.c:731`.
///
/// `Curl_cpool_prune_dead`'s own documentation calls this "at most once per
/// second" (`lib/conncache.h:131`). The comparison is `elapsed >= 1000`, so a
/// call at exactly one thousand milliseconds runs; see
/// [`ConnectionPool::prune_dead`].
pub(crate) const PRUNE_INTERVAL_MS: TimeDiff = 1000;

/// `PROTOPT_SSL_REUSE` (`lib/urldata.h:555-557`): this scheme may reuse an
/// existing TLS connection in the same family without itself carrying
/// `PROTOPT_SSL`.
///
/// Carried here because matching consumes it -- a matcher passed to
/// [`ConnectionPool::find`] reads it off the candidate through
/// [`PooledConnection::may_reuse_tls`]. The scheme table itself belongs to
/// `crate::protocols`, so the POLICY that combines these bits is injected and
/// is not duplicated in this module.
pub(crate) const PROTOPT_SSL_REUSE: u32 = 1 << 15;

/// `PROTOPT_CONN_REUSE` (`lib/urldata.h:558`): this scheme can reuse
/// connections at all.
///
/// Bit 16, immediately above [`PROTOPT_SSL_REUSE`]. Bit 9 is FREE -- the C
/// records `/* (1 << 9) was PROTOPT_STREAM, now free */` at
/// `lib/urldata.h:544` -- and must stay free: reusing it would give a
/// meaning to a value that older code may still set.
pub(crate) const PROTOPT_CONN_REUSE: u32 = 1 << 16;

// =========================================================================
// The connection-limit verdict
// =========================================================================

/// What [`ConnectionPool::check_limits`] answers.
///
/// The C returns a bare `int` drawn from three macros at
/// `lib/conncache.h:90-92`:
///
/// ```text
/// #define CPOOL_LIMIT_OK     0
/// #define CPOOL_LIMIT_DEST   1
/// #define CPOOL_LIMIT_TOTAL  2
/// ```
///
/// The values are pinned as discriminants rather than left to declaration
/// order, and [`Self::as_i32`] / [`Self::from_i32`] are the checked crossing
/// for any boundary that still speaks in integers. A caller that only wants
/// "may I create another connection?" asks [`Self::is_ok`], which is the C's
/// `result == CPOOL_LIMIT_OK`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum CpoolLimit {
    /// `CPOOL_LIMIT_OK`: there is room.
    #[default]
    Ok = 0,
    /// `CPOOL_LIMIT_DEST`: this destination is at
    /// `CURLMOPT_MAX_HOST_CONNECTIONS` and nothing could be given up.
    Destination = 1,
    /// `CPOOL_LIMIT_TOTAL`: the pool is at
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS` and nothing could be given up.
    Total = 2,
}

#[allow(dead_code)] // consumers: `crate::protocols` and `crate::multi`
impl CpoolLimit {
    /// True for [`Self::Ok`] alone.
    pub(crate) const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// The pinned integer, for a boundary that speaks in `int`.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The inverse of [`Self::as_i32`], admitting only the three defined
    /// values.
    ///
    /// Checked rather than transmuted: an integer arriving from outside this
    /// module has no guarantee of naming a member, and silently accepting a
    /// fourth value would let "there is room" and "the pool is full" become
    /// the same answer.
    pub(crate) const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::Destination),
            2 => Some(Self::Total),
            _ => None,
        }
    }
}

// =========================================================================
// The connection-check bitmaps
// =========================================================================

/// What a protocol's connection check is being asked to do --
/// `CONNCHECK_*` (`lib/urldata.h:560-563`).
///
/// A newtype over the bits rather than an enumeration, because the C values
/// are a bitmap that can be combined:
///
/// ```text
/// CONNCHECK_NONE      = 0
/// CONNCHECK_ISDEAD    = 1 << 0
/// CONNCHECK_KEEPALIVE = 1 << 1
/// ```
///
/// Hand-written rather than derived from a bitflag crate: AAP section 0.5.1
/// pins the dependency set and `bitflags` is not in it, and the five
/// operations below are the whole of what the C does with these bits.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConnCheck(u32);

#[allow(dead_code)] // consumer: `crate::protocols`, once schemes land
impl ConnCheck {
    /// `CONNCHECK_NONE`: no checks (`lib/urldata.h:560`).
    pub(crate) const NONE: Self = Self(0);

    /// `CONNCHECK_ISDEAD`: is the connection dead
    /// (`lib/urldata.h:561`)? The bit [`ConnectionHealth`] passes when it
    /// consults a protocol rather than the filter chain.
    pub(crate) const ISDEAD: Self = Self(1 << 0);

    /// `CONNCHECK_KEEPALIVE`: perform any keepalive function
    /// (`lib/urldata.h:562`). The bit an upkeep pass uses.
    pub(crate) const KEEPALIVE: Self = Self(1 << 1);

    /// Every defined bit, and therefore the mask
    /// [`Self::from_bits_truncate`] applies.
    pub(crate) const ALL: Self = Self(Self::ISDEAD.0 | Self::KEEPALIVE.0);

    /// The raw bitmap, for the one boundary that needs it: a protocol's
    /// check is described by the C as taking an `unsigned int`.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// A bitmap with every undefined bit dropped.
    ///
    /// Truncating rather than rejecting, because that is what C does with an
    /// unrecognised bit: the callee tests the bits it knows and ignores the
    /// rest.
    pub(crate) const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// Are all of `other`'s bits set here?
    ///
    /// `Self::NONE` is contained in everything, which is the reading of
    /// `flags & 0 == 0` the C's tests rely on.
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Both bitmaps together -- the C's `|`.
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Is this [`Self::NONE`]?
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// What a protocol's connection check reports -- `CONNRESULT_*`
/// (`lib/urldata.h:564-565`).
///
/// ```text
/// CONNRESULT_NONE = 0
/// CONNRESULT_DEAD = 1 << 0
/// ```
///
/// A separate type from [`ConnCheck`] even though the two currently overlap
/// numerically. They are a REQUEST and an ANSWER, the C keeps them as
/// separate macro families, and letting one stand for the other is exactly
/// how `state & CONNRESULT_DEAD` (`lib/url.c:679`) would come to be written
/// with the wrong constant.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConnResult(u32);

#[allow(dead_code)] // consumer: `crate::protocols`, once schemes land
impl ConnResult {
    /// `CONNRESULT_NONE`: no extra information (`lib/urldata.h:564`).
    pub(crate) const NONE: Self = Self(0);

    /// `CONNRESULT_DEAD`: the connection is dead (`lib/urldata.h:565`).
    ///
    /// This is the bit `Curl_conn_seems_dead` masks out of the protocol's
    /// answer at `lib/url.c:679`, and the only one the C defines.
    pub(crate) const DEAD: Self = Self(1 << 0);

    /// Every defined bit.
    pub(crate) const ALL: Self = Self(Self::DEAD.0);

    /// The raw bitmap.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// A bitmap with every undefined bit dropped. See
    /// [`ConnCheck::from_bits_truncate`].
    pub(crate) const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// Are all of `other`'s bits set here?
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Both bitmaps together.
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Is this [`Self::NONE`]?
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// =========================================================================
// The two ABI-visible identities
// =========================================================================

/// A connection's identity as the application sees it -- C's
/// `conn->connection_id`, a `curl_off_t` assigned in `Curl_cpool_add`
/// (`lib/conncache.c:489`).
///
/// This is what `CURLINFO_CONN_ID` reports and what every `#%d` in a
/// connection trace line prints, so it is a contract and not an
/// implementation detail. Three properties follow, and each is tested:
///
/// * **Monotonic.** The counter only ever moves up, so two connections in one
///   pool never share an identity even after one of them is gone.
/// * **Never recycled.** Reusing a storage slot does NOT reuse an identity.
///   The internal [`PoolKey`] is the thing that gets reused, and that is why
///   the two types exist separately.
/// * **`curl_off_t`-shaped.** The inner type is [`CurlOffT`], which AAP
///   section 0.6.1's ABI work fixes at [`i64`], so no conversion is needed at
///   the `getinfo` boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConnectionId(CurlOffT);

#[allow(dead_code)] // consumers: `crate::easy` (getinfo) and `crate::multi`
impl ConnectionId {
    /// The "no connection" sentinel, `-1`.
    ///
    /// C writes it directly into `data->state.lastconnect_id`
    /// (`lib/conncache.c:280`, `:287`) and `CURLINFO_CONN_ID` hands it back
    /// unchanged for a transfer that has not connected. It is a sentinel and
    /// never an identity the pool assigns: the counter starts at zero.
    pub(crate) const NONE: Self = Self(-1);

    /// The first identity a fresh pool hands out, `0`.
    ///
    /// C leaves `cpool->next_connection_id` zeroed by `calloc`, so the first
    /// connection added is `#0`. Named rather than written as a literal
    /// because two tests and one trace assertion depend on it.
    pub(crate) const FIRST: Self = Self(0);

    /// An identity from its number.
    pub(crate) const fn new(id: CurlOffT) -> Self {
        Self(id)
    }

    /// The number, exactly as `CURLINFO_CONN_ID` reports it.
    pub(crate) const fn get(self) -> CurlOffT {
        self.0
    }

    /// Is this the [`Self::NONE`] sentinel?
    pub(crate) const fn is_none(self) -> bool {
        self.0 < 0
    }

    /// The same identity in the form the filter and shutdown layers use.
    ///
    /// [`ConnId`] is a `u64` because `crate::conn::filters` only ever stamps
    /// it on a chain and prints it, and it has no sentinel. Every identity
    /// this pool assigns is non-negative, so the conversion is exact for
    /// every real connection.
    ///
    /// [`Self::NONE`] maps to zero, which is deliberate and tested: the
    /// sentinel is a transfer's "not connected yet" state and is never handed
    /// to the shutdown layer, so there is no line it can mislabel -- and
    /// answering a total function is better than a fallible one on a path no
    /// caller can reach.
    pub(crate) fn as_conn_id(self) -> ConnId {
        ConnId::new(u64::try_from(self.0).unwrap_or(0))
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A transfer's identity within its pool -- C's `data->id`, assigned in
/// `Curl_cpool_xfer_init` (`lib/conncache.c:277`).
///
/// What `CURLINFO_XFER_ID` reports. The counter lives on the pool rather than
/// on the transfer because the C puts it there: a transfer joining a SHARED
/// pool takes its number from the share, so two multi handles over one share
/// cannot hand out the same transfer identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TransferId(CurlOffT);

#[allow(dead_code)] // consumers: `crate::easy` (getinfo) and `crate::multi`
impl TransferId {
    /// The first identity a fresh pool hands out, `0`.
    pub(crate) const FIRST: Self = Self(0);

    /// An identity from its number.
    pub(crate) const fn new(id: CurlOffT) -> Self {
        Self(id)
    }

    /// The number, exactly as `CURLINFO_XFER_ID` reports it.
    pub(crate) const fn get(self) -> CurlOffT {
        self.0
    }
}

impl fmt::Display for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What [`ConnectionPool::xfer_init`] hands a transfer joining the pool.
///
/// `Curl_cpool_xfer_init` (`lib/conncache.c:269-289`) writes two fields on the
/// transfer and returns nothing. Returning them instead of writing through a
/// borrow is what keeps `crate::easy`'s state out of this module: the pool
/// owns the counters, the transfer owns the fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct XferInit {
    /// `data->id` -- the next transfer identity (`:277`).
    pub(crate) transfer_id: TransferId,
    /// `data->state.lastconnect_id`, reset to [`ConnectionId::NONE`]
    /// (`:280`).
    pub(crate) lastconnect_id: ConnectionId,
}

// =========================================================================
// Internal storage: a generational slab
// =========================================================================

/// Where a connection lives inside the pool.
///
/// This replaces two C mechanisms at once, and neither replacement is
/// optional if the pool is to own its connections:
///
/// * The `struct connectdata *` a caller holds across pool operations. A
///   pointer to a freed connection has the same representation as a live one,
///   so C's protection is discipline. Here [`Self::generation`] changes when
///   the slot is vacated, so the old key stops resolving.
/// * The `struct Curl_llist_node cpool_node` embedded in the connection
///   (`lib/conncache.c:93-105`). An intrusive node means the collection and
///   the element point at each other; a key means only the collection points
///   at anything.
///
/// The two fields are private: a key is produced by
/// [`ConnectionPool::add`] and consumed by the pool, and letting a caller
/// build one out of two integers would hand back exactly the forgery the
/// generation exists to prevent. [`Self::slot`] and [`Self::generation`] read
/// them, which is all a diagnostic needs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct PoolKey {
    /// Which slot of the slab.
    slot: usize,
    /// Which occupant of that slot. Advanced when the slot is vacated.
    generation: u32,
}

#[allow(dead_code)] // consumers: `crate::protocols` and `crate::multi`
impl PoolKey {
    /// Which slot this key names.
    pub(crate) const fn slot(self) -> usize {
        self.slot
    }

    /// Which occupant of that slot this key names.
    pub(crate) const fn generation(self) -> u32 {
        self.generation
    }
}

impl fmt::Display for PoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.slot, self.generation)
    }
}

/// A [`PoolKey`] that no longer names a connection.
///
/// Returned where a caller needs to distinguish "the connection you are
/// holding a key to has gone" from "there is nothing to do", which the bare
/// [`None`] of [`ConnectionPool::get`] cannot express. The C has no analogue
/// because the equivalent situation there is a dangling pointer.
///
/// It converts to `CURLE_BAD_FUNCTION_ARGUMENT`: a stale key is a caller
/// error, and the C code whose argument is a freed connection is a caller
/// error too -- it simply has no way to say so.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct StaleKey {
    /// The key that failed to resolve, for the diagnostic.
    key: PoolKey,
}

#[allow(dead_code)] // consumers: `crate::protocols` and `crate::multi`
impl StaleKey {
    /// The key that failed to resolve.
    pub(crate) const fn key(self) -> PoolKey {
        self.key
    }
}

impl fmt::Display for StaleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stale connection key {}", self.key)
    }
}

impl From<StaleKey> for CURLcode {
    fn from(_stale: StaleKey) -> Self {
        Self::BadFunctionArgument
    }
}

/// One slot of a [`GenerationalSlab`].
#[derive(Debug)]
enum Slot<T> {
    /// Free, and part of the free chain.
    Vacant {
        /// The generation the NEXT occupant will be handed.
        generation: u32,
        /// The next free slot, forming a chain with no allocation.
        next_free: Option<usize>,
    },
    /// Taken.
    Occupied {
        /// The generation the key handed out for this occupant carries.
        generation: u32,
        /// The occupant. Owned outright: dropping the slab drops it.
        value: T,
    },
    /// Retired: the generation counter for this slot has run out, so the slot
    /// is never reused. See [`GenerationalSlab::remove`].
    Retired,
}

/// A vector of slots with a free chain and a generation per slot.
///
/// Written here rather than taken from a crate because AAP section 0.5.1 pins
/// the dependency set and no slab crate is in it. It is deliberately small:
/// insert, remove, two accessors and a length, which is every operation the
/// pool performs.
///
/// # Why the generation is checked on EVERY access
///
/// A cheaper design validates only on removal. That is not enough: the whole
/// point is that a key outliving its connection must not resolve, and a read
/// is exactly where that would do damage -- it would hand back a DIFFERENT
/// connection with the same slot, and the caller would act on it believing it
/// was the one it asked for.
#[derive(Debug)]
struct GenerationalSlab<T> {
    /// Every slot, indexed by [`PoolKey::slot`].
    slots: Vec<Slot<T>>,
    /// Head of the free chain, if any slot is free.
    free: Option<usize>,
    /// How many slots are occupied.
    len: usize,
}

impl<T> GenerationalSlab<T> {
    /// An empty slab. Allocates nothing.
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: None,
            len: 0,
        }
    }

    /// How many occupants.
    fn len(&self) -> usize {
        self.len
    }

    /// Stores `value` and hands back the key that names it.
    ///
    /// A free slot is preferred over growing the vector, and the key carries
    /// that slot's CURRENT generation -- which [`Self::remove`] already
    /// advanced when it vacated the slot. So a key from a previous occupant
    /// of the same slot differs in its generation field and stops resolving,
    /// which is the property [`PoolKey`] exists for.
    fn insert(&mut self, value: T) -> PoolKey {
        self.len += 1;
        match self.free {
            Some(slot) => {
                let (generation, next_free) = match &self.slots[slot] {
                    Slot::Vacant {
                        generation,
                        next_free,
                    } => (*generation, *next_free),
                    // Unreachable by construction: only `remove` links a slot
                    // into the chain, and it links only vacant ones. Handled
                    // rather than asserted so that a future edit which broke
                    // the invariant would leak a slot instead of corrupting
                    // the chain.
                    Slot::Occupied { .. } | Slot::Retired => {
                        self.free = None;
                        self.len -= 1;
                        return self.insert(value);
                    }
                };
                self.free = next_free;
                self.slots[slot] = Slot::Occupied { generation, value };
                PoolKey { slot, generation }
            }
            None => {
                let slot = self.slots.len();
                self.slots.push(Slot::Occupied {
                    generation: 0,
                    value,
                });
                PoolKey {
                    slot,
                    generation: 0,
                }
            }
        }
    }

    /// Takes the occupant `key` names, advancing that slot's generation.
    ///
    /// [`None`] when the key is stale or names a slot beyond the slab, and
    /// the slab is left untouched in both cases -- a stale removal must not
    /// evict whoever legitimately holds the slot now.
    ///
    /// # Generation exhaustion
    ///
    /// `u32` gives a slot four billion occupants. Wrapping past that would
    /// make a very old key resolve again, so instead the slot is RETIRED: it
    /// is not linked into the free chain and is never handed out again. The
    /// cost is one dead vector element per four billion reuses of one slot;
    /// the benefit is that staleness detection is total rather than
    /// probabilistic, and can be stated without a caveat.
    fn remove(&mut self, key: PoolKey) -> Option<T> {
        let slot = self.slots.get_mut(key.slot)?;
        let generation = match slot {
            Slot::Occupied { generation, .. }
                if *generation == key.generation =>
            {
                *generation
            }
            Slot::Occupied { .. } | Slot::Vacant { .. } | Slot::Retired => {
                return None
            }
        };
        let taken = core::mem::replace(slot, Slot::Retired);
        let value = match taken {
            Slot::Occupied { value, .. } => value,
            // The match above already proved this slot occupied, and nothing
            // ran in between; kept as an arm rather than a panic so that this
            // module contains no path that can abort a transfer.
            Slot::Vacant { .. } | Slot::Retired => return None,
        };
        self.len -= 1;
        match generation.checked_add(1) {
            Some(next) => {
                self.slots[key.slot] = Slot::Vacant {
                    generation: next,
                    next_free: self.free,
                };
                self.free = Some(key.slot);
            }
            None => {
                // Left `Retired`, and deliberately not linked into the free
                // chain.
            }
        }
        Some(value)
    }

    /// The occupant `key` names, or [`None`] when the key is stale.
    fn get(&self, key: PoolKey) -> Option<&T> {
        match self.slots.get(key.slot)? {
            Slot::Occupied { generation, value }
                if *generation == key.generation =>
            {
                Some(value)
            }
            Slot::Occupied { .. } | Slot::Vacant { .. } | Slot::Retired => None,
        }
    }

    /// The occupant `key` names, mutably, or [`None`] when the key is stale.
    fn get_mut(&mut self, key: PoolKey) -> Option<&mut T> {
        match self.slots.get_mut(key.slot)? {
            Slot::Occupied { generation, value }
                if *generation == key.generation =>
            {
                Some(value)
            }
            Slot::Occupied { .. } | Slot::Vacant { .. } | Slot::Retired => None,
        }
    }
}

// =========================================================================
// What the pool is handed, and what it then owns
// =========================================================================

/// Everything needed to put a new connection into the pool.
///
/// The C has no analogue because there is nothing to describe: a
/// `struct connectdata` is already fully built when `Curl_cpool_add` is
/// called, and `add` only fills in `connection_id` (`lib/conncache.c:489`).
/// Here the identity is assigned by [`ConnectionPool::add`] for exactly the
/// same reason, so the connection cannot be CONSTRUCTED before it is added --
/// which is why the parts arrive as a description and leave as a
/// [`PooledConnection`].
///
/// The three injected objects -- the filter chains, the shutdown timer and the
/// scheme's disconnect handler -- pass straight through to
/// [`ShuttingDownConnection`], so this module never needs to know what any of
/// them does.
pub(crate) struct ConnectionSpec {
    /// C's `conn->destination`: the pool's reuse key, matched by exact bytes.
    destination: String,
    /// C's `conn->cfilter[2]`.
    chains: FilterChains,
    /// The injected deadline; storage belongs to `conn/mod.rs`.
    timer: Box<dyn ShutdownTimer>,
    /// `conn->scheme->run->disconnect`, when the scheme has one.
    handler: Option<Box<dyn ProtocolDisconnect>>,
    /// C's `conn->created`, the instant the connection came into being. Read
    /// by the max-lifetime half of the injected health predicate.
    created: CurlTime,
    /// C's `conn->connect_only`: the application took the socket over.
    connect_only: bool,
    /// `conn->scheme->flags & PROTOPT_NONETWORK`.
    no_network: bool,
    /// `conn->scheme->flags`, from which matching reads
    /// [`PROTOPT_CONN_REUSE`] and [`PROTOPT_SSL_REUSE`].
    protocol_flags: u32,
}

impl fmt::Debug for ConnectionSpec {
    /// Partial by design, as [`ShuttingDownConnection`]'s is: the timer and
    /// the handler are reported by PRESENCE because their contents belong to
    /// the multi handle and the scheme respectively.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSpec")
            .field("destination", &self.destination)
            .field("chains", &self.chains)
            .field("has_handler", &self.handler.is_some())
            .field("created", &self.created)
            .field("connect_only", &self.connect_only)
            .field("no_network", &self.no_network)
            .field("protocol_flags", &self.protocol_flags)
            .finish()
    }
}

#[allow(dead_code)] // consumer: `crate::protocols`, once schemes land
impl ConnectionSpec {
    /// A description with every flag clear and no disconnect handler.
    ///
    /// `created` is a parameter rather than read from a clock, because the
    /// instant wanted is when the CONNECTION was created and not when it
    /// happened to be pooled; the two differ by the whole of the connect
    /// sequence, and the max-lifetime rule of `lib/url.c:638-647` measures
    /// against the former.
    pub(crate) fn new(
        destination: impl Into<String>,
        chains: FilterChains,
        timer: Box<dyn ShutdownTimer>,
        created: CurlTime,
    ) -> Self {
        Self {
            destination: destination.into(),
            chains,
            timer,
            handler: None,
            created,
            connect_only: false,
            no_network: false,
            protocol_flags: 0,
        }
    }

    /// Installs the scheme's disconnect handler.
    #[must_use]
    pub(crate) fn with_handler(
        mut self,
        handler: Box<dyn ProtocolDisconnect>,
    ) -> Self {
        self.handler = Some(handler);
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

    /// Sets `conn->scheme->flags`.
    #[must_use]
    pub(crate) fn with_protocol_flags(mut self, flags: u32) -> Self {
        self.protocol_flags = flags;
        self
    }

    /// The destination this connection reaches.
    pub(crate) fn destination(&self) -> &str {
        &self.destination
    }
}

/// A connection the pool owns -- C's `struct connectdata` reduced to the
/// fields the pool and its policies actually read.
///
/// # Composition rather than duplication
///
/// The teardown half of a connection already has an owner:
/// [`ShuttingDownConnection`] holds the identity, the destination, both filter
/// chains, the timer, the disconnect handler and the `aborted`,
/// `connect_only` and `no_network` flags. Declaring any of those a second time
/// here would create two places for one fact, so this type OWNS one of those
/// values and delegates to it. Handing it to the shutdown layer is then
/// [`Self::into_shutting_down`], a move of the inner value -- which is what
/// makes "ownership moves out exactly once" a property of the type rather
/// than of the code that uses it.
///
/// One flag is deliberately mirrored rather than delegated: `in_pool`.
/// [`ShuttingDownConnection`]'s copy can only be set by a builder that
/// consumes the value, so it cannot be flipped in place while the connection
/// is alive in the pool; [`Self::in_pool`] is the live one, and
/// [`Self::into_shutting_down`] stamps the inner copy `false` on the way out
/// so that the precondition `crate::conn::shutdown::terminate` asserts holds
/// by construction.
pub(crate) struct PooledConnection {
    /// C's `conn->connection_id`, assigned by [`ConnectionPool::add`].
    connection_id: ConnectionId,
    /// C's `conn->created`.
    created: CurlTime,
    /// C's `conn->lastused`: when the connection stopped being used. The
    /// operand of every age comparison in this module.
    lastused: CurlTime,
    /// C's `conn->attached_xfers`. `CONN_INUSE(c)` is
    /// `(!!(c)->attached_xfers)` (`lib/urldata.h:609`), so
    /// [`Self::is_in_use`] is exactly "this is nonzero" -- never "somebody
    /// holds a key to it".
    attached_xfers: u32,
    /// C's `conn->bits.close`: some layer has already decided to discard it.
    wants_close: bool,
    /// C's `conn->bits.no_reuse`: it may be finished with, but not reused.
    no_reuse: bool,
    /// C's `conn->bits.in_cpool`. See the type's documentation for why this
    /// is mirrored rather than delegated.
    in_pool: bool,
    /// `conn->scheme->flags`.
    protocol_flags: u32,
    /// The teardown half, owned. See the type's documentation.
    inner: ShuttingDownConnection,
}

impl fmt::Debug for PooledConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledConnection")
            .field("connection_id", &self.connection_id)
            .field("destination", &self.destination())
            .field("created", &self.created)
            .field("lastused", &self.lastused)
            .field("attached_xfers", &self.attached_xfers)
            .field("wants_close", &self.wants_close)
            .field("no_reuse", &self.no_reuse)
            .field("in_pool", &self.in_pool)
            .field("protocol_flags", &self.protocol_flags)
            .field("connect_only", &self.connect_only())
            .field("aborted", &self.aborted())
            .finish()
    }
}

#[allow(dead_code)] // consumers: `crate::protocols` and `crate::multi`
impl PooledConnection {
    /// Builds the pooled connection a description names, under `id`.
    ///
    /// Private: the identity has to come from the pool's counter, so this is
    /// reachable only through [`ConnectionPool::add`].
    fn new(id: ConnectionId, spec: ConnectionSpec) -> Self {
        let ConnectionSpec {
            destination,
            chains,
            timer,
            handler,
            created,
            connect_only,
            no_network,
            protocol_flags,
        } = spec;

        let mut inner = ShuttingDownConnection::new(
            id.as_conn_id(),
            destination,
            chains,
            timer,
        )
        .with_connect_only(connect_only)
        .with_no_network(no_network)
        .with_in_pool(true);
        if let Some(handler) = handler {
            inner = inner.with_handler(handler);
        }

        Self {
            connection_id: id,
            created,
            // C never initialises `lastused` in `Curl_cpool_add`; the
            // connection carries whatever the connect sequence left there,
            // and `Curl_cpool_conn_now_idle` is what actually sets it
            // (`lib/conncache.c:572`). Seeding it from `created` gives a
            // newly pooled connection a defined age instead of a zero
            // reading that would make it look infinitely idle to the
            // oldest-idle scans.
            lastused: created,
            attached_xfers: 0,
            wants_close: false,
            no_reuse: false,
            in_pool: true,
            protocol_flags,
            inner,
        }
    }

    /// C's `conn->connection_id` -- what `CURLINFO_CONN_ID` reports.
    pub(crate) const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// C's `conn->destination`, delegated to the inner value so there is one
    /// copy of the string and one source of truth for it.
    pub(crate) fn destination(&self) -> &str {
        self.inner.destination()
    }

    /// C's `conn->created`.
    pub(crate) const fn created(&self) -> CurlTime {
        self.created
    }

    /// C's `conn->lastused`.
    pub(crate) const fn lastused(&self) -> CurlTime {
        self.lastused
    }

    /// Sets `conn->lastused` -- `lib/conncache.c:572`, "it was used up until
    /// now".
    pub(crate) fn set_lastused(&mut self, at: CurlTime) {
        self.lastused = at;
    }

    /// C's `conn->attached_xfers`.
    pub(crate) const fn attached_xfers(&self) -> u32 {
        self.attached_xfers
    }

    /// `CONN_INUSE(conn)` (`lib/urldata.h:609`).
    pub(crate) const fn is_in_use(&self) -> bool {
        self.attached_xfers != 0
    }

    /// One more transfer is using this connection.
    ///
    /// Saturating: the count is a `u32` and C increments it without a guard,
    /// where overflow would be undefined. Saturating keeps the connection
    /// permanently "in use", which fails safe -- it can then only leave the
    /// pool through an aborted termination.
    pub(crate) fn attach(&mut self) {
        self.attached_xfers = self.attached_xfers.saturating_add(1);
    }

    /// One fewer transfer is using this connection.
    ///
    /// Saturating for the same reason, in the other direction: a detach
    /// without a matching attach must not wrap the count to `u32::MAX` and
    /// pin the connection in the pool forever.
    pub(crate) fn detach(&mut self) {
        self.attached_xfers = self.attached_xfers.saturating_sub(1);
    }

    /// Sets the attached-transfer count outright.
    ///
    /// Present because the pool's own tests and `crate::multi` both need to
    /// place a connection in a chosen state without replaying the attaches
    /// that got it there.
    pub(crate) fn set_attached_xfers(&mut self, count: u32) {
        self.attached_xfers = count;
    }

    /// C's `conn->bits.close`.
    pub(crate) const fn wants_close(&self) -> bool {
        self.wants_close
    }

    /// C's `connclose()`: mark the connection for closing.
    pub(crate) fn mark_close(&mut self) {
        self.wants_close = true;
    }

    /// C's `conn->bits.no_reuse`.
    pub(crate) const fn no_reuse(&self) -> bool {
        self.no_reuse
    }

    /// Sets `conn->bits.no_reuse` -- `cpool_mark_stale`
    /// (`lib/conncache.c:842-849`).
    pub(crate) fn mark_no_reuse(&mut self) {
        self.no_reuse = true;
    }

    /// C's `conn->bits.in_cpool`.
    pub(crate) const fn is_in_pool(&self) -> bool {
        self.in_pool
    }

    /// C's `conn->connect_only`, delegated.
    pub(crate) fn connect_only(&self) -> bool {
        self.inner.connect_only()
    }

    /// C's `conn->bits.aborted`, delegated.
    pub(crate) fn aborted(&self) -> bool {
        self.inner.aborted()
    }

    /// `conn->scheme->flags & PROTOPT_NONETWORK`, delegated.
    pub(crate) fn no_network(&self) -> bool {
        self.inner.no_network()
    }

    /// `conn->scheme->flags`.
    pub(crate) const fn protocol_flags(&self) -> u32 {
        self.protocol_flags
    }

    /// Does this scheme carry [`PROTOPT_CONN_REUSE`]?
    pub(crate) const fn may_reuse_connection(&self) -> bool {
        self.protocol_flags & PROTOPT_CONN_REUSE != 0
    }

    /// Does this scheme carry [`PROTOPT_SSL_REUSE`]?
    pub(crate) const fn may_reuse_tls(&self) -> bool {
        self.protocol_flags & PROTOPT_SSL_REUSE != 0
    }

    /// Both filter chains, shared -- delegated.
    pub(crate) fn chains(&self) -> &FilterChains {
        self.inner.chains()
    }

    /// Both filter chains, mutable -- delegated. What an injected health
    /// predicate or upkeep action drives.
    pub(crate) fn chains_mut(&mut self) -> &mut FilterChains {
        self.inner.chains_mut()
    }

    /// Is the given chain connected? Delegated.
    pub(crate) fn is_connected(&self, sockindex: SocketIndex) -> bool {
        self.inner.is_connected(sockindex)
    }

    /// How long this connection has been idle, in milliseconds.
    ///
    /// `curlx_ptimediff_ms(&now, &conn->lastused)`, the score of both
    /// oldest-idle scans (`lib/conncache.c:324`, `:360`) and the operand of
    /// the max-idle-age rule (`lib/url.c:629`).
    pub(crate) fn idle_age_ms(&self, now: CurlTime) -> TimeDiff {
        timediff_ms(now, self.lastused)
    }

    /// How long ago this connection was created, in milliseconds.
    ///
    /// `curlx_ptimediff_ms(&now, &conn->created)`, the operand of the
    /// max-lifetime rule (`lib/url.c:639`).
    pub(crate) fn lifetime_ms(&self, now: CurlTime) -> TimeDiff {
        timediff_ms(now, self.created)
    }

    /// Hands the teardown half over, taking ownership of the whole value.
    ///
    /// Two things happen here and both are preconditions of
    /// `crate::conn::shutdown::terminate`:
    ///
    /// * `aborted` is stamped on the inner value. This is
    ///   `conn->bits.aborted = aborted` (`lib/conncache.c:211`), and it is
    ///   what the scheme's disconnect handler receives as its `dead`
    ///   argument.
    /// * `in_pool` is stamped `false`, because a connection reaching
    ///   termination must have left the pool already.
    ///
    /// Consuming `self` is the point: there is no way to hand the same
    /// connection over twice, and no way to keep using it afterwards.
    fn into_shutting_down(self, aborted: bool) -> ShuttingDownConnection {
        self.inner.with_aborted(aborted).with_in_pool(false)
    }
}

// =========================================================================
// The injected dead/reuse predicate -- AAP pattern P12's seam
// =========================================================================

/// Why a connection was judged unusable.
///
/// The C carries no reason: `Curl_conn_seems_dead` returns a bare `bool` and
/// each branch emits its own `infof` before doing so. Naming the branch lets
/// this module report a decision it did not make without duplicating the text
/// that explains it -- which is what keeps the diagnostics in one place.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: `crate::protocols`, once schemes land
pub(crate) enum DeadReason {
    /// Idle for longer than `CURLOPT_MAXAGE_CONN` (`lib/url.c:628-636`).
    MaxIdleAge,
    /// Created longer ago than `CURLOPT_MAXLIFETIME_CONN`
    /// (`lib/url.c:638-647`).
    MaxLifetime,
    /// The scheme's own check answered with [`ConnResult::DEAD`]
    /// (`lib/url.c:668-682`).
    ProtocolCheck,
    /// The filter chain reports the connection is not alive
    /// (`lib/url.c:687`).
    NotAlive,
    /// The connection is alive but bytes are already waiting, so it is not a
    /// clean state to reuse (`lib/url.c:688-699`).
    InputPending,
}

/// What [`ConnectionHealth::seems_dead`] answers.
///
/// A struct rather than `Option<DeadReason>` so that "alive" is a value with
/// a name, and so that a caller reading `verdict.dead` cannot accidentally
/// read `verdict.reason.is_some()` and get a different answer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct DeadVerdict {
    /// The C's return value: `TRUE` means remove and disconnect.
    pub(crate) dead: bool,
    /// Which branch decided, when one did.
    pub(crate) reason: Option<DeadReason>,
}

#[allow(dead_code)] // consumer: `crate::protocols`, once schemes land
impl DeadVerdict {
    /// The connection is usable -- the C's `return FALSE`.
    pub(crate) const ALIVE: Self = Self {
        dead: false,
        reason: None,
    };

    /// The connection is not usable, for `reason`.
    pub(crate) const fn dead(reason: DeadReason) -> Self {
        Self {
            dead: true,
            reason: Some(reason),
        }
    }
}

/// Whether a pooled connection may still be used -- the policy of
/// `Curl_conn_seems_dead` and `conn_maxage` (`lib/url.c:619-711`).
///
/// **This module does not implement that policy and must not.** `lib/url.c`
/// is superseded by `crate::protocols`, which this module names nowhere: the
/// dependency runs the other way, because a protocol installs filters into a
/// connection and a connection is what the pool holds. AAP pattern P12 is the
/// seam, and this trait is it.
///
/// # The contract, measured at `lib/url.c:622-700`
///
/// An implementation MUST behave as follows, in this order:
///
/// 1. **Only evaluate unused connections.** The whole body is inside
///    `if(!CONN_INUSE(conn))` (`:659`), and the C's comment says why: "The
///    check for a dead socket makes sense only if the connection is not in
///    use". An in-use connection answers [`DeadVerdict::ALIVE`].
/// 2. **Maximum idle age BEFORE maximum lifetime.** `conn_maxage` tests
///    `CURLOPT_MAXAGE_CONN` against [`PooledConnection::idle_age_ms`] first
///    (`:628-636`) and only then `CURLOPT_MAXLIFETIME_CONN` against
///    [`PooledConnection::lifetime_ms`] (`:638-647`). The order is
///    observable: a connection that violates both is reported as
///    [`DeadReason::MaxIdleAge`].
/// 3. **Then the scheme's own check.** When the scheme registers one, invoke
///    it with [`ConnCheck::ISDEAD`] and test the answer for
///    [`ConnResult::DEAD`] (`:668-682`). The C's brief attach/detach around
///    the call has no successor here: the connection is a parameter.
/// 4. **Otherwise chain liveness, and reject a live connection with pending
///    input.** `Curl_conn_is_alive` gives both answers at once
///    (`:686-687`); a connection that is alive but has bytes waiting is
///    [`DeadReason::InputPending`], because reuse wants a clean state and
///    what is waiting may be a TLS close notification (`:688-699`).
///
/// # The diagnostics belong to the implementation
///
/// These four strings are `infof` output and therefore frozen by AAP section
/// 0.8.1's preservation mandate. They are emitted by the IMPLEMENTATION, not
/// here, and are quoted only so that the contract can be checked against the
/// C:
///
/// ```text
/// "Too old connection (%d ms idle, max idle is %d ms), disconnect it"
/// "Too old connection (created %d ms ago, max lifetime is %d ms), \
///  disconnect it"
/// "connection has input pending, not reusable"
/// "Connection %d seems to be dead"
/// ```
///
/// The pool receives only the decision and the reason.
pub(crate) trait ConnectionHealth {
    /// Is `conn` still usable?
    ///
    /// `conn` is mutable because branches three and four drive the filter
    /// chain, which the C reaches through a briefly attached transfer.
    fn seems_dead(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &mut PooledConnection,
    ) -> DeadVerdict;
}

/// A predicate that judges nothing dead -- the behaviour of a scheme with no
/// age limits, no check of its own and a healthy chain.
///
/// Not a stub: it is the exact answer the C gives when
/// `data->set.conn_max_idle_ms` and `data->set.conn_max_age_ms` are both zero
/// (their defaults), the scheme registers no `connection_check`, and the chain
/// reports alive with nothing pending. `crate::multi` needs a predicate before
/// any scheme is selected, and this is the correct one for that moment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: `crate::multi`, before a scheme is picked
pub(crate) struct AssumeHealthy;

impl ConnectionHealth for AssumeHealthy {
    fn seems_dead(
        &mut self,
        _cx: &mut CallCtx<'_, '_>,
        _conn: &mut PooledConnection,
    ) -> DeadVerdict {
        DeadVerdict::ALIVE
    }
}

// =========================================================================
// The injected upkeep action
// =========================================================================

/// What an upkeep pass does to one connection -- `Curl_conn_upkeep`
/// (`lib/conncache.c:739-746`).
///
/// Injected for the same reason [`ConnectionHealth`] is: what "upkeep" means
/// is the scheme's business, and the pool's business is visiting every
/// connection exactly once.
pub(crate) trait UpkeepAction {
    /// Keep `conn` alive.
    ///
    /// # Errors
    ///
    /// Whatever the action reports. C discards the result -- `conn_upkeep`
    /// calls `Curl_conn_upkeep` and returns `0` regardless
    /// (`lib/conncache.c:743-745`), so `Curl_cpool_upkeep` always answers
    /// `CURLE_OK`. Propagating it instead is a deliberate strengthening: a
    /// keepalive that failed is worth reporting, and a caller that wants the
    /// C's behaviour discards the result itself.
    fn upkeep(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &mut PooledConnection,
    ) -> CurlResult<()>;
}

/// The production [`UpkeepAction`]: drive the filter chain's keepalive.
///
/// `Curl_conn_upkeep` reduces to `Curl_conn_keep_alive(data, conn,
/// FIRSTSOCKET)`, which walks to the head filter of the primary chain and
/// calls its `keep_alive` (`lib/cfilters.c:1005-1015`). That is exactly
/// [`FilterChains::chain_mut`] plus
/// [`crate::conn::filters::FilterChain::keep_alive`], and an empty chain
/// succeeds, as the C's `cf ? ... : CURLE_OK` does.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: `crate::multi`'s upkeep entry point
pub(crate) struct KeepAliveUpkeep;

impl UpkeepAction for KeepAliveUpkeep {
    fn upkeep(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        conn: &mut PooledConnection,
    ) -> CurlResult<()> {
        conn.chains_mut()
            .chain_mut(SocketIndex::First)
            .keep_alive(cx)
    }
}

// =========================================================================
// Parameters and outcomes
// =========================================================================

/// The two connection limits [`ConnectionPool::check_limits`] enforces.
///
/// C reads them off the multi handle at the top of the function
/// (`lib/conncache.c:383-386`) and re-reads them on every call rather than
/// caching, because an application may change either at any time. They arrive
/// as a parameter here for the reason `crate::conn::shutdown`'s
/// `conns_in_pool` does: the pool holds no handle back to the multi handle.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct ConnectionLimits {
    /// `multi->max_host_connections`, `CURLMOPT_MAX_HOST_CONNECTIONS`. Zero
    /// means no limit.
    pub(crate) max_host: usize,
    /// `multi->max_total_connections`, `CURLMOPT_MAX_TOTAL_CONNECTIONS`. Zero
    /// means no limit.
    pub(crate) max_total: usize,
}

/// What [`ConnectionPool::conn_now_idle`] needs in order to decide whether the
/// pool is over its cap.
///
/// Both come off the multi handle in the C (`lib/conncache.c:564-570`), and
/// both are needed because the effective cap is the configured value when it
/// is nonzero and a function of the running-transfer count when it is not.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct IdleLimits {
    /// `multi->maxconnects`, `CURLMOPT_MAXCONNECTS`. Zero selects the derived
    /// cap described by [`effective_maxconnects`].
    pub(crate) maxconnects: u32,
    /// `Curl_multi_xfers_running(multi)`: how many transfers are running.
    /// Read only when `maxconnects` is zero.
    pub(crate) running_transfers: u32,
}

/// What a pruning pass looked at and what it removed -- C's
/// `struct cpool_reaper_ctx` (`lib/conncache.c:687-690`).
///
/// C zeroes it, fills it in and never reads it. It is returned here because a
/// test needs to distinguish "the interval gate skipped the pass" from "the
/// pass ran and found nothing", which are the same observable state
/// otherwise.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct PruneStats {
    /// How many connections the injected predicate was asked about.
    ///
    /// C increments this for every connection that was not already an idle
    /// no-reuse one, INCLUDING connections in use -- `Curl_conn_seems_dead`
    /// then answers not-dead for those because of its own
    /// `if(!CONN_INUSE(conn))` gate. Here the pool applies that gate itself
    /// (see [`ConnectionPool::prune_dead`]), so an in-use connection is never
    /// counted. The figure is diagnostic in both trees.
    pub(crate) checked: usize,
    /// How many connections were terminated.
    pub(crate) reaped: usize,
}

/// What became of a connection [`ConnectionPool::terminate`] was asked to
/// discard.
///
/// C's `Curl_conn_terminate` returns `void` and expresses two of these three
/// outcomes as an early `return` (`lib/conncache.c:649-653`, and the same test
/// again inside `cpool_discard_conn` at `:200-205`). Naming them is what lets
/// [`ConnectionPool::conn_now_idle`] and [`ConnectionPool::prune_dead`] tell
/// whether the connection they chose actually went, which both of them need in
/// order not to loop.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum TerminateOutcome {
    /// Ownership was consumed: the connection has left the pool and is either
    /// released or queued for shutdown.
    Terminated,
    /// Still in the pool, because it is in use and the request was not an
    /// abort. C's `if(CONN_INUSE(conn) && !aborted) return;`.
    LeftInUse,
    /// The key named no live connection.
    NotFound,
}

#[allow(dead_code)] // consumers: `crate::protocols` and `crate::multi`
impl TerminateOutcome {
    /// Did the connection leave the pool?
    pub(crate) const fn is_terminated(self) -> bool {
        matches!(self, Self::Terminated)
    }
}

/// What a matcher answers for the entry it has just examined --
/// `Curl_cpool_conn_match_cb` (`lib/conncache.h:96-98`) plus the one side
/// effect the C's own matcher performs.
///
/// The C callback returns a bare `bool`, but `url_match_conn` does more than
/// answer it: on finding a dead candidate it calls `Curl_conn_terminate` on
/// that connection and THEN returns `FALSE` to continue the scan
/// (`lib/url.c:1291-1296`). Reproducing that needs a third answer, because a
/// matcher here cannot be handed the pool -- doing so would alias the very
/// borrow the traversal holds, which is the aliasing the C only avoids by
/// advancing its list cursor before every callback (`lib/conncache.c:618-619`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: `crate::protocols`, once reuse matching lands
pub(crate) enum MatchVerdict {
    /// `return FALSE`: not suitable, keep looking.
    Continue,
    /// `return TRUE`: suitable, stop here.
    Select,
    /// `Curl_conn_terminate(...); return FALSE`: not suitable, and it must
    /// leave the pool. The entry is removed at once -- so the traversal
    /// cannot revisit it -- and the owned connection is handed back in
    /// [`FindOutcome::discarded`] for the caller to terminate.
    DiscardAndContinue,
}

/// What [`ConnectionPool::find`] reports.
///
/// [`Self::matched`] is the C's `bool` return, after the done callback has had
/// its chance to override it. The other two fields have no C counterpart
/// because the C reaches both through the caller's `userdata`: the selected
/// connection through `match->found`, and the discarded ones not at all --
/// they are already gone by the time the callback returns.
pub(crate) struct FindOutcome {
    /// The combined result of the last matcher and the done callback.
    pub(crate) matched: bool,
    /// The entry the matcher selected, when it selected one. Still in the
    /// pool: selecting is not removing.
    pub(crate) selected: Option<PoolKey>,
    /// Entries the matcher asked to discard. Already removed from the pool
    /// and owned by this value, so the caller must terminate or drop them.
    pub(crate) discarded: Vec<PooledConnection>,
}

impl fmt::Debug for FindOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FindOutcome")
            .field("matched", &self.matched)
            .field("selected", &self.selected)
            .field("discarded", &self.discarded.len())
            .finish()
    }
}

/// The effective connection cap -- `lib/conncache.c:564-570`.
///
/// ```text
/// if(!data->multi->maxconnects) {
///   unsigned int running = Curl_multi_xfers_running(data->multi);
///   maxconnects = (running <= UINT_MAX / 4) ? running * 4 : UINT_MAX;
/// }
/// else
///   maxconnects = data->multi->maxconnects;
/// ```
///
/// Three details are pinned by tests because each is easy to get wrong:
///
/// * A configured value of zero does NOT mean "no connections"; it selects
///   the derived cap.
/// * The derived cap is four times the RUNNING TRANSFER count, not four times
///   anything about the pool.
/// * The multiplication saturates at [`u32::MAX`] rather than wrapping. C
///   writes the guard as `running <= UINT_MAX / 4` and picks `UINT_MAX` when
///   it fails, which is precisely [`u32::saturating_mul`] -- so the two agree
///   on every input including the boundary, where `UINT_MAX / 4` multiplied by
///   four is still representable and must NOT saturate.
pub(crate) fn effective_maxconnects(configured: u32, running: u32) -> u32 {
    if configured != 0 {
        return configured;
    }
    running.saturating_mul(4)
}

/// Which handle a shutdown step is charged to.
///
/// `ShutdownHandle::of` is private to `crate::conn::shutdown`, so the one
/// decision it makes is repeated here rather than reached for. It is C's
/// `data->multi && data->multi->admin` (`lib/cshutdn.c:139`), which
/// [`ShutdownHost::has_admin`] answers whole -- and the pool always charges to
/// the admin handle when there is one, because every one of its own shutdown
/// calls passes `cpool->idata` (`lib/conncache.c:222`, `:226`).
fn admin_handle<H>(host: &H) -> ShutdownHandle
where
    H: ShutdownHost + ?Sized,
{
    if host.has_admin() {
        ShutdownHandle::Admin
    } else {
        ShutdownHandle::Caller
    }
}

// =========================================================================
// A destination bundle
// =========================================================================

/// The connections to one destination -- C's `struct cpool_bundle`
/// (`lib/conncache.c:62-67`).
///
/// C's three members become one. `struct Curl_llist conns` becomes a
/// [`Vec`] of keys; `size_t dest_len` becomes nothing, because a Rust string
/// carries its own length and the C only kept the figure so that it could
/// pass it to the hash as a key length; and `char dest[1]`, the
/// over-allocated trailing array, becomes the [`BTreeMap`] key, so the
/// destination is stored once rather than once per bundle plus once per
/// connection.
///
/// # Order
///
/// Insertion order, and only insertion order. `Curl_llist_append`
/// (`lib/conncache.c:94`) puts a new connection at the tail and every
/// traversal starts at the head, so a plain [`Vec`] with `push` and
/// index-preserving removal reproduces the sequence exactly. Nothing is ever
/// moved within it: see the module's eviction-policy point 4.
#[derive(Debug, Default)]
struct Bundle {
    /// The connections to this destination, oldest INSERTION first.
    order: Vec<PoolKey>,
}

// =========================================================================
// The pool
// =========================================================================

/// The pool of reusable connections -- C's `struct cpool`
/// (`lib/conncache.h:49-60`).
///
/// C's ten members become seven, and the three that go are the module
/// documentation's "no successor" list: `idata`, `share`, `locked` and
/// `initialised` all disappear, while `dest2bundle`, `num_conn`,
/// `next_connection_id`, `next_easy_id` and `last_cleanup` all remain. Two
/// members are added, and both exist because the pool now OWNS its
/// connections instead of pointing at them: the slab that holds them, and the
/// identity map that finds one without a full traversal.
///
/// # Ownership
///
/// Every connection is owned by [`Self::conns`] and referenced from exactly
/// two places -- its destination bundle and the identity map -- by key, never
/// by pointer. Removing it clears both references and hands the value out, so
/// a connection can be terminated once and only once. Dropping the pool drops
/// every connection it still holds, which releases their filter chains: C's
/// `Curl_hash_destroy` does the same for its bundles, but only because
/// `Curl_cpool_destroy` emptied them first, and it LEAKS any connection that
/// `cpool_discard_conn` declined to take (`lib/conncache.c:245-249`).
///
/// # Not a lock, and not a singleton
///
/// There is no interior lock; see the module documentation. There is also no
/// global instance: C selects between three pools by asking the transfer which
/// one it belongs to (`cpool_get_instance`, `lib/conncache.c:256-267`), and
/// that selection belongs to whoever owns the pools -- a share, a multi handle
/// or an easy handle's implicit multi. This type is just the pool.
#[derive(Debug)]
pub(crate) struct ConnectionPool {
    /// Every pooled connection, owned. Keyed by [`PoolKey`].
    conns: GenerationalSlab<PooledConnection>,
    /// C's `struct Curl_hash dest2bundle`, keyed by the exact destination
    /// bytes -- the C hashes with `Curl_hash_str` and compares with
    /// `curlx_str_key_compare` (`lib/conncache.c:118-119`), which is
    /// case-SENSITIVE, so `String` equality is the same predicate.
    ///
    /// A [`BTreeMap`] rather than a hash map, for determinism: the pool-wide
    /// scans and traversals visit bundles in this order, and a test that
    /// asserts the maximum-age rule must not be able to pass by accident
    /// because a hash happened to place the right bundle first. The order is
    /// never read as a recency signal -- see the module's eviction-policy
    /// point 4.
    dest2bundle: BTreeMap<String, Bundle>,
    /// Identity to storage. C has no counterpart: `Curl_cpool_get_conn`
    /// (`lib/conncache.c:778-792`) and `Curl_cpool_do_by_id` (`:812-826`)
    /// both walk the entire pool comparing `conn->connection_id`. The map
    /// answers the same question, and -- more to the point -- lets a lookup
    /// VALIDATE that the identity still names a live connection instead of
    /// silently finding nothing.
    by_id: BTreeMap<ConnectionId, PoolKey>,
    /// C's `size_t num_conn`.
    ///
    /// Kept as its own field rather than derived from `conns.len()`, because
    /// the C keeps it and every trace line and limit comparison reads it. It
    /// is maintained in lockstep with the slab and a `debug_assert` in
    /// [`Self::add`] and [`Self::remove`] proves the two agree, so the
    /// duplication cannot drift silently.
    num_conn: usize,
    /// C's `curl_off_t next_connection_id`.
    next_connection_id: CurlOffT,
    /// C's `curl_off_t next_easy_id`.
    next_transfer_id: CurlOffT,
    /// C's `struct curltime last_cleanup`: when pruning last ran. Zero on a
    /// fresh pool, exactly as `calloc` leaves it, so the first prune is never
    /// gated.
    last_cleanup: CurlTime,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // consumers: `crate::multi`, `crate::share`, `crate::easy`
impl ConnectionPool {
    // -- construction and interrogation ----------------------------------

    /// An empty pool -- `Curl_cpool_init` (`lib/conncache.c:113-126`).
    ///
    /// **Cannot fail**, which the C's own header states (`lib/conncache.h:63`)
    /// and its `void` return already promised. The C's `size` argument is the
    /// hash's initial bucket count and has no counterpart: a [`BTreeMap`] has
    /// no bucket count to size.
    pub(crate) fn new() -> Self {
        Self {
            conns: GenerationalSlab::new(),
            dest2bundle: BTreeMap::new(),
            by_id: BTreeMap::new(),
            num_conn: 0,
            next_connection_id: ConnectionId::FIRST.get(),
            next_transfer_id: TransferId::FIRST.get(),
            last_cleanup: CurlTime::ZERO,
        }
    }

    /// C's `cpool->num_conn`: how many connections are pooled.
    pub(crate) const fn count(&self) -> usize {
        self.num_conn
    }

    /// Is the pool empty?
    pub(crate) const fn is_empty(&self) -> bool {
        self.num_conn == 0
    }

    /// How many bundles the pool holds -- one per distinct destination.
    pub(crate) fn destinations(&self) -> usize {
        self.dest2bundle.len()
    }

    /// How many connections to `destination` are pooled --
    /// `Curl_llist_count(&bundle->conns)` over the bundle
    /// `cpool_find_bundle` returns, or zero when there is no bundle
    /// (`lib/conncache.c:396`).
    pub(crate) fn destination_count(&self, destination: &str) -> usize {
        self.dest2bundle
            .get(destination)
            .map_or(0, |bundle| bundle.order.len())
    }

    /// When pruning last ran -- C's `cpool->last_cleanup`.
    pub(crate) const fn last_cleanup(&self) -> CurlTime {
        self.last_cleanup
    }

    // -- transfer initialisation -----------------------------------------

    /// Enrols a transfer in this pool -- `Curl_cpool_xfer_init`
    /// (`lib/conncache.c:269-289`).
    ///
    /// Two things happen, and both are reproduced exactly:
    ///
    /// ```text
    /// data->id = cpool->next_easy_id++;
    /// if(cpool->next_easy_id <= 0)
    ///   cpool->next_easy_id = 0;
    /// data->state.lastconnect_id = -1;
    /// ```
    ///
    /// The guard is a WRAP SAFEGUARD, not an error path: `curl_off_t` is
    /// signed, so a counter that ran past [`i64::MAX`] would go negative and
    /// start colliding with the `-1` sentinel. C resets it to zero instead,
    /// and so does this -- using [`CurlOffT::wrapping_add`] so that the
    /// increment which triggers the guard is defined rather than undefined as
    /// it is in C.
    pub(crate) fn xfer_init(&mut self) -> XferInit {
        let transfer_id = TransferId::new(self.next_transfer_id);
        self.next_transfer_id = self.next_transfer_id.wrapping_add(1);
        if self.next_transfer_id <= 0 {
            self.next_transfer_id = 0;
        }
        XferInit {
            transfer_id,
            lastconnect_id: ConnectionId::NONE,
        }
    }

    // -- adding and removing ----------------------------------------------

    /// Puts a new connection into the pool -- `Curl_cpool_add`
    /// (`lib/conncache.c:466-498`).
    ///
    /// In C's order: find or create the destination bundle, link the
    /// connection into it and set `bits.in_cpool`, assign
    /// `conn->connection_id` from the counter, increment `num_conn`, and
    /// trace. The identity is assigned HERE and nowhere else, which is why
    /// this takes a [`ConnectionSpec`] and not a built connection.
    ///
    /// **Infallible.** The C returns `CURLcode` and its only failure is a
    /// failed `calloc` for the bundle (`:483`); a failed allocation aborts
    /// this process before a caller could observe a code, so there is no
    /// error to report and no arm no test could cover.
    ///
    /// # Identity exhaustion
    ///
    /// The counter saturates at [`i64::MAX`] rather than wrapping. Reaching it
    /// needs 2^63 connections in one pool, so the arm is unreachable in any
    /// real process -- but saturating is still the right choice over wrapping,
    /// because a wrapped counter would eventually hand out `-1`, and `-1` is
    /// [`ConnectionId::NONE`].
    pub(crate) fn add(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        spec: ConnectionSpec,
    ) -> PoolKey {
        let id = ConnectionId::new(self.next_connection_id);
        self.next_connection_id = self.next_connection_id.saturating_add(1);

        let conn = PooledConnection::new(id, spec);
        let destination = conn.destination().to_owned();
        let key = self.conns.insert(conn);
        self.dest2bundle
            .entry(destination)
            .or_default()
            .order
            .push(key);
        self.by_id.insert(id, key);
        self.num_conn += 1;
        debug_assert_eq!(
            self.num_conn,
            self.conns.len(),
            "the connection count and the slab must agree"
        );

        if let Some(tracer) = cx.tracer_mut() {
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "[CPOOL] added connection {}. The cache now contains {} \
                 members",
                id,
                self.num_conn,
            );
        }
        key
    }

    /// Takes a connection out of the pool -- `cpool_remove_conn`
    /// (`lib/conncache.c:162-182`).
    ///
    /// C unlinks the connection from its bundle, destroys the bundle when
    /// that leaves it empty, clears `bits.in_cpool` and decrements
    /// `num_conn`. All four happen here, plus the identity mapping is dropped
    /// -- and then the connection is handed OUT rather than left behind a
    /// pointer the caller already had.
    ///
    /// That difference is the whole of AAP pattern P5's "explicit ownership":
    /// after this returns, the pool cannot reach the connection and the caller
    /// cannot leave it un-terminated by accident, because the value has to go
    /// somewhere.
    ///
    /// [`None`] when `key` is stale, and the pool is then untouched.
    pub(crate) fn remove(&mut self, key: PoolKey) -> Option<PooledConnection> {
        let (destination, id) = {
            let conn = self.conns.get(key)?;
            (conn.destination().to_owned(), conn.connection_id())
        };
        let mut conn = self.conns.remove(key)?;
        self.unlink_from_bundle(&destination, key);
        self.by_id.remove(&id);
        conn.in_pool = false;
        self.num_conn = self.num_conn.saturating_sub(1);
        debug_assert_eq!(
            self.num_conn,
            self.conns.len(),
            "the connection count and the slab must agree"
        );
        Some(conn)
    }

    /// Takes the connection with the given identity out of the pool.
    ///
    /// Validates the mapping before acting on it and, when the mapping has
    /// outlived its connection, DROPS the mapping rather than answering with
    /// it. [`Self::remove`] clears both together so the situation cannot
    /// arise, and the defensive clean-up is here so that it cannot persist if
    /// it ever did.
    pub(crate) fn remove_by_id(
        &mut self,
        id: ConnectionId,
    ) -> Option<PooledConnection> {
        let key = self.by_id.get(&id).copied()?;
        if self.conns.get(key).is_none() {
            self.by_id.remove(&id);
            return None;
        }
        self.remove(key)
    }

    /// Unlinks `key` from `destination`'s bundle, dropping the bundle when it
    /// empties -- `cpool_bundle_remove` plus `cpool_remove_bundle`
    /// (`lib/conncache.c:99-106`, `:154-160`).
    fn unlink_from_bundle(&mut self, destination: &str, key: PoolKey) {
        let emptied = match self.dest2bundle.get_mut(destination) {
            Some(bundle) => {
                if let Some(at) =
                    bundle.order.iter().position(|held| *held == key)
                {
                    // Order-preserving removal. A swapping removal would be
                    // cheaper and would REORDER the bundle, which is the one
                    // thing point 4 of the module's eviction policy forbids.
                    bundle.order.remove(at);
                }
                bundle.order.is_empty()
            }
            None => false,
        };
        if emptied {
            self.dest2bundle.remove(destination);
        }
    }

    /// Unlinks a key whose connection is already gone, wherever it is.
    ///
    /// Defensive only, and reachable only from [`Self::destroy`]: a bundle
    /// holding a key the slab does not is an invariant violation that
    /// [`Self::remove`] cannot produce. Unlinking rather than retrying is
    /// what makes `destroy`'s loop terminate whatever state it is handed.
    fn unlink_stale(&mut self, key: PoolKey) {
        let mut emptied = None;
        for (destination, bundle) in &mut self.dest2bundle {
            if let Some(at) = bundle.order.iter().position(|held| *held == key)
            {
                bundle.order.remove(at);
                if bundle.order.is_empty() {
                    emptied = Some(destination.clone());
                }
                break;
            }
        }
        if let Some(destination) = emptied {
            self.dest2bundle.remove(&destination);
        }
    }

    // -- lookup ------------------------------------------------------------

    /// The connection `key` names, or [`None`] when the key is stale.
    pub(crate) fn get(&self, key: PoolKey) -> Option<&PooledConnection> {
        self.conns.get(key)
    }

    /// The connection `key` names, mutably.
    pub(crate) fn get_mut(
        &mut self,
        key: PoolKey,
    ) -> Option<&mut PooledConnection> {
        self.conns.get_mut(key)
    }

    /// [`Self::get`] with the failure named.
    ///
    /// # Errors
    ///
    /// [`StaleKey`] when the key no longer resolves -- either because the
    /// connection was removed or because the slot has been reused by a
    /// different one.
    pub(crate) fn try_get(
        &self,
        key: PoolKey,
    ) -> Result<&PooledConnection, StaleKey> {
        self.conns.get(key).ok_or(StaleKey { key })
    }

    /// [`Self::get_mut`] with the failure named.
    ///
    /// # Errors
    ///
    /// As [`Self::try_get`].
    pub(crate) fn try_get_mut(
        &mut self,
        key: PoolKey,
    ) -> Result<&mut PooledConnection, StaleKey> {
        self.conns.get_mut(key).ok_or(StaleKey { key })
    }

    /// The storage key for an ABI-visible identity, when it still names a
    /// live connection.
    ///
    /// Both halves are checked: the identity must be mapped, AND the mapped
    /// key must still resolve in the slab. A stale or removed identity answers
    /// [`None`], never a different connection.
    pub(crate) fn key_of(&self, id: ConnectionId) -> Option<PoolKey> {
        let key = self.by_id.get(&id).copied()?;
        self.conns.get(key).map(|_| key)
    }

    /// The connection with the given identity -- `Curl_cpool_get_conn`
    /// (`lib/conncache.c:778-792`).
    ///
    /// C walks the whole pool comparing `conn->connection_id`; this consults
    /// [`Self::key_of`], which answers the same question and additionally
    /// validates the generation.
    pub(crate) fn get_by_id(
        &self,
        id: ConnectionId,
    ) -> Option<&PooledConnection> {
        self.key_of(id).and_then(|key| self.conns.get(key))
    }

    /// [`Self::get_by_id`], mutably.
    pub(crate) fn get_by_id_mut(
        &mut self,
        id: ConnectionId,
    ) -> Option<&mut PooledConnection> {
        let key = self.key_of(id)?;
        self.conns.get_mut(key)
    }

    /// Runs `action` against the connection with the given identity --
    /// `Curl_cpool_do_by_id` (`lib/conncache.c:812-826`).
    ///
    /// Answers whether there was one, which C cannot: its `cpool_do_conn`
    /// returns `1` to stop the traversal and `Curl_cpool_do_by_id` discards
    /// that, so a caller cannot tell a completed action from a missing
    /// connection. Only the matching live connection is visited, and at most
    /// one.
    pub(crate) fn do_by_id<F>(&mut self, id: ConnectionId, action: F) -> bool
    where
        F: FnOnce(PoolKey, &mut PooledConnection),
    {
        match self.key_of(id) {
            Some(key) => match self.conns.get_mut(key) {
                Some(conn) => {
                    action(key, conn);
                    true
                }
                None => false,
            },
            None => false,
        }
    }

    /// Every pooled key, in bundle order then insertion order.
    ///
    /// The successor of `cpool_foreach`'s two nested walks
    /// (`lib/conncache.c:512-545`), and of the reason it advances its cursor
    /// before every callback: "we need to update curr before calling func(),
    /// because func() might decide to remove the connection". A snapshot makes
    /// that total rather than one-deep -- a callback may remove ANY
    /// connection, not just the current one, and the traversal still cannot
    /// follow a key that is gone because every step re-resolves it.
    fn all_keys(&self) -> Vec<PoolKey> {
        self.dest2bundle
            .values()
            .flat_map(|bundle| bundle.order.iter().copied())
            .collect()
    }

    /// The "first" connection in the pool -- `cpool_get_first`
    /// (`lib/conncache.c:128-145`): the head of the first non-empty bundle.
    fn first_key(&self) -> Option<PoolKey> {
        self.dest2bundle
            .values()
            .find_map(|bundle| bundle.order.first().copied())
    }

    // -- the two oldest-idle scans ---------------------------------------

    /// The longest-idle connection in one bundle --
    /// `cpool_bundle_get_oldest_idle` (`lib/conncache.c:308-334`).
    ///
    /// The C body, transcribed:
    ///
    /// ```text
    /// timediff_t highscore = -1;
    /// while(curr) {
    ///   if(!CONN_INUSE(conn)) {
    ///     score = curlx_ptimediff_ms(pnow, &conn->lastused);
    ///     if(score > highscore) { highscore = score; oldest_idle = conn; }
    ///   }
    ///   curr = Curl_node_next(curr);
    /// }
    /// ```
    ///
    /// Four properties, all of them deliberate and all of them tested:
    ///
    /// * **A FULL scan.** Every entry is scored; the walk does not stop early.
    /// * **`highscore` starts at `-1`**, not at zero. An idle age of exactly
    ///   zero -- a connection that became idle this very instant -- still
    ///   beats it, so a bundle of freshly idle connections has an answer
    ///   rather than none.
    /// * **The comparison is strictly `>`.** On a tie the EARLIER entry wins,
    ///   which for equal ages makes the result insertion-ordered and therefore
    ///   deterministic.
    /// * **Only in-use connections are skipped.** Close-marked and
    ///   connect-only connections ARE candidates here, unlike in
    ///   [`Self::oldest_idle`]. See the module's eviction-policy point 3.
    pub(crate) fn bundle_oldest_idle(
        &self,
        destination: &str,
        now: CurlTime,
    ) -> Option<PoolKey> {
        let bundle = self.dest2bundle.get(destination)?;
        let mut highscore: TimeDiff = -1;
        let mut oldest_idle = None;
        for key in &bundle.order {
            let conn = match self.conns.get(*key) {
                Some(conn) => conn,
                None => continue,
            };
            if conn.is_in_use() {
                continue;
            }
            let score = conn.idle_age_ms(now);
            if score > highscore {
                highscore = score;
                oldest_idle = Some(*key);
            }
        }
        oldest_idle
    }

    /// The longest-idle connection anywhere in the pool --
    /// `cpool_get_oldest_idle` (`lib/conncache.c:336-368`).
    ///
    /// Identical to [`Self::bundle_oldest_idle`] in every respect except the
    /// exclusion set, which is wider by two:
    ///
    /// ```text
    /// if(CONN_INUSE(conn) || conn->bits.close || conn->connect_only)
    ///   continue;
    /// ```
    ///
    /// The asymmetry is the C's and is preserved rather than tidied away; the
    /// module's eviction-policy point 3 records why. A connection marked for
    /// closing is already on its way out and a connect-only connection belongs
    /// to the application, so neither is the pool's to give up in order to
    /// make room somewhere else -- whereas a bundle over its OWN limit has no
    /// other candidate to offer.
    pub(crate) fn oldest_idle(&self, now: CurlTime) -> Option<PoolKey> {
        let mut highscore: TimeDiff = -1;
        let mut oldest_idle = None;
        for bundle in self.dest2bundle.values() {
            for key in &bundle.order {
                let conn = match self.conns.get(*key) {
                    Some(conn) => conn,
                    None => continue,
                };
                if conn.is_in_use() || conn.wants_close() || conn.connect_only()
                {
                    continue;
                }
                let score = conn.idle_age_ms(now);
                if score > highscore {
                    highscore = score;
                    oldest_idle = Some(*key);
                }
            }
        }
        oldest_idle
    }

    // -- matching ----------------------------------------------------------

    /// Looks for a reusable connection to `destination` -- `Curl_cpool_find`
    /// (`lib/conncache.c:595-633`).
    ///
    /// The bundle is visited head to tail -- insertion order, which is stable
    /// and is not a recency order -- and the walk stops at the first
    /// [`MatchVerdict::Select`]. `done` then runs and may override the answer,
    /// which is the whole purpose of C's second callback: `url_match_result`
    /// (`lib/url.c:1303-1330`) turns "nothing matched" into a decision about
    /// whether to wait for multiplexing.
    ///
    /// # "All callbacks are invoked while the pool's lock is held"
    ///
    /// `lib/conncache.h:105` states that contract and it is preserved -- by
    /// construction rather than by a lock. This method holds `&mut self` for
    /// the whole traversal, so no other caller can observe or mutate the pool
    /// between two matcher calls.
    ///
    /// # What a callback may and may not do
    ///
    /// It gets the entry's key and the entry, mutably, so it can inspect it,
    /// record it, or mark it. It does NOT get the pool: handing one out would
    /// alias the borrow the traversal itself holds, and would reintroduce
    /// exactly the re-entrancy C guards against by hand. Removal is expressed
    /// instead as [`MatchVerdict::DiscardAndContinue`], which unlinks the entry
    /// immediately -- so the scan cannot revisit it -- and moves the owned
    /// connection into [`FindOutcome::discarded`] for the caller to terminate.
    ///
    /// `done` additionally receives the SELECTED entry, mutably, which is how
    /// `url_match_result`'s "attach it now while still under lock, so the
    /// connection does no longer appear idle and can be reaped"
    /// (`lib/url.c:1309-1311`) is expressed without the callback needing the
    /// pool either.
    pub(crate) fn find<M, D>(
        &mut self,
        destination: &str,
        mut matcher: M,
        done: Option<D>,
    ) -> FindOutcome
    where
        M: FnMut(PoolKey, &mut PooledConnection) -> MatchVerdict,
        D: FnOnce(bool, Option<&mut PooledConnection>) -> bool,
    {
        let mut matched = false;
        let mut selected = None;
        let mut discarded = Vec::new();

        let order = match self.dest2bundle.get(destination) {
            Some(bundle) => bundle.order.clone(),
            None => Vec::new(),
        };

        for key in order {
            // Re-resolved on every step. This is C's "get next node now,
            // callback might discard current" (`:618-619`) made total: a
            // callback that discarded some OTHER entry would leave C's
            // already-advanced cursor pointing at freed memory, while a key
            // that no longer resolves is simply skipped.
            let verdict = match self.conns.get_mut(key) {
                Some(conn) => matcher(key, conn),
                None => continue,
            };
            match verdict {
                MatchVerdict::Continue => {}
                MatchVerdict::Select => {
                    matched = true;
                    selected = Some(key);
                    break;
                }
                MatchVerdict::DiscardAndContinue => {
                    if let Some(conn) = self.remove(key) {
                        discarded.push(conn);
                    }
                }
            }
        }

        if let Some(done) = done {
            let entry = selected.and_then(|key| self.conns.get_mut(key));
            matched = done(matched, entry);
        }

        FindOutcome {
            matched,
            selected,
            discarded,
        }
    }

    // -- the connection limits --------------------------------------------

    /// Has the pool reached its configured limits -- `Curl_cpool_check_limits`
    /// (`lib/conncache.c:370-463`).
    ///
    /// It does not merely report: it TRIES to make room, by discarding the
    /// oldest idle connections, and only reports a limit once it has failed
    /// to.
    ///
    /// # The two loops
    ///
    /// Both have the same shape and the difference between them is the whole
    /// of the asymmetry the module's eviction policy describes:
    ///
    /// 1. **Destination.** While `live + shutdowns >= max_host`: force-close
    ///    the oldest SHUTTING-DOWN connection to this destination if there is
    ///    one; otherwise take this bundle's oldest idle connection
    ///    ([`Self::bundle_oldest_idle`], which excludes only in-use ones) and
    ///    terminate it. If neither is possible, stop. Still full afterwards is
    ///    [`CpoolLimit::Destination`].
    /// 2. **Total.** While `count() + queue.count() >= max_total`: force-close
    ///    the oldest shutting-down connection to ANY destination if there is
    ///    one; otherwise take the pool's oldest idle connection
    ///    ([`Self::oldest_idle`], which additionally excludes close-marked and
    ///    connect-only ones) and terminate it. Still full afterwards is
    ///    [`CpoolLimit::Total`].
    ///
    /// # Four details that are load-bearing
    ///
    /// * **Both limits zero returns immediately, with no scan** (`:388-389`).
    ///   The C tests this before it even takes the lock.
    /// * **Shutdown first, always.** A connection that is already draining is
    ///   cheaper to give up than a healthy idle one, and the C tries it first
    ///   in both loops (`:399-403`, `:436-440`).
    /// * **The bundle is looked up AGAIN after a termination** (`:421-423`),
    ///   because terminating the bundle's last connection destroys the bundle.
    ///   Reading a count through `destination_count` re-resolves it every
    ///   time, which is the same correction expressed so that it cannot be
    ///   forgotten.
    /// * **The shutdown count is never cached across iterations** (`:425`,
    ///   `:453`). Terminating a connection may ADD one to the queue, so a
    ///   cached figure would be wrong in the direction that matters.
    ///
    /// # Pooled and shutting-down connections count together
    ///
    /// Both loops add the queue's population to the pool's. This is the same
    /// invariant `crate::conn::shutdown::ShutdownQueue::add` enforces from the
    /// other side, and it belongs in both places: a draining connection still
    /// holds a descriptor and still occupies a slot against the limit the
    /// application set.
    pub(crate) async fn check_limits<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        queue: &mut ShutdownQueue,
        destination: &str,
        limits: ConnectionLimits,
    ) -> CpoolLimit
    where
        H: ShutdownHost + ?Sized,
    {
        // `:388-389`.
        if limits.max_host == 0 && limits.max_total == 0 {
            return CpoolLimit::Ok;
        }

        if limits.max_host != 0 {
            let mut live = self.destination_count(destination);
            let mut shutdowns = queue.destination_count(destination);
            while live + shutdowns >= limits.max_host {
                if shutdowns != 0 {
                    // `:399-403`. Failing to close one means nothing here can
                    // be given up now.
                    if !queue.close_oldest(cx, host, Some(destination)).await {
                        break;
                    }
                } else if live == 0 {
                    // `:404-405`, C's `else if(!bundle) break;`. A bundle is
                    // destroyed when it empties, so no connections to this
                    // destination is the same condition.
                    break;
                } else {
                    let now = cx.now();
                    let oldest_idle =
                        match self.bundle_oldest_idle(destination, now) {
                            Some(key) => key,
                            // `:412-413`. Everything here is in use.
                            None => break,
                        };
                    if let Some(conn) = self.conns.get(oldest_idle) {
                        let id = conn.connection_id();
                        if let Some(tracer) = cx.tracer_mut() {
                            trc_feat!(
                                tracer,
                                TraceFeature::Multi,
                                "Discarding connection #{} from {} to reach \
                                 destination limit of {}",
                                id,
                                live,
                                limits.max_host,
                            );
                        }
                    }
                    let outcome = self
                        .terminate(cx, host, queue, oldest_idle, false)
                        .await;
                    if !outcome.is_terminated() {
                        // Unreachable: the scan above excludes in-use
                        // connections, which is the only thing that declines
                        // a termination. Breaking rather than trusting that
                        // makes this loop provably finite.
                        break;
                    }
                    // `:421-423`: "in case the bundle was destroyed in
                    // disconnect, look it up again".
                    live = self.destination_count(destination);
                }
                // `:425`, at the BOTTOM of every iteration.
                shutdowns = queue.destination_count(destination);
            }
            // `:427-430`.
            if live + shutdowns >= limits.max_host {
                return CpoolLimit::Destination;
            }
        }

        if limits.max_total != 0 {
            // `:434`.
            let mut shutdowns = queue.count();
            while self.num_conn + shutdowns >= limits.max_total {
                if shutdowns != 0 {
                    // `:436-440`, and `NULL` there means any destination.
                    if !queue.close_oldest(cx, host, None).await {
                        break;
                    }
                } else {
                    let now = cx.now();
                    let oldest_idle = match self.oldest_idle(now) {
                        Some(key) => key,
                        // `:444-445`.
                        None => break,
                    };
                    if let Some(conn) = self.conns.get(oldest_idle) {
                        let id = conn.connection_id();
                        let count = self.num_conn;
                        if let Some(tracer) = cx.tracer_mut() {
                            trc_feat!(
                                tracer,
                                TraceFeature::Multi,
                                "Discarding connection #{} from {} to reach \
                                 total limit of {}",
                                id,
                                count,
                                limits.max_total,
                            );
                        }
                    }
                    let outcome = self
                        .terminate(cx, host, queue, oldest_idle, false)
                        .await;
                    if !outcome.is_terminated() {
                        // Unreachable, for the reason the destination loop
                        // gives.
                        break;
                    }
                }
                // `:453`.
                shutdowns = queue.count();
            }
            // `:455-458`.
            if self.num_conn + shutdowns >= limits.max_total {
                return CpoolLimit::Total;
            }
        }

        CpoolLimit::Ok
    }

    // -- becoming idle -----------------------------------------------------

    /// A pooled connection has become idle -- `Curl_cpool_conn_now_idle`
    /// (`lib/conncache.c:553-593`).
    ///
    /// Returns whether the connection that just became idle is STILL IN THE
    /// POOL: C's `kept`, documented at `lib/conncache.h:123` as "TRUE if idle
    /// connection kept in pool, FALSE if closed". It is `false` exactly when
    /// the pool-wide scan picked that same connection as its victim, which can
    /// happen because a connection that has this instant become idle has an
    /// idle age of zero and may still be the oldest in a pool where everything
    /// else is in use.
    ///
    /// # The order of the two steps matters
    ///
    /// `conn->lastused` is stamped FIRST (`:572`, "it was used up until now")
    /// and only then is the cap consulted. Reversing them would score the
    /// connection against a stale `lastused` and make it look like the oldest
    /// thing in the pool whatever its real age.
    ///
    /// # The cap
    ///
    /// [`effective_maxconnects`] computes it, and a cap of zero disables the
    /// check entirely (`:573`, `maxconnects` in the `&&`). The comparison is
    /// strictly `>`: a pool holding exactly `maxconnects` connections is at
    /// its cap, not over it.
    pub(crate) async fn conn_now_idle<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        queue: &mut ShutdownQueue,
        key: PoolKey,
        limits: IdleLimits,
    ) -> bool
    where
        H: ShutdownHost + ?Sized,
    {
        let maxconnects =
            effective_maxconnects(limits.maxconnects, limits.running_transfers);

        // `:572`, and before anything reads an age.
        let now = cx.now();
        match self.conns.get_mut(key) {
            Some(conn) => conn.set_lastused(now),
            // A connection that is not in the pool cannot be evicted from it,
            // so "kept" is the honest answer.
            None => return true,
        }

        if maxconnects == 0 {
            return true;
        }
        // C compares a `size_t` against an `unsigned int`, which the usual
        // arithmetic conversions widen. Every target of AAP section 0.8.3 is
        // 64-bit, so this conversion is exact; the fallback exists only so
        // that the expression is total.
        let cap = usize::try_from(maxconnects).unwrap_or(usize::MAX);
        if self.num_conn <= cap {
            return true;
        }

        // `:579-580`, emitted BEFORE the scan.
        let count = self.num_conn;
        if let Some(tracer) = cx.tracer_mut() {
            infof!(
                tracer,
                "Connection pool is full, closing the oldest of {}/{}",
                count,
                maxconnects,
            );
        }

        let oldest_idle = match self.oldest_idle(now) {
            Some(oldest) => oldest,
            // `:584`, C's `if(oldest_idle)`: with no victim, `kept` is
            // `(NULL != conn)`, which is TRUE.
            None => return true,
        };
        // `:583`, and computed BEFORE the termination invalidates the key.
        let kept = oldest_idle != key;
        self.terminate(cx, host, queue, oldest_idle, false).await;
        kept
    }

    // -- termination -------------------------------------------------------

    /// Terminates a pooled connection -- `Curl_conn_terminate`
    /// (`lib/conncache.c:635-685`).
    ///
    /// C's header says "Takes ownership of `conn`" (`lib/conncache.h:42`).
    /// Here that is not a comment: [`Self::remove`] moves the connection out
    /// of the pool and the value is then consumed, so a borrowed free and a
    /// double free are both unrepresentable.
    ///
    /// # The three outcomes
    ///
    /// * [`TerminateOutcome::LeftInUse`] -- the connection is in use and this
    ///   is not an abort, so it stays exactly where it is (`:647-653`). The
    ///   pool is not touched. C reaches the same state through an early
    ///   `return` after a `DEBUGASSERT(0)`, having written a diagnostic that
    ///   asks whether the case can happen at all.
    /// * [`TerminateOutcome::NotFound`] -- the key named no live connection.
    ///   C has no counterpart; its argument is a pointer, and a pointer to a
    ///   connection that is already gone is not a case it can detect.
    /// * [`TerminateOutcome::Terminated`] -- the connection has left the pool
    ///   and has been released or handed to the shutdown queue.
    ///
    /// # `connect_only` forces an abort
    ///
    /// `:668-669`, and the C's comment gives the reason: "treat the connection
    /// as aborted in CONNECT_ONLY situations, so no graceful shutdown is
    /// attempted". The application took the socket over, so libcurl does not
    /// know what state the protocol is in and must not speak on it.
    ///
    /// # Two different farewells
    ///
    /// With a multi handle the line is `"closing"` or `"shutting down"`
    /// according to `aborted` and the connection goes to [`Self::discard`],
    /// which may enqueue it (`:671-676`). Without one, the line is always
    /// `"closing"` and the connection is terminated on the spot with
    /// `do_shutdown = !aborted` (`:677-681`) -- note that this is the one path
    /// where a graceful pass is requested from `terminate` itself, whereas
    /// [`Self::discard`] always passes `false` because it has already made its
    /// own attempt.
    pub(crate) async fn terminate<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        queue: &mut ShutdownQueue,
        key: PoolKey,
        aborted: bool,
    ) -> TerminateOutcome
    where
        H: ShutdownHost + ?Sized,
    {
        let (id, in_use, attached) = match self.conns.get(key) {
            Some(conn) => (
                conn.connection_id(),
                conn.is_in_use(),
                conn.attached_xfers(),
            ),
            None => return TerminateOutcome::NotFound,
        };

        // `:647-653`.
        if in_use && !aborted {
            if let Some(tracer) = cx.tracer_mut() {
                infof!(tracer, "conn terminate when inuse: {}", attached);
            }
            return TerminateOutcome::LeftInUse;
        }

        // `:661-664`: out of the pool BEFORE anything shuts down.
        let conn = match self.remove(key) {
            Some(conn) => conn,
            None => return TerminateOutcome::NotFound,
        };

        // `:668-669`.
        let aborted = aborted || conn.connect_only();

        if host.has_multi() {
            // `:673-674`.
            let verb = if aborted { "closing" } else { "shutting down" };
            if let Some(tracer) = cx.tracer_mut() {
                infof!(tracer, "{} connection #{}", verb, id);
            }
            // `:675`.
            let leftover = self.discard(cx, host, queue, conn, aborted).await;
            // Unreachable: the in-use test at the top of this function has
            // exactly the condition `discard` re-tests, and nothing in
            // between can attach a transfer -- the connection is owned by
            // this frame. Dropping releases the filter chains even so, where
            // C would leave the connection alive with no owner at all.
            debug_assert!(
                leftover.is_none(),
                "discard declined a connection this function already vetted"
            );
            drop(leftover);
        } else {
            // `:679-680`. Always "closing", and the one place a graceful pass
            // is asked for by `terminate` rather than by `discard`.
            if let Some(tracer) = cx.tracer_mut() {
                infof!(tracer, "closing connection #{}", id);
            }
            let inner = conn.into_shutting_down(aborted);
            shutdown_terminate(cx, host, inner, !aborted).await;
        }

        TerminateOutcome::Terminated
    }

    /// Disposes of a connection that has already left the pool --
    /// `cpool_discard_conn` (`lib/conncache.c:184-229`).
    ///
    /// Its precondition is `!conn->bits.in_cpool` (`:194`), which
    /// [`PooledConnection::into_shutting_down`] and [`Self::remove`] between
    /// them guarantee.
    ///
    /// # Why a dead or aborted connection gets no graceful shutdown
    ///
    /// `:213-219`, quoting the C: *"We do not shutdown dead connections. The
    /// term 'dead' can be misleading here, as we also mark errored
    /// connections/transfers as 'dead'. If we do a shutdown for an aborted
    /// transfer, the server might think it was successful otherwise (for
    /// example an ftps: upload). This is not what we want."*
    ///
    /// So `aborted` short-circuits the shutdown step: `done` starts `true` and
    /// the one hopeful pass is skipped entirely. That is not an optimisation
    /// -- a polite goodbye on a failed upload is a correctness bug on the
    /// wire.
    ///
    /// # Otherwise: one non-blocking attempt, then hand over or queue
    ///
    /// `:220-228`. One `run_once` (`:222`), charged to the admin handle
    /// because every shutdown call the C makes from this file passes
    /// `cpool->idata`. If it finished, or if there is no multi handle to own
    /// the background work, the connection is released now; otherwise it joins
    /// the shutdown queue, which is told the pool's CURRENT population so that
    /// it can enforce the combined limit.
    ///
    /// # The return value
    ///
    /// [`Some`] gives the connection BACK, and means the same as C's early
    /// `return`: it is in use and this was not an abort, so it was not
    /// disposed of. [`None`] means it was consumed. Handing it back rather
    /// than leaving it behind a pointer is what stops [`Self::destroy`] from
    /// reproducing the C's leak at `:245-249`.
    async fn discard<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        queue: &mut ShutdownQueue,
        conn: PooledConnection,
        aborted: bool,
    ) -> Option<PooledConnection>
    where
        H: ShutdownHost + ?Sized,
    {
        debug_assert!(
            !conn.is_in_pool(),
            "a connection must leave the pool before it is discarded"
        );

        // `:200-205`.
        if conn.is_in_use() && !aborted {
            let id = conn.connection_id();
            let attached = conn.attached_xfers();
            if let Some(tracer) = cx.tracer_mut() {
                trc_feat!(
                    tracer,
                    TraceFeature::Multi,
                    "[CPOOL] not discarding #{} still in use by {} transfers",
                    id,
                    attached,
                );
            }
            return Some(conn);
        }

        // `:207-211`.
        let aborted = aborted || conn.connect_only();

        // `:218-219`: an aborted connection is already "done", so `:222` is
        // skipped and no farewell is sent.
        let mut done = aborted;
        let mut inner = conn.into_shutting_down(aborted);
        if !done {
            let handle = admin_handle(host);
            // `:222`.
            done = inner.run_once(cx, host, handle).await;
        }

        // `:225-228`.
        if done || !host.has_multi() {
            shutdown_terminate(cx, host, inner, false).await;
        } else {
            queue.add(cx, host, inner, self.num_conn).await;
        }
        None
    }

    /// Destroys the pool -- `Curl_cpool_destroy`
    /// (`lib/conncache.c:231-254`).
    ///
    /// Every remaining connection goes through the same disposal path as any
    /// other, in the C's order: take the first one out, discard it, repeat.
    /// The pool is empty afterwards.
    ///
    /// # Differences from the C, both deliberate
    ///
    /// * **No signal disposition is saved.** C brackets the loop with
    ///   `sigpipe_init`/`sigpipe_apply`/`sigpipe_restore` (`:235-251`);
    ///   nothing here writes to a raw descriptor, so there is nothing to
    ///   guard.
    /// * **Nothing leaks.** C removes the connection from the pool and then
    ///   calls `cpool_discard_conn`, which declines an in-use connection and
    ///   returns -- leaving a connection that is out of the pool and pointed
    ///   at by nobody. Here the declined connection comes back as a value and
    ///   is dropped, which releases its filter chains.
    pub(crate) async fn destroy<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        queue: &mut ShutdownQueue,
    ) where
        H: ShutdownHost + ?Sized,
    {
        // `:237-238`. The C prefixes "[SHARE] " when the pool belongs to a
        // share; which owner a pool has is not this type's knowledge, so the
        // prefix is the owner's to add.
        let count = self.num_conn;
        if let Some(tracer) = cx.tracer_mut() {
            trc_feat!(
                tracer,
                TraceFeature::Multi,
                "[CPOOL] destroy, {} connections",
                count,
            );
        }

        // `:242-249`.
        while let Some(key) = self.first_key() {
            match self.remove(key) {
                Some(conn) => {
                    let leftover =
                        self.discard(cx, host, queue, conn, false).await;
                    drop(leftover);
                }
                None => {
                    // Defensive, and the reason this loop cannot spin: a
                    // bundle holding a key the slab does not is an invariant
                    // violation `remove` cannot produce, and unlinking it
                    // makes progress where retrying would not.
                    self.unlink_stale(key);
                }
            }
        }

        debug_assert!(
            self.dest2bundle.is_empty() && self.num_conn == 0,
            "destroy must leave the pool empty"
        );
    }

    // -- pruning, upkeep and network change --------------------------------

    /// Reaps dead and unreusable connections -- `Curl_cpool_prune_dead`
    /// (`lib/conncache.c:718-737`).
    ///
    /// # The interval gate
    ///
    /// At most once per [`PRUNE_INTERVAL_MS`]. The C test is
    /// `if(elapsed >= 1000L)`, so a call at exactly one thousand milliseconds
    /// runs and one at nine hundred and ninety-nine does not. When the gate
    /// closes the pass does nothing at all -- it does not scan, and it does
    /// not move `last_cleanup`.
    ///
    /// # Restart after every removal
    ///
    /// `while(cpool_foreach(data, cpool, &reaper, cpool_reap_dead_cb));` --
    /// the callback returns `1` after terminating ONE connection, which aborts
    /// the traversal, and the `while` starts a fresh one. The counters carry
    /// across restarts because C zeroes the reaper context once, outside the
    /// loop (`:727`).
    ///
    /// The loop is finite because a restart happens only after a connection
    /// has actually left the pool.
    ///
    /// # What the predicate is and is not asked
    ///
    /// * An **idle no-reuse** connection is terminated WITHOUT consulting the
    ///   predicate (`:696`, `terminate = !CONN_INUSE(conn) &&
    ///   conn->bits.no_reuse`). There is nothing to ask: it has already been
    ///   ruled out.
    /// * An **in-use** connection is not pruned. C reaches that answer
    ///   through the predicate -- `Curl_conn_seems_dead`'s whole body is
    ///   inside `if(!CONN_INUSE(conn))` (`lib/url.c:659`) -- and the gate is
    ///   applied here as well. Doing so makes the restart loop provably
    ///   finite rather than dependent on an injected implementation honouring
    ///   its contract, and it is why [`PruneStats::checked`] does not count
    ///   in-use connections where the C's does.
    /// * Everything else IS asked, through [`ConnectionHealth`].
    pub(crate) async fn prune_dead<H, P>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        queue: &mut ShutdownQueue,
        health: &mut P,
    ) -> PruneStats
    where
        H: ShutdownHost + ?Sized,
        P: ConnectionHealth + ?Sized,
    {
        let mut stats = PruneStats::default();

        // `:729-731`.
        let elapsed = timediff_ms(cx.now(), self.last_cleanup);
        if elapsed < PRUNE_INTERVAL_MS {
            return stats;
        }

        // `:732-733`.
        while self
            .reap_one_dead(cx, host, queue, health, &mut stats)
            .await
        {}

        // `:734`, and only on a pass that actually ran.
        self.last_cleanup = cx.now();
        stats
    }

    /// One traversal of `cpool_reap_dead_cb` (`lib/conncache.c:692-709`),
    /// stopping at the first connection it removes.
    ///
    /// Answers whether it removed one, which is C's `cpool_foreach` returning
    /// `TRUE` because the callback returned `1`.
    async fn reap_one_dead<H, P>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        queue: &mut ShutdownQueue,
        health: &mut P,
        stats: &mut PruneStats,
    ) -> bool
    where
        H: ShutdownHost + ?Sized,
        P: ConnectionHealth + ?Sized,
    {
        for key in self.all_keys() {
            let (in_use, no_reuse) = match self.conns.get(key) {
                Some(conn) => (conn.is_in_use(), conn.no_reuse()),
                None => continue,
            };

            // `lib/url.c:659`, applied here; see this function's caller.
            if in_use {
                continue;
            }

            // `:696`.
            let mut reap = no_reuse;
            if !reap {
                // `:699-700`.
                stats.checked += 1;
                reap = match self.conns.get_mut(key) {
                    Some(conn) => health.seems_dead(cx, conn).dead,
                    None => continue,
                };
            }

            if reap {
                // `:702-707`.
                let outcome = self.terminate(cx, host, queue, key, false).await;
                if outcome.is_terminated() {
                    stats.reaped += 1;
                    return true;
                }
            }
        }
        false
    }

    /// Runs an upkeep pass over every pooled connection --
    /// `Curl_cpool_upkeep` (`lib/conncache.c:748-759`).
    ///
    /// Every connection is visited, including connections in use: C's
    /// `cpool_foreach` applies no filter and `conn_upkeep` returns `0`
    /// unconditionally so the traversal always completes.
    ///
    /// # Errors
    ///
    /// The FIRST error any action reported, once the whole pass has finished.
    /// C answers `CURLE_OK` always, because `conn_upkeep` throws its result
    /// away (`:744`). Reporting it is the strengthening
    /// [`UpkeepAction::upkeep`] documents; the pass is not cut short, because
    /// abandoning the remaining connections would leave them un-maintained
    /// for a reason that has nothing to do with them.
    pub(crate) fn upkeep<A>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        action: &mut A,
    ) -> CurlResult<()>
    where
        A: UpkeepAction + ?Sized,
    {
        let mut result = Ok(());
        for key in self.all_keys() {
            if let Some(conn) = self.conns.get_mut(key) {
                let outcome = action.upkeep(cx, conn);
                if result.is_ok() {
                    result = outcome;
                }
            }
        }
        result
    }

    /// The network changed -- `Curl_cpool_nw_changed`
    /// (`lib/conncache.c:862-873`).
    ///
    /// Two passes, in this order and for this reason:
    ///
    /// 1. **Mark EVERY connection no-reuse** (`cpool_mark_stale`, `:842-849`),
    ///    including connections currently in use. An interface change or a
    ///    resume from suspend invalidates every existing route, so no
    ///    connection may be handed to a new transfer -- but one already
    ///    carrying a transfer is not the pool's to interrupt.
    /// 2. **Terminate every IDLE one** (`cpool_reap_no_reuse`, `:851-860`),
    ///    restarting after each removal exactly as pruning does.
    ///
    /// The connections left behind stay marked, so each is removed by
    /// [`Self::prune_dead`] -- or by the very next pass of this function --
    /// the moment its last transfer detaches. Returns how many were removed;
    /// C returns nothing.
    pub(crate) async fn network_changed<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        queue: &mut ShutdownQueue,
    ) -> usize
    where
        H: ShutdownHost + ?Sized,
    {
        for key in self.all_keys() {
            if let Some(conn) = self.conns.get_mut(key) {
                conn.mark_no_reuse();
            }
        }

        let mut removed = 0;
        while self.reap_one_no_reuse(cx, host, queue).await {
            removed += 1;
        }
        removed
    }

    /// One traversal of `cpool_reap_no_reuse` (`lib/conncache.c:851-860`),
    /// stopping at the first connection it removes.
    async fn reap_one_no_reuse<H>(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        host: &mut H,
        queue: &mut ShutdownQueue,
    ) -> bool
    where
        H: ShutdownHost + ?Sized,
    {
        for key in self.all_keys() {
            let eligible = match self.conns.get(key) {
                Some(conn) => !conn.is_in_use() && conn.no_reuse(),
                None => continue,
            };
            if eligible {
                let outcome = self.terminate(cx, host, queue, key, false).await;
                if outcome.is_terminated() {
                    return true;
                }
            }
        }
        false
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::future::Future;
    use std::time::Duration;

    use crate::conn::filters::{link, ConnFilter, FilterBase, Liveness};
    use crate::error::CURLMcode;
    use crate::trace::{TimerId, TraceConfig, TraceState, Tracer, WriterSink};
    use crate::util::timeval::{Clock, TestClock};

    /// This file, for the structural assertions at the end of the module.
    const OWN_SOURCE: &str = include_str!("pool.rs");

    // -- fixtures: time, tracing and driving -------------------------------

    /// A clock fixed at a known instant, so that no test waits in real time.
    ///
    /// Every age in this module is a difference between two readings of the
    /// injected clock, which is what makes the maximum-age rule testable at
    /// all: a test places connections at chosen instants instead of sleeping.
    fn clock_at(secs: i64) -> TestClock {
        TestClock::new(CurlTime::new(secs, 0))
    }

    /// Runs `body` against a tracer whose `MULTI` feature is verbose and
    /// returns everything it wrote.
    ///
    /// `MULTI` is the feature every `[CPOOL]` and `[SHUTDOWN]` line is emitted
    /// under, because `CURL_TRC_M` is a multi-handle line.
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

    /// Drives a future to completion with no `tokio` runtime at all.
    ///
    /// Sound for every path these tests take: `tokio::time::timeout` is
    /// reachable only through a scheme's disconnect handler
    /// (`crate::conn::shutdown`'s `run_conn_handler`), and no connection built
    /// here installs one.
    fn drive<F: Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }

    // -- fixtures: the injected shutdown timer -----------------------------

    /// A deadline that is never started and never expires.
    ///
    /// The real one belongs to `conn/mod.rs`. Nothing in this module reads a
    /// shutdown deadline -- the pool hands connections over and the queue owns
    /// their timing -- so a null implementation is honest rather than lazy.
    #[derive(Clone, Copy, Debug, Default)]
    struct NullTimer;

    impl ShutdownTimer for NullTimer {
        fn started(&self, _sockindex: SocketIndex) -> bool {
            false
        }

        fn start(&mut self, _sockindex: SocketIndex, _timeout_ms: TimeDiff) {}

        fn time_left_ms(&self, _sockindex: SocketIndex) -> TimeDiff {
            0
        }

        fn clear(&mut self, _sockindex: SocketIndex) {}
    }

    // -- fixtures: the injected multi handle -------------------------------

    /// A recording [`ShutdownHost`].
    ///
    /// Every mutating method takes `&mut self`, so the record is a plain field:
    /// this module needs no shared-mutable fixture anywhere, which is itself
    /// evidence for [`the_pool_holds_no_interior_lock`].
    #[derive(Debug)]
    struct TestHost {
        has_admin: bool,
        has_multi: bool,
        socket_cb: bool,
        assess: CURLMcode,
        max_total: usize,
        events: Vec<String>,
    }

    impl TestHost {
        /// A multi handle with an admin handle, no socket callback and no
        /// connection limit.
        fn new() -> Self {
            Self {
                has_admin: true,
                has_multi: true,
                socket_cb: false,
                assess: CURLMcode::Ok,
                max_total: 0,
                events: Vec::new(),
            }
        }

        /// A caller with no multi handle -- C's `else` branch at
        /// `lib/conncache.c:677`.
        fn without_multi() -> Self {
            Self {
                has_admin: false,
                has_multi: false,
                ..Self::new()
            }
        }

        fn note(&mut self, what: impl Into<String>) {
            self.events.push(what.into());
        }
    }

    impl ShutdownHost for TestHost {
        fn has_admin(&self) -> bool {
            self.has_admin
        }

        fn has_multi(&self) -> bool {
            self.has_multi
        }

        /// Always false, deliberately: a handle reported internal is the one
        /// path on which a disconnect handler is wrapped in a `tokio` timeout,
        /// and [`drive`] runs without a runtime.
        fn is_internal(&self, _handle: ShutdownHandle) -> bool {
            false
        }

        fn set_operation_timeout_ms(
            &mut self,
            handle: ShutdownHandle,
            timeout_ms: TimeDiff,
        ) {
            self.note(format!("timeout({handle:?},{timeout_ms})"));
        }

        fn restart_operation_timing(&mut self, handle: ShutdownHandle) {
            self.note(format!("startop({handle:?})"));
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
            self.note(format!("assess({handle:?},#{id})"));
            self.assess
        }

        fn conn_done(
            &mut self,
            handle: ShutdownHandle,
            id: ConnId,
            _cx: &mut CallCtx<'_, '_>,
            _chains: &mut FilterChains,
        ) {
            self.note(format!("conn_done({handle:?},#{id})"));
        }

        fn connchanged(&mut self) {
            self.note("connchanged");
        }

        fn expire(
            &mut self,
            handle: ShutdownHandle,
            timeout_ms: TimeDiff,
            timer: TimerId,
        ) {
            self.note(format!("expire({handle:?},{timeout_ms},{timer})"));
        }

        fn max_total_connections(&self) -> usize {
            self.max_total
        }
    }

    // -- fixtures: a filter that takes several passes to shut down ---------

    /// A connected bottom-of-chain filter whose shutdown needs `steps` passes.
    ///
    /// The only reason this module needs a filter at all: with an empty chain
    /// `run_once` reports done on its first pass, so a connection would never
    /// reach the shutdown queue and
    /// [`a_graceful_termination_is_handed_to_the_queue`] would have nothing to
    /// observe.
    #[derive(Debug)]
    struct SlowFilter {
        base: FilterBase,
        steps_left: usize,
    }

    impl SlowFilter {
        fn new(sockindex: SocketIndex, steps: usize) -> Self {
            let mut base = FilterBase::new(sockindex);
            base.set_connected(true);
            Self {
                base,
                steps_left: steps,
            }
        }
    }

    impl ConnFilter for SlowFilter {
        fn trace_name(&self) -> &'static str {
            "slow"
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

        fn close(&mut self, _cx: &mut CallCtx<'_, '_>) {
            self.base.set_connected(false);
        }

        fn shutdown(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            if self.steps_left > 0 {
                self.steps_left -= 1;
                return Ok(false);
            }
            Ok(true)
        }
    }

    // -- fixtures: the injected health predicate ---------------------------

    /// A [`ConnectionHealth`] that follows the documented contract of
    /// `lib/url.c:622-700` exactly, with each of its four inputs settable.
    ///
    /// It exists so that all four branches -- maximum idle age, maximum
    /// lifetime, the scheme's own check and chain liveness -- are exercised
    /// with no live socket and with `crate::protocols` absent, which is the
    /// point of AAP pattern P12's seam.
    #[derive(Debug, Default)]
    struct ContractHealth {
        /// `CURLOPT_MAXAGE_CONN`; zero disables the rule, as C's does.
        max_idle_ms: TimeDiff,
        /// `CURLOPT_MAXLIFETIME_CONN`; zero disables the rule.
        max_age_ms: TimeDiff,
        /// The scheme's `connection_check` answer, when it registers one.
        protocol_check: Option<ConnResult>,
        /// The liveness to report. [`None`] asks the real filter chain, which
        /// is how the seam is shown to reach the filter layer.
        liveness: Option<Liveness>,
        /// The identity of every connection the pool asked about, in order.
        asked: Vec<ConnectionId>,
        /// The reason returned for each answer that was "dead".
        reasons: Vec<DeadReason>,
    }

    impl ConnectionHealth for ContractHealth {
        fn seems_dead(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            conn: &mut PooledConnection,
        ) -> DeadVerdict {
            self.asked.push(conn.connection_id());

            // Contract step 1: `if(!CONN_INUSE(conn))` (`lib/url.c:659`).
            if conn.is_in_use() {
                return DeadVerdict::ALIVE;
            }

            let now = cx.now();

            // Contract step 2: idle age BEFORE lifetime (`:628-647`).
            let verdict = if self.max_idle_ms != 0
                && conn.idle_age_ms(now) > self.max_idle_ms
            {
                DeadVerdict::dead(DeadReason::MaxIdleAge)
            } else if self.max_age_ms != 0
                && conn.lifetime_ms(now) > self.max_age_ms
            {
                DeadVerdict::dead(DeadReason::MaxLifetime)
            } else if let Some(state) = self.protocol_check {
                // Contract step 3: `state & CONNRESULT_DEAD` (`:677-679`).
                if state.contains(ConnResult::DEAD) {
                    DeadVerdict::dead(DeadReason::ProtocolCheck)
                } else {
                    DeadVerdict::ALIVE
                }
            } else {
                // Contract step 4: chain liveness, and reject pending input
                // even on a live connection (`:684-700`).
                let liveness = match self.liveness {
                    Some(liveness) => liveness,
                    None => {
                        let wants_close = conn.wants_close();
                        conn.chains_mut()
                            .chain_mut(SocketIndex::First)
                            .is_alive(cx, wants_close)
                    }
                };
                if !liveness.alive {
                    DeadVerdict::dead(DeadReason::NotAlive)
                } else if liveness.input_pending {
                    DeadVerdict::dead(DeadReason::InputPending)
                } else {
                    DeadVerdict::ALIVE
                }
            };

            if let Some(reason) = verdict.reason {
                self.reasons.push(reason);
            }
            verdict
        }
    }

    /// A predicate that condemns everything it is asked about, and records
    /// what it was asked.
    #[derive(Debug, Default)]
    struct AlwaysDead {
        asked: Vec<ConnectionId>,
    }

    impl ConnectionHealth for AlwaysDead {
        fn seems_dead(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            conn: &mut PooledConnection,
        ) -> DeadVerdict {
            self.asked.push(conn.connection_id());
            DeadVerdict::dead(DeadReason::NotAlive)
        }
    }

    // -- fixtures: the injected upkeep action ------------------------------

    /// An [`UpkeepAction`] that records every visit and can fail on one of
    /// them.
    #[derive(Debug, Default)]
    struct RecordingUpkeep {
        visited: Vec<ConnectionId>,
        fail_on: Option<ConnectionId>,
    }

    impl UpkeepAction for RecordingUpkeep {
        fn upkeep(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            conn: &mut PooledConnection,
        ) -> CurlResult<()> {
            let id = conn.connection_id();
            self.visited.push(id);
            if self.fail_on == Some(id) {
                return Err(CURLcode::SendError.into());
            }
            Ok(())
        }
    }

    // -- fixtures: connections --------------------------------------------

    /// A description with empty chains, a null deadline and no handler.
    fn spec(destination: &str, created: CurlTime) -> ConnectionSpec {
        ConnectionSpec::new(
            destination,
            FilterChains::new(None),
            Box::new(NullTimer),
            created,
        )
    }

    /// A description whose primary chain needs `steps` shutdown passes.
    fn slow_spec(
        cx: &mut CallCtx<'_, '_>,
        destination: &str,
        created: CurlTime,
        steps: usize,
    ) -> ConnectionSpec {
        let mut chains = FilterChains::new(None);
        chains
            .chain_mut(SocketIndex::First)
            .add(cx, link(SlowFilter::new(SocketIndex::First, steps)));
        ConnectionSpec::new(destination, chains, Box::new(NullTimer), created)
    }

    /// Pools an idle connection to `destination` whose `lastused` -- and
    /// therefore whose age -- is `at`.
    fn add_idle_at(
        pool: &mut ConnectionPool,
        cx: &mut CallCtx<'_, '_>,
        destination: &str,
        at: CurlTime,
    ) -> PoolKey {
        let key = pool.add(cx, spec(destination, at));
        pool.get_mut(key)
            .expect("the connection was just added")
            .set_lastused(at);
        key
    }

    /// A connection already inside the shutdown queue, to `destination`.
    fn shutting(id: u64, destination: &str) -> ShuttingDownConnection {
        ShuttingDownConnection::new(
            ConnId::new(id),
            destination,
            FilterChains::new(Some(ConnId::new(id))),
            Box::new(NullTimer),
        )
    }

    /// Puts `count` connections to `destination` into `queue`.
    fn fill_queue(
        cx: &mut CallCtx<'_, '_>,
        host: &mut TestHost,
        queue: &mut ShutdownQueue,
        destination: &str,
        count: u64,
    ) {
        for id in 0..count {
            drive(queue.add(cx, host, shutting(900 + id, destination), 0));
        }
    }

    // -- (1) add and remove, and the bundle lifecycle ----------------------

    /// Adding links the connection into its destination bundle; removing
    /// unlinks it and destroys the bundle when it empties.
    ///
    /// `cpool_bundle_add` / `cpool_bundle_remove` plus `cpool_remove_bundle`
    /// (`lib/conncache.c:89-106`, `:154-182`). The bundle's disappearance is
    /// not incidental: [`ConnectionPool::check_limits`] looks the bundle up
    /// again after a termination precisely because of it.
    #[test]
    fn adding_and_removing_manages_the_destination_bundle() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        assert!(pool.is_empty());
        assert_eq!(pool.destinations(), 0);

        let first = pool.add(&mut cx, spec("a:80", clock.now()));
        let second = pool.add(&mut cx, spec("a:80", clock.now()));
        let other = pool.add(&mut cx, spec("b:80", clock.now()));

        assert_eq!(pool.count(), 3);
        assert_eq!(pool.destinations(), 2);
        assert_eq!(pool.destination_count("a:80"), 2);
        assert_eq!(pool.destination_count("b:80"), 1);
        assert_eq!(pool.destination_count("c:80"), 0);
        assert!(pool.get(first).expect("live").is_in_pool());

        // Removal hands the connection OUT, and clears its in-pool flag.
        let taken = pool.remove(first).expect("live");
        assert!(!taken.is_in_pool());
        assert_eq!(pool.count(), 2);
        // One left in the bundle, so the bundle survives.
        assert_eq!(pool.destinations(), 2);
        assert_eq!(pool.destination_count("a:80"), 1);

        // The last one out takes the bundle with it.
        assert!(pool.remove(second).is_some());
        assert_eq!(pool.destinations(), 1);
        assert_eq!(pool.destination_count("a:80"), 0);

        assert!(pool.remove(other).is_some());
        assert!(pool.is_empty());
        assert_eq!(pool.destinations(), 0);
    }

    /// The `[CPOOL] added connection ...` line is emitted with the identity and
    /// the new population -- `lib/conncache.c:491-493`.
    #[test]
    fn adding_traces_the_identity_and_the_population() {
        let clock = clock_at(10);
        let mut pool = ConnectionPool::new();

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            pool.add(&mut cx, spec("a:80", clock.now()));
            pool.add(&mut cx, spec("a:80", clock.now()));
        });

        assert!(
            text.contains(
                "[CPOOL] added connection 0. The cache now contains 1 members"
            ),
            "got {text:?}"
        );
        assert!(
            text.contains(
                "[CPOOL] added connection 1. The cache now contains 2 members"
            ),
            "got {text:?}"
        );
    }

    // -- (2) monotonic connection identities --------------------------------

    /// Identities start at zero, only increase, and are never recycled --
    /// `conn->connection_id = cpool->next_connection_id++`
    /// (`lib/conncache.c:489`).
    #[test]
    fn connection_identities_are_monotonic_and_never_recycled() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let first = pool.add(&mut cx, spec("a:80", clock.now()));
        assert_eq!(
            pool.get(first).expect("live").connection_id(),
            ConnectionId::FIRST
        );

        // Remove it, freeing the slot, then add two more.
        assert!(pool.remove(first).is_some());
        let second = pool.add(&mut cx, spec("a:80", clock.now()));
        let third = pool.add(&mut cx, spec("b:80", clock.now()));

        let second_id = pool.get(second).expect("live").connection_id();
        let third_id = pool.get(third).expect("live").connection_id();

        // The SLOT was reused; the IDENTITY was not.
        assert_eq!(second.slot(), first.slot());
        assert_eq!(second_id, ConnectionId::new(1));
        assert_eq!(third_id, ConnectionId::new(2));
        assert!(second_id.get() > ConnectionId::FIRST.get());
        assert!(third_id.get() > second_id.get());
    }

    /// The sentinel is negative, is not an identity, and converts totally.
    #[test]
    fn the_no_connection_sentinel_is_distinct_and_converts() {
        assert_eq!(ConnectionId::NONE.get(), -1);
        assert!(ConnectionId::NONE.is_none());
        assert!(!ConnectionId::FIRST.is_none());
        // The one input for which the conversion has no exact answer, pinned
        // so that the fallback documented on `as_conn_id` is covered rather
        // than merely asserted to be unreachable.
        assert_eq!(ConnectionId::NONE.as_conn_id(), ConnId::new(0));
        assert_eq!(ConnectionId::new(7).as_conn_id(), ConnId::new(7));
        assert_eq!(ConnectionId::new(7).to_string(), "7");
    }

    // -- (3) transfer identities -------------------------------------------

    /// Transfer identities start at zero, increase, and every enrolment resets
    /// the last-connect identity to the sentinel --
    /// `Curl_cpool_xfer_init` (`lib/conncache.c:269-289`).
    #[test]
    fn transfer_identities_advance_and_reset_the_last_connect_identity() {
        let mut pool = ConnectionPool::new();

        let first = pool.xfer_init();
        assert_eq!(first.transfer_id, TransferId::FIRST);
        assert_eq!(first.lastconnect_id, ConnectionId::NONE);

        let second = pool.xfer_init();
        assert_eq!(second.transfer_id, TransferId::new(1));
        assert_eq!(second.lastconnect_id, ConnectionId::NONE);

        let third = pool.xfer_init();
        assert_eq!(third.transfer_id, TransferId::new(2));
        assert_eq!(third.transfer_id.to_string(), "2");
    }

    /// The wrap safeguard: a counter that would go negative is reset to zero
    /// instead -- `if(cpool->next_easy_id <= 0) cpool->next_easy_id = 0;`
    /// (`lib/conncache.c:278-279`).
    #[test]
    fn the_transfer_counter_resets_rather_than_going_negative() {
        let mut pool = ConnectionPool::new();
        pool.next_transfer_id = CurlOffT::MAX;

        // The last representable identity is handed out...
        let last = pool.xfer_init();
        assert_eq!(last.transfer_id, TransferId::new(CurlOffT::MAX));
        // ...and the counter, which would have wrapped negative, is zeroed.
        assert_eq!(pool.next_transfer_id, 0);

        let after = pool.xfer_init();
        assert_eq!(after.transfer_id, TransferId::FIRST);
    }

    // -- (4) and (5) the generational slab ---------------------------------

    /// Reusing a slot hands out a different generation.
    #[test]
    fn reusing_a_slot_advances_its_generation() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let first = pool.add(&mut cx, spec("a:80", clock.now()));
        assert_eq!(first.generation(), 0);
        assert!(pool.remove(first).is_some());

        let second = pool.add(&mut cx, spec("a:80", clock.now()));
        assert_eq!(second.slot(), first.slot(), "the slot must be reused");
        assert_eq!(second.generation(), 1, "the generation must advance");
        assert_ne!(second, first);

        assert!(pool.remove(second).is_some());
        let third = pool.add(&mut cx, spec("a:80", clock.now()));
        assert_eq!(third.slot(), first.slot());
        assert_eq!(third.generation(), 2);
        assert_eq!(third.to_string(), format!("{}@2", first.slot()));
    }

    /// A key held across a removal cannot see the connection that replaced it.
    ///
    /// This is the whole reason [`PoolKey`] carries a generation. The C's
    /// equivalent -- a `struct connectdata *` retained across a free -- would
    /// resolve, and would resolve to the WRONG connection.
    #[test]
    fn a_stale_key_cannot_see_the_replacement() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let stale = pool.add(&mut cx, spec("a:80", clock.now()));
        assert!(pool.remove(stale).is_some());
        let fresh = pool.add(&mut cx, spec("b:443", clock.now()));
        assert_eq!(stale.slot(), fresh.slot());

        // Every access refuses the stale key.
        assert!(pool.get(stale).is_none());
        assert!(pool.get_mut(stale).is_none());
        assert!(pool.remove(stale).is_none());
        assert_eq!(pool.try_get(stale).err().map(StaleKey::key), Some(stale));
        assert_eq!(
            pool.try_get_mut(stale).err().map(StaleKey::key),
            Some(stale)
        );
        assert_eq!(
            CURLcode::from(StaleKey { key: stale }),
            CURLcode::BadFunctionArgument
        );
        assert_eq!(
            StaleKey { key: stale }.to_string(),
            format!("stale connection key {stale}")
        );

        // And the replacement is untouched and still reachable by its own key.
        assert_eq!(pool.count(), 1);
        assert_eq!(pool.get(fresh).expect("live").destination(), "b:443");
    }

    /// A retired slot is never handed out again, so staleness detection is
    /// total rather than probabilistic.
    #[test]
    fn an_exhausted_generation_retires_the_slot() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let key = pool.add(&mut cx, spec("a:80", clock.now()));
        // Place the slot one reuse away from exhaustion.
        match &mut pool.conns.slots[key.slot()] {
            Slot::Occupied { generation, .. } => *generation = u32::MAX,
            Slot::Vacant { .. } | Slot::Retired => {
                panic!("the slot was just filled")
            }
        }
        let exhausted = PoolKey {
            slot: key.slot(),
            generation: u32::MAX,
        };
        assert!(pool.remove(exhausted).is_some());

        // The slot is gone rather than recycled, so the next insert takes a
        // fresh one and the exhausted key still resolves to nothing.
        let next = pool.add(&mut cx, spec("a:80", clock.now()));
        assert_ne!(next.slot(), key.slot());
        assert!(pool.get(exhausted).is_none());
        assert!(matches!(pool.conns.slots[key.slot()], Slot::Retired));
    }

    /// Lookup by ABI identity validates the mapping and the generation, and a
    /// mapping that outlived its connection is cleaned up rather than trusted.
    #[test]
    fn identity_lookup_validates_and_cleans_up() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let key = pool.add(&mut cx, spec("a:80", clock.now()));
        let id = pool.get(key).expect("live").connection_id();

        assert_eq!(pool.key_of(id), Some(key));
        assert_eq!(
            pool.get_by_id(id).map(PooledConnection::destination),
            Some("a:80")
        );
        assert!(pool.get_by_id_mut(id).is_some());

        // Only the matching live connection is visited, and at most one.
        let mut seen = Vec::new();
        assert!(pool.do_by_id(id, |visited, conn| {
            seen.push((visited, conn.connection_id()));
        }));
        assert_eq!(seen, vec![(key, id)]);
        assert!(!pool.do_by_id(ConnectionId::new(999), |_, _| {
            panic!("no connection has that identity")
        }));

        // After removal the identity resolves to nothing.
        assert!(pool.remove(key).is_some());
        assert!(pool.key_of(id).is_none());
        assert!(pool.get_by_id(id).is_none());
        assert!(pool.remove_by_id(id).is_none());

        // A mapping without a connection -- which `remove` cannot produce --
        // is dropped rather than followed.
        pool.by_id.insert(id, key);
        assert!(pool.remove_by_id(id).is_none());
        assert!(!pool.by_id.contains_key(&id), "the mapping must be cleaned");

        // And the ordinary path removes by identity.
        let again = pool.add(&mut cx, spec("a:80", clock.now()));
        let again_id = pool.get(again).expect("live").connection_id();
        assert!(pool.remove_by_id(again_id).is_some());
        assert!(pool.is_empty());
    }

    // -- (6), (7) and (8) the two scans ------------------------------------

    /// The bundle scan skips ONLY connections in use.
    ///
    /// Close-marked and connect-only connections are candidates here, which is
    /// the asymmetry the module's eviction-policy point 3 records.
    #[test]
    fn the_bundle_scan_excludes_only_connections_in_use() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();
        let now = clock.now();

        // The oldest of the three is in use, so it is not a candidate.
        let busy = add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        pool.get_mut(busy).expect("live").attach();

        let marked =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(2, 0));
        pool.get_mut(marked).expect("live").mark_close();

        let fresh =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(900, 0));

        // The close-marked one is older than the fresh one and IS chosen.
        assert_eq!(pool.bundle_oldest_idle("a:80", now), Some(marked));

        // With every candidate in use there is no answer at all.
        pool.get_mut(marked).expect("live").attach();
        pool.get_mut(fresh).expect("live").attach();
        assert_eq!(pool.bundle_oldest_idle("a:80", now), None);

        // A destination with no bundle likewise.
        assert_eq!(pool.bundle_oldest_idle("nowhere:80", now), None);
    }

    /// A connect-only connection is also a bundle-scan candidate.
    #[test]
    fn the_bundle_scan_will_take_a_connect_only_connection() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let taken_over = pool.add(
            &mut cx,
            spec("a:80", CurlTime::new(1, 0)).with_connect_only(true),
        );
        pool.get_mut(taken_over)
            .expect("live")
            .set_lastused(CurlTime::new(1, 0));
        add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(900, 0));

        assert!(pool.get(taken_over).expect("live").connect_only());
        assert_eq!(
            pool.bundle_oldest_idle("a:80", clock.now()),
            Some(taken_over)
        );
    }

    /// The pool-wide scan skips in-use, close-marked AND connect-only
    /// connections -- `lib/conncache.c:357-358`.
    #[test]
    fn the_pool_scan_excludes_in_use_close_marked_and_connect_only() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();
        let now = clock.now();

        let busy = add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        pool.get_mut(busy).expect("live").attach();

        let marked =
            add_idle_at(&mut pool, &mut cx, "b:80", CurlTime::new(2, 0));
        pool.get_mut(marked).expect("live").mark_close();

        let taken_over = pool.add(
            &mut cx,
            spec("c:80", CurlTime::new(3, 0)).with_connect_only(true),
        );
        pool.get_mut(taken_over)
            .expect("live")
            .set_lastused(CurlTime::new(3, 0));

        let eligible =
            add_idle_at(&mut pool, &mut cx, "d:80", CurlTime::new(900, 0));

        // Three older connections are all excluded; the youngest wins because
        // it is the only candidate.
        assert_eq!(pool.oldest_idle(now), Some(eligible));

        // And the two scans disagree about the very same pool, which is the
        // asymmetry stated as eviction-policy point 3.
        assert_eq!(pool.bundle_oldest_idle("b:80", now), Some(marked));
        assert_eq!(pool.bundle_oldest_idle("c:80", now), Some(taken_over));

        pool.get_mut(eligible).expect("live").attach();
        assert_eq!(pool.oldest_idle(now), None);
    }

    /// Selection is by MAXIMUM IDLE AGE, not by insertion order and not by any
    /// recency ordering.
    ///
    /// The connections are added youngest-first and in a destination order
    /// that puts the winner last in both the bundle map and the insertion
    /// sequence, so an implementation that answered "the front of the list" or
    /// "the first bundle" would give a different result.
    #[test]
    fn selection_is_maximum_age_and_not_insertion_order() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();
        let now = clock.now();

        // Inserted newest first, and into ascending destinations, so the
        // oldest is LAST by every order but age.
        let newest =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(900, 0));
        let middle =
            add_idle_at(&mut pool, &mut cx, "b:80", CurlTime::new(500, 0));
        let oldest =
            add_idle_at(&mut pool, &mut cx, "c:80", CurlTime::new(5, 0));

        assert_eq!(pool.oldest_idle(now), Some(oldest));
        assert_ne!(pool.oldest_idle(now), Some(newest));

        // Within one bundle the same holds, and the ages are read from the
        // injected clock rather than from any access order: touching the
        // oldest connection does not make it young.
        let one = add_idle_at(&mut pool, &mut cx, "z:80", CurlTime::new(10, 0));
        let two =
            add_idle_at(&mut pool, &mut cx, "z:80", CurlTime::new(800, 0));
        assert_eq!(pool.bundle_oldest_idle("z:80", now), Some(one));
        assert!(pool.get(one).is_some());
        assert!(pool.get(two).is_some());
        assert_eq!(pool.bundle_oldest_idle("z:80", now), Some(one));

        // On a tie the earlier entry wins, because the comparison is strictly
        // greater-than -- which makes the answer deterministic.
        let mut tie = ConnectionPool::new();
        let early =
            add_idle_at(&mut tie, &mut cx, "t:80", CurlTime::new(100, 0));
        let late =
            add_idle_at(&mut tie, &mut cx, "t:80", CurlTime::new(100, 0));
        assert_eq!(tie.bundle_oldest_idle("t:80", now), Some(early));
        assert_ne!(tie.bundle_oldest_idle("t:80", now), Some(late));
        assert_eq!(tie.oldest_idle(now), Some(early));

        // A connection that became idle this instant still beats the `-1`
        // starting score, so a pool of freshly idle connections has an answer.
        let mut fresh = ConnectionPool::new();
        let just_now = add_idle_at(&mut fresh, &mut cx, "f:80", now);
        assert_eq!(fresh.get(just_now).expect("live").idle_age_ms(now), 0);
        assert_eq!(fresh.oldest_idle(now), Some(just_now));
        assert_eq!(middle.generation(), 0);
    }

    // -- (9) to (16) the connection limits ---------------------------------

    /// With both limits zero the check returns at once and scans nothing.
    #[test]
    fn no_limits_answers_immediately() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        let limits = ConnectionLimits::default();

        let verdict = drive(
            pool.check_limits(&mut cx, &mut host, &mut queue, "a:80", limits),
        );
        assert_eq!(verdict, CpoolLimit::Ok);
        assert!(verdict.is_ok());
        assert_eq!(pool.count(), 1, "nothing may be evicted");
    }

    /// The destination limit gives up a SHUTTING-DOWN connection before it
    /// touches a pooled one -- `lib/conncache.c:399-403`.
    #[test]
    fn the_destination_limit_closes_a_shutdown_entry_first() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let pooled =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        fill_queue(&mut cx, &mut host, &mut queue, "a:80", 1);
        assert_eq!(queue.destination_count("a:80"), 1);

        let limits = ConnectionLimits {
            max_host: 2,
            max_total: 0,
        };
        let verdict = drive(
            pool.check_limits(&mut cx, &mut host, &mut queue, "a:80", limits),
        );

        assert_eq!(verdict, CpoolLimit::Ok);
        assert_eq!(queue.destination_count("a:80"), 0, "the queue gave way");
        assert!(
            pool.get(pooled).is_some(),
            "the pooled connection must survive"
        );
    }

    /// With no shutdown entry the destination limit takes the bundle's oldest
    /// idle connection -- `lib/conncache.c:406-419`.
    #[test]
    fn the_destination_limit_takes_the_bundles_oldest_idle() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let oldest =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        let newest =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(900, 0));
        let elsewhere =
            add_idle_at(&mut pool, &mut cx, "b:80", CurlTime::new(2, 0));

        let limits = ConnectionLimits {
            max_host: 2,
            max_total: 0,
        };
        let text = multi_trace(|tracer| {
            let mut traced = CallCtx::new(&clock).with_tracer(tracer);
            let verdict = drive(pool.check_limits(
                &mut traced,
                &mut host,
                &mut queue,
                "a:80",
                limits,
            ));
            assert_eq!(verdict, CpoolLimit::Ok);
        });

        assert!(pool.get(oldest).is_none(), "the oldest idle one must go");
        assert!(pool.get(newest).is_some());
        assert!(
            pool.get(elsewhere).is_some(),
            "another destination is not the destination limit's business"
        );
        assert!(
            text.contains(
                "Discarding connection #0 from 2 to reach destination limit \
                 of 2"
            ),
            "got {text:?}"
        );
    }

    /// The bundle is looked up AGAIN after a termination, because terminating
    /// its last connection destroys it -- `lib/conncache.c:421-423`.
    ///
    /// Without the re-read, `live` would still be one and the answer would be
    /// [`CpoolLimit::Destination`] even though there is now room.
    #[test]
    fn the_bundle_is_looked_up_again_after_a_termination() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let only = add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        assert_eq!(pool.destinations(), 1);

        let limits = ConnectionLimits {
            max_host: 1,
            max_total: 0,
        };
        let verdict = drive(
            pool.check_limits(&mut cx, &mut host, &mut queue, "a:80", limits),
        );

        assert_eq!(verdict, CpoolLimit::Ok, "the re-read must find room");
        assert!(pool.get(only).is_none());
        assert_eq!(pool.destinations(), 0, "the bundle went with it");
    }

    /// A destination that is still full answers `CPOOL_LIMIT_DEST`, which is
    /// the integer one -- `lib/conncache.h:91`.
    #[test]
    fn a_full_destination_answers_dest() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        // The only connection to this destination is in use, so the bundle
        // scan has nothing to offer.
        let busy = add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        pool.get_mut(busy).expect("live").attach();

        let limits = ConnectionLimits {
            max_host: 1,
            max_total: 0,
        };
        let verdict = drive(
            pool.check_limits(&mut cx, &mut host, &mut queue, "a:80", limits),
        );

        assert_eq!(verdict, CpoolLimit::Destination);
        assert_eq!(verdict.as_i32(), 1);
        assert!(!verdict.is_ok());
        assert!(
            pool.get(busy).is_some(),
            "an in-use connection is untouched"
        );
    }

    /// The total limit also gives up a shutting-down connection first, for any
    /// destination -- `lib/conncache.c:436-440`.
    #[test]
    fn the_total_limit_closes_a_shutdown_entry_first() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let pooled =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        // A DIFFERENT destination, so only the total limit can see it.
        fill_queue(&mut cx, &mut host, &mut queue, "z:80", 1);

        let limits = ConnectionLimits {
            max_host: 0,
            max_total: 2,
        };
        let verdict = drive(
            pool.check_limits(&mut cx, &mut host, &mut queue, "a:80", limits),
        );

        assert_eq!(verdict, CpoolLimit::Ok);
        assert_eq!(queue.count(), 0, "the queue gave way");
        assert!(pool.get(pooled).is_some());
    }

    /// With no shutdown entry the total limit takes the POOL-WIDE oldest idle
    /// connection, from whichever destination -- `lib/conncache.c:442-451`.
    #[test]
    fn the_total_limit_takes_the_pool_wide_oldest_idle() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        // The oldest is in a bundle other than the one being asked about.
        let oldest =
            add_idle_at(&mut pool, &mut cx, "b:80", CurlTime::new(1, 0));
        let newest =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(900, 0));

        let limits = ConnectionLimits {
            max_host: 0,
            max_total: 2,
        };
        let text = multi_trace(|tracer| {
            let mut traced = CallCtx::new(&clock).with_tracer(tracer);
            let verdict = drive(pool.check_limits(
                &mut traced,
                &mut host,
                &mut queue,
                "a:80",
                limits,
            ));
            assert_eq!(verdict, CpoolLimit::Ok);
        });

        assert!(pool.get(oldest).is_none());
        assert!(pool.get(newest).is_some());
        assert!(
            text.contains(
                "Discarding connection #0 from 2 to reach total limit of 2"
            ),
            "got {text:?}"
        );
    }

    /// A pool that is still full answers `CPOOL_LIMIT_TOTAL`, which is the
    /// integer two -- `lib/conncache.h:92`.
    #[test]
    fn a_full_pool_answers_total() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let busy = add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        pool.get_mut(busy).expect("live").attach();

        let limits = ConnectionLimits {
            max_host: 0,
            max_total: 1,
        };
        let verdict = drive(
            pool.check_limits(&mut cx, &mut host, &mut queue, "b:80", limits),
        );

        assert_eq!(verdict, CpoolLimit::Total);
        assert_eq!(verdict.as_i32(), 2);
        assert!(pool.get(busy).is_some());
    }

    /// The three limit results carry the C's integers, and nothing else
    /// converts back.
    #[test]
    fn the_limit_results_carry_the_pinned_integers() {
        assert_eq!(CpoolLimit::Ok.as_i32(), 0);
        assert_eq!(CpoolLimit::Destination.as_i32(), 1);
        assert_eq!(CpoolLimit::Total.as_i32(), 2);
        assert_eq!(CpoolLimit::default(), CpoolLimit::Ok);

        assert_eq!(CpoolLimit::from_i32(0), Some(CpoolLimit::Ok));
        assert_eq!(CpoolLimit::from_i32(1), Some(CpoolLimit::Destination));
        assert_eq!(CpoolLimit::from_i32(2), Some(CpoolLimit::Total));
        assert_eq!(CpoolLimit::from_i32(3), None);
        assert_eq!(CpoolLimit::from_i32(-1), None);
    }

    /// Pooled and shutting-down connections count TOGETHER against the total
    /// limit, tested from the pool's side.
    ///
    /// Identical pool state, and the only difference is the queue's
    /// population: with the queue empty there is room, and with one entry there
    /// is not.
    #[test]
    fn the_total_limit_counts_the_pool_and_the_queue_together() {
        let clock = clock_at(1_000);
        let limits = ConnectionLimits {
            max_host: 0,
            max_total: 2,
        };

        // Queue empty: one pooled connection is inside a limit of two, and
        // nothing is disturbed.
        {
            let mut cx = CallCtx::new(&clock);
            let mut host = TestHost::new();
            let mut queue = ShutdownQueue::new();
            let mut pool = ConnectionPool::new();
            let pooled =
                add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));

            let verdict =
                drive(pool.check_limits(
                    &mut cx, &mut host, &mut queue, "a:80", limits,
                ));
            assert_eq!(verdict, CpoolLimit::Ok);
            assert!(pool.get(pooled).is_some());
            assert_eq!(pool.count(), 1);
        }

        // One queue entry, same pool: the pair reaches the limit and something
        // has to give.
        {
            let mut cx = CallCtx::new(&clock);
            let mut host = TestHost::new();
            let mut queue = ShutdownQueue::new();
            let mut pool = ConnectionPool::new();
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
            fill_queue(&mut cx, &mut host, &mut queue, "z:80", 1);

            let verdict =
                drive(pool.check_limits(
                    &mut cx, &mut host, &mut queue, "a:80", limits,
                ));
            assert_eq!(verdict, CpoolLimit::Ok);
            assert_eq!(queue.count(), 0, "the queue was made to give way");
        }
    }

    /// The same invariant from the OTHER side: the queue force-closes its
    /// oldest entry when the pool's population, passed in as a value, puts the
    /// pair at the limit.
    ///
    /// `crate::conn::shutdown::ShutdownQueue::add` owns this half; asserting it
    /// here is what makes the shared invariant tested from both directions
    /// rather than assumed to agree.
    #[test]
    fn the_queue_enforces_the_shared_limit_from_the_pooled_count() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        host.max_total = 3;
        let mut queue = ShutdownQueue::new();

        drive(queue.add(&mut cx, &mut host, shutting(1, "a:80"), 0));
        assert_eq!(queue.count(), 1);

        // A pooled population of two, plus this one queued, reaches three: the
        // queue's oldest entry is force-closed before the new one is admitted.
        drive(queue.add(&mut cx, &mut host, shutting(2, "a:80"), 2));
        assert_eq!(queue.count(), 1, "one out, one in");

        // With a pooled population of zero the same queue admits freely.
        drive(queue.add(&mut cx, &mut host, shutting(3, "a:80"), 0));
        assert_eq!(queue.count(), 2);
    }

    // -- (17), (18), (19) and (20) the idle cap ----------------------------

    /// A configured cap is used as given -- `lib/conncache.c:568-569`.
    #[test]
    fn a_configured_cap_is_used_verbatim() {
        assert_eq!(effective_maxconnects(7, 0), 7);
        assert_eq!(effective_maxconnects(7, 1_000), 7);
        assert_eq!(effective_maxconnects(1, 1_000), 1);
    }

    /// A cap of zero derives one from the running-transfer count, four times
    /// over -- `lib/conncache.c:565-566`.
    #[test]
    fn a_zero_cap_derives_four_times_the_running_transfers() {
        assert_eq!(effective_maxconnects(0, 0), 0);
        assert_eq!(effective_maxconnects(0, 1), 4);
        assert_eq!(effective_maxconnects(0, 3), 12);
        assert_eq!(effective_maxconnects(0, 25), 100);
    }

    /// The derived cap saturates rather than wrapping, and the C's boundary is
    /// reproduced exactly.
    ///
    /// C writes the guard as `running <= UINT_MAX / 4`, so the largest input
    /// that still multiplies is `u32::MAX / 4` -- and its product must NOT
    /// saturate.
    #[test]
    fn the_derived_cap_saturates_at_the_c_boundary() {
        let boundary = u32::MAX / 4;
        assert_eq!(effective_maxconnects(0, boundary), boundary * 4);
        assert_eq!(effective_maxconnects(0, boundary), 4_294_967_292);
        assert_eq!(effective_maxconnects(0, boundary + 1), u32::MAX);
        assert_eq!(effective_maxconnects(0, u32::MAX), u32::MAX);
    }

    /// Becoming idle stamps `lastused` first, and reports whether the
    /// just-idled connection survived.
    #[test]
    fn becoming_idle_stamps_the_instant_and_reports_survival() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        // Two idle connections and a cap of one, so the pool is over it.
        let just_idle =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        let older =
            add_idle_at(&mut pool, &mut cx, "b:80", CurlTime::new(2, 0));
        let limits = IdleLimits {
            maxconnects: 1,
            running_transfers: 0,
        };

        let text = multi_trace(|tracer| {
            let mut traced = CallCtx::new(&clock).with_tracer(tracer);
            let kept = drive(pool.conn_now_idle(
                &mut traced,
                &mut host,
                &mut queue,
                just_idle,
                limits,
            ));
            assert!(kept, "the connection that just became idle is the newest");
        });

        assert!(
            text.contains("Connection pool is full, closing the oldest of 2/1"),
            "got {text:?}"
        );
        // The stamp happened, and it happened BEFORE the scan -- which is why
        // the other connection was the older one.
        assert_eq!(pool.get(just_idle).expect("live").lastused(), clock.now());
        assert!(pool.get(older).is_none());
        assert_eq!(pool.count(), 1);
    }

    /// When the just-idled connection is the only candidate it is the one that
    /// goes, and the answer is `false` -- C's `kept = (oldest_idle != conn)`.
    #[test]
    fn the_just_idled_connection_can_be_the_one_evicted() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let just_idle =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        // Every other connection is in use, so the scan can only pick the one
        // that has this instant become idle.
        let busy = add_idle_at(&mut pool, &mut cx, "b:80", CurlTime::new(2, 0));
        pool.get_mut(busy).expect("live").attach();

        let kept = drive(pool.conn_now_idle(
            &mut cx,
            &mut host,
            &mut queue,
            just_idle,
            IdleLimits {
                maxconnects: 1,
                running_transfers: 0,
            },
        ));

        assert!(!kept, "the just-idled connection was the one closed");
        assert!(pool.get(just_idle).is_none());
        assert!(pool.get(busy).is_some());
    }

    /// A cap of zero disables the check, a pool at exactly its cap is not over
    /// it, and a stale key is reported as kept.
    #[test]
    fn the_idle_cap_is_only_consulted_when_it_can_bite() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let one = add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        let two = add_idle_at(&mut pool, &mut cx, "b:80", CurlTime::new(2, 0));

        // Cap zero: both `maxconnects` and `running_transfers` zero disables
        // it entirely.
        assert!(drive(pool.conn_now_idle(
            &mut cx,
            &mut host,
            &mut queue,
            one,
            IdleLimits::default(),
        )));
        assert_eq!(pool.count(), 2);

        // Exactly at the cap: `>` and not `>=`.
        assert!(drive(pool.conn_now_idle(
            &mut cx,
            &mut host,
            &mut queue,
            one,
            IdleLimits {
                maxconnects: 2,
                running_transfers: 0,
            },
        )));
        assert_eq!(pool.count(), 2);

        // A key that no longer resolves cannot be evicted from the pool, so
        // "kept" is the answer.
        assert!(pool.remove(two).is_some());
        assert!(drive(pool.conn_now_idle(
            &mut cx,
            &mut host,
            &mut queue,
            two,
            IdleLimits {
                maxconnects: 1,
                running_transfers: 0,
            },
        )));
        assert_eq!(pool.count(), 1);
    }

    // -- (21) to (24) the injected predicate's four branches ---------------

    /// Maximum idle age condemns a connection, and it is checked BEFORE
    /// maximum lifetime -- `lib/url.c:628-647`.
    #[test]
    fn the_predicate_rejects_a_connection_idle_for_too_long() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        // Idle for 999 seconds, and created 999 seconds ago, so BOTH rules
        // would fire -- which is what makes the ordering observable.
        let stale =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        let mut health = ContractHealth {
            max_idle_ms: 5_000,
            max_age_ms: 5_000,
            liveness: Some(Liveness::alive(false)),
            ..ContractHealth::default()
        };

        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));

        assert_eq!(stats.reaped, 1);
        assert_eq!(stats.checked, 1);
        assert!(pool.get(stale).is_none());
        assert_eq!(health.reasons, vec![DeadReason::MaxIdleAge]);
    }

    /// Maximum lifetime condemns a connection that is within its idle limit --
    /// `lib/url.c:638-647`.
    #[test]
    fn the_predicate_rejects_a_connection_that_has_lived_too_long() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        // Created long ago but used a moment ago, so only the lifetime rule
        // can fire.
        let key = pool.add(&mut cx, spec("a:80", CurlTime::new(1, 0)));
        pool.get_mut(key).expect("live").set_lastused(clock.now());

        let mut health = ContractHealth {
            max_idle_ms: 60_000,
            max_age_ms: 5_000,
            liveness: Some(Liveness::alive(false)),
            ..ContractHealth::default()
        };
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));

        assert_eq!(stats.reaped, 1);
        assert!(pool.get(key).is_none());
        assert_eq!(health.reasons, vec![DeadReason::MaxLifetime]);
    }

    /// The scheme's own check is consulted with [`ConnCheck::ISDEAD`] and its
    /// answer is masked for [`ConnResult::DEAD`] -- `lib/url.c:668-682`.
    #[test]
    fn the_predicate_consults_the_schemes_own_check() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();

        // A scheme that reports the connection dead.
        let mut pool = ConnectionPool::new();
        let condemned =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(999, 0));
        let mut health = ContractHealth {
            protocol_check: Some(ConnResult::DEAD),
            ..ContractHealth::default()
        };
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));
        assert_eq!(stats.reaped, 1);
        assert!(pool.get(condemned).is_none());
        assert_eq!(health.reasons, vec![DeadReason::ProtocolCheck]);

        // A scheme that reports nothing keeps it.
        let mut pool = ConnectionPool::new();
        let spared =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(999, 0));
        let mut health = ContractHealth {
            protocol_check: Some(ConnResult::NONE),
            ..ContractHealth::default()
        };
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));
        assert_eq!(stats.reaped, 0);
        assert_eq!(stats.checked, 1);
        assert!(pool.get(spared).is_some());
        assert!(health.reasons.is_empty());
    }

    /// The two bitmaps carry the C's values and round-trip through their raw
    /// forms -- `lib/urldata.h:560-565`.
    #[test]
    fn the_check_and_result_bitmaps_round_trip() {
        assert_eq!(ConnCheck::NONE.bits(), 0);
        assert_eq!(ConnCheck::ISDEAD.bits(), 1);
        assert_eq!(ConnCheck::KEEPALIVE.bits(), 2);
        assert_eq!(ConnCheck::ALL.bits(), 3);
        assert!(ConnCheck::NONE.is_empty());
        assert!(!ConnCheck::ISDEAD.is_empty());
        assert_eq!(ConnCheck::default(), ConnCheck::NONE);

        let both = ConnCheck::ISDEAD.union(ConnCheck::KEEPALIVE);
        assert_eq!(both, ConnCheck::ALL);
        assert!(both.contains(ConnCheck::ISDEAD));
        assert!(both.contains(ConnCheck::KEEPALIVE));
        assert!(both.contains(ConnCheck::NONE));
        assert!(!ConnCheck::KEEPALIVE.contains(ConnCheck::ISDEAD));
        assert_eq!(ConnCheck::from_bits_truncate(0xffff_ffff), ConnCheck::ALL);
        assert_eq!(ConnCheck::from_bits_truncate(1), ConnCheck::ISDEAD);
        assert_eq!(ConnCheck::from_bits_truncate(4), ConnCheck::NONE);

        assert_eq!(ConnResult::NONE.bits(), 0);
        assert_eq!(ConnResult::DEAD.bits(), 1);
        assert_eq!(ConnResult::ALL, ConnResult::DEAD);
        assert!(ConnResult::NONE.is_empty());
        assert_eq!(ConnResult::default(), ConnResult::NONE);
        assert!(ConnResult::DEAD.contains(ConnResult::DEAD));
        assert!(!ConnResult::NONE.contains(ConnResult::DEAD));
        assert_eq!(ConnResult::NONE.union(ConnResult::DEAD), ConnResult::DEAD);
        assert_eq!(
            ConnResult::from_bits_truncate(0xffff_ffff),
            ConnResult::DEAD
        );
        assert_eq!(ConnResult::from_bits_truncate(2), ConnResult::NONE);

        // A request and an answer are different types even where the numbers
        // coincide, which is what stops one being written for the other.
        assert_eq!(ConnCheck::ISDEAD.bits(), ConnResult::DEAD.bits());
    }

    /// The reuse capability bits carry the C's values, and bit nine stays free
    /// -- `lib/urldata.h:544`, `:555-558`.
    #[test]
    fn the_reuse_capability_bits_are_the_c_values() {
        assert_eq!(PROTOPT_SSL_REUSE, 1 << 15);
        assert_eq!(PROTOPT_CONN_REUSE, 1 << 16);
        assert_eq!(PROTOPT_SSL_REUSE, 32_768);
        assert_eq!(PROTOPT_CONN_REUSE, 65_536);
        // Neither claims the retired bit.
        let free_bit: u32 = 1 << 9;
        assert_eq!(PROTOPT_SSL_REUSE & free_bit, 0);
        assert_eq!(PROTOPT_CONN_REUSE & free_bit, 0);

        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();
        let key = pool.add(
            &mut cx,
            spec("a:80", clock.now())
                .with_protocol_flags(PROTOPT_CONN_REUSE | PROTOPT_SSL_REUSE),
        );
        let conn = pool.get(key).expect("live");
        assert!(conn.may_reuse_connection());
        assert!(conn.may_reuse_tls());
        assert_eq!(
            conn.protocol_flags(),
            PROTOPT_CONN_REUSE | PROTOPT_SSL_REUSE
        );

        let plain = pool.add(&mut cx, spec("b:80", clock.now()));
        assert!(!pool.get(plain).expect("live").may_reuse_connection());
        assert!(!pool.get(plain).expect("live").may_reuse_tls());
    }

    /// A live connection with bytes already waiting is rejected anyway --
    /// `lib/url.c:688-699`.
    #[test]
    fn the_predicate_rejects_a_live_connection_with_input_pending() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let key =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(999, 0));
        let mut health = ContractHealth {
            liveness: Some(Liveness::alive(true)),
            ..ContractHealth::default()
        };

        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));
        assert_eq!(stats.reaped, 1);
        assert!(pool.get(key).is_none());
        assert_eq!(health.reasons, vec![DeadReason::InputPending]);
    }

    /// The predicate reaches the real filter chain, and an empty chain reports
    /// dead -- which is how the seam is shown to be wired rather than merely
    /// injected.
    #[test]
    fn the_predicate_can_reach_the_filter_chain() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let empty_chain =
            add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(999, 0));
        // `liveness: None` sends the predicate to `FilterChain::is_alive`.
        let mut health = ContractHealth::default();

        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));
        assert_eq!(stats.reaped, 1);
        assert!(pool.get(empty_chain).is_none());
        assert_eq!(health.reasons, vec![DeadReason::NotAlive]);
    }

    /// The default predicate condemns nothing.
    #[test]
    fn the_assume_healthy_predicate_keeps_everything() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let key = add_idle_at(&mut pool, &mut cx, "a:80", CurlTime::new(1, 0));
        let mut health = AssumeHealthy;

        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));
        assert_eq!(
            stats,
            PruneStats {
                checked: 1,
                reaped: 0,
            }
        );
        assert!(pool.get(key).is_some());
        // The two constructors, compared against their literal forms: an
        // "alive" verdict carries no reason and a "dead" one always does.
        assert_eq!(
            DeadVerdict::ALIVE,
            DeadVerdict {
                dead: false,
                reason: None,
            }
        );
        assert_eq!(
            DeadVerdict::dead(DeadReason::NotAlive),
            DeadVerdict {
                dead: true,
                reason: Some(DeadReason::NotAlive),
            }
        );
    }

    // -- (25) to (28) pruning ----------------------------------------------

    /// Pruning is gated at [`PRUNE_INTERVAL_MS`], and a gated call does
    /// nothing at all -- `lib/conncache.c:729-735`.
    #[test]
    fn pruning_is_gated_at_one_second() {
        assert_eq!(PRUNE_INTERVAL_MS, 1000);

        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();
        let mut health = AlwaysDead::default();

        // The first pass always runs: `last_cleanup` is the zero reading.
        let first = add_idle_at(&mut pool, &mut cx, "a:80", clock.now());
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));
        assert_eq!(stats.reaped, 1);
        assert!(pool.get(first).is_none());
        assert_eq!(pool.last_cleanup(), clock.now());
        let stamped = pool.last_cleanup();

        // 999 milliseconds later: nothing is scanned, nothing is reaped, and
        // the stamp does not move.
        clock.advance(Duration::from_millis(999));
        let second = add_idle_at(&mut pool, &mut cx, "a:80", clock.now());
        let mut cx = CallCtx::new(&clock);
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));
        assert_eq!(stats, PruneStats::default());
        assert!(pool.get(second).is_some());
        assert_eq!(pool.last_cleanup(), stamped);
        assert_eq!(health.asked.len(), 1, "the predicate was not asked again");

        // One millisecond more makes exactly one thousand, and `>=` runs.
        clock.advance(Duration::from_millis(1));
        let mut cx = CallCtx::new(&clock);
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));
        assert_eq!(stats.reaped, 1);
        assert!(pool.get(second).is_none());
        assert_eq!(pool.last_cleanup(), clock.now());
    }

    /// One pass reaps every eligible connection, restarting the traversal after
    /// each removal -- `while(cpool_foreach(...))` (`lib/conncache.c:732-733`).
    #[test]
    fn pruning_restarts_after_every_removal() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        // Three across two destinations, so the restart crosses bundles too.
        for destination in ["a:80", "a:80", "b:80"] {
            let key = add_idle_at(&mut pool, &mut cx, destination, clock.now());
            pool.get_mut(key).expect("live").mark_no_reuse();
        }
        assert_eq!(pool.count(), 3);

        let mut health = AlwaysDead::default();
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));

        assert_eq!(stats.reaped, 3, "a single call must clear all three");
        assert!(pool.is_empty());
        assert_eq!(pool.destinations(), 0);
    }

    /// An idle no-reuse connection is terminated WITHOUT the predicate being
    /// asked -- `terminate = !CONN_INUSE(conn) && conn->bits.no_reuse`
    /// (`lib/conncache.c:696`).
    #[test]
    fn an_idle_no_reuse_connection_bypasses_the_predicate() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let marked = add_idle_at(&mut pool, &mut cx, "a:80", clock.now());
        pool.get_mut(marked).expect("live").mark_no_reuse();
        assert!(pool.get(marked).expect("live").no_reuse());

        let mut health = ContractHealth::default();
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));

        assert_eq!(stats.reaped, 1);
        assert_eq!(stats.checked, 0, "nothing was checked");
        assert!(
            health.asked.is_empty(),
            "the predicate must not be consulted, got {:?}",
            health.asked
        );
        assert!(pool.get(marked).is_none());
    }

    /// An in-use connection is never pruned, not even by a predicate that
    /// condemns everything -- `lib/url.c:659`.
    #[test]
    fn an_in_use_connection_is_never_pruned() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let busy = add_idle_at(&mut pool, &mut cx, "a:80", clock.now());
        pool.get_mut(busy).expect("live").attach();
        // Marked no-reuse AS WELL, so both of pruning's routes are blocked.
        pool.get_mut(busy).expect("live").mark_no_reuse();
        assert!(pool.get(busy).expect("live").is_in_use());

        let mut health = AlwaysDead::default();
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));

        assert_eq!(stats, PruneStats::default());
        assert!(health.asked.is_empty(), "an in-use connection is not asked");
        assert!(pool.get(busy).is_some());
        assert_eq!(pool.count(), 1);
    }

    /// Attaching and detaching drive `CONN_INUSE`, and both saturate rather
    /// than wrapping.
    #[test]
    fn the_attached_transfer_count_drives_conn_inuse() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();
        let key = pool.add(&mut cx, spec("a:80", clock.now()));
        let conn = pool.get_mut(key).expect("live");

        assert_eq!(conn.attached_xfers(), 0);
        assert!(!conn.is_in_use());

        conn.attach();
        assert_eq!(conn.attached_xfers(), 1);
        assert!(conn.is_in_use());
        conn.attach();
        assert_eq!(conn.attached_xfers(), 2);

        conn.detach();
        assert!(conn.is_in_use());
        conn.detach();
        assert!(!conn.is_in_use());

        // A detach without an attach must not wrap the count and pin the
        // connection in the pool forever.
        conn.detach();
        assert_eq!(conn.attached_xfers(), 0);
        assert!(!conn.is_in_use());

        conn.set_attached_xfers(u32::MAX);
        conn.attach();
        assert_eq!(conn.attached_xfers(), u32::MAX);
        conn.set_attached_xfers(0);
        assert!(!conn.is_in_use());
    }

    // -- (29) to (31) termination and the shutdown handoff -----------------

    /// An aborted connection sends no farewell -- `lib/conncache.c:213-219`.
    ///
    /// The observable is the absence of the `[SHUTDOWN] shutdown, done=` line
    /// that `run_once` emits: an aborted connection never reaches that call,
    /// which is exactly what stops a server reading a failed upload as a
    /// successful one.
    #[test]
    fn an_aborted_connection_skips_the_graceful_shutdown() {
        let clock = clock_at(10);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();
        let mut setup = CallCtx::new(&clock);
        let described = slow_spec(&mut setup, "a:80", clock.now(), 3);
        let key = pool.add(&mut setup, described);

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            let outcome = drive(
                pool.terminate(&mut cx, &mut host, &mut queue, key, true),
            );
            assert_eq!(outcome, TerminateOutcome::Terminated);
        });

        assert!(
            !text.contains("[SHUTDOWN] shutdown, done="),
            "an aborted connection must not be shut down gracefully, \
             got {text:?}"
        );
        assert!(text.contains("closing connection #0"), "got {text:?}");
        assert!(
            !text.contains("shutting down connection #0"),
            "got {text:?}"
        );
        assert!(pool.is_empty());
        assert_eq!(queue.count(), 0, "an aborted connection is not queued");
    }

    /// A connect-only connection is forced to an abort even when the caller
    /// asked for a graceful termination -- `lib/conncache.c:207-210`, `:668`.
    #[test]
    fn a_connect_only_connection_is_forced_to_abort() {
        let clock = clock_at(10);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();
        let mut setup = CallCtx::new(&clock);
        let mut chains = FilterChains::new(None);
        chains
            .chain_mut(SocketIndex::First)
            .add(&mut setup, link(SlowFilter::new(SocketIndex::First, 3)));
        let key = pool.add(
            &mut setup,
            ConnectionSpec::new(
                "a:80",
                chains,
                Box::new(NullTimer),
                clock.now(),
            )
            .with_connect_only(true),
        );

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            // `aborted` is FALSE here; `connect_only` overrides it.
            let outcome = drive(
                pool.terminate(&mut cx, &mut host, &mut queue, key, false),
            );
            assert_eq!(outcome, TerminateOutcome::Terminated);
        });

        assert!(
            !text.contains("[SHUTDOWN] shutdown, done="),
            "connect-only must suppress the farewell, got {text:?}"
        );
        assert!(
            text.contains("closing connection #0"),
            "the verb must be \"closing\", got {text:?}"
        );
        assert_eq!(queue.count(), 0);
        assert!(pool.is_empty());
    }

    /// A graceful termination that does not finish in one pass is handed to the
    /// shutdown queue, with the pool's population -- `lib/conncache.c:225-228`.
    #[test]
    fn a_graceful_termination_is_handed_to_the_queue() {
        let clock = clock_at(10);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();
        let mut setup = CallCtx::new(&clock);
        // Two connections, so the queue is told a population of one.
        let described = slow_spec(&mut setup, "a:80", clock.now(), 3);
        let key = pool.add(&mut setup, described);
        let survivor = pool.add(&mut setup, spec("b:80", clock.now()));

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            let outcome = drive(
                pool.terminate(&mut cx, &mut host, &mut queue, key, false),
            );
            assert_eq!(outcome, TerminateOutcome::Terminated);
        });

        assert!(
            text.contains("shutting down connection #0"),
            "the verb must be \"shutting down\", got {text:?}"
        );
        assert!(
            text.contains("[SHUTDOWN] shutdown, done=0"),
            "one hopeful pass must have run and reported unfinished, \
             got {text:?}"
        );
        assert_eq!(queue.count(), 1, "it must be queued, not released");
        assert_eq!(queue.destination_count("a:80"), 1);
        assert_eq!(pool.count(), 1);
        assert!(pool.get(survivor).is_some());
    }

    /// A connection whose chains report done on the first pass is released
    /// immediately rather than queued -- C's `if(done || !data->multi)`.
    #[test]
    fn a_shutdown_that_finishes_at_once_is_not_queued() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();
        // Empty chains: nothing is connected, so both report done.
        let key = pool.add(&mut cx, spec("a:80", clock.now()));

        let outcome =
            drive(pool.terminate(&mut cx, &mut host, &mut queue, key, false));

        assert_eq!(outcome, TerminateOutcome::Terminated);
        assert_eq!(queue.count(), 0);
        assert!(pool.is_empty());
    }

    /// With no multi handle the connection is terminated on the spot, and the
    /// graceful pass is requested by `terminate` itself with
    /// `do_shutdown = !aborted` -- `lib/conncache.c:677-681`.
    ///
    /// The observable is the `force ` prefix of the shutdown layer's closing
    /// line, which that layer chooses from whether the filters ever reported
    /// themselves finished. A chain that completes in ONE pass therefore
    /// distinguishes the two cases exactly: with `aborted` false the final pass
    /// runs and the close is graceful. Nothing is queued either way, because
    /// there is no owner for background work.
    #[test]
    fn without_a_multi_handle_a_graceful_pass_still_runs() {
        let clock = clock_at(10);
        let mut host = TestHost::without_multi();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();
        let mut setup = CallCtx::new(&clock);
        // Zero steps: the chain is connected and finishes on its first pass.
        let described = slow_spec(&mut setup, "a:80", clock.now(), 0);
        let key = pool.add(&mut setup, described);

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            let outcome = drive(
                pool.terminate(&mut cx, &mut host, &mut queue, key, false),
            );
            assert_eq!(outcome, TerminateOutcome::Terminated);
        });

        assert!(
            text.contains("closing connection #0"),
            "the verb is always \"closing\" without a multi handle, \
             got {text:?}"
        );
        assert!(
            !text.contains("shutting down connection #0"),
            "got {text:?}"
        );
        // `do_shutdown = !aborted` was TRUE, so the final pass ran and the
        // filters reported themselves finished: no `force ` prefix.
        assert!(
            text.contains("[SHUTDOWN] closing connection #0"),
            "the close must be graceful, got {text:?}"
        );
        assert!(
            !text.contains("[SHUTDOWN] force closing connection #0"),
            "got {text:?}"
        );
        assert_eq!(queue.count(), 0);
        assert!(pool.is_empty());
        assert!(host.events.iter().all(|event| event != "connchanged"));
    }

    /// With no multi handle an ABORT skips even that final pass --
    /// `do_shutdown = !aborted` with `aborted` true (`lib/conncache.c:680`).
    ///
    /// Identical to [`without_a_multi_handle_a_graceful_pass_still_runs`] in
    /// every respect but the request, and the close is announced as forced
    /// rather than graceful.
    #[test]
    fn without_a_multi_handle_an_abort_skips_the_final_pass() {
        let clock = clock_at(10);
        let mut host = TestHost::without_multi();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();
        let mut setup = CallCtx::new(&clock);
        let described = slow_spec(&mut setup, "a:80", clock.now(), 0);
        let key = pool.add(&mut setup, described);

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            let outcome = drive(
                pool.terminate(&mut cx, &mut host, &mut queue, key, true),
            );
            assert_eq!(outcome, TerminateOutcome::Terminated);
        });

        assert!(
            text.contains("[SHUTDOWN] force closing connection #0"),
            "an abort must skip the final pass, got {text:?}"
        );
        assert!(
            !text.contains("[SHUTDOWN] closing connection #0"),
            "got {text:?}"
        );
        assert_eq!(queue.count(), 0);
        assert!(pool.is_empty());
    }

    /// An in-use connection is left exactly where it is unless the request is
    /// an abort -- `lib/conncache.c:647-653`.
    #[test]
    fn terminating_an_in_use_connection_leaves_it_in_the_pool() {
        let clock = clock_at(10);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();
        let mut setup = CallCtx::new(&clock);
        let key = pool.add(&mut setup, spec("a:80", clock.now()));
        pool.get_mut(key).expect("live").set_attached_xfers(2);

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            let outcome = drive(
                pool.terminate(&mut cx, &mut host, &mut queue, key, false),
            );
            assert_eq!(outcome, TerminateOutcome::LeftInUse);
            assert!(!outcome.is_terminated());
        });

        assert!(
            text.contains("conn terminate when inuse: 2"),
            "got {text:?}"
        );
        assert_eq!(pool.count(), 1, "the pool must be untouched");
        assert!(pool.get(key).expect("live").is_in_pool());

        // An ABORT takes it anyway.
        let mut cx = CallCtx::new(&clock);
        let outcome =
            drive(pool.terminate(&mut cx, &mut host, &mut queue, key, true));
        assert_eq!(outcome, TerminateOutcome::Terminated);
        assert!(pool.is_empty());
    }

    /// A stale key answers `NotFound` and changes nothing.
    #[test]
    fn terminating_a_stale_key_answers_not_found() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let key = pool.add(&mut cx, spec("a:80", clock.now()));
        assert!(pool.remove(key).is_some());
        let survivor = pool.add(&mut cx, spec("b:80", clock.now()));

        let outcome =
            drive(pool.terminate(&mut cx, &mut host, &mut queue, key, false));
        assert_eq!(outcome, TerminateOutcome::NotFound);
        assert_eq!(pool.count(), 1);
        assert!(pool.get(survivor).is_some());
    }

    /// Destroying the pool moves every remaining connection through the same
    /// disposal path and leaves nothing behind -- `lib/conncache.c:231-254`.
    #[test]
    fn destroying_the_pool_empties_it() {
        let clock = clock_at(10);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();
        let mut setup = CallCtx::new(&clock);

        for destination in ["a:80", "a:80", "b:80"] {
            pool.add(&mut setup, spec(destination, clock.now()));
        }
        // One in use, which C removes from the pool and then LEAKS; here it is
        // dropped instead.
        let busy = pool.add(&mut setup, spec("c:80", clock.now()));
        pool.get_mut(busy).expect("live").attach();
        assert_eq!(pool.count(), 4);

        let text = multi_trace(|tracer| {
            let mut cx = CallCtx::new(&clock).with_tracer(tracer);
            drive(pool.destroy(&mut cx, &mut host, &mut queue));
        });

        assert!(
            text.contains("[CPOOL] destroy, 4 connections"),
            "got {text:?}"
        );
        assert!(
            text.contains(
                "[CPOOL] not discarding #3 still in use by 1 \
                           transfers"
            ),
            "got {text:?}"
        );
        assert!(pool.is_empty());
        assert_eq!(pool.destinations(), 0);
        assert_eq!(pool.count(), 0);

        // Destroying an empty pool is harmless and idempotent.
        let mut cx = CallCtx::new(&clock);
        drive(pool.destroy(&mut cx, &mut host, &mut queue));
        assert!(pool.is_empty());
    }

    // -- (32) find ---------------------------------------------------------

    /// The matcher stops at the first selection, and the done callback may
    /// override the answer -- `lib/conncache.c:614-630`.
    #[test]
    fn find_stops_early_and_the_done_callback_can_override() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let first = pool.add(&mut cx, spec("a:80", clock.now()));
        let second = pool.add(&mut cx, spec("a:80", clock.now()));
        let third = pool.add(&mut cx, spec("a:80", clock.now()));

        // Visits in bundle insertion order and stops at the second.
        let mut visited = Vec::new();
        let outcome = pool.find(
            "a:80",
            |key, conn| {
                visited.push(conn.connection_id());
                if key == second {
                    MatchVerdict::Select
                } else {
                    MatchVerdict::Continue
                }
            },
            None::<fn(bool, Option<&mut PooledConnection>) -> bool>,
        );

        assert_eq!(
            visited,
            vec![ConnectionId::new(0), ConnectionId::new(1)],
            "the third entry must not be visited"
        );
        assert!(outcome.matched);
        assert_eq!(outcome.selected, Some(second));
        assert!(outcome.discarded.is_empty());

        // The done callback receives the selected entry and may attach to it
        // while the traversal's borrow is still the only one --
        // `url_match_result`'s "attach it now while still under lock".
        let outcome = pool.find(
            "a:80",
            |key, _conn| {
                if key == third {
                    MatchVerdict::Select
                } else {
                    MatchVerdict::Continue
                }
            },
            Some(|matched: bool, entry: Option<&mut PooledConnection>| {
                assert!(matched);
                let entry = entry.expect("the selected entry is handed over");
                entry.attach();
                true
            }),
        );
        assert!(outcome.matched);
        assert!(pool.get(third).expect("live").is_in_use());

        // A done callback may override "nothing matched" into a match, and the
        // other way round.
        let outcome = pool.find(
            "a:80",
            |_key, _conn| MatchVerdict::Continue,
            Some(|matched: bool, entry: Option<&mut PooledConnection>| {
                assert!(!matched);
                assert!(entry.is_none());
                true
            }),
        );
        assert!(outcome.matched, "the callback overrode the answer");
        assert_eq!(outcome.selected, None);

        let outcome = pool.find(
            "a:80",
            |key, _conn| {
                if key == first {
                    MatchVerdict::Select
                } else {
                    MatchVerdict::Continue
                }
            },
            Some(|_matched: bool, _entry: Option<&mut PooledConnection>| false),
        );
        assert!(!outcome.matched);
        assert_eq!(outcome.selected, Some(first), "still recorded");

        // An unknown destination visits nothing, and the callback still runs.
        let outcome = pool.find(
            "nowhere:80",
            |_key, _conn| panic!("there is no bundle to visit"),
            Some(|matched: bool, entry: Option<&mut PooledConnection>| {
                assert!(!matched);
                assert!(entry.is_none());
                false
            }),
        );
        assert!(!outcome.matched);
        assert!(format!("{outcome:?}").contains("discarded: 0"));
    }

    /// A matcher may discard the entry it is looking at, and the traversal
    /// continues from the next one -- `lib/url.c:1291-1296`.
    #[test]
    fn find_lets_the_matcher_discard_the_current_entry() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let doomed = pool.add(&mut cx, spec("a:80", clock.now()));
        let wanted = pool.add(&mut cx, spec("a:80", clock.now()));
        assert_eq!(pool.count(), 2);

        let mut visited = Vec::new();
        let outcome = pool.find(
            "a:80",
            |key, conn| {
                visited.push(conn.connection_id());
                if key == doomed {
                    MatchVerdict::DiscardAndContinue
                } else {
                    MatchVerdict::Select
                }
            },
            None::<fn(bool, Option<&mut PooledConnection>) -> bool>,
        );

        assert_eq!(visited, vec![ConnectionId::new(0), ConnectionId::new(1)]);
        assert!(outcome.matched);
        assert_eq!(outcome.selected, Some(wanted));
        assert_eq!(outcome.discarded.len(), 1, "the entry is handed back");
        assert_eq!(outcome.discarded[0].connection_id(), ConnectionId::new(0));
        assert!(
            !outcome.discarded[0].is_in_pool(),
            "a discarded entry has already left the pool"
        );
        // And it really is out: the pool holds one connection and the doomed
        // key no longer resolves.
        assert_eq!(pool.count(), 1);
        assert!(pool.get(doomed).is_none());
        assert!(pool.get(wanted).is_some());
    }

    // -- upkeep ------------------------------------------------------------

    /// Upkeep visits every pooled connection, in use or not, and reports the
    /// first failure without cutting the pass short.
    #[test]
    fn upkeep_visits_every_connection() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        for destination in ["a:80", "a:80", "b:80"] {
            pool.add(&mut cx, spec(destination, clock.now()));
        }
        let busy = pool.add(&mut cx, spec("c:80", clock.now()));
        pool.get_mut(busy).expect("live").attach();

        let mut action = RecordingUpkeep::default();
        assert!(pool.upkeep(&mut cx, &mut action).is_ok());
        assert_eq!(
            action.visited,
            vec![
                ConnectionId::new(0),
                ConnectionId::new(1),
                ConnectionId::new(2),
                ConnectionId::new(3),
            ],
            "every connection, including the one in use"
        );

        // A failure is reported, and the remaining connections are still
        // visited.
        let mut action = RecordingUpkeep {
            fail_on: Some(ConnectionId::new(1)),
            ..RecordingUpkeep::default()
        };
        let outcome = pool.upkeep(&mut cx, &mut action);
        assert_eq!(
            outcome.err().map(crate::error::Error::into_code),
            Some(CURLcode::SendError)
        );
        assert_eq!(action.visited.len(), 4, "the pass was not cut short");

        // The production action drives the primary chain's keepalive, which an
        // empty chain reports as success.
        let mut keepalive = KeepAliveUpkeep;
        assert!(pool.upkeep(&mut cx, &mut keepalive).is_ok());
    }

    // -- (33) network change ------------------------------------------------

    /// A network change marks EVERY connection no-reuse and then removes only
    /// the idle ones -- `lib/conncache.c:842-873`.
    #[test]
    fn a_network_change_marks_all_and_removes_only_the_idle() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let idle_a = add_idle_at(&mut pool, &mut cx, "a:80", clock.now());
        let idle_b = add_idle_at(&mut pool, &mut cx, "b:80", clock.now());
        let busy = add_idle_at(&mut pool, &mut cx, "c:80", clock.now());
        pool.get_mut(busy).expect("live").attach();
        assert!(!pool.get(busy).expect("live").no_reuse());

        let removed =
            drive(pool.network_changed(&mut cx, &mut host, &mut queue));

        assert_eq!(removed, 2, "both idle connections go");
        assert!(pool.get(idle_a).is_none());
        assert!(pool.get(idle_b).is_none());
        assert_eq!(pool.count(), 1);

        // The one that stayed is MARKED, so it leaves the moment it is idle --
        // which the very next pass demonstrates.
        assert!(pool.get(busy).expect("live").no_reuse());
        pool.get_mut(busy).expect("live").detach();
        let removed =
            drive(pool.network_changed(&mut cx, &mut host, &mut queue));
        assert_eq!(removed, 1);
        assert!(pool.is_empty());

        // An empty pool is a no-op.
        let removed =
            drive(pool.network_changed(&mut cx, &mut host, &mut queue));
        assert_eq!(removed, 0);
    }

    /// A marked in-use connection is also reaped by the next PRUNE, without the
    /// predicate being asked.
    #[test]
    fn a_marked_connection_is_reaped_once_it_becomes_idle() {
        let clock = clock_at(10);
        let mut cx = CallCtx::new(&clock);
        let mut host = TestHost::new();
        let mut queue = ShutdownQueue::new();
        let mut pool = ConnectionPool::new();

        let busy = add_idle_at(&mut pool, &mut cx, "a:80", clock.now());
        pool.get_mut(busy).expect("live").attach();
        drive(pool.network_changed(&mut cx, &mut host, &mut queue));
        assert_eq!(pool.count(), 1);

        pool.get_mut(busy).expect("live").detach();
        let mut health = ContractHealth::default();
        let stats =
            drive(pool.prune_dead(&mut cx, &mut host, &mut queue, &mut health));
        assert_eq!(stats.reaped, 1);
        assert!(health.asked.is_empty(), "no-reuse bypasses the predicate");
        assert!(pool.is_empty());
    }

    // -- connection state and delegation -----------------------------------

    /// The pooled connection delegates to its teardown half rather than
    /// duplicating it, and reports every fact the policies read.
    #[test]
    fn a_pooled_connection_reports_its_state() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let key = pool.add(
            &mut cx,
            spec("host:443", CurlTime::new(100, 0))
                .with_no_network(true)
                .with_protocol_flags(PROTOPT_CONN_REUSE),
        );
        let conn = pool.get_mut(key).expect("live");

        assert_eq!(conn.destination(), "host:443");
        assert_eq!(conn.created(), CurlTime::new(100, 0));
        // `lastused` is seeded from `created`, so a newly pooled connection has
        // a defined age rather than looking infinitely idle.
        assert_eq!(conn.lastused(), CurlTime::new(100, 0));
        assert_eq!(conn.lifetime_ms(clock.now()), 900_000);
        assert_eq!(conn.idle_age_ms(clock.now()), 900_000);
        assert!(conn.no_network());
        assert!(!conn.connect_only());
        assert!(!conn.aborted());
        assert!(conn.is_in_pool());
        assert!(!conn.wants_close());
        assert!(!conn.no_reuse());
        // A scheme that uses no network counts as CONNECTED with no filter
        // chain at all -- the `else` branch of `Curl_conn_is_connected`
        // (`lib/cfilters.c:611-612`), which is what makes `file://` work.
        assert!(conn.is_connected(SocketIndex::First));
        assert!(conn.is_connected(SocketIndex::Secondary));

        conn.set_lastused(CurlTime::new(999, 0));
        assert_eq!(conn.idle_age_ms(clock.now()), 1_000);
        conn.mark_close();
        assert!(conn.wants_close());
        conn.mark_no_reuse();
        assert!(conn.no_reuse());

        // Both chains are reachable, and the shared one agrees with the
        // mutable one.
        assert!(conn.chains_mut().chain_mut(SocketIndex::First).is_empty());
        let conn = pool.get(key).expect("live");
        assert!(conn.chains().chain(SocketIndex::First).is_empty());
        assert!(format!("{conn:?}").contains("host:443"));

        // A scheme that DOES use the network is not connected while its chain
        // is empty, which is the complement of the assertion above.
        let networked = pool.add(&mut cx, spec("other:80", clock.now()));
        let networked = pool.get(networked).expect("live");
        assert!(!networked.no_network());
        assert!(!networked.is_connected(SocketIndex::First));
        assert!(!networked.is_connected(SocketIndex::Secondary));
    }

    /// A description reports its destination and prints without revealing the
    /// injected objects' contents.
    #[test]
    fn a_connection_description_is_inspectable() {
        let clock = clock_at(10);
        let described = spec("a:80", clock.now())
            .with_connect_only(true)
            .with_no_network(true)
            .with_protocol_flags(PROTOPT_SSL_REUSE);
        assert_eq!(described.destination(), "a:80");
        let text = format!("{described:?}");
        assert!(text.contains("ConnectionSpec"), "got {text:?}");
        assert!(text.contains("has_handler: false"), "got {text:?}");
        assert!(text.contains("connect_only: true"), "got {text:?}");
    }

    // -- (34) and (35) structural guarantees --------------------------------

    /// The shutdown queue is reached ONLY as a parameter, and its population is
    /// asked for rather than mirrored.
    ///
    /// This is the pool's half of the property `crate::conn::shutdown`'s
    /// `the_pool_is_reached_only_through_the_parameter` test asserts from the
    /// other side. Together they make the shared
    /// connection-limit invariant a pair of explicit exchanges rather than a
    /// cycle: the pool passes its count in, and asks the queue for its counts;
    /// the queue holds no handle back.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source text, not the program")]
    fn the_pool_and_the_queue_exchange_only_values() {
        // The queue arrives as a parameter, everywhere.
        assert!(
            OWN_SOURCE.contains("queue: &mut ShutdownQueue"),
            "the queue must arrive as a parameter"
        );

        // The pool's own count is what the queue is told.
        assert!(
            OWN_SOURCE.contains("queue.add(cx, host, inner, self.num_conn)"),
            "the pooled population must be passed as a value"
        );

        // And the queue's counts are ASKED for, never cached in a field.
        assert!(OWN_SOURCE.contains("queue.count()"), "must ask the queue");
        assert!(
            OWN_SOURCE.contains("queue.destination_count(destination)"),
            "must ask the queue per destination"
        );

        // The pool structure itself holds no queue. The declaration is located
        // rather than pattern-matched, so this cannot pass by the words merely
        // being absent from the file.
        let marker = "pub(crate) struct ConnectionPool {";
        let at = OWN_SOURCE
            .find(marker)
            .expect("the pool structure is declared in this file");
        let body = &OWN_SOURCE[at + marker.len()..];
        let end = body.find("\n}").expect("the declaration is terminated");
        let fields = &body[..end];
        assert!(
            !fields.contains("ShutdownQueue"),
            "the pool must hold no queue, found: {fields}"
        );
        assert!(
            !fields.contains("ShutdownHost"),
            "the pool must hold no multi handle, found: {fields}"
        );
    }

    /// The pool carries no interior lock, no re-entrancy bit and no global
    /// state.
    ///
    /// `lib/conncache.c:41-60` puts the lock in `crate::share`
    /// (`CURL_LOCK_DATA_CONNECT`, taken only when the pool is shared) and uses
    /// its own `locked` bit purely as a `DEBUGASSERT`. Neither has a successor
    /// here: `&mut self` on every entry point makes re-entrancy
    /// unrepresentable, so there is nothing left for a lock or a bit to
    /// protect.
    ///
    /// The forbidden spellings are assembled from fragments so that this
    /// assertion is not itself the occurrence it forbids -- the same discipline
    /// `crate::conn::shutdown`'s structural tests use.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source text, not the program")]
    fn the_pool_holds_no_interior_lock() {
        for forbidden in [
            concat!("Mut", "ex"),
            concat!("Rw", "Lock"),
            concat!("Ref", "Cell"),
            concat!("Atomic", "Bool"),
            concat!("Atomic", "Usize"),
            concat!("compare_", "exchange"),
            concat!("lock", "ed: bool"),
            concat!("static ", "mut"),
        ] {
            assert!(
                !OWN_SOURCE.contains(forbidden),
                "{forbidden:?} must not appear in this module"
            );
        }

        // And the positive form: every mutating entry point takes `&mut self`,
        // so two callers cannot be inside the pool at once.
        for entry in [
            "pub(crate) fn add(\n        &mut self,",
            "pub(crate) fn remove(&mut self, key: PoolKey)",
            "pub(crate) fn xfer_init(&mut self) -> XferInit",
        ] {
            assert!(
                OWN_SOURCE.contains(entry),
                "{entry:?} must mutate through an exclusive borrow"
            );
        }
    }

    /// The eviction policy is age-based and is not an ordering structure.
    ///
    /// The complement of [`selection_is_maximum_age_and_not_insertion_order`]:
    /// that test shows the ANSWER is by age, and this one shows there is no
    /// recency machinery in the module that could give any other answer. A
    /// bundle is a vector that is only ever appended to and removed from in
    /// place, so "move to the front on use" is not merely unused -- it is
    /// absent.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source text, not the program")]
    fn the_module_holds_no_recency_ordering() {
        for forbidden in [
            concat!("Linked", "List"),
            concat!("swap_", "remove"),
            concat!("move_to_", "front"),
            concat!("push_", "front"),
            concat!("VecDe", "que"),
        ] {
            assert!(
                !OWN_SOURCE.contains(forbidden),
                "{forbidden:?} must not appear in this module"
            );
        }

        // The bundle holds keys in insertion order and nothing else: no
        // instant, no counter, no rank that an ordering rule could read.
        let marker = "struct Bundle {";
        let at = OWN_SOURCE
            .find(marker)
            .expect("the bundle is declared in this file");
        let body = &OWN_SOURCE[at + marker.len()..];
        let end = body.find("\n}").expect("the declaration is terminated");
        let fields = &body[..end];
        assert!(fields.contains("order: Vec<PoolKey>"), "got {fields}");
        for forbidden in ["rank", "recent", "sequence"] {
            assert!(
                !fields.contains(forbidden),
                "{forbidden:?} must not be bundle state, found: {fields}"
            );
        }
    }

    /// The clock is injected, so no test in this module waits in real time and
    /// no production path reads a host clock directly.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source text, not the program")]
    fn the_module_reads_only_the_injected_clock() {
        for forbidden in [
            concat!("Instant", "::now"),
            concat!("SystemTime", "::now"),
            concat!("SystemClock", "::default"),
        ] {
            assert!(
                !OWN_SOURCE.contains(forbidden),
                "{forbidden:?} must not appear in this module"
            );
        }
        assert!(
            OWN_SOURCE.contains("cx.now()"),
            "every reading must come through the call context"
        );
    }

    /// This module names no protocol, TLS or transfer layer.
    ///
    /// The dead/reuse policy of `lib/url.c:622-700` belongs to
    /// `crate::protocols`, and importing it would be a cycle: a protocol
    /// installs filters into a connection, and a connection is what this pool
    /// holds. The policy arrives as [`ConnectionHealth`] instead, which is AAP
    /// pattern P12's seam. Assembled from fragments for the reason
    /// [`the_pool_holds_no_interior_lock`] gives.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source text, not the program")]
    fn the_module_names_no_higher_layer() {
        for forbidden in [
            concat!("use crate", "::protocols"),
            concat!("use crate", "::tls"),
            concat!("use crate", "::multi"),
            concat!("use crate", "::easy"),
            concat!("use crate", "::transfer"),
            concat!("use crate", "::share"),
            concat!("use crate", "::ffi"),
            concat!("use crate", "::proxy"),
            concat!("use crate", "::dns"),
            concat!("use ", "libc"),
        ] {
            assert!(
                !OWN_SOURCE.contains(forbidden),
                "{forbidden:?} must not be imported"
            );
        }

        // Nor does it reimplement the share layer's lock data; it is named in
        // the documentation as an EXTERNAL identifier and nowhere else.
        assert!(
            OWN_SOURCE.contains("CURL_LOCK_DATA_CONNECT"),
            "the external lock-data identifier must be documented"
        );
        // Assembled from fragments, for the reason above: a literal here
        // would be the very occurrence it forbids.
        assert!(
            !OWN_SOURCE.contains(concat!("CURL_LOCK_", "ACCESS_SINGLE")),
            "share locking must not be reimplemented here"
        );
    }

    /// The generational slab is written in this file, with no new dependency.
    ///
    /// AAP section 0.5.1 pins the dependency set, and no slab, index-map,
    /// bitflag or cache crate is in it. The storage, the free chain and both
    /// bitmap newtypes are therefore local.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source text, not the program")]
    fn the_storage_and_bitmaps_are_local() {
        for forbidden in [
            concat!("use ", "slab"),
            concat!("use ", "slotmap"),
            concat!("use ", "indexmap"),
            concat!("use ", "bitflags"),
            concat!("bitflags", "!"),
        ] {
            assert!(
                !OWN_SOURCE.contains(forbidden),
                "{forbidden:?} must not appear in this module"
            );
        }
        assert!(OWN_SOURCE.contains("struct GenerationalSlab<T>"));
        assert!(OWN_SOURCE.contains("struct ConnCheck(u32)"));
        assert!(OWN_SOURCE.contains("struct ConnResult(u32)"));
    }
}
