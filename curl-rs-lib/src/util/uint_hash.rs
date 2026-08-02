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

//! The integer-keyed hash map -- supersedes `lib/uint-hash.c` (241 lines)
//! and `lib/uint-hash.h` (61 lines).
//!
//! # What this container actually is
//!
//! Read as a data structure it is a hash map keyed on `uint32_t`. Read from
//! its call sites it is one specific thing: the **transfer-id to
//! per-stream-state map** for the multiplexed protocols. All three C
//! consumers construct it identically, with 63 slots, and every one of them
//! keys on `data->mid`:
//!
//! | Call site | Measured at | Destructor passed |
//! |---|---|---|
//! | `lib/http2.c` | `:183` | `h2_stream_hash_free` |
//! | `lib/vquic/curl_ngtcp2.c` | `:163` | `h3_stream_hash_free` |
//! | `lib/vquic/curl_quiche.c` | `:118` | `h3_stream_hash_free` |
//!
//! Two of the three are in scope and become `crate::protocols::http2` and
//! `crate::protocols::http3`. The third is excluded, because quiche is
//! dropped in favour of quinn, and it is listed anyway: it contributes two
//! of the three iteration sites audited below.
//!
//! The key is `mid`, declared `uint32_t mid` at `lib/urldata.h:1630` and
//! documented there as a unique identifier inside one multi instance.
//!
//! A `mid` of 0 is a LIVE transfer identifier and must never be read as a
//! sentinel: the multi layer spells "not in a multi" as `UINT32_MAX`
//! instead (`lib/multi.c:516`, `:774`, `:876-877`, `:2875`). This container
//! places no interpretation on any key whatsoever -- 0 and [`u32::MAX`] are
//! both ordinary storable keys here, and the sentinel meaning belongs to the
//! multi layer alone.
//!
//! # What vanished, and why
//!
//! Five constructs in the C have no successor here. They are enumerated
//! rather than summarized, because each is something a reader may look for
//! and fail to find.
//!
//! 1. **`struct uint_hash_entry` and its `next` chain**
//!    (`lib/uint-hash.c:38-42`). The C allocates a node per entry carrying
//!    `next`, `value` and `id`, and threads those nodes through 63 bucket
//!    chains. [`HashMap`] owns its own storage, so the intrusive chain
//!    becomes an owned collection, and the pointer-to-pointer unlink surgery
//!    of `uint32_hash_entry_unlink` (`:93-99`) goes with it.
//! 2. **`uint32_hash_hash(id, slots)` (`:33-36`)**, whose entire body is
//!    `id % slots` -- a bare modulo with no mixing step. [`HashMap`]'s
//!    SipHash replaces it. The substitution is safe because the hash value is
//!    not externally observable: it only selects a bucket, and no consumer
//!    ever sees it. Iteration ORDER is a separate question, audited below,
//!    where the substitution is not quite free.
//! 3. **`slots`**, which is 63 at every one of the three call sites. Nothing
//!    corresponds to it, because [`HashMap`] grows on demand. It survives
//!    only as the argument of [`Uint32Hash::with_capacity`], which forwards
//!    it as a capacity HINT. No fixed-bucket chained table is built here and
//!    none should be reintroduced.
//! 4. **The lazily allocated `table`.** `Curl_uint32_hash_init` leaves it
//!    NULL and the first `Curl_uint32_hash_set` allocates it (`:120-124`), so
//!    a map that is never written never allocates. `HashMap::new` is lazy in
//!    exactly the same way, so the behaviour carries over at no cost. The
//!    coincidence is recorded because it is the reason no explicit laziness
//!    appears below.
//! 5. **`CURL_UINT32_HASHINIT 0x7117e779` (`:29-31`)**, a DEBUGBUILD-only
//!    magic number stored in `h->init` and re-checked by every entry point to
//!    catch use of an uninitialized or already destroyed map. Rust's type
//!    system supersedes it: a [`Uint32Hash`] cannot be observed before it is
//!    constructed or after it is dropped. The constant is quoted so that a
//!    search for it lands here.
//!
//! ## One measured bug in the C, recorded so that nobody reproduces it
//!
//! The lazy allocation at `lib/uint-hash.c:121` reads
//!
//! ```text
//! h->table = curlx_calloc(h->slots, sizeof(*he));
//! ```
//!
//! where `he` is declared as a pointer to `struct uint_hash_entry`, so
//! `sizeof(*he)` is the size of the STRUCT rather than the size of a
//! pointer. Measured by compiling that declaration on this host: 24 bytes
//! against 8, so an array of 63 bucket pointers is allocated at three times
//! the size it needs. The defect is benign, because it over-allocates rather
//! than under-allocates, and it disappears entirely with [`HashMap`].
//!
//! ## Why the C asserted a non-zero slot count
//!
//! `Curl_uint32_hash_init` carries `DEBUGASSERT(slots)` (`:49`) for a
//! concrete reason rather than out of habit: the bucket index is
//! `id % slots`, and a modulo by zero traps. That hazard cannot arise here,
//! because no modulo is taken. [`Uint32Hash::with_capacity`] keeps a
//! `debug_assert!` on the same condition regardless, so that a caller ported
//! from a C site which computed its slot count still hears about a zero.
//!
//! # The destructor collapses into `Drop`, losslessly
//!
//! The C destructor is declared `typedef void Curl_uint32_hash_dtor(uint32_t
//! id, void *value)` (`lib/uint-hash.h:29`): it receives BOTH the key and
//! the value. [`Drop`] receives only the value, so the collapse would lose
//! the key if any consumer used it.
//!
//! **Audited, and no consumer uses it.** Every destructor in the tree
//! discards the key with an explicit `(void)id;` on its first line:
//!
//! | Destructor | Measured at |
//! |---|---|
//! | `h2_stream_hash_free` | `lib/http2.c:170-175` |
//! | `h3_stream_hash_free` | `lib/vquic/curl_ngtcp2.c:254-259` |
//! | `h3_stream_hash_free` | `lib/vquic/curl_quiche.c:187-192` |
//! | `t1616_mydtor` | `tests/unit/unit1616.c:28-33` |
//!
//! Each body then forwards to a plain context-freeing helper that releases
//! buffers and the struct. [`Drop`] on `V` therefore reproduces all four
//! exactly, and `crate::protocols::http2` and `crate::protocols::http3` can
//! rely on that: neither has to drain this map explicitly to recover a key
//! during teardown. Should some future consumer genuinely need the key while
//! tearing a value down, the honest remedy is for THAT consumer to drain the
//! map itself, and not for this type to grow a callback field.
//!
//! One conflation disappears in passing. `uint32_hash_entry_clear`
//! (`:74-84`) runs the destructor only `if(e->value)`, so a stored NULL was
//! silently skipped. A `V` cannot be absent, so the case cannot arise.
//!
//! # The two booleans mean DIFFERENT things
//!
//! This is the single easiest thing to get wrong here, so it is stated
//! before either method appears.
//!
//! [`Uint32Hash::set`] reports **that the value was taken**. The C returns
//! FALSE only on allocation failure, and both witnesses in the tree read a
//! FALSE as *the callee did not take ownership, so the caller still has to
//! release it*:
//!
//! ```text
//! tests/unit/unit1616.c:62-64
//!     ok = Curl_uint32_hash_set(&hash, key, value);
//!     if(!ok)
//!       curlx_free(value);
//!
//! lib/http2.c:388-391
//!     if(!Curl_uint32_hash_set(&ctx->streams, data->mid, stream)) {
//!       h2_stream_ctx_free(stream);
//!       return CURLE_OUT_OF_MEMORY;
//!     }
//! ```
//!
//! [`Uint32Hash::remove`] reports **that the key was present**. That one
//! really is `HashMap::remove(..).is_some()`.
//!
//! Returning `HashMap::insert(..).is_none()` from `set` would therefore
//! INVERT the meaning both call sites depend on: it answers "was the key
//! absent", which is false for an overwrite the C reports as success. The
//! asymmetry is restated at each of the two methods, because a reader who
//! meets them in isolation assumes the two booleans match, and they do not.
//!
//! # Overwriting a key destroys the old value and leaves the count alone
//!
//! `Curl_uint32_hash_set` (`:127-134`) walks the bucket chain and, on a hit,
//! calls `uint32_hash_entry_clear` -- which runs the destructor on the OLD
//! value -- then stores the new pointer in the SAME entry and returns TRUE.
//! No node is linked, so `h->size` does not move.
//!
//! [`Uint32Hash::set`] reproduces that shape step for step: it looks the key
//! up first and, on a hit, assigns through the returned `&mut V`. The
//! assignment drops the displaced value in place, which IS the destructor
//! call, and the map length is untouched. Two consequences follow, and both
//! are deliberate:
//!
//! - **The displaced value is never handed back.** The C contract is that
//!   the old value is destroyed on the caller's behalf. Returning it would
//!   move a destruction responsibility onto every call site and turn a `set`
//!   that a C programmer reads as fire-and-forget into a leak wherever the
//!   result is discarded without thought.
//! - **An overwrite cannot fail.** Reusing the existing entry allocates
//!   nothing in the C and nothing here, so the reservation that models the
//!   C's out-of-memory branch is taken only on the insert path. Reserving
//!   first would report failure for an operation the C cannot fail.
//!
//! New entries are PREPENDED to their bucket in the C
//! (`uint32_hash_elem_link`, `:101-108`), so within one bucket the C order
//! is reverse insertion. That detail is observable only through
//! [`Uint32Hash::visit`], which the audit below covers.
//!
//! # `visit` is an early-exit walk, not a plain for-each
//!
//! `Curl_uint32_hash_visit` (`:225-240`) walks bucket 0 upwards and, inside
//! each bucket, follows the `next` chain, and **a callback returning FALSE
//! stops the entire walk**. That is the point of the API rather than a
//! detail of it: two of its three call sites use it as a search.
//! [`Uint32Hash::visit`] keeps the contract exactly, and it hands out
//! `&mut V` rather than `&V` because the measured consumers mutate the
//! stream they are given. [`Uint32Hash::visit_ref`] is the shared-borrow
//! variant, for a walk that only reads.
//!
//! The `void *user_data` third parameter has no successor: a closure
//! captures whatever it needs with its real type, so the cast that every C
//! callback performed on entry has nowhere left to happen.
//!
//! ## The callback may not structurally modify the map
//!
//! The borrow checker forbids inserting or removing during a walk. That is
//! not a restriction this port adds. `lib/uint-hash.h` offers no such
//! guarantee either, and the C walk holds an entry pointer across the
//! callback and then dereferences its `next` field, so a callback that freed
//! the entry would leave the C reading released memory. The Rust rule and
//! the real C contract coincide exactly.
//!
//! Worth saying plainly, because the neighbouring integer-keyed bitset does
//! document iteration under modification in its own header, so a reader
//! arriving from there expects the opposite guarantee here.
//!
//! ## Iteration order: audited per call site, and [`HashMap`] is sound
//!
//! The C order is deterministic -- bucket `id % 63` ascending, reverse
//! insertion inside a bucket -- while `HashMap::iter_mut` order is
//! unspecified and randomized per process. Emitted bytes are a byte-exact
//! oracle across 1,476 of the test fixtures, so the difference was audited
//! rather than assumed. Exactly three call sites exist in the whole tree,
//! and `lib/http2.c` is not one of them: it uses only init, set, get, remove
//! and destroy.
//!
//! | Callback | Defined | Walked | Shape | Sensitive |
//! |---|---|---|---|---|
//! | `cf_ngtcp2_sfind` | `:307` | `:325` | search | **No** |
//! | `cf_quiche_disp_event` | `:577` | `:625` | search | **No** |
//! | `cf_quiche_stream_do` | `:206` | `:227` | dispatch | **No** |
//!
//! The first row is in `lib/vquic/curl_ngtcp2.c` and the other two are in
//! `lib/vquic/curl_quiche.c`.
//!
//! The two searches are order-insensitive because their predicate matches at
//! most one entry: a QUIC stream identifier designates exactly one stream,
//! and both callbacks return FALSE the moment they match, so whichever order
//! the walk takes it finds the same single entry. The first is additionally
//! behind `#if NGTCP2_VERSION_NUM < 0x011100`; newer ngtcp2 recovers the
//! stream from `ngtcp2_conn_get_stream_user_data` and never walks at all.
//!
//! The dispatch needed the closer look, since a for-each over every stream
//! CAN be order-sensitive when it produces output. Its only two inner
//! callbacks are `cf_quiche_do_expire`, which sets `stream->xfer_result` and
//! marks the transfer dirty, and `cf_quiche_do_resume`, which clears
//! `stream->quic_flow_blocked` and marks the transfer dirty. Both write
//! per-stream state idempotently, neither accumulates into anything shared,
//! and **neither emits a single byte to the network**. The one consequence
//! of ordering is the sequence of trace lines, which no byte-exact
//! expectation covers.
//!
//! **Conclusion: [`HashMap`] is sound for every consumer that exists.**
//!
//! Flagged for whoever writes `crate::protocols::http2` and
//! `crate::protocols::http3` rather than settled silently on their behalf.
//! If a new consumer needs a for-each whose ORDER reaches the wire, the
//! honest fix is to change the one field below to `BTreeMap<u32, V>`. That
//! yields ascending `mid` order, which is deterministic and is closer to
//! processing transfers in identifier order than the C's bucket order ever
//! was, and every method here keeps its signature: the only observable
//! change is that [`Uint32Hash::visit`] and [`Uint32Hash::visit_ref`] become
//! ordered. Do not reach for a custom hasher instead. Performance is an
//! explicit non-goal of this work, a non-default hasher trades away
//! denial-of-service resistance for no required benefit, and it would not
//! make the order deterministic in any case.
//!
//! # Remaining differences from the C, each one deliberate
//!
//! - **`clear` is unconditional here.** `Curl_uint32_hash_clear` exists only
//!   in unit-test builds: `lib/uint-hash.c:201-206` wraps the file-static
//!   `uint_hash_clear` in `#ifdef UNITTESTS`, while `uint_hash_clear` itself
//!   is used year-round by `Curl_uint32_hash_destroy`. Hiding the public form
//!   behind a build flag would buy nothing and would make the operation
//!   untestable without one.
//! - **`clear` keeps the allocation.** The C clear destroys every entry and
//!   leaves `h->table` allocated; `HashMap::clear` likewise retains capacity.
//!   Another coincidence rather than a design decision, and recorded so that
//!   nobody adds a shrink to "finish the job".
//! - **`destroy` becomes ordinary drop glue, and no [`Drop`] implementation
//!   is written.** `Curl_uint32_hash_destroy` (`:208-217`) clears, releases
//!   the table, asserts `h->size == 0` and zeroes `slots` while leaving
//!   `dtor` set. Dropping a [`Uint32Hash`] drops its map, which drops every
//!   value: the same effect, with the size assertion made unnecessary by
//!   construction. An explicit implementation was considered and rejected --
//!   it would add nothing and would block moving the field out of the struct.
//! - **`get` is strictly more precise.** `Curl_uint32_hash_get` returns NULL
//!   both for "absent" and for "present, holding NULL". `Option<&V>` can only
//!   mean absent, and no consumer stores a null-equivalent value: all three
//!   store a freshly allocated stream context.
//! - **`count` saturates rather than wrapping.** The C caches the population
//!   in a `uint32_t` that `++h->size` would wrap at 2^32. Reporting
//!   [`u32::MAX`] for a map that large is strictly more honest, and reaching
//!   the case at all needs 2^32 distinct keys.
//!
//! # Layering, safety and dependencies
//!
//! One import, [`HashMap`], and nothing else. This module names no sibling
//! module and no crate dependency, which keeps `crate::util` at the base of
//! the module graph where every other module can reach it without a cycle.
//! No error type is in play, because every fallible path in this API answers
//! with a `bool` exactly as the C does, so there is no `CURLcode` here.
//!
//! Nothing below holds a raw pointer, stores a function pointer, or hides a
//! payload behind a boxed dynamic type. Reintroducing a type-erased payload
//! to imitate `void *` would rebuild precisely the cast this transformation
//! exists to remove, so [`Uint32Hash`] is generic over `V` instead. The
//! `struct uint_hash_entry **he_anchor` double-indirection that the C needs
//! to unlink from the middle of a bucket chain has no counterpart at all.
//!
//! Edition 2021, and the minimum supported Rust version is 1.75.
//! `HashMap::try_reserve`, the one member here that is not ancient, has been
//! stable since 1.57 and is comfortably inside that floor.

use std::collections::HashMap;

/// A hash map keyed on [`u32`] -- supersedes `struct uint_hash`
/// (`lib/uint-hash.h:33-41`).
///
/// The C struct carries four fields plus a debug sentinel: `table`, `dtor`,
/// `slots`, `size` and `init`. Every one of the five is absorbed here. The
/// bucket array and the population counter are [`HashMap`]'s own business,
/// the destructor becomes [`Drop`] on `V`, the slot count survives only as
/// the hint [`Uint32Hash::with_capacity`] forwards, and the sentinel is
/// replaced by the type system. What is left is one field, which is the
/// whole point.
///
/// Changing that field to a `BTreeMap<u32, V>` is the single-line remedy
/// documented at the module level, should a consumer ever need a
/// deterministic walk order.
pub(crate) struct Uint32Hash<V> {
    map: HashMap<u32, V>,
}

impl<V> Uint32Hash<V> {
    /// Creates an empty map -- supersedes `Curl_uint32_hash_init`
    /// (`lib/uint-hash.c:44-58`) for the caller that has no slot count to
    /// offer.
    ///
    /// No allocation happens until the first [`Uint32Hash::set`], matching
    /// the C, whose `init` leaves `h->table` NULL.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Creates an empty map, pre-sized from a slot count -- supersedes
    /// `Curl_uint32_hash_init` (`lib/uint-hash.c:44-58`) for the three call
    /// sites that pass one.
    ///
    /// All three pass 63. The C treats the argument as a bucket count and
    /// takes `id % slots` to index; there is no modulo here, so it is a
    /// capacity hint and nothing more, and passing a different value changes
    /// no observable behaviour.
    ///
    /// # Panics
    ///
    /// Panics in a debug build when `slots` is zero, reproducing the C's
    /// `DEBUGASSERT(slots)` at `:49`. The C needed it because a modulo by
    /// zero traps; the assertion is kept so that a caller ported from a site
    /// which computed its slot count still hears about a zero.
    #[allow(dead_code)]
    pub(crate) fn with_capacity(slots: u32) -> Self {
        debug_assert!(
            slots > 0,
            "a zero slot count is a caller bug: the C indexed with a \
             modulo by this value"
        );
        // A capacity that the platform cannot express is simply not applied,
        // rather than clamped to `usize::MAX`, which would ask the allocator
        // for an impossible reservation. Unreachable on all four mandated
        // targets, every one of which is 64-bit.
        let capacity = usize::try_from(slots).unwrap_or(0);
        Self {
            map: HashMap::with_capacity(capacity),
        }
    }

    /// Stores `value` under `id`, reporting whether the value was taken --
    /// supersedes `Curl_uint32_hash_set` (`lib/uint-hash.c:113-142`).
    ///
    /// # The returned boolean
    ///
    /// `true` means **the map has taken ownership of `value`**. `false` means
    /// the reservation the insert needed could not be made, so nothing was
    /// stored. It does NOT report whether the key was previously absent, and
    /// an implementation returning `HashMap::insert(..).is_none()` here would
    /// invert what both C call sites depend on. See the module documentation
    /// for the two witnesses.
    ///
    /// Because `value` is moved in, a `false` cannot hand it back, whereas
    /// the C caller still held its pointer. That difference is not a loss:
    /// the C caller had to release the value itself in that branch, and here
    /// the value is dropped for it.
    ///
    /// # Overwriting
    ///
    /// An existing key keeps its slot. The displaced value is dropped in
    /// place, which is what `uint32_hash_entry_clear` did by invoking the
    /// destructor, and it is not returned to the caller. The population is
    /// unchanged, exactly as the C leaves `h->size` alone on that path.
    #[allow(dead_code)]
    pub(crate) fn set(&mut self, id: u32, value: V) -> bool {
        // The C's chain walk, and its consequence: an overwrite reuses the
        // entry, so it allocates nothing and cannot fail. Assigning through
        // the borrow drops the displaced value, which IS the destructor call
        // at `lib/uint-hash.c:130`.
        if let Some(slot) = self.map.get_mut(&id) {
            *slot = value;
            return true;
        }

        // The C's only failure branch: `:121-123` for the bucket array and
        // `:137-138` for the entry. Reserving before inserting is what keeps
        // that branch reachable at all, since `HashMap::insert` itself aborts
        // on allocation failure rather than reporting it.
        if self.map.try_reserve(1).is_err() {
            return false;
        }

        // Bound rather than folded into the assertion on purpose:
        // `debug_assert!` does not evaluate its argument once debug
        // assertions are off, so inserting inside one would silently drop the
        // insert from every release build.
        let displaced = self.map.insert(id, value);
        debug_assert!(
            displaced.is_none(),
            "the lookup above already handled every present key"
        );
        true
    }

    /// Removes the entry for `id`, reporting whether one was present --
    /// supersedes `Curl_uint32_hash_remove` (`lib/uint-hash.c:144-164`).
    ///
    /// # The returned boolean
    ///
    /// `true` means **the key was present** and its value has been dropped,
    /// which is the destructor call the C made through
    /// `uint32_hash_entry_destroy`. `false` means the key was absent, which
    /// in the C also covered the case of a map whose table had never been
    /// allocated.
    ///
    /// Note the asymmetry with [`Uint32Hash::set`], whose boolean answers a
    /// different question entirely.
    #[allow(dead_code)]
    pub(crate) fn remove(&mut self, id: u32) -> bool {
        // The removed value lives in the temporary this expression builds and
        // is dropped when the statement ends, so the destructor still runs.
        self.map.remove(&id).is_some()
    }

    /// Borrows the value stored under `id` -- supersedes
    /// `Curl_uint32_hash_get` (`lib/uint-hash.c:166-182`).
    ///
    /// [`None`] means absent. The C returned NULL both for an absent key and
    /// for a key holding NULL; the two cannot be confused here.
    #[allow(dead_code)]
    pub(crate) fn get(&self, id: u32) -> Option<&V> {
        self.map.get(&id)
    }

    /// Mutably borrows the value stored under `id`.
    ///
    /// The C has no separate accessor for this: `Curl_uint32_hash_get`
    /// returns a `void *` through which the caller mutates the stream
    /// context, and every consumer does. Splitting the shared and exclusive
    /// borrows is what lets the borrow checker distinguish a read from a
    /// write at each of those sites.
    #[allow(dead_code)]
    pub(crate) fn get_mut(&mut self, id: u32) -> Option<&mut V> {
        self.map.get_mut(&id)
    }

    /// Reports how many entries are stored -- supersedes
    /// `Curl_uint32_hash_count` (`lib/uint-hash.c:219-223`).
    ///
    /// The C returns the cached `h->size`. The count saturates at
    /// [`u32::MAX`] rather than wrapping as `++h->size` would, and reaching
    /// that value needs 2^32 distinct keys.
    #[allow(dead_code)]
    pub(crate) fn count(&self) -> u32 {
        u32::try_from(self.map.len()).unwrap_or(u32::MAX)
    }

    /// Reports whether the map holds no entries.
    ///
    /// The C has no such entry point, and this is not decoration: two of the
    /// three `Curl_uint32_hash_count` call sites in `lib/vquic/curl_ngtcp2.c`
    /// (`:202` and `:374`) exist only to write `if(!count(..))`, which is an
    /// emptiness test spelled through a population query. This is the direct
    /// successor of that idiom.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drops every stored value, leaving the map empty -- supersedes
    /// `Curl_uint32_hash_clear` (`lib/uint-hash.c:201-206`) and the
    /// file-static `uint_hash_clear` (`:184-199`) it wraps.
    ///
    /// Every value is dropped, which is the destructor call the C made per
    /// entry. The allocation is retained, matching the C, which frees
    /// `h->table` only in `Curl_uint32_hash_destroy`. Unlike the C wrapper,
    /// this is available in every build rather than only under `UNITTESTS`.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        self.map.clear();
    }

    /// Walks the entries with exclusive access, stopping early on request --
    /// supersedes `Curl_uint32_hash_visit` (`lib/uint-hash.c:225-240`).
    ///
    /// `cb` receives each key and a mutable borrow of its value, and
    /// **returning `false` ends the walk immediately**, exactly as the C
    /// returns from its nested loops. Returning `true` continues.
    ///
    /// The `void *user_data` the C threaded through has no parameter here: a
    /// closure captures what it needs, with its own type, so the cast every C
    /// callback opened with is gone.
    ///
    /// `cb` cannot insert into or remove from the map while the walk is in
    /// progress. The borrow checker enforces that, and the C offers no such
    /// guarantee either -- it holds an entry pointer across the callback and
    /// then follows that entry's `next` field.
    ///
    /// The visiting ORDER is unspecified. See the module documentation for
    /// the per-call-site audit that establishes no consumer depends on it,
    /// and for the remedy if one ever does.
    #[allow(dead_code)]
    pub(crate) fn visit<F>(&mut self, mut cb: F)
    where
        F: FnMut(u32, &mut V) -> bool,
    {
        for (id, value) in self.map.iter_mut() {
            if !cb(*id, value) {
                return;
            }
        }
    }

    /// Walks the entries with shared access, stopping early on request.
    ///
    /// The read-only counterpart of [`Uint32Hash::visit`], with the same
    /// early-exit contract. `visit` is the form the measured consumers need,
    /// because they mutate the stream they are handed; this one exists for a
    /// walk that only inspects, so that a caller does not have to take an
    /// exclusive borrow it has no use for.
    #[allow(dead_code)]
    pub(crate) fn visit_ref<F>(&self, mut cb: F)
    where
        F: FnMut(u32, &V) -> bool,
    {
        for (id, value) in self.map.iter() {
            if !cb(*id, value) {
                return;
            }
        }
    }
}

/// An empty map, equivalent to [`Uint32Hash::new`].
///
/// Written by hand rather than derived. `#[derive(Default)]` places a
/// `V: Default` bound on the generated implementation, which would demand
/// something of the value type that neither [`HashMap`] nor any consumer
/// here requires.
impl<V> Default for Uint32Hash<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::rc::Rc;

    /// The fixture `tests/unit/unit1616.c` uses, reproduced exactly: 15
    /// slots at `:37`, keys 20 and 25 at `:56-57`, values 199 and 204 at
    /// `:61` and `:75`.
    const SLOTS: u32 = 15;
    const KEY: u32 = 20;
    const KEY2: u32 = 25;
    const VALUE: i32 = 199;
    const VALUE2: i32 = 204;

    /// A value whose drops are counted.
    ///
    /// The C proved its destructor ran by handing `Curl_uint32_hash_dtor` a
    /// heap pointer and letting the leak checker complain. `Drop` is the
    /// successor of that destructor, so the equivalent evidence here is a
    /// counter: every assertion about destruction below reads this rather
    /// than assuming the collapse worked.
    struct Counted {
        tag: u32,
        drops: Rc<Cell<usize>>,
    }

    impl Counted {
        fn new(tag: u32, drops: &Rc<Cell<usize>>) -> Self {
            Self {
                tag,
                drops: Rc::clone(drops),
            }
        }
    }

    impl Drop for Counted {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    fn counter() -> Rc<Cell<usize>> {
        Rc::new(Cell::new(0))
    }

    /// `tests/unit/unit1616.c:46-86`, step for step.
    ///
    /// The C test is the only unit test of this container, and its coverage
    /// relocates here because a Rust static library does not export
    /// crate-private items for a C program to link against.
    #[test]
    fn the_unit1616_sequence_is_reproduced() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::with_capacity(SLOTS);

        assert!(hash.set(KEY, VALUE), "insertion into hash failed");
        assert_eq!(hash.get(KEY), Some(&VALUE), "lookup present entry failed");
        assert_eq!(hash.get(KEY2), None, "lookup missing entry failed");

        hash.clear();
        assert_eq!(hash.count(), 0, "clear left entries behind");

        assert!(hash.set(KEY2, VALUE2), "insertion into hash failed");
        assert_eq!(
            hash.get(KEY2),
            Some(&VALUE2),
            "lookup present entry failed"
        );
        assert_eq!(
            hash.get(KEY),
            None,
            "the cleared entry came back after a later insertion"
        );
    }

    /// The trap: `set` answers "the value was taken", never "the key was
    /// absent". An implementation written as
    /// `HashMap::insert(..).is_none()` fails precisely this test.
    #[test]
    fn set_reports_that_the_value_was_taken_not_that_the_key_was_absent() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::new();

        assert!(hash.set(KEY, VALUE), "a fresh insertion must report true");
        assert!(
            hash.set(KEY, VALUE2),
            "an overwrite must report true as well -- the C returns TRUE on \
             that path at lib/uint-hash.c:132"
        );
    }

    /// `set` on an existing key runs the destructor on the displaced value
    /// and leaves the population alone, per `lib/uint-hash.c:127-134`.
    #[test]
    fn overwriting_a_key_drops_the_displaced_value_exactly_once() {
        let drops = counter();
        let mut hash: Uint32Hash<Counted> = Uint32Hash::with_capacity(SLOTS);

        assert!(hash.set(KEY, Counted::new(1, &drops)));
        assert_eq!(hash.count(), 1);
        assert_eq!(drops.get(), 0, "nothing has been displaced yet");

        assert!(hash.set(KEY, Counted::new(2, &drops)));
        assert_eq!(
            drops.get(),
            1,
            "the displaced value must be dropped exactly once"
        );
        assert_eq!(
            hash.count(),
            1,
            "an overwrite must not change the population"
        );
        assert_eq!(
            hash.get(KEY).map(|value| value.tag),
            Some(2),
            "the new value must be the one stored"
        );

        drop(hash);
        assert_eq!(drops.get(), 2, "the surviving value must drop as well");
    }

    /// `remove` answers a different question from `set`: it reports whether
    /// the key was present (`lib/uint-hash.c:155-163`).
    #[test]
    fn remove_reports_whether_the_key_was_present() {
        let drops = counter();
        let mut hash: Uint32Hash<Counted> = Uint32Hash::with_capacity(SLOTS);
        assert!(hash.set(KEY, Counted::new(1, &drops)));

        assert!(hash.remove(KEY), "removing a present key reports true");
        assert_eq!(hash.count(), 0, "removal must decrement the population");
        assert_eq!(drops.get(), 1, "removal must drop the value once");

        assert!(!hash.remove(KEY), "removing an absent key reports false");
        assert_eq!(hash.count(), 0, "a failed removal changes nothing");
        assert_eq!(drops.get(), 1, "a failed removal drops nothing");
    }

    /// The C guarded `remove` and `get` with `if(h->table)`, so both were
    /// well defined on a map that had never been written. Laziness carries
    /// over, and so must the tolerance.
    #[test]
    fn an_untouched_map_tolerates_every_read_and_removal() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::with_capacity(SLOTS);

        assert!(hash.is_empty());
        assert_eq!(hash.count(), 0);
        assert_eq!(hash.get(KEY), None);
        assert_eq!(hash.get_mut(KEY), None);
        assert!(!hash.remove(KEY), "removal from an empty map reports false");
    }

    /// `clear` destroys every entry, which the C did by invoking the
    /// destructor per entry in `uint_hash_clear` (`:184-199`).
    #[test]
    fn clear_drops_every_value_and_empties_the_map() {
        let drops = counter();
        let mut hash: Uint32Hash<Counted> = Uint32Hash::with_capacity(SLOTS);
        for tag in 0..5_u32 {
            assert!(hash.set(tag, Counted::new(tag, &drops)));
        }
        assert_eq!(hash.count(), 5);

        hash.clear();
        assert_eq!(drops.get(), 5, "every value must be dropped once");
        assert_eq!(hash.count(), 0);
        assert!(hash.is_empty());

        // Usable afterwards, as it is in the C: unit1616 inserts again after
        // its clear.
        assert!(hash.set(KEY, Counted::new(99, &drops)));
        assert_eq!(hash.count(), 1);
        assert_eq!(drops.get(), 5, "the new insertion drops nothing");
    }

    /// Dropping the map is the successor of `Curl_uint32_hash_destroy`.
    #[test]
    fn dropping_the_map_drops_every_value_exactly_once() {
        let drops = counter();
        {
            let mut hash: Uint32Hash<Counted> = Uint32Hash::new();
            for tag in 0..8_u32 {
                assert!(hash.set(tag, Counted::new(tag, &drops)));
            }
            assert_eq!(drops.get(), 0, "nothing drops while the map lives");
        }
        assert_eq!(drops.get(), 8, "every value drops exactly once");
    }

    /// The early exit is the point of the API: `lib/uint-hash.c:235-236`
    /// returns from both loops the moment the callback answers FALSE.
    #[test]
    fn visit_stops_when_the_callback_returns_false() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::with_capacity(SLOTS);
        for key in 0..6_u32 {
            assert!(hash.set(key, i32::from(key as u16)));
        }

        let mut calls = 0_usize;
        hash.visit(|_id, _value| {
            calls += 1;
            false
        });
        assert_eq!(calls, 1, "a false on the first entry must end the walk");

        let mut calls = 0_usize;
        hash.visit(|_id, _value| {
            calls += 1;
            calls < 3
        });
        assert_eq!(calls, 3, "the walk must end on the third callback");
    }

    /// A callback that never stops sees every entry once. Compared as a set,
    /// because the visiting order is unspecified and the module-level audit
    /// establishes that no consumer depends on it.
    #[test]
    fn visit_reaches_every_entry_exactly_once() {
        let expected: HashSet<u32> =
            [0, 1, 7, 63, 64, 1_000, u32::MAX].into_iter().collect();
        let mut hash: Uint32Hash<u32> = Uint32Hash::with_capacity(SLOTS);
        for key in &expected {
            assert!(hash.set(*key, *key));
        }

        let mut seen: Vec<u32> = Vec::new();
        hash.visit(|id, value| {
            assert_eq!(id, *value, "the key and value must arrive paired");
            seen.push(id);
            true
        });

        assert_eq!(seen.len(), expected.len(), "no entry may repeat");
        assert_eq!(seen.into_iter().collect::<HashSet<u32>>(), expected);
    }

    /// The mutable borrow is what the measured consumers need: both quiche
    /// callbacks write to the stream they are handed.
    #[test]
    fn visit_can_mutate_the_values_it_is_handed() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::with_capacity(SLOTS);
        assert!(hash.set(KEY, VALUE));
        assert!(hash.set(KEY2, VALUE2));

        hash.visit(|_id, value| {
            *value += 1;
            true
        });

        assert_eq!(hash.get(KEY), Some(&(VALUE + 1)));
        assert_eq!(hash.get(KEY2), Some(&(VALUE2 + 1)));
    }

    /// The C's `if(h && h->table && cb)` guard at `:229` means a map that was
    /// never written never calls back. Same here, and after a `clear` too.
    #[test]
    fn visit_on_an_empty_map_never_calls_back() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::with_capacity(SLOTS);

        let mut calls = 0_usize;
        hash.visit(|_id, _value| {
            calls += 1;
            true
        });
        assert_eq!(calls, 0, "an untouched map must not call back");

        assert!(hash.set(KEY, VALUE));
        hash.clear();
        hash.visit(|_id, _value| {
            calls += 1;
            true
        });
        assert_eq!(calls, 0, "a cleared map must not call back either");
    }

    /// The shared-borrow walk carries the same early-exit contract.
    #[test]
    fn visit_ref_walks_and_stops_like_visit() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::with_capacity(SLOTS);
        for key in 0..4_u32 {
            assert!(hash.set(key, VALUE));
        }

        let mut calls = 0_usize;
        hash.visit_ref(|_id, value| {
            assert_eq!(*value, VALUE);
            calls += 1;
            true
        });
        assert_eq!(calls, 4, "the full walk must see every entry");

        let mut calls = 0_usize;
        hash.visit_ref(|_id, _value| {
            calls += 1;
            false
        });
        assert_eq!(calls, 1, "a false must end the walk immediately");

        let mut calls = 0_usize;
        let empty: Uint32Hash<i32> = Uint32Hash::new();
        empty.visit_ref(|_id, _value| {
            calls += 1;
            true
        });
        assert_eq!(calls, 0, "an empty map must not call back");
    }

    /// Both extremes of the key domain are ordinary keys. `mid` 0 is a live
    /// transfer identifier, and `UINT32_MAX` carries its sentinel meaning in
    /// the multi layer rather than in this container.
    #[test]
    fn zero_and_the_maximum_are_ordinary_keys() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::new();

        assert!(hash.set(0, VALUE));
        assert!(hash.set(u32::MAX, VALUE2));
        assert_eq!(hash.count(), 2);
        assert_eq!(hash.get(0), Some(&VALUE));
        assert_eq!(hash.get(u32::MAX), Some(&VALUE2));

        assert!(hash.remove(0));
        assert_eq!(hash.get(0), None);
        assert_eq!(
            hash.get(u32::MAX),
            Some(&VALUE2),
            "removing one extreme must not disturb the other"
        );

        assert!(hash.remove(u32::MAX));
        assert!(hash.is_empty());
    }

    /// The C cached its population in `h->size`, adjusted at exactly two
    /// places: `elem_link` increments and `entry_unlink` decrements. Every
    /// mutating operation is checked against that accounting here.
    #[test]
    fn count_tracks_every_mutating_operation() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::with_capacity(SLOTS);
        assert_eq!(hash.count(), 0);
        assert!(hash.is_empty());

        assert!(hash.set(KEY, VALUE));
        assert_eq!(hash.count(), 1, "a fresh insertion increments");
        assert!(!hash.is_empty());

        assert!(hash.set(KEY, VALUE2));
        assert_eq!(hash.count(), 1, "an overwrite leaves the count alone");

        assert!(hash.set(KEY2, VALUE));
        assert_eq!(hash.count(), 2, "a second key increments");

        assert!(hash.remove(KEY));
        assert_eq!(hash.count(), 1, "a successful removal decrements");

        assert!(!hash.remove(KEY));
        assert_eq!(hash.count(), 1, "a failed removal changes nothing");

        hash.clear();
        assert_eq!(hash.count(), 0, "clear empties the count");
        assert!(hash.is_empty());
    }

    /// `Curl_uint32_hash_get` returned a `void *` through which consumers
    /// wrote; the exclusive accessor is that write path.
    #[test]
    fn get_mut_modifies_in_place() {
        let mut hash: Uint32Hash<i32> = Uint32Hash::new();
        assert!(hash.set(KEY, VALUE));

        let slot = hash.get_mut(KEY).expect("the key was just inserted");
        *slot = VALUE2;

        assert_eq!(hash.get(KEY), Some(&VALUE2));
        assert_eq!(hash.count(), 1, "a write through the borrow adds nothing");
    }

    /// The slot count is a hint and nothing else, so the two constructors and
    /// `Default` must be indistinguishable through the API.
    #[test]
    fn the_constructors_agree_because_slots_are_only_a_hint() {
        let mut from_new: Uint32Hash<i32> = Uint32Hash::new();
        let mut from_capacity: Uint32Hash<i32> = Uint32Hash::with_capacity(1);
        let mut from_default: Uint32Hash<i32> = Uint32Hash::default();

        for hash in [&mut from_new, &mut from_capacity, &mut from_default] {
            assert!(hash.is_empty());
            assert_eq!(hash.count(), 0);
            // Well past a hint of one, which the C would have had to reach
            // through a bucket chain and which here simply grows the map.
            for key in 0..200_u32 {
                assert!(hash.set(key, VALUE));
            }
            assert_eq!(hash.count(), 200);
            assert_eq!(hash.get(199), Some(&VALUE));
        }
    }

    /// A zero slot count is the caller bug the C asserted on, and the
    /// assertion is reproduced rather than the trap it guarded against.
    #[test]
    #[should_panic(expected = "a zero slot count is a caller bug")]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "debug_assert! is inert without debug assertions"
    )]
    fn a_zero_slot_count_trips_the_debug_assertion() {
        let _hash: Uint32Hash<i32> = Uint32Hash::with_capacity(0);
    }

    /// The container is generic over the value, so the stream context each
    /// consumer stores arrives with its own type rather than as an untyped
    /// pointer. Exercised with a struct shaped like those contexts.
    #[test]
    fn a_structured_value_round_trips_without_a_cast() {
        #[derive(Debug, PartialEq, Eq)]
        struct StreamCtx {
            id: u64,
            flow_blocked: bool,
        }

        let mut hash: Uint32Hash<StreamCtx> = Uint32Hash::with_capacity(63);
        assert!(hash.set(
            7,
            StreamCtx {
                id: 4,
                flow_blocked: true,
            }
        ));

        hash.visit(|_mid, stream| {
            if stream.flow_blocked {
                stream.flow_blocked = false;
            }
            true
        });

        assert_eq!(
            hash.get(7),
            Some(&StreamCtx {
                id: 4,
                flow_blocked: false,
            })
        );
    }
}
