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

//! Integer-keyed bitsets: one dense and fixed-capacity, one sparse and
//! unbounded.
//!
//! Supersedes `lib/uint-bset.c` (231 lines) with `lib/uint-bset.h` (112) and
//! `lib/uint-spbset.c` (251) with `lib/uint-spbset.h` (91), which AAP 0.4.1
//! maps onto this one file.
//!
//! These are **not general-purpose containers**, and reading them as such is
//! the one way to get them wrong. They exist to carry the multi handle's
//! transfer bookkeeping, their capacity behaviour is observable through the
//! public multi interface, and their iteration contract is relied upon while
//! the set is being modified. The measured consumers are `lib/multi.c`,
//! `lib/multi_ev.c` and `lib/multi_ntfy.c`, through the declarations in
//! `lib/multihandle.h`, `lib/multi_ev.h` and `lib/multi_ntfy.h`.
//!
//! # Two representations, and why they differ
//!
//! [`Uint32Bset`] keeps a **real bitset** -- a `Vec<u64>` of 64-bit slots --
//! because its capacity is *observable behaviour* rather than an
//! implementation detail. `lib/uint-bset.h:29-30` describes it as holding
//! "the numbers from 0 - (nmax - 1), rounded to the next 64 multiple", and
//! two consequences of that bound are asserted by the reference unit test:
//!
//! - [`Uint32Bset::add`] returns `false` for a number at or above the
//!   capacity (`lib/uint-bset.c:109-110`), asserted at
//!   `tests/unit/unit3211.c:72-73`.
//! - Resizing downwards **silently truncates**, because only
//!   `min(new, old)` slots survive (`lib/uint-bset.c:52-53`), asserted at
//!   `tests/unit/unit3211.c:110-121`.
//!
//! A `HashSet<u32>` would accept every number and lose both, so it is not a
//! candidate. This is the one place in `util` where a hand-rolled bit
//! representation is the *faithful* choice rather than a performance choice.
//!
//! [`Uint32SpBset`] keeps a [`BTreeSet<u32>`]. Its C original is a linked
//! list of 256-bit chunks -- `CURL_UINT32_SPBSET_CH_SLOTS 4` with
//! `CURL_UINT32_SPBSET_CH_MASK 255`, annotated "4 slots = 256 bits, keep
//! this a 2^n value" (`lib/uint-spbset.h:36-38`) -- and that chunking buys
//! exactly one thing: memory efficiency when the members are few and close
//! together (`lib/uint-spbset.h:31-33`). Memory efficiency is a performance
//! property, and performance is an explicit non-goal (AAP 0.1.1), while the
//! set's *behaviour* is fully described by "holds any `u32`, supports add,
//! remove, contains, count, clear, first and next-greater-than". A
//! `BTreeSet` satisfies every one of those, and expresses the iteration
//! contract below directly as one `range` query. The substitution is
//! therefore recorded here as a deliberate, auditable decision rather than
//! an accident of convenience.
//!
//! # The iteration-under-modification contract
//!
//! `lib/uint-bset.h:86-96` and `lib/uint-spbset.h:77-87` carry word-for-word
//! identical prose -- verified byte-identical with `diff` over the two
//! ranges, which reports no difference. It is the central guarantee of this
//! API, and the multi handle depends on it while adding and completing
//! transfers inside the loop:
//!
//! > Get the next number in the bitset, following `last` in natural order.
//! > Put another way, this is the smallest number greater than `last` in
//! > the bitset. `last` does not have to be present in the set.
//! >
//! > Returns FALSE when no such number is in the set.
//! >
//! > This allows to iterate the set while being modified:
//! > - added numbers higher than 'last' will be picked up by the iteration.
//! > - added numbers lower than 'last' will not show up.
//! > - removed numbers lower or equal to 'last' will not show up.
//! > - removed numbers higher than 'last' will not be visited.
//!
//! Both `next` methods reproduce those four bullets at their own definition,
//! because they are a contract and not commentary.
//!
//! # Why neither type implements `Iterator`
//!
//! The contract above is the reason. An [`Iterator`] borrows the collection
//! for as long as it lives, so the pattern the multi handle actually needs
//! -- walk the set and remove the member just visited, as at
//! `lib/multi.c:1295-1296`, `:1379-1380`, `:2771-2772`, `:3088`, `:3105`,
//! `:3322-3326` and `:3701` -- would be rejected by the borrow checker.
//! `next` is therefore a **stateless query keyed on `last`**: it holds no
//! cursor, it takes `&self`, and `last` need not be a member. Implementing
//! [`Iterator`] or [`IntoIterator`] here would make correct C code
//! untranslatable, so neither is implemented, deliberately.
//!
//! HOW TO CHECK THAT, because an unanchored search reports a false failure
//! against this file itself: the paragraph above legitimately NAMES both
//! traits, so `grep -n 'impl Iterator\|IntoIterator' <this file>` matches the
//! prose. This is the same situation `util/mod.rs:100-116` records for the
//! `unsafe` keyword, and it is answered the same way -- anchor past the
//! leading whitespace and require the token before any slash on the line, so
//! that a `//`, `///` or `//!` line can never match:
//!
//! ```text
//!   grep -nE '^[[:space:]]*(unsafe )?impl\b' <this file>
//!     -> must print exactly two lines, `impl Uint32Bset {` and
//!        `impl Uint32SpBset {`, both inherent
//!   grep -nE '^[^/]*\b(Into)?Iterator\b' <this file>
//!     -> must print NOTHING
//! ```
//!
//! Measured on this file: the first prints those two lines and nothing else,
//! and the second prints nothing. The compiler is the real authority in any
//! case, since a `for` loop over either type is a compile error without the
//! trait.
//!
//! # The consumer contract, for whoever writes `multi`
//!
//! `struct Curl_multi` holds one `uint32_tbl xfers`
//! (`lib/multihandle.h:90`) and **exactly four** dense sets --
//! `process`, `dirty`, `pending` and `msgsent` (`:92-95`) -- under the
//! invariant stated at `:91`: "Each transfer's mid may be present in at most
//! one of these". That invariant is the *consumer's* to uphold, and this
//! module deliberately does not police it; what this module owes the
//! consumer is the primitives that make it cheap to uphold and cheap to
//! test, which are [`Uint32Bset::contains`], [`Uint32Bset::remove`] and
//! [`Uint32Bset::count`].
//!
//! Two further facts a caller must not rediscover the hard way. The general
//! capacity these sets are resized to is `INITIAL_MAX_CONCURRENT_STREAMS`,
//! `((1U << 31) - 1)` (`lib/multihandle.h:79`). And the transfer identifier
//! `0` is **live**: the multi handle's own administrative easy handle is
//! assigned `mid` 0 on init and added to `process` immediately
//! (`lib/multi.c:279`), so `0` is a meaningful member and never a sentinel
//! or a stand-in for "none".
//!
//! # C machinery with no successor here
//!
//! Recorded rather than silently dropped, so that a reader diffing this file
//! against the two C translation units can account for every construct.
//!
//! - `Curl_uint32_bset_init` and `Curl_uint32_spbset_init` are
//!   `memset(bset, 0, sizeof(*bset))`, which is capacity 0 and an empty set.
//!   That is [`Default`], derived on both types, and [`Uint32Bset::new`] /
//!   [`Uint32SpBset::new`] beside it.
//! - `Curl_uint32_bset_destroy` frees and zeroes; `Curl_uint32_spbset_clear`
//!   walks the chunk list freeing each node. Both are [`Drop`] on the owned
//!   collection, so neither has a counterpart to call.
//! - `CURL_UINT32_BSET_MAGIC 0x62757473` (`lib/uint-bset.c:29`) and
//!   `CURL_UINT32_SPBSET_MAGIC 0x70737362` (`lib/uint-spbset.c:30`) are
//!   `DEBUGBUILD`-only use-after-free sentinels, checked by `DEBUGASSERT` on
//!   entry to each operation. The values are cited so that a search for
//!   either lands here; the type system supersedes both, because a freed
//!   `Uint32Bset` cannot be named.
//! - `Curl_popcount64` (`lib/uint-bset.c:174-192`) and `Curl_ctz64`
//!   (`:194-230`) are software fallbacks, reached only when the platform
//!   supplies no `CURL_POPCOUNT64` / `CURL_CTZ64` intrinsic. They are
//!   replaced by [`u64::count_ones`] and [`u64::trailing_zeros`], which are
//!   portable and single instructions on every target of AAP 0.8.3. The
//!   equivalence that matters most is that `Curl_ctz64` returns 64 for input
//!   zero (`lib/uint-bset.c:206-207`) and so does `trailing_zeros`; both
//!   this and the popcount equivalence are asserted in the tests below
//!   rather than taken on trust. Neither fallback is carried behind a
//!   feature: a second implementation of a settled primitive is a second
//!   thing to keep correct.
//! - `first_slot_used` is a pure lower-bound hint on the first non-empty
//!   slot, and it is dropped. The claim that dropping it changes nothing
//!   observable was checked against each of its five sites:
//!   `add` lowers it (`lib/uint-bset.c:112-113`), `first` refreshes it
//!   (`:138`), `clear` sets it to `UINT32_MAX` (`:102`), `resize` resets it
//!   to 0 (`:58`), and `count` ignores it and always scans from slot 0
//!   (`:81`). Only `empty` (`:91`) and `first` (`:135`) ever *read* it, and
//!   both read it solely as a starting index for a scan that is looking for
//!   the first non-zero slot -- so starting at 0 instead reaches the same
//!   slot, having examined some additional zero slots on the way. It is a
//!   speed hint and nothing else, and nothing outside `lib/uint-bset.c`
//!   names it: a repository-wide search for the identifier finds it only in
//!   that file and its header.
//! - `Curl_uint32_bset_capacity` is compiled only under `UNITTESTS`
//!   (`lib/uint-bset.c:70-75`), so it does not exist in a production
//!   libcurl. [`Uint32Bset::capacity`] is unconditional here: it costs one
//!   multiplication, the capacity it reports is observable through `add`
//!   regardless, and a conditionally-compiled accessor would be a second
//!   build configuration to keep working for no gain.
//! - `Curl_uint32_spbset_clear` is declared `UNITTEST` -- that is,
//!   non-`static` only for unit-test builds (`lib/uint-spbset.c:34`) -- yet
//!   `destroy` calls it (`:47`). It is an ordinary method here.
//! - The `panchor == NULL` branch of `uint32_spbset_get_chunk`
//!   (`lib/uint-spbset.c:108-112`), commented "prepend to head, switching
//!   places", is **unreachable**. It is entered only when the loop breaks at
//!   `:89-93`, which requires `head.offset > i_offset`; but `head.offset` is
//!   written only by the `memset`s in `init` (`:38`) and `clear` (`:72`), so
//!   it is invariantly 0, and `i_offset` is a masked `u32` and so is never
//!   negative. Were it ever reached it would also mis-attribute the old
//!   head's bits, since it copies the old slots into the new chunk and then
//!   overwrites `offset` with the new value (`:109`, `:113`). The finding is
//!   recorded because it is part of why a flat `BTreeSet` loses nothing, and
//!   because it saves the next reader the same twenty minutes.
//!
//! # Reference tests
//!
//! `tests/unit/unit3211.c` (dense, 150 lines) and `tests/unit/unit3213.c`
//! (sparse, 125 lines) cannot link against a Rust static library, because
//! they call internal symbols and `pub(crate)` items are genuinely absent
//! from the symbol table. Per AAP 0.8.7 their coverage relocates into the
//! `#[cfg(test)]` module at the end of this file, using their exact measured
//! vectors, and internals are **not** re-exported to make them link.

use std::collections::BTreeSet;

use crate::error::CURLcode;

/// The width of one slot of [`Uint32Bset`], and the multiple that
/// [`Uint32Bset::resize`] rounds a requested capacity up to.
///
/// `lib/uint-bset.c` spells this as the literal 64 at each of its seven uses.
const BITS_PER_SLOT: u32 = 64;

/// `BITS_PER_SLOT - 1`: the addend that makes integer division round up, and
/// the margin the overflow guard in [`Uint32Bset::slot_count`] leaves.
///
/// Both appear as the literal 63 in `lib/uint-bset.c:42-43`.
const ROUND_TO_SLOT: u32 = BITS_PER_SLOT - 1;

/// The most slots [`Uint32Bset`] will ever hold: `UINT32_MAX / 64`, which is
/// 67,108,863.
///
/// This is the clamp of `lib/uint-bset.c:43`, and it exists so that the
/// rounding-up addition on the line above it cannot overflow.
const MAX_SLOTS: u32 = u32::MAX / BITS_PER_SLOT;

/// The largest capacity [`Uint32Bset`] can report: 4,294,967,232, which is
/// `u32::MAX - 63`.
///
/// The compiler proves this product does not overflow, because an overflowing
/// arithmetic operation in a constant is a hard error rather than a wrap. That
/// is the whole justification for the saturating multiplication in
/// [`Uint32Bset::capacity`] being unreachable.
const MAX_CAPACITY: u32 = MAX_SLOTS * BITS_PER_SLOT;

/// A dense, fixed-capacity bitset over `u32`: `struct uint32_bset`.
///
/// Supersedes `lib/uint-bset.h:40-47`, whose three live fields were
/// `uint64_t *slots`, `uint32_t nslots` and `uint32_t first_slot_used`, plus a
/// `DEBUGBUILD`-only `int init` sentinel. Only the slots survive: the slot
/// count is the vector's length, and the hint and the sentinel have no
/// successor for the reasons given in the module documentation.
///
/// Holds the numbers `0 ..= capacity() - 1`, where the capacity is always a
/// multiple of 64 and is therefore usually larger than the `nmax` handed to
/// [`resize`](Self::resize). A number at or above the capacity cannot be
/// stored, and [`add`](Self::add) reports that by returning `false` rather
/// than by growing.
///
/// Equality is *representational*: two sets are equal when they hold the same
/// members **and** have the same capacity. That is deliberate rather than
/// incidental, because the capacity is observable through
/// [`add`](Self::add) -- two sets that agree on every member but differ in
/// capacity do not behave alike.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct Uint32Bset {
    /// One `u64` per 64 consecutive numbers, least significant bit first.
    ///
    /// `slots.len()` is the C's `nslots`. The vector's own spare capacity is
    /// never consulted -- [`capacity`](Self::capacity) is derived from the
    /// length -- so a shrink that leaves the allocation oversized is
    /// invisible.
    slots: Vec<u64>,
}

impl Uint32Bset {
    /// An empty set with capacity 0.
    ///
    /// `Curl_uint32_bset_init` (`lib/uint-bset.c:32-38`) is
    /// `memset(bset, 0, sizeof(*bset))`, which leaves `slots` null and
    /// `nslots` 0. Capacity 0 is a usable state and not an error: every
    /// [`add`](Self::add) returns `false` until [`resize`](Self::resize) is
    /// called, which is exactly what the C does.
    #[allow(dead_code)]
    pub(crate) const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// The number of 64-bit slots needed to hold `0 ..= nmax - 1`.
    ///
    /// Transcribed from `lib/uint-bset.c:42-43`:
    ///
    /// ```text
    /// uint32_t nslots = (nmax < (UINT32_MAX - 63)) ?
    ///                   ((nmax + 63) / 64) : (UINT32_MAX / 64);
    /// ```
    ///
    /// The guard is an overflow guard, and reproducing it is the point. Any
    /// `nmax` that passes it is at most `u32::MAX - 64`, so the rounding-up
    /// addition reaches at most `u32::MAX - 1` and cannot wrap; the
    /// `saturating_add` therefore returns precisely the C's `nmax + 63` and
    /// its saturation arm is unreachable. Every `nmax` that fails the guard
    /// clamps to [`MAX_SLOTS`], so the largest reachable capacity is
    /// [`MAX_CAPACITY`].
    ///
    /// Kept separate from [`resize`](Self::resize), and pure, so that the
    /// clamp can be tested at the boundary without allocating the half a
    /// gibibyte of slots that boundary implies.
    const fn slot_count(nmax: u32) -> u32 {
        if nmax < u32::MAX - ROUND_TO_SLOT {
            nmax.saturating_add(ROUND_TO_SLOT) / BITS_PER_SLOT
        } else {
            MAX_SLOTS
        }
    }

    /// The slot holding number `i`, as an index.
    ///
    /// The C's `i / 64` (`lib/uint-bset.c:108`). The widening to `usize` is
    /// lossless on every target: the quotient is at most
    /// `u32::MAX / 64`, which fits a 32-bit `usize` let alone the 64-bit
    /// `usize` of all four targets of AAP 0.8.3. The index is *not* range
    /// checked here -- every caller passes it to a slice accessor that
    /// performs the check, which is the same test as the C's
    /// `if(islot >= bset->nslots)` and cannot be forgotten.
    const fn slot_index(i: u32) -> usize {
        (i / BITS_PER_SLOT) as usize
    }

    /// The one-bit mask selecting number `i` within its slot.
    ///
    /// The C's `((uint64_t)1 << (i % 64))` (`lib/uint-bset.c:111`). The
    /// remainder is in `0 ..= 63`, so the shift is always in range for a
    /// `u64` and no wrapping shift is relied upon.
    const fn bit(i: u32) -> u64 {
        1_u64 << (i % BITS_PER_SLOT)
    }

    /// The smallest member held in a non-empty `slot` at index `islot`.
    ///
    /// The C's `(i * 64) + CURL_CTZ64(bset->slots[i])`
    /// (`lib/uint-bset.c:137`, `:165`). Both saturating arms are unreachable:
    /// `islot` indexes a live slot so it is below [`MAX_SLOTS`], and
    /// `trailing_zeros` of a non-zero `u64` is at most 63, so the result is at
    /// most `MAX_CAPACITY - 1`.
    fn member_at(islot: usize, slot: u64) -> u32 {
        debug_assert!(slot != 0, "member_at requires a non-empty slot");
        let base = u32::try_from(islot)
            .unwrap_or(MAX_SLOTS)
            .saturating_mul(BITS_PER_SLOT);
        base.saturating_add(slot.trailing_zeros())
    }

    /// Resizes the set to hold `0 ..= nmax - 1`, rounded up to a multiple of
    /// 64.
    ///
    /// `Curl_uint32_bset_resize` (`lib/uint-bset.c:40-61`). Every branch of
    /// the original is preserved:
    ///
    /// - **A resize to the same slot count is a complete no-op**, contents
    ///   included. The C reaches this through `if(nslots != bset->nslots)`,
    ///   and `tests/unit/unit3211.c:100-108` depends on it: it doubles the
    ///   capacity and comes back, and expects every member to survive the
    ///   round trip.
    /// - **Growing preserves the existing members and zero-fills the rest**,
    ///   which the C gets from `calloc` plus a `memcpy` of the old slots.
    /// - **Shrinking silently drops the members at or above the new
    ///   capacity**, because the C copies only `min(new, old)` slots
    ///   (`:52-53`). This is a documented behaviour, asserted at
    ///   `tests/unit/unit3211.c:110-121`, and not a defect to be smoothed
    ///   over.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`], the C's `CURLE_OUT_OF_MEMORY` (`:49`), when
    /// the slots for a *growing* resize cannot be allocated. The set is
    /// unchanged in that case, exactly as in C, where the early return
    /// happens before any field is written.
    ///
    /// Two properties of the allocation deserve stating, because the obvious
    /// implementation gets both wrong. `Vec::try_reserve` is used rather than
    /// `vec![0; n]` or `Vec::resize` alone: the latter two abort the process
    /// on allocation failure, which would silently discard the error path the
    /// C's callers propagate -- `lib/multi.c:259-262` and `:404-407` test
    /// this result and fail multi-handle creation on it. And the subsequent
    /// `Vec::resize` cannot itself allocate, because `try_reserve` has
    /// already secured capacity for exactly the new length.
    ///
    /// One divergence, stated rather than buried: a *shrinking* resize cannot
    /// fail here, where in C it allocates a smaller block and can therefore
    /// report `CURLE_OUT_OF_MEMORY`. Returning success where the C might
    /// report an allocation failure is not an observable behaviour change --
    /// allocation failure is an environmental condition, no fixture asserts
    /// it, and the C's own callers treat the result as pass or fail rather
    /// than as a description of the set. The old allocation is retained
    /// instead of being handed back, which is invisible because
    /// [`capacity`](Self::capacity) reads the length and never the vector's
    /// spare capacity. `Vec::shrink_to_fit` is deliberately not called: it
    /// can abort on failure, which would turn a graceful C error into a dead
    /// process.
    #[allow(dead_code)]
    pub(crate) fn resize(&mut self, nmax: u32) -> Result<(), CURLcode> {
        let nslots = Self::slot_count(nmax) as usize;
        if nslots == self.slots.len() {
            return Ok(());
        }
        // `checked_sub` yields `None` exactly when this is a shrink, which
        // needs no allocation; `Vec::resize` below then truncates.
        if let Some(additional) = nslots.checked_sub(self.slots.len()) {
            self.slots
                .try_reserve(additional)
                .map_err(|_| CURLcode::OutOfMemory)?;
        }
        self.slots.resize(nslots, 0);
        Ok(())
    }

    /// The capacity: the set holds `0 ..= capacity() - 1`.
    ///
    /// `Curl_uint32_bset_capacity` (`lib/uint-bset.c:70-75`), which is
    /// `nslots * 64` and is compiled only under `UNITTESTS`. Always a
    /// multiple of 64, and so usually larger than the `nmax` passed to
    /// [`resize`](Self::resize).
    ///
    /// Both fallible steps are unreachable and are written defensively rather
    /// than elided: [`resize`](Self::resize) is the only writer of the slot
    /// count and it clamps at [`MAX_SLOTS`], so the conversion is exact and
    /// the product is at most [`MAX_CAPACITY`].
    #[allow(dead_code)]
    pub(crate) fn capacity(&self) -> u32 {
        debug_assert!(
            self.slots.len() <= MAX_SLOTS as usize,
            "resize clamps the slot count at MAX_SLOTS"
        );
        let nslots = u32::try_from(self.slots.len()).unwrap_or(MAX_SLOTS);
        let capacity = nslots.saturating_mul(BITS_PER_SLOT);
        debug_assert!(capacity <= MAX_CAPACITY);
        capacity
    }

    /// The cardinality: how many numbers the set holds.
    ///
    /// `Curl_uint32_bset_count` (`lib/uint-bset.c:77-86`). Note that the C
    /// scans **all** slots from index 0 and deliberately does not start at
    /// `first_slot_used`, so no hint is needed to reproduce it.
    ///
    /// The sum cannot overflow: at most [`MAX_SLOTS`] slots contribute at most
    /// 64 each, and that product is [`MAX_CAPACITY`], which is below
    /// `u32::MAX`. The C accumulates into a `uint32_t` on the same reasoning.
    #[allow(dead_code)]
    pub(crate) fn count(&self) -> u32 {
        self.slots.iter().map(|slot| slot.count_ones()).sum()
    }

    /// Whether the set holds no numbers.
    ///
    /// `Curl_uint32_bset_empty` (`lib/uint-bset.c:88-96`), which returns
    /// `FALSE` at the first non-zero slot. A zero-capacity set is empty,
    /// which falls out of an empty vector having no non-zero slot.
    ///
    /// Named `is_empty` rather than the C's `empty` to match Rust convention
    /// and to keep clippy's naming lints satisfied under the `-D warnings`
    /// gate of AAP 0.8.4; [`count`](Self::count) is the cardinality
    /// accessor beside it.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.slots.iter().all(|slot| *slot == 0)
    }

    /// Removes every number, keeping the capacity.
    ///
    /// `Curl_uint32_bset_clear` (`lib/uint-bset.c:98-104`). The C guards the
    /// `memset` with `if(bset->nslots)` and, on a zero-capacity set, leaves
    /// `first_slot_used` untouched rather than setting it to `UINT32_MAX`;
    /// with the hint dropped, the guard has nothing left to protect, and
    /// filling an empty slice is already a no-op.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        self.slots.fill(0);
    }

    /// Adds `i`, reporting whether it is **within the capacity**.
    ///
    /// `Curl_uint32_bset_add` (`lib/uint-bset.c:106-115`).
    ///
    /// The return value is the single most easily mistaken thing in this
    /// module. It means "`i` was in range", **not** "`i` was newly
    /// inserted". `lib/uint-bset.h:73` is explicit: "Numbers can be added
    /// more than once, without making a difference", so adding the same
    /// number twice returns `true` both times. The set-like reading is not
    /// merely different, it is inverted: `HashSet::insert` and
    /// `BTreeSet::insert` return "was absent", so returning theirs would
    /// report a successful re-add as a failure and silently flip a branch in
    /// the consumers -- `lib/multi_ev.c:143-149` returns this boolean
    /// straight out as a success flag.
    ///
    /// A number at or above [`capacity`](Self::capacity) is rejected rather
    /// than accommodated; the set never grows implicitly.
    #[allow(dead_code)]
    pub(crate) fn add(&mut self, i: u32) -> bool {
        if let Some(slot) = self.slots.get_mut(Self::slot_index(i)) {
            *slot |= Self::bit(i);
            true
        } else {
            false
        }
    }

    /// Removes `i`, if it is present.
    ///
    /// `Curl_uint32_bset_remove` (`lib/uint-bset.c:117-122`). Returns
    /// nothing, and a number outside the capacity is a **silent no-op**
    /// rather than an error -- the C's `if(islot < bset->nslots)` simply
    /// declines to act, and `lib/multi.c:871-874` relies on that by removing
    /// a `mid` from all four sets without first asking which one holds it.
    ///
    /// One curiosity of the original, noted so a reader does not attach
    /// meaning to it: this is the single place that declares the slot index
    /// as `size_t` where every sibling function uses `uint32_t`
    /// (`lib/uint-bset.c:119`). The behaviour is identical either way.
    #[allow(dead_code)]
    pub(crate) fn remove(&mut self, i: u32) {
        if let Some(slot) = self.slots.get_mut(Self::slot_index(i)) {
            *slot &= !Self::bit(i);
        }
    }

    /// Whether the set holds `i`.
    ///
    /// `Curl_uint32_bset_contains` (`lib/uint-bset.c:124-130`). A number
    /// outside the capacity is absent rather than an error.
    #[allow(dead_code)]
    pub(crate) fn contains(&self, i: u32) -> bool {
        self.slots
            .get(Self::slot_index(i))
            .is_some_and(|slot| (slot & Self::bit(i)) != 0)
    }

    /// The smallest number in the set, or [`None`] when it is empty.
    ///
    /// `Curl_uint32_bset_first` (`lib/uint-bset.c:132-144`).
    ///
    /// Takes `&mut self` because the C does: `first` is the one operation
    /// that *refreshes* `first_slot_used` (`:138`), and the receiver keeps
    /// the mutability of the C's call sites so that a reader diffing
    /// `lib/multi.c` against its successor sees the same shape. The hint
    /// itself is dropped, so nothing is written here.
    ///
    /// On failure the C additionally writes `UINT32_MAX` through the
    /// out-parameter and into the hint (`:142`). That write is unobservable
    /// and is recorded only because the C's callers *could* read it: none
    /// does. Every one of them is the loop
    /// `if(first(&s, &mid)) { do { ... } while(next(&s, mid, &mid)); }` --
    /// `lib/multi.c:1234`, `:1290`, `:1374`, `:2763`, `:3080`, `:3315`,
    /// `:3693` and `lib/multi_ev.c:539` -- in which the variable is dead once
    /// the loop ends.
    #[allow(dead_code)]
    pub(crate) fn first(&mut self) -> Option<u32> {
        // The C's `for(i = first_slot_used; i < nslots; ++i)` with the hint
        // replaced by 0. Written as a loop rather than as iterator
        // combinators to keep the correspondence with the original legible.
        for (islot, slot) in self.slots.iter().enumerate() {
            if *slot != 0 {
                return Some(Self::member_at(islot, *slot));
            }
        }
        None
    }

    /// The smallest number in the set strictly greater than `last`.
    ///
    /// `Curl_uint32_bset_next` (`lib/uint-bset.c:146-172`). The contract,
    /// reproduced from `lib/uint-bset.h:86-96`, which is word-for-word
    /// identical to `lib/uint-spbset.h:77-87`:
    ///
    /// > Get the next number in the bitset, following `last` in natural
    /// > order. Put another way, this is the smallest number greater than
    /// > `last` in the bitset. `last` does not have to be present in the set.
    /// >
    /// > Returns FALSE when no such number is in the set.
    /// >
    /// > This allows to iterate the set while being modified:
    /// > - added numbers higher than 'last' will be picked up by the
    /// >   iteration.
    /// > - added numbers lower than 'last' will not show up.
    /// > - removed numbers lower or equal to 'last' will not show up.
    /// > - removed numbers higher than 'last' will not be visited.
    ///
    /// All four bullets follow from "the smallest member strictly greater
    /// than `last`" being computed fresh on every call, against the set as it
    /// stands at that moment. That is also why this takes `&self` and holds
    /// no cursor, and why neither [`Iterator`] nor [`IntoIterator`] is
    /// implemented for this type: a borrowing iterator would forbid the
    /// modification the contract promises.
    ///
    /// # One deliberate divergence
    ///
    /// The C opens with `++last` on a `uint32_t` (`:152`), which wraps to 0
    /// when `last` is `UINT32_MAX` and restarts the scan from the bottom of
    /// the set. Here the increment is checked and [`None`] is returned
    /// instead. No reachable call site can tell the difference: `u32::MAX` is
    /// not a storable member, since [`MAX_CAPACITY`] is `u32::MAX - 63` and
    /// the largest member is one below the capacity -- and the C itself calls
    /// `UINT32_MAX` "a value we cannot store" where it writes it as the
    /// failure sentinel (`:170`). Wrapping would restart a finished
    /// iteration, so declining is both the safer and the more faithful
    /// reading.
    #[allow(dead_code)]
    pub(crate) fn next(&self, last: u32) -> Option<u32> {
        // "look for number one higher than last" (`lib/uint-bset.c:152`).
        let from = last.checked_add(1)?;
        let islot = Self::slot_index(from);
        // The C's `if(islot < bset->nslots)`, whose else-branch is the
        // failure return: a slot past the end yields `None` here.
        let slot = *self.slots.get(islot)?;
        // "shift away the bits we already iterated in this slot" (`:155`).
        let shifted = slot >> (from % BITS_PER_SLOT);
        if shifted != 0 {
            return Some(from.saturating_add(shifted.trailing_zeros()));
        }
        // "no more bits set in the last slot, scan forward" (`:162`). The
        // increment cannot overflow: `islot` indexed a live slot above, so it
        // is below the vector's length.
        let after = islot.saturating_add(1);
        for (index, slot) in self.slots.iter().enumerate().skip(after) {
            if *slot != 0 {
                return Some(Self::member_at(index, *slot));
            }
        }
        None
    }
}

/// A sparse, unbounded bitset over `u32`: `struct uint32_spbset`.
///
/// Supersedes `lib/uint-spbset.h:42-53`. `lib/uint-spbset.h:28-33` is the
/// whole specification: "A 'sparse' bitset for uint32_t values. It can hold
/// any uint32_t value. Optimized for the case where only a small set of
/// numbers need to be kept, especially when 'close' together."
///
/// # Why this is a `BTreeSet` and not a chunk list
///
/// The C keeps a singly-linked list of chunks, each covering an aligned block
/// of 256 numbers -- `CURL_UINT32_SPBSET_CH_SLOTS 4` slots of 64 bits, with
/// `CURL_UINT32_SPBSET_CH_MASK 255` masking a number down to its block, and
/// the note "keep this a 2^n value" (`lib/uint-spbset.h:36-38`). The first
/// chunk is stored inline in the set rather than heap-allocated (`:49`), so a
/// small set needs no allocation at all.
///
/// Every one of those choices serves memory efficiency, which the header says
/// outright, and none of them is visible through the operations: the set's
/// behaviour is "holds any `u32`, supports add, remove, contains, count,
/// clear, first and next-greater-than", and a [`BTreeSet<u32>`] satisfies all
/// of it. Memory efficiency is a performance property and performance is an
/// explicit non-goal of this migration (AAP 0.1.1), which resolves the
/// question in favour of the representation a reader can check by eye.
///
/// The iteration contract of [`next`](Self::next) is the deciding practical
/// argument: over a `BTreeSet` it is one `range` query with no cursor and no
/// borrow, which is exactly the shape that contract demands. Reproducing the
/// chunk list would also have to be `unsafe`-free, which rules out the
/// intrusive `next` pointer the C uses and so would not resemble the original
/// anyway.
///
/// This is the opposite conclusion to [`Uint32Bset`], and the difference is
/// not a matter of taste: there, the capacity is observable and forced a real
/// bit representation; here, nothing observable depends on the layout.
///
/// Unlike [`Uint32Bset`] this type has no capacity and no `resize`: it holds
/// any `u32`, so there is nothing to configure and nothing to truncate.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct Uint32SpBset {
    /// The members, ordered, which is what makes
    /// [`first`](Self::first) and [`next`](Self::next) direct queries.
    members: BTreeSet<u32>,
}

impl Uint32SpBset {
    /// An empty set.
    ///
    /// `Curl_uint32_spbset_init` (`lib/uint-spbset.c:36-42`) is
    /// `memset(bset, 0, sizeof(*bset))`, which zeroes the inline head chunk
    /// and leaves its `next` pointer null.
    #[allow(dead_code)]
    pub(crate) const fn new() -> Self {
        Self {
            members: BTreeSet::new(),
        }
    }

    /// The cardinality: how many numbers the set holds.
    ///
    /// `Curl_uint32_spbset_count` (`lib/uint-spbset.c:50-62`), which walks
    /// every chunk summing the population of its four slots.
    ///
    /// The saturation is unreachable in any real program: it would take
    /// 4,294,967,296 distinct members -- every `u32` -- to exceed a `u32`
    /// count, which is around 16 gibibytes of keys before any container
    /// overhead. The C would wrap its `uint32_t` accumulator to 0 in that
    /// case; saturating is the more defensible answer, and the difference is
    /// unobservable.
    #[allow(dead_code)]
    pub(crate) fn count(&self) -> u32 {
        u32::try_from(self.members.len()).unwrap_or(u32::MAX)
    }

    /// Whether the set holds no numbers.
    ///
    /// The C has no such function for the sparse set -- `count() == 0` is how
    /// its callers ask -- but it is provided here for symmetry with
    /// [`Uint32Bset::is_empty`] and because it answers the question without
    /// counting.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Removes every number.
    ///
    /// `Curl_uint32_spbset_clear` (`lib/uint-spbset.c:64-73`), which frees
    /// every chunk after the inline head and then zeroes the head. It is
    /// declared `UNITTEST` in C -- non-`static` only for unit-test builds
    /// (`:34`) -- yet `Curl_uint32_spbset_destroy` calls it (`:47`), so it is
    /// an ordinary method here.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        self.members.clear();
    }

    /// Adds `i`, reporting whether the insertion **succeeded**.
    ///
    /// `Curl_uint32_spbset_add` (`lib/uint-spbset.c:117-131`).
    ///
    /// The return value means "the storage for `i` was available", **not**
    /// "`i` was newly inserted". `lib/uint-spbset.h:62-64` states both halves:
    /// "Numbers can be added more than once, without making a difference.
    /// Returns FALSE if allocations failed." The C's only `false` is the
    /// `curlx_calloc` failure of a new chunk (`:123-124`).
    ///
    /// A `BTreeSet` insertion cannot report failure, so this always returns
    /// `true`. `BTreeSet::insert`'s own boolean is deliberately **not**
    /// forwarded: it means "was absent", which is the inverse of what a caller
    /// branching on failure expects, and the one consumer that reads this
    /// value -- `mev_sh_entry_xfer_add` at `lib/multi_ev.c:143-149`, which
    /// returns it straight out as a success flag -- would then treat a
    /// re-registered transfer as a failure.
    #[allow(dead_code)]
    pub(crate) fn add(&mut self, i: u32) -> bool {
        self.members.insert(i);
        true
    }

    /// Removes `i`, if it is present.
    ///
    /// `Curl_uint32_spbset_remove` (`lib/uint-spbset.c:133-145`). Returns
    /// nothing, and removing an absent number is a silent no-op: the C looks
    /// up the chunk without growing and does nothing when there is none.
    #[allow(dead_code)]
    pub(crate) fn remove(&mut self, i: u32) {
        self.members.remove(&i);
    }

    /// Whether the set holds `i`.
    ///
    /// `Curl_uint32_spbset_contains` (`lib/uint-spbset.c:147-161`).
    #[allow(dead_code)]
    pub(crate) fn contains(&self, i: u32) -> bool {
        self.members.contains(&i)
    }

    /// The smallest number in the set, or [`None`] when it is empty.
    ///
    /// `Curl_uint32_spbset_first` (`lib/uint-spbset.c:163-178`).
    ///
    /// Takes `&self`, unlike [`Uint32Bset::first`], and the asymmetry is
    /// inherited rather than invented: the dense set's `first` refreshes its
    /// `first_slot_used` hint, while the sparse set has no hint and its C
    /// original mutates nothing.
    ///
    /// The C's three failure sentinels are worth recording, because they
    /// disagree with each other and a reader of the C should not spend time
    /// reconciling them. This function writes `*pfirst = 0` with the comment
    /// "give it a defined value even if it should not be used" (`:176`); the
    /// internal `uint32_spbset_chunk_first` writes `UINT32_MAX` (`:190`); and
    /// `Curl_uint32_spbset_next` writes `UINT32_MAX` (`:249`). Returning
    /// [`None`] makes all three moot, and note that `0` as a sentinel would
    /// have been actively misleading, since `0` is a live member -- the multi
    /// handle's administrative transfer holds `mid` 0.
    #[allow(dead_code)]
    pub(crate) fn first(&self) -> Option<u32> {
        self.members.iter().next().copied()
    }

    /// The smallest number in the set strictly greater than `last`.
    ///
    /// `Curl_uint32_spbset_next` (`lib/uint-spbset.c:221-251`). The contract,
    /// reproduced from `lib/uint-spbset.h:77-87`, which is word-for-word
    /// identical to `lib/uint-bset.h:86-96`:
    ///
    /// > Get the next number in the bitset, following `last` in natural
    /// > order. Put another way, this is the smallest number greater than
    /// > `last` in the bitset. `last` does not have to be present in the set.
    /// >
    /// > Returns FALSE when no such number is in the set.
    /// >
    /// > This allows to iterate the set while being modified:
    /// > - added numbers higher than 'last' will be picked up by the
    /// >   iteration.
    /// > - added numbers lower than 'last' will not show up.
    /// > - removed numbers lower or equal to 'last' will not show up.
    /// > - removed numbers higher than 'last' will not be visited.
    ///
    /// The C reaches this by finding the chunk containing `last + 1`, shifting
    /// the already-iterated bits out of that chunk's slot, and then taking the
    /// first member of each following chunk in turn. Over an ordered set the
    /// same answer is one half-open range query, and the four bullets follow
    /// from it being evaluated fresh against the set as it stands at the
    /// moment of the call. That is why this takes `&self` and holds no cursor,
    /// and why neither [`Iterator`] nor [`IntoIterator`] is implemented for
    /// this type.
    ///
    /// The same deliberate divergence as [`Uint32Bset::next`] applies to the
    /// C's opening `++last` (`:227`): the increment is checked here, so
    /// `next(u32::MAX)` is [`None`] rather than a wrap to 0 that would restart
    /// a finished iteration. Unlike the dense set, `u32::MAX` *is* a storable
    /// member here -- but it can never have a successor, which is precisely
    /// what [`None`] says.
    #[allow(dead_code)]
    pub(crate) fn next(&self, last: u32) -> Option<u32> {
        // "look for the next higher number" (`lib/uint-spbset.c:227`).
        let from = last.checked_add(1)?;
        self.members.range(from..).next().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `s1` of both reference tests: "spread numbers, some at slot edges"
    /// (`tests/unit/unit3211.c:130-133`, `tests/unit/unit3213.c:99-102`).
    ///
    /// 0 and 1 sit at the bottom of slot 0, 63 is its top bit, and 64, 65, 66
    /// are the bottom of slot 1 -- so the vector crosses a slot boundary in
    /// both directions, which is what makes it worth using verbatim.
    const S1: [u32; 10] = [0, 1, 4, 17, 63, 64, 65, 66, 90, 99];

    /// `s2` of both reference tests: "set with all bits in slot1 set"
    /// (`tests/unit/unit3211.c:134-144`, `tests/unit/unit3213.c:103-113`).
    ///
    /// Transcribed in the original's eight-per-line layout rather than built
    /// from a range, so that it can be compared against the C by eye.
    /// [`s2_is_exactly_the_second_slot`] proves the transcription is
    /// `64 ..= 127`.
    const S2: [u32; 64] = [
        64, 65, 66, 67, 68, 69, 70, 71, //
        72, 73, 74, 75, 76, 77, 78, 79, //
        80, 81, 82, 83, 84, 85, 86, 87, //
        88, 89, 90, 91, 92, 93, 94, 95, //
        96, 97, 98, 99, 100, 101, 102, 103, //
        104, 105, 106, 107, 108, 109, 110, 111, //
        112, 113, 114, 115, 116, 117, 118, 119, //
        120, 121, 122, 123, 124, 125, 126, 127,
    ];

    /// `s3` of the sparse reference test: "very spread numbers"
    /// (`tests/unit/unit3213.c:114-118`).
    ///
    /// Sparse only. Its span, 2,232 to 30,318, would need 474 slots of a dense
    /// set to hold 16 members, which is the case the C's chunk list exists
    /// for.
    const S3: [u32; 16] = [
        2232, 5167, 8204, 8526, 8641, 10056, 10140, 10611, 10998, 11626, 13735,
        15539, 17947, 24295, 27833, 30318,
    ];

    /// The length of a reference vector as the `u32` that `count` returns.
    fn cardinality(s: &[u32]) -> u32 {
        u32::try_from(s.len()).expect("a reference vector is short")
    }

    /// `check_set` of `tests/unit/unit3211.c:30-124`, step for step and in the
    /// original order.
    ///
    /// Every `fail_unless` of the original becomes one assertion here, with the
    /// original's message carried over so a failure is greppable against the C.
    fn dense_check_set(name: &str, capacity: u32, s: &[u32]) {
        let mut bset = Uint32Bset::new();
        bset.resize(capacity).expect("bset resize failed");
        // The original asserts `c == (((capacity + 63) / 64) * 64)`
        // (`tests/unit/unit3211.c:42`). Written with `div_ceil`, which is the
        // same value: clippy's `manual_div_ceil` rejects the C's spelling
        // under the `-D warnings` gate, and suppressing a correct lint to
        // keep a transcription would be the wrong trade when the expression
        // it asks for is clearer. `u32::div_ceil` is stable as of Rust 1.73,
        // inside the declared MSRV of 1.75.
        assert_eq!(
            bset.capacity(),
            capacity.div_ceil(64) * 64,
            "{name}: wrong capacity"
        );

        bset.clear();
        assert_eq!(bset.count(), 0, "{name}: set count is not 0");

        // Add all, checking after each that the numbers not yet added are
        // still absent -- which also proves no add sets a neighbouring bit.
        for (index, member) in s.iter().enumerate() {
            assert!(bset.add(*member), "{name}: failed to add {member}");
            for later in &s[index + 1..] {
                assert!(
                    !bset.contains(*later),
                    "{name}: unexpectedly found {later}"
                );
            }
        }

        for member in s {
            assert!(
                bset.contains(*member),
                "{name}: failed presence check for {member}"
            );
        }

        // Iterate over all numbers, in ascending order.
        let mut n = bset.first().expect("first failed");
        assert_eq!(n, s[0], "{name}: first not correct number");
        for expected in &s[1..] {
            n = bset.next(n).expect("next failed");
            assert_eq!(n, *expected, "{name}: next not correct number");
        }

        // Adding the capacity number does not work (0 - capacity-1).
        let c = bset.capacity();
        assert!(!bset.add(c), "{name}: add out of range worked");
        assert_eq!(bset.count(), cardinality(s), "{name}: set count is wrong");

        for member in s.iter().step_by(2) {
            bset.remove(*member);
            assert!(
                !bset.contains(*member),
                "{name}: unexpectedly found {member}"
            );
        }
        for member in s.iter().skip(1).step_by(2) {
            assert!(
                bset.contains(*member),
                "{name}: unexpectedly gone {member}"
            );
        }
        assert_eq!(
            bset.count(),
            cardinality(s) / 2,
            "{name}: set count is wrong"
        );

        bset.clear();
        assert_eq!(bset.count(), 0, "{name}: set count is not 0");
        for member in s {
            assert!(
                !bset.contains(*member),
                "{name}: unexpectedly there {member}"
            );
        }

        for member in s {
            assert!(bset.add(*member), "{name}: failed to add {member}");
        }

        bset.resize(capacity * 2).expect("resize double failed");
        for member in s {
            assert!(
                bset.contains(*member),
                "{name}: unexpectedly lost {member} after doubling"
            );
        }

        bset.resize(capacity).expect("resize back failed");
        for member in s {
            assert!(
                bset.contains(*member),
                "{name}: unexpectedly lost {member} after resizing back"
            );
        }

        bset.resize(capacity / 2).expect("resize half failed");
        // Halved the size: exactly the members below the new capacity remain.
        // The reference vectors are ascending, which is why the original can
        // then check the first `n` entries.
        let c = bset.capacity();
        let n = s.iter().filter(|member| **member < c).count();
        assert_eq!(
            bset.count(),
            u32::try_from(n).expect("a reference vector is short"),
            "{name}: set count(halved) wrong"
        );
        for member in &s[..n] {
            assert!(
                bset.contains(*member),
                "{name}: unexpectedly lost {member} after halving"
            );
        }
    }

    /// `check_spbset` of `tests/unit/unit3213.c:31-93`, step for step. The
    /// sparse set has no capacity, so the original has no resize steps.
    fn sparse_check_set(name: &str, s: &[u32]) {
        let mut bset = Uint32SpBset::new();

        bset.clear();
        assert_eq!(bset.count(), 0, "{name}: set count is not 0");

        for (index, member) in s.iter().enumerate() {
            assert!(bset.add(*member), "{name}: failed to add {member}");
            for later in &s[index + 1..] {
                assert!(
                    !bset.contains(*later),
                    "{name}: unexpectedly found {later}"
                );
            }
        }

        for member in s {
            assert!(
                bset.contains(*member),
                "{name}: failed presence check for {member}"
            );
        }

        let mut n = bset.first().expect("first failed");
        assert_eq!(n, s[0], "{name}: first not correct number");
        for expected in &s[1..] {
            n = bset.next(n).expect("next failed");
            assert_eq!(n, *expected, "{name}: next not correct number");
        }

        for member in s.iter().step_by(2) {
            bset.remove(*member);
            assert!(
                !bset.contains(*member),
                "{name}: unexpectedly found {member}"
            );
        }
        for member in s.iter().skip(1).step_by(2) {
            assert!(
                bset.contains(*member),
                "{name}: unexpectedly gone {member}"
            );
        }
        assert_eq!(
            bset.count(),
            cardinality(s) / 2,
            "{name}: set count is wrong"
        );

        bset.clear();
        assert_eq!(bset.count(), 0, "{name}: set count is not 0");
        for member in s {
            assert!(
                !bset.contains(*member),
                "{name}: unexpectedly there {member}"
            );
        }

        for member in s {
            assert!(bset.add(*member), "{name}: failed to add {member}");
        }
    }

    #[test]
    fn s2_is_exactly_the_second_slot() {
        let range: Vec<u32> = (64..=127).collect();
        assert_eq!(S2.as_slice(), range.as_slice());
    }

    #[test]
    fn dense_unit3211_s1() {
        dense_check_set("s1", 100, &S1);
    }

    #[test]
    fn dense_unit3211_s2() {
        dense_check_set("s2", 1000, &S2);
    }

    #[test]
    fn sparse_unit3213_s1() {
        sparse_check_set("s1", &S1);
    }

    #[test]
    fn sparse_unit3213_s2() {
        sparse_check_set("s2", &S2);
    }

    #[test]
    fn sparse_unit3213_s3() {
        sparse_check_set("s3", &S3);
    }

    #[test]
    fn a_new_dense_set_has_capacity_zero() {
        // `Curl_uint32_bset_init` is a `memset`, so this is the C's state
        // immediately after init, and it is a usable state.
        let mut bset = Uint32Bset::new();
        assert_eq!(bset.capacity(), 0);
        assert_eq!(bset.count(), 0);
        assert!(bset.is_empty());
        assert_eq!(bset.first(), None);
        assert_eq!(bset.next(0), None);
        assert_eq!(bset, Uint32Bset::default());
    }

    #[test]
    fn a_zero_capacity_dense_set_rejects_every_add() {
        let mut bset = Uint32Bset::new();
        for i in [0, 1, 63, 64, 1000, u32::MAX] {
            assert!(!bset.add(i), "add({i}) must fail at capacity 0");
        }
        assert_eq!(bset.count(), 0);
        assert!(bset.is_empty());
        // And an explicit resize to 0 is the same state, not an error.
        bset.resize(0).expect("resize to 0 succeeds");
        assert_eq!(bset.capacity(), 0);
        assert!(!bset.add(0));
    }

    #[test]
    fn capacity_rounds_the_request_up_to_a_multiple_of_64() {
        // The C's `((nmax + 63) / 64) * 64`, at and around every interesting
        // boundary.
        for (nmax, expected) in [
            (0_u32, 0_u32),
            (1, 64),
            (2, 64),
            (63, 64),
            (64, 64),
            (65, 128),
            (100, 128),
            (128, 128),
            (129, 192),
            (1000, 1024),
        ] {
            let mut bset = Uint32Bset::new();
            bset.resize(nmax).expect("resize succeeds");
            assert_eq!(
                bset.capacity(),
                expected,
                "resize({nmax}) must give capacity {expected}"
            );
        }
    }

    #[test]
    fn the_number_at_the_capacity_is_out_of_range() {
        // `tests/unit/unit3211.c:72-73` in isolation: the highest storable
        // number is one below the capacity, and the capacity itself is not
        // storable.
        let mut bset = Uint32Bset::new();
        bset.resize(1).expect("resize succeeds");
        assert_eq!(bset.capacity(), 64);
        assert!(bset.add(63), "63 is the last number of a 64-bit capacity");
        assert!(!bset.add(64), "64 is the capacity and is out of range");
        assert!(!bset.contains(64));
        assert_eq!(bset.count(), 1);
    }

    #[test]
    fn the_slot_count_formula_clamps_instead_of_overflowing() {
        // The C's guard, `(nmax < (UINT32_MAX - 63))`, exercised at its
        // boundary through the pure helper so that no half-gibibyte
        // allocation is needed to cover the arithmetic.
        assert_eq!(MAX_SLOTS, 67_108_863);
        assert_eq!(MAX_CAPACITY, 4_294_967_232);
        assert_eq!(MAX_CAPACITY, u32::MAX - 63);

        assert_eq!(Uint32Bset::slot_count(u32::MAX), MAX_SLOTS);
        assert_eq!(Uint32Bset::slot_count(u32::MAX - 63), MAX_SLOTS);
        // One below the guard takes the rounding-up arm, where `nmax + 63`
        // reaches `u32::MAX - 1` and must not wrap. It lands on the same slot
        // count, which is why the clamp is seamless rather than a step.
        assert_eq!(Uint32Bset::slot_count(u32::MAX - 64), MAX_SLOTS);

        assert_eq!(Uint32Bset::slot_count(0), 0);
        assert_eq!(Uint32Bset::slot_count(1), 1);
        assert_eq!(Uint32Bset::slot_count(64), 1);
        assert_eq!(Uint32Bset::slot_count(65), 2);
        assert_eq!(Uint32Bset::slot_count(1000), 16);
    }

    #[test]
    #[ignore = "allocates half a gibibyte of slots; run with --ignored"]
    fn resizing_to_the_clamp_reports_the_clamped_capacity() {
        // The allocating counterpart of the test above: proves that the
        // clamped resize really happens, that `capacity` reports
        // `u32::MAX - 63` without overflowing, and that the last storable
        // number is one below it.
        let mut bset = Uint32Bset::new();
        bset.resize(u32::MAX).expect("the clamped resize succeeds");
        assert_eq!(bset.capacity(), MAX_CAPACITY);
        assert!(bset.add(MAX_CAPACITY - 1));
        assert!(!bset.add(MAX_CAPACITY));
        assert_eq!(bset.count(), 1);
        assert_eq!(bset.first(), Some(MAX_CAPACITY - 1));
        assert_eq!(bset.next(MAX_CAPACITY - 1), None);
    }

    #[test]
    fn a_resize_to_the_same_slot_count_is_a_complete_no_op() {
        // The C's `if(nslots != bset->nslots)`. Every `nmax` in 65..=128 maps
        // to two slots, so none of these resizes may disturb the contents --
        // which is what `tests/unit/unit3211.c:100-108` depends on.
        let mut bset = Uint32Bset::new();
        bset.resize(100).expect("resize succeeds");
        assert!(bset.add(0));
        assert!(bset.add(127));
        for nmax in [65, 100, 127, 128] {
            bset.resize(nmax).expect("resize succeeds");
            assert_eq!(bset.capacity(), 128, "resize({nmax}) changes capacity");
            assert!(bset.contains(0), "resize({nmax}) lost 0");
            assert!(bset.contains(127), "resize({nmax}) lost 127");
            assert_eq!(bset.count(), 2);
        }
    }

    #[test]
    fn growing_keeps_the_members_and_zero_fills_the_new_slots() {
        let mut bset = Uint32Bset::new();
        bset.resize(64).expect("resize succeeds");
        assert!(bset.add(0));
        assert!(bset.add(63));

        bset.resize(1000).expect("growing resize succeeds");
        assert_eq!(bset.capacity(), 1024);
        assert!(bset.contains(0));
        assert!(bset.contains(63));
        // Nothing else appeared: the new slots are zero, not uninitialised.
        assert_eq!(bset.count(), 2);
        assert_eq!(bset.first(), Some(0));
        assert_eq!(bset.next(0), Some(63));
        assert_eq!(bset.next(63), None);
        // The newly reachable range is usable.
        assert!(bset.add(1023));
        assert!(!bset.add(1024));
    }

    #[test]
    fn shrinking_silently_drops_the_members_above_the_new_capacity() {
        // The C copies only `min(new, old)` slots, so this is a documented
        // behaviour and not a defect: `tests/unit/unit3211.c:110-121` asserts
        // it.
        let mut bset = Uint32Bset::new();
        bset.resize(128).expect("resize succeeds");
        assert!(bset.add(5));
        assert!(bset.add(63));
        assert!(bset.add(64));
        assert!(bset.add(100));
        assert_eq!(bset.count(), 4);

        bset.resize(64).expect("shrinking resize succeeds");
        assert_eq!(bset.capacity(), 64);
        assert!(bset.contains(5), "5 is below the new capacity");
        assert!(bset.contains(63), "63 is below the new capacity");
        assert!(!bset.contains(64), "64 was truncated away");
        assert!(!bset.contains(100), "100 was truncated away");
        assert_eq!(bset.count(), 2);
        assert_eq!(bset.first(), Some(5));
        assert_eq!(bset.next(5), Some(63));
        assert_eq!(bset.next(63), None);

        // Growing back does not resurrect them: the bits are gone, and the
        // refilled slots are zero.
        bset.resize(128).expect("regrowing resize succeeds");
        assert_eq!(bset.capacity(), 128);
        assert!(!bset.contains(64));
        assert!(!bset.contains(100));
        assert_eq!(bset.count(), 2);
    }

    #[test]
    fn shrinking_to_zero_capacity_empties_the_set() {
        let mut bset = Uint32Bset::new();
        bset.resize(128).expect("resize succeeds");
        assert!(bset.add(7));
        bset.resize(0).expect("resize to 0 succeeds");
        assert_eq!(bset.capacity(), 0);
        assert_eq!(bset.count(), 0);
        assert!(bset.is_empty());
        assert!(!bset.contains(7));
        assert_eq!(bset.first(), None);
    }

    #[test]
    fn adding_the_same_number_twice_reports_in_range_both_times() {
        // `lib/uint-bset.h:73`: "Numbers can be added more than once, without
        // making a difference." The return value is emphatically not
        // `BTreeSet::insert`'s "was absent".
        let mut dense = Uint32Bset::new();
        dense.resize(64).expect("resize succeeds");
        assert!(dense.add(9), "first add of 9");
        assert!(dense.add(9), "second add of 9 is still in range");
        assert!(dense.add(9), "third add of 9 is still in range");
        assert_eq!(dense.count(), 1);

        let mut sparse = Uint32SpBset::new();
        assert!(sparse.add(9), "first add of 9");
        assert!(sparse.add(9), "second add of 9 still succeeds");
        assert!(sparse.add(9), "third add of 9 still succeeds");
        assert_eq!(sparse.count(), 1);
    }

    #[test]
    fn removing_an_absent_or_out_of_range_number_is_a_silent_no_op() {
        // `lib/multi.c:871-874` removes a `mid` from all four sets without
        // asking which one holds it, so this must not panic and must not
        // disturb the set.
        let mut dense = Uint32Bset::new();
        dense.resize(64).expect("resize succeeds");
        assert!(dense.add(1));
        for i in [0, 2, 63, 64, 65, 1000, u32::MAX] {
            dense.remove(i);
        }
        assert!(dense.contains(1), "the present member survived");
        assert_eq!(dense.count(), 1);
        // Also on a zero-capacity set, where there is no slot at all.
        let mut empty = Uint32Bset::new();
        empty.remove(0);
        empty.remove(u32::MAX);
        assert_eq!(empty.count(), 0);

        let mut sparse = Uint32SpBset::new();
        assert!(sparse.add(1));
        for i in [0, 2, 63, 64, 65, 1000, u32::MAX] {
            sparse.remove(i);
        }
        assert!(sparse.contains(1));
        assert_eq!(sparse.count(), 1);
    }

    #[test]
    fn next_does_not_require_last_to_be_a_member() {
        // `lib/uint-bset.h:88`: "`last` does not have to be present in the
        // set."
        let mut dense = Uint32Bset::new();
        dense.resize(64).expect("resize succeeds");
        for i in [0, 5, 9] {
            assert!(dense.add(i));
        }
        assert_eq!(dense.next(2), Some(5), "2 is not a member");
        assert_eq!(dense.next(4), Some(5));
        assert_eq!(dense.next(5), Some(9));
        assert_eq!(dense.next(8), Some(9), "8 is not a member");
        assert_eq!(dense.next(9), None);
        assert_eq!(dense.next(63), None);

        let mut sparse = Uint32SpBset::new();
        for i in [0, 5, 9] {
            assert!(sparse.add(i));
        }
        assert_eq!(sparse.next(2), Some(5));
        assert_eq!(sparse.next(4), Some(5));
        assert_eq!(sparse.next(5), Some(9));
        assert_eq!(sparse.next(8), Some(9));
        assert_eq!(sparse.next(9), None);
        assert_eq!(sparse.next(1_000_000), None);
    }

    #[test]
    fn next_at_the_u32_maximum_declines_rather_than_wrapping() {
        // The C's `++last` wraps to 0 here and restarts the scan from the
        // bottom, which would revisit member 0 after the iteration had
        // finished. The checked increment is the deliberate divergence
        // documented on both `next` methods.
        let mut dense = Uint32Bset::new();
        dense.resize(128).expect("resize succeeds");
        assert!(dense.add(0));
        assert_eq!(
            dense.next(u32::MAX),
            None,
            "wrapping would have returned Some(0)"
        );

        let mut sparse = Uint32SpBset::new();
        assert!(sparse.add(0));
        assert!(sparse.add(u32::MAX));
        assert_eq!(
            sparse.next(u32::MAX),
            None,
            "u32::MAX is a member but can have no successor"
        );
        assert_eq!(sparse.next(u32::MAX - 1), Some(u32::MAX));
    }

    #[test]
    fn first_on_an_empty_set_is_none() {
        let mut dense = Uint32Bset::new();
        dense.resize(1000).expect("resize succeeds");
        assert_eq!(dense.first(), None, "capacity without members is empty");
        assert!(dense.is_empty());
        assert!(dense.add(999));
        dense.remove(999);
        assert_eq!(dense.first(), None, "empty again after the last removal");

        let sparse = Uint32SpBset::new();
        assert_eq!(sparse.first(), None);
        assert!(sparse.is_empty());
    }

    #[test]
    fn is_empty_agrees_with_count_across_the_whole_capacity() {
        let mut bset = Uint32Bset::new();
        bset.resize(200).expect("resize succeeds");
        assert_eq!(bset.capacity(), 256);
        assert!(bset.is_empty());
        // One member in each slot, including both boundary bits.
        for i in [0, 63, 64, 127, 128, 191, 192, 255] {
            assert!(bset.add(i), "add({i}) must be in range");
            assert!(!bset.is_empty());
        }
        assert_eq!(bset.count(), 8);
        for i in [0, 63, 64, 127, 128, 191, 192, 255] {
            bset.remove(i);
        }
        assert!(bset.is_empty());
        assert_eq!(bset.count(), 0);
    }

    #[test]
    fn equality_includes_the_capacity() {
        // Documented on the type: capacity is observable, so two sets holding
        // the same members but differing in capacity are not equal.
        let mut narrow = Uint32Bset::new();
        narrow.resize(64).expect("resize succeeds");
        let mut wide = Uint32Bset::new();
        wide.resize(128).expect("resize succeeds");
        assert!(narrow.add(1));
        assert!(wide.add(1));
        assert_ne!(narrow, wide, "same member, different capacity");
        narrow.resize(128).expect("resize succeeds");
        assert_eq!(narrow, wide);

        let mut a = Uint32SpBset::new();
        let mut b = Uint32SpBset::new();
        assert_eq!(a, b);
        assert!(a.add(7));
        assert_ne!(a, b);
        assert!(b.add(7));
        assert_eq!(a, b);
    }

    // The four bullets of the iteration-under-modification contract, one test
    // each, for both types. They are the reason `next` is a stateless query
    // rather than an `Iterator`, so they are asserted rather than assumed.

    #[test]
    fn bullet_1_dense_added_above_last_is_picked_up() {
        let mut bset = Uint32Bset::new();
        bset.resize(1024).expect("resize succeeds");
        for i in [10, 20, 30] {
            assert!(bset.add(i));
        }
        let first = bset.first().expect("the set is not empty");
        assert_eq!(first, 10);
        let second = bset.next(first).expect("20 follows 10");
        assert_eq!(second, 20);
        // Added higher than `last`: must be visited.
        assert!(bset.add(25));
        assert_eq!(bset.next(second), Some(25));
    }

    #[test]
    fn bullet_2_dense_added_below_last_does_not_show_up() {
        let mut bset = Uint32Bset::new();
        bset.resize(1024).expect("resize succeeds");
        for i in [10, 20, 30] {
            assert!(bset.add(i));
        }
        let last = 20;
        // Added lower than `last`: must not be visited, even though it is now
        // a member.
        assert!(bset.add(15));
        assert!(bset.contains(15));
        assert_eq!(bset.next(last), Some(30));
    }

    #[test]
    fn bullet_3_dense_removed_at_or_below_last_does_not_show_up() {
        let mut bset = Uint32Bset::new();
        bset.resize(1024).expect("resize succeeds");
        for i in [10, 20, 30] {
            assert!(bset.add(i));
        }
        let last = 20;
        // Removing the member just visited, and one before it, is exactly what
        // `lib/multi.c:1295-1296` does mid-loop. The walk continues unchanged.
        bset.remove(20);
        bset.remove(10);
        assert_eq!(bset.next(last), Some(30));
        assert_eq!(bset.count(), 1);
    }

    #[test]
    fn bullet_4_dense_removed_above_last_is_not_visited() {
        let mut bset = Uint32Bset::new();
        bset.resize(1024).expect("resize succeeds");
        for i in [10, 20, 30] {
            assert!(bset.add(i));
        }
        let last = 20;
        // Removed higher than `last`: must not be visited, and the iteration
        // ends because nothing else is left above it.
        bset.remove(30);
        assert_eq!(bset.next(last), None);
    }

    #[test]
    fn bullet_1_sparse_added_above_last_is_picked_up() {
        let mut bset = Uint32SpBset::new();
        for i in [10, 20, 30] {
            assert!(bset.add(i));
        }
        let first = bset.first().expect("the set is not empty");
        assert_eq!(first, 10);
        let second = bset.next(first).expect("20 follows 10");
        assert_eq!(second, 20);
        assert!(bset.add(25));
        assert_eq!(bset.next(second), Some(25));
        // Across a chunk boundary of the C representation, too, so the
        // guarantee is not an artefact of everything living in one chunk.
        assert!(bset.add(300));
        assert_eq!(bset.next(30), Some(300));
    }

    #[test]
    fn bullet_2_sparse_added_below_last_does_not_show_up() {
        let mut bset = Uint32SpBset::new();
        for i in [10, 20, 30] {
            assert!(bset.add(i));
        }
        assert!(bset.add(15));
        assert!(bset.contains(15));
        assert_eq!(bset.next(20), Some(30));
    }

    #[test]
    fn bullet_3_sparse_removed_at_or_below_last_does_not_show_up() {
        let mut bset = Uint32SpBset::new();
        for i in [10, 20, 30] {
            assert!(bset.add(i));
        }
        // `lib/multi_ev.c:586` removes the member just visited mid-loop.
        bset.remove(20);
        bset.remove(10);
        assert_eq!(bset.next(20), Some(30));
        assert_eq!(bset.count(), 1);
    }

    #[test]
    fn bullet_4_sparse_removed_above_last_is_not_visited() {
        let mut bset = Uint32SpBset::new();
        for i in [10, 20, 30] {
            assert!(bset.add(i));
        }
        bset.remove(30);
        assert_eq!(bset.next(20), None);
    }

    /// `Curl_popcount64` of `lib/uint-bset.c:175-191`, transcribed so that the
    /// replacement can be compared against it rather than merely asserted to
    /// be equivalent.
    ///
    /// The multiplication is `wrapping_mul` because C's unsigned arithmetic
    /// wraps by definition and this one genuinely does overflow -- which is
    /// the reasoning that [`u64::count_ones`] removes entirely. The
    /// subtraction is written the same way for consistency, although the
    /// Hamming-weight identity means no borrow can occur there.
    fn curl_popcount64(x: u64) -> u32 {
        const M1: u64 = 0x5555_5555_5555_5555;
        const M2: u64 = 0x3333_3333_3333_3333;
        const M4: u64 = 0x0f0f_0f0f_0f0f_0f0f;
        const H01: u64 = 0x0101_0101_0101_0101;
        let mut x = x.wrapping_sub((x >> 1) & M1);
        x = (x & M2) + ((x >> 2) & M2);
        x = (x + (x >> 4)) & M4;
        u32::try_from(x.wrapping_mul(H01) >> 56).expect("a count of 64 bits")
    }

    /// `Curl_ctz64` of `lib/uint-bset.c:195-230`, transcribed for the same
    /// reason. Note the documented answer for zero: 64.
    fn curl_ctz64(x: u64) -> u32 {
        const ML32: u64 = 0xFFFF_FFFF;
        const ML16: u64 = 0x0000_FFFF;
        const ML8: u64 = 0x0000_00FF;
        const ML4: u64 = 0x0000_000F;
        const ML2: u64 = 0x0000_0003;
        if x == 0 {
            return 64;
        }
        let mut x = x;
        let mut n: u32 = 1;
        if x & ML32 == 0 {
            n += 32;
            x >>= 32;
        }
        if x & ML16 == 0 {
            n += 16;
            x >>= 16;
        }
        if x & ML8 == 0 {
            n += 8;
            x >>= 8;
        }
        if x & ML4 == 0 {
            n += 4;
            x >>= 4;
        }
        if x & ML2 == 0 {
            n += 2;
            x >>= 2;
        }
        n - u32::try_from(x & 1).expect("one bit")
    }

    #[test]
    fn trailing_zeros_is_curl_ctz64_including_the_answer_for_zero() {
        // The single most important equivalence, because `first` and `next`
        // rely on it and the C spells the zero case out explicitly at
        // `lib/uint-bset.c:206-207`.
        assert_eq!(0_u64.trailing_zeros(), 64);
        assert_eq!(curl_ctz64(0), 64);

        for k in 0..64 {
            let single = 1_u64 << k;
            assert_eq!(single.trailing_zeros(), k, "one bit at {k}");
            assert_eq!(curl_ctz64(single), k, "the C agrees at {k}");
        }

        let cases: [u64; 10] = [
            1,
            2,
            3,
            u64::MAX,
            u64::MAX - 1,
            0x8000_0000_0000_0000,
            0x0000_0001_0000_0000,
            0xdead_beef_0000_0000,
            0x0f0f_0f0f_0f0f_0f00,
            0x5555_5555_5555_5555,
        ];
        for x in cases {
            assert_eq!(
                x.trailing_zeros(),
                curl_ctz64(x),
                "trailing_zeros disagrees with Curl_ctz64 for {x:#018x}"
            );
        }
    }

    #[test]
    fn count_ones_is_curl_popcount64() {
        assert_eq!(0_u64.count_ones(), 0);
        assert_eq!(u64::MAX.count_ones(), 64);
        assert_eq!(curl_popcount64(0), 0);
        assert_eq!(curl_popcount64(u64::MAX), 64);

        for k in 0..64 {
            let single = 1_u64 << k;
            assert_eq!(single.count_ones(), 1, "one bit at {k}");
            assert_eq!(curl_popcount64(single), 1, "the C agrees at {k}");
            // A prefix of set bits, which walks every population from 1 to 64.
            let prefix = u64::MAX >> k;
            assert_eq!(prefix.count_ones(), curl_popcount64(prefix));
        }

        let cases: [u64; 8] = [
            1,
            2,
            3,
            0x5555_5555_5555_5555,
            0x3333_3333_3333_3333,
            0x0f0f_0f0f_0f0f_0f0f,
            0xdead_beef_cafe_babe,
            0x8000_0000_0000_0001,
        ];
        for x in cases {
            assert_eq!(
                x.count_ones(),
                curl_popcount64(x),
                "count_ones disagrees with Curl_popcount64 for {x:#018x}"
            );
        }
    }

    #[test]
    fn the_sparse_set_holds_any_u32() {
        // `lib/uint-spbset.h:29`: "It can hold any uint32_t value." The dense
        // set cannot: its largest capacity stops 64 short of `u32::MAX`.
        let mut bset = Uint32SpBset::new();
        for i in [0, 255, 256, u32::MAX] {
            assert!(bset.add(i), "add({i}) must succeed");
        }
        for i in [0, 255, 256, u32::MAX] {
            assert!(bset.contains(i), "contains({i}) must hold");
        }
        assert_eq!(bset.count(), 4);
        assert_eq!(bset.first(), Some(0));
        assert_eq!(bset.next(0), Some(255));
        assert_eq!(bset.next(255), Some(256));
        assert_eq!(bset.next(256), Some(u32::MAX));
        assert_eq!(bset.next(u32::MAX), None);
    }

    #[test]
    fn the_sparse_set_iterates_across_its_chunk_boundaries() {
        // 256 is `CURL_UINT32_SPBSET_CH_SLOTS * 64`, so in the C
        // representation each of these members lands in a different chunk or
        // at a chunk edge. The order must still be plain ascending order.
        let mut bset = Uint32SpBset::new();
        let members = [0, 255, 256, 511, 512, 767, 768];
        for i in members {
            assert!(bset.add(i));
        }
        let mut walked = Vec::new();
        let mut current = bset.first();
        while let Some(member) = current {
            walked.push(member);
            current = bset.next(member);
        }
        assert_eq!(walked.as_slice(), members.as_slice());

        // Removing a chunk's only member must not strand the chunks after it.
        bset.remove(256);
        bset.remove(511);
        assert_eq!(bset.next(255), Some(512));
        assert_eq!(bset.next(0), Some(255));
    }

    #[test]
    fn clearing_keeps_the_dense_capacity_but_not_the_members() {
        // `Curl_uint32_bset_clear` zeroes the slots and leaves `nslots` alone,
        // so the capacity survives a clear where a resize to 0 would not.
        let mut bset = Uint32Bset::new();
        bset.resize(200).expect("resize succeeds");
        for i in [0, 100, 255] {
            assert!(bset.add(i));
        }
        assert_eq!(bset.count(), 3);
        bset.clear();
        assert_eq!(bset.capacity(), 256, "clear must not change the capacity");
        assert_eq!(bset.count(), 0);
        assert!(bset.is_empty());
        assert!(bset.add(255), "the capacity is still usable after a clear");

        // And a clear on a zero-capacity set is a no-op rather than a panic,
        // which is what the C's `if(bset->nslots)` guard achieves.
        let mut empty = Uint32Bset::new();
        empty.clear();
        assert_eq!(empty.capacity(), 0);
        assert!(empty.is_empty());
    }
}
