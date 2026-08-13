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

//! The integer-keyed hash map -- supersedes `lib/uint-hash.c` and
//! `lib/uint-hash.h`.
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

use std::collections::HashMap;

/// A hash map keyed on [`u32`] -- supersedes `struct uint_hash`
/// (`lib/uint-hash.h:33-41`).
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
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drops every stored value, leaving the map empty -- supersedes
    /// `Curl_uint32_hash_clear` (`lib/uint-hash.c:201-206`) and the
    /// file-static `uint_hash_clear` (`:184-199`) it wraps.
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

    /// A callback that never stops sees every entry once.
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
