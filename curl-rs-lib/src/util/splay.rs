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

// THE LICENCE BANNER ABOVE, byte-identical to `util/mod.rs`'s
// and measured from `lib/llist.c:1-23`.

// CONVENTIONS THIS FILE HOLDS ITSELF TO, and where each one comes from.
//
// FOUR THINGS THIS FILE MUST NOT NAME, each for its own reason:
//
//   * `unsafe` -- `src/lib.rs` carries `#![deny(unsafe_code)]` and grants
//     exactly one exemption, on `mod ffi`, which is not here. This module is
//     the single strongest argument for the substitution recorded below:
//     `Curl_splay`'s rotation loop rewires four pointer fields through a
//     stack-allocated sentinel node, and `Curl_splayremove` splays a subtree
//     recursively. Neither has a safe hand-written expression.
//   * a raw pointer, in any spelling -- the C node embeds four of them plus an
//     untyped payload.
//   * `tokio` -- this is a data structure. The reactor that waits until the
//     earliest instant arrives belongs to `crate::conn` and
//     `crate::transfer`; this file only answers which entry is earliest.
//   * a Cargo feature -- the timer tree is unconditional. The vocabulary is
//     fixed at fifteen names and none of them gates expiry scheduling, so
//     no `#[cfg(feature = ...)]` appears below and none may be added.

//! The expiry timer tree -- supersedes `lib/splay.c` and `lib/splay.h`.
//!
//! # The whole C surface, item by item
//!
//! Six declared entry points (`lib/splay.h:40-57`). Each is reproduced here,
//! or recorded as deliberately collapsed into a neighbour. Nothing is dropped
//! silently.
//!
//! | C item | Site | Rust counterpart |
//! |---|---|---|
//! | `struct Curl_tree` | `splay.h:31-38` | [`TimerTree`] plus [`TimerKey`] |
//! | `Curl_splay` | `splay.c:41-93` | [`TimerTree::peek`] -- collapsed |
//! | `Curl_splayinsert` | `splay.c:104-147` | [`TimerTree::insert`] |
//! | `Curl_splaygetbest` | `splay.c:149-195` | [`TimerTree::get_best`] |
//! | `Curl_splayremove` | `splay.c:208-278` | [`TimerTree::remove`] |
//! | `Curl_splayset` | `splay.c:281-285` | none -- the map holds the value |
//! | `Curl_splayget` | `splay.c:287-291` | none -- the map holds the value |
//!
//! Two collapses, stated rather than implied:
//!
//! * **`Curl_splay` has no public successor.** It is the top-down splay that
//!   brings the closest key to the root, and its single external use is
//!   `multi.c:3353`, `multi->timetree = Curl_splay(&tv_zero, multi->timetree);`
//!   -- whose whole purpose is *bring the smallest to the root so I can
//!   inspect it*, immediately followed by reads of `multi->timetree->key`
//!   (`:3356`, `:3364`) and of its payload (`:3365`, `:3372`).
//!   [`TimerTree::peek`] is that idiom, and it hands back both halves.
//! * **`Curl_splayset` and `Curl_splayget` disappear into the value.** The C
//!   sets the payload on the node *before* inserting it
//!   (`multi.c:3583-3584`) because the node is embedded in the easy handle
//!   and the tree never owns it. Here the payload is an argument to
//!   [`TimerTree::insert`] and comes back out of [`TimerTree::get_best`], so
//!   there is no window in which an entry exists without one.
//!
//! # The comparison is at microsecond resolution
//!
//! `splay.c:28-35` defines the whole of the C's ordering:
//!
//! ```c
//! /* negative value: when i is smaller than j
//!    zero          : when i is equal   to   j
//!    positive when : when i is larger  than j */
//! #define splay_compare(i, j) curlx_ptimediff_us(i, j)
//! ```
//!
//! `curlx_ptimediff_us`, not the millisecond form: two timers 300
//! microseconds apart are distinct entries in the C and are distinct entries
//! here. [`CurlTime`]'s derived [`Ord`] supplies the same order -- seconds
//! first, microseconds only to break a tie -- and a test below asserts that
//! its result agrees in sign with [`timediff_us`] across a table of pairs
//! that spans a second boundary.
//!
//! # Relocated test coverage
//!
//! `tests/unit/unit1309.c` is this module's test-relocation source: the C
//! marks both `Curl_splayinsert` (`splay.c:102`) and `Curl_splayremove`
//! (`splay.c:206`) `@unittest: 1309`. That file links a debug static libcurl
//! and calls internal `Curl_*` symbols, which a Rust static library genuinely
//! does not export, so its coverage relocates into the `#[cfg(test)]` module
//! below rather than being made to link -- a documented deviation, not a
//! defect to work around.

use std::collections::BTreeMap;

use super::timeval::CurlTime;

/// The identity of one registered timer: the instant it is due, then the
/// order in which it arrived.
///
/// # Ordering
///
/// Both halves are load-bearing:
///
/// * [`at`] first reproduces `splay_compare` (`splay.c:35`), which is
///   `curlx_ptimediff_us` and therefore orders at microsecond resolution.
/// * [`seq`] second reproduces the C's same-key list, whose tail-append and
///   head-first removal make firing order first-in, first-out. The module
///   documentation records the measurement.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) struct TimerKey {
    /// The instant this timer is due -- the C's `struct Curl_tree::key`.
    pub(crate) at: CurlTime,
    /// The arrival order among all registrations, which breaks a tie between
    /// two timers due at the same instant.
    pub(crate) seq: u64,
}

/// The expiry timer collection -- supersedes the splay tree rooted at
/// `struct Curl_multi::timetree`.
///
/// `T` is the payload the C carried in `void *ptr` and reached through
/// `Curl_splayget`. In `lib/multi.c` it is the easy handle
/// (`multi.c:3583`); here the collection owns whatever it is given, so a
/// payload cannot outlive its entry and an entry cannot exist without one.
///
/// # Example
///
/// ```ignore
/// let mut timers: TimerTree<&str> = TimerTree::new();
/// let soon = timers.insert(CurlTime::new(1, 0), "first");
/// let also_soon = timers.insert(CurlTime::new(1, 0), "second");
/// // Nothing is due yet.
/// assert!(timers.get_best(CurlTime::new(0, 999_999)).is_none());
/// // Both are due at one second, oldest first.
/// assert_eq!(timers.get_best(CurlTime::new(1, 0)), Some((soon, "first")));
/// assert_eq!(timers.remove(also_soon), Some("second"));
/// assert!(timers.is_empty());
/// ```
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct TimerTree<T> {
    /// The registered timers, held in [`TimerKey`] order.
    entries: BTreeMap<TimerKey, T>,
    /// The arrival number the next registration receives.
    next_seq: u64,
}

impl<T> Default for TimerTree<T> {
    /// The empty collection -- the C's `multi->timetree = NULL`.
    ///
    /// Written by hand rather than derived. `#[derive(Default)]` would add a
    /// `T: Default` bound that nothing needs and that would exclude every
    /// payload without one, the easy handle among them.
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_seq: 0,
        }
    }
}

impl<T> TimerTree<T> {
    /// A collection with no timers in it.
    ///
    /// The successor of the C's null root: `lib/multi.c` has no constructor
    /// call to port, because `struct Curl_multi` is zero-initialised and an
    /// empty splay tree IS a null pointer (`unit1309.c:71`, *"the empty
    /// tree"*). Equivalent to [`Default::default`].
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Registers a timer due at `at` and returns its identity.
    ///
    /// Supersedes `Curl_splayinsert` (`splay.c:104-147`), which is
    /// `@unittest: 1309`. The C's two paths both collapse into one insertion
    /// here, and both are worth recording because one of them carries frozen
    /// behaviour:
    ///
    /// * **A fresh key** (`splay.c:128-146`) made the new node the root, took
    ///   the old root as its `smaller` or `larger` child depending on the
    ///   comparison, and initialised a one-element circular list with
    ///   `node->samen = node->samep = node`. Nothing of that survives: a
    ///   [`BTreeMap`] places the key without a rotation and without a list.
    /// * **A key already present** (`splay.c:113-125`) marked the new node
    ///   `SPLAY_SUBNODE`, spliced it in at `t->samep` -- the TAIL of the
    ///   circular list -- and returned the old root, *"the root node always
    ///   stays the same"*. **Tail append is what makes removal first-in,
    ///   first-out**, and it is reproduced by the increasing arrival number
    ///   below rather than by a list. The module documentation records why
    ///   that order is observable.
    #[allow(dead_code)]
    pub(crate) fn insert(&mut self, at: CurlTime, payload: T) -> TimerKey {
        let key = TimerKey {
            at,
            seq: self.next_seq,
        };
        self.next_seq = self.next_seq.wrapping_add(1);
        // `BTreeMap::insert` hands back the value it displaced, and for a key
        // built from a never-repeating arrival number there can never be one.
        // Binding it and asserting is how the identity invariant of
        // [`TimerKey`] is checked rather than assumed; in a release build the
        // assertion compiles away and the displaced value, if the impossible
        // happened, is dropped here.
        let displaced = self.entries.insert(key, payload);
        debug_assert!(
            displaced.is_none(),
            "TimerTree: an arrival number repeated and displaced a live \
             entry, so TimerKey is no longer an identity"
        );
        key
    }

    /// Removes and returns the earliest timer due at or before `key`, or
    /// [`None`] if none is.
    ///
    /// Supersedes `Curl_splaygetbest` (`splay.c:149-195`), whose own
    /// description is *"Finds and deletes the best-fit node from the tree.
    /// Return a pointer to the resulting tree. best-fit means the smallest
    /// node if it is not larger than the key."* This is the function
    /// `lib/multi.c` calls in a loop to drain due timers (`:2801`, `:3051`),
    /// so its five measured steps are reproduced in order:
    ///
    /// 1. **An empty tree yields nothing** (`splay.c:159-162`): the C sets
    ///    `*removed = NULL` and returns `NULL`. Here [`None`].
    /// 2. **The smallest is brought to the root** (`:165`) by splaying on
    ///    `tv_zero`, a `{ 0, 0 }` reading that no key can be below. That is a
    ///    lookup, not a mutation of contents, and
    ///    [`BTreeMap::first_key_value`] performs it directly.
    /// 3. **A cut-off that is INCLUSIVE of an equal key** (`:167-171`). The C
    ///    writes `if(splay_compare(pkey, &t->key) < 0)`, which is
    ///    `pkey - t->key < 0`, so it gives up only when the query instant is
    ///    strictly BELOW the earliest entry. An entry whose instant equals
    ///    `key` is therefore due and is returned. The comparison below is
    ///    spelled `key < earliest` for exactly that reason: `<=` would leave
    ///    a due timer unfired for a whole tick, and reversing it would fire
    ///    timers early.
    /// 4. **Entries at one instant come out oldest first** (`:173-188`, *"
    ///    FIRST! Check if there is a list with identical keys"*). The C takes
    ///    the list head and promotes `t->samen` in its place. Here the
    ///    arrival number is part of the key, so the earliest arrival is
    ///    already the first entry in the map and step 4 needs no code of its
    ///    own.
    /// 5. **Otherwise the root itself is removed** (`:190-194`).
    #[allow(dead_code)]
    pub(crate) fn get_best(&mut self, key: CurlTime) -> Option<(TimerKey, T)> {
        // Steps 1 and 2: the earliest instant in the collection, or nothing
        // at all. `?` covers the empty case without a branch of its own.
        let earliest = self.entries.first_key_value()?.0.at;

        // Step 3: `splay_compare(pkey, &t->key) < 0` -- even the earliest is
        // too far ahead. Strictly below, so an entry AT `key` is due.
        if key < earliest {
            return None;
        }

        // Steps 4 and 5: the first entry in key order is the earliest
        // instant, and within that instant the earliest arrival.
        self.entries.pop_first()
    }

    /// Removes the timer named by `key`, returning its payload, or [`None`] if
    /// the collection does not hold it.
    ///
    /// Returning the payload is more than the C offered -- `Curl_splayremove`
    /// only unlinked, because the caller already held the node -- and it costs
    /// nothing, since the collection has to give up ownership either way.
    #[allow(dead_code)]
    pub(crate) fn remove(&mut self, key: TimerKey) -> Option<T> {
        self.entries.remove(&key)
    }

    /// Borrows the earliest timer without removing it.
    ///
    /// This is the successor of the `Curl_splay(&tv_zero, t)` idiom rather
    /// than of `Curl_splay` itself (`splay.c:41-93`), whose rotation code has
    /// no reason to exist here and could not be written safely if it did. The
    /// single external use is `multi.c:3353`:
    ///
    /// ```c
    /// /* splay the lowest to the bottom */
    /// multi->timetree = Curl_splay(&tv_zero, multi->timetree);
    /// *expire_time = multi->timetree ? multi->timetree->key : tv_zero;
    /// ```
    #[allow(dead_code)]
    pub(crate) fn peek(&self) -> Option<(&TimerKey, &T)> {
        self.entries.first_key_value()
    }

    /// How many timers are registered.
    ///
    /// **An addition, not a port.** `lib/splay.h` declares no such function
    /// and the C multi handle tracks its own counts separately. It is provided
    /// because it costs nothing and because the non-mutation guarantee of
    /// [`Self::get_best`] cannot be stated in a test without it.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no timer is registered -- the C's `!multi->timetree`.
    ///
    /// **An addition, not a port**, for the same reason as [`Self::len`], and
    /// it is the direct expression of the two assertions `unit1309.c` makes
    /// (`:101`, `:131`): *"tree not empty after removing all nodes"* and
    /// *"tree not empty when it should be"*.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// TESTS
//
// Four things the C test could not check are added, each because the
// migration makes them checkable:
//
// 1. THE DRAIN ORDER ITSELF. The C prints `payload / 10` and `payload % 10`
//    for every extracted node (`unit1309.c:124-126`) and asserts nothing
//    whatsoever about either. Its only assertions are that the root is null
//    after each phase (`:101`, `:131`). Six tests below assert it, including
//    the interleaved case that no amount of printing would have caught.
//   2. THE CUT-OFF DIRECTION. `Curl_splaygetbest`'s comparison is `<` and not
//      `<=`, so an entry due at exactly the query instant is extracted. The C
//      test steps its query in hundreds of microseconds past keys that are
//      never a multiple of a hundred, so it never lands on the boundary at
//      all and cannot distinguish the two operators.
//   3. THAT A QUERY TOO EARLY REMOVES NOTHING. Extracting before comparing is
//      an easy transposition to make and a silent one to live with, and the C
//      test never issues a query below its earliest key.
//   4. THAT A PAYLOAD IS DISPOSED OF EXACTLY ONCE. The C node is embedded in
//      the caller's own structure and the tree owns nothing, so there is no
//      disposal for `unit1309.c` to observe. Ownership makes it observable.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::timeval::timediff_us;
    use std::cell::Cell;

    /// The C's node count -- `#define NUM_NODES 50` (`unit1309.c:63`).
    const NUM_NODES: usize = 50;

    /// The C's key for node `i`: `key.tv_usec = (541 * i) % 1023`
    /// (`unit1309.c:78`, and identically at `:108`).
    fn unit1309_usec(i: usize) -> i32 {
        i32::try_from((541 * i) % 1023).expect("the remainder is below 1023")
    }

    /// A payload that records its own disposal in a shared counter.
    ///
    /// It has no counterpart in `unit1309.c`, whose payloads are borrowed
    /// `size_t` slots in a caller-owned array (`unit1309.c:67`). Construct 4
    /// of the module documentation -- the untyped, unowned `void *ptr` --
    /// is what this demonstrates the removal of.
    struct Tracked<'log> {
        log: &'log Cell<u32>,
    }

    impl<'log> Tracked<'log> {
        fn new(log: &'log Cell<u32>) -> Self {
            Self { log }
        }
    }

    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            self.log.set(self.log.get() + 1);
        }
    }

    // --- the collection itself ---------------------------------------------

    /// The C's empty tree is a null root (`unit1309.c:71`), and both
    /// constructors here produce the same thing.
    #[test]
    fn a_new_collection_is_empty() {
        let fresh: TimerTree<u8> = TimerTree::new();
        assert!(fresh.is_empty());
        assert_eq!(fresh.len(), 0);
        assert_eq!(fresh.peek(), None);

        let default: TimerTree<u8> = TimerTree::default();
        assert!(default.is_empty());
        assert_eq!(default.len(), 0);
        assert_eq!(default.peek(), None);
    }

    /// Every operation on an empty collection answers cleanly. The C returns
    /// a null tree from `Curl_splaygetbest` (`splay.c:159-162`) and code 1
    /// from `Curl_splayremove` (`:214-215`); both become "not present" here,
    /// and neither may panic.
    #[test]
    fn an_empty_collection_yields_nothing_and_does_not_panic() {
        let mut timers: TimerTree<u8> = TimerTree::new();

        assert_eq!(timers.get_best(CurlTime::ZERO), None);
        assert_eq!(timers.get_best(CurlTime::new(i64::MAX, 999_999)), None);
        assert_eq!(timers.peek(), None);
        assert_eq!(
            timers.remove(TimerKey {
                at: CurlTime::ZERO,
                seq: 0,
            }),
            None
        );

        assert!(timers.is_empty());
        assert_eq!(timers.len(), 0);
    }

    // --- the key, which is the identity ------------------------------------

    /// The instant dominates and the arrival number only breaks a tie, which
    /// is the whole of the frozen firing order. The derived comparison is
    /// asserted to equal the pair the governing plan specifies rather than
    /// trusted to be it.
    #[test]
    fn the_key_orders_by_instant_before_arrival() {
        let early = TimerKey {
            at: CurlTime::new(0, 1),
            seq: u64::MAX,
        };
        let late = TimerKey {
            at: CurlTime::new(0, 2),
            seq: 0,
        };
        assert!(early < late, "the instant must dominate the arrival number");

        let first = TimerKey {
            at: CurlTime::new(3, 3),
            seq: 7,
        };
        let second = TimerKey {
            at: CurlTime::new(3, 3),
            seq: 8,
        };
        assert!(first < second, "the arrival number must break a tie");

        for (left, right) in [(early, late), (first, second), (late, early)] {
            assert_eq!(
                left.cmp(&right),
                (left.at, left.seq).cmp(&(right.at, right.seq)),
                "the key order must be the order of the pair"
            );
        }
    }

    /// `splay_compare(i, j)` is `curlx_ptimediff_us(i, j)` (`splay.c:35`), so
    /// the SIGN of the microsecond difference is the C's comparison. The pairs
    /// cross a second boundary in both directions and include two negative
    /// seconds, which is where a field-by-field order and a subtraction could
    /// disagree.
    #[test]
    fn the_instant_order_agrees_with_the_microsecond_difference_sign() {
        let pairs = [
            (CurlTime::ZERO, CurlTime::ZERO),
            (CurlTime::new(0, 1), CurlTime::ZERO),
            (CurlTime::ZERO, CurlTime::new(0, 1)),
            (CurlTime::new(0, 300), CurlTime::ZERO),
            (CurlTime::new(1, 0), CurlTime::new(0, 999_999)),
            (CurlTime::new(0, 999_999), CurlTime::new(1, 0)),
            (CurlTime::new(2, 0), CurlTime::new(1, 999_999)),
            (CurlTime::new(1, 500_000), CurlTime::new(1, 500_000)),
            (CurlTime::new(-1, 0), CurlTime::ZERO),
            (CurlTime::new(-1, 999_999), CurlTime::ZERO),
        ];

        for (left, right) in pairs {
            assert_eq!(
                left.cmp(&right),
                timediff_us(left, right).cmp(&0),
                "{left:?} against {right:?}"
            );
        }
    }

    // --- ordering, which is frozen behaviour -------------------------------

    /// Instants registered out of order come out in ascending order.
    #[test]
    fn draining_yields_ascending_instants() {
        let mut timers: TimerTree<&str> = TimerTree::new();
        timers.insert(CurlTime::new(3, 0), "third");
        timers.insert(CurlTime::new(1, 0), "first");
        timers.insert(CurlTime::new(4, 500), "fourth");
        timers.insert(CurlTime::new(1, 1), "second");

        let far_ahead = CurlTime::new(1_000, 0);
        let mut order = Vec::new();
        while let Some((_, payload)) = timers.get_best(far_ahead) {
            order.push(payload);
        }

        assert_eq!(order, ["first", "second", "third", "fourth"]);
        assert!(timers.is_empty());
    }

    /// Three timers at ONE instant fire in the order they were registered.
    ///
    /// This is the C's tail append at `t->samep` (`splay.c:118-124`) plus its
    /// head-first extraction (`:173-188`), reproduced through the arrival
    /// number.
    #[test]
    fn three_entries_at_one_instant_drain_in_insertion_order() {
        let at = CurlTime::new(7, 42);
        let mut timers: TimerTree<&str> = TimerTree::new();
        let first = timers.insert(at, "first");
        let second = timers.insert(at, "second");
        let third = timers.insert(at, "third");

        assert!(first < second, "arrival numbers must increase");
        assert!(second < third, "arrival numbers must increase");

        assert_eq!(timers.get_best(at), Some((first, "first")));
        assert_eq!(timers.get_best(at), Some((second, "second")));
        assert_eq!(timers.get_best(at), Some((third, "third")));
        assert_eq!(timers.get_best(at), None);
    }

    /// The interleaved case, and the reason this module has the shape it has.
    #[test]
    fn interleaved_instants_drain_by_instant_then_by_arrival() {
        let t0 = CurlTime::new(0, 0);
        let t1 = CurlTime::new(0, 1);
        let mut timers: TimerTree<char> = TimerTree::new();
        timers.insert(t1, 'a');
        timers.insert(t0, 'b');
        timers.insert(t1, 'c');
        timers.insert(t0, 'd');

        let mut order = Vec::new();
        while let Some((_, payload)) = timers.get_best(t1) {
            order.push(payload);
        }

        assert_eq!(order, ['b', 'd', 'a', 'c']);
    }

    /// A microsecond is the resolution, not a millisecond.
    #[test]
    fn instants_one_microsecond_apart_are_distinct_and_ordered() {
        let mut timers: TimerTree<&str> = TimerTree::new();
        let later = timers.insert(CurlTime::new(5, 301), "later");
        let earlier = timers.insert(CurlTime::new(5, 300), "earlier");

        assert_eq!(
            timers.get_best(CurlTime::new(5, 300)),
            Some((earlier, "earlier"))
        );
        // One microsecond short of what remains: nothing is due.
        assert_eq!(timers.get_best(CurlTime::new(5, 300)), None);
        assert_eq!(timers.len(), 1);
        assert_eq!(
            timers.get_best(CurlTime::new(5, 301)),
            Some((later, "later"))
        );
    }

    // --- the extraction cut-off --------------------------------------------

    /// The C's operator is `<`, so an entry due at exactly the query instant
    /// is extracted and one a single microsecond later is not.
    #[test]
    fn the_cut_off_includes_an_entry_whose_instant_equals_the_query() {
        let at = CurlTime::new(2, 250);
        let mut timers: TimerTree<u8> = TimerTree::new();
        let key = timers.insert(at, 9);

        assert_eq!(timers.get_best(CurlTime::new(2, 249)), None);
        assert_eq!(timers.len(), 1);
        assert_eq!(timers.get_best(at), Some((key, 9)));
        assert!(timers.is_empty());
    }

    /// A query below the earliest instant removes NOTHING, and a later query
    /// still finds everything.
    #[test]
    fn nothing_is_removed_when_even_the_earliest_is_too_far_ahead() {
        let at = CurlTime::new(10, 0);
        let mut timers: TimerTree<u8> = TimerTree::new();
        let key = timers.insert(at, 1);
        timers.insert(CurlTime::new(11, 0), 2);

        for too_early in [CurlTime::ZERO, CurlTime::new(9, 999_999)] {
            assert_eq!(timers.get_best(too_early), None);
            assert_eq!(timers.len(), 2, "the collection must be untouched");
            assert_eq!(timers.peek(), Some((&key, &1)));
        }

        assert_eq!(timers.get_best(at), Some((key, 1)));
        assert_eq!(timers.len(), 1);
    }

    // --- removal by identity -----------------------------------------------

    /// Removing one entry of an instant leaves its siblings in their original
    /// relative order -- the C's constant-time subnode unlink
    /// (`splay.c:219-235`), which preserves the list.
    #[test]
    fn removing_one_sibling_leaves_the_others_in_their_original_order() {
        let at = CurlTime::new(9, 12_345);
        let mut timers: TimerTree<char> = TimerTree::new();
        let first = timers.insert(at, 'a');
        let middle = timers.insert(at, 'b');
        let last = timers.insert(at, 'c');

        assert_eq!(timers.remove(middle), Some('b'));
        assert_eq!(timers.len(), 2);

        assert_eq!(timers.get_best(at), Some((first, 'a')));
        assert_eq!(timers.get_best(at), Some((last, 'c')));
        assert_eq!(timers.get_best(at), None);
    }

    /// A key the collection never issued is not present, whichever half of it
    /// is wrong. This is the C's code 2 (`splay.c:248-249`) with nothing to
    /// report, because a map either holds a key or does not.
    #[test]
    fn a_key_that_was_never_registered_is_not_present() {
        let at = CurlTime::new(1, 1);
        let mut timers: TimerTree<u8> = TimerTree::new();
        let key = timers.insert(at, 5);

        let forged_arrival = TimerKey {
            at,
            seq: key.seq + 1,
        };
        assert_eq!(timers.remove(forged_arrival), None);

        let forged_instant = TimerKey {
            at: CurlTime::new(1, 2),
            seq: key.seq,
        };
        assert_eq!(timers.remove(forged_instant), None);

        assert_eq!(timers.len(), 1, "no near miss may remove the real entry");
        assert_eq!(timers.remove(key), Some(5));
    }

    /// A double remove answers "not present" the second time, for a lone
    /// entry and for one the C would have called a subnode. The C needed a
    /// self-pointing `samen` to catch this (`splay.c:230-231`).
    #[test]
    fn a_second_remove_of_the_same_key_is_not_present() {
        let at = CurlTime::new(4, 4);
        let mut timers: TimerTree<u8> = TimerTree::new();
        let head = timers.insert(at, 1);
        let sibling = timers.insert(at, 2);

        assert_eq!(timers.remove(head), Some(1));
        assert_eq!(timers.remove(head), None);

        assert_eq!(timers.remove(sibling), Some(2));
        assert_eq!(timers.remove(sibling), None);

        assert!(timers.is_empty());
    }

    /// Removing the last entry leaves an empty collection, by either route.
    /// The C states the same contract for `newroot` at `splay.c:203-204`.
    #[test]
    fn removing_the_last_entry_leaves_an_empty_collection() {
        let at = CurlTime::new(6, 0);
        let mut timers: TimerTree<u8> = TimerTree::new();

        let only = timers.insert(at, 7);
        assert_eq!(timers.remove(only), Some(7));
        assert!(timers.is_empty());
        assert_eq!(timers.len(), 0);
        assert_eq!(timers.peek(), None);

        let only = timers.insert(at, 8);
        assert_eq!(timers.get_best(at), Some((only, 8)));
        assert!(timers.is_empty());
        assert_eq!(timers.peek(), None);
    }

    /// The arrival number never rewinds, so a handle to a departed entry
    /// cannot come to name a live one.
    #[test]
    fn the_arrival_number_does_not_rewind_when_the_collection_empties() {
        let at = CurlTime::new(1, 0);
        let mut timers: TimerTree<u8> = TimerTree::new();

        let first = timers.insert(at, 1);
        assert_eq!(timers.get_best(at), Some((first, 1)));
        assert!(timers.is_empty());

        let second = timers.insert(at, 2);
        assert!(second > first, "the arrival number must keep increasing");
        assert_eq!(timers.remove(first), None, "a stale handle names nothing");
        assert_eq!(timers.remove(second), Some(2));
    }

    // --- inspection without removal ----------------------------------------

    /// Borrowing the earliest entry is a read, and it hands back both halves
    /// -- the instant `multi.c:3356` copies out and the payload `:3365` traces.
    #[test]
    fn peek_is_a_read_and_exposes_both_halves() {
        let earliest = CurlTime::new(2, 3);
        let mut timers: TimerTree<&str> = TimerTree::new();
        timers.insert(CurlTime::new(5, 0), "later");
        let key = timers.insert(earliest, "the easy handle");

        assert_eq!(timers.peek(), Some((&key, &"the easy handle")));
        assert_eq!(timers.peek(), Some((&key, &"the easy handle")));
        assert_eq!(timers.len(), 2, "borrowing must not remove");

        let (peeked, payload) = timers.peek().expect("a registered timer");
        assert_eq!(peeked.at, earliest);
        assert_eq!(*payload, "the easy handle");

        assert_eq!(
            timers.get_best(earliest),
            Some((key, "the easy handle")),
            "the entry must still be extractable"
        );
    }

    // --- ownership ---------------------------------------------------------

    /// Every payload is disposed of exactly once, with no destructor
    /// registered anywhere.
    ///
    /// `Curl_splayset` and `Curl_splayget` (`splay.c:281-291`) collapse into
    /// the collection's value, so a payload cannot outlive its entry and an
    /// entry cannot exist without one.
    #[test]
    fn every_payload_is_disposed_of_exactly_once() {
        let log = Cell::new(0_u32);
        {
            let mut timers: TimerTree<Tracked<'_>> = TimerTree::new();
            let first = timers.insert(CurlTime::new(1, 0), Tracked::new(&log));
            timers.insert(CurlTime::new(2, 0), Tracked::new(&log));
            timers.insert(CurlTime::new(3, 0), Tracked::new(&log));
            assert_eq!(log.get(), 0, "a registered payload is still live");

            // A removed payload belongs to the caller and is disposed of when
            // the caller lets it go, which is at the end of this statement.
            drop(timers.remove(first));
            assert_eq!(log.get(), 1);

            drop(timers.get_best(CurlTime::new(2, 0)));
            assert_eq!(log.get(), 2);
            assert_eq!(timers.len(), 1);
        }

        assert_eq!(log.get(), 3, "the collection disposes of what it holds");
    }

    // --- ported: `tests/unit/unit1309.c` -----------------------------------

    /// The C test's first phase (`unit1309.c:73-101`): fifty distinct instants
    /// registered in ascending index order, then removed in `(i + 7) % 50`
    /// order with every removal required to succeed, leaving an empty tree.
    #[test]
    fn unit1309_fifty_distinct_instants_are_all_removable() {
        let mut timers: TimerTree<i32> = TimerTree::new();
        let mut handles: Vec<TimerKey> = Vec::with_capacity(NUM_NODES);

        for i in 0..NUM_NODES {
            let usec = unit1309_usec(i);
            handles.push(timers.insert(CurlTime::new(0, usec), usec));
        }
        assert_eq!(
            timers.len(),
            NUM_NODES,
            "541 and 1023 share no factor, so the fifty instants differ"
        );

        for i in 0..NUM_NODES {
            let victim = (i + 7) % NUM_NODES;
            assert!(
                timers.remove(handles[victim]).is_some(),
                "remove {victim} failed"
            );
        }

        assert!(timers.is_empty(), "tree not empty after removing all nodes");
        assert_eq!(timers.peek(), None);
    }

    /// The C test's second phase (`unit1309.c:103-131`): a rebuild with
    /// `i % 3 + 1` entries at each instant, payload `tv_usec * 10 + j`,
    /// drained by repeated extraction at 0, 100, ... 1100 microseconds until
    /// the tree is empty.
    #[test]
    fn unit1309_same_instant_siblings_drain_oldest_first() {
        let mut timers: TimerTree<i32> = TimerTree::new();
        let mut registered = 0_usize;

        for i in 0..NUM_NODES {
            let usec = unit1309_usec(i);
            for j in 0..=(i % 3) {
                let sibling = i32::try_from(j).expect("j is 0, 1 or 2");
                timers.insert(CurlTime::new(0, usec), usec * 10 + sibling);
                registered += 1;
            }
        }
        assert_eq!(timers.len(), registered);
        assert_eq!(
            registered, 99,
            "the C adds 1, 2 or 3 entries per instant in that cycle"
        );

        let mut drained: Vec<i32> = Vec::with_capacity(registered);
        for limit in (0..=1100_i32).step_by(100) {
            let now = CurlTime::new(0, limit);
            while let Some((key, payload)) = timers.get_best(now) {
                assert!(
                    key.at <= now,
                    "an entry ahead of the query was extracted"
                );
                drained.push(payload);
            }
        }

        assert!(timers.is_empty(), "tree not empty when it should be");
        assert_eq!(drained.len(), registered);

        let mut ascending = drained.clone();
        ascending.sort_unstable();
        assert_eq!(
            drained, ascending,
            "the drain must be ascending by instant then by arrival"
        );
    }
}
