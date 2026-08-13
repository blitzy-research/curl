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

// THE LICENCE BANNER ABOVE, byte-identical to `util/mod.rs`'s.

//! The general-purpose ordered collection -- supersedes `lib/llist.c` and
//! `lib/llist.h`.
//!
//! # The answer this file exists to give
//!
//! **[`VecDeque<T>`] is what replaced `Curl_llist`.** Reach for it directly.
//!
//! There is deliberately no `LList` type here, and no alias for one. This
//! module is not a linked list, does not contain a linked list, and exists in
//! part to make sure nobody writes one: it holds the module documentation you
//! are reading, which is the crate's canonical answer to "what replaced
//! `Curl_llist`?", plus exactly the three helpers [`VecDeque`] genuinely
//! lacks.
//!
//! ## 2. Take and dispose are different operations
//!
//! `lib/llist.h:75-77` is explicit: `Curl_node_take_elem` removes the node
//! and returns the payload, and *"Will NOT invoke a registered `dtor`"*.
//! `Curl_node_remove` does invoke it. The distinction is an ownership
//! transfer versus a disposal, and it survives into this module:
//!
//! * [`VecDeque::remove`] **returns** the value. Ownership moves to the
//!   caller and nothing is dropped. This is `Curl_node_take_elem`.
//! * [`dispose`] **drops** the value and reports whether there was one. This
//!   is `Curl_node_remove`.
//!
//! # Conventions
//!
//! Crate-private, like every child of `super`: the C tree's
//! `extern Curl_xyz(...)` was private by convention and visible to the
//! linker, whereas `pub(crate) fn xyz(...)` is private by enforcement.
//! Nothing here backs an exported C symbol, so this file declares no `pub`
//! item, and no intrusive list type is exposed at any visibility because none
//! exists to expose.
//!
//! No `unsafe`, no reference counting, no interior mutability with runtime
//! borrow checks, no raw pointers, and no dependency: the only import is
//! [`VecDeque`] from the standard library. `super` sits at the base of the
//! crate's module graph and depends on nothing, and nothing in this file
//! fails, so it needs no error type either. Edition 2021, and the minimum
//! supported Rust version is 1.75.

use std::collections::VecDeque;

/// Inserts `value` after the element at index `after`, or at the head when
/// `after` is [`None`].
///
/// Two traps are handled here, once, so that no call site has to handle them:
///
/// * **The anchor is a position, and the insertion point is the one after
///   it.** `after == Some(0)` puts `value` at index 1, not index 0. The
///   corresponding `+ 1` is written exactly once, below.
/// * **[`None`] prepends** and does not append. `Curl_llist_append` is the
///   append operation, and its successor is [`VecDeque::push_back`].
///
/// # Errors
///
/// Returns `Err(value)`, handing the value back rather than dropping it, when
/// `after` names a position the collection does not have. The C has no
/// equivalent: `Curl_llist_insert_next` takes a node pointer whose membership
/// it never verifies, so passing a node from another list -- or a removed one
/// -- corrupts both. The only production caller, `lib/multi.c:3523`, derives
/// its anchor from a walk of the very list it inserts into and therefore
/// cannot fail; a `Result` is nevertheless returned in preference to a panic,
/// because the value is the caller's and losing it would be worse than either.
///
/// Note that `after == Some(index)` with `index < len` can never make
/// [`VecDeque::insert`] panic: `index + 1 <= len` follows, which is the
/// documented precondition, and the addition cannot overflow because a
/// collection's length is bounded well below [`usize::MAX`].
///
/// # Examples
///
/// ```ignore
/// let mut list: VecDeque<u8> = VecDeque::new();
/// list.push_back(1);
/// list.push_back(3);
/// // The C's `Curl_llist_insert_next(list, head, &two, node)`.
/// assert!(insert_after(&mut list, Some(0), 2).is_ok());
/// // The C's null-anchor branch.
/// assert!(insert_after(&mut list, None, 0).is_ok());
/// assert_eq!(list, [0, 1, 2, 3]);
/// ```
#[allow(dead_code)]
pub(crate) fn insert_after<T>(
    list: &mut VecDeque<T>,
    after: Option<usize>,
    value: T,
) -> Result<(), T> {
    match after {
        // `lib/llist.c:89-94`: a null anchor makes the new element the head,
        // whether or not the list already has elements.
        None => {
            list.push_front(value);
            Ok(())
        }
        // `lib/llist.c:89-102`: the new element goes between `e` and
        // `e->_next`, and becomes the tail when `e` had no successor. Index
        // arithmetic expresses both, with no case analysis and no tail
        // fix-up.
        Some(index) if index < list.len() => {
            list.insert(index + 1, value);
            Ok(())
        }
        Some(_) => Err(value),
    }
}

/// Removes the element at `index` and **drops** it, reporting whether there
/// was one.
///
/// **This is the disposing half of a pair, and the distinction is deliberate.**
/// [`VecDeque::remove`] is the other half -- it *returns* the value, which is
/// `Curl_node_take_elem` and its documented contract that it *"Will NOT invoke
/// a registered `dtor`"* (`lib/llist.h:75-77`). Both remove an element; only
/// one ends its life. Naming the disposing form is what keeps a call site from
/// reading as though it might be the transferring one, and it gives the twenty
/// `Curl_node_remove` sites in the C tree a successor that says so.
///
/// # Examples
///
/// ```ignore
/// let mut list: VecDeque<u8> = VecDeque::from([1, 2, 3]);
/// assert!(dispose(&mut list, 1)); // the 2 is dropped here
/// assert_eq!(list, [1, 3]);
/// assert!(!dispose(&mut list, 9)); // no such position
/// ```
#[allow(dead_code)]
pub(crate) fn dispose<T>(list: &mut VecDeque<T>, index: usize) -> bool {
    // `VecDeque::remove` yields the value; not binding it drops it here, at
    // the end of this statement, which is precisely the C's "unlink, then run
    // the destructor". `is_some` reports what the C could not.
    list.remove(index).is_some()
}

/// Drops every element from the back forwards, leaving the collection empty.
///
/// ```c
/// while(list->_size > 0)
///   Curl_node_uremove(list->_tail, user);
/// ```
///
/// # Examples
///
/// ```ignore
/// let mut list: VecDeque<u8> = VecDeque::from([1, 2, 3]);
/// dispose_tail_first(&mut list); // drops 3, then 2, then 1
/// assert!(list.is_empty());
/// ```
#[allow(dead_code)]
pub(crate) fn dispose_tail_first<T>(list: &mut VecDeque<T>) {
    // Each popped value is dropped at the end of the loop condition, before
    // the next is taken, so the disposal order is exactly the removal order.
    // `drain(..).rev()` would look equivalent and is not: abandoning that
    // iterator early drops the remainder in the drain's own order, whereas
    // this loop has no remainder to abandon.
    while list.pop_back().is_some() {}
}

// TESTS
//
// Every assertion the C test makes is ported below, and three things it could
// not check are added, each because the migration makes them checkable:
//
//   1. THE NULL-ANCHOR PREPEND ON A NON-EMPTY COLLECTION. The C test never
//      reaches it. Its case 3 is captioned "list has >1 element, adding one
//      element after \"NULL\"" (`unit1300.c:116-123`) and then passes
//      `Curl_llist_head(&llist)` (`:125`) -- the caption describes a test the
//      code does not perform, so the one branch most likely to be got
//      backwards is the one branch `unit1300.c` leaves uncovered. Three tests
//      below cover it.
//   2. DISPOSAL, DISTINCTLY FROM TRANSFER. The C's registered destructor is
//      `test_Curl_llist_dtor` (`unit1300.c:29-34`), whose entire body is
//      `(void)key; (void)value;`. Recording nothing, it cannot tell a
//      disposal from an ownership transfer, so the C cannot test the
//      `Curl_node_take_elem` contract at all. `T`'s own `Drop` can.
//   3. THAT EVERY ELEMENT IS DISPOSED OF EXACTLY ONCE. This is what the
//      `_init` sentinels of `lib/llist.c:29-31` existed to approximate, by
//      catching a node reused after removal. A drop count states it directly.

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A payload that records its own disposal in a shared log.
    ///
    /// Supersedes `test_Curl_llist_dtor` (`tests/unit/unit1300.c:29-34`) and
    /// carries no context pointer, because a Rust destructor reaches whatever
    /// it borrowed -- which is the whole of construct 6 in the module
    /// documentation, demonstrated rather than asserted.
    struct Tracked<'log> {
        id: u64,
        log: &'log Cell<u64>,
    }

    impl<'log> Tracked<'log> {
        fn new(id: u64, log: &'log Cell<u64>) -> Self {
            Self { id, log }
        }
    }

    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            // Decimal accumulation records how many disposals happened AND the
            // order they happened in, which two separate counters could not:
            // 3 then 2 then 1 leaves 321, and 1 then 2 then 3 leaves 123.
            // Every identifier used below is a single non-zero digit, so no
            // carry can conflate two disposals and a leading zero cannot hide
            // one.
            self.log.set(self.log.get() * 10 + self.id);
        }
    }

    /// The collection's contents, for comparison against a literal.
    ///
    /// The C compares payload identity -- `Curl_node_elem(head) ==
    /// &unusedData_case1` -- because its elements are borrowed pointers. Here
    /// the collection owns its elements, so the ported assertions compare
    /// values, using the same 1, 2, 3 the C test uses.
    fn ids(list: &VecDeque<i32>) -> Vec<i32> {
        list.iter().copied().collect()
    }

    /// The identifiers of a tracked collection, in order.
    fn tracked_ids(list: &VecDeque<Tracked<'_>>) -> Vec<u64> {
        list.iter().map(|item| item.id).collect()
    }

    // --- ported: `Curl_llist_init` (`unit1300.c:59-75`) ---------------------

    /// The C's four documented assumptions for an initialised list: size 0,
    /// null head, null tail, and -- untested there because it has no accessor
    /// -- a null destructor. The fourth has no counterpart at all: there is
    /// nothing to register, so nothing can be left unregistered.
    #[test]
    fn a_new_collection_is_empty_with_no_front_and_no_back() {
        let list: VecDeque<i32> = VecDeque::new();

        assert_eq!(list.len(), 0, "initial size should be zero");
        assert!(list.is_empty());
        assert!(list.front().is_none(), "front should start absent");
        assert!(list.back().is_none(), "back should start absent");
    }

    // --- ported: `Curl_llist_insert_next` (`unit1300.c:77-132`) -------------

    /// Case 1: inserting into an empty collection. The C passes
    /// `Curl_llist_head(&llist)`, which on an empty list is `NULL`, so the
    /// anchor is [`None`] here.
    #[test]
    fn insert_after_none_into_an_empty_collection_sets_front_and_back() {
        let mut list: VecDeque<i32> = VecDeque::new();

        assert!(insert_after(&mut list, None, 1).is_ok());

        assert_eq!(list.len(), 1, "size should be 1 after one insertion");
        assert_eq!(list.front(), Some(&1), "front should be the first entry");
        assert_eq!(
            list.back(),
            list.front(),
            "back and front should be the same"
        );
    }

    /// Cases 2 and 3: with one element, then with more than one, inserting
    /// after the front. The C checks that `next(head)` is the new element and
    /// that the back is set correctly in the first case and left alone in the
    /// second.
    #[test]
    fn insert_after_the_front_lands_between_front_and_its_successor() {
        let mut list: VecDeque<i32> = VecDeque::new();
        assert!(insert_after(&mut list, None, 1).is_ok());

        // Case 2: one element, insert after the front.
        assert!(insert_after(&mut list, Some(0), 3).is_ok());
        assert_eq!(ids(&list), [1, 3], "the element after the front is wrong");
        assert_eq!(list.back(), Some(&3), "the back is wrong");

        // Case 3: more than one element, insert after the front again.
        assert!(insert_after(&mut list, Some(0), 2).is_ok());
        assert_eq!(ids(&list), [1, 2, 3], "the new element is misplaced");
        assert_ne!(list.back(), Some(&2), "the back should not have moved");
        assert_eq!(list.back(), Some(&3), "the back should still be the 3");
    }

    // --- the null-anchor branch `unit1300.c` never reaches ------------------

    /// `lib/llist.c:89-94`: a null anchor prepends whether or not the
    /// collection already has elements. This is the branch the C test's case 3
    /// describes in its caption and does not perform.
    #[test]
    fn a_none_anchor_prepends_to_a_non_empty_collection() {
        let mut list: VecDeque<i32> = VecDeque::from([2, 3]);

        assert!(insert_after(&mut list, None, 1).is_ok());

        assert_eq!(ids(&list), [1, 2, 3], "a null anchor must prepend");
        assert_eq!(list.front(), Some(&1));
        assert_eq!(list.back(), Some(&3), "prepending must not touch the back");
    }

    /// The anchor is the position *after* which the value lands, so anchoring
    /// on the last position appends. This is `Curl_llist_append`'s own
    /// implementation: it is a single call to
    /// `Curl_llist_insert_next(list, list->_tail, ...)` (`lib/llist.c:123`).
    #[test]
    fn insert_after_the_last_position_appends() {
        let mut list: VecDeque<i32> = VecDeque::from([1, 2]);

        // The length is bound first because the mutable borrow of `list` in
        // the call would otherwise conflict with reading its length inside the
        // same expression. Worth noting rather than hiding: a consumer would
        // write `push_back` here instead, and this spelling exists only to
        // prove the two agree.
        let last = list.len() - 1;
        assert!(insert_after(&mut list, Some(last), 3).is_ok());

        assert_eq!(ids(&list), [1, 2, 3]);
        assert_eq!(list.back(), Some(&3), "the new element becomes the back");
    }

    /// An anchor the collection does not have hands the value back instead of
    /// dropping it or panicking. The C cannot detect this case: it never
    /// verifies that the node it is given belongs to the list.
    #[test]
    fn insert_after_an_unknown_anchor_returns_the_value() {
        let mut list: VecDeque<i32> = VecDeque::from([1, 2]);

        assert_eq!(insert_after(&mut list, Some(2), 9), Err(9));
        assert_eq!(insert_after(&mut list, Some(usize::MAX), 9), Err(9));
        assert_eq!(ids(&list), [1, 2], "a rejected insertion changes nothing");

        // And on an empty collection, where no position exists at all.
        let mut empty: VecDeque<i32> = VecDeque::new();
        assert_eq!(insert_after(&mut empty, Some(0), 9), Err(9));
        assert!(empty.is_empty());
    }

    /// A rejected insertion must not run the value's destructor either: the
    /// value is handed back, so its lifetime is the caller's again.
    #[test]
    fn a_rejected_insertion_does_not_dispose_of_the_value() {
        let log = Cell::new(0_u64);
        let mut list: VecDeque<Tracked<'_>> = VecDeque::new();

        let returned = insert_after(&mut list, Some(3), Tracked::new(1, &log));

        assert!(returned.is_err(), "position 3 does not exist");
        assert_eq!(log.get(), 0, "the value must not have been disposed of");
        drop(returned);
        assert_eq!(
            log.get(),
            1,
            "and it is disposed of when the caller lets go"
        );
    }

    // --- ported: `Curl_node_remove` (`unit1300.c:134-216`) ------------------

    /// All four C removal cases in sequence, against the same collection the C
    /// builds. The link-surgery assertions -- "element->previous->next will be
    /// element->next" and its mirror -- have no counterpart, because
    /// contiguity is the container's own invariant rather than something a
    /// caller maintains; what is asserted instead is the observable
    /// consequence, that the survivors keep their order and adjacency.
    #[test]
    fn dispose_reproduces_the_four_unit1300_removal_cases() {
        // The C's state at this point: [1, 2, 3].
        let mut list: VecDeque<i32> = VecDeque::new();
        assert!(insert_after(&mut list, None, 1).is_ok());
        assert!(insert_after(&mut list, Some(0), 3).is_ok());
        assert!(insert_after(&mut list, Some(0), 2).is_ok());
        assert_eq!(ids(&list), [1, 2, 3]);

        // Case 1: more than one element, remove the front.
        let successor = list[1];
        let size = list.len();
        assert!(dispose(&mut list, 0), "the front was there to remove");
        assert_eq!(list.len(), size - 1, "size not decremented as expected");
        assert_eq!(list.front(), Some(&successor), "wrong new front");
        assert_eq!(ids(&list), [2, 3]);

        // Case 2: remove a non-front element with at least two present. The C
        // first inserts a fourth element after the front to get back to three.
        assert!(insert_after(&mut list, Some(0), 3).is_ok());
        assert_eq!(list.len(), 3, "should be 3 members");
        assert_eq!(ids(&list), [2, 3, 3]);
        assert!(dispose(&mut list, 1), "the middle was there to remove");
        assert_eq!(
            ids(&list),
            [2, 3],
            "the neighbours of a removed element must close up"
        );

        // Case 3: remove the back with at least one element present.
        let penultimate = list[list.len() - 2];
        let last = list.len() - 1;
        assert!(dispose(&mut list, last));
        assert_eq!(
            list.back(),
            Some(&penultimate),
            "the back is not adjusted when removing the back"
        );
        assert_eq!(ids(&list), [2]);

        // Case 4: remove the front with exactly one element present.
        assert!(dispose(&mut list, 0));
        assert!(
            list.front().is_none(),
            "front is set while the list is empty"
        );
        assert!(list.back().is_none(), "back is set while the list is empty");
        assert!(list.is_empty());
    }

    // --- ported: `Curl_llist_append` (`unit1300.c:218-264`) -----------------

    /// The C's three append cases: into an empty list, into a non-empty one,
    /// and into one with two members, checking each time that the front's
    /// successor is what it should be and that the back is the new element.
    #[test]
    fn push_back_reproduces_the_three_unit1300_append_cases() {
        let mut list: VecDeque<i32> = VecDeque::new();

        // Case 1: empty.
        list.push_back(1);
        assert_eq!(list.len(), 1, "size should be 1 after one append");
        assert_eq!(list.front(), Some(&1), "front should be the first entry");
        assert_eq!(list.back(), list.front(), "back and front should agree");

        // Case 2: not empty.
        list.push_back(2);
        assert_eq!(ids(&list), [1, 2], "the front's successor is wrong");
        assert_eq!(list.back(), Some(&2), "the back is wrong");

        // Case 3: two members already.
        list.push_back(3);
        assert_eq!(list[1], 2, "the front's successor should not have changed");
        assert_eq!(list.back(), Some(&3), "the back should be the new element");
        assert_eq!(ids(&list), [1, 2, 3], "append must preserve order");
    }

    // --- ported: `Curl_llist_destroy` (`unit1300.c:266-267`) ----------------

    /// The C destroys two lists, and the second -- `llist_destination` -- is
    /// initialised at `:57` and never used, so the call is a tear-down of an
    /// empty list. Both spellings of that must be harmless here.
    #[test]
    fn disposing_of_an_empty_collection_is_harmless() {
        let mut untouched: VecDeque<i32> = VecDeque::new();

        dispose_tail_first(&mut untouched);
        untouched.clear();

        assert!(untouched.is_empty());
        assert!(!dispose(&mut untouched, 0), "there is nothing at index 0");
        assert_eq!(untouched.remove(0), None, "nor anything to take");
    }

    // --- take versus dispose: the distinction the C test cannot make --------

    /// `Curl_node_take_elem` *"Will NOT invoke a registered `dtor`"*
    /// (`lib/llist.h:75-77`). Its successor is [`VecDeque::remove`], and the
    /// value it yields is the caller's -- as at `lib/vtls/vtls_scache.c:893`,
    /// where a TLS session is handed out of a cache whose destructor would
    /// have freed it.
    #[test]
    fn remove_transfers_ownership_and_disposes_of_nothing() {
        let log = Cell::new(0_u64);
        let mut list: VecDeque<Tracked<'_>> = VecDeque::new();
        list.push_back(Tracked::new(1, &log));
        list.push_back(Tracked::new(2, &log));
        list.push_back(Tracked::new(3, &log));

        let taken = list.remove(1).expect("index 1 is occupied");

        assert_eq!(taken.id, 2, "the value itself is returned");
        assert_eq!(log.get(), 0, "taking must not run the destructor");
        assert_eq!(tracked_ids(&list), [1, 3], "and the element is gone");

        // The caller now owns it, so disposal happens when the caller says so.
        drop(taken);
        assert_eq!(log.get(), 2, "disposed of once, by the caller");
    }

    /// `Curl_node_remove` *does* invoke the destructor, via
    /// `Curl_node_uremove` (`lib/llist.c:185-187`).
    #[test]
    fn dispose_runs_the_destructor_exactly_once() {
        let log = Cell::new(0_u64);
        let mut list: VecDeque<Tracked<'_>> = VecDeque::new();
        list.push_back(Tracked::new(1, &log));
        list.push_back(Tracked::new(2, &log));
        list.push_back(Tracked::new(3, &log));

        assert!(dispose(&mut list, 1), "index 1 was occupied");

        assert_eq!(log.get(), 2, "the 2 was disposed of, and only the 2");
        assert_eq!(tracked_ids(&list), [1, 3]);
    }

    /// Out-of-range removal is reported, not fatal, in both spellings. The C
    /// tolerates a null node by returning early (`lib/llist.c:130-131` and
    /// `:179-180`) and has no way to report anything.
    #[test]
    fn out_of_range_removal_is_reported_and_never_panics() {
        let log = Cell::new(0_u64);
        let mut list: VecDeque<Tracked<'_>> = VecDeque::new();
        list.push_back(Tracked::new(1, &log));

        assert!(!dispose(&mut list, 1), "index 1 does not exist");
        assert!(!dispose(&mut list, usize::MAX), "nor does the last index");
        assert!(list.remove(1).is_none(), "nor is there anything to take");
        assert_eq!(log.get(), 0, "a failed removal disposes of nothing");
        assert_eq!(list.len(), 1, "and changes nothing");

        let mut empty: VecDeque<Tracked<'_>> = VecDeque::new();
        assert!(!dispose(&mut empty, 0));
        assert!(empty.remove(0).is_none());
    }

    // --- disposal order, and the divergence from the C ----------------------

    /// The leak-and-double-free test the `_init` sentinels approximated: every
    /// element is disposed of exactly once when the collection goes away.
    #[test]
    fn dropping_the_collection_disposes_of_every_element_exactly_once() {
        let log = Cell::new(0_u64);
        {
            let mut list: VecDeque<Tracked<'_>> = VecDeque::new();
            list.push_back(Tracked::new(1, &log));
            list.push_back(Tracked::new(2, &log));
            list.push_back(Tracked::new(3, &log));
            assert_eq!(log.get(), 0, "nothing is disposed of while in scope");
        }

        // Three digits: three disposals, no more and no fewer. Front to back,
        // which is the divergence from `Curl_llist_destroy` recorded in the
        // module documentation.
        assert_eq!(log.get(), 123, "front-to-back, exactly once each");
    }

    /// [`VecDeque::clear`] has the same order as dropping the collection, and
    /// is the successor to use when the order does not matter -- which, per the
    /// audit in the module documentation, is every consumer that exists.
    #[test]
    fn clear_disposes_front_to_back() {
        let log = Cell::new(0_u64);
        let mut list: VecDeque<Tracked<'_>> = VecDeque::new();
        list.push_back(Tracked::new(1, &log));
        list.push_back(Tracked::new(2, &log));
        list.push_back(Tracked::new(3, &log));

        list.clear();

        assert_eq!(log.get(), 123, "front to back");
        assert!(list.is_empty());
    }

    /// `Curl_llist_destroy` removes from the tail (`lib/llist.c:200-201`), so
    /// destructors run in reverse insertion order. [`dispose_tail_first`]
    /// reproduces that exactly, and this test is the reason the helper exists:
    /// it makes the divergence a checked property rather than a remark.
    #[test]
    fn dispose_tail_first_disposes_in_reverse_insertion_order() {
        let log = Cell::new(0_u64);
        let mut list: VecDeque<Tracked<'_>> = VecDeque::new();
        list.push_back(Tracked::new(1, &log));
        list.push_back(Tracked::new(2, &log));
        list.push_back(Tracked::new(3, &log));

        dispose_tail_first(&mut list);

        assert_eq!(
            log.get(),
            321,
            "reverse insertion order, exactly once each"
        );
        assert!(list.is_empty(), "the collection is left empty");
    }

    /// And the two orders really are different, which is what makes the
    /// divergence worth documenting: the same three elements leave two
    /// distinguishable traces.
    #[test]
    fn the_two_disposal_orders_are_distinguishable() {
        let forwards = Cell::new(0_u64);
        let backwards = Cell::new(0_u64);

        let mut a: VecDeque<Tracked<'_>> = VecDeque::new();
        let mut b: VecDeque<Tracked<'_>> = VecDeque::new();
        for id in 1..=3 {
            a.push_back(Tracked::new(id, &forwards));
            b.push_back(Tracked::new(id, &backwards));
        }

        a.clear();
        dispose_tail_first(&mut b);

        assert_eq!(forwards.get(), 123);
        assert_eq!(backwards.get(), 321);
        assert_ne!(forwards.get(), backwards.get());
    }

    // --- the three consumer shapes the survey found -------------------------

    /// `Curl_llist_count` (30 call sites) becomes [`VecDeque::len`], with
    /// [`VecDeque::is_empty`] for the emptiness tests it is used for.
    #[test]
    fn len_and_is_empty_track_additions_and_removals() {
        let mut list: VecDeque<i32> = VecDeque::new();
        assert_eq!(list.len(), 0);
        assert!(list.is_empty());

        list.push_back(1);
        list.push_back(2);
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());

        assert!(insert_after(&mut list, None, 0).is_ok());
        assert_eq!(list.len(), 3);

        assert!(dispose(&mut list, 0));
        assert_eq!(list.len(), 2);

        assert!(list.remove(0).is_some());
        assert_eq!(list.len(), 1);

        dispose_tail_first(&mut list);
        assert_eq!(list.len(), 0);
        assert!(list.is_empty());
    }

    /// `Curl_llist_head` (58 sites) and `Curl_llist_tail` become
    /// [`VecDeque::front`] and [`VecDeque::back`].
    #[test]
    fn front_and_back_report_the_first_and_last_elements() {
        let mut list: VecDeque<i32> = VecDeque::from([1, 2, 3]);

        assert_eq!(list.front(), Some(&1));
        assert_eq!(list.back(), Some(&3));

        assert!(dispose(&mut list, 0));
        assert_eq!(list.front(), Some(&2), "the front moves up");
        assert_eq!(list.back(), Some(&3), "the back is unaffected");

        list.clear();
        assert_eq!(list.front(), None);
        assert_eq!(list.back(), None);
    }

    /// The queue shape: nineteen of the C's twenty `Curl_node_remove` sites
    /// walk and remove, and `curl_multi_info_read` (`lib/multi.c:2943`) takes
    /// the head of the message queue. [`VecDeque::push_back`] and
    /// [`VecDeque::pop_front`] are that, with the drain loop of
    /// `lib/cshutdn.c:280` alongside.
    #[test]
    fn a_queue_is_push_back_and_pop_front() {
        let mut queue: VecDeque<i32> = VecDeque::new();
        queue.push_back(1);
        queue.push_back(2);
        queue.push_back(3);

        assert_eq!(queue.pop_front(), Some(1), "first in, first out");
        assert_eq!(queue.pop_front(), Some(2));

        let mut drained = Vec::new();
        while let Some(item) = queue.pop_front() {
            drained.push(item);
        }
        assert_eq!(drained, [3]);
        assert_eq!(queue.pop_front(), None, "and the empty queue yields none");
    }

    /// Removal by identity: [`Iterator::position`] then [`dispose`], or
    /// [`VecDeque::retain`] for a predicate over many. Never a node handle,
    /// which is what makes the `_list` back-pointer unnecessary.
    #[test]
    fn removal_by_identity_is_position_then_dispose() {
        let mut list: VecDeque<i32> = VecDeque::from([10, 20, 30, 40]);

        let at = list.iter().position(|item| *item == 30);
        assert_eq!(at, Some(2));
        assert!(dispose(&mut list, at.expect("30 is present")));
        assert_eq!(ids(&list), [10, 20, 40]);

        assert_eq!(list.iter().position(|item| *item == 30), None);

        list.retain(|item| *item != 20);
        assert_eq!(ids(&list), [10, 40]);
    }

    /// `Curl_node_next` (42 sites) and `Curl_node_prev` become iteration in
    /// each direction; `Curl_node_elem` (51 sites) collapses entirely, because
    /// an iterator yields the element rather than a node wrapping it.
    #[test]
    fn iteration_replaces_the_node_walk_in_both_directions() {
        let list: VecDeque<i32> = VecDeque::from([1, 2, 3]);

        assert_eq!(list.iter().copied().collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(list.iter().rev().copied().collect::<Vec<_>>(), [3, 2, 1]);

        // The C walk terminates when `Curl_node_next` returns NULL, so it can
        // in principle visit an element twice or none. Summing proves each was
        // visited exactly once without asserting the length twice over.
        assert_eq!(list.iter().sum::<i32>(), 6);
    }

    /// The sorted insert of `lib/multi.c:3493-3527`, end to end, because it is
    /// the only production caller of `Curl_llist_insert_next` and it reaches
    /// the null-anchor branch by design. `prev` starts as `NULL` (`:3499`) and
    /// stays null when the collection is empty or the new value sorts ahead of
    /// the front.
    #[test]
    fn the_sorted_insert_of_multi_addtimeout_still_works() {
        fn add(list: &mut VecDeque<u32>, stamp: u32) {
            // `lib/multi.c:3512-3518`: walk while the existing stamp is not
            // later than the new one, remembering the last position passed.
            let mut anchor = None;
            for (index, existing) in list.iter().enumerate() {
                if *existing > stamp {
                    break;
                }
                anchor = Some(index);
            }
            assert!(insert_after(list, anchor, stamp).is_ok());
        }

        let mut timeouts: VecDeque<u32> = VecDeque::new();

        add(&mut timeouts, 50); // empty: the null-anchor branch
        add(&mut timeouts, 70); // after the only element
        add(&mut timeouts, 10); // sorts ahead of the front: null again
        add(&mut timeouts, 60); // into the middle
        add(&mut timeouts, 10); // equal to the front: after it, per `> stamp`

        assert_eq!(
            timeouts.iter().copied().collect::<Vec<_>>(),
            [10, 10, 50, 60, 70],
            "the head of the list must be the timeout nearest in time"
        );
    }
}
