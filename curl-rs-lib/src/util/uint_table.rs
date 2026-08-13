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

// THE LICENCE BANNER ABOVE -- 23 lines, the form measured at `lib/llist.c:1-23`
// rendered as Rust line comments, byte-identical to the block at the head of
// `crate::util`'s own `mod.rs`. `reuse lint` runs in continuous integration and
// wants a licence-identifier tag naming `curl`; line 21 is it.

//! The integer-keyed transfer table: the slab that assigns `mid`.
//!
//! Supersedes `lib/uint-table.c` and `lib/uint-table.h`, whose eleven public
//! functions and two file-static helpers are reproduced here in full. It is a
//! fixed-capacity array of rows addressed directly by an unsigned 32-bit key,
//! and it hands those keys out ITSELF rather than accepting them from a
//! caller. That is the whole reason it exists, and the reason it is not a hash
//! map.
//!
//! # Flagged for whoever ports `lib/multi.c`: the destructor is NULL
//!
//! `lib/multi.c:245` is the only `Curl_uint32_tbl_init` call in the tree and
//! it passes **NULL** for `entry_dtor`. The C table therefore deliberately
//! does NOT own its entries: the multi handle keeps its easy handles alive
//! elsewhere and wants nothing destroyed when a row is vacated.
//!
//! In Rust the destructor becomes `Drop` on the entry type, so ownership
//! follows from the choice of that type and this module cannot decide it. If
//! the ported multi handle wants the C's non-owning behaviour, the entry type
//! must be a handle, an index or another `Copy` key rather than an owned easy
//! handle. This is raised, not resolved -- it belongs to the module that
//! instantiates the table.
//!
//! # Layering
//!
//! `crate::util` is the base of this crate's module graph and depends on
//! nothing above it. This file imports exactly one internal item,
//! [`crate::error::CURLcode`], for [`Uint32Tbl::resize`]'s error type, and no
//! external crate at all.

use crate::error::CURLcode;

/// The one key value the table never assigns, and the initial
/// `last_key_added`.
const NO_KEY: u32 = u32::MAX;

/// One occupied row: the caller's entry, plus the generation that dates it.
struct Row<T> {
    /// The value the caller handed to [`Uint32Tbl::add`].
    entry: T,
    /// The value of [`Uint32Tbl::next_generation`] at the moment this row was
    /// filled. Unique across the table's whole lifetime, so a [`Key`] carrying
    /// a different stamp for the same index is stale by definition.
    generation: u64,
}

/// Obtained from [`Uint32Tbl::key_of`] and consumed by
/// [`Uint32Tbl::get_checked`], [`Uint32Tbl::get_checked_mut`],
/// [`Uint32Tbl::contains_key`] and [`Uint32Tbl::remove_key`]. The usual
/// sequence is to `add`, then ask for the key of the index just returned:
///
/// ```text
/// let mid = table.add(entry)?;        // the `mid`, exactly as the C assigns
/// let key = table.key_of(mid)?;       // the same row, now dated
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) struct Key {
    /// The row index. This is the plain `u32` key -- the `mid` -- and it is
    /// never combined with, packed against, or derived from the generation.
    index: u32,
    /// The stamp the row carried when this key was issued.
    generation: u64,
}

#[allow(dead_code)]
impl Key {
    /// The plain row index, which is the `mid`.
    ///
    /// Present so that a holder of a [`Key`] can reach the integer the C would
    /// have handed it -- for trace output, or to call one of the unchecked
    /// accessors -- without this module having to expose the field.
    pub(crate) const fn index(self) -> u32 {
        self.index
    }

    /// The generation stamp this key was issued with.
    ///
    /// Useful for diagnostics: two keys with the same [`Self::index`] and
    /// different generations name two different occupants of one row.
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

/// A fixed-capacity table of entries addressed by a `u32` key that the table
/// assigns itself.
///
/// Supersedes `struct uint32_tbl` (`lib/uint-table.h:31-40`). The C's `nrows`
/// has no field here because `rows.len()` already is it: a second copy would
/// be a second source of truth, and the two could disagree.
#[allow(dead_code)]
pub(crate) struct Uint32Tbl<T> {
    /// The rows, indexed directly by key. `None` is a vacant row, which is the
    /// C's NULL. Never reordered, never sorted, and never compacted -- the
    /// index IS the key.
    rows: Vec<Option<Row<T>>>,
    /// The cached number of occupied rows, mirroring `nentries`. Maintained by
    /// [`Self::place`] and [`Self::clear_rows`] and by nothing else, so the
    /// invariant "this equals the number of `Some` rows" has exactly two
    /// places to hold.
    nentries: u32,
    /// The key most recently assigned, or [`NO_KEY`] when none has been.
    /// The round-robin cursor; see [`Self::add`].
    last_key_added: u32,
    /// The stamp the next filled row will carry. Advances on every occupancy
    /// change, so no value is ever issued twice.
    next_generation: u64,
}

impl<T> Default for Uint32Tbl<T> {
    /// Delegates to [`Self::new`], and must keep doing so.
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl<T> Uint32Tbl<T> {
    /// An empty table of zero capacity: `Curl_uint32_tbl_init`
    /// (`lib/uint-table.c:35-44`).
    pub(crate) const fn new() -> Self {
        Self {
            rows: Vec::new(),
            nentries: 0,
            // NOT zero. This is the assignment that makes the first key 0.
            last_key_added: NO_KEY,
            next_generation: 0,
        }
    }

    /// The table capacity: `Curl_uint32_tbl_capacity`
    /// (`lib/uint-table.c:101-104`), which returns `nrows`.
    ///
    /// The cast is lossless. [`Self::resize`] is the only thing that changes
    /// the length and its argument is a `u32`, so the length can never exceed
    /// `u32::MAX`.
    pub(crate) fn capacity(&self) -> u32 {
        self.rows.len() as u32
    }

    /// The number of occupied rows: `Curl_uint32_tbl_count`
    /// (`lib/uint-table.c:106-109`), which returns the cached `nentries`
    /// rather than counting.
    pub(crate) const fn count(&self) -> u32 {
        self.nentries
    }

    /// Whether the table holds no entries.
    ///
    /// No C counterpart -- the C spells this `!Curl_uint32_tbl_count(tbl)`, as
    /// at `lib/multi.c:2916`. It is written out because a type offering a
    /// count and no emptiness test reads oddly in Rust, and because
    /// [`Self::first`] uses it for the short-circuit the C performs inline.
    pub(crate) const fn is_empty(&self) -> bool {
        self.nentries == 0
    }

    /// Resize the table: `Curl_uint32_tbl_resize`
    /// (`lib/uint-table.c:63-83`).
    ///
    /// # Errors
    ///
    /// * [`CURLcode::BadFunctionArgument`] when `nrows` is zero. A zero
    ///   capacity is NOT a valid empty table here, which is a real difference
    ///   from the integer-keyed bitsets, where it is legal. The C's own
    ///   justification sits immediately above the check at
    ///   `lib/uint-table.c:65`: "we use `tbl->nrows + 1` during iteration,
    ///   want that to work" -- a reference to the `nrows + 1` that
    ///   [`Self::add`] can compute for its scan cursor.
    /// * [`CURLcode::OutOfMemory`] when the growth cannot be allocated. The C
    ///   allocates the new array BEFORE touching the table, so a failure
    ///   leaves the table exactly as it was; `Vec::try_reserve` reproduces
    ///   that ordering, and the subsequent extension cannot reallocate because
    ///   the capacity is already reserved. `vec![None; n]` would abort the
    ///   process instead of reporting, discarding the C's error path
    ///   altogether.
    ///
    /// Three further behaviours are load-bearing and each has a test:
    ///
    /// * A same-size resize is a COMPLETE no-op, contents included -- the C
    ///   guards the whole body with `if(nrows != tbl->nrows)`.
    /// * Growth zero-fills the new rows, from the C's `calloc` plus a `memcpy`
    ///   of only `CURLMIN(nrows, tbl->nrows)` entries.
    /// * `last_key_added` is NOT reset, unlike in [`Self::clear`]. Growing a
    ///   table does not restart the round-robin, and shrinking can leave the
    ///   cursor above the new capacity -- which is exactly what the
    ///   `min(last_key_added, capacity)` clamp in [`Self::add`] exists to
    ///   absorb, in addition to absorbing the [`NO_KEY`] sentinel.
    ///
    /// One deliberate divergence, invisible through this API: the C frees the
    /// old array and allocates one of exactly `nrows`, whereas shrinking here
    /// truncates and keeps the surplus allocation. `Vec::shrink_to_fit` is not
    /// called because it aborts on allocation failure rather than reporting,
    /// which would undo the whole reason `try_reserve` is used above. Capacity
    /// is reported from `rows.len()`, so [`Self::capacity`] answers
    /// identically either way, and the consumer never shrinks this table --
    /// `lib/multi.c:398` only ever resizes when `new_size > capacity`.
    pub(crate) fn resize(&mut self, nrows: u32) -> Result<(), CURLcode> {
        if nrows == 0 {
            return Err(CURLcode::BadFunctionArgument);
        }
        let current = self.capacity();
        if nrows == current {
            return Ok(());
        }
        if nrows < current {
            // Drop the entries at or above the new capacity first, so that
            // `Drop` runs and the count is decremented for each, and only
            // then discard the rows themselves. Doing it the other way round
            // would still drop the entries -- `Vec::truncate` does -- but it
            // would leave `nentries` overstating the table.
            self.clear_rows(nrows, current);
            self.rows.truncate(nrows as usize);
            return Ok(());
        }
        // `nrows > current`, so the difference is positive and fits a `usize`
        // on every 64-bit target.
        let extra = (nrows - current) as usize;
        self.rows
            .try_reserve(extra)
            .map_err(|_| CURLcode::OutOfMemory)?;
        self.rows.resize_with(nrows as usize, || None);
        Ok(())
    }

    /// Empty the table: `Curl_uint32_tbl_clear` (`lib/uint-table.c:93-99`).
    pub(crate) fn clear(&mut self) {
        let capacity = self.capacity();
        self.clear_rows(0, capacity);
        debug_assert_eq!(
            self.nentries, 0,
            "clearing every row must leave the count at zero"
        );
        self.last_key_added = NO_KEY;
    }

    /// The entry stored under `key`, or `None`: `Curl_uint32_tbl_get`
    /// (`lib/uint-table.c:111-114`), whose body is
    /// `(key < tbl->nrows) ? tbl->rows[key] : NULL`.
    pub(crate) fn get(&self, key: u32) -> Option<&T> {
        self.row(key).map(|row| &row.entry)
    }

    /// [`Self::get`] with a mutable borrow of the entry.
    pub(crate) fn get_mut(&mut self, key: u32) -> Option<&mut T> {
        self.rows
            .get_mut(key as usize)?
            .as_mut()
            .map(|row| &mut row.entry)
    }

    /// Whether `key` names an occupied row: `Curl_uint32_tbl_contains`
    /// (`lib/uint-table.c:157-160`), whose body is
    /// `(key < tbl->nrows) ? !!tbl->rows[key] : FALSE`.
    ///
    /// Load-bearing rather than a convenience: `lib/multi.c:449-450` tests
    /// "only the admin handle remains" as `count() != 1 || !contains(0)`.
    pub(crate) fn contains(&self, key: u32) -> bool {
        self.row(key).is_some()
    }

    /// Store `entry` in a free row and return the key assigned to it, or
    /// `None` when the table is full: `Curl_uint32_tbl_add`
    /// (`lib/uint-table.c:116-150`).
    ///
    /// `lib/uint-table.h:64-68` is the contract:
    ///
    /// > Add a new entry to the table and assign it a free key. Returns FALSE
    /// > if the table is full.
    /// >
    /// > Keys are assigned in a round-robin manner. No matter the capacity,
    /// > UINT_MAX is never assigned.
    ///
    /// # The algorithm, transcribed
    ///
    /// ```text
    /// if(!entry || !pkey) return FALSE;
    /// *pkey = UINT32_MAX;
    /// if(tbl->nentries == tbl->nrows) return FALSE;         /* full */
    ///
    /// start_pos = CURLMIN(tbl->last_key_added, tbl->nrows) + 1;
    ///
    /// for(key = start_pos; key < tbl->nrows; ++key)         /* scan upward */
    ///   if(!tbl->rows[key]) { ...take it...; return TRUE; }
    /// /* no free entry at or above tbl->maybe_next_key, wrap around */
    /// for(key = 0; key < start_pos; ++key)                  /* then wrap */
    ///   if(!tbl->rows[key]) { ...take it...; return TRUE; }
    /// DEBUGASSERT(0);   /* Did not find any free row? Should not happen */
    /// return FALSE;
    /// ```
    ///
    /// Two scans, in that order, and the first vacant row found wins. They are
    /// NOT merged into a single modular scan, because the key sequence is
    /// frozen behaviour and two scans are what produce it. The `or_else`
    /// below is that ordering: the wrap scan runs only when the upward scan
    /// found nothing.
    pub(crate) fn add(&mut self, entry: T) -> Option<u32> {
        let capacity = self.capacity();
        if self.nentries == capacity {
            // Full. Also the "never resized" case, where both are zero.
            return None;
        }

        // `saturating_add` rather than `+`: the clamp already bounds the left
        // operand by `capacity`, and `lib/multi.c:373` bounds the capacity
        // itself by `UINT_MAX - 1`, so a real table can never reach the
        // saturation point. Saturating anyway keeps the expression total
        // instead of relying on a bound another module maintains -- and where
        // the C would wrap to 0 at the theoretical maximum, saturating yields
        // `u32::MAX`, which makes the upward scan empty and the wrap scan
        // cover every row. Both spellings then pick the lowest vacant row,
        // and that case is unreachable in any event: `last_key_added` equals
        // `u32::MAX` only on a fresh or cleared table, where row 0 is vacant.
        let start_pos = self.last_key_added.min(capacity).saturating_add(1);

        let found = self
            .free_row_from(start_pos, capacity)
            .or_else(|| self.free_row_from(0, start_pos));

        match found {
            Some(key) => Some(self.place(key, entry)),
            None => {
                // Unreachable: the test above proved `nentries < capacity`, so
                // some row in `0..capacity` is vacant, and the two scans
                // between them cover exactly that range. The C reaches
                // `DEBUGASSERT(0)` here (`lib/uint-table.c:147-148`) and then
                // returns FALSE; both halves are reproduced. The condition is
                // written as the invariant that would have to have been
                // violated rather than as `false`, which keeps
                // `clippy::assertions_on_constants` quiet and says something
                // useful when it fires.
                debug_assert!(
                    self.nentries == capacity,
                    "no vacant row was found although the table reported \
                     spare capacity: count {} of {capacity}",
                    self.nentries
                );
                None
            }
        }
    }

    /// Remove the entry stored under `key`: `Curl_uint32_tbl_remove`
    /// (`lib/uint-table.c:152-155`), whose whole body is
    /// `uint32_tbl_clear_rows(tbl, key, key + 1)`.
    ///
    /// One divergence, and it is a defect removal rather than a behaviour
    /// change. The C computes `key + 1` in `uint32_t`, so
    /// `remove(UINT32_MAX)` overflows to 0; the resulting range
    /// `for(i = UINT32_MAX; i < CURLMIN(0, nrows); ++i)` is empty and nothing
    /// happens. `checked_add` produces the same no-op without the overflow,
    /// which matters because Rust would panic on it in a debug build.
    pub(crate) fn remove(&mut self, key: u32) {
        // The absent `else` is the `u32::MAX` case: that value is never a
        // valid row index, the C's wrapped bound makes its loop empty, and
        // doing nothing is the same no-op.
        if let Some(upto_excluding) = key.checked_add(1) {
            self.clear_rows(key, upto_excluding);
        }
    }

    /// The occupied row with the smallest key: `Curl_uint32_tbl_first`
    /// (`lib/uint-table.c:177-188`).
    pub(crate) fn first(&self) -> Option<(u32, &T)> {
        if self.is_empty() {
            return None;
        }
        self.next_at(0)
    }

    /// The occupied row with the smallest key greater than `last_key`:
    /// `Curl_uint32_tbl_next` (`lib/uint-table.c:190-200`).
    ///
    /// `lib/uint-table.h:82-92` is a CONTRACT rather than commentary, because
    /// the multi handle adds and completes transfers inside the loop that
    /// walks this table:
    ///
    /// > Get the next key in the table, following `last_key` in natural order.
    /// > Put another way, this is the smallest key greater than `last_key` in
    /// > the table. `last_key` does not have to be present in the table.
    /// >
    /// > Returns FALSE when no such entry is in the table.
    /// >
    /// > This allows to iterate the table while being modified:
    /// > - added keys higher than 'last_key' will be picked up by the
    /// >   iteration.
    /// > - added keys lower than 'last_key' will not show up.
    /// > - removed keys lower or equal to 'last_key' will not show up.
    /// > - removed keys higher than 'last_key' will not be visited.
    ///
    /// # Why this module implements no iterator, and must not
    ///
    /// `Iterator` and `IntoIterator` are deliberately absent. A borrowing
    /// iterator holds the table for as long as the walk lasts, so the
    /// modification the contract above REQUIRES becomes uncompilable -- the
    /// borrow checker would reject exactly the pattern `lib/multi.c:2852-2891`
    /// is written in, where `Curl_uint32_tbl_remove` is called between two
    /// `Curl_uint32_tbl_next` calls. Keeping this a stateless `&self` query
    /// keyed on `last_key` is what lets the caller mutate freely between
    /// steps: each call re-reads the table as it stands.
    pub(crate) fn next(&self, last_key: u32) -> Option<(u32, &T)> {
        self.next_at(last_key.checked_add(1)?)
    }

    /// A dated key for the occupied row `key`, or `None` if it is vacant or
    /// out of range.
    pub(crate) fn key_of(&self, key: u32) -> Option<Key> {
        self.row(key).map(|row| Key {
            index: key,
            generation: row.generation,
        })
    }

    /// [`Self::get`] with the stale-key check: the entry only if `key` still
    /// names the occupant it was issued for.
    pub(crate) fn get_checked(&self, key: Key) -> Option<&T> {
        let row = self.row(key.index)?;
        if row.generation == key.generation {
            Some(&row.entry)
        } else {
            None
        }
    }

    /// [`Self::get_checked`] with a mutable borrow of the entry.
    pub(crate) fn get_checked_mut(&mut self, key: Key) -> Option<&mut T> {
        let row = self.rows.get_mut(key.index as usize)?.as_mut()?;
        if row.generation == key.generation {
            Some(&mut row.entry)
        } else {
            None
        }
    }

    /// Whether `key` still names the occupant it was issued for.
    ///
    /// The generational counterpart of [`Self::contains`]. `false` covers all
    /// three ways a key can fail: the row is vacant, the row has been refilled
    /// by a later [`Self::add`], or the index is out of range after a
    /// shrinking [`Self::resize`].
    pub(crate) fn contains_key(&self, key: Key) -> bool {
        self.get_checked(key).is_some()
    }

    /// Remove the row `key` names, but only if the key is still live.
    pub(crate) fn remove_key(&mut self, key: Key) -> bool {
        if !self.contains_key(key) {
            return false;
        }
        self.remove(key.index);
        true
    }

    /// The occupied row under `key`, or `None` for a vacant or out-of-range
    /// key.
    fn row(&self, key: u32) -> Option<&Row<T>> {
        self.rows.get(key as usize)?.as_ref()
    }

    /// The next generation stamp, advancing the counter.
    fn advance_generation(&mut self) -> u64 {
        let issued = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        issued
    }

    /// Fill the vacant row `key` with `entry` and return `key`.
    ///
    /// # Panics
    ///
    /// The index is written directly rather than through `Vec::get_mut`, so a
    /// key outside the table panics. Both callers obtain `key` from
    /// [`Self::free_row_from`], which only ever yields an in-range index of a
    /// vacant row, so a panic here would mean this module had broken its own
    /// invariant -- and failing loudly beats filling a row that is already
    /// occupied and losing the entry that was in it.
    fn place(&mut self, key: u32, entry: T) -> u32 {
        debug_assert!(
            self.rows.get(key as usize).is_some_and(Option::is_none),
            "a row chosen by the free-row scan must be in range and vacant"
        );
        let generation = self.advance_generation();
        self.rows[key as usize] = Some(Row { entry, generation });
        // Bounded by the capacity, itself a `u32`, so this cannot overflow;
        // saturating keeps it total without an unchecked `+= 1`.
        self.nentries = self.nentries.saturating_add(1);
        self.last_key_added = key;
        key
    }

    /// The lowest vacant row in `from..upto_excluding`, clamped to the
    /// capacity.
    fn free_row_from(&self, from: u32, upto_excluding: u32) -> Option<u32> {
        let end = upto_excluding.min(self.capacity());
        if from >= end {
            return None;
        }
        // In range: `end <= capacity() == rows.len()` and `from < end`. Both
        // widenings follow the comparison rather than preceding it.
        let span = &self.rows[from as usize..end as usize];
        let offset = span.iter().position(Option::is_none)?;
        // `offset < end - from`, so `from + offset < end <= u32::MAX`; the
        // widening of `offset` is lossless for the same reason and the
        // addition cannot saturate.
        Some(from.saturating_add(offset as u32))
    }

    /// The lowest occupied row at or above `from`: `uint32_tbl_next_at`
    /// (`lib/uint-table.c:162-175`).
    fn next_at(&self, from: u32) -> Option<(u32, &T)> {
        let mut key = from;
        for slot in self.rows.iter().skip(from as usize) {
            if let Some(row) = slot {
                return Some((key, &row.entry));
            }
            // Bounded by the capacity, so this cannot overflow; saturating
            // keeps it total.
            key = key.saturating_add(1);
        }
        None
    }

    /// Vacate every occupied row in `from..upto_excluding`, dropping its entry
    /// and decrementing the count: `uint32_tbl_clear_rows`
    /// (`lib/uint-table.c:46-61`).
    ///
    /// ```text
    /// end = CURLMIN(upto_excluding, tbl->nrows);
    /// for(i = from; i < end; ++i)
    ///   if(tbl->rows[i]) {
    ///     if(tbl->entry_dtor) tbl->entry_dtor(i, tbl->rows[i]);
    ///     tbl->rows[i] = NULL; tbl->nentries--;
    ///   }
    /// ```
    fn clear_rows(&mut self, from: u32, upto_excluding: u32) {
        let end = upto_excluding.min(self.capacity());
        if from >= end {
            return;
        }
        // In range for the same reason as in `free_row_from`.
        let span = &mut self.rows[from as usize..end as usize];
        let mut vacated: u32 = 0;
        for slot in span {
            if slot.take().is_some() {
                vacated = vacated.saturating_add(1);
            }
        }
        debug_assert!(
            self.nentries >= vacated,
            "the count must not understate the occupied rows: {} < {vacated}",
            self.nentries
        );
        self.nentries = self.nentries.saturating_sub(vacated);
        self.next_generation =
            self.next_generation.wrapping_add(u64::from(vacated));
    }
}

// No `Drop` implementation, and that is a decision rather than an omission.
//
// `Curl_uint32_tbl_destroy` (`lib/uint-table.c:85-91`) clears the table, frees
// the row array and zeroes the struct. Dropping a `Uint32Tbl<T>` drops its
// `Vec`, which drops every `Some(Row<T>)` still in it, which drops every `T`:
// the same three steps, in the same order, generated by the compiler. Writing
// them out by hand would add a body that can be got wrong -- forgetting a
// field, or dropping twice -- to no end, and an empty `impl Drop` would be
// worse than nothing, because it would silently make `Uint32Tbl<T>` unable to
// be destructured or partially moved.

#[cfg(test)]
mod tests {
    use super::{Uint32Tbl, NO_KEY};
    use crate::error::CURLcode;
    use std::cell::Cell;
    use std::rc::Rc;

    /// `tests/unit/unit3212.c:31`, `#define TBL_SIZE 100`. Every ported
    /// assertion below uses the same number so that a reader can put the two
    /// files side by side.
    const TBL_SIZE: u32 = 100;

    /// The C's `t3212_setup` (`tests/unit/unit3212.c:33-37`): initialise, then
    /// resize to `TBL_SIZE`. Panics on a resize failure, which is the
    /// `UNITTEST_BEGIN` macro's own behaviour when its setup expression
    /// returns non-zero.
    fn setup() -> Uint32Tbl<u32> {
        let mut table = Uint32Tbl::new();
        table
            .resize(TBL_SIZE)
            .expect("resize to TBL_SIZE must succeed");
        table
    }

    /// A payload that counts its own destructions.
    struct Tracked {
        /// Which entry this is, so a test can tell them apart.
        tag: u32,
        /// The shared destruction counter.
        drops: Rc<Cell<u32>>,
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.drops.set(self.drops.get().saturating_add(1));
        }
    }

    /// A factory for [`Tracked`] values sharing one counter.
    fn tracker() -> (Rc<Cell<u32>>, impl Fn(u32) -> Tracked) {
        let drops = Rc::new(Cell::new(0_u32));
        let handle = Rc::clone(&drops);
        (drops, move |tag| Tracked {
            tag,
            drops: Rc::clone(&handle),
        })
    }

    // `tests/unit/unit3212.c`, ported step for step. The line reference on
    // each test names the assertion it reproduces.

    /// `:54` -- the capacity is what `resize` asked for.
    #[test]
    fn capacity_is_what_resize_asked_for() {
        let table = setup();
        assert_eq!(table.capacity(), TBL_SIZE, "wrong capacity");
        assert_eq!(table.count(), 0);
        assert!(table.is_empty());
    }

    /// `:56-59` -- the first `TBL_SIZE` adds yield keys 0, 1, 2, ... 99 in
    /// exactly that order.
    ///
    /// Each key is asserted individually rather than only the final count,
    /// because the SEQUENCE is the contract: these integers become `mid` and
    /// reach trace output.
    #[test]
    fn the_first_hundred_keys_are_zero_through_ninety_nine_in_order() {
        let mut table = setup();
        for expected in 0..TBL_SIZE {
            let key = table.add(expected).expect("failed to add");
            assert_eq!(key, expected, "unexpected key assigned");
        }
    }

    /// `:61-62` -- the table is full, and the next add fails without
    /// disturbing the count.
    #[test]
    fn a_full_table_refuses_further_entries() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        assert_eq!(table.count(), TBL_SIZE, "wrong count");
        assert!(table.add(TBL_SIZE).is_none(), "could add more");
        assert_eq!(
            table.count(),
            TBL_SIZE,
            "a refused add must not change the count"
        );
    }

    /// `:64-69` -- removing every second key decrements the count each time.
    #[test]
    fn removing_every_second_key_decrements_the_count_each_time() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        let mut remaining = TBL_SIZE;
        let mut key = 0;
        while key < TBL_SIZE {
            table.remove(key);
            remaining -= 1;
            assert_eq!(
                table.count(),
                remaining,
                "wrong count after remove of {key}"
            );
            key += 2;
        }
        assert_eq!(remaining, TBL_SIZE / 2);
    }

    /// `:71-74` -- removing the same keys again does not change the count.
    ///
    /// `remove` on an absent key is a silent no-op, and it returns nothing at
    /// all, so this is the only way to observe that it did nothing.
    #[test]
    fn removing_an_absent_key_is_a_silent_no_op() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        let mut key = 0;
        while key < TBL_SIZE {
            table.remove(key);
            key += 2;
        }
        let settled = table.count();
        let mut key = 0;
        while key < TBL_SIZE {
            table.remove(key);
            assert_eq!(
                table.count(),
                settled,
                "wrong count after repeated remove of {key}"
            );
            key += 2;
        }
        // And an out-of-range key is equally inert.
        table.remove(TBL_SIZE);
        table.remove(TBL_SIZE * 10);
        assert_eq!(table.count(), settled);
    }

    /// `:76-80` -- the odd keys still report present and still yield their
    /// entry.
    #[test]
    fn the_odd_keys_survive_and_still_yield_their_entry() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        let mut key = 0;
        while key < TBL_SIZE {
            table.remove(key);
            key += 2;
        }
        let mut key = 1;
        while key < TBL_SIZE {
            assert!(table.contains(key), "does not contain {key}");
            assert_eq!(table.get(key), Some(&key), "wrong entry at {key}");
            key += 2;
        }
        // ... and the even keys do not.
        let mut key = 0;
        while key < TBL_SIZE {
            assert!(!table.contains(key), "does contain {key}");
            assert_eq!(table.get(key), None);
            key += 2;
        }
    }

    /// `:82-92` -- `first` is key 1, `next(1)` is key 3, and `next(42)` is
    /// key 43.
    ///
    /// The last of those is the interesting one: 42 has been removed, which
    /// exercises the header's "`last_key` does not have to be present in the
    /// table".
    #[test]
    fn first_and_next_walk_the_occupied_rows_in_key_order() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        let mut key = 0;
        while key < TBL_SIZE {
            table.remove(key);
            key += 2;
        }
        assert_eq!(table.first(), Some((1, &1)), "unexpected first key");
        assert_eq!(table.next(1), Some((3, &3)), "unexpected second key");
        assert!(!table.contains(42), "42 must be absent for this to bite");
        assert_eq!(table.next(42), Some((43, &43)), "unexpected next42 key");
        // The walk ends rather than wrapping: 99 is the highest odd key.
        assert_eq!(table.next(99), None);
        assert_eq!(table.next(TBL_SIZE), None);
    }

    /// `:95-98` -- doubling the capacity preserves the count.
    #[test]
    fn growing_preserves_every_entry() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        let mut key = 0;
        while key < TBL_SIZE {
            table.remove(key);
            key += 2;
        }
        let before = table.count();
        table.resize(TBL_SIZE * 2).expect("error doubling size");
        assert_eq!(table.count(), before, "wrong resize count");
        assert_eq!(table.capacity(), TBL_SIZE * 2);
        let mut key = 1;
        while key < TBL_SIZE {
            assert_eq!(table.get(key), Some(&key), "lost entry {key}");
            key += 2;
        }
    }

    /// `:100-107` -- halving the capacity leaves exactly half the entries, and
    /// every odd key below the new capacity is still there.
    #[test]
    fn shrinking_drops_the_entries_at_or_above_the_new_capacity() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        let mut key = 0;
        while key < TBL_SIZE {
            table.remove(key);
            key += 2;
        }
        let before = table.count();
        table.resize(TBL_SIZE * 2).expect("error doubling size");
        table.resize(TBL_SIZE / 2).expect("error halving size");
        assert_eq!(table.count(), before / 2, "wrong half size count");
        assert_eq!(table.capacity(), TBL_SIZE / 2);
        let mut key = 1;
        while key < TBL_SIZE / 2 {
            assert!(table.contains(key), "does not contain {key}");
            assert_eq!(table.get(key), Some(&key), "wrong entry at {key}");
            key += 2;
        }
        // Everything at or above the new capacity is gone, including from the
        // range that used to be in bounds.
        for key in (TBL_SIZE / 2)..(TBL_SIZE * 2) {
            assert!(!table.contains(key), "{key} survived the shrink");
        }
    }

    /// `:109-114` -- after `clear` the count is zero and nothing is present.
    #[test]
    fn clear_empties_the_table_without_changing_its_capacity() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        table.clear();
        assert_eq!(table.count(), 0, "count not 0 after clear");
        assert!(table.is_empty());
        assert_eq!(table.capacity(), TBL_SIZE, "clear must not resize");
        for key in 0..TBL_SIZE {
            assert!(!table.contains(key), "does contain {key}, should not");
        }
        assert_eq!(table.first(), None);
    }

    /// `:116-121` -- after a clear the next key is 0; remove it and the next
    /// key is 1.
    ///
    /// This is the pair that proves the asymmetry between `clear`, which
    /// resets the round-robin cursor to the sentinel, and `remove`, which does
    /// not.
    #[test]
    fn the_first_key_after_a_clear_is_zero_and_the_next_is_one() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        table.clear();

        let key = table.add(7).expect("failed to add");
        assert_eq!(key, 0, "unexpected key assigned after clear");

        table.remove(key);
        let key = table.add(8).expect("failed to add");
        assert_eq!(key, 1, "unexpected key assigned after remove");
    }

    /// `:123-133` -- fill to capacity, remove key 17, and the next add gets
    /// key 17. Then do it again: the C's comment calls the second one
    /// "triggering key search wrap around", and both must hold.
    #[test]
    fn a_freed_key_in_a_full_table_is_reissued_twice_over() {
        let mut table = setup();
        table.clear();
        for value in 0..table.capacity() {
            table.add(value).expect("failed to add");
        }
        assert!(table.add(0).is_none(), "add on full");

        table.remove(17);
        let key = table.add(17).expect("failed to add again");
        assert_eq!(key, 17, "unexpected key assigned");

        // Again. `last_key_added` is now 17, so `start_pos` is 18, the upward
        // scan finds every row from 18 to the end occupied, and the wrap scan
        // finds row 17 -- the only vacant one.
        table.remove(17);
        let key = table.add(17).expect("failed to add again");
        assert_eq!(key, 17, "unexpected key assigned");
    }

    // Behaviour the C unit test does not reach.

    /// A zero capacity is rejected, and the table is left exactly as it was.
    ///
    /// This is a real difference from the integer-keyed bitsets, where a zero
    /// capacity is legal. `lib/uint-table.c:65-68` gives the reason above the
    /// check: "we use `tbl->nrows + 1` during iteration, want that to work".
    #[test]
    fn resize_to_zero_is_a_bad_function_argument_and_changes_nothing() {
        let mut table = setup();
        table.add(1).expect("failed to add");
        table.add(2).expect("failed to add");

        assert_eq!(table.resize(0), Err(CURLcode::BadFunctionArgument));
        assert_eq!(
            table.capacity(),
            TBL_SIZE,
            "a rejected resize must not act"
        );
        assert_eq!(table.count(), 2);
        assert_eq!(table.get(0), Some(&1));
        assert_eq!(table.get(1), Some(&2));

        // Including on a table that has never been sized.
        let mut fresh: Uint32Tbl<u32> = Uint32Tbl::new();
        assert_eq!(fresh.resize(0), Err(CURLcode::BadFunctionArgument));
        assert_eq!(fresh.capacity(), 0);
    }

    /// A table that has never been resized has zero capacity and accepts
    /// nothing, because the C's `nentries == nrows` test is satisfied by
    /// `0 == 0`.
    #[test]
    fn a_table_of_zero_capacity_accepts_nothing() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        assert_eq!(table.capacity(), 0);
        assert!(table.is_empty());
        assert!(table.add(1).is_none());
        assert_eq!(table.count(), 0);
        assert_eq!(table.first(), None);
        assert_eq!(table.next(0), None);
        assert!(!table.contains(0));
        assert_eq!(table.get(0), None);
        // And clearing or removing on it is inert rather than a panic.
        table.clear();
        table.remove(0);
        assert_eq!(table.capacity(), 0);
    }

    /// A same-size resize is a complete no-op: contents, count and cursor all
    /// survive.
    #[test]
    fn a_same_size_resize_is_a_complete_no_op() {
        let mut table = setup();
        for value in 0..10 {
            table.add(value).expect("failed to add");
        }
        table
            .resize(TBL_SIZE)
            .expect("same-size resize must succeed");
        assert_eq!(table.capacity(), TBL_SIZE);
        assert_eq!(table.count(), 10);
        for key in 0..10 {
            assert_eq!(table.get(key), Some(&key));
        }
        // The cursor survived too, so the next key continues the sequence.
        assert_eq!(table.add(99), Some(10));
    }

    /// Growth zero-fills the new rows: nothing is present above the old
    /// capacity, and the new rows are usable.
    #[test]
    fn growing_zero_fills_the_new_rows() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(4).expect("resize must succeed");
        for value in 0..4 {
            table.add(value).expect("failed to add");
        }
        table.resize(8).expect("resize must succeed");
        for key in 4..8 {
            assert!(!table.contains(key), "row {key} must arrive vacant");
        }
        assert_eq!(table.count(), 4);
        // The cursor is at 3, so the upward scan takes 4, 5, 6, 7 in order.
        for expected in 4..8 {
            assert_eq!(table.add(expected), Some(expected));
        }
        assert!(table.add(0).is_none());
    }

    /// `resize` does NOT reset the round-robin cursor, unlike `clear`.
    ///
    /// Shown twice over: growing does not restart the sequence at 0, and
    /// shrinking leaves a cursor above the new capacity that the
    /// `min(last_key_added, capacity)` clamp then absorbs.
    #[test]
    fn resize_does_not_restart_the_round_robin_but_clear_does() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(4).expect("resize must succeed");
        for value in 0..4 {
            table.add(value).expect("failed to add");
        }
        // Growing: the cursor is still 3, so the next key is 4 and not 0.
        table.resize(6).expect("resize must succeed");
        assert_eq!(table.add(4), Some(4));

        // Shrinking below the cursor: the clamp yields `capacity`, so
        // `start_pos` becomes `capacity + 1`, the upward scan is empty and the
        // wrap scan takes the lowest vacant row.
        table.resize(3).expect("resize must succeed");
        assert_eq!(table.count(), 3);
        table.remove(1);
        assert_eq!(table.add(1), Some(1), "the clamp must rescue the cursor");

        // Whereas `clear` really does restart at 0.
        table.clear();
        assert_eq!(table.add(0), Some(0));
    }

    /// `u32::MAX` is never returned by `add`, over a complete fill.
    #[test]
    fn the_invalid_key_is_never_assigned() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(8).expect("resize must succeed");
        for round in 0..4_u32 {
            for value in 0..8 {
                let key = table.add(value).expect("failed to add");
                assert_ne!(key, NO_KEY, "the invalid key was assigned");
                assert!(key < 8, "key {key} is outside the table");
            }
            assert!(table.add(0).is_none());
            // Empty it a different way each round so that both the `clear`
            // path and the `remove` path are covered.
            if round % 2 == 0 {
                table.clear();
            } else {
                for key in 0..8 {
                    table.remove(key);
                }
            }
        }
    }

    /// `get`, `contains` and `remove` are all safe no-ops at `u32::MAX`.
    ///
    /// `remove(u32::MAX)` is the one that would panic if `key + 1` were
    /// written as an unchecked addition, because Rust traps that overflow in a
    /// debug build where C wraps it silently.
    #[test]
    fn the_invalid_key_is_safe_to_get_contains_and_remove() {
        let mut table = setup();
        for value in 0..TBL_SIZE {
            table.add(value).expect("failed to add");
        }
        assert_eq!(table.get(NO_KEY), None);
        assert_eq!(table.get_mut(NO_KEY), None);
        assert!(!table.contains(NO_KEY));
        assert_eq!(table.key_of(NO_KEY), None);
        table.remove(NO_KEY);
        assert_eq!(table.count(), TBL_SIZE, "remove(MAX) must change nothing");
        // And one below it, which is in range arithmetically but not in the
        // table.
        table.remove(NO_KEY - 1);
        assert_eq!(table.count(), TBL_SIZE);
    }

    /// `next(u32::MAX)` yields `None` without panicking and without
    /// restarting the scan from 0.
    #[test]
    fn next_from_the_invalid_key_yields_nothing() {
        let mut table = setup();
        table.add(11).expect("failed to add");
        assert_eq!(table.first(), Some((0, &11)));
        assert_eq!(table.next(NO_KEY), None, "the scan must not restart at 0");
        // The step below the sentinel behaves normally -- it is simply past
        // the end of a 100-row table.
        assert_eq!(table.next(NO_KEY - 1), None);
    }

    /// The wrap scan never reads past the last row, on the smallest table that
    /// can reach the dangerous state.
    ///
    /// With a capacity of 1 and the cursor at 0, `start_pos` is 1: the C's
    /// wrap bound `key < start_pos` admits `key == 1`, one past the only row.
    /// Nothing here can, because the bound is clamped to the capacity.
    #[test]
    fn the_wrap_scan_never_reads_past_the_last_row() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(1).expect("resize must succeed");

        // Fresh: `start_pos` is `capacity + 1` == 2, so the upward scan is
        // empty and the wrap scan must find row 0 without ever looking at
        // row 1.
        assert_eq!(table.add(1), Some(0));
        assert!(table.add(2).is_none());

        // Now the cursor is 0 and `start_pos` is 1. The upward scan `1..1` is
        // empty; the wrap scan `0..min(1, 1)` finds row 0 again.
        table.remove(0);
        assert_eq!(table.add(3), Some(0));
        assert_eq!(table.count(), 1);
        assert_eq!(table.get(0), Some(&3));
        assert!(!table.contains(1), "row 1 does not exist");
    }

    /// The clamped wrap scan visits exactly the keys the C's unclamped one
    /// would, in the same order.
    #[test]
    fn the_wrap_scan_visits_the_same_keys_the_c_would() {
        /// The C's `add`, key-selection half only, with its unclamped wrap
        /// bound intact. `occupied[capacity]` stands in for the byte the C
        /// would read one past its array, and is deliberately `true` so that a
        /// scan reaching it does NOT take it -- had it been `false` the C would
        /// have written out of bounds, which is the defect itself.
        fn c_key_choice(occupied: &[bool], last_key_added: u32) -> Option<u32> {
            let capacity = (occupied.len() - 1) as u32;
            let live = occupied[..capacity as usize]
                .iter()
                .filter(|row| **row)
                .count() as u32;
            if live == capacity {
                // `if(tbl->nentries == tbl->nrows) return FALSE;`
                return None;
            }
            let start_pos = last_key_added.min(capacity).saturating_add(1);
            // `for(key = start_pos; key < tbl->nrows; ++key)`
            let upward =
                (start_pos..capacity).find(|key| !occupied[*key as usize]);
            // `for(key = 0; key < start_pos; ++key)` -- the UNCLAMPED bound,
            // which is the whole point of this oracle.
            upward
                .or_else(|| (0..start_pos).find(|key| !occupied[*key as usize]))
        }

        const CAPACITY: u32 = 6;
        // Every occupancy pattern of six rows, against every cursor value the
        // table can hold -- the sentinel plus each valid row index.
        for pattern in 0_u32..(1 << CAPACITY) {
            for cursor in 0..=CAPACITY {
                let last_key_added =
                    if cursor == CAPACITY { NO_KEY } else { cursor };

                let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
                table.resize(CAPACITY).expect("resize must succeed");
                let mut occupied = vec![false; CAPACITY as usize + 1];
                // The sentinel row the C would read past the end.
                occupied[CAPACITY as usize] = true;
                for key in 0..CAPACITY {
                    if pattern & (1 << key) != 0 {
                        occupied[key as usize] = true;
                        table.rows[key as usize] = Some(super::Row {
                            entry: key,
                            generation: u64::from(key),
                        });
                        table.nentries += 1;
                    }
                }
                table.last_key_added = last_key_added;

                let expected = c_key_choice(&occupied, last_key_added);
                let actual = table.add(u32::MAX);
                assert_eq!(
                    actual, expected,
                    "pattern {pattern:#08b}, cursor {last_key_added} \
                     disagreed with the C"
                );
            }
        }
    }

    /// A table of capacity one recycles its only key indefinitely.
    #[test]
    fn a_table_of_capacity_one_recycles_its_only_key() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(1).expect("resize must succeed");
        for round in 0..16 {
            assert_eq!(table.add(round), Some(0));
            assert!(table.add(round).is_none());
            assert_eq!(table.first(), Some((0, &round)));
            assert_eq!(table.next(0), None);
            table.remove(0);
            assert!(table.is_empty());
        }
    }

    /// `get_mut` hands back a borrow that really does write through.
    #[test]
    fn get_mut_hands_back_a_mutable_entry() {
        let mut table = setup();
        let key = table.add(1).expect("failed to add");
        *table.get_mut(key).expect("the row is occupied") = 42;
        assert_eq!(table.get(key), Some(&42));
        assert_eq!(table.get_mut(key + 1), None, "a vacant row has nothing");
    }

    /// An empty table has no first entry, whichever way it became empty.
    #[test]
    fn an_empty_table_has_no_first_entry() {
        let mut table = setup();
        assert_eq!(table.first(), None);
        let key = table.add(1).expect("failed to add");
        assert_eq!(table.first(), Some((0, &1)));
        table.remove(key);
        assert_eq!(table.first(), None, "emptied by remove");
        table.add(2).expect("failed to add");
        table.clear();
        assert_eq!(table.first(), None, "emptied by clear");
    }

    /// `Default` agrees with `new`, including the cursor, which a derived
    /// implementation would have got wrong.
    #[test]
    fn default_agrees_with_new_and_the_cursor_is_the_sentinel() {
        let made: Uint32Tbl<u32> = Uint32Tbl::new();
        let defaulted: Uint32Tbl<u32> = Uint32Tbl::default();
        assert_eq!(made.capacity(), defaulted.capacity());
        assert_eq!(made.count(), defaulted.count());
        assert_eq!(made.last_key_added, defaulted.last_key_added);
        assert_eq!(
            defaulted.last_key_added, NO_KEY,
            "a derived Default would leave this at 0 and shift every key"
        );

        // And the consequence, which is what actually matters: the first key
        // out of a defaulted table is 0, not 1.
        let mut defaulted: Uint32Tbl<u32> = Uint32Tbl::default();
        defaulted.resize(4).expect("resize must succeed");
        assert_eq!(defaulted.add(1), Some(0));
    }

    // Destruction accounting. The C's `entry_dtor` becomes `Drop`, so these
    // are the tests the C unit test could not have.

    /// `remove` drops exactly the one entry it vacates, exactly once.
    #[test]
    fn remove_drops_exactly_one_entry() {
        let (drops, make) = tracker();
        let mut table: Uint32Tbl<Tracked> = Uint32Tbl::new();
        table.resize(4).expect("resize must succeed");
        for tag in 0..4 {
            table.add(make(tag)).expect("failed to add");
        }
        assert_eq!(drops.get(), 0, "nothing is dropped by adding");

        table.remove(2);
        assert_eq!(drops.get(), 1, "remove drops exactly one");
        assert_eq!(table.count(), 3);

        // A repeat, and an out-of-range key, drop nothing further.
        table.remove(2);
        table.remove(99);
        assert_eq!(drops.get(), 1);

        drop(table);
        assert_eq!(drops.get(), 4, "the remaining three go with the table");
    }

    /// A shrinking `resize` drops exactly the entries at or above the new
    /// capacity, and no others.
    #[test]
    fn shrinking_drops_exactly_the_entries_it_discards() {
        let (drops, make) = tracker();
        let mut table: Uint32Tbl<Tracked> = Uint32Tbl::new();
        table.resize(8).expect("resize must succeed");
        for tag in 0..8 {
            table.add(make(tag)).expect("failed to add");
        }

        table.resize(5).expect("resize must succeed");
        assert_eq!(drops.get(), 3, "rows 5, 6 and 7 are discarded");
        assert_eq!(table.count(), 5);
        for key in 0..5 {
            assert_eq!(
                table.get(key).map(|entry| entry.tag),
                Some(key),
                "row {key} must be untouched"
            );
        }

        // Growing again drops nothing.
        table.resize(9).expect("resize must succeed");
        assert_eq!(drops.get(), 3);

        drop(table);
        assert_eq!(drops.get(), 8, "each of the eight is dropped once");
    }

    /// `clear` drops every entry exactly once and nothing twice.
    #[test]
    fn clear_drops_every_entry_exactly_once() {
        let (drops, make) = tracker();
        let mut table: Uint32Tbl<Tracked> = Uint32Tbl::new();
        table.resize(6).expect("resize must succeed");
        for tag in 0..6 {
            table.add(make(tag)).expect("failed to add");
        }
        table.remove(0);
        assert_eq!(drops.get(), 1);

        table.clear();
        assert_eq!(drops.get(), 6, "the five survivors are dropped once each");

        // A second clear on an empty table drops nothing.
        table.clear();
        assert_eq!(drops.get(), 6);

        drop(table);
        assert_eq!(drops.get(), 6, "an empty table has nothing left to drop");
    }

    /// Dropping the table drops every remaining entry exactly once.
    ///
    /// This is what stands in for `Curl_uint32_tbl_destroy`, and it is why no
    /// `Drop` implementation is written by hand.
    #[test]
    fn dropping_the_table_drops_every_remaining_entry_exactly_once() {
        let (drops, make) = tracker();
        {
            let mut table: Uint32Tbl<Tracked> = Uint32Tbl::new();
            table.resize(16).expect("resize must succeed");
            for tag in 0..16 {
                table.add(make(tag)).expect("failed to add");
            }
            table.remove(3);
            table.remove(11);
            assert_eq!(drops.get(), 2);
        }
        assert_eq!(drops.get(), 16, "fourteen more, one each");
    }

    // The iteration-under-modification contract of `lib/uint-table.h:88-92`,
    // one test per bullet. The multi handle depends on all four.

    /// "added keys higher than 'last_key' will be picked up by the iteration."
    #[test]
    fn a_key_added_above_the_cursor_is_picked_up_by_the_iteration() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(8).expect("resize must succeed");
        for value in 0..8 {
            table.add(value).expect("failed to add");
        }
        // Vacate rows 5 and 6, then walk. Row 5 is refilled while the cursor
        // sits at 2, which is below it, so the walk must reach it.
        table.remove(5);
        table.remove(6);

        let mut visited = Vec::new();
        let mut cursor = table.first().map(|(key, _)| key);
        while let Some(key) = cursor {
            visited.push(key);
            if key == 2 {
                // `last_key_added` is 7, so the upward scan is empty and the
                // wrap scan takes row 5 -- above the cursor.
                assert_eq!(table.add(55), Some(5));
            }
            cursor = table.next(key).map(|(next, _)| next);
        }
        assert_eq!(visited, vec![0, 1, 2, 3, 4, 5, 7]);
    }

    /// "added keys lower than 'last_key' will not show up."
    #[test]
    fn a_key_added_below_the_cursor_does_not_show_up() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(8).expect("resize must succeed");
        for value in 0..8 {
            table.add(value).expect("failed to add");
        }
        table.remove(1);

        let mut visited = Vec::new();
        let mut cursor = table.first().map(|(key, _)| key);
        while let Some(key) = cursor {
            visited.push(key);
            if key == 4 {
                // Row 1 is the only vacancy, so it is what `add` takes -- and
                // it is below the cursor, so the walk has already passed it.
                assert_eq!(table.add(11), Some(1));
            }
            cursor = table.next(key).map(|(next, _)| next);
        }
        assert_eq!(visited, vec![0, 2, 3, 4, 5, 6, 7], "1 must not appear");
        assert!(table.contains(1), "but it is in the table afterwards");
    }

    /// "removed keys lower or equal to 'last_key' will not show up."
    ///
    /// The walk has already passed them, so removing them cannot disturb it --
    /// and in particular removing the CURRENT key, which is what
    /// `lib/multi.c:2874` does, leaves the walk able to continue from it.
    #[test]
    fn a_key_removed_at_or_below_the_cursor_does_not_show_up() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(6).expect("resize must succeed");
        for value in 0..6 {
            table.add(value).expect("failed to add");
        }

        let mut visited = Vec::new();
        let mut cursor = table.first().map(|(key, _)| key);
        while let Some(key) = cursor {
            visited.push(key);
            // Remove the row just visited, exactly as the multi handle's
            // cleanup loop does.
            table.remove(key);
            if key >= 1 {
                // And one strictly below it, already visited.
                table.remove(key - 1);
            }
            cursor = table.next(key).map(|(next, _)| next);
        }
        assert_eq!(visited, vec![0, 1, 2, 3, 4, 5], "every key once");
        assert!(table.is_empty(), "the walk emptied the table");
    }

    /// "removed keys higher than 'last_key' will not be visited."
    #[test]
    fn a_key_removed_above_the_cursor_is_not_visited() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(8).expect("resize must succeed");
        for value in 0..8 {
            table.add(value).expect("failed to add");
        }

        let mut visited = Vec::new();
        let mut cursor = table.first().map(|(key, _)| key);
        while let Some(key) = cursor {
            visited.push(key);
            if key == 2 {
                table.remove(5);
                table.remove(7);
            }
            cursor = table.next(key).map(|(next, _)| next);
        }
        assert_eq!(visited, vec![0, 1, 2, 3, 4, 6], "5 and 7 are skipped");
    }

    /// A key obtained before a `remove` fails the checked lookup afterwards,
    /// while the plain index API keeps behaving exactly as the C does.
    #[test]
    fn a_generational_key_goes_stale_when_its_row_is_removed() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(4).expect("resize must succeed");
        let index = table.add(7).expect("failed to add");
        let key = table.key_of(index).expect("the row is occupied");
        assert_eq!(key.index(), index, "the key carries the plain index");
        assert_eq!(table.get_checked(key), Some(&7));
        assert!(table.contains_key(key));

        table.remove(index);
        assert_eq!(table.get_checked(key), None, "the key is stale");
        assert!(!table.contains_key(key));
        assert!(
            !table.remove_key(key),
            "and removing through it does nothing"
        );
        // The plain API answers exactly as the C would.
        assert_eq!(table.get(index), None);
        assert!(!table.contains(index));
    }

    /// A row index reused by a later `add` does not revive a stale key.
    ///
    /// The ABA case, and the reason the generation is a table-wide counter
    /// rather than a per-row flag: the index is identical, the occupant is
    /// not.
    #[test]
    fn a_reused_row_index_does_not_revive_a_stale_generational_key() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(1).expect("resize must succeed");
        let index = table.add(7).expect("failed to add");
        let stale = table.key_of(index).expect("the row is occupied");

        table.remove(index);
        let reused = table.add(9).expect("failed to add");
        assert_eq!(reused, index, "the C would reissue this very index");

        let fresh = table.key_of(reused).expect("the row is occupied");
        assert_ne!(
            stale.generation(),
            fresh.generation(),
            "the stamps must differ"
        );
        assert_eq!(table.get_checked(stale), None, "the old key stays stale");
        assert_eq!(table.get_checked(fresh), Some(&9));
        // And the plain index API cannot tell them apart, which is precisely
        // the C behaviour the checked form exists to improve on without
        // changing.
        assert_eq!(table.get(index), Some(&9));
    }

    /// A `clear` and a shrinking `resize` both stale every key they touch.
    #[test]
    fn clearing_and_shrinking_both_stale_the_keys_they_touch() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(4).expect("resize must succeed");
        let mut keys = Vec::new();
        for value in 0..4 {
            let index = table.add(value).expect("failed to add");
            keys.push(table.key_of(index).expect("the row is occupied"));
        }

        table.resize(2).expect("resize must succeed");
        assert!(table.contains_key(keys[0]), "row 0 survived");
        assert!(table.contains_key(keys[1]), "row 1 survived");
        assert!(!table.contains_key(keys[2]), "row 2 was discarded");
        assert!(!table.contains_key(keys[3]), "row 3 was discarded");

        table.clear();
        for key in &keys {
            assert!(!table.contains_key(*key), "clear stales everything");
        }
    }

    /// `get_checked_mut` writes through a live key and refuses a stale one.
    ///
    /// The capacity is 1 so that the vacated row is certainly the one reused:
    /// on a wider table the round-robin cursor would move the new entry to the
    /// NEXT row, and the stale key would then be refused merely because its
    /// row is empty rather than because its stamp is old.
    #[test]
    fn the_checked_mutable_accessor_refuses_a_stale_key() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(1).expect("resize must succeed");
        let index = table.add(1).expect("failed to add");
        let key = table.key_of(index).expect("the row is occupied");
        *table.get_checked_mut(key).expect("the key is live") = 5;
        assert_eq!(table.get_checked(key), Some(&5));

        table.remove(index);
        let reused = table.add(6).expect("failed to add");
        assert_eq!(reused, index, "the only row must be the one reused");
        assert!(
            table.get_checked_mut(key).is_none(),
            "a stale key must not hand out a mutable borrow"
        );
        assert_eq!(table.get(index), Some(&6), "the new occupant is untouched");
    }

    /// `remove_key` evicts through a live key and reports that it did.
    #[test]
    fn remove_key_evicts_through_a_live_key_and_reports_it() {
        let (drops, make) = tracker();
        let mut table: Uint32Tbl<Tracked> = Uint32Tbl::new();
        table.resize(2).expect("resize must succeed");
        let index = table.add(make(1)).expect("failed to add");
        let key = table.key_of(index).expect("the row is occupied");

        assert!(table.remove_key(key), "a live key evicts");
        assert_eq!(drops.get(), 1, "and drops exactly the one entry");
        assert!(!table.remove_key(key), "a spent key does not evict twice");
        assert_eq!(drops.get(), 1);
    }

    /// The generation field does not disturb the plain key sequence.
    ///
    /// The whole point of layering rather than packing: the round-robin
    /// integers are byte-identical to what a table without any generation
    /// would have produced, which is what keeps `mid` frozen.
    #[test]
    fn the_plain_key_sequence_is_unaffected_by_the_generation_field() {
        let mut table = setup();
        // The full sequence from `tests/unit/unit3212.c`, replayed while
        // taking a dated key at every step so that the counter is exercised
        // continuously.
        for expected in 0..TBL_SIZE {
            let key = table.add(expected).expect("failed to add");
            assert_eq!(key, expected);
            let dated = table.key_of(key).expect("the row is occupied");
            assert_eq!(dated.index(), key);
        }
        assert!(table.add(0).is_none());

        table.remove(17);
        assert_eq!(table.add(17), Some(17));
        table.remove(17);
        assert_eq!(table.add(17), Some(17));

        table.clear();
        assert_eq!(table.add(0), Some(0));
        table.remove(0);
        assert_eq!(table.add(1), Some(1));
    }

    /// The generation counter is strictly monotone across every mutation, so
    /// no stamp is ever issued twice.
    #[test]
    fn the_generation_counter_advances_on_every_occupancy_change() {
        let mut table: Uint32Tbl<u32> = Uint32Tbl::new();
        table.resize(4).expect("resize must succeed");

        let mut seen = Vec::new();
        for round in 0..4_u32 {
            for value in 0..4 {
                let index = table.add(value).expect("failed to add");
                let key = table.key_of(index).expect("the row is occupied");
                seen.push(key.generation());
            }
            if round % 2 == 0 {
                table.clear();
            } else {
                for key in 0..4 {
                    table.remove(key);
                }
            }
        }

        // Strictly increasing, hence all distinct.
        for pair in seen.windows(2) {
            assert!(pair[0] < pair[1], "the counter went backwards: {pair:?}");
        }
        assert_eq!(table.next_generation, 32);
    }
}
