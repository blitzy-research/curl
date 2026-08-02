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
//
// That tag's spelling appears EXACTLY ONCE in this file, on line 21, and must
// stay that way. `reuse` scans every line for the tag WITH its trailing colon
// and parses whatever follows as a licence expression, so a second, prose
// mention becomes a parse error rather than prose -- the measurement behind
// that rule is recorded at `util/mod.rs:33-42`. Every reference below therefore
// says "the licence-identifier tag" and never spells it.

//! The integer-keyed transfer table: the slab that assigns `mid`.
//!
//! Supersedes `lib/uint-table.c` (200 lines) and `lib/uint-table.h` (96),
//! whose eleven public functions and two file-static helpers are reproduced
//! here in full. It is a fixed-capacity array of rows addressed directly by an
//! unsigned 32-bit key, and it hands those keys out ITSELF rather than
//! accepting them from a caller. That is the whole reason it exists, and the
//! reason it is not a hash map.
//!
//! # Why the key sequence is frozen behaviour and not an implementation detail
//!
//! The key this table assigns IS the transfer identifier `mid`
//! (`lib/urldata.h:1630`, `uint32_t mid;`, with `uint32_t master_mid;`
//! immediately after it), and `mid` is printed. Measured rather than assumed:
//!
//! | Emitting site | Format string |
//! |---|---|
//! | `lib/multi.c:529` | `"added to multi, mid=%u, running=%u, total=%u"` |
//! | `lib/multi.c:887` | `"removed from multi, mid=%u, running=%u, ..."` |
//! | `lib/multi.c:2860` | `"multi_cleanup: still present with mid=%u, ..."` |
//! | `lib/multi.c:3959` | `"invalid easy handle in xfer table for mid=%u"` |
//! | `lib/http2.c:860` | `"promise easy handle added to multi, mid=%u"` |
//! | `lib/multi_ntfy.c:171` | `"[NTFY] add %u for xfer %u"` |
//! | `lib/doh.c:1313` | `"Curl_doh_close: xfer for mid=%u not found!"` |
//!
//! A `--trace` transcript therefore contains these integers verbatim. The
//! preservation mandate of specification 0.8.1 freezes observable behaviour,
//! and the test corpus compares captured output as ONE string rather than line
//! by line (specification 0.6.7), so the algorithm below is transcribed and
//! not improved. `tests/unit/unit3212.c` pins the assigned sequence in seven
//! separate places, and every one of its assertions is ported into this file's
//! own test module -- the relocation that specification 0.8.7 requires, since
//! a Rust static library genuinely does not export `pub(crate)` items and no
//! quality of implementation would let that C program link.
//!
//! Two consequences follow, and both are prohibitions:
//!
//! * A hash map is wrong. Its key comes from the caller; this table's key
//!   comes from the table, by a deterministic rule.
//! * No free list, no bitmap of vacant rows, and no "next free" cursor beyond
//!   the C's own `last_key_added`. Each of those would change which key a
//!   given `add` returns. Performance is an explicit non-goal of this work
//!   (specification 0.1.1), so the two linear scans in [`Uint32Tbl::add`] and
//!   the one in [`Uint32Tbl::next`] stay linear.
//!
//! # The C structure, and the one initial value that decides everything
//!
//! `lib/uint-table.h:31-40` and `lib/uint-table.c:35-44`:
//!
//! ```text
//! typedef void Curl_uint32_tbl_entry_dtor(uint32_t key, void *entry);
//!
//! struct uint32_tbl {
//!   void **rows;                 /* array of void* holding entries */
//!   Curl_uint32_tbl_entry_dtor *entry_dtor;
//!   uint32_t nrows;              /* length of `rows` array */
//!   uint32_t nentries;           /* entries in table */
//!   uint32_t last_key_added;     /* UINT_MAX or last key added */
//! #ifdef DEBUGBUILD
//!   int init;
//! #endif
//! };
//!
//! void Curl_uint32_tbl_init(struct uint32_tbl *tbl,
//!                           Curl_uint32_tbl_entry_dtor *entry_dtor)
//! {
//!   memset(tbl, 0, sizeof(*tbl));
//!   tbl->entry_dtor = entry_dtor;
//!   tbl->last_key_added = UINT32_MAX;      /* <-- NOT zero */
//! }
//! ```
//!
//! `init` zeroes the struct and then writes `UINT32_MAX` -- [`NO_KEY`] here --
//! over `last_key_added`. That single assignment is what makes the first
//! assigned key 0; the arithmetic is worked through in [`Uint32Tbl::add`].
//! A derived `Default` would leave the field at zero and silently change the
//! first key from 0 to 1, which is why [`Uint32Tbl`]'s `Default` is written by
//! hand and delegates to [`Uint32Tbl::new`].
//!
//! `init` also leaves the capacity at zero: `rows` is NULL and `nrows` is 0,
//! so a table is unusable until [`Uint32Tbl::resize`] has been called. The
//! consumer does exactly that, at `lib/multi.c:245` and `:263`.
//!
//! Two fields have no successor here. `entry_dtor` collapses into `Drop` on
//! the entry type, and the DEBUGBUILD `init` sentinel guarded against use
//! after free, which Rust's ownership rules make unrepresentable. The sentinel
//! value is `CURL_UINT32_TBL_MAGIC 0x62757473` (`lib/uint-table.c:29`) and it
//! is byte-identical to `CURL_UINT32_BSET_MAGIC` in `lib/uint-bset.c` -- an
//! upstream copy-paste, recorded here only so that a reader does not go
//! hunting for a relationship that is not there.
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
//! One detail is lost in the collapse and is worth naming: the C destructor
//! receives BOTH the key and the entry, `void (*)(uint32_t key, void *entry)`,
//! because a `void *` carries no type information and a destructor might need
//! to know which row it was in. `Drop::drop` receives only `&mut self`. No
//! consumer depends on the key argument, because the only consumer passes NULL.
//!
//! # The rest of the consumer contract, recorded so it is not re-derived
//!
//! Everything below is measured in `lib/multi.c` and `lib/multihandle.h`. The
//! arithmetic belongs in the ported multi handle rather than here, but it
//! constrains this module's contract and so is written down:
//!
//! * `#define CURL_XFER_TABLE_SIZE 512` (`lib/multi.c:52`), "initial
//!   multi->xfers table size for a full multi". `curl_multi_init` passes it
//!   at `:337`; the single-transfer path passes a much smaller value.
//! * `#define INITIAL_MAX_CONCURRENT_STREAMS ((1U << 31) - 1)`
//!   (`lib/multihandle.h:79`).
//! * `const uint32_t max_capacity = UINT_MAX - 1;` (`lib/multi.c:373`), with
//!   the comment "UINT_MAX is our \"invalid\" id, do not let the table grow up
//!   to that." That clamp is the second half of the never-assign-`UINT_MAX`
//!   guarantee; the first half is this module's own use of the value as a
//!   sentinel, and the two together are why [`NO_KEY`] can never be returned
//!   by [`Uint32Tbl::add`].
//! * The growth policy (`lib/multi.c:374-397`): aim for at least 25% vacant
//!   rows with a floor of four, `min_unused = CURLMAX(capacity >> 2, 4)`; grow
//!   when `unused <= min_unused`; round the new size up to a multiple of 64,
//!   `new_size = (((used + min_unused) + 63) / 64) * 64`, because -- in the
//!   C's own words at `:391`, typo included -- "make it a 64 multiple, since
//!   our bitsets frow by that and small (easy_multi) grows to at least 64 on
//!   first resize"; and three corner-case guards clamp to `max_capacity` so
//!   that the rounding cannot overflow near `UINT_MAX`.
//! * The cross-module ordering invariant, quoted verbatim from
//!   `lib/multi.c:400-403`: "Grow the bitsets first. Should one fail, we do
//!   not need to downsize the already resized ones. The sets continue to work
//!   properly when larger than the table, but not the other way around."
//!   **Resize the four bitsets before the table, always.**
//!   `lib/multi.c:258-263` observes the same order on the initialisation
//!   path, before any transfer exists. A bitset wider than
//!   the table is harmless; a table wider than a bitset is not.
//! * `Curl_uint32_tbl_add(&multi->xfers, multi->admin, &multi->admin->mid)`
//!   (`lib/multi.c:278`) runs before any application transfer, so the internal
//!   admin easy handle "gets assigned `mid` 0 on multi init"
//!   (`lib/multihandle.h:100-101`). **`mid` 0 is live and meaningful and is
//!   never a sentinel.** `lib/multi.c:449-450` leans on that directly, testing
//!   "only the admin handle remains" as `count() != 1 || !contains(0)`, which
//!   is why both accessors are load-bearing rather than conveniences.
//! * `lib/multi.c:413` discards the entry when `add` fails and returns
//!   `CURLM_OUT_OF_MEMORY`. It never needs the rejected value back, which is
//!   what settles [`Uint32Tbl::add`]'s return type as `Option<u32>` rather
//!   than `Result<u32, T>`.
//! * `lib/multi.c:2852-2891` and `:3734-3740` walk the table with
//!   `first`/`next` and call `remove` INSIDE the loop. That is the whole
//!   reason this module exposes no iterator; see [`Uint32Tbl::next`].
//!
//! # Generational keys, layered on and never replacing the index
//!
//! Specification 0.6.9 asks the multi handle for "a slab with generational
//! keys so a stale handle is detectably stale rather than a dangling pointer".
//! This module is that slab. The generation is an ADDITIONAL field:
//!
//! * [`Uint32Tbl::add`] returns the plain round-robin row index, unchanged and
//!   unpacked. That integer is the `mid` that reaches trace output, so it must
//!   be exactly what the C would have assigned.
//! * The generation is NEVER encoded into the key integer. Packing an index
//!   and a counter into one `u32` would change every `mid` and break the
//!   preservation mandate.
//! * [`Key`] pairs an index with the generation that was current when its row
//!   was filled, and [`Uint32Tbl::get_checked`] is an opt-in stale-key check
//!   ALONGSIDE [`Uint32Tbl::get`], never a replacement for it. A caller that
//!   holds a bare `u32` keeps the C's exact semantics.
//!
//! The counter is a `u64` on the table rather than a `u32` on the row, and it
//! advances on every occupancy change -- each row filled and each row vacated.
//! Advancing on `add` alone would already make a [`Key`] stale the moment its
//! row is removed, because a vacant row matches no generation at all;
//! advancing on removal too is what the specification's design note asks for
//! and costs nothing. `u64` rather than `u32` removes the last theoretical
//! hole: a 32-bit counter wraps after about 4.3 billion occupancy changes, and
//! a long-lived process could reach that and revive a stale key, whereas 2^64
//! changes is unreachable -- at one change every nanosecond it is roughly 584
//! years. [`Key`] is crate-internal and never crosses the C ABI, so its width
//! costs nothing there either.
//!
//! # Defects removed, which is the point of the migration
//!
//! * The `void **rows` array with hand-written `calloc`, `memcpy` and `free`
//!   becomes a `Vec`, so length and capacity are the type's responsibility.
//! * The `void *` entry becomes a generic `T`, so no cast happens at any
//!   boundary and `Box<dyn Any>` is not used to imitate one.
//! * The C's `add` can read one element past the end of `rows`. The
//!   analysis and the fix are in [`Uint32Tbl::add`] and
//!   [`Uint32Tbl::free_row_from`], and the equivalence of the fixed loop to
//!   the C's is asserted by test rather than argued in prose.
//! * `remove(u32::MAX)` and `next(u32::MAX)` both overflow `key + 1` in the C.
//!   Each is handled with `checked_add` here, and each divergence is recorded
//!   at the method that makes it.
//!
//! There is no `unsafe` in this file, no raw pointer and no
//! `#[allow(unsafe_code)]`. `crate::util` is granted no exemption from the
//! crate root's lint level, and `mod source_policy` in `src/lib.rs` asserts
//! that mechanically over the whole tree.
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
///
/// `Curl_uint32_tbl_init` writes `UINT32_MAX` into `last_key_added`
/// (`lib/uint-table.c:40`), and the C's `add` and `next_at` both write it into
/// their out-parameter on failure with the comment "always invalid"
/// (`lib/uint-table.c:172`, `:185`, `:197`). `lib/uint-table.h:68` states the
/// guarantee as a contract: "No matter the capacity, UINT_MAX is never
/// assigned."
///
/// Two mechanisms keep that true and neither is sufficient alone. Here, the
/// value doubles as "no key has been assigned yet", so [`Uint32Tbl::add`]
/// treats it as a cursor before the first row rather than as a row. In the
/// consumer, `lib/multi.c:373` clamps capacity to `UINT_MAX - 1`, so the
/// highest row index a maximal table can hold is `UINT_MAX - 2` and a key can
/// never reach this value from below.
const NO_KEY: u32 = u32::MAX;

/// One occupied row: the caller's entry, plus the generation that dates it.
///
/// The C stores a bare `void *` per row and uses "the row is NULL" as its only
/// occupancy marker -- which is precisely what `Option<Row<T>>` expresses, and
/// the reason `add` rejecting a NULL entry (`lib/uint-table.c:121`) has no
/// counterpart here: a `T` value cannot be null, so the branch disappears
/// rather than being ported.
struct Row<T> {
    /// The value the caller handed to [`Uint32Tbl::add`].
    entry: T,
    /// The value of [`Uint32Tbl::next_generation`] at the moment this row was
    /// filled. Unique across the table's whole lifetime, so a [`Key`] carrying
    /// a different stamp for the same index is stale by definition.
    generation: u64,
}

/// A row index paired with the generation that was current when the row was
/// filled: the generational key of specification 0.6.9.
///
/// Obtained from [`Uint32Tbl::key_of`] and consumed by
/// [`Uint32Tbl::get_checked`], [`Uint32Tbl::get_checked_mut`],
/// [`Uint32Tbl::contains_key`] and [`Uint32Tbl::remove_key`]. The usual
/// sequence is to `add`, then ask for the key of the index just returned:
///
/// ```text
/// let mid = table.add(entry)?;        // the `mid`, exactly as the C assigns
/// let key = table.key_of(mid)?;       // the same row, now dated
/// ```
///
/// Both fields are private on purpose. A caller cannot construct a [`Key`]
/// from an index and a guessed generation, so the only keys in circulation are
/// ones this table issued -- which is what makes a failed
/// [`Uint32Tbl::get_checked`] mean "that row has been reused or vacated"
/// rather than "the caller made the numbers up".
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
    ///
    /// `#[derive(Default)]` would be WRONG here, not merely different. It
    /// would leave `last_key_added` at 0, whereas
    /// `Curl_uint32_tbl_init` writes `UINT32_MAX` over the zeroed struct
    /// (`lib/uint-table.c:38-40`). The arithmetic in [`Self::add`] turns that
    /// one difference into a different first key -- 1 instead of 0 -- which
    /// would shift every `mid` in a trace transcript by one and hand the
    /// multi handle's admin easy handle the wrong identifier
    /// (`lib/multihandle.h:100-101`). A test asserts the delegation.
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl<T> Uint32Tbl<T> {
    /// An empty table of zero capacity: `Curl_uint32_tbl_init`
    /// (`lib/uint-table.c:35-44`).
    ///
    /// [`Self::resize`] must be called before the table can hold anything,
    /// exactly as in the C, where `init` leaves `rows` NULL. The consumer does
    /// so immediately (`lib/multi.c:245` then `:263`). Until then
    /// [`Self::add`] reports the table full, because zero entries in zero rows
    /// satisfies the C's `nentries == nrows` test.
    ///
    /// The `entry_dtor` parameter has no counterpart: destruction is `Drop` on
    /// `T`. See this module's documentation for what that means for the caller
    /// that passes NULL.
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
    /// `lib/uint-table.h:48-49` states the shrink semantic: "When `nmax` is
    /// reduced, all present entries with key equal or larger to `nmax` are
    /// removed." Each such entry is dropped and the count is decremented for
    /// each, by way of [`Self::clear_rows`].
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
    ///
    /// Every entry is dropped and the count returns to zero; the capacity is
    /// untouched. Crucially, `last_key_added` is reset to [`NO_KEY`], which
    /// [`Self::remove`] does NOT do. That asymmetry is the whole reason
    /// `tests/unit/unit3212.c` gets key 0 after a clear (`:116-117`) but key
    /// 17 after removing key 17 from a full table (`:127-129`).
    ///
    /// The C declares this `UNITTEST`, meaning `static` in a production build
    /// and `extern` only when the unit tests are compiled, yet calls it
    /// internally from `Curl_uint32_tbl_destroy` (`lib/uint-table.c:88`). Here
    /// it is unconditionally `pub(crate)`: the visibility trick existed to let
    /// a C test program reach a file-static symbol, and the test that needed
    /// it now lives inside this file.
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
    ///
    /// Out-of-range keys are answered with `None` rather than a panic, which
    /// is what the C's bound test does. `key == u32::MAX` is therefore safe,
    /// and a test says so.
    pub(crate) fn get(&self, key: u32) -> Option<&T> {
        self.row(key).map(|row| &row.entry)
    }

    /// [`Self::get`] with a mutable borrow of the entry.
    ///
    /// No C counterpart is needed: the C hands back a `void *` and the caller
    /// mutates through it regardless of how it was obtained. Rust needs the
    /// two forms to be separate, and this one is what lets a consumer update
    /// an entry in place instead of removing and re-adding it -- which would
    /// change the key.
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
    ///
    /// The C's comment names a field, `maybe_next_key`, that no longer exists
    /// -- the struct calls it `last_key_added` -- which is recorded so that a
    /// reader does not go looking for it.
    ///
    /// # Why the first key after `new` or [`Self::clear`] is 0
    ///
    /// This is the heart of the module and it is not obvious. With
    /// `last_key_added == NO_KEY == u32::MAX`, the clamp
    /// `min(u32::MAX, capacity)` yields `capacity`, so `start_pos` is
    /// `capacity + 1`. The upward scan `(capacity + 1)..capacity` is empty,
    /// the wrap scan starts at 0, and row 0 is vacant on a fresh or cleared
    /// table. Hence key 0 -- which `tests/unit/unit3212.c:113-117` asserts
    /// directly, and which is how the multi handle's admin easy handle comes
    /// to hold `mid` 0.
    ///
    /// The same clamp does a second job: after a shrinking [`Self::resize`]
    /// the cursor can sit at or above the new capacity, and clamping brings it
    /// back into range instead of skipping the upward scan by accident.
    ///
    /// # The latent out-of-bounds read in the C, and why the fix is equivalent
    ///
    /// When `start_pos == capacity + 1`, the C's wrap condition
    /// `key < start_pos` admits `key == tbl->nrows`, so `tbl->rows[nrows]`
    /// would be read one element past the array -- and, if that byte pattern
    /// happened to look NULL, WRITTEN past it. Nothing in `add` prevents that;
    /// it is prevented only by the `nentries == nrows` test above, which
    /// guarantees a vacant row somewhere in `0..nrows` and so guarantees the
    /// loop returns before reaching `nrows`.
    ///
    /// [`Self::free_row_from`] clamps its exclusive bound to the capacity, so
    /// the wrap scan here visits `0..min(start_pos, capacity)` and the extra
    /// index is unreachable by construction rather than by argument. Note that
    /// the C already applies exactly this clamp in `uint32_tbl_clear_rows`
    /// (`lib/uint-table.c:52`, `CURLMIN(upto_excluding, tbl->nrows)`) and
    /// simply omits it here -- so the fix is the C's own idiom applied
    /// consistently, not a new invention.
    ///
    /// The two loops still visit the same keys in the same order. `start_pos`
    /// is `min(last_key_added, capacity) + 1`, hence at most `capacity + 1`,
    /// so the only index the clamp removes is `capacity` itself, which the C
    /// can never reach. `the_wrap_scan_visits_the_same_keys_the_c_would`
    /// asserts that rather than leaving it as prose.
    ///
    /// # The return type
    ///
    /// `Option<u32>`, not `Result<u32, T>`. The C returns a plain `bool` and
    /// writes `UINT32_MAX` into the out-parameter on failure, and the only
    /// caller -- `lib/multi.c:413` -- turns that into `CURLM_OUT_OF_MEMORY`
    /// without wanting the rejected entry back. So `entry` is dropped on the
    /// full-table path, exactly as the C leaves it unstored.
    ///
    /// The C's `if(!entry || !pkey) return FALSE` guard has no counterpart: a
    /// `T` value cannot be null and the key comes back by return rather than
    /// through a pointer.
    ///
    /// # Never `u32::MAX`
    ///
    /// Every key returned is a valid row index, so it is strictly less than
    /// the capacity. [`NO_KEY`] documents the two mechanisms that keep the
    /// capacity itself below `u32::MAX`, and a test fills a table and checks
    /// the value never appears.
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
    /// Returns nothing, deliberately. The C returns nothing, so a `bool`
    /// saying whether the key was present would be a value no caller could
    /// have been written against, and offering it would invite a consumer to
    /// branch on information the C never provided. [`Self::remove_key`] does
    /// report, because it has no C counterpart to be faithful to.
    ///
    /// Removing an absent or out-of-range key is a silent no-op that leaves
    /// the count untouched; `tests/unit/unit3212.c:71-74` removes the same
    /// keys twice and asserts the count does not move.
    ///
    /// `last_key_added` is NOT touched. That is what makes a freed key the
    /// next key assigned when the table is otherwise full -- see
    /// [`Self::clear`], which does the opposite.
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
    ///
    /// `lib/uint-table.h:77-78`: "Get the first entry in the table (with the
    /// smallest `key`). Returns FALSE if the table is empty."
    ///
    /// The C's two out-parameters and `bool` return become one
    /// `Option<(u32, &T)>`. The `tbl->nentries &&` short-circuit at
    /// `lib/uint-table.c:182` is reproduced with [`Self::is_empty`]; it is
    /// redundant, since an empty table has no occupied row for the scan to
    /// find either, but it is what the C does and it is free.
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
    /// All four bullets have a test of their own.
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
    ///
    /// So this is not an oversight to be tidied up later. An iterator would be
    /// a smaller API that cannot express the consumer's access pattern.
    ///
    /// # The `u32::MAX` divergence, recorded as a defect removal
    ///
    /// The C computes `last_key + 1` in `uint32_t`, so `next(UINT32_MAX)`
    /// overflows to 0 and RESTARTS the scan from the beginning -- it would
    /// hand back the first entry again and a caller looping on it would never
    /// terminate. `u32::MAX` is never a valid key, so no correct caller
    /// reaches that path, and `checked_add` turns it into `None` instead. This
    /// is a deliberate divergence: the C's behaviour there is a wrap, not a
    /// documented feature, and reproducing it would mean reproducing an
    /// infinite loop.
    pub(crate) fn next(&self, last_key: u32) -> Option<(u32, &T)> {
        self.next_at(last_key.checked_add(1)?)
    }

    /// A dated key for the occupied row `key`, or `None` if it is vacant or
    /// out of range.
    ///
    /// No C counterpart -- this is the generational half of specification
    /// 0.6.9. The returned [`Key`] carries the row's current generation, so it
    /// stops matching the moment the row is vacated or refilled.
    pub(crate) fn key_of(&self, key: u32) -> Option<Key> {
        self.row(key).map(|row| Key {
            index: key,
            generation: row.generation,
        })
    }

    /// [`Self::get`] with the stale-key check: the entry only if `key` still
    /// names the occupant it was issued for.
    ///
    /// This is the opt-in safety check specification 0.6.9 asks for, and it is
    /// ADDITIONAL to [`Self::get`] rather than a replacement. A caller holding
    /// a bare `u32` keeps the C's semantics exactly, including the C's
    /// inability to tell "the transfer I meant" from "whatever occupies that
    /// row now".
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
    ///
    /// Returns whether anything was removed. This is the one place a report is
    /// offered where [`Self::remove`] gives none, and the difference is
    /// deliberate: [`Self::remove`] mirrors a C function whose `void` return
    /// is part of the contract, whereas this method has no C counterpart and
    /// exists precisely so that a caller can detect a stale key. Discarding
    /// that answer would defeat its whole purpose.
    ///
    /// Under a stale key the table is left completely untouched, which is what
    /// makes this safe to call with a key of unknown age: it cannot evict some
    /// unrelated transfer that has since been given the same row.
    pub(crate) fn remove_key(&mut self, key: Key) -> bool {
        if !self.contains_key(key) {
            return false;
        }
        self.remove(key.index);
        true
    }

    /// The occupied row under `key`, or `None` for a vacant or out-of-range
    /// key.
    ///
    /// The shared bound test behind [`Self::get`], [`Self::contains`],
    /// [`Self::key_of`] and [`Self::get_checked`]. `Vec::get` performs the
    /// C's `key < tbl->nrows` comparison, so the `u32` to `usize` widening
    /// follows the bound test rather than preceding it -- and the widening is
    /// lossless on all four mandated targets, every one of which is 64-bit.
    fn row(&self, key: u32) -> Option<&Row<T>> {
        self.rows.get(key as usize)?.as_ref()
    }

    /// The next generation stamp, advancing the counter.
    ///
    /// `wrapping_add` because the arithmetic must be total, not because the
    /// wrap is reachable: 2^64 occupancy changes at one per nanosecond is
    /// roughly 584 years. A `u32` counter would wrap after about 4.3 billion,
    /// which a long-lived process could plausibly reach, and a wrapped
    /// generation could revive a stale [`Key`]. That is the whole reason the
    /// field is 64 bits wide.
    fn advance_generation(&mut self) -> u64 {
        let issued = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        issued
    }

    /// Fill the vacant row `key` with `entry` and return `key`.
    ///
    /// The four assignments the C's `add` performs on a hit
    /// (`lib/uint-table.c:129-134`): store the entry, bump the count, record
    /// the cursor, report the key. Factored out so that both scans in
    /// [`Self::add`] share one body and cannot drift apart, exactly as the C's
    /// two loops share one hand-copied block -- except that here the copy is
    /// impossible.
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
    ///
    /// One of the C's two scan loops in `add` (`lib/uint-table.c:128-136` and
    /// `:138-146`), which are byte-for-byte identical apart from their bounds.
    ///
    /// The clamp is where the C's latent one-past-the-end read is eliminated;
    /// [`Self::add`] carries the analysis and the proof that the visited keys
    /// are unchanged. Clamping HERE rather than at each call site means the
    /// two scans cannot disagree about it, and it mirrors what the C already
    /// does in `uint32_tbl_clear_rows` (`lib/uint-table.c:52`).
    ///
    /// The scan is linear, over a subslice, and stays that way: a free list or
    /// a vacancy bitmap would find a different row and so change the key
    /// sequence, which specification 0.8.1 freezes.
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
    ///
    /// The shared scan behind [`Self::first`] and [`Self::next`]. The C writes
    /// `UINT32_MAX` and NULL into its out-parameters on a miss, both marked
    /// "always invalid"; `None` supersedes the pair.
    ///
    /// `from` beyond the capacity yields `None`, which is the C's
    /// `for(; key < tbl->nrows; ...)` declining to run at all. The scan is
    /// linear and stays linear -- an index of occupied rows would have to be
    /// maintained across every mutation, and the walk is not on a hot path.
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
    ///
    /// The single mutation primitive behind [`Self::remove`], [`Self::clear`]
    /// and [`Self::resize`]'s shrink path, kept as one function for the same
    /// reason the C does: three callers that each cleared rows their own way
    /// could disagree about the count.
    ///
    /// `Option::take` is where the entry is dropped -- the taken value is a
    /// temporary that falls out of scope at the end of the statement, running
    /// `T`'s `Drop`. That is the destructor call the C makes explicitly, and
    /// it happens for every vacated row whether or not the caller wants it,
    /// which is the one place where "the C passes NULL for `entry_dtor`"
    /// becomes a decision for whoever chooses `T`. This module's
    /// documentation flags it.
    ///
    /// The count and the generation counter are updated after the scan rather
    /// than inside it, because the loop holds a mutable borrow of `rows`.
    /// Advancing the counter by the number of rows vacated is exactly
    /// equivalent to advancing it once per row.
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
//
// A test confirms the automatic drop really runs, with a payload that counts
// its own destructions, so this paragraph is checked rather than asserted.

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
    ///
    /// The C table takes an `entry_dtor` and its only consumer passes NULL, so
    /// no C test exercises destruction at all. In Rust the destructor IS
    /// `Drop`, so it is exercised here: the counter is shared, and every test
    /// that uses this type asserts an exact number of drops rather than "at
    /// least one".
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

    // ---------------------------------------------------------------------
    // `tests/unit/unit3212.c`, ported step for step. The line reference on
    // each test names the assertion it reproduces.
    // ---------------------------------------------------------------------

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

    // ---------------------------------------------------------------------
    // Behaviour the C unit test does not reach.
    // ---------------------------------------------------------------------

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
    ///
    /// The deliberate divergence: the C computes `last_key + 1` in `uint32_t`,
    /// wraps to 0 and hands back the first entry again, which turns a caller's
    /// loop into a non-terminating one. `u32::MAX` is never a valid key, so no
    /// correct caller reaches this.
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
    ///
    /// The C's bound is `key < start_pos` where `start_pos` is at most
    /// `capacity + 1`, so the only index the clamp removes is `capacity`
    /// itself -- which the C can never reach, because the full-table test
    /// guarantees a vacant row below it. This reproduces the C's own scan over
    /// every reachable state of a small table and checks that the key `add`
    /// picks is identical.
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

    // ---------------------------------------------------------------------
    // Destruction accounting. The C's `entry_dtor` becomes `Drop`, so these
    // are the tests the C unit test could not have.
    // ---------------------------------------------------------------------

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

    // ---------------------------------------------------------------------
    // The iteration-under-modification contract of `lib/uint-table.h:88-92`,
    // one test per bullet. The multi handle depends on all four.
    // ---------------------------------------------------------------------

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

    // ---------------------------------------------------------------------
    // Generational keys. Specification 0.6.9's slab, layered on top of the
    // frozen index API rather than replacing it.
    // ---------------------------------------------------------------------

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
        // And a vacated row advances it too, which is what specification
        // 0.6.9's design note asks for: sixteen fills plus sixteen vacatings.
        assert_eq!(table.next_generation, 32);
    }
}
