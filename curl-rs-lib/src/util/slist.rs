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

// THE LICENCE BANNER ABOVE -- 23 lines, and the one spelling rule inside it.

// DEAD CODE, and why every allowance below is at an item rather than here.
//
// The C ABI shim that presents this list to C, `curl-rs-ffi/src/ffi/slist.rs`,
// is already written and is deliberately SELF-CONTAINED: it builds the
// C-shaped chain in C-allocated nodes through the five replaceable
// `curl_global_init_mem` hooks, because an application may release a node with
// `curl_free` or replace the allocator wholesale, and a block produced by
// Rust's `GlobalAlloc` could not be released by the application's `free`. So
// the boundary owns the C chain and this module owns the engine-side value:
// two representations by design, meeting only where the shim converts between
// them.

//! The `curl_slist` string list: an owned, ordered sequence of byte strings.
//!
//! Supersedes `lib/slist.c` and `lib/slist.h`.
//!
//! # What this module supersedes, function by function
//!
//! `lib/slist.c` defines four functions and one static helper:
//!
//! | C function | Measured at | Successor here |
//! |---|---|---|
//! | `slist_get_last` (static) | `:29-43` | none; see below |
//! | `Curl_slist_append_nodup` | `:54-76` | [`SList::append_nodup`] |
//! | `curl_slist_append` | `:85-97` | [`SList::append`] |
//! | `Curl_slist_duplicate` | `:104-121` | [`SList::duplicate`] |
//! | `curl_slist_free_all` | `:124-139` | [`SList::free_all`] |
//!
//! The struct is public too, and is reproduced because it is the shape all 51
//! files under `lib/` and `src/` that touch this type agree on
//! (`include/curl/curl.h:2793-2797`):
//!
//! ```c
//! /* linked-list structure for the CURLOPT_QUOTE option (and other) */
//! struct curl_slist {
//!   char *data;
//!   struct curl_slist *next;
//! };
//! ```
//!
//! # What C's return values meant, and what they stop meaning here
//!
//! Every one of the four C functions signals through a pointer, and three
//! separate ambiguities in that signalling disappear rather than being
//! reproduced. Each is recorded because a reader comparing the two
//! implementations will notice the absence and should find the reason:
//!
//! * **The head return.** All three C constructors return the head of the
//!   list, which is what lets `curl_slist_append(NULL, s)` double as an
//!   initialiser -- the documented idiom is `list = curl_slist_append(list,
//!   s);` starting from `NULL`, and every consumer relies on it. Here the head
//!   is the `&mut self` receiver, so there is nothing to return and nothing to
//!   reassign. [`SList::default`] is the empty list that `NULL` stood for.
//! * **The failure return, and the leak it invites.** C returns `NULL` when
//!   the node allocation fails. A caller that wrote `list =
//!   curl_slist_append(list, s);` has then overwritten its only pointer to a
//!   list that is still allocated -- a well-known footgun that
//!   `docs/libcurl/curl_slist_append.md` works around by telling callers to
//!   keep their own copy of the head. It is reproduced at the ABI boundary
//!   because a program written against curl 8.x depends on it, and it cannot
//!   arise here: `Vec::push` does not report failure, and the list is borrowed
//!   rather than replaced.
//! * **`NULL` meaning two different things.** `Curl_slist_duplicate` returns
//!   `NULL` both when it fails and when the input list was empty -- its own
//!   comment says so, "or NULL in case of an error (or if the input list was
//!   NULL)" (`lib/slist.h:28-30`) -- so a caller cannot distinguish the two.
//!   [`Clone`] removes the ambiguity: cloning an empty list yields an empty
//!   list, and there is no failure case to confuse it with. The C also frees
//!   the partially built output before returning `NULL`; a clone that cannot
//!   partially fail has nothing to unwind.

use std::iter;
use std::slice;
use std::vec;

/// The iterator [`SList::iter`] returns, and the one `&SList` iterates as.
pub type Iter<'a> =
    iter::Map<slice::Iter<'a, Vec<u8>>, fn(&'a Vec<u8>) -> &'a [u8]>;

/// An ordered, owned sequence of byte strings: the engine-side `curl_slist`.
///
/// Supersedes the `struct curl_slist` chain of `lib/slist.c`. The C-shaped
/// struct itself lives only at the ABI boundary, in
/// `curl-rs-ffi/src/ffi/slist.rs`; this type is what the engine holds, and it
/// exposes no node, no successor pointer and nothing intrusive.
///
/// # Invariants
///
/// * **Order is preserved exactly.** Elements come back in the order they were
///   appended, because that order is observable on the wire. See the module
///   documentation for the fixture measurement that makes this binding.
/// * **Bytes are stored verbatim.** No sorting, deduplication, trimming,
///   case-folding, encoding validation or normalisation happens at any point.
///   An element is the byte sequence that was handed in, including the empty
///   sequence and including bytes that are not valid UTF-8.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SList {
    /// The elements, in the order they were appended.
    ///
    /// Private, and deliberately so: handing out the `Vec` itself would let a
    /// caller sort or deduplicate a live list, which the order contract
    /// forbids. [`as_slice`] lends a shared borrow and [`into_inner`] hands
    /// over ownership of a list that is thereby consumed, so neither offers
    /// in-place reordering of a list still in use.
    items: Vec<Vec<u8>>,
}

impl SList {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Appends a **copy** of `data` at the tail.
    ///
    /// Supersedes the exported `curl_slist_append` (`lib/slist.c:85-97`), which
    /// is symbol 85 of the 100 in `lib/libcurl.def`. The C is
    ///
    /// ```c
    /// char *dupdata = curlx_strdup(data);
    /// if(!dupdata)
    ///   return NULL;
    /// list = Curl_slist_append_nodup(list, dupdata);
    /// if(!list)
    ///   curlx_free(dupdata);
    /// return list;
    /// ```
    ///
    /// so the four behaviours it composes map as follows:
    ///
    /// * **It copies.** `curlx_strdup` duplicates the string, which is why
    ///   `docs/libcurl/curl_slist_append.md` says the function "copies the
    ///   string" and the caller keeps ownership of its own buffer. `data` is
    ///   borrowed here and copied with `to_vec`, which is the same contract.
    ///   [`append_nodup`] is the variant that does not copy.
    /// * **It appends at the TAIL**, via `Curl_slist_append_nodup`, which links
    ///   the node after `slist_get_last(list)`. `Vec::push` puts it in the same
    ///   place.
    /// * **It returns the head**, which is what lets it double as an
    ///   initialiser. The head is the receiver here, so there is nothing to
    ///   return and nothing for a caller to reassign.
    /// * **It returns `NULL` on allocation failure**, having freed the
    ///   duplicate it had just made so that nothing leaks. Neither half can
    ///   arise here: `Vec::push` reports no failure, and there is no
    ///   intermediate duplicate with a separate lifetime to release.
    pub fn append(&mut self, data: &[u8]) {
        self.items.push(data.to_vec());
    }

    /// Appends `data` at the tail, **taking ownership** of it.
    ///
    /// Supersedes `Curl_slist_append_nodup` (`lib/slist.c:54-76`), which is
    /// internal: `lib/slist.h:38-39` declares it and `lib/libcurl.def` does not
    /// export it. Three properties of the C are worth naming, because two of
    /// them are the whole reason the function exists separately from
    /// [`append`]:
    ///
    /// * **It does not copy.** `new_item->data = CURL_UNCONST(data)` stores the
    ///   pointer it was given, and the comment at `lib/slist.c:46-48` says the
    ///   string "should have been `malloc()`ated" because the list now owns it.
    ///   Taking `Vec<u8>` by value is that same transfer, expressed so the
    ///   compiler enforces it: the caller cannot keep using the buffer, and
    ///   cannot free it twice.
    /// * **On failure it does NOT release the string.** `lib/slist.c:51-52`
    ///   states it outright -- "If an error occurs, NULL is returned and the
    ///   string argument is NOT released" -- leaving the caller holding a
    ///   buffer it must free itself. There is no failure path here, so there is
    ///   no split ownership to reason about; the "nodup" distinction survives
    ///   only in this name, because Rust makes it structural rather than
    ///   conventional.
    /// * **`DEBUGASSERT(data)`** guards against a null string, which is a
    ///   programming error rather than a runtime condition -- unlike
    ///   [`append`], which reaches `strdup` and would have to handle it.
    pub fn append_nodup(&mut self, data: Vec<u8>) {
        self.items.push(data);
    }

    /// Appends a copy of a UTF-8 string at the tail.
    #[allow(dead_code)]
    pub(crate) fn push_str(&mut self, data: &str) {
        self.items.push(data.as_bytes().to_vec());
    }

    /// A deep copy of this list, in the same order.
    ///
    /// Two properties of the C do not survive, and both are improvements
    /// rather than divergences:
    ///
    /// * **`NULL` is no longer ambiguous.** `lib/slist.h:28-30` says the C
    ///   returns "NULL in case of an error (or if the input list was NULL)", so
    ///   a caller cannot tell failure from an empty input. Cloning an empty
    ///   list yields an empty list, and there is no failure value to confuse it
    ///   with.
    /// * **There is no partial output to unwind.** On a failed append the C
    ///   calls `curl_slist_free_all(outlist)` to release what it had built so
    ///   far. A clone cannot partially fail, so the cleanup path disappears
    ///   along with the leak it existed to prevent.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn duplicate(&self) -> Self {
        self.clone()
    }

    /// Releases every element and the storage that held them.
    ///
    /// Supersedes the exported `curl_slist_free_all` (`lib/slist.c:124-139`),
    /// which is symbol 86 of the 100 in `lib/libcurl.def`. The C is a
    /// `do`/`while` that frees each payload before its node and stops when the
    /// successor is null:
    ///
    /// ```c
    /// if(!list)
    ///   return;
    /// item = list;
    /// do {
    ///   next = item->next;
    ///   Curl_safefree(item->data);
    ///   curlx_free(item);
    ///   item = next;
    /// } while(next);
    /// ```
    pub fn free_all(&mut self) {
        // Assigning a fresh empty `Vec` drops the old one, which drops every
        // element and then releases the spine. `Vec::clear` would drop the
        // elements but retain the spine, which is `clear`'s job rather than
        // this one's.
        self.items = Vec::new();
    }

    /// Empties the list, keeping the storage for reuse.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        self.items.clear();
    }

    /// The number of elements.
    ///
    /// C has no counterpart: counting a `curl_slist` means walking it, which is
    /// what `slist_get_last` (`lib/slist.c:29-43`) does for its own purposes.
    /// Here the count is stored, so this is O(1).
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the list holds no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Borrows each element in append order.
    pub fn iter(&self) -> Iter<'_> {
        self.items.iter().map(Vec::as_slice)
    }

    /// Borrows each element in append order, decoded as UTF-8 where possible.
    #[allow(dead_code)]
    pub(crate) fn iter_str(&self) -> impl Iterator<Item = Option<&str>> + '_ {
        self.iter().map(|value| std::str::from_utf8(value).ok())
    }

    /// Borrows the element at `index`, or `None` if there is no such element.
    ///
    /// Index zero is the head, and the last index is the element
    /// `slist_get_last` would have returned. There is no C counterpart because
    /// a chain is not indexable; a C caller walks to the position it wants.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn get(&self, index: usize) -> Option<&[u8]> {
        self.items.get(index).map(Vec::as_slice)
    }

    /// Borrows the first element, or `None` when the list is empty.
    ///
    /// The head of the chain: what a non-null `struct curl_slist *` points at.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn first(&self) -> Option<&[u8]> {
        self.items.first().map(Vec::as_slice)
    }

    /// Borrows the last element, or `None` when the list is empty.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn last(&self) -> Option<&[u8]> {
        self.items.last().map(Vec::as_slice)
    }

    /// Borrows every element at once.
    ///
    /// The bulk form of [`iter`], for a caller that wants a slice rather
    /// than an iterator -- notably the ABI boundary, which walks the elements
    /// in order to build a C-shaped chain for `curl_slist_append` or for the
    /// `struct curl_slist **` out-parameter of `curl_trailer_callback`
    /// (`include/curl/curl.h:407-408`).
    #[must_use]
    pub fn as_slice(&self) -> &[Vec<u8>] {
        &self.items
    }

    /// Consumes the list and yields its elements, in append order.
    ///
    /// The ownership-transfer counterpart of [`as_slice`], for the ABI boundary
    /// again: handing a built list over to C means giving up the buffers rather
    /// than copying them, which is the same transfer `append_nodup` performs in
    /// the other direction.
    #[must_use]
    pub fn into_inner(self) -> Vec<Vec<u8>> {
        self.items
    }
}

// THE BULK-BUILDING AND ITERATION TRAITS.

impl Extend<Vec<u8>> for SList {
    /// Appends every value at the tail, taking ownership of each.
    ///
    /// The bulk form of [`SList::append_nodup`]: the same transfer, the same
    /// tail position, once per value, and the incoming order preserved. C
    /// builds a chain from many strings by calling append in a loop, which is
    /// exactly what `Curl_slist_duplicate` does (`lib/slist.c:109-119`).
    fn extend<I: IntoIterator<Item = Vec<u8>>>(&mut self, values: I) {
        self.items.extend(values);
    }
}

impl<'a> Extend<&'a [u8]> for SList {
    /// Appends a copy of every value at the tail.
    ///
    /// The bulk form of [`SList::append`], with the same copying contract: the
    /// caller keeps its buffers.
    fn extend<I: IntoIterator<Item = &'a [u8]>>(&mut self, values: I) {
        self.items
            .extend(values.into_iter().map(|value| value.to_vec()));
    }
}

impl FromIterator<Vec<u8>> for SList {
    /// Collects owned buffers into a list, in the order they arrive.
    fn from_iter<I: IntoIterator<Item = Vec<u8>>>(values: I) -> Self {
        Self {
            items: values.into_iter().collect(),
        }
    }
}

impl<'a> FromIterator<&'a [u8]> for SList {
    /// Collects copies of borrowed buffers into a list, in the order they
    /// arrive.
    fn from_iter<I: IntoIterator<Item = &'a [u8]>>(values: I) -> Self {
        Self {
            items: values.into_iter().map(|value| value.to_vec()).collect(),
        }
    }
}

impl IntoIterator for SList {
    type Item = Vec<u8>;
    type IntoIter = vec::IntoIter<Vec<u8>>;

    /// Consumes the list and yields each element, in append order.
    ///
    /// The owning counterpart of [`SList::iter`]. Yields `Vec<u8>` rather than
    /// `&[u8]` because ownership moves out with the value.
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl<'a> IntoIterator for &'a SList {
    type Item = &'a [u8];
    type IntoIter = Iter<'a>;

    /// Borrows each element in append order.
    ///
    /// Identical to [`SList::iter`], and the same [`Iter`] type, so
    /// `for value in &list` and `list.iter()` cannot come to disagree about
    /// either the order or the item type.
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::SList;

    /// Three header lines in a fixed order, the shape `CURLOPT_HTTPHEADER`
    /// carries and the shape whose order is observable on the wire.
    const HEADERS: [&[u8]; 3] = [
        b"Accept: */*",
        b"X-Trace-Id: 7",
        b"Content-Type: application/octet-stream",
    ];

    /// A list holding [`HEADERS`], built through the exported append path.
    fn headers() -> SList {
        let mut list = SList::new();
        for header in HEADERS {
            list.append(header);
        }
        list
    }

    /// The elements of `list` as a vector of owned buffers, for comparison.
    fn collected(list: &SList) -> Vec<Vec<u8>> {
        list.iter().map(<[u8]>::to_vec).collect()
    }

    // ORDER IS THE CONTRACT. This is the module's headline invariant, so it
    // is asserted first and from every direction.

    #[test]
    fn order_is_preserved_exactly_as_appended() {
        let mut list = SList::new();
        list.append(b"A");
        list.append(b"B");
        list.append(b"C");

        assert_eq!(
            collected(&list),
            vec![b"A".to_vec(), b"B".to_vec(), b"C".to_vec()]
        );
        assert_eq!(list.first(), Some(&b"A"[..]));
        assert_eq!(list.last(), Some(&b"C"[..]));
        assert_eq!(list.get(1), Some(&b"B"[..]));
    }

    #[test]
    fn every_way_of_appending_lands_at_the_tail() {
        let mut list = SList::new();
        list.append(b"first");
        list.append_nodup(b"second".to_vec());
        list.push_str("third");
        list.extend([b"fourth".to_vec()]);
        list.extend([&b"fifth"[..]]);

        assert_eq!(
            collected(&list),
            vec![
                b"first".to_vec(),
                b"second".to_vec(),
                b"third".to_vec(),
                b"fourth".to_vec(),
                b"fifth".to_vec(),
            ]
        );
    }

    #[test]
    fn collecting_preserves_the_incoming_order() {
        let owned: SList =
            [b"one".to_vec(), b"two".to_vec()].into_iter().collect();
        assert_eq!(collected(&owned), vec![b"one".to_vec(), b"two".to_vec()]);

        let borrowed: SList = HEADERS.into_iter().collect();
        assert_eq!(collected(&borrowed), collected(&headers()));
    }

    #[test]
    fn nothing_sorts_deduplicates_trims_or_folds_case() {
        let mut list = SList::new();
        // Reverse-alphabetical, mixed case, padded, and repeated: a sort, a
        // trim, a case fold or a deduplication would each be visible here.
        list.append(b"zulu");
        list.append(b"  Alpha  ");
        list.append(b"ALPHA");
        list.append(b"  Alpha  ");

        assert_eq!(
            collected(&list),
            vec![
                b"zulu".to_vec(),
                b"  Alpha  ".to_vec(),
                b"ALPHA".to_vec(),
                b"  Alpha  ".to_vec(),
            ]
        );
    }

    #[test]
    fn duplicate_entries_are_kept() {
        // `CURLOPT_HTTPHEADER` legitimately carries repeated header names, so
        // two appends of one value must produce two elements.
        let mut list = SList::new();
        list.append(b"Set-Cookie: a=1");
        list.append(b"Set-Cookie: a=1");

        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0), list.get(1));
    }

    #[test]
    fn a_thousand_appends_preserve_order_and_count() {
        // Cheap regression cover against a future "optimisation" that batches,
        // reorders or deduplicates.
        let mut list = SList::new();
        for index in 0..1000_u32 {
            list.push_str(&format!("X-Item-{index}"));
        }

        assert_eq!(list.len(), 1000);
        for (index, value) in list.iter().enumerate() {
            assert_eq!(value, format!("X-Item-{index}").as_bytes());
        }
    }

    // The four C functions.

    #[test]
    fn appending_to_an_empty_list_creates_a_one_element_list() {
        // `curl_slist_append(NULL, s)` doubles as an initialiser, and every
        // consumer relies on it. The empty list is what `NULL` stood for.
        let mut list = SList::new();
        assert!(list.is_empty());

        list.append(b"Expect:");

        assert!(!list.is_empty());
        assert_eq!(list.len(), 1);
        assert_eq!(list.first(), Some(&b"Expect:"[..]));
    }

    #[test]
    fn new_and_default_agree_and_are_empty() {
        assert_eq!(SList::new(), SList::default());
        assert!(SList::new().is_empty());
        assert_eq!(SList::default().len(), 0);
        assert_eq!(SList::default().first(), None);
        assert_eq!(SList::default().last(), None);
        assert_eq!(SList::default().iter().count(), 0);
    }

    #[test]
    fn append_copies_so_the_caller_keeps_its_buffer() {
        // `curlx_strdup` duplicates, so the caller's buffer stays its own and
        // stays usable. Mutating it afterwards must not reach the list.
        let mut buffer = b"Accept: text/plain".to_vec();
        let mut list = SList::new();
        list.append(&buffer);

        buffer.clear();
        buffer.extend_from_slice(b"overwritten");

        assert_eq!(list.first(), Some(&b"Accept: text/plain"[..]));
    }

    #[test]
    fn append_nodup_stores_the_buffer_it_is_given() {
        // The ownership-transfer form. There is no copy, and there is no way
        // for the caller to retain the buffer: that is the whole distinction
        // from `append`, and Rust makes it structural rather than documented.
        let buffer = b"Authorization: Basic Zm9v".to_vec();
        let mut list = SList::new();
        list.append_nodup(buffer);

        assert_eq!(list.first(), Some(&b"Authorization: Basic Zm9v"[..]));
    }

    #[test]
    fn push_str_stores_the_utf8_bytes() {
        let mut list = SList::new();
        list.push_str("Accept-Language: sv-SE");
        list.push_str("X-Note: \u{e5}\u{e4}\u{f6}");

        assert_eq!(list.get(0), Some(&b"Accept-Language: sv-SE"[..]));
        assert_eq!(list.get(1), Some("X-Note: \u{e5}\u{e4}\u{f6}".as_bytes()));
    }

    #[test]
    fn duplicate_is_a_deep_copy_that_preserves_order() {
        let original = headers();
        let copy = original.duplicate();

        assert_eq!(collected(&copy), collected(&original));
        assert_eq!(copy, original);
    }

    #[test]
    fn duplicate_and_clone_agree() {
        // `duplicate` exists so a grep for the C stem lands; it must not drift
        // away from the trait it delegates to.
        let original = headers();
        assert_eq!(original.duplicate(), original.clone());
    }

    #[test]
    fn mutating_a_duplicate_does_not_touch_the_original() {
        let original = headers();
        let mut copy = original.duplicate();
        copy.append(b"X-Added: 1");
        copy.free_all();

        assert!(copy.is_empty());
        assert_eq!(original.len(), HEADERS.len());
        assert_eq!(collected(&original), collected(&headers()));
    }

    #[test]
    fn duplicating_an_empty_list_yields_an_empty_list() {
        // The C returns NULL here, and `lib/slist.h:28-30` admits that NULL
        // also means failure -- so a C caller cannot tell the two apart. The
        // clone is unambiguous: empty in, empty out, no failure value.
        let empty = SList::new();
        let copy = empty.duplicate();

        assert!(copy.is_empty());
        assert_eq!(copy, empty);
    }

    #[test]
    fn free_all_empties_the_list_and_is_idempotent() {
        let mut list = headers();
        list.free_all();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert_eq!(list.iter().count(), 0);

        // Calling it again must be harmless, mirroring the `if(!list) return;`
        // that opens `curl_slist_free_all` (`lib/slist.c:129-130`).
        list.free_all();
        assert!(list.is_empty());
    }

    #[test]
    fn free_all_on_an_empty_list_is_a_no_op() {
        // `docs/libcurl/curl_slist_free_all.md`: "Passing in a NULL pointer in
        // *list* makes this function return immediately with no action."
        let mut list = SList::new();
        list.free_all();
        assert_eq!(list, SList::new());
    }

    #[test]
    fn free_all_releases_the_spine_and_clear_keeps_it() {
        // The documented difference between the two, asserted rather than
        // asserted-in-prose. Reaching `items` directly is what a child test
        // module is for; no public accessor exists for capacity, and none
        // should, since a caller has no business knowing.
        let mut kept = headers();
        kept.clear();
        assert!(kept.is_empty());
        assert!(
            kept.items.capacity() > 0,
            "clear must keep the spine for reuse"
        );

        let mut released = headers();
        released.free_all();
        assert!(released.is_empty());
        assert_eq!(
            released.items.capacity(),
            0,
            "free_all must return the spine to the allocator"
        );
    }

    #[test]
    fn clear_on_an_empty_list_is_a_no_op() {
        let mut list = SList::new();
        list.clear();
        assert_eq!(list, SList::new());
    }

    #[test]
    fn a_cleared_list_can_be_refilled_in_order() {
        let mut list = headers();
        list.clear();
        list.append(b"X-Second-Life: 1");

        assert_eq!(collected(&list), vec![b"X-Second-Life: 1".to_vec()]);
    }

    #[test]
    fn dropping_a_list_releases_every_element() {
        // A drop-counting wrapper is not available: the element type is
        // `Vec<u8>`, fixed by the byte-transparency requirement, and it cannot
        // be instrumented. What IS observable is that nothing leaks, and that
        // is asserted by the tools rather than by this body -- `cargo miri
        // test` reports a leaked allocation as a failure, and the
        // AddressSanitizer gate reports it too. Each element below owns a
        // heap buffer large enough that a missed release would be reported.
        let mut list = SList::new();
        for index in 0..64_u32 {
            list.append_nodup(vec![u8::try_from(index % 256).unwrap(); 512]);
        }
        assert_eq!(list.len(), 64);
        drop(list);

        // Dropping a list that still holds a clone's worth of data, and a list
        // that was emptied first, both have to be clean.
        let original = headers();
        let copy = original.duplicate();
        drop(original);
        assert_eq!(collected(&copy), collected(&headers()));
        drop(copy);
    }

    // Byte transparency: the tests that justify `Vec<Vec<u8>>` over
    // `Vec<String>`.

    #[test]
    fn arbitrary_bytes_round_trip_unchanged() {
        // 0x80 and 0xFF are not valid UTF-8 on their own; the third sequence
        // is valid multi-byte UTF-8. All three must come back byte for byte.
        // A `String` element type could store only the third.
        let latin1 = b"X-Name: Bj\xF8rn";
        let lone_continuation = b"X-Raw: \x80\x81\x82";
        let every_high_byte: Vec<u8> = (0x80..=0xFF_u8).collect();
        let utf8 = "X-Note: \u{a5}\u{20ac}\u{1f600}".as_bytes();

        let mut list = SList::new();
        list.append(latin1);
        list.append(lone_continuation);
        list.append(&every_high_byte);
        list.append(utf8);

        assert_eq!(list.get(0), Some(&latin1[..]));
        assert_eq!(list.get(1), Some(&lone_continuation[..]));
        assert_eq!(list.get(2), Some(&every_high_byte[..]));
        assert_eq!(list.get(3), Some(utf8));
    }

    #[test]
    fn iter_str_reports_invalid_utf8_as_none() {
        let mut list = SList::new();
        list.append(b"Accept: */*");
        list.append(b"X-Raw: \xFF\xFE");
        list.push_str("X-Note: \u{20ac}");

        let decoded: Vec<Option<&str>> = list.iter_str().collect();
        assert_eq!(
            decoded,
            vec![Some("Accept: */*"), None, Some("X-Note: \u{20ac}")]
        );

        // Nothing was replaced or skipped: the raw bytes are still reachable.
        assert_eq!(list.get(1), Some(&b"X-Raw: \xFF\xFE"[..]));
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn an_interior_nul_is_stored_verbatim() {
        // C cannot produce such an element -- `strdup` stops at the first NUL,
        // and `CStr::from_ptr` at the ABI boundary stops there too -- so the
        // no-interior-NUL invariant is enforced where it arises rather than
        // here. This module is transparent about whatever it is handed, which
        // is what `Vec<u8>` storage means, and the assertion records that
        // choice so nobody later adds a rejection that C never had.
        let with_nul = b"X-Raw: a\0b";
        let mut list = SList::new();
        list.append(with_nul);

        assert_eq!(list.get(0), Some(&with_nul[..]));
        assert_eq!(list.get(0).map(<[u8]>::len), Some(10));
    }

    #[test]
    fn an_empty_element_is_a_real_element() {
        // C stores a one-byte `""` buffer, which is a present element and not
        // an absence. `Expect:` with no value is exactly this case in practice.
        let mut list = SList::new();
        list.append(b"");
        list.append_nodup(Vec::new());
        list.push_str("");

        assert!(!list.is_empty(), "a list of empty elements is not empty");
        assert_eq!(list.len(), 3);
        for value in &list {
            assert!(value.is_empty());
        }
    }

    // Traversal, borrowing and equality.

    #[test]
    fn iteration_by_reference_and_by_value_agree_with_iter() {
        let list = headers();

        let by_reference: Vec<Vec<u8>> =
            (&list).into_iter().map(<[u8]>::to_vec).collect();
        let from_iter = collected(&list);
        let by_value: Vec<Vec<u8>> = list.into_iter().collect();

        assert_eq!(by_reference, from_iter);
        assert_eq!(by_value, from_iter);
    }

    #[test]
    fn as_slice_and_into_inner_expose_the_same_order() {
        let list = headers();
        let borrowed: Vec<Vec<u8>> = list.as_slice().to_vec();
        let owned = list.into_inner();

        assert_eq!(borrowed, owned);
        assert_eq!(owned.len(), HEADERS.len());
        assert_eq!(owned[0], HEADERS[0]);
        assert_eq!(owned[2], HEADERS[2]);
    }

    #[test]
    fn get_out_of_range_is_none() {
        let list = headers();
        assert_eq!(list.get(HEADERS.len()), None);
        assert_eq!(list.get(usize::MAX), None);
        assert_eq!(SList::new().get(0), None);
    }

    #[test]
    fn equality_is_element_wise_and_order_sensitive() {
        let forwards = headers();

        let mut backwards = SList::new();
        for header in HEADERS.iter().rev() {
            backwards.append(header);
        }

        assert_eq!(forwards, headers());
        assert_ne!(forwards, backwards);
        assert_eq!(forwards.len(), backwards.len());
    }

    #[test]
    fn extending_an_existing_list_appends_rather_than_replaces() {
        let mut list = SList::new();
        list.append(b"Accept: */*");
        list.extend(HEADERS);

        assert_eq!(list.len(), 1 + HEADERS.len());
        assert_eq!(list.first(), Some(&b"Accept: */*"[..]));
        assert_eq!(list.last(), Some(HEADERS[2]));
    }
}
