// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The two exported string-list functions -- supersedes the public half of
//! `lib/slist.c`.
//!
//! | Symbol | C authority | Failure answer |
//! |--------|-------------|----------------|
//! | `curl_slist_append` | `lib/slist.c:85-97` | null |
//! | `curl_slist_free_all` | `lib/slist.c:124-139` | none: it is `void` |
//!
//! These are two of the 100 names in `lib/libcurl.def` -- its lines 85 and
//! 86 -- and they are the only two this module may define. The prototypes are
//! frozen at `include/curl/curl.h:2842-2849` and `:2853-2859`, and a second
//! definition of either name anywhere in the crate is a link error rather
//! than a review finding.
//!
//! # The append contract, exactly
//!
//! `curl_slist_append` duplicates the string, wraps it in a node, and returns
//! the head of the list. Three behaviours are easy to get wrong and are
//! reproduced deliberately:
//!
//! * **The return value is the HEAD, not the new node.** Appending to a
//!   non-empty list returns the same pointer that was passed in. Appending to
//!   `NULL` returns the new node, which is why the documented idiom is
//!   `list = curl_slist_append(list, s);` starting from `NULL`.
//! * **Failure returns null and frees nothing the caller owns.** C frees only
//!   the string it just duplicated (`lib/slist.c:93-94`); the caller's list is
//!   left intact and still needs releasing.
//!   `docs/libcurl/curl_slist_append.md:74-79` states the consequence from the
//!   caller's side -- "To avoid overwriting an existing non-empty list on
//!   failure, the new list should be returned to a temporary variable" -- so
//!   the leak trap is part of the documented contract. Do not "fix" it.
//! * **Append is O(n).** `slist_get_last` walks to the tail on every call
//!   (`lib/slist.c:29-43`). This module walks it too. A tail cache would be
//!   faster and would change nothing a caller can observe -- but performance
//!   is an explicit non-goal, and the extra pointer
//!   would have nowhere to live in a struct whose layout is frozen.
//!
//! # Panic containment
//!
//! Both entry points route their body through [`super::panic_boundary`], the
//! crate's single `catch_unwind`, because unwinding across the C ABI is
//! undefined behaviour. `curl_slist_append` answers null, which is its
//! documented failure value; `curl_slist_free_all` returns quietly, having no
//! channel to report anything through. Neither writes anything derived from
//! the caller's data, which matters because the fixture corpus compares
//! output byte for byte.

use core::ffi::{c_char, c_void};
use core::ptr;

use super::memory;
use super::panic_boundary::{guard_ptr, guard_void};
use super::types::curl_slist;

/// The three allocator operations `lib/slist.c` performs, in one table.
///
/// Gathering them makes the mapping from C to Rust auditable in one place and
/// makes the failure paths executable; the module documentation records why
/// injection was chosen over installing a failing hook.
struct NodeAllocator {
    /// `curlx_strdup(data)` (`lib/slist.c:87`): duplicate the caller's string
    /// into memory the node owns. Returns null on failure.
    dup: unsafe fn(*const c_char) -> *mut c_char,
    /// `curlx_malloc(sizeof(struct curl_slist))` (`lib/slist.c:62`): one
    /// uninitialised node. Returns null on failure.
    node: fn(usize) -> *mut c_void,
    /// `curlx_free` (`lib/slist.c:94` and `:136`): release a block this table
    /// produced.
    release: unsafe fn(*mut c_void),
}

/// The one table the exported entry points use: libcurl's own hooks.
///
/// `dup` is the *strdup* hook rather than malloc-and-copy, which is what
/// `curlx_strdup` resolves to inside libcurl (`lib/curl_setup.h:1474`), so an
/// application's five replaceable callbacks see the same call C makes.
const LIBCURL_HOOKS: NodeAllocator = NodeAllocator {
    dup: memory::strdup,
    node: memory::malloc,
    release: memory::free,
};

/// The body of [`curl_slist_append`], with its allocations injected.
///
/// # Safety
///
/// `list` must be either null or the head of a well-formed, terminating
/// `curl_slist` chain that nothing else is mutating for the duration of the
/// call, and `data` must be either null or a pointer to a NUL-terminated
/// string that stays valid and unmodified for the duration of the call.
/// `alloc`'s three operations must be mutually consistent: a block that `dup`
/// or `node` returns must be releasable by `release`.
unsafe fn append_through(
    alloc: &NodeAllocator,
    list: *mut curl_slist,
    data: *const c_char,
) -> *mut curl_slist {
    if data.is_null() {
        // See the module documentation: C's behaviour here is undefined and
        // the manual forbids the call, so null -- an answer every correct
        // caller already handles -- is the one defined response available.
        return ptr::null_mut();
    }

    // SAFETY: `data` is non-null here and, by this function's contract,
    // addresses a NUL-terminated string that stays valid for the call, which
    // is all a `strdup` requires. The block returned is this module's to own
    // until it is either stored in a node or released below.
    let copied = unsafe { (alloc.dup)(data) };
    if copied.is_null() {
        // C returns here too, and deliberately does NOT touch `list`
        // (`lib/slist.c:89-90`). Freeing it would be the documented leak
        // "fixed" into a use-after-free for every caller that kept its own
        // copy of the head, which is what the manual tells them to do.
        return ptr::null_mut();
    }

    let node =
        (alloc.node)(core::mem::size_of::<curl_slist>()).cast::<curl_slist>();
    if node.is_null() {
        // C frees the duplicate it just made and returns null
        // (`lib/slist.c:93-94`), again leaving the caller's list untouched.
        // SAFETY: `copied` came from this same table's `dup` moments ago, has
        // not been stored anywhere, and is released exactly once.
        unsafe { (alloc.release)(copied.cast::<c_void>()) };
        return ptr::null_mut();
    }

    // SAFETY: `node` is a fresh, uninitialised block of exactly
    // `size_of::<curl_slist>()` bytes from an allocator that returns memory
    // suitably aligned for any fundamental type, and `curl_slist` needs only
    // pointer alignment. Writing the whole struct is its initialization, and
    // it happens before any read.
    unsafe {
        node.write(curl_slist {
            data: copied,
            next: ptr::null_mut(),
        });
    }

    if list.is_null() {
        // "if this is the first item, then new_item *is* the list"
        // (`lib/slist.c:69-71`).
        return node;
    }

    // SAFETY: by contract `list` heads a well-formed, terminating chain that
    // nothing else is mutating, so every `next` read below is either null or a
    // live node, and the walk ends. `node` is live, initialised and owned by
    // nobody else, so publishing it as the tail's successor hands the chain
    // its single owner of that node.
    unsafe {
        let mut tail = list;
        while !(*tail).next.is_null() {
            tail = (*tail).next;
        }
        (*tail).next = node;
    }

    // The head does not move on append: a caller writing
    // `list = curl_slist_append(list, s)` in a loop depends on it.
    list
}

/// The body of [`curl_slist_free_all`], with its release injected.
///
/// # Safety
///
/// `list` must be either null or the head of a well-formed, terminating
/// `curl_slist` chain whose nodes and whose non-null `data` blocks all came
/// from `alloc`, none of which has been released already, and which nothing
/// else is using for the duration of the call. The chain must not be used
/// afterwards.
unsafe fn free_all_through(alloc: &NodeAllocator, list: *mut curl_slist) {
    // A null list falls straight out of the loop condition, which is C's
    // `if(!list) return;` (`lib/slist.c:129-130`) expressed once instead of
    // twice.
    let mut item = list;
    while !item.is_null() {
        // SAFETY: `item` is non-null by the loop condition and, by contract,
        // addresses a live node, so `next` is initialised. It is read BEFORE
        // the node is released -- reading it after would be a use-after-free,
        // which is why C keeps the same order (`lib/slist.c:133-137`).
        let next = unsafe { (*item).next };
        // SAFETY: `data` and the node itself both came from `alloc` by
        // contract and neither has been released, so each is released exactly
        // once here. A null `data` is forwarded rather than filtered, which is
        // what C's `Curl_safefree` does too, so an accounting hook sees the
        // same calls.
        unsafe {
            (alloc.release)((*item).data.cast::<c_void>());
            (alloc.release)(item.cast::<c_void>());
        }
        item = next;
    }
}

/// Appends a copy of a string to a linked list, returning the list head.
///
/// # Safety
///
/// `list` must be either null or the head of a well-formed `curl_slist` chain
/// produced by this function, and `data` must be either null or a pointer to
/// a NUL-terminated string that stays valid for the duration of the call.
/// Neither the chain nor the string may be mutated by another thread while
/// this runs. The returned list must eventually be released with
/// [`curl_slist_free_all`].
#[no_mangle]
pub unsafe extern "C" fn curl_slist_append(
    list: *mut curl_slist,
    data: *const c_char,
) -> *mut curl_slist {
    // SAFETY: this function's contract is exactly `append_through`'s, and the
    // caller's two pointers reach it unchanged. Containment cannot weaken it:
    // it only substitutes a documented failure value for a return.
    guard_ptr(|| unsafe { append_through(&LIBCURL_HOOKS, list, data) })
}

/// Releases an entire list, including every string it holds.
///
/// # Safety
///
/// `list` must be either null or the head of a well-formed `curl_slist` chain
/// produced by [`curl_slist_append`], none of whose nodes has been released
/// already, and must not be used afterwards. No other thread may be using the
/// chain while this runs.
#[no_mangle]
pub unsafe extern "C" fn curl_slist_free_all(list: *mut curl_slist) {
    // SAFETY: this function's contract is exactly `free_all_through`'s, and
    // the caller's pointer reaches it unchanged. `curl_slist_free_all` has no
    // error channel, so containment can only return quietly, which is what
    // `guard_void` does.
    guard_void(|| unsafe { free_all_through(&LIBCURL_HOOKS, list) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::handle;
    use crate::ffi::panic_boundary::contained;
    use core::ffi::CStr;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Walks a chain the way a C consumer does -- `->data`, then `->next` --
    /// copying each string out as raw bytes, so a payload that is not UTF-8
    /// survives the round trip.
    fn collect(list: *mut curl_slist) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut node = list;
        while !node.is_null() {
            // SAFETY: `node` came from `curl_slist_append` and has not been
            // released, so both fields are initialised and `data` is the
            // NUL-terminated copy that call made. Each borrow ends inside its
            // own iteration and nothing mutates the chain meanwhile.
            unsafe {
                out.push(CStr::from_ptr((*node).data).to_bytes().to_vec());
                node = (*node).next;
            }
        }
        out
    }

    /// Appends every item in order through the exported entry point, adding
    /// each terminator here so a payload may hold any byte at all.
    fn build(items: &[&[u8]]) -> *mut curl_slist {
        let mut list: *mut curl_slist = ptr::null_mut();
        for item in items {
            let mut owned = item.to_vec();
            owned.push(0);
            // SAFETY: `list` is null or a chain these same calls built, and
            // `owned` is a live NUL-terminated buffer for the call's duration.
            let next = unsafe {
                curl_slist_append(list, owned.as_ptr().cast::<c_char>())
            };
            assert!(!next.is_null(), "appending {item:?} must succeed");
            list = next;
        }
        list
    }

    #[test]
    fn appending_preserves_insertion_order() {
        let list = build(&[b"Accept: */*", b"X-One: 1", b"X-Two: 2"]);
        assert_eq!(
            collect(list),
            [
                b"Accept: */*".to_vec(),
                b"X-One: 1".to_vec(),
                b"X-Two: 2".to_vec(),
            ]
        );
        // SAFETY: `list` is the chain just built and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn the_first_append_returns_the_new_node_and_later_ones_return_the_head() {
        let first = b"one\0";
        // SAFETY: a null list plus a live NUL-terminated string is the
        // documented way to start a list.
        let head = unsafe {
            curl_slist_append(ptr::null_mut(), first.as_ptr().cast::<c_char>())
        };
        assert!(!head.is_null());

        let second = b"two\0";
        // SAFETY: `head` is the one-node chain from the call above.
        let again = unsafe {
            curl_slist_append(head, second.as_ptr().cast::<c_char>())
        };
        assert_eq!(again, head, "appending must return the ORIGINAL head");
        assert_eq!(collect(head), [b"one".to_vec(), b"two".to_vec()]);
        // SAFETY: `head` owns both nodes and is not used afterwards.
        unsafe { curl_slist_free_all(head) };
    }

    #[test]
    fn the_string_is_copied_and_the_callers_buffer_may_be_scribbled() {
        let mut buffer = b"copied\0".to_vec();
        // SAFETY: `buffer` is a live NUL-terminated string for this call.
        let list = unsafe {
            curl_slist_append(ptr::null_mut(), buffer.as_ptr().cast::<c_char>())
        };
        assert!(!list.is_null());
        // SAFETY: reading the node the call above produced.
        let stored = unsafe { (*list).data };
        assert_ne!(
            stored.cast_const(),
            buffer.as_ptr().cast::<c_char>(),
            "the node must not alias the caller's buffer"
        );

        // Destroy the caller's copy completely rather than merely dropping it:
        // a borrowed `data` would read back as 0xFF bytes or worse.
        buffer.iter_mut().for_each(|byte| *byte = 0xFF);
        drop(buffer);

        assert_eq!(collect(list), [b"copied".to_vec()]);
        // SAFETY: `list` owns its node and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn a_payload_of_arbitrary_bytes_is_copied_byte_for_byte() {
        // A UTF-8 sequence, a lone continuation byte and 0xFF, none of which a
        // `String` could carry. These lists hold header values, `--resolve`
        // entries and `CURLOPT_QUOTE` commands, so a byte altered here
        // silently changes what a consumer believes it configured.
        let payload: &[u8] = &[0xC3, 0xA9, 0x80, 0xFF, b'=', b'1'];
        let list = build(&[payload]);
        assert_eq!(collect(list), [payload.to_vec()]);
        // SAFETY: `list` owns its node and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn an_interior_nul_truncates_exactly_as_strdup_does() {
        // C duplicates with `strdup`, which stops at the first NUL, so the
        // stored string is the prefix. Reproduced rather than improved: a
        // longer copy would make `->data` disagree with what every C
        // consumer's own `strlen` reports about it.
        let list = build(&[b"keep\0dropped"]);
        assert_eq!(collect(list), [b"keep".to_vec()]);
        // SAFETY: `list` owns its node and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn an_empty_string_is_a_legitimate_entry() {
        let list = build(&[b"", b"after"]);
        assert_eq!(collect(list), [Vec::new(), b"after".to_vec()]);
        // SAFETY: `list` is the chain just built and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn a_null_string_is_refused_without_touching_the_list() {
        let list = build(&[b"kept"]);
        // SAFETY: passing a null `data` is exactly what this asserts about,
        // and `list` heads the chain just built.
        let result = unsafe { curl_slist_append(list, ptr::null()) };
        assert!(result.is_null(), "a null string must not produce a node");
        assert_eq!(
            collect(list),
            [b"kept".to_vec()],
            "the list must be untouched"
        );
        // SAFETY: `list` still owns its single node and is not used
        // afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        // SAFETY: null is explicitly permitted, and C returns early on it
        // (`lib/slist.c:129-130`).
        unsafe { curl_slist_free_all(ptr::null_mut()) };
    }

    #[test]
    fn the_node_layout_is_the_frozen_one() {
        // Whatever a caller does, the node stays the frozen two words in the
        // frozen order, because a consumer reads `->data` and `->next`
        // directly (`include/curl/curl.h:2793-2797`).
        use core::mem::{align_of, size_of};
        assert_eq!(size_of::<curl_slist>(), 2 * size_of::<*mut c_void>());
        assert_eq!(align_of::<curl_slist>(), align_of::<*mut c_void>());
    }

    #[test]
    fn a_long_list_appends_at_the_tail_every_time() {
        // Exercises the O(n) tail walk on every append, which is the part of
        // the C this module reproduces rather than optimises.
        let owned: Vec<Vec<u8>> =
            (0..64).map(|n| format!("item-{n}").into_bytes()).collect();
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let list = build(&refs);
        assert_eq!(collect(list), owned);
        // SAFETY: `list` owns all 64 nodes and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn the_conversion_helper_reads_a_chain_this_module_built() {
        // The other half of the boundary. `handle::slist_to_vec` is the one
        // sanctioned C-chain-to-`Vec` conversion, and its own tests build
        // stack nodes deliberately so they depend on no allocator; this closes
        // that loop from the allocating side, and it is why this module writes
        // no conversion of its own.
        let list = build(&[b"Accept: */*", b"", b"X-Trailing: 1"]);
        // SAFETY: `list` heads a well-formed chain this module built, every
        // `data` is NUL-terminated, and nothing mutates it during the call.
        let seen = unsafe { handle::slist_to_vec(list) };
        assert_eq!(
            seen,
            vec![
                b"Accept: */*".to_vec(),
                Vec::new(),
                b"X-Trailing: 1".to_vec(),
            ]
        );
        // SAFETY: `list` owns all three nodes and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    /// A duplication that always fails, standing in for a `strdup` that
    /// returns null under memory pressure.
    ///
    /// # Safety
    ///
    /// Nothing beyond `memory::strdup`'s contract: it reads no argument.
    unsafe fn failing_dup(_data: *const c_char) -> *mut c_char {
        ptr::null_mut()
    }

    /// A node allocation that always fails.
    fn failing_node(_size: usize) -> *mut c_void {
        ptr::null_mut()
    }

    #[test]
    fn a_failed_duplicate_answers_null_and_leaves_the_list_alone() {
        let list = build(&[b"kept", b"also kept"]);
        let table = NodeAllocator {
            dup: failing_dup,
            node: memory::malloc,
            release: memory::free,
        };
        let addition = b"never stored\0";
        // SAFETY: `list` heads the chain just built, `addition` is a live
        // NUL-terminated string, and the injected table is self-consistent --
        // its `dup` simply never succeeds.
        let result = unsafe {
            append_through(&table, list, addition.as_ptr().cast::<c_char>())
        };
        assert!(result.is_null(), "a failed duplicate must answer null");
        assert_eq!(
            collect(list),
            [b"kept".to_vec(), b"also kept".to_vec()],
            "the caller's list must be exactly as it was"
        );
        // SAFETY: `list` still owns both nodes -- nothing released them -- and
        // is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    /// Releases through the real hook and counts the call.
    ///
    /// A `static` because a function pointer cannot capture, and it is read by
    /// exactly one test, so it needs no lock and no other test can perturb it.
    static NODE_FAILURE_RELEASES: AtomicUsize = AtomicUsize::new(0);

    /// Counts a release and performs it.
    ///
    /// # Safety
    ///
    /// Exactly `memory::free`'s contract, which this forwards unchanged.
    unsafe fn counting_release(block: *mut c_void) {
        NODE_FAILURE_RELEASES.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarded unchanged, so the precondition is the one this
        // function's own caller has already met.
        unsafe { memory::free(block) };
    }

    #[test]
    fn a_failed_node_allocation_releases_the_duplicate_and_keeps_the_list() {
        let list = build(&[b"kept"]);
        let table = NodeAllocator {
            dup: memory::strdup,
            node: failing_node,
            release: counting_release,
        };
        let addition = b"duplicated, then released\0";
        // SAFETY: `list` heads the chain just built, `addition` is a live
        // NUL-terminated string, and the table's `dup` and `release` are the
        // same hooks, so the duplicate it makes is releasable by it.
        let result = unsafe {
            append_through(&table, list, addition.as_ptr().cast::<c_char>())
        };
        assert!(result.is_null(), "a failed node must answer null");
        assert_eq!(
            NODE_FAILURE_RELEASES.load(Ordering::Relaxed),
            1,
            "the duplicate must be released exactly once, as \
             lib/slist.c:93-94 does"
        );
        assert_eq!(
            collect(list),
            [b"kept".to_vec()],
            "the caller's list must survive an allocation failure intact -- \
             the documented leak, deliberately not 'fixed'"
        );
        // SAFETY: `list` still owns its node and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    /// A duplication that panics, standing in for an application-supplied
    /// allocator callback that does.
    ///
    /// # Safety
    ///
    /// Nothing: it never dereferences its argument.
    unsafe fn panicking_dup(_data: *const c_char) -> *mut c_char {
        panic!("a panic must never unwind across the C ABI");
    }

    #[test]
    fn a_panicking_allocation_is_contained_and_answers_null() {
        let list = build(&[b"kept"]);
        let table = NodeAllocator {
            dup: panicking_dup,
            node: memory::malloc,
            release: memory::free,
        };
        let addition = b"never stored\0";
        let before = contained();
        // `guard_ptr` and `append_through` are exactly what
        // `curl_slist_append` composes -- pinned by
        // `the_entry_points_are_guarded_and_delegate_to_the_libcurl_table` --
        // so this exercises the shipped arrangement with the one input a test
        // can supply without touching the process-wide hook registry.
        // SAFETY: `list` heads the chain just built and `addition` is a live
        // NUL-terminated string; the panic happens before any pointer is
        // written, so nothing is left half-initialised.
        let result: *mut curl_slist = guard_ptr(|| unsafe {
            append_through(&table, list, addition.as_ptr().cast::<c_char>())
        });
        assert!(result.is_null(), "a contained panic must answer null");
        // Strictly greater rather than exactly one more: the counter is
        // process-wide and other tests panic inside the boundary too.
        assert!(contained() > before, "the panic must have been contained");
        assert_eq!(
            collect(list),
            [b"kept".to_vec()],
            "the caller's list must be untouched"
        );
        // SAFETY: `list` still owns its node and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    /// Counts releases for the panicking-release test.
    static SILENT_FREE_RELEASES: AtomicUsize = AtomicUsize::new(0);

    /// Releases the block, then panics on the second call.
    ///
    /// # Safety
    ///
    /// Exactly `memory::free`'s contract, which this forwards unchanged.
    unsafe fn release_then_panic_on_the_second(block: *mut c_void) {
        // SAFETY: forwarded unchanged, so the precondition is the one this
        // function's own caller has already met.
        unsafe { memory::free(block) };
        if SILENT_FREE_RELEASES.fetch_add(1, Ordering::Relaxed) == 1 {
            panic!("a panic must never unwind across the C ABI");
        }
    }

    #[test]
    fn a_panic_while_releasing_leaves_free_all_silent() {
        let list = build(&[b"only"]);
        let table = NodeAllocator {
            dup: memory::strdup,
            node: memory::malloc,
            release: release_then_panic_on_the_second,
        };
        let before = contained();
        // SAFETY: `list` heads the one-node chain just built, both of whose
        // blocks came from the very hooks this table releases through, and it
        // is not used afterwards.
        guard_void(|| unsafe { free_all_through(&table, list) });
        // Reaching this line is itself the assertion: `curl_slist_free_all`
        // has no error channel, so a contained panic can only return quietly.
        assert_eq!(
            SILENT_FREE_RELEASES.load(Ordering::Relaxed),
            2,
            "both blocks must be released before the panic"
        );
        assert!(contained() > before, "the panic must have been contained");
    }

    #[test]
    fn the_entry_points_are_guarded_and_delegate_to_the_libcurl_table() {
        // Asserting on this module's own source is how the wiring is pinned
        // deterministically. Comparing function pointers is not guaranteed to
        // hold across codegen units, and observing the hooks would mean
        // installing them -- process-wide, with no test-visible lock, which
        // `escape.rs` records as making unrelated tests flaky. The technique
        // is the one `crate::unsafe_boundary` already uses to police this
        // crate from inside it.
        let source = include_str!("slist.rs");

        let table = source
            .split("const LIBCURL_HOOKS: NodeAllocator = NodeAllocator {")
            .nth(1)
            .expect("the shipped allocator table must exist");
        let table = &table[..table
            .find("};")
            .expect("the shipped allocator table must close")];
        for hook in ["memory::strdup", "memory::malloc", "memory::free"] {
            assert!(
                table.contains(hook),
                "the shipped table must go through {hook}, so that a chain \
                 built here is releasable by curl_free and by whatever \
                 curl_global_init_mem installed"
            );
        }

        // Assembled rather than written out, so the assertion cannot match
        // itself: the literal would appear in the very source it scans.
        let direct = format!("{}::", "libc");
        assert!(
            !source.contains(&direct),
            "allocating directly would bypass curl_global_init_mem"
        );

        let entry_points = [
            ("pub unsafe extern \"C\" fn curl_slist_append", "guard_ptr("),
            (
                "pub unsafe extern \"C\" fn curl_slist_free_all",
                "guard_void(",
            ),
        ];
        for (signature, guard) in entry_points {
            let body = source
                .split(signature)
                .nth(1)
                .expect("both entry points must be defined here");
            // Bounded to the item: an unbounded scan would answer about some
            // other function, which is a trap this project has hit before.
            let body = &body
                [..body.find("\n}").expect("an entry point's body must close")];
            assert!(
                body.contains(guard),
                "{signature} must route its body through {guard}"
            );
            assert!(
                body.contains("&LIBCURL_HOOKS"),
                "{signature} must use the shipped allocator table"
            );
        }
    }

    #[test]
    fn this_module_defines_exactly_the_two_symbols_it_owns() {
        // Two of the 100 names in `lib/libcurl.def`, and no third. An extra
        // export here would collide with the module that owns it -- a link
        // error -- and a missing one would leave a consumer linking against
        // nothing.
        let source = include_str!("slist.rs");
        // Assembled for the same reason as above: written out, the attribute
        // would match itself and inflate the count.
        let attribute = format!("#[{}]", "no_mangle");
        assert_eq!(
            source.matches(&attribute).count(),
            2,
            "slist.rs owns exactly curl_slist_append and curl_slist_free_all"
        );
        for symbol in ["curl_slist_append", "curl_slist_free_all"] {
            let definition = format!("fn {symbol}(");
            assert_eq!(
                source.matches(&definition).count(),
                1,
                "{symbol} must have exactly one definition in the crate"
            );
        }
    }
}
