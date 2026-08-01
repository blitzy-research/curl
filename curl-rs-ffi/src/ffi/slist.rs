// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The two exported string-list functions -- supersedes the public half of
//! `lib/slist.c`.
//!
//! | Symbol | Authority |
//! |--------|-----------|
//! | `curl_slist_append`   | `lib/slist.c:99-110` |
//! | `curl_slist_free_all` | `lib/slist.c:117-133` |
//!
//! # Why this list keeps its intrusive C shape
//!
//! Specification 0.1.2 and 0.6.9 are explicit that the intrusive linked list is
//! one of the constructs the rewrite exists to remove, and that internally
//! `curl_slist` becomes a `Vec`. That applies to the ENGINE. It cannot apply
//! here, because `struct curl_slist` is layout-visible: `include/curl/curl.h`
//! declares both fields, `docs/examples/` walks them, and a consumer legally
//! builds a list by hand and hands it to `curl_easy_setopt`. So the boundary
//! keeps the C representation exactly -- two words, `data` then `next` -- and
//! the conversion to and from an owned `Vec` happens where an option value is
//! consumed, not here.
//!
//! That is why this module allocates through [`super::memory`] rather than with
//! Rust's allocator. A caller may free a node with `curl_free`, and libcurl's
//! own documentation lets an application replace the allocator wholesale
//! through `curl_global_init_mem`; a block produced by Rust's `GlobalAlloc`
//! could not be released by the application's `free`. Every allocation and
//! release below therefore goes through the same five replaceable hooks the C
//! uses.
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
//! * **Failure returns NULL and frees nothing the caller owns.** C frees only
//!   the string it just duplicated (`lib/slist.c:106-108`); the caller's list
//!   is left intact and still needs releasing. Returning NULL on failure while
//!   the old head remains live is a leak trap in the C API, and preserving it
//!   is required: a caller written against curl 8.x already keeps its own copy
//!   of the head for exactly this reason.
//! * **Append is O(n).** `slist_get_last` walks to the tail on every call
//!   (`lib/slist.c:83-95`). This module walks it too. A tail cache would be
//!   faster and would change nothing a caller can observe -- but performance is
//!   an explicit non-goal (specification 0.1.1), and the extra pointer would
//!   have nowhere to live in a struct whose layout is frozen.
//!
//! # A NULL string
//!
//! `curl_slist_append(list, NULL)` reaches `curlx_strdup(NULL)`, which is the
//! platform `strdup`, whose behaviour on NULL is undefined -- in practice a
//! segmentation fault. `Curl_slist_append_nodup` guards it with
//! `DEBUGASSERT(data)`, which compiles away in a release build. There is
//! therefore no defined output to preserve, and this module returns NULL: the
//! same answer it gives for an allocation failure, which is a documented
//! return value that every correct caller already handles. This is recorded as
//! a deliberate divergence from an UNDEFINED behaviour, not from a defined one.

use core::ffi::{c_char, c_void};
use core::ptr;

use super::memory;
use super::panic_boundary::{guard_ptr, guard_void};
use super::types::curl_slist;

/// Appends a copy of a string to a linked list, returning the list head.
///
/// Supersedes `curl_slist_append` (`lib/slist.c:99-110`).
///
/// # Safety
///
/// `list` must be either null or a pointer to a well-formed `curl_slist` chain
/// whose every node was produced by this function, and `data` must be either
/// null or a pointer to a NUL-terminated string. The returned list must
/// eventually be released with [`curl_slist_free_all`].
#[no_mangle]
pub unsafe extern "C" fn curl_slist_append(
    list: *mut curl_slist,
    data: *const c_char,
) -> *mut curl_slist {
    guard_ptr(|| {
        if data.is_null() {
            // See the module documentation: C's behaviour here is undefined,
            // and NULL is the one defined answer available.
            return ptr::null_mut();
        }

        // SAFETY: the caller guarantees `data` addresses a NUL-terminated
        // string, which is `CStr::from_ptr`'s whole precondition. The borrow
        // ends before anything is written.
        let bytes =
            unsafe { core::ffi::CStr::from_ptr(data) }.to_bytes_with_nul();

        let copied = memory::copy_to_c_string(&bytes[..bytes.len() - 1]);
        if copied.is_null() {
            return ptr::null_mut();
        }

        let node = memory::malloc(core::mem::size_of::<curl_slist>())
            .cast::<curl_slist>();
        if node.is_null() {
            // C frees the duplicate it made and returns NULL
            // (`lib/slist.c:106-108`), leaving the caller's list untouched.
            // SAFETY: `copied` came from this module's allocator moments ago
            // and has not been handed to anyone else.
            unsafe { memory::free(copied.cast::<c_void>()) };
            return ptr::null_mut();
        }

        // SAFETY: `node` is a fresh, suitably aligned, uninitialised
        // allocation of exactly `size_of::<curl_slist>()` bytes. Writing the
        // whole struct is the initialization.
        unsafe {
            node.write(curl_slist {
                data: copied,
                next: ptr::null_mut(),
            });
        }

        if list.is_null() {
            // "if this is the first item, then new_item *is* the list"
            // (`lib/slist.c:114-116`).
            return node;
        }

        // SAFETY: the caller guarantees `list` heads a well-formed chain, so
        // every `next` reached below is either null or a live node.
        unsafe {
            let mut tail = list;
            while !(*tail).next.is_null() {
                tail = (*tail).next;
            }
            (*tail).next = node;
        }

        list
    })
}

/// Releases an entire list, including every string it holds.
///
/// Supersedes `curl_slist_free_all` (`lib/slist.c:117-133`). A null argument is
/// a no-op, as it is in C.
///
/// # Safety
///
/// `list` must be either null or a pointer to a well-formed `curl_slist` chain
/// produced by [`curl_slist_append`], and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn curl_slist_free_all(list: *mut curl_slist) {
    guard_void(|| {
        let mut item = list;
        while !item.is_null() {
            // SAFETY: the caller guarantees `item` is a live node of a
            // well-formed chain, so reading `next` before the node is released
            // is sound -- and reading it AFTER would not be, which is why the
            // C keeps the same order (`lib/slist.c:127-130`).
            let next = unsafe { (*item).next };
            // SAFETY: `data` was produced by this module's allocator in
            // `curl_slist_append`, and the node itself likewise. `memory::free`
            // tolerates null, which is what `Curl_safefree` relies on too.
            unsafe {
                memory::free((*item).data.cast::<c_void>());
                memory::free(item.cast::<c_void>());
            }
            item = next;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    /// Collects a list's strings the way a C consumer walks it.
    fn collect(list: *mut curl_slist) -> Vec<String> {
        let mut out = Vec::new();
        let mut node = list;
        while !node.is_null() {
            // SAFETY: `node` came from `curl_slist_append` and has not been
            // freed; `data` is a NUL-terminated string it allocated.
            unsafe {
                out.push(
                    CStr::from_ptr((*node).data)
                        .to_str()
                        .expect("the tests use ASCII")
                        .to_owned(),
                );
                node = (*node).next;
            }
        }
        out
    }

    /// Appends every string in order, returning the head.
    fn build(items: &[&str]) -> *mut curl_slist {
        let mut list: *mut curl_slist = ptr::null_mut();
        for item in items {
            let owned = CString::new(*item).unwrap();
            // SAFETY: `list` is null or a chain this function built, and
            // `owned` is a live NUL-terminated string for the call's duration.
            let next = unsafe { curl_slist_append(list, owned.as_ptr()) };
            assert!(!next.is_null(), "appending {item:?} must succeed");
            list = next;
        }
        list
    }

    #[test]
    fn appending_preserves_insertion_order() {
        let list = build(&["Accept: */*", "X-One: 1", "X-Two: 2"]);
        assert_eq!(collect(list), ["Accept: */*", "X-One: 1", "X-Two: 2"]);
        // SAFETY: `list` is the chain just built and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn the_first_append_returns_the_new_node_and_later_ones_return_the_head() {
        let first = CString::new("one").unwrap();
        // SAFETY: a null list plus a live string is the documented start.
        let head =
            unsafe { curl_slist_append(ptr::null_mut(), first.as_ptr()) };
        assert!(!head.is_null());

        let second = CString::new("two").unwrap();
        // SAFETY: `head` is a one-node chain from the call above.
        let again = unsafe { curl_slist_append(head, second.as_ptr()) };
        assert_eq!(again, head, "appending must return the ORIGINAL head");
        assert_eq!(collect(head), ["one", "two"]);
        // SAFETY: `head` owns both nodes and is not used afterwards.
        unsafe { curl_slist_free_all(head) };
    }

    #[test]
    fn the_string_is_copied_not_borrowed() {
        let list = {
            let temporary = CString::new("copied").unwrap();
            // SAFETY: `temporary` is live for the duration of this call.
            let list = unsafe {
                curl_slist_append(ptr::null_mut(), temporary.as_ptr())
            };
            assert!(!list.is_null());
            // SAFETY: reading the node the call just produced.
            let stored = unsafe { (*list).data };
            assert_ne!(
                stored.cast_const(),
                temporary.as_ptr(),
                "the node must not alias the caller's buffer"
            );
            list
        };
        // The caller's buffer is gone; the list must still read back.
        assert_eq!(collect(list), ["copied"]);
        // SAFETY: `list` owns its node and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn an_empty_string_is_a_legitimate_entry() {
        let list = build(&["", "after"]);
        assert_eq!(collect(list), ["", "after"]);
        // SAFETY: `list` is the chain just built and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn a_null_string_is_refused_without_touching_the_list() {
        let list = build(&["kept"]);
        // SAFETY: passing a null `data` is exactly what this asserts about.
        let result = unsafe { curl_slist_append(list, ptr::null()) };
        assert!(result.is_null(), "a null string must not produce a node");
        assert_eq!(collect(list), ["kept"], "the list must be untouched");
        // SAFETY: `list` still owns its single node and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        // SAFETY: null is explicitly permitted, and C returns early on it
        // (`lib/slist.c:123-124`).
        unsafe { curl_slist_free_all(ptr::null_mut()) };
    }

    /// Whatever a caller does, the node layout stays the frozen two words in
    /// the frozen order, because a consumer reads `->data` and `->next`
    /// directly.
    #[test]
    fn the_node_layout_is_the_frozen_one() {
        use core::mem::{align_of, size_of};
        assert_eq!(size_of::<curl_slist>(), 2 * size_of::<*mut c_void>());
        assert_eq!(align_of::<curl_slist>(), align_of::<*mut c_void>());
    }

    /// A long list exercises the tail walk on every append, which is the part
    /// of the C this module deliberately reproduces rather than optimises.
    #[test]
    fn a_long_list_appends_at_the_tail_every_time() {
        let owned: Vec<String> = (0..64).map(|n| format!("item-{n}")).collect();
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        let list = build(&refs);
        assert_eq!(collect(list), refs);
        // SAFETY: `list` owns all 64 nodes and is not used afterwards.
        unsafe { curl_slist_free_all(list) };
    }
}
