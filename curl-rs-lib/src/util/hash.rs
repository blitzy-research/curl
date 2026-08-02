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

//! The string-keyed hash table -- supersedes `lib/hash.c` (388 lines) and
//! `lib/hash.h` (105 lines).
//!
//! The C original is a chained hash table with a fixed bucket count, an
//! inline flexible-array key and four function pointers. Rust ships
//! `std::collections::HashMap`, so almost all of it is DELETED rather than
//! translated. Exactly one part is not replaceable and is transcribed
//! byte-for-byte: [`hash_str`], which is a NON-canonical djb2 variant.
//!
//! # What this module is for
//!
//! `Curl_hash_str` and `curlx_str_key_compare` are declared in the C header
//! as public helpers, and six of the seven `Curl_hash_init` call sites pass
//! that exact pair. [`StrHash`] is the collection those six become; the two
//! free functions are kept because the header exports them and a consumer
//! may want the raw hash value rather than a bucket index.
//!
//! Measured consumers of the C API, from
//! `grep -rl 'Curl_hash_init\|Curl_hash_add\|Curl_hash_pick' lib/`:
//! `multi.c`, `url.c`, `conncache.c`, `multi_ev.c`, `hostip.c`, `easy.c`,
//! four TLS backends (`vtls/gtls.c`, `openssl.c`, `schannel.c`,
//! `wolfssl.c`), and the two god-struct headers `urldata.h` and
//! `multihandle.h`. It backs the DNS cache, the connection cache, the multi
//! handle's socket-to-transfer map and the TLS session cache.
//!
//! # `Curl_hash_str`, and the two details that make it non-canonical
//!
//! The C body, `lib/hash.c:326-339`, is five lines:
//!
//! ```text
//! size_t h = 5381;
//! while(key_str < end) {
//!   size_t j = (size_t)*key_str++;
//!   h += h << 5;
//!   h ^= j;
//! }
//! return (h % slots_num);
//! ```
//!
//! 1. `h += h << 5` is `h * 33` written as an add-and-shift. Canonical djb2
//!    writes `h * 33 + c`, folding the byte in with the multiply.
//! 2. `h ^= j` is **XOR, not addition**. Canonical djb2 ADDS the byte; the
//!    XOR form is usually called djb2a. curl uses the XOR form. This is the
//!    single likeliest transcription slip, and it is asserted directly by
//!    `the_byte_is_xored_not_added`.
//!
//! Two further properties are not visible in the five lines but change the
//! result, and both are reproduced deliberately:
//!
//! * **The arithmetic wraps.** `h += h << 5` overflows a 64-bit `size_t`
//!   within a handful of bytes, and C unsigned arithmetic is defined to
//!   wrap. Rust's `+` PANICS on overflow in a debug build, so the add is
//!   written [`usize::wrapping_add`]. The shift needs no such treatment:
//!   Rust only checks the shift AMOUNT, and bits shifted off the top are
//!   discarded silently exactly as in C.
//! * **The byte sign-extends.** `key_str` is `const char *`, and `char` is
//!   SIGNED on all four mandated targets (x86_64 and aarch64, Linux and
//!   macOS). So `(size_t)*key_str` on a byte >= 0x80 first becomes a
//!   negative `char`, then sign-extends to a huge `size_t`, and it is that
//!   huge value which is XORed in. Reading the byte as `u8` would produce a
//!   different hash for every non-ASCII key. Measured against a compiled
//!   transcription of the C: a one-byte key `[0x80]` hashes to
//!   `0xfffffffffffd4a25`, where a `u8` read gives `177445`.
//!
//! The hash value is not externally observable -- it only selects a bucket,
//! and lookup decides membership with the comparator -- so a `u8` read
//! would have been *functionally* correct. The sign extension is reproduced
//! anyway so that a future reader diffing this module against `lib/hash.c`
//! finds no discrepancy to investigate. `sign_extension_is_reproduced`
//! pins it.
//!
//! `% slots_num` folds the hash into a bucket index. Delegating to
//! `HashMap` removes the modulo, so the primary form [`hash_str`] returns
//! the UNFOLDED hash and [`hash_str_slot`] applies the fold for a caller
//! that genuinely wants a bucket index.
//!
//! # `curlx_str_key_compare`
//!
//! `lib/hash.c:341-348` is `(key1_len == key2_len) && !memcmp(...)`. Two
//! things about it trip readers, and both are preserved by
//! [`str_key_compare`]:
//!
//! * It returns **1 on MATCH** -- the inverse of the `memcmp` convention a
//!   reader may assume, and the reason the Rust successor returns a `bool`
//!   whose `true` means equal.
//! * It is **case-SENSITIVE**, an exact-length byte comparison. It is NOT
//!   curl's case-insensitive folding and must not be routed through
//!   `crate::util::strcase`. Callers wanting case-insensitive keys
//!   normalise before inserting; the DNS cache lowercases hostnames at the
//!   call site.
//!
//! In Rust the whole function collapses into `PartialEq` on the key type:
//! `&[u8] == &[u8]` compares length first and then bytes, which is exactly
//! the C predicate. The thin wrapper is kept only so the C name has a
//! landing site.
//!
//! # What vanishes
//!
//! Everything below is in `lib/hash.h:29-76` and has NO successor. It is
//! listed rather than summarised because each item is an invariant somebody
//! would otherwise look for.
//!
//! * **Four function pointers** -- `hash_function`, `comp_function`,
//!   `Curl_hash_dtor` and `Curl_hash_elem_dtor`. See the note on the two
//!   destructor levels below, and on where the other two went.
//! * **`struct Curl_hash_element::next`** -- the chaining link. `HashMap`
//!   owns its own collision strategy.
//! * **`char key[1]`** -- a flexible array member, allocated as
//!   `curlx_malloc(sizeof(struct Curl_hash_element) + key_len)` and filled
//!   by `memcpy` (`lib/hash.c:100-118`). `Vec<u8>` as the key type replaces
//!   it and removes the size arithmetic, and with it the overflow question
//!   that arithmetic raises.
//! * **`slots` and `size` bookkeeping** -- `size` becomes `HashMap::len`.
//!   `slots` is discussed under "The bucket count" below.
//! * **The `init` sentinel** -- `#define HASHINIT 0x7017e781`
//!   (`lib/hash.c:30`) is stamped into `h->init` by `Curl_hash_init` and
//!   re-checked by nine `DEBUGASSERT`s, so that calling any entry point on
//!   an uninitialised or already-destroyed table is caught in a debug
//!   build. The sibling `ITERINIT 0x5FEDCBA9` (`lib/hash.c:31`) does the
//!   same for the iterator. Both are gone because the condition they detect
//!   cannot arise: a `StrHash` cannot be observed before `new` returns it
//!   or after `Drop` runs. The values are quoted here so that a search for
//!   either sentinel lands on this explanation.
//! * **`struct Curl_hash_iterator`** -- replaced by [`StrHash::iter`], and
//!   the borrow checker then ENFORCES what the C could only hope for. The
//!   C's `cpool_foreach` (`lib/conncache.c:512-544`) carries the comment
//!   "we need to update curr before calling func(), because func() might
//!   decide to remove the connection"; in Rust an iterator borrows the map
//!   immutably, so removing during iteration does not compile.
//! * **`Curl_hash_print`** -- declared at `lib/hash.h:103` but its
//!   DEFINITION sits inside `#if 0` (`lib/hash.c:34-69`), so it has never
//!   been compiled, and its only appearance in a consumer is inside a
//!   comment at `lib/multi.c:538`. It is therefore not ported. The
//!   `fmt::Debug` implementation on [`StrHash`] stands in for it, rendering
//!   keys with `String::from_utf8_lossy` to mirror the C's `%.*s`.
//!
//! ## Where the hash and comparator function pointers went
//!
//! They were not vestigial: the C really did have two implementations of
//! the pair, and knowing which is which is what makes removing them safe.
//! Of the seven `Curl_hash_init` call sites, six pass `Curl_hash_str` with
//! `curlx_str_key_compare` -- `multi.c:250`, `url.c:498`, `url.c:3280`,
//! `easy.c:970`, `conncache.c:118` and `hostip.c:1270`. The seventh,
//! `multi_ev.c:622`, passes `mev_sh_entry_hash`, which is
//! `fd % slots_num` over a `curl_socket_t` (`multi_ev.c:58-63`), with a
//! matching comparator.
//!
//! So the runtime pointer existed to serve exactly one alternative: an
//! integer-keyed table. In Rust that consumer takes a DIFFERENT map type
//! keyed by the socket -- `crate::util::uint_hash` is the module the
//! transformation map assigns it -- rather than handing a function pointer
//! to a byte-keyed one. This module is byte-keyed and does not need to be
//! told how to hash.
//!
//! ## The bucket count has no successor
//!
//! `Curl_hash_init(h, slots, ...)` fixes the bucket count at construction
//! and the C NEVER rehashes: `slots` is read by `CURL_HASH_SLOT`
//! (`lib/hash.c:158`) on every operation and by the full-table walks, and
//! nothing ever grows it. A table given 23 buckets and 10,000 entries
//! degrades into 23 linked lists. `HashMap` grows instead.
//!
//! This is a deliberate CHANGE, and it is safe because the bucket count is
//! not observable: it affects only which bucket a key lands in, and no C
//! caller can see that. **No fixed-bucket chained table is rebuilt here.**
//!
//! [`StrHash::with_slots`] exists nonetheless, because two of the six
//! string-keyed call sites pass a count computed at runtime rather than a
//! literal -- `Curl_cpool_init`'s `size` parameter (`conncache.c:114-118`)
//! and `Curl_dnscache_init`'s `size` parameter (`hostip.c:1268-1271`). It
//! forwards to `HashMap::with_capacity`, which is a pre-allocation HINT and
//! not a cap, so it changes allocation timing and nothing else. The other
//! four sites pass a literal 23 and can simply call [`StrHash::new`].
//!
//! ## Two destructor levels collapse into `Drop`
//!
//! The C has a table-wide `Curl_hash_dtor` taking `(void *ptr)` and a
//! per-element `Curl_hash_elem_dtor` taking `(void *key, size_t key_len,
//! void *ptr)`, installed by `Curl_hash_add2`. `hash_elem_clear_ptr`
//! (`lib/hash.c:120-132`) prefers the per-element one when present, which
//! is what `lib/hash.h:60` means by "General element construct, unless
//! element itself carries one". Both become `Drop` on the value type, so
//! there is no `add2` here and no destructor argument anywhere.
//!
//! One capability is genuinely lost and must be recorded rather than
//! glossed: **the per-element destructor also receives the KEY**, and
//! `Drop for V` does not. A consumer whose teardown needs the key -- to
//! remove a matching entry from a second index, say -- cannot get it from
//! `Drop` and must iterate explicitly, reading each key from
//! [`StrHash::iter`] or [`StrHash::keys`] before removing. The C also
//! called the destructor only when `he->ptr` was non-NULL; that guard has
//! no analogue because a `V` is an owned value and cannot be null.
//!
//! # Iteration order: the one behavioural difference, and who inherits it
//!
//! **`HashMap` iteration order is unspecified and randomised per process**
//! (SipHash keyed from a random seed), whereas the C's chained table walks
//! buckets in index order and is therefore DETERMINISTIC for a given key
//! set and slot count. This is the likeliest source of a subtle behavioural
//! difference anywhere in this module, so the C call sites were audited
//! individually rather than assumed harmless.
//!
//! `grep -rn 'Curl_hash_start_iterate\|Curl_hash_next_element' lib/*.c
//! lib/vtls/*.c` finds four sites, **all four in `lib/conncache.c`**, of
//! which three are live:
//!
//! 1. `cpool_get_first` (`conncache.c:129-145`) returns whichever bundle
//!    the bucket walk reaches first, so it IS order-dependent by
//!    construction. Its only callers, `conncache.c:242` and `:248`, sit in
//!    `Curl_cpool_destroy`'s drain loop -- take the first, remove it,
//!    discard it, take the first again -- so order changes the SEQUENCE of
//!    closes and not the outcome: every connection is closed either way.
//! 2. `cpool_get_oldest_idle` (`conncache.c:336-368`) is a max-reduction
//!    over every connection with `highscore` starting at -1. The
//!    comparison is a STRICT `score > highscore`, so the result is
//!    order-independent EXCEPT on a tie, where the first connection
//!    encountered wins. Two connections whose `lastused` timestamps are
//!    equal to the millisecond may therefore be evicted in either order.
//! 3. `cpool_foreach` (`conncache.c:512-544`) visits every connection and
//!    ABORTS on the first callback returning 1. Which connection is
//!    reached first therefore decides the outcome whenever the callback can
//!    abort early. This is the one genuinely order-sensitive site.
//! 4. `Curl_cpool_print` (`conncache.c:877-909`) is inside `#if 0` and has
//!    never been compiled.
//!
//! **Conclusion, addressed to whoever writes
//! `curl-rs-lib/src/conn/pool.rs`:** the connection pool is the ONLY
//! consumer that inherits order sensitivity, it inherits it at those three
//! sites, and site 3 is the one that can change an observable outcome. If
//! deterministic behaviour is wanted there, sort explicitly on a field that
//! is already part of the value -- `lastused` for eviction -- or hold the
//! pool in a `BTreeMap`. Do NOT reach for a stable hasher: the bucket
//! order the C happened to produce was never a specified behaviour, and
//! reproducing it would freeze an accident.
//!
//! **And, equally importantly, addressed to whoever writes
//! `curl-rs-lib/src/dns/`:** the DNS cache does NOT inherit this. It never
//! iterates. `lib/hostip.c` prunes through `Curl_hash_clean_with_criterium`
//! (`hostip.c:291`) with the callback `dnscache_entry_is_stale`
//! (`hostip.c:258-274`), which decides each entry on its own timestamp and
//! accumulates the surviving maximum age -- a per-entry test plus a
//! max-reduction, order-independent in both halves.
//!
//! # The criterium polarity trap
//!
//! `Curl_hash_clean_with_criterium` and `HashMap::retain` have OPPOSITE
//! polarity, and getting it backwards would silently empty a cache or
//! silently never prune one. The C, at `lib/hash.c:311-323`, is
//!
//! ```text
//! if(!comp || comp(user, (*he_anchor)->ptr)) { unlink; destroy; }
//! else he_anchor = &(*he_anchor)->next;
//! ```
//!
//! so the callback returning TRUE means **REMOVE**, and a NULL callback
//! removes EVERYTHING. The live consumer says the same thing in words at
//! `hostip.c:255-257`: "Returning non-zero means remove the entry, return 0
//! to keep it in the cache." `HashMap::retain`'s closure returning `true`
//! means KEEP.
//!
//! [`StrHash::clean_with_criterium`] keeps **curl's** polarity, so a
//! transliterated consumer is correct without thinking about it, and
//! performs the single inversion internally. The inversion therefore exists
//! in exactly one place in this workspace, and
//! `the_criterium_removes_what_it_selects` and
//! `an_always_true_criterium_empties_the_table` assert both directions.
//! The C's `void *user` context becomes a closure capture, which is the
//! typed-context requirement applied to this module.
//!
//! # The 14 C entry points and their fate
//!
//! `lib/hash.h:78-103` declares fourteen functions. Every one is mapped.
//!
//! | C entry point                    | Rust successor                        |
//! |----------------------------------|---------------------------------------|
//! | `Curl_hash_init`                 | `StrHash::new` / `with_slots`         |
//! | `Curl_hash_add`                  | `StrHash::insert`                     |
//! | `Curl_hash_add2`                 | `insert`; the dtor becomes `Drop`     |
//! | `Curl_hash_delete`               | `StrHash::remove`                     |
//! | `Curl_hash_pick`                 | `StrHash::get` / `get_mut`            |
//! | `Curl_hash_destroy`              | `Drop`, run automatically             |
//! | `Curl_hash_count`                | `StrHash::len` / `is_empty`           |
//! | `Curl_hash_clean`                | `StrHash::clear`                      |
//! | `Curl_hash_clean_with_criterium` | `StrHash::clean_with_criterium`       |
//! | `Curl_hash_str`                  | `hash_str` / `hash_str_slot`          |
//! | `curlx_str_key_compare`          | `str_key_compare`                     |
//! | `Curl_hash_start_iterate`        | `StrHash::iter` / `iter_mut`          |
//! | `Curl_hash_next_element`         | the same iterators                    |
//! | `Curl_hash_print`                | `fmt::Debug`; never compiled in C     |
//!
//! The C return values are not documented in the header and callers branch
//! on them, so they were read from the bodies:
//!
//! * `Curl_hash_add` and `Curl_hash_add2` return the stored pointer, or
//!   NULL on allocation failure (`lib/hash.c:161-192`). Neither half
//!   survives. Rust has no allocation-failure return -- the allocator
//!   aborts -- and what [`StrHash::insert`] returns instead is the
//!   DISPLACED value, which the C destroyed through the destructor at
//!   `lib/hash.c:179`. Dropping the returned `Option` reproduces the C
//!   exactly; keeping it is strictly more capable.
//! * `Curl_hash_delete` returns `int`: **0 on success**
//!   (`lib/hash.c:226`) and **1 when the key was absent**
//!   (`lib/hash.c:231`). [`StrHash::remove`] carries the same distinction
//!   in the shape of its return -- `Some` is the C's 0 and `None` is the
//!   C's 1 -- and hands back the removed value as well.
//! * `Curl_hash_init` returns `void`. Its own doc comment at
//!   `lib/hash.c:71-72` claims "Return 1 on error, 0 is fine", which is
//!   stale and describes no version of the function in this tree. Noted so
//!   that nobody ports a non-existent error path.
//!
//! # Layering
//!
//! `util` is the base of this crate's module graph and depends on nothing.
//! This module imports from `std` only, adds no dependency to any manifest
//! and reaches no sibling module. It contains no `unsafe` block: the C's
//! flexible-array-member allocation and its `he_anchor` pointer-to-pointer
//! unlink surgery (`lib/hash.c:141-147`) are both expressed as safe
//! collection operations.
//!
//! # A note on performance, since a hash table invites the question
//!
//! Performance is an explicit non-goal of this migration and faithfulness
//! wins where the two conflict. `HashMap`'s default SipHash hasher is kept
//! deliberately. Wiring [`hash_str`] in as a `BuildHasher` "to match curl"
//! would trade SipHash's hash-flooding resistance for fidelity in a value
//! no caller can observe, on a table whose keys include attacker-influenced
//! hostnames. The default is both the safer choice and the smaller change.

use std::collections::HashMap;
use std::fmt;

/// The seed of curl's djb2 variant, `lib/hash.c:330`.
///
/// Named rather than inlined so that the empty-key case reads as "the seed,
/// returned unmodified" instead of as an unexplained 5381.
const HASH_SEED: usize = 5381;

/// Hashes a byte key exactly as `Curl_hash_str` does, without folding the
/// result into a bucket index.
///
/// Supersedes `Curl_hash_str` (`lib/hash.c:326-339`). The algorithm and the
/// two ways it deviates from canonical djb2 are set out in the module
/// documentation; the short version is `h = h * 33` written as an
/// add-and-shift, then `h ^= byte` -- XOR, where canonical djb2 adds.
///
/// The C signature takes `slots_num` and returns `h % slots_num`. That fold
/// is separated out into [`hash_str_slot`] because delegating storage to
/// `HashMap` removes the need for it, while the unfolded value remains
/// useful to a caller that wants the hash itself.
///
/// Two deliberate reproductions of C behaviour, both load-bearing:
///
/// * the running value WRAPS, hence [`usize::wrapping_add`], where Rust's
///   `+` would panic in a debug build;
/// * each byte is read as a SIGNED `char` and sign-extended, so a byte
///   >= 0x80 contributes a value with its whole high half set.
///
/// The empty key never enters the loop, so the seed is returned unmodified:
///
/// ```text
/// hash_str(b"") == 5381
/// ```
///
/// That block is deliberately `text` rather than a runnable example. Every
/// item in this module is `pub(crate)`, and rustdoc compiles a doctest as a
/// separate crate that can only reach the public surface, so a runnable
/// example here would fail to compile rather than document anything. The
/// executable form of the same claim is
/// `the_empty_key_returns_the_seed_unmodified` in the test module below.
#[allow(dead_code)]
pub(crate) fn hash_str(key: &[u8]) -> usize {
    let mut h = HASH_SEED;
    for &byte in key {
        // The one deliberate `as` chain in this module, reproducing the C's
        // `size_t j = (size_t)*key_str++` where `key_str` is `const char *`.
        // `char` is signed on all four mandated targets, so a byte >= 0x80
        // becomes a negative `char` and then sign-extends across the whole
        // `size_t`. Reading `byte` directly as a `usize` would silently
        // change the hash of every non-ASCII key.
        let j = byte as i8 as usize;
        // `h += h << 5` is `h * 33`. Only the ADD can overflow: Rust checks
        // the shift AMOUNT, not the shifted-out bits, so `<< 5` on a usize
        // discards high bits silently exactly as C does.
        h = h.wrapping_add(h << 5);
        h ^= j;
    }
    h
}

/// Hashes a byte key and folds the result into `slots` buckets.
///
/// This is `Curl_hash_str` in full, including the `% slots_num` the C
/// applies before returning (`lib/hash.c:338`). Nothing in this crate needs
/// it to store anything -- [`StrHash`] delegates bucketing to `HashMap` --
/// but the C header exports the folded form, so the folded form exists.
///
/// # Panics
///
/// Panics when `slots` is zero, because the fold is a remainder operation.
/// The C would execute `h % 0`, which is undefined behaviour; every C caller
/// passes a non-zero count and `Curl_hash_init` carries a
/// `DEBUGASSERT(slots)` to that effect (`lib/hash.c:84`). The
/// `debug_assert!` below reproduces that assertion with a message, and the
/// remainder itself makes the release build a clean panic rather than
/// undefined behaviour -- a strict improvement, and the reason no `Option`
/// is returned for a condition no correct caller can reach.
#[allow(dead_code)]
pub(crate) fn hash_str_slot(key: &[u8], slots: usize) -> usize {
    debug_assert!(
        slots > 0,
        "a hash table with zero buckets has no valid slot index; the C \
         computes h % 0 here, which is undefined behaviour"
    );
    hash_str(key) % slots
}

/// Compares two byte keys for exact equality.
///
/// Supersedes `curlx_str_key_compare` (`lib/hash.c:341-348`), whose body is
/// `(key1_len == key2_len) && !memcmp(k1, k2, key1_len)`.
///
/// Two properties of the C are easy to misread and are preserved here:
///
/// * the C returns **1 on MATCH**, which is the inverse of `memcmp`'s own
///   convention, so the Rust successor returns `true` for equal keys;
/// * the comparison is **case-SENSITIVE**. It is not curl's case-insensitive
///   folding and must not be routed through `crate::util::strcase`; a
///   caller wanting case-insensitive keys normalises before inserting, as
///   the DNS cache does by lowercasing hostnames at the call site.
///
/// In Rust the function collapses entirely into `PartialEq` on the slices:
/// `&[u8] == &[u8]` tests length and then bytes, which is the C predicate
/// term for term. [`StrHash`] therefore does not call this at all -- its
/// key type provides `Eq` -- and the function is kept so the C name has a
/// landing site and a direct caller has one too.
#[allow(dead_code)]
pub(crate) fn str_key_compare(k1: &[u8], k2: &[u8]) -> bool {
    k1 == k2
}

/// A byte-keyed hash table -- the successor to `struct Curl_hash`.
///
/// A thin wrapper over `HashMap<Vec<u8>, V>`. Every method below is a
/// delegation, and that is the whole point: the C's chained table, its
/// bucket array, its collision chains and its four function pointers are
/// deleted rather than reimplemented. What the wrapper adds is exactly
/// three things that a bare `HashMap` would not carry:
///
/// 1. the C names, in this file's documentation, so that a search for
///    `Curl_hash_add` or `Curl_hash_delete` lands somewhere;
/// 2. [`Self::clean_with_criterium`], which is the one operation with no
///    `HashMap` equivalent AND the one with an inverted polarity, so the
///    inversion lives in a single tested place instead of at every call
///    site;
/// 3. a key type fixed at `Vec<u8>`, which is what removes the
///    `hash_function` and `comp_function` pointers -- see the module
///    documentation for why the C needed them and why this does not.
///
/// # Naming
///
/// The C type is `struct Curl_hash`. Stripping the `Curl_` prefix, as this
/// crate does throughout, would give `Hash`, which collides with the name
/// of the ubiquitous `std::hash::Hash` trait and would force every future
/// consumer importing both to disambiguate. `StrHash` is used instead, and
/// it is not an invention: `curl-rs-lib/src/util/mod.rs` already introduces
/// this module as "the string-keyed hash table", and the C's own comparator
/// is spelled `curlx_str_key_compare`.
///
/// # Keys
///
/// Keys are arbitrary byte strings, NOT C strings, and their length is
/// carried explicitly exactly as the C's `key_len` parameter carries it.
/// Interior NUL bytes are ordinary key bytes and a trailing NUL is part of
/// the key when the caller includes it -- which matters, because
/// `cpool_find_bundle` keys the connection pool on
/// `strlen(conn->destination) + 1` (`lib/conncache.c:147-152`) and so its
/// keys really do end in a NUL byte.
pub(crate) struct StrHash<V> {
    /// The entries, owning both key and value.
    ///
    /// `Vec<u8>` supersedes the C's `char key[1]` flexible array member,
    /// which `hash_elem_create` allocated as
    /// `sizeof(struct Curl_hash_element) + key_len` and filled with
    /// `memcpy` (`lib/hash.c:100-118`). The default `RandomState` hasher is
    /// deliberate; see the performance note in the module documentation.
    entries: HashMap<Vec<u8>, V>,
}

impl<V> StrHash<V> {
    /// Creates an empty table.
    ///
    /// Supersedes `Curl_hash_init` (`lib/hash.c:77-98`) for the four call
    /// sites that pass a literal bucket count of 23 -- `multi.c:250`,
    /// `url.c:498`, `url.c:3280` and `easy.c:970`. The `slots`, `hfunc`,
    /// `comparator` and `dtor` arguments all have no successor; the module
    /// documentation records where each of them went.
    ///
    /// Like the C, this allocates nothing. `Curl_hash_init` set
    /// `h->table = NULL` and left `Curl_hash_add2` to `curlx_calloc` the
    /// bucket array on first insert (`lib/hash.c:169-173`); `HashMap::new`
    /// likewise defers its first allocation until an entry is added.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Creates an empty table sized for at least `slots` entries.
    ///
    /// Supersedes `Curl_hash_init` for the two string-keyed call sites that
    /// compute a count at runtime rather than writing a literal:
    /// `Curl_cpool_init`'s `size` parameter (`conncache.c:114-118`) and
    /// `Curl_dnscache_init`'s `size` parameter (`hostip.c:1268-1271`).
    ///
    /// The meaning differs from the C's and the difference is the point.
    /// `slots` there was a FIXED bucket count that was never grown, so
    /// exceeding it degraded the table into that many linked lists. Here it
    /// is a capacity hint passed to `HashMap::with_capacity`: the table
    /// still grows without limit, and the hint only moves allocation
    /// earlier. Nothing observable changes, which
    /// `a_capacity_hint_changes_nothing_observable` asserts.
    ///
    /// A zero hint is accepted and is equivalent to [`Self::new`]. The C
    /// would have failed a `DEBUGASSERT(slots)` (`lib/hash.c:84`) and then
    /// divided by zero; there is no division here, so there is nothing to
    /// reject.
    #[allow(dead_code)]
    pub(crate) fn with_slots(slots: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(slots),
        }
    }

    /// Inserts `value` under `key`, returning the value it displaced.
    ///
    /// Supersedes `Curl_hash_add` (`lib/hash.c:202-205`) and, together with
    /// `Drop`, `Curl_hash_add2` (`lib/hash.c:161-192`). An existing entry is
    /// REPLACED, matching the C, which cleared the old pointer through its
    /// destructor and overwrote in place (`lib/hash.c:176-183`).
    ///
    /// Neither half of the C return value survives, and both replacements
    /// are deliberate:
    ///
    /// * the C returned `p` on success and NULL on allocation failure. Rust
    ///   has no allocation-failure return -- the allocator aborts -- so
    ///   there is no failure to report;
    /// * what is returned instead is the DISPLACED value, which the C
    ///   destroyed at `lib/hash.c:179`. Ignoring the result drops it
    ///   immediately and reproduces the C exactly; binding it is strictly
    ///   more capable.
    ///
    /// `key` is copied into an owned `Vec<u8>`, which is what the C did with
    /// `memcpy` into its flexible array member. The copy is therefore
    /// faithful rather than incidental.
    #[allow(dead_code)]
    pub(crate) fn insert(&mut self, key: &[u8], value: V) -> Option<V> {
        self.entries.insert(key.to_vec(), value)
    }

    /// Removes the entry under `key`, returning its value.
    ///
    /// Supersedes `Curl_hash_delete` (`lib/hash.c:212-232`), which returns
    /// `int`: 0 when the entry was found and removed (`lib/hash.c:226`) and
    /// 1 when the key was absent (`lib/hash.c:231`). That distinction is
    /// preserved in the shape of the return -- `Some` is the C's 0, `None`
    /// is the C's 1 -- and the removed value comes back with it instead of
    /// being destroyed on the spot.
    ///
    /// Removing an absent key is not an error in either language; it simply
    /// reports absence.
    #[allow(dead_code)]
    pub(crate) fn remove(&mut self, key: &[u8]) -> Option<V> {
        self.entries.remove(key)
    }

    /// Looks up the value stored under `key`.
    ///
    /// Supersedes `Curl_hash_pick` (`lib/hash.c:238-254`), which walked the
    /// key's collision chain calling `comp_func` and returned `he->ptr` or
    /// NULL. `Option<&V>` replaces the nullable pointer, so a caller cannot
    /// forget the absent case.
    #[allow(dead_code)]
    pub(crate) fn get(&self, key: &[u8]) -> Option<&V> {
        self.entries.get(key)
    }

    /// Looks up the value stored under `key` for modification.
    ///
    /// The C had no separate mutable accessor: `Curl_hash_pick` handed back
    /// a `void *` through which callers mutated freely, with nothing
    /// tracking whether anyone else held the same pointer. Splitting the
    /// accessor in two is what lets the borrow checker track that instead.
    #[allow(dead_code)]
    pub(crate) fn get_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    /// Returns the number of entries.
    ///
    /// Supersedes `Curl_hash_count` (`lib/hash.c:295-299`), which returned
    /// the hand-maintained `h->size` counter that `hash_elem_link` and
    /// `hash_elem_unlink` incremented and decremented (`lib/hash.c:141-156`).
    /// `HashMap` maintains its own, so the counter and both helpers are
    /// gone.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the table holds no entries.
    ///
    /// The C had no such predicate -- callers wrote `!Curl_hash_count(h)`.
    /// It is provided because Rust convention pairs it with [`Self::len`].
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes every entry, keeping the table usable.
    ///
    /// Supersedes `Curl_hash_clean` (`lib/hash.c:278-293`), which walked all
    /// `slots` buckets unlinking and destroying each element. Each value's
    /// `Drop` runs here, which is what the C's two destructor levels
    /// existed to arrange.
    ///
    /// `Curl_hash_destroy` (`lib/hash.c:263-272`) has no separate successor:
    /// it was `Curl_hash_clean` followed by freeing the bucket array, and
    /// both halves are the compiler's job now.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    /// Removes every entry whose value the criterium SELECTS.
    ///
    /// Supersedes `Curl_hash_clean_with_criterium` (`lib/hash.c:302-324`).
    ///
    /// # Polarity
    ///
    /// `select` returning `true` means **REMOVE**, which is curl's polarity
    /// and the OPPOSITE of `HashMap::retain`, whose closure returning `true`
    /// means keep. The C is explicit -- at `lib/hash.c:315`,
    /// `if(!comp || comp(user, ptr))` unlinks and destroys -- and the live
    /// consumer states it in words at `hostip.c:255-257`: "Returning
    /// non-zero means remove the entry, return 0 to keep it in the cache."
    ///
    /// curl's polarity is kept so that a consumer transliterated from the C
    /// is correct without having to notice the difference, and the single
    /// inversion is performed below. It exists in exactly one place in this
    /// workspace and is asserted in both directions by
    /// `the_criterium_removes_what_it_selects` and
    /// `an_always_true_criterium_empties_the_table`.
    ///
    /// # The two arguments that are not here
    ///
    /// The C signature is `(h, void *user, int (*comp)(void *, void *))`.
    /// The `user` context becomes whatever the closure captures, which is
    /// the typed-context substitution this migration applies to every C
    /// callback pair. A NULL `comp` removed EVERYTHING; that case is
    /// [`Self::clear`], and it is not expressible here because `select` is
    /// not optional -- which is a deliberate narrowing, since "pass NULL to
    /// mean clear" is a trap rather than a feature.
    ///
    /// The criterium receives `&V` and NOT the key, because the C's
    /// `comp(user, ptr)` receives only the value. Widening it would be a
    /// change with no call site asking for one: the sole live consumer,
    /// `dnscache_entry_is_stale` (`hostip.c:258-274`), reads only the entry.
    /// A consumer that genuinely needs keys should collect them from
    /// [`Self::keys`] and then call [`Self::remove`], which is what the C
    /// would also have required.
    #[allow(dead_code)]
    pub(crate) fn clean_with_criterium<F>(&mut self, mut select: F)
    where
        F: FnMut(&V) -> bool,
    {
        // THE INVERSION. `select` is curl's predicate, so true means remove;
        // `retain` keeps what its closure accepts. Every other expression of
        // this operation in the workspace should call through here rather
        // than write `retain` again.
        self.entries.retain(|_key, value| !select(value));
    }

    /// Iterates over every entry as a key/value pair.
    ///
    /// Supersedes the `Curl_hash_start_iterate` / `Curl_hash_next_element`
    /// pair (`lib/hash.c:350-388`) and the whole of
    /// `struct Curl_hash_iterator`. Keys are yielded as slices because the
    /// C's `struct Curl_hash_element` exposed `he->key` and `he->key_len`
    /// together and `Curl_cpool_print` read them.
    ///
    /// # Order
    ///
    /// **Unspecified, and randomised per process.** The C walked buckets in
    /// index order, which was deterministic for a given key set and slot
    /// count. The module documentation audits all three live C call sites
    /// and records which one can change an observable outcome; read it
    /// before relying on order here.
    #[allow(dead_code)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&[u8], &V)> + '_ {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_slice(), value))
    }

    /// Iterates over every entry, allowing the values to be modified.
    ///
    /// The C reached the same effect by handing out the `void *he->ptr` from
    /// `Curl_hash_next_element` and letting the caller write through it --
    /// which is precisely why `cpool_foreach` (`lib/conncache.c:512-544`)
    /// has to advance its cursor before invoking the callback, in case the
    /// callback removes the element it was handed. Here the map is borrowed
    /// mutably for the life of the iterator, so that hazard is a compile
    /// error rather than a comment.
    ///
    /// Order is unspecified, exactly as for [`Self::iter`].
    #[allow(dead_code)]
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&[u8], &mut V)> + '_ {
        self.entries
            .iter_mut()
            .map(|(key, value)| (key.as_slice(), value))
    }

    /// Iterates over every key.
    ///
    /// The C had no key-only walk; a caller ran the iterator and read
    /// `he->key`. This is the accessor the module documentation points at
    /// for the one capability the destructor collapse loses -- teardown
    /// logic that needs the key must collect it here first, because
    /// `Drop for V` never sees it.
    ///
    /// Order is unspecified, exactly as for [`Self::iter`].
    #[allow(dead_code)]
    pub(crate) fn keys(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.entries.keys().map(Vec::as_slice)
    }

    /// Iterates over every value.
    ///
    /// Order is unspecified, exactly as for [`Self::iter`].
    #[allow(dead_code)]
    pub(crate) fn values(&self) -> impl Iterator<Item = &V> + '_ {
        self.entries.values()
    }
}

impl<V> Default for StrHash<V> {
    /// Equivalent to [`StrHash::new`].
    ///
    /// Provided because a Rust type with an argument-free `new` is expected
    /// to have one, and because `clippy::new_without_default` is
    /// warn-by-default under a `-D warnings` gate. It has no C counterpart:
    /// `struct Curl_hash` was embedded by value in its owners and zeroed by
    /// `Curl_hash_init`.
    fn default() -> Self {
        Self::new()
    }
}

impl<V: fmt::Debug> fmt::Debug for StrHash<V> {
    /// Renders the table as a map, standing in for `Curl_hash_print`.
    ///
    /// `Curl_hash_print` (`lib/hash.h:103`, defined at `lib/hash.c:34-69`)
    /// is a diagnostic dumper that has never been compiled: its definition
    /// sits inside `#if 0`, and its only appearance in a consumer is a
    /// commented-out line at `lib/multi.c:538`. It is therefore not ported,
    /// and this is the substitution.
    ///
    /// Keys are rendered with `String::from_utf8_lossy` because the C
    /// printed them with `%.*s`, treating the key bytes as text without
    /// checking that they are. Two details of the C output are deliberately
    /// NOT reproduced: the bucket index it grouped by, which no longer
    /// exists, and the raw element and value addresses it printed, which
    /// would be neither stable nor useful.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                self.entries
                    .iter()
                    .map(|(key, value)| (String::from_utf8_lossy(key), value)),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{hash_str, hash_str_slot, str_key_compare, StrHash};
    use std::cell::Cell;
    use std::rc::Rc;

    // These tests hold the coverage that `tests/unit/unit1305.c`,
    // `unit1602.c` and `unit1603.c` hold for the C -- the three files named
    // by the `@unittest:` annotations on `Curl_hash_add`, `Curl_hash_delete`,
    // `Curl_hash_destroy`, `Curl_hash_clean` and `Curl_hash_init`. Those C
    // programs link a debug static libcurl and call internal `Curl_*`
    // symbols, which a Rust static library genuinely does not export, so
    // their assertions relocate here rather than being made to link.

    // THE DIFFERENTIAL ORACLE
    //
    // The expected hashes below are NOT hand-computed. A C program
    // containing a verbatim transcription of `lib/hash.c:326-348` was
    // compiled with gcc and run, and each value is one call's result with
    // the `% slots_num` fold removed so that the whole 64-bit hash is
    // compared rather than a bucket index. A divergence therefore means this
    // module disagrees with the shipped C, not that a hand calculation was
    // wrong.
    //
    // The same program reported `sizeof(size_t) == 8` and `char` signed,
    // which are the two platform facts the transcription depends on.
    //
    // The corpus is chosen for the places a mistranscription would show up:
    // the empty key (the loop bound), one and three ASCII bytes (the XOR),
    // two keys differing only in case, the three bytes either side of the
    // sign boundary (0x7F, 0x80, 0xFF), a key mixing signed and unsigned
    // ranges, a NUL-terminated connection-pool destination of the exact
    // shape `cpool_find_bundle` builds, a 32-byte run (the wrap), bare NUL
    // bytes, and a run of eight 0xFF.
    const C_ORACLE: [(&[u8], usize); 15] = [
        (b"", 5381),
        (b"a", 177_604),
        (b"abc", 193_409_669),
        (b"Host", 6_384_122_373),
        (b"host", 6_382_761_253),
        (&[0x80], 18_446_744_073_709_373_989),
        (&[0xFF], 18_446_744_073_709_374_042),
        (&[0x7F], 177_626),
        (&[b'a', 0x80, b'b', 0xFF], 6_382_547_225),
        (b"https://example.com:443\0", 3_967_404_914_050_609_914),
        (
            b"0123456789abcdefghijklmnopqrstuv",
            10_432_658_764_684_196_659,
        ),
        (&[0x00], 177_573),
        (&[0x00, 0x00], 5_859_909),
        (b"example.com", 13_753_681_666_016_513_922),
        (&[0xFF; 8], 7_567_926_139_714_181),
    ];

    // The same C program's `curlx_str_key_compare` over every ordered pair
    // of the corpus, row-major, one character per call. It is a pure
    // identity matrix, which is itself the finding: all fifteen keys are
    // pairwise distinct, INCLUDING the pair differing only in case and the
    // pair differing only in length.
    const C_COMPARE_MATRIX: &str = concat!(
        "100000000000000010000000000000001000000000000000100000000000",
        "000010000000000000001000000000000000100000000000000010000000",
        "000000001000000000000000100000000000000010000000000000001000",
        "000000000000100000000000000010000000000000001",
    );

    /// The bucket counts the C's own callers use, plus three others.
    ///
    /// 23 is the literal that four of the six string-keyed
    /// `Curl_hash_init` call sites pass. The rest are there so the fold is
    /// exercised on a power of two and on counts smaller and larger than
    /// the corpus.
    const SLOT_COUNTS: [usize; 4] = [7, 23, 91, 256];

    /// A value that counts its own drops.
    ///
    /// This is the instrument for the one property the C's two destructor
    /// levels existed to arrange: that every stored value is destroyed
    /// exactly once, whether the table is cleared, overwritten, pruned or
    /// dropped. `Rc<Cell<usize>>` rather than an atomic because the counter
    /// never leaves the thread that made it.
    struct Tracked {
        drops: Rc<Cell<usize>>,
    }

    impl Tracked {
        fn new(drops: &Rc<Cell<usize>>) -> Self {
            Self {
                drops: Rc::clone(drops),
            }
        }
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    /// `hash_str` with the byte folded in by ADDITION instead of XOR.
    ///
    /// Canonical djb2. Present only so that
    /// `the_byte_is_xored_not_added` can assert the two disagree, which is
    /// what makes that test able to fail.
    fn canonical_djb2(key: &[u8]) -> usize {
        let mut h: usize = 5381;
        for &byte in key {
            let j = byte as i8 as usize;
            h = h.wrapping_add(h << 5);
            h = h.wrapping_add(j);
        }
        h
    }

    /// `hash_str` with each byte read as UNSIGNED.
    ///
    /// Present only so that `sign_extension_is_reproduced` can assert the
    /// two disagree above 0x7F.
    fn unsigned_byte_variant(key: &[u8]) -> usize {
        let mut h: usize = 5381;
        for &byte in key {
            let j = usize::from(byte);
            h = h.wrapping_add(h << 5);
            h ^= j;
        }
        h
    }

    #[test]
    fn the_empty_key_returns_the_seed_unmodified() {
        // Trivial, but it is the only test that proves the loop bound: a
        // transcription that ran the body once for a zero-length key would
        // return something else.
        assert_eq!(hash_str(b""), 5381);
    }

    #[test]
    fn hash_str_matches_the_compiled_c_oracle() {
        for (key, expected) in C_ORACLE {
            assert_eq!(
                hash_str(key),
                expected,
                "hash_str disagrees with the C for key {key:02x?}"
            );
        }
    }

    #[test]
    fn the_byte_is_xored_not_added() {
        // The deviation from canonical djb2 that a transcription is most
        // likely to lose. Asserted from both sides: our value is the C's,
        // and the add-variant's value is NOT.
        assert_eq!(hash_str(b"a"), 177_604);
        assert_eq!(canonical_djb2(b"a"), 177_670);
        assert_ne!(hash_str(b"a"), canonical_djb2(b"a"));

        // Not a one-key accident -- but the separation is not universal
        // either, and the exception is worth stating because it is the sort
        // of thing an over-strong assertion hides.
        //
        // `h ^ 0` and `h + 0` are both `h`, so a key made entirely of ZERO
        // bytes drives the two forms through identical states and they
        // return the same value. That includes the empty key, which runs the
        // loop no times at all. For every other corpus entry -- measured,
        // not assumed -- the forms diverge, which is what makes those
        // entries able to detect the slip and the all-zero ones unable to.
        for (key, _) in C_ORACLE {
            let every_byte_is_zero = key.iter().all(|&byte| byte == 0);
            if every_byte_is_zero {
                assert_eq!(
                    hash_str(key),
                    canonical_djb2(key),
                    "an all-zero key cannot separate XOR from add, so \
                     {key:02x?} must give the same value under both"
                );
            } else {
                assert_ne!(
                    hash_str(key),
                    canonical_djb2(key),
                    "XOR and add agree on {key:02x?}, so this corpus \
                     entry cannot detect the slip"
                );
            }
        }
    }

    #[test]
    fn sign_extension_is_reproduced() {
        // `char` is signed on all four mandated targets, so 0x80 enters the
        // XOR as a sign-extended `size_t` with its whole high half set. The
        // C oracle says 0xfffffffffffd4a25; an unsigned read says 177445.
        assert_eq!(hash_str(&[0x80]), 0xffff_ffff_fffd_4a25);
        assert_eq!(unsigned_byte_variant(&[0x80]), 177_445);
        assert_ne!(hash_str(&[0x80]), unsigned_byte_variant(&[0x80]));

        // The two forms agree exactly on keys made of bytes <= 0x7F, which
        // is why the distinction is invisible until a non-ASCII key
        // arrives, and disagree on every key containing one.
        for (key, _) in C_ORACLE {
            let has_high_byte = key.iter().any(|&byte| byte > 0x7F);
            if has_high_byte {
                assert_ne!(hash_str(key), unsigned_byte_variant(key));
            } else {
                assert_eq!(hash_str(key), unsigned_byte_variant(key));
            }
        }
    }

    #[test]
    fn the_running_value_wraps_without_panicking() {
        // `h += h << 5` overflows a 64-bit accumulator within a handful of
        // bytes. Rust's `+` panics on overflow in a debug build, and the
        // test profile IS a debug build, so a plain `+` in `hash_str`
        // fails here rather than silently in production.
        for length in [16_usize, 32, 64, 1024, 8192] {
            // A checked conversion rather than a cast. The only `as` chain
            // this module permits is the sign extension inside `hash_str`
            // itself, so even a provably-in-range narrowing goes through
            // `try_from` here.
            let key: Vec<u8> = (0..length)
                .map(|i| u8::try_from(i % 251).expect("i % 251 is below 256"))
                .collect();
            // The assertion is that the call returns at all; the value is
            // pinned separately by the oracle test.
            let _ = hash_str(&key);
        }

        // And the oracle's own long entry, so that wrapping is checked
        // against the C rather than merely checked for absence of panic.
        assert_eq!(
            hash_str(b"0123456789abcdefghijklmnopqrstuv"),
            10_432_658_764_684_196_659
        );
    }

    #[test]
    fn hash_str_slot_folds_the_full_hash() {
        // The C's `Curl_hash_str` is this fold; the same C program verified
        // the identity below directly against `Curl_hash_str` for these
        // four slot counts over the whole corpus.
        for (key, expected) in C_ORACLE {
            for slots in SLOT_COUNTS {
                assert_eq!(
                    hash_str_slot(key, slots),
                    expected % slots,
                    "fold disagrees for {key:02x?} over {slots} slots"
                );
                assert!(hash_str_slot(key, slots) < slots);
            }
        }
    }

    #[test]
    fn hash_str_slot_accepts_the_bucket_count_the_c_consumers_use() {
        // 23 is the literal at `multi.c:250`, `url.c:498`, `url.c:3280` and
        // `easy.c:970`, and a single bucket is the degenerate count a
        // runtime-sized table could legitimately receive.
        for (key, _) in C_ORACLE {
            assert!(hash_str_slot(key, 23) < 23);
            assert_eq!(hash_str_slot(key, 1), 0);
        }
    }

    #[test]
    fn interior_and_trailing_nul_bytes_are_ordinary_key_bytes() {
        // The C loop is bounded by `key_length`, not by a terminator, so a
        // NUL is hashed like any other byte. This matters concretely:
        // `cpool_find_bundle` keys the connection pool on
        // `strlen(conn->destination) + 1`, so its keys really do end in one.
        assert_ne!(hash_str(b""), hash_str(&[0x00]));
        assert_ne!(hash_str(&[0x00]), hash_str(&[0x00, 0x00]));
        assert_ne!(hash_str(b"ab"), hash_str(b"ab\0"));

        // And the same holds for the comparator, so the trailing NUL is
        // part of the identity of a pool key rather than decoration.
        assert!(!str_key_compare(b"ab", b"ab\0"));

        // A key that is only NUL bytes still advances the accumulator,
        // which an implementation that stopped at a terminator would not.
        assert_eq!(hash_str(&[0x00]), 177_573);
        assert_eq!(hash_str(&[0x00, 0x00]), 5_859_909);
    }

    #[test]
    fn str_key_compare_matches_the_compiled_c_oracle() {
        let expected: Vec<bool> =
            C_COMPARE_MATRIX.chars().map(|c| c == '1').collect();
        // Non-vacuity, in the manner of the neighbouring `strcase` module:
        // a transcript of the wrong length would otherwise let the loop
        // below check almost nothing.
        assert_eq!(
            expected.len(),
            C_ORACLE.len() * C_ORACLE.len(),
            "the oracle transcript must cover every ordered pair"
        );

        let mut at = 0;
        for (left, _) in C_ORACLE {
            for (right, _) in C_ORACLE {
                assert_eq!(
                    str_key_compare(left, right),
                    expected[at],
                    "disagreement on {left:02x?} against {right:02x?}"
                );
                at += 1;
            }
        }
    }

    #[test]
    fn str_key_compare_is_case_sensitive() {
        // The single most likely wrong assumption about this function. It is
        // NOT curl's case-insensitive comparison and must not be routed
        // through `crate::util::strcase`.
        assert!(!str_key_compare(b"Host", b"host"));
        assert!(!str_key_compare(b"ACCEPT", b"accept"));
        assert!(str_key_compare(b"Host", b"Host"));
    }

    #[test]
    fn str_key_compare_requires_equal_length() {
        // The C tests `key1_len == key2_len` BEFORE `memcmp`, so a common
        // prefix is not a match in either direction.
        assert!(!str_key_compare(b"abc", b"abcd"));
        assert!(!str_key_compare(b"abcd", b"abc"));
        assert!(!str_key_compare(b"", b"a"));
        assert!(!str_key_compare(b"a", b""));
    }

    #[test]
    fn str_key_compare_accepts_two_empty_keys() {
        // Equal lengths of zero, and `memcmp(_, _, 0)` is 0, so the C
        // returns 1 here.
        assert!(str_key_compare(b"", b""));
    }

    #[test]
    fn str_key_compare_returns_true_on_match() {
        // Named for the trap: the C returns 1 on MATCH, which is the
        // inverse of the `memcmp` convention a reader may carry in.
        assert!(str_key_compare(b"same", b"same"));
        assert!(!str_key_compare(b"same", b"diff"));
    }

    #[test]
    fn insert_and_get_round_trip() {
        let mut table: StrHash<u32> = StrHash::new();
        assert!(table.insert(b"alpha", 1).is_none());
        assert!(table.insert(b"beta", 2).is_none());

        assert_eq!(table.get(b"alpha"), Some(&1));
        assert_eq!(table.get(b"beta"), Some(&2));
        assert_eq!(table.get(b"gamma"), None);
    }

    #[test]
    fn re_inserting_a_key_replaces_the_value_and_returns_the_old_one() {
        // `Curl_hash_add2` overwrote in place and destroyed the old value.
        // Here the old value comes back instead, and the count does not
        // grow.
        let mut table: StrHash<u32> = StrHash::new();
        assert_eq!(table.insert(b"key", 1), None);
        assert_eq!(table.insert(b"key", 2), Some(1));
        assert_eq!(table.get(b"key"), Some(&2));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn remove_reports_the_success_and_absent_distinction() {
        // The C returned 0 on success and 1 when the key was absent. `Some`
        // is that 0 and `None` is that 1.
        let mut table: StrHash<u32> = StrHash::new();
        table.insert(b"key", 7);

        assert_eq!(table.remove(b"key"), Some(7));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn removing_an_absent_key_reports_absence_without_error() {
        let mut table: StrHash<u32> = StrHash::new();
        assert_eq!(table.remove(b"never-inserted"), None);

        table.insert(b"present", 1);
        assert_eq!(table.remove(b"absent"), None);
        // The failed removal left the table untouched.
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(b"present"), Some(&1));

        // Removing twice: the second call reports absence.
        assert_eq!(table.remove(b"present"), Some(1));
        assert_eq!(table.remove(b"present"), None);
    }

    #[test]
    fn len_and_is_empty_track_the_entry_count() {
        let mut table: StrHash<usize> = StrHash::new();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());

        for (index, (key, _)) in C_ORACLE.iter().enumerate() {
            table.insert(key, index);
            assert_eq!(table.len(), index + 1);
            assert!(!table.is_empty());
        }
        assert_eq!(table.len(), C_ORACLE.len());
    }

    #[test]
    fn clear_empties_the_table_and_leaves_it_usable() {
        let mut table: StrHash<u32> = StrHash::new();
        table.insert(b"a", 1);
        table.insert(b"b", 2);

        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.get(b"a"), None);

        // `Curl_hash_clean` left the table usable, unlike
        // `Curl_hash_destroy` which also zeroed `slots`.
        table.insert(b"c", 3);
        assert_eq!(table.get(b"c"), Some(&3));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn the_criterium_removes_what_it_selects() {
        // THE POLARITY TEST. curl's callback returning TRUE means REMOVE,
        // which is the opposite of `HashMap::retain`. Getting this backwards
        // silently empties a cache or silently never prunes one, so both
        // halves are asserted: the selected entries are gone AND the
        // unselected ones are still there.
        // The loop variable is `u8` so that it can be a key byte directly:
        // the only `as` chain this module permits is the sign extension
        // inside `hash_str`.
        let mut table: StrHash<u8> = StrHash::new();
        for value in 0..10_u8 {
            table.insert(&[b'k', value], value);
        }

        // Select the even values for removal.
        table.clean_with_criterium(|value| value % 2 == 0);

        assert_eq!(table.len(), 5);
        for value in 0..10_u8 {
            let key = [b'k', value];
            if value % 2 == 0 {
                assert_eq!(
                    table.get(&key),
                    None,
                    "{value} was selected and should be gone"
                );
            } else {
                assert_eq!(
                    table.get(&key),
                    Some(&value),
                    "{value} was not selected and should remain"
                );
            }
        }
    }

    #[test]
    fn an_always_true_criterium_empties_the_table() {
        // The C's NULL-callback case, which removed everything, is
        // `clear`; an always-true criterium is the same outcome reached
        // through the callback, and it is the direction an inverted
        // implementation would turn into a no-op.
        let mut table: StrHash<u32> = StrHash::new();
        table.insert(b"a", 1);
        table.insert(b"b", 2);
        table.insert(b"c", 3);

        table.clean_with_criterium(|_| true);
        assert!(table.is_empty());
    }

    #[test]
    fn an_always_false_criterium_removes_nothing() {
        // The mirror direction, which an inverted implementation would turn
        // into "empty the cache".
        let mut table: StrHash<u32> = StrHash::new();
        table.insert(b"a", 1);
        table.insert(b"b", 2);

        table.clean_with_criterium(|_| false);
        assert_eq!(table.len(), 2);
        assert_eq!(table.get(b"a"), Some(&1));
        assert_eq!(table.get(b"b"), Some(&2));
    }

    #[test]
    fn the_criterium_sees_every_value_exactly_once() {
        // The C walked every bucket and every chain, so the callback saw
        // each entry once. `retain` gives the same guarantee, and the
        // `dnscache_prune` consumer depends on it: it accumulates the
        // maximum surviving age as a side effect of being called for all of
        // them.
        let mut table: StrHash<u32> = StrHash::new();
        for value in 0..20_u32 {
            table.insert(&value.to_be_bytes(), value);
        }

        let mut seen: Vec<u32> = Vec::new();
        table.clean_with_criterium(|value| {
            seen.push(*value);
            false
        });

        seen.sort_unstable();
        assert_eq!(seen, (0..20_u32).collect::<Vec<u32>>());
    }

    #[test]
    fn the_criterium_drops_exactly_the_values_it_removed() {
        let drops = Rc::new(Cell::new(0_usize));
        let mut table: StrHash<Tracked> = StrHash::new();
        for index in 0..6_u8 {
            table.insert(&[index], Tracked::new(&drops));
        }
        assert_eq!(drops.get(), 0);

        let mut remove_next = true;
        table.clean_with_criterium(|_| {
            let decision = remove_next;
            remove_next = !remove_next;
            decision
        });

        assert_eq!(table.len(), 3);
        assert_eq!(drops.get(), 3, "only the removed values were dropped");

        drop(table);
        assert_eq!(drops.get(), 6, "the survivors dropped with the table");
    }

    #[test]
    fn a_capacity_hint_changes_nothing_observable() {
        // `with_slots` forwards to `HashMap::with_capacity`, which is a
        // pre-allocation hint and not a cap -- unlike the C's `slots`, which
        // was a fixed bucket count that was never grown. So a table built
        // with a hint of 1 must accept far more than one entry and behave
        // identically to one built with `new`.
        let mut hinted: StrHash<u32> = StrHash::with_slots(1);
        let mut plain: StrHash<u32> = StrHash::new();
        let mut zero_hinted: StrHash<u32> = StrHash::with_slots(0);

        for index in 0..200_u32 {
            let key = index.to_be_bytes();
            hinted.insert(&key, index);
            plain.insert(&key, index);
            zero_hinted.insert(&key, index);
        }

        assert_eq!(hinted.len(), 200);
        assert_eq!(plain.len(), 200);
        assert_eq!(zero_hinted.len(), 200);

        for index in 0..200_u32 {
            let key = index.to_be_bytes();
            assert_eq!(hinted.get(&key), Some(&index));
            assert_eq!(plain.get(&key), Some(&index));
            assert_eq!(zero_hinted.get(&key), Some(&index));
        }

        // And a generous hint over the C's own literal bucket count.
        let mut like_the_c: StrHash<u32> = StrHash::with_slots(23);
        like_the_c.insert(b"only", 1);
        assert_eq!(like_the_c.len(), 1);
    }

    #[test]
    fn dropping_the_table_drops_every_value_exactly_once() {
        // The property the C's two destructor levels existed to arrange,
        // and the one `Curl_hash_destroy` asserted with
        // `DEBUGASSERT(h->size == 0)`.
        let drops = Rc::new(Cell::new(0_usize));
        {
            let mut table: StrHash<Tracked> = StrHash::new();
            for index in 0..25_u8 {
                table.insert(&[index], Tracked::new(&drops));
            }
            assert_eq!(drops.get(), 0, "nothing drops while the table lives");
        }
        assert_eq!(drops.get(), 25);
    }

    #[test]
    fn clear_drops_every_value_exactly_once() {
        let drops = Rc::new(Cell::new(0_usize));
        let mut table: StrHash<Tracked> = StrHash::new();
        for index in 0..8_u8 {
            table.insert(&[index], Tracked::new(&drops));
        }

        table.clear();
        assert_eq!(drops.get(), 8);

        // Dropping the now-empty table drops nothing further, which is the
        // double-free the C avoided by setting `he->ptr = NULL` after
        // calling the destructor.
        drop(table);
        assert_eq!(drops.get(), 8);
    }

    #[test]
    fn replacing_a_value_drops_only_the_displaced_one() {
        // `Curl_hash_add2` on an existing key called the destructor for the
        // old value and kept the new one. Here the old value is RETURNED,
        // so it drops when the caller lets go of it -- and a caller that
        // ignores the result, as the C effectively did, drops it at the end
        // of the statement.
        let drops = Rc::new(Cell::new(0_usize));
        let mut table: StrHash<Tracked> = StrHash::new();

        table.insert(b"key", Tracked::new(&drops));
        assert_eq!(drops.get(), 0);

        // Result ignored: the displaced value drops here.
        table.insert(b"key", Tracked::new(&drops));
        assert_eq!(drops.get(), 1);
        assert_eq!(table.len(), 1);

        // Result bound: the displaced value outlives the call.
        let displaced = table.insert(b"key", Tracked::new(&drops));
        assert_eq!(drops.get(), 1);
        assert!(displaced.is_some());
        drop(displaced);
        assert_eq!(drops.get(), 2);

        drop(table);
        assert_eq!(drops.get(), 3);
    }

    #[test]
    fn removing_a_value_drops_it_once_when_the_caller_lets_go() {
        let drops = Rc::new(Cell::new(0_usize));
        let mut table: StrHash<Tracked> = StrHash::new();
        table.insert(b"key", Tracked::new(&drops));

        let taken = table.remove(b"key");
        assert!(taken.is_some());
        assert_eq!(drops.get(), 0, "the value moved out rather than dying");

        drop(taken);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn iteration_visits_every_entry_exactly_once() {
        // The successor to `Curl_hash_start_iterate` plus
        // `Curl_hash_next_element`. Order is unspecified and randomised per
        // process, so the assertion sorts -- which is exactly the discipline
        // any order-sensitive consumer must adopt.
        let mut table: StrHash<u32> = StrHash::new();
        for index in 0..12_u32 {
            table.insert(&index.to_be_bytes(), index);
        }

        let mut visited: Vec<(Vec<u8>, u32)> = table
            .iter()
            .map(|(key, value)| (key.to_vec(), *value))
            .collect();
        visited.sort();

        let expected: Vec<(Vec<u8>, u32)> = (0..12_u32)
            .map(|index| (index.to_be_bytes().to_vec(), index))
            .collect();
        assert_eq!(visited, expected);
    }

    #[test]
    fn iteration_yields_the_key_bytes_including_high_and_nul_bytes() {
        // The C's `struct Curl_hash_element` exposed `he->key` with
        // `he->key_len`, so a key is bytes and not text. A key containing
        // 0x00 and 0xFF must come back unchanged.
        let mut table: StrHash<u32> = StrHash::new();
        let awkward: &[u8] = &[0x00, 0xFF, b'x', 0x80, 0x00];
        table.insert(awkward, 1);

        let keys: Vec<Vec<u8>> = table.keys().map(<[u8]>::to_vec).collect();
        assert_eq!(keys, vec![awkward.to_vec()]);
        assert_eq!(table.get(awkward), Some(&1));
    }

    #[test]
    fn iter_mut_can_modify_every_value() {
        // The C reached this by handing out `void *he->ptr`; here the
        // mutable borrow is tracked, which is what makes removing during
        // iteration a compile error rather than the hazard
        // `cpool_foreach` works around by hand.
        let mut table: StrHash<u32> = StrHash::new();
        for index in 0..5_u32 {
            table.insert(&index.to_be_bytes(), index);
        }

        for (_key, value) in table.iter_mut() {
            *value *= 10;
        }

        let mut values: Vec<u32> = table.values().copied().collect();
        values.sort_unstable();
        assert_eq!(values, vec![0, 10, 20, 30, 40]);
    }

    #[test]
    fn keys_and_values_agree_with_iter() {
        let mut table: StrHash<usize> = StrHash::new();
        for (index, (key, _)) in C_ORACLE.iter().enumerate() {
            table.insert(key, index);
        }

        let mut from_iter_keys: Vec<Vec<u8>> =
            table.iter().map(|(key, _)| key.to_vec()).collect();
        let mut from_keys: Vec<Vec<u8>> =
            table.keys().map(<[u8]>::to_vec).collect();
        from_iter_keys.sort();
        from_keys.sort();
        assert_eq!(from_iter_keys, from_keys);

        let mut from_iter_values: Vec<usize> =
            table.iter().map(|(_, value)| *value).collect();
        let mut from_values: Vec<usize> = table.values().copied().collect();
        from_iter_values.sort_unstable();
        from_values.sort_unstable();
        assert_eq!(from_iter_values, from_values);
        assert_eq!(from_values.len(), C_ORACLE.len());
    }

    #[test]
    fn get_mut_modifies_in_place() {
        let mut table: StrHash<u32> = StrHash::new();
        table.insert(b"counter", 1);

        if let Some(value) = table.get_mut(b"counter") {
            *value += 41;
        }
        assert_eq!(table.get(b"counter"), Some(&42));
        assert!(table.get_mut(b"missing").is_none());
    }

    #[test]
    fn the_debug_rendering_stands_in_for_curl_hash_print() {
        // `Curl_hash_print` printed `[key=%.*s, ...]`, treating key bytes as
        // text without checking that they are. `from_utf8_lossy` does the
        // same without reading past the key.
        let mut table: StrHash<u32> = StrHash::new();
        table.insert(b"Host", 1);
        let rendered = format!("{table:?}");
        assert!(rendered.contains("Host"), "got {rendered}");
        assert!(rendered.contains('1'), "got {rendered}");

        // An empty table renders without panicking, and a non-UTF-8 key is
        // rendered lossily rather than refused.
        let empty: StrHash<u32> = StrHash::new();
        assert_eq!(format!("{empty:?}"), "{}");

        let mut binary: StrHash<u32> = StrHash::new();
        binary.insert(&[0xFF, 0xFE], 2);
        assert!(!format!("{binary:?}").is_empty());
    }

    #[test]
    fn default_equals_new() {
        let from_default: StrHash<u32> = StrHash::default();
        let from_new: StrHash<u32> = StrHash::new();
        assert_eq!(from_default.len(), from_new.len());
        assert!(from_default.is_empty());
    }

    #[test]
    fn the_table_stores_every_corpus_key_distinctly() {
        // The comparator matrix says all fifteen corpus keys are pairwise
        // distinct; this is the same claim made of the collection, so a key
        // type that lost the length or folded case would show up here as a
        // short table.
        let mut table: StrHash<usize> = StrHash::new();
        for (index, (key, _)) in C_ORACLE.iter().enumerate() {
            assert!(
                table.insert(key, index).is_none(),
                "{key:02x?} collided with an earlier corpus key"
            );
        }
        assert_eq!(table.len(), C_ORACLE.len());

        for (index, (key, _)) in C_ORACLE.iter().enumerate() {
            assert_eq!(table.get(key), Some(&index));
        }
    }
}
