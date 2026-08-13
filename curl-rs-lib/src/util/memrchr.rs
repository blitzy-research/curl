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

//! Reverse byte search -- supersedes `lib/curl_memrchr.c` and
//! `lib/curl_memrchr.h`.
//!
//! One function wide, and deliberately so: the C translation unit defines
//! exactly one symbol and its header declares exactly one, so this module
//! publishes exactly one. It is a file of its own rather than a paragraph in
//! `super` because the transformation map names it as its own module -- and
//! because the C original is a separate translation unit for a reason that
//! is worth keeping in view: the whole of it sits inside a portability
//! guard, which is a property of a file rather than of a function.
//!
//! # `int` going in, [`u8`] here
//!
//! C takes the needle as an `int` and compares it as `(unsigned char)c`, so
//! `Curl_memrchr(s, 0x141, n)` searches for `0x41`. That narrowing is real,
//! silent, and part of the standard `memchr` family's contract rather than a
//! quirk of curl's clone. Taking a [`u8`] moves it to the caller, where it
//! has to be written down instead of happening invisibly.
//!
//! Nothing is lost by insisting on it: every needle in the C tree is already
//! a character literal -- `'/'` at `lib/urlapi.c:784` and `:1261`, `'.'` at
//! `lib/cookie.c:168` and `:170`, and `'.'` at `lib/vtls/hostcheck.c:102`.
//!
//! # Visibility and layering
//!
//! `pub(crate)`. Neither `memrchr` nor `Curl_memrchr` appears in
//! `lib/libcurl.def`, so no exported symbol is backed from here, nothing in
//! `curl-rs-ffi` reaches it, and the crate root adds no re-export for it.
//!
//! This file names no sibling module. `super` records the layering rule for
//! the whole directory -- `util` may depend on nothing inside this crate
//! except `crate::error` -- and here not even that is needed, because a
//! reverse byte search cannot fail. Every input has an answer, and the
//! answer for "not found" is [`None`] rather than an error.

/// Returns the index of the last occurrence of `needle` in `haystack`.
#[allow(dead_code)]
pub(crate) fn memrchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    // Fully qualified rather than imported. `use memchr::memrchr;` would
    // collide with this module's own item of the same name, and aliasing the
    // import to hide the collision would leave the call site reading as
    // though it delegated somewhere else.
    ::memchr::memrchr(needle, haystack)
}

#[cfg(test)]
mod tests {
    use super::memrchr;

    /// A transliteration of `Curl_memrchr` (`lib/curl_memrchr.c:37-52`) that
    /// walks the way the C walks, used as the differential oracle below.
    fn walk_backwards(needle: u8, haystack: &[u8]) -> Option<usize> {
        // `if(n > 0)`.
        if haystack.is_empty() {
            return None;
        }

        // `p += n - 1`.
        let mut position = haystack.len() - 1;

        loop {
            // `if(*p == (unsigned char)c) return CURL_UNCONST(p);`
            if haystack[position] == needle {
                return Some(position);
            }

            // The guard the C does not have.
            if position == 0 {
                return None;
            }

            // `p--`.
            position -= 1;
        }
    }

    #[test]
    fn finds_a_match_at_the_very_end() {
        assert_eq!(memrchr(b'c', b"abc"), Some(2));
    }

    #[test]
    fn finds_a_match_at_the_very_start() {
        assert_eq!(memrchr(b'a', b"abc"), Some(0));
    }

    /// Backwards, not forwards. This is the single behaviour separating this
    /// function from `memchr`, so it gets a test of its own rather than a
    /// line inside a larger one.
    #[test]
    fn the_last_of_several_occurrences_wins() {
        assert_eq!(memrchr(b'a', b"aXaXa"), Some(4));
        assert_eq!(memrchr(b'X', b"aXaXa"), Some(3));
    }

    #[test]
    fn an_absent_byte_is_not_found() {
        assert_eq!(memrchr(b'z', b"abc"), None);
    }

    /// The `if(n > 0)` guard: nothing is read, and nothing is found.
    #[test]
    fn an_empty_haystack_is_never_a_match() {
        assert_eq!(memrchr(b'a', b""), None);
        assert_eq!(memrchr(0x00, b""), None);
    }

    #[test]
    fn a_single_byte_haystack_hits_and_misses() {
        assert_eq!(memrchr(b'a', b"a"), Some(0));
        assert_eq!(memrchr(b'b', b"a"), None);
    }

    /// A NUL is an ordinary searchable value. The C compares
    /// `(unsigned char)c` against `*p` and never treats zero as a
    /// terminator, because the length arrives separately -- so a haystack may
    /// contain any number of them and the last one still wins.
    #[test]
    fn a_nul_byte_is_searchable_like_any_other() {
        assert_eq!(memrchr(0x00, b"a\0b\0"), Some(3));
        assert_eq!(memrchr(0x00, b"a\0b"), Some(1));
        assert_eq!(memrchr(b'b', b"a\0b\0"), Some(2));
    }

    /// The high half of the range works, which is what the C's
    /// `(unsigned char)` cast is for: on a platform where `char` is signed, a
    /// comparison that skipped that cast would get `0xff` wrong.
    #[test]
    fn a_high_byte_is_searchable() {
        assert_eq!(memrchr(0xff, &[0x00, 0xff, 0x41]), Some(1));
        assert_eq!(memrchr(0x80, &[0x7f, 0x80, 0x81]), Some(1));
    }

    /// All 256 byte values are findable, in a haystack holding each of them
    /// exactly once at its own index -- so the expected answer for a byte is
    /// the byte itself, and a scan that lost the top bit anywhere would fail
    /// on 128 of the 256 checks rather than on a lucky one.
    #[test]
    fn every_byte_value_is_findable() {
        let haystack: Vec<u8> = (0..=u8::MAX).collect();
        for byte in 0..=u8::MAX {
            assert_eq!(memrchr(byte, &haystack), Some(usize::from(byte)));
        }
    }

    /// The same haystack twice over: every answer moves to the second copy.
    /// That is "the last occurrence wins" checked across all 256 values
    /// instead of on one hand-picked string.
    #[test]
    fn the_second_copy_of_a_doubled_haystack_wins() {
        let mut haystack: Vec<u8> = (0..=u8::MAX).collect();
        haystack.extend(0..=u8::MAX);
        for byte in 0..=u8::MAX {
            let expected = Some(256 + usize::from(byte));
            assert_eq!(memrchr(byte, &haystack), expected);
        }
    }

    /// Differential against `walk_backwards` over every string of length 0 to
    /// 4 inclusive drawn from a three-symbol alphabet, for four needles: 121
    /// haystacks and 484 comparisons.
    #[test]
    fn agrees_with_the_c_walk_on_every_short_input() {
        const ALPHABET: [u8; 3] = [b'a', b'b', 0x00];
        const NEEDLES: [u8; 4] = [b'a', b'b', 0x00, 0xff];

        let mut haystack: Vec<u8> = Vec::with_capacity(4);
        let mut compared = 0_usize;

        for length in 0_u32..=4 {
            for combination in 0..ALPHABET.len().pow(length) {
                haystack.clear();
                let mut code = combination;
                for _ in 0..length {
                    haystack.push(ALPHABET[code % ALPHABET.len()]);
                    code /= ALPHABET.len();
                }

                for needle in NEEDLES {
                    assert_eq!(
                        memrchr(needle, &haystack),
                        walk_backwards(needle, &haystack),
                        "needle {needle:#04x} in {haystack:?}"
                    );
                }
                compared += NEEDLES.len();
            }
        }

        assert_eq!(compared, 484, "the sweep must not silently shrink");
    }

    /// `lib/urlapi.c:782-787` removes the last path segment by finding the
    /// last `/` and truncating the output buffer at that offset -- and does
    /// nothing at all when there is no slash, which is its `if(last)`.
    #[test]
    fn the_url_normaliser_trims_at_the_last_slash() {
        let out = b"/alpha/beta/gamma";
        let last = memrchr(b'/', out).expect("the buffer holds a slash");
        assert_eq!(last, 11);
        assert_eq!(&out[..last], &b"/alpha/beta"[..]);

        assert_eq!(memrchr(b'/', b"gamma"), None);
    }

    /// `lib/cookie.c:166-172` finds the last dot, then the last dot BEFORE
    /// it, and keeps everything after that second one. The C passes
    /// `last - domain` as the inner search's length; here the caller slices,
    /// which is the same bound expressed as a range.
    #[test]
    fn the_cookie_jar_finds_a_top_domain_with_two_reverse_searches() {
        let domain = b"www.example.co.uk";
        let last = memrchr(b'.', domain).expect("a trailing label separator");
        assert_eq!(last, 14);
        let first = memrchr(b'.', &domain[..last]).expect("a second separator");
        assert_eq!(first, 11);
        assert_eq!(&domain[first + 1..], &b"co.uk"[..]);

        // One dot only: the inner search runs over the prefix before it and
        // finds nothing, which is the C leaving `first` NULL so that the
        // whole domain is its own top domain.
        let single = b"example.com";
        let only = memrchr(b'.', single).expect("a separator");
        assert_eq!(memrchr(b'.', &single[..only]), None);

        // A leading dot makes that prefix empty, which reaches the `n == 0`
        // guard through a real call site rather than in isolation.
        let leading = b".uk";
        assert_eq!(memrchr(b'.', leading), Some(0));
        assert_eq!(memrchr(b'.', &leading[..0]), None);
    }

    /// `lib/vtls/hostcheck.c:100-102` refuses a wildcard pattern with fewer
    /// than two dots by asking whether the last dot IS the first dot. The
    /// forward half of that predicate is `memchr`, and pairing the two is
    /// why this module sits beside that function instead of reimplementing
    /// it.
    #[test]
    fn the_hostname_check_compares_the_first_dot_with_the_last() {
        let one_label = b"*.example";
        assert_eq!(::memchr::memchr(b'.', one_label), Some(1));
        assert_eq!(memrchr(b'.', one_label), Some(1));

        let two_labels = b"*.example.com";
        assert_eq!(::memchr::memchr(b'.', two_labels), Some(1));
        assert_eq!(memrchr(b'.', two_labels), Some(9));
    }
}
