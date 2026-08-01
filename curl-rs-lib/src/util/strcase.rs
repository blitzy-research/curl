//! Locale-independent ASCII case comparison -- supersedes the public half of
//! `lib/strcase.c` (the two 256-entry folding tables) and all of
//! `lib/strequal.c`.
//!
//! # Why this module is `pub` when its parent is not
//!
//! `crate::util` is `pub(crate)`, private by ENFORCEMENT rather than by the
//! `Curl_` naming convention the C tree relied on. This file nevertheless
//! declares two `pub` items, for the same reason [`super::parsedate`] declares
//! one: `curl_strequal` and `curl_strnequal` are two of the 100 symbols
//! `lib/libcurl.def` exports, and the crate root re-exports [`strequal`] and
//! [`strnequal`] so that `curl-rs-ffi` can reach them. Everything else here is
//! `pub(crate)` or private.
//!
//! The boundary is drawn so that this module owns every comparison decision --
//! the folding rule, the NUL handling, the two asymmetric null-pointer
//! contracts -- and the adapter is left with nothing but converting a
//! `*const c_char` into an `Option<&CStr>`.
//!
//! # The contract being reproduced
//!
//! `lib/strequal.c:76-84` and `:87-95` define the two exported functions. Both
//! delegate to a static comparator when BOTH pointers are non-NULL and
//! otherwise apply a null-pointer rule that differs between them:
//!
//! ```text
//! curl_strequal (s1, s2)     -> casecompare(s1, s2)         when both non-NULL
//!                            -> s1 == NULL && s2 == NULL     otherwise
//! curl_strnequal(s1, s2, n)  -> ncasecompare(s1, s2, n)      when both non-NULL
//!                            -> s1 == NULL && s2 == NULL && n != 0   otherwise
//! ```
//!
//! The trailing `&& n` in the second is not a typo in the C and is not dead
//! weight: `curl_strnequal(NULL, NULL, 0)` returns 0 while
//! `curl_strequal(NULL, NULL)` returns 1. Two null pointers are "equal" only
//! when a non-zero number of bytes was asked for. That asymmetry is part of
//! the frozen contract (AAP 0.8.1) and is reproduced exactly, with a test
//! naming it.
//!
//! # The folding rule, and the proof that `to_ascii_uppercase` is identical
//!
//! C does not call `toupper()`. `lib/strcase.c:72-77` explains why -- the
//! locale can change what `toupper()` does, notoriously for Turkish `i` -- and
//! folds through a hand-written 256-entry table instead. That table was read
//! and compared against the identity map entry by entry:
//!
//! * `touppermap` (`lib/strcase.c:28-47`) is the identity at every index
//!   except 97..=122 (`a`..=`z`), which map to 65..=90 (`A`..=`Z`).
//! * `tolowermap` (`lib/strcase.c:50-69`) is the identity at every index
//!   except 65..=90, which map to 97..=122.
//!
//! `u8::to_ascii_uppercase` maps exactly 97..=122 to 65..=90 and is the
//! identity elsewhere, by definition rather than by locale. It is therefore
//! the same function as `Curl_raw_toupper`, and the two folding tables are not
//! transcribed. This is a proven equivalence, not a convenience: the
//! substitution was made only after measuring both tables.
//!
//! Neither `Curl_raw_toupper` nor `Curl_raw_tolower` is an exported symbol --
//! `lib/libcurl.def` lists neither -- so no wrapper for them exists here.
//! Adding one would create an item with no caller, which the crate's
//! dead-code policy forbids.
//!
//! # What is deliberately NOT ported
//!
//! `lib/strcase.c` also defines `Curl_strntoupper`, `Curl_strntolower`,
//! `Curl_safecmp` and `Curl_timestrcmp`, and `lib/strcase.h` declares
//! `Curl_strcasecompare` and `Curl_strncasecompare`. All six are internal
//! (`Curl_`-prefixed, absent from `lib/libcurl.def`), so under the AAP 0.4.2
//! rule they become `pub(crate)` items in whichever module needs them -- and
//! at this commit none does. They are not written here as unused helpers:
//! `Curl_timestrcmp` in particular is a CONSTANT-TIME comparison used for
//! credentials, and a copy of it sitting unused would invite a caller to reach
//! for the ordinary comparison next to it by mistake. It belongs with the
//! authentication code that needs it, when that lands.

use std::ffi::CStr;

/// The comparator behind `curl_strequal`, on the byte content of two strings.
///
/// Supersedes `casecompare` (`lib/strequal.c:35-49`). The C walks the first
/// string to its NUL and, on reaching it, returns `!*first == !*second` --
/// which, with `*first` known to be zero there, is exactly "the second string
/// also ended here". A shorter second string is caught inside the loop, where
/// its NUL fails to match a non-NUL byte. So the whole function is
/// case-insensitive equality of the two byte sequences INCLUDING their
/// lengths, which is what `<[u8]>::eq_ignore_ascii_case` computes.
///
/// `eq_ignore_ascii_case` folds to lower case where C folds to upper. For
/// ASCII the two agree on every input, because both collapse exactly the 26
/// `a`/`A` pairs and leave every other byte alone; a test compares the two
/// directions over a corpus that includes the bytes just outside those ranges.
fn casecompare(first: &[u8], second: &[u8]) -> bool {
    first.eq_ignore_ascii_case(second)
}

/// The comparator behind `curl_strnequal`, on the byte content of two strings.
///
/// Supersedes `ncasecompare` (`lib/strequal.c:51-63`), which has no standard
/// counterpart and is therefore reproduced as an explicit walk:
///
/// ```text
/// while(*first && max) { if(fold(*first) != fold(*second)) return 0;
///                        max--; first++; second++; }
/// if(max == 0) return 1;
/// return fold(*first) == fold(*second);
/// ```
///
/// Two details decide the result and are easy to lose in translation:
///
/// * The loop stops on EITHER the first string's NUL or the byte budget
///   running out, and `max == 0` short-circuits to true BEFORE the tail
///   comparison. So `ncasecompare("abc", "abx", 2)` is true: only two bytes
///   were asked for and those two matched.
/// * When the budget survives, the first string has ended, and the tail
///   comparison is `fold(0) == fold(*second)` -- that is, the second string
///   must have ended at the same offset. So `ncasecompare("ab", "abc", 9)` is
///   false.
///
/// The fold itself is `u8::eq_ignore_ascii_case`, which folds DOWN, whereas
/// the C's `touppermap` folds UP. The two decide every byte pair identically,
/// and that is proven rather than assumed: `the_two_folding_directions_agree_
/// on_every_byte_pair` below checks all 65,536 pairs, and the whole function is
/// additionally differential-tested against the frozen `curl_strnequal` over
/// 3,388 bits. Using the standard-library primitive is therefore a change of
/// spelling, not of behaviour.
///
/// The C reads the NUL terminator itself, one past the last content byte.
/// These slices come from [`CStr::to_bytes`] and so exclude it, which is why
/// every read below is `get(i).copied().unwrap_or(0)`: index `len()` yields
/// the zero the C would have read there. A `CStr` cannot contain an interior
/// zero, so no earlier index can produce one by accident.
fn ncasecompare(first: &[u8], second: &[u8], max: usize) -> bool {
    let byte_at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0);

    let mut i = 0usize;
    let mut budget = max;
    while budget != 0 {
        let a = byte_at(first, i);
        if a == 0 {
            break;
        }
        if !a.eq_ignore_ascii_case(&byte_at(second, i)) {
            return false;
        }
        budget -= 1;
        i += 1;
    }

    if budget == 0 {
        // The caller's byte budget was satisfied without a mismatch. C returns
        // 1 here without looking at either string again, so neither does this.
        return true;
    }

    // The first string ended with budget to spare; C compares its NUL against
    // whatever the second string has at the same offset.
    byte_at(second, i) == 0
}

/// Case-insensitive comparison of two whole strings -- backs `curl_strequal`.
///
/// Reproduces `lib/strequal.c:76-84`. `None` models a NULL pointer: two NULLs
/// compare equal, and one NULL against a string does not.
///
/// The comparison is locale-independent by construction: only the 26 ASCII
/// letter pairs are folded, whatever the process locale says. That is the
/// entire reason the function exists rather than deferring to `strcasecmp`.
///
/// # Examples
///
/// ```
/// use std::ffi::CString;
/// let a = CString::new("Content-Type").unwrap();
/// let b = CString::new("CONTENT-TYPE").unwrap();
/// assert!(curl_rs_lib::strequal(Some(a.as_c_str()), Some(b.as_c_str())));
/// assert!(curl_rs_lib::strequal(None, None));
/// assert!(!curl_rs_lib::strequal(Some(a.as_c_str()), None));
/// ```
#[must_use]
pub fn strequal(s1: Option<&CStr>, s2: Option<&CStr>) -> bool {
    match (s1, s2) {
        (Some(a), Some(b)) => casecompare(a.to_bytes(), b.to_bytes()),
        // "if both pointers are NULL then treat them as equal"
        // (lib/strequal.c:82-83).
        (None, None) => true,
        _ => false,
    }
}

/// Case-insensitive comparison of at most `n` bytes -- backs `curl_strnequal`.
///
/// Reproduces `lib/strequal.c:87-95`, including the null-pointer rule that
/// differs from [`strequal`]: two NULLs are equal only when `n` is non-zero.
///
/// # Examples
///
/// ```
/// use std::ffi::CString;
/// let a = CString::new("HTTP/1.1 200").unwrap();
/// let b = CString::new("http/1.1 404").unwrap();
/// // The first eight bytes match case-insensitively.
/// assert!(curl_rs_lib::strnequal(Some(a.as_c_str()), Some(b.as_c_str()), 8));
/// assert!(!curl_rs_lib::strnequal(Some(a.as_c_str()), Some(b.as_c_str()), 12));
/// // Two null pointers are equal only for a non-zero count.
/// assert!(curl_rs_lib::strnequal(None, None, 1));
/// assert!(!curl_rs_lib::strnequal(None, None, 0));
/// ```
#[must_use]
pub fn strnequal(s1: Option<&CStr>, s2: Option<&CStr>, n: usize) -> bool {
    match (s1, s2) {
        (Some(a), Some(b)) => ncasecompare(a.to_bytes(), b.to_bytes(), n),
        // "treat them as equal if max is non-zero" (lib/strequal.c:93-94).
        (None, None) => n != 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// The folding equivalence this module rests on, checked rather than
    /// asserted in prose: over every byte value, upper-folding and
    /// lower-folding must agree on whether two bytes are the same letter.
    // The two manual folds below are precisely what this test compares, so
    // `clippy::manual_ignore_case_cmp` must not collapse them into
    // `eq_ignore_ascii_case`: that is exactly the primitive whose equivalence
    // to the C's upward fold is under test, and substituting it on both sides
    // would leave the assertion comparing a value with itself.
    #[allow(clippy::manual_ignore_case_cmp)]
    #[test]
    fn the_two_folding_directions_agree_on_every_byte_pair() {
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let upper = a.to_ascii_uppercase() == b.to_ascii_uppercase();
                let lower = a.to_ascii_lowercase() == b.to_ascii_lowercase();
                assert_eq!(
                    upper, lower,
                    "bytes {a} and {b} disagree between the two fold directions"
                );
            }
        }
    }

    /// `Curl_raw_toupper`'s table is the identity except for `a`..=`z`. This
    /// asserts the same of the substitute, so the measurement recorded in the
    /// module documentation is executable rather than a claim.
    #[test]
    fn the_fold_touches_only_the_twenty_six_letters() {
        for byte in 0u8..=255 {
            let folded = byte.to_ascii_uppercase();
            if byte.is_ascii_lowercase() {
                assert_eq!(
                    folded,
                    byte - 32,
                    "byte {byte} must fold to upper case"
                );
            } else {
                assert_eq!(folded, byte, "byte {byte} must be left alone");
            }
        }
    }

    #[test]
    fn whole_string_comparison_ignores_ascii_case_only() {
        assert!(strequal(Some(&cs("Accept")), Some(&cs("ACCEPT"))));
        assert!(strequal(Some(&cs("")), Some(&cs(""))));
        // Non-ASCII bytes are compared verbatim: these two differ only in a
        // byte outside a-z/A-Z, so no folding can make them equal.
        assert!(!strequal(Some(&cs("tea\u{e9}")), Some(&cs("tea\u{c9}"))));
    }

    #[test]
    fn a_length_difference_is_never_equal() {
        assert!(!strequal(Some(&cs("Accept")), Some(&cs("Accept-Encoding"))));
        assert!(!strequal(Some(&cs("Accept-Encoding")), Some(&cs("Accept"))));
        assert!(!strequal(Some(&cs("a")), Some(&cs(""))));
        assert!(!strequal(Some(&cs("")), Some(&cs("a"))));
    }

    #[test]
    fn the_two_null_pointer_rules_differ_exactly_as_the_c_does() {
        // lib/strequal.c:82-83 -- two NULLs are equal, unconditionally.
        assert!(strequal(None, None));
        // lib/strequal.c:93-94 -- two NULLs are equal only for a non-zero n.
        assert!(!strnequal(None, None, 0));
        assert!(strnequal(None, None, 1));
        // One NULL is never equal to a string, in either function.
        assert!(!strequal(Some(&cs("x")), None));
        assert!(!strequal(None, Some(&cs("x"))));
        assert!(!strnequal(Some(&cs("x")), None, 1));
        assert!(!strnequal(None, Some(&cs("x")), 1));
    }

    #[test]
    fn a_satisfied_byte_budget_short_circuits_before_the_tail() {
        // Only two bytes were asked for and those two match, so the third
        // byte's difference is never examined.
        assert!(strnequal(Some(&cs("abc")), Some(&cs("abx")), 2));
        assert!(!strnequal(Some(&cs("abc")), Some(&cs("abx")), 3));
        // A zero budget is satisfied immediately, even for unequal strings.
        assert!(strnequal(Some(&cs("abc")), Some(&cs("xyz")), 0));
    }

    #[test]
    fn a_surviving_budget_requires_both_strings_to_have_ended() {
        // The budget outlives the first string, so C compares its NUL against
        // the second string's next byte.
        assert!(!strnequal(Some(&cs("ab")), Some(&cs("abc")), 9));
        assert!(!strnequal(Some(&cs("abc")), Some(&cs("ab")), 9));
        assert!(strnequal(Some(&cs("ab")), Some(&cs("AB")), 9));
        assert!(strnequal(Some(&cs("")), Some(&cs("")), 9));
    }

    // =======================================================================
    // DIFFERENTIAL AGAINST THE REAL C LIBCURL.
    //
    // The two bit strings below were produced by a C program linked against
    // the frozen `libcurl.so.4.8.0` built from this repository's own `lib/`
    // tree, calling `curl_strequal` and `curl_strnequal` over the 22-entry
    // corpus in `CORPUS` -- every ordered pair for the first, and every
    // ordered pair against each of the seven byte budgets in `BUDGETS` for the
    // second. Each character is that call's return value. This is an ORACLE,
    // not an expectation someone wrote down: nothing here was hand-computed,
    // so a divergence means this module disagrees with the shipped C rather
    // than with somebody's reading of it.
    //
    // The corpus deliberately includes the four bytes adjacent to the folded
    // ranges (`@` 0x40, `[` 0x5B, `` ` `` 0x60, `{` 0x7B), a DEL (0x7F), a
    // byte above ASCII (0x80), and two UTF-8 strings differing only in a
    // continuation byte -- exactly the places a fold that was too eager would
    // show up.
    // =======================================================================

    const C_STREQUAL_BITS: &str = concat!(
        "1000000000000000000000011000000000000000000001100000000000000000000001110000",
        "0000000000000001110000000000000000000111000000000000000000000010000000000000",
        "0000000001000000000000000000000011000000000000000000001100000000000000000000",
        "0010000000000000000000000100000000000000000000001000000000000000000000010000",
        "0000000000000000001000000000000000000000010000000000000000000000100000000000",
        "0000000000010000000000000000000000100000000000000000000001000000000000000000",
        "0000100000000000000000000001",
    );

    const C_STRNEQUAL_BITS: &str = concat!(
        "1111111100000010000001000000100000010000001000000100000010000001000000100000",
        "0100000010000001000000100000010000001000000100000010000001000000100000010000",
        "0010000001111111111111111000001100000110000011000001100000110000011000001100",
        "0001000000100000010000001000000100000010000001000000100000010000001100000110",
        "0000100000011111111111111110000011000001100000110000011000001100000110000011",
        "0000010000001000000100000010000001000000100000010000001000000100000011000001",
        "1000001000000110000011000001111111111111111111111110000111000011000001100000",
        "1100000100000010000001000000100000010000001000000100000010000001000000111000",
        "0111000010000001100000110000011111111111111111111111100001110000110000011000",
        "0011000001000000100000010000001000000100000010000001000000100000010000001110",
        "0001110000100000011000001100000111111111111111111111111000011100001100000110",
        "0000110000010000001000000100000010000001000000100000010000001000000100000011",
        "1000011100001000000110000011000001110000111000011100001111111111000011000001",
        "1000001100000100000010000001000000100000010000001000000100000010000001000000",
        "1110000111000010000001100000110000011100001110000111000011100001111111110000",
        "0110000011000001000000100000010000001000000100000010000001000000100000010000",
        "0011100001110000100000011000001100000110000011000001100000110000011000001111",
        "1111111111111100010000001000000100000010000001000000100000010000001000000100",
        "0000110000011000001000000110000011000001100000110000011000001100000110000011",
        "1111111111111111000100000010000001000000100000010000001000000100000010000001",
        "0000001100000110000010000001100000110000011000001100000110000011000001100000",
        "1111000111100011111111000000100000010000001000000100000010000001000000100000",
        "0100000011000001100000100000010000001000000100000010000001000000100000010000",
        "0010000001000000100000011111111000000100000010000001000000100000010000001000",
        "0001000000100000010000001000000100000010000001000000100000010000001000000100",
        "0000100000010000001000000100000011111111000000100000010000001000000100000010",
        "0000010000001000000100000010000001000000100000010000001000000100000010000001",
        "0000001000000100000010000001000000100000011111111000000100000010000001000000",
        "1000000100000010000001000000100000010000001000000100000010000001000000100000",
        "0100000010000001000000100000010000001000000100000011111111000000100000010000",
        "0010000001000000100000010000001000000100000010000001000000100000010000001000",
        "0001000000100000010000001000000100000010000001000000100000011111111000000100",
        "0000100000010000001000000100000010000001000000100000010000001000000100000010",
        "0000010000001000000100000010000001000000100000010000001000000100000011111111",
        "1111001000000100000010000001000000100000010000001000000100000010000001000000",
        "1000000100000010000001000000100000010000001000000100000010000001000000111110",
        "0111111110000001000000100000010000001000000100000010000001000000100000010000",
        "0010000001000000100000010000001000000100000010000001000000100000010000001000",
        "0001000000111111111110001000000100000010000001000000100000010000001000000100",
        "0000100000010000001000000100000010000001000000100000010000001000000100000010",
        "0000010000001111000111111110000001000000100000011000001100000111000011100001",
        "1100001110000111000011000001100000110000010000001000000100000010000001000000",
        "1000000100000010000001000000111111111100001000000110000011000001110000111000",
        "0111000011100001110000110000011000001100000100000010000001000000100000010000",
        "00100000010000001000000100000011100001111111",
    );

    const CORPUS: [&str; 22] = [
        "",
        "a",
        "A",
        "ab",
        "AB",
        "Ab",
        "abc",
        "abx",
        "Accept",
        "ACCEPT",
        "accept-encoding",
        "z",
        "{",
        "@",
        "[",
        "`",
        "HTTP/1.1 200",
        "http/1.1 404",
        "tea\u{e9}",
        "tea\u{c9}",
        "ab\u{7f}",
        "ab\u{80}",
    ];

    const BUDGETS: [usize; 7] = [0, 1, 2, 3, 8, 12, 64];

    #[test]
    fn whole_string_comparison_matches_the_c_oracle() {
        let expected: Vec<bool> =
            C_STREQUAL_BITS.chars().map(|c| c == '1').collect();
        assert_eq!(
            expected.len(),
            CORPUS.len() * CORPUS.len(),
            "the oracle transcript must cover every ordered pair"
        );
        let mut k = 0usize;
        for left in CORPUS {
            for right in CORPUS {
                let got = strequal(Some(&cs(left)), Some(&cs(right)));
                assert_eq!(
                    got, expected[k],
                    "curl_strequal({left:?}, {right:?}): C said {} and this says {got}",
                    expected[k]
                );
                k += 1;
            }
        }
    }

    #[test]
    fn bounded_comparison_matches_the_c_oracle() {
        let expected: Vec<bool> =
            C_STRNEQUAL_BITS.chars().map(|c| c == '1').collect();
        assert_eq!(
            expected.len(),
            CORPUS.len() * CORPUS.len() * BUDGETS.len(),
            "the oracle transcript must cover every ordered pair at every budget"
        );
        let mut k = 0usize;
        for left in CORPUS {
            for right in CORPUS {
                for n in BUDGETS {
                    let got = strnequal(Some(&cs(left)), Some(&cs(right)), n);
                    assert_eq!(
                        got, expected[k],
                        "curl_strnequal({left:?}, {right:?}, {n}): C said {} and this says {got}",
                        expected[k]
                    );
                    k += 1;
                }
            }
        }
    }

    /// The C driver also printed its six null-pointer answers:
    /// `curl_strequal(NULL,NULL)=1`, `curl_strequal("x",NULL)=0`,
    /// `curl_strequal(NULL,"x")=0`, `curl_strnequal(NULL,NULL,0)=0`,
    /// `curl_strnequal(NULL,NULL,1)=1`, `curl_strnequal("x",NULL,1)=0`.
    #[test]
    fn the_null_pointer_answers_match_the_c_oracle() {
        assert!(strequal(None, None));
        assert!(!strequal(Some(&cs("x")), None));
        assert!(!strequal(None, Some(&cs("x"))));
        assert!(!strnequal(None, None, 0));
        assert!(strnequal(None, None, 1));
        assert!(!strnequal(Some(&cs("x")), None, 1));
    }

    /// The prefix comparison must behave like the whole-string one once the
    /// budget is large enough to cover both strings and their terminators.
    #[test]
    fn a_large_budget_reduces_to_whole_string_comparison() {
        let corpus = [
            "",
            "a",
            "A",
            "ab",
            "AB",
            "Ab",
            "abc",
            "Accept",
            "ACCEPT",
            "accept-encoding",
            "z",
            "{",
            "@",
            "[",
            "`",
        ];
        for left in corpus {
            for right in corpus {
                let whole = strequal(Some(&cs(left)), Some(&cs(right)));
                let bounded = strnequal(Some(&cs(left)), Some(&cs(right)), 64);
                assert_eq!(
                    whole, bounded,
                    "{left:?} vs {right:?}: whole={whole} bounded={bounded}"
                );
            }
        }
    }
}
