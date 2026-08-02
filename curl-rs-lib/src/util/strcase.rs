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

//! ASCII-only, locale-independent case folding and comparison.
//!
//! Supersedes all of `lib/strcase.c` (146 lines) and all of
//! `lib/strequal.c` (95 lines), with `lib/strcase.h` as the declaration
//! contract. The inventory is six functions plus one macro from the first
//! pair of files and two exported functions plus two file-static
//! comparators from the second:
//!
//! | C                  | Where                   | Here             |
//! |--------------------|-------------------------|------------------|
//! | `touppermap[256]`  | `lib/strcase.c:28-48`   | [`raw_toupper`]  |
//! | `tolowermap[256]`  | `lib/strcase.c:50-70`   | [`raw_tolower`]  |
//! | `Curl_raw_toupper` | `lib/strcase.c:72-77`   | [`raw_toupper`]  |
//! | `Curl_raw_tolower` | `lib/strcase.c:79-84`   | [`raw_tolower`]  |
//! | `Curl_strntoupper` | `lib/strcase.c:86-99`   | [`strntoupper`]  |
//! | `Curl_strntolower` | `lib/strcase.c:101-114` | [`strntolower`]  |
//! | `Curl_safecmp`     | `lib/strcase.c:116-124` | [`safecmp`]      |
//! | `Curl_timestrcmp`  | `lib/strcase.c:126-146` | [`timestrcmp`]   |
//! | `checkprefix()`    | `lib/strcase.h:31-33`   | [`checkprefix`]  |
//! | `casecompare`      | `lib/strequal.c:35-49`  | [`casecompare`]  |
//! | `ncasecompare`     | `lib/strequal.c:51-64`  | [`ncasecompare`] |
//! | `curl_strequal`    | `lib/strequal.c:76-84`  | [`strequal`]     |
//! | `curl_strnequal`   | `lib/strequal.c:87-95`  | [`strnequal`]    |
//!
//! # The folding is ASCII-only and locale-independent BY DESIGN
//!
//! C does not call `toupper()`, and `lib/strcase.c:72-73` states why in as
//! many words: *"Portable, consistent toupper. Do not use toupper()
//! because its behavior is altered by the current locale."*
//! `lib/strequal.c:28-33` adds the historical motivation, citing the
//! Turkish `strcasecmp` problem: in a Turkish locale the dotless i
//! (U+0131) and the dotted capital I (U+0130) fold into the ASCII letters
//! rather than being left alone, so a header comparison changes meaning
//! with the environment.
//!
//! Both 256-entry tables were read and diffed against the identity map
//! index by index rather than sampled:
//!
//! * `touppermap` (`lib/strcase.c:28-48`) is the identity at every index
//!   except 97..=122 (`a`..=`z`), which map to 65..=90 (`A`..=`Z`).
//! * `tolowermap` (`lib/strcase.c:50-70`) is the identity at every index
//!   except 65..=90, which map to 97..=122.
//! * **Every byte 0x80..=0xFF maps to ITSELF in both tables.** Nothing
//!   above ASCII is folded, and neither is anything between `Z` (0x5A) and
//!   `a` (0x61) -- the six bytes `[ \ ] ^ _` and the backquote.
//!
//! `u8::to_ascii_uppercase` maps exactly 97..=122 to 65..=90 and is the
//! identity elsewhere, by definition rather than by locale, so it is the
//! same function as `Curl_raw_toupper` and the tables are not transcribed.
//! That equivalence is proven by the tests at the foot of this file, not
//! assumed: both are compared against a locally reconstructed copy of the
//! C tables at all 256 indices.
//!
//! Nothing here may reach for a Unicode-aware fold: the case-conversion
//! methods that consult the Unicode tables, on either a scalar value or a
//! string slice, are prohibited in this file. They fold the Turkish dotted
//! capital I (U+0130), the long s with dot above (U+1E9B), the Cyrillic
//! alphabet and the German sharp s (U+00DF), producing matches curl does
//! not make, and they would do it silently on real-world headers and URLs.
//! Only the explicitly ASCII-suffixed spellings appear below, and a grep
//! for the Unicode-aware ones finds nothing but this paragraph. The
//! primitive is a BYTE, not a scalar value: curl compares byte strings,
//! and a multi-byte UTF-8 sequence must pass through untouched byte by
//! byte.
//!
//! # Public-ABI semantics, and why the shapes here are what they are
//!
//! `curl_strequal` and `curl_strnequal` are two of the 100 symbols
//! `lib/libcurl.def` exports. Their behaviour is frozen -- specification
//! 0.8.1 -- including two edge cases that read like defects:
//!
//! ```text
//! curl_strequal (s1, s2)     -> casecompare(s1, s2)        both non-NULL
//!                            -> s1 == NULL && s2 == NULL    otherwise
//! curl_strnequal(s1, s2, n)  -> ncasecompare(s1, s2, n)     both non-NULL
//!                            -> s1 == NULL && s2 == NULL && n != 0
//! ```
//!
//! The trailing `&& n` at `lib/strequal.c:94` is not dead weight:
//! `curl_strnequal(NULL, NULL, 0)` returns 0 while
//! `curl_strequal(NULL, NULL)` returns 1. Two null pointers are "equal"
//! only when a non-zero number of bytes was asked for. That asymmetry is
//! shipped ABI, it is reproduced exactly, and a test names it so that a
//! later reader does not mistake it for a copied bug.
//!
//! [`strequal`] and [`strnequal`] take `Option<&CStr>`, not `&[u8]` and
//! not a raw pointer, and that is the contract the crate root documents
//! next to its re-export of them. Three reasons, in order of weight:
//!
//! 1. The whole null-pointer rule stays inside this crate, where honouring
//!    it needs no raw-pointer handling at all. The adapter in
//!    `curl-rs-ffi/src/ffi/misc.rs` is left with nothing to decide: it
//!    converts a possibly-null C string pointer into an `Option<&CStr>`
//!    and calls this. Both asymmetric rules above belong to the contract,
//!    so they live with the contract.
//! 2. C's `ncasecompare` reads the NUL TERMINATOR itself, one byte past
//!    the last content byte. A `CStr` cannot contain an interior zero, so
//!    synthesising that terminator at index `len()` is exact. An arbitrary
//!    `&[u8]` carries no such guarantee: an interior zero would make this
//!    module and the C disagree, silently.
//! 3. Those two are the shapes the adapters already call.
//!
//! The byte-native surface is still here, and it is where the rest of the
//! engine talks to this module: [`casecompare`], [`ncasecompare`] and
//! [`checkprefix`] all take `&[u8]`. They stay `pub(crate)`, because the
//! crate root re-exports two names and not the module -- no other crate
//! has business calling an internal comparator.
//!
//! # Visibility
//!
//! [`strequal`] and [`strnequal`] are `pub` because the crate root
//! re-exports them for `curl-rs-ffi`; a `pub` item inside this
//! `pub(crate)` module is the standard private-module / public-re-export
//! idiom. Everything else is `pub(crate)`, including the two folding
//! primitives: specification 0.4.2 turns C's `extern Curl_xyz(...)` into
//! `pub(crate) fn xyz(...)`, and `lib/libcurl.def` was searched -- none of
//! `Curl_raw_toupper`, `Curl_raw_tolower`, `Curl_strntoupper`,
//! `Curl_strntolower`, `Curl_safecmp` or `Curl_timestrcmp` appears among
//! its 100 names. Widening any of them would misrepresent the ABI surface
//! as larger than it is, and specification 0.8.7 forbids re-exporting
//! internals even to make `tests/unit` and `tests/libtest` link.

use std::ffi::CStr;

// ---------------------------------------------------------------------------
// The fold. `lib/strcase.c:28-84`.
// ---------------------------------------------------------------------------

/// The byte a lower-case ASCII letter folds to, and every other byte
/// unchanged.
///
/// Supersedes `Curl_raw_toupper` (`lib/strcase.c:72-77`), whose body is a
/// single lookup into `touppermap` (`:28-48`). The table is the identity
/// everywhere except `a`..=`z`, so `u8::to_ascii_uppercase` computes it --
/// a measured equivalence, checked over all 256 indices by
/// `the_upward_fold_reproduces_the_c_table` at the foot of this file.
///
/// Locale-independent by construction: no environment can change which 26
/// pairs collapse. That is the entire reason the C carried a table instead
/// of calling `toupper()`.
///
/// Takes and returns a `u8` where the C takes and returns `char`. The C
/// casts to `unsigned char` before indexing (`lib/strcase.c:76`), so the
/// byte is what the operation was always about; the signedness of C's
/// `char` never reached the table.
#[must_use]
pub(crate) const fn raw_toupper(byte: u8) -> u8 {
    byte.to_ascii_uppercase()
}

/// The byte an upper-case ASCII letter folds to, and every other byte
/// unchanged.
///
/// Supersedes `Curl_raw_tolower` (`lib/strcase.c:79-84`) and its
/// `tolowermap` (`:50-70`), the mirror of [`raw_toupper`] in every respect
/// including the untouched 0x80..=0xFF range.
///
/// Both directions exist because both are used: comparison folds UP, as
/// `lib/strequal.c:38` does, while normalisation of a scheme or a host
/// folds DOWN.
#[must_use]
pub(crate) const fn raw_tolower(byte: u8) -> u8 {
    byte.to_ascii_lowercase()
}

/// The byte at `index`, or the NUL the C would have read past the end.
///
/// The C comparators walk a NUL-terminated string and read the terminator
/// itself: `lib/strequal.c:48` tests `*first` after the loop has already
/// stopped on it, and `:63` compares that terminator against whatever the
/// second string has at the same offset. The slices here come from
/// [`CStr::to_bytes`] and so exclude the terminator, which is why every
/// read goes through this helper: index `len()` yields the zero the C
/// would have found there.
///
/// For the two comparators the synthetic terminator is the ONLY zero in
/// play, because their slices come from a `CStr` and a `CStr` cannot
/// contain an interior zero. [`timestrcmp`] uses the same helper over
/// arbitrary slices, where an interior zero can occur -- and there stopping
/// at it is exactly what the C does, which is why that function documents
/// the behaviour rather than guarding against it.
#[must_use]
const fn byte_at(bytes: &[u8], index: usize) -> u8 {
    // `slice::get` is not `const` under this crate's minimum supported Rust
    // version, so the bound is tested directly rather than through
    // `get(index).copied().unwrap_or(0)`.
    if index < bytes.len() {
        bytes[index]
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// The comparators. `lib/strequal.c:35-95`.
// ---------------------------------------------------------------------------

/// Case-insensitive equality of two whole byte strings.
///
/// Supersedes `casecompare` (`lib/strequal.c:35-49`). The C walks the
/// first string to its NUL and, on reaching it, returns
/// `!*first == !*second` -- a comparison of ZERO-NESS, not of bytes, and
/// its own comment says so: *"Note that the characters may not be exactly
/// the same even if they match, we only want to compare zero-ness."* With
/// `*first` known to be zero at that point, the test means exactly "the
/// second string also ended here".
///
/// The correspondence to the Rust form is worth spelling out, because the
/// C's shape hides it. Three cases, and they are exhaustive:
///
/// * Equal lengths -- the loop compares every byte and the tail test
///   compares two terminators, which are both zero.
/// * `first` longer -- at offset `second.len()` the C reads `second`'s NUL
///   against a non-zero byte of `first`, and no fold maps a letter to
///   zero, so the loop returns 0.
/// * `second` longer -- the loop ends having matched every byte of
///   `first`, and the tail test compares `first`'s zero terminator against
///   a non-zero byte of `second`, giving `1 == 0`.
///
/// So the whole function is case-insensitive equality of the two byte
/// sequences INCLUDING their lengths. The fold is [`raw_toupper`], upward,
/// exactly as `lib/strequal.c:38` folds.
#[must_use]
pub(crate) fn casecompare(first: &[u8], second: &[u8]) -> bool {
    // The length test is the tail comparison of `lib/strequal.c:48`,
    // hoisted: the three cases enumerated above show that a length
    // difference can only ever produce "not equal".
    if first.len() != second.len() {
        return false;
    }

    first
        .iter()
        .zip(second.iter())
        .all(|(left, right)| raw_toupper(*left) == raw_toupper(*right))
}

/// Case-insensitive equality of at most `max` bytes of two byte strings.
///
/// Supersedes `ncasecompare` (`lib/strequal.c:51-64`), which has no
/// standard-library counterpart and is therefore reproduced as an explicit
/// walk:
///
/// ```text
/// while(*first && max) { if(fold(*first) != fold(*second)) return 0;
///                        max--; first++; second++; }
/// if(max == 0) return 1;                 /* they are equal this far */
/// return fold(*first) == fold(*second);
/// ```
///
/// The loop has TWO exits and they do different things. Reproducing only
/// one of them is the easy way to get this function subtly wrong, so both
/// are written out separately below:
///
/// * The BUDGET ran out. `max == 0` returns true immediately, WITHOUT
///   looking at either string again. So `ncasecompare("abcd", "abZZ", 2)`
///   is true: two bytes were asked for and those two matched, and the
///   later divergence is never examined.
/// * The FIRST STRING ended with budget to spare. One further folded
///   comparison is made, of `first`'s terminator against whatever `second`
///   has at the same offset -- so `second` must have ended there too, and
///   `ncasecompare("ab", "abc", 9)` is false.
///
/// Note which string governs the loop: only `first`'s terminator stops it.
/// That is what makes the argument order of [`checkprefix`] matter.
#[must_use]
pub(crate) fn ncasecompare(first: &[u8], second: &[u8], max: usize) -> bool {
    let mut index = 0usize;
    let mut budget = max;

    while budget != 0 {
        let left = byte_at(first, index);
        if left == 0 {
            break;
        }
        if raw_toupper(left) != raw_toupper(byte_at(second, index)) {
            return false;
        }
        budget -= 1;
        index += 1;
    }

    if budget == 0 {
        // `lib/strequal.c:60-61` -- "they are equal this far". The C returns
        // here without a further read, and so does this.
        return true;
    }

    // `lib/strequal.c:63` -- the first string has ended, so compare its
    // terminator against the second string's byte at the same offset.
    raw_toupper(byte_at(second, index)) == 0
}

/// Case-insensitive comparison of two whole strings -- backs
/// `curl_strequal`.
///
/// Reproduces `lib/strequal.c:76-84`. `None` models a NULL pointer: two
/// NULLs compare equal, and one NULL against a string does not.
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
// pub: backs curl_strequal / curl_strnequal in curl-rs-ffi/src/ffi/misc.rs.
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

/// Case-insensitive comparison of at most `n` bytes -- backs
/// `curl_strnequal`.
///
/// Reproduces `lib/strequal.c:87-95`, including the null-pointer rule that
/// differs from [`strequal`]: two NULLs are equal only when `n` is
/// non-zero. That is the literal `&& n` of `lib/strequal.c:94`, and it is
/// frozen ABI rather than an oversight to tidy up.
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
// pub: backs curl_strequal / curl_strnequal in curl-rs-ffi/src/ffi/misc.rs.
#[must_use]
pub fn strnequal(s1: Option<&CStr>, s2: Option<&CStr>, n: usize) -> bool {
    match (s1, s2) {
        (Some(a), Some(b)) => ncasecompare(a.to_bytes(), b.to_bytes(), n),
        // "treat them as equal if max is non-zero" (lib/strequal.c:93-94).
        (None, None) => n != 0,
        _ => false,
    }
}

/// True when `subject` begins with `prefix`, compared case-insensitively.
///
/// Supersedes the `checkprefix()` macro of `lib/strcase.h:31-33`, the
/// pervasive prefix test of the C tree -- header matching, scheme
/// matching, option parsing.
///
/// **The macro's argument order is the reverse of what its name suggests,
/// and this function keeps the macro's spelling rather than the
/// expansion's.** `checkprefix(a, b)` expands to
/// `curl_strnequal(b, STRCONST(a))`, and `STRCONST(x)` is
/// `x, sizeof(x) - 1` (`lib/curl_setup.h:1285`), so the macro means
/// `curl_strnequal(subject, literal, strlen(literal))`: the LITERAL is the
/// first macro argument and the SUBJECT is the second, while the subject
/// is the FIRST argument of the call it expands to. Call it as
/// `checkprefix("Content-", header)`. Swapping the two silently inverts
/// every prefix test, because [`ncasecompare`]'s loop is governed by its
/// first argument's terminator.
///
/// Three consequences of that expansion, each verified against the C:
///
/// * An empty prefix matches anything, because `max` is then zero and
///   `lib/strequal.c:60-61` returns "equal this far" before reading a
///   byte.
/// * A subject shorter than the prefix never matches: the subject's
///   terminator stops the loop with budget left, and the tail comparison
///   finds a non-zero byte still to come in the prefix.
/// * Only `prefix.len()` bytes are examined, so trailing content in the
///   subject is irrelevant -- which is the point of a prefix test.
///
/// `prefix` is a `&str` because every C call site passes a string literal.
/// A prefix containing an interior NUL would break the analogy with the
/// macro, whose `sizeof(x) - 1` counts the literal's declared bytes; no
/// call site does that, and the byte-level form [`ncasecompare`] is
/// available for anything that needs it.
#[must_use]
#[allow(dead_code)] // No consumer yet; scheme and header matching will call it.
pub(crate) fn checkprefix(prefix: &str, subject: &[u8]) -> bool {
    ncasecompare(subject, prefix.as_bytes(), prefix.len())
}

// ---------------------------------------------------------------------------
// Folding copies. `lib/strcase.c:86-114`.
// ---------------------------------------------------------------------------

/// Copies an upper-case fold of `src` into `dest`, returning the number of
/// bytes written.
///
/// Supersedes `Curl_strntoupper` (`lib/strcase.c:86-99`):
///
/// ```text
/// void Curl_strntoupper(char *dest, const char *src, size_t n)
/// {
///   if(n < 1) return;
///   do { *dest++ = Curl_raw_toupper(*src); } while(*src++ && --n);
/// }
/// ```
///
/// # The C's caveat disappears, and no observable behaviour changes with it
///
/// The C comment (`lib/strcase.c:86-90`) warns: *"The strings may overlap.
/// No more than n characters of the string are copied (including any NUL)
/// and the destination string will NOT be null-terminated if that limit is
/// reached."* Two hazards live in that sentence, and both are structural
/// rather than accidental:
///
/// * The caller must remember `n` and must remember that the result may be
///   unterminated, because a bare `char *` carries no length. Forget
///   either and the next read runs off the end of the buffer.
/// * The `do`/`while` writes before it tests, so `n` is a count the caller
///   has to have got right; there is nothing to check it against.
///
/// A Rust slice carries its own length, so `n` is not a separate argument:
/// it IS `dest.len()`, and the caller passes `&mut dest[..n]` to say what
/// the C said. The write is bounded by the shorter of the two slices and
/// the count is returned, so a truncating call is detectable rather than
/// silent -- information the C simply did not offer.
///
/// # Exactly where this differs from the C, measured rather than asserted
///
/// The CONTENT bytes are byte-for-byte the C's, at every length and every
/// budget: `the_folding_copies_match_the_c_oracle` below checks that
/// against a transcript taken from the C itself.
///
/// The one difference is the terminator, and it is worth being precise
/// instead of claiming more than is true. The C's loop tests `*src++`
/// AFTER writing, so when the budget outlives the source it also writes
/// the source's NUL -- `Curl_strntoupper(dest, "ab", 5)` leaves
/// `41 42 00` and stops, which was confirmed by running it. This function
/// writes `41 42` and returns 2, because a `&[u8]` has no terminator to
/// copy and appending a zero would be inventing a byte the source never
/// had. Callers that need a C string terminate it themselves, at the
/// offset this function returns; callers that hold a slice never wanted
/// one. So the caveat the C comment had to state -- that the destination
/// may be left unterminated -- stops being a hazard rather than being
/// solved: there is nothing to forget.
///
/// The C additionally permits `dest` and `src` to overlap, which Rust's
/// borrow rules exclude at compile time. In-place folding is expressed by
/// `<[u8]>::make_ascii_uppercase`, which is the same ASCII-only operation
/// and needs no wrapper here.
///
/// # Usage
///
/// ```text
/// let mut buf = [0u8; 4];
/// assert_eq!(strntoupper(&mut buf, b"htTp"), 4);
/// assert_eq!(&buf, b"HTTP");
/// ```
#[allow(dead_code)] // No consumer yet; scheme normalisation will call it.
pub(crate) fn strntoupper(dest: &mut [u8], src: &[u8]) -> usize {
    let count = dest.len().min(src.len());
    for index in 0..count {
        dest[index] = raw_toupper(src[index]);
    }
    count
}

/// Copies a lower-case fold of `src` into `dest`, returning the number of
/// bytes written.
///
/// Supersedes `Curl_strntolower` (`lib/strcase.c:101-114`), the mirror of
/// `Curl_strntoupper` in every respect. See [`strntoupper`] for why the
/// C's `n` parameter and its not-null-terminated caveat both disappear
/// here without any change in the bytes produced.
///
/// In-place folding is `<[u8]>::make_ascii_lowercase`.
#[allow(dead_code)] // No consumer yet; host normalisation will call it.
pub(crate) fn strntolower(dest: &mut [u8], src: &[u8]) -> usize {
    let count = dest.len().min(src.len());
    for index in 0..count {
        dest[index] = raw_tolower(src[index]);
    }
    count
}

// ---------------------------------------------------------------------------
// Null-safe comparisons. `lib/strcase.c:116-146`.
// ---------------------------------------------------------------------------

/// Null-safe, **case-SENSITIVE** equality of two optional byte strings.
///
/// Supersedes `Curl_safecmp` (`lib/strcase.c:116-124`):
///
/// ```text
/// bool Curl_safecmp(const char *a, const char *b)
/// {
///   if(a && b) return !strcmp(a, b);
///   return !a && !b;
/// }
/// ```
///
/// It lives in `strcase.c` and it is NOT a case-insensitive comparison.
/// The delegate is `strcmp`, not `strcasecmp`, so `safecmp(Some(b"A"),
/// Some(b"a"))` is false. Assuming otherwise from the file it came from is
/// the mistake this paragraph exists to prevent.
///
/// The rule for absent operands is the intuitive one: both absent compare
/// equal, one absent does not. Note that [`timestrcmp`] below answers the
/// same question with the OPPOSITE polarity -- `true` here means
/// "identical", whereas `0` there means "identical".
#[must_use]
#[allow(dead_code)] // No consumer yet; connection reuse will call it.
pub(crate) fn safecmp(a: Option<&[u8]>, b: Option<&[u8]>) -> bool {
    match (a, b) {
        (Some(left), Some(right)) => left == right,
        // `return !a && !b` -- two absent strings are equal.
        (None, None) => true,
        _ => false,
    }
}

/// Compares two optional byte strings without branching on their contents;
/// returns `0` when they are identical.
///
/// Supersedes `Curl_timestrcmp` (`lib/strcase.c:126-146`), whose comment
/// states the contract: *"returns 0 if the two strings are identical. The
/// time this function spends is a function of the shortest string, not of
/// the contents."*
///
/// ```text
/// int match = 0, i = 0;
/// if(a && b) {
///   while(1) { match |= a[i] ^ b[i]; if(!a[i] || !b[i]) break; i++; }
/// }
/// else return a || b;
/// return match;
/// ```
///
/// # This function is SECURITY-RELEVANT
///
/// Every caller in the C tree compares credentials with it -- `user` and
/// `passwd` when deciding whether a pooled connection may be reused
/// (`lib/url.c:612-613`, `:1043-1046`, `:1126-1127`, `:1192-1193`), the
/// Digest user and password (`lib/vauth/digest_sspi.c:426-427`), the FTP
/// account (`lib/ftp.c:4311`) and the `.netrc` login
/// (`lib/netrc.c:272`) -- and every one of them uses the result only for
/// its zero-ness.
///
/// The defence is that the control flow must not depend on the DATA. So
/// the differences of all byte pairs are accumulated with `|=` and the
/// loop breaks only on a terminator, never on a mismatch. An early exit,
/// however tempting, leaks the length of the matching prefix through the
/// time taken and would defeat the entire purpose of the function.
/// Therefore, and this is a prohibition rather than a preference: do NOT
/// rewrite the body as `a == b`, as `starts_with`, as `iter().eq(..)`, or
/// as anything else that short-circuits, and do not let a later
/// simplification reintroduce one.
///
/// # The honest limitation
///
/// Rust offers no timing guarantee, and neither did the C. The optimiser
/// is free to vectorise, to unroll, or in principle to introduce a branch;
/// `#[inline(never)]` keeps the body from being folded into a caller where
/// that is likelier, but it is a discouragement, not a proof. What is
/// claimed here is exactly what the C claimed: the SOURCE contains no
/// data-dependent branch. Anything stronger would need a primitive the
/// language does not provide, so nothing stronger is claimed.
///
/// # The polarity, which is the inverse of [`safecmp`]
///
/// `0` means identical. The absent-operand branch is C's `return a || b`,
/// which yields `0` when BOTH are absent -- absent equals absent -- and
/// `1` when exactly one is. Getting this backwards would turn "the
/// credentials differ" into "the connection may be reused".
///
/// # Return value
///
/// Zero when the strings are identical, non-zero otherwise. Only the
/// zero-ness is contractual: the C accumulates into a signed `int` whose
/// exact value depends on the platform's `char` signedness, so no caller
/// may depend on the magnitude, and none does.
///
/// One consequence of reproducing the C exactly is worth stating, because
/// it is the one place this function and [`safecmp`] genuinely differ
/// rather than merely inverting: the walk stops at the first zero byte in
/// either operand, because that is the C string terminator. So a slice
/// carrying an INTERIOR zero is compared only up to it, whereas
/// [`safecmp`] compares the whole slice. Every call site holds credential
/// text, which never contains a zero, so the distinction does not arise in
/// practice -- but it is a difference, not an equivalence, and a caller
/// handling arbitrary bytes should reach for a whole-slice comparison
/// instead.
#[must_use]
#[inline(never)]
#[allow(dead_code)] // No consumer yet; connection reuse will call it.
pub(crate) fn timestrcmp(a: Option<&[u8]>, b: Option<&[u8]>) -> i32 {
    let (left, right) = match (a, b) {
        (Some(left), Some(right)) => (left, right),
        // `return a || b` -- zero for two absent strings, one when exactly
        // one is present. Not a comparison, so no timing claim applies.
        (None, None) => return 0,
        _ => return 1,
    };

    let mut difference = 0u8;
    let mut index = 0usize;
    loop {
        let one = byte_at(left, index);
        let two = byte_at(right, index);
        // Accumulate unconditionally: this is the line that must never
        // become a branch on the comparison.
        difference |= one ^ two;
        if one == 0 || two == 0 {
            break;
        }
        index += 1;
    }

    // `difference` is zero exactly when every compared pair was equal,
    // which is the C's zero-ness contract. Widening a `u8` keeps that
    // property while avoiding the C's platform-dependent sign extension.
    i32::from(difference)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap_or_else(|_| {
            unreachable!("every test string is free of interior NUL bytes")
        })
    }

    // THE TWO C FOLDING TABLES, TRANSCRIBED.
    //
    // `lib/strcase.c:28-48` and `:50-70` verbatim, value for value in
    // declaration order. They are here rather than in the implementation
    // because their only job is to make the equivalence claimed in the
    // module documentation EXECUTABLE: `raw_toupper` is
    // `u8::to_ascii_uppercase`, and the two tests below prove that agrees
    // with the C at all 256 indices. Deriving the expectation from the same
    // rule the implementation uses would prove nothing, so these digits are
    // the C's digits.
    //
    // `#[rustfmt::skip]` because they are DATA. The only edit made to the C
    // text is the row width -- twelve values per line instead of fifteen, so
    // that every line fits the 80-column limit -- and no value is reordered,
    // added or dropped.

    #[rustfmt::skip]
    const TOUPPERMAP: [u8; 256] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
        36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
        72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
        84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
        96, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75,
        76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87,
        88, 89, 90, 123, 124, 125, 126, 127, 128, 129, 130, 131,
        132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
        144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
        156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167,
        168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
        180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
        192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203,
        204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
        216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
        228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
        240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
        252, 253, 254, 255,
    ];

    #[rustfmt::skip]
    const TOLOWERMAP: [u8; 256] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
        36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, 62, 63, 64, 97, 98, 99, 100, 101, 102, 103,
        104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
        116, 117, 118, 119, 120, 121, 122, 91, 92, 93, 94, 95,
        96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
        108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
        120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
        132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
        144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
        156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167,
        168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
        180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
        192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203,
        204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
        216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
        228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
        240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
        252, 253, 254, 255,
    ];

    /// [`raw_toupper`] agrees with `touppermap` at every one of the 256
    /// indices, which is what licenses the substitution of
    /// `u8::to_ascii_uppercase` for the C's table lookup.
    #[test]
    fn the_upward_fold_reproduces_the_c_table() {
        for byte in 0u8..=255 {
            assert_eq!(
                raw_toupper(byte),
                TOUPPERMAP[byte as usize],
                "raw_toupper disagrees with touppermap at index {byte}"
            );
        }
    }

    /// [`raw_tolower`] agrees with `tolowermap` at every one of the 256
    /// indices.
    #[test]
    fn the_downward_fold_reproduces_the_c_table() {
        for byte in 0u8..=255 {
            assert_eq!(
                raw_tolower(byte),
                TOLOWERMAP[byte as usize],
                "raw_tolower disagrees with tolowermap at index {byte}"
            );
        }
    }

    /// Nothing above ASCII folds, in either direction. Asserted over the
    /// WHOLE 0x80..=0xFF range rather than on a sample, because a
    /// Unicode-aware fold would differ on exactly some of those bytes and a
    /// sample could miss them.
    #[test]
    fn neither_fold_touches_a_byte_above_ascii() {
        for byte in 0x80u8..=0xFF {
            assert_eq!(
                raw_toupper(byte),
                byte,
                "byte {byte:#04x} must not fold upward"
            );
            assert_eq!(
                raw_tolower(byte),
                byte,
                "byte {byte:#04x} must not fold downward"
            );
        }
    }

    /// Only the 52 ASCII letters move; every other ASCII byte is left
    /// exactly alone.
    ///
    /// The interesting region is 0x5B..=0x60 -- `[`, `\`, `]`, `^`, `_` and
    /// the backquote -- which sits BETWEEN `Z` (0x5A) and `a` (0x61). An
    /// implementation that folded by adding or subtracting 32 over a
    /// too-wide range would corrupt precisely those six bytes, and they
    /// appear in real header and URL text.
    #[test]
    fn neither_fold_touches_a_non_letter() {
        for byte in 0u8..=0x7F {
            if byte.is_ascii_lowercase() {
                assert_eq!(raw_toupper(byte), byte - 32);
                assert_eq!(raw_tolower(byte), byte);
            } else if byte.is_ascii_uppercase() {
                assert_eq!(raw_toupper(byte), byte);
                assert_eq!(raw_tolower(byte), byte + 32);
            } else {
                assert_eq!(
                    raw_toupper(byte),
                    byte,
                    "non-letter {byte:#04x} must not fold upward"
                );
                assert_eq!(
                    raw_tolower(byte),
                    byte,
                    "non-letter {byte:#04x} must not fold downward"
                );
            }
        }

        // Named explicitly so a regression in the gap between `Z` and `a`
        // reads as such in the failure output. The six bytes of that gap are
        // 0x5B..=0x60; the digits and the opening brace bracket the letters
        // on either side.
        for byte in *b"09[\\]^_`{" {
            assert_eq!(
                raw_toupper(byte),
                byte,
                "gap byte {byte:#04x} must not fold upward"
            );
            assert_eq!(
                raw_tolower(byte),
                byte,
                "gap byte {byte:#04x} must not fold downward"
            );
        }
        // Control bytes and DEL.
        for byte in [0x00u8, 0x09, 0x0A, 0x0D, 0x1B, 0x7F] {
            assert_eq!(raw_toupper(byte), byte);
            assert_eq!(raw_tolower(byte), byte);
        }
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

    #[test]
    fn whole_string_comparison_ignores_ascii_case_only() {
        assert!(strequal(Some(&cs("CURL")), Some(&cs("curl"))));
        assert!(strequal(Some(&cs("Accept")), Some(&cs("ACCEPT"))));
        assert!(strequal(Some(&cs("")), Some(&cs(""))));
        assert!(!strequal(Some(&cs("curl")), Some(&cs("curlx"))));
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
        // The zero case answering "not equal" while the unbounded comparison
        // answers "equal" is the shipped `&& n` asymmetry: intentional
        // fidelity to the frozen ABI, not a copied bug.
        assert!(!strnequal(None, None, 0));
        assert!(strnequal(None, None, 1));
        // One NULL is never equal to a string, in either function.
        assert!(!strequal(Some(&cs("x")), None));
        assert!(!strequal(None, Some(&cs("x"))));
        assert!(!strnequal(Some(&cs("x")), None, 1));
        assert!(!strnequal(None, Some(&cs("x")), 1));
        assert!(!strnequal(Some(&cs("x")), None, 0));
    }

    #[test]
    fn a_satisfied_byte_budget_short_circuits_before_the_tail() {
        // Only two bytes were asked for and those two match, so the third
        // byte's difference is never examined.
        assert!(strnequal(Some(&cs("abc")), Some(&cs("abx")), 2));
        assert!(!strnequal(Some(&cs("abc")), Some(&cs("abx")), 3));
        // The agent-prompt's own example of the same exit.
        assert!(ncasecompare(b"abcd", b"abZZ", 2));
        assert!(!ncasecompare(b"abcd", b"abZZ", 3));
        // A zero budget is satisfied immediately, even for unequal strings.
        assert!(strnequal(Some(&cs("abc")), Some(&cs("xyz")), 0));
        assert!(ncasecompare(b"abc", b"xyz", 0));
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

    /// The scheme-lookup path of `protocols/mod.rs`.
    ///
    /// The registry derived from `lib/url.c` stores four names in UPPERCASE
    /// -- `WS`, `WSS`, `SFTP`, `SCP` -- and matches them against lowercase
    /// user input through this comparator. If the fold regressed, those four
    /// schemes would stop resolving while every lowercase-stored scheme kept
    /// working, which is exactly the kind of partial failure a test has to
    /// catch rather than a reader.
    #[test]
    fn the_uppercase_registry_names_match_lowercase_input() {
        assert!(ncasecompare(b"WS", b"ws", 2));
        assert!(ncasecompare(b"WSS", b"wss", 3));
        assert!(ncasecompare(b"SFTP", b"sftp", 4));
        assert!(ncasecompare(b"SCP", b"scp", 3));

        // Through the exported entry point as well, since that is what the C
        // registry actually calls.
        assert!(strnequal(Some(&cs("WS")), Some(&cs("ws")), 2));
        assert!(strnequal(Some(&cs("WSS")), Some(&cs("wss")), 3));
        assert!(strnequal(Some(&cs("SFTP")), Some(&cs("sftp")), 4));
        assert!(strnequal(Some(&cs("SCP")), Some(&cs("scp")), 3));

        // And the whole-string form, mixed case in both directions.
        assert!(strequal(Some(&cs("SFTP")), Some(&cs("sFtP"))));
        // `WS` must not be confused with `WSS`.
        assert!(!strequal(Some(&cs("WS")), Some(&cs("wss"))));
    }

    /// Non-ASCII does not fold, so a Unicode-aware implementation would fail
    /// this test -- which is the point of it.
    #[test]
    fn nothing_outside_ascii_folds() {
        // Turkish dotless i (U+0131) and dotted capital I (U+0130) against
        // their ASCII counterparts. A locale-sensitive `strcasecmp` is what
        // `lib/strequal.c:28-33` cites as the reason this module exists.
        assert!(!strequal(Some(&cs("\u{131}")), Some(&cs("I"))));
        assert!(!strequal(Some(&cs("\u{131}")), Some(&cs("i"))));
        assert!(!strequal(Some(&cs("\u{130}")), Some(&cs("i"))));
        assert!(!strequal(Some(&cs("\u{130}")), Some(&cs("I"))));
        // And against each other: they differ in one continuation byte.
        assert!(!strequal(Some(&cs("\u{131}")), Some(&cs("\u{130}"))));
        assert!(!casecompare("\u{131}".as_bytes(), "\u{130}".as_bytes()));

        // The German sharp s must not equal "SS". A Unicode-aware fold maps
        // it to two bytes of `S`, so this is the assertion that fails the
        // moment such a fold is substituted for the ASCII one.
        assert!(!strequal(Some(&cs("\u{df}")), Some(&cs("SS"))));
        assert!(!casecompare("\u{df}".as_bytes(), b"SS"));
        assert!(!strequal(Some(&cs("stra\u{df}e")), Some(&cs("STRASSE"))));

        // Cyrillic A (U+0410) against Cyrillic a (U+0430): a Unicode fold
        // would equate them, a byte fold must not.
        assert!(!strequal(Some(&cs("\u{410}")), Some(&cs("\u{430}"))));

        // Long s with dot above (U+1E9B) folds under Unicode but not here.
        assert!(!strequal(Some(&cs("\u{1e9b}")), Some(&cs("\u{1e60}"))));

        // A multi-byte sequence passes through byte for byte, so identical
        // non-ASCII text still compares equal, and the ASCII letters around
        // it still fold.
        assert!(strequal(Some(&cs("tea\u{e9}")), Some(&cs("tea\u{e9}"))));
        assert!(strequal(Some(&cs("TEA\u{e9}")), Some(&cs("tea\u{e9}"))));
    }

    /// The byte-native comparators and the `CStr` entry points must agree
    /// whenever the strings carry no interior NUL -- which a `CStr` never
    /// does. This is what lets the rest of the engine call [`casecompare`]
    /// and [`ncasecompare`] directly and still get ABI-identical answers.
    #[test]
    fn the_byte_native_comparators_agree_with_the_c_string_forms() {
        let corpus =
            ["", "a", "A", "ab", "AB", "Ab", "abc", "z", "@", "[", "`"];
        for left in corpus {
            for right in corpus {
                assert_eq!(
                    casecompare(left.as_bytes(), right.as_bytes()),
                    strequal(Some(&cs(left)), Some(&cs(right))),
                    "casecompare disagrees for {left:?} vs {right:?}"
                );
                for n in [0usize, 1, 2, 3, 8, 64] {
                    assert_eq!(
                        ncasecompare(left.as_bytes(), right.as_bytes(), n),
                        strnequal(Some(&cs(left)), Some(&cs(right)), n),
                        "ncasecompare disagrees for {left:?} vs {right:?} at {n}"
                    );
                }
            }
        }
    }

    // The two bit strings below are a differential oracle, not hand-written
    // expectations: a C program linked against the frozen `libcurl.so.4.8.0`
    // built from this repository's own `lib/` tree called `curl_strequal` and
    // `curl_strnequal` over the 22-entry `CORPUS`, and each character is one
    // call's return value. The first covers every ordered pair; the second
    // covers every ordered pair against each of the seven `BUDGETS`. A
    // divergence therefore means this module disagrees with the shipped C.
    //
    // The corpus includes the four bytes adjacent to the folded ranges (`@`
    // 0x40, `[` 0x5B, `` ` `` 0x60, `{` 0x7B), a DEL (0x7F), a byte above
    // ASCII (0x80), and two UTF-8 strings differing only in a continuation
    // byte -- the places an over-eager fold would show up.

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

    /// The macro's argument order, which is the reverse of what its name
    /// suggests. `checkprefix(literal, subject)` expands to
    /// `curl_strnequal(subject, literal, strlen(literal))`, so the literal
    /// comes FIRST. Swapping the two silently inverts every prefix test in
    /// the tree, which is why both directions are asserted here.
    #[test]
    fn checkprefix_takes_the_literal_first_and_the_subject_second() {
        assert!(checkprefix("Content-", b"content-type: x"));
        assert!(!checkprefix("content-type", b"Content-"));

        // Real header matching, in both casings.
        assert!(checkprefix("location:", b"Location: /elsewhere"));
        assert!(checkprefix("LOCATION:", b"location: /elsewhere"));
        assert!(!checkprefix("location:", b"Content-Length: 3"));

        // Scheme matching.
        assert!(checkprefix("https://", b"HTTPS://example.com/"));
        assert!(!checkprefix("https://", b"http://example.com/"));
    }

    #[test]
    fn checkprefix_handles_the_three_boundary_cases() {
        // An empty prefix matches anything, because `max` is zero and
        // `lib/strequal.c:60-61` returns "equal this far" before any read.
        assert!(checkprefix("", b""));
        assert!(checkprefix("", b"anything at all"));

        // A subject shorter than the prefix never matches.
        assert!(!checkprefix("Content-Type", b"Content-"));
        assert!(!checkprefix("abc", b""));

        // Trailing content in the subject is irrelevant: only the prefix's
        // own length is examined.
        assert!(checkprefix("ab", b"abcdefgh"));
        assert!(checkprefix("abcdefgh", b"ABCDEFGH"));

        // Equal lengths reduce to a whole-string comparison.
        assert!(checkprefix("abc", b"ABC"));
        assert!(!checkprefix("abc", b"abx"));
    }

    #[test]
    fn the_folding_copies_fold_and_report_their_length() {
        let mut buffer = [0u8; 4];
        assert_eq!(strntoupper(&mut buffer, b"htTp"), 4);
        assert_eq!(&buffer, b"HTTP");

        let mut buffer = [0u8; 4];
        assert_eq!(strntolower(&mut buffer, b"HtTP"), 4);
        assert_eq!(&buffer, b"http");

        // Non-letters and non-ASCII bytes pass through untouched, exactly as
        // the tables do.
        let source = [b'a', b'[', b'9', 0xC3, 0xA9, b'Z'];
        let mut buffer = [0u8; 6];
        assert_eq!(strntoupper(&mut buffer, &source), 6);
        assert_eq!(buffer, [b'A', b'[', b'9', 0xC3, 0xA9, b'Z']);
        let mut buffer = [0u8; 6];
        assert_eq!(strntolower(&mut buffer, &source), 6);
        assert_eq!(buffer, [b'a', b'[', b'9', 0xC3, 0xA9, b'z']);
    }

    /// C's `n` becomes the destination's own length, so a truncating call is
    /// bounded by the type system instead of by the caller's memory, and the
    /// returned count says how much was written -- information the C never
    /// offered. The bytes produced are unchanged.
    #[test]
    fn the_folding_copies_are_bounded_by_the_shorter_slice() {
        // Destination shorter than the source: writes exactly what fits.
        let mut buffer = [0u8; 2];
        assert_eq!(strntoupper(&mut buffer, b"http"), 2);
        assert_eq!(&buffer, b"HT");

        // Source shorter than the destination: the tail is left untouched
        // rather than terminated, and the count says where it stopped.
        let mut buffer = [b'.'; 5];
        assert_eq!(strntolower(&mut buffer, b"AB"), 2);
        assert_eq!(&buffer, b"ab...");

        // A zero-length destination is the C's `if(n < 1) return;`.
        let mut buffer: [u8; 0] = [];
        assert_eq!(strntoupper(&mut buffer, b"http"), 0);
        assert_eq!(strntolower(&mut buffer, b"HTTP"), 0);

        // A zero-length source writes nothing.
        let mut buffer = [b'.'; 3];
        assert_eq!(strntoupper(&mut buffer, b""), 0);
        assert_eq!(&buffer, b"...");
    }

    /// `Curl_safecmp` lives in `strcase.c` and is NOT case-insensitive: it
    /// delegates to `strcmp`, not `strcasecmp`.
    #[test]
    fn safecmp_is_case_sensitive_and_absence_safe() {
        assert!(!safecmp(Some(b"A"), Some(b"a")));
        assert!(!safecmp(Some(b"Accept"), Some(b"ACCEPT")));
        assert!(safecmp(Some(b"Accept"), Some(b"Accept")));
        assert!(safecmp(Some(b""), Some(b"")));
        assert!(!safecmp(Some(b"a"), Some(b"ab")));

        // `return !a && !b` -- both absent are equal, one absent is not.
        assert!(safecmp(None, None));
        assert!(!safecmp(Some(b"a"), None));
        assert!(!safecmp(None, Some(b"a")));
        assert!(!safecmp(Some(b""), None));
    }

    /// `Curl_timestrcmp` returns 0 for identical strings, and its
    /// absent-operand branch is C's `return a || b`.
    #[test]
    fn timestrcmp_returns_zero_only_for_identical_strings() {
        assert_eq!(timestrcmp(Some(b"secret"), Some(b"secret")), 0);
        assert_eq!(timestrcmp(Some(b""), Some(b"")), 0);

        assert_ne!(timestrcmp(Some(b"secret"), Some(b"Secret")), 0);
        assert_ne!(timestrcmp(Some(b"secret"), Some(b"secreu")), 0);
        assert_ne!(timestrcmp(Some(b"secret"), Some(b"secrets")), 0);
        assert_ne!(timestrcmp(Some(b"secrets"), Some(b"secret")), 0);
        assert_ne!(timestrcmp(Some(b"secret"), Some(b"")), 0);
        assert_ne!(timestrcmp(Some(b""), Some(b"secret")), 0);
        // A difference in the FIRST byte and a difference in the LAST byte
        // must both be reported: an early exit would still catch the first,
        // so the last is the one that proves the accumulation happens.
        assert_ne!(timestrcmp(Some(b"Xecret"), Some(b"secret")), 0);
        assert_ne!(timestrcmp(Some(b"secreX"), Some(b"secret")), 0);
        // Non-ASCII differences are reported too: this is not a fold.
        assert_ne!(timestrcmp(Some(&[0x80u8]), Some(&[0x00u8])), 0);
        assert_ne!(timestrcmp(Some(b"A"), Some(b"a")), 0);

        // `return a || b`: zero when both are absent, one when exactly one
        // is. Never a comparison, so no timing claim applies to it.
        assert_eq!(timestrcmp(None, None), 0);
        assert_eq!(timestrcmp(Some(b"a"), None), 1);
        assert_eq!(timestrcmp(None, Some(b"a")), 1);
        assert_eq!(timestrcmp(Some(b""), None), 1);
    }

    // THE SECOND DIFFERENTIAL ORACLE -- for the six functions the transcripts
    // above do not reach.
    //
    // `C_STREQUAL_BITS` and `C_STRNEQUAL_BITS` cover only the two exported
    // comparators. The five constants below extend the same method to
    // `Curl_safecmp`, `Curl_timestrcmp`, `checkprefix()`, `Curl_strntoupper`
    // and `Curl_strntolower`, over the SAME 22-entry `CORPUS` and the same
    // seven `BUDGETS`, so a divergence in any of them fails a test instead of
    // reaching a caller.
    //
    // How they were produced, so the numbers are auditable rather than
    // magical: a C driver was built whose only content besides four
    // `#include` lines was `lib/strcase.c:28-146` and `lib/strequal.c:35-95`
    // copied VERBATIM out of this repository -- both folding tables and all
    // eight functions, unedited -- and it printed one character per call.
    // The driver was compiled with `gcc -O2 -Wall -Wextra`, produced no
    // diagnostic, and was deleted afterwards; only its output is kept.
    //
    // The bit strings are indexed with `CORPUS` in the outer loop and
    // `CORPUS` in the inner, 484 entries each. For `checkprefix` the OUTER
    // string is the literal and the INNER one the subject, matching the
    // macro's own argument order -- which is the asymmetry that makes this
    // particular transcript worth having.
    //
    // The hex strings are the CONTENT bytes written by the two folding
    // copies, iterating `CORPUS` outer and `BUDGETS` inner, taking
    // `min(budget, len)` bytes each time. 345 bytes each. The C's extra
    // terminator is deliberately outside the content region; the test named
    // `the_folding_copies_stop_short_of_the_c_terminator` records that one
    // difference separately, with the bytes the C actually produced.

    const C_SAFECMP_BITS: &str = concat!(
        "1000000000000000000000010000000000000000000000100000000000000000000001000000",
        "0000000000000000100000000000000000000001000000000000000000000010000000000000",
        "0000000001000000000000000000000010000000000000000000000100000000000000000000",
        "0010000000000000000000000100000000000000000000001000000000000000000000010000",
        "0000000000000000001000000000000000000000010000000000000000000000100000000000",
        "0000000000010000000000000000000000100000000000000000000001000000000000000000",
        "0000100000000000000000000001",
    );

    const C_TIMESTRCMP_BITS: &str = concat!(
        "1000000000000000000000010000000000000000000000100000000000000000000001000000",
        "0000000000000000100000000000000000000001000000000000000000000010000000000000",
        "0000000001000000000000000000000010000000000000000000000100000000000000000000",
        "0010000000000000000000000100000000000000000000001000000000000000000000010000",
        "0000000000000000001000000000000000000000010000000000000000000000100000000000",
        "0000000000010000000000000000000000100000000000000000000001000000000000000000",
        "0000100000000000000000000001",
    );

    const C_CHECKPREFIX_BITS: &str = concat!(
        "1111111111111111111111011111111110000000001101111111111000000000110001111100",
        "0000000000110001111100000000000011000111110000000000001100000010000000000000",
        "0000000001000000000000000000000011100000000000000000001110000000000000000000",
        "0010000000000000000000000100000000000000000000001000000000000000000000010000",
        "0000000000000000001000000000000000000000010000000000000000000000100000000000",
        "0000000000010000000000000000000000100000000000000000000001000000000000000000",
        "0000100000000000000000000001",
    );

    const C_STRNTOUPPER_HEX: &str = concat!(
        "4141414141414141414141414141424142414241424142414142414241424142414241414241",
        "4241424142414241414241424341424341424341424341414241425841425841425841425841",
        "4143414343414343455054414343455054414343455054414143414343414343455054414343",
        "4550544143434550544141434143434143434550542d454143434550542d454e434f44414343",
        "4550542d454e434f44494e475a5a5a5a5a5a7b7b7b7b7b7b4040404040405b5b5b5b5b5b6060",
        "60606060484854485454485454502f312e31485454502f312e3120323030485454502f312e31",
        "20323030484854485454485454502f312e31485454502f312e3120343034485454502f312e31",
        "20343034545445544541544541c3a9544541c3a9544541c3a9545445544541544541c3895445",
        "41c389544541c38941414241427f41427f41427f41427f4141424142c24142c2804142c28041",
        "42c280",
    );

    const C_STRNTOLOWER_HEX: &str = concat!(
        "6161616161616161616161616161626162616261626162616162616261626162616261616261",
        "6261626162616261616261626361626361626361626361616261627861627861627861627861",
        "6163616363616363657074616363657074616363657074616163616363616363657074616363",
        "6570746163636570746161636163636163636570742d656163636570742d656e636f64616363",
        "6570742d656e636f64696e677a7a7a7a7a7a7b7b7b7b7b7b4040404040405b5b5b5b5b5b6060",
        "60606060686874687474687474702f312e31687474702f312e3120323030687474702f312e31",
        "20323030686874687474687474702f312e31687474702f312e3120343034687474702f312e31",
        "20343034747465746561746561c3a9746561c3a9746561c3a9747465746561746561c3897465",
        "61c389746561c38961616261627f61627f61627f61627f6161626162c26162c2806162c28061",
        "62c280",
    );

    /// One transcript character per call, `1` where the C answered "equal".
    fn expect_bits(transcript: &str, calls: usize) -> Vec<bool> {
        assert_eq!(
            transcript.len(),
            calls,
            "the oracle transcript must cover exactly the calls made"
        );
        transcript.chars().map(|c| c == '1').collect()
    }

    #[test]
    fn safecmp_matches_the_c_oracle() {
        let expected = expect_bits(C_SAFECMP_BITS, CORPUS.len() * CORPUS.len());
        let mut k = 0usize;
        for left in CORPUS {
            for right in CORPUS {
                let got =
                    safecmp(Some(left.as_bytes()), Some(right.as_bytes()));
                assert_eq!(
                    got, expected[k],
                    "Curl_safecmp({left:?}, {right:?}): C said {} and this \
                     says {got}",
                    expected[k]
                );
                k += 1;
            }
        }
    }

    #[test]
    fn timestrcmp_matches_the_c_oracle() {
        let expected =
            expect_bits(C_TIMESTRCMP_BITS, CORPUS.len() * CORPUS.len());
        let mut k = 0usize;
        for left in CORPUS {
            for right in CORPUS {
                let got =
                    timestrcmp(Some(left.as_bytes()), Some(right.as_bytes()));
                assert_eq!(
                    got == 0,
                    expected[k],
                    "Curl_timestrcmp({left:?}, {right:?}): C said identical={} \
                     and this returned {got}",
                    expected[k]
                );
                k += 1;
            }
        }
    }

    /// The outer string is the LITERAL and the inner one the SUBJECT, which
    /// is the macro's own argument order. A transposed implementation fails
    /// this test on the very first asymmetric pair.
    #[test]
    fn checkprefix_matches_the_c_oracle() {
        let expected =
            expect_bits(C_CHECKPREFIX_BITS, CORPUS.len() * CORPUS.len());
        let mut k = 0usize;
        for literal in CORPUS {
            for subject in CORPUS {
                let got = checkprefix(literal, subject.as_bytes());
                assert_eq!(
                    got, expected[k],
                    "checkprefix({literal:?}, {subject:?}): C said {} and \
                     this says {got}",
                    expected[k]
                );
                k += 1;
            }
        }
    }

    #[test]
    fn the_folding_copies_match_the_c_oracle() {
        for (transcript, fold) in [
            (
                C_STRNTOUPPER_HEX,
                strntoupper as fn(&mut [u8], &[u8]) -> usize,
            ),
            (
                C_STRNTOLOWER_HEX,
                strntolower as fn(&mut [u8], &[u8]) -> usize,
            ),
        ] {
            let expected: Vec<u8> = transcript
                .as_bytes()
                .chunks(2)
                .map(|pair| {
                    let text = std::str::from_utf8(pair)
                        .unwrap_or_else(|_| unreachable!("hex is ASCII"));
                    u8::from_str_radix(text, 16)
                        .unwrap_or_else(|_| unreachable!("hex is well formed"))
                })
                .collect();

            let mut at = 0usize;
            for source in CORPUS {
                let bytes = source.as_bytes();
                for budget in BUDGETS {
                    // 0xEE fills the buffer so that a write past the reported
                    // count would show up rather than blending into zeros.
                    let mut destination = [0xEEu8; 128];
                    let written = fold(&mut destination[..budget], bytes);

                    let content = budget.min(bytes.len());
                    assert_eq!(
                        written, content,
                        "{source:?} at budget {budget}: wrote {written} bytes, \
                         expected {content}"
                    );
                    assert_eq!(
                        &destination[..content],
                        &expected[at..at + content],
                        "{source:?} at budget {budget} disagrees with the C"
                    );
                    // Nothing beyond the reported count was touched.
                    assert!(
                        destination[content..].iter().all(|b| *b == 0xEE),
                        "{source:?} at budget {budget} wrote past its count"
                    );
                    at += content;
                }
            }
            assert_eq!(
                at,
                expected.len(),
                "the oracle transcript must be consumed exactly"
            );
        }
    }

    /// The single measured difference from the C, recorded with the bytes the
    /// C actually produced so the claim in [`strntoupper`]'s documentation is
    /// checkable rather than remembered.
    ///
    /// `Curl_strntoupper(dest, "ab", 5)` over a buffer pre-filled with `0xEE`
    /// leaves `41 42 00 EE EE`: two folded bytes and the source's NUL. This
    /// function writes the two folded bytes, reports 2, and invents no
    /// terminator, because a `&[u8]` source never had one.
    #[test]
    fn the_folding_copies_stop_short_of_the_c_terminator() {
        let mut destination = [0xEEu8; 5];
        assert_eq!(strntoupper(&mut destination, b"ab"), 2);
        assert_eq!(destination, [0x41, 0x42, 0xEE, 0xEE, 0xEE]);

        // And with the budget clamped to the C's `n`, the content region is
        // identical to the C's first two bytes.
        let mut destination = [0xEEu8; 5];
        assert_eq!(strntoupper(&mut destination[..5], b"ab"), 2);
        assert_eq!(&destination[..2], &[0x41u8, 0x42]);
    }

    /// The C's own null-pointer answers, printed by the same driver:
    /// `safecmp(N,N)=1`, `safecmp("a",N)=0`, `safecmp(N,"a")=0`,
    /// `timestrcmp(N,N)=0`, `timestrcmp("a",N)=1`, `timestrcmp(N,"a")=1`.
    #[test]
    fn the_null_safe_pair_matches_the_c_oracle_on_absent_operands() {
        assert!(safecmp(None, None));
        assert!(!safecmp(Some(b"a"), None));
        assert!(!safecmp(None, Some(b"a")));
        assert_eq!(timestrcmp(None, None), 0);
        assert_eq!(timestrcmp(Some(b"a"), None), 1);
        assert_eq!(timestrcmp(None, Some(b"a")), 1);
    }

    /// The two null-safe comparisons answer the same question with OPPOSITE
    /// polarity, and getting that backwards would turn "the credentials
    /// differ" into "the connection may be reused".
    ///
    /// Asserted over NUL-free inputs, which is every real call site: the
    /// two functions do diverge on a slice carrying an interior zero,
    /// because [`timestrcmp`] stops there as the C string semantics
    /// require while [`safecmp`] compares the whole slice. That difference
    /// is documented on `timestrcmp` rather than papered over here.
    #[test]
    fn timestrcmp_polarity_is_the_inverse_of_safecmp() {
        let cases: [(Option<&[u8]>, Option<&[u8]>); 7] = [
            (Some(b"secret"), Some(b"secret")),
            (Some(b"secret"), Some(b"Secret")),
            (Some(b"secret"), Some(b"secrets")),
            (Some(b""), Some(b"")),
            (None, None),
            (Some(b"a"), None),
            (None, Some(b"a")),
        ];
        for (left, right) in cases {
            assert_eq!(
                safecmp(left, right),
                timestrcmp(left, right) == 0,
                "polarity disagreement for {left:?} vs {right:?}"
            );
        }
    }
}
