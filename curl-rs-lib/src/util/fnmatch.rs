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

//! Shell-style wildcard matching, for FTP directory listings.
//!
//! Supersedes `lib/curl_fnmatch.c` (385 lines) and `lib/curl_fnmatch.h` (46),
//! which AAP 0.4.1 maps onto this file. The whole of the C is wrapped in
//! `#ifndef CURL_DISABLE_FTP` (`lib/curl_fnmatch.c:26`), so the whole of this
//! module carries `#[cfg(feature = "ftp")]`, written as an inner attribute
//! below for the same reason `src/ffi/gss.rs` writes its own that way: the
//! gate belongs with the code it governs, and the parent then declares the
//! module unconditionally.
//!
//! # The one consumer, and why the result is not a `bool`
//!
//! Exactly one call site exists in the C tree. `lib/ftplistparser.c:321-323`
//! chooses the comparator for a wildcard FTP download:
//!
//! ```text
//! compare = data->set.fnmatch;          /* CURLOPT_FNMATCH_FUNCTION */
//! if(!compare)
//!   compare = Curl_fnmatch;             /* this module */
//! ```
//!
//! and then admits a listed file only when the comparator returns zero
//! (`:327-328`). The user may supply that comparator through
//! `CURLOPT_FNMATCH_FUNCTION` (`lib/setopt.c:2729`), so the three integers
//! `curl_fnmatch_callback` returns are part of the public ABI, not an
//! internal convention: `CURL_FNMATCH_MATCH` 0, `CURL_FNMATCH_NOMATCH` 1 and
//! `CURL_FNMATCH_FAIL` 2 (`lib/curl_fnmatch.h:26-28`). [`FnMatch`] therefore
//! pins all three discriminants explicitly, for the reason AAP 0.6.1 gives
//! for `CURLcode`: a caller compiled against curl 8.19.0-DEV holds the
//! numbers, not the names. Collapsing the enumeration to a `bool` would erase
//! a third outcome that a user callback is entitled to return.
//!
//! At this call site `NOMATCH` and `FAIL` are indistinguishable -- both are
//! non-zero, so both exclude the file. They are still kept apart, because the
//! callback contract distinguishes them and this module's job is to reproduce
//! that contract rather than the one call site's use of it.
//!
//! # The C ships TWO matchers, and this is a port of the one that does not
//!
//! `lib/curl_fnmatch.c` splits at `:30` on `HAVE_FNMATCH`:
//!
//! * `#ifndef HAVE_FNMATCH` -- curl's own recursive-backtracking matcher,
//!   `:32-358`, about 320 lines.
//! * `#else` -- a 25-line shim, `:359-382`, delegating to the system
//!   `fnmatch(3)` and mapping `0` to `MATCH`, `FNM_NOMATCH` to `NOMATCH` and
//!   anything else to `FAIL`.
//!
//! `HAVE_FNMATCH` is detected on all four mandated targets: `configure.ac`
//! lists `fnmatch` among its checked functions at `:4177`, and `CMakeLists.txt`
//! runs `check_function_exists("fnmatch" HAVE_FNMATCH)` at `:1580`. Linux and
//! macOS both provide it, so **the shipping C binary uses the system
//! `fnmatch(3)` on every target this workspace builds for.**
//!
//! This module nevertheless ports curl's own matcher. Three reasons, in order
//! of weight:
//!
//! 1. Rust's standard library has no `fnmatch`, and the crate set is closed
//!    -- no `glob`, `globset`, `wildmatch` or `regex` may be added, and none
//!    of them reproduces the semantics recorded below in any case.
//! 2. Reaching the platform function would need `unsafe`, which AAP 0.8.2
//!    confines to `mod ffi`; `libc` is not a dependency of this layer.
//! 3. Curl's own matcher is the behaviour its header documents
//!    (`lib/curl_fnmatch.h:30-42`) and the one upstream ships wherever
//!    `fnmatch(3)` is absent. It is a supported configuration, exactly as
//!    AAP 0.8.7 treats unversioned symbol export.
//!
//! The escalation path, recorded and deliberately not taken: were an eligible
//! fixture ever to fail on this difference, the remedy is to route through
//! the platform `fnmatch(3)` from `src/ffi/sys.rs`, the sanctioned `unsafe`
//! island -- never to weaken the pure-Rust matcher to meet a fixture.
//!
//! # The divergence, measured rather than described
//!
//! `tests/unit/unit1307.c` is the authoritative account of where the two
//! matchers part company, because each of its rows can carry up to three
//! expectations. `LINUX_DIFFER` is `0x80` with a shift of 8 and `MAC_DIFFER`
//! is `0x40` with a shift of 16 (`:39-49`); the runner applies a shift only
//! for the matching platform and then masks with `0x03` regardless
//! (`:293-299`), so **the un-shifted low two bits are the `SYSTEM_CUSTOM`
//! expectation -- the one this port must satisfy.**
//!
//! The table holds **157 rows** (measured, not the round number the migration
//! notes carry), of which **11** declare a platform difference:
//!
//! | `unit1307.c` | pattern | string | custom | linux | mac |
//! |---|---|---|---|---|---|
//! | 78 | 200 bytes, mostly `[` | 200 `[` | `NOMATCH` | same | `FAIL` |
//! | 87 | `[` | `[` | `NOMATCH` | `MATCH` | `FAIL` |
//! | 88 | `[]` | `[]` | `NOMATCH` | `MATCH` | `FAIL` |
//! | 130 | `[\xFF]` | `\xFF` | `MATCH` | `FAIL` | `FAIL` |
//! | 152 | `[!\xFF]` | empty | `NOMATCH` | `FAIL` | same |
//! | 153 | `[!\xFF]` | `\xFF` | `NOMATCH` | `FAIL` | `FAIL` |
//! | 154 | `[!\xFF]` | `a` | `MATCH` | `FAIL` | `FAIL` |
//! | 186 | `[[:foo:]]` | `bar` | `NOMATCH` | same | `FAIL` |
//! | 187 | `[[:foo:]]` | `f]` | `MATCH` | `NOMATCH` | `FAIL` |
//! | 225 | `\` | `\` | `MATCH` | `NOMATCH` | same |
//! | 264 | 103 bytes, `*` and `[` | `a` | `NOMATCH` | `FAIL` | same |
//!
//! Two further measurements were taken rather than assumed, by extracting
//! `lib/curl_fnmatch.c:32-358` verbatim into a standalone C harness and
//! running both branches over all 157 rows:
//!
//! * curl's own matcher agrees with the custom column on **157 of 157** rows.
//!   The port below is differential-tested against that same corpus.
//! * On a glibc host, curl's matcher and `fnmatch(3)` actually disagree on
//!   only **4** rows -- 87, 88, 187 and 225 -- and on those four the platform
//!   answer is the one the linux column declares. The `FAIL` expectations for
//!   the `\xFF` rows and for row 264 are stale: this glibc returns the same
//!   answer as curl's own matcher there. So 11 rows are declared divergent
//!   and 4 are divergent in practice; both numbers are stated because a
//!   reader checking the table against a modern platform would otherwise
//!   conclude the table is wrong.
//!
//! Every one of the 11 needs a pathological pattern: an unmatched or empty
//! `[`, a `0xFF` byte inside a bracket expression, an unknown keyword, or a
//! lone trailing backslash.
//!
//! # What the divergence costs, quantified
//!
//! Nothing that any fixture observes, and that is measured too.
//!
//! Seven `tests/data` fixtures exercise wildcard matching: `test574`,
//! `test575`, `test576` (`*.txt` and `*` over a UNIX listing), `test1113` and
//! `test1114` (the same over a DOS listing), and `test1162` and `test1163`.
//! The last two DO use pathological patterns -- `[*\s-'tl` and `*[][`, both
//! unterminated bracket expressions -- so the migration notes' claim that
//! none is pathological is inaccurate; the conclusion nevertheless holds, for
//! a better reason. Each of those two asserts only
//! `<errorcode>78</errorcode>`, `CURLE_REMOTE_FILE_NOT_FOUND`, meaning no
//! filename matched, and every comparator answer other than zero produces
//! that outcome at `lib/ftplistparser.c:327`. Neither pattern sits on a
//! divergent row. An eighth file, `test1458`, matches a search for
//! "wildcard" only because it exercises `--resolve` with a wildcard host.
//!
//! The ninth is `test1307`, the unit driver -- and it is listed in
//! `tests/data/DISABLED:46-47` under the comment "fnmatch differences are
//! just too common to make testing them sensible". Upstream disables it, so
//! the harness never runs it against any implementation, and AAP 0.8.7's
//! relocation of its coverage into the `#[cfg(test)]` module at the foot of
//! this file is the only place that coverage can live. All 157 rows are
//! ported there, taking the custom column for every one.
//!
//! # The documented feature set, from `lib/curl_fnmatch.h:30-42`
//!
//! Reproduced because it is the specification of what follows, and its
//! omissions are as load-bearing as its inclusions:
//!
//! > Implemented with recursive backtracking, if you want to use
//! > `Curl_fnmatch`, please note that there is not implemented UTF/Unicode
//! > support.
//! >
//! > Implemented features:
//! > `'?'` notation, does not match UTF characters;
//! > `'*'` can also work with UTF string;
//! > `[a-zA-Z0-9]` enumeration support
//! >
//! > keywords: `alnum`, `digit`, `xdigit`, `alpha`, `print`, `blank`,
//! > `lower`, `graph`, `space` and `upper` (use as `"[[:alnum:]]"`)
//!
//! So `'?'` matches exactly one **byte**, not one Unicode scalar value, and
//! `'*'` is incidentally UTF-8-safe because it matches any run of bytes.
//! There are ten keywords and no more; an eleventh spelling is a syntax
//! error. Everything here operates on `&[u8]` for that reason -- never
//! `&str`, which would make four rows of `unit1307` unrepresentable.
//!
//! # Two frozen quirks that read like defects
//!
//! Both are reproduced deliberately. AAP 0.8.1 freezes observable behaviour,
//! and "the C is probably wrong here" is not a licence to differ.
//!
//! ## `[[:space:]]` matches only space and tab
//!
//! The bracket cascade tests the `space` flag with `ISBLANK`, not `ISSPACE`
//! (`lib/curl_fnmatch.c:315-316`). `ISBLANK` is space and tab alone
//! (`lib/curl_ctype.h:45`) whereas `ISSPACE` adds `0x0a` through `0x0d`
//! (`:46`), so `[[:space:]]` in curl does not match a newline, a carriage
//! return, a vertical tab or a form feed. Almost certainly an upstream
//! oversight, verified against the extracted C rather than inferred, and
//! frozen. It also makes the `space` and `blank` flags behave identically;
//! both are still parsed and stored, so the parse side stays faithful.
//!
//! ## Three effective stars can report a non-match
//!
//! `maxstars` starts at 2 (`lib/curl_fnmatch.c:357`) and is spent once per
//! `'*'` that enters the backtracking scan. When it reaches zero a further
//! `'*'` returns `NOMATCH` immediately (`:263-264`), so a pattern with three
//! effective stars can be reported as a non-match even where it plainly
//! matches: `*a*b*c` against `aXbYc` is `NOMATCH`, while `a*b*c` against the
//! same string, and `*a*b` against `aXb`, both match. This is a deliberate
//! guard against catastrophic backtracking. The budget, and the point at
//! which it is spent, are reproduced exactly; raising it, or replacing the
//! recursion with a dynamic-programming or automaton matcher, would change
//! the answer on the pathological rows. Performance is an explicit non-goal
//! (AAP 0.1.1), so no memoisation is added either.
//!
//! One reassurance follows from the same budget: the recursion below is
//! provably at most three frames deep, because the only recursive call is the
//! star scan and it passes a strictly smaller budget. The scan itself is a
//! loop.
//!
//! # NUL, empty, and the shape of the signature
//!
//! The C walks four `const unsigned char *` cursors and reads the NUL
//! terminator as an ordinary byte, one past the last content byte. Every read
//! here is `slice.get(i).copied().unwrap_or(0)` instead -- the idiom
//! `util/strcase.rs` already uses -- so index `len()` yields exactly the zero
//! the C would have read there, and no read can run off the end. The deepest
//! lookahead in the C is three bytes past the cursor, in the range parser,
//! and it is reached only when the intervening bytes were non-NUL, so this
//! model reproduces it without ever needing a byte beyond the virtual
//! terminator.
//!
//! Two consequences worth stating:
//!
//! * A zero byte **inside** either slice terminates it, exactly as it would
//!   have terminated the C string. `("a\0b", "a")` matches, because the C
//!   pattern would have been `a`.
//! * `Curl_fnmatch` returns `FAIL` for a NULL pattern or string
//!   (`lib/curl_fnmatch.h`'s prototype takes pointers;
//!   `lib/curl_fnmatch.c:353-355`). A `&[u8]` cannot be null, so that check
//!   has no place here: it belongs at the C boundary, where a pointer still
//!   exists. An **empty** slice is a different thing entirely and is matched
//!   normally -- `("", "")` matches and `("", "a")` does not. `FAIL` is
//!   consequently never returned by [`fnmatch`]; the variant exists because
//!   the callback contract has it.
//!
//! The `void *ptr` first parameter of the C signature exists only to satisfy
//! the callback prototype and is unused (`lib/curl_fnmatch.c:351-352`), so it
//! is absent here. The dispatch that chooses between this function and a
//! user-supplied callback still needs it, and that dispatch belongs to
//! `protocols/ftp/listparser.rs`.
//!
//! # Conventions
//!
//! No `unsafe`, no raw pointers and no `libc`: the crate root's
//! `#![deny(unsafe_code)]` exempts only `mod ffi`, and this is the module
//! where the C was at its most pointer-hazardous, so the discipline matters
//! most here. Every cursor is a bounds-checked index. The C function names
//! are kept -- `fnmatch`, `match_loop`, `setcharset`, `setcharorrange`,
//! `parsekeyword`, `charclass` -- so that a grep against
//! `lib/curl_fnmatch.c` still lands. Edition 2021, minimum supported Rust
//! version 1.75, and nothing here needs anything newer.

#![cfg(feature = "ftp")]

/// The three outcomes of a wildcard comparison.
///
/// Supersedes the three macros at `lib/curl_fnmatch.h:26-28`. Every
/// discriminant is written out; none is left to Rust's implicit "previous plus
/// one", for the reason AAP 0.6.1 records for `CURLcode`. `#[repr(i32)]`
/// because `curl_fnmatch_callback` returns C `int`, and a user-supplied
/// `CURLOPT_FNMATCH_FUNCTION` therefore hands these exact integers back across
/// the boundary.
///
/// [`Fail`](FnMatch::Fail) is unreachable from [`fnmatch`], whose arguments are
/// slices and so cannot be null. It is part of the type because it is part of
/// the callback contract: the C returns it for a null pointer
/// (`lib/curl_fnmatch.c:353-355`), and the FFI layer that still holds pointers
/// is where that check belongs.
// The whole module is unreferenced until `protocols/ftp/listparser.rs` lands
// and calls this from its comparator dispatch -- the single consumer measured
// at `lib/ftplistparser.c:321-323`. The allowance is per item, as this
// directory's policy requires, and comes off when that module arrives. It
// covers the variants as well as the type, which is what the `Fail` variant
// needs: nothing in a non-test build constructs it.
#[allow(dead_code)]
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FnMatch {
    /// `CURL_FNMATCH_MATCH` = `0`. The pattern matched the whole string.
    Match = 0,
    /// `CURL_FNMATCH_NOMATCH` = `1`. It did not, including every case where
    /// the pattern itself is malformed.
    NoMatch = 1,
    /// `CURL_FNMATCH_FAIL` = `2`. The comparison could not be performed. See
    /// the note on the type: [`fnmatch`] never returns this.
    Fail = 2,
}

// THE CHARACTER PREDICATES -- `lib/curl_ctype.h`, transcribed range by range.
//
// These are curl's own ASCII tables, not `<ctype.h>`, so they are
// locale-independent by construction -- which is the whole point of the header
// existing. The standard library's Unicode-aware `char` classification
// methods -- the alphanumeric, alphabetic, case and whitespace family -- would
// answer differently for every byte from 0x80 up, so not one of them is named
// anywhere in this file; each predicate below is an explicit byte range
// instead. `unit1307` rows 130 and 152-154 feed a raw 0xFF and would change
// answer under a Unicode predicate.
//
// Two of them are unusual enough to be worth naming here rather than leaving
// to a reader's assumption: ISPRINT and ISGRAPH both include the control range
// 9..=0x0d, by way of ISLOWPRINT, so `[[:print:]]` matches a tab and a
// carriage return while `[[:graph:]]` matches a tab but not a space.
//
// The C spells each range as two comparisons, `((x) >= 'A') && ((x) <= 'Z')`.
// An inclusive range's `contains` is that same test, byte for byte, and is
// what `clippy::manual_range_contains` asks for; the two forms are
// interchangeable here because every bound below is a `u8` constant, so no
// widening or signedness question arises.
//
// Three of the ten -- ISUPPER, ISLOWER and ISDIGIT -- coincide exactly with a
// standard-library ASCII helper, and `clippy::manual_is_ascii_check` asks for
// the helper. Each of the three carries a targeted allowance instead, because
// the other seven have no such counterpart: four are compositions, ISBLANK is
// a two-byte set, and ISPRINT and ISGRAPH differ from every helper on offer.
// The ASCII-graphic helper in particular is `0x21..=0x7e` and would SILENTLY
// DROP the 9..=0x0d control range that curl's ISGRAPH admits. Spelling three
// of a ten-macro family with helpers and seven with ranges would invite a
// later reader to finish the job and reach for that one; keeping all ten in a
// single shape that diffs against `lib/curl_ctype.h` line by line is worth
// more than three shorter function bodies. The sibling `util/strcase.rs:239`
// resolves the same tension the same way.

/// `ISUPPER` -- `lib/curl_ctype.h:42`.
// Uniform with the other nine: see the note above the family.
#[allow(clippy::manual_is_ascii_check)]
fn is_upper(c: u8) -> bool {
    (b'A'..=b'Z').contains(&c)
}

/// `ISLOWER` -- `lib/curl_ctype.h:43`.
// Uniform with the other nine: see the note above the family.
#[allow(clippy::manual_is_ascii_check)]
fn is_lower(c: u8) -> bool {
    (b'a'..=b'z').contains(&c)
}

/// `ISDIGIT` -- `lib/curl_ctype.h:44`.
// Uniform with the other nine: see the note above the family.
#[allow(clippy::manual_is_ascii_check)]
fn is_digit(c: u8) -> bool {
    (b'0'..=b'9').contains(&c)
}

/// `ISALPHA` -- `lib/curl_ctype.h:38`, defined as `ISLOWER || ISUPPER`.
fn is_alpha(c: u8) -> bool {
    is_lower(c) || is_upper(c)
}

/// `ISALNUM` -- `lib/curl_ctype.h:41`, defined as
/// `ISDIGIT || ISLOWER || ISUPPER`.
fn is_alnum(c: u8) -> bool {
    is_digit(c) || is_lower(c) || is_upper(c)
}

/// `ISXDIGIT` -- `lib/curl_ctype.h:39`, defined as
/// `ISDIGIT || ISLOWHEXALHA || ISUPHEXALHA`, whose two halves are `a`..=`f`
/// (`:27`) and `A`..=`F` (`:28`).
fn is_xdigit(c: u8) -> bool {
    is_digit(c) || (b'a'..=b'f').contains(&c) || (b'A'..=b'F').contains(&c)
}

/// `ISBLANK` -- `lib/curl_ctype.h:45`. Space and tab, and nothing else.
fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// `ISLOWPRINT` -- `lib/curl_ctype.h:33`. The five control bytes 9..=0x0d,
/// which is tab, newline, vertical tab, form feed and carriage return.
fn is_lowprint(c: u8) -> bool {
    (9..=0x0d).contains(&c)
}

/// `ISPRINT` -- `lib/curl_ctype.h:35`, defined as
/// `ISLOWPRINT || (>= ' ' && <= 0x7e)`. Note the control range: this is not
/// the `isprint(3)` of the C library. `0x7e` is `~`, the last graphic ASCII
/// byte, so the upper bound is spelled as that character.
fn is_print(c: u8) -> bool {
    is_lowprint(c) || (b' '..=b'~').contains(&c)
}

/// `ISGRAPH` -- `lib/curl_ctype.h:36`, defined as
/// `ISLOWPRINT || (> ' ' && <= 0x7e)`. Differs from [`is_print`] by the space
/// alone, and carries the same control range. The C's strict `> ' '` is `>=`
/// the next byte, `0x21`, which is `!`.
fn is_graph(c: u8) -> bool {
    is_lowprint(c) || (b'!'..=b'~').contains(&c)
}

/// The class a byte belongs to, for the purpose of deciding a range.
///
/// Supersedes `char_class` (`lib/curl_fnmatch.c:59-64`). All four variants are
/// kept, `Other` included, because [`setcharorrange`] compares two classes for
/// equality and "neither endpoint is a letter or a digit" has to be
/// distinguishable from "both are digits".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CharClass {
    /// `CCLASS_OTHER` = `0`.
    Other,
    /// `CCLASS_DIGIT` = `1`.
    Digit,
    /// `CCLASS_UPPER` = `2`.
    Upper,
    /// `CCLASS_LOWER` = `3`.
    Lower,
}

/// The class of a byte.
///
/// Supersedes `charclass` (`lib/curl_fnmatch.c:125-134`), whose order of tests
/// is upper, lower, digit, other. The order cannot matter -- the three
/// predicates are mutually exclusive -- but it is kept so the two functions
/// read the same.
fn charclass(c: u8) -> CharClass {
    if is_upper(c) {
        CharClass::Upper
    } else if is_lower(c) {
        CharClass::Lower
    } else if is_digit(c) {
        CharClass::Digit
    } else {
        CharClass::Other
    }
}

/// A POSIX character class named inside a bracket expression.
///
/// The C has no such enumeration: it stores these as flags at indices past the
/// end of the byte range in one 271-byte array, so that a class and a literal
/// byte can share a single lookup table. Those indices are recorded here so a
/// reader can still grep `lib/curl_fnmatch.c`, and the layout note below
/// explains why this port does not reproduce the trick.
///
/// Declared in the order of the C's constants (`lib/curl_fnmatch.c:37-46`),
/// which is NOT the order in which they are consulted; see [`CASCADE`] for
/// that.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PosixClass {
    /// `CURLFNM_ALNUM` = 257, that is `CURLFNM_CHARSET_LEN + 1`.
    Alnum,
    /// `CURLFNM_DIGIT` = 258.
    Digit,
    /// `CURLFNM_XDIGIT` = 259.
    Xdigit,
    /// `CURLFNM_ALPHA` = 260.
    Alpha,
    /// `CURLFNM_PRINT` = 261.
    Print,
    /// `CURLFNM_BLANK` = 262.
    Blank,
    /// `CURLFNM_LOWER` = 263.
    Lower,
    /// `CURLFNM_GRAPH` = 264.
    Graph,
    /// `CURLFNM_SPACE` = 265.
    Space,
    /// `CURLFNM_UPPER` = 266.
    Upper,
}

/// The number of POSIX classes, and so the width of the class-flag array.
///
/// Ten, matching the ten keywords the header documents. The C reserves fifteen
/// slots past the byte range -- `CURLFNM_CHSET_SIZE` is
/// `CURLFNM_CHARSET_LEN + 15` (`lib/curl_fnmatch.c:33`) -- and uses eleven of
/// them: one for the negation flag and ten for these. The remaining four are
/// spare in the C and have no counterpart here.
const CLASS_COUNT: usize = 10;

/// The contents of one bracket expression.
///
/// Supersedes the `unsigned char charset[CURLFNM_CHSET_SIZE]` of
/// `lib/curl_fnmatch.c:256`, a 271-byte array in which indices 0..=255 are
/// literal bytes, index 256 (`CURLFNM_NEGATE`) is the negation flag and indices
/// 257..=266 are the ten class flags. Splitting it into three fields is the
/// point of the migration: the C's "index past the end of the byte range"
/// convention is exactly the kind of arithmetic that a typed field removes, and
/// it removes it without changing a single answer, because the byte index and
/// the flag indices never overlap in the C either -- a byte is at most 255.
///
/// The C's `memset(charset, 0, CURLFNM_CHSET_SIZE)` at the head of
/// [`setcharset`] (`:165`) exists because `loop` declares one array and reuses
/// it for every bracket expression it meets. Here each call constructs its own
/// value, so the clear is structural.
struct CharSet {
    /// One flag per literal byte. `charset[c]` in the C.
    bytes: [bool; 256],
    /// `charset[CURLFNM_NEGATE]`. Set by a leading `^` or `!`.
    negate: bool,
    /// One flag per [`PosixClass`], indexed by `class as usize`.
    classes: [bool; CLASS_COUNT],
}

impl CharSet {
    /// An empty set: no literal byte, no class, not negated.
    fn new() -> Self {
        CharSet {
            bytes: [false; 256],
            negate: false,
            classes: [false; CLASS_COUNT],
        }
    }

    /// Adds a literal byte. `charset[c] = 1` in the C.
    fn add_byte(&mut self, c: u8) {
        self.bytes[usize::from(c)] = true;
    }

    /// Whether a literal byte is in the set.
    fn has_byte(&self, c: u8) -> bool {
        self.bytes[usize::from(c)]
    }

    /// Adds a class. `charset[CURLFNM_ALNUM] = 1` and its nine siblings.
    fn add_class(&mut self, class: PosixClass) {
        self.classes[class as usize] = true;
    }

    /// Whether a class was named in the expression.
    fn has_class(&self, class: PosixClass) -> bool {
        self.classes[class as usize]
    }
}

/// The byte at `index`, or the terminator the C would have read past the end.
///
/// The C walks NUL-terminated strings and reads the terminator as an ordinary
/// byte; `&[u8]` carries no terminator, so index `len()` and beyond yield the
/// zero that read would have produced. Every byte access in this module goes
/// through here, which is what makes an out-of-bounds read impossible while
/// still reproducing the C's lookahead exactly.
fn byte_at(bytes: &[u8], index: usize) -> u8 {
    bytes.get(index).copied().unwrap_or(0)
}

/// Parses a `[:keyword:]` class name and records it in `set`.
///
/// Supersedes `parsekeyword` (`lib/curl_fnmatch.c:69-122`). `at` enters
/// pointing just past the `[:` and, on success, leaves pointing just past the
/// closing `]` of the `:]` pair -- the C's `*pattern = p` at `:98`. Returns
/// `true` for the C's `SETCHARSET_OK`, whose value is 1 while `SETCHARSET_FAIL`
/// is 0 (`:66-67`); the polarity reads like an error code and is not one, so
/// the C's `if(parsekeyword(...))` means "if it succeeded".
///
/// On failure nothing has been recorded in `set`: the C writes its flag only
/// after the name has been recognised, so a rejected keyword cannot leave a
/// half-parsed expression behind. That matters at the call site, which reuses
/// the same set for the literal `[` it falls back to.
///
/// Two details of the C's bound check are reproduced rather than tidied:
///
/// * The buffer is ten bytes and the check is `i >= sizeof(keyword)`, tested
///   BEFORE the store and against the loop counter -- which also counts the
///   `:` and the `]`. The longest name that can therefore parse is EIGHT
///   bytes, not ten. This has no observable consequence, because a name of any
///   length that is not one of the ten fails identically and both failures
///   lead the caller to treat `[` as a literal; the counter is nonetheless
///   left where the C has it.
/// * Only lower-case letters are accepted in the body, so `[[:ALNUM:]]` is a
///   syntax error rather than a class.
fn parsekeyword(pattern: &[u8], at: &mut usize, set: &mut CharSet) -> bool {
    /// `sizeof(keyword)` at `lib/curl_fnmatch.c:72`.
    const KEYWORD_CAPACITY: usize = 10;

    // `parsekey_state` (`lib/curl_fnmatch.c:54-57`), as a two-valued flag:
    // false is CURLFNM_PKW_INIT, true is CURLFNM_PKW_DDOT. An enumeration
    // would carry no more information than the name of the transition, which
    // the comment at the transition already gives.
    let mut seen_colon = false;
    let mut keyword = [0u8; KEYWORD_CAPACITY];
    let mut length = 0usize;
    let mut cursor = *at;

    let mut counter = 0usize;
    loop {
        let c = byte_at(pattern, cursor);
        cursor += 1;
        if counter >= KEYWORD_CAPACITY {
            return false;
        }
        if seen_colon {
            // CURLFNM_PKW_DDOT: the only byte that may follow the `:` is `]`.
            if c != b']' {
                return false;
            }
            break;
        }
        // CURLFNM_PKW_INIT.
        if is_lower(c) {
            keyword[length] = c;
            length += 1;
        } else if c == b':' {
            seen_colon = true;
        } else {
            // A NUL arrives here too, so an unterminated keyword fails rather
            // than reading on.
            return false;
        }
        counter += 1;
    }

    // The C's `strcmp` chain (`:99-120`), in its order. Order cannot change the
    // outcome of an exact comparison; it is preserved so the two read alike.
    // `keyword` is zero-filled and the body admits only lower-case letters, so
    // the C's NUL-terminated view of the buffer is exactly this prefix.
    #[rustfmt::skip]
    let class = match &keyword[..length] {
        b"digit"  => PosixClass::Digit,
        b"alnum"  => PosixClass::Alnum,
        b"alpha"  => PosixClass::Alpha,
        b"xdigit" => PosixClass::Xdigit,
        b"print"  => PosixClass::Print,
        b"graph"  => PosixClass::Graph,
        b"space"  => PosixClass::Space,
        b"blank"  => PosixClass::Blank,
        b"upper"  => PosixClass::Upper,
        b"lower"  => PosixClass::Lower,
        // An unknown keyword is a syntax error. Through the caller that
        // degrades to "treat `[` as a literal", which is why `[[:foo:]]`
        // matches the two-byte string `f]` -- `unit1307.c:187`.
        _ => return false,
    };

    *at = cursor;
    set.add_class(class);
    true
}

/// Adds one literal byte, or one range, to `set`.
///
/// Supersedes `setcharorrange` (`lib/curl_fnmatch.c:137-156`). The quirks below
/// are the reason `[a-zA-Z0-9]` behaves as the header advertises and `[A-z]`
/// does not span the punctuation between `Z` and `a`:
///
/// * A range is recognised only when the START byte is alphanumeric, and only
///   when the byte after it is `-`.
/// * Both endpoints must be in the SAME [`CharClass`], and each intermediate
///   byte is added only if it too is in that class. The C's own comment at
///   `:151` explains why: "Chars in class may be not consecutive."
/// * The end byte must not be below the start byte. A reversed range is not an
///   error; it degrades into separate literals.
/// * A backslash before the end byte is honoured, so `[a-\c]` is the range
///   `a`..=`c`.
/// * **The caller's cursor advances by exactly one byte unless the range
///   parsed successfully.** The C's `*pp = p` at `:153` sits inside the success
///   branch, which is what makes a malformed range decay into literals instead
///   of failing: the `-` and the end byte are then re-read as ordinary
///   members.
fn setcharorrange(pattern: &[u8], at: &mut usize, set: &mut CharSet) {
    // `const unsigned char *p = (*pp)++;` -- the local keeps the old position
    // and the caller's cursor moves on by one, unconditionally.
    let start = *at;
    *at += 1;

    // `unsigned char c = *p++;`
    let mut c = byte_at(pattern, start);
    set.add_byte(c);

    // `if(ISALNUM(c) && *p++ == '-')`. The C's `&&` short-circuits, so when the
    // start byte is not alphanumeric the `-` is never even read.
    if !is_alnum(c) || byte_at(pattern, start + 1) != b'-' {
        return;
    }

    let cc = charclass(c);
    let mut cursor = start + 2;
    let mut endrange = byte_at(pattern, cursor);
    cursor += 1;
    if endrange == b'\\' {
        endrange = byte_at(pattern, cursor);
        cursor += 1;
    }

    if endrange < c || charclass(endrange) != cc {
        return;
    }

    // `while(c++ != endrange) if(charclass(c) == cc) charset[c] = 1;`
    //
    // The comparison uses the value BEFORE the increment and the body the value
    // after, so the bytes added are `c + 1` through `endrange` inclusive, and
    // the start byte itself was already added above. `endrange >= c` is
    // established, so the counter reaches `endrange` exactly and cannot
    // overflow.
    while c != endrange {
        c += 1;
        if charclass(c) == cc {
            set.add_byte(c);
        }
    }
    *at = cursor;
}

/// Parses a whole bracket expression.
///
/// Supersedes `setcharset` (`lib/curl_fnmatch.c:159-249`). `at` enters pointing
/// just past the opening `[` and, on success, leaves pointing AT the `]` that
/// closed the expression -- the C never advances over it, which is why its
/// caller resumes at `pp + 1` (`:331`).
///
/// `Some` is the C's `SETCHARSET_OK` and `None` its `SETCHARSET_FAIL`.
/// Returning the set rather than filling a caller-owned buffer is what makes
/// "a failed parse yields no set" structural: the C's caller keeps a separate
/// cursor for the same reason, and simply discards it (`:298`). On failure `at`
/// is left wherever the scan stopped, which is harmless for exactly that
/// reason.
///
/// The state machine is `setcharset_state` (`:48-52`) and its three states are
/// transcribed branch for branch. The two non-default states exist only to
/// handle a `]` that appears FIRST, where POSIX makes it a literal member
/// rather than the terminator.
fn setcharset(pattern: &[u8], at: &mut usize) -> Option<CharSet> {
    // `CURLFNM_SCHS_DEFAULT`, `_RIGHTBR` and `_RIGHTBRLEFTBR` -- the second is
    // entered only after a leading literal `]`, and the third only after a `[`
    // that followed it.
    enum State {
        Default,
        RightBr,
        RightBrLeftBr,
    }

    let mut state = State::Default;
    let mut something_found = false;
    // `memset(charset, 0, CURLFNM_CHSET_SIZE)` at `:165`, which the C needs
    // because `loop` reuses one array across every bracket expression in a
    // pattern. Constructing the value here makes the clear unskippable.
    let mut set = CharSet::new();

    loop {
        let c = byte_at(pattern, *at);
        if c == 0 {
            // `:168-169` -- an unterminated bracket expression, at any point in
            // any state.
            return None;
        }

        match state {
            State::Default => {
                if c == b']' {
                    if something_found {
                        // The expression is complete, and the cursor stays on
                        // the `]`.
                        return Some(set);
                    }
                    // A LEADING `]` is a literal member.
                    something_found = true;
                    state = State::RightBr;
                    set.add_byte(c);
                    *at += 1;
                } else if c == b'[' {
                    // Look ahead for `[:`. `probe` is a separate cursor so that
                    // a rejected keyword leaves the real one untouched, exactly
                    // as the C's local `pp` does at `:182`.
                    let mut probe = *at + 1;
                    let colon = byte_at(pattern, probe);
                    probe += 1;
                    if colon == b':'
                        && parsekeyword(pattern, &mut probe, &mut set)
                    {
                        *at = probe;
                    } else {
                        // Not a class: the `[` is an ordinary member.
                        set.add_byte(c);
                        *at += 1;
                    }
                    something_found = true;
                } else if c == b'^' || c == b'!' {
                    // Three-way, and the middle arm is easy to miss: a SECOND
                    // negation character is taken as a literal, because the
                    // flag is already set and nothing else has been found. So
                    // `[!!x]` negates once and then matches a literal `!` --
                    // measured, and asserted in the tests.
                    if !something_found {
                        if set.negate {
                            set.add_byte(c);
                            something_found = true;
                        } else {
                            set.negate = true;
                        }
                    } else {
                        set.add_byte(c);
                    }
                    *at += 1;
                } else if c == b'\\' {
                    // `c = *(++(*p));` -- the cursor moves FIRST, then the
                    // escaped byte is read.
                    *at += 1;
                    if byte_at(pattern, *at) != 0 {
                        setcharorrange(pattern, at, &mut set);
                    } else {
                        // A backslash at the very end of the pattern. The C
                        // records a literal backslash here (`:210`) and the
                        // NEXT iteration then reads the terminator and fails,
                        // so the flag can never influence a result: `[\` is a
                        // non-match, measured against the extracted C. The
                        // assignment is kept because the transcription is
                        // branch for branch, not outcome for outcome.
                        set.add_byte(b'\\');
                    }
                    something_found = true;
                } else {
                    setcharorrange(pattern, at, &mut set);
                    something_found = true;
                }
            }
            State::RightBr => {
                if c == b'[' {
                    state = State::RightBrLeftBr;
                    set.add_byte(c);
                    *at += 1;
                } else if c == b']' {
                    return Some(set);
                } else if is_print(c) {
                    set.add_byte(c);
                    *at += 1;
                    state = State::Default;
                } else {
                    // The C reaches this by `goto fail` rather than returning
                    // directly, and says why at `:233-235`: it avoids a
                    // nonsense "statement not reached" warning from the Solaris
                    // compiler at the foot of the function. The behaviour is a
                    // plain failure, and that is what is written here.
                    return None;
                }
            }
            State::RightBrLeftBr => {
                if c == b']' {
                    return Some(set);
                }
                state = State::Default;
                set.add_byte(c);
                *at += 1;
            }
        }
    }
}

/// The order in which a bracket expression's class flags are consulted.
///
/// This is the `else if` chain of `lib/curl_fnmatch.c:305-324`, as data. **The
/// order is significant and the chain is not a set of independent tests:** only
/// the FIRST flag that is set is consulted, so an expression naming two classes
/// silently ignores the second. `[[:alnum:][:space:]]` therefore does NOT match
/// a space -- `alnum` wins the chain and answers no -- which is measurably
/// different from the `||` of every flag that a reader might assume.
///
/// Written as a table for two reasons. It keeps that ordering visible as the
/// single thing it is, so a later edit cannot quietly turn the chain into a
/// disjunction; and the `space` and `blank` rows have identical predicates, so
/// an `if`/`else if` chain would draw `clippy::if_same_then_else` and invite
/// exactly the collapse that would erase the quirk below.
///
/// **`space` is tested with `ISBLANK`, not `ISSPACE`** (`:315-316`). That is
/// almost certainly an upstream oversight -- `[[:space:]]` consequently matches
/// only a space and a tab, never a newline, carriage return, vertical tab or
/// form feed -- and it is frozen behaviour under AAP 0.8.1. Do not "fix" it.
/// Both flags are kept even though they now behave identically, so that the
/// parse side stays faithful to the ten documented keywords.
#[rustfmt::skip]
const CASCADE: [(PosixClass, fn(u8) -> bool); CLASS_COUNT] = [
    (PosixClass::Alnum,  is_alnum),   // CURLFNM_ALNUM  -- :305-306
    (PosixClass::Alpha,  is_alpha),   // CURLFNM_ALPHA  -- :307-308
    (PosixClass::Digit,  is_digit),   // CURLFNM_DIGIT  -- :309-310
    (PosixClass::Xdigit, is_xdigit),  // CURLFNM_XDIGIT -- :311-312
    (PosixClass::Print,  is_print),   // CURLFNM_PRINT  -- :313-314
    (PosixClass::Space,  is_blank),   // CURLFNM_SPACE  -- :315-316  ISBLANK!
    (PosixClass::Upper,  is_upper),   // CURLFNM_UPPER  -- :317-318
    (PosixClass::Lower,  is_lower),   // CURLFNM_LOWER  -- :319-320
    (PosixClass::Blank,  is_blank),   // CURLFNM_BLANK  -- :321-322
    (PosixClass::Graph,  is_graph),   // CURLFNM_GRAPH  -- :323-324
];

/// Whether `byte` is a member of `set`.
///
/// Supersedes the decision cascade of `lib/curl_fnmatch.c:300-327`: a literal
/// hit wins outright, otherwise the first class flag in [`CASCADE`] order
/// decides, and negation inverts whatever came out.
fn matches_set(set: &CharSet, byte: u8) -> bool {
    let found = if set.has_byte(byte) {
        true
    } else {
        // `.find` is the `else if` chain: the first row whose flag is set
        // supplies the answer, and a set naming no class at all answers no.
        CASCADE
            .iter()
            .find(|(class, _)| set.has_class(*class))
            .is_some_and(|(_, predicate)| predicate(byte))
    };

    // `:326-327` -- after the cascade, never inside it.
    if set.negate {
        !found
    } else {
        found
    }
}

/// The recursion budget a comparison starts with.
///
/// Two, from `lib/curl_fnmatch.c:357`. Not a tuning knob: see the module
/// documentation for what spending it does to a pattern with three effective
/// stars, and why that is reproduced rather than corrected.
const MAX_STARS: u32 = 2;

/// The matcher.
///
/// Supersedes `loop` (`lib/curl_fnmatch.c:251-344`), transcribed arm for arm.
/// `maxstars` is the remaining recursion budget; the only recursive call is the
/// star scan and it passes a strictly smaller one, so the depth is at most
/// `MAX_STARS + 1` frames -- three -- however long the pattern is. The scan
/// itself is a loop, and the C's own `charset` array -- declared once per frame
/// at `:256` and cleared per bracket expression -- becomes a value returned by
/// [`setcharset`].
fn match_loop(pattern: &[u8], string: &[u8], maxstars: u32) -> FnMatch {
    let mut p = 0usize;
    let mut s = 0usize;

    loop {
        match byte_at(pattern, p) {
            b'*' => {
                // `:263-264` -- the budget is spent, so this star is not even
                // attempted. A pattern that would match is reported as a
                // non-match here, deliberately.
                if maxstars == 0 {
                    return FnMatch::NoMatch;
                }

                // `:265-276` -- regroup consecutive stars and question marks,
                // which the C explains is sound because `*?*?*` can be written
                // `??*`. Each question mark consumed here eats one byte of the
                // string and fails if there is none left.
                loop {
                    p += 1;
                    let next = byte_at(pattern, p);
                    if next == 0 {
                        // The pattern ended on the star: it matches the rest of
                        // the string, whatever is left of it.
                        return FnMatch::Match;
                    }
                    if next == b'?' {
                        if byte_at(string, s) == 0 {
                            return FnMatch::NoMatch;
                        }
                        s += 1;
                    } else if next != b'*' {
                        break;
                    }
                }

                // `:277-282` -- try the pattern suffix at each remaining
                // position. `for(maxstars--; *s; s++)` spends the budget ONCE,
                // before the scan, not once per recursion; and the scan visits
                // only positions holding a byte, so the suffix is never tried
                // against an empty remainder.
                let budget = maxstars - 1;
                let mut scan = s;
                while byte_at(string, scan) != 0 {
                    let outcome =
                        match_loop(&pattern[p..], &string[scan..], budget);
                    if outcome == FnMatch::Match {
                        return FnMatch::Match;
                    }
                    scan += 1;
                }
                return FnMatch::NoMatch;
            }
            b'?' => {
                // `:283-288` -- exactly one byte, not one Unicode scalar value.
                if byte_at(string, s) == 0 {
                    return FnMatch::NoMatch;
                }
                s += 1;
                p += 1;
            }
            0 => {
                // `:289-290` -- the pattern is exhausted, so this is a match
                // only if the string is too.
                return if byte_at(string, s) == 0 {
                    FnMatch::Match
                } else {
                    FnMatch::NoMatch
                };
            }
            b'\\' => {
                // `:291-296`. `if(p[1]) p++;` -- a backslash at the very END of
                // the pattern is NOT advanced over, so the comparison below
                // tests the backslash against itself and a lone `\` matches a
                // lone `\`. That is `unit1307.c:225`, where curl's own matcher
                // answers match and the platform `fnmatch(3)` answers no.
                if byte_at(pattern, p + 1) != 0 {
                    p += 1;
                }
                let expected = byte_at(pattern, p);
                let actual = byte_at(string, s);
                s += 1;
                p += 1;
                if actual != expected {
                    return FnMatch::NoMatch;
                }
            }
            b'[' => {
                // `:297-336`. The cursor handed to the parser is a COPY, so a
                // syntax error leaves `p` untouched -- and a syntax error is a
                // MISMATCH, not a failure: `("[", "[")` is a non-match, which
                // is `unit1307.c:87` and the most surprising branch in the
                // function.
                let mut probe = p + 1;
                let Some(set) = setcharset(pattern, &mut probe) else {
                    return FnMatch::NoMatch;
                };

                // `:301-302` -- an empty remainder never matches a bracket
                // expression, not even a negated one, and this test comes
                // BEFORE the set is consulted.
                let byte = byte_at(string, s);
                if byte == 0 || !matches_set(&set, byte) {
                    return FnMatch::NoMatch;
                }

                // `:331-332` -- the parser stopped on the closing `]`, so the
                // `+ 1` steps over it.
                p = probe + 1;
                s += 1;
            }
            expected => {
                // `:338-341` -- an exact byte comparison. No case folding: this
                // matcher is case-sensitive and the C never sets
                // `FNM_CASEFOLD`.
                if byte_at(string, s) != expected {
                    return FnMatch::NoMatch;
                }
                p += 1;
                s += 1;
            }
        }
    }
}

/// Matches `string` against the wildcard `pattern`.
///
/// Supersedes `Curl_fnmatch` (`lib/curl_fnmatch.c:349-358`), the default
/// comparator for a wildcard FTP transfer. See the module documentation for the
/// pattern syntax, for the two frozen quirks the C carries, and for why this is
/// a port of curl's own matcher rather than of the `fnmatch(3)` shim beside it.
///
/// The C's first parameter, `void *ptr`, exists only to satisfy the
/// `curl_fnmatch_callback` prototype and is unused (`:351-352`), so it has no
/// counterpart here; the comparator dispatch that needs it lives with the FTP
/// listing parser. The C's null-pointer check (`:353-355`) has none either: a
/// slice cannot be null, and an EMPTY slice is a different thing, matched
/// normally. [`FnMatch::Fail`] is therefore never returned.
///
/// # Examples
///
/// ```text
/// fnmatch(b"*.txt",       b"text.txt")  == FnMatch::Match
/// fnmatch(b"??.txt",      b"a99.txt")   == FnMatch::NoMatch
/// fnmatch(b"[a-bA-Z9]*",  b"Zero")      == FnMatch::Match
/// fnmatch(b"[[:digit:]]", b"7")         == FnMatch::Match
/// ```
// Unreferenced until the FTP listing parser lands; see the note on [`FnMatch`].
#[allow(dead_code)]
pub(crate) fn fnmatch(pattern: &[u8], string: &[u8]) -> FnMatch {
    match_loop(pattern, string, MAX_STARS)
}

// ---------------------------------------------------------------------------
// The relocated unit test
// ---------------------------------------------------------------------------

/// `tests/unit/unit1307.c`, relocated, plus the cases that pin the quirks.
///
/// AAP 0.8.7 records that `tests/unit/*.c` cannot link against a Rust
/// `staticlib` -- a `pub(crate)` item is genuinely absent from the symbol
/// table rather than merely hidden -- and that the coverage of those C
/// programs is relocated into `#[cfg(test)]` modules such as this one.
/// `unit1307.c` is the only unit test that covers `Curl_fnmatch`, and all
/// 157 of its rows are reproduced here: 155 inline in [`TABLE`], and the
/// 200-byte and 103-byte pathological rows as dedicated tests, because byte
/// runs that long read better built than quoted.
///
/// Every row is taken at its *un-shifted* `SYSTEM_CUSTOM` expectation
/// (`tests/unit/unit1307.c:265-320`), which is the answer curl's own matcher
/// gives and therefore the answer this port must give. The eleven rows whose
/// declared Linux or macOS expectation differs carry a comment naming that
/// difference, so a later reader can see it is known and deliberate rather
/// than wonder whether a row was mistranscribed.
///
/// The expectations of the targeted tests below were measured, not reasoned
/// about: `lib/curl_fnmatch.c`'s `#ifndef HAVE_FNMATCH` branch was compiled
/// as a standalone oracle and queried for each one, so every assertion in
/// this module is the C's own answer to the same question.
#[cfg(test)]
mod tests {
    use super::FnMatch::{Fail, Match, NoMatch};
    use super::{
        charclass, fnmatch, is_alnum, is_alpha, is_blank, is_digit, is_graph,
        is_lower, is_lowprint, is_print, is_upper, is_xdigit, CharClass,
        FnMatch, MAX_STARS,
    };

    /// Renders a pattern or a string for an assertion message.
    ///
    /// Lossy on purpose: the corpus carries bytes that are not valid UTF-8
    /// (`unit1307.c:130` feeds a bare `0xFF`), and a mangled character in a
    /// failure message is better than no message.
    fn show(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// The 155 inline rows of `tests/unit/unit1307.c:68-262`.
    ///
    /// The C's own section comments are kept as landmarks, and its
    /// duplicated rows are kept duplicated rather than tidied: `[[[[]`
    /// against `[` appears at :93 and :94, `[[:print:]]` against `\x08` at
    /// :174 and :175, and the empty pattern against the empty string at :217
    /// and :259. This table is the specification for this module, so it is
    /// transcribed, not curated.
    #[rustfmt::skip]
    const TABLE: &[(&[u8], &[u8], FnMatch)] = &[
        // brackets syntax -- unit1307.c:77
        // unit1307.c:78 is ported by its own test, since
        // 200 bytes do not belong in a literal here:
        // `the_bracket_repetition_row_exhausts_the_budget`.
        (b"\\[", b"[", Match),
        // unit1307.c:87 diverges: linux Match, mac Fail
        (b"[", b"[", NoMatch),
        // unit1307.c:88 diverges: linux Match, mac Fail
        (b"[]", b"[]", NoMatch),
        (b"[][]", b"[", Match),
        (b"[][]", b"]", Match),
        (b"[[]", b"[", Match),
        (b"[[[]", b"[", Match),
        (b"[[[[]", b"[", Match),
        (b"[[[[]", b"[", Match),
        (b"[][[]", b"]", Match),
        (b"[][[[]", b"[", Match),
        (b"[[]", b"]", NoMatch),
        (b"[a@]", b"a", Match),
        (b"[a-z]", b"a", Match),
        (b"[a-z]", b"A", NoMatch),
        (b"?[a-z]", b"?Z", NoMatch),
        (b"[A-Z]", b"C", Match),
        (b"[A-Z]", b"c", NoMatch),
        (b"[0-9]", b"7", Match),
        (b"[7-8]", b"7", Match),
        (b"[7-]", b"7", Match),
        (b"[7-]", b"-", Match),
        (b"[7-]", b"[", NoMatch),
        (b"[a-bA-F]", b"F", Match),
        (b"[a-bA-B9]", b"9", Match),
        (b"[a-bA-B98]", b"8", Match),
        (b"[a-bA-B98]", b"C", NoMatch),
        (b"[a-bA-Z9]", b"F", Match),
        (b"[a-bA-Z9]ero*", b"Zero chance.", Match),
        (b"S[a-][x]opho*", b"Saxophone", Match),
        (b"S[a-][x]opho*", b"SaXophone", NoMatch),
        (b"S[a-][x]*.txt", b"S-x.txt", Match),
        (b"[\\a-\\b]", b"a", Match),
        (b"[\\a-\\b]", b"b", Match),
        (b"[?*[][?*[][?*[]", b"?*[", Match),
        (b"[][?*-]", b"]", Match),
        (b"[][?*-]", b"[", Match),
        (b"[][?*-]", b"?", Match),
        (b"[][?*-]", b"*", Match),
        (b"[][?*-]", b"-", Match),
        (b"[]?*-]", b"-", Match),
        // unit1307.c:130 diverges: linux Fail, mac Fail
        (b"[\xff]", b"\xff", Match),
        (b"?/b/c", b"a/b/c", Match),
        (b"^_{}~", b"^_{}~", Match),
        (b"!#%+,-./01234567889", b"!#%+,-./01234567889", Match),
        (b"PQRSTUVWXYZ]abcdefg", b"PQRSTUVWXYZ]abcdefg", Match),
        (b":;=@ABCDEFGHIJKLMNO", b":;=@ABCDEFGHIJKLMNO", Match),
        // negate -- unit1307.c:137
        (b"[!a]", b"b", Match),
        (b"[!a]", b"a", NoMatch),
        (b"[^a]", b"b", Match),
        (b"[^a]", b"a", NoMatch),
        (b"[^a-z0-9A-Z]", b"a", NoMatch),
        (b"[^a-z0-9A-Z]", b"-", Match),
        (b"curl[!a-z]lib", b"curl lib", Match),
        (b"curl[! ]lib", b"curl lib", NoMatch),
        (b"[! ][ ]", b"  ", NoMatch),
        (b"[! ][ ]", b"a ", Match),
        (b"*[^a].t?t", b"a.txt", NoMatch),
        (b"*[^a].t?t", b"ca.txt", NoMatch),
        (b"*[^a].t?t", b"ac.txt", Match),
        (b"*[^a]", b"", NoMatch),
        // unit1307.c:152 diverges: linux Fail
        (b"[!\xff]", b"", NoMatch),
        // unit1307.c:153 diverges: linux Fail, mac Fail
        (b"[!\xff]", b"\xff", NoMatch),
        // unit1307.c:154 diverges: linux Fail, mac Fail
        (b"[!\xff]", b"a", Match),
        (b"[!?*[]", b"?", NoMatch),
        (b"[!!]", b"!", NoMatch),
        (b"[!!]", b"x", Match),
        (b"[[:alpha:]]", b"a", Match),
        (b"[[:alpha:]]", b"9", NoMatch),
        (b"[[:alnum:]]", b"a", Match),
        (b"[[:alnum:]]", b"[", NoMatch),
        (b"[[:alnum:]]", b"]", NoMatch),
        (b"[[:alnum:]]", b"9", Match),
        (b"[[:digit:]]", b"9", Match),
        (b"[[:xdigit:]]", b"9", Match),
        (b"[[:xdigit:]]", b"F", Match),
        (b"[[:xdigit:]]", b"G", NoMatch),
        (b"[[:upper:]]", b"U", Match),
        (b"[[:upper:]]", b"u", NoMatch),
        (b"[[:lower:]]", b"l", Match),
        (b"[[:lower:]]", b"L", NoMatch),
        (b"[[:print:]]", b"L", Match),
        (b"[[:print:]]", b"\x08", NoMatch),
        (b"[[:print:]]", b"\x08", NoMatch),
        (b"[[:space:]]", b" ", Match),
        (b"[[:space:]]", b"x", NoMatch),
        (b"[[:graph:]]", b" ", NoMatch),
        (b"[[:graph:]]", b"x", Match),
        (b"[[:blank:]]", b"\t", Match),
        (b"[[:blank:]]", b" ", Match),
        (b"[[:blank:]]", b"\r", NoMatch),
        (b"[^[:blank:]]", b"\t", NoMatch),
        (b"[^[:print:]]", b"\x08", Match),
        (b"[[:lower:]][[:lower:]]", b"ll", Match),
        // unit1307.c:186 diverges: mac Fail
        (b"[[:foo:]]", b"bar", NoMatch),
        // unit1307.c:187 diverges: linux NoMatch, mac Fail
        (b"[[:foo:]]", b"f]", Match),
        (b"curl[[:blank:]];-)", b"curl ;-)", Match),
        (b"*[[:blank:]]*", b" ", Match),
        (b"*[[:blank:]]*", b"", NoMatch),
        (b"*[[:blank:]]*", b"hi, im_Pavel", Match),
        // common using -- unit1307.c:194
        (b"Filename.dat", b"Filename.dat", Match),
        (b"*curl*", b"lets use curl!!", Match),
        (b"filename.txt", b"filename.dat", NoMatch),
        (b"*.txt", b"text.txt", Match),
        (b"*.txt", b"a.txt", Match),
        (b"*.txt", b".txt", Match),
        (b"*.txt", b"txt", NoMatch),
        (b"??.txt", b"99.txt", Match),
        (b"??.txt", b"a99.txt", NoMatch),
        (b"?.???", b"a.txt", Match),
        (b"*.???", b"somefile.dat", Match),
        (b"*.???", b"photo.jpeg", NoMatch),
        (b".*", b".htaccess", Match),
        (b".*", b".", Match),
        (b".*", b"..", Match),
        // many stars => one star -- unit1307.c:211
        (b"**.txt", b"text.txt", Match),
        (b"***.txt", b"t.txt", Match),
        (b"****.txt", b".txt", Match),
        // empty string or pattern -- unit1307.c:216
        (b"", b"", Match),
        (b"", b"hello", NoMatch),
        (b"file", b"", NoMatch),
        (b"?", b"", NoMatch),
        (b"*", b"", Match),
        (b"x", b"", NoMatch),
        // backslash -- unit1307.c:224
        // unit1307.c:225 diverges: linux NoMatch
        (b"\\", b"\\", Match),
        (b"\\\\", b"\\", Match),
        (b"\\\\", b"\\\\", NoMatch),
        (b"\\?", b"?", Match),
        (b"\\*", b"*", Match),
        (b"?.txt", b"?.txt", Match),
        (b"*.txt", b"*.txt", Match),
        (b"\\?.txt", b"?.txt", Match),
        (b"\\*.txt", b"*.txt", Match),
        (b"\\?.txt", b"x.txt", NoMatch),
        (b"\\*.txt", b"x.txt", NoMatch),
        (b"\\*\\\\.txt", b"*\\.txt", Match),
        (b"*\\**\\?*\\\\*", b"cc*cc?cccc", NoMatch),
        (b"*\\?*\\**", b"cc?cc", NoMatch),
        (b"\\\"\\$\\&\\'\\(\\)", b"\"$&'()", Match),
        (b"\\*\\?\\[\\\\\\`\\|", b"*?[\\`|", Match),
        (b"[\\a\\b]c", b"ac", Match),
        (b"[\\a\\b]c", b"bc", Match),
        (b"[\\a\\b]d", b"bc", NoMatch),
        (b"[a-bA-B\\?]", b"?", Match),
        (b"cu[a-ab-b\\r]l", b"curl", Match),
        (b"[\\a-z]", b"c", Match),
        (b"?*?*?.*?*", b"abc.c", Match),
        (b"?*?*?.*?*", b"abcc", NoMatch),
        (b"?*?*?.*?*", b"abc.", NoMatch),
        (b"?*?*?.*?*", b"abc.c++", Match),
        (b"?*?*?.*?*", b"abcdef.c++", Match),
        (b"?*?*?.?", b"abcdef.c", Match),
        (b"?*?*?.?", b"abcdef.cd", NoMatch),
        // U+00E4, Latin small letter a with diaeresis, as
        // its two UTF-8 bytes -- unit1307.c:256-257.
        (b"Lindm\xc3\xa4tarv", b"Lindm\xc3\xa4tarv", Match),
        (b"", b"", Match),
        // unit1307.c:260 is ported by its own test, for the
        // same reason: `the_long_pathological_row_is_a_non_match`.
    ];

    #[test]
    fn the_relocated_unit1307_table_matches_curls_own_matcher() {
        for (index, &(pattern, string, expected)) in TABLE.iter().enumerate() {
            assert_eq!(
                fnmatch(pattern, string),
                expected,
                "row {index}: pattern {:?} against string {:?}",
                show(pattern),
                show(string)
            );
        }
    }

    #[test]
    fn the_relocated_table_is_the_whole_c_table() {
        // 157 rows at unit1307.c:68-262, of which two are ported as their
        // own tests immediately below.
        assert_eq!(TABLE.len() + 2, 157);
    }

    /// `unit1307.c:78`: 200 bytes of `[` repetition against 200 bytes of `[`.
    ///
    /// The row exists to exercise the star budget against a pattern that
    /// would otherwise backtrack catastrophically. It diverges: macOS
    /// `fnmatch(3)` is declared to answer `FAIL`, curl's own matcher and
    /// Linux both answer `NOMATCH`.
    #[test]
    fn the_bracket_repetition_row_exhausts_the_star_budget() {
        let mut pattern = Vec::new();
        pattern.extend_from_slice(b"*[*");
        pattern.resize(pattern.len() + 174, b'[');
        pattern.extend_from_slice(b"\x01\x7f");
        pattern.resize(pattern.len() + 21, b'[');
        assert_eq!(pattern.len(), 200);

        let string = [b'['; 200];
        assert_eq!(fnmatch(&pattern, &string), NoMatch);
    }

    /// `unit1307.c:260`: 103 bytes of nested brackets and stars against `a`.
    ///
    /// A fuzzer-shaped row. It diverges: Linux `fnmatch(3)` is declared to
    /// answer `FAIL`, curl's own matcher and macOS both answer `NOMATCH`.
    #[test]
    fn the_long_pathological_row_is_a_non_match() {
        let mut pattern = Vec::new();
        pattern.extend_from_slice(b"**]*[*[\x13]**[*\x13)]*]*[**[*\x13~r-]*]");
        pattern.extend_from_slice(b"**[.*]*[");
        pattern.resize(pattern.len() + 29, 0xe3);
        pattern.extend_from_slice(b"*[\x13]**[*\x13)]*]*[*[\x13]*[~r]*]*\xba");
        pattern.extend_from_slice(b"\x13\xa6~b-]*");
        assert_eq!(pattern.len(), 103);

        assert_eq!(fnmatch(&pattern, b"a"), NoMatch);
    }

    // -- the frozen behaviours ------------------------------------------

    /// The star budget starts at 2 and a third effective star is refused.
    ///
    /// `lib/curl_fnmatch.c:357` passes 2, and :265 returns `NOMATCH` the
    /// moment the budget is gone -- before any scanning. A pattern with
    /// three effective stars can therefore be reported as a non-match even
    /// when it plainly matches. This is curl's catastrophic-backtracking
    /// guard and it is frozen behaviour under AAP 0.8.1: it is not to be
    /// raised, removed, or worked around with memoisation.
    #[test]
    fn the_third_effective_star_is_refused() {
        assert_eq!(MAX_STARS, 2);

        // Two stars backtrack normally.
        assert_eq!(fnmatch(b"a*b*c", b"aXbYc"), Match);
        assert_eq!(fnmatch(b"*a*b", b"aXb"), Match);

        // Three do not -- and note the second row, where the string needs no
        // backtracking at all and is still refused, because the budget is
        // spent before the pattern suffix is examined.
        assert_eq!(fnmatch(b"*a*b*c", b"aXbYc"), NoMatch);
        assert_eq!(fnmatch(b"*a*b*c", b"abc"), NoMatch);
        assert_eq!(fnmatch(b"*x*y*z*", b"axbycz"), NoMatch);
        assert_eq!(fnmatch(b"a*b*c*d", b"aWbXcYd"), NoMatch);

        // Adjacent stars are not "effective": the regrouping loop at
        // lib/curl_fnmatch.c:268-275 collapses a run of them into one, and
        // the run costs a single unit of budget however long it is.
        assert_eq!(fnmatch(b"*", b"anything"), Match);
        assert_eq!(fnmatch(b"**", b"anything"), Match);
        assert_eq!(fnmatch(b"***", b"anything"), Match);
    }

    /// Consecutive stars and question marks regroup.
    ///
    /// "`'*?*?*'` can be expressed as `'??*'`" -- `lib/curl_fnmatch.c:267`.
    /// Each `?` consumed while regrouping advances the string by one byte
    /// and fails if the string is exhausted (:270-272), which is why the
    /// two forms agree on every input rather than merely on long ones.
    #[test]
    fn consecutive_stars_and_question_marks_regroup() {
        let strings: [&[u8]; 6] = [b"", b"a", b"ab", b"abc", b"abcdef", b"?"];
        for string in strings {
            assert_eq!(
                fnmatch(b"*?*?*", string),
                fnmatch(b"??*", string),
                "regrouping disagrees on {:?}",
                show(string)
            );
        }
        assert_eq!(fnmatch(b"*?*?*", b"a"), NoMatch);
        assert_eq!(fnmatch(b"*?*?*", b"ab"), Match);
        assert_eq!(fnmatch(b"?*?*?", b"abc"), Match);
        assert_eq!(fnmatch(b"???*", b"abc"), Match);
    }

    /// A trailing backslash matches a literal backslash.
    ///
    /// `lib/curl_fnmatch.c:284` advances past the backslash only when a byte
    /// follows it (`if(p[1]) p++;`), so at the end of a pattern the cursor
    /// still points at the backslash and the comparison on :285 tests it
    /// against itself. `unit1307.c:225` records that Linux `fnmatch(3)`
    /// answers `NOMATCH` here; curl's own matcher answers `MATCH`, and that
    /// is the behaviour this port reproduces.
    #[test]
    fn a_trailing_backslash_matches_a_literal_backslash() {
        assert_eq!(fnmatch(b"\\", b"\\"), Match);
        assert_eq!(fnmatch(b"a\\", b"a\\"), Match);
        assert_eq!(fnmatch(b"\\\\", b"\\"), Match);
        assert_eq!(fnmatch(b"\\", b"a"), NoMatch);
        assert_eq!(fnmatch(b"\\", b""), NoMatch);
        assert_eq!(fnmatch(b"a\\", b"ab"), NoMatch);
    }

    /// A syntax error inside `[...]` is a non-match, never a failure.
    ///
    /// `lib/curl_fnmatch.c:333` returns `CURL_FNMATCH_NOMATCH` when
    /// `setcharset` refuses the expression, and `pp` is deliberately a copy
    /// of `p + 1` (:296) so the cursor survives the failed parse. This is
    /// why `[` against `[` is a non-match rather than the literal match a
    /// reader might expect -- and `unit1307.c:87-88` records that Linux
    /// `fnmatch(3)` does answer `MATCH` and macOS answers `FAIL`.
    #[test]
    fn a_bracket_syntax_error_is_a_non_match_not_a_failure() {
        let cases: [(&[u8], &[u8]); 9] = [
            (b"[", b"["),
            (b"[", b"a"),
            (b"[", b""),
            (b"[abc", b"a"),
            (b"[a-", b"a"),
            (b"[]", b"[]"),
            (b"[[:", b"x"),
            (b"[!", b"a"),
            (b"x[", b"x["),
        ];
        for (pattern, string) in cases {
            assert_eq!(
                fnmatch(pattern, string),
                NoMatch,
                "pattern {:?} against string {:?}",
                show(pattern),
                show(string)
            );
        }
    }

    /// `[[:space:]]` matches only space and tab.
    ///
    /// `lib/curl_fnmatch.c:315-316` tests `CURLFNM_SPACE` with `ISBLANK`
    /// rather than `ISSPACE`, so the carriage return, line feed, vertical
    /// tab and form feed that `lib/curl_ctype.h:46` would admit are all
    /// non-matches. This is almost certainly an upstream defect. It is
    /// frozen behaviour under AAP 0.8.1 and must not be "fixed": the
    /// observable behaviour is the contract, defect and all.
    #[test]
    fn the_space_class_is_tested_with_isblank() {
        assert_eq!(fnmatch(b"[[:space:]]", b" "), Match);
        assert_eq!(fnmatch(b"[[:space:]]", b"\t"), Match);
        for byte in [b'\n', b'\r', 0x0b, 0x0c] {
            assert_eq!(
                fnmatch(b"[[:space:]]", &[byte]),
                NoMatch,
                "byte {byte:#04x} must not match the space class"
            );
        }

        // BLANK is the same predicate, which is why the two classes are
        // indistinguishable at run time even though both flags are parsed.
        assert_eq!(fnmatch(b"[[:blank:]]", b" "), Match);
        assert_eq!(fnmatch(b"[[:blank:]]", b"\t"), Match);
        assert_eq!(fnmatch(b"[[:blank:]]", b"\n"), NoMatch);
    }

    /// Only the first class flag set in a bracket expression is consulted.
    ///
    /// `lib/curl_fnmatch.c:307-327` is an `else if` chain, not a set of
    /// independent tests, so a pattern that names two classes silently
    /// ignores the second. The chain order is fixed by the code, not by the
    /// pattern, which is why writing the classes the other way round changes
    /// nothing.
    #[test]
    fn only_the_first_class_flag_in_a_set_is_consulted() {
        // ALNUM (:309) precedes SPACE (:315), so the space class is never
        // reached and a space is not matched.
        assert_eq!(fnmatch(b"[[:alnum:][:space:]]", b" "), NoMatch);
        assert_eq!(fnmatch(b"[[:alnum:][:space:]]", b"a"), Match);
        assert_eq!(fnmatch(b"[[:space:][:alnum:]]", b" "), NoMatch);
        assert_eq!(fnmatch(b"[[:space:][:alnum:]]", b"a"), Match);

        // ALPHA (:311) precedes DIGIT (:312) for the same reason.
        assert_eq!(fnmatch(b"[[:digit:][:alpha:]]", b"a"), Match);
        assert_eq!(fnmatch(b"[[:digit:][:alpha:]]", b"7"), NoMatch);

        // The literal-byte test at :308 comes before every class, so a set
        // that mixes literals with a class honours both.
        assert_eq!(fnmatch(b"[x[:digit:]]", b"x"), Match);
        assert_eq!(fnmatch(b"[x[:digit:]]", b"7"), Match);
    }

    /// A range needs both endpoints in one character class.
    ///
    /// `lib/curl_fnmatch.c:146-153`: the start byte must be alphanumeric,
    /// the two endpoints must share a `char_class`, and each intermediate
    /// byte is added only if it too belongs to that class -- the C's own
    /// comment explains that "Chars in class may be not consecutive." When
    /// the range is refused the caller's cursor has advanced by exactly one
    /// byte, so the expression degrades into literals instead of failing.
    #[test]
    fn a_range_keeps_both_endpoints_in_one_character_class() {
        // `[A-z]` is not a span. 'A' is upper and 'z' is lower, so the range
        // is refused and the set is the three literals {'A', '-', 'z'}.
        assert_eq!(fnmatch(b"[A-z]", b"A"), Match);
        assert_eq!(fnmatch(b"[A-z]", b"-"), Match);
        assert_eq!(fnmatch(b"[A-z]", b"z"), Match);
        // 'Z' and 'a' are the span's would-be endpoints, '_', '[' and '^' sit
        // in the punctuation a POSIX span would have swallowed, and 'M' is an
        // interior letter. None of them is a member.
        for byte in *b"Za_[^M" {
            assert_eq!(
                fnmatch(b"[A-z]", &[byte]),
                NoMatch,
                "byte {byte:#04x} is not one of the three literals"
            );
        }

        // Within one class a range is a range.
        assert_eq!(fnmatch(b"[0-9]", b"5"), Match);
        assert_eq!(fnmatch(b"[a-f]", b"c"), Match);
        assert_eq!(fnmatch(b"[a-f]", b"g"), NoMatch);

        // A non-alphanumeric start byte is never a range start (:147), so
        // this is the literal set {0x80, '-', 0xff}.
        assert_eq!(fnmatch(b"[\x80-\xff]", b"\x90"), NoMatch);
        assert_eq!(fnmatch(b"[\x80-\xff]", b"\x80"), Match);
        assert_eq!(fnmatch(b"[\x80-\xff]", b"-"), Match);
    }

    /// A reversed range degrades to literals.
    ///
    /// `lib/curl_fnmatch.c:149` requires `endrange >= c`, so `[z-a]` is the
    /// literal set {'z', '-', 'a'} rather than an error or an empty set.
    #[test]
    fn a_reversed_range_degrades_to_literals() {
        assert_eq!(fnmatch(b"[z-a]", b"z"), Match);
        assert_eq!(fnmatch(b"[z-a]", b"-"), Match);
        assert_eq!(fnmatch(b"[z-a]", b"a"), Match);
        assert_eq!(fnmatch(b"[z-a]", b"b"), NoMatch);
    }

    /// A backslash-escaped range endpoint is honoured.
    ///
    /// `lib/curl_fnmatch.c:148` reads one byte past a `\` when it appears
    /// where the end of a range is expected.
    #[test]
    fn an_escaped_range_endpoint_is_honoured() {
        assert_eq!(fnmatch(b"[a-\\c]", b"b"), Match);
        assert_eq!(fnmatch(b"[a-\\c]", b"d"), NoMatch);
        assert_eq!(fnmatch(b"[0-\\9]", b"5"), Match);
    }

    /// Negation takes `!` or `^`, and only in the leading position.
    ///
    /// `lib/curl_fnmatch.c:196-206` is a three-way branch: the byte negates
    /// the set only when nothing has been found yet *and* the negate flag is
    /// not already set; otherwise it is a literal. `[!!x]` therefore negates
    /// once and then matches a literal `!`, which is why `x` -- a member of
    /// the negated set -- is a non-match.
    #[test]
    fn negation_takes_bang_or_caret_in_the_leading_position() {
        assert_eq!(fnmatch(b"[!abc]", b"d"), Match);
        assert_eq!(fnmatch(b"[!abc]", b"a"), NoMatch);
        assert_eq!(fnmatch(b"[^abc]", b"d"), Match);
        assert_eq!(fnmatch(b"[^abc]", b"a"), NoMatch);

        // The second '!' is a literal, so the set is {'!', 'x'}, negated.
        assert_eq!(fnmatch(b"[!!x]", b"!"), NoMatch);
        assert_eq!(fnmatch(b"[!!x]", b"x"), NoMatch);
        assert_eq!(fnmatch(b"[!!x]", b"a"), Match);
        assert_eq!(fnmatch(b"[^^x]", b"^"), NoMatch);
        assert_eq!(fnmatch(b"[^^x]", b"a"), Match);

        // Not in the leading position, '!' is an ordinary member.
        assert_eq!(fnmatch(b"[a!]", b"!"), Match);

        // An empty string never matches a bracket expression, not even a
        // negated one (lib/curl_fnmatch.c:306).
        assert_eq!(fnmatch(b"[!a]", b""), NoMatch);
    }

    /// A leading `]` is a literal, not the end of the expression.
    ///
    /// `lib/curl_fnmatch.c:180-186`: with nothing found yet, `]` is added as
    /// a member and the parser moves to its second state, where a following
    /// `]` does close the expression.
    #[test]
    fn a_leading_right_bracket_is_a_literal() {
        assert_eq!(fnmatch(b"[]]", b"]"), Match);
        assert_eq!(fnmatch(b"[]]", b"x"), NoMatch);
        assert_eq!(fnmatch(b"[]a]", b"]"), Match);
        assert_eq!(fnmatch(b"[]a]", b"a"), Match);
        assert_eq!(fnmatch(b"[]a]", b"x"), NoMatch);
        assert_eq!(fnmatch(b"[!]]", b"]"), NoMatch);
        assert_eq!(fnmatch(b"[!]]", b"x"), Match);
    }

    /// An unknown POSIX keyword degrades the `[` to a literal.
    ///
    /// `parsekeyword` returns failure for a keyword outside the ten it
    /// knows, and `lib/curl_fnmatch.c:188-194` then treats the `[` as an
    /// ordinary member instead of failing the whole expression. That is why
    /// `[[:foo:]]` matches the two-byte string `f]`: the set becomes
    /// {'[', ':', 'f', 'o'}, one member matches `f`, and the trailing `]` of
    /// the pattern matches the `]` of the string. `unit1307.c:187` records
    /// that Linux `fnmatch(3)` answers `NOMATCH` and macOS answers `FAIL`.
    #[test]
    fn an_unknown_posix_keyword_degrades_the_bracket_to_a_literal() {
        assert_eq!(fnmatch(b"[[:foo:]]", b"f]"), Match);
        assert_eq!(fnmatch(b"[[:foo:]]", b"bar"), NoMatch);
        assert_eq!(fnmatch(b"[[:foo:]]", b"["), NoMatch);

        // A missing ':' terminator fails the keyword the same way.
        assert_eq!(fnmatch(b"[[:alnum]]", b"a]"), Match);
        assert_eq!(fnmatch(b"[[:]]", b"]"), NoMatch);
    }

    /// A POSIX keyword is bounded and lower-case only.
    ///
    /// The C's buffer is ten bytes and the bound is checked before the store
    /// (`lib/curl_fnmatch.c:87-88`), while the body accepts only
    /// `ISLOWER` bytes (:96). Every over-long or wrongly-cased keyword takes
    /// the same route as an unknown one: the keyword fails, the `[` becomes
    /// a literal, and the set swallows the keyword text.
    #[test]
    fn a_posix_keyword_is_bounded_and_lower_case_only() {
        assert_eq!(fnmatch(b"[[:abcdefghij:]]", b"a]"), Match);
        assert_eq!(fnmatch(b"[[:abcdefghi:]]", b"a]"), Match);
        assert_eq!(fnmatch(b"[[:abcdefgh:]]", b"a]"), Match);

        // Upper case is refused, so the class is not recognised.
        assert_eq!(fnmatch(b"[[:ALNUM:]]", b"A"), NoMatch);
        assert_eq!(fnmatch(b"[[:ALNUM:]]", b"A]"), Match);

        // The same keyword in lower case is the class.
        assert_eq!(fnmatch(b"[[:alnum:]]", b"A"), Match);

        // All ten known keywords parse, and each answers for its own class.
        let known: [(&[u8], &[u8]); 10] = [
            (b"[[:digit:]]", b"7"),
            (b"[[:alnum:]]", b"z"),
            (b"[[:alpha:]]", b"z"),
            (b"[[:xdigit:]]", b"F"),
            (b"[[:print:]]", b"~"),
            (b"[[:graph:]]", b"~"),
            (b"[[:space:]]", b" "),
            (b"[[:blank:]]", b"\t"),
            (b"[[:upper:]]", b"Q"),
            (b"[[:lower:]]", b"q"),
        ];
        for (pattern, string) in known {
            assert_eq!(
                fnmatch(pattern, string),
                Match,
                "keyword {:?} did not admit {:?}",
                show(pattern),
                show(string)
            );
        }
    }

    /// `?` matches exactly one byte, not one Unicode scalar value.
    ///
    /// `lib/curl_fnmatch.h:33-36` states plainly that there is no UTF or
    /// Unicode support and that `?` "does not match UTF characters", while
    /// `*` works over a UTF-8 string because it does not care about
    /// boundaries. U+00E4 below is two bytes, so it takes two `?`.
    #[test]
    fn a_question_mark_matches_exactly_one_byte() {
        assert_eq!(fnmatch(b"?", b"a"), Match);
        assert_eq!(fnmatch(b"?", b"\xc3\xa4"), NoMatch);
        assert_eq!(fnmatch(b"??", b"\xc3\xa4"), Match);
        assert_eq!(fnmatch(b"???", b"\xc3\xa4a"), Match);
        assert_eq!(fnmatch(b"?\xc3\xa4", b"a\xc3\xa4"), Match);
        assert_eq!(fnmatch(b"*", b"\xc3\xa4"), Match);
    }

    /// Bytes above ASCII are matched literally, inside brackets and out.
    ///
    /// The predicates in `lib/curl_ctype.h` are ASCII-only and
    /// locale-independent, so a byte above 0x7f belongs to no class and is
    /// only ever a literal. `unit1307.c:130` and :152-154 record that both
    /// Linux and macOS `fnmatch(3)` answer `FAIL` for these rows, where
    /// curl's own matcher answers plainly.
    #[test]
    fn bytes_above_ascii_are_matched_literally() {
        assert_eq!(fnmatch(b"[\xff]", b"\xff"), Match);
        assert_eq!(fnmatch(b"[\xff]", b"a"), NoMatch);
        assert_eq!(fnmatch(b"[!\xff]", b"a"), Match);
        assert_eq!(fnmatch(b"[!\xff]", b"\xff"), NoMatch);
        assert_eq!(fnmatch(b"[!\xff]", b""), NoMatch);
        assert_eq!(fnmatch(b"*\xff*", b"a\xffb"), Match);
    }

    /// The empty pattern and the empty string.
    ///
    /// `lib/curl_fnmatch.c:279-280`: an exhausted pattern matches only an
    /// exhausted string. A NULL pattern or string is a third case,
    /// `CURL_FNMATCH_FAIL` (:353), which cannot arise here because the
    /// arguments are slices -- it belongs at the FFI boundary, where a C
    /// caller can still pass NULL.
    #[test]
    fn the_empty_pattern_matches_only_the_empty_string() {
        assert_eq!(fnmatch(b"", b""), Match);
        assert_eq!(fnmatch(b"", b"a"), NoMatch);
        assert_eq!(fnmatch(b"a", b""), NoMatch);
        assert_eq!(fnmatch(b"[a]", b""), NoMatch);
        assert_eq!(fnmatch(b"?", b""), NoMatch);
        assert_eq!(fnmatch(b"*", b""), Match);
        assert_eq!(fnmatch(b"**", b""), Match);
    }

    /// An interior NUL ends the pattern and the string.
    ///
    /// The C walks NUL-terminated strings, so `"a\0b"` is the two-byte
    /// C string `"a"` and no C caller can express anything else. `byte_at`
    /// reproduces that by reading 0 both past the end of a slice and at an
    /// embedded NUL, which keeps a slice-shaped caller from observing
    /// behaviour a C caller could not.
    #[test]
    fn an_interior_nul_terminates_the_pattern_and_the_string() {
        assert_eq!(fnmatch(b"a\0b", b"a"), Match);
        assert_eq!(fnmatch(b"a", b"a\0b"), Match);
        assert_eq!(fnmatch(b"a\0b", b"a\0c"), Match);
        assert_eq!(fnmatch(b"a\0b", b"ab"), NoMatch);
        assert_eq!(fnmatch(b"[a]\0[b]", b"a"), Match);
        assert_eq!(fnmatch(b"*\0b", b"anything"), Match);
    }

    /// Long inputs do not overflow the stack.
    ///
    /// The matcher walks the pattern iteratively; only the `'*'` arm
    /// recurses (`lib/curl_fnmatch.c:277`), and the star budget bounds that
    /// to three frames however long the input is. AAP 0.1.1 makes
    /// performance a non-goal, so this asserts termination and depth, not
    /// speed.
    #[test]
    fn long_inputs_do_not_overflow_the_stack() {
        let literal = [b'x'; 10_000];
        assert_eq!(fnmatch(&literal, &literal), Match);

        let questions = [b'?'; 10_000];
        let letters = [b'y'; 10_000];
        assert_eq!(fnmatch(&questions, &letters), Match);

        // A thousand bracket expressions: the '[' arm advances the cursor
        // rather than recursing, so this is depth 1.
        let brackets = b"[a]".repeat(1_000);
        let members = [b'a'; 1_000];
        assert_eq!(fnmatch(&brackets, &members), Match);

        // One star followed by five thousand literals.
        let mut star = Vec::with_capacity(5_001);
        star.push(b'*');
        star.resize(5_001, b'a');
        let tail = [b'a'; 5_000];
        assert_eq!(fnmatch(&star, &tail), Match);

        // Fifty stars: the budget is gone long before the pattern ends, and
        // the answer arrives without descending fifty frames.
        let many = b"*a".repeat(50);
        let run = [b'a'; 100];
        assert_eq!(fnmatch(&many, &run), NoMatch);
    }

    /// Nothing this module can express reports `Fail`.
    ///
    /// `Fail` exists because `CURLOPT_FNMATCH_FUNCTION` is a public callback
    /// whose three return values are ABI-visible, and because the C rejects
    /// a NULL pattern or string with it (`lib/curl_fnmatch.c:353`). With
    /// byte slices there is no NULL, so the matcher itself never produces
    /// it -- a bracket syntax error is a non-match, not a failure.
    #[test]
    fn no_case_in_this_module_reports_fail() {
        for (index, &(pattern, string, _)) in TABLE.iter().enumerate() {
            assert_ne!(fnmatch(pattern, string), Fail, "row {index}");
        }

        let awkward: [(&[u8], &[u8]); 8] = [
            (b"[", b"["),
            (b"[[:", b"x"),
            (b"[[:foo:]]", b"f]"),
            (b"\\", b"\\"),
            (b"[!\xff]", b"\xff"),
            (b"[z-a]", b"-"),
            (b"", b""),
            (b"*a*b*c", b"abc"),
        ];
        for (pattern, string) in awkward {
            assert_ne!(
                fnmatch(pattern, string),
                Fail,
                "pattern {:?} against string {:?}",
                show(pattern),
                show(string)
            );
        }
    }

    /// The three results carry the C's integers.
    ///
    /// `lib/curl_fnmatch.h:26-28`, and ABI-visible through the
    /// `CURLOPT_FNMATCH_FUNCTION` callback, whose implementations are
    /// compiled C holding these values in their instruction stream.
    /// AAP 0.6.1 requires such integers to be pinned rather than inferred.
    #[test]
    fn the_three_results_carry_the_c_integers() {
        assert_eq!(Match as i32, 0);
        assert_eq!(NoMatch as i32, 1);
        assert_eq!(Fail as i32, 2);
        assert_eq!(std::mem::size_of::<FnMatch>(), 4);
    }

    /// The byte predicates reproduce `lib/curl_ctype.h` exactly.
    ///
    /// Restated here as range patterns rather than range containment, so a
    /// transcription slip in the implementation cannot be mirrored by the
    /// same slip in the test. Exhaustive over all 256 bytes: these
    /// predicates are ASCII-only and locale-independent, and Rust's
    /// Unicode-aware `char` predicates would answer differently above 0x7f.
    // The restatement has to stay a literal range for all ten, or the three
    // that `clippy::manual_is_ascii_check` can rewrite would be checked
    // against the standard library while the other seven are checked against
    // `lib/curl_ctype.h`. It is the header this test is the oracle for.
    #[allow(clippy::manual_is_ascii_check)]
    #[test]
    fn the_byte_predicates_reproduce_curl_ctype_h() {
        for c in 0..=u8::MAX {
            assert_eq!(is_upper(c), matches!(c, b'A'..=b'Z'), "{c:#04x}");
            assert_eq!(is_lower(c), matches!(c, b'a'..=b'z'), "{c:#04x}");
            assert_eq!(is_digit(c), matches!(c, b'0'..=b'9'), "{c:#04x}");
            assert_eq!(
                is_alpha(c),
                matches!(c, b'a'..=b'z' | b'A'..=b'Z'),
                "{c:#04x}"
            );
            assert_eq!(
                is_alnum(c),
                matches!(c, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'),
                "{c:#04x}"
            );
            assert_eq!(
                is_xdigit(c),
                matches!(c, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'),
                "{c:#04x}"
            );
            assert_eq!(is_blank(c), matches!(c, b' ' | b'\t'), "{c:#04x}");
            assert_eq!(is_lowprint(c), matches!(c, 0x09..=0x0d), "{c:#04x}");
            assert_eq!(
                is_print(c),
                matches!(c, 0x09..=0x0d | 0x20..=0x7e),
                "{c:#04x}"
            );
            assert_eq!(
                is_graph(c),
                matches!(c, 0x09..=0x0d | 0x21..=0x7e),
                "{c:#04x}"
            );
        }

        // The two surprises worth stating outright: both ISPRINT and
        // ISGRAPH admit the 0x09..=0x0d control range through ISLOWPRINT
        // (lib/curl_ctype.h:33-36), and ISGRAPH excludes the space that
        // ISPRINT admits. Neither 0x7f nor 0x08 is admitted by either.
        assert!(is_print(b'\t'));
        assert!(is_graph(b'\t'));
        assert!(is_print(b' '));
        assert!(!is_graph(b' '));
        assert!(!is_print(0x7f));
        assert!(!is_graph(0x7f));
        assert!(!is_print(0x08));
        assert!(!is_graph(0x08));
    }

    /// `charclass` partitions the bytes into exactly four classes.
    ///
    /// `lib/curl_fnmatch.c:125-134`. Totality is what makes the range
    /// filter at :150-152 well defined: every intermediate byte has a class
    /// to be compared against.
    #[test]
    fn charclass_partitions_the_bytes_into_four_classes() {
        assert_eq!(charclass(b'7'), CharClass::Digit);
        assert_eq!(charclass(b'Q'), CharClass::Upper);
        assert_eq!(charclass(b'q'), CharClass::Lower);
        for c in [b'-', b'_', b'[', b' ', 0x00, 0x7f, 0xff] {
            assert_eq!(charclass(c), CharClass::Other, "{c:#04x}");
        }

        for c in 0..=u8::MAX {
            let class = charclass(c);
            assert_eq!(class == CharClass::Digit, is_digit(c), "{c:#04x}");
            assert_eq!(class == CharClass::Upper, is_upper(c), "{c:#04x}");
            assert_eq!(class == CharClass::Lower, is_lower(c), "{c:#04x}");
            assert_eq!(class == CharClass::Other, !is_alnum(c), "{c:#04x}");
        }
    }
}
