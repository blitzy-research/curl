// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Brace and range globbing for URLs and output file names.
//!
//! Supersedes `src/tool_urlglob.c` (715 lines) and `src/tool_urlglob.h` (82
//! lines): the `{a,b,c}` / `[1-100]` / `[a-z:2]` expansion that turns one
//! command-line URL into many transfers, and the `#1` / `#2` back-reference
//! substitution that lets an `-o` file name track the glob that produced it.
//!
//! # This is frozen surface
//!
//! The module parses user input and emits diagnostics, and AAP section 0.8.1
//! freezes both: the acceptance rules and the diagnostic text are part of the
//! command-line contract. Nothing here may be reworded, re-cased, re-punctuated
//! or made "more sensible". Where a faithful translation and a tidier one
//! disagree, faithfulness wins (AAP section 0.1.1: performance and elegance are
//! non-goals), which is why the odometer stays lazy -- `[1-1000000]` must never
//! materialise a million strings -- and why several C quirks below are
//! reproduced deliberately rather than corrected.
//!
//! # The C original, function by function
//!
//! | C | `src/tool_urlglob.c` | Here |
//! |---|---|---|
//! | `globerror` | `:31-37` | [`GlobFailure`] |
//! | `glob_fixed` | `:39-59` | the literal commit inside [`Parser::run`] |
//! | `multiply` | `:66-88` | [`multiply`] |
//! | `glob_set` | `:90-209` | [`Parser::glob_set`] |
//! | `glob_range` | `:211-341` | [`Parser::glob_range`] |
//! | `peek_ipv6` | `:343-384` | [`Parser::peek_ipv6`] |
//! | `add_glob` | `:386-404` | [`Parser::add_glob`] |
//! | `glob_parse` | `:406-484` | [`Parser::run`] |
//! | `glob_inuse` | `:486-489` | absent -- see below |
//! | `glob_url` | `:491-530` | [`UrlGlob::parse`] |
//! | `glob_cleanup` | `:532-551` | absent -- `Drop` |
//! | `glob_next_url` | `:553-634` | [`UrlGlob::next_url`] |
//! | `glob_match_url` | `:636-715` | [`UrlGlob::match_url`] |
//!
//! The model is `src/tool_urlglob.h:28-59`: a `globtype` tag plus a three-arm
//! `union`, which is exactly a Rust enum ([`PatternKind`]), so the C's three
//! `default: DEBUGASSERT(0); return CURLE_FAILED_INIT;` arms (`:592-594`,
//! `:622-624`, `:681-684`) are unreachable by construction and are deleted
//! rather than translated into a panic. `globindex` (`:36-37`) is `-1` for a
//! fixed literal and a 0-based counter for a real glob, which is
//! [`UrlPattern::globindex`] as an [`Option`].
//!
//! # Two limits, and which one is real
//!
//! `GLOB_PATTERN_NUM 30` (`src/tool_urlglob.h:62`) is documented as "the total
//! number of globs supported" and is **dead code**: `grep -rn GLOB_PATTERN_NUM
//! src/` returns only its own definition. The enforced limit is `add_glob`'s
//! `glob->pnum < 255` (`src/tool_urlglob.c:393`), so [`PATTERN_LIMIT`] is 255
//! and not 30. Both lines are cited so that the next reader does not "correct"
//! it back.
//!
//! # What is deliberately absent
//!
//! * The `_WIN32 || MSDOS` branch of `glob_match_url` (`:700-710`), which calls
//!   `sanitize_file_name` and is the sole reason the C signature carries a
//!   `SANITIZEcode *` out-parameter (`src/tool_urlglob.h:78`, set once at
//!   `:643` and never touched again on the POSIX path). Windows and MS-DOS are
//!   out of scope (AAP section 0.2.2) and all four mandated targets take the
//!   `#else` at `:711-713`, so the parameter is dropped entirely. This is a
//!   deliberate omission, not an oversight.
//! * `glob_cleanup` (`:532-551`), which is `free()`. Ownership is in the types.
//! * `glob_inuse` (`:486-489`), which is `return glob->palloc ? TRUE : FALSE;`
//!   -- "has this glob been initialised?". It collapses into the *existence* of
//!   the value: the caller holds `Option<UrlGlob>` (two of them, per the note
//!   below) and asks `.is_some()`. No method is provided because no caller
//!   needs one. The one C asymmetry this loses is that C's failed `glob_url`
//!   still leaves `palloc == 2`, so `glob_inuse` reports true after a failure;
//!   that is unobservable, because `src/tool_operate.c:1213-1214` and `:1238`
//!   return the error immediately and reach `glob_cleanup` only later.
//!
//! # Who calls this, and what belongs to them
//!
//! Every consumer in the C tree is `src/tool_operate.c`, that is
//! `curl-rs/src/operate/`. Two facts belong to that caller and not here:
//!
//! * There are **two independent glob states** per operation -- `urlglob` for
//!   the URL (`:1238`) and `inglob` for `-T` / `--upload-file` (`:1213`) -- so
//!   the surface below is a plain value the caller can hold twice.
//! * Globbing is gated by `if(!config->globoff ...)` (`:1210`, `:1235`), the
//!   `-g` / `--globoff` flag. Skipping the parse is the caller's decision;
//!   nothing here reads a configuration.
//!
//! # The registry this module has to be handed, and the gap that remains
//!
//! `peek_ipv6` (`:343-384`) exists because `[` is ambiguous between a range and
//! an IPv6 literal, and it resolves the ambiguity by asking the URL API to
//! parse the bracketed text with `CURLU_GUESS_SCHEME` (`:375`). That decision
//! must come from the engine's own parser, or globbing and URL parsing would
//! disagree on inputs such as `http://[::1]:8080/` versus `http://[1-5]/`, so
//! [`Parser::peek_ipv6`] calls `curl_rs_lib::url::Url::set` with
//! [`UrlFlags::GUESS_SCHEME`]. No hand-rolled IPv6 matcher, no general-purpose
//! URL crate, no regular expression.
//!
//! That parser takes its scheme table as a constructor argument by design:
//! `curl-rs-lib/src/url/mod.rs` states there is "deliberately no global here to
//! reach for instead: no `static mut`, no lazily-initialised singleton, no
//! registration side effect. The registry is a constructor argument and `Url`
//! holds the borrow." So [`UrlGlob::parse`] takes one too, which is also AAP
//! section 0.3.3 pattern P12 (dependency injection) and is what lets this
//! module be tested without a live engine.
//!
//! **Reported gap.** `curl-rs-lib` does not yet expose a registry *value*. Its
//! own documentation records the intended wiring -- `protocols/mod.rs`, which
//! supersedes `lib/url.c`'s 33-entry `all_schemes[]`, implements
//! `url::SchemeRegistry` and exposes `pub fn scheme_registry() -> &'static dyn
//! crate::url::SchemeRegistry`, re-exported from the crate root -- and
//! `curl-rs-lib/src/protocols/mod.rs` currently declares only its `ftp` child.
//! Until that re-export lands, `curl-rs/src/operate/` has nothing to pass here.
//! The missing addition is exactly that one function and its `pub use`. Nothing
//! was substituted for it: no other parser, no new dependency, no `unsafe`, and
//! the feature is not dropped. Measured mitigation, so the scope of the gap is
//! not overstated: every string this probe passes begins with `[`, so
//! `is_absolute_url` finds no scheme (`url/mod.rs:1321-1357`), `parse_scheme`
//! returns before its lookup (`:2389-2412`) and `guess_scheme` stores `http`
//! without consulting the table (`:2454-2475`) -- the registry is never read on
//! this path, whatever it contains.
//!
//! # Bytes, not text
//!
//! The C takes `const char *` and hands back `char *`, so this module works in
//! bytes end to end. Three reasons, each measured rather than stylistic: the
//! diagnostic truncation below is a byte truncation at 511 and must not split a
//! character; `argv` on the four mandated Unix targets is not guaranteed to be
//! UTF-8; and an output file name wants `std::os::unix::ffi::OsStrExt` at the
//! call site. A caller holding a `String` passes `s.as_bytes()`. A NUL byte
//! ends the input, exactly as it ends C's string.
//!
//! # Documented translation differences
//!
//! None changes an observable byte of the tool; each is recorded so it is not
//! mistaken for an oversight.
//!
//! 1. **Exhaustion is sticky.** C leaves every pattern back at its minimum when
//!    it reports "no more" (`:597-599`), so a further `glob_next_url` call
//!    resumes the cycle and yields the second combination again.
//!    [`UrlGlob::next_url`] stays exhausted instead, which is what
//!    [`Iterator`] and [`FusedIterator`] mean. Unobservable: the only consumer
//!    is driven by the `urlnum` / `urlidx` counters (`src/tool_operate.c:1225`,
//!    `:1305-1310`) and never calls past the end. The post-exhaustion *state*
//!    is identical either way -- all minimums -- so [`UrlGlob::match_url`]
//!    still renders what C would render.
//! 2. **Overflow that C leaves undefined raises the error C raises
//!    elsewhere.** `(max - min) / step + 1` overflows a signed 64-bit integer,
//!    and `idx += step` can overflow past `max`; both are undefined behaviour
//!    in C, and its own `DEBUGASSERT(*amount >= 0)` (`:69`) documents that the
//!    value is meant to stay non-negative. Here the count is computed with a
//!    checked add and reports `range overflow`, and an advance that cannot be
//!    represented is treated as "past `max`", which is what it is. No panic, no
//!    wrap.
//!
//!    The count divergence is exactly one input wide, and it was measured
//!    rather than assumed. `span / step + 1` can only overflow when the span is
//!    the whole signed 64-bit range and the step is 1, that is
//!    `[0-9223372036854775807]`: for a step of 2 or more the quotient is at
//!    most half the maximum. On that input a release build of the C tool wraps
//!    to a negative count, `multiply`'s `with <= 0` arm then stores a count of
//!    **zero**, and the tool proceeds -- curl 8.14.1 on x86_64 attempts a
//!    transfer to host `0` -- while a build with `DEBUGASSERT` live, which is
//!    the build the test suite uses, aborts on the assertion instead. Neither
//!    is a specification, so the defined behaviour is chosen and named:
//!    `range overflow`, the same refusal every other unrepresentable count
//!    gets. Every overflow that does not depend on undefined behaviour still
//!    matches the oracle exactly, column included --
//!    `[1-99999999999][1-99999999999]` reports `range overflow in URL position
//!    31` in both.
//! 3. **`glob_match_url`'s ceiling reports `CURLE_TOO_LARGE`, not
//!    `CURLE_OUT_OF_MEMORY`.** Verified rather than assumed: `dyn_nappend`
//!    returns `CURLE_TOO_LARGE` when `len + idx + 1` exceeds the buffer's
//!    ceiling (`lib/curlx/dynbuf.c`), and `:693-694` propagates `result`
//!    unchanged. The parse and `glob_next_url` paths do map every buffer
//!    failure onto `CURLE_OUT_OF_MEMORY`, because they spell that code out
//!    (`:183`, `:430`, `:451`, `:608`, `:614`, `:620`).
//! 4. **Allocation failure is absent.** The six `globerror(glob, NULL, ...)`
//!    sites (`:49`, `:54`, `:143`, `:151`, `:158`, `:397`) report a failed
//!    `malloc`; Rust aborts instead, so only the ceiling checks above survive.
//!    They print nothing, which is why [`GlobFailure::message`] is optional.

use std::io::Write;
use std::iter::FusedIterator;
use std::mem;

use curl_rs_lib::error::{CURLUcode, CURLcode};
use curl_rs_lib::url::{SchemeRegistry, Url, UrlFlags, UrlPart};

use crate::output::msgs::ERROR_PREFIX;

/// The greatest number of patterns one URL may hold.
///
/// `add_glob` reallocates only `if(glob->pnum < 255)` and otherwise reports
/// `too many {} sets` (`src/tool_urlglob.c:393`, `:400`). The check runs only
/// when `pnum` reaches `palloc`, and `palloc` starts at 2 (`:506`) and doubles
/// (`:392`), giving 2, 4, 8 ... 256; the first size at which both conditions
/// hold is 256. So 255 patterns are accepted and the 256th is refused, which is
/// what the comparison below reproduces.
///
/// **Patterns, not globs.** Each run of literal text between two expressions is
/// a pattern too (`:454-461`), so `http://x/{a}{b}` holds three.
const PATTERN_LIMIT: usize = 255;

/// The greatest number of elements one `{...}` set may hold.
///
/// `if(size >= 100000)` (`src/tool_urlglob.c:133`), tested *before* the element
/// is appended, on the comma case that the closing brace also falls through to.
/// A set of exactly 100,000 elements is therefore accepted and the 100,001st is
/// refused with `range overflow`.
const SET_ELEMENT_LIMIT: usize = 100_000;

/// `MAX_IP6LEN` (`src/tool_urlglob.c:343`).
///
/// The guard is `hlen >= MAX_IP6LEN` (`:364-365`) against a `char[128]` that
/// also has to hold a terminator, so the longest bracketed text that can be an
/// IPv6 literal is 127 bytes including both brackets.
const MAX_IP6LEN: usize = 128;

/// `MAX_OUTPUT_GLOB_LENGTH` (`src/tool_urlglob.c:636`): the ceiling on one
/// substituted output file name.
const MAX_OUTPUT_GLOB_LENGTH: usize = 1024 * 1024;

/// `MAX_CONFIG_LINE_LENGTH` (`src/tool_cfgable.h:32`), the ceiling `glob_url`
/// gives its scratch buffer at `src/tool_urlglob.c:502`.
///
/// It bounds both a single parsed literal or set element and one expanded URL,
/// because C reuses the same `dynbuf` for the parse and for `glob_next_url`.
const MAX_CONFIG_LINE_LENGTH: usize = 10 * 1024 * 1024;

/// The ceiling `glob_range` gives the `:[num]` step of an alphabetic range:
/// `curlx_str_number(&p, &num, 256)` (`src/tool_urlglob.c:247`).
const ASCII_STEP_LIMIT: i64 = 256;

/// `('z' - 'a')` (`src/tool_urlglob.c:266`): the widest alphabetic span.
///
/// 25, which is what refuses `[A-z]` -- a span of 57 -- while accepting
/// `[a-z]`.
const ASCII_SPAN_LIMIT: i32 = b'z' as i32 - b'a' as i32;

/// The usable size of `glob_url`'s `char text[512]` (`src/tool_urlglob.c:511`).
///
/// `curl_mvsnprintf` stops at the ceiling and then "scrap\[s\] the last
/// letter" to make room for the terminator (`lib/mprintf.c`), so a rendered
/// diagnostic is clipped to 511 bytes. Long URLs really are truncated, and
/// that is preserved rather than improved.
const DIAG_TEXT_CAPACITY: usize = 511;

/// What `glob_url` writes to `*urlnum` when it fails
/// (`src/tool_urlglob.c:525`).
///
/// One, not zero: the caller goes on to attempt a single unexpanded URL.
const URLNUM_ON_ERROR: i64 = 1;

// The frozen diagnostic strings. Thirteen `globerror` call sites carry a
// message and they spell nine distinct strings; the four `range overflow` sites
// (`:127`, `:134`, `:277`, `:333`) and the two `bad range` sites (`:268`,
// `:323`) share their text. Every one maps to `CURLE_URL_MALFORMAT`.

/// `src/tool_urlglob.c:110`.
const ERR_UNMATCHED_BRACE: &str = "unmatched brace";

/// `src/tool_urlglob.c:115` -- "no nested expressions at this time".
const ERR_NESTED_BRACE: &str = "nested brace";

/// `src/tool_urlglob.c:120`.
const ERR_EMPTY_SET: &str = "empty string within braces";

/// `src/tool_urlglob.c:127`, `:134`, `:277`, `:333`.
const ERR_RANGE_OVERFLOW: &str = "range overflow";

/// `src/tool_urlglob.c:170`.
const ERR_UNEXPECTED_CLOSE_BRACKET: &str = "unexpected close bracket";

/// `src/tool_urlglob.c:268`, `:323`.
const ERR_BAD_RANGE: &str = "bad range";

/// `src/tool_urlglob.c:336`.
const ERR_BAD_RANGE_SPEC: &str = "bad range specification";

/// `src/tool_urlglob.c:400`.
const ERR_TOO_MANY_SETS: &str = "too many {} sets";

/// `src/tool_urlglob.c:437`.
const ERR_UNMATCHED_CLOSE: &str = "unmatched close brace/bracket";

/// One expression of a parsed URL: the three arms of `union c`
/// (`src/tool_urlglob.h:38-58`) as the tagged enumeration they already are.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PatternKind {
    /// `struct { char **elem; curl_off_t size, idx; size_t palloc; } set`
    /// (`src/tool_urlglob.h:39-44`): a `{a,b,c}` set, or a literal run of text
    /// committed as a single-element set by `glob_fixed` (`:39-59`).
    ///
    /// `size` and `palloc` are gone -- a [`Vec`] carries both.
    Set {
        /// The elements, in the order the input spelled them.
        elems: Vec<Vec<u8>>,
        /// `c.set.idx`: which element the odometer currently stands on.
        idx: usize,
    },

    /// `struct { int min, max, letter; unsigned char step; } ascii`
    /// (`src/tool_urlglob.h:45-50`): an `[a-z]` or `[a-z:2]` range.
    Ascii {
        /// `c.ascii.min`, the first letter.
        min: u8,
        /// `c.ascii.max`, the last letter the step may reach.
        max: u8,
        /// `c.ascii.letter`, the letter the odometer currently stands on.
        letter: u8,
        /// `c.ascii.step`, validated non-zero and no wider than the span.
        step: u8,
    },

    /// `struct { curl_off_t min, max, idx, step; int npad; } num`
    /// (`src/tool_urlglob.h:51-57`): a `[1-100]`, `[1-100:5]` or `[001-999]`
    /// range. `curl_off_t` is a signed 64-bit integer.
    Num {
        /// `c.num.min`, the first value.
        min: i64,
        /// `c.num.max`, the last value the step may reach.
        max: i64,
        /// `c.num.idx`, the value the odometer currently stands on.
        idx: i64,
        /// `c.num.step`, validated non-zero and no wider than the span.
        step: i64,
        /// `c.num.npad`: the zero-padding width, counted only when the minimum
        /// begins with `0` (`src/tool_urlglob.c:289-297`). Load-bearing for the
        /// bytes that reach the wire -- `[001-100]` must render `001`.
        npad: usize,
    },
}

/// One entry of `glob->pattern[]`: `struct URLPattern`
/// (`src/tool_urlglob.h:34-59`).
#[derive(Clone, Debug, Eq, PartialEq)]
struct UrlPattern {
    /// `int globindex`, "the number of this particular glob or -1 if not used
    /// within {} or []" (`src/tool_urlglob.h:36-37`).
    ///
    /// [`None`] is the C's `-1`, that is a fixed literal. The counter is
    /// separate from the pattern index because literals do not consume one
    /// (`src/tool_urlglob.c:469`, `:477`), which is exactly why
    /// [`UrlGlob::match_url`] resolves `#N` against this field rather than
    /// against a position in the vector.
    globindex: Option<u32>,

    /// The expression itself.
    kind: PatternKind,
}

/// The one failure a bounded buffer can report: `CURLE_TOO_LARGE` from
/// `dyn_nappend` when `len + idx + 1` would exceed the ceiling
/// (`lib/curlx/dynbuf.c`).
///
/// Kept distinct from [`CURLcode`] because the two call sites map it
/// differently, and the difference is C's: the parse and odometer paths spell
/// `CURLE_OUT_OF_MEMORY` (`src/tool_urlglob.c:183`, `:430`, `:451`, `:608`,
/// `:614`, `:620`) while `glob_match_url` propagates the buffer's own code
/// (`:693-694`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DynTooLarge;

/// `curlx_dyn_addn`: append `bytes`, or refuse because the ceiling is reached.
///
/// `dyn_nappend` computes `fit = len + idx + 1` -- the new bytes, the old bytes
/// and a terminator -- and fails when `fit > s->toobig`, so the greatest length
/// a buffer of ceiling `cap` can hold is `cap - 1`. Rust needs no terminator,
/// but the arithmetic is reproduced because the ceiling is observable: it is
/// what turns an over-long output file name into an error.
///
/// # Errors
///
/// [`DynTooLarge`] when the append would cross the ceiling. Nothing is appended
/// in that case, which matters because the caller reports rather than retries.
fn dyn_addn(
    buf: &mut Vec<u8>,
    bytes: &[u8],
    cap: usize,
) -> Result<(), DynTooLarge> {
    let fit = bytes.len().saturating_add(buf.len()).saturating_add(1);
    if fit > cap {
        return Err(DynTooLarge);
    }

    buf.extend_from_slice(bytes);
    Ok(())
}

/// `multiply` (`src/tool_urlglob.c:66-88`): accumulate the URL count, reporting
/// overflow.
///
/// Returns `true` when the product cannot be represented, which is the C's
/// `return 1`. The two C code paths -- `__builtin_mul_overflow` when the
/// compiler has it, otherwise `sum / with != *amount` -- exist only because C
/// has no portable checked multiply; [`i64::checked_mul`] is both.
///
/// The non-positive short-circuit at `:71-73` is reproduced exactly: a zero
/// operand makes the count zero and is *not* an error.
fn multiply(amount: &mut i64, with: i64) -> bool {
    // `DEBUGASSERT(*amount >= 0); DEBUGASSERT(with >= 0);` (`:69-70`). Debug
    // assertions, as in C: an overflowing range is user input and must produce
    // `range overflow`, never an abort.
    debug_assert!(*amount >= 0, "the URL count is never negative");
    debug_assert!(with >= 0, "a pattern never contributes a negative count");

    let sum = if with <= 0 || *amount <= 0 {
        0
    } else {
        match amount.checked_mul(with) {
            Some(product) => product,
            None => return true,
        }
    };

    *amount = sum;
    false
}

impl PatternKind {
    /// Advance this pattern one place, reporting whether it wrapped.
    ///
    /// The three arms of `glob_next_url`'s counter
    /// (`src/tool_urlglob.c:571-591`).
    /// `true` is the C's `carry = TRUE`: the pattern went back to its minimum
    /// and the pattern to its left must move.
    ///
    /// All three compare with `>` (or `==`, for a set) *after* adding the step,
    /// so a step that would overshoot never produces the overshot value:
    /// `[1-10:4]` yields 1, 5 and 9, never 13.
    fn advance(&mut self) -> bool {
        match self {
            // `if((pat->c.set.elem) && (++pat->c.set.idx == pat->c.set.size))`
            // (`:573-576`). `>=` rather than `==` so that an index which
            // somehow stood past the end wraps instead of indexing out of
            // bounds. Sets are never empty here in any case: `{}` is refused
            // at `:118-123` and `glob_fixed` always stores one element.
            Self::Set { elems, idx } => {
                *idx = idx.saturating_add(1);
                if *idx >= elems.len() {
                    *idx = 0;
                    true
                } else {
                    false
                }
            }

            // `pat->c.ascii.letter += pat->c.ascii.step; if(letter > max)`
            // (`:579-583`). C holds `letter` in an `int`, so the sum cannot
            // overflow there; here it is widened for the same reason.
            Self::Ascii {
                min,
                max,
                letter,
                step,
            } => {
                let next = u16::from(*letter).saturating_add(u16::from(*step));
                if next > u16::from(*max) {
                    *letter = *min;
                    true
                } else {
                    // `next <= max <= u8::MAX`, so this is exact; the fallback
                    // exists only to keep the conversion infallible.
                    *letter = u8::try_from(next).unwrap_or(*max);
                    false
                }
            }

            // `pat->c.num.idx += pat->c.num.step; if(idx > max)` (`:586-590`).
            // A sum that cannot be represented is past `max` by definition, so
            // it wraps -- see translation difference 2 in the module
            // documentation, and note that C's own overflow here is undefined.
            Self::Num {
                min,
                max,
                idx,
                step,
                ..
            } => match idx.checked_add(*step) {
                Some(next) if next <= *max => {
                    *idx = next;
                    false
                }
                _ => {
                    *idx = *min;
                    true
                }
            },
        }
    }

    /// Append this pattern's current value to `out`.
    ///
    /// The single renderer behind both `glob_next_url` (`:602-626`) and
    /// `glob_match_url` (`:666-686`), which spell the same three cases twice in
    /// C. Sharing it is what keeps them from drifting, and the zero padding is
    /// the reason it matters.
    ///
    /// # Errors
    ///
    /// [`DynTooLarge`] when `out` would cross `cap`.
    fn render(&self, out: &mut Vec<u8>, cap: usize) -> Result<(), DynTooLarge> {
        match self {
            // `curlx_dyn_add(&glob->buf, pat->c.set.elem[pat->c.set.idx])`
            // (`:607`, `:670`), inside C's `if(pat->c.set.elem)` guard. An
            // absent element contributes nothing, which is what that guard does
            // for the allocation-failure state Rust cannot reach.
            Self::Set { elems, idx } => match elems.get(*idx) {
                Some(elem) => dyn_addn(out, elem, cap),
                None => Ok(()),
            },

            // `char letter = (char)pat->c.ascii.letter;` then one byte
            // (`:612-613`, `:673-674`).
            Self::Ascii { letter, .. } => dyn_addn(out, &[*letter], cap),

            // `curlx_dyn_addf(&glob->buf, "%0*" CURL_FORMAT_CURL_OFF_T,
            //  pat->c.num.npad, pat->c.num.idx)` (`:618-619`, `:678-679`): zero
            // padding to `npad` digits, and plain decimal when `npad` is 0.
            // The most byte-visible line in the file.
            Self::Num { idx, npad, .. } => {
                let text = format!("{:0width$}", idx, width = *npad);
                dyn_addn(out, text.as_bytes(), cap)
            }
        }
    }
}

/// A buffer that stops accepting bytes at its ceiling instead of growing.
///
/// `glob_url` formats its diagnostic into a `char text[512]` with
/// `curl_msnprintf` (`src/tool_urlglob.c:511`, `:514-516`), which clips rather
/// than failing. This reproduces that, and reproduces it *while* formatting
/// rather than afterwards, because the caret run is `pos - 1` bytes wide and
/// `pos` can be millions: C never materialises those spaces and neither does
/// this.
struct Clipped {
    /// What has been kept.
    text: Vec<u8>,
    /// The ceiling, in bytes.
    cap: usize,
}

impl Clipped {
    /// A buffer clipped at `cap` bytes.
    fn new(cap: usize) -> Self {
        Self {
            text: Vec::with_capacity(cap),
            cap,
        }
    }

    /// Append as much of `bytes` as still fits.
    fn push(&mut self, bytes: &[u8]) {
        let room = self.cap.saturating_sub(self.text.len());
        let take = room.min(bytes.len());
        self.text
            .extend_from_slice(bytes.get(..take).unwrap_or(bytes));
    }

    /// Append up to `count` copies of `byte`, as far as the ceiling allows.
    fn fill(&mut self, byte: u8, count: usize) {
        let room = self.cap.saturating_sub(self.text.len());
        let take = room.min(count);
        self.text.extend(std::iter::repeat(byte).take(take));
    }
}

/// Why a URL could not be globbed: `globerror`'s two fields plus its code
/// (`src/tool_urlglob.c:31-37`).
///
/// C stores the message and the column on the glob itself and returns the code;
/// gathering all three here is what lets the glob exist only on success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct GlobFailure {
    /// The `CURLcode` C returns.
    code: CURLcode,

    /// `glob->error`, the frozen text, or [`None`] for the allocation-failure
    /// sites that pass `NULL` and print nothing (`:49`, `:54`, `:143`, `:151`,
    /// `:158`, `:397`).
    message: Option<&'static str>,

    /// `glob->pos`, the 1-based column, or 0 to print the bare message.
    pos: usize,
}

#[allow(dead_code)]
impl GlobFailure {
    /// `globerror(glob, err, pos, CURLE_URL_MALFORMAT)`: a malformed pattern.
    const fn malformed(message: &'static str, pos: usize) -> Self {
        Self {
            code: CURLcode::UrlMalformat,
            message: Some(message),
            pos,
        }
    }

    /// `globerror(glob, NULL, 0, CURLE_OUT_OF_MEMORY)`: a buffer ceiling that C
    /// reports as an allocation failure and prints nothing for.
    const fn out_of_memory() -> Self {
        Self {
            code: CURLcode::OutOfMemory,
            message: None,
            pos: 0,
        }
    }

    /// The code `glob_url` returns.
    pub(crate) const fn code(&self) -> CURLcode {
        self.code
    }

    /// What `glob_url` writes to `*urlnum` on this path (`:525`).
    ///
    /// Always one. A malformed glob still leaves the caller with a single
    /// unexpanded URL to attempt, and that is deliberate.
    pub(crate) const fn urlnum(&self) -> i64 {
        URLNUM_ON_ERROR
    }

    /// `glob->error`: the frozen diagnostic text, when there is one.
    pub(crate) const fn message(&self) -> Option<&'static str> {
        self.message
    }

    /// `glob->pos`: the 1-based column, or 0 when the message stands alone.
    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    /// Write the diagnostic exactly as `glob_url` writes it (`:509-524`).
    ///
    /// `if(error && glob->error)`: a failure with no message prints nothing at
    /// all, which is why this can be a no-op.
    ///
    /// The prefix is `curl: `, taken from the crate's single owner. It is not
    /// derived from `CARGO_BIN_NAME`, `CARGO_PKG_NAME` or `argv[0]`: the Cargo
    /// binary is named for this crate, and every self-reported string stays
    /// `curl` (`src/tool_urlglob.c:523`, `src/tool_msgs.c:32`,
    /// `src/tool_version.h:28`). Emitting the crate's own name with a colon
    /// would break parity with the fixtures, so nobody should "fix" this into
    /// doing so.
    fn emit(&self, sink: &mut dyn Write, url: &[u8]) {
        let Some(message) = self.message else {
            return;
        };

        let text = render_diagnostic(message, self.pos, url);

        // `curl_mfprintf(error, "curl: (%d) %s\n", result, t)`.
        let mut line = Vec::with_capacity(text.len() + 16);
        line.extend_from_slice(ERROR_PREFIX.as_bytes());
        line.push(b'(');
        line.extend_from_slice(self.code.as_i32().to_string().as_bytes());
        line.extend_from_slice(b") ");
        line.extend_from_slice(&text);
        line.push(b'\n');

        // C discards `curl_mfprintf`'s return value, and so does this: a
        // diagnostic that cannot be written must not become a second failure.
        let _ = sink.write_all(&line);
    }
}

/// Render `glob_url`'s diagnostic body -- everything between `curl: (%d) ` and
/// the newline (`src/tool_urlglob.c:513-520`).
///
/// With a column: `"<message> in URL position <pos>:\n<url>\n<spaces>^"`,
/// clipped to [`DIAG_TEXT_CAPACITY`]. Without one -- `pos == 0`, which the two
/// set-overflow sites pass deliberately (`:127`, `:134`) -- the bare message,
/// with no URL echo and no caret.
///
/// The caret run is C's `%*s` with width `pos - 1` and the argument `" "`.
/// `formatf` subtracts the argument's length from the width and pads on the
/// left (`lib/mprintf.c`), so the run is `max(pos - 1, 1)` spaces: the caret
/// lands under column `pos` for every `pos >= 2`, and under column 2 when
/// `pos == 1` because a width of 0 still emits the one-byte argument. The
/// off-by-one at `pos == 1` is C's and is reproduced, not corrected.
fn render_diagnostic(message: &str, pos: usize, url: &[u8]) -> Vec<u8> {
    if pos == 0 {
        return message.as_bytes().to_vec();
    }

    let mut text = Clipped::new(DIAG_TEXT_CAPACITY);
    text.push(message.as_bytes());
    text.push(b" in URL position ");
    text.push(pos.to_string().as_bytes());
    text.push(b":\n");
    text.push(url);
    text.push(b"\n");
    text.fill(b' ', if pos >= 2 { pos - 1 } else { 1 });
    text.push(b"^");
    text.text
}

/// A parsed URL pattern and the odometer standing on it: `struct URLGlob`
/// (`src/tool_urlglob.h:64-72`).
///
/// Three of the C's six fields survive. `buf` was a scratch buffer shared by
/// the parser and the odometer and is an implementation detail of each;
/// `pnum` / `palloc` are [`Vec::len`]; `error` / `pos` moved to
/// [`GlobFailure`], because a glob only exists once parsing has succeeded.
///
/// # Examples
///
/// ```ignore
/// let (mut glob, count) = UrlGlob::parse(b"http://x/[1-3]", schemes, None)?;
/// assert_eq!(count, 3);
/// assert_eq!(glob.next_url(), Some(Ok(b"http://x/1".to_vec())));
/// ```
///
/// The example is not compiled because the scheme registry it needs is not yet
/// reachable from this crate; see the module documentation's reported gap.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct UrlGlob {
    /// `glob->pattern[0 .. pnum]`, left to right as the URL spelled them.
    patterns: Vec<UrlPattern>,

    /// `char beenhere` (`src/tool_urlglob.h:69`): whether the first
    /// combination has been handed out yet (`src/tool_urlglob.c:561-562`).
    beenhere: bool,

    /// Whether the odometer has run past its last combination.
    ///
    /// C has no such field: it leaves every pattern at its minimum and would
    /// resume the cycle. See translation difference 1 in the module
    /// documentation for why this stays exhausted, and why that is
    /// unobservable.
    exhausted: bool,
}

#[allow(dead_code)]
impl UrlGlob {
    /// `glob_url` (`src/tool_urlglob.c:491-530`): parse `url` and count the
    /// transfers it expands to.
    ///
    /// On success the count is the C's `*urlnum`, which is 1 for a URL holding
    /// no expression at all. On failure the diagnostic has already been written
    /// to `error` -- exactly as C writes it to its `FILE *` -- and
    /// [`GlobFailure::urlnum`] carries the count C would have stored.
    ///
    /// `error` is [`Option`] because the C parameter is nullable and is tested
    /// for null at `:510`; both call sites pass the tool's error stream, or
    /// `NULL` when `--silent` is in force without `--show-error`
    /// (`src/tool_operate.c:1198`). A [`Write`] rather than a `FILE *` keeps
    /// the emitted bytes assertable.
    ///
    /// `schemes` is the URL API's scheme table, needed only to resolve the
    /// `[` ambiguity; see the module documentation.
    ///
    /// # Errors
    ///
    /// [`GlobFailure`] for a malformed pattern, or for a literal, set element
    /// or expression that crosses [`MAX_CONFIG_LINE_LENGTH`].
    pub(crate) fn parse(
        url: &[u8],
        schemes: &'static dyn SchemeRegistry,
        error: Option<&mut dyn Write>,
    ) -> Result<(Self, i64), GlobFailure> {
        let mut parser = Parser::new(url, schemes);

        match parser.run() {
            Ok(amount) => Ok((
                Self {
                    patterns: parser.patterns,
                    beenhere: false,
                    exhausted: false,
                },
                amount,
            )),
            Err(failure) => {
                if let Some(sink) = error {
                    failure.emit(sink, url);
                }
                Err(failure)
            }
        }
    }

    /// `glob_next_url` (`src/tool_urlglob.c:553-634`): the next URL, or
    /// [`None`] when the pattern is spent.
    ///
    /// [`None`] is the C's "success with a null output" (`:597-599`) and is not
    /// a failure. It is distinct from `Some(Ok(vec![]))`, which is the C's
    /// `strdup("")` at `:628-629` -- an empty *URL*, which is what a URL
    /// holding no pattern at all expands to.
    ///
    /// The first call hands out the all-minimums combination without advancing
    /// (`:561-562`); every later call advances first, right to left, with the
    /// carry propagating leftward (`:566-596`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`] when the expanded URL crosses
    /// [`MAX_CONFIG_LINE_LENGTH`], which is the code C reports for its scratch
    /// buffer refusing the append (`:608`, `:614`, `:620`).
    pub(crate) fn next_url(&mut self) -> Option<Result<Vec<u8>, CURLcode>> {
        if self.exhausted {
            return None;
        }

        if self.beenhere {
            if !self.advance() {
                self.exhausted = true;
                return None;
            }
        } else {
            self.beenhere = true;
        }

        // `curlx_dyn_reset(&glob->buf)` at `:559`, then the left-to-right walk
        // at `:602-626`.
        let mut out = Vec::new();
        for pattern in &self.patterns {
            if pattern
                .kind
                .render(&mut out, MAX_CONFIG_LINE_LENGTH)
                .is_err()
            {
                return Some(Err(CURLcode::OutOfMemory));
            }
        }

        Some(Ok(out))
    }

    /// Move the odometer one place, reporting whether a combination remains.
    ///
    /// `for(i = 0; carry && (i < glob->pnum); i++)` over
    /// `glob->pattern[glob->pnum - 1 - i]` (`:566-596`): rightmost first, and a
    /// carry that survives the leftmost pattern means the sequence is spent.
    ///
    /// A glob with no patterns -- which an empty URL produces -- never enters
    /// the loop, so the carry survives and the single empty combination is all
    /// there is. That is C's behaviour too.
    fn advance(&mut self) -> bool {
        let mut carry = true;

        for pattern in self.patterns.iter_mut().rev() {
            if !carry {
                break;
            }
            carry = pattern.kind.advance();
        }

        !carry
    }

    /// `glob_match_url` (`src/tool_urlglob.c:636-715`): substitute `#N`
    /// back-references in an output file name.
    ///
    /// `#` is a substitution only when a digit follows it (`:649`); any other
    /// `#` is literal. The number is parsed with the pattern count as its
    /// ceiling and must be non-zero (`:654`), then decremented to a 0-based
    /// index (`:656`), then matched against [`UrlPattern::globindex`] rather
    /// than used as a position (`:658-663`) -- which is what makes `#1` mean
    /// "the first real glob" even when literal text occupies earlier slots.
    ///
    /// A `#N` that resolves to nothing -- out of range, zero, or naming a slot
    /// no glob claims -- is echoed **verbatim**, source bytes and all
    /// (`:687-689`, whose comment reads "use the #\[num\] in the output").
    /// That is user-visible and must not become an error.
    ///
    /// The `SANITIZEcode` out-parameter of the C signature is absent; see the
    /// module documentation.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] when the result crosses
    /// [`MAX_OUTPUT_GLOB_LENGTH`], which is the code the C's buffer reports and
    /// `:693-694` propagates unchanged.
    pub(crate) fn match_url(
        &self,
        filename: &[u8],
    ) -> Result<Vec<u8>, CURLcode> {
        let mut out = Vec::new();
        let mut cursor = 0usize;

        // `while(*filename)`: a NUL ends the name, as it ends C's string.
        while at(filename, cursor) != 0 {
            let byte = at(filename, cursor);

            if byte != b'#' || !at(filename, cursor + 1).is_ascii_digit() {
                dyn_addn(&mut out, &[byte], MAX_OUTPUT_GLOB_LENGTH)
                    .map_err(|_| CURLcode::TooLarge)?;
                cursor = cursor.saturating_add(1);
                continue;
            }

            // `const char *ptr = filename;` then `filename++` (`:650-653`).
            let start = cursor;
            cursor = cursor.saturating_add(1);

            let limit = i64::try_from(self.patterns.len()).unwrap_or(i64::MAX);
            let chosen = match str_number(filename, &mut cursor, limit) {
                // `&& num`: zero is not a back-reference.
                Some(num) if num != 0 => {
                    let wanted = num - 1;
                    self.patterns.iter().find(|pattern| {
                        pattern
                            .globindex
                            .is_some_and(|index| i64::from(index) == wanted)
                    })
                }
                _ => None,
            };

            match chosen {
                Some(pattern) => pattern
                    .kind
                    .render(&mut out, MAX_OUTPUT_GLOB_LENGTH)
                    .map_err(|_| CURLcode::TooLarge)?,
                None => {
                    let echoed = filename.get(start..cursor).unwrap_or(&[]);
                    dyn_addn(&mut out, echoed, MAX_OUTPUT_GLOB_LENGTH)
                        .map_err(|_| CURLcode::TooLarge)?;
                }
            }
        }

        Ok(out)
    }
}

impl Iterator for UrlGlob {
    /// The three states `glob_next_url` reports: a URL, a failure, and
    /// "no more" as [`None`].
    type Item = Result<Vec<u8>, CURLcode>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_url()
    }
}

/// Sound because [`UrlGlob::next_url`] latches its exhaustion; see translation
/// difference 1 in the module documentation.
impl FusedIterator for UrlGlob {}

/// The byte at `index`, or NUL past the end.
///
/// C walks a NUL-terminated `const char *` and every one of its loops stops on
/// the terminator. Reading 0 past the end reproduces that without a single
/// fallible index, and an embedded NUL ends the input here exactly as it would
/// end C's string.
fn at(input: &[u8], index: usize) -> u8 {
    input.get(index).copied().unwrap_or(0)
}

/// `curlx_str_number(&p, &num, max)` with base 10
/// (`lib/curlx/strparse.c:158-198`).
///
/// Returns the value and advances `cursor` past the digits, or [`None`] --
/// leaving `cursor` exactly where it was, which is what C's local pointer does
/// -- when there is no digit at all (`STRE_NO_NUM`) or the value would exceed
/// `max` (`STRE_OVERFLOW`). No sign, no `0x` prefix and no leading blanks are
/// accepted; leading zeroes are.
///
/// Both of the C's overflow branches are reproduced because both are reachable
/// from this module and they are not equivalent. `glob_range` passes 256 and
/// `CURL_OFF_T_MAX`, taking the general branch; `glob_match_url` passes the
/// pattern count, which takes the `max < base` branch whenever a URL holds
/// fewer than ten patterns. With `max` 3 and the input `4` the general branch
/// would hand back 4 -- above its own ceiling -- which is precisely why C
/// special-cases a low ceiling.
fn str_number(input: &[u8], cursor: &mut usize, max: i64) -> Option<i64> {
    /// The base, spelled once: C's `str_num_base(linep, nump, max, 10)`.
    const BASE: i64 = 10;

    // `DEBUGASSERT(max >= 0)`, whose comment reads "mostly to catch SIZE_MAX,
    // which is too large".
    debug_assert!(max >= 0, "a numeric ceiling is never negative");

    let mut probe = *cursor;
    let mut num: i64 = 0;

    if !at(input, probe).is_ascii_digit() {
        return None;
    }

    if max < BASE {
        // The low-ceiling branch: accumulate, then test.
        loop {
            num = num * BASE + i64::from(at(input, probe) - b'0');
            probe = probe.saturating_add(1);
            if num > max {
                return None;
            }
            if !at(input, probe).is_ascii_digit() {
                break;
            }
        }
    } else {
        // The general branch: `if(num > ((max - n) / base)) return overflow;`
        // tested before the accumulate, so the accumulate cannot overflow.
        loop {
            let digit = i64::from(at(input, probe) - b'0');
            if num > (max - digit) / BASE {
                return None;
            }
            num = num * BASE + digit;
            probe = probe.saturating_add(1);
            if !at(input, probe).is_ascii_digit() {
                break;
            }
        }
    }

    *cursor = probe;
    Some(num)
}

/// `curlx_str_single(&p, byte)` (`lib/curlx/strparse.c:125-133`): step over one
/// expected byte.
///
/// `true` is C's `STRE_OK`. A mismatch leaves `cursor` untouched.
fn str_single(input: &[u8], cursor: &mut usize, byte: u8) -> bool {
    if at(input, *cursor) != byte {
        return false;
    }

    *cursor = cursor.saturating_add(1);
    true
}

/// `curlx_str_passblanks(&p)` (`lib/curlx/strparse.c:300-304`): step over
/// spaces and tabs.
///
/// `ISBLANK` is space or horizontal tab and nothing else
/// (`lib/curl_ctype.h:45`). This is what makes `[1- 100]` a valid range
/// (`src/tool_urlglob.c:302`).
fn pass_blanks(input: &[u8], cursor: &mut usize) {
    while matches!(at(input, *cursor), b' ' | b'\t') {
        *cursor = cursor.saturating_add(1);
    }
}

/// Why the literal scanner stopped.
///
/// C expresses this with the byte the cursor stands on after its inner
/// `while(*pattern && *pattern != '{')` loop (`src/tool_urlglob.c:418-453`),
/// which can only be a NUL, a `{`, or the `[` that broke out at `:434`. Naming
/// the three makes the outer loop's `match` exhaustive, so no arm has to guess
/// at a case that cannot arise.
enum LiteralStop {
    /// The URL ended.
    End,
    /// A `{` opens a set.
    Brace,
    /// A `[` opens a range -- already ruled out as an IPv6 literal or an empty
    /// `[]`.
    Bracket,
}

/// The parser: `glob_parse` and its two helpers, with the state C threads
/// through `const char **patternp`, `size_t *posp` and `curl_off_t *amount`.
struct Parser<'input> {
    /// The URL being parsed. Never modified.
    input: &'input [u8],

    /// C's `pattern`: the byte offset the parser stands on.
    cursor: usize,

    /// C's `pos`: the 1-based column used for diagnostics, started at 1 by
    /// `glob_url` (`src/tool_urlglob.c:508`).
    ///
    /// It is *not* derived from [`Self::cursor`], and must not be: C advances
    /// the two independently, and one place where they diverge is preserved
    /// below.
    pos: usize,

    /// C's `glob->buf`: the literal or set element being accumulated.
    scratch: Vec<u8>,

    /// C's `glob->pattern[]`, grown as expressions are committed.
    patterns: Vec<UrlPattern>,

    /// C's `amount`: the running product of every pattern's size.
    amount: i64,

    /// C's `globindex`, "count 'actual' globs" (`:413`) -- incremented only for
    /// a set or a range, never for a literal.
    globindex: u32,

    /// The URL API's scheme table, used only by [`Self::peek_ipv6`].
    schemes: &'static dyn SchemeRegistry,
}

impl<'input> Parser<'input> {
    /// A parser positioned at the start of `input`, with column 1.
    fn new(input: &'input [u8], schemes: &'static dyn SchemeRegistry) -> Self {
        Self {
            input,
            cursor: 0,
            pos: 1,
            scratch: Vec::new(),
            patterns: Vec::new(),
            amount: 0,
            globindex: 0,
            schemes,
        }
    }

    /// The byte under the cursor, or NUL at the end.
    fn byte(&self) -> u8 {
        at(self.input, self.cursor)
    }

    /// The byte `ahead` places past the cursor, or NUL past the end.
    fn ahead(&self, ahead: usize) -> u8 {
        at(self.input, self.cursor.saturating_add(ahead))
    }

    /// Append to the scratch buffer, honouring its ceiling.
    ///
    /// # Errors
    ///
    /// [`GlobFailure::out_of_memory`], which is the code C substitutes for
    /// every scratch-buffer refusal (`:183`, `:430`, `:451`).
    fn keep(&mut self, bytes: &[u8]) -> Result<(), GlobFailure> {
        dyn_addn(&mut self.scratch, bytes, MAX_CONFIG_LINE_LENGTH)
            .map_err(|DynTooLarge| GlobFailure::out_of_memory())
    }

    /// `glob_parse` (`src/tool_urlglob.c:406-484`): the driver.
    ///
    /// Literal text is accumulated until an expression opens, committed as a
    /// single-element set, and then the expression is parsed on the next turn
    /// of the loop -- the shape of C's outer `while`, where the literal commit
    /// and the expression are handled in different iterations.
    ///
    /// # Errors
    ///
    /// Whatever the step that failed reported.
    fn run(&mut self) -> Result<i64, GlobFailure> {
        // `*amount = 1` (`:415`): a URL with no expression expands to itself.
        self.amount = 1;

        loop {
            let stop = self.literal()?;

            // `if(curlx_dyn_len(&glob->buf))` (`:454-461`): commit the literal
            // through `glob_fixed`, which stores one element and sets
            // `globindex = -1` (`:43`).
            if !self.scratch.is_empty() {
                let pattern = UrlPattern {
                    globindex: None,
                    kind: PatternKind::Set {
                        elems: vec![mem::take(&mut self.scratch)],
                        idx: 0,
                    },
                };
                let pos = self.pos;
                self.add_glob(pattern, pos)?;
                continue;
            }

            match stop {
                // `if(!*pattern) break;` (`:463-464`).
                LiteralStop::End => break,

                // `pattern++; pos++; glob_set(..., globindex++)` (`:465-471`).
                LiteralStop::Brace => {
                    self.cursor = self.cursor.saturating_add(1);
                    self.pos = self.pos.saturating_add(1);
                    let index = self.globindex;
                    self.globindex = self.globindex.saturating_add(1);
                    let pattern = self.glob_set(index)?;
                    let pos = self.pos;
                    self.add_glob(pattern, pos)?;
                }

                // `pattern++; pos++; glob_range(.., globindex++)`
                // (`:473-479`).
                LiteralStop::Bracket => {
                    self.cursor = self.cursor.saturating_add(1);
                    self.pos = self.pos.saturating_add(1);
                    let index = self.globindex;
                    self.globindex = self.globindex.saturating_add(1);
                    let pattern = self.glob_range(index)?;
                    let pos = self.pos;
                    self.add_glob(pattern, pos)?;
                }
            }
        }

        Ok(self.amount)
    }

    /// The literal scanner: C's inner `while(*pattern && *pattern != '{')`
    /// (`src/tool_urlglob.c:418-453`).
    ///
    /// # The escape rule here is narrow, and deliberately unlike the one inside
    /// a set
    ///
    /// A backslash escapes only `{`, `[`, `}` and `]` (`:441-443`, whose
    /// comment reads "only allow \ to escape known 'special letters'"); before
    /// anything else it is an ordinary byte and is copied. Inside a set the
    /// rule is broad -- a backslash escapes whatever follows it (`:175`).
    /// Unifying the two would silently change which inputs are accepted.
    ///
    /// # Errors
    ///
    /// `unmatched close brace/bracket` for a bare `}` or `]` (`:436-438`), or a
    /// scratch-buffer refusal.
    fn literal(&mut self) -> Result<LiteralStop, GlobFailure> {
        loop {
            match self.byte() {
                0 => return Ok(LiteralStop::End),
                b'{' => return Ok(LiteralStop::Brace),
                b'}' | b']' => {
                    return Err(GlobFailure::malformed(
                        ERR_UNMATCHED_CLOSE,
                        self.pos,
                    ))
                }
                b'[' => {
                    // `[` is ambiguous, so the URL API decides (`:419-434`).
                    let mut skip = self.peek_ipv6()?.unwrap_or(0);

                    // `if(!ipv6 && (pattern[1] == ']')) skip = 2;` -- an empty
                    // `[]` is copied through as text.
                    if skip == 0 && self.ahead(1) == b']' {
                        skip = 2;
                    }

                    if skip == 0 {
                        return Ok(LiteralStop::Bracket);
                    }

                    let end = self.cursor.saturating_add(skip);
                    let text = self
                        .input
                        .get(self.cursor..end)
                        .unwrap_or(&[])
                        .to_vec();
                    self.keep(&text)?;
                    self.cursor = end;

                    // `pos` is deliberately NOT advanced: C moves `pattern` by
                    // `skip` at `:431` and leaves `pos` alone, so a diagnostic
                    // after an IPv6 literal or an empty `[]` names a column
                    // short of the real one. Reproduced, not corrected.
                }
                byte => {
                    // `if(*pattern == '\\' && (pattern[1] is special))`
                    // (`:441-448`).
                    if byte == b'\\'
                        && matches!(self.ahead(1), b'{' | b'[' | b'}' | b']')
                    {
                        self.cursor = self.cursor.saturating_add(1);
                        self.pos = self.pos.saturating_add(1);
                    }

                    // `curlx_dyn_addn(&glob->buf, pattern++, 1); ++pos;`
                    // (`:450-452`) -- the byte the cursor stands on *after* a
                    // possible escape.
                    let current = self.byte();
                    self.keep(&[current])?;
                    self.cursor = self.cursor.saturating_add(1);
                    self.pos = self.pos.saturating_add(1);
                }
            }
        }
    }

    /// `add_glob` (`src/tool_urlglob.c:386-404`): commit one pattern.
    ///
    /// # Errors
    ///
    /// `too many {} sets` once the pattern would be the 256th; see
    /// [`PATTERN_LIMIT`] for the derivation.
    fn add_glob(
        &mut self,
        pattern: UrlPattern,
        pos: usize,
    ) -> Result<(), GlobFailure> {
        // C writes `glob->pattern[glob->pnum]` in the caller and increments
        // `pnum` here (`:390`); pushing does both.
        self.patterns.push(pattern);

        if self.patterns.len() > PATTERN_LIMIT {
            return Err(GlobFailure::malformed(ERR_TOO_MANY_SETS, pos));
        }

        Ok(())
    }

    /// `peek_ipv6` (`src/tool_urlglob.c:343-384`): is the bracketed text an
    /// IPv6 literal?
    ///
    /// Returns the number of bytes to copy through when it is -- the C's
    /// `*skip`, which counts both brackets -- and [`None`] when it is not. The
    /// C's reasoning, verbatim at `:348-350`: "Valid globs contain a hyphen and
    /// <= 1 colon. IPv6 literals contain no hyphens and >= 2 colons."
    ///
    /// The decision is the engine's, taken by parsing the bracketed text with
    /// [`UrlFlags::GUESS_SCHEME`] so that it works without a `https://` prefix
    /// (`:374-375`). Any refusal other than an allocation failure means "not an
    /// IPv6 literal" rather than a failure (`:377-382`), and that asymmetry is
    /// preserved.
    ///
    /// # Errors
    ///
    /// [`GlobFailure::out_of_memory`] only, mirroring `if(rc ==
    /// CURLUE_OUT_OF_MEMORY) return CURLE_OUT_OF_MEMORY;`.
    fn peek_ipv6(&self) -> Result<Option<usize>, GlobFailure> {
        let rest = self.input.get(self.cursor..).unwrap_or(&[]);

        // `strchr(str, ']')` searches a NUL-terminated string, so a NUL bounds
        // the search as surely as the end of the slice does.
        let bounded = match rest.iter().position(|byte| *byte == 0) {
            Some(nul) => rest.get(..nul).unwrap_or(rest),
            None => rest,
        };

        // `if(!endbr) return CURLE_OK;` -- no closing bracket, so not IPv6.
        let Some(bracket) = bounded.iter().position(|byte| *byte == b']')
        else {
            return Ok(None);
        };

        // `hlen = endbr - str + 1; if(hlen >= MAX_IP6LEN) return CURLE_OK;`
        let hlen = bracket.saturating_add(1);
        if hlen >= MAX_IP6LEN {
            return Ok(None);
        }

        let host = bounded.get(..hlen).unwrap_or(bounded);
        let mut url = Url::new(self.schemes);

        match url.set(UrlPart::Url, Some(host), UrlFlags::GUESS_SCHEME) {
            Ok(()) => Ok(Some(hlen)),
            Err(CURLUcode::OutOfMemory) => Err(GlobFailure::out_of_memory()),
            Err(_) => Ok(None),
        }
    }

    /// `glob_set` (`src/tool_urlglob.c:90-209`): a `{a,b,c}` set, entered just
    /// after the opening brace.
    ///
    /// C's own summary is at `:94-96`: "processes a set expression with the
    /// point behind the opening '{'. ','-separated elements are collected until
    /// the next closing '}'".
    ///
    /// # The closing brace is a comma too
    ///
    /// `case '}'` sets `done` and then *falls through* into `case ','`
    /// (`:130-131`), so the final element is appended by exactly the code that
    /// appends a comma-separated one. A translation that handled the brace
    /// separately would drop the last element, which is why the two share one
    /// arm below rather than being spelled twice.
    ///
    /// # Errors
    ///
    /// `unmatched brace`, `nested brace`, `empty string within braces`,
    /// `unexpected close bracket`, `range overflow`, or a scratch-buffer
    /// refusal.
    fn glob_set(&mut self, globindex: u32) -> Result<UrlPattern, GlobFailure> {
        // `size_t opos = *posp - 1` (`:101`): the column of the `{` itself,
        // which is where `unmatched brace` points rather than at the end.
        let opos = self.pos.saturating_sub(1);

        // C's `opattern` (`:100`), the start of the body, never moved.
        // Comparing against it is what tells `{}` from `{a,,b}`: only an
        // immediate `}` is empty, because after a comma the cursor has moved.
        let body = self.cursor;

        let mut elems: Vec<Vec<u8>> = Vec::new();

        loop {
            match self.byte() {
                // `case '\0'`: the URL ended while the set was open
                // (`:109-111`).
                0 => {
                    return Err(GlobFailure::malformed(
                        ERR_UNMATCHED_BRACE,
                        opos,
                    ))
                }

                // `case '{': case '[':` -- "no nested expressions at this
                // time" (`:113-116`).
                b'{' | b'[' => {
                    return Err(GlobFailure::malformed(
                        ERR_NESTED_BRACE,
                        self.pos,
                    ))
                }

                // `case ']'`: illegal closing bracket (`:169-172`).
                b']' => {
                    return Err(GlobFailure::malformed(
                        ERR_UNEXPECTED_CLOSE_BRACKET,
                        self.pos,
                    ))
                }

                // `case '}'` and `case ','` (`:118-167`).
                byte @ (b'}' | b',') => {
                    let closing = byte == b'}';

                    if closing {
                        if self.cursor == body {
                            return Err(GlobFailure::malformed(
                                ERR_EMPTY_SET,
                                self.pos,
                            ));
                        }

                        // `if(multiply(amount, size + 1))` (`:125-129`), whose
                        // comment reads "add 1 to size since it will be
                        // incremented below". The column is deliberately 0, so
                        // the bare message prints with no URL echo.
                        let size =
                            i64::try_from(elems.len()).unwrap_or(i64::MAX);
                        if multiply(&mut self.amount, size.saturating_add(1)) {
                            return Err(GlobFailure::malformed(
                                ERR_RANGE_OVERFLOW,
                                0,
                            ));
                        }
                    }

                    // `if(size >= 100000)` (`:132-134`), tested before the
                    // append. Column 0 again.
                    if elems.len() >= SET_ELEMENT_LIMIT {
                        return Err(GlobFailure::malformed(
                            ERR_RANGE_OVERFLOW,
                            0,
                        ));
                    }

                    // `elem[size] = curlx_strdup(curlx_dyn_ptr(&glob->buf) ?
                    //  curlx_dyn_ptr(&glob->buf) : "")` then `curlx_dyn_reset`
                    // (`:155-162`): an empty accumulator yields an empty
                    // element, which is what makes `{a,,b}` three elements
                    // rather than an error.
                    elems.push(mem::take(&mut self.scratch));

                    self.cursor = self.cursor.saturating_add(1);

                    if closing {
                        // `if(!done) ++(*posp)` (`:165-166`): the closing brace
                        // does NOT bump the column, so `pos` is left naming the
                        // `}` rather than the byte after it.
                        break;
                    }

                    self.pos = self.pos.saturating_add(1);
                }

                byte => {
                    // `case '\\'` (`:174-179`): inside a set a backslash
                    // escapes ANY following byte. This is the broad rule;
                    // `literal`'s is narrow, and the difference is deliberate.
                    if byte == b'\\' && self.ahead(1) != 0 {
                        self.cursor = self.cursor.saturating_add(1);
                        self.pos = self.pos.saturating_add(1);
                    }

                    // `default:` -- copy one byte to the element (`:180-187`).
                    let current = self.byte();
                    self.keep(&[current])?;
                    self.cursor = self.cursor.saturating_add(1);
                    self.pos = self.pos.saturating_add(1);
                }
            }
        }

        // `pat->c.set.idx = 0` (`:197`): the odometer starts on the first
        // element. The C's `error:` label at `:201-208`, which frees the
        // partial element array, has no counterpart: an abandoned `Vec` drops
        // itself.
        Ok(UrlPattern {
            globindex: Some(globindex),
            kind: PatternKind::Set { elems, idx: 0 },
        })
    }

    /// `glob_range` (`src/tool_urlglob.c:211-341`): a `[...]` range, entered
    /// just after the opening bracket.
    ///
    /// The accepted forms are C's own list at `:215-219`: a character range
    /// such as `a-z]` or `B-Q]`, a numeric range such as `0-9]` or `17-2000]`,
    /// and a numeric range with leading zeroes such as `001-999]`. Either may
    /// carry a `:step`.
    ///
    /// # ASCII, and only ASCII
    ///
    /// The arm is chosen by `ISALPHA` then `ISDIGIT` (`:228`, `:279`), which
    /// are locale-independent ASCII macros admitting `A-Z`, `a-z` and `0-9`
    /// and nothing else (`lib/curl_ctype.h:38-44`).
    /// [`u8::is_ascii_alphabetic`] and [`u8::is_ascii_digit`] are those macros;
    /// `char::is_alphabetic` would accept letters curl refuses and would be a
    /// real change to the accepted input set.
    ///
    /// # Errors
    ///
    /// `bad range` for a malformed range, `range overflow` for one whose size
    /// cannot be counted, or `bad range specification` when the first byte is
    /// neither a letter nor a digit.
    fn glob_range(
        &mut self,
        globindex: u32,
    ) -> Result<UrlPattern, GlobFailure> {
        // C's `*patternp`, kept so the consumed length can be added to the
        // column exactly as `*posp += (pattern - *patternp)` does.
        let start = self.cursor;
        let first = self.byte();

        if first.is_ascii_alphabetic() {
            self.glob_range_ascii(start, globindex)
        } else if first.is_ascii_digit() {
            self.glob_range_num(start, globindex)
        } else {
            // `:335-337`, the only site for this text. `[!-@]` reaches it, and
            // the column has not been advanced, so it names the first byte of
            // the body.
            Err(GlobFailure::malformed(ERR_BAD_RANGE_SPEC, self.pos))
        }
    }

    /// The alphabetic arm of [`Self::glob_range`]
    /// (`src/tool_urlglob.c:228-278`).
    fn glob_range_ascii(
        &mut self,
        start: usize,
        globindex: u32,
    ) -> Result<UrlPattern, GlobFailure> {
        let mut pmatch = false;
        let mut min_c = 0u8;
        let mut max_c = 0u8;

        // `unsigned char step = 1` (`:234`).
        let mut step = 1u8;

        // `if((pattern[1] == '-') && pattern[2] && pattern[3])` (`:238`): the
        // shape check needs all four bytes present.
        if self.ahead(1) == b'-' && self.ahead(2) != 0 && self.ahead(3) != 0 {
            min_c = self.byte();
            max_c = self.ahead(2);
            let end_c = self.ahead(3);
            pmatch = true;

            if end_c == b':' {
                // `const char *p = &pattern[4]` (`:246`). C assigns
                // `pattern = p` at `:251` whether or not the step parsed, so
                // the cursor is left wherever the parse stopped, which is
                // what makes the reported column depend on how far it got.
                self.cursor = start.saturating_add(4);

                // `if(curlx_str_number(&p, &num, 256) ||
                //     curlx_str_single(&p, ']')) step = 0; else step = num;`
                // (`:247-250`). The `||` short-circuits, so a failed number
                // never reaches the bracket test.
                step = 0;
                if let Some(num) =
                    str_number(self.input, &mut self.cursor, ASCII_STEP_LIMIT)
                {
                    if str_single(self.input, &mut self.cursor, b']') {
                        // `step = (unsigned char)num`: the cast truncates, and
                        // that is observable -- 256 becomes 0 and is then
                        // refused by the `!step` conjunct below, so `[a-z:256]`
                        // is not a step of 256.
                        step = u8::try_from(num).unwrap_or(0);
                    }
                }
            } else if end_c != b']' {
                // `:253-255` -- "then this is wrong". The cursor is
                // deliberately left where it was.
                pmatch = false;
            } else {
                // `pattern += 4` (`:258`).
                self.cursor = start.saturating_add(4);
            }
        }

        // `*posp += (pattern - *patternp)` (`:261`), before validation, so the
        // caret lands after the offending range rather than on its first byte.
        self.pos = self.pos.saturating_add(self.cursor.saturating_sub(start));

        // `:263-266`, conjunct for conjunct: no match; a zero step; equal
        // endpoints with a step other than 1; or, for unequal endpoints,
        // reversed order, a step wider than the span, or a span wider than
        // `'z' - 'a'`. The last is what refuses `[A-z]`.
        let min = as_signed_char(min_c);
        let max = as_signed_char(max_c);
        let span = max - min;

        if !pmatch
            || step == 0
            || (min == max && step != 1)
            || (min != max
                && (min > max
                    || i32::from(step) > span
                    || span > ASCII_SPAN_LIMIT))
        {
            return Err(GlobFailure::malformed(ERR_BAD_RANGE, self.pos));
        }

        // `multiply(amount, ((max - min) / step + 1))` (`:275-277`). The span
        // is at most 25 and the step at least 1, so the count is at most 26 and
        // only the product can overflow.
        let count = span / i32::from(step) + 1;
        if multiply(&mut self.amount, i64::from(count)) {
            return Err(GlobFailure::malformed(ERR_RANGE_OVERFLOW, self.pos));
        }

        // `pat->c.ascii.letter = pat->c.ascii.min = min_c` (`:272`): the
        // odometer starts on the first letter.
        Ok(UrlPattern {
            globindex: Some(globindex),
            kind: PatternKind::Ascii {
                min: min_c,
                max: max_c,
                letter: min_c,
                step,
            },
        })
    }

    /// The numeric arm of [`Self::glob_range`] (`src/tool_urlglob.c:279-333`).
    fn glob_range_num(
        &mut self,
        start: usize,
        globindex: u32,
    ) -> Result<UrlPattern, GlobFailure> {
        let mut min_n = 0i64;
        let mut max_n = 0i64;
        let mut step_n = 0i64;
        let mut npad = 0usize;

        // `if(*pattern == '0')` (`:289-297`): "leading zero specified, count
        // them!". The loop starts at the first digit, so it counts EVERY digit
        // of the minimum and not only the zeroes -- `[001-999]` gives 3 and
        // `[10-20]` gives 0 -- and the width then applies to every value the
        // pattern produces, as the comment at `:294-295` says.
        if self.byte() == b'0' {
            let mut probe = self.cursor;
            while at(self.input, probe).is_ascii_digit() {
                probe = probe.saturating_add(1);
                npad = npad.saturating_add(1);
            }
        }

        // The cascade at `:299-315`. Every step advances the cursor only on
        // success, so a shape that does not match leaves `step_n` at 0 -- C's
        // "else bad syntax" (`:312`) -- and leaves the column naming wherever
        // the parse stopped.
        if let Some(num) = str_number(self.input, &mut self.cursor, i64::MAX) {
            min_n = num;

            if str_single(self.input, &mut self.cursor, b'-') {
                // `curlx_str_passblanks(&pattern)` (`:302`): blanks after the
                // hyphen are skipped, so `[1- 100]` is a valid range.
                pass_blanks(self.input, &mut self.cursor);

                if let Some(num) =
                    str_number(self.input, &mut self.cursor, i64::MAX)
                {
                    max_n = num;

                    if str_single(self.input, &mut self.cursor, b']') {
                        step_n = 1;
                    } else if str_single(self.input, &mut self.cursor, b':') {
                        if let Some(num) =
                            str_number(self.input, &mut self.cursor, i64::MAX)
                        {
                            if str_single(self.input, &mut self.cursor, b']') {
                                step_n = num;
                            }
                        }
                    }
                }
            }
        }

        // `*posp += (pattern - *patternp)` (`:317`).
        self.pos = self.pos.saturating_add(self.cursor.saturating_sub(start));

        // `:319-321`. Note there is no span cap here, unlike the alphabetic
        // arm's 25.
        if step_n == 0
            || (min_n == max_n && step_n != 1)
            || (min_n != max_n && (min_n > max_n || step_n > max_n - min_n))
        {
            return Err(GlobFailure::malformed(ERR_BAD_RANGE, self.pos));
        }

        // `multiply(amount, ((max - min) / step + 1))` (`:331-333`). The
        // subtraction is safe -- both are non-negative and now known ordered --
        // but the increment overflows for `[0-9223372036854775807]`, where C is
        // undefined; see translation difference 2 in the module documentation.
        let span = max_n - min_n;
        let Some(count) = (span / step_n).checked_add(1) else {
            return Err(GlobFailure::malformed(ERR_RANGE_OVERFLOW, self.pos));
        };

        if multiply(&mut self.amount, count) {
            return Err(GlobFailure::malformed(ERR_RANGE_OVERFLOW, self.pos));
        }

        // `pat->c.num.idx = pat->c.num.min = min_n` (`:327`). The stale comment
        // at `:325-326` about "typecasting to ints" does not apply: every value
        // stays a signed 64-bit integer here, as the struct's own fields are.
        Ok(UrlPattern {
            globindex: Some(globindex),
            kind: PatternKind::Num {
                min: min_n,
                max: max_n,
                idx: min_n,
                step: step_n,
                npad,
            },
        })
    }
}

/// The value C's `char` holds for `byte` where `char` is signed.
///
/// `glob_range` keeps `min_c`, `max_c` and `end_c` in `char`
/// (`src/tool_urlglob.c:231-233`) and compares them with `>` at `:265`, so its
/// answer for a byte at or above 0x80 depends on the platform's `char`
/// signedness: signed on x86_64 Linux and on both Apple targets, where the
/// arm64 ABI specifies a signed `char`, and unsigned on aarch64 Linux. The
/// signed reading is reproduced here because the oracle this implementation is
/// measured against is curl 8.19.0-DEV built for x86_64 Linux, which refuses
/// `[z-\x80]` through the `min_c > max_c` conjunct.
///
/// Only `max_c` is affected: `min_c` reaches the comparison solely through
/// `ISALPHA`, which admits no byte at or above 0x80. The other two conjuncts
/// agree with C either way, because a negative span makes C's
/// `step > (unsigned)(max_c - min_c)` false while its `min_c > max_c` has
/// already refused the range.
fn as_signed_char(byte: u8) -> i32 {
    if byte >= 0x80 {
        i32::from(byte) - 256
    } else {
        i32::from(byte)
    }
}

#[cfg(test)]
mod tests {
    use curl_rs_lib::url::SchemeInfo;

    use super::*;

    /// A test double for the scheme table [`UrlGlob::parse`] is handed.
    ///
    /// Deliberately tiny rather than a copy of the engine's 33-entry table,
    /// which would be a second source of truth. It can be tiny because the
    /// probe never reads it: every string it parses begins with `[`, so the
    /// engine finds no scheme to look up and guesses one without consulting a
    /// registry. The two entries exist only so the double is honest about the
    /// contract it implements, and they are the shape
    /// `curl-rs-lib/src/url/mod.rs` documents for an out-of-crate
    /// implementation.
    struct Schemes;

    impl SchemeRegistry for Schemes {
        fn lookup(&self, scheme: &[u8]) -> Option<SchemeInfo> {
            // ASCII-only folding, as curl's own lookup folds.
            if scheme.eq_ignore_ascii_case(b"http") {
                Some(SchemeInfo {
                    name: "http",
                    default_port: 80,
                    url_options: false,
                    runnable: true,
                })
            } else if scheme.eq_ignore_ascii_case(b"https") {
                Some(SchemeInfo {
                    name: "https",
                    default_port: 443,
                    url_options: false,
                    runnable: true,
                })
            } else {
                None
            }
        }
    }

    static SCHEMES: Schemes = Schemes;

    /// Everything `url` expands to, as text, with the count `parse` promised.
    ///
    /// [`None`] when the parse was refused or a URL could not be rendered, so a
    /// test that expects an expansion cannot pass vacuously on a failure. The
    /// walk goes through the [`Iterator`] implementation, which exercises it as
    /// well as [`UrlGlob::next_url`].
    fn expand(url: &str) -> Option<(Vec<String>, i64)> {
        let (mut glob, count) =
            UrlGlob::parse(url.as_bytes(), &SCHEMES, None).ok()?;

        let mut produced = Vec::new();
        for next in &mut glob {
            produced.push(String::from_utf8(next.ok()?).ok()?);
        }

        Some((produced, count))
    }

    /// The diagnostic a refused URL reports: text, column and code.
    ///
    /// [`None`] when the URL was in fact accepted, so an acceptance cannot be
    /// mistaken for the refusal a test asserts.
    fn refusal(url: &[u8]) -> Option<(&'static str, usize, CURLcode)> {
        match UrlGlob::parse(url, &SCHEMES, None) {
            Err(failure) => Some((
                failure.message().unwrap_or("<none>"),
                failure.position(),
                failure.code(),
            )),
            Ok(_) => None,
        }
    }

    /// The exact bytes `glob_url` writes to its error stream for `url`.
    fn diagnostic(url: &[u8]) -> Vec<u8> {
        let mut sink: Vec<u8> = Vec::new();
        let outcome = UrlGlob::parse(url, &SCHEMES, Some(&mut sink));

        assert!(
            outcome.is_err(),
            "this helper is for refused URLs, and {url:?} was accepted"
        );

        sink
    }

    /// `str_list` as owned strings, so an expectation reads like the URLs it
    /// describes.
    fn owned(list: &[&str]) -> Vec<String> {
        list.iter().map(|text| (*text).to_string()).collect()
    }

    /// Advance `url`'s odometer `steps` places past its first combination, then
    /// substitute `template`.
    fn substitute(url: &str, steps: usize, template: &str) -> Option<String> {
        let (mut glob, _) =
            UrlGlob::parse(url.as_bytes(), &SCHEMES, None).ok()?;

        for _ in 0..=steps {
            glob.next_url()?.ok()?;
        }

        String::from_utf8(glob.match_url(template.as_bytes()).ok()?).ok()
    }

    // Expansion correctness.

    #[test]
    fn a_set_expands_in_the_order_it_was_written() {
        let expected = owned(&["http://x/a", "http://x/b", "http://x/c"]);
        assert_eq!(expand("http://x/{a,b,c}"), Some((expected, 3)));
    }

    #[test]
    fn a_numeric_range_counts_up() {
        let expected = owned(&["http://x/1", "http://x/2", "http://x/3"]);
        assert_eq!(expand("http://x/[1-3]"), Some((expected, 3)));
    }

    #[test]
    fn a_leading_zero_pads_every_value() {
        // The `npad` rule at src/tool_urlglob.c:289-297 and the `%0*` render at
        // :618-619. This is the single most byte-visible behaviour in the file.
        let expected = owned(&["http://x/001", "http://x/002", "http://x/003"]);
        assert_eq!(expand("http://x/[001-003]"), Some((expected, 3)));
    }

    #[test]
    fn a_minimum_without_a_leading_zero_is_not_padded() {
        let expected = owned(&["http://x/10", "http://x/11", "http://x/12"]);
        assert_eq!(expand("http://x/[10-12]"), Some((expected, 3)));
    }

    #[test]
    fn a_step_never_overshoots_the_maximum() {
        // `idx += step` then `if(idx > max)` (:586-587): 1, 5, 9 and not 13.
        let expected = owned(&["http://x/1", "http://x/5", "http://x/9"]);
        assert_eq!(expand("http://x/[1-10:4]"), Some((expected, 3)));
    }

    #[test]
    fn an_alphabetic_range_walks_the_letters() {
        let expected = owned(&["a", "b", "c", "d", "e"]);
        assert_eq!(expand("[a-e]"), Some((expected, 5)));
    }

    #[test]
    fn an_alphabetic_range_honours_its_step() {
        assert_eq!(expand("[a-e:2]"), Some((owned(&["a", "c", "e"]), 3)));
    }

    #[test]
    fn the_odometer_runs_right_to_left() {
        // The rightmost pattern moves fastest (:566-570), and the carry crosses
        // the literal `/` in between on its way to the set.
        let expected = owned(&["a/1", "a/2", "b/1", "b/2"]);
        assert_eq!(expand("{a,b}/[1-2]"), Some((expected, 4)));
    }

    #[test]
    fn a_url_without_a_pattern_expands_to_itself() {
        assert_eq!(expand("http://x/y"), Some((owned(&["http://x/y"]), 1)));
    }

    #[test]
    fn an_empty_url_yields_one_empty_url() {
        // C's `*globbed = strdup("")` at :628-629: an empty string, which is
        // not the same state as the null that means "no more".
        assert_eq!(expand(""), Some((owned(&[""]), 1)));
    }

    #[test]
    fn the_promised_count_matches_what_is_produced() {
        for url in [
            "http://x/{a,b,c}",
            "http://x/[1-3]",
            "http://x/[001-003]",
            "http://x/[1-10:4]",
            "[a-e]",
            "[a-e:2]",
            "{a,b}/[1-2]",
            "http://x/y",
            "",
            "{a,,b}",
            "[5-5]",
            "{a}{b}{c}",
        ] {
            let expansion = expand(url);
            assert!(expansion.is_some(), "{url} should expand");
            let (produced, count) = expansion.unwrap_or_default();

            assert_eq!(
                i64::try_from(produced.len()).unwrap_or(-1),
                count,
                "{url} promised {count} URLs and produced {}",
                produced.len()
            );
        }
    }

    #[test]
    fn exhaustion_is_not_a_failure_and_does_not_restart() {
        let parsed = UrlGlob::parse(b"[1-2]", &SCHEMES, None);
        assert!(parsed.is_ok(), "[1-2] should parse: {parsed:?}");
        let Ok((mut glob, count)) = parsed else {
            return;
        };

        assert_eq!(count, 2);
        assert_eq!(glob.next_url(), Some(Ok(b"1".to_vec())));
        assert_eq!(glob.next_url(), Some(Ok(b"2".to_vec())));

        // Translation difference 1: C would resume its cycle here and hand back
        // `2` again. Staying exhausted is what `FusedIterator` promises.
        assert_eq!(glob.next_url(), None);
        assert_eq!(glob.next_url(), None);
        assert_eq!(glob.next_url(), None);
    }

    // Acceptance rules -- alphabetic ranges.

    #[test]
    fn alphabetic_ranges_are_accepted_and_refused_as_c_does() {
        for accepted in ["[a-e]", "[a-a]", "[a-z]", "[a-z:25]", "[B-Q]"] {
            assert_eq!(
                refusal(accepted.as_bytes()),
                None,
                "{accepted} should be accepted"
            );
        }

        for (refused, why) in [
            // Reversed endpoints.
            ("[e-a]", ERR_BAD_RANGE),
            // Equal endpoints with a step other than 1.
            ("[a-a:2]", ERR_BAD_RANGE),
            // A span of 57, wider than 'z' - 'a'.
            ("[A-z]", ERR_BAD_RANGE),
            // A zero step.
            ("[a-z:0]", ERR_BAD_RANGE),
            // A step wider than the span: the number overflows the 256 ceiling
            // and `step` becomes 0.
            ("[a-z:999]", ERR_BAD_RANGE),
            // 256 itself, which `(unsigned char)` truncates to 0.
            ("[a-z:256]", ERR_BAD_RANGE),
            // A step of 26 over a span of 25.
            ("[a-z:26]", ERR_BAD_RANGE),
            // Nothing after the hyphen.
            ("[a-]", ERR_BAD_RANGE),
            // Neither ':' nor ']' where the terminator belongs.
            ("[a-z!]", ERR_BAD_RANGE),
        ] {
            let outcome = refusal(refused.as_bytes());
            assert_eq!(
                outcome.map(|(message, _, code)| (message, code)),
                Some((why, CURLcode::UrlMalformat)),
                "{refused} should be refused with {why}"
            );
        }
    }

    #[test]
    fn a_signed_char_reading_refuses_a_high_maximum() {
        // `[z-\x80]` has a span of 6 read unsigned and a reversed order read
        // signed, so the two readings disagree; see `as_signed_char`.
        //
        // Measured against the oracle rather than reasoned about: curl on
        // x86_64 Linux answers `bad range in URL position 6` for this input,
        // which is the signed reading, and both the text and the column are
        // asserted here.
        assert_eq!(
            refusal(b"[z-\x80]"),
            Some((ERR_BAD_RANGE, 6, CURLcode::UrlMalformat))
        );
    }

    // Acceptance rules -- numeric ranges.

    #[test]
    fn numeric_ranges_are_accepted_and_refused_as_c_does() {
        for accepted in [
            "[1-100]",
            "[5-5]",
            "[1-100:5]",
            "[0-9]",
            "[001-999]",
            "[1-2:1]",
        ] {
            assert_eq!(
                refusal(accepted.as_bytes()),
                None,
                "{accepted} should be accepted"
            );
        }

        for refused in [
            "[100-1]",
            "[5-5:2]",
            "[1-100:0]",
            "[1-100:200]",
            "[1-2",
            "[1-2:3]",
            "[9-1]",
        ] {
            let outcome = refusal(refused.as_bytes());
            assert_eq!(
                outcome.map(|(message, _, code)| (message, code)),
                Some((ERR_BAD_RANGE, CURLcode::UrlMalformat)),
                "{refused} should be refused"
            );
        }
    }

    #[test]
    fn blanks_after_the_hyphen_are_skipped() {
        // `curlx_str_passblanks` at :302.
        assert_eq!(refusal(b"[1- 100]"), None);
        assert_eq!(refusal(b"[1-\t100]"), None);

        let expansion = expand("[1- 3]");
        assert!(expansion.is_some(), "[1- 3] should expand");
        let (produced, count) = expansion.unwrap_or_default();

        assert_eq!(count, 3);
        assert_eq!(produced, owned(&["1", "2", "3"]));
    }

    #[test]
    fn a_minimum_too_large_for_a_signed_64_bit_integer_is_a_bad_range() {
        // `curlx_str_number` refuses the value and leaves the cursor alone, so
        // the cascade never runs and `step_n` stays 0.
        let outcome = refusal(b"[99999999999999999999-1]");
        assert_eq!(outcome.map(|(message, _, _)| message), Some(ERR_BAD_RANGE));
    }

    #[test]
    fn a_range_that_is_neither_letters_nor_digits_names_itself() {
        // The only site for this text (:335-337).
        assert_eq!(
            refusal(b"[!-@]"),
            Some((ERR_BAD_RANGE_SPEC, 2, CURLcode::UrlMalformat))
        );
    }

    #[test]
    fn classification_is_ascii_only() {
        // `ISALPHA` admits A-Z and a-z and nothing else, so a non-ASCII letter
        // is neither a character range nor a numeric one and reaches the
        // `bad range specification` arm. `char::is_alphabetic` would accept it
        // and widen the input set.
        //
        // The letter is written as its two UTF-8 bytes rather than as itself
        // because `scripts/spacecheck.pl` refuses a byte at or above 0x80 in
        // any tracked file. These are U+00E9, LATIN SMALL LETTER E WITH ACUTE.
        assert_eq!(
            refusal(b"[\xc3\xa9-z]").map(|(message, _, _)| message),
            Some(ERR_BAD_RANGE_SPEC)
        );

        // A lone high byte, which is what a non-UTF-8 argument could carry,
        // reaches the same arm.
        assert_eq!(
            refusal(b"[\xe9-z]").map(|(message, _, _)| message),
            Some(ERR_BAD_RANGE_SPEC)
        );
    }

    // Acceptance rules -- sets.

    #[test]
    fn an_unterminated_set_points_at_its_opening_brace() {
        assert_eq!(
            refusal(b"http://x/{"),
            Some((ERR_UNMATCHED_BRACE, 10, CURLcode::UrlMalformat))
        );
        assert_eq!(
            refusal(b"http://x/{a,b"),
            Some((ERR_UNMATCHED_BRACE, 10, CURLcode::UrlMalformat))
        );
    }

    #[test]
    fn nesting_is_refused_for_both_openers() {
        assert_eq!(
            refusal(b"{a{b}}").map(|(message, _, _)| message),
            Some(ERR_NESTED_BRACE)
        );
        assert_eq!(
            refusal(b"{a[1-2]}").map(|(message, _, _)| message),
            Some(ERR_NESTED_BRACE)
        );
    }

    #[test]
    fn an_immediately_closed_set_is_empty_but_a_middle_element_may_be() {
        assert_eq!(
            refusal(b"{}").map(|(message, _, _)| message),
            Some(ERR_EMPTY_SET)
        );

        // `opattern == pattern` is only true on the first byte of the body
        // (:119), so an empty element anywhere else is accepted.
        assert_eq!(expand("{a,,b}"), Some((owned(&["a", "", "b"]), 3)));
        assert_eq!(expand("{,a}"), Some((owned(&["", "a"]), 2)));
        assert_eq!(expand("{a,}"), Some((owned(&["a", ""]), 2)));
    }

    #[test]
    fn a_close_bracket_inside_a_set_names_itself() {
        assert_eq!(
            refusal(b"{a]").map(|(message, _, _)| message),
            Some(ERR_UNEXPECTED_CLOSE_BRACKET)
        );
    }

    #[test]
    fn a_bare_closer_in_literal_text_is_unmatched() {
        assert_eq!(
            refusal(b"}"),
            Some((ERR_UNMATCHED_CLOSE, 1, CURLcode::UrlMalformat))
        );
        assert_eq!(
            refusal(b"]"),
            Some((ERR_UNMATCHED_CLOSE, 1, CURLcode::UrlMalformat))
        );
        assert_eq!(
            refusal(b"http://x/a}b").map(|(message, _, _)| message),
            Some(ERR_UNMATCHED_CLOSE)
        );
    }

    // Limits.

    #[test]
    fn the_two_hundred_and_fifty_sixth_pattern_is_refused() {
        // PATTERN_LIMIT's derivation: `pnum < 255` at :393 against a `palloc`
        // that doubles, so 255 patterns fit and the next one does not.
        let accepted = "{a}".repeat(PATTERN_LIMIT);
        assert_eq!(refusal(accepted.as_bytes()), None);

        let refused = "{a}".repeat(PATTERN_LIMIT + 1);
        assert_eq!(
            refusal(refused.as_bytes())
                .map(|(message, _, code)| (message, code)),
            Some((ERR_TOO_MANY_SETS, CURLcode::UrlMalformat))
        );
    }

    #[test]
    fn a_literal_run_counts_towards_the_pattern_limit() {
        // Each run of literal text is a pattern too (:454-461), so alternating
        // literals and sets reaches the ceiling twice as fast.
        let refused = "x{a}".repeat(PATTERN_LIMIT);
        assert_eq!(
            refusal(refused.as_bytes()).map(|(message, _, _)| message),
            Some(ERR_TOO_MANY_SETS)
        );
    }

    #[test]
    fn a_set_may_hold_a_hundred_thousand_elements_but_not_one_more() {
        // `if(size >= 100000)` is tested before the append (:133).
        let mut accepted = String::with_capacity(2 * SET_ELEMENT_LIMIT + 2);
        accepted.push('{');
        for index in 0..SET_ELEMENT_LIMIT {
            if index != 0 {
                accepted.push(',');
            }
            accepted.push('a');
        }
        accepted.push('}');

        let parsed = UrlGlob::parse(accepted.as_bytes(), &SCHEMES, None);
        assert!(
            parsed.is_ok(),
            "a set of 100,000 elements should parse: {:?}",
            parsed.as_ref().err()
        );
        let Ok((glob, count)) = parsed else { return };

        assert_eq!(count, 100_000);
        assert_eq!(glob.patterns.len(), 1);

        let mut refused = accepted;
        refused.pop();
        refused.push_str(",a}");

        // Column 0, so the bare message prints with no URL echo (:134).
        assert_eq!(
            refusal(refused.as_bytes()),
            Some((ERR_RANGE_OVERFLOW, 0, CURLcode::UrlMalformat))
        );
    }

    #[test]
    fn a_product_too_large_for_a_signed_64_bit_integer_overflows() {
        // Two ranges of 10^11 each: the product is about 10^22 and the count
        // cannot be represented. The column is asserted because the oracle
        // reports this same input as `range overflow in URL position 31`.
        assert_eq!(
            refusal(b"[1-99999999999][1-99999999999]"),
            Some((ERR_RANGE_OVERFLOW, 31, CURLcode::UrlMalformat))
        );
    }

    #[test]
    fn a_count_that_cannot_be_represented_overflows() {
        // The one input where `span / step + 1` overflows, and the one place
        // this module knowingly answers differently from the C: translation
        // difference 2 records that a release build of the C tool stores a
        // count of zero here and proceeds, on undefined behaviour, while a
        // build with its assertions live aborts instead. This refuses the
        // input, with the message every other unrepresentable count gets.
        let outcome = refusal(b"[0-9223372036854775807]");
        assert_eq!(
            outcome.map(|(message, _, code)| (message, code)),
            Some((ERR_RANGE_OVERFLOW, CURLcode::UrlMalformat))
        );

        // A step of 2 or more halves the quotient, so nothing else can reach
        // the overflow and every neighbouring input is still accepted.
        assert_eq!(refusal(b"[0-9223372036854775807:2]"), None);
        assert_eq!(refusal(b"[1-9223372036854775807]"), None);
    }

    #[test]
    fn an_expanded_url_may_not_cross_the_scratch_ceiling() {
        // The scratch buffer's own ceiling, reported as C reports it (:608).
        let element = "a".repeat(MAX_CONFIG_LINE_LENGTH / 2);
        let url = format!("{{{element}}}{{{element}}}");

        let parsed = UrlGlob::parse(url.as_bytes(), &SCHEMES, None);
        assert!(
            parsed.is_ok(),
            "two large elements should parse: {:?}",
            parsed.as_ref().err()
        );
        let Ok((mut glob, _)) = parsed else { return };

        assert_eq!(glob.next_url(), Some(Err(CURLcode::OutOfMemory)));
    }

    // Escaping, which differs between literal text and a set.

    #[test]
    fn literal_text_escapes_only_the_four_special_bytes() {
        for (input, expected) in [
            ("a\\{b", "a{b"),
            ("a\\[b", "a[b"),
            ("a\\}b", "a}b"),
            ("a\\]b", "a]b"),
        ] {
            assert_eq!(
                expand(input),
                Some((owned(&[expected]), 1)),
                "{input} should escape its special byte"
            );
        }

        // Anything else keeps the backslash: the comment at :440 reads "only
        // allow \\ to escape known 'special letters'".
        assert_eq!(expand("a\\db"), Some((owned(&["a\\db"]), 1)));
        assert_eq!(expand("a\\\\b"), Some((owned(&["a\\\\b"]), 1)));
    }

    #[test]
    fn a_set_escapes_whatever_follows_the_backslash() {
        // The broad rule at :174-179, and the difference from literal text is
        // the point of this test.
        assert_eq!(expand("{a\\,b}"), Some((owned(&["a,b"]), 1)));
        assert_eq!(expand("{a\\xb}"), Some((owned(&["axb"]), 1)));
        assert_eq!(expand("{a\\}b}"), Some((owned(&["a}b"]), 1)));
        assert_eq!(expand("{a\\\\b}"), Some((owned(&["a\\b"]), 1)));
    }

    #[test]
    fn a_trailing_backslash_inside_a_set_is_not_an_escape() {
        // `if(pattern[1])` at :175: with nothing following, the backslash is
        // copied and the set is then unterminated.
        assert_eq!(
            refusal(b"{a\\").map(|(message, _, _)| message),
            Some(ERR_UNMATCHED_BRACE)
        );
    }

    // The `[` ambiguity.

    #[test]
    fn an_ipv6_literal_is_not_a_range() {
        assert_eq!(
            expand("http://[::1]:8080/"),
            Some((owned(&["http://[::1]:8080/"]), 1))
        );
        assert_eq!(
            expand("http://[::1]/"),
            Some((owned(&["http://[::1]/"]), 1))
        );
    }

    #[test]
    fn a_range_that_could_not_be_an_address_is_a_range() {
        let expected = owned(&["http://1/", "http://2/", "http://3/"]);
        assert_eq!(expand("http://[1-3]/"), Some((expected, 3)));
    }

    #[test]
    fn an_empty_bracket_pair_is_copied_through() {
        // `if(!ipv6 && (pattern[1] == ']')) skip = 2` (:426-427).
        assert_eq!(expand("http://x/[]"), Some((owned(&["http://x/[]"]), 1)));
        assert_eq!(
            expand("http://x/[]/y"),
            Some((owned(&["http://x/[]/y"]), 1))
        );
    }

    #[test]
    fn a_bracket_run_at_the_ceiling_is_never_an_address() {
        // `if(hlen >= MAX_IP6LEN) return CURLE_OK` (:364-365): the probe gives
        // up, so the text is offered to `glob_range`, which refuses it.
        let long = "a".repeat(MAX_IP6LEN);
        let url = format!("http://[{long}]/");

        assert_eq!(
            refusal(url.as_bytes()).map(|(message, _, _)| message),
            Some(ERR_BAD_RANGE)
        );
    }

    #[test]
    fn the_column_is_not_advanced_over_a_copied_bracket_run() {
        // The quirk at :428-433: `pattern` moves by `skip` and `pos` does not,
        // so a later diagnostic names a column short of the real one. The `}`
        // below really sits at column 14.
        assert_eq!(
            refusal(b"http://[::1]/}"),
            Some((ERR_UNMATCHED_CLOSE, 9, CURLcode::UrlMalformat))
        );
    }

    #[test]
    fn a_closing_brace_does_not_advance_the_column() {
        // `if(!done) ++(*posp)` at :165-166: after a set, `pos` names the `}`.
        // The second `}` below really sits at column 13.
        assert_eq!(
            refusal(b"http://x/{a}}"),
            Some((ERR_UNMATCHED_CLOSE, 12, CURLcode::UrlMalformat))
        );
    }

    // Diagnostics: the frozen bytes.

    #[test]
    fn a_diagnostic_wraps_the_message_the_url_and_a_caret() {
        assert_eq!(
            diagnostic(b"http://x/{"),
            b"curl: (3) unmatched brace in URL position 10:\n\
              http://x/{\n         ^\n"
                .to_vec()
        );
    }

    #[test]
    fn a_caret_at_column_one_sits_one_place_to_the_right() {
        // `%*s` with a width of 0 still emits its one-byte argument, so C puts
        // the caret at column 2. Reproduced, not corrected.
        assert_eq!(
            diagnostic(b"}"),
            b"curl: (3) unmatched close brace/bracket in URL position 1:\n\
              }\n ^\n"
                .to_vec()
        );
    }

    #[test]
    fn a_caret_at_the_last_column_lands_under_it() {
        assert_eq!(
            diagnostic(b"x{}"),
            b"curl: (3) empty string within braces in URL position 3:\n\
              x{}\n  ^\n"
                .to_vec()
        );
    }

    #[test]
    fn a_column_of_zero_prints_the_bare_message() {
        // The two set-overflow sites pass 0 deliberately (:127, :134), and
        // `if(glob->pos)` at :513 then skips the URL echo and the caret.
        let mut refused = String::with_capacity(2 * SET_ELEMENT_LIMIT + 4);
        refused.push('{');
        for index in 0..=SET_ELEMENT_LIMIT {
            if index != 0 {
                refused.push(',');
            }
            refused.push('a');
        }
        refused.push('}');

        assert_eq!(
            diagnostic(refused.as_bytes()),
            b"curl: (3) range overflow\n".to_vec()
        );
    }

    #[test]
    fn the_code_in_the_prefix_is_the_malformed_url_code() {
        assert_eq!(CURLcode::UrlMalformat.as_i32(), 3);

        let emitted = diagnostic(b"}");
        assert!(
            emitted.starts_with(b"curl: (3) "),
            "the prefix must be `curl: (3) ` and was {emitted:?}"
        );
    }

    #[test]
    fn the_prefix_is_never_the_binary_name() {
        let emitted = diagnostic(b"}");
        let text = String::from_utf8_lossy(&emitted).into_owned();

        assert!(
            text.starts_with("curl: "),
            "the self-reported name is `curl`, and this was {text:?}"
        );
        assert!(
            !text.contains("curl-rs"),
            "the Cargo binary is `curl-rs` but the diagnostic must not say so"
        );
    }

    #[test]
    fn an_over_long_diagnostic_is_clipped_rather_than_grown() {
        // `char text[512]` with `curl_msnprintf`, which keeps 511 bytes.
        let mut url = Vec::with_capacity(1024);
        url.push(b'}');
        url.extend(std::iter::repeat(b'a').take(1000));

        let emitted = diagnostic(&url);
        let prefix = b"curl: (3) ";

        assert_eq!(emitted.len(), prefix.len() + DIAG_TEXT_CAPACITY + 1);
        assert!(emitted.starts_with(prefix));
        assert_eq!(emitted.last(), Some(&b'\n'));

        // Everything after the message and the echoed URL was clipped away, so
        // the caret never arrives.
        assert!(!emitted.ends_with(b"^\n"));
    }

    #[test]
    fn nothing_is_written_when_no_sink_is_given() {
        // `if(error && glob->error)` at :510: a null stream prints nothing, and
        // the failure is reported all the same.
        assert!(UrlGlob::parse(b"}", &SCHEMES, None).is_err());
    }

    #[test]
    fn a_failure_reports_a_count_of_one() {
        // `*urlnum = 1` at :525, not zero.
        let parsed = UrlGlob::parse(b"}", &SCHEMES, None);
        assert!(parsed.is_err(), "a bare closing brace must be refused");
        let Err(failure) = parsed else { return };

        assert_eq!(failure.urlnum(), URLNUM_ON_ERROR);
        assert_eq!(failure.urlnum(), 1);
        assert_eq!(failure.code(), CURLcode::UrlMalformat);
        assert_eq!(failure.message(), Some(ERR_UNMATCHED_CLOSE));
        assert_eq!(failure.position(), 1);
    }

    #[test]
    fn a_failure_without_a_message_prints_nothing() {
        // The allocation-failure shape: `globerror(glob, NULL, ...)`.
        let mut sink: Vec<u8> = Vec::new();
        GlobFailure::out_of_memory().emit(&mut sink, b"http://x/");

        assert!(sink.is_empty());
        assert_eq!(GlobFailure::out_of_memory().message(), None);
        assert_eq!(GlobFailure::out_of_memory().code(), CURLcode::OutOfMemory);
    }

    // `#N` substitution.

    #[test]
    fn a_back_reference_follows_the_glob_it_names() {
        assert_eq!(
            substitute("http://x/{a,b}", 0, "out#1.txt"),
            Some("outa.txt".to_string())
        );
        assert_eq!(
            substitute("http://x/{a,b}", 1, "out#1.txt"),
            Some("outb.txt".to_string())
        );
    }

    #[test]
    fn a_back_reference_skips_literal_patterns() {
        // The lookup is by `globindex` (:658-663), and the leading literal
        // carries -1, so `#1` is the first real glob rather than the first
        // pattern.
        assert_eq!(
            substitute("http://x/{a,b}/[7-9]", 0, "#1-#2"),
            Some("a-7".to_string())
        );
        assert_eq!(
            substitute("http://x/{a,b}/[7-9]", 1, "#1-#2"),
            Some("a-8".to_string())
        );
        assert_eq!(
            substitute("http://x/{a,b}/[7-9]", 3, "#1-#2"),
            Some("b-7".to_string())
        );
    }

    #[test]
    fn a_back_reference_reproduces_the_padding() {
        assert_eq!(
            substitute("http://x/[001-003]", 1, "f#1.bin"),
            Some("f002.bin".to_string())
        );
    }

    #[test]
    fn an_unresolvable_back_reference_is_echoed_verbatim() {
        // ":687-689 -- #[num] out of range, use the #[num] in the output".
        for template in ["out#2.txt", "out#0.txt", "out#9.txt", "out#77.txt"] {
            assert_eq!(
                substitute("http://x/{a,b}", 0, template),
                Some(template.to_string()),
                "{template} names no glob and must be echoed"
            );
        }
    }

    #[test]
    fn a_hash_without_a_digit_is_literal() {
        for template in ["out#x.txt", "out#.txt", "out#", "#", "##1"] {
            let expected = template.replace("#1", "a");
            assert_eq!(
                substitute("http://x/{a,b}", 0, template),
                Some(expected),
                "{template} has no substitution but the one it spells"
            );
        }
    }

    #[test]
    fn substitution_leaves_every_other_byte_alone() {
        assert_eq!(
            substitute("[1-2]", 0, "a/b/c d\te.f"),
            Some("a/b/c d\te.f".to_string())
        );
    }

    #[test]
    fn an_over_long_output_name_reports_the_buffer_ceiling() {
        // Verified rather than assumed: `dyn_nappend` reports CURLE_TOO_LARGE
        // and :693-694 propagates it unchanged.
        let parsed = UrlGlob::parse(b"x", &SCHEMES, None);
        assert!(parsed.is_ok(), "a literal URL should parse: {parsed:?}");
        let Ok((mut glob, _)) = parsed else { return };

        assert_eq!(glob.next_url(), Some(Ok(b"x".to_vec())));

        let template = vec![b'x'; MAX_OUTPUT_GLOB_LENGTH];
        assert_eq!(glob.match_url(&template), Err(CURLcode::TooLarge));

        // One byte below the ceiling still fits: `fit = len + idx + 1`.
        let template = vec![b'x'; MAX_OUTPUT_GLOB_LENGTH - 1];
        assert_eq!(
            glob.match_url(&template).map(|out| out.len()),
            Ok(template.len())
        );
    }

    // The helpers, exercised directly.

    #[test]
    fn multiply_reports_overflow_and_treats_zero_as_zero() {
        let mut amount = 6i64;
        assert!(!multiply(&mut amount, 7));
        assert_eq!(amount, 42);

        // The non-positive short-circuit at :71-73 is not an error.
        let mut amount = 5i64;
        assert!(!multiply(&mut amount, 0));
        assert_eq!(amount, 0);

        let mut amount = 0i64;
        assert!(!multiply(&mut amount, 5));
        assert_eq!(amount, 0);

        let mut amount = i64::MAX;
        assert!(multiply(&mut amount, 2));
        assert_eq!(amount, i64::MAX, "an overflow leaves the count untouched");
    }

    #[test]
    fn str_number_reproduces_both_of_the_c_overflow_branches() {
        // The general branch, taken whenever the ceiling is at least the base.
        let mut cursor = 0usize;
        assert_eq!(str_number(b"123]", &mut cursor, i64::MAX), Some(123));
        assert_eq!(cursor, 3);

        // Leading zeroes are accepted and do not change the value.
        let mut cursor = 0usize;
        assert_eq!(str_number(b"007", &mut cursor, i64::MAX), Some(7));
        assert_eq!(cursor, 3);

        // No digit at all: `STRE_NO_NUM`, and the cursor does not move.
        let mut cursor = 2usize;
        assert_eq!(str_number(b"ab-cd", &mut cursor, i64::MAX), None);
        assert_eq!(cursor, 2);

        // Over the ceiling: `STRE_OVERFLOW`, and the cursor does not move.
        let mut cursor = 0usize;
        assert_eq!(str_number(b"257]", &mut cursor, ASCII_STEP_LIMIT), None);
        assert_eq!(cursor, 0);

        // 256 is exactly the ceiling and is accepted here; it is the
        // `(unsigned char)` cast in `glob_range` that then makes it a zero
        // step.
        let mut cursor = 0usize;
        assert_eq!(
            str_number(b"256]", &mut cursor, ASCII_STEP_LIMIT),
            Some(256)
        );
        assert_eq!(u8::try_from(256i64).unwrap_or(0), 0);

        // The low-ceiling branch tests after accumulating, which is why C
        // special-cases it: the general branch would have accepted 4 here.
        let mut cursor = 0usize;
        assert_eq!(str_number(b"4", &mut cursor, 3), None);
        assert_eq!(cursor, 0);

        let mut cursor = 0usize;
        assert_eq!(str_number(b"3", &mut cursor, 3), Some(3));
        assert_eq!(cursor, 1);

        // A ceiling of zero accepts a written zero and nothing else.
        let mut cursor = 0usize;
        assert_eq!(str_number(b"0", &mut cursor, 0), Some(0));
        let mut cursor = 0usize;
        assert_eq!(str_number(b"1", &mut cursor, 0), None);
    }

    #[test]
    fn str_single_and_pass_blanks_step_only_over_what_they_match() {
        let mut cursor = 0usize;
        assert!(str_single(b"]x", &mut cursor, b']'));
        assert_eq!(cursor, 1);

        assert!(!str_single(b"]x", &mut cursor, b']'));
        assert_eq!(cursor, 1, "a mismatch leaves the cursor alone");

        // Past the end reads NUL, which matches nothing.
        let mut cursor = 9usize;
        assert!(!str_single(b"]x", &mut cursor, b']'));

        let mut cursor = 0usize;
        pass_blanks(b" \t \tz", &mut cursor);
        assert_eq!(cursor, 4);

        let mut cursor = 0usize;
        pass_blanks(b"z", &mut cursor);
        assert_eq!(cursor, 0);

        // A newline is not a blank: `ISBLANK` is space and tab only.
        let mut cursor = 0usize;
        pass_blanks(b"\nz", &mut cursor);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn a_nul_ends_the_input_as_it_ends_a_c_string() {
        assert_eq!(at(b"ab", 0), b'a');
        assert_eq!(at(b"ab", 2), 0, "past the end reads NUL");
        assert_eq!(expand("a\0b"), Some((owned(&["a"]), 1)));
    }

    #[test]
    fn as_signed_char_matches_a_signed_c_char() {
        assert_eq!(as_signed_char(b'a'), 97);
        assert_eq!(as_signed_char(0x7f), 127);
        assert_eq!(as_signed_char(0x80), -128);
        assert_eq!(as_signed_char(0xff), -1);
    }

    #[test]
    fn dyn_addn_refuses_the_append_that_would_cross_the_ceiling() {
        // `fit = len + idx + 1 > toobig`, so a ceiling of 4 holds 3 bytes.
        let mut buf = Vec::new();
        assert_eq!(dyn_addn(&mut buf, b"abc", 4), Ok(()));
        assert_eq!(dyn_addn(&mut buf, b"d", 4), Err(DynTooLarge));
        assert_eq!(buf, b"abc".to_vec(), "a refusal appends nothing");
    }

    #[test]
    fn a_clipped_buffer_stops_at_its_ceiling() {
        let mut clipped = Clipped::new(4);
        clipped.push(b"ab");
        clipped.fill(b' ', 9);
        clipped.push(b"^");
        assert_eq!(clipped.text, b"ab  ".to_vec());
    }

    #[test]
    fn render_diagnostic_places_the_caret_by_column() {
        assert_eq!(
            render_diagnostic("bad range", 4, b"abcdef"),
            b"bad range in URL position 4:\nabcdef\n   ^".to_vec()
        );
        assert_eq!(
            render_diagnostic("bad range", 1, b"abcdef"),
            b"bad range in URL position 1:\nabcdef\n ^".to_vec()
        );
        assert_eq!(
            render_diagnostic("bad range", 0, b"abcdef"),
            b"bad range".to_vec()
        );
    }

    #[test]
    fn every_frozen_message_is_spelled_exactly_as_the_c_spells_it() {
        // The nine distinct strings across the thirteen `globerror` sites that
        // carry one. Byte-for-byte, and every one `CURLE_URL_MALFORMAT`.
        assert_eq!(ERR_UNMATCHED_BRACE, "unmatched brace");
        assert_eq!(ERR_NESTED_BRACE, "nested brace");
        assert_eq!(ERR_EMPTY_SET, "empty string within braces");
        assert_eq!(ERR_RANGE_OVERFLOW, "range overflow");
        assert_eq!(ERR_UNEXPECTED_CLOSE_BRACKET, "unexpected close bracket");
        assert_eq!(ERR_BAD_RANGE, "bad range");
        assert_eq!(ERR_BAD_RANGE_SPEC, "bad range specification");
        assert_eq!(ERR_TOO_MANY_SETS, "too many {} sets");
        assert_eq!(ERR_UNMATCHED_CLOSE, "unmatched close brace/bracket");
    }

    #[test]
    fn the_limits_are_the_ones_the_c_enforces() {
        assert_eq!(
            PATTERN_LIMIT, 255,
            "src/tool_urlglob.c:393, not the dead 30"
        );
        assert_eq!(SET_ELEMENT_LIMIT, 100_000);
        assert_eq!(MAX_IP6LEN, 128);
        assert_eq!(MAX_OUTPUT_GLOB_LENGTH, 1024 * 1024);
        assert_eq!(MAX_CONFIG_LINE_LENGTH, 10 * 1024 * 1024);
        assert_eq!(ASCII_STEP_LIMIT, 256);
        assert_eq!(ASCII_SPAN_LIMIT, 25);
        assert_eq!(DIAG_TEXT_CAPACITY, 511);
    }

    #[test]
    fn a_literal_pattern_carries_no_glob_index() {
        let parsed = UrlGlob::parse(b"http://x/{a}/[1-2]", &SCHEMES, None);
        assert!(parsed.is_ok(), "the URL should parse: {parsed:?}");
        let Ok((glob, _)) = parsed else { return };

        let indices: Vec<Option<u32>> = glob
            .patterns
            .iter()
            .map(|pattern| pattern.globindex)
            .collect();

        // Literal, set, literal, range: only the expressions are numbered, and
        // they are numbered from zero in the order they appear.
        assert_eq!(indices, vec![None, Some(0), None, Some(1)]);
    }
}
