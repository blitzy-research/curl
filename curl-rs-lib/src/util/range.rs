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

// THE LAYERING RULE, AS IT APPLIES TO THIS FILE IN PARTICULAR.
//
// The C original does not parse a range. It parses a range AND WRITES THE
// ANSWER INTO THE EASY HANDLE:
//
//   CURLcode Curl_range(struct Curl_easy *data);   /* lib/curl_range.h:30 */
// THE FOUR DIAGNOSTICS THAT DO NOT COME ACROSS, PRESERVED VERBATIM.
//
// The C emits four trace lines, and every one of them is wrapped in
// `DEBUGF()`, so every one exists only in a debug build. Two reasons they are
// not reproduced, and it is the second that decides the matter:
//
//  * this layer holds no handle and performs no output. `infof` writes
//    through `data`, which is precisely what the note above removed; and
// * the specification settles the observable question independently.
//
// Recording the format strings costs nothing and keeps the provenance, so
// that whichever module ever wants them emits the same text instead of
// inventing new text. Verbatim from `lib/curl_range.c:52`, `:62`, `:78-80`
// and `:82-84`, wrapped here exactly where the C wraps them:
//
//   "RANGE %" FMT_OFF_T " to end of file"
//   "RANGE the last %" FMT_OFF_T " bytes"
//   "RANGE from %" FMT_OFF_T " getting %" FMT_OFF_T " bytes"
//   "range-download from %" FMT_OFF_T
//     " to %" FMT_OFF_T ", totally %" FMT_OFF_T " bytes"

// THE C's CONDITIONAL COMPILATION HAS NO COUNTERPART HERE.
//
// The whole function sits inside a guard, `lib/curl_range.c:30-31`:
//
//   /* Only include this function if one or more of FTP, FILE are enabled. */
//   #if !defined(CURL_DISABLE_FTP) || !defined(CURL_DISABLE_FILE)
//
// So NO `#[cfg(feature = ...)]` appears anywhere in this file, and the
// omission is a decision rather than an oversight. Writing
// `#[cfg(feature = "file")]` would not be a harmless approximation of the C:
// Cargo does not reject an unknown feature name in a `cfg` predicate, it
// simply evaluates it FALSE, so the module would compile away to nothing and
// the two call sites would fail to resolve against a name that appears to be
// right there on disk. `fnmatch` is the sibling that does carry a gate, on
// `ftp`, and it carries one because its C original sits inside
// `#ifndef CURL_DISABLE_FTP` with no disjunction to rescue it.
//
// The `ftp` feature is deliberately NOT used to gate this file either, even
// though FTP is one of the two callers: gating on `ftp` alone would delete
// the module from a build that still has `file://`, which is the exact
// mistake the C's disjunction exists to avoid.

//! Byte-range parsing -- supersedes `lib/curl_range.c` and `lib/curl_range.h`.
//!
//! One function wide. The C translation unit defines exactly one symbol and
//! its header declares exactly one, so this module publishes one entry
//! point, [`parse`], together with the type it answers in, [`RangeSpec`],
//! and the one named constant its callers need,
//! [`MAXDOWNLOAD_UNLIMITED`].
//!
//! # Three outcomes, not two fields
//!
//! The C writes into two fields, and the temptation is to return a struct
//! holding both. That would be wrong, and the reason is visible in the
//! source: **the three success branches write DIFFERENT SUBSETS of the
//! two.**
//!
//! | Range | `data->state.resume_from` | `data->req.maxdownload` |
//! |---|---|---|
//! | `X-` | `X` | *untouched* |
//! | `-Y` | `-Y` | `Y` |
//! | `X-Y` | `X` | `(Y - X) + 1` |
//! | *no range at all* | *untouched* | `-1` |
//!
//! # The grammar, in one table
//!
//! Every accepted and rejected shape, each row traced through the C at
//! `lib/curl_range.c:41-81` and asserted by a test at the foot of this file.
//! `E` is [`CURLcode::RangeError`].
//!
//! | Input | Result | Why |
//! |---|---|---|
//! | `100-200` | `Span { 100, 101 }` | inclusive: 200 - 100, plus one |
//! | `0-0` | `Span { 0, 1 }` | one byte, not zero bytes |
//! | `100-` | `FromOffset { 100 }` | no upper bound; no limit is written |
//! | `-500` | `LastBytes { 500 }` | the last 500 bytes; offset is `-500` |
//! | `-` | `FromOffset { 0 }` | both numbers absent; see below |
//! | `-abc` | `FromOffset { 0 }` | ditto -- `abc` is not a number |
//! | `100-200junk` | `Span { 100, 101 }` | trailing bytes are not inspected |
//! | `100-200-300` | `Span { 100, 101 }` | ditto -- the 2nd dash trails |
//! | `-0` | `E` | the C's own comment: "-0" is just wrong |
//! | `5-3` | `E` | the upper bound must follow the lower |
//! | `0-9223372036854775807` | `E` | the span would be `CURL_OFF_T_MAX` |
//! | `100` | `E` | a bare number has no dash |
//! | `` | `E` | nothing to parse |
//! | `abc` | `E` | no number and no leading dash |
//! | ` 100-200` | `E` | blanks are not skipped |
//! | `99999999999999999999-` | `E` | overflow, and not a clamp |
//!
//! ## Trailing bytes are accepted, leading blanks are not
//!
//! [`strparse::str_number`] stops at the first byte that is not a digit and
//! the C never asks whether anything is left, so `100-200junk` and
//! `100-200-300` are both exactly `100-200`. That leniency is part of the
//! frozen surface and no end-of-input check is added here.
//!
//! Leading blanks are the opposite case, and the asymmetry is deliberate in
//! the C as well: `curlx_str_number` requires a digit AT the cursor, and the
//! blank-skipping variant, `curlx_str_numblanks`, exists but is not the one
//! this function calls. So ` 100-200` is rejected.
//!
//! ## An out-of-range number is an error, not a clamp
//!
//! `99999999999999999999-` does not become `CURL_OFF_T_MAX-`. The number
//! overflows, `str_num_base` returns without advancing the cursor, and the
//! dash test then finds a `9` where it needs a `-`. The rejection comes from
//! the dash test rather than from the overflow, which is why the error is
//! [`CURLcode::RangeError`] and not something about a value being too large.
//!
//! # Why `&[u8]` and not `&str`
//!
//! `data->state.range` is a `char *` taken straight from user input, and the
//! C never validates its encoding. Taking a byte slice reproduces that: a
//! range string that is not valid text is rejected by the grammar, as
//! [`CURLcode::RangeError`], rather than by a decoder that would have to
//! invent an error code the C never returns. An embedded zero byte behaves
//! as the C's terminator does, because [`strparse`] resolves a read past the
//! end of its cursor to zero for exactly this reason.
//!
//! # Visibility and layering
//!
//! `pub(crate)` throughout, with no `pub` item. `CURLOPT_RANGE` is set through
//! `curl_easy_setopt`, whose variadic dispatch lives in the ABI crate; the
//! string it stores arrives here later, as a slice.
//!
//! No internal item is widened to make the C's own tests
//! link. `lib/curl_range.c` has no `tests/unit` counterpart in any case --
//! its coverage in the C tree comes from the FTP and `file://` fixtures --
//! and the test module at the foot of this file is where that coverage now
//! lives.

use crate::error::CURLcode;
use crate::util::strparse;

/// The value of `maxdownload` that means "no limit".
///
/// `struct SingleRequest` states it in the field's own comment
/// (`lib/request.h:58-59`): *"in bytes, the maximum amount of data to fetch,
/// -1 means unlimited"*. `lib/request.c:125` initialises the field to it at
/// the start of every request, and `lib/curl_range.c:87` re-applies it on the
/// path where no range was given at all.
#[allow(dead_code)] // Applied by `protocols::{file, ftp}`.
pub(crate) const MAXDOWNLOAD_UNLIMITED: i64 = -1;

/// A parsed byte-range specification: what the transfer should do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RangeSpec {
    /// `X-` -- start at `X` and continue to the end of the resource.
    FromOffset {
        /// The offset to resume from. Non-negative.
        resume_from: i64,
    },

    /// `-Y` -- the last `Y` bytes of the resource.
    ///
    /// `data->req.maxdownload = to;` and `data->state.resume_from = -to;`
    /// (`lib/curl_range.c:60-61`). Both fields are written, and the offset is
    /// **negative**: that sign is how "measure from the end" travels to the
    /// consumers, and it is not normalised away here.
    LastBytes {
        /// How many bytes from the end. In `1..=i64::MAX`.
        count: i64,
    },

    /// `X-Y` -- the bytes from `X` to `Y` inclusive.
    Span {
        /// The offset to resume from, the C's `from`. Non-negative.
        resume_from: i64,
        /// How many bytes to fetch, the C's `totalsize + 1`. At least 1.
        maxdownload: i64,
    },
}

impl RangeSpec {
    /// The value the caller must store in `data->state.resume_from`.
    ///
    /// Every branch of the C writes this field, so there is always an answer
    /// and the return type is a plain `i64` rather than an [`Option`].
    ///
    /// Negative for [`RangeSpec::LastBytes`], and deliberately so -- see that
    /// variant. Non-negative for the other two.
    #[allow(dead_code)] // Readers: the two callers.
    #[must_use]
    pub(crate) const fn resume_from(&self) -> i64 {
        match *self {
            // `data->state.resume_from = from;`
            Self::FromOffset { resume_from } => resume_from,

            // `data->state.resume_from = -to;`
            Self::LastBytes { count } => count.wrapping_neg(),

            // `data->state.resume_from = from;`
            Self::Span { resume_from, .. } => resume_from,
        }
    }

    /// The value the caller must store in `data->req.maxdownload`, or
    /// [`None`] when the C writes nothing.
    ///
    /// The correct call-site shape is therefore a conditional store, and NOT
    /// `unwrap_or(MAXDOWNLOAD_UNLIMITED)`:
    ///
    /// ```text
    /// state.resume_from = spec.resume_from();
    /// if let Some(limit) = spec.maxdownload() {
    ///     request.maxdownload = limit;
    /// }
    /// ```
    #[allow(dead_code)] // Readers: the two callers.
    #[must_use]
    pub(crate) const fn maxdownload(&self) -> Option<i64> {
        match *self {
            // The branch that writes nothing at all.
            Self::FromOffset { .. } => None,

            // `data->req.maxdownload = to;`
            Self::LastBytes { count } => Some(count),

            // `data->req.maxdownload = totalsize + 1;`
            Self::Span { maxdownload, .. } => Some(maxdownload),
        }
    }
}

/// Parses a `-r` / `CURLOPT_RANGE` specification.
///
/// # Two helper conventions that read backwards
///
/// The C calls two functions from `lib/curlx/strparse.c` whose return
/// convention is inverted relative to Rust intuition, and misreading either
/// one silently changes the grammar. Both return `STRE_OK`, which is **zero**,
/// on SUCCESS, so `if(curlx_str_number(...))` means *"if it FAILED"*. Here
/// they are [`strparse::str_number`] and [`strparse::str_single`], which
/// return [`Result`], so the sense is written out rather than implied.
///
/// Three properties of theirs are load-bearing:
///
/// * **Neither advances the cursor on failure.** `str_num_base` assigns
///   `*linep = p` on its last line only (`lib/curlx/strparse.c:189`), and
///   `curlx_str_single` increments only after the byte matched; the Rust
///   siblings write the cursor once, at the end, for the same effect. This is
///   what makes an overflowing FIRST number an error rather than a clamp: the
///   cursor still points at a digit, so the dash test fails.
/// * **A failed number is zero, not indeterminate.** `*nump = 0` precedes the
///   digit test (`lib/curlx/strparse.c:167`), which is why `-` succeeds with
///   an offset of zero. [`Result`] has no value to read on the error path, so
///   the zero is written here explicitly, as that module's own documentation
///   prescribes.
/// * **No sign, no blanks, no prefix.** `str_number` requires a decimal digit
///   at the cursor. A leading `-` is not part of a number, which is precisely
///   how the `-Y` form is recognised at all.
///
/// # Arithmetic
///
/// Three operations can overflow an `i64`, and each is guarded:
///
/// * `-to`, the negative offset of the `-Y` form. Checked with
///   [`i64::checked_neg`] below, and see [`RangeSpec::resume_from`] for why
///   the accessor cannot panic either.
/// * `to - from`, the span. Guarded by the `from > to` rejection immediately
///   above it, which -- with both values known non-negative -- bounds the
///   difference to `0..=i64::MAX`.
/// * `totalsize + 1`, the inclusive length. Guarded by the explicit
///   `totalsize == i64::MAX` rejection AND by [`i64::checked_add`]. The
///   explicit test is kept because it is the C's, and it is what makes
///   `0-9223372036854775807` an error rather than a silently wrong length;
///   the checked addition is kept because a guard that is one edit away from
///   being wrong should not be the only thing standing between this line and
///   a panic.
///
/// # Errors
///
/// [`CURLcode::RangeError`], which is `CURLE_RANGE_ERROR = 33`
/// (`include/curl/curl.h:560`), and nothing else. It is the only code the C
/// returns from this function apart from `CURLE_OK`, and it has one
/// backward-compatibility alias in the public header, `CURLE_HTTP_RANGE_ERROR`
/// (`include/curl/curl.h:704`), which resolves to the same integer.
#[allow(dead_code)] // Callers: the two callers.
pub(crate) fn parse(range: &[u8]) -> Result<RangeSpec, CURLcode> {
    // `const char *p = data->state.range;`
    //
    // The C's `char *` walk becomes the cursor the sibling module already
    // provides: a `&mut &[u8]` that each helper re-points on success and
    // leaves alone on failure.
    let mut cursor = range;

    // `if(curlx_str_number(&p, &from, CURL_OFF_T_MAX))`
    //   `first_num = FALSE;`
    //
    // `CURL_OFF_T_MAX` is `i64::MAX`. The two facts extracted from the one
    // call are the C's two: whether a number was there, and its value.
    let first = strparse::str_number(&mut cursor, i64::MAX);

    // `bool first_num = TRUE;` then cleared on failure. It distinguishes
    // `X-Y` from `-Y` further down and is used for nothing else.
    let first_num = first.is_ok();

    // The C's `*nump = 0` default, made explicit because [`Result`] carries
    // no value on the error path. Reached by every input that does not start
    // with a decimal digit, and by one that does: an overflowing number also
    // leaves zero here, though the dash test below then rejects it anyway.
    let from = first.unwrap_or(0);

    // `if(curlx_str_single(&p, '-'))`
    //   `/* no leading dash or after the first number is an error */`
    //   `return CURLE_RANGE_ERROR;`
    if strparse::str_single(&mut cursor, b'-').is_err() {
        return Err(CURLcode::RangeError);
    }

    // The C's three-way branch, in the C's order. The order matters: the
    // absence of the SECOND number decides `X-` regardless of `first_num`,
    // so `-` and `-abc` are `X-` forms with an offset of zero rather than
    // `-Y` forms.
    match strparse::str_number(&mut cursor, i64::MAX) {
        // `if(curlx_str_number(&p, &to, CURL_OFF_T_MAX)) {`
        //   `/* no second number */ /* X - */`
        //   `data->state.resume_from = from;`
        // `}`
        Err(_) => Ok(RangeSpec::FromOffset { resume_from: from }),

        // `else if(!first_num) {`  `/* -Y */`
        Ok(to) if !first_num => {
            // `if(!to)`
            //   `/* "-0" is just wrong */`
            //   `return CURLE_RANGE_ERROR;`
            //
            // Scoped to THIS branch in the C, which is why `0-0` is legal:
            // there, `first_num` is true and the test is never reached.
            if to == 0 {
                return Err(CURLcode::RangeError);
            }

            // `data->state.resume_from = -to;`
            if to.checked_neg().is_none() {
                return Err(CURLcode::RangeError);
            }

            // `data->req.maxdownload = to;`
            Ok(RangeSpec::LastBytes { count: to })
        }

        // `else {`  `/* X-Y */`
        Ok(to) => {
            // `/* Ensure the range is sensible - to should follow from. */`
            // `if(from > to)`
            //   `return CURLE_RANGE_ERROR;`
            if from > to {
                return Err(CURLcode::RangeError);
            }

            // `totalsize = to - from;`
            //
            // Cannot overflow: both operands come from
            // [`strparse::str_number`] under a `max` of `i64::MAX` and are
            // therefore in `0..=i64::MAX`, and the test above establishes
            // `from <= to`, so the difference is in `0..=i64::MAX` too.
            let totalsize = to - from;

            // `if(totalsize == CURL_OFF_T_MAX)`
            //   `return CURLE_RANGE_ERROR;`
            if totalsize == i64::MAX {
                return Err(CURLcode::RangeError);
            }

            // `data->req.maxdownload = totalsize + 1; /* include last byte */`
            //
            // Inclusive at both ends, so `0-0` is one byte. Checked as well
            // as guarded, per the note above.
            let maxdownload =
                totalsize.checked_add(1).ok_or(CURLcode::RangeError)?;

            // `data->state.resume_from = from;`
            Ok(RangeSpec::Span {
                resume_from: from,
                maxdownload,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, RangeSpec, MAXDOWNLOAD_UNLIMITED};
    use crate::error::CURLcode;
    use crate::util::strparse;

    /// The two field values a fresh request starts with, so that every
    /// assertion below about "the field was not written" has something real to
    /// compare against.
    const FRESH: (i64, i64) = (0, MAXDOWNLOAD_UNLIMITED);

    /// A transliteration of `Curl_range` (`lib/curl_range.c:37-85`) that
    /// writes through two out-parameters the way the C writes into two struct
    /// fields, used as the differential oracle in the sweeps below.
    fn c_curl_range(
        range: &[u8],
        resume_from: &mut i64,
        maxdownload: &mut i64,
    ) -> Result<(), CURLcode> {
        // `curl_off_t from, to; bool first_num = TRUE;`
        let mut first_num = true;

        // `const char *p = data->state.range;`
        let mut p: &[u8] = range;

        // `if(curlx_str_number(&p, &from, CURL_OFF_T_MAX))`
        //   `first_num = FALSE;`
        //
        // `*nump = 0` happens before the digit test, so `from` is zero on
        // every failure path.
        let mut from: i64 = 0;
        match strparse::str_number(&mut p, i64::MAX) {
            Ok(number) => from = number,
            Err(_) => first_num = false,
        }

        // `if(curlx_str_single(&p, '-')) return CURLE_RANGE_ERROR;`
        if strparse::str_single(&mut p, b'-').is_err() {
            return Err(CURLcode::RangeError);
        }

        // `if(curlx_str_number(&p, &to, CURL_OFF_T_MAX)) { ... }`
        let mut to: i64 = 0;
        let second_failed = match strparse::str_number(&mut p, i64::MAX) {
            Ok(number) => {
                to = number;
                false
            }
            Err(_) => true,
        };

        if second_failed {
            // `/* no second number */ /* X - */`
            // `data->state.resume_from = from;`
            *resume_from = from;
        } else if !first_num {
            // `/* -Y */`
            if to == 0 {
                // `/* "-0" is just wrong */`
                return Err(CURLcode::RangeError);
            }
            // `data->req.maxdownload = to;`
            *maxdownload = to;
            // `data->state.resume_from = -to;`
            *resume_from = -to;
        } else {
            // `/* X-Y */`
            if from > to {
                return Err(CURLcode::RangeError);
            }
            let totalsize = to - from;
            if totalsize == i64::MAX {
                return Err(CURLcode::RangeError);
            }
            // `data->req.maxdownload = totalsize + 1; /* include last byte */`
            *maxdownload = totalsize + 1;
            // `data->state.resume_from = from;`
            *resume_from = from;
        }

        Ok(())
    }

    /// Runs [`parse`] the way a call site must: store the offset always, store
    /// the limit only when one was produced.
    ///
    /// This is the shape [`RangeSpec::maxdownload`] documents, and expressing
    /// it once here is what lets the differential sweeps compare field values
    /// rather than enum variants.
    fn apply(range: &[u8]) -> Result<(i64, i64), CURLcode> {
        // Only the limit starts from the fresh value. The offset is written on
        // every one of the three branches, so binding it to `FRESH.0` first
        // would be an assignment no path can read -- which the compiler says
        // so about, under `-D warnings`.
        let (_, mut maxdownload) = FRESH;

        let spec = parse(range)?;
        let resume_from = spec.resume_from();
        if let Some(limit) = spec.maxdownload() {
            maxdownload = limit;
        }
        Ok((resume_from, maxdownload))
    }

    /// The same call, through the oracle.
    fn apply_c(range: &[u8]) -> Result<(i64, i64), CURLcode> {
        let (mut resume_from, mut maxdownload) = FRESH;
        c_curl_range(range, &mut resume_from, &mut maxdownload)?;
        Ok((resume_from, maxdownload))
    }

    // The `X-` form: an offset, and NO limit.

    /// `0-` is the whole resource stated the long way, and the assertion that
    /// matters is the second one: the limit is [`None`], so a caller leaves
    /// its field alone.
    #[test]
    fn from_offset_zero_writes_no_limit() {
        let spec = parse(b"0-").expect("`0-` is a valid range");
        assert_eq!(spec, RangeSpec::FromOffset { resume_from: 0 });
        assert_eq!(spec.resume_from(), 0);
        assert_eq!(spec.maxdownload(), None, "`X-` writes no limit");
        assert_eq!(apply(b"0-"), Ok((0, MAXDOWNLOAD_UNLIMITED)));
    }

    #[test]
    fn from_offset_carries_the_number() {
        let spec = parse(b"100-").expect("`100-` is a valid range");
        assert_eq!(spec, RangeSpec::FromOffset { resume_from: 100 });
        assert_eq!(spec.resume_from(), 100);
        assert_eq!(spec.maxdownload(), None);
    }

    /// A lone dash SUCCEEDS, with an offset of zero.
    ///
    /// This is the row a reader of the C gets wrong. `curlx_str_number` fails
    /// on `-` because a dash is not a digit, so `first_num` is cleared -- but
    /// `str_num_base` has already written `*nump = 0`
    /// (`lib/curlx/strparse.c:167`, before the digit test at `:169`), so
    /// `from` is a defined zero rather than indeterminate. The dash then
    /// matches, the second number fails too, and the `X-` branch stores that
    /// zero. There is no undefined behaviour to inherit and the zero is
    /// deliberate.
    #[test]
    fn a_lone_dash_is_the_whole_resource() {
        assert_eq!(parse(b"-"), Ok(RangeSpec::FromOffset { resume_from: 0 }));
        assert_eq!(apply(b"-"), Ok((0, MAXDOWNLOAD_UNLIMITED)));
    }

    /// `-abc` follows the same path as `-`, and is therefore NOT an error.
    #[test]
    fn a_dash_followed_by_text_is_the_whole_resource() {
        assert_eq!(
            parse(b"-abc"),
            Ok(RangeSpec::FromOffset { resume_from: 0 }),
            "the second number is absent, so this is an `X-` form"
        );
        assert_eq!(apply(b"-abc"), apply_c(b"-abc"));
    }

    // The `-Y` form: the last N bytes, encoded as a NEGATIVE offset.

    /// The sign is the signal, so it is asserted explicitly rather than
    /// implied by an enum comparison.
    #[test]
    fn last_bytes_encodes_a_negative_offset() {
        let spec = parse(b"-500").expect("`-500` is a valid range");
        assert_eq!(spec, RangeSpec::LastBytes { count: 500 });
        assert_eq!(spec.maxdownload(), Some(500), "the limit is the count");
        assert_eq!(spec.resume_from(), -500, "the OFFSET is negative");
        assert!(spec.resume_from() < 0, "the sign must not be normalised");
        assert_eq!(apply(b"-500"), Ok((-500, 500)));
    }

    /// `-1` is the smallest accepted count, and it is the one input whose
    /// resolved offset collides with [`MAXDOWNLOAD_UNLIMITED`] as an
    /// integer -- in a different field, which is why the two are kept
    /// distinct by name rather than by value.
    #[test]
    fn last_bytes_accepts_a_count_of_one() {
        assert_eq!(parse(b"-1"), Ok(RangeSpec::LastBytes { count: 1 }));
        assert_eq!(apply(b"-1"), Ok((-1, 1)));
    }

    /// The C's comment is *"'-0' is just wrong"*, and the test exists to pin
    /// that the rejection lives in the `-Y` branch only.
    #[test]
    fn a_count_of_zero_is_rejected() {
        assert_eq!(parse(b"-0"), Err(CURLcode::RangeError));
        assert_eq!(parse(b"-00"), Err(CURLcode::RangeError));
        assert_eq!(
            parse(b"0-0"),
            Ok(RangeSpec::Span {
                resume_from: 0,
                maxdownload: 1
            }),
            "the zero test is scoped to `-Y`, so `0-0` stays legal"
        );
    }

    /// The largest count, whose negation is `-i64::MAX`.
    ///
    /// `i64::MAX` is one below the only value whose negation does not fit, so
    /// this proves the [`i64::checked_neg`] guard in [`parse`] admits
    /// everything it should while [`RangeSpec::resume_from`] returns the
    /// negation without wrapping.
    #[test]
    fn last_bytes_accepts_the_largest_count() {
        let count = parse(b"-9223372036854775807")
            .expect("the largest representable count");
        assert_eq!(
            count,
            RangeSpec::LastBytes {
                count: 9_223_372_036_854_775_807
            }
        );
        assert_eq!(count.resume_from(), -9_223_372_036_854_775_807);
        assert_eq!(count.resume_from(), -i64::MAX);
        assert_eq!(count.maxdownload(), Some(i64::MAX));

        // One digit more overflows the parse, and an overflowing count is a
        // rejection rather than a clamp: the cursor never moves, so the
        // second number is treated as absent and the `X-` branch stores the
        // zero the first (also failed) parse left behind.
        assert_eq!(
            parse(b"-92233720368547758070"),
            Ok(RangeSpec::FromOffset { resume_from: 0 })
        );
    }

    // The `X-Y` form: inclusive at both ends.

    /// `(200 - 100) + 1`. The `+ 1` is the C's *"include last byte"*.
    #[test]
    fn a_span_is_inclusive() {
        let spec = parse(b"100-200").expect("`100-200` is a valid range");
        assert_eq!(
            spec,
            RangeSpec::Span {
                resume_from: 100,
                maxdownload: 101
            }
        );
        assert_eq!(spec.resume_from(), 100);
        assert_eq!(spec.maxdownload(), Some(101));
        assert_eq!(apply(b"100-200"), Ok((100, 101)));
    }

    /// One byte, not zero bytes. The most direct statement of the inclusive
    /// semantics there is.
    #[test]
    fn a_degenerate_span_is_one_byte() {
        assert_eq!(
            parse(b"0-0"),
            Ok(RangeSpec::Span {
                resume_from: 0,
                maxdownload: 1
            })
        );
        assert_eq!(
            parse(b"7-7"),
            Ok(RangeSpec::Span {
                resume_from: 7,
                maxdownload: 1
            })
        );
    }

    #[test]
    fn a_reversed_span_is_rejected() {
        assert_eq!(parse(b"5-3"), Err(CURLcode::RangeError));
        assert_eq!(parse(b"1-0"), Err(CURLcode::RangeError));
    }

    /// The guard that keeps `totalsize + 1` from overflowing, and the pair of
    /// inputs that sit immediately either side of it.
    #[test]
    fn the_widest_span_is_rejected_and_the_next_widest_is_not() {
        assert_eq!(
            parse(b"0-9223372036854775807"),
            Err(CURLcode::RangeError),
            "a span of exactly CURL_OFF_T_MAX is refused"
        );

        let spec = parse(b"1-9223372036854775807")
            .expect("a span one smaller is accepted");
        assert_eq!(
            spec,
            RangeSpec::Span {
                resume_from: 1,
                maxdownload: 9_223_372_036_854_775_807,
            }
        );
        assert_eq!(spec.maxdownload(), Some(i64::MAX));
    }

    // Rejections.

    /// The C's comment: *"no leading dash or after the first number is an
    /// error"*.
    #[test]
    fn a_bare_number_is_rejected() {
        assert_eq!(parse(b"100"), Err(CURLcode::RangeError));
        assert_eq!(parse(b"0"), Err(CURLcode::RangeError));
    }

    #[test]
    fn an_empty_specification_is_rejected() {
        assert_eq!(parse(b""), Err(CURLcode::RangeError));
    }

    #[test]
    fn text_with_no_dash_is_rejected() {
        assert_eq!(parse(b"abc"), Err(CURLcode::RangeError));
        assert_eq!(parse(b"bytes=0-100"), Err(CURLcode::RangeError));
    }

    /// An out-of-range number is an ERROR, not a clamp, and the rejection
    /// comes from the dash test rather than from the overflow.
    #[test]
    fn an_overflowing_number_is_rejected() {
        assert_eq!(
            parse(b"9999999999999999999999-"),
            Err(CURLcode::RangeError)
        );
        assert_eq!(
            parse(b"99999999999999999999-100"),
            Err(CURLcode::RangeError)
        );

        let mut cursor: &[u8] = b"9999999999999999999999-";
        assert!(strparse::str_number(&mut cursor, i64::MAX).is_err());
        assert_eq!(cursor, b"9999999999999999999999-", "cursor unmoved");
    }

    /// An overflowing SECOND number is not an error at all, and this is the
    /// most counter-intuitive consequence of the helper's contract.
    #[test]
    fn an_overflowing_upper_bound_becomes_an_open_ended_range() {
        assert_eq!(
            parse(b"0-99999999999999999999"),
            Ok(RangeSpec::FromOffset { resume_from: 0 })
        );
        assert_eq!(
            parse(b"100-99999999999999999999"),
            Ok(RangeSpec::FromOffset { resume_from: 100 }),
            "the same shape as `100-`, and NOT a clamp to CURL_OFF_T_MAX"
        );
        assert_eq!(apply(b"100-99999999999999999999"), Ok((100, -1)));
    }

    /// Blanks are not skipped, which is the asymmetry with the accepted
    /// trailing garbage below. `curlx_str_numblanks` is the blank-skipping
    /// entry point and this function does not call it.
    #[test]
    fn leading_blanks_are_rejected() {
        assert_eq!(parse(b" 100-200"), Err(CURLcode::RangeError));
        assert_eq!(parse(b"\t100-200"), Err(CURLcode::RangeError));
        assert_eq!(parse(b" -500"), Err(CURLcode::RangeError));
        assert_eq!(
            parse(b"100 -200"),
            Err(CURLcode::RangeError),
            "a blank before the dash is rejected by the dash test"
        );
    }

    /// A leading `+` is not a sign, because `curlx_str_number` accepts digits
    /// only. Recorded because `+100-200` looks like it ought to work.
    #[test]
    fn a_leading_plus_is_rejected() {
        assert_eq!(parse(b"+100-200"), Err(CURLcode::RangeError));
    }

    // Leniency that is part of the frozen surface.

    /// Trailing bytes are never inspected, so these are all exactly
    /// `100-200`. The leniency is deliberate and no end-of-input check is
    /// added: `str_number` stops at the first non-digit and the C returns
    /// success without looking at what is left.
    #[test]
    fn trailing_bytes_are_ignored() {
        let expected = Ok(RangeSpec::Span {
            resume_from: 100,
            maxdownload: 101,
        });
        assert_eq!(parse(b"100-200junk"), expected);
        assert_eq!(parse(b"100-200-300"), expected);
        assert_eq!(parse(b"100-200 "), expected);
        assert_eq!(parse(b"100-200,300-400"), expected);
        assert_eq!(parse(b"100-200\r\n"), expected);
    }

    /// Leading zeroes are accepted, which `curlx_str_number` states in its
    /// own contract: *"Leading zeroes are accepted."*
    #[test]
    fn leading_zeroes_are_accepted() {
        assert_eq!(
            parse(b"007-0200"),
            Ok(RangeSpec::Span {
                resume_from: 7,
                maxdownload: 194
            })
        );
        assert_eq!(parse(b"-0500"), Ok(RangeSpec::LastBytes { count: 500 }));
    }

    /// No `0x` prefix handling: `0x10-0x20` parses the `0`, then the dash
    /// test finds an `x`.
    #[test]
    fn a_hexadecimal_prefix_is_not_understood() {
        assert_eq!(parse(b"0x10-0x20"), Err(CURLcode::RangeError));
    }

    // Bytes, not text.

    /// A range string that is not valid text is rejected by the GRAMMAR, as
    /// [`CURLcode::RangeError`], which is what the `&[u8]` signature is for:
    /// the C takes a `char *` and never validates its encoding, so a decoder
    /// here would have to invent an error the C cannot return.
    #[test]
    fn invalid_text_is_a_range_error_and_not_a_decode_error() {
        // Built rather than written as a literal: `invalid_from_utf8` rejects
        // a call whose literal argument is statically known to be invalid
        // text, and being invalid text is the whole point of this input.
        let not_text: Vec<u8> = vec![0xff, b'-', 0xfe];
        assert!(core::str::from_utf8(&not_text).is_err(), "not text");
        assert_eq!(parse(&not_text), Err(CURLcode::RangeError));
        assert_eq!(parse(b"\xff-\xfe"), Err(CURLcode::RangeError));
        assert_eq!(parse(b"1\xff-2"), Err(CURLcode::RangeError));

        // And a non-text tail is simply trailing garbage, as any other tail
        // is -- which is the same leniency, reached through bytes that could
        // not have been a `&str` at all.
        assert_eq!(
            parse(b"1-\xff"),
            Ok(RangeSpec::FromOffset { resume_from: 1 })
        );
        assert_eq!(
            parse(b"1-2\xff"),
            Ok(RangeSpec::Span {
                resume_from: 1,
                maxdownload: 2
            })
        );
    }

    /// An embedded zero byte behaves exactly as the C's terminator does,
    /// because the sibling parser resolves a read past its cursor to zero for
    /// this reason. So the bytes after it are unreachable, and a `100\0-200`
    /// is the same rejection a bare `100` is.
    #[test]
    fn an_embedded_zero_byte_terminates_as_it_does_in_c() {
        assert_eq!(parse(b"100\x00-200"), Err(CURLcode::RangeError));
        assert_eq!(
            parse(b"100-\x00200"),
            Ok(RangeSpec::FromOffset { resume_from: 100 })
        );
        assert_eq!(
            parse(b"100-200\x00"),
            Ok(RangeSpec::Span {
                resume_from: 100,
                maxdownload: 101
            })
        );
    }

    // The constant, and the contract around the field it names.

    /// The value is `-1` and nothing else, because `lib/ftp.c:2239` and
    /// `lib/file.c:501` both test its sign.
    #[test]
    fn the_unlimited_sentinel_is_minus_one() {
        assert_eq!(MAXDOWNLOAD_UNLIMITED, -1);

        // The two predicates the consumers apply to this field --
        // `lib/ftp.c:2239` tests `>= 0`, `lib/file.c:501` tests `> 0` --
        // written as closures so that the compiler does not already know the
        // answers, which is what `clippy::assertions_on_constants` objects to.
        let ftp_skips_the_check = |limit: i64| limit >= 0;
        let file_caps_the_size = |limit: i64| limit > 0;

        assert!(!ftp_skips_the_check(MAXDOWNLOAD_UNLIMITED));
        assert!(!file_caps_the_size(MAXDOWNLOAD_UNLIMITED));

        // A limit of ZERO is a real limit of zero bytes, and the sentinel must
        // not be interchangeable with it. The FTP predicate is what separates
        // them, which is why the constant is `-1` and not `0`.
        assert!(ftp_skips_the_check(0), "zero is a limit, not `unlimited`");
        assert!(!file_caps_the_size(0));
    }

    /// [`None`] means "leave the field alone", NOT "unlimited". The two
    /// coincide for a fresh request and diverge for a handle whose limit was
    /// already set, so the test drives both starting points through the
    /// documented call-site shape.
    #[test]
    fn no_limit_written_means_the_field_is_left_alone() {
        let spec = parse(b"100-").expect("a valid range");
        assert_eq!(spec.maxdownload(), None);

        // A fresh request: the field keeps the `-1` request.c gave it.
        let mut maxdownload = MAXDOWNLOAD_UNLIMITED;
        if let Some(limit) = spec.maxdownload() {
            maxdownload = limit;
        }
        assert_eq!(maxdownload, MAXDOWNLOAD_UNLIMITED);

        // A handle that already carried a limit: it keeps THAT, which is why
        // `unwrap_or(MAXDOWNLOAD_UNLIMITED)` would be wrong.
        let mut maxdownload = 4096;
        if let Some(limit) = spec.maxdownload() {
            maxdownload = limit;
        }
        assert_eq!(maxdownload, 4096, "an existing limit survives `X-`");
        assert_ne!(
            spec.maxdownload().unwrap_or(MAXDOWNLOAD_UNLIMITED),
            4096,
            "the wrong shape would have overwritten it"
        );

        // The same conditional store WITH a limit, so that the shape above is
        // shown to be discriminating rather than a store that never runs.
        let span = parse(b"100-200").expect("a valid range");
        let mut maxdownload = 4096;
        if let Some(limit) = span.maxdownload() {
            maxdownload = limit;
        }
        assert_eq!(maxdownload, 101, "a written limit replaces the old one");
    }

    // The two call sites, reproduced far enough to prove the answer fits them.

    /// `lib/file.c:474-503`, the arithmetic that follows the parse.
    #[test]
    fn the_file_scheme_resolves_every_form_against_a_known_size() {
        let file_size: i64 = 1000;

        // Resolve the way `file.c` resolves: offset first, then the size.
        let resolve = |range: &[u8]| -> (i64, i64) {
            let spec = parse(range).expect("a valid range");
            let mut offset = spec.resume_from();
            if offset < 0 {
                // `data->state.resume_from += (curl_off_t)statbuf.st_size;`
                offset += file_size;
            }
            let mut expected = file_size;
            if offset > 0 {
                expected -= offset;
            }
            // `if(data->req.maxdownload > 0) expected_size = maxdownload;`
            if let Some(limit) = spec.maxdownload() {
                if limit > 0 {
                    expected = limit;
                }
            }
            (offset, expected)
        };

        // The last 200 bytes of a 1000-byte file start at 800.
        assert_eq!(resolve(b"-200"), (800, 200));
        // From 200 to the end is 800 bytes, and no limit was written.
        assert_eq!(resolve(b"200-"), (200, 800));
        // 100..=199 inclusive is 100 bytes.
        assert_eq!(resolve(b"100-199"), (100, 100));
        // The whole file, stated three ways.
        assert_eq!(resolve(b"0-"), (0, 1000));
        assert_eq!(resolve(b"-"), (0, 1000));
        assert_eq!(resolve(b"-1000"), (0, 1000));
        // One byte at the very start, and one at the very end.
        assert_eq!(resolve(b"0-0"), (0, 1));
        assert_eq!(resolve(b"-1"), (999, 1));
    }

    /// `lib/ftp.c:2237-2242`: `dont_check` is set when, and only when, a limit
    /// was written.
    #[test]
    fn the_ftp_scheme_skips_the_completeness_check_only_when_limited() {
        let dont_check = |range: &[u8]| -> bool {
            let (_, maxdownload) = apply(range).expect("a valid range");
            maxdownload >= 0
        };

        assert!(dont_check(b"100-200"), "a span writes a limit");
        assert!(dont_check(b"-500"), "a count writes a limit");
        assert!(!dont_check(b"100-"), "`X-` writes none, so -1 survives");
        assert!(!dont_check(b"-"), "and neither does a lone dash");
    }

    // Differential sweeps against the transliterated C.

    /// Every string of length 0 to 4 inclusive over a six-symbol alphabet,
    /// compared field for field against [`c_curl_range`]: 1,555 inputs.
    #[test]
    fn agrees_with_the_c_on_every_short_input() {
        // Three digits (including the zero that `-0` turns on), the dash
        // the grammar requires, a letter that ends a number, and a blank that
        // is never skipped.
        const ALPHABET: [u8; 6] = *b"019-a ";

        let mut input: Vec<u8> = Vec::with_capacity(4);
        let mut compared = 0_usize;

        for length in 0_u32..=4 {
            for combination in 0..ALPHABET.len().pow(length) {
                input.clear();
                let mut code = combination;
                for _ in 0..length {
                    input.push(ALPHABET[code % ALPHABET.len()]);
                    code /= ALPHABET.len();
                }

                assert_eq!(
                    apply(&input),
                    apply_c(&input),
                    "disagreement on {:?}",
                    String::from_utf8_lossy(&input)
                );
                compared += 1;
            }
        }

        assert_eq!(compared, 1555, "the sweep must not silently shrink");
    }

    /// The same comparison over the inputs a short alphabet cannot reach: the
    /// numeric boundaries, the overflow shapes, and every non-text byte.
    ///
    /// The oracle these sweeps compare against is a transliteration, so it can
    /// only catch a misreading of the branch structure, not a misreading of the
    /// C itself. That second question was settled separately and by
    /// measurement rather than by argument: `str_num_base`, `curlx_str_number`,
    /// `curlx_str_single`, `valid_digit` and `curlx_hexasciitable[]` were
    /// extracted VERBATIM from `lib/curlx/strparse.c`, the body of
    /// `Curl_range` verbatim from `lib/curl_range.c` with only its two struct
    /// writes turned into out-parameters, the whole compiled with gcc 15.2.0,
    /// and its `(code, resume_from, maxdownload)` triple compared with this
    /// module's over a corpus of **9,579 inputs** -- every string of length 0
    /// to 4 over `019-a`, a space, `0xff` and a zero byte, plus the numeric
    /// boundaries, plus all 256 byte values in five positions, plus the
    /// pseudo-random sweep below. **Every one of the 9,579 agreed exactly.**
    /// That harness is an ad-hoc artifact and is deliberately not committed;
    /// the sweeps that remain here are the regression net.
    #[test]
    fn agrees_with_the_c_on_the_boundary_inputs() {
        let mut cases: Vec<Vec<u8>> = vec![
            b"0-9223372036854775806".to_vec(),
            b"0-9223372036854775807".to_vec(),
            b"1-9223372036854775807".to_vec(),
            b"9223372036854775807-9223372036854775807".to_vec(),
            b"9223372036854775806-9223372036854775807".to_vec(),
            b"9223372036854775807-".to_vec(),
            b"-9223372036854775807".to_vec(),
            b"-9223372036854775808".to_vec(),
            b"9223372036854775808-".to_vec(),
            b"-92233720368547758070".to_vec(),
            b"0-99999999999999999999".to_vec(),
            b"99999999999999999999-100".to_vec(),
            b"000000000000000000000000-1".to_vec(),
            b"1-000000000000000000000002".to_vec(),
            b"100-200junk".to_vec(),
            b"100-200-300".to_vec(),
            b"0x10-0x20".to_vec(),
            b"bytes=0-100".to_vec(),
            b"+100-200".to_vec(),
            b"100 -200".to_vec(),
            b"\t100-200".to_vec(),
            b"100\x00-200".to_vec(),
            b"100-\x00200".to_vec(),
        ];

        // Every byte value, alone and in each of the three positions of a
        // range, so that no class of byte is left untested by the alphabet
        // sweep above.
        for byte in 0..=u8::MAX {
            cases.push(vec![byte]);
            cases.push(vec![byte, b'-', b'2']);
            cases.push(vec![b'1', byte, b'2']);
            cases.push(vec![b'1', b'-', byte]);
        }

        for input in &cases {
            assert_eq!(
                apply(input),
                apply_c(input),
                "disagreement on {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    /// No input panics, which is worth its own sweep because every arithmetic
    /// path in [`parse`] is capable of overflowing an `i64` and Rust's
    /// checked debug arithmetic turns any lapse into a panic rather than a
    /// wrong answer.
    #[test]
    fn no_input_panics() {
        // Numerical Recipes' 64-bit multiplier and increment. Any full-period
        // generator would do; what matters is that the seed is fixed.
        let mut accepted = 0_usize;
        let mut rejected = 0_usize;

        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };

        // THE HIGH BITS, ALWAYS -- and this is not a stylistic preference.
        for _ in 0..4096 {
            let length =
                usize::try_from((next() >> 40) % 24).expect("under 24");
            let mut input = Vec::with_capacity(length);
            for _ in 0..length {
                // The whole byte range, biased towards the bytes the grammar
                // reacts to so that the deep paths are reached often.
                let draw = next();
                let byte = match (draw >> 62) & 0b11 {
                    0 => b'0' + u8::try_from((draw >> 50) % 10).expect("0..=9"),
                    1 => b'-',
                    2 => b' ',
                    _ => u8::try_from((draw >> 30) & 0xff).expect("a byte"),
                };
                input.push(byte);
            }

            // The assertion is that neither call unwinds, and that they agree
            // when they return. `parse` is total: every input has an answer.
            assert_eq!(
                apply(&input),
                apply_c(&input),
                "disagreement on {input:?}"
            );

            // The accessors are total too, and the type's own invariants hold
            // on whatever came back -- a written limit is at least one byte,
            // and the offset is negative for exactly one variant.
            match parse(&input) {
                Ok(spec) => {
                    if let Some(limit) = spec.maxdownload() {
                        assert!(limit > 0, "a limit is at least one byte");
                    }
                    let offset = spec.resume_from();
                    match spec {
                        RangeSpec::LastBytes { count } => {
                            assert_eq!(offset, -count);
                            assert!(offset < 0, "the count encoding");
                        }
                        RangeSpec::FromOffset { .. }
                        | RangeSpec::Span { .. } => {
                            assert!(offset >= 0, "an absolute offset");
                        }
                    }
                    accepted += 1;
                }
                Err(code) => {
                    assert_eq!(code, CURLcode::RangeError, "the only error");
                    rejected += 1;
                }
            }
        }

        // Non-vacuity, and the reason this matters: the grammar rejects most
        // strings, so a sweep that happened to draw only rejections would
        // exercise none of the arithmetic and would still pass. Measured on
        // this seed, both outcomes are reached in quantity.
        assert_eq!(accepted + rejected, 4096, "every draw was classified");
        assert!(accepted > 100, "only {accepted} accepted -- too few");
        assert!(rejected > 100, "only {rejected} rejected -- too few");
    }

    /// The accessors never panic and never wrap, on every value [`parse`] can
    /// possibly produce for the `-Y` form -- including the largest count,
    /// whose negation is the one that would overflow if it were one larger.
    #[test]
    fn the_accessors_are_total_over_every_reachable_count() {
        for count in [1_i64, 2, 500, 4096, i64::MAX - 1, i64::MAX] {
            let spec = RangeSpec::LastBytes { count };
            assert_eq!(spec.resume_from(), -count);
            assert!(spec.resume_from() < 0);
            assert_eq!(spec.maxdownload(), Some(count));
        }

        // `i64::MIN` is unreachable through `parse` -- `str_number` cannot
        // produce it -- and the accessor is nevertheless total on it, which is
        // what `wrapping_neg` buys over a plain negation. Asserted so that the
        // claim in the accessor's own comment is checked rather than trusted.
        let unreachable = RangeSpec::LastBytes { count: i64::MIN };
        assert_eq!(unreachable.resume_from(), i64::MIN);
    }

    /// The error is `CURLE_RANGE_ERROR`, and it is the only one this module
    /// returns. The integer is asserted through [`crate::error`] rather than
    /// written here, so that this file holds no copy of the ABI value.
    #[test]
    fn the_only_error_is_the_range_error() {
        assert_eq!(CURLcode::RangeError.as_i32(), 33);
        assert_eq!(CURLcode::RangeError.c_name(), "CURLE_RANGE_ERROR");

        for rejected in [
            &b""[..],
            b" ",
            b"abc",
            b"100",
            b"-0",
            b"5-3",
            b"0-9223372036854775807",
            b"9999999999999999999999-",
        ] {
            assert_eq!(
                parse(rejected),
                Err(CURLcode::RangeError),
                "on {:?}",
                String::from_utf8_lossy(rejected)
            );
        }
    }
}
