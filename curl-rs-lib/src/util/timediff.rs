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

//! Time differences and the millisecond conversions -- supersedes
//! `lib/curlx/timediff.c` and `lib/curlx/timediff.h`.
//!
//! Small and foundational. [`TimeDiff`] is the type in which *every* timeout,
//! every elapsed-time measurement and every `CURLINFO_*_TIME` figure in this
//! crate is carried, and [`mstotv`] is how curl tells `select` and `poll`
//! which of three completely different things to do: block indefinitely, poll
//! without blocking, or wait a bounded time. Getting the last of those
//! backwards hangs a reactor, so the mapping is spelled out below and pinned
//! by a test rather than left to a reader's inference.
//!
//! # The whole C surface, item by item
//!
//! Six items -- one typedef, three macros, two functions -- and each is
//! either reproduced here or recorded as deliberately subsumed. Nothing is
//! dropped silently.
//!
//! | C item | Site | Rust counterpart |
//! |---|---|---|
//! | `timediff_t` | `timediff.h:30` | [`TimeDiff`] |
//! | `TIMEDIFF_T_MAX` | `timediff.h:33` | [`TIMEDIFF_T_MAX`] |
//! | `TIMEDIFF_T_MIN` | `timediff.h:34` | [`TIMEDIFF_T_MIN`] |
//! | `FMT_TIMEDIFF_T` | `timediff.h:31` | none -- subsumed, see below |
//! | `curlx_mstotv` | `timediff.c:34-77` | [`mstotv`] |
//! | `curlx_tvtoms` | `timediff.c:82-85` | [`tvtoms`] |
//!
//! # `FMT_TIMEDIFF_T` has no successor, and that is not an omission
//!
//! `timediff.h:31` defines it as `FMT_OFF_T`, which `lib/curl_setup.h:603`
//! defines as `CURL_FORMAT_CURL_OFF_T`, which `include/curl/system.h`
//! resolves per platform to the `printf` length modifier `"lld"` or `"I64d"`
//! (`:54`, `:62`, `:71`, `:77`). It exists solely because C's `printf` cannot
//! discover the width of its own argument. Rust's `{}` formats an `i64`
//! directly, so there is nothing for the macro to carry and no constant is
//! declared for it. The only place a length modifier still matters is the ten
//! exported `curl_m*printf` symbols, which belong to the ABI crate.
//!
//! # The boundary with the clock, stated so it is not crossed twice
//!
//! This module owns **types and unit conversion**. The module beside it,
//! `timeval.rs` (superseding `lib/curlx/timeval.c`), owns **the clock**:
//! `struct curltime`, `curlx_now`, and the injectable time source that lets
//! the protocol modules be tested without a real one.
//!
//! Five C functions therefore belong *there* and must not be duplicated here,
//! because every one of them takes `struct curltime` arguments rather than a
//! bare count of milliseconds -- `curlx_timediff_ms`, `curlx_ptimediff_ms`,
//! `curlx_timediff_ceil_ms`, `curlx_timediff_us` and `curlx_ptimediff_us`,
//! declared at `lib/curlx/timeval.h:49`, `:50-51`, `:59-60`, `:68` and
//! `:69-70`. They return a [`TimeDiff`], which is the whole of their
//! dependency on this file. The expiry splay tree, `splay.rs` (superseding
//! `lib/splay.c`), depends on this file the same way, so the name
//! [`TimeDiff`] and the two constant names are a stable contract and should
//! not be renamed for tidiness.

use core::time::Duration;

/// curl's time-difference type: `timediff_t`.
///
/// `lib/curlx/timediff.h:28-30` defines it as `curl_off_t` and prefaces the
/// typedef with its own justification, which is worth carrying over rather
/// than paraphrasing: "Use a larger type even for 32-bit time_t systems so
/// that we can keep microsecond accuracy in it". That is why milliseconds and
/// microseconds both fit here with room to spare -- [`i64::MAX`] microseconds
/// is roughly 292,000 years -- and it is why the type is wider than the
/// platform's own clock type rather than matching it.
#[allow(dead_code)]
pub(crate) type TimeDiff = i64;

/// The largest representable difference: `TIMEDIFF_T_MAX`.
pub(crate) const TIMEDIFF_T_MAX: TimeDiff = TimeDiff::MAX;

/// The most negative representable difference: `TIMEDIFF_T_MIN`.
///
/// `lib/curlx/timediff.h:34` defines it as `CURL_OFF_T_MIN`, which
/// `lib/curl_setup.h:601` derives as `(-CURL_OFF_T_MAX - 1)`. Evaluated, that
/// is `-(2^63 - 1) - 1`, or `-2^63`, or [`i64::MIN`] -- the C spells it as a
/// negation of the maximum only because a C source file cannot write the most
/// negative 64-bit literal directly without the compiler treating it as an
/// unsigned value first.
#[allow(dead_code)]
pub(crate) const TIMEDIFF_T_MIN: TimeDiff = TimeDiff::MIN;

/// Converts a count of milliseconds into a wait duration -- `curlx_mstotv`.
///
/// Supersedes `curlx_mstotv` (`lib/curlx/timediff.c:34-77`, declared at
/// `lib/curlx/timediff.h:44`). The three-way contract is the C's, unchanged:
///
/// | `ms` | Returns | The caller then |
/// |---|---|---|
/// | negative | [`None`] | blocks indefinitely -- there is no timeout |
/// | zero | `Some(Duration::ZERO)` | polls, without blocking at all |
/// | positive | `Some(d)` | waits at most `d` |
#[allow(dead_code)]
pub(crate) fn mstotv(ms: TimeDiff) -> Option<Duration> {
    if ms < 0 {
        // "No timeout" -- `lib/select.c:74` hands this straight to `select`
        // as a null pointer, which is that call's own "wait forever".
        return None;
    }

    // Non-negative from here, so `unsigned_abs` only changes the type.
    Some(Duration::from_millis(ms.unsigned_abs()))
}

/// Converts a duration into a count of milliseconds -- `curlx_tvtoms`.
///
/// ```text
/// return (tv->tv_sec * 1000) + (timediff_t)(tv->tv_usec / 1000);
/// ```
///
/// # Saturation, and the asymmetry that disappears
///
/// One asymmetry in the C vanishes here rather than being reproduced:
/// `curlx_mstotv` checks its pointer while `curlx_tvtoms` dereferences its own
/// without any check at all, so a null argument is a crash rather than a
/// diagnostic. Taking a [`Duration`] by value removes the possibility instead
/// of having to guard against it.
#[allow(dead_code)]
pub(crate) fn tvtoms(d: Duration) -> TimeDiff {
    // Truncating, exactly as `tv_usec / 1000` truncates; saturating, because
    // the source range is wider than the destination's.
    TimeDiff::try_from(d.as_millis()).unwrap_or(TIMEDIFF_T_MAX)
}

// TESTS

#[cfg(test)]
mod tests {
    use super::*;

    // --- the three-way mapping ---------------------------------------------

    /// A negative count means "no timeout", which is the C's null return
    /// (`lib/curlx/timediff.c:39-40`).
    #[test]
    fn a_negative_count_means_block_indefinitely() {
        assert_eq!(mstotv(-1), None);
        assert_eq!(mstotv(-2), None);
        assert_eq!(mstotv(-1000), None);
        assert_eq!(mstotv(TIMEDIFF_T_MIN), None);
        assert_eq!(mstotv(i64::MIN), None);
    }

    /// Zero maps to a zero duration, which is the C's "0 in both fields"
    /// (`lib/curlx/timediff.c:71-74`) -- and emphatically NOT to `None`.
    #[test]
    fn zero_milliseconds_is_the_zero_duration_not_none() {
        assert_eq!(mstotv(0), Some(Duration::ZERO));

        // The collapse the implementation relies on, asserted rather than
        // assumed: the positive expression covers the zero case exactly.
        assert_eq!(Duration::from_millis(0), Duration::ZERO);

        let zero = mstotv(0).expect("zero milliseconds is a duration");
        assert_eq!(zero.as_secs(), 0);
        assert_eq!(zero.subsec_micros(), 0);
        assert!(zero.is_zero());
    }

    /// The mistake that hangs a reactor, given its own assertion because it is
    /// the one this module exists to prevent.
    #[test]
    fn no_timeout_and_poll_are_distinguishable() {
        assert_ne!(mstotv(-1), mstotv(0));
        assert!(mstotv(-1).is_none());
        assert!(mstotv(0).is_some());
    }

    /// A positive count is a bounded wait.
    #[test]
    fn a_positive_count_is_a_bounded_wait() {
        assert_eq!(mstotv(1), Some(Duration::from_millis(1)));
        assert_eq!(mstotv(999), Some(Duration::from_millis(999)));
        assert_eq!(mstotv(1000), Some(Duration::from_secs(1)));
        assert_eq!(mstotv(86_400_000), Some(Duration::from_secs(86_400)));
    }

    /// The seconds-and-microseconds split of `lib/curlx/timediff.c:42-44`,
    /// checked against `Duration`'s own accessors so the equivalence claimed
    /// in the module documentation is measured rather than asserted in prose.
    #[test]
    fn mstotv_splits_seconds_and_microseconds_as_the_c_does() {
        // The example the agent-facing specification names: 1500 ms is one
        // second plus 500,000 microseconds.
        let d = mstotv(1500).expect("1500 ms is a duration");
        assert_eq!(d.as_secs(), 1);
        assert_eq!(d.subsec_micros(), 500_000);

        // The C's `/* max=999000 */` upper bound on the microsecond field.
        let d = mstotv(1999).expect("1999 ms is a duration");
        assert_eq!(d.as_secs(), 1);
        assert_eq!(d.subsec_micros(), 999_000);

        // And the general rule, over a spread of values: tv_sec is ms / 1000
        // and tv_usec is (ms % 1000) * 1000.
        for ms in [1_i64, 7, 999, 1000, 1001, 59_999, 60_000, 1_234_567] {
            let d = mstotv(ms).expect("a positive count is a duration");
            let secs = u64::try_from(ms / 1000).expect("non-negative");
            let usecs =
                u32::try_from((ms % 1000) * 1000).expect("at most 999000");
            assert_eq!(d.as_secs(), secs, "seconds wrong for {ms} ms");
            assert_eq!(d.subsec_micros(), usecs, "micros wrong for {ms} ms");
        }
    }

    // --- the inverse -------------------------------------------------------

    /// `tv_usec / 1000` is integer division: 999 microseconds are zero
    /// milliseconds, not one (`lib/curlx/timediff.c:82-85`).
    #[test]
    fn tvtoms_truncates_it_does_not_round() {
        assert_eq!(tvtoms(Duration::from_micros(999)), 0);
        assert_eq!(tvtoms(Duration::from_micros(1_000)), 1);
        assert_eq!(tvtoms(Duration::from_micros(1_999)), 1);
        assert_eq!(tvtoms(Duration::from_micros(2_000)), 2);

        // Sub-microsecond precision truncates the same way rather than
        // rounding up to the next millisecond.
        assert_eq!(tvtoms(Duration::from_nanos(999_999)), 0);
        assert_eq!(tvtoms(Duration::from_nanos(1_000_000)), 1);
        assert_eq!(tvtoms(Duration::from_nanos(1_999_999)), 1);
    }

    /// Whole seconds carry the C's `tv_sec * 1000` factor.
    #[test]
    fn tvtoms_scales_whole_seconds() {
        assert_eq!(tvtoms(Duration::ZERO), 0);
        assert_eq!(tvtoms(Duration::from_secs(2)), 2000);
        assert_eq!(tvtoms(Duration::from_secs(86_400)), 86_400_000);

        // Both halves of the C expression at once: seconds scaled, remainder
        // truncated.
        assert_eq!(tvtoms(Duration::new(3, 456_789_000)), 3456);
    }

    /// Positive millisecond counts survive the round trip exactly, which is
    /// what makes the pair usable as a conversion rather than as an estimate.
    #[test]
    fn positive_counts_round_trip_exactly() {
        for ms in [
            1_i64,
            2,
            9,
            10,
            99,
            100,
            999,
            1000,
            1001,
            60_000,
            3_600_000,
            86_400_000,
            999_999_999,
        ] {
            let d = mstotv(ms).expect("a positive count is a duration");
            assert_eq!(tvtoms(d), ms, "round trip failed for {ms} ms");
        }

        // Zero round-trips too, which the three-way mapping requires: it is a
        // duration, so it must come back as one.
        let zero = mstotv(0).expect("zero milliseconds is a duration");
        assert_eq!(tvtoms(zero), 0);
    }

    // --- bounds and extremes -----------------------------------------------

    /// `TIMEDIFF_T_MAX` and `TIMEDIFF_T_MIN` are the signed 64-bit bounds,
    /// derived in the C from `CURL_OFF_T_MAX` (`lib/curl_setup.h:599`) and
    /// `CURL_OFF_T_MIN` (`:601`).
    #[test]
    fn the_bounds_are_the_signed_64_bit_bounds() {
        assert_eq!(TIMEDIFF_T_MAX, i64::MAX);
        assert_eq!(TIMEDIFF_T_MIN, i64::MIN);

        // The C's own spelling of each, evaluated: 0x7FFFFFFFFFFFFFFF and
        // (-CURL_OFF_T_MAX - 1).
        assert_eq!(TIMEDIFF_T_MAX, 0x7FFF_FFFF_FFFF_FFFF);
        assert_eq!(TIMEDIFF_T_MIN, -TIMEDIFF_T_MAX - 1);
    }

    /// The extremes convert without panicking. `Duration` has no trouble with
    /// the largest millisecond count, and the reverse direction saturates
    /// rather than wrapping into a negative value.
    #[test]
    fn the_extremes_neither_panic_nor_wrap() {
        let longest = mstotv(TIMEDIFF_T_MAX).expect("the maximum is a wait");
        assert_eq!(longest, Duration::from_millis(u64::MAX / 2));
        assert!(longest.as_secs() > 9_000_000_000_000_000);

        // `Duration::MAX` is about 1.8e22 ms, which exceeds `TimeDiff`, so it
        // saturates. Wrapping here would report a negative wait.
        let saturated = tvtoms(Duration::MAX);
        assert_eq!(saturated, TIMEDIFF_T_MAX);
        assert!(saturated > 0);

        // The largest input that still converts exactly, and the first that
        // has to saturate. Both answer the same value, which is the point of
        // saturating: the boundary is not observable as a sign flip.
        let exact = tvtoms(Duration::from_millis(u64::MAX / 2));
        assert_eq!(exact, TIMEDIFF_T_MAX);
        let just_over = Duration::from_millis(u64::MAX / 2 + 1);
        assert_eq!(tvtoms(just_over), TIMEDIFF_T_MAX);
    }

    // --- the type itself ---------------------------------------------------

    /// A `TimeDiff` is signed, and a negative one is an ordinary value rather
    /// than an error: `lib/curlx/timeval.h:44-45` documents that reversing the
    /// arguments to a difference "you get a weird negative time-diff back".
    /// This is a compile-level assertion as much as a runtime one -- an
    /// unsigned alias would not compile.
    #[test]
    fn a_time_diff_is_signed_and_may_be_negative() {
        let d: TimeDiff = -5;
        assert!(d < 0);
        assert_eq!(d, -5);
        assert_eq!(d.abs(), 5);
        assert_eq!(TimeDiff::MIN.signum(), -1);

        // Reversing a difference negates it, which is the caller's mistake
        // that the signed type surfaces instead of hiding.
        let newer: TimeDiff = 1_000;
        let older: TimeDiff = 4_000;
        assert_eq!(newer - older, -3_000);

        // And the module does not rewrite it: a negative count reaches
        // `mstotv` and is answered as "no timeout", not clamped to zero.
        assert_eq!(mstotv(newer - older), None);
    }

    /// `timediff_t` and `curl_off_t` are the same C type
    /// (`lib/curlx/timediff.h:30`), so the two aliases this crate declares for
    /// them must agree. Checked rather than assumed, because they are declared
    /// in different files.
    #[test]
    fn time_diff_and_curl_off_t_are_the_same_integer() {
        assert_eq!(
            core::mem::size_of::<TimeDiff>(),
            core::mem::size_of::<crate::util::CurlOffT>()
        );
        assert_eq!(core::mem::size_of::<TimeDiff>(), 8);

        // Stronger than comparing widths, and the reason this assignment is
        // written out rather than folded into the assertion above: it would
        // not COMPILE if the parent's alias were unsigned or a different
        // width, so the type identity is checked by the compiler and the sign
        // by the assertion.
        let widest: crate::util::CurlOffT = TIMEDIFF_T_MIN;
        assert!(widest < 0);
        assert_eq!(widest, i64::MIN);
    }
}
