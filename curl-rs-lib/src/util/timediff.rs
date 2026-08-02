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
//! `lib/curlx/timediff.c` (85 lines) and `lib/curlx/timediff.h` (51).
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
//! # The three-way mapping, which is the point of the module
//!
//! The C states its contract twice, identically, at `timediff.c:26-33` and
//! `timediff.h:36-43`. Reproduced here with only the C block comment's `*`
//! decoration removed, because it is the contract every reactor call site
//! depends on:
//!
//! ```text
//! Return values:
//!    NULL IF tv is NULL or ms < 0 (eg. no timeout -> blocking select)
//!    tv with 0 in both fields IF ms == 0 (eg. 0ms timeout -> polling select)
//!    tv with converted fields IF ms > 0 (eg. >0ms timeout -> waiting select)
//! ```
//!
//! Three outcomes, and `Option<Duration>` carries them exactly:
//!
//! | Input | C result | Rust result | Meaning to the caller |
//! |---|---|---|---|
//! | `ms < 0` | `NULL` | `None` | no timeout: block indefinitely |
//! | `ms == 0` | zero in both fields | `Some(Duration::ZERO)` | poll |
//! | `ms > 0` | converted fields | `Some(d)` | wait at most `d` |
//!
//! `None` and `Some(Duration::ZERO)` mean *opposite* things and must never be
//! conflated: `None` blocks forever, `Some(Duration::ZERO)` refuses to block
//! at all. The C call sites make that concrete -- `lib/select.c:74` assigns
//! the result to `ptimeout` and hands it straight to `select` at `:92` and
//! `:94`, where a null pointer is the platform's own "no timeout", and
//! `lib/curlx/wait.c:83` does the same inline. Swapping the two turns a poll
//! into a hang or a bounded wait into a busy spin, which is the single
//! highest-consequence mistake available in this file.
//!
//! # Two collapses, both deliberate and both recorded
//!
//! **The out-parameter disappears.** The C signature is
//! `struct timeval *curlx_mstotv(struct timeval *tv, timediff_t ms)`: the
//! caller owns the storage, passes a pointer to it, and reads a pointer back
//! that is either that same pointer or null. So the C has to check `if(!tv)`
//! (`timediff.c:36-37`) and fold "you gave me nowhere to write" into the same
//! null return as "you asked for no timeout" -- two unrelated conditions
//! sharing one result. Returning an owned value removes the first condition
//! outright: there is no storage to be absent, so `None` means only "no
//! timeout". The C's `struct timeval` is a platform ABI type and does not
//! appear here at all; the storage it provided is what `Duration` now owns.
//!
//! **The second-and-microsecond split disappears too.** `timediff.c:42-44`
//! computes `tv_sec = ms / 1000` and `tv_usec = (ms % 1000) * 1000`, with the
//! C's own comment recording that the second of those is at most `999000`.
//! `Duration::from_millis` produces exactly that value -- the same whole
//! seconds and the same subsecond microseconds -- so the split is not
//! reimplemented, only its equivalence is asserted, by
//! `mstotv_splits_seconds_and_microseconds_as_the_c_does`. The C's separate
//! `else` branch writing zero into both fields (`timediff.c:71-74`) collapses
//! into the same expression for the same reason: `Duration::from_millis(0)`
//! *is* `Duration::ZERO`, which
//! `zero_milliseconds_is_the_zero_duration_not_none` proves.
//!
//! # The three clamp branches, and the licence for collapsing them
//!
//! `timediff.c:45-69` is three `#ifdef` arms -- `HAVE_SUSECONDS_T`, `_WIN32`,
//! and a fallback -- each guarded in turn by `#if TIMEDIFF_T_MAX > TIME_T_MAX`
//! / `> LONG_MAX` / `> INT_MAX`, and each clamping `tv_sec` to the maximum of
//! whichever type the platform's `tv_sec` field happens to be:
//!
//! ```text
//! HAVE_SUSECONDS_T -> tv_sec = (time_t)tv_sec, clamped at TIME_T_MAX
//! _WIN32           -> tv_sec = (long)tv_sec,   clamped at LONG_MAX
//! otherwise        -> tv_sec = (int)tv_sec,    clamped at INT_MAX
//! ```
//!
//! All three collapse to one unconditional conversion here, and the reason is
//! specific rather than a shrug. The mandated targets are
//! `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
//! `x86_64-apple-darwin` and `aarch64-apple-darwin`; all four are 64-bit,
//! where `time_t` is 64 bits and `TIMEDIFF_T_MAX > TIME_T_MAX` is false, so
//! the first arm's clamp is compiled out on every one of them and the other
//! two arms are not compiled at all. The 32-bit case the guards exist for is
//! a deliberate forfeit of the migration (AAP 0.2.2), not an oversight, and it
//! must not be claimed as supported. Independently of the platform, the Rust
//! side has nothing left to clamp *against*: `Duration` counts whole seconds
//! in a `u64` and cannot overflow for any non-negative [`TimeDiff`], because
//! [`i64::MAX`] milliseconds is about 2.9e8 years and still only 9.2e15
//! seconds.
//!
//! # Signedness is load-bearing: a negative difference is legal
//!
//! `timediff_t` is signed and stays signed. `lib/curlx/timeval.h:44-45`
//! documents the reason in the C's own words -- "Make sure that the first
//! argument (newer) is the more recent time and older is the older time, as
//! otherwise you get a weird negative time-diff back..." -- and repeats it at
//! `:54-55` and `:63-64`. A negative value is therefore a *caller* mistake
//! that the type deliberately surfaces, not an error the callee traps. An
//! unsigned type, or a clamp at zero, would hide exactly the bug the C
//! exposes, so neither is used; [`mstotv`] answers `None` for a negative
//! input, which is what the C does, and nothing else in this module rejects
//! or rewrites one.
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
//!
//! # What is deliberately absent
//!
//! - **No millisecond or microsecond factor constant.** `1_000` and
//!   `1_000_000` appear nowhere in the code below, because `Duration`'s own
//!   constructors and accessors are where the factors live. A `pub(crate)
//!   const` for either would be an item with no consumer, which this layer's
//!   policy treats as scaffolding to be recorded rather than written.
//! - **No `millis_to_duration` / `duration_to_millis` alias.** The C stems
//!   `mstotv` and `tvtoms` are kept precisely so that a grep against
//!   `lib/curlx/timediff.c` still lands on this file; a second name for each
//!   function would double the audit surface and let the two drift.
//! - **No newtype around [`TimeDiff`].** It is a plain alias on purpose. The
//!   crate does arithmetic on time differences everywhere -- expiry
//!   bookkeeping, rate limiting, progress accounting -- and a newtype would
//!   push operator boilerplate into every consumer while buying no safety
//!   that the alias does not already provide. Recorded here so that a later
//!   reader does not "improve" it.
//!
//! # Conventions
//!
//! Every item is `pub(crate)`: the C tree's `curlx_` prefix made these
//! private by convention and still visible to the linker, whereas
//! `pub(crate)` is private by enforcement (AAP 0.4.2). Nothing here is
//! reachable from `curl-rs-ffi`, none of it is re-exported by the crate root,
//! and none of it is widened to make `tests/unit` or `tests/libtest` link --
//! that is a documented deviation (AAP 0.8.7), not a defect to work around.
//!
//! The file adds no dependency and imports exactly one item,
//! [`core::time::Duration`]. It names no sibling module, so the layering rule
//! that makes `util` the base of the crate's module graph holds here by
//! construction. Edition 2021, and the minimum supported Rust version is
//! 1.75: `Duration::ZERO` and `Duration::MAX` were stabilized in 1.53,
//! `Duration::as_millis` in 1.33, `i64::unsigned_abs` in 1.51 and
//! `TryFrom<u128> for i64` in 1.34, so nothing below needs a newer compiler.
//! Performance is an explicit non-goal, so nothing here carries an `#[inline]`
//! hint or is shaped by a speed argument.
//!
//! HOW TO CHECK THE PLATFORM-TYPE CLAIM, because an unanchored search reports
//! a false failure against this file itself: the prose above legitimately
//! names the C structure this module replaces and cites the two C files whose
//! stem it shares, so a bare `grep -n 'timeval' <this file>` matches those
//! citations. The claim is about *code*, and the anchored form is
//!
//! ```text
//! grep -nE '^[^/]*\btimeval\b' curl-rs-lib/src/util/timediff.rs
//! ```
//!
//! which must print nothing. Requiring the token before any slash on the line
//! is what excludes every `//`, `///` and `//!` line: a comment begins with a
//! slash, so it can never match. Measured on this file: it prints nothing.

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
///
/// It resolves to [`i64`] on every mandated target. `curl_off_t` is
/// `CURL_TYPEOF_CURL_OFF_T` (`include/curl/system.h:396`), which is `long` or
/// `long long` depending on the platform, and `lib/curl_setup.h:595-596`
/// rejects outright any platform where it is narrower than 8 bytes with
/// `#error "too small curl_off_t"`. So 64-bit signed is not an assumption made
/// here; it is the only width the C tree compiles for.
///
/// The parent module already aliases the same C type as
/// [`CurlOffT`](super::CurlOffT), for offsets and file sizes rather than for
/// durations. Two names for one width is deliberate: a signature reading
/// `TimeDiff` says "this is a span of time", and one reading `CurlOffT` says
/// "this is a position in a stream". This alias is written against [`i64`]
/// directly rather than layered on the other so that the module depends on
/// nothing but [`core::time::Duration`]; that the two agree is asserted by
/// `time_diff_and_curl_off_t_are_the_same_integer` rather than assumed.
///
/// A plain alias, not a newtype, and not by accident -- see the module's "What
/// is deliberately absent" section for why, and do not convert it.
#[allow(dead_code)]
pub(crate) type TimeDiff = i64;

/// The largest representable difference: `TIMEDIFF_T_MAX`.
///
/// `lib/curlx/timediff.h:33` defines it as `CURL_OFF_T_MAX`, which
/// `lib/curl_setup.h:599` pins to `0x7FFFFFFFFFFFFFFF`. That is exactly
/// [`i64::MAX`], which is why this is expressed against the Rust constant
/// instead of transcribing the hexadecimal literal -- and
/// `the_bounds_are_the_signed_64_bit_bounds` checks the two agree.
///
/// [`tvtoms`] saturates here rather than wrapping, which is this constant's
/// one consumer today.
pub(crate) const TIMEDIFF_T_MAX: TimeDiff = TimeDiff::MAX;

/// The most negative representable difference: `TIMEDIFF_T_MIN`.
///
/// `lib/curlx/timediff.h:34` defines it as `CURL_OFF_T_MIN`, which
/// `lib/curl_setup.h:601` derives as `(-CURL_OFF_T_MAX - 1)`. Evaluated, that
/// is `-(2^63 - 1) - 1`, or `-2^63`, or [`i64::MIN`] -- the C spells it as a
/// negation of the maximum only because a C source file cannot write the most
/// negative 64-bit literal directly without the compiler treating it as an
/// unsigned value first.
///
/// It exists here for the same reason it exists in the C: a difference may
/// legitimately be negative, and code that reasons about the range needs both
/// ends of it. See the module's note on signedness.
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
///
/// Two branches implement three outcomes because the second and third share
/// one expression, exactly as the arithmetic permits: `Duration::from_millis`
/// applied to `0` yields `Duration::ZERO`, which is what the C writes into
/// both fields on its `else` path (`timediff.c:71-74`). The module
/// documentation records both collapses, and two tests pin them.
///
/// # Conversion, without a bare cast
///
/// `ms` is signed and `Duration::from_millis` takes a `u64`, so a conversion
/// is unavoidable. `as` is not used for it: `-1i64 as u64` is
/// `18446744073709551615`, which would turn "no timeout" into a wait of about
/// 584 million years -- the exact class of silent narrowing that
/// `lib/curlx/warnless.c` exists to catch, and the reason its successors in
/// the parent module mask explicitly instead. [`i64::unsigned_abs`] is used
/// after the sign test instead. It is total, it cannot panic and it cannot
/// wrap even at [`i64::MIN`], and past the sign test it is the identity on
/// magnitude, so its only observable effect is the change of type.
///
/// A checked `u64::try_from(ms)` would be equally correct and equally cheap,
/// but its error arm is unreachable once `ms` is known to be non-negative, so
/// it would introduce a branch that no test can cover and no input can reach.
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
/// Supersedes `curlx_tvtoms` (`lib/curlx/timediff.c:82-85`, declared at
/// `lib/curlx/timediff.h:49`), whose whole body is
///
/// ```text
/// return (tv->tv_sec * 1000) + (timediff_t)(tv->tv_usec / 1000);
/// ```
///
/// # It truncates, and it must
///
/// `tv_usec / 1000` is integer division on a non-negative value, so it
/// truncates toward zero and does not round: 999 microseconds contribute
/// **zero** milliseconds, and 1,999 contribute one. `Duration::as_millis`
/// truncates identically, which is why it is used unaltered rather than
/// wrapped in any rounding correction. Rounding up instead would inflate every
/// converted timeout by up to a millisecond, and
/// `tvtoms_truncates_it_does_not_round` fixes the behaviour so that a later
/// "fix" of that kind fails a test rather than shipping.
///
/// Ceiling behaviour is a *different* function in the C, namely
/// `curlx_timediff_ceil_ms` (`lib/curlx/timeval.h:59-60`), and it belongs to
/// the clock module rather than here.
///
/// # Saturation, and the asymmetry that disappears
///
/// `Duration::as_millis` returns a `u128`, whose range exceeds
/// [`TimeDiff`]'s: `Duration::MAX` is about 1.8e22 milliseconds against a
/// ceiling of 9.2e18. The conversion therefore saturates at
/// [`TIMEDIFF_T_MAX`] rather than wrapping into a negative value, which is
/// both what the C's own clamps do at every width boundary and the only answer
/// that keeps the sign meaningful. No `as` cast appears, for the reason given
/// on [`mstotv`].
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
//
// `tests/unit/*.c` (59 files) and `tests/libtest/*.c` (235) link a debug
// static build of the C library and call internal `Curl_*` symbols, which a
// Rust static library does not export. Their coverage therefore relocates into
// `#[cfg(test)]` modules inside the files under test (AAP 0.8.7), and this is
// this file's share of that relocation.
//
// Nothing here needs a network, a clock or a fixture: every assertion is a
// hand-computed value taken from the C, so the whole module is also valid
// under Miri and under `cargo test --release`.

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
