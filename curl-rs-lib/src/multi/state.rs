//**************************************************************************
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
//**************************************************************************/
//! The multi-handle transfer state machine.
//!
//! Rust counterpart of the C `CURLMstate` enumeration at
//! `lib/multihandle.h:51-70`. Every easy handle carries one of these values,
//! and `mstate()` (`lib/multi.c:130-190`) is the only function that changes
//! it.
//!
//! # Eighteen tokens, seventeen states, seventeen names
//!
//! The C enumeration declares eighteen tokens, but the eighteenth,
//! `MSTATE_LAST`, is annotated in the header as "not a true state, never use
//! this" (`lib/multihandle.h:69`) and exists only to size arrays such as
//! `finit[MSTATE_LAST]` (`lib/multi.c:138`). [`CurlMstate`] therefore has
//! seventeen variants and deliberately **no** `Last` variant: a value that
//! must never be used has no business being constructible, and omitting it
//! means every `match` over this type covers only reachable states instead of
//! carrying an unreachable arm. The sentinel survives as the integers
//! [`CurlMstate::COUNT`] and [`CurlMstate::LAST`], so a caller that needs the
//! bound still has it yet cannot hold it as a state. The name table is
//! seventeen entries long for the same reason: `Curl_trc_mstate_names[]`
//! (`lib/curl_trc.c:334`) carries no `"LAST"` string.
//!
//! # Declaration order is semantics, not aesthetics
//!
//! `lib/multi.c` orders states with `<` and `>` rather than testing for
//! equality, so `Ord` is part of this type's contract and the discriminants
//! below are written out rather than inferred. The four sites that fix the
//! order:
//!
//! - `Curl_is_connecting()`, which is exactly `data->mstate < MSTATE_DO`
//!   (`lib/multi.c:359-361`);
//! - the `premature` flag of `curl_multi_remove_handle()`, which is
//!   `data->mstate < MSTATE_COMPLETED` (`lib/multi.c:786`);
//! - the partial-response guard `MSTATE_DO < mstate < MSTATE_COMPLETED`,
//!   which closes the stream with "Removed with partial response"
//!   (`lib/multi.c:791-795`);
//! - the `oldstate < MSTATE_DONE` gate deciding whether entering `COMPLETED`
//!   still owes the application a done notification (`lib/multi.c:178`).
//!
//! # One exhaustive `match` replaces a hand-maintained parallel array
//!
//! `lib/multihandle.h:48-49` makes keeping the names in step a manual
//! obligation: "if you add a state here, add the name to the statenames[]
//! array in curl_trc.c as well!". That note has itself drifted, which is the
//! whole argument for deriving the names here. No `statenames[]` exists in
//! `lib/curl_trc.c` -- the real array is `Curl_trc_mstate_names[]` at
//! `lib/curl_trc.c:334` -- and the identifier the note gives survives in the
//! tree only at `lib/mqtt.c:628`, an unrelated MQTT array, the SOCKS one
//! being spelled `cf_socks_statename[]` (`lib/socks.c:71`). A maintainer
//! following the comment literally searches for a symbol that is not in the
//! file it names. [`CurlMstate::name`] ends that class of drift: the emitted
//! strings are unchanged, byte for byte and in the same order, but a state
//! added without a name no longer compiles.
//!
//! # Exhaustiveness is a crate-wide contract
//!
//! No `match` on this type anywhere in the crate may carry a `_` arm.
//! Exhaustiveness checking is what turns an unhandled state from a runtime
//! fall-through into a compile error, and the C tree shows the exact
//! fall-through it replaces: `Curl_multi_pollset()` already lists all
//! seventeen states and still needs a `default:` arm that logs "unexpected
//! multi state" and asserts (`lib/multi.c:1113-1160`, the arm at
//! `lib/multi.c:1157-1160`). The two full-coverage matches this rule governs
//! are that pollset switch, which becomes `crate::multi::events`, and
//! `multi_runsingle()`'s switch (`lib/multi.c:2427-2751`), which becomes
//! `crate::multi`.
//!
//! # Scope, and the two fallbacks that must never be unified
//!
//! This module owns the enumeration, its names and its ordering predicates,
//! and nothing else. The state-entry hook table (`lib/multi.c:138-157`)
//! belongs to `crate::multi`, because its hooks reach into transfer and
//! connection machinery; `CURLMcode` belongs to `crate::error`; the message
//! queue belongs to `crate::multi::notify`; and the timer enumeration --
//! together with `Curl_trc_timer_names[]` (`lib/curl_trc.c:281`) and its
//! own, different `"UNKNOWN?"` fallback (`lib/curl_trc.c:303`) -- belongs to
//! `crate::multi::events`. This module's fallback is `"?"`, the two strings
//! are not interchangeable, and they must never be merged.
//!
//! There are no intra-crate imports and no third-party dependencies here,
//! only `core`, and no `unsafe`, in keeping with the crate root's denial of the
//! `unsafe_code` lint. (The root denies rather than forbids: `forbid` cannot be
//! relaxed later, so it would reject the one exemption `mod ffi` requires.)

// WHY A HANDFUL OF ITEMS BELOW CARRY `#[allow(dead_code)]`. Every production
// consumer of this state machine lives in a module that has not landed yet --
// the multi handle itself drives the transitions, `multi/mod.rs` re-exports
// the type, and `crate::transfer` reads it -- so those accessors are
// legitimately unreferenced in a non-test build even though this module's own
// tests exercise every one of them.
//
// The allowance is per item and never on this module's root, which the crate's
// own policy test enforces (`lib.rs`, `no_lint_level_for_dead_code_is_set_on_
// a_crate_or_module_root`): a root-level level would also hide the next
// unreferenced item somebody adds. No level for the `unsafe_code` lint is set
// here at any level, by design -- the crate root's denial governs and this
// module contains no `unsafe`, so the crate-wide guarantee stays in force.

/// State of one transfer inside a multi handle.
///
/// The C original is the `CURLMstate` typedef at `lib/multihandle.h:51-70`,
/// and each variant keeps that token's own comment. `repr(u8)` is honest
/// rather than merely compact: the values run from 0 to 16 and this type
/// never crosses the C ABI, unlike `CURLMcode`, which is `repr(i32)` and
/// lives in `crate::error`.
///
/// There is deliberately no `Default`. C has none either -- the initial state
/// is set explicitly by `multistate(data, MSTATE_INIT)` when a handle joins a
/// multi handle (`lib/multi.c:489`) -- and inventing one would hide that
/// step. The type is likewise not `non_exhaustive`, because callers inside
/// this crate are required to match it exhaustively.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code)]
pub(crate) enum CurlMstate {
    /// `MSTATE_INIT` -- 0 - start in this state.
    Init = 0,
    /// `MSTATE_PENDING` -- no connections, waiting for one.
    Pending = 1,
    /// `MSTATE_SETUP` -- start a new transfer.
    Setup = 2,
    /// `MSTATE_CONNECT` -- resolve/connect has been sent off.
    Connect = 3,
    /// `MSTATE_RESOLVING` -- awaiting the resolve to finalize.
    Resolving = 4,
    /// `MSTATE_CONNECTING` -- awaiting the TCP connect to finalize.
    Connecting = 5,
    /// `MSTATE_PROTOCONNECT` -- initiate protocol connect procedure.
    ProtoConnect = 6,
    /// `MSTATE_PROTOCONNECTING` -- completing the protocol-specific connect
    /// phase.
    ProtoConnecting = 7,
    /// `MSTATE_DO` -- start send off the request (part 1).
    Do = 8,
    /// `MSTATE_DOING` -- sending off the request (part 1).
    Doing = 9,
    /// `MSTATE_DOING_MORE` -- send off the request (part 2).
    DoingMore = 10,
    /// `MSTATE_DID` -- done sending off request.
    Did = 11,
    /// `MSTATE_PERFORMING` -- transfer data.
    Performing = 12,
    /// `MSTATE_RATELIMITING` -- wait because limit-rate exceeded.
    RateLimiting = 13,
    /// `MSTATE_DONE` -- post data transfer operation.
    Done = 14,
    /// `MSTATE_COMPLETED` -- operation complete.
    Completed = 15,
    /// `MSTATE_MSGSENT` -- the operation complete message is sent.
    MsgSent = 16,
}

impl CurlMstate {
    /// Number of real states, and so the length of the name table.
    ///
    /// The C `MSTATE_LAST` read as a count: what sizes `finit[MSTATE_LAST]`
    /// (`lib/multi.c:138`) and what
    /// `CURL_ARRAYSIZE(Curl_trc_mstate_names)` evaluates to
    /// (`lib/curl_trc.c:356`).
    #[allow(dead_code)]
    pub(crate) const COUNT: usize = 17;

    /// Integer value of the C sentinel `MSTATE_LAST`
    /// (`lib/multihandle.h:69`), for bounds checks that want it as a number.
    ///
    /// Published as an integer rather than as a variant precisely because the
    /// header forbids using it as a state.
    #[allow(dead_code)]
    pub(crate) const LAST: u8 = 17;

    /// Name answered when an integer does not denote a state.
    ///
    /// `"?"`, exactly as `Curl_trc_mstate_name()` answers when its bounds
    /// check fails (`lib/curl_trc.c:356-358`) -- not `"UNKNOWN?"`, which is
    /// the unrelated timer fallback. `'static` is written out rather than
    /// elided because rustc 1.75, the declared minimum supported version,
    /// warns `elided_lifetimes_in_associated_constant` otherwise, and the build
    /// gate requires zero warnings.
    #[allow(dead_code)]
    const UNKNOWN_NAME: &'static str = "?";

    /// The state's trace name.
    ///
    /// One exhaustive `match` in place of `Curl_trc_mstate_names[]`
    /// (`lib/curl_trc.c:334`) and of the stale maintenance note paired with
    /// it (`lib/multihandle.h:48-49`). Carrying no `_` arm is what makes a
    /// state added without a name a compile error.
    ///
    /// The strings are frozen output rather than an implementation detail:
    /// `mstate()` emits them as `CURL_TRC_M(data, "-> [%s]", ...)`
    /// (`lib/multi.c:166`) by way of `CURL_MSTATE_NAME()`
    /// (`lib/curl_trc.h:321`), so they reach `--trace` logs verbatim. They
    /// keep the C spelling exactly: no `MSTATE_` prefix, and `"DOING_MORE"`
    /// keeps its underscore even though the variant is `DoingMore`.
    ///
    /// Built without verbose strings, `CURL_MSTATE_NAME()` degrades to the
    /// literal `"-"` (`lib/curl_trc.h:333`). Whether to reproduce that is
    /// `crate::trace`'s decision, since it decides whether to ask for a name
    /// at all; this function only supplies one.
    #[allow(dead_code)]
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Init => "INIT",
            Self::Pending => "PENDING",
            Self::Setup => "SETUP",
            Self::Connect => "CONNECT",
            Self::Resolving => "RESOLVING",
            Self::Connecting => "CONNECTING",
            Self::ProtoConnect => "PROTOCONNECT",
            Self::ProtoConnecting => "PROTOCONNECTING",
            Self::Do => "DO",
            Self::Doing => "DOING",
            Self::DoingMore => "DOING_MORE",
            Self::Did => "DID",
            Self::Performing => "PERFORMING",
            Self::RateLimiting => "RATELIMITING",
            Self::Done => "DONE",
            Self::Completed => "COMPLETED",
            Self::MsgSent => "MSGSENT",
        }
    }

    /// Validate a raw integer as a state, or `None` outside `0..COUNT`.
    ///
    /// Counterpart of the bounds check in `Curl_trc_mstate_name()`
    /// (`lib/curl_trc.c:356-357`), where C compares against `CURL_ARRAYSIZE`
    /// before indexing. Unreachable from safe Rust, where a [`CurlMstate`] is
    /// valid by construction; it exists because integers do arrive
    /// unvalidated across the C ABI in `curl-rs-ffi`, and because letting
    /// each caller re-derive the mapping would rebuild exactly the parallel
    /// table this module removes.
    #[allow(dead_code)]
    pub(crate) fn from_i32(state: i32) -> Option<Self> {
        match state {
            0 => Some(Self::Init),
            1 => Some(Self::Pending),
            2 => Some(Self::Setup),
            3 => Some(Self::Connect),
            4 => Some(Self::Resolving),
            5 => Some(Self::Connecting),
            6 => Some(Self::ProtoConnect),
            7 => Some(Self::ProtoConnecting),
            8 => Some(Self::Do),
            9 => Some(Self::Doing),
            10 => Some(Self::DoingMore),
            11 => Some(Self::Did),
            12 => Some(Self::Performing),
            13 => Some(Self::RateLimiting),
            14 => Some(Self::Done),
            15 => Some(Self::Completed),
            16 => Some(Self::MsgSent),
            // This arm matches an `i32`, not a `CurlMstate`: it is C's failed
            // bounds check, not a wildcard over the enumeration. The
            // no-`_`-arm rule stated above governs matches on the state type.
            _ => None,
        }
    }

    /// Trace name for a raw integer, `"?"` when it is not a state.
    ///
    /// Behaves exactly as `Curl_trc_mstate_name()` does
    /// (`lib/curl_trc.c:354-358`). The answer is routed through
    /// [`name`](Self::name) rather than through a table of its own, so a
    /// state's string is still written in exactly one place.
    #[allow(dead_code)]
    pub(crate) fn name_from_i32(state: i32) -> &'static str {
        match Self::from_i32(state) {
            Some(state) => state.name(),
            None => Self::UNKNOWN_NAME,
        }
    }

    /// Whether the transfer has not yet started sending its request.
    ///
    /// `Curl_is_connecting()` verbatim -- `data->mstate < MSTATE_DO`
    /// (`lib/multi.c:359-361`). The C function accepts a `Curl_easy *` only
    /// to reach `data->mstate`, so the predicate belongs on the state.
    #[allow(dead_code)]
    pub(crate) fn is_connecting(self) -> bool {
        self < Self::Do
    }

    /// Whether removing the handle now would cut a transfer short.
    ///
    /// The `premature` computation of `curl_multi_remove_handle()` --
    /// `data->mstate < MSTATE_COMPLETED` (`lib/multi.c:786`).
    #[allow(dead_code)]
    pub(crate) fn is_premature(self) -> bool {
        self < Self::Completed
    }

    /// Whether a request is in flight, so abandoning it would leave the
    /// connection holding a partial response.
    ///
    /// The guard at `lib/multi.c:791-792`,
    /// `MSTATE_DO < mstate && mstate < MSTATE_COMPLETED`, which is what makes
    /// `curl_multi_remove_handle()` close the stream with "Removed with
    /// partial response" (`lib/multi.c:795`). The lower bound is strict, so
    /// `Do` itself is excluded.
    #[allow(dead_code)]
    pub(crate) fn is_in_transfer(self) -> bool {
        Self::Do < self && self < Self::Completed
    }
}

/// Formats as the trace name, keeping `{}` and `{:?}` distinguishable: `{}`
/// gives the C string (`"DOING_MORE"`), `{:?}` the Rust variant
/// (`DoingMore`). [`CurlMstate::name`] remains the primary entry point,
/// because callers splicing the name into `&str`-shaped trace output must not
/// be forced through a formatting machine to get it.
impl core::fmt::Display for CurlMstate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::CurlMstate;

    /// Every real state, in declaration order. Typed `[_; CurlMstate::COUNT]`,
    /// so a variant added without extending this array is a compile error.
    #[rustfmt::skip]
    const ALL: [CurlMstate; CurlMstate::COUNT] = [
        CurlMstate::Init, CurlMstate::Pending, CurlMstate::Setup,
        CurlMstate::Connect, CurlMstate::Resolving, CurlMstate::Connecting,
        CurlMstate::ProtoConnect, CurlMstate::ProtoConnecting, CurlMstate::Do,
        CurlMstate::Doing, CurlMstate::DoingMore, CurlMstate::Did,
        CurlMstate::Performing, CurlMstate::RateLimiting, CurlMstate::Done,
        CurlMstate::Completed, CurlMstate::MsgSent,
    ];

    /// The seventeen strings `Curl_trc_mstate_names[]` holds
    /// (`lib/curl_trc.c:334`), in the same order and with no `"LAST"` entry.
    /// Transcribed from the C array independently of `CurlMstate::name`, so
    /// this is a genuine oracle rather than a restatement of the
    /// implementation. `rustfmt` is kept off the table because these are
    /// frozen trace literals.
    #[rustfmt::skip]
    const NAMES: [&str; CurlMstate::COUNT] = [
        "INIT", "PENDING", "SETUP", "CONNECT", "RESOLVING", "CONNECTING",
        "PROTOCONNECT", "PROTOCONNECTING", "DO", "DOING", "DOING_MORE", "DID",
        "PERFORMING", "RATELIMITING", "DONE", "COMPLETED", "MSGSENT",
    ];

    /// The exhaustiveness guarantee: what the C parallel array asserted by
    /// hand, now checked mechanically.
    #[test]
    fn names_match_the_c_table_exactly() {
        for (state, expected) in ALL.iter().zip(NAMES.iter()) {
            assert_eq!(state.name(), *expected, "wrong name for {state:?}");
        }
        assert_eq!(CurlMstate::Init.name(), "INIT");
        assert_eq!(CurlMstate::ProtoConnecting.name(), "PROTOCONNECTING");
        // The variant is `DoingMore`; the string keeps the C spelling.
        assert_eq!(CurlMstate::DoingMore.name(), "DOING_MORE");
        assert_eq!(CurlMstate::MsgSent.name(), "MSGSENT");
    }

    /// Eighteen C tokens, seventeen states, seventeen names, and pinned
    /// integers (`lib/multihandle.h:51-70`, `lib/curl_trc.c:334`). Reordering
    /// would change trace output and every `Ord` comparison in `lib/multi.c`.
    #[test]
    fn discriminants_and_counts_match_the_c_header() {
        for (index, state) in ALL.iter().enumerate() {
            assert_eq!(*state as usize, index, "wrong value for {state:?}");
        }
        assert_eq!(CurlMstate::Init as u8, 0);
        assert_eq!(CurlMstate::Do as u8, 8);
        assert_eq!(CurlMstate::MsgSent as u8, 16);
        assert_eq!(CurlMstate::COUNT, 17);
        assert_eq!(ALL.len(), 17);
        assert_eq!(NAMES.len(), 17);
        assert_eq!(CurlMstate::LAST, 17);
        assert_eq!(usize::from(CurlMstate::LAST), CurlMstate::COUNT);
        assert!(!NAMES.contains(&"LAST"), "MSTATE_LAST has no name string");
    }

    /// Declaration order is the ordering, and `oldstate < MSTATE_DONE` is the
    /// done-notification gate of `mstate()` (`lib/multi.c:178`).
    #[test]
    fn ordering_follows_declaration_order() {
        for pair in ALL.windows(2) {
            assert!(pair[0] < pair[1], "{:?} !< {:?}", pair[0], pair[1]);
        }
        assert_eq!(ALL.iter().min(), Some(&CurlMstate::Init));
        assert_eq!(ALL.iter().max(), Some(&CurlMstate::MsgSent));
        for state in ALL {
            assert_eq!(state < CurlMstate::Done, (state as u8) < 14);
        }
        assert!(CurlMstate::Init < CurlMstate::Done);
        assert!(CurlMstate::Performing < CurlMstate::Done);
        assert!(CurlMstate::Done >= CurlMstate::Done);
        assert!(CurlMstate::Completed >= CurlMstate::Done);
    }

    /// `Curl_is_connecting()` -- `data->mstate < MSTATE_DO`
    /// (`lib/multi.c:359-361`). The boundary is stated as a literal set
    /// rather than re-derived from the implementation.
    #[test]
    fn is_connecting_matches_curl_is_connecting() {
        #[rustfmt::skip]
        let connecting = [
            CurlMstate::Init, CurlMstate::Pending, CurlMstate::Setup,
            CurlMstate::Connect, CurlMstate::Resolving,
            CurlMstate::Connecting, CurlMstate::ProtoConnect,
            CurlMstate::ProtoConnecting,
        ];
        for state in ALL {
            assert_eq!(
                state.is_connecting(),
                connecting.contains(&state),
                "is_connecting wrong for {state:?}"
            );
        }
        assert!(!CurlMstate::Do.is_connecting());
        assert!(!CurlMstate::MsgSent.is_connecting());
    }

    /// The `premature` flag (`lib/multi.c:786`) and the partial-response
    /// guard (`lib/multi.c:791-792`) of `curl_multi_remove_handle()`.
    #[test]
    fn premature_and_in_transfer_match_remove_handle() {
        #[rustfmt::skip]
        let in_transfer = [
            CurlMstate::Doing, CurlMstate::DoingMore, CurlMstate::Did,
            CurlMstate::Performing, CurlMstate::RateLimiting,
            CurlMstate::Done,
        ];
        for state in ALL {
            assert_eq!(
                state.is_premature(),
                state < CurlMstate::Completed,
                "is_premature wrong for {state:?}"
            );
            assert_eq!(
                state.is_in_transfer(),
                in_transfer.contains(&state),
                "is_in_transfer wrong for {state:?}"
            );
        }
        // `Do` is the strict lower bound and is therefore excluded.
        assert!(!CurlMstate::Do.is_in_transfer());
        assert!(CurlMstate::Do.is_premature());
        assert!(!CurlMstate::Completed.is_premature());
        assert!(!CurlMstate::MsgSent.is_premature());
    }

    /// `Curl_trc_mstate_name()`'s bounds check and its `"?"` answer
    /// (`lib/curl_trc.c:354-358`). The fallback is `"?"`; `"UNKNOWN?"`
    /// belongs to the timer table (`lib/curl_trc.c:303`) and must never
    /// appear here.
    #[test]
    fn name_from_i32_falls_back_to_question_mark() {
        for (index, state) in ALL.iter().enumerate() {
            let raw = i32::try_from(index).expect("index fits in i32");
            assert_eq!(CurlMstate::name_from_i32(raw), state.name());
            assert_eq!(CurlMstate::from_i32(raw), Some(*state));
        }
        assert_eq!(CurlMstate::name_from_i32(0), "INIT");
        assert_eq!(CurlMstate::name_from_i32(16), "MSGSENT");
        for out_of_range in [-1, 17, 18, 99, i32::MIN, i32::MAX] {
            assert_eq!(CurlMstate::from_i32(out_of_range), None);
            assert_eq!(CurlMstate::name_from_i32(out_of_range), "?");
            assert_ne!(CurlMstate::name_from_i32(out_of_range), "UNKNOWN?");
        }
        // MSTATE_LAST is a bound, never a state.
        assert_eq!(CurlMstate::from_i32(i32::from(CurlMstate::LAST)), None);
        assert_eq!(CurlMstate::UNKNOWN_NAME, "?");
    }

    #[test]
    fn display_delegates_to_name() {
        for state in ALL {
            assert_eq!(state.to_string(), state.name());
        }
        assert_eq!(format!("{}", CurlMstate::DoingMore), "DOING_MORE");
        assert_eq!(format!("{:?}", CurlMstate::DoingMore), "DoingMore");
    }
}
