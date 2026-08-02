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
//! The multi interface: many transfers, one driver.
//!
//! Supersedes `lib/multi.c` together with `lib/multihandle.h`, `lib/multi_ev.c`
//! and `lib/multi_ntfy.c`. `pub` because it backs the 22 exported
//! `curl_multi_*` symbols of `lib/libcurl.def`, including `curl_multi_socket`
//! and `curl_multi_socket_all`, which are deprecated in the public headers yet
//! still exported and therefore still in the parity set. Nothing deprecated is
//! removed.
//!
//! # What this root owns, and what it delegates
//!
//! The transfer state machine is not here: it is [`state`], which reproduces
//! the eighteen `CURLMstate` tokens of `lib/multihandle.h:51-70` as a
//! `#[repr(...)]` enum whose discriminant order is part of its contract,
//! because `lib/multi.c` compares states with `<` and `>` rather than for
//! equality. Keeping the enumeration in its own file matches AAP section
//! 0.4.1, which maps `curl-rs-lib/src/multi/state.rs` from `lib/multi.c` with
//! `lib/multihandle.h`, and it keeps the state machine reviewable apart from
//! the driver that runs it.
//!
//! What this root does own is the one capability question the multi interface
//! answers about itself, described next.
//!
//! # `ENABLE_WAKEUP` is a capability, not a preference
//!
//! `curl_multi_wakeup` interrupts a `curl_multi_poll` that is blocked waiting
//! for socket activity. C implements it by writing one byte into a
//! self-pipe -- `Curl_wakeup_init(multi->wakeup_pair, TRUE)` at
//! `lib/multi.c:297-301` -- and the whole feature is compiled out when that
//! primitive is unavailable. The macro that governs it is derived, not
//! configured:
//!
//! ```text
//! /* lib/multihandle.h:73-76 */
//! #ifndef CURL_DISABLE_SOCKETPAIR
//! #define ENABLE_WAKEUP
//! #endif
//! ```
//!
//! So `ENABLE_WAKEUP` is exactly "a socket pair can be created", and eight
//! sites in `lib/multi.c` (`:297`, `:1357`, `:1433`, `:1455`, `:1533`,
//! `:1548`, `:1604`, `:2908`) branch on it. `src/curlinfo.c:162-167` reports
//! it as the `wakeup: ` row of its capability table, printing `OFF` under
//! `#ifndef ENABLE_WAKEUP`.
//!
//! [`wakeup_available`] is that row's authority. It is declared here, in the
//! module that owns the feature, rather than being re-derived by the
//! diagnostic binary, so the report and the behaviour cannot disagree.

/// The completion-message queue and the notification subsystem.
///
/// `pub`, unlike [`state`] beside it, and the difference is the ABI. Four
/// exported symbols rest on this module -- `curl_multi_info_read`,
/// `curl_multi_get_offt`, `curl_multi_notify_enable` and
/// `curl_multi_notify_disable` -- and the vocabulary their signatures name
/// travels with them: `CURLMSG`, `CURLMinfo_offt` and the two
/// `CURLMNOTIFY_*` macros all appear in `include/curl/multi.h`. Their pinned
/// engine-side counterparts are therefore reachable from `curl-rs-ffi`, which
/// bridges each to its C-shaped declaration. A `CURLMstate`, by contrast,
/// crosses no boundary at all.
///
/// Only that vocabulary is public. The queue, the notification store, the
/// chunk ring and the enabled bitset are `pub(crate)`: the shim reaches them
/// through this crate's multi handle, never directly, so a static library that
/// does not export `pub(crate)` items costs nothing here.
///
/// Declared before [`state`] because `rustfmt.toml` sets
/// `reorder_modules = true` and would otherwise move it.
pub mod notify;

/// The transfer state machine: the seventeen reachable `CURLMstate` values.
///
/// `pub(crate)`: no exported symbol takes or returns a state. The multi
/// interface exposes state-dependent *behaviour* through `curl_multi_perform`
/// and `curl_multi_info_read`, and `CURLINFO` exposes derived counters, but
/// the enumeration itself is internal -- `CURLMstate` appears in
/// `lib/multihandle.h`, an internal header, and not in `include/curl/multi.h`.
pub(crate) mod state;

/// Whether `curl_multi_wakeup` can interrupt a blocked poll on this target.
///
/// The authority for the `wakeup: ` row of `src/curlinfo.c:162-167` and for
/// the eight `ENABLE_WAKEUP` branches in `lib/multi.c`.
///
/// # How the answer is computed
///
/// `lib/multihandle.h:73-76` defines `ENABLE_WAKEUP` unless
/// `CURL_DISABLE_SOCKETPAIR` is defined, so the question reduces to whether a
/// socket pair can be created. Two facts settle it for this workspace:
///
/// * There is no `CURL_DISABLE_SOCKETPAIR` counterpart. The Cargo feature
///   vocabulary is the fifteen names listed in the crate root, and no member
///   of it disables the socket pair, so no build configuration can remove the
///   primitive the way `--disable-socketpair` does in a C build.
/// * `socketpair(2)` is present on every target in the four-target matrix --
///   `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
///   `x86_64-apple-darwin` and `aarch64-apple-darwin` -- all of which are
///   Unix.
///
/// The result is therefore `cfg!(unix)`, and that is written as a `cfg!` test
/// rather than as a bare `true` deliberately: it states the actual dependency,
/// so a target outside the matrix would report `OFF` truthfully instead of
/// inheriting an unexamined `ON`. Under-reporting a capability is safe;
/// over-reporting is not (AAP section 0.6.5).
///
/// `USE_WINSOCK`'s `WSACreateEvent` alternative at `lib/multi.c:294-298` has
/// no counterpart here, because Windows is outside the matrix and the crate
/// carries no code path for it.
///
/// # Examples
///
/// ```
/// // Every supported target provides the primitive.
/// assert!(curl_rs_lib::multi::wakeup_available());
/// ```
pub fn wakeup_available() -> bool {
    cfg!(unix)
}

#[cfg(test)]
mod tests {
    use super::wakeup_available;

    #[test]
    fn wakeup_is_available_on_every_supported_target() {
        // All four mandated targets are Unix, so the derived `ENABLE_WAKEUP`
        // of `lib/multihandle.h:73-76` holds on all of them.
        assert!(wakeup_available());
    }

    #[test]
    fn the_predicate_tracks_the_socket_pair_primitive() {
        // Not a tautology: the assertion is that the answer is *derived* from
        // the platform's socket-pair support, which is precisely what
        // `CURL_DISABLE_SOCKETPAIR` governs in the C build. If this crate were
        // ever built for a non-Unix target, the row would report OFF rather
        // than claim a capability it does not have.
        assert_eq!(wakeup_available(), cfg!(unix));
    }
}
