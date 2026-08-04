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
//! The transfer core: the loop, its buffers and its accounting.
//!
//! Supersedes `lib/transfer.c` (the transfer loop, which becomes async),
//! `lib/request.c` (per-request state), `lib/sendf.c` (manual buffers become
//! `BytesMut`), `lib/cw-out.c` with `lib/cw-pause.c` (the client-writer chain
//! and pause handling), `lib/progress.c` (accounting, with the output format
//! frozen), `lib/ratelimit.c` (`--limit-rate` pacing),
//! `lib/content_encoding.c` (zlib, brotli and zstd calls become `flate2`,
//! `brotli` and `zstd`) and `lib/http_chunks.c` (chunked framing, byte-exact
//! in both directions).
//!
//! `pub(crate)`: a transfer is driven through an easy or a multi handle, and
//! no exported symbol names a transfer directly.
//!
//! This is one of the two directories the line-coverage gate of
//! specification 0.8.4 measures, at 80 percent of lines or better. Almost
//! everything here is time-driven, so the clock reaches this directory by
//! injection -- as a [`CurlTime`] parameter or a [`Clock`] reference from
//! `crate::util::timeval` -- and never by reading the host clock. A module
//! that read the clock itself could not be tested deterministically, and the
//! gate would be out of reach.
//!
//! [`CurlTime`]: crate::util::timeval::CurlTime
//! [`Clock`]: crate::util::timeval::Clock
//!
//! # Partially delivered
//!
//! Of this module's planned children, [`ratelimit`] and [`progress`] exist.
//! The transfer loop itself, per-request state, the send and client-writer
//! paths, content encoding and chunked framing arrive with their own files,
//! and each declaration lands WITH its file -- a `mod` line without a file is
//! `error[E0583]`, which no attribute can reach, because module resolution
//! never gets far enough to produce a lint.
//!
//! The order in which they compose is dependency order rather than
//! preference. [`ratelimit`] came first because it depends on nothing but the
//! utility layer: it is a self-contained arithmetic primitive that progress
//! accounting EMBEDS, following `lib/urldata.h:786-791`, where
//! `struct pgrs_dir` carries a `struct Curl_rlimit` as a member. [`progress`]
//! is second, and it is the only module in this directory that may name
//! [`ratelimit`]; nothing may invert that direction.

/// Transfer accounting and timing: supersedes `lib/progress.c` and
/// `lib/progress.h`.
///
/// Owns the state `CURLINFO_*_T`, the progress callbacks, the low-speed abort
/// and `--write-out`'s `%{time_*}`, `%{size_*}` and `%{speed_*}` variables all
/// read -- the measured `struct Progress` and `struct pgrs_dir` of
/// `lib/urldata.h:786-831`.
///
/// It renders nothing. The built-in meter's layout, `time2str` and `max6out`
/// belong to `curl-rs/src/output/progress.rs` and
/// `curl-rs/src/callbacks/progress.rs`, where the emitted bytes are frozen;
/// this module preserves every value they read and hands it over in one
/// snapshot. It reads no clock and arms no timer either: an instant arrives as
/// a parameter or a `Clock` to sample, and the low-speed check RETURNS the
/// `EXPIRE_SPEEDCHECK` request rather than making it.
pub(crate) mod progress;

/// The token bucket behind `--limit-rate`: supersedes `lib/ratelimit.c` and
/// `lib/ratelimit.h`.
///
/// Serves `CURLOPT_MAX_RECV_SPEED_LARGE` and `CURLOPT_MAX_SEND_SPEED_LARGE`,
/// which is what the command-line tool sets for `--limit-rate`, and the
/// pause mechanism, which is expressed as a blocked limiter rather than as a
/// separate flag.
///
/// It computes durations and nothing else: no timer is armed here, and no
/// transfer state is touched, so the `PERFORMING` and `RATELIMITING`
/// transitions and the `TOOFAST` expiry identifier belong to the transfer
/// loop that consumes it. The contract between the two is transcribed from
/// `lib/multi.c:1880-1921` into the documentation of the module's `wait_ms`
/// and `next_step_ms`.
pub(crate) mod ratelimit;
