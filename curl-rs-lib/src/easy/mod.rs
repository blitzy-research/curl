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

//! The easy interface: one handle, one transfer.
//!
//! Supersedes `lib/easy.c`, `lib/setopt.c` (308 options), `lib/getinfo.c`
//! (70 `CURLINFO` accessors) and the generated `lib/easyoptions.c` with
//! `lib/easygetopt.c`. `pub` because it backs the 21 exported
//! `curl_easy_*` symbols of `lib/libcurl.def`, and because the "peer
//! verification disabled" state that obliges `curl-rs` to warn on standard
//! error before proceeding is readable through this surface.
//!
//! # The god-struct is decomposed here
//!
//! `lib/urldata.h` is included nearly universally in C and concentrates
//! connection, transfer and TLS state in one declaration. Those fields
//! migrate to the module that owns their lifecycle, and cross-module
//! access becomes an explicit borrow rather than an implicit reach into
//! shared mutable state.
//!
//! # The option table is NOT declared here
//!
//! `curl-rs-ffi` is the sole source of truth for the 308 `CURLoption`
//! identifiers, their backward-compatibility aliases and the
//! `curl_easyoption` metadata array behind `curl_easy_option_by_name`,
//! `_by_id` and `_next`; this module **consumes** that table (AAP 0.1.2).
//! Two tables would drift, and the drift would stay invisible until a
//! consumer queried an option by name and received the wrong identifier.
//!
//! [`options`] is where that consumption happens. It owns the lookup
//! algorithm and the option-identity vocabulary the rest of the engine
//! dispatches on -- and it owns no rows.
//!
//! # Partially delivered
//!
//! Two of this module's planned children exist: [`options`], and now
//! [`handle`] -- the decomposed easy handle itself, from `lib/easy.c` with
//! `lib/urldata.h`. The option setters (`lib/setopt.c`) and the `CURLINFO`
//! accessors (`lib/getinfo.c`) arrive with their own files. This file is the
//! module root and declares exactly the children that exist: a `mod` line
//! without its file is `error[E0583]`, which no attribute can suppress,
//! so each declaration lands with the file it names.
//!
//! [`handle`] delivers the state those two remaining files act on -- the
//! option set with its frozen defaults, the metadata store, the identity
//! token and the `curl_easy_getinfo` backing store -- so it lands first by
//! necessity rather than by preference.

/// The easy handle: `lib/urldata.h`'s god-struct, decomposed.
///
/// `pub` because both adapter crates need the handle type: `curl-rs-ffi`
/// owns it across the C boundary for `curl_easy_init` and
/// `curl_easy_cleanup`, and `curl-rs` reads the *"peer verification
/// disabled"* state through it in order to warn on standard error before
/// proceeding. Its internals stay `pub(crate)`.
pub mod handle;

/// Option identity: the lookup behind `curl_easy_option_by_name`,
/// `curl_easy_option_by_id` and `curl_easy_option_next`.
///
/// Supersedes `lib/easygetopt.c` and consumes the metadata table that
/// `lib/easyoptions.c` generates in C.
///
/// `pub` for two consumers rather than one. `curl-rs-ffi` needs the
/// algorithm, because it owns the table the algorithm searches and must
/// not write a second search of its own. `curl-rs` needs the vocabulary --
/// chiefly `OptionId` and its band decode -- to name options while
/// translating command-line configuration into option calls.
pub mod options;
