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
//! The URL API, percent-encoding and internationalised domain names.
//!
//! Supersedes `lib/urlapi.c`, `lib/escape.c` and `lib/idn.c`. `pub` because it
//! backs eight of the 100 exported symbols: the six-strong URL API --
//! `curl_url`, `curl_url_cleanup`, `curl_url_dup`, `curl_url_get`,
//! `curl_url_set` and `curl_url_strerror` -- together with `curl_escape` and
//! `curl_unescape`.
//!
//! # `CURLU` is the one public handle that is a real struct
//!
//! The handle typedefs of the public headers are deliberately **not** uniform,
//! and treating them uniformly breaks consumers. `CURL`, `CURLM` and `CURLSH`
//! are `typedef void` (`include/curl/curl.h:109-110`,
//! `include/curl/multi.h:57`), so a consumer may assign any of them to a
//! `void *` and many do. `CURLU` alone is
//! `typedef struct Curl_URL CURLU` (`include/curl/urlapi.h:107`) -- a genuine
//! opaque struct. Its representation is therefore part of the contract in a way
//! the others' is not, and `curl-rs-ffi` carries it as an opaque pointer rather
//! than as `*mut c_void`.
//!
//! # curl's parsing quirks are preserved, not delegated
//!
//! The `url` crate is a workspace dependency and is used where it helps, but
//! this module does not delegate parsing to it wholesale. curl accepts URLs
//! that a WHATWG-conformant parser rejects, normalises differently in several
//! places, and exposes the results through `curl_url_get` part by part, so the
//! divergences are directly observable through the API and through the fixture
//! corpus. AAP section 0.8.1 freezes them. Where curl and a general-purpose
//! parser disagree, curl wins, and the disagreement is documented at the site
//! that implements it.
//!
//! # The modules declared here
//!
//! [`escape`] carries percent-encoding and percent-decoding, superseding
//! `lib/escape.c`. It is `pub` because four of the 100 exported symbols are
//! backed from it -- `curl_easy_escape` and `curl_easy_unescape` together with
//! the two ABI-compatibility forwarders `curl_escape` and `curl_unescape`,
//! which `lib/escape.c:36-45` defines as nothing but calls into them.
//!
//! It is a module of its own rather than part of the URL parser because the
//! transformation is independent of any parsed URL: the four exported functions
//! ignore the `CURL *` handle they accept, and have done since 7.82.0
//! (`lib/escape.c:48`, `:161`). The parser is a consumer of the module, not the
//! other way round, which is also why the two strict `urlreject` modes of
//! `Curl_urldecode` are recorded there as belonging to whoever lands
//! `lib/urlapi.c` rather than being added ahead of a caller.
//!
//! [`idn`] carries internationalised domain names, superseding `lib/idn.c`
//! with the `idna` crate in place of libidn2. It is separable from the rest of
//! the URL surface because it is a pure host-name transformation with no
//! dependency on a parsed URL, and it additionally owns two capability
//! predicates that the version banner consumes -- which is why it is `pub`
//! rather than `pub(crate)`: `lib/version.c:407-416` computes `idn_present` and
//! `lib/version.c:496` registers it as `FEATURE("IDN", idn_present,
//! CURL_VERSION_IDN)`, so the answer has to be reachable from
//! [`crate::version`] and, through it, from `curl_version_info`.
//!
//! One consequence of that decoupling is recorded here because it is easy to
//! get wrong in the other direction: an `idna`-backed build advertises the
//! `IDN` feature yet reports no `libidn` version, because libidn2 is not what
//! is linked. In C those two are coupled -- `idn_present` *is*
//! `info->libidn != NULL` -- so reproducing the coupling would mean emitting a
//! `libidn2/...` token, which additionally sets `$feature{"libidn2"}` in the
//! test harness (`tests/runtests.pl:625-626`) on a false premise. Truthful
//! advertisement is the requirement (AAP section 0.6.5), and it decouples them.

/// Percent-encoding and percent-decoding: supersedes `lib/escape.c`.
///
/// Owns the unreserved-byte set, the uppercase hex digits, and the decode
/// walk's strict `alloc > 2` lookahead test, each asserted against a
/// self-describing oracle measured from the frozen library.
///
/// `pub` because [`escape::escape`] and [`escape::unescape`] back four of the
/// 100 symbols `lib/libcurl.def` exports, and `curl-rs-ffi` has no other route
/// to them.
pub mod escape;

/// Internationalised domain names: supersedes `lib/idn.c`.
///
/// Converts hostnames between their Unicode and A-label forms with the `idna`
/// crate, reproducing curl's acceptance rules and error codes, and answers the
/// two capability questions the `--version` banner asks about IDN support.
///
/// `pub` for that second reason: [`idn::available`] and [`idn::version_string`]
/// are the authority behind the `IDN` feature bit and the `libidn` field of
/// `curl_version_info_data`, both of which cross the C ABI.
pub mod idn;
