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

//! The protocol implementations and the scheme registry.
//!
//! Supersedes `lib/url.c`'s scheme lookup -- `Curl_get_scheme` (`lib/url.c:1469`)
//! and `Curl_getn_scheme` (`lib/url.c:1477`) over the table registered at
//! `lib/url.c:1488` -- together with `lib/cf-https-connect.c`'s ALPN version
//! negotiation, and, as its children land, `lib/http.c` with `lib/http1.c`,
//! `lib/http2.c`, `lib/vquic/*`, `lib/ftp.c` with `lib/pingpong.c`,
//! `lib/ftplistparser.c` and `lib/fileinfo.c`, `lib/vssh/*`, `lib/file.c` and
//! `lib/ws.c`.
//!
//! # Declared unconditionally; the gates are inside
//!
//! The per-protocol capability names -- `http2`, `http3`, `ftp`, `ssh` and
//! `websockets` -- belong on the child declarations in this file, NOT on the
//! declaration of this module in `curl-rs-lib/src/lib.rs`, so that the registry
//! itself always exists. A build with every protocol feature switched off still
//! has to answer `curl_easy_setopt(CURLOPT_URL, "smtp://...")` with
//! `CURLE_UNSUPPORTED_PROTOCOL` rather than fail to compile, and it still has to
//! report a truthful `Protocols:` line.
//!
//! # The registry is wider than the implementation, deliberately
//!
//! The C tree defines and registers 33 URL schemes. Nine are implemented here;
//! the other 24 are registered for ABI completeness, return
//! `CURLE_UNSUPPORTED_PROTOCOL`, and are deliberately WITHHELD from the
//! `Protocols:` banner so that the 283 fixtures targeting them skip cleanly
//! instead of running and failing. Under-reporting a capability makes a fixture
//! skip; over-reporting makes it run and fail, so truthful advertisement is the
//! optimal strategy and not merely the honest one.
//!
//! A note for anyone reading the C: the backing array is declared
//! `all_schemes[67]` at `lib/url.c:1488` but only 33 entries are defined and
//! registered. The array is over-allocated, and 67 must not be read as a count.
//!
//! # Serialization is ours, not a library's
//!
//! When the HTTP/1.1 module lands it owns request-line composition and header
//! emission in curl's exact order, using `hyper` only for connection
//! management, keep-alive and framing. That is a design constraint rather than
//! a preference: 1,476 of the 1,914 fixtures compare full request bytes as a
//! single joined string with no per-line matching and no reordering, so
//! delegating serialization would fail a large fraction of them for reasons
//! unrelated to correctness. The same principle governs FTP command sequencing
//! below.
//!
//! # Partially delivered
//!
//! Of this directory's planned modules only the FTP directory-listing parser
//! exists yet; the scheme registry itself, `http1`, `http2`, `http3`, `sftp`,
//! `scp`, `file`, `ws` and the 13-scheme stub table arrive with their own
//! files. This file is the module root and declares exactly the one child that
//! exists: a `mod` line without its file is `error[E0583]`, which no attribute
//! can suppress, so each declaration lands with the file it names -- the
//! convention `curl-rs-lib/src/lib.rs` states for the whole crate and that
//! `url`, `tls`, `multi`, `easy`, `conn`, `cookies`, `auth` and `transfer`
//! already follow.
//!
//! `pub(crate)`: a scheme is selected by URL, never named by a caller, so no
//! exported symbol of `lib/libcurl.def` resolves a name in this directory.

/// FTP and FTPS -- `lib/ftp.c`, `lib/pingpong.c`, `lib/ftplistparser.c` and
/// `lib/fileinfo.c`.
///
/// Gated on `ftp`, matching the C's `CURL_DISABLE_FTP`. The gate sits here
/// rather than on this module's own declaration for the reason recorded above.
///
/// **Partially delivered**: only the directory-listing parser exists yet.
#[cfg(feature = "ftp")]
pub(crate) mod ftp;
