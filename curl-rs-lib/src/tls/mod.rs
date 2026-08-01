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
//! TLS -- rustls, and rustls only.
//!
//! Supersedes `lib/vtls/`. In the C tree that directory is an abstraction over
//! seven interchangeable backends: `struct Curl_ssl` carries roughly 22 entry
//! points (`lib/vtls/vtls_int.h:141-190`) and `lib/vtls/vtls.c` dispatches
//! through it to OpenSSL, GnuTLS, mbedTLS, wolfSSL, Schannel, Secure Transport
//! or rustls-ffi. Here the abstraction is retained but the dispatch collapses
//! to a single implementation, because backend *identity* is observable through
//! the public ABI -- `curl_version_info` reports it and `curl_global_sslset`
//! enumerates it -- while backend *choice* is not: rustls is the only TLS
//! implementation at any configuration.
//!
//! # There is no `tls` feature, and there must never be one
//!
//! This module is declared unconditionally by the crate root. An
//! off-switchable `tls` feature would permit a build with no TLS at all, which
//! contradicts both "rustls exclusively" and "certificate validation on by
//! default". The prohibition is mechanically enforced rather than merely
//! stated: writing `feature = "tls"` anywhere produces
//! `warning: unexpected 'cfg' condition value: 'tls'`, and continuous
//! integration runs clippy with `-D warnings`.
//!
//! # Cryptographic provider: `ring`, pinned, with no default features
//!
//! `rustls`, `tokio-rustls` and `quinn` are pinned in the workspace manifest
//! with `default-features = false` and the `ring` provider. Nothing under this
//! directory may enable a feature that unions `aws_lc_rs`,
//! `prefer-post-quantum` or `platform-verifier` back into the graph. Cargo
//! unions features across the whole graph, so one stray feature on one
//! optional dependency re-links a second provider, and three distinct defects
//! follow: `prefer-post-quantum` changes the bytes of the ClientHello relative
//! to curl 8.19.0-DEV and so endangers every HTTPS fixture under the
//! byte-exact fixture comparison; `aws-lc-rs` vendors C and assembly and adds
//! CMake and NASM to the build's requirements, which is hostile to the
//! cross-compiled `aarch64-unknown-linux-gnu` target; and
//! `platform-verifier` delegates trust decisions to the operating-system
//! store, which conflicts with `--cacert`, `--capath` and `--insecure`
//! remaining authoritative.
//!
//! # Backend identity: one struct member whose position is contractual
//!
//! When the backend-identity struct is declared, `curl_ssl_backend info` must
//! be its **first** member. `lib/vtls/vtls_int.h:142-145` gives the reason
//! verbatim: "This *must* be the first entry to allow returning the list of
//! available backends in `curl_global_sslset()`." The reported identity is
//! `CURLSSLBACKEND_RUSTLS`, whose value 14 already exists in the public
//! `curl_sslbackend` enumeration of `include/curl/curl.h`, so no value is
//! invented and `curl_global_sslset` can name a rustls backend without
//! extending the public vocabulary. That identity reaches C through
//! [`crate::version`], not by widening this directory's visibility.
//!
//! # The two modules declared here
//!
//! Both are pure, self-contained pieces of the TLS surface that carry no
//! dependency on a live session, which is why they are separable from the
//! session machinery and testable without a network:
//!
//! - [`cipher_suite`] -- the cipher-suite name mapping of
//!   `lib/vtls/cipher_suite.c`. Its job is acceptance parity: curl accepts
//!   several spellings for the same suite (the OpenSSL name, the IANA/RFC
//!   name, and a raw hexadecimal identifier), and a list that a real curl
//!   accepts must be accepted here too, with the same separators and the same
//!   diagnostics for the entries it rejects.
//! - [`keylog`] -- `SSLKEYLOGFILE` support from `lib/vtls/keylog.c`. The file
//!   format is read by external tools, so its record shape, its label length
//!   bound and its append semantics are frozen output.
//!
//! Visibility throughout is `pub(crate)`: `lib/vtls/`'s internal contracts were
//! `extern` declarations under a `Curl_` prefix, private by convention and
//! visible to the linker, and they become private by enforcement here.

/// Cipher-suite name mapping: supersedes `lib/vtls/cipher_suite.c`.
///
/// Parses the suite lists that `CURLOPT_SSL_CIPHER_LIST` and
/// `CURLOPT_TLS13_CIPHERS` accept, renders an identifier back to a name for
/// diagnostics and for `CURLINFO`, and reports per-entry diagnostics for the
/// entries a provider does not offer.
pub(crate) mod cipher_suite;

/// `SSLKEYLOGFILE` support: supersedes `lib/vtls/keylog.c`.
///
/// Writes the NSS-format key-log records that packet analysers consume. The
/// destination comes from the environment, exactly as in C, and the record
/// text is frozen output rather than a formatting choice.
pub(crate) mod keylog;
