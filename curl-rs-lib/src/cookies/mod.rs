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

//! Persisted client state: the cookie jar, `.netrc`, HSTS and Alt-Svc.
//!
//! Supersedes `lib/cookie.c`, `lib/psl.c`, `lib/netrc.c`, `lib/hsts.c` and
//! `lib/altsvc.c`. What these five have in common is the reason they share
//! a module: every one of them reads and writes a file on the user's disk
//! whose format is FROZEN. A jar written by curl 8.19.0-DEV must be
//! readable here and one written here must be readable there, and the same
//! obligation applies to the HSTS and Alt-Svc caches and to `.netrc`. That
//! is why the jar is implemented natively rather than delegated to a
//! general-purpose cookie crate -- no such crate commits to the Netscape
//! on-disk shape -- and why `publicsuffix` is used for nothing but the
//! domain-matching rules that libpsl previously supplied.
//!
//! `pub(crate)`: no exported symbol of `lib/libcurl.def` resolves a name
//! here. The cookie engine, the caches and `.netrc` are all reached through
//! an easy handle's option surface.
//!
//! # Partially delivered
//!
//! Of this module's planned children, [`netrc`], the public-suffix rules of
//! `psl`, the HSTS cache of `hsts` and the Alt-Svc cache of `altsvc` exist;
//! only the cookie jar itself (`lib/cookie.c`) arrives with its own file.
//! This file is the module root and declares exactly the four
//! children that exist: a `mod` line without its file is
//! `error[E0583]`, which no attribute can suppress, so each declaration
//! lands with the file it names -- the convention `curl-rs-lib/src/lib.rs`
//! states for the whole crate and that `url`, `tls`, `multi` and `easy`
//! already follow.
//!
//! # Four of the five children are gated and one is NOT
//!
//! The capability names are `cookies`, `hsts` and `altsvc`, and they gate
//! the jar, the HSTS cache and the Alt-Svc cache respectively -- matching
//! the C's `CURL_DISABLE_COOKIES`, `CURL_DISABLE_HSTS` and
//! `CURL_DISABLE_ALTSVC`. `hsts` and `altsvc` carry theirs on the
//! declarations below; the `cookies` gate belongs on the jar's declaration
//! when it lands.
//!
//! `cookies` additionally gates `psl`, which the C expresses as a separate
//! `USE_LIBPSL` switch. The reason is mechanical rather than stylistic:
//! the public-suffix rules are the ONE child of this module that reaches an
//! external crate, and `publicsuffix` is declared `optional` in
//! `curl-rs-lib/Cargo.toml` with `cookies = ["dep:publicsuffix"]` as its only
//! activator, so an unconditional declaration would fail to RESOLVE the
//! crate under `--no-default-features` rather than merely compile a larger
//! tree.
//!
//! [`netrc`] carries NO gate, deliberately. The C has
//! `#ifndef CURL_DISABLE_NETRC` (`lib/netrc.h:28`), but credential lookup
//! serves every protocol rather than only HTTP -- `lib/url.c:2608` runs it
//! for any scheme that can carry a user and a password -- so attaching it
//! to the cookie engine would silently disable `--netrc` for FTP and SFTP.
//! The crate's capability vocabulary is closed at fifteen names in
//! `curl-rs-lib/Cargo.toml` and none of them is a netrc switch, so there is
//! nothing to attach it to in any case. The module's own header records the
//! measurement.

/// The Alt-Svc cache (RFC 7838), behind `--alt-svc <file>`.
///
/// Supersedes `lib/altsvc.c` and `lib/altsvc.h`, and backs `CURLOPT_ALTSVC`
/// (10287) and `CURLOPT_ALTSVC_CTRL` (286).
///
/// **Gated on `altsvc`**, the successor of C's `CURL_DISABLE_ALTSVC`, as this
/// module's header says it must be. The C additionally gates the file on
/// `CURL_DISABLE_HTTP` (`lib/altsvc.c:30`); there is no counterpart, because
/// the crate's capability vocabulary is closed at fifteen names and none of
/// them switches HTTP off.
///
/// It carries two things beyond the cache itself, and both are recorded here
/// so that a later module imports rather than redeclares them: `AlpnId`, the
/// successor of `enum alpnid` (`lib/hostip.h:49-54`), whose eventual home is
/// `crate::dns`; and the two name conversions of `lib/connect.c:73-95`, whose
/// eventual home is `crate::conn`. Neither module provides them at this
/// commit. The child's own header states the contract for moving them.
#[cfg(feature = "altsvc")]
pub(crate) mod altsvc;

/// `.netrc` credential lookup, behind `--netrc`, `--netrc-file` and
/// `--netrc-optional`.
///
/// Supersedes `lib/netrc.c` and `lib/netrc.h`, and backs `CURLOPT_NETRC`
/// (51) and `CURLOPT_NETRC_FILE` (10118).
///
/// **Declared unconditionally**, for the reason recorded above. The
/// module compiles and is reachable under
/// `cargo build -p curl-rs-lib --no-default-features`.
pub(crate) mod netrc;

/// The Public Suffix List -- may this host set a cookie for this domain, or
/// would that be a "super cookie" set at registry level?
///
/// Supersedes `lib/psl.c` and `lib/psl.h`, replacing the `libpsl` binding
/// with the `publicsuffix` crate. Its two consumers are the jar's
/// `is_public_suffix` check, the port of `lib/cookie.c:774-819`, and
/// [`crate::version`], which must report the `PSL` capability truthfully
/// rather than assume it.
///
/// **Gated on `cookies`**, unlike [`netrc`] above, for the dependency reason
/// recorded in this module's header. Availability is therefore a RUN-TIME
/// property inside the module as well as a compile-time one: the list source
/// is injected, so "configured but unloadable" fails closed exactly as the
/// C's `USE_LIBPSL` arm with a null list does, while "never configured"
/// reproduces the `#ifndef USE_LIBPSL` arm in which no cookie is dropped on
/// public-suffix grounds.
#[cfg(feature = "cookies")]
pub(crate) mod psl;

/// The HTTP Strict Transport Security cache, behind `--hsts <file>`.
///
/// Supersedes `lib/hsts.c` and `lib/hsts.h`, and backs `CURLOPT_HSTS`
/// (10300), `CURLOPT_HSTS_CTRL` (299) and the four callback options
/// `CURLOPT_HSTSREADFUNCTION` (20301), `CURLOPT_HSTSREADDATA` (10302),
/// `CURLOPT_HSTSWRITEFUNCTION` (20303) and `CURLOPT_HSTSWRITEDATA` (10304).
///
/// **Gated on `hsts`**, matching the C's `CURL_DISABLE_HSTS`. The C
/// additionally requires HTTP -- `#if !defined(CURL_DISABLE_HTTP) &&
/// !defined(CURL_DISABLE_HSTS)` at `lib/hsts.c:30` -- which has no
/// counterpart here because HTTP/1.1 is unconditional in this crate and the
/// capability vocabulary is closed at fifteen names in
/// `curl-rs-lib/Cargo.toml`, none of which is an HTTP switch.
///
/// Its on-disk format is a frozen, consumer-visible contract and is NOT the
/// Netscape jar's: the HSTS header carries no trailing blank line where the
/// jar's does. The module's own header records the measurement and the two
/// are deliberately not shared.
#[cfg(feature = "hsts")]
pub(crate) mod hsts;
