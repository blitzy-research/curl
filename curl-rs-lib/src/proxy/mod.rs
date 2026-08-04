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

//! Proxy support: tunnelling, SOCKS, the PROXY protocol header, and the
//! no-proxy predicate.
//!
//! Supersedes `lib/http_proxy.c` with `lib/cf-h1-proxy.c` and
//! `lib/cf-h2-proxy.c` (CONNECT tunnelling over HTTP/1 and HTTP/2),
//! `lib/socks.c` (SOCKS4 and SOCKS5), `lib/socks_gssapi.c` (behind the
//! default-off `negotiate` feature), `lib/cf-haproxy.c` (the PROXY protocol
//! header) and `lib/noproxy.c` (`NO_PROXY` matching) -- the six files the
//! transformation map assigns to this directory's six modules.
//!
//! # Five filters and one predicate
//!
//! Every other module here is a connection filter in the chain that
//! [`crate::conn`] owns, which is why proxying needs no special case in the
//! protocol layer: a tunnelled connection and a direct one present the same
//! interface to the scheme above them. `lib/cfilters.h` gives the C's filters
//! `CF_TYPE_PROXY` in their type bitmap for exactly that reason.
//!
//! [`noproxy`] is the exception and is deliberately not a filter. It is a
//! pure predicate over two byte strings, consulted BEFORE any filter is
//! inserted, and its answer decides whether the proxy filters are built at
//! all. That ordering is the whole of the proxy-bypass mechanism, and it is
//! why the module that implements it owns no state, no socket and no place in
//! the chain.
//!
//! `pub(crate)`, and so is everything it declares: a proxy is configured
//! through options -- `CURLOPT_PROXY`, `CURLOPT_NOPROXY`,
//! `CURLOPT_PROXYTYPE` and their relatives -- and observed through
//! `CURLINFO_*`, so no exported symbol of `lib/libcurl.def` is backed from
//! this directory directly.

/// `NO_PROXY` and `--noproxy` host matching -- supersedes `lib/noproxy.c` and
/// `lib/noproxy.h`.
///
/// The first module of this directory to land, and the only one with no
/// dependency on the filter chain: `grep -n 'cfilters\.h\|Curl_cf' lib/
/// noproxy.c lib/noproxy.h` returns nothing, and its two includes are
/// `curlx/inet_pton.h` and `curlx/strparse.h`. So it rests on
/// [`crate::util`] alone and can be built and tested before anything else
/// here exists.
///
/// No `#[allow(dead_code)]` on this declaration, deliberately: a lint level
/// for `dead_code` on a module root would also silence the next unreferenced
/// item somebody adds. The allowance belongs on the ITEM whose consumer has
/// yet to land, which is where `noproxy::check_noproxy` carries it.
pub(crate) mod noproxy;
