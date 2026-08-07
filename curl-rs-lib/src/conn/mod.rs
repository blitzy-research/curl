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

//! Connection establishment and the filter chain.
//!
//! Supersedes `lib/connect.c` together with `lib/cfilters.c`,
//! `lib/cf-socket.c`, `lib/cf-ip-happy.c`, `lib/conncache.c`,
//! `lib/cshutdn.c`, `lib/select.c` and `lib/curlx/wait.c` -- the seven files
//! AAP section 0.4.1 maps onto this directory's seven modules.
//!
//! # What this directory is, and what it is not
//!
//! It is the layer between a protocol and a socket: establishing a connection,
//! racing two address families for it, stacking the filters a scheme needs on
//! top of it, accounting for which sockets a transfer is waiting on, pooling
//! connections for reuse, and shutting them down. It is NOT where protocol
//! semantics live -- those are `crate::protocols` -- and it is not where the
//! transfer loop lives, which is `crate::transfer`.
//!
//! Together with `crate::transfer` this is the crate's ASYNCHRONOUS layer, and
//! that is a deliberate division: `crate::util::bufq` and
//! `crate::util::timeval` keep `tokio` out of the utility layer precisely so
//! that the runtime enters the crate here. `poll` and `select` become the
//! reactor, `alarm` and `sigsetjmp` become `tokio::time::timeout`, and no
//! module below this one needs to know that.
//!
//! # The order the modules must be built in
//!
//! [`select`] is the foundation and has no dependency on anything else in this
//! directory, which was measured rather than assumed:
//! `grep -n "Curl_cfilter\|cfilters\.h\|Curl_conn_" lib/select.h lib/select.c`
//! returns nothing, `struct easy_pollset` is defined at `lib/select.h:120` and
//! only forward-declared at `lib/cfilters.h:57`, and both `lib/cfilters.c:33`
//! and `lib/cf-socket.c:64` include `select.h` rather than the reverse. Every
//! other module here consumes the readiness vocabulary it defines: a filter
//! adjusts a pollset (`Curl_cft_adjust_pollset`, `lib/cfilters.h:84`), the
//! socket filter sets the exact flags it needs (`lib/cf-socket.c:1341-1351`),
//! Happy Eyeballs waits on two of them at once, and the shutdown loop folds
//! many of them into one wait (`lib/cshutdn.c:474-533`).
//!
//! `pub(crate)`, and so is everything it declares: no exported symbol of
//! `lib/libcurl.def` is backed from this directory directly. The public
//! surface reaches it through `crate::multi` and `crate::easy`, which is what
//! keeps connection state out of the C ABI's reach.

/// Socket-readiness accounting -- supersedes `lib/select.c`, `lib/select.h`,
/// `lib/curlx/wait.c` and `lib/curlx/wait.h`.
///
/// The foundation of this directory, for the reason the module documentation
/// above records: it names nothing else in `conn/`, and everything else in
/// `conn/` names it. It owns the `CURL_POLL_*`, `CURL_CSELECT_*` and
/// `CURL_WAIT_POLL*` bitmaps, the pollset a filter chain adjusts, the two
/// aggregation buffers a multi handle waits on, and the wait primitives
/// themselves.
///
/// No `#[allow(dead_code)]` on this declaration, deliberately: the allowances
/// belong on the ITEMS whose consumers have yet to land, so that an item added
/// later with no consumer is still reported.
pub(crate) mod select;

/// The connection filter chain -- supersedes `lib/cfilters.c` and
/// `lib/cfilters.h`.
///
/// The second module of this directory in the order the module documentation
/// above sets out, and for the reason recorded there: it CONSUMES the readiness
/// vocabulary [`select`] defines -- a filter adjusts an `easy_pollset`
/// (`Curl_cft_adjust_pollset`, `lib/cfilters.h:82-84`) and the connect driver
/// waits on one (`lib/cfilters.c:563-579`) -- while `select.h` names nothing
/// from `cfilters.h`.
///
/// It owns the composition mechanism for everything that follows: C's
/// `Curl_cftype` vtable becomes [`filters::ConnFilter`], its untyped
/// `void *ctx` becomes a typed field on each implementing struct, and the
/// intrusive `next` pointer becomes an owned, pinned link. Sockets, Happy
/// Eyeballs, TLS, the proxies, HTTP/2 and HTTP/3 all arrive later as
/// IMPLEMENTATIONS of that one trait rather than as parallel stacks -- which is
/// what lets `crate::protocols` name no TLS type while TLS is interposed
/// beneath it.
///
/// No `#[allow(dead_code)]` on this declaration, for the same reason as
/// [`select`]: the allowances belong on the items.
pub(crate) mod filters;

/// The graceful-shutdown queue -- supersedes `lib/cshutdn.c` and
/// `lib/cshutdn.h`.
///
/// The third module of this directory, and it consumes both of the two before
/// it: it drives [`filters::FilterChain::shutdown`] and
/// [`filters::FilterChain::close_and_clear`] one non-blocking step at a time,
/// and it folds many of the resulting [`select::EasyPollset`]s into one wait
/// (`lib/cshutdn.c:474-533`). Nothing in `cfilters.h` or `select.h` names
/// anything from `cshutdn.h`, so the direction is one-way.
///
/// It owns what C keeps as `struct cshutdn` on the multi handle
/// (`lib/multihandle.h:147`): a FIFO of connections that a transfer has
/// finished with but whose protocols have not yet said goodbye. C links them
/// with a non-owning intrusive list; here the queue owns each connection by
/// value and termination consumes it, which is what makes a double free or a
/// re-queue unrepresentable rather than merely avoided.
///
/// Its two seams onto the rest of the crate are INJECTED traits --
/// [`shutdown::ShutdownHost`] for the multi handle and
/// [`shutdown::ProtocolDisconnect`] for the scheme's disconnect handler -- so
/// that neither `crate::multi` nor `crate::protocols` is named from here and
/// the module graph stays acyclic.
///
/// No `#[allow(dead_code)]` on this declaration, for the same reason as
/// [`select`] and [`filters`]: the allowances belong on the items.
pub(crate) mod shutdown;
