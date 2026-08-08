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

/// The raw transports and the multi wakeup -- supersedes `lib/cf-socket.c`,
/// `lib/cf-socket.h`, `lib/socketpair.c`, `lib/socketpair.h`,
/// `lib/curlx/nonblock.c` and `lib/curlx/nonblock.h`.
///
/// The fourth module of this directory, and it consumes all three before it: its
/// four filters IMPLEMENT [`filters::ConnFilter`], they adjust a
/// [`select::EasyPollset`], and [`shutdown`] is what eventually drives their
/// graceful close. It also consumes [`addr2string`] from this file, which is the
/// one helper that belongs to the parent rather than to a module -- see that
/// function for why.
///
/// It is the BOTTOM of every chain: everything that arrives later -- TLS, the
/// proxies, HTTP/2, HTTP/3 -- sits above one of these four and reaches the
/// network through it.
///
/// No `#[allow(dead_code)]` on this declaration, for the same reason as
/// [`select`], [`filters`] and [`shutdown`]: the allowances belong on the items.
pub(crate) mod socket;

/// The connection pool -- supersedes `lib/conncache.c` and
/// `lib/conncache.h`.
///
/// The fifth module of this directory, and it consumes the first three of
/// them: it owns connections whose teardown half is [`shutdown`]'s
/// [`shutdown::ShuttingDownConnection`], it hands them to
/// [`shutdown::ShutdownQueue`] or to [`shutdown::terminate`] when they are
/// finished with, and through them it reaches [`filters::FilterChains`] and
/// the readiness vocabulary of [`select`]. Nothing in `cshutdn.h`,
/// `cfilters.h` or `select.h` names anything from `conncache.h`, so the
/// direction is one-way -- and `crate::conn::shutdown`'s own tests assert
/// that it never imports this module, which is what keeps the shared
/// connection-limit invariant a parameter rather than a cycle.
///
/// It owns what C keeps as `struct cpool` (`lib/conncache.h:49-60`): the
/// connections a transfer has finished with but which may still be REUSED,
/// bundled per destination. C links them with an intrusive list node embedded
/// in each connection and reaches one through a raw pointer; here the pool
/// owns each connection by value and hands out a generational key, so a key
/// held across a removal is detected instead of dereferenced.
///
/// Its policy seams are INJECTED traits -- [`pool::ConnectionHealth`] for the
/// dead/reuse decision that `lib/url.c:622-700` makes and
/// [`pool::UpkeepAction`] for what keeping a connection alive means -- so that
/// `crate::protocols` is not named from here and the module graph stays
/// acyclic. Its eviction policy is a maximum-idle-age full scan and is
/// documented in full at the top of the module; it must not be confused with
/// [`shutdown::ShutdownQueue`]'s FIFO.
///
/// No `#[allow(dead_code)]` on this declaration, for the same reason as
/// [`select`], [`filters`] and [`shutdown`]: the allowances belong on the
/// items.
pub(crate) mod pool;

/// An address rendered as text, with its port in host byte order.
///
/// What [`addr2string`] hands back. C writes through two out-parameters -- a
/// `char *addr` the caller sized at `MAX_IPADR_LEN` and a `uint16_t *port` --
/// and returns a `bool`; pairing them in one value is what makes it impossible
/// to read the port of a conversion that failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AddrText {
    /// The address as `curlx_inet_ntop` renders it, or the empty string for an
    /// unnamed `AF_UNIX` socket.
    pub(crate) addr: String,
    /// The port in HOST byte order -- C's `ntohs(si->sin_port)`. Zero for
    /// `AF_UNIX`, which has no port.
    pub(crate) port: u16,
}

/// Why [`addr2string`] could not render an address.
///
/// One variant, because the C has one failure: *"`default: break;` ... `addr[0]
/// = '\0'; *port = 0; errno = SOCKEAFNOSUPPORT; return FALSE;`"*
/// (`lib/connect.c:252-258`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Addr2StringError {
    /// The family is none of `AF_INET`, `AF_INET6` or `AF_UNIX`.
    AfNotSupported,
}

impl Addr2StringError {
    /// The `errno` C sets, which its callers then print.
    ///
    /// `errno = SOCKEAFNOSUPPORT` (`lib/connect.c:256`), and the number is
    /// genuinely observable: `set_remote_ip` renders it into *"curl_sa_addr
    /// inet_ntop() failed with errno %d: %s"* (`lib/cf-socket.c:1035-1036`).
    /// It comes from [`crate::ffi::sys::SOCKEAFNOSUPPORT`] because it differs
    /// between the mandated targets and `libc` is named nowhere outside that
    /// directory.
    ///
    /// The C's own comment on `Curl_addr2string` warns about which `errno` this
    /// is: *"note it calls `curlx_inet_ntop` which sets `errno` on fail, not
    /// `SOCKERRNO`"* (`lib/connect.c:209-210`). On the four mandated targets the
    /// two are the same variable, so the distinction has no successor -- but it
    /// is why the message says `errno` and not `SOCKERRNO`.
    pub(crate) const fn errno(self) -> i32 {
        match self {
            Self::AfNotSupported => crate::ffi::sys::SOCKEAFNOSUPPORT,
        }
    }
}

/// Renders a socket address as text and a port -- `Curl_addr2string`
/// (`lib/connect.c:211-258`), declared at `lib/connect.h:75`.
///
/// # Why this lives in the parent rather than in [`socket`]
///
/// Because it is `lib/connect.c`'s function, and `lib/connect.c` is what this
/// file supersedes. Three call sites in `lib/cf-socket.c` use it --
/// `set_remote_ip` (`:1032`), `set_local_ip` (`:1013`) and
/// `cf_tcp_set_accepted_remote_ip` (`:2000`) -- and each reports its own failure
/// with its own message, so the helper must not decide how a failure is
/// announced. [`socket`] consumes it and does not reimplement it.
///
/// # The three families, and the one that is not an error
///
/// * `AF_INET` and `AF_INET6` delegate to [`crate::util::inet`], never to
///   [`std::net::Ipv6Addr`]'s [`std::fmt::Display`]. That is not pedantry:
///   curl renders an IPv4-compatible address as `::a.b.c.d` where the standard
///   library does not, and declines to compress a single zero word where the
///   standard library compresses it. Both divergences reach `--verbose` output
///   and `CURLINFO_PRIMARY_IP`.
/// * `AF_UNIX` SUCCEEDS with its path, or with the EMPTY STRING for a socket
///   that has no name -- the C's `if(salen > sizeof(CURL_SA_FAMILY_T))` test,
///   whose comment is *"socket with no name"* -- and a port of zero either way.
///   An unnamed Unix socket is a perfectly ordinary thing, so this is a success
///   and not a failure.
/// * Anything else fails, having reported nothing.
///
/// The port is returned in HOST byte order: `*port = ntohs(si->sin_port)`.
/// [`std::net::SocketAddr::port`] already is, so no conversion appears here --
/// which is worth stating, because a `htons` added "for symmetry" would corrupt
/// every port on a little-endian target.
///
/// # Errors
///
/// [`Addr2StringError::AfNotSupported`]. **This branch is unreachable through
/// every constructor in this crate**: an address only ever arrives as a
/// [`crate::dns::ResolvedSockAddr`], which is `Ip` or `Unix` and nothing else,
/// or from [`socket2::Socket::local_addr`] and `peer_addr` on a socket created
/// from one of those. It is implemented rather than asserted away because it is
/// the C's behaviour and because a future family -- `AF_PACKET`, a VSOCK
/// address -- would otherwise reach a panic instead of a code.
pub(crate) fn addr2string(
    sa: &socket2::SockAddr,
) -> Result<AddrText, Addr2StringError> {
    // `switch(sa->sa_family) { case AF_INET: ... case AF_INET6: ... }`
    if let Some(inet) = sa.as_socket() {
        let addr = match inet {
            std::net::SocketAddr::V4(v4) => {
                crate::util::inet::ntop4(&v4.ip().octets())
            }
            std::net::SocketAddr::V6(v6) => {
                crate::util::inet::ntop6(&v6.ip().octets())
            }
        };
        return Ok(AddrText {
            addr,
            port: inet.port(),
        });
    }

    // `case AF_UNIX:` -- a path, or no name at all, and a port of zero.
    if sa.is_unix() {
        let addr = sa.as_pathname().map_or_else(String::new, |path| {
            path.to_string_lossy().into_owned()
        });
        return Ok(AddrText { addr, port: 0 });
    }

    // `default: break;` and then the shared failure tail.
    Err(Addr2StringError::AfNotSupported)
}
